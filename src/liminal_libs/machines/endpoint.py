"""A model server asked over http (1.62.0): what the AI plugins ask an instance with, on this machine or on another
(the user, 2026-11-16: "i need 3 plugins for inference serving local models on the platform, :: lama.cpp, ollama and
vLLM"; "also remote connection to instances if possible").

    at = Endpoint(base_url("127.0.0.1", 11434))      # an instance's address, built from its parts
    at.get("/api/version")                            # an answer's JSON (None when it has none)
    at.answer("GET", "/health", ok=(200, 503))        # the whole answer: its status, its headers, its body
    for line in at.lines("POST", "/api/pull", json=ask, cancel=cancelled):    # a stream, line by line as it comes
    at.models(), at.chat(model, prompt)               # the OpenAI-compatible two the three servers share

machines/rest.py asks a cloud's API over https and reads each answer whole. A model server needs three things it does
not give: plain http to this machine (a server run here has no certificate), an answer read as it comes (a model's
download says its progress line by line), and a bound on all that is read (what answers at a port need not be the
server expected there).

- The address. https anywhere; http to this machine (instances.is_local: 127.0.0.1, localhost, ::1); http to another
  machine only once its user accepted that (`plain=True`): else a Refusal naming ACCEPT_PLAIN, which the page asks
  as a second, explicit confirmation. No host is named here: an instance's address is its user's, a maker's (a
  registry's) is its plugin's, and base_url builds either from its parts.
- Sending. `transport(method, url, headers, body, timeout, stream) -> Reply` is a test's stand-in; else the `requests`
  package with nothing taken from the environment (no proxy, no ~/.netrc, no CA bundle of its variables), the body
  asked for as it is (not compressed). No redirect is followed: an instance answers at its own address or not at
  all. The key goes as a bearer and is taken out of every word an error says (rest.scrub), before any is cut.
- Bounds. An answer is read as it comes, a piece for each receive, so its bounds are looked at after every one (a
  read that gets nothing ends at the socket's own wait): refused past `most` bytes, and whole within twice its wait
  or not at all. A stream's line is refused past LINE_MOST bytes; a stream is left `deadline` seconds after it was
  asked for, and ends with Cancelled once its `cancel()` says so. A chat's text is cut at ANSWER_CHARS.
- One deadline for the whole of an ask (1.76.0): its connection (each address its name has, in turn), a TLS
  handshake, the status line and the headers, and the body; twice its wait for an answer read whole, `deadline` for
  a stream. The requests transport keeps it with a watchdog, a thread of the request's own that ends with it: once
  the time is up it shuts the request's socket, so that a connect, a handshake or a read waiting on it ends then,
  however slowly its bytes came (each within the socket's wait), and the ask fails as one whose read waited too long
  (Overdue, a TimeoutError: "no answer from ... within N s", or for a body "its answer was not whole after N s"); a
  stream is left where it is, as at its deadline. On Windows a TLS socket is only shut down, never closed under
  OpenSSL, which reads and writes through its number (closed, that number goes to the next socket made): a wait
  there ends at its peer's next byte or at its own timeout, one wait past the deadline at most. A name being looked
  up is not cut short (nothing cuts a lookup short): the ask ends once the name is found, and a name not found is
  said as one, even once the deadline has passed. Only the library's own transport is given the deadline: a
  stand-in has no socket to shut, and the bounds above are its asker's alone.
- Asked only when a caller asks, with a short wait (LOOK_S): nothing is polled, and nothing is sent a second time.
  A look that failed is the next look's to repeat, and a write that got no answer may have been done.

`seen` is what the last ask came to (when, its status, how long it took, its error's words): what a plugin's
api_facts() says, never an ask of its own. `Progress` says how far a download is, a line every two seconds at most.
"""
from __future__ import annotations

import contextvars
import functools
import ipaddress
import json as jsonlib
import os
import re
import socket
import ssl
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

from ..instances import Refusal, has_control, is_local
from .rest import Answer, _json_of, scrub
from .terminal import Cancelled
from .world import _close, _sayer, size_words

LOOK_S = 3.0  # seconds an ask waits unless its caller says otherwise: a page's look at an instance is short
MOST = 4 << 20  # bytes read of one answer at most
LINE_MOST = 1 << 16  # bytes of one line of a stream
ANSWER_CHARS = 4000  # characters kept of a chat's answer
CHAT_S = 120.0  # seconds a chat waits: a model that is not loaded is loaded first
ACCEPT_PLAIN = "accept_plain"  # the argument that, true, lets another machine be asked over plain http
AGENT = "liminal-libs (model server client)"  # a fixed name: nothing of the user's, nothing of the machine's
OK = (200, 201, 202, 204)
STREAMS = (200, 201, 202)  # the statuses a stream begins with
PIECE = 1 << 16  # bytes of an answer read at a time, at most
SMALL = 512  # bytes of a read where the transport cannot hand on what has come so far (urllib3 before 2)
PORTS = {"http": 80, "https": 443}  # a scheme's own port: an address that names a scheme and no port means it
CANCELLED = "cancelled"
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,251}[a-z0-9])?$")  # a host's name (a compose service's underscore too)


class EndpointError(Exception):
    """An ask that failed, in words (the key taken out). `status`: the answer's HTTP status; 0 when no answer came
    (nothing listens there, none in time, a connection that broke off)."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status

    @property
    def refused(self) -> bool:
        """The instance refused who asked (401, 403): it wants a key, or another one."""
        return self.status in (401, 403)


class Overdue(TimeoutError):
    """A request cut off at its deadline (1.76.0): the whole of it, its connection, a TLS handshake, the headers and
    the body, took longer than `seconds`, and its socket was shut (the requests transport's watchdog). A TimeoutError,
    as a read that waited past its socket's timeout raises one, and trouble() says it as it says that one, in these
    seconds."""

    def __init__(self, seconds: float):
        super().__init__(float(seconds))
        self.seconds = float(seconds)

    def __str__(self) -> str:
        return f"no whole answer within {self.seconds:g} s: the request was cut off at its deadline"


def _nothing() -> None:
    return None


@dataclass
class Reply:
    """What a transport hands back before the body is read: the answer's status, its headers, its body in pieces as
    they come (`chunks`: the asker reads them, under its bounds) and `close()`, which lets the connection go. The
    asker calls it once, whether it read to the end or not."""

    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    chunks: Iterable[bytes] = ()
    close: Callable[[], None] = _nothing


# -- an address --------------------------------------------------------------------------------------------------------
def _port(value) -> int:
    try:
        port = int(str(value).strip()) if not isinstance(value, bool) else 0
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise ValueError(f"a port is a whole number from 1 to 65535, not {str(value)[:20]!r}")
    return port


def _host(name) -> str:
    """A host as an address names it, in lower case and without brackets: an IPv4 or IPv6 address, or a name."""
    host = str(name or "").strip().strip("[]").rstrip(".").lower()
    if "%" in host:
        raise ValueError(f"{str(name)[:80]!r} is an address with a zone (%), which is not taken: name the host")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not host.isascii():  # an international name: its ASCII form is the user's to give, not a guess of this one's
        raise ValueError(f"{str(name or '')[:80]!r} is a name with letters outside ASCII: give it as your DNS knows "
                         "it, in its ASCII form (xn--...)")
    if not _NAME.match(host):
        raise ValueError(f"{str(name or '')[:80]!r} is no host's name and no address")
    return host


def _prefix(path) -> str:
    """A path as the prefix asks go under: "" for none, else /a/b without a last slash."""
    steps = [s for s in str(path or "").split("/") if s]
    if any(s in (".", "..") for s in steps):
        raise ValueError("an address's path holds no . and no ..: give the path the server answers under, as it is")
    return "".join(f"/{s}" for s in steps)


def parse_address(text, default_port: int) -> tuple[str, int, bool, str]:
    """An instance's address as its user typed it: (host, port, tls, prefix).

    - `gpu-box` and `gpu-box:8000` are http, at the port given, else at `default_port` (the maker's own);
    - with a scheme (http or https) and no port, the port is the scheme's own, 80 or 443 (Ollama's own rule for
      OLLAMA_HOST), never the maker's;
    - a path is the prefix every ask goes under (a proxy's sub-path, llama.cpp's --api-prefix), without a last slash;
    - an IPv6 address stands in brackets when a port or a path follows it: [::1]:8000.

    ValueError in words for anything else: another scheme, a user name or a password, a query, a fragment, a port or
    a host that is none. Whether the address may be asked at all (plain http to another machine) is Endpoint's to
    say, not this function's."""
    typed = str(text if text is not None else "").strip()
    shown = repr(typed[:80])
    if not typed:
        raise ValueError("no address given: a host (gpu-box), a host and its port (gpu-box:8000), or an http or https "
                         "address")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in typed):
        raise ValueError(f"an address holds no space and no line break: not {shown}")
    scheme, rest = "", typed
    found = _SCHEME.match(typed)
    if found:
        scheme, rest = found.group(1).lower(), typed[found.end():]
        if scheme not in PORTS:
            raise ValueError(f"an instance is asked over http or https, not over {scheme}")
    if "@" in rest.split("/", 1)[0]:  # said before anything of it is shown back: a password may be in it
        raise ValueError("an address carries no user name and no password: an instance's key is kept on its own, "
                         "never in its address")
    if "?" in rest or "#" in rest:
        raise ValueError("an address carries no query (?) and no fragment (#): a host, a port and a path only")
    if rest.count(":") > 1 and not rest.startswith("["):  # an IPv6 address written bare: alone, or it is none
        try:
            ipaddress.IPv6Address(rest.split("%", 1)[0])
        except ValueError:
            raise ValueError(f"{shown} is no address: an IPv6 address stands in brackets when a port or a path "
                             "follows it ([::1]:8000)") from None
        return _host(rest), PORTS[scheme] if scheme else _port(default_port), scheme == "https", ""
    try:
        parts = urlsplit("//" + rest)
        named = parts.hostname or ""
    except ValueError:
        raise ValueError(f"{shown} is no address: a host, a host and its port, or an http or https address") from None
    try:
        port = parts.port
    except ValueError:
        raise ValueError(f"{shown} is no address: its port is a whole number from 1 to 65535") from None
    if not named:
        raise ValueError(f"{shown} names no host")
    if port is None:
        port = PORTS[scheme] if scheme else default_port
    return _host(named), _port(port), scheme == "https", _prefix(parts.path)


def base_url(host, port, tls: bool = False, prefix: str = "") -> str:
    """An address built from its parts, as Endpoint takes it: the scheme (https with `tls`), the host (an IPv6
    address in brackets), the port unless it is the scheme's own, and the prefix. ValueError for a part that is
    none."""
    scheme = "https" if tls else "http"
    name, number = _host(host), _port(port)
    where = f"[{name}]" if ":" in name else name
    at = "" if number == PORTS[scheme] else f":{number}"
    return f"{scheme}://{where}{at}{_prefix(prefix)}"


# -- the client --------------------------------------------------------------------------------------------------------
class Endpoint:
    """One instance's address, asked (module docstring). `base`: an http or https address (base_url); `key`: sent as a
    bearer with every ask, when there is one; `headers`: sent with every ask (a registry's Accept); `plain`: exactly
    True once the user accepted plain http to another machine; `timeout`: an ask's wait in seconds, unless the ask
    says its own; `most`: the bytes read of one answer; `agent`: the User-Agent, a fixed name when none is given.

    Making one sends nothing. It raises a Refusal naming ACCEPT_PLAIN for plain http to another machine that was not
    accepted, and a ValueError in words for what is no http or https address or no key."""

    def __init__(self, base: str, *, key: str = "", headers: Mapping[str, str] | None = None, plain: bool = False,
                 timeout: float = LOOK_S, most: int = MOST, transport: Callable | None = None, agent: str = "",
                 clock: Callable[[], float] = time.monotonic):
        if not _SCHEME.match(str(base or "").strip()):
            raise ValueError("an instance's address says http or https first: base_url builds one from its parts")
        self.host, self.port, self.tls, self.prefix = parse_address(base, 0)
        self.local = is_local(self.host)
        if not self.tls and not self.local and plain is not True:
            raise Refusal(f"{self.host} would be asked over plain http: its key and everything sent to it can be read "
                          "on the way. Give an https address, or accept it for a network you trust.",
                          accept=ACCEPT_PLAIN)
        self.base = base_url(self.host, self.port, self.tls, self.prefix)
        self.timeout = _wait(timeout)
        self._key = _key(key)
        # taken out of every word said: the key, and the key as a server or a proxy that changes a case says it back
        self._secrets = tuple(dict.fromkeys((self._key, self._key.lower(), self._key.upper()))) if self._key else ()
        # the caller's headers over this client's own; the body is asked for as it is whatever they say
        self._headers = _merged({"User-Agent": str(agent or AGENT)}, headers or {}, {"Accept-Encoding": "identity"})
        self._accept = next((v for k, v in self._headers.items() if k.lower() == "accept"), "")
        self._most = max(1, int(most))
        self._transport = transport or requests_transport
        self._clock = clock
        where = f"[{self.host}]" if ":" in self.host else self.host
        self._at = f"{where}:{self.port}"  # the instance in an error's words
        self.seen: dict = {"at": None, "status": 0, "seconds": 0.0, "error": ""}  # the last ask (module docstring)

    # -- asking --------------------------------------------------------------------------------------------------------
    def url(self, path: str, params: Mapping | None = None) -> str:
        """`path` under the instance's address, with `params` (the None ones left out). A path is never an address
        of its own: whatever it holds, it is asked of this instance's host."""
        text = str(path or "")
        if has_control(text):
            raise ValueError("a path holds no line break and no control character")
        url = f"{self.base}/{text.lstrip('/')}" if text else self.base
        query = {k: v for k, v in (params or {}).items() if v is not None}
        if query:
            url += ("&" if "?" in url else "?") + urlencode(query, doseq=True)
        return url

    def get(self, path: str, *, params: Mapping | None = None, timeout: float | None = None):
        """A GET's JSON (None when the answer has none). EndpointError for any status but 200, 201, 202, 204."""
        return self._ask("GET", path, None, params, timeout, OK).data

    def text(self, path: str, *, timeout: float | None = None) -> str:
        """A GET's body as text (Ollama's "Ollama is running", a server's metrics)."""
        return self._ask("GET", path, None, None, timeout, OK, "*/*").body.decode("utf-8", "replace")

    def post(self, path: str, json=None, *, timeout: float | None = None):
        """A POST's JSON, `json` sent as its body. Sent once: a write that got no answer may have been done."""
        return self._ask("POST", path, json, None, timeout, OK).data

    def delete(self, path: str, json=None, *, timeout: float | None = None):
        """A DELETE's JSON, `json` sent as its body (Ollama's delete names its model there)."""
        return self._ask("DELETE", path, json, None, timeout, OK).data

    def answer(self, method: str, path: str, *, json=None, params: Mapping | None = None,
               timeout: float | None = None, ok: Iterable[int] = OK) -> Answer:
        """One ask and its whole answer (rest.Answer: status, headers by lowercased name, body, seconds, data) when
        its status is one of `ok`; else an EndpointError in the server's words. A status that is itself the news
        (llama.cpp's 503 while it loads a model) is asked with it in `ok`."""
        return self._ask(method, path, json, params, timeout, ok)

    def lines(self, method: str, path: str, *, json=None, timeout: float | None = None, deadline: float = 3600.0,
              cancel: Callable[[], bool] | None = None) -> Iterator[str]:
        """An answer that comes as it is made, a line at a time: newline-delimited JSON (Ollama's pull), or a
        server-sent stream's lines as they are (llama.cpp's `event:` and `data:` lines). Blank lines are not handed
        on, nor a line's end; nothing is parsed.

        Nothing is sent until the first line is asked for. `timeout`: the longest the stream may say nothing.
        `deadline`: seconds after which the stream is left where it is, without an error: `seen["error"]` then says
        so, and the caller knows by the last line it got whether the work was done. It is the whole request's
        deadline too (the module docstring): a read waiting when it comes is ended then, and the stream left there;
        an answer that has not begun by then is an EndpointError (no answer within it). `cancel()`: looked at before
        each read and after each line, and when a read fails; once true, Cancelled. A line past LINE_MOST bytes, a
        status that is no stream's, a connection that breaks off: EndpointError. The connection is let go at the
        end, however it ends, and when the caller stops reading early."""
        method = str(method).upper()
        url, lead = self.url(path), f"{method} {self._where(path)}"
        body = None if json is None else jsonlib.dumps(json, separators=(",", ":")).encode()
        wait = self.timeout if timeout is None else _wait(timeout)
        started = self._clock()
        ends = started + max(0.0, float(deadline))
        too_long = f"a line of its stream is longer than {size_words(LINE_MOST)}: not read"
        status, error = 0, ""
        reply: Reply | None = None
        try:
            if cancel is not None and cancel():
                raise Cancelled(CANCELLED)
            try:
                reply = self._send(method, url, body, wait, True, "*/*", max(0.0, float(deadline)))
            except Exception as e:  # noqa: BLE001 - the connection's trouble, in words
                raise self._failed(lead, self._trouble(e, wait)) from None
            status = int(reply.status)
            if status not in STREAMS:
                try:
                    said = self._words(self._whole(reply, started, wait, lead))
                except EndpointError:
                    raise
                except Exception as e:  # noqa: BLE001 - its error's body broke off: the status alone
                    said = self._trouble(e, wait)
                raise self._failed(lead, f"HTTP {status}: {said}", status)
            self._as_asked(_lower(reply.headers), lead, status)
            kept = b""
            chunks = iter(reply.chunks)
            while True:
                if cancel is not None and cancel():
                    raise Cancelled(CANCELLED)
                if self._clock() >= ends:
                    error = f"{lead}: its stream was left after {float(deadline):g} s, before its end"
                    return
                try:
                    piece = next(chunks)
                except StopIteration:
                    break
                except Exception as e:  # noqa: BLE001 - the connection's trouble, in words
                    if cancel is not None and cancel():  # cancelled while the read waited: that is how it ended
                        raise Cancelled(CANCELLED) from None
                    if _overdue(e) is not None:  # its deadline came while the read waited: left there, as above
                        error = f"{lead}: its stream was left after {float(deadline):g} s, before its end"
                        return
                    raise self._failed(lead, f"its stream broke off: {self._trouble(e, wait)}") from None
                rows = (kept + piece).split(b"\n")
                kept = rows.pop()  # the line that has not ended yet (its \r may have come, its \n not)
                rows = [_bare(row) for row in rows]
                if len(kept) > LINE_MOST + 1 or any(len(row) > LINE_MOST for row in rows):
                    raise self._failed(lead, too_long, status)
                for row in rows:
                    line = row.decode("utf-8", "replace")
                    if line.strip():
                        yield line
                        if cancel is not None and cancel():
                            raise Cancelled(CANCELLED)
            if len(_bare(kept)) > LINE_MOST:
                raise self._failed(lead, too_long, status)
            last = _bare(kept).decode("utf-8", "replace")  # a last line that did not end
            if last.strip():
                yield last
        except EndpointError as e:
            status, error = e.status, str(e)
            raise
        except Cancelled:
            error = f"{lead}: {CANCELLED}"
            raise
        finally:
            _close(reply)
            self._note(status, self._clock() - started, error)

    def models(self) -> list[dict]:
        """The models the instance lists the OpenAI way (GET /v1/models), each {"id", "owner", "context"}: its
        `owned_by` ("" when it says none) and the context it says in tokens (vLLM's max_model_len, llama.cpp's
        meta.n_ctx_train), None where it says none (Ollama's list). EndpointError when what answers is no such
        list."""
        found = self._ask("GET", "/v1/models", None, None, None, OK)
        rows = found.data.get("data") if isinstance(found.data, Mapping) else None
        if not isinstance(rows, list):
            error = self._failed(f"GET {self._where('/v1/models')}", "what answered is no list of models: not an "
                                 "OpenAI-compatible server, or not at this address", found.status)
            self._note(found.status, found.seconds, str(error))
            raise error
        out = []
        for row in rows:
            if not isinstance(row, Mapping) or not isinstance(row.get("id"), str) or not row["id"]:
                continue
            meta = row.get("meta") if isinstance(row.get("meta"), Mapping) else {}
            owner = row.get("owned_by")
            out.append({"id": row["id"], "owner": owner if isinstance(owner, str) else "",
                        "context": _count(row.get("max_model_len")) or _count(meta.get("n_ctx_train")) or None})
        return out

    def chat(self, model: str, prompt: str, *, system: str = "", max_tokens: int = 512,
             timeout: float = CHAT_S) -> dict:
        """One prompt answered the OpenAI way (POST /v1/chat/completions, not streamed), bounded: `max_tokens` at the
        server, ANSWER_CHARS here. {"text", "cut" (the text was longer than ANSWER_CHARS and is cut there), "model"
        (as the server names it), "finish" (its finish_reason: "length" when the tokens ran out), "tokens":
        {"prompt", "completion"} (None where it counts none), "seconds"}."""
        messages = [{"role": "system", "content": str(system)}] if system else []
        messages.append({"role": "user", "content": str(prompt)})
        ask = {"model": str(model), "messages": messages, "max_tokens": max(1, int(max_tokens)), "stream": False}
        got = self._ask("POST", "/v1/chat/completions", ask, None, timeout, OK)
        data = got.data if isinstance(got.data, Mapping) else {}
        choices = data.get("choices")
        first = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], Mapping) else None
        if first is None:
            error = self._failed(f"POST {self._where('/v1/chat/completions')}", "its answer holds no choice: no "
                                 "answer of a chat's", got.status)
            self._note(got.status, got.seconds, str(error))
            raise error
        message = first.get("message") if isinstance(first.get("message"), Mapping) else {}
        text = _content(message.get("content"))
        usage = data.get("usage") if isinstance(data.get("usage"), Mapping) else {}
        named, finish = data.get("model"), first.get("finish_reason")
        return {"text": text[:ANSWER_CHARS], "cut": len(text) > ANSWER_CHARS,
                "model": named if isinstance(named, str) and named else str(model),
                "finish": finish if isinstance(finish, str) else "",
                "tokens": {"prompt": _count(usage.get("prompt_tokens")),
                           "completion": _count(usage.get("completion_tokens"))},
                "seconds": round(got.seconds, 3)}

    # -- how -----------------------------------------------------------------------------------------------------------
    def _where(self, path: str) -> str:
        """A path as an error names it: the path asked, under the address's prefix (/v1/v1/models, when the address
        typed ended in /v1), without its query, the key taken out, 120 characters at most."""
        text = str(path or "").split("?", 1)[0]
        asked = f"{self.prefix}/{text.lstrip('/')}" if text else (self.prefix or "/")
        return scrub(asked, self._secrets)[:120]

    def _failed(self, lead: str, words: str, status: int = 0) -> EndpointError:
        return EndpointError(scrub(f"{lead}: {words}", self._secrets), status)

    def _trouble(self, e: BaseException, wait: float) -> str:
        """Why no answer came (trouble), the key taken out before its words are cut."""
        return trouble(e, self._at, wait, self._secrets)

    def _as_asked(self, headers: Mapping[str, str], lead: str, status: int) -> None:
        """EndpointError for a body that comes encoded (gzip, br): none was asked for, and one unpacked here would be
        read past its bound before it could be counted. The coding is said back with the key taken out first."""
        coding = str(headers.get("content-encoding", "")).strip()
        if coding.lower() not in ("", "identity"):
            shown = scrub(coding, self._secrets)[:20].lower()
            raise self._failed(lead, f"its answer comes {shown}-encoded, which was not asked for: not read", status)

    def _note(self, status: int, seconds: float, error: str) -> None:
        self.seen = {"at": time.time(), "status": int(status), "seconds": round(max(0.0, float(seconds)), 3),
                     "error": scrub(error, self._secrets)}

    def _send(self, method: str, url: str, body: bytes | None, wait: float, stream: bool, accept: str = "",
              deadline: float | None = None) -> Reply:
        """The ask sent. The library's own transport is given its deadline (`deadline`: seconds for the whole of it,
        which its watchdog keeps); a stand-in is asked as it always was, with the six it takes."""
        headers = _merged(self._headers, {"Accept": self._accept or accept or "application/json"},
                          {"Content-Type": "application/json"} if body is not None else {},
                          {"Authorization": f"Bearer {self._key}"} if self._key else {})
        if deadline is not None and self._transport is _OWN:
            return _OWN(method, url, headers, body, wait, stream, deadline=deadline)
        return self._transport(method, url, headers, body, wait, stream)

    def _ask(self, method: str, path: str, json, params: Mapping | None, timeout: float | None, ok: Iterable[int],
             accept: str = "") -> Answer:
        method = str(method).upper()
        url, lead = self.url(path, params), f"{method} {self._where(path)}"
        body = None if json is None else jsonlib.dumps(json, separators=(",", ":")).encode()
        wait = self.timeout if timeout is None else _wait(timeout)
        started = self._clock()
        reply: Reply | None = None
        try:
            try:
                reply = self._send(method, url, body, wait, False, accept, 2 * wait)  # whole within twice its wait
                answer = self._whole(reply, started, wait, lead)
            except EndpointError:
                raise
            except Exception as e:  # noqa: BLE001 - the connection's trouble, in words
                raise self._failed(lead, self._trouble(e, wait)) from None
            finally:
                _close(reply)
            if answer.status not in set(ok):
                raise self._failed(lead, f"HTTP {answer.status}: {self._words(answer)}", answer.status)
        except EndpointError as e:
            self._note(e.status, self._clock() - started, str(e))
            raise
        self._note(answer.status, answer.seconds, "")
        return answer

    def _whole(self, reply: Reply, started: float, wait: float, lead: str) -> Answer:
        """A reply's body read under the bounds, as an Answer: refused past `most` bytes (by what it says its
        length is, before a byte is read; else as it comes), and when it is not whole within twice the wait (looked
        at after every piece, and a transport hands on a piece for every receive), or within the deadline its
        transport's watchdog kept (Overdue: said in the same words, in that deadline's seconds)."""
        status, headers = int(reply.status), _lower(reply.headers)
        self._as_asked(headers, lead, status)
        said = _count(headers.get("content-length"))
        if said is not None and said > self._most:
            raise self._failed(lead, f"its answer is {size_words(said)}, and {size_words(self._most)} is the most "
                               "read of one: not read", status)
        ends = started + 2 * wait
        got, pieces = 0, []
        try:
            for piece in reply.chunks:
                got += len(piece)
                if got > self._most:
                    raise self._failed(lead, f"its answer is longer than {size_words(self._most)}: not read", status)
                if self._clock() > ends:
                    raise self._failed(lead, f"its answer was not whole after {2 * wait:g} s: not read")
                pieces.append(piece)
        except EndpointError:
            raise
        except Exception as e:  # noqa: BLE001 - its asker says the connection's trouble; the deadline's is said here
            late = _overdue(e)
            if late is None:
                raise
            raise self._failed(lead, f"its answer was not whole after {late.seconds:g} s: not read") from None
        answer = Answer(status, headers, b"".join(pieces), self._clock() - started)
        answer.data = _json_of(answer)  # rest.py's reading: by its content type, or by how it begins
        return answer

    def _words(self, answer: Answer) -> str:
        """An error answer's own words: the message of its JSON (OpenAI's {"error": {"message"}} as llama.cpp and
        vLLM send it, Ollama's {"error": "..."}, a web framework's "detail"), else the start of its body. The key is
        taken out of all of them before they are cut (the body is whole in memory already, `most` bytes at most)."""
        words = ""
        if isinstance(answer.data, Mapping):
            for key in ("error", "message", "detail", "error_description", "title"):
                words = _said(answer.data.get(key))
                if words:
                    break
        if not words:
            words = answer.body.decode("utf-8", "replace").strip() or "no words came back"
        return " ".join(scrub(words, self._secrets).split())[:400]


# -- an answer's parts -------------------------------------------------------------------------------------------------
def _wait(timeout) -> float:
    wait = float(timeout)
    if not wait > 0:
        raise ValueError(f"an ask waits a number of seconds above 0, not {timeout!r}")
    return wait


def _key(key) -> str:
    """A key as it is sent: without the spaces and the line break it was pasted with. ValueError (the key not in
    its words) for one that holds a space, a line break or a control character, which would end the header it goes
    in, and for one with a character outside ASCII (a curly quote a word processor made of a straight one), which a
    header cannot carry: sent, it would fail as though no answer had come."""
    value = str(key or "").strip()
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("the key holds a space or a line break: enter it again, alone")
    if not value.isascii():
        raise ValueError("the key holds a character that is no plain letter, digit or sign (a curly quote, an "
                         "accented letter): enter it again as its maker gave it")
    return value


def _bare(row: bytes) -> bytes:
    """A stream's line without the carriage return a server that writes \\r\\n ends it with."""
    return row[:-1] if row.endswith(b"\r") else row


def _merged(*parts: Mapping[str, str]) -> dict[str, str]:
    """Headers laid over each other, a later one replacing an earlier one of the same name however it is cased."""
    out: dict[str, tuple[str, str]] = {}
    for part in parts:
        for name, value in part.items():
            out[str(name).lower()] = (str(name), str(value))
    return dict(out.values())


def _lower(headers) -> dict[str, str]:
    try:
        return {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}
    except (TypeError, ValueError):
        return {}


def _count(value) -> int | None:
    """A whole number that is none below 0, as an answer gives one (a number, or a header's digits); else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        return int(value) if value >= 0 and value == int(value) else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _said(value) -> str:
    """The words of one field of an error's JSON: a string as it is, an object's message, a list as JSON (whole:
    the key is taken out of them before they are cut)."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, Mapping):
        for key in ("message", "error", "detail", "code", "type"):
            inner = value.get(key)
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
        return ""
    if isinstance(value, list) and value:
        return jsonlib.dumps(value)
    return ""


def _content(value) -> str:
    """A chat message's content as text: a string, or the text parts of a list of parts; "" for none."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(p["text"] for p in value if isinstance(p, Mapping) and isinstance(p.get("text"), str))
    return ""


# -- why no answer came ------------------------------------------------------------------------------------------------
def _chain(e: BaseException) -> list[BaseException]:
    """An error with what caused it, as far as it says (its cause, its context, a `reason`, its arguments): the
    socket's own error sits two or three deep in the one `requests` raises."""
    found: list[BaseException] = []
    todo: list[object] = [e]
    while todo and len(found) < 24:
        x = todo.pop()
        if not isinstance(x, BaseException) or any(x is f for f in found):
            continue
        found.append(x)
        todo += [x.__cause__, x.__context__, getattr(x, "reason", None), *(getattr(x, "args", None) or ())]
    return found


def _overdue(e: BaseException) -> Overdue | None:
    """The deadline that cut a request off, where `e` is one or was caused by one (Overdue); else None."""
    return next((x for x in _chain(e) if isinstance(x, Overdue)), None)


def _unfound(e: BaseException) -> bool:
    """Whether `e` is a name this machine does not find, or was caused by one (socket.gaierror, or urllib3's
    NameResolutionError)."""
    return any(isinstance(x, socket.gaierror) or type(x).__name__ == "NameResolutionError" for x in _chain(e))


def trouble(e: BaseException, at: str, timeout: float | None = None, secrets: Iterable[str] = ()) -> str:
    """Why `at` (a host and port) gave no answer, in words: nothing listens there, none in time (`timeout` seconds;
    a request its deadline cut off, in the deadline's own: Overdue), a name this machine does not find, a certificate
    it does not trust; else the error's own name and words, `secrets` taken out of them before they are cut."""
    chain = _chain(e)
    names = {type(x).__name__ for x in chain}
    late = next((x for x in chain if isinstance(x, Overdue)), None)
    if late is not None:  # its deadline cut it off, whatever the shut socket said: as a slow read, in those seconds
        return f"no answer from {at} within {late.seconds:g} s"
    if any(isinstance(x, ConnectionRefusedError) for x in chain):
        return f"nothing listens at {at}"
    if any(isinstance(x, TimeoutError) or "Timeout" in type(x).__name__ for x in chain):
        return f"no answer from {at} within {timeout:g} s" if timeout else f"no answer from {at} in time"
    if _unfound(e):
        return f"{at} is no name this machine finds"
    if "SSLCertVerificationError" in names:
        return f"the certificate {at} shows is not one this machine trusts"
    words = " ".join(scrub(str(e), tuple(secrets)).split())
    return f"no answer from {at}: {type(e).__name__}: {words}"[:300]


# -- one deadline for the whole of a request ---------------------------------------------------------------------------
# the watch of the request this thread sends now (requests_transport sets it while its adapter sends): what the
# request's connections hand their sockets to
_WATCH: contextvars.ContextVar[_Watch | None] = contextvars.ContextVar("liminal_endpoint_watch", default=None)
# where a wait on a socket ends only once the socket is closed, not once it is shut down (Windows): _shut closes a
# plain socket there as well (the tests shut their stand-ins both ways, on any system)
_CLOSES = os.name == "nt"


def _shut(sock, tls: bool = False) -> None:
    """A socket shut so that what waits on it in another thread ends: shut down both ways (on Linux a wait ends then)
    and, where a wait ends only once its socket is closed (_CLOSES: Windows), closed as well, by the C socket itself,
    since socket.close() puts that off while a file made of it is open (http.client reads an answer through one): a
    call on it then finds no socket, as CPython looks its number up again before each one. socket.socket's own
    shutdown, never an SSLSocket's, which lets go of its TLS state under the thread reading it. One closed already is
    let be.

    A TLS socket (ssl's, or one held as one: `tls`) is only ever shut down: OpenSSL reads and writes through the
    number it was given, and closing it would free that number for the next socket this process makes (Windows gives
    it out again at once), whose connection a read or a write waiting in OpenSSL would then read from and write to.
    A call on it after that ends at once, and one already waiting ends then on Linux; on Windows that one ends at its
    peer's next byte (which resets the connection) or at its own timeout, one wait past the deadline at most. Its
    owner closes it then."""
    real = isinstance(sock, socket.socket)
    try:
        if real:
            socket.socket.shutdown(sock, socket.SHUT_RDWR)
        else:
            sock.shutdown(socket.SHUT_RDWR)
    except (OSError, ValueError, AttributeError):
        pass
    if _CLOSES and not tls and not isinstance(sock, ssl.SSLSocket):
        try:
            if real:
                super(socket.socket, sock).close()
            else:
                sock.close()
        except (OSError, ValueError, AttributeError):
            pass


class _Watch:
    """One request's deadline, kept by a watchdog: a thread of the request's own ("endpoint-deadline") that waits
    `seconds`, then shuts every socket the request holds (hold: each from before it connects, a TLS one from before
    its handshake), so that a connect, a handshake or a read waiting on one ends (_shut); `fired` says it did. stop()
    ends it with its request: its thread is waited for, and nothing is shut after it returns. A socket held once it
    has fired is shut at once; one let go (release: a TLS socket is to take its number) is never reached."""

    def __init__(self, seconds: float):
        self.seconds = max(0.0, float(seconds))
        self.fired = False
        self._lock = threading.Lock()
        self._held: list[tuple] = []  # (a socket, whether it is a TLS one), as they were held
        self._ended = threading.Event()
        self._thread = threading.Thread(target=self._keep, name="endpoint-deadline", daemon=True)
        self._thread.start()

    def _keep(self) -> None:
        if self._ended.wait(min(self.seconds, threading.TIMEOUT_MAX)):
            return  # its request ended first
        with self._lock:
            if self._ended.is_set():
                return
            self.fired = True
            held, self._held = self._held, []
        for sock, tls in held:
            _shut(sock, tls)

    def hold(self, sock, tls: bool = False):
        """`sock` held till its request ends, shut once the time is up (at once when it is up already); `sock` back.
        `tls`: a TLS socket, which is only ever shut down (_shut)."""
        with self._lock:
            if not self.fired:
                self._held.append((sock, tls))
                return sock
        _shut(sock, tls)
        return sock

    def release(self, sock) -> None:
        """`sock` held no longer, before a TLS socket takes its number (and is held in its place): nothing the watchdog
        does reaches it from now on. Overdue when the time is up already: it was shut, or is being shut (on Windows
        closed), and nothing is to take its number."""
        with self._lock:
            if self.fired:
                raise Overdue(self.seconds)
            self._held = [(held, tls) for held, tls in self._held if held is not sock]

    def stop(self) -> None:
        """Its request ended: nothing is shut from now on, and its thread is gone once this returns."""
        with self._lock:
            self._ended.set()
            self._held = []
        if self._thread is not threading.current_thread():
            self._thread.join()


def _socket(family, kind, proto):
    """A socket as _dial makes one (a test's stand-in)."""
    return socket.socket(family, kind, proto)


def _dial(host: str, port: int, timeout, source, options, watch: _Watch):
    """A connection made as urllib3 makes one (urllib3.util.connection.create_connection: each address its name has,
    in turn, until one answers; the socket's options, its timeout and its source address set first), every socket
    held by `watch` from before it connects, so that the deadline cuts a connect short. Once it has fired: Overdue,
    and no address tried after it (none at all, when the name was found after it). Else the last address's error, as
    urllib3 raises it."""
    from urllib3.util.connection import allowed_gai_family

    if host.startswith("["):
        host = host.strip("[]")
    err: OSError | None = None
    for family, kind, proto, _, where in socket.getaddrinfo(host, port, allowed_gai_family(), socket.SOCK_STREAM):
        if watch.fired:
            break
        sock = None
        try:
            sock = watch.hold(_socket(family, kind, proto))
            for option in options or ():
                sock.setsockopt(*option)
            if timeout is None or isinstance(timeout, (int, float)):  # else urllib3's "the default": none is set
                sock.settimeout(timeout)
            if source:
                sock.bind(source)
            sock.connect(where)
            return sock
        except OSError as e:
            err = e
            if sock is not None:
                sock.close()
    if watch.fired:
        raise Overdue(watch.seconds)
    if err is None:
        raise OSError("getaddrinfo returns an empty list")
    try:
        raise err
    finally:
        err = None  # (as urllib3's: no cycle through the traceback)


class _Held:
    """A TLS context as a watched connection hands it to urllib3, which reads it, and sets its verify_mode and its
    check_hostname, as it would a context of its own (each read and set on the context itself). Its wrap_socket hands
    the TLS socket to the request's watch before its handshake, so that a handshake given a byte at a time is cut
    short at the deadline too, and lets the plain socket under it go first, before ssl takes its number for OpenSSL:
    that number is the TLS socket's from then on, which the watchdog only shuts down, never closes (_shut), and
    shutting the plain one would no longer reach it."""

    __slots__ = ("_context", "_watch")

    def __init__(self, context, watch: _Watch):
        object.__setattr__(self, "_context", context)
        object.__setattr__(self, "_watch", watch)

    def wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True, suppress_ragged_eofs=True,
                    server_hostname=None, session=None):
        asked = {"server_side": server_side, "do_handshake_on_connect": False,
                 "suppress_ragged_eofs": suppress_ragged_eofs, "server_hostname": server_hostname}
        if session is not None:  # (a context of pyOpenSSL's, as urllib3 can be made to use, takes none)
            asked["session"] = session
        self._watch.release(sock)  # (Overdue when the time is up already: the plain socket is shut, or being shut)
        tls = self._context.wrap_socket(sock, **asked)
        self._watch.hold(tls, tls=True)
        # pyOpenSSL's (urllib3's only where ssl has no SNI) shakes hands in its wrap_socket, over the plain socket let
        # go, within that socket's own waits; and its own socket has no do_handshake
        handshake = getattr(tls, "do_handshake", None)
        if do_handshake_on_connect and callable(handshake):
            try:
                handshake()
            except BaseException:
                try:
                    tls.close()  # as ssl's own wrap_socket lets go of one whose handshake failed
                except OSError:
                    pass
                raise
        return tls

    def __getattr__(self, name):
        if name in _Held.__slots__:  # (not set yet: a copy being made)
            raise AttributeError(name)
        return getattr(self._context, name)

    def __setattr__(self, name, value):
        if name in _Held.__slots__:  # its own (a copy being made)
            object.__setattr__(self, name, value)
        else:
            setattr(self._context, name, value)


def _context():
    """The TLS context a watched connection goes over when it is given none: urllib3's own default, as urllib3 makes
    one for each connection (its certificate and its host's name checked, TLS 1.2 at least; the CA bundle `requests`
    names is loaded into it as it connects). A test's stand-in."""
    from urllib3.util import ssl_

    return ssl_.create_urllib3_context()


@functools.lru_cache(maxsize=None)
def _watched() -> type:
    """requests' HTTP adapter with its connections watched, made once (urllib3 is imported then): while a request is
    sent under a watch (_WATCH), its connection hands it its socket from before it connects (_dial), and over https
    the TLS socket from before its handshake (_Held), each error said as urllib3 says it. Without a watch (a stream
    given no deadline: a download), every connection is urllib3's own, as it was."""
    import requests
    from urllib3 import connection, connectionpool, exceptions

    named = getattr(exceptions, "NameResolutionError", None)  # urllib3 2's; before it, a NewConnectionError

    class Dialing:
        def _new_conn(self):
            watch = _WATCH.get()
            if watch is None:
                return super()._new_conn()
            try:
                sock = _dial(self._dns_host, self.port, self.timeout, self.source_address, self.socket_options, watch)
            except Overdue:
                raise
            except socket.gaierror as e:
                if named is not None:
                    raise named(self.host, self, e) from e
                raise exceptions.NewConnectionError(self, f"Failed to establish a new connection: {e}") from e
            except TimeoutError as e:
                raise exceptions.ConnectTimeoutError(
                    self, f"Connection to {self.host} timed out. (connect timeout={self.timeout})") from e
            except OSError as e:
                raise exceptions.NewConnectionError(self, f"Failed to establish a new connection: {e}") from e
            sys.audit("http.client.connect", self, self.host, self.port)
            return sock

    class Plain(Dialing, connection.HTTPConnection):
        """http, its socket watched."""

    class Tls(Dialing, connection.HTTPSConnection):
        """https, its sockets watched: the TLS one through its context (_Held)."""

        def connect(self):
            watch = _WATCH.get()
            if watch is not None:
                given = self.ssl_context
                given = given._context if isinstance(given, _Held) else given
                self.ssl_context = _Held(given if given is not None else _context(), watch)
            return super().connect()

    class PlainPool(connectionpool.HTTPConnectionPool):
        ConnectionCls = Plain

    class TlsPool(connectionpool.HTTPSConnectionPool):
        ConnectionCls = Tls

    class Adapter(requests.adapters.HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            super().init_poolmanager(*args, **kwargs)
            self.poolmanager.pool_classes_by_scheme = {"http": PlainPool, "https": TlsPool}

    return Adapter


# -- the transport -----------------------------------------------------------------------------------------------------
def _session():
    """A `requests` session that takes nothing from the environment (as rest.py's: no ~/.netrc credentials added to
    a request, no proxy and no CA bundle from its variables) and adds no header of its own (not the package's name
    and version, not its wish for a compressed body): a request goes as it was made, straight to its host. Its way
    out is the watched adapter (_watched), so that a request's deadline reaches its sockets."""
    import requests

    session = requests.Session()
    session.trust_env = False
    session.headers.clear()
    adapter = _watched()()
    for prefix in ("https://", "http://"):
        session.mount(prefix, adapter)
    return session


def _pieces(raw, piece: int, watch: _Watch | None = None) -> Iterator[bytes]:
    """An answer's body as it is on the wire (nothing unpacked: nothing packed was asked for), handed on as it comes:
    each piece what one receive gave, `piece` bytes at most (urllib3's read1, from its version 2 on; before it, reads
    of SMALL bytes at most). Whoever reads it looks at its bounds, its deadline and its cancel after every receive,
    never only once a whole piece of a slow sender has come; a read that gets nothing ends at the socket's own
    timeout. Under a `watch` (the request's deadline), a read its watchdog ended, and any read once it has fired, is
    Overdue: what came as the socket was shut is not handed on, nor is the nothing a shut socket reads taken for the
    body's end."""
    one = getattr(raw, "read1", None)
    reads = iter(lambda: one(piece, decode_content=False), b"") if callable(one) else \
        raw.stream(min(piece, SMALL), decode_content=False)
    while True:
        try:
            data = next(reads, b"")
        except Exception:  # noqa: BLE001 - the connection's trouble, its reader's to say: unless the deadline did it
            if watch is not None and watch.fired:
                raise Overdue(watch.seconds) from None
            raise
        if watch is not None and watch.fired:
            raise Overdue(watch.seconds)
        if not data:
            return
        yield data


def requests_transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float,
                       stream: bool, piece: int = PIECE, deadline: float | None = None) -> Reply:
    """The transport when a caller gives none: one request through the `requests` package, its answer handed back
    with the body not read yet. No redirect is followed, and a redirect's body is never read: the request is given
    to the session's adapter itself, because Session.request, even told to follow nothing, reads a redirect's whole
    body, without a bound, to let its connection go. `timeout`: seconds each socket operation waits. `stream`: what
    the caller reads (a stream's lines, or an answer whole); the body is handed on as it comes either way, `piece`
    bytes at most at a time.

    `deadline` (1.76.0): seconds the whole request may take once it is sent, its connection (each address its name
    has), a TLS handshake, the status line and the headers, and the body as it is read. None: twice `timeout` for an
    answer read whole (Endpoint's bound on one, and Jenkins'), and none for a stream, which its reader bounds itself
    (Endpoint.lines gives its own; a download looks at its own after every receive). A watchdog keeps it (_Watch, a
    thread of the request's own, gone once the reply is closed or the request has failed): once the time is up it
    shuts the request's socket, so that whatever waits on it ends then (on Windows, a TLS one's within one wait of it:
    _shut), and the request is Overdue, the TimeoutError a read that waited too long raises: from here for its
    connection and its head, from the body's next read for the body (nothing that came after it is handed on, nor
    taken for the body's end). A name being looked up is not cut short: the request ends once it is found, and a name
    not found is said as one (requests' ConnectionError, as before), even once the deadline has passed."""
    import requests

    session = _session()
    watch: _Watch | None = None
    try:
        request = session.prepare_request(requests.Request(method, url, headers=dict(headers), data=body))
        seconds = (None if stream else 2 * float(timeout)) if deadline is None else float(deadline)
        watch = None if seconds is None else _Watch(seconds)
        sending = _WATCH.set(watch)
        try:
            response = session.get_adapter(url).send(request, stream=True, timeout=timeout, verify=True, cert=None,
                                                     proxies={})
        finally:
            _WATCH.reset(sending)
        if watch is not None and watch.fired:  # its time was up as its answer came: cut off all the same
            response.close()
            raise Overdue(watch.seconds)
    except BaseException as e:
        # what its shut socket made of it is said as its deadline; a name not found is its lookup's own failure, which
        # no socket was shut for (nothing cuts a lookup short), and is said as it is
        cut = watch is not None and watch.fired and isinstance(e, Exception) and not _unfound(e)
        try:
            if watch is not None:
                watch.stop()
        finally:
            session.close()
        if cut and not isinstance(e, Overdue):
            raise Overdue(watch.seconds) from None
        raise

    def close() -> None:
        try:
            if watch is not None:
                watch.stop()
            response.close()
        finally:
            session.close()

    return Reply(response.status_code, dict(response.headers), _pieces(response.raw, piece, watch), close)


_OWN = requests_transport  # the library's own transport, which an Endpoint gives each ask's deadline (Endpoint._send)


# -- how far a download is ---------------------------------------------------------------------------------------------
class Progress:
    """How far a download is, said to a job's log (`log(line)`; None: said to no one) every `every` seconds at most:
    "name: 12.3 MB of 60.1 MB (20%)", or "name: 12.3 MB so far" when its whole size is not known. The first word of
    something new (another `what`) is said at once. A log that fails is let be: the work goes on without its panel.
    """

    def __init__(self, log, every: float = 2.0, clock: Callable[[], float] = time.monotonic):
        self._tell = _sayer(log)  # to no one when there is none; a log that fails is let be
        self._every, self._clock = float(every), clock
        self._lock = threading.Lock()
        self._said: float | None = None  # when it last spoke
        self._what: str | None = None  # of what

    def say(self, done, total=None, what: str = "") -> None:
        """`done` bytes of `total` (None or 0: not known) of `what`, unless it spoke of it less than `every` seconds
        ago."""
        now = self._clock()
        with self._lock:
            if self._said is not None and what == self._what and now - self._said < self._every:
                return
            self._said, self._what = now, what
        size = int(total) if total else 0
        if size > 0:
            words = f"{size_words(done)} of {size_words(size)} ({min(100, max(0, int(done)) * 100 // size)}%)"
        else:
            words = f"{size_words(done)} so far"
        self._tell(f"{what}: {words}" if what else words)

    def end(self, words: str) -> None:
        """The last word on it, said whenever it comes; what is said next is said at once."""
        with self._lock:
            self._said = self._what = None
        self._tell(words)
