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
- Asked only when a caller asks, with a short wait (LOOK_S): nothing is polled, and nothing is sent a second time.
  A look that failed is the next look's to repeat, and a write that got no answer may have been done.

`seen` is what the last ask came to (when, its status, how long it took, its error's words): what a plugin's
api_facts() says, never an ask of its own. `Progress` says how far a download is, a line every two seconds at most.
"""
from __future__ import annotations

import ipaddress
import json as jsonlib
import re
import socket
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
        so, and the caller knows by the last line it got whether the work was done. `cancel()`: looked at before
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
                reply = self._send(method, url, body, wait, True, "*/*")
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

    def _send(self, method: str, url: str, body: bytes | None, wait: float, stream: bool, accept: str = "") -> Reply:
        headers = _merged(self._headers, {"Accept": self._accept or accept or "application/json"},
                          {"Content-Type": "application/json"} if body is not None else {},
                          {"Authorization": f"Bearer {self._key}"} if self._key else {})
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
                reply = self._send(method, url, body, wait, False, accept)
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
        at after every piece, and a transport hands on a piece for every receive)."""
        status, headers = int(reply.status), _lower(reply.headers)
        self._as_asked(headers, lead, status)
        said = _count(headers.get("content-length"))
        if said is not None and said > self._most:
            raise self._failed(lead, f"its answer is {size_words(said)}, and {size_words(self._most)} is the most "
                               "read of one: not read", status)
        ends = started + 2 * wait
        got, pieces = 0, []
        for piece in reply.chunks:
            got += len(piece)
            if got > self._most:
                raise self._failed(lead, f"its answer is longer than {size_words(self._most)}: not read", status)
            if self._clock() > ends:
                raise self._failed(lead, f"its answer was not whole after {2 * wait:g} s: not read")
            pieces.append(piece)
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


def trouble(e: BaseException, at: str, timeout: float | None = None, secrets: Iterable[str] = ()) -> str:
    """Why `at` (a host and port) gave no answer, in words: nothing listens there, none in time, a name this machine
    does not find, a certificate it does not trust; else the error's own name and words, `secrets` taken out of
    them before they are cut."""
    chain = _chain(e)
    names = {type(x).__name__ for x in chain}
    if any(isinstance(x, ConnectionRefusedError) for x in chain):
        return f"nothing listens at {at}"
    if any(isinstance(x, TimeoutError) or "Timeout" in type(x).__name__ for x in chain):
        return f"no answer from {at} within {timeout:g} s" if timeout else f"no answer from {at} in time"
    if any(isinstance(x, socket.gaierror) for x in chain) or "NameResolutionError" in names:
        return f"{at} is no name this machine finds"
    if "SSLCertVerificationError" in names:
        return f"the certificate {at} shows is not one this machine trusts"
    words = " ".join(scrub(str(e), tuple(secrets)).split())
    return f"no answer from {at}: {type(e).__name__}: {words}"[:300]


# -- the transport -----------------------------------------------------------------------------------------------------
def _session():
    """A `requests` session that takes nothing from the environment (as rest.py's: no ~/.netrc credentials added to
    a request, no proxy and no CA bundle from its variables) and adds no header of its own (not the package's name
    and version, not its wish for a compressed body): a request goes as it was made, straight to its host."""
    import requests

    session = requests.Session()
    session.trust_env = False
    session.headers.clear()
    return session


def _pieces(raw, piece: int) -> Iterator[bytes]:
    """An answer's body as it is on the wire (nothing unpacked: nothing packed was asked for), handed on as it comes:
    each piece what one receive gave, `piece` bytes at most (urllib3's read1, from its version 2 on; before it, reads
    of SMALL bytes at most). Whoever reads it looks at its bounds, its deadline and its cancel after every receive,
    never only once a whole piece of a slow sender has come; a read that gets nothing ends at the socket's own
    timeout."""
    one = getattr(raw, "read1", None)
    if callable(one):
        while True:
            data = one(piece, decode_content=False)
            if not data:
                return
            yield data
    else:
        yield from raw.stream(min(piece, SMALL), decode_content=False)


def requests_transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float,
                       stream: bool, piece: int = PIECE) -> Reply:
    """The transport when a caller gives none: one request through the `requests` package, its answer handed back
    with the body not read yet. No redirect is followed, and a redirect's body is never read: the request is given
    to the session's adapter itself, because Session.request, even told to follow nothing, reads a redirect's whole
    body, without a bound, to let its connection go. `timeout`: seconds each socket operation waits. `stream`: what
    the caller reads (a stream's lines, or an answer whole); the body is handed on as it comes either way, `piece`
    bytes at most at a time."""
    import requests

    session = _session()
    try:
        request = session.prepare_request(requests.Request(method, url, headers=dict(headers), data=body))
        response = session.get_adapter(url).send(request, stream=True, timeout=timeout, verify=True, cert=None,
                                                 proxies={})
    except BaseException:
        session.close()
        raise

    def close() -> None:
        try:
            response.close()
        finally:
            session.close()

    return Reply(response.status_code, dict(response.headers), _pieces(response.raw, piece), close)


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
