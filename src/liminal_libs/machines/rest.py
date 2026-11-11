"""A JSON REST API over HTTPS for a platform plugin (a cloud's: DigitalOcean, Linode, Vultr, EC2, Azure, Google Cloud):
the plugin names the address and how a request proves who sends it; this client sends, keeps what the answers said of
the API's limits, waits out a rate limit, and words every failure with the plugin's secrets taken out.

    api = RestClient("https://<the API's host>/v2", auth=bearer(token), secrets=(token,), error=vendor_words)
    api.get("/account")            # the answer's JSON
    api.post("/things", {"a": 1})  # a write: never sent twice on a timeout (it may have been done)
    for item in api.pages("/things", items="things", next_of=...):  # every page of a list

`transport(method, url, headers, body, timeout) -> (status, headers, body bytes)` is a test's stand-in; else the
`requests` package over HTTPS. Nothing here names a host: the plugins do (a cloud's address is its plugin's to know).

What the client learned of the API (`seen`: its rate limit and what is left of it, the last answer, how long it took, the
requests made) is what a plugin's api_facts() says (`facts()`), never a request of its own.
"""
from __future__ import annotations

import json as jsonlib
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlencode, urljoin, urlsplit

RETRY_CODES = frozenset({429, 500, 502, 503, 504})
LIMIT_PREFIXES = ("ratelimit", "x-ratelimit", "x-rate-limit", "x-ms-ratelimit", "retry-after")
WAIT_MOST_S = 30.0  # the longest a request waits for a rate limit before it gives up (the plugin tries again later)
TIMEOUT_S = 30.0
AGENT = "Liminal platform plugin"


class RestError(Exception):
    """A request that failed, in words (the plugin's secrets taken out): its HTTP status (0: none came back), the vendor's
    code for it, the request's id when the answer gave one, and how long the API asked to wait (a rate limit)."""

    def __init__(self, message: str, status: int = 0, code: str = "", request_id: str = "", retry_after: float | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.request_id = request_id
        self.retry_after = retry_after

    @property
    def refused(self) -> bool:
        """The API refused who asked (401, 403): a token wrong, expired or without the scope."""
        return self.status in (401, 403)


@dataclass
class Answer:
    """An answer: its status, its headers (lowercased names), its body and its JSON (None when it is none), how long it
    took."""

    status: int
    headers: dict[str, str]
    body: bytes
    seconds: float = 0.0
    data: object = None

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


@dataclass
class Seen:
    """What the answers said of the API: the requests made and failed, the last answer's status, when and how long, the
    rate limit's headers as last given (`limits`)."""

    requests: int = 0
    failed: int = 0
    last_status: int = 0
    last_at: float | None = None
    last_seconds: float = 0.0
    last_error: str = ""
    limits: dict[str, str] = field(default_factory=dict)


def bearer(token: str | Callable[[], str]) -> Callable[[str, str, dict, bytes], dict]:
    """The auth of an API taking a bearer token (`token`, or a function giving the current one: a token that expires)."""

    def auth(method: str, url: str, headers: dict, body: bytes) -> dict:
        value = str(token() if callable(token) else token).strip()  # a token pasted with its line break: sent without
        if any(c.isspace() for c in value):
            raise ValueError("the token holds a space or a line break: enter it again, alone")
        return {**headers, "Authorization": f"Bearer {value}"}

    return auth


class TokenSource:
    """A token that expires, kept until a minute before it does: `fetch()` -> (token, seconds it lasts), asked again only
    then (an OAuth client's: Azure's client credentials, Google's service account)."""

    def __init__(self, fetch: Callable[[], tuple[str, float]], clock: Callable[[], float] = time.time, early_s: float = 60.0):
        self._fetch = fetch
        self._clock = clock
        self._early = early_s
        self._lock = threading.Lock()
        self._token = ""
        self._until = 0.0

    def __call__(self) -> str:
        with self._lock:
            if not self._token or self._clock() >= self._until:
                token, lasts = self._fetch()
                self._token, self._until = token, self._clock() + max(0.0, float(lasts) - self._early)
            return self._token

    def forget(self) -> None:
        """The token dropped (refused: a 401): the next request asks for a new one."""
        with self._lock:
            self._token, self._until = "", 0.0


def scrub(text: str, secrets: Iterable[str]) -> str:
    """`text` with every secret (of four characters or more) taken out: each as given, without its surrounding spaces
    and line breaks, and each of its lines (a key pasted with a line break, or a key file's lines, said back in an
    error's quoting of a header, 1.49.2)."""
    parts: set[str] = set()
    for s in secrets:
        if not s:
            continue
        s = str(s)
        parts |= {s, s.strip(), *(line.strip() for line in s.splitlines())}
    for s in sorted({p for p in parts if len(p) >= 4}, key=len, reverse=True):
        text = text.replace(s, "•••")
    return text


def _requests_transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float):
    import requests

    resp = requests.request(method, url, headers=dict(headers), data=body, timeout=timeout, allow_redirects=False)
    return resp.status_code, dict(resp.headers), resp.content


class RestClient:
    """A JSON REST API at `base` (module docstring): `auth(method, url, headers, body) -> headers` signs or bears a
    request; `error(answer) -> (words, code)` reads the vendor's error body (else its "message" or "error"); `secrets` are
    taken out of every word it says. Thread safe: a plugin's background reading and its page's asks share one."""

    def __init__(self, base: str, *, auth: Callable | None = None, headers: Mapping[str, str] | None = None,
                 transport: Callable | None = None, timeout: float = TIMEOUT_S, secrets: Iterable[str] = (),
                 error: Callable[[Answer], tuple[str, str]] | None = None, retries: int = 2,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 wait_most: float = WAIT_MOST_S, on_refused: Callable[[], None] | None = None,
                 throttled: Callable[[Answer], bool] | None = None):
        if not base.startswith("https://"):
            raise ValueError(f"an API is asked over HTTPS, not at {base!r}")
        self.base = base.rstrip("/")
        self._auth = auth
        self._headers = {"Accept": "application/json", "User-Agent": AGENT, **(headers or {})}
        self._transport = transport or _requests_transport
        self._timeout = timeout
        self._secrets = tuple(secrets)
        self._error = error
        self._retries = max(0, int(retries))
        self._clock = clock
        self._sleep = sleep
        self._wait_most = wait_most
        self._on_refused = on_refused  # a 401's: the token is no good (a 403 is a right missing, the token kept)
        self._throttled = throttled  # an answer the vendor means as "slow down" though it is no 429 (1.49.1)
        self._lock = threading.Lock()
        self.seen = Seen()

    # -- sending --------------------------------------------------------------------------------------------------------
    def url(self, path: str, params: Mapping | None = None) -> str:
        """`path` under the base (an address given whole is kept: a list's next page), with `params` (None ones left out)."""
        url = path if path.startswith("https://") else f"{self.base}/{path.lstrip('/')}" if path else self.base
        query = {k: v for k, v in (params or {}).items() if v is not None}
        if query:
            url += ("&" if "?" in url else "?") + urlencode(query, doseq=True)
        return url

    def request(self, method: str, path: str, *, params: Mapping | None = None, json=None, form: Mapping | None = None,
                headers: Mapping[str, str] | None = None, ok: Iterable[int] = (200, 201, 202, 204),
                data: bytes | None = None) -> Answer:
        """One request; its answer when its status is one of `ok`, else a RestError in words. A 429 is waited out (its
        Retry-After, at most `wait_most`), any method; a 5xx or a broken connection tried again for a read (GET, HEAD)
        only: a write that may have been done is never sent twice. `data`: a body sent as it is (an XML document),
        its Content-Type in `headers`; one of `json`, `form` and `data` at most."""
        method = method.upper()
        url = self.url(path, params)
        if urlsplit(url).scheme != "https":
            raise RestError(f"not an HTTPS address: {scrub(url, self._secrets)}")
        if sum(x is not None for x in (json, form, data)) > 1:
            raise ValueError("a request has one body: json, form or data")
        body: bytes | None = None
        sent = dict(self._headers)
        if data is not None:
            body = bytes(data)
        elif json is not None:
            body = jsonlib.dumps(json, separators=(",", ":")).encode()
            sent["Content-Type"] = "application/json"
        elif form is not None:
            body = urlencode({k: v for k, v in form.items() if v is not None}).encode()
            sent["Content-Type"] = "application/x-www-form-urlencoded"
        sent.update(headers or {})
        reads = method in ("GET", "HEAD")
        attempt = 0
        while True:
            attempt += 1
            signed = self._auth(method, url, dict(sent), body or b"") if self._auth else sent
            started = time.monotonic()
            try:
                status, got, raw = self._transport(method, url, signed, body, self._timeout)
            except Exception as e:  # noqa: BLE001 - the connection's trouble, in words
                words = scrub(f"{type(e).__name__}: {e}", self._secrets)
                self._note(0, {}, time.monotonic() - started, words)
                if reads and attempt <= self._retries:
                    self._sleep(min(2.0 ** attempt, self._wait_most))
                    continue
                raise RestError(f"{method} {self._where(url)}: {words}") from None
            answer = Answer(int(status), {str(k).lower(): str(v) for k, v in (got or {}).items()}, raw or b"",
                            time.monotonic() - started)
            answer.data = _json_of(answer)
            if answer.status in set(ok):
                self._note(answer.status, answer.headers, answer.seconds, "")
                return answer
            words, code = self._words(answer)
            self._note(answer.status, answer.headers, answer.seconds, words)
            wait = _retry_after(answer, self._clock())
            if answer.status == 401 and self._on_refused:
                self._on_refused()
            slow = answer.status == 429 or bool(self._throttled and _asks(self._throttled, answer))
            if (answer.status in RETRY_CODES or slow) and attempt <= self._retries and (slow or reads):
                delay = wait if wait is not None else min(2.0 ** attempt, self._wait_most)
                if delay <= self._wait_most:
                    self._sleep(max(0.0, delay))
                    continue
            raise RestError(f"{method} {self._where(url)}: HTTP {answer.status}: {words}", answer.status, code,
                            _request_id(answer), wait)

    def get(self, path: str, params: Mapping | None = None):
        return self.request("GET", path, params=params).data

    def post(self, path: str, json=None, params: Mapping | None = None, form: Mapping | None = None):
        return self.request("POST", path, params=params, json=json, form=form).data

    def put(self, path: str, json=None, params: Mapping | None = None):
        return self.request("PUT", path, params=params, json=json).data

    def patch(self, path: str, json=None, params: Mapping | None = None):
        return self.request("PATCH", path, params=params, json=json).data

    def delete(self, path: str, params: Mapping | None = None, json=None):
        return self.request("DELETE", path, params=params, json=json).data

    def pages(self, path: str, params: Mapping | None = None, *, items: str | Callable[[object], list],
              next_of: Callable[[object, dict], tuple[str, dict] | None], most: int = 50,
              headers: Mapping[str, str] | None = None) -> Iterator:
        """Every item of a list across its pages: `items` names the answer's list (or takes it out), `next_of(data,
        params)` gives the next page's (path, params) or None at the last; at most `most` pages are asked;
        `headers` go with each (a filter header: Linode's X-Filter)."""
        params = dict(params or {})
        for _ in range(max(1, most)):
            data = self.request("GET", path, params=params, headers=headers).data
            found = items(data) if callable(items) else (data or {}).get(items) if isinstance(data, Mapping) else None
            yield from (found or [])
            nxt = next_of(data, params)
            if not nxt:
                return
            path, params = nxt

    # -- what it learned ------------------------------------------------------------------------------------------------
    def _note(self, status: int, headers: Mapping[str, str], seconds: float, error: str) -> None:
        limits = {k: v for k, v in headers.items() if k.startswith(LIMIT_PREFIXES)}
        with self._lock:
            s = self.seen
            s.requests += 1
            s.failed += 0 if not error else 1
            s.last_status, s.last_at, s.last_seconds, s.last_error = status, self._clock(), seconds, error
            if limits:  # merged: an API giving its reads' and its writes' limits on different answers keeps both
                s.limits.update(limits)

    def facts(self, labels: Mapping[str, str] | None = None) -> dict[str, str]:
        """What the answers said, in words (a plugin's api_facts): the requests made, the last answer, and the rate
        limit's headers named by `labels` ({header: label}; every limit header as is when None)."""
        with self._lock:
            src = self.seen
            s = Seen(src.requests, src.failed, src.last_status, src.last_at, src.last_seconds, src.last_error, dict(src.limits))
        out: dict[str, str] = {}
        if not s.requests:
            return {"Requests": "none yet"}
        out["Requests"] = f"{s.requests:,} made" + (f", {s.failed:,} failed" if s.failed else "")
        when = time.strftime("%b %d %H:%M:%S", time.localtime(s.last_at)) if s.last_at else ""
        out["Last answer"] = (f"HTTP {s.last_status}" if s.last_status else "none (no connection)") + \
            (f" in {s.last_seconds * 1000:.0f} ms" if s.last_status else "") + (f", {when}" if when else "")
        if s.last_error:
            out["Last trouble"] = s.last_error[:200]
        for header, value in s.limits.items():  # as given (clock_of says a reset's epoch as a clock time)
            if labels is None:
                out[header] = value
            elif header in labels:
                out[labels[header]] = value
        return out

    def _where(self, url: str) -> str:
        parts = urlsplit(url)
        return scrub(parts.path or "/", self._secrets)

    def _words(self, answer: Answer) -> tuple[str, str]:
        words, code = "", ""
        if self._error is not None:
            try:
                words, code = self._error(answer)
            except Exception:  # noqa: BLE001 - an error body the vendor's reader could not read: the generic one
                words, code = "", ""
        if not words:
            data = answer.data
            if isinstance(data, Mapping):
                for key in ("message", "error_description", "error", "detail", "title"):
                    value = data.get(key)
                    if isinstance(value, Mapping):
                        value = value.get("message") or value.get("code")
                    if isinstance(value, str) and value.strip():
                        words = value.strip()
                        break
                code = code or str(data.get("id") or data.get("code") or "")
            if not words:
                words = answer.body[:200].decode("utf-8", "replace").strip() or "no words came back"
        return scrub(words, self._secrets)[:400], scrub(code, self._secrets)


def _json_of(answer: Answer):
    if not answer.body:
        return None
    kind = answer.header("content-type")
    if "json" not in kind and answer.body.lstrip()[:1] not in (b"{", b"["):
        return None
    try:
        return jsonlib.loads(answer.body)
    except ValueError:
        return None


def _asks(throttled: Callable[[Answer], bool], answer: Answer) -> bool:
    try:
        return bool(throttled(answer))
    except Exception:  # noqa: BLE001 - a reader that cannot tell: not taken as a slow down
        return False


def clock_of(header: str, value: str) -> str:
    """A reset header's epoch time as this machine's clock time (the epoch kept beside it); any other value as given."""
    if "reset" not in header:
        return value
    try:
        at = float(value)
    except ValueError:
        return value
    return f"{time.strftime('%H:%M:%S', time.localtime(at))} ({value})" if at > 1e9 else value


def _retry_after(answer: Answer, now: float) -> float | None:
    """The seconds the API asked to wait: Retry-After (seconds or an HTTP date), else the longest of a vendor's own
    `...-retry-after` headers (Azure Cost Management's), else a reset time in epoch seconds."""
    value = answer.header("retry-after")
    if value:
        try:
            return max(0.0, float(value))
        except ValueError:
            from email.utils import parsedate_to_datetime

            try:
                return max(0.0, parsedate_to_datetime(value).timestamp() - now)
            except (TypeError, ValueError):
                pass
    own = []
    for name, text in answer.headers.items():
        if name.endswith("-retry-after"):
            try:
                own.append(float(text))
            except ValueError:
                pass
    if own:
        return max(0.0, max(own))
    if answer.status == 429:
        for name in ("ratelimit-reset", "x-ratelimit-reset"):
            reset = answer.header(name)
            try:
                at = float(reset)
            except ValueError:
                continue
            return max(0.0, at - now) if at > 1e9 else at  # an epoch time, or seconds from now
    return None


def _request_id(answer: Answer) -> str:
    for name in ("x-request-id", "x-amzn-requestid", "x-amz-request-id", "x-ms-request-id", "x-goog-request-id",
                 "request-id"):
        if answer.header(name):
            return answer.header(name)
    data = answer.data
    return str(data.get("request_id") or "") if isinstance(data, Mapping) else ""


def joined(base: str, path: str) -> str:
    """`path` joined to an address the way a browser would (a list's relative next link)."""
    return urljoin(base, path)
