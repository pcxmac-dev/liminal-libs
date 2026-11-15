"""The apps linked together (the user, 2026-11-04: "objects that I can bind together, like the login
app and the integrator app ... I can still link to an existing integrator and get its functions tied
into the chart app ... seamlessly like it is local"; 2026-11-14: "the idea is for an app like charts to be
able to 'link' to an app like platform or an app like integrator or both"; "linking vs including the
objects, is so that parts of the code can be executed remotely, and connected through the icon bridge"):
what a super app does with another app's URL, on this machine or another. Reach it (`Binding.reachable`),
read its tray for the icons on the far right (`tray_of`), and pass its pages' requests on (`forward`:
the super app's front proxies `/<name>/...` to the linked app's `/...`, the answers and the cookies back,
a cookie's path narrowed to the prefix). A linked app is never started from here: one that does not
answer is said to be not running (1.52.0; the user, 2026-11-14: "don't start any of the applications in
the background"; until then `start_app` ran its module detached). The login an app inherits is not
linked but included, an object in that app (apps.app.App.login_object)."""
from __future__ import annotations

import http.client
import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from urllib.parse import urlsplit

from .. import web
from .login import SESSION_HEADER

# The request headers passed on to a bound app: who the page is (the charts profile cookie and
# header, the login session), that it is the app's own page (the write header), what it accepts. Not
# where it comes from (Origin, Sec-Fetch-Site: the front checked them; the bound app takes a request
# saying neither)
FORWARDED = ("Cookie", "Content-Type", "Accept", "Last-Event-ID", web.WRITE_HEADER, web.PROFILE_HEADER, SESSION_HEADER)
PASSED_BACK = ("Content-Type", "Cache-Control", "X-Content-Type-Options")
START_SECONDS = 30.0  # how long wait_for waits for an app to answer, at the most


LOOPBACK = ("127.0.0.1", "localhost", "::1")
REACH_SECONDS = 2.0  # how long a linked app on another machine is given to answer
CONNECT_SECONDS = 10.0  # how long a request passed on waits for the connection (not for the answer)


@dataclass(frozen=True)
class Binding:
    """A linked app: its name (the prefix the super app serves it under: `/platform/...`) and its URL, on
    this machine or another. `module` is kept for the callers of 1.9-1.51; nothing is started from it."""

    name: str
    url: str
    module: str = ""

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or "127.0.0.1"

    @property
    def port(self) -> int:
        parts = urlsplit(self.url)
        return parts.port or (443 if parts.scheme == "https" else 80)

    @property
    def prefix(self) -> str:
        return f"/{self.name}"

    def reachable(self, timeout: float = REACH_SECONDS) -> bool:
        """Whether something answers at its address: this machine's port (web.listening), or another
        machine's, reached over the network (1.53.0: a link may be remote, the user, 2026-11-14: "so that
        parts of the code can be executed remotely"; until then only this machine's port was asked)."""
        if self.host in LOOPBACK:
            return web.listening(self.port)
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout):
                return True
        except OSError:
            return False

    def tray(self) -> dict | None:
        return tray_of(self.url)


def tray_of(url: str, timeout: float = 5.0) -> dict | None:
    """A bound app's tray (`GET /api/tray`), read by the front itself (no page's origin travels);
    None when nothing answers or the answer is not a tray."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url.rstrip("/") + "/api/tray", headers={"Accept": "application/json"}),
                         timeout=timeout) as resp:
            tray = json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None
    return tray if isinstance(tray, dict) and "items" in tray else None


def wait_for(port: int, seconds: float = START_SECONDS, step: float = 0.25) -> bool:
    """Whether something answers at `port` within `seconds`."""
    end = time.monotonic() + seconds
    while True:
        if web.listening(port):
            return True
        if time.monotonic() >= end:
            return False
        time.sleep(step)


def forward(handler, method: str, url: str, path: str, *, cookie_path: str | None = None,
            drop_cookies: tuple[str, ...] = (), keep_cookies: tuple[str, ...] = (),
            unavailable: str = "the app does not answer; ask again shortly") -> None:
    """The request passed on to the bound app at `url` as `path` (its body read here, within
    MAX_BODY), its answer passed back as it comes (an event stream chunk by chunk), its cookies too
    (their path narrowed to `cookie_path` when given: the prefix the super app serves the bound app
    under). `drop_cookies`: the names (by prefix) of the browser's cookies that are not this app's
    business and stay here (the login app's session, kept from the integrator). `keep_cookies`
    (1.53.0): when given, only the cookies whose names begin so travel (a linked app's own: nothing
    else of the browser's reaches an app that may be on another machine). An https address is reached
    over TLS, its certificate checked."""
    raw_length = handler.headers.get("Content-Length") or "0"
    length = int(raw_length) if raw_length.isdecimal() else -1
    if length < 0:
        return web.send_json(handler, {"error": "bad Content-Length"}, HTTPStatus.BAD_REQUEST)
    if length > web.MAX_BODY:
        return web.send_json(handler, {"error": "request too large"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
    body = handler.rfile.read(length) if length else None
    target = urlsplit(url)
    headers = {name: value for name in FORWARDED if (value := handler.headers.get(name)) is not None}
    if (drop_cookies or keep_cookies) and headers.get("Cookie"):
        kept = []
        for c in (c.strip() for c in headers["Cookie"].split(";")):
            name = c.partition("=")[0]
            if not c or (drop_cookies and name.startswith(drop_cookies)) or (keep_cookies and not name.startswith(keep_cookies)):
                continue
            kept.append(c)
        if kept:
            headers["Cookie"] = "; ".join(kept)
        else:
            del headers["Cookie"]
    headers["Host"] = target.netloc
    connection = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    conn = connection(target.hostname, target.port, timeout=CONNECT_SECONDS)
    try:
        conn.connect()  # within CONNECT_SECONDS (another machine that never answers is not waited on for good)
        conn.sock.settimeout(None)  # then as long as the answer takes: an event stream stays open
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
    except OSError:
        conn.close()
        return web.send_json(handler, {"error": unavailable}, HTTPStatus.SERVICE_UNAVAILABLE)
    try:
        ctype = resp.getheader("Content-Type") or "application/octet-stream"
        passed = [(name, value) for name in PASSED_BACK if (value := resp.getheader(name)) is not None]
        passed += [("Set-Cookie", _repath(c, cookie_path)) for c in resp.msg.get_all("Set-Cookie") or []]
        if ctype.startswith("text/event-stream"):
            handler.send_response(resp.status)
            for name, value in passed:
                handler.send_header(name, value)
            handler.end_headers()
            try:
                while chunk := resp.read1(65536):
                    handler.wfile.write(chunk)
                    handler.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass  # the page went away
            return
        data = resp.read()
        web.send(handler, resp.status, data, ctype, passed)
    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
        pass  # the page went away
    finally:
        conn.close()


def _repath(cookie: str, prefix: str | None) -> str:
    """A bound app's cookie with its path under the prefix it is served at (`Path=/` -> `Path=/login`)."""
    if not prefix:
        return cookie
    parts = [p.strip() for p in cookie.split(";")]
    out = [p for p in parts if not p.lower().startswith("path=")]
    out.insert(1, f"Path={prefix}")
    return "; ".join(out)
