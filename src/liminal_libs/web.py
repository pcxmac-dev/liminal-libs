"""What every app's server shares (the user, 2026-11-01: "make sure that the library calls
contribute to code reuse"; 2026-11-04: "the library basically facilitates the interprocess
communication, the way the apps can bind to each other, or interoperate"): the chart front, the
integrator's page and data API, the login app and every app to come answer only requests addressed
to this machine from their own pages, serve their page's files from their own folder and the
library's (ui.STATIC: the icons, the theme), and send bodies the same way. Moved here from the
charts app's gui/web.py (liminal-libs 1.7.0); the apps' frame on top of it is apps/app.py.

The server class is here too (`Server`): the standard library's, but holding its port alone on
Windows as well, where the standard one lets a second server share it.

Nothing here opens a database."""
from __future__ import annotations

import ipaddress
import json
import mimetypes
import os
import socket
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path

MAX_BODY = 5 * 1024 * 1024
WRITE_HEADER = "X-Liminal-Charts"  # every write carries it: no other site's page can send it without a preflight
PROFILE_COOKIE = "mc_profile"  # the chart app's profile this browser signed in as (profiles keep things apart)
# The profile a page loaded as, sent with its writes: a tab left open as one profile while another
# tab signed in as a second (or out) wrote its lists over the second's (the cookie names the newest)
PROFILE_HEADER = "X-Liminal-Profile"
# A front (a reverse proxy beside an app, its TLS end: liminal-login's docker/Caddyfile) sets it on every request it hands
# on, over whatever a client sent. It connects from this machine too, so its mark tells the requests of anyone who
# reaches the front from those of a program here (from_this_machine). Never set by the apps' own fronts (apps.binding),
# which pass on a mark they were handed and add none
FRONT_HEADER = "X-Liminal-Front"
# A front's word on where the browser was and how it came: read by peer and forwarded_https, and passed on by the apps'
# own fronts as they came (apps.binding.FORWARDED). Caddy writes both unasked, and no page or program of Liminal's sends
# either, so a request that carries one was handed on by something, marked or not (from_this_machine)
FRONT_SAYS = ("X-Forwarded-For", "X-Forwarded-Proto")
LOCAL_HOSTS = ("127.0.0.1", "localhost")
ALWAYS = (("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"))
NO_BODY = (HTTPStatus.ACCEPTED, HTTPStatus.NO_CONTENT)  # send_json sends these with no body when their data is None


def listening(port: int) -> bool:
    """Whether something answers on 127.0.0.1:`port` already. The standard HTTPServer's own bind
    cannot tell on Windows: it binds with SO_REUSEADDR, which there lets a second server take a port
    in use (the fetcher's page took the integrator's front's port and the front proxied to itself).
    `Server` binds its port alone, so there its bind is refused too. This check stays: it is asked
    before the bind, and the app says in words that the port is taken."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _windows() -> bool:
    """Whether this is Windows. Asked each time a server binds, so a test can stand in for the other system."""
    return os.name == "nt"


class Server(ThreadingHTTPServer):
    """The server an app answers on: the standard library's ThreadingHTTPServer, but its port is its own.

    The standard one sets SO_REUSEADDR on every system. On Windows that lets a later socket bind a port an app already
    serves, and Windows then hands each connection to either of them. So on Windows this one sets SO_EXCLUSIVEADDRUSE
    before its bind, and not SO_REUSEADDR: while it is open, every other bind of its port is refused.

    Elsewhere it keeps SO_REUSEADDR. There it never lets two servers share a port someone listens on, and a restart
    needs it: these servers close each connection first (HTTP/1.0), so the last ones wait in TIME_WAIT on the app's
    port, and a restart within a minute would be refused ("address already in use"). It never sets SO_REUSEPORT, which
    would let a second server share the port on Linux.

    Microsoft documents one cost on Windows: a port bound this way may not be bound again at once while a connection
    the closed server accepted is still winding down. tests/test_web.py says what was seen when it was tried."""

    allow_reuse_address = not _windows()  # this system's; server_bind decides again from _windows(), when it binds
    allow_reuse_port = False

    def server_bind(self) -> None:
        """The socket's options, then the standard bind: on Windows SO_EXCLUSIVEADDRUSE, set before the bind as
        Windows asks; elsewhere SO_REUSEADDR, which the standard bind sets from allow_reuse_address."""
        windows = _windows()
        self.allow_reuse_address = not windows
        if windows:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def _head(handler, status: int, framing, headers) -> None:
    """An answer's status and headers: `framing` first (the body's type and length, as pairs), then no
    caching and no sniffing unless `headers` (pairs, or a dict) say otherwise, then whatever they carry."""
    given = list(headers.items()) if isinstance(headers, dict) else list(headers or [])
    names = {name.lower() for name, _ in given}
    handler.send_response(status)
    for name, value in framing:
        handler.send_header(name, value)
    for name, value in ALWAYS:
        if name.lower() not in names:
            handler.send_header(name, value)
    for name, value in given:
        handler.send_header(name, value)
    handler.end_headers()


def send(handler, status: int, body: bytes, ctype: str, headers=None) -> None:
    """An answer with `body`: its type and length, no caching and no sniffing unless `headers`
    (pairs, or a dict) say otherwise, and whatever else they carry (a cookie, say)."""
    _head(handler, status, (("Content-Type", ctype), ("Content-Length", str(len(body)))), headers)
    handler.wfile.write(body)


def send_json(handler, data, status: int = 200, headers=None) -> None:
    """An answer in JSON. A 202 or a 204 whose data is None has no body at all, and no Content-Type. The 202 says
    Content-Length 0; the 204 says no length, as RFC 9110 (8.6) asks. That is MCP's "202 Accepted with no body".
    Every other answer is JSON, a None among them ("null")."""
    if data is None and status in NO_BODY:
        framing = () if status == HTTPStatus.NO_CONTENT else (("Content-Length", "0"),)
        return _head(handler, status, framing, headers)
    send(handler, status, json.dumps(data, allow_nan=False).encode(), "application/json", headers)


def drain(handler) -> None:
    """A request's body read and dropped, before an answer that does not use it (a refusal). Answered and closed with
    its body unread, or still arriving, a connection is reset on Windows, and the client reads no answer at all where
    a 403 was sent (1.61.1: seen as a ConnectionAbortedError in place of the refusal, on a busy machine). At most
    MAX_BODY is read: a larger body is not taken in. Called before anything else has read the body, and once."""
    raw = handler.headers.get("Content-Length") or ""
    if raw.isdecimal() and 0 < int(raw) <= MAX_BODY:
        try:
            handler.rfile.read(int(raw))
        except (OSError, ValueError):
            pass  # the client went away, or sent less than it said: the answer is sent all the same


def refuse(handler, status: int, body: bytes, ctype: str = "text/plain") -> None:
    """A refusal of a request whose body is not used: the body dropped (drain), then the answer."""
    drain(handler)
    send(handler, status, body, ctype)


def local_only(handler) -> bool:
    """Only requests addressed to this machine are answered (blocks DNS rebinding from web pages)."""
    host = (handler.headers.get("Host") or "").split(":")[0]
    if host not in LOCAL_HOSTS:
        refuse(handler, HTTPStatus.FORBIDDEN, b"forbidden")
        return False
    return True


def from_this_app(handler) -> bool:
    """Whether an /api/ request comes from this app's own pages (or the address bar, or a program on
    this machine). A browser says where a request comes from (Sec-Fetch-Site) and, for most, the
    page's origin (Origin); a GET needs no header, so another site's page could otherwise reach the
    routes that start work or write (an <img> asking /api/inventory for one ticker after another,
    each a thread; /api/trading filling paper orders). A request saying neither (not from a browser,
    or one too old to say) passes: writes still need WRITE_HEADER, which no other page can send."""
    site = handler.headers.get("Sec-Fetch-Site")
    origin = handler.headers.get("Origin")
    if (site is None or site in ("same-origin", "none")) \
            and (origin is None or origin == f"http://{handler.headers.get('Host')}"):
        return True
    refuse(handler, HTTPStatus.FORBIDDEN, b"forbidden: not from this app's pages")
    return False


def loopback(address) -> bool:
    """Whether an address is this machine's own: 127.0.0.0/8, ::1, or an IPv4 one written as IPv6 (::ffff:127.0.0.1)."""
    try:
        ip = ipaddress.ip_address(str(address or "").split("%", 1)[0])
    except ValueError:
        return False
    return (getattr(ip, "ipv4_mapped", None) or ip).is_loopback


def handed_on(handler) -> bool:
    """Whether a front handed the request on: it carries the front's mark (FRONT_HEADER), whatever its value, empty too."""
    return handler.headers.get(FRONT_HEADER) is not None


def from_this_machine(handler) -> bool:
    """Whether a request was sent by a program on this machine itself: from a loopback address, and not handed on by a
    front. A front beside an app connects from loopback as well (Caddy in the app's own network, docker/), so what it
    hands on, the requests of anyone who reaches it, is told apart by its mark (FRONT_HEADER). A net under the mark: a
    request that carries a front's word on where the browser was or how it came (FRONT_SAYS), whatever it says, empty
    too, is not from this machine either, so a front set up without the mark that writes them, as Caddy does unasked,
    still lets nobody be someone at the machine. The mark stays what a front must set: nginx's plain proxy_pass and a
    TCP forward write neither, and what they hand on reads as a program's here. What only someone at the machine may do
    asks this: a sign-in without a password, an account made without a session (liminal-login). A request with no peer
    known (a stand-in handler) is not from this machine."""
    address = getattr(handler, "client_address", None) or ("",)
    if handed_on(handler) or any(handler.headers.get(name) is not None for name in FRONT_SAYS):
        return False
    return loopback(address[0])


def header_lines(handler, name: str) -> list[str]:
    """Every line a request carries of one header, in the order sent. `headers.get` gives one of several and does not
    promise which, and several read as one list (RFC 9110, 5.3): a front may add its own line under a client's where
    another writes one line (X-Forwarded-For: HAProxy's forwardfor). A stand-in's plain dict of headers has one."""
    every = getattr(handler.headers, "get_all", None)
    found = every(name) if every is not None else [handler.headers.get(name)]
    return [str(value) for value in found or () if value is not None]


def peer(handler) -> str:
    """Where a request came from, as far as an app can tell: the address it was sent from; for one a front handed on,
    the address the front says it was reached from (the last of X-Forwarded-For, of its last line when it has several:
    the one the front writes itself, whatever a client sent before it), else the front's own. What a sign-in's throttle
    counts by (liminal-login)."""
    address = getattr(handler, "client_address", None) or ("",)
    if handed_on(handler):
        said = ",".join(header_lines(handler, "X-Forwarded-For")).rsplit(",", 1)[-1].strip()
        if said:
            return said[:64]
    return str(address[0])


def forwarded_https(handler) -> bool:
    """Whether the browser reached a front over https, as the front says (X-Forwarded-Proto: the scheme the first of
    them was reached by, which Caddy writes itself over whatever a client sent). A cookie set then is Secure, so that the
    browser sends it over https alone; a program on this machine reaches an app over http and says no such thing."""
    said = (handler.headers.get("X-Forwarded-Proto") or "").split(",", 1)[0].strip().lower()
    return said == "https"


def cookie(handler, name: str) -> str | None:
    """The value of the request's cookie `name`, or None."""
    for part in (handler.headers.get("Cookie") or "").split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value
    return None


def profile_cookie(handler) -> int | None:
    """The chart app's profile this browser signed in as, by its cookie: decimal digits only, of a
    size SQLite holds ('²' passed isdigit and failed int). Whether it still exists is the data API's
    to check."""
    value = cookie(handler, PROFILE_COOKIE)
    if value is not None and value.isdecimal() and len(value) <= 9:
        return int(value)
    return None


def static_target(rel: str, dirs) -> Path | None:
    """The file `static_file` serves for `rel`: in the first of `dirs` holding it, as this machine's file system finds
    it (on Windows another case, a trailing dot or a stream's name finds the same file), never one outside them; None
    for none (1.46.1)."""
    for folder in dirs:
        if folder is None:
            continue
        root = Path(folder).resolve()
        target = (root / rel).resolve()
        if root in target.parents and target.is_file():
            return target
    return None


def static_file(handler, rel: str, dirs) -> None:
    """One of a page's files (index.html, a script, a stylesheet, a vendored library) from the first
    of `dirs` holding it (an app's own folder first, then the library's ui.STATIC: icons.js,
    liminal.css), never a file outside them."""
    target = static_target(rel, dirs)
    if target is None:
        return send(handler, HTTPStatus.NOT_FOUND, b"not found", "text/plain")
    ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    if ctype.startswith("text/") or ctype == "application/javascript":
        ctype += "; charset=utf-8"
    send(handler, HTTPStatus.OK, target.read_bytes(), ctype)
