"""A request a front handed on, told from one a program on this machine sent (liminal_libs.web; LOG-C1, 2026-11-23: the
Docker login let anyone who reached its front in without a password, since the front connects from 127.0.0.1 too).

- from_this_machine: a loopback peer, and no front's mark (X-Liminal-Front, whatever its value, empty too); a peer
  elsewhere, or none known, is not this machine. Nor is a request that carries a front's word on where the browser was
  or how it came (X-Forwarded-For, X-Forwarded-Proto) with no mark: the net under the mark, for a front set up
  without it (the review of LOG-C1's fix, 2026-11-25).
- peer: the socket's address; for a request a front handed on, the address the front says (the last X-Forwarded-For,
  of its last line when the front added its own under a client's).
- forwarded_https: the browser reached the front over https (X-Forwarded-Proto), so a cookie set then may be Secure.
- An app's front (apps.binding.forward) passes a mark it was handed on, with the front's word on where the browser was
  (every line of it) and how it came, and adds none of its own.
- A login an app holds (apps.serve_object) is asked with the request's own peer and mark.

The helpers are asked of stand-in handlers (their peer and headers, nothing else); the real ones run on 127.0.0.1,
port 0 (a free one), in threads, as the frame's tests run theirs. No test starts a process or uses an app's port."""
from __future__ import annotations

import json
import threading
from http.client import HTTPConnection, HTTPMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from liminal_libs import web
from liminal_libs.apps import FORWARDED, App, forward


def _handler(peer="127.0.0.1", headers=()):
    """A request as the helpers see it: its peer (client_address) and its headers, read as the server reads them."""
    message = HTTPMessage()
    for name, value in headers:
        message[name] = value
    return SimpleNamespace(client_address=(peer, 50123) if peer is not None else None, headers=message)


MARK = (web.FRONT_HEADER, "1")


@pytest.mark.parametrize("peer", ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1"])
def test_a_program_here_is_from_this_machine(peer):
    assert web.loopback(peer) and web.from_this_machine(_handler(peer))
    assert not web.handed_on(_handler(peer))


@pytest.mark.parametrize("value", ["1", "0", "", "no", "false"])
def test_whatever_the_mark_says_a_request_a_front_handed_on_is_not(value):
    """A front sets its mark on every request it hands on, over a client's; any mark at all, empty too, is a front's."""
    assert web.handed_on(_handler(headers=[(web.FRONT_HEADER, value)]))
    assert not web.from_this_machine(_handler(headers=[(web.FRONT_HEADER, value)]))
    assert not web.from_this_machine(_handler(headers=[("x-liminal-front", value)]))  # a header's name in any case


@pytest.mark.parametrize("name, value", [("X-Forwarded-For", "198.51.100.7"), ("X-Forwarded-For", "127.0.0.1"),
                                         ("X-Forwarded-For", ""), ("x-forwarded-for", "198.51.100.7"),
                                         ("X-Forwarded-Proto", "https"), ("X-Forwarded-Proto", "http"),
                                         ("X-Forwarded-Proto", ""), ("x-forwarded-proto", "https")])
def test_a_request_that_carries_a_fronts_word_is_not_from_this_machine_though_unmarked(name, value):
    """The net under the mark: a front set up without it, which says where the browser was or how it came as Caddy does
    unasked, hands nothing on as a program's here. Whatever the word says, empty too. It is not a marked front's
    (handed_on), and its word on the address is not believed (peer): the request is only not this machine's."""
    handler = _handler("127.0.0.1", [(name, value)])
    assert not web.from_this_machine(handler) and not web.handed_on(handler)
    assert web.peer(handler) == "127.0.0.1"
    # what it goes by, an app's own front passes on as it came: the app behind reads the same
    assert name.lower() in {said.lower() for said in web.FRONT_SAYS} and set(web.FRONT_SAYS) <= set(FORWARDED)
    plain = SimpleNamespace(client_address=("127.0.0.1", 50123), headers={web.FRONT_SAYS[0]: value})  # a plain dict's
    assert not web.from_this_machine(plain)


@pytest.mark.parametrize("peer", ["192.168.1.20", "10.0.0.5", "100.64.1.2", "203.0.113.7", "::ffff:192.168.1.20",
                                  "2001:db8::1", "fe80::1%3", "", "not an address", None])
def test_a_peer_elsewhere_or_none_known_is_not_this_machine(peer):
    assert not web.from_this_machine(_handler(peer))
    assert not web.loopback(peer)


def test_the_peer_is_the_sockets_and_for_a_front_the_address_it_says():
    assert web.peer(_handler("127.0.0.1")) == "127.0.0.1"
    # a program here saying another address is not believed: only a front's word counts
    assert web.peer(_handler("127.0.0.1", [("X-Forwarded-For", "198.51.100.7")])) == "127.0.0.1"
    assert web.peer(_handler("127.0.0.1", [MARK, ("X-Forwarded-For", "198.51.100.7")])) == "198.51.100.7"
    # a chain: the last is what the front itself wrote (anything before it, a client may have sent)
    assert web.peer(_handler("127.0.0.1", [MARK, ("X-Forwarded-For", "10.9.9.9, 198.51.100.7")])) == "198.51.100.7"
    # the same when the front adds a line of its own under a client's (HAProxy's forwardfor): the last line's last
    two = [MARK, ("X-Forwarded-For", "10.9.9.9"), ("X-Forwarded-For", "10.8.8.8, 198.51.100.7")]
    assert web.header_lines(_handler(headers=two), "x-forwarded-for") == ["10.9.9.9", "10.8.8.8, 198.51.100.7"]
    assert web.peer(_handler("127.0.0.1", two)) == "198.51.100.7"
    # a front whose own line says nothing: its own address, never the line a client sent above it
    silent = [MARK, ("X-Forwarded-For", "10.9.9.9"), ("X-Forwarded-For", "")]
    assert web.peer(_handler("127.0.0.1", silent)) == "127.0.0.1"
    assert web.peer(_handler("127.0.0.1", [MARK])) == "127.0.0.1"  # a front that says nothing: its own
    assert len(web.peer(_handler("127.0.0.1", [MARK, ("X-Forwarded-For", "x" * 500)]))) == 64  # bounded
    assert web.peer(_handler(None)) == ""
    # a stand-in whose headers are a plain dict, as the apps' tests make them: the one line it has
    plain = SimpleNamespace(client_address=("127.0.0.1", 50123),
                            headers={web.FRONT_HEADER: "1", "X-Forwarded-For": "198.51.100.7"})
    assert web.header_lines(plain, "X-Forwarded-For") == ["198.51.100.7"] and web.header_lines(plain, "Cookie") == []
    assert web.peer(plain) == "198.51.100.7"


@pytest.mark.parametrize("said, https", [("https", True), ("HTTPS", True), (" https ", True), ("https, http", True),
                                         ("http", False), ("http, https", False), ("", False), (None, False)])
def test_the_front_says_whether_the_browser_came_over_https(said, https):
    headers = [("X-Forwarded-Proto", said)] if said is not None else []
    assert web.forwarded_https(_handler(headers=headers)) is https


class _Asks(BaseHTTPRequestHandler):
    """A real server's handler: says what the helpers make of the request it got."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        web.send_json(self, {"here": web.from_this_machine(self), "peer": web.peer(self), "https": web.forwarded_https(self),
                             "mark": self.headers.get(web.FRONT_HEADER), "for": self.headers.get("X-Forwarded-For"),
                             "proto": self.headers.get("X-Forwarded-Proto")})


def _serve(handler) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _get(port, path="/", headers=()):
    """A GET with its headers as given: a dict, or pairs when one header goes on several lines."""
    conn = HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.putrequest("GET", path)
        for name, value in (headers.items() if isinstance(headers, dict) else headers):
            conn.putheader(name, value)
        conn.endheaders()
        r = conn.getresponse()
        return r.status, json.loads(r.read())
    finally:
        conn.close()


def test_a_real_request_from_here_and_one_a_front_marked():
    server = _serve(_Asks)
    port = server.server_address[1]
    try:
        assert _get(port)[1] == {"here": True, "peer": "127.0.0.1", "https": False, "mark": None, "for": None, "proto": None}
        said = _get(port, headers={web.FRONT_HEADER: "1", "X-Forwarded-For": "198.51.100.7", "X-Forwarded-Proto": "https"})[1]
        assert (said["here"], said["peer"], said["https"]) == (False, "198.51.100.7", True)
        # X-Forwarded-For on two lines, as a front that adds its own under a client's sends it: the last line counts
        said = _get(port, headers=[MARK, ("X-Forwarded-For", "10.9.9.9"), ("X-Forwarded-For", "198.51.100.7")])[1]
        assert (said["here"], said["peer"]) == (False, "198.51.100.7")
        # no mark, but a front's word on where the browser was, or on how it came: not from here, its address its own
        said = _get(port, headers={"X-Forwarded-For": "198.51.100.7"})[1]
        assert (said["here"], said["peer"], said["mark"]) == (False, "127.0.0.1", None)
        said = _get(port, headers={"X-Forwarded-Proto": "https"})[1]
        assert (said["here"], said["peer"], said["https"]) == (False, "127.0.0.1", True)
    finally:
        server.shutdown()
        server.server_close()


def test_an_apps_front_passes_a_mark_on_as_it_came_and_adds_none():
    """A request a TLS front handed one app's front is not from this machine at the app behind it either; one from a page
    here still is (the charts front passing the platform's login on, say)."""
    upstream = _serve(_Asks)
    url = f"http://127.0.0.1:{upstream.server_address[1]}"

    class Front(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            forward(self, "GET", url, "/asked")

    front = _serve(Front)
    port = front.server_address[1]
    try:
        assert _get(port)[1] == {"here": True, "peer": "127.0.0.1", "https": False, "mark": None, "for": None, "proto": None}
        said = _get(port, headers={web.FRONT_HEADER: "1", "X-Forwarded-For": "198.51.100.7", "X-Forwarded-Proto": "https"})[1]
        assert said == {"here": False, "peer": "198.51.100.7", "https": True, "mark": "1", "for": "198.51.100.7", "proto": "https"}
        # every line of X-Forwarded-For goes on, in the order sent: the app behind reads the same last address
        said = _get(port, headers=[MARK, ("X-Forwarded-For", "10.9.9.9"), ("X-Forwarded-For", "198.51.100.7")])[1]
        assert (said["here"], said["peer"], said["for"]) == (False, "198.51.100.7", "10.9.9.9, 198.51.100.7")
        # an unmarked front's word goes on as it came too: the app behind is told what this one was, and reads the same
        said = _get(port, headers={"X-Forwarded-For": "198.51.100.7"})[1]
        assert said == {"here": False, "peer": "127.0.0.1", "https": False, "mark": None, "for": "198.51.100.7", "proto": None}
        said = _get(port, headers={"X-Forwarded-Proto": "http"})[1]
        assert (said["here"], said["mark"], said["for"], said["proto"]) == (False, None, None, "http")
    finally:
        front.shutdown()
        front.server_close()
        upstream.shutdown()
        upstream.server_close()


class _HeldLogin(App):
    """A login an app holds, as far as these tests need one: it says what the helpers make of a request it is asked."""

    NAME, TITLE, ICON = "login", "Login", "lambda"

    def __init__(self, log=print, superclass=None):
        super().__init__(log)

    def api(self, handler, method, path, query, body):
        if method == "GET" and path == "/api/asked":
            return 200, {"here": web.from_this_machine(handler), "peer": web.peer(handler),
                         "https": web.forwarded_https(handler)}
        return super().api(handler, method, path, query, body)


class _Holds(App):
    NAME, TITLE, ICON = "holds", "Holds", "chip"
    LOGIN, LOGIN_CLASS = True, _HeldLogin


def test_a_login_an_app_holds_is_asked_with_the_requests_own_peer_and_mark():
    """An app answers its login's requests with the object it holds (serve_object), handing it the request as it came:
    a page here is from this machine at the held login too (its sign-in without a password goes on working through the
    app that holds it), and what a front handed the app is not."""
    app = _Holds(log=lambda m: None)
    port = int(app.start(0).rstrip("/").rsplit(":", 1)[1])
    try:
        assert _get(port, "/login/api/asked")[1] == {"here": True, "peer": "127.0.0.1", "https": False}
        marked = [MARK, ("X-Forwarded-For", "198.51.100.7"), ("X-Forwarded-Proto", "https")]
        assert _get(port, "/login/api/asked", marked)[1] == {"here": False, "peer": "198.51.100.7", "https": True}
        # the app behind a front that set no mark but said where the browser was: its login lets nobody be at the machine
        unmarked = [("X-Forwarded-For", "198.51.100.7")]
        assert _get(port, "/login/api/asked", unmarked)[1] == {"here": False, "peer": "127.0.0.1", "https": False}
    finally:
        app.stop()
