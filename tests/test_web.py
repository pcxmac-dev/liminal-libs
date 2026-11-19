"""What every app's server shares (liminal_libs.web): an answer with no body, and the server class.

- send_json: a 202 or a 204 whose data is None goes with no body and no Content-Type (MCP's "202 Accepted with no
  body"). The 202 says Content-Length 0, the 204 no length (RFC 9110, 8.6). Every other answer is JSON as before.
- Server: the standard ThreadingHTTPServer, but its port is its own. On Windows it sets SO_EXCLUSIVEADDRUSE before its
  bind and no SO_REUSEADDR; elsewhere SO_REUSEADDR; never SO_REUSEPORT.

The answers are written by a real request handler into memory and read back by http.client, as a client reads them.
The server's options are asked of a stand-in socket, for each system. Every test here asks for the shared guard
(no_outside) but one: the real check of the server's terms, on 127.0.0.1, port 0 (a free one), in a thread, as the
frame's tests run theirs (test_apps.py). No test starts a process or uses one of the four apps' ports."""
from __future__ import annotations

import io
import json
import os
import socket
import threading
from http import HTTPStatus
from http.client import HTTPConnection, HTTPResponse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from liminal_libs import web

guarded = pytest.mark.usefixtures("no_outside")
EXCLUSIVE = -5  # Windows' SO_EXCLUSIVEADDRUSE (~SO_REUSEADDR), so another system can stand in for Windows


class Quiet(BaseHTTPRequestHandler):
    """A request handler that keeps no log of its own (the standard one writes each request to stderr)."""

    def log_message(self, format, *args):  # noqa: A002 - the standard library's name
        pass


class Hello(Quiet):
    """The real check's handler: the request's body read and dropped first, then a 202 with no body, as MCP's."""

    def do_POST(self):
        web.drain(self)
        web.send_json(self, None, HTTPStatus.ACCEPTED, [("Mcp-Session-Id", "s1")])


class Wire:
    """The bytes an answer wrote, as the socket a client reads them from (http.client asks it for makefile alone)."""

    def __init__(self, raw: bytes):
        self.raw = raw

    def makefile(self, mode, *args, **kwargs):
        return io.BytesIO(self.raw)


def answered(send, method: str = "POST"):
    """What a client reads of the answer `send(handler)` writes: a real handler writing into memory, with no request
    and no socket, its bytes read back by http.client. Returns (the response, its body, the bytes written)."""
    handler = Quiet.__new__(Quiet)  # only its answer is used: nothing is read from a request
    handler.wfile = io.BytesIO()
    handler.request_version, handler.command = "HTTP/1.0", method
    handler.requestline = f"{method} /api/machines/mcp/rpc HTTP/1.0"
    send(handler)
    raw = handler.wfile.getvalue()
    response = HTTPResponse(Wire(raw), method=method)
    response.begin()
    return response, response.read(), raw


def header_names(raw: bytes) -> list[str]:
    """The answer's header names in the order they were written."""
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]
    return [line.split(b":", 1)[0].decode("ascii") for line in head]


# -- send_json: no body for a 202 or a 204 whose data is None ----------------------------------------------------------
@guarded
@pytest.mark.parametrize("status", [202, HTTPStatus.ACCEPTED], ids=["int", "HTTPStatus"])
def test_a_202_whose_data_is_none_has_no_body_and_says_a_length_of_0(status):
    response, body, raw = answered(lambda h: web.send_json(h, None, status, [("Mcp-Session-Id", "s1")]))
    assert response.status == 202 and body == b"" and raw.endswith(b"\r\n\r\n")  # nothing after the headers
    assert response.getheader("Content-Length") == "0" and response.getheader("Content-Type") is None
    assert response.getheader("Mcp-Session-Id") == "s1"  # what the caller gives still goes
    assert response.getheader("Cache-Control") == "no-store"
    assert response.getheader("X-Content-Type-Options") == "nosniff"
    assert header_names(raw) == ["Server", "Date", "Content-Length", "Cache-Control", "X-Content-Type-Options",
                                 "Mcp-Session-Id"]


@guarded
@pytest.mark.parametrize("status", [204, HTTPStatus.NO_CONTENT], ids=["int", "HTTPStatus"])
def test_a_204_whose_data_is_none_has_no_body_and_says_no_length(status):
    response, body, raw = answered(lambda h: web.send_json(h, None, status, {"Mcp-Session-Id": "s1"}), "DELETE")
    assert response.status == 204 and body == b"" and raw.endswith(b"\r\n\r\n")
    assert response.getheader("Content-Length") is None and response.getheader("Content-Type") is None
    assert header_names(raw) == ["Server", "Date", "Cache-Control", "X-Content-Type-Options", "Mcp-Session-Id"]


@guarded
def test_every_other_answer_is_json_as_before_none_among_them():
    # a 202 with data is still JSON (every 202 the apps answer today carries a dict) ...
    response, body, raw = answered(lambda h: web.send_json(h, {"job": "j1"}, 202))
    assert (response.status, json.loads(body), response.getheader("Content-Type")) == (202, {"job": "j1"},
                                                                                       "application/json")
    assert response.getheader("Content-Length") == str(len(body))
    assert header_names(raw) == ["Server", "Date", "Content-Type", "Content-Length", "Cache-Control",
                                 "X-Content-Type-Options"]
    # ... a 200 with None is still "null", and so is any status but the two
    for status in (200, 201, 400):
        response, body, _ = answered(lambda h: web.send_json(h, None, status))
        assert (response.status, body, response.getheader("Content-Length")) == (status, b"null", "4")
        assert response.getheader("Content-Type") == "application/json"


@guarded
def test_send_writes_its_headers_as_before_and_a_header_given_wins_over_a_default():
    response, body, raw = answered(lambda h: web.send(h, 200, b"hi", "text/plain", {"Cache-Control": "max-age=5"}))
    assert body == b"hi" and response.getheader("Cache-Control") == "max-age=5"
    assert header_names(raw) == ["Server", "Date", "Content-Type", "Content-Length", "X-Content-Type-Options",
                                 "Cache-Control"]


# -- Server: its port its own ------------------------------------------------------------------------------------------
class Unbound:
    """A stand-in socket: what is asked of it, in order. It binds nothing and listens on nothing."""

    def __init__(self):
        self.asked: list[tuple] = []

    def setsockopt(self, level, option, value):
        self.asked.append(("setsockopt", level, option, value))

    def bind(self, address):
        self.asked.append(("bind", address))

    def getsockname(self):
        return ("127.0.0.1", 50123)

    def close(self):
        self.asked.append(("close",))


@guarded
@pytest.mark.parametrize("windows", [True, False], ids=["windows", "elsewhere"])
def test_the_server_sets_its_systems_options_before_it_binds(monkeypatch, windows):
    monkeypatch.setattr(web, "_windows", lambda: windows)
    monkeypatch.setattr(socket, "SO_EXCLUSIVEADDRUSE", getattr(socket, "SO_EXCLUSIVEADDRUSE", EXCLUSIVE), raising=False)
    monkeypatch.setattr(socket, "getfqdn", lambda name="": "here")  # the name the standard bind looks up after it
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: Unbound())  # no socket of this system's is made
    server = web.Server(("127.0.0.1", 0), Quiet, bind_and_activate=False)
    unbound = server.socket
    assert isinstance(unbound, Unbound) and unbound.asked == []
    server.server_bind()
    option = socket.SO_EXCLUSIVEADDRUSE if windows else socket.SO_REUSEADDR
    # one option, set before the bind; never both (Windows refuses the pair) and never SO_REUSEPORT
    assert unbound.asked == [("setsockopt", socket.SOL_SOCKET, option, 1), ("bind", ("127.0.0.1", 0))]
    assert server.allow_reuse_address is (not windows)
    assert (server.server_address, server.server_port, server.server_name) == (("127.0.0.1", 50123), 50123, "here")
    server.server_close()
    assert unbound.asked[-1] == ("close",)


@guarded
def test_the_class_says_this_systems_choice_and_is_the_standard_threading_server():
    assert issubclass(web.Server, ThreadingHTTPServer) and web.Server.daemon_threads is True
    assert web.Server.allow_reuse_address is (os.name != "nt") and web.Server.allow_reuse_port is False
    assert web._windows() is (os.name == "nt")


# A note kept beside this test (the build notes of 2026-11-18, L16). The exclusive bind has one documented cost:
# Microsoft says a port bound with SO_EXCLUSIVEADDRUSE may not be bound again at once while a connection its closed
# listener accepted is still winding down. On Windows 11 Pro 26H2 build 26300.9974 (the development machine,
# 2026-11-18), a new exclusive listener bound 127.0.0.1 and 0.0.0.0 with the old listener's connection in TIME_WAIT, in
# FIN_WAIT_2, and still ESTABLISHED with its accepted socket open, from the same process and from a second one; a live
# listener was refused every time (WinError 10048) (wf_70c82024-e96's socket-semantics lens). The apps' handlers are
# HTTP/1.0 (no protocol_version is set anywhere), so no connection is kept alive between requests: what is open when an
# app's process ends are its streams and held reads (the charts' /api/stream, the platform's job and terminal reads).
# Still to come: the trial on the real path, once, on an app the user runs, and only with the user's yes for that
# restart (its task ended and run again within a second, a browser tab open on it). If the new process cannot bind
# there, the answer is a short bounded retry of the bind on the same port, never another port, keeping the exclusive
# bind. This test does not rebind after the close: what Windows does then is for that trial to show.
def test_a_real_server_holds_its_port_alone_while_it_serves():
    """The one real check the server's terms allow, and the one test here without the guard: a server on 127.0.0.1,
    port 0, in a thread. It answers a real request (a 202 with no body, read by a real client). Its socket says its
    system's option. While it serves, a second server on its port is refused, on every system: another of these, and
    the standard one, which sets SO_REUSEADDR (on Windows that once took a port in use)."""
    server = web.Server(("127.0.0.1", 0), Hello)
    thread = threading.Thread(target=server.serve_forever, name="test-web-server", daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/api/machines/mcp/rpc", body=b'{"jsonrpc": "2.0", "method": "notifications/initialized"}',
                     headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        got = (r.status, r.read(), r.getheader("Content-Type"), r.getheader("Content-Length"),
               r.getheader("Mcp-Session-Id"))
        conn.close()
        assert got == (202, b"", None, "0", "s1")
        if os.name == "nt":
            assert server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE) == 1
            assert server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
        else:
            assert server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0
        for make in (web.Server, ThreadingHTTPServer):
            try:
                second = make(("127.0.0.1", port), Quiet)
            except OSError:
                continue
            second.server_close()
            pytest.fail(f"{make.__name__} bound port {port} while a web.Server served it")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
    assert not thread.is_alive()
