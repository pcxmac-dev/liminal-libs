"""The apps bound together (liminal_libs.apps.binding): a front passes its pages' requests on to a
bound app and its answers and cookies back, reads the bound app's tray, starts the app when nothing
answers (a stand-in Popen here), waits for it; an app served until quiet ends on its own. No process
starts: servers run in threads on port 0."""
from __future__ import annotations

import json
import threading
import time
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from liminal_libs import web
from liminal_libs.apps import App, Binding, TrayItem, forward, tray_of, wait_for
from liminal_libs.apps import binding as binding_mod


class Upstream(BaseHTTPRequestHandler):
    """A bound app's server, as far as a front needs one: it echoes what it got, sets a cookie, streams."""

    def log_message(self, *a):
        pass

    def _json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "liminal_login=tok; Path=/; HttpOnly; SameSite=Strict")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for i in range(2):
                self.wfile.write(f"data: {i}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.05)
            return
        self._json(200, {"path": self.path, "origin": self.headers.get("Origin"), "host": self.headers.get("Host"),
                         "cookie": self.headers.get("Cookie"), "session": self.headers.get("X-Liminal-Session")})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self._json(202, {"got": json.loads(self.rfile.read(n) or b"{}"), "write": self.headers.get(web.WRITE_HEADER)})


def _front(url: str):
    """A super app's front: /demo/... passed on to the bound app at `url`."""

    class Front(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _go(self, method):
            if not web.local_only(self) or not web.from_this_app(self):
                return
            if not self.path.startswith("/demo/"):
                return web.send(self, 404, b"not found", "text/plain")
            forward(self, method, url, self.path[len("/demo"):], cookie_path="/demo", drop_cookies=("other_",),
                    unavailable="demo is away")

        def do_GET(self):
            self._go("GET")

        def do_POST(self):
            self._go("POST")

    return Front


def _get(port, path, headers=None):
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers=headers or {})
    r = conn.getresponse()
    return r.status, r.read(), r


def test_a_front_passes_its_pages_requests_on_and_the_answers_and_cookies_back():
    up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{up.server_address[1]}"
    front = ThreadingHTTPServer(("127.0.0.1", 0), _front(url))
    threading.Thread(target=front.serve_forever, daemon=True).start()
    port = front.server_address[1]
    try:
        status, body, r = _get(port, "/demo/api/echo?x=1", {"Cookie": "other_app=1; liminal_login=tok; other_two=2",
                                                           "Origin": f"http://127.0.0.1:{port}",
                                                           "Sec-Fetch-Site": "same-origin", "X-Liminal-Session": "tok"})
        j = json.loads(body)
        assert status == 200 and j["path"] == "/api/echo?x=1" and j["cookie"] == "liminal_login=tok" and j["session"] == "tok"
        assert json.loads(_get(port, "/demo/api/echo", {"Cookie": "other_app=1"})[1])["cookie"] is None  # none left: no header
        assert j["origin"] is None and j["host"] == url.split("//", 1)[1]  # where it came from stays here
        assert r.getheader("Set-Cookie") == "liminal_login=tok; Path=/demo; HttpOnly; SameSite=Strict"  # the cookie's path narrowed
        assert _get(port, "/demo/api/echo", {"Origin": "http://evil.example"})[0] == 403
        assert _get(port, "/other")[0] == 404
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/demo/api/x", body=json.dumps({"a": 1}), headers={"Content-Type": "application/json", web.WRITE_HEADER: "1"})
        r = conn.getresponse()
        assert r.status == 202 and json.loads(r.read()) == {"got": {"a": 1}, "write": "1"}
        status, body, r = _get(port, "/demo/api/stream")
        assert status == 200 and body == b"data: 0\n\ndata: 1\n\n" and r.getheader("Content-Type").startswith("text/event-stream")
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/demo/api/x", body=b"{}", headers={"Content-Length": "-5", web.WRITE_HEADER: "1"})
        assert conn.getresponse().status == 400
        up.shutdown()
        up.server_close()
        status, body, _ = _get(port, "/demo/api/echo")
        assert status == 503 and json.loads(body) == {"error": "demo is away"}
    finally:
        front.shutdown()
        front.server_close()
    assert binding_mod._repath("a=1; Path=/; HttpOnly", "/login") == "a=1; Path=/login; HttpOnly"
    assert binding_mod._repath("a=1; HttpOnly", "/login") == "a=1; Path=/login; HttpOnly"
    assert binding_mod._repath("a=1; Path=/", None) == "a=1; Path=/"


class DemoApp(App):
    NAME, TITLE, ICON = "demo", "Demo", "plug"

    def items(self):
        return (TrayItem("things", "key", "Things", app="demo"),)


def test_a_linked_apps_tray_is_read_and_an_absent_app_is_never_started(tmp_path, monkeypatch):
    DemoApp.STATIC = tmp_path
    app = DemoApp(log=lambda m: None)
    url = app.start(0).rstrip("/")
    port = int(url.rsplit(":", 1)[1])
    try:
        b = Binding("demo", url, "demo_module")
        assert b.port == port and b.prefix == "/demo" and b.reachable()
        tray = b.tray()
        assert tray["app"] == "demo" and [i["id"] for i in tray["items"]] == ["demo", "things"]
        assert wait_for(port, 1) is True
    finally:
        app.stop()
    assert tray_of(url) is None and not Binding("demo", url).reachable() and wait_for(port, 0.3, 0.05) is False
    # an app that does not answer is not running, and nothing here starts it (1.52.0; the user, 2026-11-14: "don't
    # start any of the applications in the background"): start_app is gone
    assert not hasattr(binding_mod, "start_app")


class Looks:
    """serve's stop as a test drives it: each of serve's waits (a look every 0.5 s) is taken when the test says (look),
    and moves the app's clock on by its 0.5 s; no real time passes. A served app's quiet end was timed by real sleeps
    against real 0.5 s looks until 2026-11-25, and a slow runner failed it."""

    BOUND_S = 60.0  # a last resort only: a look serve never reaches fails the test, it does not hang it

    def __init__(self, clock: list):
        self.clock, self._go, self._waiting, self._set = clock, threading.Semaphore(0), threading.Semaphore(0), False

    def wait(self, timeout=None):
        if self._set:
            return True
        self._waiting.release()  # serve waits here: the test may act, then look
        assert self._go.acquire(timeout=self.BOUND_S), "the test never looked"
        self.clock[0] += timeout
        return self._set

    def set(self):
        self._set = True

    def is_set(self):
        return self._set

    def waiting(self) -> None:
        """Until serve waits for its next look."""
        assert self._waiting.acquire(timeout=self.BOUND_S), "serve never waited for its next look"

    def look(self) -> None:
        """serve's next look, taken now."""
        self._go.release()


def test_an_app_served_until_quiet_ends_once_no_page_has_been_in_touch(tmp_path, monkeypatch):
    from liminal_libs.apps import app as app_mod

    clock = [0.0]

    class Clock:  # the app's time: its monotonic the test's, the rest the real module's
        monotonic = staticmethod(lambda: clock[0])

        def __getattr__(self, name):
            return getattr(time, name)
    monkeypatch.setattr(app_mod, "time", Clock())
    DemoApp.STATIC = tmp_path
    lines: list[str] = []
    app = DemoApp(log=lines.append)
    done: list[str] = []
    looks = Looks(clock)
    thread = threading.Thread(target=lambda: done.append(app.serve(0, stop=looks, until_quiet=0.6)), daemon=True)
    thread.start()
    looks.waiting()  # served, touched at 0.0, waiting for its first look
    port = int(app.served.rstrip("/").rsplit(":", 1)[1])
    looks.look()  # 0.5: quiet for 0.5 s, not yet 0.6
    looks.waiting()
    assert _get(port, "/api/tray")[0] == 200  # in touch at 0.5: the clock starts again
    looks.look()  # 1.0: quiet for 0.5 s since the touch (1.0 s since it began: it would have ended here without it)
    looks.waiting()
    assert web.listening(port) and not done
    looks.look()  # 1.5: quiet for 1.0 s: it ends
    thread.join(Looks.BOUND_S)
    assert not thread.is_alive(), "the app did not end once quiet"
    assert done == [app.served] and not web.listening(port) and any("no page has been in touch" in m for m in lines)


def test_a_link_is_reached_at_its_own_address_on_another_machine_too(monkeypatch):
    """1.53.0 (the user, 2026-11-14: "linking vs including the objects, is so that parts of the code can be executed
    remotely"): a loopback link asks this machine's port; another machine's address is asked over the network, briefly;
    nothing is started either way."""
    import socket as socket_mod

    asked: list = []

    class Answer:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def connect(address, timeout=None):
        asked.append((address, timeout))
        if address[0] == "down.example":
            raise OSError("no route to host")
        return Answer()
    monkeypatch.setattr(socket_mod, "create_connection", connect)
    assert Binding("platform", "http://box.example:8775").reachable() is True
    assert Binding("platform", "http://down.example:8775").reachable(timeout=0.5) is False
    assert asked == [(("box.example", 8775), binding_mod.REACH_SECONDS), (("down.example", 8775), 0.5)]
    seen: list = []
    monkeypatch.setattr(binding_mod.web, "listening", lambda port: seen.append(port) or False)
    assert Binding("platform", "http://127.0.0.1:8775").reachable() is False and seen == [8775] and len(asked) == 2
    assert Binding("x", "https://box.example").port == 443 and Binding("x", "http://box.example").port == 80
    assert Binding("x", "http://box.example:9").host == "box.example" and Binding("x", "http://[::1]:8775").host == "::1"


def test_a_link_passes_on_only_the_linked_apps_own_cookies_when_told():
    """1.53.0 (keep_cookies): what reaches a linked app, which may be on another machine, is its own cookies and nothing
    else of the browser's (the front's own login and profile stay here); drop_cookies still drops by name."""

    class Keeping(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            forward(self, "GET", url, self.path[len("/demo"):], cookie_path="/demo", keep_cookies=("liminal_login_demo",),
                    drop_cookies=("liminal_login_demo_old",))

    up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{up.server_address[1]}"
    front = ThreadingHTTPServer(("127.0.0.1", 0), Keeping)
    threading.Thread(target=front.serve_forever, daemon=True).start()
    try:
        cookie = "liminal_login_charts=c; mc_profile=3; liminal_login=own; liminal_login_demo=d; liminal_login_demo_old=x"
        j = json.loads(_get(front.server_address[1], "/demo/api/echo", {"Cookie": cookie})[1])
        assert j["cookie"] == "liminal_login_demo=d"  # its own alone
        assert json.loads(_get(front.server_address[1], "/demo/api/echo", {"Cookie": "mc_profile=3"})[1])["cookie"] is None
    finally:
        front.shutdown()
        front.server_close()
        up.shutdown()
        up.server_close()
