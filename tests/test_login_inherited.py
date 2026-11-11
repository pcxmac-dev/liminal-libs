"""An app that inherits a login app (liminal_libs.apps.App, 1.46.0; the user, 2026-11-10: "make sure that the platform
inherits the login app so we can login to platform"): its page is the sign-in until the browser is signed in there, the
login app's page and API under /login/ (its cookies back), its tray at /api/trays, and the login app started for it as
its superclass when nothing answers. A stand-in plays the login app; no process starts."""
from __future__ import annotations

import json
import socket
import threading
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from liminal_libs import web
from liminal_libs.apps import App, Scope
from liminal_libs.apps import app as app_mod


class StandInLogin(BaseHTTPRequestHandler):
    """The login app as far as an inheriting app needs it: its status (signed in by its cookie), its tray, its page, a
    sign-in that sets its cookie."""

    def log_message(self, *a):
        pass

    def _json(self, status, data, cookie=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        cookie = self.headers.get("Cookie") or ""
        if self.path.startswith("/api/status"):
            return self._json(200, {"signedIn": "liminal_login_demo=tok" in cookie, "path": self.path, "cookie": cookie,
                                    "origin": self.headers.get("Origin")})
        if self.path == "/api/tray":
            return self._json(200, {"app": "login", "icon": "lambda", "title": "Login: Demo",
                                    "items": [{"id": "login", "icon": "lambda", "title": "Login: Demo", "kind": "app", "app": "login"}]})
        body = b"<html>the login page</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        got = json.loads(self.rfile.read(n) or b"{}")
        self._json(200, {"got": got, "write": self.headers.get(web.WRITE_HEADER)}, "liminal_login_demo=tok; Path=/; HttpOnly")


class Demo(App):
    NAME, TITLE, ICON = "demo", "Liminal Demo", "chip"
    LOGIN_URL_VAR = "LIMINAL_DEMO_LOGIN_URL"
    LOGIN_URL = "http://127.0.0.1:1"


def _call(port, method, path, body=None, headers=None):
    conn = HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=None if body is None else json.dumps(body).encode(), headers=headers or {})
    r = conn.getresponse()
    return r.status, r.read(), r


@pytest.fixture
def login_standin():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), StandInLogin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_an_app_that_inherits_a_login_opens_on_its_sign_in_until_the_browser_is_signed_in(tmp_path, monkeypatch, login_standin):
    (tmp_path / "index.html").write_text("<html><title>Demo</title>the app's page</html>", encoding="utf-8")
    Demo.STATIC = tmp_path
    monkeypatch.setenv("LIMINAL_DEMO_LOGIN_URL", f"http://127.0.0.1:{login_standin.server_address[1]}/")
    monkeypatch.setattr(app_mod, "start_app", lambda *a, **k: pytest.fail("nothing to start: the login answers"))
    app = Demo(log=lambda m: None)
    port = int(app.start(0).rstrip("/").rsplit(":", 1)[1])
    try:
        status, body, _ = _call(port, "GET", "/")
        assert status == 200 and b'id="signinFrame"' in body and b"signin.js" in body  # not signed in: the sign-in
        assert _call(port, "GET", "/signin.js")[0] == 200
        status, body, _ = _call(port, "GET", "/", headers={"Cookie": "liminal_login_demo=tok; other=1"})
        assert status == 200 and b"the app's page" in body  # signed in there: the app
        # the login app under /login/: its page, its API, its writes, its cookie back at its own path
        assert _call(port, "GET", "/login/")[1] == b"<html>the login page</html>"
        st = json.loads(_call(port, "GET", "/login/api/status?x=1", headers={"Cookie": "liminal_login_demo=tok"})[1])
        assert st["path"] == "/api/status?x=1" and st["signedIn"] is True and st["origin"] is None  # where it came from: checked here
        status, body, r = _call(port, "POST", "/login/api/sign-in/secret", {"name": "secret"},
                                {"Content-Type": "application/json", web.WRITE_HEADER: "1"})
        assert status == 200 and json.loads(body) == {"got": {"name": "secret"}, "write": "1"}
        assert r.getheader("Set-Cookie") == "liminal_login_demo=tok; Path=/; HttpOnly"
        assert _call(port, "GET", "/login/api/status", headers={"Origin": "http://evil.example"})[0] == 403  # another site's
        assert json.loads(_call(port, "GET", "/api/trays")[1])["trays"][0]["icon"] == "lambda"
    finally:
        app.stop()


def test_the_login_app_is_started_for_the_app_as_its_superclass_when_none_answers(tmp_path, monkeypatch):
    (tmp_path / "index.html").write_text("<html>the app's page</html>", encoding="utf-8")
    Demo.STATIC = tmp_path
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    monkeypatch.setenv("LIMINAL_DEMO_LOGIN_URL", f"http://127.0.0.1:{free}")
    started: list = []
    monkeypatch.setattr(app_mod, "start_app", lambda module, port, env=None, log=print: started.append((module, port, env)) or True)
    monkeypatch.setattr(app_mod, "wait_for", lambda port, seconds=0: False)  # it never answers: the app opens as before
    monkeypatch.setattr(Scope, "find", classmethod(lambda cls, start=None, env=None: None))  # no login file here
    app = Demo(log=lambda m: None)
    port = int(app.start(0).rstrip("/").rsplit(":", 1)[1])
    try:
        status, body, _ = _call(port, "GET", "/")
        assert status == 200 and body == b"<html>the app's page</html>"
        module, at, env = started[0]
        assert (module, at) == ("liminal_login", free)
        assert env["LIMINAL_LOGIN_FOR"] == "demo" and env["LIMINAL_LOGIN_FOR_TITLE"] == "Liminal Demo"
        assert env["LIMINAL_LOGIN_FOR_URL"] == f"http://127.0.0.1:{port}"  # where the login asks it for its plugins' pairs
        assert _call(port, "GET", "/login/api/status")[0] == 503
    finally:
        app.stop()
    monkeypatch.setenv("LIMINAL_DEMO_LOGIN_URL", "none")  # none: no sign-in, no /login/
    assert Demo(log=lambda m: None).login_url() is None
    assert App(log=lambda m: None).login_url() is None  # an app that names no login inherits none
