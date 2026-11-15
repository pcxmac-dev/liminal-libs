"""An app that inherits the login (liminal_libs.apps.App; 1.46.0, an object since 1.52.0; the user, 2026-11-10: "make sure
that the platform inherits the login app so we can login to platform"; 2026-11-14: "the platform and integrator inherit
the login function, they are separate login instances, class vs object"; "login doesn't point to anything except the
app that inherited it"): one object of the login class made for the app, in its process, its superclass the app itself;
its page and API under /login/ at the app's own port (its cookies back), its tray at /api/trays, the app's page the
sign-in until the browser is signed in there. A stand-in plays the login class; no process starts, no other port opens."""
from __future__ import annotations

import json
import socket
from http.client import HTTPConnection

import pytest

from liminal_libs import web
from liminal_libs.apps import App, PortTaken
from liminal_libs.apps import app as app_mod
from liminal_libs.apps import binding as binding_mod


class StandInLogin(App):
    """The login class as far as an app that inherits it needs it: made with that app as its superclass, a session by
    its cookie, its page, a sign-in that sets its cookie, the pairs asked of the app that inherited it."""

    NAME, ICON = "login", "lambda"
    made: list = []
    closed: list = []

    def __init__(self, log=print, superclass=None):
        super().__init__(log)
        self.superclass = superclass
        self.TITLE = f"Login: {superclass.TITLE}"
        StandInLogin.made.append(self)

    def session(self, handler):
        return "a session" if "liminal_login_demo=tok" in (handler.headers.get("Cookie") or "") else None

    def api(self, handler, method, path, query, body):
        if method == "GET" and path == "/api/status":
            return 200, {"signedIn": self.session(handler) is not None, "path": path, "query": query,
                         "origin": handler.headers.get("Origin")}
        if method == "GET" and path == "/api/pairs/known":
            return 200, {"pairs": self.superclass.login_pairs()}  # asked of the app that inherited it, nothing else
        if method == "POST" and path == "/api/sign-in/secret":
            return 200, {"got": body, "write": handler.headers.get(web.WRITE_HEADER)}, \
                [("Set-Cookie", "liminal_login_demo=tok; Path=/; HttpOnly")]
        return super().api(handler, method, path, query, body)

    def close(self):
        StandInLogin.closed.append(self)


class Demo(App):
    NAME, TITLE, ICON = "demo", "Liminal Demo", "chip"
    LOGIN, LOGIN_VAR = True, "LIMINAL_DEMO_LOGIN"
    LOGIN_CLASS = StandInLogin


def _call(port, method, path, body=None, headers=None):
    conn = HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=None if body is None else json.dumps(body).encode(), headers=headers or {})
    r = conn.getresponse()
    return r.status, r.read(), r


@pytest.fixture
def pages(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "index.html").write_text("<html><title>Demo</title>the app's page</html>", encoding="utf-8")
    (tmp_path / "login").mkdir()
    (tmp_path / "login" / "index.html").write_text("<html>the login page</html>", encoding="utf-8")
    Demo.STATIC, StandInLogin.STATIC = tmp_path / "app", tmp_path / "login"
    StandInLogin.made, StandInLogin.closed = [], []
    return tmp_path


def _port(app) -> int:
    return int(app.start(0).rstrip("/").rsplit(":", 1)[1])


def test_an_app_holds_the_login_it_inherits_as_an_object_at_its_own_port(pages, monkeypatch):
    monkeypatch.delenv("LIMINAL_DEMO_LOGIN", raising=False)
    app = Demo(log=lambda m: None)
    port = _port(app)
    try:
        status, body, _ = _call(port, "GET", "/")
        assert status == 200 and b'id="signinFrame"' in body and b"signin.js" in body  # not signed in: the sign-in
        assert _call(port, "GET", "/signin.js")[0] == 200
        status, body, _ = _call(port, "GET", "/", headers={"Cookie": "liminal_login_demo=tok; other=1"})
        assert status == 200 and b"the app's page" in body  # signed in there: the app
        # the login object under /login/, at this app's own port: its page, its API, its writes, its cookie back
        assert _call(port, "GET", "/login/")[1] == b"<html>the login page</html>"
        st = json.loads(_call(port, "GET", "/login/api/status?x=1", headers={"Cookie": "liminal_login_demo=tok"})[1])
        assert st == {"signedIn": True, "path": "/api/status", "query": {"x": "1"}, "origin": None}
        status, body, r = _call(port, "POST", "/login/api/sign-in/secret", {"name": "secret"},
                                {"Content-Type": "application/json", web.WRITE_HEADER: "1"})
        assert status == 200 and json.loads(body) == {"got": {"name": "secret"}, "write": "1"}
        assert r.getheader("Set-Cookie") == "liminal_login_demo=tok; Path=/; HttpOnly"
        # its own checks, here: a write without the header, another site's page
        assert _call(port, "POST", "/login/api/sign-in/secret", {"name": "x"}, {"Content-Type": "application/json"})[0] == 403
        assert _call(port, "GET", "/login/api/status", headers={"Origin": "http://evil.example"})[0] == 403
        tray = json.loads(_call(port, "GET", "/api/trays")[1])["trays"][0]
        assert tray["icon"] == "lambda" and tray["title"] == "Login: Liminal Demo"
        # one object, made for this app, its superclass the app itself: the pairs its plugins ask for asked of it
        app.login_pairs = lambda: [{"name": "demo-api-key"}]
        assert json.loads(_call(port, "GET", "/login/api/pairs/known")[1]) == {"pairs": [{"name": "demo-api-key"}]}
        assert len(StandInLogin.made) == 1 and StandInLogin.made[0].superclass is app and app.login_object() is StandInLogin.made[0]
    finally:
        app.stop()
    assert StandInLogin.closed == StandInLogin.made  # the app's end closes the login it held
    assert not hasattr(binding_mod, "start_app") and not hasattr(app_mod, "start_app")  # nothing here starts an app


def test_two_apps_that_inherit_the_login_hold_two_logins(pages):
    """Separate instances: each app its own object, its own superclass."""

    class Other(Demo):
        NAME, TITLE = "other", "Liminal Other"

    a, b = Demo(log=lambda m: None), Other(log=lambda m: None)
    assert a.login_object() is not b.login_object()
    assert [m.superclass for m in StandInLogin.made] == [a, b] and a.login_object() is a.login_object()


def test_the_page_by_its_files_own_name_is_the_sign_in_too(pages, monkeypatch):
    """1.46.1 (a review of the platform's page asking its login every minute whether you are still signed in, 2026-11-10):
    the app's page by its file's own name (/index.html) was served whatever the sign-in said, so a page opened there
    while signed out, told so, reloaded into itself every minute and never showed the sign-in. It is the sign-in there
    too until the browser is signed in; an app that inherits no login serves the file as before."""
    monkeypatch.delenv("LIMINAL_DEMO_LOGIN", raising=False)
    app = Demo(log=lambda m: None)
    port = _port(app)
    try:
        for path in ("/index.html", "/index.html?x=1"):
            status, body, _ = _call(port, "GET", path)
            assert status == 200 and b'id="signinFrame"' in body, path  # not signed in: the sign-in, there too
            status, body, _ = _call(port, "GET", path, headers={"Cookie": "liminal_login_demo=tok"})
            assert status == 200 and b"the app's page" in body, path  # signed in: the app
        # another spelling the file system finds the same file by (Windows: another case, a trailing dot) is gated alike;
        # where it finds none (Linux), nothing is served
        for path in ("/Index.html", "/INDEX.HTML", "/index.html."):
            status, body, _ = _call(port, "GET", path)
            if web.static_target(path.lstrip("/"), [Demo.STATIC]) is not None:
                assert status == 200 and b'id="signinFrame"' in body, path
            else:
                assert status == 404, path
        # the sign-in by its own name, signed in: the app's page (it reloaded into itself, the login saying signed in)
        status, body, _ = _call(port, "GET", "/signin.html", headers={"Cookie": "liminal_login_demo=tok"})
        assert status == 200 and b"the app's page" in body
        status, body, _ = _call(port, "GET", "/signin.html")
        assert status == 200 and b'id="signinFrame"' in body
        assert b"window.LiminalIcons" in _call(port, "GET", "/icons.js")[1]  # every other file as before
    finally:
        app.stop()
    monkeypatch.setenv("LIMINAL_DEMO_LOGIN", "none")  # inheriting no login: the file, whoever asks
    app = Demo(log=lambda m: None)
    port = _port(app)
    try:
        assert b"the app's page" in _call(port, "GET", "/index.html")[1] and b"the app's page" in _call(port, "GET", "/")[1]
        assert _call(port, "GET", "/login/api/status")[0] == 404 and app.login_object() is None
    finally:
        app.stop()


def test_a_login_class_that_cannot_be_had_leaves_the_page_as_it_was(pages, monkeypatch):
    monkeypatch.delenv("LIMINAL_DEMO_LOGIN", raising=False)

    class Missing(Demo):
        LOGIN_CLASS = "no_such_login_module_here:LoginApp"

    said: list[str] = []
    app = Missing(log=said.append)
    port = _port(app)
    try:
        status, body, _ = _call(port, "GET", "/")
        assert status == 200 and b"the app's page" in body  # no login object: the app's page as before
        assert _call(port, "GET", "/login/api/status")[0] == 503
        assert _call(port, "GET", "/login/api/status")[0] == 503
        assert sum("could not be made" in m for m in said) == 1  # said once, not tried again
    finally:
        app.stop()


def test_the_declaration_of_1_46_still_inherits_the_login_its_address_unused(pages, monkeypatch):
    """A class that still names a login app of its own (LOGIN_URL, LOGIN_URL_VAR: liminal-platform until it moves) holds
    the login as an object all the same; nothing answers or starts at that address."""

    class Old(App):
        NAME, TITLE = "old", "Liminal Old"
        LOGIN_URL_VAR, LOGIN_URL = "LIMINAL_OLD_LOGIN_URL", "http://127.0.0.1:1"
        LOGIN_CLASS = StandInLogin

    monkeypatch.delenv("LIMINAL_OLD_LOGIN_URL", raising=False)
    old = Old(log=lambda m: None)
    assert old.inherits_login() and old.login_object().superclass is old
    monkeypatch.setenv("LIMINAL_OLD_LOGIN_URL", "off")
    assert not Old(log=lambda m: None).inherits_login()
    assert not App(log=lambda m: None).inherits_login() and App(log=lambda m: None).login_object() is None


def test_a_taken_port_is_refused_never_traded_for_another(pages, monkeypatch):
    """1.52.0 (the user, 2026-11-14: "i only want ports for liminal-login ; liminal-platform ; liminal-charts ;
    liminal-integrator"; "never provide ports for anything else"): an app whose port another program holds is not
    started, and not started on a free port instead."""
    monkeypatch.setenv("LIMINAL_DEMO_LOGIN", "none")
    with socket.socket() as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        taken = holder.getsockname()[1]
        app = Demo(log=lambda m: None)
        with pytest.raises(PortTaken) as e:
            app.start(taken)
        assert e.value.port == taken and f"port {taken} is taken" in str(e.value) and "Liminal Demo" in str(e.value)
        assert app.served is None and app._httpd is None
