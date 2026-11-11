"""An app's common frame: its page served at its own port on this machine alone, its tray, its
routes, the files of its page (its own folder first, then the library's: the icons and the theme).

The user, 2026-11-04: "every app, whether it's a login, the charts, platform, or integrator has its
own web kind of server and has a menu on the right-hand side with icons"; "the library basically
facilitates the interprocess communication, the way the apps can bind to each other, or interoperate
... As well as the framework for the graphics". An app is a subclass naming itself (NAME, TITLE, the
master ICON, its PORT and the variable overriding it, its own STATIC folder) and answering its routes
in `api`; everything a server must do alike (only this machine, only its own pages, the write
header on every write, the body's size and shape, the files, a taken port) is here, once. The chart
front (liminal_charts.gui.front) and the integrator's page do the same by hand today and move onto
this frame at 0.3.0, when a super app composes the trays of the apps it is bound to."""
from __future__ import annotations

import inspect
import json
import os
import sys
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .. import web
from ..ui import STATIC as UI_STATIC
import urllib.error
import urllib.request

from .binding import START_SECONDS, Binding, forward, start_app, wait_for
from .login import PAIRS_PATH, inherited_by, pairs_wanted
from .traffic import RecordingLogin, Traffic, node_of
from .tray import Tray, TrayItem

TRAFFIC_PATH = "/api/traffic"  # what the app's page draws of who talks to whom: never noted itself
SIGNIN = "signin.html"  # an app's sign-in while it inherits a login app (ui/static, 1.46.0)
LOGIN_PREFIX = "/login"  # where an app serves the login app it inherits


def _is_login(path: str) -> bool:
    return path == LOGIN_PREFIX or path.startswith(LOGIN_PREFIX + "/")


def _caller(handler) -> str:
    """Who sent a request: the app's page in a browser (it names its origin), else a program."""
    h = handler.headers
    return "page" if (h.get("Origin") or h.get("Sec-Fetch-Site") or h.get("Referer")) else "client"


class Refused(Exception):
    """An answer the app refuses: its status and the reason, sent as {"error": reason}."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


class App:
    """The frame of one app. A subclass sets the class attributes and overrides `api` (its routes),
    `items` (its tray's plugins) and, when its page depends on the request, `page`."""

    NAME = ""  # "login", "charts", "integrator", "platform", "plugins"
    TITLE = ""
    ICON = ""  # the master icon's name in icons.js (charts "disk", integrator "scroll", platform "chip", login "lambda")
    PORT = 0  # its page's default port on 127.0.0.1 (0: a free one)
    PORT_VAR = ""  # the environment variable overriding PORT (LIMINAL_LOGIN_PORT ...)
    STATIC: Path | None = None  # the app's own page files (index.html, its scripts)
    INDEX = "index.html"
    API = "1.0"  # the app's own API version, for its clients
    # who talks to whom (apps.traffic; `GET /api/traffic`): the page's requests, the plugins attached and detached and
    # asked by name are noted in every app; an app may also note what its plugins read and keep through its login
    # (each plugin lent a login noting it) and the programs and hosts the app and its plugins reach (once served)
    TRACE_LOGIN = False
    WATCH_OUTSIDE = False
    READ_HOOKS: tuple[str, ...] = ()  # hooks asked by name that only read (noted as reads, not asks)
    # the login app this app inherits (1.46.0; the user, 2026-11-10: "make sure that the platform inherits the login app
    # so we can login to platform"): where it answers, LOGIN_URL_VAR in the environment else LOGIN_URL ("none" or "off":
    # none); started for this app as its superclass when nothing answers there (apps.login.inherited_by), its page and
    # API under /login/, its tray at /api/trays, and this app's page its sign-in until the browser is signed in there
    LOGIN_URL_VAR = ""
    LOGIN_URL = ""

    def __init__(self, log=print, login=None):
        self.log = log
        self.login = login  # the authorization interface of this app's namespace (apps.authorization.Login)
        self.served: str | None = None  # the URL once started
        self.touched = time.monotonic()  # the last request (serve's until_quiet)
        self._plugins: dict[str, object] = {}  # the plugins attached, by name (attach)
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.traffic = Traffic()  # what is said, between whom (apps.traffic)
        self.traffic.me = self.NAME
        self.traffic.own(self, self.NAME)
        self._login_lock = threading.Lock()  # one start of its login app, however many pages ask at once

    # -- the login app it inherits (1.46.0) ------------------------------------------------------------------------
    def login_url(self) -> str | None:
        """Where the login app this app inherits answers; None when it inherits none."""
        if not (self.LOGIN_URL_VAR or self.LOGIN_URL):
            return None
        raw = (os.environ.get(self.LOGIN_URL_VAR) or "").strip() if self.LOGIN_URL_VAR else ""
        if raw.lower() in ("none", "off"):
            return None
        return (raw or self.LOGIN_URL).rstrip("/") or None

    def bound_login(self) -> Binding | None:
        """Its login app, answering: at its address, or started for this app as its superclass and waited for. None:
        it inherits none, or none could be started."""
        url = self.login_url()
        if url is None:
            return None
        bound = Binding("login", url, "liminal_login")
        if bound.reachable():
            return bound
        with self._login_lock:
            if bound.reachable():
                return bound
            if not self.start_login(bound.port):
                return None
            if wait_for(bound.port, START_SECONDS):
                self.log(f"{self.NAME}: its login app answers at {url}/")
                return bound
        self.log(f"{self.NAME}: the login app started for it never answered at port {bound.port}")
        return None

    def start_login(self, port: int) -> bool:
        """The login app started for this app, which it inherits: told so (its name, its title, this app's address, so
        it asks this app for the pairs its plugins ask for) and given the login's file this app finds."""
        from .scope import Scope

        env = inherited_by(self.NAME, self.TITLE or self.NAME.capitalize(), (self.served or self.url()).rstrip("/"))
        try:
            scope = Scope.find()
        except (OSError, ValueError):
            scope = None
        if scope is not None and scope.path is not None:
            env["LIMINAL_LOGIN_CFG"] = str(scope.path)
        return start_app("liminal_login", port, env, self.log)

    def signed_in(self, handler) -> bool | None:
        """Whether the browser of `handler` is signed in to its login app (asked with that browser's login cookies);
        None when it inherits none or none answers."""
        bound = self.bound_login()
        if bound is None:
            return None
        cookies = "; ".join(c.strip() for c in (handler.headers.get("Cookie") or "").split(";")
                            if c.strip().startswith("liminal_login"))
        headers = {"Accept": "application/json", **({"Cookie": cookies} if cookies else {})}
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(urllib.request.Request(bound.url + "/api/status", headers=headers), timeout=5) as resp:
                return bool(json.loads(resp.read()).get("signedIn"))
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            return None

    def trays(self) -> list[dict]:
        """The trays of the apps this one binds (its login app's), for the foot of its rail."""
        bound = self.bound_login()
        tray = bound.tray() if bound is not None else None
        return [tray] if tray else []

    def login_for(self, name: str):
        """The login `name` (a plugin, or the app itself by its own name) is lent: the app's; noting what it reads and
        keeps there when the app traces its login (TRACE_LOGIN)."""
        if self.login is None or not self.TRACE_LOGIN:
            return self.login
        return RecordingLogin(self.login, name, self.traffic)

    # -- the plugins attached (the user, 2026-11-06: "the app itself (either chart or integrator) has
    # plugin ABC as well"; "the plugin ABC will enumerate attached plugins and their API") ------------
    def attach(self, plugin) -> dict:
        """A plugin attached to this app: it gets this app and its login (the one way to its keys);
        returns the interface the plugin offers (what `plugins` enumerates)."""
        interface = plugin.attach(self, self.login_for(plugin.name))
        self._plugins[plugin.name] = plugin
        self.traffic.own(plugin, plugin.name)
        self.traffic.record(self.NAME, plugin.name, "attach", "attached")
        self.log(f"{self.NAME}: {plugin.name} attached ({plugin.KIND}; hooks {', '.join(interface['hooks']) or 'none'})")
        return interface

    def detach(self, name: str) -> bool:
        plugin = self._plugins.pop(name, None)
        if plugin is None:
            return False
        plugin.detach()
        self.traffic.record(self.NAME, name, "attach", "detached")
        self.log(f"{self.NAME}: {name} detached")
        return True

    def plugin(self, name: str):
        return self._plugins.get(name)

    def plugins(self) -> dict[str, dict]:
        """The plugins attached and their API, by name (`GET /api/plugins`)."""
        return {name: p.interface() for name, p in self._plugins.items()}

    def login_pairs(self) -> list[dict]:
        """The pairs this app's plugins ask for, for a login app it inherits (`GET /api/login/pairs`, 1.43.0): its
        attached plugins' (apps.login.pairs_wanted). The login knows no plugin itself."""
        return pairs_wanted(self._plugins.values())

    def ask(self, name: str, hook: str, *args, **kwargs):
        """One attached plugin's hook called by name (LookupError: no such plugin or hook); noted as asked by whoever
        calls (a plugin asking another through its app, else the app)."""
        plugin = self._plugins.get(name)
        if plugin is None:
            raise LookupError(f"no plugin {name!r} is attached to {self.NAME}")
        caller = self.traffic.actor(sys._getframe(1)) or self.NAME
        with self.traffic.timed(caller, name, "read" if hook in self.READ_HOOKS else "ask", hook):
            return plugin.ask(hook, *args, **kwargs)

    # -- who talks to whom (apps.traffic) ---------------------------------------------------------------------------
    def classify(self, method: str, path: str) -> str:
        """A request's class (traffic.CLASSES): a GET reads, anything else asks for a change; an app knows its streams
        and its asks."""
        return "read" if method == "GET" else "change"

    def known_ports(self) -> dict[int, str]:
        """This machine's ports of the framework's apps, by port (a link to one is drawn as that app); the frame knows
        none but its own."""
        return {}

    def plugin_node(self, p) -> dict:
        """A plugin as the connections picture draws it."""
        return {"id": p.name, "role": "plugin", "title": getattr(p, "title", "") or p.name, "icon": getattr(p, "ICON", "") or "plug",
                "state": "attached" if self._plugins.get(p.name) is p else "detached", "attached": self._plugins.get(p.name) is p}

    def connections(self, last: int = 200) -> dict:
        """Who talks to whom (`GET /api/traffic`): the app, its page, its login, its plugins and whatever they reached,
        as nodes; the links counted by class; the latest rows."""
        snap = self.traffic.snapshot(last)
        nodes: dict[str, dict] = {self.NAME: {"id": self.NAME, "role": "app", "title": self.TITLE or self.NAME,
                                              "icon": self.ICON or "chip", "sub": f"this app, at {self.served or self.url()}"}}
        if self.login is not None:
            try:
                d = self.login.describe()
            except Exception:  # noqa: BLE001 - a login that cannot say
                d = {}
            kind = str(d.get("kind") or type(self.login).__name__)
            sub = "the user's environment variables" if kind == "EnvironmentLogin" else "the login app" if kind == "LoginClient" else kind
            nodes["login"] = {"id": "login", "role": "login", "title": "Login", "icon": "lambda", "sub": sub,
                              "signedIn": bool(d.get("signedIn"))}
        for p in self._plugins.values():
            nodes[p.name] = self.plugin_node(p)
        for link in snap["links"]:
            for end in (link["from"], link["to"]):
                if end not in nodes:
                    nodes[end] = node_of(end)
        return {"app": self.NAME, **snap, "nodes": list(nodes.values())}

    def interface(self) -> dict:
        """What this app offers (the same shape a plugin gives of itself: `GET /api/interface`): its
        name and API version, the methods a plugin or another app may call on it."""
        methods = {}
        for name in ("describe", "tray", "plugins", "attach", "detach", "ask", "interface", "connections"):
            try:
                methods[name] = str(inspect.signature(getattr(self, name)))
            except (TypeError, ValueError):
                methods[name] = "(...)"
        return {"name": self.NAME, "kind": "app", "api": self.API, "login": self.login.describe() if self.login is not None else None,
                "plugins": sorted(self._plugins), "methods": methods}

    def touch(self) -> None:
        """A page is in touch (every request): what `serve(until_quiet=...)` waits on."""
        self.touched = time.monotonic()

    # -- what the app says about itself ----------------------------------------------------------
    def tray(self) -> Tray:
        """The app's tray: its master icon, then its plugins' (`items`)."""
        me = TrayItem(self.NAME, self.ICON, self.TITLE, "app", self.NAME)
        return Tray(self.NAME, self.ICON, self.TITLE, (me, *self.items()))

    def items(self) -> tuple[TrayItem, ...]:
        """The icons of the app's view plugins, in order (none in the frame)."""
        return ()

    def describe(self) -> dict:
        """What a client or a super app learns first (`GET /api/app`)."""
        return {"app": self.NAME, "title": self.TITLE, "icon": self.ICON, "api": self.API, "port": self.port(),
                "url": self.served or self.url()}

    def port(self) -> int:
        """The port to serve at: PORT_VAR in the environment when set to a number, else PORT."""
        raw = (os.environ.get(self.PORT_VAR) or "").strip() if self.PORT_VAR else ""
        return int(raw) if raw.isdecimal() else self.PORT

    def url(self, port: int | None = None) -> str:
        return f"http://127.0.0.1:{self.port() if port is None else port}/"

    def static_dirs(self) -> tuple[Path, ...]:
        """Where the page's files are looked for, in order: the app's own folder, then the library's."""
        return tuple(d for d in (self.STATIC, UI_STATIC) if d is not None)

    def page(self, handler) -> str:
        """The file "/" serves: INDEX; for an app that inherits a login app, its sign-in (the library's signin.html, the
        login app's page held in it) until the browser is signed in there (1.46.0). Without a login app answering, the
        app's page as before."""
        if self.login_url() is not None and self.signed_in(handler) is False:
            return SIGNIN
        return self.INDEX

    def page_files(self) -> set:
        """The files that are the page "/" serves, as the app's folders hold them: its INDEX and the sign-in (SIGNIN);
        asked for by their own names they are that page too (1.46.1)."""
        dirs = self.static_dirs()
        return {t for t in (web.static_target(self.INDEX, dirs), web.static_target(SIGNIN, dirs)) if t is not None}

    # -- the routes ------------------------------------------------------------------------------
    def api(self, handler, method: str, path: str, query: dict, body: dict | None):
        """The app's routes: returns (status, data) or (status, data, headers) for an /api/ request,
        or raises Refused. `handler` is the request (its headers: a cookie, a session); `body` is the
        JSON object of a write (an empty dict for none), None for a GET. The frame answers
        /api/tray and /api/app; a subclass answers its own first and falls back to this."""
        if method == "GET" and path == "/api/tray":
            return 200, self.tray().as_dict()
        if method == "GET" and path == "/api/app":
            return 200, self.describe()
        if method == "GET" and path == "/api/plugins":
            return 200, {"plugins": self.plugins()}
        if method == "GET" and path == "/api/interface":
            return 200, self.interface()
        if method == "GET" and path == PAIRS_PATH:  # what a login app this app inherits asks it (apps.login)
            return 200, {"pairs": self.login_pairs()}
        if method == "GET" and path == TRAFFIC_PATH:
            raw = str(query.get("last") or "200")
            return 200, self.connections(min(int(raw), 400) if raw.isdecimal() else 200)
        if method == "GET" and path == "/api/ui":  # the UI's preferences every page applies (ui/static/theme.js)
            from ..ui import preferences

            return 200, preferences()
        raise Refused(HTTPStatus.NOT_FOUND, "not found")

    # -- the server ------------------------------------------------------------------------------
    def start(self, port: int | None = None, open_browser: bool = False) -> str:
        """Serve in a thread of its own on `port` (the app's by default), or a free one when it is
        taken; returns the URL (`served`)."""
        port = self.port() if port is None else port
        if port and web.listening(port):  # a bind alone cannot tell on Windows (web.listening)
            self.log(f"{self.NAME}: port {port} is taken (another server answers there): a free one instead")
            port = 0
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(self))
        except OSError:
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self))
        self._httpd = httpd
        self.served = f"http://127.0.0.1:{httpd.server_address[1]}/"
        if self.WATCH_OUTSIDE:  # the programs and hosts it and its plugins reach, from now on
            self.traffic.watch({**self.known_ports(), httpd.server_address[1]: self.NAME})
        self._thread = threading.Thread(target=httpd.serve_forever, name=f"{self.NAME}-server", daemon=True)
        self._thread.start()
        self.log(f"{self.NAME}: its page at {self.served}")
        if open_browser:
            threading.Timer(0.5, webbrowser.open, args=(self.served,)).start()
        return self.served

    def stop(self) -> None:
        """End the server (the page stops answering)."""
        self.traffic.unwatch()
        httpd, self._httpd = self._httpd, None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if self._thread is not None:
            self._thread.join(5)
            self._thread = None

    def serve(self, port: int | None = None, open_browser: bool = False, stop: threading.Event | None = None,
              until_quiet: float | None = None) -> str:
        """`start`, then wait until `stop` is set, Ctrl+C, or (`until_quiet`, seconds) no request has
        come for that long (an app started by another app's front for itself ends again on its own);
        the server ends; returns the URL served."""
        url = self.start(port, open_browser)
        stop = stop or threading.Event()
        self.touch()
        try:
            while not stop.wait(0.5):
                if until_quiet is not None and time.monotonic() - self.touched > until_quiet:
                    self.log(f"{self.NAME}: no page has been in touch for {until_quiet:g} s: the server ends")
                    break
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            self.stop()
        return url


def attach_registry(app: App, only: str | None = None) -> list[str]:
    """Every plugin the registry loaded (the providers, the publishers, the assistants; `only`: one
    system, "integrator" or "platform") attached to `app` unless another app holds it already;
    returns the names attached. The registry is imported when called (it loads the plugins)."""
    from ..sources.registry import assistants, machines, providers, publishers

    out = []
    for p in [*providers().values(), *publishers().values(), *assistants().values(), *machines().values()]:
        if only is not None and p.SYSTEM != only:
            continue
        if p.app is not None and p.app is not app:
            continue
        app.attach(p)
        out.append(p.name)
    return out


def make_handler(app: App):
    """The requests of an app's page: the files from its folders, /api/ answered by `app.api`, only
    from this machine and the app's own pages; every write with the write header, a JSON object of
    at most MAX_BODY."""

    class Handler(BaseHTTPRequestHandler):
        server_version = f"liminal-{app.NAME}"

        def log_message(self, fmt, *args):  # keep the console quiet
            pass

        def do_GET(self) -> None:
            app.touch()
            if not web.local_only(self):
                return
            parts = urlsplit(self.path)
            if _is_login(parts.path) and app.login_url() is not None:  # the login app it inherits (1.46.0)
                if web.from_this_app(self):
                    self._login("GET")
                return
            if parts.path == "/api/trays" and app.login_url() is not None:
                if web.from_this_app(self):
                    web.send_json(self, {"trays": app.trays()})
                return
            if parts.path.startswith("/api/"):
                if web.from_this_app(self):
                    self._answer("GET", parts, None)
                return
            # the page at "/", or by its file's own name, or the sign-in's, however this machine's file system finds them
            # (1.46.1: /index.html, /Index.html or /index.html. on Windows was served whatever the sign-in said, and a
            # page opened there while signed out reloaded into itself, never the sign-in; /signin.html signed in, the
            # sign-in reloading into itself)
            dirs = app.static_dirs()
            rel = parts.path.lstrip("/")
            if not rel or web.static_target(rel, dirs) in app.page_files():
                rel = app.page(self)
            web.static_file(self, rel, dirs)

        def _login(self, method: str) -> None:
            """The request passed on to the login app this app inherits, as /<the rest>; its answer and its cookies
            back, their path kept (its session at /, so this app's page sends it and the app can ask who is in)."""
            bound = app.bound_login()
            if bound is None:
                raw = self.headers.get("Content-Length") or "0"
                if raw.isdecimal() and 0 < int(raw) <= web.MAX_BODY:
                    self.rfile.read(int(raw))
                return web.send_json(self, {"error": f"the login app of {app.NAME} is not running (none answers, none could "
                                                     "be started)"}, HTTPStatus.SERVICE_UNAVAILABLE)
            path = self.path[len(LOGIN_PREFIX):]
            if not path or path.startswith("?"):
                path = "/" + path
            forward(self, method, bound.url, path, unavailable="the login app does not answer; ask again shortly")

        def _write(self, method: str) -> None:
            app.touch()
            if not web.local_only(self) or not web.from_this_app(self):
                return
            if _is_login(urlsplit(self.path).path) and app.login_url() is not None:
                return self._login(method)  # the login app checks its own write header and reads its own body
            if self.headers.get(web.WRITE_HEADER) != "1":
                return web.send(self, HTTPStatus.FORBIDDEN, b"missing request header", "text/plain")
            parts = urlsplit(self.path)
            if not parts.path.startswith("/api/"):
                return web.send(self, HTTPStatus.NOT_FOUND, b"not found", "text/plain")
            raw = self.headers.get("Content-Length") or "0"
            length = int(raw) if raw.isdecimal() else -1
            if length < 0:
                return web.send_json(self, {"error": "bad Content-Length"}, HTTPStatus.BAD_REQUEST)
            if length > web.MAX_BODY:
                return web.send_json(self, {"error": "request too large"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            data = self.rfile.read(length) if length else b""
            body: dict = {}
            if data:
                try:
                    body = json.loads(data)
                except ValueError:
                    return web.send_json(self, {"error": "the body is not JSON"}, HTTPStatus.BAD_REQUEST)
                if not isinstance(body, dict):
                    return web.send_json(self, {"error": "the body must be a JSON object"}, HTTPStatus.BAD_REQUEST)
            self._answer(method, parts, body)

        def do_POST(self) -> None:
            self._write("POST")

        def do_PUT(self) -> None:
            self._write("PUT")

        def do_DELETE(self) -> None:
            self._write("DELETE")

        def _answer(self, method: str, parts, body: dict | None) -> None:
            query = {k: v[-1] for k, v in parse_qs(parts.query).items()}
            began, status = time.perf_counter(), HTTPStatus.INTERNAL_SERVER_ERROR
            try:
                try:
                    out = app.api(self, method, parts.path, query, body)
                except Refused as e:
                    status = e.status
                    return web.send_json(self, {"error": e.reason}, e.status)
                except Exception as e:  # noqa: BLE001 - the app's fault, logged there; the page gets no detail
                    app.log(f"{app.NAME}: {method} {parts.path} failed: {type(e).__name__}: {e}")
                    return web.send_json(self, {"error": f"{app.NAME} could not answer; see its log"},
                                         HTTPStatus.INTERNAL_SERVER_ERROR)
                status, data, *rest = out
                web.send_json(self, data, status, rest[0] if rest else None)
            finally:  # every request noted (its path, never its query or body) but the picture's own
                if parts.path != TRAFFIC_PATH:
                    app.traffic.record(_caller(self), app.NAME, app.classify(method, parts.path), f"{method} {parts.path}",
                                       (time.perf_counter() - began) * 1000, int(status) < 400)

    return Handler
