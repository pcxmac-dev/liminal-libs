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

import importlib
import inspect
import json
import os
import sys
import threading
import time
import webbrowser
from collections.abc import Mapping
from contextlib import nullcontext
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .. import jsonread
from .. import lifecycle
from .. import web
from ..lifecycle import Signal
from ..ui import STATIC as UI_STATIC
from . import asking
from .authorization import as_user
from .codebase import Codebase
from .login import PAIRS_PATH, pairs_wanted
from .traffic import RecordingLogin, Traffic, node_of
from .tray import Tray, TrayItem

TRAFFIC_PATH = "/api/traffic"  # what the app's page draws of who talks to whom: never noted itself
CODEBASE_PATH = "/api/codebase"  # its repositories, its code and how much of it is which language (apps.codebase)
APIS_PATH = "/api/app/apis"  # its own External and Internal API (1.63.0); ?plugin=NAME: an attached plugin's two
KEPT_INTERNAL = 256  # plugins' Internal APIs an app keeps at the most (App.plugin_internal), one for each object
SIGNIN = "signin.html"  # an app's sign-in while it inherits the login (ui/static, 1.46.0)
LOGIN_PREFIX = "/login"  # where an app serves the login it inherits
LOGIN_CLASS = "liminal_login.app:LoginApp"  # the login class an app inherits (liminal-login's), made here when first asked
# How an app is told to end, and its plugins asked what they are (1.86.0, Monday list item 38; liminal_libs.lifecycle and
# liminal_libs.stop), for an app that is not a liminal-net node yet: each with the proof of this user's key
# (lifecycle.PROOF_HEADER: what host.py's pipes and liminal-net's handshake authenticate with), a write with the write
# header too. Without the proof: 401; a wrong one: 403.
STOP_PATH = "/api/app/stop"  # TERM: POST {"timeout": s}
SIGNAL_PATH = "/api/app/signal"  # POST {"signal": "TERM" | "KILL", "timeout": s}
PROCESSES_PATH = "/api/app/processes"  # GET: what this app's process started (the ledger's rows of it)
PLUGIN_ASKS = ("status", "interface", "apis", "needs", "processes")  # GET /api/plugins/<name>/<what>: reads alone


def _is_login(path: str) -> bool:
    return path == LOGIN_PREFIX or path.startswith(LOGIN_PREFIX + "/")


def _caller(handler) -> str:
    """Who sent a request: the app's page in a browser (it names its origin), else a program."""
    h = handler.headers
    return "page" if (h.get("Origin") or h.get("Sec-Fetch-Site") or h.get("Referer")) else "client"


def _cards_of(obj) -> tuple[list, dict]:
    """What an app or a plugin associates with, as its External API draws it (1.63.0): its cards (liminal_libs.apis'
    as_dicts of its `apis`) and what it learned of them (facts_of); none when its declaration cannot be read or
    imported."""
    from ..apis import as_dicts, facts_of  # (plain: the standard library alone, no registry)

    try:
        apis = as_dicts(obj.apis)
    except Exception:  # noqa: BLE001 - a declaration that cannot be read (an apis.py that cannot be imported): none
        return [], {}
    return apis, facts_of(obj) if apis else {}


class Refused(Exception):
    """An answer the app refuses: its status and the reason, sent as {"error": reason}."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


class PortTaken(OSError):
    """An app's port held by another program: the app is not started there, and never on another port instead (the
    user, 2026-11-14: "i only want ports for liminal-login ; liminal-platform ; liminal-charts ; liminal-integrator";
    "never provide ports for anything else"). Until 1.52.0 a free one was taken in its place."""

    def __init__(self, app: "App", port: int, cause: BaseException | None = None):
        who = app.TITLE or app.NAME or "the app"
        why = f" ({cause})" if cause is not None else ""
        super().__init__(f"{who}: port {port} is taken{why}: something else answers there (is {who} running already?); "
                         "nothing was started on another port")
        self.port = port


class App:
    """The frame of one app. A subclass sets the class attributes and overrides `api` (its routes),
    `items` (its tray's plugins) and, when its page depends on the request, `page`. For its own two
    views (1.63.0) it declares `apis`, ROUTES, LINKED, CALLS, ATTRIBUTES and INTERNAL_NOTES; where it
    knows more of its plugins than the frame does, it says so in askable, known_plugins and call_words."""

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
    # its own two views (1.63.0; GET /api/app/apis): its External API, the cards of what it associates with (`apis`:
    # liminal_libs.apis' Api, declared in its own package; a property importing them when asked, where its start must
    # not load them) and what it learned of them (api_facts); its Internal API, made from the object by
    # liminal_libs.internal (internal, plugin_internal), with these words of its own
    apis: tuple = ()
    ROUTES: tuple = ()  # its own routes beside the frame's: (method, path, about[, kind[, who]]), a `{...}` part varies
    LINKED: tuple = ()  # the apps it links, each reached at its own address: (name, how[, variable[, prefix]])
    CALLS: Mapping[str, Mapping[str, str]] = {}  # what its own code calls on a plugin of each KIND: {kind: {name: how}}
    ATTRIBUTES: Mapping[str, tuple[str, ...]] = {}  # what its code reads of a plugin by name, never called: {kind: ()}
    INTERNAL_NOTES: tuple[str, ...] = ()  # a few lines more for its Internal API, each at most 400 characters
    # the login this app inherits (1.46.0; the user, 2026-11-10: "make sure that the platform inherits the login app so we
    # can login to platform"; 2026-11-14: "the platform and integrator inherit the login function, they are separate login
    # instances, class vs object"; "login doesn't point to anything except the app that inherited it"): since 1.52.0 an
    # object of the login class (LOGIN_CLASS) made for this app, here, in its process: its page and API under /login/ at
    # this app's own port, its tray at /api/trays, its users its own (the superclass's folder), the pairs its plugins ask
    # for asked of this app itself; this app's page its sign-in until the browser is signed in there. LOGIN_VAR "none" or
    # "off" in the environment: none. No login of its own at a port of its own, and nothing started for it.
    LOGIN = False
    LOGIN_VAR = ""
    LOGIN_CLASS: object = LOGIN_CLASS  # a class, or "module:Class"; made with log= and superclass= (this app)
    # 1.46-1.51's declaration (a login app of its own at an address of its own, started for this app): a class that still
    # names one inherits the login all the same, its address unused, LOGIN_URL_VAR's "none" or "off" honoured
    LOGIN_URL_VAR = ""
    LOGIN_URL = ""
    STOP_GRACE_S = lifecycle.GRACE_S  # its plugins' grace past their deadline at a TERM (1.87.0)

    def __init__(self, log=print, login=None):
        self.log = log
        self.login = login  # the authorization interface of this app's namespace (apps.authorization.Login)
        self.served: str | None = None  # the URL once started
        self.touched = time.monotonic()  # the last request (serve's until_quiet)
        self._plugins: dict[str, object] = {}  # the plugins attached, by name (attach)
        self._internal: dict[tuple, tuple] = {}  # what each plugin shares (plugin_internal), by (id, tabs): (it, that)
        self._internal_known: tuple = ()  # the plugins it knew when those were made (known_plugins)
        self._httpd: web.Server | None = None
        self._thread: threading.Thread | None = None
        self.traffic = Traffic()  # what is said, between whom (apps.traffic)
        self.traffic.me = self.NAME
        self.traffic.own(self, self.NAME)
        # the code this app is made of (apps.codebase, 1.59.0; the user, 2026-11-16: "this class will be added to all
        # the 'apps' just like connections"): nothing is read until its page asks
        self.codebase = Codebase(self)
        self._login_lock = threading.Lock()  # one login object made, however many pages ask at once
        self._login_object = None  # the login it inherits, once made (login_object)
        self._login_missing = False  # the login class could not be had: said once, not tried again
        # its end (1.86.0, terminate): once begun nothing new is taken; KILL may come while a TERM is under way
        self._lent: dict[str, object] = {}  # the login each plugin was attached with, by name (attach)
        self._term_lock = threading.Lock()
        self._terminating = False
        self._terminated: dict | None = None  # the report of its end, once ended
        self._kill_now = threading.Event()
        self._serving: threading.Event | None = None  # serve's stop, set once it has ended
        self.stop_timeout = lifecycle.TERM_TIMEOUT_S  # what a TERM gives its plugins and its processes (stop)

    # -- the login it inherits: an object here (1.46.0; 1.52.0) -------------------------------------------------------
    def inherits_login(self) -> bool:
        """Whether this app inherits the login: LOGIN (or a LOGIN_URL, 1.46-1.51's declaration), unless LOGIN_VAR (or
        LOGIN_URL_VAR) says "none" or "off" in the environment."""
        if not (self.LOGIN or self.LOGIN_URL):
            return False
        for var in (self.LOGIN_VAR, self.LOGIN_URL_VAR):
            if var and (os.environ.get(var) or "").strip().lower() in ("none", "off"):
                return False
        return True

    def login_object(self):
        """The login this app inherits: one object of the login class, made for this app here when first asked. None
        when it inherits none, or the class cannot be had or made (liminal-login not installed: said once in the log, the
        app's page then served as without a login)."""
        if not self.inherits_login():
            return None
        with self._login_lock:
            if self._login_object is None and not self._login_missing and not self._terminating:  # none made once ending
                try:
                    self._login_object = self.make_login()
                except Exception as e:  # noqa: BLE001 - not installed, a store that cannot open: the page as without one
                    self._login_missing = True
                    self.log(f"{self.NAME}: the login it inherits could not be made ({type(e).__name__}: {e}): no sign-in")
            return self._login_object

    def make_login(self):
        """The object of the login class (LOGIN_CLASS) for this app: its superclass is this app itself, the one thing it
        points to (its name and title, the pairs its plugins ask for); nothing is started and no port is opened for it."""
        cls = self.LOGIN_CLASS
        if isinstance(cls, str):
            module, _, name = cls.partition(":")
            cls = getattr(importlib.import_module(module), name)
        return cls(log=self.log, superclass=self)

    def signed_in(self, handler) -> bool | None:
        """Whether the browser of `handler` is signed in to the login this app inherits (its session asked of the login
        object, by that browser's cookie); None when it inherits none, or none could be made."""
        login = self.login_object()
        if login is None:
            return None
        try:
            return login.session(handler) is not None
        except Exception:  # noqa: BLE001 - a login that cannot say: as if there were none
            return None

    def user_login(self, handler):
        """The login of the person at the browser of `handler` (1.88.0, Monday list item 21: their preferences and
        licences are theirs): the session the login this app inherits gives that browser, as a Login (the login
        object's own user_login), else this app's login (`login`: an EnvironmentLogin keeps none, so the files are
        read as before). Never raises: a login that cannot say is as if none were signed in there."""
        login = self.login_object() if self.inherits_login() else None
        own = getattr(login, "user_login", None) if login is not None else None
        if callable(own):
            try:
                theirs = own(handler)
            except Exception:  # noqa: BLE001 - a login that cannot say: this app's login
                theirs = None
            if theirs is not None:
                return theirs
        return self.login

    def present(self, handler) -> bool | None:
        """Whether the person at the browser of `handler` is shown to be there, for a hook only its page may ask
        (PAGE_ONLY_HOOKS; apps.asking). The login's own proof of presence when it offers one (its present(handler)),
        else whether that browser is signed in to it (signed_in). True only when the proof says True: a login that
        cannot say, or a proof that fails, is False. None when this app holds no login: it inherits none, or none
        could be made. A login object that is itself an app has the frame's present() too: that one is not its proof."""
        login = self.login_object()
        try:
            prove = getattr(login, "present", None) if login is not None else None
        except Exception:  # noqa: BLE001 - a login that cannot say whether it has a proof proves nothing
            return False
        if callable(prove) and getattr(prove, "__func__", None) is not App.present:
            try:
                return prove(handler) is True
            except Exception:  # noqa: BLE001 - a proof that fails proves nothing
                return False
        said = self.signed_in(handler)
        if said is None:
            return None if login is None else False
        return said is True

    def trays(self) -> list[dict]:
        """The trays of what this app holds besides its own, for the foot of its rail: the login it inherits."""
        login = self.login_object()
        return [login.tray().as_dict()] if login is not None else []

    def lent_login(self):
        """The login this app lends its plugins: the one it was given (None when it was given none: its plugins then
        hold the environment's through Plugin.held_login, and behave as before 1.86.0)."""
        return self.login

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
        returns the interface the plugin offers (what `plugins` enumerates). A plugin that does not keep the login it
        was given (its attach put another in its place) is let go again and refused (1.86.0); so is any plugin while
        the app is ending."""
        if self._terminating:
            raise RuntimeError(f"{self.NAME} is ending: {plugin.name} is not attached")
        login = self.login_for(plugin.name)
        interface = plugin.attach(self, login)
        if getattr(plugin, "login", None) is not login:
            try:
                plugin.detach()
            finally:
                raise RuntimeError(f"{plugin.name} did not keep the login {self.NAME} attached it with: refused")
        self._plugins[plugin.name] = plugin
        self._lent[plugin.name] = login
        self.traffic.own(plugin, plugin.name)
        self.traffic.record(self.NAME, plugin.name, "attach", "attached")
        self.log(f"{self.NAME}: {plugin.name} attached ({plugin.KIND}; hooks {', '.join(interface['hooks']) or 'none'})")
        return interface

    def detach(self, name: str) -> bool:
        """The plugin of that name let go: it holds this app and its login no more; False when none is attached. An
        on-demand plugin's last client is its app: what it started (lifecycle.spawn, owned by its name) is told TERM
        with it and given its STOP_DEADLINE_S (1.86.0); what still runs then is reported, never killed (1.88.4)."""
        plugin = self._plugins.pop(name, None)
        if plugin is None:
            return False
        self._lent.pop(name, None)
        plugin.detach()
        lifecycle.end_owned(name, Signal.TERM, lifecycle.deadline_in(lifecycle.stop_deadline(plugin)))
        self.traffic.record(self.NAME, name, "attach", "detached")
        self.log(f"{self.NAME}: {name} detached")
        return True

    # -- its end (1.86.0, Monday list item 38; liminal_libs.lifecycle) ---------------------------------------------
    def parts(self) -> tuple:
        """The objects of a platform this app includes besides its login and its plugins (each told a signal after the
        login, before the plugins): the frame's, none."""
        return ()

    def owned_apps(self) -> tuple:
        """The objects of other apps it holds in its process (bound, not linked): told a signal after its plugins. The
        frame's, none."""
        return ()

    @property
    def stopping(self) -> bool:
        """Whether it is ending: nothing new is taken (a request is answered 503, a plugin is not attached)."""
        return self._terminating

    def terminate(self, sig=Signal.TERM, timeout: float | None = None, plugins: bool = True) -> dict:
        """The app ended in good order (TERM) or now (KILL). It refuses new work; passes the signal down to the login it
        includes, then each platform part (parts), then every plugin attached (each detached after), then every app
        object it owns (owned_apps); then ends the trees of the processes it started (the ledger's, its own and its
        plugins'), TERM, and what is left at `timeout` reported, never killed (1.88.4, "all shutdowns need to be
        clean"); KILL, asked for outright: at once, but never to a process that holds data (mongod, a host), which is
        asked to end cleanly instead; then its server. Each plugin is given its own STOP_DEADLINE_S within `timeout`,
        and one that misses it is reported late, its trees asked again (TERM) and left.
        Safe to call twice, from any thread: the second TERM returns the first's report; a KILL while a TERM is under
        way kills what was started at once. `plugins` False: its plugins are neither told nor let go here (an app whose
        own stop tells them itself: stop). Returns what came of each: {"app", "signal", "objects", "processes"}."""
        sig = Signal.of(sig)
        timeout = self.stop_timeout if timeout is None else timeout
        with self._term_lock:
            if self._terminated is not None:
                return self._terminated
            already = self._terminating
            self._terminating = True
            if sig is Signal.KILL:
                self._kill_now.set()
        if already:
            if sig is Signal.KILL:
                return {"app": self.NAME, "signal": sig.value, "objects": [],
                        "processes": lifecycle.end_owned(None, Signal.KILL, lifecycle.deadline_in(0))}
            return {"app": self.NAME, "signal": sig.value, "objects": [], "processes": [], "already": True}
        deadline = lifecycle.deadline_in(timeout)
        objects: list[dict] = []
        now = (lambda: Signal.KILL if self._kill_now.is_set() else sig)
        login = self._login_object
        if login is not None:
            objects.append(lifecycle.deliver(login, now(), deadline, sender=self, name="login"))
        for part in self.parts():
            objects.append(lifecycle.deliver(part, now(), deadline, sender=self))
        # its plugins told together, under one deadline and a grace (1.87.0): their own deadlines, the plugins' at most
        names = [n for n in list(self._plugins) if self._plugins.get(n) is not None] if plugins or now() is Signal.KILL \
            else []
        if names:
            longest = max(lifecycle.stop_deadline(self._plugins[n]) for n in names)
            together = min(deadline, lifecycle.deadline_in(min(longest, lifecycle.PLUGINS_DEADLINE_S)))
            objects += lifecycle.deliver_all([(n, self._plugins[n]) for n in names], now(), together, sender=self,
                                             grace=0.0 if now() is Signal.KILL else self.STOP_GRACE_S)
        for name in names:
            plugin = self._plugins.get(name)
            if plugin is None:
                continue
            if now() is Signal.KILL:
                self._plugins.pop(name, None)
                self._lent.pop(name, None)
                from ..sources.plugin import Plugin

                if isinstance(plugin, Plugin):
                    Plugin.detach(plugin)  # let go without its own detach, which may wait
            else:
                try:
                    self.detach(name)
                except Exception as e:  # noqa: BLE001 - the others are detached all the same
                    objects.append({"name": name, "how": "failed", "why": f"detach: {type(e).__name__}: {e}"})
        for other in self.owned_apps():
            objects.append(lifecycle.deliver(other, now(), deadline, sender=self))
        processes = lifecycle.end_owned(None, now(), deadline)
        self._end_server()
        with self._login_lock:
            self._login_object = None
        report = {"app": self.NAME, "signal": sig.value, "objects": objects, "processes": processes}
        with self._term_lock:
            self._terminated = report
        if self._serving is not None:
            self._serving.set()
        return report

    def signal(self, sig, deadline: float, sender=None) -> dict:
        """This app as an object another holds (the login an app includes, an app bound in its process): TERM, its
        own stop (`close` where it has one, which stops it), so a subclass's own end runs; KILL, terminate now."""
        sig = Signal.of(sig)
        if sig is Signal.KILL:
            return self.terminate(Signal.KILL, 0)
        self.stop_timeout = lifecycle.left(deadline)
        closing = getattr(self, "close", None)
        (closing if callable(closing) else self.stop)()
        return self._terminated or {"app": self.NAME, "signal": sig.value}

    def signal_plugin(self, name: str, sig) -> dict:
        """One attached plugin told `sig` by this app (the one way a signal reaches a plugin: through its app), then let
        go; within its STOP_DEADLINE_S: past it, it is late and its trees are asked again (TERM) and left, never killed
        (1.88.4). KILL, asked for outright, kills its trees at once, but never what holds data."""
        sig = Signal.of(sig)
        plugin = self._plugins.get(name)
        if plugin is None:
            raise LookupError(f"no plugin {name!r} is attached to {self.NAME}")
        deadline = lifecycle.deadline_in(lifecycle.stop_deadline(plugin))
        out = lifecycle.deliver(plugin, sig, deadline, sender=self, name=name, within=True)
        if sig is Signal.KILL:
            self._plugins.pop(name, None)
            self._lent.pop(name, None)
            from ..sources.plugin import Plugin

            if isinstance(plugin, Plugin):
                Plugin.detach(plugin)
            out["processes"] = lifecycle.end_owned(name, Signal.KILL, lifecycle.deadline_in(0))
        else:
            self.detach(name)
        return out

    def ask_plugin(self, name: str, what: str):
        """What a plugin is, asked by name, read alone (GET /api/plugins/<name>/<what>; a node's `ask`): its status
        (when it answers one and its status only reads), its interface, its APIs, its needs, its mode and deadlines,
        and what it started (the ledger's rows owned by its name, a command's secrets hidden)."""
        plugin = self._plugins.get(name)
        if plugin is None:
            raise LookupError(f"no plugin {name!r} is attached to {self.NAME}")
        return lifecycle.ask_of(plugin, what, ask=lambda hook: self.ask(name, hook),
                                apis=lambda: {"internal": self.plugin_internal(plugin), **dict(zip(("apis", "apiFacts"), _cards_of(plugin)))})

    def signal_key(self) -> bytes:
        """This user's key, the proof of a signal or an ask is made from (host.key: the pipes' and liminal-net's)."""
        from ..host import key

        return key()

    def proven(self, handler) -> None:
        """A signal's or an ask's proof checked: Refused 401 without it, 403 when it is not this user's key's."""
        given = handler.headers.get(lifecycle.PROOF_HEADER) if handler is not None else None
        if not given:
            raise Refused(HTTPStatus.UNAUTHORIZED, f"no proof of this user's key ({lifecycle.PROOF_HEADER})")
        if not lifecycle.proof_ok(self.signal_key(), given):
            raise Refused(HTTPStatus.FORBIDDEN, "not this user's key")

    def later(self, fn) -> None:
        """`fn` run once this request is answered (a signal's end, which stops the server answering it)."""
        threading.Timer(0.25, fn).start()

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
        calls (a plugin asking another through its app, else the app). A plugin that asks is the asker of that call
        (apps.asking): the hook reads its name with asking.asker(), never from an argument. The app's own code asks
        as whoever it asks for: the page, inside a route that says so, else no one. A hook the plugin says only other
        plugins ask (PLUGIN_ONLY_HOOKS), or only its page (PAGE_ONLY_HOOKS), is refused to any other asker, in words
        (asking.AskRefused), and noted as an ask that failed. A plugin named "page" asks as no one."""
        plugin = self._plugins.get(name)
        if plugin is None:
            raise LookupError(f"no plugin {name!r} is attached to {self.NAME}")
        who = self.traffic.actor(sys._getframe(1))
        caller = who or self.NAME
        held = nullcontext() if not who or who == self.NAME else asking.asking(None if who == asking.PAGE else who)
        with held, self.traffic.timed(caller, name, "read" if hook in self.READ_HOOKS else "ask", hook):
            asking.check(plugin, hook)
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
        """The file "/" serves: INDEX; for an app that inherits the login, its sign-in (the library's signin.html, the
        login's page held in it) until the browser is signed in there (1.46.0). Without a login object, the app's page
        as before."""
        if self.inherits_login() and self.signed_in(handler) is False:
            return SIGNIN
        return self.INDEX

    def page_files(self) -> set:
        """The files that are the page "/" serves, as the app's folders hold them: its INDEX and the sign-in (SIGNIN);
        asked for by their own names they are that page too (1.46.1)."""
        dirs = self.static_dirs()
        return {t for t in (web.static_target(self.INDEX, dirs), web.static_target(SIGNIN, dirs)) if t is not None}

    # -- its own External and Internal API, and its plugins' (1.63.0; the user, 2026-11-16: "for all apps, and all
    # plugins, there should be an external api tab, and an internal api tab"; 2026-11-17: "all plugins are middleware",
    # "even for other plugins", "and then the app object code") ---------------------------------------------------
    def api_facts(self) -> Mapping[str, Mapping[str, str]]:
        """What it learned of what it associates with while it ran, {api name (one of `apis`): {label: words}}, asking
        nothing to answer it, as a plugin's api_facts: the frame's, nothing learned."""
        return {}

    def routes(self) -> tuple:
        """Its own routes beside the frame's, as its Internal API lists them (ROUTES); an app whose routes depend on how
        it is served says so here."""
        return self.ROUTES

    def askable(self, plugin) -> set[str]:
        """The hooks of a plugin it asks by name, for its page, a client or another plugin: the frame's ask takes any
        hook the plugin answers itself (Plugin.interface, as Plugin.gives tells them), read here as the plugin declares
        them (liminal_libs.internal.answers), so nothing of it is called or evaluated."""
        from ..internal import answers  # (plain: the standard library alone)

        return set(answers(plugin))

    def known_plugins(self) -> list:
        """The plugins it knows, which what one asks of the others and who asks it are read from: the frame's, those
        attached."""
        return list(self._plugins.values())

    def call_words(self, plugin) -> dict:
        """How its code is asked one of a plugin's hooks, in words, for that plugin's Internal API: the frame's, by
        another plugin through its app's ask, the arguments as the hook takes them."""
        return {"plugins": f"self.app.ask({plugin.name!r}, hook, *arguments)", "terms": "any hook it answers"}

    def plugin_internal(self, plugin, tabs=None) -> dict:
        """What a plugin shares with this app, as this app's code works with it: its Internal API, made from the plugin
        object itself (liminal_libs.internal.internal_of). What this app says of its plugins goes with it: its
        READ_HOOKS, its CALLS and ATTRIBUTES for the plugin's KIND, askable, known_plugins and call_words, and `tabs`,
        its own list of the plugin's tabs (else the plugin's TABS). Nothing of the plugin is called by the frame's own
        parts (a subclass's askable, known_plugins and call_words are its own). Kept for the app's life, for that object
        alone and the tabs it was asked with (by its id and those tabs, the object held with it, so an id used again is
        never taken for it; KEPT_INTERNAL at the most), while the app knows the same plugins (what they ask of each
        other is read from them): the same dict each time, which a caller adding to it copies first."""
        from ..internal import internal_of, kind_of, tabs_key  # (plain: the standard library alone)

        known = self.known_plugins()
        known = list(known.values() if isinstance(known, Mapping) else known)
        held = self._internal_known
        if len(known) != len(held) or any(a is not b for a, b in zip(known, held)):
            self._internal.clear()  # a plugin attached or let go (the frame's known: those attached): made again
            self._internal_known = held = tuple(known)
        if tabs is not None and not isinstance(tabs, (tuple, list)):  # listed once: an iterator is read once
            try:
                tabs = [] if isinstance(tabs, (str, bytes, Mapping)) else list(tabs)
            except Exception:  # noqa: BLE001 - tabs that cannot be listed: none, as internal_of reads them
                tabs = []
        key = (id(plugin), tabs_key(plugin, tabs))  # the same object asked with other tabs: its answer made apart
        hit = self._internal.get(key)
        if hit is not None and hit[0] is plugin:
            return hit[1]
        kind = kind_of(plugin)
        calls = self.CALLS.get(kind, {}) if isinstance(self.CALLS, Mapping) else {}
        attributes = self.ATTRIBUTES.get(kind, ()) if isinstance(self.ATTRIBUTES, Mapping) else ()
        answer = internal_of(plugin, reads=self.READ_HOOKS, calls=calls, askable=self.askable(plugin), tabs=tabs,
                             known=known, words=self.call_words(plugin), attributes=attributes)
        if self._internal_known is not held:  # others came to be known while it was made: not kept, made again
            return answer
        if len(self._internal) >= KEPT_INTERNAL:  # more objects than an app holds plugins: made again, the old let go
            self._internal.clear()
        self._internal[key] = (plugin, answer)
        return answer

    def internal(self) -> dict:
        """This app's own Internal API, its object code's side (liminal_libs.internal.app_internal). What it calls and
        reads on its plugins of each kind and how it is asked for them; what it offers them and other apps; its routes,
        the login it includes, the apps it links and its plugins. Made when asked; nothing of a plugin is asked."""
        from ..internal import app_internal

        return app_internal(self)

    def own_apis(self) -> dict:
        """Its own two views, as GET /api/app/apis answers them: what a client learns of it first, its Internal API and
        its External API. `app` is describe(), `internal` is internal(), and `apis` and `apiFacts` are the cards of what
        it associates with and what it learned of them, the two keys a plugin's status carries, so a page draws both
        with the same calls. Made for each request, asking no plugin anything; a declaration that cannot be read or
        imported is none."""
        apis, facts = _cards_of(self)
        return {"app": self.describe(), "internal": self.internal(), "apis": apis, "apiFacts": facts}

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
        if method == "GET" and path == CODEBASE_PATH:  # read in a thread when first asked, kept, `fresh=1`: again
            return 200, self.codebase.snapshot(fresh=str(query.get("fresh") or "").lower() in ("1", "true", "yes"))
        if method == "POST" and path == CODEBASE_PATH + "/fetch":  # the user's click: the remotes asked what they have
            paths = (body or {}).get("paths")  # the repositories asked, by where they are; none named: every one
            return 202, self.codebase.fetch(paths if isinstance(paths, list) else None)
        if method == "GET" and path == "/api/ui":  # the UI's preferences every page applies (ui/static/theme.js)
            from ..ui import preferences

            return 200, preferences(login=self.user_login(handler))  # the asking person's (1.88.0)
        if method == "GET" and path == APIS_PATH:  # its own two views; ?plugin=NAME, an attached plugin's (1.63.0)
            name = str(query.get("plugin") or "")
            if not name:
                return 200, self.own_apis()
            plugin = self._plugins.get(name)
            if plugin is None:
                raise Refused(HTTPStatus.NOT_FOUND, f"no plugin {name!r} is attached to {self.NAME}")
            apis, facts = _cards_of(plugin)
            return 200, {"name": name, "internal": self.plugin_internal(plugin), "apis": apis, "apiFacts": facts}
        if path in (STOP_PATH, SIGNAL_PATH) and method == "POST":  # its end, asked with this user's key (1.86.0)
            self.proven(handler)
            body = body or {}
            try:
                sig = Signal.of(body.get("signal") or "TERM") if path == SIGNAL_PATH else Signal.TERM
            except ValueError as e:
                raise Refused(HTTPStatus.BAD_REQUEST, str(e)) from None
            raw = body.get("timeout")
            timeout = float(raw) if isinstance(raw, (int, float)) and raw >= 0 else self.stop_timeout
            if sig is Signal.TERM:
                self.stop_timeout = timeout
            self.later(self.stop if sig is Signal.TERM else (lambda: self.terminate(Signal.KILL, 0)))
            return 202, {"app": self.NAME, "signal": sig.value, "pid": os.getpid(), "timeout": timeout,
                         "plugins": sorted(self._plugins)}
        if method == "GET" and path == PROCESSES_PATH:
            self.proven(handler)
            return 200, {"app": self.NAME, "pid": os.getpid(), "processes": lifecycle.shown_rows(lifecycle.mine())}
        if path.startswith("/api/plugins/"):  # /api/plugins/<name>/<what>: a read; /api/plugins/<name>/signal: a write
            name, _, what = path[len("/api/plugins/"):].partition("/")
            if method == "POST" and what == "signal":
                self.proven(handler)
                try:
                    return 200, self.signal_plugin(name, (body or {}).get("signal") or "TERM")
                except ValueError as e:
                    raise Refused(HTTPStatus.BAD_REQUEST, str(e)) from None
                except LookupError as e:
                    raise Refused(HTTPStatus.NOT_FOUND, str(e)) from None
            if method == "GET" and what in (*PLUGIN_ASKS, "mode"):
                self.proven(handler)
                try:
                    return 200, self.ask_plugin(name, what)
                except LookupError as e:
                    raise Refused(HTTPStatus.NOT_FOUND, str(e)) from None
        raise Refused(HTTPStatus.NOT_FOUND, "not found")

    # -- the server ------------------------------------------------------------------------------
    def start(self, port: int | None = None, open_browser: bool = False) -> str:
        """Serve in a thread of its own on `port` (the app's by default; 0, any free one, is a test's); returns the URL
        (`served`). A port another program holds is refused (PortTaken), never traded for another (1.52.0). The server
        is web.Server, whose port is its own on every system: on Windows no later server can bind it while it serves."""
        port = self.port() if port is None else port
        with self._term_lock:  # started again after an end: a new life (1.86.0)
            self._terminating, self._terminated = False, None
            self._kill_now.clear()
        if port and web.listening(port):  # who holds it, said in words before the bind (web.Server's bind refuses too)
            raise PortTaken(self, port)
        try:
            httpd = web.Server(("127.0.0.1", port), make_handler(self))
        except OSError as e:
            raise PortTaken(self, port, e) from None
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
        """The app ended in good order: terminate(TERM) within stop_timeout (1.86.0; until then the server and the
        login object alone). A subclass that ends more of its own does it here and calls this."""
        # An app whose class has a stop of its own tells its plugins there, as it did before 1.86.0 (the platform's
        # tells each machine plugin once, enabled or not): they are not told a second time here
        self.terminate(Signal.TERM, self.stop_timeout, plugins=type(self).stop is App.stop)

    def _end_server(self) -> None:
        """End the server (the page stops answering)."""
        self.traffic.unwatch()
        httpd, self._httpd = self._httpd, None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(5)
        self._thread = None

    def serve(self, port: int | None = None, open_browser: bool = False, stop: threading.Event | None = None,
              until_quiet: float | None = None) -> str:
        """`start`, then wait until `stop` is set, Ctrl+C, or (`until_quiet`, seconds) no request has
        come for that long; the server ends; returns the URL served."""
        url = self.start(port, open_browser)
        stop = stop or threading.Event()
        self._serving = stop  # set by terminate: a signal's end ends the wait (1.86.0)
        # its stop event (1.87.0; Windows: a console-less pythonw hears no Ctrl+C and no SIGTERM): liminal-signal sets
        # it before it ends anything, and the app then ends in good order
        event = self.stop_event()
        self.touch()
        try:
            while not stop.wait(0.5):
                if until_quiet is not None and time.monotonic() - self.touched > until_quiet:
                    self.log(f"{self.NAME}: no page has been in touch for {until_quiet:g} s: the server ends")
                    break
                if event is not None and event.is_set():
                    self.log(f"{self.NAME}: asked to stop (its stop event): the server ends")
                    break
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            try:
                self.stop()
            finally:
                if event is not None:
                    event.close()
        return url

    def stop_event(self):
        """Its stop event (lifecycle.StopEvent, named after it), or None: none is held off Windows."""
        return lifecycle.StopEvent(lifecycle.stop_event_name(self.NAME)) if os.name == "nt" else None


def attach_registry(app: App, only: str | None = None) -> list[str]:
    """Every plugin the registry loaded (the providers, the publishers, the assistants, the machines, the
    databases, the auditors'; `only`: one system, "integrator" or "platform") attached to `app` unless another app
    holds it already; returns the names attached. The registry is imported when called (it loads the plugins)."""
    from ..sources.registry import assistants, auditors, databases, machines, providers, publishers

    out = []
    for p in [*providers().values(), *publishers().values(), *assistants().values(), *machines().values(),
              *databases().values(), *auditors().values()]:
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
            if _is_login(parts.path) and app.inherits_login():  # the login it inherits, an object here (1.52.0)
                if web.from_this_app(self):
                    self._login("GET")
                return
            if parts.path == "/api/trays" and app.inherits_login():
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
            """The request answered by the login object this app holds, as /<the rest>, here (serve_object): its
            answer and its cookies (at /, so this app's page sends them and the app can ask who is in)."""
            if app.stopping:  # ending: nothing new taken (1.86.0)
                web.drain(self)
                return web.send_json(self, {"error": f"{app.NAME} is ending"}, HTTPStatus.SERVICE_UNAVAILABLE)
            login = app.login_object()
            if login is None:
                web.drain(self)
                return web.send_json(self, {"error": f"{app.NAME} inherits the login, but it could not be made here "
                                                     "(see its log)"}, HTTPStatus.SERVICE_UNAVAILABLE)
            path = self.path[len(LOGIN_PREFIX):]
            if not path or path.startswith("?"):
                path = "/" + path
            serve_object(self, login, method, path)

        def _write(self, method: str) -> None:
            app.touch()
            if not web.local_only(self) or not web.from_this_app(self):
                return
            if _is_login(urlsplit(self.path).path) and app.inherits_login():
                return self._login(method)  # the login object checks its own write header and reads its own body
            if self.headers.get(web.WRITE_HEADER) != "1":  # (refused with its body read and dropped: web.refuse)
                return web.refuse(self, HTTPStatus.FORBIDDEN, b"missing request header")
            parts = urlsplit(self.path)
            if not parts.path.startswith("/api/"):
                return web.refuse(self, HTTPStatus.NOT_FOUND, b"not found")
            raw = self.headers.get("Content-Length") or "0"
            length = int(raw) if raw.isdecimal() else -1
            if length < 0:
                return web.send_json(self, {"error": "bad Content-Length"}, HTTPStatus.BAD_REQUEST)
            if length > web.MAX_BODY:
                return web.send_json(self, {"error": "request too large"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            data = self.rfile.read(length) if length else b""
            body: dict = {}
            if data:
                try:  # 1.75.2: nested past jsonread.MAX_DEPTH is refused alike on every Python
                    body = jsonread.loads(data)
                except (ValueError, RecursionError):  # nested too deep to read is not JSON here either (1.66.0)
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
            if app.stopping and parts.path not in (STOP_PATH, SIGNAL_PATH):  # ending: nothing new taken (1.86.0)
                return web.send_json(self, {"error": f"{app.NAME} is ending"}, HTTPStatus.SERVICE_UNAVAILABLE)
            query = {k: v[-1] for k, v in parse_qs(parts.query).items()}
            began, headers = time.perf_counter(), None
            try:
                # the asking person's login for the request's block (1.88.0): what their page reads or keeps of their
                # preferences (ui.preferences, a plugin's hook asked from it) is theirs, a second user's their own
                with as_user(app.user_login(self)):
                    status, data, *rest = app.api(self, method, parts.path, query, body)
                headers = rest[0] if rest else None
            except Refused as e:
                status, data = e.status, {"error": e.reason}
            except Exception as e:  # noqa: BLE001 - the app's fault, logged there; the page gets no detail
                app.log(f"{app.NAME}: {method} {parts.path} failed: {type(e).__name__}: {e}")
                status, data = HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{app.NAME} could not answer; see its log"}
            # every request noted (its path, never its query or body) but the picture's own, and noted before it is
            # answered (1.61.2): whoever asks the picture on the heels of this answer finds the request in it. Noted
            # after, as it was, the next request could be answered first, by another thread
            if parts.path != TRAFFIC_PATH:
                app.traffic.record(_caller(self), app.NAME, app.classify(method, parts.path), f"{method} {parts.path}",
                                   (time.perf_counter() - began) * 1000, int(status) < 400)
            web.send_json(self, data, status, headers)

    return Handler


def serve_object(handler, obj: App, method: str, path: str) -> None:
    """A request answered by another app's object held in this process (the login an app inherits: App.login_object), as
    if it had come to that object at `path` (the rest after its prefix): its files, its routes and its checks (this
    machine only, this page's own origin only, the write header and a JSON object of at most MAX_BODY on a write), its
    answer and its cookies back on the same connection. Nothing is forwarded, no other port is used and nothing is
    started (1.52.0; the user, 2026-11-14: "linking vs including the objects, is so that parts of the code can be
    executed remotely": an object included is answered here, an app linked is reached at its own address)."""
    cls = obj.__dict__.get("_inner_handler")
    if cls is None:
        cls = obj.__dict__["_inner_handler"] = make_handler(obj)
    inner = cls.__new__(cls)  # the request as it came (its connection, its headers), not read again
    inner.__dict__.update(handler.__dict__)
    inner.path = path
    try:
        if method == "GET":
            inner.do_GET()
        else:
            inner._write(method)
    finally:
        handler.close_connection = getattr(inner, "close_connection", getattr(handler, "close_connection", True))
