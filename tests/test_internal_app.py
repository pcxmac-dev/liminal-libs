"""liminal_libs.internal, an app's side (liminal-libs 1.63.0): an app's own Internal API is its object code's side,
what it calls and reads on its plugins of each kind and what it offers them and other apps (app_internal; DECISIONS.md
part C, addendum 14); the frame's routes, FRAME_ROUTES and LOGIN_ROUTES, held to the code answering them
(literals_in, route_problems); and the frame's own route for both views, GET /api/app/apis, with ?plugin=NAME for an
attached plugin's (apps/app.py), and the frame's parts behind it: what it says of its plugins (askable, known_plugins,
call_words, its CALLS and ATTRIBUTES) handed to the library, each plugin's answer kept, its own cards. On a DemoApp
with a stand-in login and stand-in plugins: no server is started, no login object is made, nothing is reached."""
from __future__ import annotations

import inspect
import json
import sys
from urllib.parse import urlsplit

import pytest

import liminal_libs.apps.app as frame
from liminal_libs import internal
from liminal_libs.apis import Api, Call, as_dicts
from liminal_libs.apps import App, Login, Unauthorized
from liminal_libs.apps.login import PAIRS_PATH
from liminal_libs.apps.tabs import Tab
from liminal_libs.machines.plugin import MachinePlugin

pytestmark = pytest.mark.usefixtures("no_outside")

MADE: list = []
FRAME_VIEWS = ("api_facts", "routes", "askable", "known_plugins", "call_words", "plugin_internal", "internal",
               "own_apis")  # the frame's methods for both views (apps/app.py, 1.63.0)


class StandInLogin(Login):
    NAMESPACE = "demo"

    def user(self) -> dict:
        return {"name": "ada"}

    def vector(self, name: str) -> str:
        raise Unauthorized("no pairs here")


class NeverMade:
    """A login class reading an app's Internal API must never make (App.login_object is never asked)."""

    def __init__(self, **kwargs):
        MADE.append(kwargs)


class Plug(MachinePlugin):
    """A machine plugin attached to the demo app."""

    name, title = "plug", "Plug"
    HOOKS = (*MachinePlugin.HOOKS, "poke")

    def poke(self, what):
        """A change."""
        return what


class DemoApp(App):
    NAME, TITLE, ICON, PORT_VAR = "demo", "Demo", "plug", "LIMINAL_DEMO_PORT"
    LOGIN, LOGIN_VAR, LOGIN_CLASS = True, "LIMINAL_DEMO_LOGIN", NeverMade
    TRACE_LOGIN = True
    READ_HOOKS = ("present", "status")
    ROUTES = (("GET", "/api/demo", "its own read"),
              ("POST", "/api/demo/{name}/poke", "a plugin poked", "ask", "page"),
              ("GET", "/api/tray", "its tray, said again by the app"))  # (one of the frame's: listed once, as its own)
    LINKED = (("integrator", "its data, at its own address", "LIMINAL_FETCHER_PORT"),
              ("platform", "the machine, under its own prefix", "LIMINAL_PLATFORM_URL", "/platform/"), ("bad",))
    CALLS = {"machine": {"status": "its state", "poke": "a poke"}, "feed": {"build": "its source"}}
    ATTRIBUTES = {"machine": ("name", "title", "ICON")}
    INTERNAL_NOTES = ("A note of the app's.",)

    def call_words(self, plugin) -> dict:
        return {"plugins": f"self.app.ask('{plugin.name}', hook, *arguments)",
                "clients": f"POST /api/demo/{plugin.name}/poke", "terms": "any hook it answers"}


def demo(monkeypatch, **env) -> DemoApp:
    for var in ("LIMINAL_DEMO_LOGIN", "LIMINAL_DEMO_PORT"):
        monkeypatch.delenv(var, raising=False)
    for var, value in env.items():
        monkeypatch.setenv(var, value)
    MADE.clear()
    return DemoApp(log=lambda m: None, login=StandInLogin())


def test_an_apps_internal_api_is_its_object_codes_side(monkeypatch):
    app = demo(monkeypatch)
    plug = Plug()
    app.attach(plug)
    got = internal.app_internal(app)
    assert json.loads(json.dumps(got)) == got
    assert (got["v"], got["of"], got["name"], got["title"], got["icon"], got["api"]) == (1, "app", "demo", "Demo",
                                                                                        "plug", "1.0")
    assert got["port"] == 0 and got["portVar"] == "LIMINAL_DEMO_PORT" and got["url"] == app.url()
    assert got["pluginApi"] == getattr(sys.modules.get("liminal_libs.sources.registry"), "PLUGIN_API", "")
    assert got["login"] == {"namespace": "demo", "signedIn": True, "kind": "StandInLogin"}
    # what its code calls and reads on its plugins of each kind, and the words it is asked in (NAME for the plugin)
    assert got["calls"] == {"machine": {"status": "its state", "poke": "a poke"}, "feed": {"build": "its source"}}
    assert got["attributes"] == {"machine": ["name", "title", "ICON"]} and got["reads"] == ["present", "status"]
    assert got["words"] == {"machine": {"plugins": "self.app.ask('NAME', hook, *arguments)",
                                        "clients": "POST /api/demo/NAME/poke", "terms": "any hook it answers"}}
    # what it offers: interface()'s eight methods, the login it lends, what it offers code
    assert [m["name"] for m in got["methods"]] == list(internal.APP_METHODS)
    ask = next(m for m in got["methods"] if m["name"] == "ask")
    assert ask["args"] == "(name, hook, *args, **kwargs)" and ask["line"].startswith("One attached plugin's hook")
    assert {m["name"] for m in got["offers"]} <= set(internal.OFFERS)
    lends = got["lends"]
    assert lends["traced"] is True and lends["kind"] == "StandInLogin"
    names = [m["name"] for m in lends["interface"]]
    assert {"user", "vector", "key", "account", "password", "has", "may", "save", "names", "variables", "signed_in",
            "describe"} <= set(names) and not any(n.startswith("_") for n in names)
    assert next(m for m in lends["interface"] if m["name"] == "signed_in")["property"] is True
    assert next(m for m in lends["interface"] if m["name"] == "key")["args"] == "(plugin)"
    # its routes: its own first, then the frame's, then the login's it inherits; each once
    routes = [(r["method"], r["path"], r["kind"], r["who"], r["own"]) for r in got["routes"]]
    assert routes[:3] == [("GET", "/api/demo", "read", "page", True),
                          ("POST", "/api/demo/{name}/poke", "ask", "page", True),
                          ("GET", "/api/tray", "read", "page", True)]
    frame_rows = [(r[0], r[1]) for r in (*internal.FRAME_ROUTES, *internal.LOGIN_ROUTES) if r[1] != "/api/tray"]
    assert [(m, p) for m, p, _k, _w, own in routes[3:]] == frame_rows and not any(own for *_x, own in routes[3:])
    assert got["counts"] == {"routes": 3 + len(frame_rows), "own": 3, "plugins": 1}
    assert got["includes"] == [{"name": "login", "on": True, "prefix": "/login/", "variable": "LIMINAL_DEMO_LOGIN",
                                "class": f"{NeverMade.__module__}:NeverMade", "how": got["includes"][0]["how"]}]
    assert "/login/" in got["includes"][0]["how"] and MADE == []  # the login it includes was never made
    assert got["linked"] == [
        {"name": "integrator", "how": "its data, at its own address", "variable": "LIMINAL_FETCHER_PORT", "prefix": ""},
        {"name": "platform", "how": "the machine, under its own prefix", "variable": "LIMINAL_PLATFORM_URL",
         "prefix": "/platform/"}]
    assert got["plugins"] == [{"name": "plug", "title": "Plug", "kind": "machine", "system": "platform",
                               "pluginApi": "2.0", "attached": True, "builtOn": internal.built_on(plug)}]
    assert got["plugins"][0]["builtOn"]["class"] == "MachinePlugin"
    assert got["notes"] == ["A note of the app's."]


def test_an_app_that_inherits_no_login_lists_neither_its_routes_nor_includes_it_on(monkeypatch):
    app = demo(monkeypatch, LIMINAL_DEMO_LOGIN="none")
    got = internal.app_internal(app)
    paths = [r["path"] for r in got["routes"]]
    assert "/api/trays" not in paths and "/login/{rest}" not in paths and "/api/app/apis" in paths
    assert got["includes"][0]["on"] is False and "(off here: LIMINAL_DEMO_LOGIN says 'none')" in got["includes"][0][
        "how"]
    assert MADE == []


class BothSwitches(App):
    """An app with both of the frame's switches for the login it inherits (LOGIN_VAR, and 1.46-1.51's LOGIN_URL_VAR)."""

    NAME = "both"
    LOGIN, LOGIN_VAR, LOGIN_URL_VAR, LOGIN_CLASS = True, "LIMINAL_BOTH_LOGIN", "LIMINAL_BOTH_LOGIN_URL", NeverMade


def test_the_login_it_includes_is_said_off_by_the_switch_that_says_so_in_its_words(monkeypatch):
    for var in ("LIMINAL_BOTH_LOGIN", "LIMINAL_BOTH_LOGIN_URL"):
        monkeypatch.delenv(var, raising=False)
    MADE.clear()
    on = internal.app_internal(BothSwitches(log=lambda m: None))["includes"][0]
    assert (on["on"], on["variable"]) == (True, "LIMINAL_BOTH_LOGIN") and "off here" not in on["how"]
    monkeypatch.setenv("LIMINAL_BOTH_LOGIN_URL", "Off")  # the second switch, in its own case (inherits_login's rule)
    off = internal.app_internal(BothSwitches(log=lambda m: None))["includes"][0]
    assert (off["on"], off["variable"]) == (False, "LIMINAL_BOTH_LOGIN_URL")
    assert off["how"].endswith(" (off here: LIMINAL_BOTH_LOGIN_URL says 'Off')")
    monkeypatch.setenv("LIMINAL_BOTH_LOGIN", "none")  # both say so: the first is named
    first = internal.app_internal(BothSwitches(log=lambda m: None))["includes"][0]
    assert first["variable"] == "LIMINAL_BOTH_LOGIN" and first["how"].endswith("LIMINAL_BOTH_LOGIN says 'none')")
    assert MADE == []


def test_a_bare_app_gets_the_frames_routes_and_an_answer_whatever_cannot_be_read(monkeypatch):
    class Bare(App):
        NAME = "bare"

    got = internal.app_internal(Bare(log=lambda m: None))
    assert [(r["method"], r["path"]) for r in got["routes"]] == [(r[0], r[1]) for r in internal.FRAME_ROUTES]
    assert got["login"] is None and got["lends"] is None and got["includes"] == [] and got["plugins"] == []
    assert got["calls"] == {} and got["words"] == {} and got["counts"] == {"routes": len(internal.FRAME_ROUTES),
                                                                          "own": 0, "plugins": 0}

    class Faulty(DemoApp):
        def routes(self):
            raise RuntimeError("its routes depend on how it is served")

        def call_words(self, plugin):
            raise RuntimeError("no words")

        def known_plugins(self):
            return [Plug()]

    app = Faulty(log=lambda m: None, login=StandInLogin())
    monkeypatch.delenv("LIMINAL_DEMO_LOGIN", raising=False)
    got = internal.app_internal(app)
    assert not any(r["own"] for r in got["routes"]) and got["words"] == {}
    assert [(p["name"], p["attached"]) for p in got["plugins"]] == [("plug", False)]  # known, not attached
    assert json.loads(json.dumps(got)) == got


def test_routes_rows_take_classifys_default_and_say_who_asks():
    assert internal._route(("GET", "/api/x", "a read")) == {"method": "GET", "path": "/api/x", "about": "a read",
                                                            "kind": "read", "who": "page"}
    assert internal._route(("post", "/api/x", "a change"))["kind"] == "change"  # GET reads, anything else changes
    assert internal._route({"method": "POST", "path": "/api/x/ask", "about": "", "kind": "ask", "who": "client"}) == {
        "method": "POST", "path": "/api/x/ask", "about": "", "kind": "ask", "who": "client"}
    assert internal._route(("GET", "no slash", "x")) is None and internal._route(("GET",)) is None


# -- a table of routes held to its code -------------------------------------------------------------------------
def test_the_frames_routes_are_held_to_the_code_that_answers_them():
    literals = internal.literals_in(inspect.getsource(frame)) | {PAIRS_PATH}  # its whole module: its constants too
    table = (*internal.FRAME_ROUTES, *internal.LOGIN_ROUTES)
    assert {"/api/tray", "/api/app", "/api/plugins", "/api/interface", "/api/traffic", "/api/codebase", "/api/ui",
            "/api/trays"} <= literals
    assert internal.route_problems(table, literals) == []
    assert internal.route_problems(table, literals | {"/api/nothing"}) == [
        "the code answers /api/nothing, which the table does not list"]
    assert internal.route_problems((*table, ("GET", "/api/ghost/{id}", "a ghost")), literals) == [
        "the table lists GET /api/ghost/{id}, which the code does not answer"]
    assert internal.route_problems((*table, ("GET", "/api/apps", "not under /api/app")), literals) == [
        "the table lists GET /api/apps, which the code does not answer"]


def test_a_tables_rows_are_said_wrong_in_words():
    rows = (("GET", "/api/a", "a"), ("GET", "/api/a", "again"), ("FETCH", "/api/b", "b"),
            ("GET", "/api/c", "c", "reads"), ("GET", "/api/d", "d", "read", "browser"), ("GET",), "x")
    assert internal.route_problems(rows, {"/api/a", "/api/b", "/api/c", "/api/d"}) == [
        "the table lists GET /api/a twice",
        "the table's FETCH /api/b: its method is not one of GET, POST, PUT, DELETE, ANY",
        "the table's GET /api/c: its class 'reads' is not one of read, change, ask, stream",
        "the table's GET /api/d: who asks it, 'browser', is not one of page, client, plugin, app, login",
        "the table's row ('GET',) is not (method, path, about[, kind[, who]])",
        "the table's row 'x' is not (method, path, about[, kind[, who]])"]


def test_literals_are_strings_constants_and_lists_of_a_paths_parts():
    source = '''
TRAFFIC = "/api/traffic"


def api(path, parts, name):
    if path == "/api/app" or path.startswith("/api/machines/"):
        return 1
    if parts[:4] == ["", "api", "plugins", "plan"] or parts == ("", "api", "x"):
        return 2
    if path == f"/api/items/{name}":
        return 3
    if path.startswith("/api/"):  # the bare prefix: no route
        return 4
    return "not a path: /api/x in words"
'''
    assert internal.literals_in(source) == {"/api/traffic", "/api/app", "/api/machines/", "/api/plugins/plan",
                                            "/api/x", "/api/items/"}
    assert internal.literals_in("    def api(self):\n        return '/api/indented'\n") == {"/api/indented"}
    assert internal.literals_in("fetch('/api/status').then((r) => r.json()); const t = `/api/x/${n}`;") == {
        "/api/status"}  # a page script: its quoted paths
    assert internal.literals_in("", "x = '/api/one'", "y = '/api/two'") == {"/api/one", "/api/two"}


# -- the frame's own route for both views (apps/app.py) -----------------------------------------------------------
def test_interface_keeps_its_eight_methods(monkeypatch):
    app = demo(monkeypatch)
    assert set(app.interface()["methods"]) == set(internal.APP_METHODS)


def test_the_frame_answers_its_own_two_views_and_an_attached_plugins(monkeypatch):
    app = demo(monkeypatch)
    plug = Plug()
    app.attach(plug)
    status, data = app.api(None, "GET", "/api/app/apis", {}, None)[:2]
    assert status == 200 and set(data) == {"app", "internal", "apis", "apiFacts"}
    assert data["app"] == app.describe() and data["internal"]["of"] == "app" and data["apis"] == []
    assert data["apiFacts"] == {} and json.loads(json.dumps(data)) == data
    status, data = app.api(None, "GET", "/api/app/apis", {"plugin": "plug"}, None)[:2]
    assert status == 200 and {"name", "internal", "apis", "apiFacts"} <= set(data)
    assert data["name"] == "plug" and data["internal"]["of"] == "plugin" and data["internal"]["name"] == "plug"
    with pytest.raises(frame.Refused) as refused:
        app.api(None, "GET", "/api/app/apis", {"plugin": "nobody"}, None)
    assert refused.value.status == 404


def test_an_apps_own_apis_that_cannot_be_read_are_none(monkeypatch):
    class Broken(DemoApp):
        @property
        def apis(self):
            raise ImportError("its apis.py is not there")

    monkeypatch.delenv("LIMINAL_DEMO_LOGIN", raising=False)
    assert Broken(log=lambda m: None, login=StandInLogin()).own_apis()["apis"] == []


def test_the_frames_words_and_who_it_asks_by_default(monkeypatch):
    app = demo(monkeypatch)
    plug = Plug()
    app.attach(plug)
    assert App.call_words(app, plug) == {"plugins": "self.app.ask('plug', hook, *arguments)",
                                         "terms": "any hook it answers"}
    assert app.askable(plug) == set(plug.interface()["hooks"])
    assert list(app.known_plugins()) == [plug]
    assert app.internal()["of"] == "app"


def test_a_plugins_internal_api_is_kept_for_that_plugin_alone(monkeypatch):
    app = demo(monkeypatch)
    plug, other = Plug(), Plug()
    first = app.plugin_internal(plug)
    assert app.plugin_internal(plug) is first and first["of"] == "plugin"
    app._internal[(id(other), None)] = (plug, first)  # another object under the same id: never taken for it
    assert app.plugin_internal(other) is not first


class Paged(MachinePlugin):
    """A machine plugin with a tab of its own."""

    name, title = "paged", "Paged"
    HOOKS = (*MachinePlugin.HOOKS, "prod", "page")
    TABS = (Tab("page", "Page", "page", 3.0),)

    def prod(self, what):
        """A change."""

    def page(self):
        """Its tab's page."""


def test_a_plugins_answer_is_kept_for_the_tabs_it_was_asked_with(monkeypatch):
    """The same object asked with the app's own list of its tabs, with none given (its TABS) and with an empty list
    (no tab shown): each answer says the tabs it was asked with, as internal_of makes it, and each is kept apart."""
    app = demo(monkeypatch)
    paged = Paged()
    app.attach(paged)
    other = [{"id": "other", "title": "Other", "hook": "prod", "every": 9.0}]
    first = app.plugin_internal(paged)
    mine = app.plugin_internal(paged, tabs=other)
    none = app.plugin_internal(paged, tabs=[])
    assert first["tabs"] == [{"id": "page", "title": "Page", "hook": "page", "every": 3.0}]
    assert mine["tabs"] == internal.internal_of(paged, tabs=other)["tabs"] == other and none["tabs"] == []
    kinds = [{h["name"]: h["kind"] for h in d["hooks"]} for d in (first, mine, none)]
    assert [(k["page"], k["prod"]) for k in kinds] == [("tab", "change"), ("change", "tab"), ("change", "change")]
    assert app.plugin_internal(paged) is first and app.plugin_internal(paged, tabs=list(other)) is mine
    assert app.plugin_internal(paged, tabs=()) is none
    assert app.plugin_internal(paged, tabs=(t for t in other)) is mine  # an iterator, listed once: the same tabs
    status, via_route = app.api(None, "GET", "/api/app/apis", {"plugin": "paged"}, None)[:2]  # no tabs: its TABS
    assert status == 200 and via_route["internal"] is first


class Gauged(MachinePlugin):
    """A machine plugin whose hooks are properties, each counting its reads."""

    name, title = "gauged", "Gauged"
    HOOKS = (*MachinePlugin.HOOKS, "gauge", "peek")
    seen: list = []

    @property
    def gauge(self):
        """A hook that is a property, counting its reads."""
        Gauged.seen.append("gauge")
        return lambda: 1

    @property
    def peek(self):
        """Another hook that is a property."""
        Gauged.seen.append("peek")
        return lambda: 2


def test_the_frames_own_parts_evaluate_nothing_of_a_plugin(monkeypatch):
    """S1 through the frame (App.askable, App.plugin_internal, both views): a hook that is a property is said as one
    and never read; what it answers is read as it declares it, so its interface() is never called (Plugin.interface
    reads each hook it lists)."""
    Gauged.seen.clear()
    app = demo(monkeypatch)
    gauged = Gauged()
    app.attach(gauged)  # (the frame's attach records its interface, as it always has: both read there)
    assert sorted(Gauged.seen) == ["gauge", "peek"]
    Gauged.seen.clear()
    assert app.askable(gauged) == {"gauge", "peek"}
    d = app.plugin_internal(gauged)
    rows = {h["name"]: h for h in d["hooks"]}
    assert (rows["gauge"]["property"], rows["gauge"]["askable"], rows["gauge"]["users"]) == (True, True, "named")
    assert app.own_apis()["internal"]["plugins"][0]["name"] == "gauged"
    assert app.api(None, "GET", frame.APIS_PATH, {"plugin": "gauged"}, None)[0] == 200
    assert Gauged.seen == []

    class Asked(Gauged):
        def interface(self):
            Gauged.seen.append("interface")
            raise RuntimeError("asked")

    assert app.askable(Asked()) == {"gauge", "peek"} and app.plugin_internal(Asked())["name"] == "gauged"
    assert Gauged.seen == []


class Named(MachinePlugin):
    """A machine plugin given a name that is also a word of the app's words (set on the instance, as with_ does)."""

    title = "Named"


class PlatformLike(DemoApp):
    def call_words(self, plugin) -> dict:  # the platform's, word for word (its PlatformApp.call_words)
        if getattr(plugin, "KIND", "") != "machine" or not isinstance(plugin, MachinePlugin):
            return {"terms": "nothing by name"}
        return {"plugins": f"self.app.ask({plugin.name!r}, hook, [arguments])",
                "clients": f'POST /api/machines/{plugin.name}/ask {{"hook": hook, "args": [arguments]}}',
                "terms": f"one of {plugin.name}'s hooks, while it is enabled"}


def test_the_apps_words_say_NAME_for_the_plugin_whatever_it_is_named(monkeypatch):
    """The words are asked of the plugin seen under the name NAME: nothing is replaced in them afterwards, so a plugin
    named as a path's part or a key of them leaves the rest whole; the app's own checks of the plugin still hold."""
    monkeypatch.delenv("LIMINAL_DEMO_LOGIN", raising=False)
    for name in ("api", "machines", "hook", "args", "NAME", "plug"):
        app = PlatformLike(log=lambda m: None, login=StandInLogin())
        plugin = Named(name=name)
        app.attach(plugin)
        words = internal.app_internal(app)["words"]["machine"]
        assert words == {"plugins": "self.app.ask('NAME', hook, [arguments])",
                         "clients": 'POST /api/machines/NAME/ask {"hook": hook, "args": [arguments]}',
                         "terms": "one of NAME's hooks, while it is enabled"}, name
        assert app.call_words(plugin)["plugins"] == f"self.app.ask({name!r}, hook, [arguments])"  # the plugin as it is
        assert plugin.name == name


# -- the frame's parts behind both views (apps/app.py, 1.63.0) --------------------------------------------------
CARD = Api("Demo's command line", "The demo's makers", "what the demo app runs", kind="command", base="demo",
           calls=(Call("demo --version", "its version", used="to say which it is"),), verified="2026-11-17")


class Nudged(MachinePlugin):
    """A machine plugin with a hook the demo app's code does not call: asked by name alone."""

    name, title = "nudged", "Nudged"
    HOOKS = (*MachinePlugin.HOOKS, "nudge")

    def nudge(self):
        """Nudged, by name."""
        return True


class Asker(MachinePlugin):
    """A machine plugin asking another of the demo app's plugins for one of its hooks."""

    name, title = "asker", "Asker"
    ASKS = (("plug", "poke", "to poke it"),)


class Counted(MachinePlugin):
    """A machine plugin noting each hook asked of it, with cards and what it learned of them: reading what it shares,
    and its cards, asks it nothing."""

    name, title = "counted", "Counted"
    HOOKS = (*MachinePlugin.HOOKS, "poke")
    asked: list = []

    def present(self):
        """Whether it is there."""
        Counted.asked.append("present")
        return True

    def status(self):
        """Its state."""
        Counted.asked.append("status")
        return {}

    def poke(self, what):
        """A change."""
        Counted.asked.append("poke")
        return what

    @property
    def apis(self):
        return (CARD,)

    def api_facts(self):
        return {CARD.name: {"version": 3}}


class Feedish(MachinePlugin):
    """A plugin of another kind (a feed's, by its KIND): what the demo app calls on a machine plugin is not its."""

    KIND, name = "feed", "feedish"


class Mute(MachinePlugin):
    """A machine plugin that cannot say what it answers."""

    name = "mute"

    def interface(self):
        raise RuntimeError("it cannot say")


class Bare(App):
    NAME = "bare"


def test_the_frame_has_both_views_and_declares_nothing_of_its_own():
    assert all(callable(getattr(App, n, None)) for n in FRAME_VIEWS)  # (a frame without one fails here, never skips)
    assert (App.apis, App.ROUTES, App.LINKED, App.INTERNAL_NOTES, App.CALLS, App.ATTRIBUTES) == ((), (), (), (), {},
                                                                                                    {})
    assert frame.APIS_PATH == "/api/app/apis" and ("GET", frame.APIS_PATH) in {r[:2] for r in internal.FRAME_ROUTES}
    app = Bare(log=lambda m: None)
    assert app.api_facts() == {} and app.routes() is App.ROUTES and app.known_plugins() == []
    assert app.own_apis() == {"app": app.describe(), "internal": internal.app_internal(app), "apis": [],
                              "apiFacts": {}}
    assert app.api(None, "GET", frame.APIS_PATH, {"plugin": ""}, None) == (200, app.own_apis())  # no name: its own
    assert app.classify("GET", frame.APIS_PATH) == "read"  # noted as a read in who talks to whom
    with pytest.raises(frame.Refused) as refused:
        app.api(None, "POST", frame.APIS_PATH, {}, {})  # read only
    assert refused.value.status == 404


def test_a_plugins_internal_api_carries_what_the_app_says_of_its_plugins(monkeypatch):
    app = demo(monkeypatch)
    plug, nudged, asker = Plug(), Nudged(), Asker()
    for p in (plug, nudged, asker):
        app.attach(p)
    d = app.plugin_internal(plug)
    assert json.loads(json.dumps(d)) == d and (d["of"], d["name"]) == ("plugin", "plug")
    rows = {h["name"]: h for h in d["hooks"]}
    # what the app's code calls on a machine plugin (CALLS), how it is asked (call_words), what it reads (ATTRIBUTES)
    assert (rows["poke"]["how"], rows["status"]["how"], rows["present"]["how"]) == ("a poke", "its state", "")
    assert (rows["poke"]["users"], rows["poke"]["askable"], rows["poke"]["askedBy"]) == ("app", True, ["asker"])
    assert d["calls"] == app.call_words(plug) and d["calls"]["clients"] == "POST /api/demo/plug/poke"
    assert d["attributes"] == ["name", "title", "ICON"] and d["declares"] == {"ICON": Plug.ICON}
    # its READ_HOOKS: asked as reads; the hooks it answers are asked by name (the frame's ask: askable)
    assert (rows["status"]["reads"], rows["poke"]["reads"]) == (True, False)
    assert {h["name"] for h in d["hooks"] if h["askable"]} == app.askable(plug) == {"poke"}
    n = {h["name"]: h for h in app.plugin_internal(nudged)["hooks"]}
    assert (n["nudge"]["users"], n["nudge"]["how"], n["nudge"]["askedBy"]) == ("named", "", [])
    a = app.plugin_internal(asker)  # what it asks of another, and what it finds among the app's plugins
    assert a["asks"] == [{"plugin": "plug", "hook": "poke", "why": "to poke it",
                          "here": "a hook there, not said to be a service"}]
    # the app's own list of a plugin's tabs, when it gives one
    t = {h["name"]: h for h in app.plugin_internal(Plug(), tabs=[{"id": "t", "title": "T", "hook": "poke"}])["hooks"]}
    assert (t["poke"]["kind"], t["poke"]["tab"], t["poke"]["reads"]) == ("tab", "t", True)
    # CALLS and ATTRIBUTES are taken by the plugin's KIND: a feed's, not a machine plugin's ("build", which it has not)
    f = app.plugin_internal(Feedish())
    assert all(h["how"] == "" for h in f["hooks"]) and f["attributes"] == [] and f["also"] == []


def test_an_app_whose_words_are_odd_or_whose_plugin_cannot_say_still_answers(monkeypatch):
    class Odd(DemoApp):
        CALLS, ATTRIBUTES = None, ("name",)

    class Quiet(DemoApp):
        def askable(self, plugin):
            return set()  # (an app that asks its plugins nothing by name)

    monkeypatch.delenv("LIMINAL_DEMO_LOGIN", raising=False)
    d = Odd(log=lambda m: None, login=StandInLogin()).plugin_internal(Plug())
    assert all(h["how"] == "" for h in d["hooks"]) and d["attributes"] == [] and d["also"] == []
    q = {h["name"]: h for h in Quiet(log=lambda m: None, login=StandInLogin()).plugin_internal(Nudged())["hooks"]}
    assert (q["nudge"]["askable"], q["nudge"]["users"]) == (False, "")  # what the app says it asks, not the frame's
    app = demo(monkeypatch)
    assert app.askable(Mute()) == set()  # it answers nothing itself, read as declared: its interface() never asked
    assert not any(h["askable"] for h in app.plugin_internal(Mute())["hooks"])


def test_the_kept_answers_are_bounded_and_one_made_again_is_the_same(monkeypatch):
    monkeypatch.setattr(frame, "KEPT_INTERNAL", 2)
    app = demo(monkeypatch)
    plugs = [Plug() for _ in range(3)]
    first = app.plugin_internal(plugs[0])
    app.plugin_internal(plugs[1])
    assert len(app._internal) == 2
    app.plugin_internal(plugs[2])  # past the bound: those kept are let go
    assert len(app._internal) <= 2 and app._internal[(id(plugs[2]), None)][0] is plugs[2]
    again = app.plugin_internal(plugs[0])
    assert again is not first and again == first  # made again from the same object: the same words
    assert app.plugin_internal(plugs[0]) is again


def test_a_plugins_answer_is_made_again_when_the_app_knows_other_plugins(monkeypatch):
    app = demo(monkeypatch)
    plug = Plug()
    app.attach(plug)
    app.attach(Nudged())
    before = app.plugin_internal(plug)
    assert app.plugin_internal(plug) is before and {h["name"]: h for h in before["hooks"]}["poke"]["askedBy"] == []
    app.detach("nudged")
    app.attach(Asker())  # as many plugins, another one (the frame knows those attached): who asks its poke, again
    after = app.plugin_internal(plug)
    assert after is not before and {h["name"]: h for h in after["hooks"]}["poke"]["askedBy"] == ["asker"]
    assert app.plugin_internal(plug) is after
    app.detach("asker")
    assert {h["name"]: h for h in app.plugin_internal(plug)["hooks"]}["poke"]["askedBy"] == []

    asker = Asker()

    class Listed(DemoApp):
        def known_plugins(self):  # (an app may give them by name)
            return {"plug": plug, "asker": asker}

    monkeypatch.delenv("LIMINAL_DEMO_LOGIN", raising=False)
    listed = Listed(log=lambda m: None, login=StandInLogin())
    assert {h["name"]: h for h in listed.plugin_internal(plug)["hooks"]}["poke"]["askedBy"] == ["asker"]


def test_an_answer_made_while_the_app_came_to_know_another_plugin_is_given_not_kept(monkeypatch):
    """A race tested by its order: while one plugin's answer is made, another plugin is attached and a second request
    asks for its answer; the first, made with what the app knew before, is given but not kept."""
    app = demo(monkeypatch)
    plug, asker = Plug(), Asker()
    app.attach(plug)
    made = internal.internal_of
    meanwhile: list = []

    def slowly(p, **kwargs):
        if p is plug and not meanwhile:
            meanwhile.append(app.attach(asker))
            app.plugin_internal(asker)  # the second request, after the attach
        return made(p, **kwargs)

    monkeypatch.setattr(internal, "internal_of", slowly)
    first = app.plugin_internal(plug)
    assert meanwhile and {h["name"]: h for h in first["hooks"]}["poke"]["askedBy"] == []  # as it was when asked
    again = app.plugin_internal(plug)
    assert again is not first and {h["name"]: h for h in again["hooks"]}["poke"]["askedBy"] == ["asker"]
    assert app.plugin_internal(plug) is again


def test_reading_both_views_asks_no_plugin_anything(monkeypatch):
    Counted.asked.clear()
    app = demo(monkeypatch)
    counted = Counted()
    app.attach(counted)
    assert app.own_apis()["internal"]["plugins"][0]["name"] == "counted"
    status, got = app.api(None, "GET", frame.APIS_PATH, {"plugin": "counted"}, None)[:2]
    assert status == 200 and got["apis"] == as_dicts((CARD,)) and got["apiFacts"] == {CARD.name: {"version": "3"}}
    assert got["internal"] is app.plugin_internal(counted) and got["name"] == "counted"  # the kept answer
    assert Counted.asked == []  # no hook of it was asked
    app.attach(Plug(name="unread", apis=("not a card",)))  # cards that cannot be read: none, its Internal API given
    got = app.api(None, "GET", frame.APIS_PATH, {"plugin": "unread"}, None)[1]
    assert (got["apis"], got["apiFacts"], got["internal"]["name"]) == ([], {}, "unread")
    with pytest.raises(frame.Refused) as refused:
        app.api(None, "GET", frame.APIS_PATH, {"plugin": "nudged"}, None)  # not attached: not this app's to say
    assert (refused.value.status, refused.value.reason) == (404, "no plugin 'nudged' is attached to demo")


def test_an_apps_own_cards_are_read_when_asked_with_what_it_learned_of_them(monkeypatch):
    read: list = []

    class Carded(DemoApp):
        @property
        def apis(self):  # an app's apis.py imported when asked, never at its start
            read.append("apis")
            return (CARD,)

        def api_facts(self):
            return {CARD.name: {"runs": 2, "last": None}}

    class Unsaid(Carded):
        def api_facts(self):
            raise RuntimeError("it cannot say")

    class Talkative(DemoApp):
        def api_facts(self):
            return {"Something": {"said": "of no card it declares"}}

    monkeypatch.delenv("LIMINAL_DEMO_LOGIN", raising=False)
    app = Carded(log=lambda m: None, login=StandInLogin())
    app.internal()
    assert read == []  # its Internal API reads nothing of its cards
    own = app.own_apis()
    assert own["apis"] == as_dicts((CARD,)) and own["apiFacts"] == {CARD.name: {"runs": "2", "last": ""}}
    assert read == ["apis"] and json.loads(json.dumps(own)) == own
    assert Unsaid(log=lambda m: None, login=StandInLogin()).own_apis()["apiFacts"] == {}  # never fails on them
    assert Talkative(log=lambda m: None, login=StandInLogin()).own_apis()["apiFacts"] == {}  # no card: none drawn
    for odd in ("not cards", (CARD, "not a card"), 7):
        class Odd(DemoApp):
            apis = odd

        got = Odd(log=lambda m: None, login=StandInLogin()).own_apis()
        assert (got["apis"], got["apiFacts"]) == ([], {}), odd


def test_the_route_through_the_handler_is_noted_by_its_path_alone(monkeypatch):
    """The query (?plugin=NAME) reaches the route, and who talks to whom notes the path alone (never the query)."""
    app = demo(monkeypatch)
    app.attach(Plug())
    sent: list = []
    monkeypatch.setattr(frame.web, "send_json", lambda handler, data, status=200, headers=None: sent.append(
        (int(status), data)))
    handler = frame.make_handler(app)
    request = handler.__new__(handler)  # no connection: the request as the handler answers it, nothing served
    request.headers = {}
    for target in ("/api/app/apis?plugin=plug", "/api/app/apis", "/api/app/apis?plugin=nobody"):
        request._answer("GET", urlsplit(target), None)
    assert [s for s, _ in sent] == [200, 200, 404]
    assert sent[0][1]["name"] == "plug" and sent[1][1]["internal"]["of"] == "app"
    assert sent[2][1] == {"error": "no plugin 'nobody' is attached to demo"}
    rows = [r for r in app.connections()["recent"] if r["to"] == "demo" and "/api/app" in r["what"]]
    assert rows and {(r["what"], r["kind"]) for r in rows} == {("GET /api/app/apis", "read")}
    assert "plugin=" not in json.dumps(app.connections())


def test_what_the_frame_offers_is_said_in_a_line_each_and_its_old_two_answer_as_before(monkeypatch):
    app = demo(monkeypatch)
    plug = Plug()
    app.attach(plug)
    got = internal.app_internal(app)
    assert [m["name"] for m in got["methods"]] == list(internal.APP_METHODS)
    assert [m["name"] for m in got["offers"]] == list(internal.OFFERS)
    assert all(m["line"] and not m["line"].endswith("\u2026") for m in got["methods"] + got["offers"]), got["offers"]
    face = app.interface()  # as it was (tests/test_authorization.py pins it too)
    assert set(face) == {"name", "kind", "api", "login", "plugins", "methods"} and face["plugins"] == ["plug"]
    assert set(face["methods"]) == set(internal.APP_METHODS)
    assert app.api(None, "GET", "/api/plugins", {}, None) == (200, {"plugins": {"plug": plug.interface()}})
