"""The platform's core, the base the apps inherit (apps/platform.py, apps/databases.py; Monday list item 30, step 1;
the user, 2026-11-24: "inheritance bro", "through the rust interface"; 2026-11-25: the instance forms move to the
platform's Databases section, the platform the only writer of instance settings).

A subclass declaring ("database",) attaches the database plugins alone; the Databases section's two routes answer as
the integrator's did; a part that is not the running platform refuses a change with 409 and the platform makes it;
the platform's Databases section as a node lists its methods, and a stand-in Remote's change reaches the platform.
The stand-in engines are test_databases' (a file's and a server's); liminal-net is stood in for (StandInNode, a
Remote over the platform's hillock in this process): nothing is started, nothing listens, nothing is sent."""
from __future__ import annotations

import sys
from http import HTTPStatus
from types import SimpleNamespace

import pytest

from liminal_libs import layout
from liminal_libs.apps import EnvironmentLogin, Refused, attach_registry
from liminal_libs.apps import databases as section
from liminal_libs.apps import platform as core
from liminal_libs.apps.platform import Platform
from liminal_libs.assistants.plugin import AssistantPlugin
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.sources import registry
from liminal_libs.sources.plugin import PlatformPlugin
from liminal_libs.storage import databases as contract
from liminal_libs.storage.databases import DatabasePlugin

from test_databases import Flat, Served

pytestmark = pytest.mark.usefixtures("no_outside")


class Part(Platform):
    """An app inheriting the platform for its databases, as the charts and the integrator will (not the platform)."""

    NAME, TITLE, ICON = "part", "A part", "disk"
    PLATFORM_NEEDS = ("database",)


class Running(Part):
    """The running platform: the one writer (liminal-platform's app sets the flag)."""

    NAME = "platform"
    PLATFORM_WRITER = True


class Figures:
    """The integrator's Databases view of the folder, as instances.overview reads it: a listing and its forget."""

    def __init__(self):
        self.forgot = 0

    def overview(self):
        return {"entries": [{"engine": "sqlite", "size": 7, "files": 2, "group": "main"},
                            {"engine": "sqlite", "size": 5, "group": "instances"}]}

    def forget(self):
        self.forgot += 1


@pytest.fixture
def found(tmp_path, monkeypatch):
    """The two stand-in engines found by the registry as packages would be, beside a machine plugin and an AI
    assistant the registry also has; a data folder of the test's own; nothing listens on this machine."""
    monkeypatch.setattr(layout, "plugins_dir", lambda: None)
    eps = [SimpleNamespace(name=f"p{i}", value=f"fake_{i}:DATABASE", load=(lambda p=p: SimpleNamespace(DATABASE=p)))
           for i, p in enumerate((Flat(), Served()))]
    monkeypatch.setattr(registry, "_entry_points", lambda: eps)
    registry.reload()
    box, helper = MachinePlugin(name="box"), AssistantPlugin(name="helper")
    monkeypatch.setattr(registry, "machines", lambda: {"box": box})
    monkeypatch.setattr(registry, "assistants", lambda: {"helper": helper})
    servers = {("127.0.0.1", 5544): {"liminal": {}, "": {"postgres": "admin-secret"}}}
    monkeypatch.setattr(Served, "servers", servers)
    monkeypatch.setattr(contract, "listening", lambda host, port, timeout=0.3: (host, port) in servers)
    monkeypatch.setattr(registry, "errors", lambda: [
        ("plugin-platform-duckdb (plugin_platform_duckdb)", "ModuleNotFoundError: No module named 'duckdb'"),
        ("plugin-integrator-twse (plugin_integrator_twse)", "ImportError: a feed's")])
    data = tmp_path / "data"
    data.mkdir()
    (data / "liminal.db").write_text("flat\n", encoding="utf-8", newline="\n")
    yield SimpleNamespace(data=data, box=box, helper=helper, servers=servers)
    registry._providers = None


def made(cls, found, said=None, **kw):
    app = cls(log=(said.append if said is not None else (lambda m: None)), login=EnvironmentLogin(env={}), **kw)
    app.db_path = found.data / "liminal.db"
    app.databases = Figures()
    return app


def post(app, **form):
    status, body = app.api(None, "POST", "/api/databases/instances", {}, form)[:2]
    assert status == 200
    return body


# -- the plugins: platform plugins, held by section, attached by declared need ----------------------------------------
def test_a_database_plugin_is_a_platform_plugin_found_as_before():
    assert issubclass(DatabasePlugin, PlatformPlugin) and DatabasePlugin.SYSTEM == "platform"
    assert DatabasePlugin.KIND == "database" and DatabasePlugin.SECTION == "databases"
    assert core.section_of(Flat()) == "databases" and core.section_of(MachinePlugin(name="m")) == "machine"
    assert core.section_of(AssistantPlugin(name="a")) == "ai"


def test_a_subclass_needing_databases_attaches_them_alone_and_holds_them_by_section(found):
    app = made(Part, found)
    assert sorted(app.attach_needs()) == ["postgres", "sqlite"]
    assert found.box.app is None and found.helper.app is None  # the platform's own kinds are not this part's
    assert list(app.sections()) == ["databases"] and sorted(app.section("databases")) == ["postgres", "sqlite"]
    assert app.attach_needs() == []  # attached once
    assert all(p.login is app.login for p in app.section("databases").values())
    # one another app holds is left to it; one needing nothing attaches nothing
    other = made(Part, found)
    assert other.attach_needs() == [] and other.database_plugins() == {}
    bare = type("Bare", (Platform,), {"NAME": "bare"})(log=lambda m: None)
    assert bare.attach_needs() == [] and bare.sections() == {}
    with pytest.raises(Refused):  # and answers no Databases route
        bare.api(None, "GET", "/api/databases/plugins", {}, None)
    with pytest.raises(ValueError, match="none of"):
        type("Odd", (Platform,), {"PLATFORM_NEEDS": ("feed",)})()
    # a platform needing everything holds each in its section, databases first
    whole = type("Whole", (Running,), {"NAME": "whole", "PLATFORM_NEEDS": ("machine", "database", "assistant")})
    registry.reload()
    w = made(whole, found)
    assert sorted(w.attach_needs()) == ["box", "helper", "postgres", "sqlite"]
    assert list(w.sections()) == ["databases", "machine", "ai"]


def test_the_integrator_still_attaches_the_database_plugins_and_the_platforms_attach_does_not(found):
    # (the old path: the integrator holds them until it inherits the platform, step 4)
    holder = SimpleNamespace(attached=[], attach=lambda p: holder.attached.append(p.name))
    assert attach_registry(holder, only="integrator") == ["sqlite", "postgres"]
    assert "sqlite" not in attach_registry(SimpleNamespace(attach=lambda p: None), only="platform")


# -- the Databases section's routes: as the integrator's -------------------------------------------------------------
def test_the_routes_answer_as_the_integrators_did(found):
    said: list = []
    app = made(Running, found, said)
    body = app.api(None, "GET", "/api/databases/plugins", {}, None)[1]
    assert set(body) == {"plugins", "me", "suites", "dataFolder", "errors", "writer"} and body["writer"] is True
    assert body["dataFolder"] == str(found.data) and body["suites"][0] == body["me"]
    assert body["errors"] == ["plugin-platform-duckdb (plugin_platform_duckdb): ModuleNotFoundError: No module named 'duckdb'"]
    flat = next(p for p in body["plugins"] if p["name"] == "sqlite")
    own = next(r for r in flat["instances"] if r.get("builtin"))
    assert (own["bytes"], own["files"]) == (7, 2) and flat["can"]["new"] is True and flat["apis"][0]["name"] == "Flat files"
    # a form: a change only once confirmed, then made through the plugin, logged, the folder listed again
    with pytest.raises(Refused, match="confirmed on the page first") as e:
        post(app, plugin="sqlite", action="new", name="archive", where="instances/archive.db")
    assert e.value.status == HTTPStatus.BAD_REQUEST
    out = post(app, plugin="sqlite", action="new", name="archive", where="instances/archive.db", confirm=True)
    assert out["ok"] and (found.data / "instances" / "archive.db").read_text(encoding="utf-8") == "flat\n"
    assert app.databases.forgot == 1 and said[-1].startswith("platform: sqlite: new archive: ")
    assert post(app, plugin="sqlite", action="test", name="archive")["ok"]
    for form, status in (({"plugin": "nope", "action": "test"}, 404), ({"plugin": "sqlite", "action": "drop"}, 400)):
        with pytest.raises(Refused) as e:
            post(app, **form)
        assert e.value.status == status


def test_the_librarys_section_gives_what_the_integrators_module_gives(found, monkeypatch):
    """The same app asked through the integrator's instances.py (where it is installed) and through the library's:
    the same answers, so the integrator's module can become the library's names imported (step 4). The integrator's
    modules are let go after, so the library's own check that it imports none of Liminal's programs still holds."""
    before = set(sys.modules)
    try:
        theirs = pytest.importorskip("liminal_integrator.instances")
        monkeypatch.setattr(theirs.lib, "plugin_errors", registry.errors)
        app = made(Running, found)
        mine = section.overview(app)
        assert theirs.overview(app) == {**mine, "errors": [e for e in mine["errors"] if "plugin-platform-" not in e]}
        assert theirs.elsewhere(app) == section.elsewhere(app)
        test = {"plugin": "sqlite", "action": "test", "name": "data"}
        assert theirs.ask(app, test) == section.ask(app, test)
    finally:
        monkeypatch.undo()
        for name in set(sys.modules) - before:
            if name.split(".")[0] in ("liminal_integrator", "liminal_charts"):
                sys.modules.pop(name, None)


# -- one writer --------------------------------------------------------------------------------------------------------
def test_a_part_that_is_not_the_platform_reads_and_refuses_a_change_and_the_platform_makes_it(found):
    part = made(Part, found)
    body = part.api(None, "GET", "/api/databases/plugins", {}, None)[1]
    assert body["writer"] is False
    for row in body["plugins"]:
        assert row["can"]["why"] == core.ELSEWHERE and not any(v for k, v in row["can"].items() if k != "why")
    assert post(part, plugin="sqlite", action="test", name="data")["ok"]  # a read is anyone's
    for action in section.CHANGES:
        with pytest.raises(Refused, match="change this on the platform's Databases section") as e:
            post(part, plugin="sqlite", action=action, name="archive", where="instances/archive.db", confirm=True)
        assert e.value.status == HTTPStatus.CONFLICT
    assert not (found.data / "instances").exists() and part.databases.forgot == 0
    # the flag the platform app sets, or given
    assert made(Part, found, writer=True).is_platform and not made(Running, found, writer=False).is_platform
    with pytest.raises(RuntimeError, match="not the running platform"):
        part.serve_databases(node_factory=StandInNode)
    registry.reload()  # (the part holds the plugins: the platform's process has its own)
    platform = made(Running, found)
    assert post(platform, plugin="sqlite", action="new", name="archive", where="instances/archive.db", confirm=True)["ok"]


# -- through liminal-net (stood in) -------------------------------------------------------------------------------------
class RemoteError(Exception):
    """liminal_net.RemoteError as it comes back: the kind, the words, status and accept."""

    def __init__(self, kind, message, status=None, accept=None):
        super().__init__(f"{kind}: {message}")
        self.kind, self.message, self.status, self.accept = kind, message, status, accept


class StandInRemote:
    """A synapse to a node served in this process: each request given to its hillock as liminal-net gives it (the
    peer as a dict, the args as a list), an exception back as a record (kind, words, status, accept)."""

    def __init__(self, hillock, peer):
        self.hillock, self.peer = hillock, peer
        self.interface = hillock.interface
        self.asked: list = []

    def request(self, method, *args, **kwargs):
        self.asked.append(method)
        if method not in self.interface["methods"]:
            raise RemoteError("Refused", f"no method {method}", 404)
        try:
            return self.hillock.request(self.peer, method, list(args), dict(kwargs))
        except Exception as e:  # noqa: BLE001 - what crosses: a record
            raise RemoteError(type(e).__name__, getattr(e, "reason", str(e)), getattr(e, "status", None),
                              getattr(e, "accept", None)) from None


class StandInNode:
    served: dict = {}  # name -> hillock, the nodes this test's "network" holds

    def __init__(self, name, kind, scope, hillock, interface, ipc_dir=None, timing=None):
        self.name, self.kind, self.scope, self.hillock, self.interface = name, kind, scope, hillock, interface
        self.started = False
        self.reached: list = []
        self.stopped: list = []

    def stop(self, why):
        self.stopped.append(why)

    def start(self):
        self.started = True
        StandInNode.served[self.name] = self.hillock

    def reach(self, node, scope=None, launcher=None):
        self.reached.append((node, launcher))
        hillock = StandInNode.served.get(node)
        if hillock is None:
            raise ConnectionError(f"no node {node} answers")  # liminal_net.NetworkError is a ConnectionError
        return StandInRemote(hillock, {"name": self.name, "kind": self.kind, "scope": self.scope, "pid": 4242})


@pytest.fixture
def network(monkeypatch):
    monkeypatch.setattr(StandInNode, "served", {})
    return StandInNode


def test_the_platforms_databases_node_lists_its_methods_and_a_remotes_change_reaches_it(found, network, tmp_path):
    said: list = []
    platform = made(Running, found, said, node_factory=network)
    platform.PLATFORM_SCOPE = tmp_path
    node = platform.serve_databases()
    assert node.started and node.name == core.DATABASES_NODE and platform.databases_node is node
    face = node.interface
    assert face["trait"] == core.DATABASES_TRAIT and set(face["methods"]) == {"overview", "elsewhere", "test", "change"}
    assert all({"args", "returns", "signature"} <= set(m) for m in face["methods"].values())
    # a part in another process: its own node (never started), the platform's reached without a launcher
    part = made(Part, found, node_factory=network)
    part.PLATFORM_SCOPE = tmp_path
    out = part.change_on_platform({"plugin": "sqlite", "action": "new", "name": "archive",
                                   "where": "instances/archive.db", "confirm": True})
    assert out["ok"] and (found.data / "instances" / "archive.db").exists()
    own = part.own_node()
    assert not own.started and own.reached == [(core.DATABASES_NODE, None)]
    assert any("asked by app-part-platform through its node: sqlite new" in m for m in said)
    # reads cross as well; the platform's refusal comes back as it was said there, with its status and what accepts it
    assert part.ask_platform("overview")["writer"] is True
    with pytest.raises(section.Asked, match="confirmed on the page first") as e:
        part.change_on_platform({"plugin": "sqlite", "action": "forget", "name": "archive"})
    assert e.value.status == HTTPStatus.BAD_REQUEST
    with pytest.raises(LookupError):
        part.ask_platform("change")
    # a hillock whose app stopped being the platform refuses the change
    platform._writer = False
    with pytest.raises(section.Asked, match="change this on the platform's Databases section") as e:
        part.change_on_platform({"plugin": "sqlite", "action": "forget", "name": "archive", "confirm": True})
    assert e.value.status == HTTPStatus.CONFLICT and (found.data / "instances" / "archive.db").exists()
    # the section's node ends with the platform's server (App.terminate's last step)
    platform._end_server()
    assert node.stopped == ["the platform is ending"] and platform.databases_node is None


def test_a_platform_not_running_is_said_and_never_started(found, network):
    part = made(Part, found, node_factory=network)
    with pytest.raises(Refused, match="the platform is not running") as e:
        part.change_on_platform({"plugin": "sqlite", "action": "forget", "name": "x", "confirm": True})
    assert e.value.status == HTTPStatus.SERVICE_UNAVAILABLE and part.own_node().reached[0][1] is None
