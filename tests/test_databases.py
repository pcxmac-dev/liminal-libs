"""The database plugins (storage/databases.py and storage/instances.py, plugin API 2.3; the user, 2026-11-15: "for
the integrator i need plugins for each type of database and in each plugin can setup either new databases or
connections to existing databases using many different types of IP or IPC methods. each instance in the plugin has
it's own configuration how it's shared, ports, permissions etc"): a plugin an engine, found by the registry as the
integrator's own kind, holding its instances; what the user adds kept through its login as one value, a sign-in as
two pairs; a change made by the system that holds the data alone. Two stand-in engines here, a file's and a
server's: nothing is opened but the test's own files, nothing listens, nothing is sent."""
from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from liminal_libs import config, layout, mounts
from liminal_libs.apps import EnvironmentLogin, attach_registry
from liminal_libs.sources import registry
from liminal_libs.sources.apis import Api, Link as Page
from liminal_libs.sources.conformance import assert_conforms, problems
from liminal_libs.storage import databases
from liminal_libs.storage.databases import (DatabasePlugin, Instance, Kept, Made, Refusal, Share, SharePolicy,
                                            credential_variables, variable_of)


def docs(name: str) -> tuple:
    return (Api(name=name, maker="the tests", about="a stand-in engine", kind="file",
                links=(Page("Its documentation", "https://www.sqlite.org/docs.html", "docs"),), verified="2026-11-16"),)


class Flat(DatabasePlugin):
    """A file engine's stand-in: a database is a text file that begins with the word flat."""

    name = "sqlite"
    title = "Flat"
    about = "a file engine's stand-in"
    api = "2.3"
    order = 940
    options = ("SQLITE_INSTANCES",)
    apis = docs("Flat files")
    ENGINE = "sqlite"
    METHODS = ("file", "helper")
    HOLDS = ("main", "bars", "ticks")
    SHARES = True

    def builtin(self, data_dir):
        return (Instance("data", "The data folder", where="./", holds=("main", "bars")),)

    def open(self, instance, part="", read_only=True, data_dir=None):
        path = self.path_of(instance, data_dir)
        return open(path / part if part else path, "r" if read_only else "a", encoding="utf-8")

    def probe(self, instance, data_dir):
        path = self.path_of(instance, data_dir)
        if instance.folder:
            return [f"{sum(1 for p in path.iterdir() if p.suffix == '.db')} files"]
        with self.open(instance, data_dir=data_dir) as f:
            if f.readline().strip() != "flat":
                raise ValueError(f"{path.name} is not a flat file")
        return ["flat 1"]

    def make(self, instance, data_dir, **given):
        path = self.path_of(instance, data_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("flat\n", encoding="utf-8", newline="\n")
        return [f"{path.name} made"]


class Served(DatabasePlugin):
    """A server engine's stand-in: `servers` is what answers, by (host, port): each database with its roles."""

    name = "postgres"
    title = "Served"
    about = "a server engine's stand-in"
    api = "2.3"
    order = 941
    options = ("POSTGRES_INSTANCES",)
    apis = docs("Served")
    ENGINE = "postgres"
    METHODS = ("tcp", "socket")
    HOLDS = ("documents",)
    SERVER = True
    SHARED = "its server's roles decide who reaches it"
    servers: dict = {}

    def open(self, instance, part="", read_only=True, data_dir=None):
        server = self.servers.get((instance.where, instance.port))
        if server is None:
            raise ConnectionError(f"nothing answers at {instance.where}:{instance.port}")
        if instance.database not in server:
            raise LookupError(f"no database {instance.database} there")
        roles = server[instance.database]
        if instance.auth:
            got = self.credentials(instance)
            if got is None or roles.get(got[0]) != got[1]:
                raise PermissionError("the sign-in was refused")
        elif roles:
            raise PermissionError("it wants a sign-in")
        return roles

    def probe(self, instance, data_dir):
        self.open(instance, data_dir=data_dir)
        return ["served 9.9"]

    def make(self, instance, data_dir, admin_user="", admin_password="", **given):
        server = self.servers.get((instance.where, instance.port))
        if server is None:
            raise ConnectionError(f"nothing answers at {instance.where}:{instance.port}")
        if instance.database in server:
            raise ValueError(f"{instance.database} is there already")
        if not admin_user:
            server[instance.database] = {}
            return [f"{instance.database} made"]
        if server.get("") != {admin_user: admin_password}:
            raise PermissionError("the administrator's sign-in was refused")
        role, password = f"liminal_{instance.name}", databases.new_password()
        server[instance.database] = {role: password}
        self.keep_credentials(instance.name, role, password)
        return Made((f"{instance.database} made", f"the role {role} made for it"), role=role, grants=("read", "write"))


@pytest.fixture
def flat(tmp_path):
    """The file stand-in attached to an app whose database is the test's, with a login that keeps to a dict."""
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "liminal.db").write_text("flat\n", encoding="utf-8")
    env: dict = {}
    plugin = Flat()
    plugin.attach(SimpleNamespace(db_path=data / "liminal.db"), EnvironmentLogin(env=env))
    return plugin, data, env


@pytest.fixture
def served(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    env: dict = {}
    servers = {("127.0.0.1", 5544): {"liminal": {}, "": {"postgres": "admin-secret"}},
               ("db.example.net", 5432): {"docs": {"reader": "far-secret"}}}
    monkeypatch.setattr(Served, "servers", servers)
    plugin = Served()
    plugin.attach(SimpleNamespace(db_path=data / "liminal.db"), EnvironmentLogin(env=env))
    return plugin, data, env, servers


@pytest.fixture
def installed(monkeypatch):
    """Plugins loaded as installed packages' entry points; the plugin directory out of the way."""
    monkeypatch.setattr(layout, "plugins_dir", lambda: None)

    def install(*plugins):
        eps = [SimpleNamespace(name=f"p{i}", value=f"fake_{i}:DATABASE", load=(lambda p=p: SimpleNamespace(DATABASE=p)))
               for i, p in enumerate(plugins)]
        monkeypatch.setattr(registry, "_entry_points", lambda: eps)
        return registry.reload()

    yield install
    registry._providers = None


# -- what an instance is, and what is kept ---------------------------------------------------------------------------
def test_an_instance_is_kept_as_what_differs_and_read_back_whatever_was_written_by_hand():
    plain = Instance("archive", where="instances/archive.db")
    assert plain.kept() == {"name": "archive", "where": "instances/archive.db", "method": "file"} and not plain.folder
    assert Instance("data", where="./").folder and Instance("history", where="history/").folder
    full = Instance("far", title="The far one", engine="postgres", where="db.example.net", method="tcp", holds=("documents",),
                    port=5432, database="docs", tls=True, auth=True, remote=True, shared=(Share("linux::Ubuntu", "write"),),
                    role="reader", grants=("read",), made=True, at="2026-11-16T12:00:00Z", note="n")
    kept = Kept(instances={"archive": plain, "far": full}, builtin={"data": (Share("linux::Ubuntu"),)})
    text = kept.text()
    assert json.loads(text)["v"] == 1 and "\n" not in text and len(text) < 700
    back = Kept.of(text, "postgres")
    assert back.problem == "" and back.builtin == {"data": (Share("linux::Ubuntu", "read"),)}
    assert back.instances["far"] == full and back.instances["archive"] == replace(plain, engine="postgres")
    assert Kept().text() is None and Kept.of("").instances == {} and Kept.of(None).problem == ""
    # a page reads it with its methods' and its holdings' words
    assert full.as_dict()["methodTitle"] == "TCP" and full.as_dict()["holds"] == [
        {"name": "documents", "title": "documents (releases, headlines, filings)"}]
    # a value changed by hand: what is not an instance is left out, never an error; what is not a value at all is said
    assert "not readable" in Kept.of("{not json").problem and "not a list" in Kept.of("[1, 2]").problem
    odd = json.dumps({"instances": [
        {"name": "ok", "where": "instances/ok.db"}, {"name": "Bad Name", "where": "x.db"}, {"name": "nowhere"},
        {"name": "port", "where": "h", "method": "tcp", "port": True}, {"name": "port2", "where": "h", "method": "tcp", "port": 70000},
        {"name": "method", "where": "x.db", "method": "carrier-pigeon"}, "text", {"name": "ok", "where": "twice.db"},
        {"name": "shares", "where": "s.db", "holds": ["bars", "gold"], "shared": [
            {"who": "linux::Ubuntu", "access": "write"}, {"who": "nobody", "access": "read"}, {"who": "a::b", "access": "own"}, 7]}],
        "builtin": {"data": {"shared": [{"who": "linux::Ubuntu"}]}, "Bad": {"shared": [{"who": "a::b"}]}, "empty": {"shared": []},
                    "odd": 5}})
    got = Kept.of(odd, "sqlite")
    assert sorted(got.instances) == ["ok", "shares"] and got.instances["ok"].where == "instances/ok.db"
    assert got.instances["shares"].holds == ("bars",) and got.instances["shares"].shared == (Share("linux::Ubuntu", "write"),)
    assert got.builtin == {"data": (Share("linux::Ubuntu", "read"),)}
    many = json.dumps({"instances": [{"name": f"n{i}", "where": f"instances/n{i}.db"} for i in range(40)]})
    assert len(Kept.of(many).instances) == databases.MAX_INSTANCES


def test_what_a_form_gives_is_checked_and_refused_in_words():
    assert variable_of("sqlite") == "SQLITE_INSTANCES" and variable_of("my-engine") == "MY_ENGINE_INSTANCES"
    assert credential_variables("mongodb", "atlas-1") == ("MONGODB_ATLAS_1_USER", "MONGODB_ATLAS_1_PASSWORD")
    assert databases.clean_name(" Archive-2 ") == "archive-2"
    for bad in ("", "-x", "has space", "x" * 33, "ünï", "a/b"):
        with pytest.raises(Refusal, match="lowercase letters, digits and dashes"):
            databases.clean_name(bad)
    assert databases.clean_holds("bars, ticks bars", ("main", "bars", "ticks")) == ("bars", "ticks")
    assert databases.clean_holds(["main"], ("main",)) == ("main",) and databases.clean_holds(None, ("main",)) == ()
    with pytest.raises(Refusal, match="cannot hold documents"):
        databases.clean_holds("documents", ("main", "bars"))
    assert databases.clean_who(" linux::Ubuntu ") == "linux::Ubuntu" and databases.clean_who("windows::NEPTUNE") == "windows::NEPTUNE"
    for bad in ("", "Ubuntu", "linux:Ubuntu", "linux::", "a::b\nc"):
        with pytest.raises(Refusal, match="its system and its name there"):
            databases.clean_who(bad)
    assert databases.clean_title("  The   far one ") == "The far one"
    with pytest.raises(Refusal):
        databases.clean_title("x" * 61)
    assert databases.is_local("127.0.0.1") and databases.is_local("LOCALHOST") and databases.is_local("[::1]")
    assert not databases.is_local("db.example.net") and not databases.is_local("192.168.1.9")
    # a whole path as either system writes it: what is kept on one is read on the other
    for whole in (r"C:\data\x.db", r"\\server\share\x.db", "/srv/x.db", r"\data\x.db"):
        assert databases.is_absolute(whole)
    assert not databases.is_absolute("instances/x.db") and not databases.is_absolute("x.db")
    assert databases.now_iso(lambda: 0.0) == "1970-01-01T00:00:00Z" and len(databases.new_password()) >= 24


# -- the kind: conforming, found, listed --------------------------------------------------------------------------------
def test_a_database_plugin_conforms_and_says_what_it_offers():
    flat_, served_ = Flat(), Served()
    for p in (flat_, served_):
        assert problems(p) == [] and p.KIND == "database" and p.SYSTEM == "platform"  # (1.90.0, item 30)
        assert_conforms(p)
        assert set(p.interface()["hooks"]) >= {"open", "probe", "make"} and p.interface()["kind"] == "database"
    assert flat_.gives("builtin") and not served_.gives("builtin") and not flat_.gives("scan")
    assert flat_.instances_variable == "SQLITE_INSTANCES" and flat_.engine_title == "SQLite" and served_.engine_title == "PostgreSQL"
    assert flat_.driver() == (True, "") and Flat(DRIVER="no_such_driver_module").driver()[0] is False
    assert "pip install" in Flat(DRIVER="no_such_driver_module", DRIVER_HINT="pip install it").driver()[1]
    # the contract's own: no instances, nothing opened, tested or made
    bare = DatabasePlugin()
    assert bare.builtin(Path(".")) == () and bare.METHODS == () and bare.ICON == "database"
    for call in (lambda: bare.open(Instance("x")), lambda: bare.probe(Instance("x"), Path(".")), lambda: bare.make(Instance("x"), Path("."))):
        with pytest.raises(NotImplementedError):
            call()
    from liminal_libs.ui import STATIC

    assert f"    {bare.ICON}: '" in (STATIC / "icons.js").read_text(encoding="utf-8")
    # what falls short is said
    said = lambda **wrong: "\n".join(problems(Flat(**wrong)))  # noqa: E731
    assert "ENGINE 'oracle' is none of" in said(ENGINE="oracle")
    assert "METHODS ('file', 'carrier'):" in said(METHODS=("file", "carrier")) and "METHODS must be a non-empty tuple" in said(METHODS=())
    assert "HOLDS ('bars', 'gold')" in said(HOLDS=("bars", "gold")) and "each once" in said(HOLDS=("bars", "bars"))
    assert "a server's are addresses" in said(SERVER=True) and "a server's are addresses" in said(METHODS=("file", "tcp"))
    assert "which is not among its options" in said(options=())
    assert "written for plugin API 2.3, not 2.2" in said(api="2.2")
    assert "does not say who reaches its instances" in said(SHARES=False) and said(SHARES=False, SHARED="its files' own rights") == ""
    assert "must give open()" in said(open=None) and "must give probe()" in said(probe=None)
    assert "gives no make()" in said(make=None) and said(make=None, MAKES=False) == ""


def test_the_registry_finds_database_plugins_as_the_integrators_own_kind(installed):
    module = SimpleNamespace(DATABASE=Flat())
    found = registry._plugins_in(module, "test")
    assert [(p.name, p.origin, type(p)) for p in found] == [("sqlite", "test", Flat)] and registry._kind(found[0]) == "database"
    assert [p.name for p in registry._plugins_in(SimpleNamespace(DATABASES=(Flat, Served)), "test")] == ["sqlite", "postgres"]
    with pytest.raises(TypeError, match=r"^defines no PLUGIN \(.*nor DATABASE \(a DatabasePlugin\)"):
        registry._plugins_in(SimpleNamespace(), "test")
    installed(Flat(), Served)
    assert list(registry.databases()) == ["sqlite", "postgres"] and registry.database("sqlite").origin.startswith("package:")
    assert registry.database("nope") is None and registry.errors() == []
    assert "sqlite" not in registry.providers() and "sqlite" not in registry.publishers() and "sqlite" not in registry.machines()
    # the older finders are as they were: the databases are not among their answers
    assert len(registry.discover_everything()) == 5 and len(registry.discover_all()) == 3
    assert {"SQLITE_INSTANCES", "POSTGRES_INSTANCES"} <= set(registry.variables())  # read with the user's saved variables
    assert registry.plugins_loaded()[-2:] == ["sqlite", "postgres"] and registry.plugin_keys("sqlite") == []
    assert registry.plugin_databases("sqlite") == []  # it holds none of a plugin's data itself
    row = registry.database_menu()[0]
    assert (row["name"], row["engine"], row["engineTitle"], row["server"], row["variable"]) == (
        "sqlite", "sqlite", "SQLite", False, "SQLITE_INSTANCES") and row["methods"] == ["file", "helper"]
    # attached by the integrator's frame with its other plugins, never by the platform's (platform plugins since 1.90.0,
    # still the integrator's until it inherits the platform: apps/platform.py attaches them by declared need)
    app = SimpleNamespace(attached=[], attach=lambda p: app.attached.append(p.name))
    assert attach_registry(app, only="platform") == [] and attach_registry(app, only="integrator") == ["sqlite", "postgres"]
    # a selection leaves them out like any plugin
    assert registry.select("postgres").left_out == ("sqlite",) and list(registry.databases()) == ["postgres"]
    registry.select(None)
    # one plugin an engine: a second would hold the data folder's files as its own too
    class Twin(Flat):
        name = "sqlite-too"
        options = ("SQLITE_TOO_INSTANCES",)

    installed(Flat(), Twin())
    assert list(registry.databases()) == ["sqlite"]
    assert any("'sqlite' is the plugin for sqlite already" in why for _, why in registry.errors())
    # ... and a name taken by another plugin of any kind is the first's
    installed(Flat(), Served(name="sqlite", options=("SQLITE_INSTANCES",)))
    assert list(registry.databases()) == ["sqlite"] and any("a second database named 'sqlite'" in why for _, why in registry.errors())
    # left out when found unusable after loading
    installed(Flat(), Served())
    registry.leave_out("postgres", "its settings failed")
    assert list(registry.databases()) == ["sqlite"] and registry.errors()[-1][1] == "postgres: its settings failed"


# -- its instances ---------------------------------------------------------------------------------------------------------
def test_with_nothing_set_a_plugin_has_its_own_instances_and_says_how_each_is(flat):
    plugin, data, env = flat
    assert plugin.data_dir() == data and plugin.kept() == Kept()
    (own,) = plugin.instances()
    assert (own.name, own.engine, own.builtin, own.where, own.holds, own.shared) == ("data", "sqlite", True, "./", ("main", "bars"), ())
    assert plugin.instance("DATA") == own and plugin.path_of(own) == data and plugin.effective_method(own) == "file"
    with pytest.raises(LookupError, match="Flat has no instance 'nope'"):
        plugin.instance("nope")
    assert plugin.state(own) == {"method": "file", "methodTitle": "File", "path": str(data), "foreign": False,
                                 "state": "ready", "why": ""}
    # one answer compared with itself: its said holds how long it took, which two calls need not share
    tested = plugin.test("data")
    assert tested == {"ok": True, "said": tested["said"], "lines": ["1 files"]}
    assert tested["said"].startswith("data answers (file, ")
    status = plugin.status()
    assert (status["name"], status["engine"], status["server"], status["variable"], status["problem"]) == (
        "sqlite", "sqlite", False, "SQLITE_INSTANCES", "")
    assert status["can"] == {"new": True, "connect": True, "share": True, "forget": True, "why": ""}
    assert [m["name"] for m in status["methods"]] == ["file", "helper"] and status["holds"][0] == {
        "name": "main", "title": "the main file (the watchlist, the ledgers, the requests)"}
    (row,) = status["instances"]
    assert row["state"] == "ready" and row["builtin"] and row["place"] == str(data) and row["sharedWords"].startswith("no share set")
    assert env == {}  # asking keeps nothing
    # its driver not here: said, nothing tested, nothing made
    missing = Flat(DRIVER="no_such_driver_module")
    missing.attach(plugin.app, plugin.login)
    assert missing.state(own)["state"] == "no driver" and missing.test("data")["ok"] is False
    assert missing.status()["can"]["new"] is False and "not installed" in missing.status()["can"]["why"]
    with pytest.raises(Refusal, match="not installed"):
        missing.new_database("x")
    # without a login nothing is kept: said, and every change refused
    alone = Flat()
    assert [i.name for i in alone.instances(data)] == ["data"] and "integrator's page" in alone.status(data)["can"]["why"]
    for change in (lambda: alone.new_database("x", data_dir=data), lambda: alone.share("data", "linux::Ubuntu", "read", data_dir=data)):
        with pytest.raises(Refusal, match="this plugin has none"):
            change()
    # a kept value that cannot be read: the plugin's own instances alone, and why
    env["SQLITE_INSTANCES"] = "{broken"
    assert [i.name for i in plugin.instances()] == ["data"] and "not readable" in plugin.status()["problem"]
    assert plugin.new_database("fresh")["ok"] and json.loads(env["SQLITE_INSTANCES"])["instances"][0]["name"] == "fresh"


def test_a_new_database_is_made_in_the_data_folders_instances_and_never_over_a_file(flat, tmp_path):
    plugin, data, env = flat
    made = plugin.new_database("Archive", holds="bars, ticks", title="Old bars")
    assert made["ok"] and made["instance"] == "archive" and made["said"] == f"archive made: {data / 'instances' / 'archive.db'}"
    assert made["lines"] == ["archive.db made", "kept in the login's variables"]
    assert (data / "instances" / "archive.db").read_text(encoding="utf-8") == "flat\n"
    kept = json.loads(env["SQLITE_INSTANCES"])
    assert kept["instances"] == [{"name": "archive", "where": "instances/archive.db", "method": "file", "title": "Old bars",
                                  "holds": ["bars", "ticks"], "made": True, "at": kept["instances"][0]["at"]}]
    inst = plugin.instance("archive")
    assert inst.made and not inst.builtin and plugin.state(inst)["state"] == "ready" and plugin.state(inst)["bytes"] == 5
    assert plugin.test("archive")["lines"] == ["flat 1"] and [i.name for i in plugin.instances()] == ["data", "archive"]
    # a whole path elsewhere, in a folder that is there
    other = tmp_path / "other"
    other.mkdir()
    assert plugin.new_database("elsewhere", where=str(other / "e.db"))["ok"] and (other / "e.db").is_file()
    assert plugin.instance("elsewhere").where == str(other / "e.db") and plugin.path_of(plugin.instance("elsewhere")) == other / "e.db"
    for args, why in (
            (("archive",), "there is an instance archive already"), (("data",), "there is an instance data already"),
            (("Bad Name",), "lowercase letters"), (("x", "instances/x.txt"), "ends in .db or .sqlite or .sqlite3"),
            (("x", "x.db"), "goes in its instances/ folder"), (("x", "feeds/x.db"), "goes in its instances/ folder"),
            (("x", "../x.db"), "is not a path in the data folder"), (("x", "instances/archive.db"), "is there already"),
            (("x", str(tmp_path / "nowhere" / "x.db")), "is no folder here"), (("x", str(other / "e.db")), "is there already"),
            (("x", "", "documents"), "cannot hold documents")):
        with pytest.raises(Refusal, match=why):
            plugin.new_database(*args)
    assert [i["name"] for i in json.loads(env["SQLITE_INSTANCES"])["instances"]] == ["archive", "elsewhere"]
    assert not (data / "instances" / "x.db").exists()
    # what the engine could not make is not kept
    def broken(instance, data_dir, **given):
        raise OSError("the disk is full")

    failing = plugin.with_(make=broken)
    with pytest.raises(OSError, match="disk is full"):
        failing.new_database("never")
    assert "never" not in env["SQLITE_INSTANCES"]
    # a plugin that makes none says so; and there is a most
    with pytest.raises(Refusal, match="makes no new databases"):
        plugin.with_(MAKES=False).new_database("x")
    for i in range(databases.MAX_INSTANCES - 2):
        plugin.new_database(f"n{i}")
    with pytest.raises(Refusal, match=f"{databases.MAX_INSTANCES} instances at most"):
        plugin.new_database("one-too-many")


def test_a_database_that_exists_is_connected_only_when_it_answers(flat, tmp_path):
    plugin, data, env = flat
    (data / "backups").mkdir()
    (data / "backups" / "pre.db").write_text("flat\nrows\n", encoding="utf-8")
    (data / "feeds").mkdir()
    (data / "feeds" / "massive.db").write_text("flat\n", encoding="utf-8")
    old = tmp_path / "old.sqlite"
    old.write_text("flat\n", encoding="utf-8", newline="\n")
    got = plugin.connect_to("backup", r"backups\pre.db", holds=["main"])
    assert got["ok"] and got["said"] == f"backup connected: {data / 'backups' / 'pre.db'}" and got["lines"][0] == "flat 1"
    assert plugin.instance("backup").where == "backups/pre.db" and not plugin.instance("backup").made
    assert plugin.connect_to("old", str(old))["ok"] and plugin.state(plugin.instance("old"))["bytes"] == 5
    (tmp_path / "notes.db").write_text("something else\n", encoding="utf-8")
    for args, why in (
            (("x", ""), "which file"), (("x", "liminal.db"), "one of the data folder's own files"),
            (("x", "feeds/massive.db"), "holds it already"), (("x", "backups/gone.db"), "is no file here"),
            (("x", str(tmp_path / "notes.db")), "did not answer, so it is not kept: notes.db is not a flat file"),
            (("x", str(old.with_suffix(".txt"))), "ends in"), (("backup", str(old)), "already")):
        with pytest.raises(Refusal, match=why):
            plugin.connect_to(*args)
    assert sorted(i["name"] for i in json.loads(env["SQLITE_INSTANCES"])["instances"]) == ["backup", "old"]
    with pytest.raises(Refusal, match="connects to no other databases"):
        plugin.with_(CONNECTS=False).connect_to("x", str(old))
    # one that went away since: said, never an error
    old.unlink()
    assert plugin.state(plugin.instance("old"))["state"] == "absent" and plugin.test("old")["ok"] is False
    assert "old did not answer" in plugin.test("old")["said"]


def test_a_share_names_a_suite_and_is_kept_with_the_instance_or_for_the_plugins_own(flat):
    plugin, data, env = flat
    plugin.new_database("archive")
    said = plugin.share("data", "linux::Ubuntu", "read")
    assert said["ok"] and said["said"] == "linux::Ubuntu reads data"
    assert said["lines"] == ["linux::Ubuntu reads only; no other suite attaches", "kept in the login's variables"]
    assert json.loads(env["SQLITE_INSTANCES"])["builtin"] == {"data": {"shared": [{"who": "linux::Ubuntu", "access": "read"}]}}
    assert plugin.instance("data").shared == (Share("linux::Ubuntu", "read"),)
    assert plugin.share("data", "linux::Ubuntu", "WRITE")["said"] == "linux::Ubuntu reads and writes data"
    plugin.share("data", "linux::Fedora", "read")
    assert databases.shared_words(plugin, plugin.instance("data")) == (
        "linux::Ubuntu reads and writes; linux::Fedora reads only; no other suite attaches")
    # one the user added keeps its shares with it
    plugin.share("archive", "linux::Ubuntu", "read")
    assert plugin.instance("archive").shared == (Share("linux::Ubuntu", "read"),)
    assert json.loads(env["SQLITE_INSTANCES"])["instances"][0]["shared"] == [{"who": "linux::Ubuntu", "access": "read"}]
    # taken away again: with none left, it is as with none set
    assert plugin.share("archive", "linux::Ubuntu", "none")["said"] == "linux::Ubuntu no longer attaches to archive"
    assert plugin.share("archive", "linux::Ubuntu", "none")["said"] == "linux::Ubuntu had no share of archive"
    plugin.share("data", "linux::Ubuntu", "none")
    plugin.share("data", "linux::Fedora", "none")
    assert "builtin" not in json.loads(env["SQLITE_INSTANCES"]) and plugin.instance("data").shared == ()
    assert plugin.status()["instances"][0]["sharedWords"].startswith("no share set: any suite that can start a helper")
    for args, why in ((("data", "Ubuntu", "read"), "its system and its name there"), (("data", "linux::Ubuntu", "own"), "read, write or none"),
                      (("nope", "linux::Ubuntu", "read"), "no instance")):
        with pytest.raises((Refusal, LookupError), match=why):
            plugin.share(*args)
    for i in range(databases.MAX_SHARES):
        plugin.share("data", f"linux::D{i}", "read")
    with pytest.raises(Refusal, match="shares at most"):
        plugin.share("data", "linux::OneMore", "read")
    # one outside the data folder with no share is this system's alone: a helper opens no place it was not given
    away = data.parent / "away"
    away.mkdir()
    plugin.new_database("away", where=str(away / "a.db"))
    words = {r["name"]: r["sharedWords"] for r in plugin.status()["instances"]}
    assert words["away"].startswith("no share set: this system alone opens it (it is outside the data folder")
    assert words["archive"].startswith("no share set: any suite that can start a helper")
    assert plugin.share("away", "linux::Ubuntu", "read")["lines"][0] == "linux::Ubuntu reads only; no other suite attaches"
    assert plugin.share("away", "linux::Ubuntu", "none")["lines"][0].startswith("no share set: this system alone opens it")
    # an engine that keeps no shares says who reaches its instances instead
    quiet = plugin.with_(SHARES=False, SHARED="whoever may read the files")
    with pytest.raises(Refusal, match="whoever may read the files"):
        quiet.share("data", "linux::Ubuntu", "read")
    assert quiet.status()["instances"][0]["sharedWords"] == "whoever may read the files" and quiet.status()["can"]["share"] is False


def test_an_instance_is_forgotten_and_what_it_holds_stays(flat):
    plugin, data, env = flat
    plugin.new_database("archive")
    plugin.share("archive", "linux::Ubuntu", "read")
    gone = plugin.forget("archive")
    assert gone["ok"] and gone["said"] == "archive forgotten"
    assert gone["lines"][0] == f"{data / 'instances' / 'archive.db'} stays as it is: nothing of it was removed"
    assert (data / "instances" / "archive.db").is_file() and "SQLITE_INSTANCES" not in env  # nothing left to keep
    assert [i.name for i in plugin.instances()] == ["data"]
    with pytest.raises(Refusal, match="data is Flat's own: it is not forgotten"):
        plugin.forget("data")
    with pytest.raises(LookupError):
        plugin.forget("archive")
    # the file is still there: made again under its name is refused, connected is fine
    with pytest.raises(Refusal, match="is there already"):
        plugin.new_database("archive")
    assert plugin.connect_to("archive", "instances/archive.db")["ok"]


def test_changes_are_the_owning_systems_alone_and_the_other_reads_what_it_keeps(flat, monkeypatch):
    plugin, data, env = flat
    plugin.new_database("archive")
    plugin.share("data", "linux::Ubuntu", "read")
    theirs = env["SQLITE_INSTANCES"]
    # the same folder seen from another system: its instances are read from that system's own saved variables (through
    # the link), never from this one's login, and nothing of them is changed from here
    monkeypatch.setattr(mounts, "foreign", lambda path, mounts=None: True)
    asked: list = []

    def saved(self):
        asked.append(self.names)
        return {"SQLITE_INSTANCES": theirs}

    monkeypatch.setattr(config.UserEnvironment, "saved", saved)
    env.clear()
    assert [i.name for i in plugin.instances()] == ["data", "archive"] and asked[-1] == ("SQLITE_INSTANCES",)
    assert plugin.instance("data").shared == (Share("linux::Ubuntu", "read"),)
    status = plugin.status()
    assert status["foreign"] and status["can"] == {"new": False, "connect": False, "share": False, "forget": False,
                                                    "why": status["can"]["why"]}
    assert "changed from that system" in status["can"]["why"]
    assert [r["method"] for r in status["instances"]] == ["helper", "helper"]  # reached through the helper, by itself
    for change in (lambda: plugin.new_database("x"), lambda: plugin.connect_to("x", "backups/x.db"),
                   lambda: plugin.share("data", "linux::Ubuntu", "write"), lambda: plugin.forget("archive")):
        with pytest.raises(mounts.NotHere, match="done from that system, not from here"):
            change()
    assert env == {}
    # an engine with no helper reads such a file directly (DuckDB's closed months)
    assert plugin.with_(METHODS=("file",)).effective_method(plugin.instance("archive")) == "file"


def test_a_path_kept_on_one_system_is_named_on_the_other_only_where_it_can_be(flat, monkeypatch):
    plugin, data, _ = flat
    windows, linux = Instance("w", where=r"Q:\liminal\w.db"), Instance("l", where="/srv/liminal/l.db")
    if os.name == "nt":
        assert plugin.path_of(windows) == Path(r"Q:\liminal\w.db") and plugin.path_of(linux) is None
        other = linux
    else:
        assert plugin.path_of(linux) == Path("/srv/liminal/l.db") and plugin.path_of(windows) is None  # no mount of Q:
        monkeypatch.setattr(mounts, "here_path", lambda where: "/mnt/q/liminal/w.db")
        assert plugin.path_of(windows) == Path("/mnt/q/liminal/w.db")
        monkeypatch.setattr(mounts, "here_path", lambda where: None)
        other = windows
    state = plugin.state(other)
    assert state["state"] == "elsewhere" and state["path"] == other.where and "no name for that path" in state["why"]


# -- a server's -----------------------------------------------------------------------------------------------------------
def test_a_servers_instance_is_its_address_its_port_and_its_database(served, monkeypatch):
    plugin, data, env, servers = served
    asked: list = []
    monkeypatch.setattr(databases, "listening", lambda host, port, timeout=0.3: asked.append((host, port)) or (host, port) in servers)
    assert plugin.instances() == () and plugin.status()["defaultPort"] == 5432 and plugin.status()["server"] is True
    got = plugin.connect_to("docs", "127.0.0.1:5544", database="liminal", holds="documents")
    assert got["ok"] and got["said"] == "docs connected: 127.0.0.1:5544/liminal" and got["lines"][0] == "served 9.9"
    inst = plugin.instance("docs")
    assert (inst.where, inst.method, inst.port, inst.database, inst.remote, inst.auth) == ("127.0.0.1", "tcp", 5544, "liminal", False, False)
    assert plugin.path_of(inst) is None and plugin.effective_method(inst) == "tcp"
    assert plugin.state(inst) == {"method": "tcp", "methodTitle": "TCP", "address": "127.0.0.1:5544/liminal", "local": True,
                                  "state": "listening", "why": ""}
    servers.pop(("127.0.0.1", 5544))
    down = plugin.state(inst)
    assert down["state"] == "not running" and "never started to be asked" in down["why"]
    assert plugin.test("docs") == {"ok": False, "said": "docs did not answer: nothing answers at 127.0.0.1:5544", "lines": []}
    servers[("127.0.0.1", 5544)] = {"liminal": {}, "second": {}}
    # the port apart, and the engine's usual one when none is given
    assert plugin.connect_to("second", "127.0.0.1", port="5544", database="second", method="tcp")["ok"]
    assert plugin.instance("second").port == 5544
    servers[("localhost", 5432)] = {"plain": {}}
    assert plugin.connect_to("usual", "localhost", database="plain")["said"] == "usual connected: localhost:5432/plain"
    # a socket is its path
    servers[("/run/served", None)] = {"sock": {}}
    assert plugin.connect_to("sock", "/run/served", database="sock")["ok"] and plugin.instance("sock").method == "socket"
    assert plugin.state(plugin.instance("sock"))["state"] == "not asked" and plugin.state(plugin.instance("sock"))["local"] is True
    for kw, why in (({"where": "127.0.0.1", "database": ""}, "which database"), ({"where": "127.0.0.1", "database": "has space"}, "which database"),
                    ({"where": "127.0.0.1", "database": "liminal", "port": 0}, "a port is a number"),
                    ({"where": "127.0.0.1", "database": "liminal", "port": "http"}, "a port is a number"),
                    ({"where": "not a host!", "database": "liminal"}, "a server's address"),
                    ({"where": "127.0.0.1", "database": "liminal", "method": "file"}, "is reached by tcp, socket"),
                    ({"where": "relative/sock", "database": "liminal", "method": "socket"}, "a socket is its whole path"),
                    ({"where": "127.0.0.1", "database": "nope", "port": 5544}, "no database nope there"),
                    ({"where": "127.0.0.1", "database": "liminal", "port": 5544, "user": "u"}, "a name and a password")):
        with pytest.raises(Refusal, match=why):
            plugin.connect_to("x", **kw)
    assert sorted(i["name"] for i in json.loads(env["POSTGRES_INSTANCES"])["instances"]) == ["docs", "second", "sock", "usual"]
    assert all(databases.is_local(host) for host, _ in asked)  # a page's status asks this machine alone


def test_an_instances_port_is_its_own_and_changed_only_to_one_that_answers(served, flat):
    plugin, data, env, servers = served
    plugin.connect_to("docs", "127.0.0.1", port=5544, database="liminal")
    servers[("127.0.0.1", 6001)] = {"liminal": {}}
    moved = plugin.set_port("docs", "6001")
    assert moved == {"ok": True, "said": "docs's port is 6001 now", "lines": ["served 9.9", "kept in the login's variables"]}
    assert plugin.instance("docs").port == 6001 and json.loads(env["POSTGRES_INSTANCES"])["instances"][0]["port"] == 6001
    assert plugin.set_port("docs", 6001)["said"] == "docs's port is 6001 already"
    with pytest.raises(Refusal, match="nothing answered at 127.0.0.1:6002/liminal, so docs's port stays 6001"):
        plugin.set_port("docs", 6002)
    for bad in (0, 70000, "http", None, True):
        with pytest.raises(Refusal, match="a port is a number from 1 to 65535"):
            plugin.set_port("docs", bad)
    assert plugin.instance("docs").port == 6001
    # one of the plugin's own is the plugin's to change: the contract changes none
    own = Instance("here", where="127.0.0.1", method="tcp", port=5544, database="liminal")
    with_own = plugin.with_(builtin=lambda data_dir: (own,))
    with pytest.raises(Refusal, match="here is Served's own: its port is not changed here"):
        with_own.set_port("here", 6001)
    asked: list = []
    answering = with_own.with_(own_port=lambda instance, port, data_dir: asked.append((instance.name, port)) or {"ok": True})
    assert answering.set_port("here", 6001) == {"ok": True} and asked == [("here", 6001)]
    # a socket has none, a file has none
    servers[("/run/served", None)] = {"sock": {}}
    plugin.connect_to("sock", "/run/served", database="sock")
    with pytest.raises(Refusal, match="sock is reached by its socket: it has no port"):
        plugin.set_port("sock", 6001)
    files, _, _ = flat
    with pytest.raises(Refusal, match="data is reached by its file: it has no port"):
        files.set_port("data", 6001)


def test_a_server_off_this_machine_is_kept_only_when_asked_twice_with_tls_and_a_sign_in(served, monkeypatch):
    plugin, data, env, servers = served

    def never(host, port, timeout=0.3):
        raise AssertionError(f"{host} asked without the user's test")

    monkeypatch.setattr(databases, "listening", never)
    with pytest.raises(Refusal, match="db.example.net is not this machine") as first:
        plugin.connect_to("far", "db.example.net", database="docs", tls=True, user="reader", password="far-secret")
    assert first.value.accept == "accept_remote" and env == {}  # nothing kept, not even the sign-in
    for kw in ({"tls": False, "user": "reader", "password": "far-secret"}, {"tls": True}):
        with pytest.raises(Refusal, match="only with TLS and a sign-in") as second:
            plugin.connect_to("far", "db.example.net", database="docs", accept_remote=True, **kw)
        assert second.value.accept is None
    with pytest.raises(Refusal, match="did not answer, so it is not kept: the sign-in was refused"):
        plugin.connect_to("far", "db.example.net", database="docs", tls=True, accept_remote=True, user="reader", password="wrong")
    assert env == {}  # a sign-in that did not work is forgotten again
    got = plugin.connect_to("far", "db.example.net", database="docs", tls=True, accept_remote=True, user="reader",
                            password="far-secret")
    assert got["ok"] and got["said"] == "far connected: db.example.net:5432/docs"
    inst = plugin.instance("far")
    assert inst.remote and inst.tls and inst.auth and inst.role == "reader"
    state = plugin.state(inst)  # never asked by a status: another machine is asked only by a test the user starts
    assert state["state"] == "not asked" and state["local"] is False and state["address"] == "db.example.net:5432/docs"
    assert plugin.test("far")["ok"] and plugin.status()["instances"][0]["signsIn"] is True


def test_a_sign_in_is_two_pairs_through_the_login_and_never_in_what_is_kept_or_shown(served):
    plugin, data, env, servers = served
    servers[("127.0.0.1", 5544)]["guarded"] = {"liminal": "s3cret-pass"}
    plugin.connect_to("guarded", "127.0.0.1", port=5544, database="guarded", user="liminal", password="s3cret-pass")
    assert env["POSTGRES_GUARDED_USER"] == "liminal" and env["POSTGRES_GUARDED_PASSWORD"] == "s3cret-pass"
    assert "s3cret" not in env["POSTGRES_INSTANCES"] and "s3cret" not in json.dumps(plugin.status())
    assert plugin.credentials(plugin.instance("guarded")) == ("liminal", "s3cret-pass")
    # changed: both, or neither
    servers[("127.0.0.1", 5544)]["guarded"] = {"other": "n3w-pass"}
    assert plugin.test("guarded")["ok"] is False
    changed = plugin.set_credentials("guarded", "other", "n3w-pass")
    assert changed["said"] == "guarded's sign-in kept" and "n3w" not in json.dumps(changed) and plugin.test("guarded")["ok"]
    assert changed["lines"] == ["kept in the login's variables", "Test says whether the server takes it"]
    # whole, or not at all: a password that cannot be kept leaves no name behind, and the one before stays as it was

    class Full(EnvironmentLogin):
        def save(self, variable, value):
            if variable.endswith("_PASSWORD") and value:
                raise OSError("no room for it")
            return super().save(variable, value)

    full = plugin.with_(login=Full(env=env))
    with pytest.raises(OSError, match="no room for it"):
        full.set_credentials("guarded", "third", "p4ss")
    assert "POSTGRES_GUARDED_USER" not in env and plugin.instance("guarded").role == "other"
    plugin.set_credentials("guarded", "other", "n3w-pass")
    assert plugin.instance("guarded").role == "other"
    with pytest.raises(Refusal, match="both, or neither"):
        plugin.set_credentials("guarded", "other", "")
    assert plugin.set_credentials("guarded", "", "")["said"] == "guarded's sign-in forgotten"
    assert "POSTGRES_GUARDED_USER" not in env and plugin.instance("guarded").auth is False
    assert plugin.credentials(plugin.instance("guarded")) is None and plugin.status()["instances"][0].get("signsIn") is None
    # forgotten with the instance
    plugin.set_credentials("guarded", "other", "n3w-pass")
    assert "its sign-in is forgotten" in plugin.forget("guarded")["lines"]
    assert [k for k in env if k.startswith("POSTGRES_GUARDED")] == [] and "POSTGRES_INSTANCES" not in env
    # a file takes none
    flat_ = Flat()
    flat_.attach(plugin.app, plugin.login)
    (data / "liminal.db").write_text("flat\n", encoding="utf-8")
    with pytest.raises(Refusal, match="is a file: nothing signs in to it"):
        flat_.set_credentials("data", "u", "p")


def test_a_new_database_on_a_server_gets_a_role_of_its_own_and_the_administrator_is_not_kept(served):
    plugin, data, env, servers = served
    made = plugin.new_database("filings", "127.0.0.1", holds="documents", port=5544, admin_user="postgres",
                               admin_password="admin-secret")
    assert made["ok"] and made["said"] == "filings made: 127.0.0.1:5544/filings"
    assert made["lines"][:2] == ["filings made", "the role liminal_filings made for it"]
    inst = plugin.instance("filings")
    assert inst.made and inst.auth and inst.role == "liminal_filings" and inst.grants == ("read", "write") and inst.database == "filings"
    password = env["POSTGRES_FILINGS_PASSWORD"]
    assert servers[("127.0.0.1", 5544)]["filings"] == {"liminal_filings": password} and env["POSTGRES_FILINGS_USER"] == "liminal_filings"
    everything = json.dumps(env) + json.dumps(made) + json.dumps(plugin.status())
    assert "admin-secret" not in everything and password not in env["POSTGRES_INSTANCES"] + json.dumps(made) + json.dumps(plugin.status())
    assert plugin.test("filings")["ok"]
    # a server that takes no sign-in: the database alone
    plain = plugin.new_database("notes", "127.0.0.1", port=5544, database="notes_db")
    assert plain["lines"][0] == "notes_db made" and plugin.instance("notes").auth is False and plugin.instance("notes").role == ""
    with pytest.raises(PermissionError, match="administrator's sign-in was refused"):
        plugin.new_database("third", "127.0.0.1", port=5544, admin_user="postgres", admin_password="wrong")
    with pytest.raises(ValueError, match="filings is there already"):
        plugin.new_database("again", "127.0.0.1", port=5544, database="filings")
    assert sorted(i["name"] for i in json.loads(env["POSTGRES_INSTANCES"])["instances"]) == ["filings", "notes"]
    # off this machine: asked twice, and then only with a role (the administrator given) and TLS
    with pytest.raises(Refusal) as e:
        plugin.new_database("away", "db.example.net", admin_user="postgres", admin_password="x", tls=True)
    assert e.value.accept == "accept_remote"
    with pytest.raises(Refusal, match="only with TLS and a sign-in"):
        plugin.new_database("away", "db.example.net", accept_remote=True, tls=True)


def test_whether_a_port_of_this_machine_listens_is_remembered_a_moment_and_another_machines_never(monkeypatch):
    from liminal_libs.storage import instances

    asked: list = []
    clock = {"now": 50.0}

    class Answers:
        def __init__(self, address):
            asked.append(address)
            if address[1] != 4000:
                raise ConnectionRefusedError("nothing there")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(instances.socket, "create_connection", lambda address, timeout=None: Answers(address))
    monkeypatch.setattr(instances.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(instances, "_heard", {})
    assert instances.listening("127.0.0.1", 27017) is False and instances.listening("127.0.0.1", 27017) is False
    assert instances.listening("LOCALHOST", 4000) is True and instances.listening("localhost", 4000) is True
    assert asked == [("127.0.0.1", 27017), ("localhost", 4000)]  # each asked once: the second answer was remembered
    assert instances.listening("127.0.0.1", 27017, fresh=True) is False and len(asked) == 3  # asked now all the same
    clock["now"] += instances.HEARD_S
    assert instances.listening("127.0.0.1", 27017) is False and len(asked) == 4  # and again once the moment is over
    # another machine is asked each time it is asked at all (only a test the user starts asks it)
    assert instances.listening("db.example.net", 4000) is True and instances.listening("db.example.net", 4000) is True
    assert asked[-2:] == [("db.example.net", 4000)] * 2 and ("db.example.net", 4000) not in instances._heard
    assert instances.listening("127.0.0.1", "not a port") is False and instances.listening("127.0.0.1", True) is False
    assert len(asked) == 6  # what is no port is asked of nobody


# -- the shares a helper keeps to -----------------------------------------------------------------------------------------
def test_a_helpers_policy_lets_a_suite_in_as_its_share_says(tmp_path):
    data, other = tmp_path / "data", tmp_path / "other"
    for folder in (data, data / "feeds", data / "instances", other, tmp_path / "ledger"):
        folder.mkdir()
    kept = {"text": ""}
    clock = {"now": 100.0}
    policy = SharePolicy(lambda: kept["text"], data, clock=lambda: clock["now"])
    main, bars = str(data / "liminal.db"), str(data / "feeds" / "massive.db")
    # nothing set: as before, whoever asks, whatever it says of itself
    assert policy.access(main, "linux::Ubuntu") == ("write", "") and policy.access(bars, "") == ("write", "") and policy.roots() == []
    mine = Kept(instances={
        "archive": Instance("archive", where="instances/archive.db", shared=(Share("linux::Ubuntu", "write"),)),
        "away": Instance("away", where=str(other / "away.db"), shared=(Share("linux::Fedora", "read"),)),
        "private": Instance("private", where=str(tmp_path / "private" / "p.db")),
        "server": Instance("server", where="127.0.0.1", method="tcp", port=5432)},
        builtin={"data": (Share("linux::Ubuntu", "read"),)})
    kept["text"] = mine.text()
    assert policy.access(main, "linux::Ubuntu") == ("write", "")  # read a moment ago: asked again only after a while
    clock["now"] += databases.POLICY_S
    assert policy.access(main, "linux::Ubuntu") == ("read", "data is shared with linux::Ubuntu for reading only")
    assert policy.access(bars, "linux::Ubuntu")[0] == "read"  # every file of the data folder is the data instance's
    assert policy.access(main, "linux::Fedora") == ("", "data is not shared with linux::Fedora (linux::Ubuntu may attach)")
    refused = policy.access(main, "")
    assert refused[0] == "" and "does not say who it is" in refused[1] and "1.61.0" in refused[1]
    # an instance the user added is its own: its shares, not the folder's
    archive = data / "instances" / "archive.db"
    assert policy.access(str(archive), "linux::Ubuntu") == ("write", "") and policy.access(str(archive) + "-wal", "linux::Ubuntu")[0] == "write"
    assert policy.access(str(archive), "linux::Fedora")[0] == "" and policy.access(str(data / "instances" / "archive2.db"), "linux::Ubuntu")[0] == "read"
    assert policy.access(str(other / "away.db"), "linux::Fedora")[0] == "read" and policy.access(str(other / "away.db"), "linux::Ubuntu")[0] == ""
    # what the helper may open besides its own folders: the folders of the instances shared with someone, no other
    assert policy.roots() == [other.resolve()]
    assert policy.access(str(tmp_path / "ledger" / "requests.db"), "linux::Ubuntu") == ("write", "")  # its other folders: as they were
    # settings that cannot be read are as none set
    kept["text"] = "{broken"
    clock["now"] += databases.POLICY_S
    assert policy.access(main, "linux::Fedora") == ("write", "") and policy.roots() == []
