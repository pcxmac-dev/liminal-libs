"""A store's pick naming an instance (1.91.0, Monday list item 10; item 30's step 7): `engine:instance` picks one of the
database plugins' instances, opened through the plugin's `open` in this process; a bare engine is today's store,
unchanged. Stand-in plugins and stand-in servers (an in-memory SQLite database that speaks for a PostgreSQL or MariaDB
one, its statements translated where they differ): no server, no process, no port, no network."""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from liminal_libs import gov, mongo, stores
from liminal_libs.apps import EnvironmentLogin
from liminal_libs.sources import registry
from liminal_libs.storage import Store
from liminal_libs.storage.databases import DatabasePlugin, Instance, variable_of
from liminal_libs.storage.documents import GOV_ITEMS, NEWS, SqlDocuments

pytestmark = pytest.mark.usefixtures("no_outside", "stand_in_environment")

NOW = datetime(2026, 11, 25, 12, tzinfo=timezone.utc)


# -- a stand-in server --------------------------------------------------------------------------------------------------
class Server:
    """A database on a stand-in server: an in-memory SQLite database, every statement noted, MariaDB's words and the
    format marks translated to SQLite's. `down`: every connection refused, as a server that does not answer."""

    def __init__(self, dialect: str):
        self.dialect = dialect
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.log: list[str] = []
        self.opened: list["Conn"] = []
        self.down = False

    def connect(self, read_only: bool):
        if self.down:
            raise ConnectionRefusedError("the stand-in server does not answer")
        conn = Conn(self, read_only)
        self.opened.append(conn)
        return conn

    def rows(self, table: str) -> list[tuple]:
        try:
            return self.db.execute(f"SELECT * FROM {table}").fetchall()
        except sqlite3.OperationalError:
            return []

    def translate(self, sql: str) -> str:
        sql = sql.replace("%s", "?")
        if self.dialect == "mariadb":
            assert '"' not in sql, sql  # (MariaDB quotes a name with backticks)
            sql = sql.replace(" DEFAULT CHARSET=utf8mb4", "")
            sql = sql.replace(" ON DUPLICATE KEY UPDATE doc_id = doc_id", " ON CONFLICT (doc_id) DO NOTHING")
            if " ON DUPLICATE KEY UPDATE " in sql:
                sql = re.sub(r"VALUES\((`[^`]+`)\)", r"excluded.\1",
                             sql.replace(" ON DUPLICATE KEY UPDATE ", " ON CONFLICT (doc_id) DO UPDATE SET "))
        else:
            assert "`" not in sql, sql
        return sql


class Cursor:
    def __init__(self, conn):
        self.conn, self.rows = conn, []

    def execute(self, sql, args=()):
        assert not self.conn.closed, "a closed connection was used"
        self.conn.server.log.append(sql)
        if self.conn.read_only and not sql.lstrip().upper().startswith("SELECT"):
            raise PermissionError("cannot execute that in a read-only transaction")
        self.rows = self.conn.server.db.execute(self.conn.server.translate(sql), list(args)).fetchall()

    def executemany(self, sql, rows):
        assert not self.conn.closed, "a closed connection was used"
        self.conn.server.log.append(sql)
        if self.conn.read_only:
            raise PermissionError("cannot execute INSERT in a read-only transaction")
        self.conn.server.db.executemany(self.conn.server.translate(sql), [list(r) for r in rows])

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)


class Conn:
    def __init__(self, server, read_only):
        self.server, self.read_only, self.closed = server, read_only, False

    def cursor(self):
        return Cursor(self)

    def commit(self):
        self.server.db.commit()

    def rollback(self):
        self.server.db.rollback()

    def close(self):
        self.closed = True


# -- stand-in plugins ---------------------------------------------------------------------------------------------------
class ServerPlugin(DatabasePlugin):
    """A server engine's plugin whose `open` reaches a stand-in server for each of its instances."""

    api = "2.3"
    METHODS = ("tcp",)
    HOLDS = ("documents",)
    SERVER = True
    servers: dict = {}

    def builtin(self, data_dir):
        return ()

    def open(self, instance, part="", read_only=True, data_dir=None):
        self.opens.append((instance.name, read_only))
        return self.servers[instance.name].connect(read_only)


class PostgresStandIn(ServerPlugin):
    name, title, ENGINE = "postgres", "PostgreSQL", "postgres"
    options = (variable_of("postgres"),)


class MariadbStandIn(ServerPlugin):
    name, title, ENGINE = "mariadb", "MariaDB", "mariadb"
    options = (variable_of("mariadb"),)
    DRIVER = "pymysql_not_here_at_all"
    DRIVER_HINT = "driver not installed: PyMySQL is not in the app's Python"


class SqliteStandIn(DatabasePlugin):
    """SQLite's: its own instance the data folder (a bare `sqlite` pick), and files the user adds."""

    name, title, ENGINE, api = "sqlite", "SQLite", "sqlite", "2.3"
    options = (variable_of("sqlite"),)
    METHODS = ("file",)
    HOLDS = ("main", "documents")

    def builtin(self, data_dir):
        return (Instance("data", "The data folder", where="./", holds=self.HOLDS),)

    def open(self, instance, part="", read_only=True, data_dir=None):
        self.opens.append((instance.name, read_only))
        path = self.path_of(instance, data_dir)
        assert path is not None and path.is_file()
        return sqlite3.connect(path)


def kept(*instances) -> str:
    return json.dumps({"v": 1, "instances": list(instances)})


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A data folder, its main file and gov.db, and the stand-in plugins attached with a login of their own: PostgreSQL
    with `main` (documents) and `other` (holding the main file's things only), MariaDB with `docs` (its driver missing
    until a test says otherwise), SQLite with its data folder and a file `extra`. The plugins `federal` (an agency's
    items, fed-press) and `massive` (its headlines) keep documents. MongoDB is never asked."""
    main = tmp_path / "liminal.db"
    (tmp_path / "extra.db").write_bytes(b"")
    sqlite3.connect(tmp_path / "extra.db").close()
    env = {
        "POSTGRES_INSTANCES": kept({"name": "main", "title": "Main documents", "where": "127.0.0.1", "method": "tcp",
                                    "port": 5432, "database": "liminal_docs", "holds": ["documents"]},
                                   {"name": "other", "where": "127.0.0.1", "method": "tcp", "database": "x",
                                    "holds": ["main"]}),
        "MARIADB_INSTANCES": kept({"name": "docs", "where": "127.0.0.1", "method": "tcp", "port": 3306,
                                   "database": "liminal_docs"}),
        "SQLITE_INSTANCES": kept({"name": "extra", "where": "extra.db", "method": "file", "holds": ["documents"]}),
    }
    reads: list[str] = []

    class Login(EnvironmentLogin):
        def variables(self, names):
            reads.extend(names)
            return super().variables(names)

    login = Login(env=env)
    pg, maria, lite = PostgresStandIn(), MariadbStandIn(), SqliteStandIn()
    servers = {"main": Server("postgres"), "other": Server("postgres"), "docs": Server("mariadb")}
    for p in (pg, maria, lite):
        p.attach(SimpleNamespace(db_path=main), login)
        p.__dict__["opens"] = []
        p.__dict__["servers"] = servers
    plugins = {"postgres": pg, "mariadb": maria, "sqlite": lite}
    monkeypatch.setattr(registry, "database", lambda name: plugins.get(name))
    monkeypatch.setattr(registry, "databases", lambda: dict(plugins))
    monkeypatch.setattr(stores, "plugin_types", lambda name: ["documents"] if name in ("federal", "massive") else [])
    monkeypatch.setattr(stores, "document_scopes", lambda name: {
        "federal": [(GOV_ITEMS, {"source": ["fed-press"]})], "massive": [(NEWS, {"source": ["massive"]})]}.get(name, []))
    monkeypatch.setattr(stores, "item_plugin", lambda source: "federal" if source == "fed-press" else None)
    monkeypatch.setattr(mongo, "binary", lambda: None)  # MongoDB not installed: never asked
    monkeypatch.setattr(mongo, "database", lambda: pytest.fail("MongoDB was asked"))
    stores.forget_instances()
    stores.close_instances()
    store = Store(main, check_same_thread=False)
    gdb = gov.open_db(main)
    yield SimpleNamespace(main=main, store=store, gdb=gdb, env=env, plugins=plugins, servers=servers, reads=reads,
                          folder=tmp_path, login=login)
    gdb.close()
    store.close()
    stores.close_instances()
    stores.forget_instances()


def item(i, title="t"):
    return {"id": str(i), "agency": "Fed", "title": title, "published": f"2026-11-2{i}T18:00:00", "tags": ["FOMC"]}


def headline(i, t):
    return {"id": str(i), "published_ms": t, "title": f"h{i}", "publisher": "P", "url": None, "tickers": ["AAPL"]}


def held_here(w) -> tuple[int, int]:
    return (w.gdb.conn.execute("SELECT COUNT(*) FROM items").fetchone()[0],
            w.store.conn.execute("SELECT COUNT(*) FROM news").fetchone()[0])


# -- the tests ----------------------------------------------------------------------------------------------------------
def test_a_pick_naming_an_instance_writes_there_and_nowhere_else(world):
    w = world
    w.gdb.save_items("fed-press", [item(1, "before")], NOW)  # held before the pick: stays in gov.db
    assert held_here(w) == (1, 0)
    stores.pick(w.store, "federal", "documents", "postgres:main")
    assert stores.picked(w.store, "federal", "documents") == "postgres:main"
    assert stores.in_effect(w.store, "federal", "documents") == "postgres:main"  # at once: nothing to settle
    assert w.servers["main"].rows("liminal_gov_items") == []  # nothing was moved there
    w.gdb._engines_seen = None
    assert w.gdb.save_items("fed-press", [item(2, "after"), item(3, "later")], NOW) == 2
    assert w.gdb.save_items("fed-press", [item(2, "again")], NOW) == 0  # one held keeps its own
    assert held_here(w) == (1, 0)  # nothing new in gov.db
    rows = w.servers["main"].rows("liminal_gov_items")
    assert len(rows) == 2 and all(r[0] and len(r[0]) == 64 for r in rows)  # doc_id: the key's sha256
    assert {r[2] for r in rows} == {"2", "3"} and all(json.loads(r[8]) == ["FOMC"] for r in rows)
    assert w.servers["other"].log == [] and w.servers["docs"].log == []  # no other instance asked
    assert w.plugins["postgres"].opens == [("main", False)]  # opened once, through the plugin, and kept
    # read from there, with gov.db's copy of what was before
    assert [i["title"] for i in w.gdb.items()] == ["later", "after", "before"]
    # read back from where they were written (the publications' audit)
    held = w.gdb.items_held("fed-press", ["2", "3", "9"])
    assert sorted(held) == ["2", "3"] and held["2"]["title"] == "after" and held["2"]["tags"] == ["FOMC"]
    assert w.gdb.items_unlike("fed-press", [item(2, "after")], NOW, {}) == []
    # the hourly settle moves nothing: the old store keeps what it holds
    lines = []
    assert stores.settle(w.store, w.gdb.conn, w.folder, lines.append) == [] and lines == []
    assert held_here(w) == (1, 0) and len(w.servers["main"].rows("liminal_gov_items")) == 2

    # a vendor's headlines to MariaDB, its driver there now
    w.plugins["mariadb"].__dict__["DRIVER"] = ""
    w.store.save_news("massive", [headline(1, 1000)])  # before: in the main file
    stores.pick(w.store, "massive", "documents", "mariadb:docs")
    assert w.store.save_news("massive", [headline(2, 2000), headline(3, 3000)]) == 2
    assert w.store.save_news("massive", [{**headline(2, 2000), "title": "changed"}]) == 1  # headlines are replaced
    assert held_here(w) == (1, 1)
    news = w.servers["docs"].rows("liminal_news")
    assert sorted(r[2] for r in news) == ["2", "3"] and isinstance(news[0][3], int)  # published_ms: a number
    assert [n["id"] for n in w.store.news()] == ["3", "2", "1"] and w.store.news()[1]["title"] == "changed"
    assert [n["id"] for n in w.store.news("massive", since_ms=2000)] == ["3", "2"]
    assert w.store.latest_news_ms("massive") == 3000
    assert w.servers["main"].rows("liminal_news") == []


def test_a_bare_pick_behaves_exactly_as_before(world):
    w = world
    assert stores.wanted(w.store, "federal", "documents") == stores.optimal("documents") == "sqlite"
    stores.pick(w.store, "federal", "documents", "sqlite")
    assert stores.picked(w.store, "federal", "documents") == "sqlite"
    assert w.store.kv_get("store:effect:federal:documents") is None  # in effect is still settle's to say
    assert stores.in_effect(w.store, "federal", "documents") == "sqlite"
    w.gdb.save_items("fed-press", [item(1)], NOW)
    w.store.save_news("massive", [headline(1, 1000)])
    assert held_here(w) == (1, 1)
    assert stores.settle(w.store, w.gdb.conn, w.folder) == []  # nothing to move, as before
    # an engine's own instance named is the bare engine, the same store
    stores.pick(w.store, "federal", "documents", "sqlite:data")
    assert stores.picked(w.store, "federal", "documents") == "sqlite"
    # no plugin was opened, no server asked, and the old refusals are the same
    assert all(not p.opens for p in w.plugins.values()) and all(not s.log for s in w.servers.values())
    with pytest.raises(RuntimeError, match="not installed"):
        stores.pick(w.store, "federal", "documents", "mongodb")
    with pytest.raises(ValueError, match="kept in MongoDB, SQLite"):
        stores.pick(w.store, "federal", "documents", "duckdb")
    with pytest.raises(LookupError):
        stores.pick(w.store, "nobody", "documents", "sqlite")
    stores.pick(w.store, "federal", "documents", None)
    assert stores.picked(w.store, "federal", "documents") is None
    row = stores.plugin_stores(w.store, "federal", w.gdb.conn)[0]
    assert [e["name"] for e in row["engines"]] == ["mongodb", "sqlite"]  # the bare engines, as before
    assert row["counts"] == {"mongodb": None, "sqlite": 1}


def test_a_pick_that_cannot_be_used_is_refused_in_words(world):
    w = world
    cases = [
        ("postgres:nope", "PostgreSQL has no instance 'nope' here: add it on the platform's Databases section"),
        ("postgres:other", "postgres:other holds main, not documents"),
        ("mariadb:docs", "mariadb:docs cannot be opened here: driver not installed: PyMySQL is not in the app's Python"),
        ("postgres", "PostgreSQL has no store of its own here: pick one of its instances, postgres:<instance>"),
        ("duckdb:history", "documents are kept in MongoDB, SQLite, PostgreSQL, MariaDB"),
    ]
    for given, words in cases:
        with pytest.raises(ValueError, match=re.escape(words)):
            stores.pick(w.store, "federal", "documents", given)
        assert stores.picked(w.store, "federal", "documents") is None
    del w.plugins["postgres"]  # its plugin not installed here
    with pytest.raises(stores.PickRefused, match=re.escape("PostgreSQL has no plugin installed here (plugin-platform-postgres)")):
        stores.pick(w.store, "federal", "documents", "postgres:main")
    with pytest.raises(stores.PickRefused, match="only documents go to an instance you add"):
        stores.resolve("sqlite:extra", "bars")


def test_an_instance_gone_after_its_pick_is_refused_where_it_is_written(world):
    """Never written elsewhere: the read is tried again at its next due time (the pull stays in the fetch cache)."""
    w = world
    stores.pick(w.store, "federal", "documents", "postgres:main")
    w.env["POSTGRES_INSTANCES"] = kept()  # removed on the platform
    stores.forget_instances()
    with pytest.raises(stores.PickRefused, match="has no instance 'main'"):
        w.gdb.save_items("fed-press", [item(1)], NOW)
    assert held_here(w) == (0, 0)
    # the instance back, its server down: the driver's words, and still nothing elsewhere
    w.env["POSTGRES_INSTANCES"] = kept({"name": "main", "where": "127.0.0.1", "method": "tcp", "database": "d"})
    w.servers["main"].down = True
    with pytest.raises(ConnectionRefusedError):
        w.gdb.save_items("fed-press", [item(1)], NOW)
    assert held_here(w) == (0, 0)
    assert [i["title"] for i in w.gdb.items()] == []  # a read: what gov.db holds, nothing raised
    row = stores.plugin_stores(w.store, "federal", w.gdb.conn)[0]
    assert row["wanted"] == row["effect"] == "postgres:main" and "refused" not in row
    assert row["counts"]["postgres:main"] is None  # asked, and it did not answer


def test_a_sqlite_file_the_user_added_holds_documents(world):
    w = world
    stores.pick(w.store, "federal", "documents", "sqlite:extra")
    w.gdb._engines_seen = None
    assert w.gdb.save_items("fed-press", [item(1), item(2)], NOW) == 2
    assert held_here(w) == (0, 0)
    with sqlite3.connect(w.folder / "extra.db") as c:
        assert c.execute("SELECT COUNT(*) FROM liminal_gov_items").fetchone()[0] == 2
    assert w.plugins["sqlite"].opens and all(o == ("extra", False) for o in w.plugins["sqlite"].opens)
    assert [i["id"] for i in w.gdb.items()] == ["2", "1"]
    # a folder the user added is no one file to keep them in
    w.env["SQLITE_INSTANCES"] = kept({"name": "box", "where": "box/", "method": "file", "holds": ["documents"]})
    stores.forget_instances()
    with pytest.raises(stores.PickRefused, match="sqlite:box is a folder"):
        stores.pick(w.store, "federal", "documents", "sqlite:box")


def test_the_picker_lists_the_instances_that_can_hold_documents(world):
    w = world
    got = stores.instance_choices("documents", w.folder)
    assert [(c["name"], c["title"], c["ok"]) for c in got] == [
        ("sqlite:extra", "extra", True), ("postgres:main", "Main documents", True), ("mariadb:docs", "docs", False)]
    assert got[2]["why"].startswith("driver not installed") and got[1]["engineTitle"] == "PostgreSQL"
    assert stores.instance_choices("bars", w.folder) == []
    row = stores.plugin_stores(w.store, "federal", w.gdb.conn)[0]
    assert [c["name"] for c in row["instances"]] == ["sqlite:extra", "postgres:main", "mariadb:docs"]
    assert "moves nothing" in row["moves"] and "stays where it is" in row["moves"]


def test_the_instance_list_is_read_once_and_kept(world):
    w = world
    w.reads.clear()
    for _ in range(3):
        stores.resolve("postgres:main", "documents", w.folder)
    assert w.reads.count("POSTGRES_INSTANCES") == 1
    # one added on the platform since: read again once, when asked for
    w.env["POSTGRES_INSTANCES"] = kept({"name": "main", "where": "127.0.0.1", "method": "tcp", "database": "d"},
                                       {"name": "new", "where": "127.0.0.1", "method": "tcp", "database": "n"})
    stores.resolve("postgres:new", "documents", w.folder)
    assert w.reads.count("POSTGRES_INSTANCES") == 2


def test_connections_kept_are_capped_and_closed(world, monkeypatch):
    w = world
    monkeypatch.setattr(stores, "POOL_MOST", 1)
    a = stores.named_backend("postgres:main", NEWS, w.folder)
    a.count()
    first = w.servers["main"].opened[0]
    w.plugins["mariadb"].__dict__["DRIVER"] = ""
    stores.named_backend("mariadb:docs", NEWS, w.folder).count()
    assert first.closed and not w.servers["docs"].opened[0].closed  # the oldest closed past the cap
    stores.close_instances()
    assert w.servers["docs"].opened[0].closed


@pytest.mark.parametrize("dialect", ["postgres", "mariadb", "sqlite"])
def test_sql_documents_answer_as_the_others_do(dialect):
    server = Server("postgres" if dialect == "sqlite" else dialect)
    if dialect == "sqlite":
        server.translate = lambda sql: sql  # SQLite's own words
    from contextlib import contextmanager

    @contextmanager
    def session():
        yield server.connect(False)

    docs = SqlDocuments(session, NEWS, dialect, place=f"test:{dialect}")
    n = lambda i, t, title="x": {"source": "massive", "id": str(i), "published_ms": t, "title": title,  # noqa: E731
                                 "publisher": "P", "url": None, "tickers": ["AAPL"]}
    assert docs.put([n(1, 100), n(2, 300), n(3, 200)], replace=True) == 3
    assert docs.put([n(2, 300, "changed")], replace=True) == 1
    assert docs.count() == 3 and docs.count({"source": ["massive"]}) == 3 and docs.count({"source": []}) == 0
    assert [d["id"] for d in docs.find({"source": "massive"})] == ["2", "3", "1"]  # newest first
    assert [d["id"] for d in docs.find(since=200, limit=1)] == ["2"]
    assert docs.find({"id": "2"})[0]["title"] == "changed" and docs.find({"id": "2"})[0]["tickers"] == ["AAPL"]
    assert docs.newest({"source": "massive"}) == 300 and docs.newest({"source": "other"}) is None
    batches = list(docs.every(batch=2))
    assert [len(b) for b in batches] == [2, 1] and sorted(d["id"] for b in batches for d in b) == ["1", "2", "3"]
    assert all("LIMIT 2" in s for s in server.log if s.startswith("SELECT doc_id, "))  # a batch at a time
    items = SqlDocuments(session, GOV_ITEMS, dialect, place=f"test:{dialect}")
    one = {"source": "fed-press", "id": "a", "agency": "Fed", "title": "first", "published": "2026-10-01",
           "tags": ["FOMC"], "fetched_at": "t"}
    assert items.put([one]) == 1 and items.put([{**one, "title": "again"}]) == 0  # one held keeps its own
    assert items.find()[0]["title"] == "first" and items.find()[0]["tags"] == ["FOMC"]
    with pytest.raises(ValueError, match="no field"):
        items.find({"nope": 1})
    made = [s for s in server.log if s.startswith("CREATE TABLE")]
    assert len(made) == 2  # each table made once in this process
    assert ("`liminal_news`" if dialect == "mariadb" else '"liminal_news"') in made[0]


def test_the_real_postgres_plugin_opens_for_a_pick(tmp_path, monkeypatch):
    """Where the PostgreSQL plugin is installed: its own `open` reaches the stand-in through its driver's name."""
    import importlib

    plugin = registry.database("postgres")
    if plugin is None or type(plugin).__module__ != "plugin_platform_postgres":
        pytest.skip("the PostgreSQL plugin is not installed here")
    module = importlib.import_module("plugin_platform_postgres")
    server = Server("postgres")
    given = []
    monkeypatch.setattr(module, "pg_connect", lambda **kw: given.append(kw) or server.connect(False))
    env = {"POSTGRES_INSTANCES": kept({"name": "main", "where": "127.0.0.1", "method": "tcp", "port": 5432,
                                       "database": "liminal_docs", "holds": ["documents"]})}
    mine = plugin.with_(login=EnvironmentLogin(env=env))
    monkeypatch.setattr(registry, "database", lambda name: mine if name == "postgres" else None)
    stores.forget_instances()
    stores.close_instances()
    try:
        docs = stores.named_backend("postgres:main", NEWS, tmp_path)
        assert docs.put([{"source": "massive", "id": "1", "published_ms": 5, "title": "x", "publisher": None,
                          "url": None, "tickers": []}]) == 1
        assert given and given[0]["database"] == "liminal_docs" and given[0]["host"] == "127.0.0.1"
        assert len(server.rows("liminal_news")) == 1 and server.opened[0].read_only is False
    finally:
        stores.close_instances()
        stores.forget_instances()
