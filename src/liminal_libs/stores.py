"""Stores: which engine keeps each kind of a plugin's data, and the Store picker.

The user, 2026-10-31: "each module needs to support sqlite or mongo or duck db based on data type";
"lets have a 'store' picker so i can choose manually, but lets try to use the optimal data store for
the data type". Each data type lists the engines it can be kept in, the optimal first:
- bars: DuckDB (the open months in SQLite, where the feeds write; the closed ones in DuckDB, read by
  column: storage/history.py) or SQLite alone;
- documents (an agency's releases and rules, a vendor's headlines; filings and records as they come):
  MongoDB (installed here, mongo.py) or SQLite (storage/documents.py);
- series (a dataset's): SQLite (small series changed in place);
- files (the downloads as downloaded): a folder.
A plugin's choice per data type is its pick (the Plugins view), or, left to the app, the optimal one
available here. Where the data is follows the choice: bars a closed month at a time (the hourly
sync's `history run`), documents at once (settle: copied, counted, then read and written there).
What the store left holds stays ("we should always keep all source data"): only the user removes it.

A pick may name an instance (1.91.0, Monday list item 10; item 30's step 7): `engine:instance`, for example
`postgres:main`, one of the database plugins' instances the user added on the platform's Databases section. A bare
engine keeps meaning today's store, its plugin's own instance (sqlite: the data folder; mongodb: the server here), and
naming that own instance is the same as the bare engine. Documents alone go to an instance for now (bars and series
after). A pick naming an instance moves nothing: what the store left holds stays where it is, and only where new
documents are written changes, at once (no settle); they are read from there and from the SQLite file's copy. The
instance is opened through its plugin's `open` (`registry.database(engine)`, the class loaded in this process, no hop),
its list read through the plugin's login once and kept in memory (`NAMED_S`). An instance that is not there, whose
plugin is not installed here, that holds something else or whose driver is missing is refused in words (PickRefused),
when picked and when written to: never replaced by another store.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .storage import documents, history

ENGINE_TITLES = {"sqlite": "SQLite", "duckdb": "DuckDB", "mongodb": "MongoDB", "files": "Folder", "postgres": "PostgreSQL",
                 "mariadb": "MariaDB"}
OWN = ("sqlite", "duckdb", "mongodb", "files")  # the engines with a store of their own here: a bare pick names one


@dataclass(frozen=True)
class DataType:
    name: str
    title: str
    engines: tuple[str, ...]  # the engines it can be kept in, the optimal first
    why: str  # why the first is the optimal one
    held: dict  # what each engine means for it


TYPES = {t.name: t for t in (
    DataType("bars", "Bars", ("duckdb", "sqlite"),
             "closed months by column: on Massive's September 2026, 22% of SQLite's size and market-wide scans "
             "over 100 times faster; the open months stay in SQLite, where the feeds write",
             {"duckdb": "open months in SQLite, closed months in DuckDB", "sqlite": "every month in SQLite"}),
    DataType("documents", "Documents", ("mongodb", "sqlite", "postgres", "mariadb"),
             "documents of uneven shape with their attachments (releases and their PDFs, filings, records)",
             {"mongodb": "a collection on the MongoDB server here", "sqlite": "a table in its SQLite file",
              "postgres": "a table in a PostgreSQL database you added (postgres:<instance>)",
              "mariadb": "a table in a MariaDB database you added (mariadb:<instance>)"}),
    DataType("series", "Series", ("sqlite",), "small series changed in place, read a series at a time",
             {"sqlite": "its dataset's SQLite file"}),
    DataType("files", "Files", ("files",), "kept exactly as downloaded, every version",
             {"files": "a folder of the downloads"}),
)}


def available(engine: str) -> tuple[bool, str]:
    """Whether an engine can be used here, and if not why."""
    if engine in ("sqlite", "files"):
        return True, ""
    if engine == "duckdb":
        return (True, "") if history.available() else (False, "duckdb is not installed in the app's Python")
    if engine == "mongodb":
        from . import mongo

        try:
            import pymongo  # noqa: F401
        except ImportError:
            return False, "pymongo is not installed in the app's Python"
        return (True, "") if mongo.binary() else (False, "the MongoDB server is not installed here")
    if engine in ENGINE_TITLES:
        return False, (f"{ENGINE_TITLES[engine]} has no store of its own here: pick one of its instances, "
                       f"{engine}:<instance>, added on the platform's Databases section")
    return False, f"no engine {engine!r}"


def own_engines(dtype: str) -> tuple[str, ...]:
    """The engines a data type can be kept in that have a store of their own here (a bare pick), the optimal first."""
    return tuple(e for e in TYPES[dtype].engines if e in OWN)


def optimal(dtype: str) -> str:
    """The data type's best engine available here."""
    own = own_engines(dtype)
    return next((e for e in own if available(e)[0]), own[-1])


def title_of(store_name: str | None) -> str:
    """A store's words: an engine's title, or an instance's as engine:instance (PostgreSQL main)."""
    engine, instance = split(store_name or "")
    title = ENGINE_TITLES.get(engine, engine)
    return f"{title} {instance}" if instance else title


def split(store_name: str) -> tuple[str, str]:
    """A pick's engine and instance ("postgres:main" -> ("postgres", "main"); a bare engine's instance is "")."""
    engine, _, instance = str(store_name or "").strip().partition(":")
    return engine.strip().lower(), instance.strip().lower()


def is_named(store_name: str | None) -> bool:
    """Whether a store names an instance (engine:instance), not a bare engine."""
    return bool(split(store_name or "")[1])


def _pick_key(plugin: str, dtype: str) -> str:
    return f"store:pick:{plugin}:{dtype}"


def _effect_key(plugin: str, dtype: str) -> str:
    return f"store:effect:{plugin}:{dtype}"


def picked(store, plugin: str, dtype: str) -> str | None:
    """The engine picked for a plugin's data type (None: left to the app)."""
    v = store.kv_get(_pick_key(plugin, dtype))
    return v or None


def wanted(store, plugin: str, dtype: str) -> str:
    """Where a plugin's data type should be: its pick if usable here, else the optimal. A pick naming an instance is
    where it should be as it was named (refused in words where it is written when it cannot be, never replaced)."""
    p = picked(store, plugin, dtype)
    if p and is_named(p) and dtype in NAMED_TYPES:
        return p
    return p if p in own_engines(dtype) and available(p)[0] else optimal(dtype)


def effects(conn) -> dict[str, str]:
    """Each plugin's documents store in effect, from a main file's rows (any SQLite connection to it:
    the recorder's gov.db reader keeps one of its own)."""
    return {k.split(":")[2]: v for k, v in conn.execute(
        "SELECT key, value FROM kv WHERE key LIKE 'store:effect:%:documents'") if v}


def moved_to(conn, engine: str) -> list[str]:
    """The plugins whose documents are in `engine` now (markets.py: a vendor's headlines by its name)."""
    return [p for p, e in effects(conn).items() if e == engine]


def in_effect(store, plugin: str, dtype: str) -> str:
    """Where it is read and written now. Bars: the choice (their closed months move a run at a
    time, each read from DuckDB once copied); documents: where they were last settled (SQLite until
    a move to MongoDB finished)."""
    if dtype == "documents":
        return store.kv_get(_effect_key(plugin, dtype)) or "sqlite"
    return wanted(store, plugin, dtype)


# -- a plugin's data types --------------------------------------------------------------------

def plugin_types(name: str) -> list[str]:
    """The data types a plugin keeps: a feed plugin's bars, a publisher's documents (an agency's
    items, a vendor's headlines), a dataset's series and files."""
    from .sources.registry import plugin_of, providers, publisher_parts, publishers

    ps, pubs = providers(), publishers()
    out = []
    parts = [n for n in (name, *publisher_parts(name)) if n in pubs]
    if name in ps and plugin_of(name) == name:
        out.append("bars")
    if any(pubs[n].feeds for n in parts):
        out.append("documents")
    if any(pubs[n].declared for n in parts):
        out += ["series", "files"]
    return out


def document_scopes(name: str) -> list[tuple[documents.Kind, dict]]:
    """A plugin's documents: each kind with the documents of it that are the plugin's (`where`).
    An agency's items by its feeds' keys (gov.db's items); a vendor's headlines by the plugin's name
    (its read saves them under it, the main file's news)."""
    from .sources.registry import publisher_parts, publishers

    pubs = publishers()
    parts = [pubs[n] for n in (name, *publisher_parts(name)) if n in pubs]
    keys = [f.key for p in parts if not p.reads_itself for f in p.feeds]
    out = []
    if keys:
        out.append((documents.GOV_ITEMS, {"source": keys}))
    if any(p.reads_itself for p in parts):
        out.append((documents.NEWS, {"source": [name]}))
    return out


def item_plugin(source: str) -> str | None:
    """The plugin an agency item's source (a feed's key) is of."""
    from .sources.registry import publisher_of, publishers

    for p in publishers().values():
        if any(f.key == source for f in p.feeds):
            return publisher_of(p.name)
    return None


# -- documents' backends ----------------------------------------------------------------------

def backend(engine: str, kind: documents.Kind, main_conn=None, gov_conn=None, data_dir: Path | None = None,
            start: bool = False):
    """A kind's documents in an engine: SQLite (the main file's news, gov.db's items) or MongoDB.
    With `start` (a write, a move) the server is started here if it is not running; a read never
    waits for a start (the chart app reads the news every few seconds: it falls back to SQLite)."""
    if engine == "mongodb":
        from . import mongo

        if start and data_dir is not None and not mongo.alive():
            mongo.ensure(data_dir)
            mongo.alive(0)
        return documents.MongoDocuments(mongo.database(), kind)
    if is_named(engine):
        return named_backend(engine, kind, data_dir)
    if engine not in ("sqlite", "mongodb"):
        raise PickRefused(available(engine)[1])
    conn = gov_conn if kind is documents.GOV_ITEMS else main_conn
    if conn is None:
        raise RuntimeError(f"no SQLite file for {kind.name}")
    return documents.SqliteDocuments(conn, kind)


# -- a pick naming an instance (1.91.0, Monday list item 10) ------------------------------------------------------------
NAMED_TYPES = ("documents",)  # the data types an instance the user added can hold for now (bars and series after)
NAMED_S = 60.0  # an engine's instances read again through its login after this long (the platform may change them)
POOL_MOST = 8  # connections to the instances kept open in this process, at most (the oldest closed first)


class PickRefused(ValueError):
    """A store that cannot be used, in words: an instance not there, its plugin not installed here, one that holds
    something else, its driver missing. Never replaced by another store."""


_named_lock = threading.Lock()
_named: dict[tuple[str, str], tuple[float, tuple]] = {}  # (engine, data folder) -> (when read, its instances)


def forget_instances() -> None:
    """The instances read again at the next ask (a pick changed; a test)."""
    with _named_lock:
        _named.clear()


def database_plugin(engine: str):
    """The engine's database plugin as this process holds it: attached by the app here, with that app's login; else
    (a process of no app's: the recorder, the sync's extras) a copy holding the login every plugin is lent (the user's
    environment, where the instances are kept). PickRefused when no plugin of the engine is installed here."""
    from .sources import registry

    title = ENGINE_TITLES.get(engine, engine)
    try:
        plugin = registry.database(engine)
    except Exception as e:  # noqa: BLE001 - the registry that cannot load: said
        raise PickRefused(f"the database plugins could not be loaded here ({type(e).__name__}: {e})") from None
    if plugin is None:
        raise PickRefused(f"{title} has no plugin installed here (plugin-platform-{engine}): its instances cannot be "
                          "used from this process")
    if plugin.login is None:
        plugin = plugin.with_(login=plugin.held_login())
    return plugin


def _instances_of(plugin, folder: Path | None, again: bool = False) -> tuple:
    key = (plugin.ENGINE or plugin.name, str(folder or ""))
    import time

    now = time.monotonic()
    with _named_lock:
        seen = _named.get(key)
        if seen is not None and not again and now - seen[0] < NAMED_S:
            return seen[1]
    got = tuple(plugin.instances(folder))  # (read through the plugin's login: outside the lock)
    with _named_lock:
        _named[key] = (now, got)
    return got


def can_hold(plugin, inst, dtype: str) -> bool:
    """Whether an instance can hold a data type: it says it holds it, or it says nothing and its engine holds it."""
    return dtype in inst.holds if inst.holds else dtype in tuple(getattr(plugin, "HOLDS", ()) or ())


def resolve(store_name: str, dtype: str = "documents", data_dir: Path | None = None):
    """(plugin, instance) for a pick naming one; PickRefused in words for any that cannot be used."""
    engine, name = split(store_name)
    t = TYPES.get(dtype)
    if t is None:
        raise PickRefused(f"no data type {dtype!r}")
    if not name:
        raise PickRefused(f"{store_name!r} names no instance: engine:instance (postgres:main)")
    if dtype not in NAMED_TYPES:
        raise PickRefused(f"{t.title.lower()} are kept in this machine's own stores for now: only documents go to an "
                          "instance you add")
    if engine not in t.engines:
        raise PickRefused(f"{t.title.lower()} are kept in {', '.join(ENGINE_TITLES[e] for e in t.engines)}: "
                          f"not {store_name!r}")
    plugin = database_plugin(engine)
    folder = Path(data_dir) if data_dir is not None else None
    found = {i.name: i for i in _instances_of(plugin, folder)}
    if name not in found:  # (added on the platform since this process read them: read again once)
        found = {i.name: i for i in _instances_of(plugin, folder, again=True)}
    inst = found.get(name)
    title = ENGINE_TITLES.get(engine, engine)
    if inst is None:
        raise PickRefused(f"{title} has no instance {name!r} here: add it on the platform's Databases section, or "
                          "pick another")
    if not can_hold(plugin, inst, dtype):
        raise PickRefused(f"{engine}:{name} holds {', '.join(inst.holds) or 'nothing'}, not {t.title.lower()}: what it "
                          "holds is set on the platform's Databases section")
    if engine == "sqlite" and inst.folder and not inst.builtin:  # (its own, the data folder: the bare engine)
        raise PickRefused(f"sqlite:{name} is a folder: documents go to one file, an instance of its own")
    ok, why = plugin.driver()
    if not ok:
        raise PickRefused(f"{engine}:{name} cannot be opened here: {why}")
    return plugin, inst


def canonical(store_name: str | None, dtype: str = "documents", data_dir: Path | None = None) -> str | None:
    """A pick as it is kept: a bare engine as given; an engine's own instance named (sqlite:data, mongodb:local) as
    the bare engine, the same store; another instance as engine:instance, once it resolves (PickRefused if not)."""
    if not store_name:
        return None
    if not is_named(store_name):
        return split(store_name)[0]
    plugin, inst = resolve(store_name, dtype, data_dir)
    engine = split(store_name)[0]
    return engine if inst.builtin and engine in OWN else f"{engine}:{inst.name}"


def instance_choices(dtype: str, data_dir: Path | None = None) -> list[dict]:
    """The instances the user added that can hold a data type, for the Store picker: each as engine:instance with its
    title, what it is, and whether it can be used here (and if not why). [] for a type no instance holds yet. An
    engine's own instance is its bare engine (listed with the engines), so it is not listed here."""
    if dtype not in NAMED_TYPES or dtype not in TYPES:
        return []
    from .sources import registry

    try:
        held = registry.databases()
    except Exception:  # noqa: BLE001 - a picker never fails for the plugins' loading
        return []
    out = []
    for engine in TYPES[dtype].engines:
        if engine not in held:
            continue
        try:
            plugin = database_plugin(engine)
            found = _instances_of(plugin, Path(data_dir) if data_dir is not None else None)
        except Exception:  # noqa: BLE001 - one engine that cannot say leaves the others
            continue
        ok, why = plugin.driver()
        for inst in found:
            if inst.builtin or not can_hold(plugin, inst, dtype) or (engine == "sqlite" and inst.folder):
                continue
            where = f"{inst.where}:{inst.port}" if inst.port else inst.where
            out.append({"name": f"{engine}:{inst.name}", "engine": engine, "instance": inst.name,
                        "title": inst.title or inst.name, "engineTitle": ENGINE_TITLES.get(engine, engine),
                        "means": f"a table in {inst.database or inst.name} at {where}" if inst.database else
                                 f"a table in {where}",
                        "ok": ok, "why": why})
    return out


class _Held:
    """One connection to an instance, kept for this process: used by one call at a time (`lock`), closed by `close`
    (`closed` then: 1.110.0, a call that waited for it takes another)."""

    def __init__(self, value, close: Callable[[], None]):
        self.value, self._close, self.lock = value, close, threading.Lock()
        self.closed = False

    def close(self) -> None:
        self.closed = True
        try:
            self._close()
        except Exception:  # noqa: BLE001 - a connection gone already
            pass


_pool_lock = threading.Lock()
_pool: "OrderedDict[tuple, _Held]" = OrderedDict()


def _held(key: tuple, opener: Callable[[], _Held]) -> _Held:
    with _pool_lock:
        got = _pool.get(key)
        if got is not None:
            _pool.move_to_end(key)
            return got
    made = opener()  # (a connection made outside the lock: a server slow to answer holds up no other)
    with _pool_lock:
        if key in _pool:  # another thread made one meanwhile: that one is used
            made.close()
            return _pool[key]
        _pool[key] = made
        # 1.110.0 (item 14, libs-rest P3-3): past POOL_MOST the oldest connection no call is using is closed, its
        # lock taken first (never one a call holds: its statement would lose its connection); with every other one in
        # use, the pool stays over its bound until a later call
        while len(_pool) > POOL_MOST:
            idle = next((k for k, h in _pool.items() if h is not made and h.lock.acquire(blocking=False)), None)
            if idle is None:
                break
            oldest = _pool.pop(idle)
            try:
                oldest.close()
            finally:
                oldest.lock.release()
        return made


def _drop(key: tuple, held: _Held) -> None:
    with _pool_lock:
        if _pool.get(key) is held:
            del _pool[key]
    held.close()
    documents.forget_tables()


def close_instances() -> None:
    """Every connection this process keeps to an instance closed (an app's end; a test)."""
    with _pool_lock:
        items = list(_pool.values())
        _pool.clear()
    for held in items:
        held.close()
    documents.forget_tables()


def named_backend(store_name: str, kind: documents.Kind, data_dir: Path | None = None):
    """A kind's documents in an instance a pick names, opened through its plugin's `open` (read and write: a pick says
    where new documents go). PostgreSQL and MariaDB: a table each kind on its database; a SQLite file: the same; a
    MongoDB server: a collection. PickRefused, in words, when it cannot be used; a server that does not answer is
    raised as its driver said it, never written elsewhere."""
    plugin, inst = resolve(store_name, "documents", data_dir)
    engine = split(store_name)[0]
    place = f"{engine}:{inst.name}"
    folder = Path(data_dir) if data_dir is not None else None
    if engine == "sqlite":
        @contextmanager
        def session():  # (a file here: opened for each call, as the plugin opens it; a connection keeps to its thread)
            conn = plugin.open(inst, "", read_only=False, data_dir=folder)
            try:
                yield conn
            finally:
                conn.close()

        return documents.SqlDocuments(session, kind, "sqlite", place=f"{place}@{folder or ''}")
    key = (engine, inst.name, inst.where, inst.port, inst.database, str(folder or ""))
    if engine == "mongodb":
        def opener() -> _Held:
            db = plugin.open(inst, "", read_only=False, data_dir=folder)
            client = getattr(db, "client", None)
            return _Held(db, client.close if client is not None else (lambda: None))

        return documents.MongoDocuments(_held(key, opener).value, kind)

    def opener() -> _Held:
        conn = plugin.open(inst, "", read_only=False, data_dir=folder)
        return _Held(conn, conn.close)

    @contextmanager
    def session():
        while True:
            held = _held(key, opener)
            held.lock.acquire()
            if not held.closed:  # 1.110.0: closed by the pool while this call waited for it: another is taken
                break
            held.lock.release()
        try:
            yield held.value
        except Exception:
            _drop(key, held)  # a connection that failed is not used again: the next call makes another
            raise
        finally:
            held.lock.release()

    return documents.SqlDocuments(session, kind, engine, place=place)


def settle(store, gov_conn, data_dir: Path, log: Callable[[str], None] = lambda s: None,
           only: str | None = None) -> list[dict]:
    """Move each plugin's documents to the engine wanted (its pick, or the optimal): every document
    copied, counted, then the plugin's reads and writes go there. Documents written to the store
    left by a process from before (one not restarted yet) are copied on each pass. Nothing is
    removed from where they were. Returns what moved."""
    from . import mounts
    from .sources.registry import plugin_of, providers, publisher_of, publishers

    if mounts.foreign(data_dir):
        # the data is another system's: its documents are moved by that system alone (two moving them would
        # each undo the other's `store:effect` every pass); this one reads and writes where they are
        return []
    names = [n for n in providers() if plugin_of(n) == n] + [n for n in publishers() if publisher_of(n) == n]
    done = []
    for name in dict.fromkeys(names):
        if only and name != only:
            continue
        scopes = document_scopes(name)
        if not scopes:
            continue
        want, now = wanted(store, name, "documents"), in_effect(store, name, "documents")
        if is_named(want):
            # an instance picked (1.91.0): nothing is moved; new documents go there (pick set it), what the store
            # left holds stays where it is
            if want != now:
                store.kv_set(_effect_key(name, "documents"), want)
                log(f"stores: {name}'s new documents go to {title_of(want)}; what {title_of(now)} holds stays there")
                done.append({"plugin": name, "engine": want, "was": now, "copied": 0})
            continue
        others = [e for e in own_engines("documents") if e != want]
        try:
            if want == "mongodb" and not _mongo_up():  # started here; not starting: said in one line a pass
                from . import mongo

                mongo.ensure(data_dir)
                if not mongo.alive(0):
                    raise RuntimeError("the MongoDB server is not running (liminal mongo start)")
            moved = 0
            for kind, where in scopes:
                dst = backend(want, kind, store.conn, gov_conn, data_dir, start=True)
                for e in others:
                    if e == "mongodb" and not (available(e)[0] and (now == "mongodb" or _mongo_up())):
                        continue
                    src = backend(e, kind, store.conn, gov_conn)
                    read, new = documents.copy(src, dst, where)
                    moved += new
                    if want != now and dst.count(where) < src.count(where):
                        raise RuntimeError(f"{kind.name}: {dst.count(where)} in {want}, {src.count(where)} in {e}")
            if want != now:
                store.kv_set(_effect_key(name, "documents"), want)
                log(f"stores: {name}'s documents now in {title_of(want)} ({moved:,} copied from "
                    f"{title_of(now)}, which keeps its copy)")
            if moved or want != now:
                done.append({"plugin": name, "engine": want, "was": now, "copied": moved})
        except Exception as e:  # noqa: BLE001 - one plugin's store failing is its own
            log(f"stores: {name}'s documents stay in {title_of(now)}: {type(e).__name__}: {e}")
            if want != now:  # a move that failed; where they are already, nothing to report
                done.append({"plugin": name, "engine": now, "was": now, "copied": 0, "error": str(e)})
    return done


def _mongo_up() -> bool:
    from . import mongo

    return mongo.alive()


def plugin_feed_files(plugin: str) -> list[str]:
    """The feed files a plugin's bars are in: its feeds' (registry.plugin_feeds) and their live
    feeds' (Alpaca's iex), each once."""
    from .sources.registry import plugin_feeds, providers

    ps = providers()
    out: list[str] = []
    for n in plugin_feeds(plugin):
        out += [n, *(x.name for x in ps[n].live if x.name != n)]
    return list(dict.fromkeys(out))


# -- the picker -------------------------------------------------------------------------------
NAMED_MOVES = ("A pick naming an instance moves nothing: new documents go there from now, and what the store left "
               "holds stays where it is (read with them from the SQLite file's copy).")

def _folder_of(store) -> Path | None:
    """The data folder beside a store's main file (None for one in memory: the plugins' own then)."""
    path = getattr(store, "path", None)
    return None if path is None or str(path) == ":memory:" else Path(path).parent


def pick(store, plugin: str, dtype: str, engine: str | None) -> None:
    """Set a plugin's store for a data type (None: the optimal, left to the app). Bars: each of its
    feeds reads its closed months from DuckDB, or not (store:feed:<feed>:bars, read by the Store)."""
    t = TYPES.get(dtype)
    if t is None or dtype not in plugin_types(plugin):
        raise LookupError(f"{plugin} keeps no {dtype}")
    if engine is not None and is_named(engine):
        # An instance (1.91.0): refused in words unless it can be used; an engine's own instance is the bare engine.
        # Nothing is moved: new documents go there from now, what the store left holds stays where it is.
        forget_instances()  # (read again: one added on the platform a moment ago is found)
        data_dir = _folder_of(store)
        named = canonical(engine, dtype, data_dir)
        if is_named(named):
            store.kv_set(_pick_key(plugin, dtype), named)
            store.kv_set(_effect_key(plugin, dtype), named)
            return
        engine = named
    if engine is not None:
        if engine not in own_engines(dtype):
            if engine in t.engines:
                raise ValueError(available(engine)[1])
            raise ValueError(f"{t.title.lower()} are kept in {', '.join(ENGINE_TITLES[e] for e in t.engines)}")
        ok, why = available(engine)
        if not ok:
            raise RuntimeError(why)
    store.kv_set(_pick_key(plugin, dtype), engine or "")
    if dtype == "bars":
        for feed in plugin_feed_files(plugin):
            store.kv_set(f"store:feed:{feed}:bars", wanted(store, plugin, "bars"))


def bars_feeds(store) -> list[str]:
    """The feeds whose closed months go to DuckDB (their plugin's bars store)."""
    from .sources.registry import plugin_of, providers

    if not available("duckdb")[0]:
        return []
    return [f for p in providers() if plugin_of(p) == p and wanted(store, p, "bars") == "duckdb"
            for f in plugin_feed_files(p) if store.kv_get(f"store:feed:{f}:bars") in (None, "", "duckdb")]


def plugin_stores(store, name: str, gov_conn=None) -> list[dict]:
    """A plugin's data types for its page: each with its engines (the optimal first, each usable
    here or why not), its pick, where it should be and where it is, and how far a move has gone."""
    out = []
    for dtype in plugin_types(name):
        t = TYPES[dtype]
        row = {"type": dtype, "title": t.title, "why": t.why, "optimal": optimal(dtype),
               "picked": picked(store, name, dtype), "wanted": wanted(store, name, dtype),
               "effect": in_effect(store, name, dtype),
               "engines": [{"name": e, "title": ENGINE_TITLES[e], "means": t.held[e], "ok": available(e)[0],
                            "why": available(e)[1]} for e in own_engines(dtype)]}
        if dtype in NAMED_TYPES:
            # the instances the user added that can hold it (1.91.0), and whether the one picked can be used now
            row["instances"] = instance_choices(dtype, _folder_of(store))
            row["moves"] = NAMED_MOVES
            pick_now = row["wanted"] if is_named(row["wanted"]) else None
            if pick_now:
                try:
                    resolve(pick_now, dtype, _folder_of(store))
                except PickRefused as e:
                    row["refused"] = str(e)
        if dtype == "bars":
            row["progress"] = _bars_progress(store, name)
        if dtype == "documents":
            row["counts"] = _document_counts(store, name, gov_conn)
        out.append(row)
    return out


def _bars_progress(store, name: str) -> dict:
    feeds = {}
    for f in plugin_feed_files(name):
        months = store.history_months(f)
        if months or store._bars(f) is not None:
            feeds[f] = {"months": sum(1 for m in months if not m["stale"]), "stale": sum(1 for m in months if m["stale"]),
                        "bytes": sum(m["bytes"] for m in months), "bars": sum(m["bars"] + m["built"] for m in months),
                        "newest": months[0]["month"] if months else None,
                        "oldest": months[-1]["month"] if months else None}
    return feeds


def _document_counts(store, name: str, gov_conn) -> dict:
    """How many of the plugin's documents each engine holds (MongoDB's only while it runs), and the instance picked
    (1.91.0), asked when it can be used (None when it does not answer)."""
    out = {}
    named = [s for s in dict.fromkeys((in_effect(store, name, "documents"), wanted(store, name, "documents")))
             if is_named(s)]
    for engine in (*own_engines("documents"), *named):
        if engine == "mongodb" and not (available(engine)[0] and _mongo_up()):
            out[engine] = None
            continue
        n = 0
        try:
            for kind, where in document_scopes(name):
                n += backend(engine, kind, store.conn, gov_conn, data_dir=_folder_of(store)).count(where)
        except Exception:  # noqa: BLE001 - a count never fails the page
            n = None
        out[engine] = n
    return out


# -- the closed months' copy (storage/history.py): one run at a time, within a budget ---------------
HISTORY_LOCK = "history.lock"  # beside the database: one `history run` at a time
HISTORY_BUDGET_S = 20 * 60  # a `history run`'s seconds of copying


def history_due(settings) -> bool:
    """Whether a `history run` has work: feeds whose closed months go to DuckDB, and no run going. Never from
    another system than the one whose drive the data is on: the copy is that system's (mounts.owner_only)."""
    from . import claims, mounts, proc
    from .storage import Store

    if mounts.foreign(settings.db_path):
        return False
    with Store(settings.db_path) as store:
        feeds = bars_feeds(store)
    return bool(feeds) and proc.holder(settings.db_path.with_name(HISTORY_LOCK)) is None \
        and not any(h.key == claims.HISTORY for h in claims.held(settings.db_path, claims.HISTORY))
