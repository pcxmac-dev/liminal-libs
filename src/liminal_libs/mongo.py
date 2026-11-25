"""The MongoDB server here: the documents' store when a plugin's documents are kept in MongoDB (stores.py).

The user, 2026-10-31, approved MongoDB Community Server 9.0.4 (the zip from fastdl.mongodb.org,
mongod.exe unpacked under %LOCALAPPDATA%\\Programs\\MongoDB\\9.0.4, no Windows service) and chose
that the app starts it: like the live recorder, detached and without a window, when a store uses it
(the hourly sync, a store picked in the Plugins view). It listens on 127.0.0.1 only (the data stays
on this machine; never a port forwarded), its WiredTiger cache capped at CACHE_GB (the memory rules:
small caches), its data in the data folder's mongo/ and its log in logs/mongod.log. `python -m
liminal mongo stop` ends it cleanly (the server's own shutdown).
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path

from . import config
from .layout import MONGO

HOST = "127.0.0.1"
PORT = 27017
CACHE_GB = 0.5
DATABASE = "liminal"  # the app's database on the server: a kind of document is a collection in it
START_WAIT_S = 20.0  # how long a start waits for the server to answer
ALIVE_S = 3.0  # a ping's answer trusted this long (the chart app asks on every news read)
_clients: dict[int, object] = {}
_lock = threading.Lock()
_alive: list = [0.0, False]  # when the server was last asked (monotonic s), and whether it answered


def port() -> int:
    try:
        return int(config.setting("LIMINAL_MONGO_PORT") or PORT)
    except ValueError:
        return PORT


def url() -> str:
    return f"mongodb://{HOST}:{port()}/"


def installed() -> bool:
    try:
        import pymongo  # noqa: F401
    except ImportError:
        return False
    return binary() is not None


def binary() -> Path | None:
    """mongod: MONGOD if set, else the newest under %LOCALAPPDATA%\\Programs\\MongoDB\\<version>\\."""
    named = os.environ.get("MONGOD")
    if named:
        return Path(named) if Path(named).is_file() else None
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "Programs" / "MongoDB"
    found = [p for p in root.glob("*/mongod.exe")] + [p for p in root.glob("*/bin/mongod.exe")] if root.is_dir() else []

    def version(p: Path) -> tuple:
        name = p.parent.name if p.parent.name != "bin" else p.parent.parent.name
        return tuple(int(x) if x.isdigit() else 0 for x in name.split("."))
    return max(found, key=version) if found else None


def version() -> str | None:
    b = binary()
    if b is None:
        return None
    return b.parent.name if b.parent.name != "bin" else b.parent.parent.name


def client(timeout_ms: int = 2000):
    """A client for this process (pymongo pools its connections), on 127.0.0.1 only."""
    from pymongo import MongoClient

    with _lock:
        c = _clients.get(port())
        if c is None:
            c = _clients[port()] = MongoClient(HOST, port(), serverSelectionTimeoutMS=timeout_ms, connectTimeoutMS=timeout_ms,
                                               directConnection=True, appname="liminal")
        return c


def database():
    return client()[DATABASE]


def running(timeout_ms: int = 500) -> bool:
    """Whether a server answers here (a ping)."""
    try:
        from pymongo import MongoClient
        from pymongo.errors import PyMongoError
    except ImportError:
        return False
    c = MongoClient(HOST, port(), serverSelectionTimeoutMS=timeout_ms, connectTimeoutMS=timeout_ms, directConnection=True)
    try:
        c.admin.command("ping")
        return True
    except PyMongoError:
        return False
    finally:
        c.close()


def alive(max_age_s: float = ALIVE_S) -> bool:
    """Whether the server answers, asked at most every `max_age_s` (0: asked now). A read of the
    documents checks this, never a fresh ping each: a ping is a client of its own, with its threads."""
    now = time.monotonic()
    if max_age_s and now - _alive[0] < max_age_s:
        return _alive[1]
    _alive[:] = [now, running()]
    return _alive[1]


def args(data_dir: Path) -> list[str]:
    """mongod's command line: this machine only, the cache capped, the data and the log in the data folder."""
    return [str(binary()), "--dbpath", str(data_dir / MONGO), "--bind_ip", HOST, "--port", str(port()),
            "--wiredTigerCacheSizeGB", str(CACHE_GB), "--logpath", str(data_dir / "logs" / "mongod.log"), "--logappend",
            "--setParameter", "diagnosticDataCollectionEnabled=false"]


def _spawn(argv: list[str]) -> int:
    """Start mongod detached, without a window, outliving this process. Returns its id. Written in the process ledger
    (1.86.0, lifecycle.spawn: owner host:mongo, kind mongod), so liminal-stop finds it when its keeper is gone; not tied
    to its starter (a keeper that ends hands it to the next, which adopts it). 1.88.4: written as holding data, so it
    is never forced and never in a job that ends it with its starter (lifecycle.spawn's holds_data)."""
    from . import lifecycle

    flags = 0x00000008 | 0x00000200 | 0x08000000 if os.name == "nt" else 0  # DETACHED | NEW_GROUP | NO_WINDOW
    return lifecycle.spawn(argv, owner="host:mongo", kind="mongod", tied=False, holds_data=True, creationflags=flags,
                           close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL).pid


def start(data_dir: Path, wait_s: float = START_WAIT_S) -> int | None:
    """Start the server unless one answers (a start lock keeps two processes from starting it at
    once). Returns the new process's id, or None if it was running. Raises if it cannot start."""
    from . import mounts, proc

    if running():
        return None
    startable()
    mounts.owner_only(data_dir, "MongoDB is started by the system that holds its files")
    lock = data_dir / "mongo-start.lock"
    if not proc.acquire(lock):  # another process is starting it: wait for it to answer
        return None if _answers(wait_s) else _fail(data_dir)
    try:
        if running():
            return None
        (data_dir / MONGO).mkdir(parents=True, exist_ok=True)
        (data_dir / "logs").mkdir(parents=True, exist_ok=True)
        pid = _spawn(args(data_dir))
        return pid if _answers(wait_s) else _fail(data_dir)
    finally:
        proc.release(lock)


def startable() -> None:
    """Raises when the server cannot be started from here: a reading copy, or not installed."""
    from .storage.common import read_only

    if read_only():
        raise RuntimeError("read-only (LIMINAL_READONLY): MongoDB is not started from here")
    if binary() is None:
        raise RuntimeError("MongoDB is not installed here (mongod.exe under %LOCALAPPDATA%\\Programs\\MongoDB)")


def _answers(wait_s: float) -> bool:
    end = time.monotonic() + wait_s
    while time.monotonic() < end:
        if running():
            _alive[:] = [time.monotonic(), True]
            return True
        time.sleep(0.5)
    return False


def _fail(data_dir: Path):
    raise RuntimeError(f"MongoDB did not answer on {HOST}:{port()} after starting: see {data_dir / 'logs' / 'mongod.log'}")


# -- the keeper: a resident host (host.py) -----------------------------------------------------
# The server runs under a keeper, `liminal-charts host mongo`: a process whose documents live
# in MongoDB attaches to the keeper (attach, once for the process's life, or until detach), the
# keeper starts the server for its first client, and shuts it down cleanly once its last client
# has been gone for the idle time (the user, 2026-11-01: "attached software like duckdb or what
# ever should be controlled by the plugin"; no processes when the app is not in use). The keeper
# is this data folder's: named for its main database, liminal.db by convention.
KEEPER = "mongo"  # the host's name (host.py)
KEEP_SECONDS = 5.0  # how often the keeper makes sure the server still answers
_attachment = None  # this process's hold on the keeper
_attach_lock = threading.Lock()


def keeper_key(data_dir: Path) -> Path:
    return Path(data_dir) / "liminal.db"


def attach(data_dir: Path, log=print) -> bool:
    """Attach this process to the keeper of this data folder's server, the keeper (and so the
    server) started if none answers. Whether the server answers now. Raises when it cannot be
    started from here (not installed, a reading copy)."""
    global _attachment
    from . import host
    from .storage.common import read_only

    with _attach_lock:
        if _attachment is None or not _attachment.alive():
            if read_only():
                raise RuntimeError("read-only (LIMINAL_READONLY): MongoDB is not started from here")
            if binary() is None:
                if running():
                    return True  # a server somebody else runs: used, not kept
                raise RuntimeError("MongoDB is not installed here (mongod.exe under %LOCALAPPDATA%\\Programs\\MongoDB)")
            _attachment = host.attach_or_start(KEEPER, keeper_key(data_dir), log=log)
            if _attachment is None:
                if running():
                    return True  # the keeper did not come up, the server answers all the same: used
                raise RuntimeError("MongoDB's keeper did not answer (liminal host mongo)")
    return _answers(START_WAIT_S)


def detach() -> None:
    """Let the keeper go (the chart app going quiet): the server stops once every client has."""
    global _attachment
    with _attach_lock:
        held, _attachment = _attachment, None
    if held is not None:
        held.detach()
    _alive[:] = [0.0, False]  # asked again next time


def ensure(data_dir: Path) -> bool:
    """The server answering, this process attached to its keeper (stores.py, before documents are
    read or written there). Returns whether it answers."""
    try:
        return attach(data_dir)
    except RuntimeError:
        return False


GONE_PINGS = 3  # pings in a row that must fail before the keeper takes the server for gone (1.87.0)
GONE_GRACE_S = 10.0  # ... and for at least this long


def keep(data_dir: Path, stop: threading.Event, log=print, *, starter=None, answers=None, ender=None,
         alive=None, started_of=None, clock=time.monotonic, every: float | None = None) -> None:
    """The keeper's work: the server started (or the one running adopted: an orphan a keeper before left is never
    started twice), kept until the clients are gone (`stop`) or it is gone (`mongo stop` by hand), then shut down
    cleanly (stop), whether it started it or adopted it. 1.87.0 (the failed-tasks log, 2026-11-23: at 100% CPU one
    ping of 500 ms failed, the keeper ended, and mongod ran three hours with no keeper): the server is taken for gone
    only once GONE_PINGS pings in a row have failed over GONE_GRACE_S, and only when the process it started (its id
    and start time held) is gone too. The stand-ins (starter, answers, ender, alive, started_of, clock) are a test's.
    1.88.4: its end shuts the server down as `stop` does (its own shutdown, then a wait for its process to exit, never
    a kill), and says so when it is still running."""
    from . import proc

    starter, answers = starter or start, answers or running
    ender = ender or (lambda: globals()["stop"](log=log))
    alive, started_of = alive or proc.pid_alive, started_of or proc.started
    # read when it runs, as before 1.87.0 (1.88.1): a default of KEEP_SECONDS was fixed at import, and the module's
    # KEEP_SECONDS set afterwards (the charts' keeper test sets it to 0.05) was no longer heard
    every = KEEP_SECONDS if every is None else every
    pid = starter(data_dir)
    born = started_of(pid) if pid else None
    log(f"host mongo: server {'started' if pid else 'running already: adopted'} on {HOST}:{port()}")

    def ours_alive() -> bool:
        return bool(pid) and born is not None and alive(pid) and started_of(pid) == born

    misses, since = 0, None
    try:
        while not stop.wait(every):
            if answers():
                misses, since = 0, None
                continue
            misses += 1
            since = clock() if since is None else since
            if misses >= GONE_PINGS and clock() - since >= GONE_GRACE_S and not ours_alive():
                log(f"host mongo: the server has not answered {misses} pings over {clock() - since:.0f} s; "
                    "the keeper ends")
                return
    finally:
        try:
            if ender() is False and answers():  # its own shutdown, then a wait for its process: never a kill
                log("host mongo: the server is still running after its shutdown: left running, not killed")
        except Exception as e:  # noqa: BLE001 - said; the keeper ends all the same
            log(f"host mongo: the server did not shut down cleanly: {type(e).__name__}: {e}")


STOP_WAIT_S = 60.0  # what the server's own shutdown is given for its process to exit (1.88.4; 10 s and a kill before)
STOP_STEP_S = 0.5  # between two looks at it


def stop(wait_s: float = STOP_WAIT_S, clock=time.monotonic, sleep=time.sleep, log=print, *, answers=None,
         shutdown=None, alive=None, started_of=None) -> bool:
    """End the server cleanly: its own shutdown command, then a wait of up to `wait_s` (a look every STOP_STEP_S) for
    its process to exit. 1.88.4 (the user, 2026-11-24: "all shutdowns need to be clean"): a server still running then
    is reported and left, never killed (1.87.0 killed its tree past 10 s: a kill mid-checkpoint can leave its files to
    be repaired). Returns whether it ended: False when none was running, or it was still running at the end of the
    wait. The stand-ins (answers, shutdown: what returns the server's process id, alive, started_of) are a test's."""
    from . import proc

    answers, shutdown = answers or running, shutdown or _shutdown
    alive, started_of = alive or proc.pid_alive, started_of or proc.started
    if not answers():
        return False
    pid = shutdown()
    born = started_of(pid) if pid else None

    def gone() -> bool:
        if pid and born is not None:
            return not alive(pid) or started_of(pid) != born
        return not answers()  # its process could not be told: the end of its answers is all there is to go on

    end = clock() + max(wait_s, 0.0)
    while not gone() and clock() < end:
        sleep(STOP_STEP_S)
    if gone():
        return True
    log(f"mongo: the server{f' (pid {pid})' if pid else ''} is still running {wait_s:g} s after its shutdown: "
        "left running, not killed")
    return False


def port_of(cmdline: str) -> int:
    """The port a mongod command line names (--port N), else this one's (port())."""
    import re

    found = re.search(r"--port[=\s]+(\d+)", cmdline or "")
    return int(found.group(1)) if found else port()


def ask_shutdown(on_port: int, pid: int | None = None) -> bool:
    """The server on 127.0.0.1:`on_port` asked to shut down (its own command; lifecycle's end of a mongod process),
    only when it says it is process `pid` (when given). Whether it was asked. Its clients here let go."""
    try:
        return _shutdown(on_port, pid) is not None or pid is None
    except Exception:  # noqa: BLE001 - nothing answers, another server, no pymongo: not asked
        return False


def _shutdown(on_port: int | None = None, pid: int | None = None) -> int | None:
    """mongod asked to shut down (its own command), its clients here let go. Returns its process id as it said it
    (serverStatus), None when it could not be told; when `pid` is given and it says another, nothing is asked."""
    from pymongo.errors import AutoReconnect, ConnectionFailure, PyMongoError

    from pymongo import MongoClient

    on_port = port() if on_port is None else on_port
    c = MongoClient(HOST, on_port, serverSelectionTimeoutMS=2000, directConnection=True)
    said = None
    try:
        try:
            said = int(c.admin.command("serverStatus").get("pid") or 0) or None
        except (PyMongoError, TypeError, ValueError):
            said = None
        if pid is not None and said != pid:
            return None  # another server answers there: not this process's to shut down
        c.admin.command("shutdown")
    except (AutoReconnect, ConnectionFailure):
        pass  # it closes the connection as it goes
    except PyMongoError:
        raise
    finally:
        c.close()
    with _lock:
        old = _clients.pop(on_port, None)
    if old is not None:
        old.close()
    _alive[:] = [time.monotonic(), False]
    return said


def status(data_dir: Path) -> dict:
    """What the Resources view and `mongo status` show: installed (where, version), running (its
    process, memory, uptime), the app's database's size, the cache cap."""
    out = {"installed": installed(), "binary": str(binary()) if binary() else None, "version": version(),
           "host": HOST, "port": port(), "cacheGB": CACHE_GB, "dataDir": str(data_dir / MONGO),
           "running": False, "pid": None, "residentMB": None, "uptimeS": None, "dataBytes": None,
           "storageBytes": None, "collections": None}
    disk = data_dir / MONGO
    out["diskBytes"] = sum(f.stat().st_size for f in disk.rglob("*") if f.is_file()) if disk.is_dir() else None
    if not out["installed"] or not alive():
        return out
    try:
        c = client()
        s = c.admin.command("serverStatus")
        st = c[DATABASE].command("dbStats")
        out.update(running=True, pid=s.get("pid"), residentMB=(s.get("mem") or {}).get("resident"),
                   uptimeS=s.get("uptime"), serverVersion=s.get("version"), dataBytes=st.get("dataSize"),
                   storageBytes=st.get("storageSize"), collections=st.get("collections"))
    except Exception as e:  # noqa: BLE001 - a status read never fails the view
        out["error"] = f"{type(e).__name__}: {e}"
    return out
