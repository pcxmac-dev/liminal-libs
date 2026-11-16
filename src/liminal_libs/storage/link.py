"""The link: a SQLite file on another system's drive, opened by that system (liminal-libs 1.57.0).

The user, 2026-11-15: "keep the databases (sql/duck/etc) in the same place find a way to link linux to windows using an
SSHFS or networking arrangement that is safe and secure". The suite runs a second time inside WSL on Windows' own
databases. A mount cannot be made safe for that: SQLite's locks and its write-ahead log's shared memory do not cross
from Windows to Linux over /mnt/c, SSHFS or a share, so two writers, one on each side, would corrupt a file. So only
the system the files belong to opens them. A process on the other system reaches them through a **helper** it starts
there: a process of this library on the files' own system that holds the real connections, spoken to over its
standard input and output. A private pipe: no port, nothing listening, nothing installed; the helper ends with the
process that started it.

- `connect(path, ...)` is the one way a SQLite file is opened. A file on this system's own disk is opened as always
  (sqlite3.connect). A file on another system's drive (mounts.foreign) is opened through the helper, and never
  directly: there is no falling back.
- The connection it gives back is shaped like sqlite3's (execute, executemany, executescript, cursors with fetchone,
  fetchmany, fetchall and iteration, transactions, `with conn:`, rows by name with `row_factory = sqlite3.Row`), so
  the storage code runs on it unchanged. `frame(conn, sql, params)` reads a query into a DataFrame on either kind.
- Frames on the pipe are length-prefixed pickles of plain data (numbers, text, bytes, tuples, lists, dicts): nothing
  else is ever rebuilt from the pipe (_Plain). Each request has an id, so one connection's long query does not hold up
  another's; the helper works each connection in a thread of its own.
- The helper opens nothing outside the folders it was started for (its own data folder and its ledger folder), an
  ATTACH included (its authorizer), and makes no file with VACUUM INTO.
- Errors come back as sqlite3's own classes. A helper that ends is never started again by a process that has lost
  it: temporary tables, attached files and open transactions died with it, and what the process believed would be
  wrong. The process says so and is started again by whoever keeps it running.
- Every reply carries the helper's clock (Link.owner_now): the two systems' clocks differ, and what is stamped
  into a shared file is stamped by the clock of the system that owns it.
- On a system that links (Linux), an audit hook refuses any direct sqlite3.connect on another system's drive,
  whoever tries (a plugin's own code included).

For the tests the same protocol runs inside one process (Link.loopback: two pipes and the helper in a thread), and
LIMINAL_LINK=loopback sends every file through it, so a whole suite can be run over the link.
"""
from __future__ import annotations

import atexit
import io
import itertools
import os
import pickle
import queue
import re
import shlex
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import date, datetime
from pathlib import Path
from typing import Callable, Iterator

from .. import mounts

VERSION = 1  # the protocol's: both ends must speak the same
MAX_FRAME = 1 << 30  # a frame larger than this is not one of ours
BATCH_ROWS = 4000  # a query's rows come back this many at a time
MANY_ROWS = 20_000  # executemany's rows go over this many at a time
COMMAND_VAR = "LIMINAL_LINK_COMMAND"  # the helper's command on the files' own system, as this system starts it
FORCE_VAR = "LIMINAL_LINK"  # "loopback": every file goes through a link inside this process (a suite run over it)
LOG_VAR = "LIMINAL_LINK_LOG"  # a file for the helper's own words (its standard error); none by default
_DEFAULT = object()  # isolation_level left as sqlite3 has it
_here = time.time  # this system's clock, as the link's own side reads it (a test sets the two systems' apart)


class LinkError(RuntimeError):
    """The link itself failed, or was asked for something it does not do (not a database's error)."""


# -- frames ------------------------------------------------------------------------------------------------------------
class _Plain(pickle.Unpickler):
    """Plain data only: nothing on the pipe may name a class or a function to rebuild."""

    def find_class(self, module, name):
        raise pickle.UnpicklingError(f"the link carries plain data only, not {module}.{name}")


def _dumps(obj) -> bytes:
    return pickle.dumps(obj, protocol=5)


def _loads(data: bytes):
    return _Plain(io.BytesIO(data)).load()


def _write(stream, obj) -> None:
    data = _dumps(obj)
    stream.write(struct.pack(">I", len(data)))
    stream.write(data)
    stream.flush()


def _read(stream):
    """The next frame, or None at the end of the pipe."""
    head = _exactly(stream, 4)
    if head is None:
        return None
    (n,) = struct.unpack(">I", head)
    if n > MAX_FRAME:
        raise LinkError(f"a frame of {n:,} bytes: not the link's")
    body = _exactly(stream, n)
    if body is None:
        raise LinkError("the pipe ended inside a frame")
    return _loads(body)


def _exactly(stream, n: int) -> bytes | None:
    """`n` bytes of the pipe, or None when it ended before they came."""
    parts, left = [], n
    while left:
        chunk = stream.read(left)
        if not chunk:
            return None
        parts.append(chunk)
        left -= len(chunk)
    return b"".join(parts)


def _plain(value):
    """A parameter as it crosses: what sqlite3 binds as it is, a date or a time as sqlite3's own adapters wrote them."""
    if value is None or isinstance(value, (int, float, str, bytes)):
        return int(value) if isinstance(value, bool) else value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, datetime):
        return value.isoformat(" ")
    if isinstance(value, date):
        return value.isoformat()
    raise sqlite3.ProgrammingError(f"Error binding parameter: type '{type(value).__name__}' is not supported")


def _params(parameters):
    if isinstance(parameters, dict):
        return {str(k): _plain(v) for k, v in parameters.items()}
    return tuple(_plain(v) for v in parameters)


# -- the helper's side -------------------------------------------------------------------------------------------------
_helper = threading.local()  # `here` in a thread that holds a helper's connection (the guard lets its opens through)


class _Worker(threading.Thread):
    """One connection on the files' own system, worked in a thread of its own: its requests in the order they came."""

    def __init__(self, server: "Server", cid: int, path: str, kw: dict):
        super().__init__(name=f"link-connection-{cid}", daemon=True)
        self.server, self.cid, self.path, self.kw = server, cid, path, kw
        self.jobs: queue.Queue = queue.Queue()
        self.conn: sqlite3.Connection | None = None
        self.cursors: dict[int, sqlite3.Cursor] = {}
        self._ids = itertools.count(1)
        self.attach_checked = False  # the statement being run is an ATTACH whose file this worker has checked
        self.opened = threading.Event()
        self.error: BaseException | None = None

    def run(self) -> None:
        _helper.here = True  # this thread is the files' own side: what it opens, it opens as their owner
        try:
            self.conn = self._open()
        except BaseException as e:  # noqa: BLE001 - told to the one who asked
            self.error = e
            self.opened.set()
            return
        self.opened.set()
        while True:
            job = self.jobs.get()
            if job is None:
                break
            rid, op, args = job
            try:
                result = self._do(op, args)
            except BaseException as e:  # noqa: BLE001 - every failure goes back to the one who asked
                self.server.reply(rid, False, _error(e), self._state())
                continue
            self.server.reply(rid, True, result, self._state())
            if op == "close":
                break
        self._shut()

    def _open(self) -> sqlite3.Connection:
        kw = dict(self.kw)
        read_only = kw.pop("read_only", False)
        args: dict = {"timeout": float(kw.pop("timeout", 5.0)), "check_same_thread": False}
        if "isolation_level" in kw:
            args["isolation_level"] = kw.pop("isolation_level")
        if read_only:
            conn = sqlite3.connect(Path(self.path).resolve().as_uri() + "?mode=ro", uri=True, **args)
        else:
            conn = sqlite3.connect(self.path, **args)
        conn.set_authorizer(self._authorize)
        return conn

    def _authorize(self, action, arg1, arg2, db, source) -> int:
        """SQLite asks before each thing a statement does. An ATTACH of a file outside the helper's folders is
        refused: a file named in the statement is checked here; one given as a parameter is not known to SQLite
        when it asks (it says nothing of it), so it was checked before the statement ran, or the ATTACH is refused."""
        if action != sqlite3.SQLITE_ATTACH:
            return sqlite3.SQLITE_OK
        if arg1 is None:
            return sqlite3.SQLITE_OK if self.attach_checked else sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK if arg1 in ("", ":memory:") or self.server.inside(str(arg1)) else sqlite3.SQLITE_DENY

    def _attach(self, sql: str, params) -> bool:
        """Whether a statement is an ATTACH of the one file given as its parameter (`ATTACH DATABASE ? AS name`, as
        the storage writes it), that file checked against the helper's folders. Any other ATTACH is SQLite's to ask
        about: a file named in the statement is checked then, a computed one refused."""
        if not _ATTACH_ONE.match(sql) or isinstance(params, dict) or len(params) != 1:
            return False
        p = params[0]
        if not isinstance(p, str):
            return False
        if p not in ("", ":memory:") and not self.server.inside(p):
            raise mounts.NotHere(f"{p}: not in the folders this helper opens, so not attached")
        return True

    def _state(self) -> tuple:
        conn = self.conn
        try:
            return (time.time(), bool(conn.in_transaction), int(conn.total_changes)) if conn is not None else (time.time(), None, None)
        except sqlite3.Error:
            return (time.time(), None, None)

    def _do(self, op: str, args: tuple):
        conn = self.conn
        if op == "exec":
            sql, params = args
            _no_new_files(sql)
            self.attach_checked = self._attach(sql, params)
            try:
                cur = conn.execute(sql, params)
            finally:
                self.attach_checked = False
            if cur.description is None:
                return (0, None, [], True, cur.rowcount, cur.lastrowid)
            rows = cur.fetchmany(BATCH_ROWS)
            done = len(rows) < BATCH_ROWS
            cid = 0
            if not done:
                cid = next(self._ids)
                self.cursors[cid] = cur
            return (cid, tuple(d[0] for d in cur.description), rows, done, cur.rowcount, cur.lastrowid)
        if op == "fetch":
            cid, n = args
            cur = self.cursors.get(cid)
            if cur is None:
                return ([], True)
            rows = cur.fetchmany(int(n) or BATCH_ROWS)
            done = len(rows) < (int(n) or BATCH_ROWS)
            if done:
                self.cursors.pop(cid, None)
            return (rows, done)
        if op == "drop":
            cur = self.cursors.pop(args[0], None)
            if cur is not None:
                cur.close()
            return None
        if op == "many":
            sql, rows = args
            _no_new_files(sql)
            return conn.executemany(sql, rows).rowcount
        if op == "script":
            _no_new_files(args[0])
            conn.executescript(args[0])
            return None
        if op == "commit":
            conn.commit()
            return None
        if op == "rollback":
            conn.rollback()
            return None
        if op == "limit":  # a time limit on what it runs from now on (a page's read that must not hang); None: none
            seconds = args[0]
            if seconds is None:
                conn.set_progress_handler(None, 0)
            else:
                deadline = time.monotonic() + float(seconds)
                conn.set_progress_handler(lambda: 1 if time.monotonic() >= deadline else 0, 20_000)
            return None
        if op == "close":
            return None
        raise LinkError(f"the helper does not know {op!r}")

    def _shut(self) -> None:
        for cur in self.cursors.values():
            try:
                cur.close()
            except sqlite3.Error:
                pass
        self.cursors.clear()
        if self.conn is not None:
            try:
                self.conn.close()  # what was not committed is not kept, as when a process ends
            except sqlite3.Error:
                pass
        self.server.forget(self.cid)


_ATTACH_ONE = re.compile(r"^\s*ATTACH\s+(DATABASE\s+)?\?\s+AS\s+\w+\s*;?\s*$", re.IGNORECASE)


def _no_new_files(sql: str) -> None:
    """VACUUM INTO writes a file wherever it is told: the files' own system makes those itself, not for another."""
    head = sql.lstrip()[:12].upper()
    if head.startswith("VACUUM") and " INTO " in f" {sql.upper()} ":
        raise mounts.NotHere("VACUUM INTO: a copy of a database is made by the system that holds the files, not through the link")


def _error(e: BaseException) -> tuple[str, str]:
    return (type(e).__name__, str(e))


class Server:
    """The helper: the connections it holds for the process that started it, inside the folders it was started for."""

    def __init__(self, roots, saved: Callable[[tuple], dict] | None = None, log: Callable[[str], None] | None = None,
                 anywhere: bool = False):
        self.roots = [Path(r).resolve() for r in roots]
        self.anywhere = anywhere  # a suite run over the link inside one process: its files are wherever the tests put them
        self.saved = saved  # the user's saved settings on this system, by name (config.UserEnvironment), when it may tell them
        self.log = log or (lambda m: None)
        self._workers: dict[int, _Worker] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._out = None
        self._out_lock = threading.Lock()

    # -- what it may open ---------------------------------------------------------------------------------------------
    def inside(self, path: str) -> bool:
        """Whether a file is in one of the folders this helper was started for."""
        if self.anywhere:
            return True
        try:
            p = Path(path).resolve()
        except (OSError, ValueError):
            return False
        return any(p == root or root in p.parents for root in self.roots)

    # -- the pipe -----------------------------------------------------------------------------------------------------
    def reply(self, rid: int, ok: bool, result, state) -> None:
        with self._out_lock:
            try:
                _write(self._out, (rid, ok, result, state))
            except (OSError, ValueError):
                pass  # the other end is gone: the loop ends at its next read

    def forget(self, cid: int) -> None:
        with self._lock:
            self._workers.pop(cid, None)

    def serve(self, inp, out) -> None:
        """Answer the process at the other end of the pipe until it closes it; then close everything."""
        self._out = out
        try:
            while True:
                try:
                    msg = _read(inp)
                except (LinkError, pickle.UnpicklingError, EOFError, OSError, ValueError) as e:
                    self.log(f"link: the pipe gave something that is not a frame ({e}): ending")
                    break
                if msg is None:
                    break
                rid, op, cid, args = msg
                if cid:
                    with self._lock:
                        worker = self._workers.get(cid)
                    if worker is None:
                        self.reply(rid, False, ("ProgrammingError", "Cannot operate on a closed database."), (time.time(), None, None))
                    elif op == "interrupt":  # from another thread, while its query runs
                        try:
                            worker.conn.interrupt()
                            self.reply(rid, True, None, (time.time(), None, None))
                        except BaseException as e:  # noqa: BLE001
                            self.reply(rid, False, _error(e), (time.time(), None, None))
                    else:
                        worker.jobs.put((rid, op, args))
                    continue
                try:
                    result = self._own(op, args)
                except BaseException as e:  # noqa: BLE001 - told to the one who asked
                    self.reply(rid, False, _error(e), (time.time(), None, None))
                else:
                    self.reply(rid, True, result, (time.time(), None, None))
        finally:
            self.close()

    def _own(self, op: str, args: tuple):
        if op == "hello":
            version = args[0]
            if version != VERSION:
                raise LinkError(f"the helper speaks version {VERSION} of the link, the process that started it version "
                                f"{version}: bring the older of the two up to date")
            from .. import __version__

            return {"version": VERSION, "library": __version__, "pid": os.getpid(), "sqlite": sqlite3.sqlite_version,
                    "system": sys.platform, "roots": [str(r) for r in self.roots]}
        if op == "open":
            path, kw = args
            if not self.inside(path):
                raise mounts.NotHere(f"{path}: not in the folders this helper opens ({', '.join(str(r) for r in self.roots)})")
            cid = next(self._ids)
            worker = _Worker(self, cid, path, dict(kw))
            with self._lock:
                self._workers[cid] = worker
            worker.start()
            worker.opened.wait()
            if worker.error is not None:
                self.forget(cid)
                raise worker.error
            return cid
        if op == "saved":  # the user's saved settings on this system, by the names asked (never more)
            if self.saved is None:
                raise LinkError("this helper tells no settings")
            return dict(self.saved(tuple(str(n) for n in args[0])))
        if op == "clock":
            return time.time()
        raise LinkError(f"the helper does not know {op!r}")

    def close(self) -> None:
        with self._lock:
            workers = list(self._workers.values())
        for w in workers:
            w.jobs.put(None)
        for w in workers:
            w.join(timeout=10)


# -- the other side ----------------------------------------------------------------------------------------------------
class _Wait:
    __slots__ = ("event", "ok", "result", "state")

    def __init__(self):
        self.event = threading.Event()
        self.ok, self.result, self.state = False, None, None


class Link:
    """This process's link to the system that owns a drive's files: the helper there, and the pipe to it.

    `inp`, `out`: the pipe's two ends as binary files (the helper's answers, the requests to it). `owner_path`: how a
    path here is named there (a Windows drive seen from WSL: mounts.owner_path). `proc`: the helper's process, when
    this started one."""

    def __init__(self, inp, out, *, owner_path: Callable[[str], str | None] | None = None, proc=None,
                 name: str = "the files' own system"):
        self._in, self._out, self.proc, self.name = inp, out, proc, name
        self.owner_path = owner_path or (lambda p: str(p))
        self._ids = itertools.count(1)
        self._waiting: dict[int, _Wait] = {}
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self.dead: str | None = None
        self.skew = 0.0  # the owner's clock minus this one's, as the last reply showed it
        self.heard = 0.0
        self._reader = threading.Thread(target=self._listen, name="link-replies", daemon=True)
        self._reader.start()
        self.info: dict = self.call("hello", VERSION)[0]

    # -- making one ---------------------------------------------------------------------------------------------------
    @classmethod
    def loopback(cls, roots=(), saved=None, anywhere: bool = False) -> "Link":
        """A link to a helper inside this process (a thread, two pipes): the whole protocol, no other process."""
        to_helper_r, to_helper_w = os.pipe()
        to_client_r, to_client_w = os.pipe()
        server = Server(roots, saved=saved, anywhere=anywhere)
        helper_in, helper_out = os.fdopen(to_helper_r, "rb"), os.fdopen(to_client_w, "wb")

        def run() -> None:
            try:
                server.serve(helper_in, helper_out)
            finally:
                for f in (helper_in, helper_out):
                    try:
                        f.close()
                    except OSError:
                        pass

        threading.Thread(target=run, name="link-helper", daemon=True).start()
        link = cls(os.fdopen(to_client_r, "rb"), os.fdopen(to_helper_w, "wb"), name="a helper in this process")
        link.server = server
        return link

    @classmethod
    def start(cls, command: str, cwd: str | None = None, owner_path=None, name: str = "the files' own system") -> "Link":
        """The helper started on the files' own system with `command` (through WSL's interop: a Windows program run
        from Linux), spoken to over its standard input and output. Its own words go to LIMINAL_LINK_LOG, or nowhere."""
        log = os.environ.get(LOG_VAR)
        err = open(log, "ab") if log else subprocess.DEVNULL
        try:
            proc = subprocess.Popen(shlex.split(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, cwd=cwd)
        except OSError as e:
            raise LinkError(f"the helper could not be started ({command}): {e}") from None
        finally:
            if log:
                err.close()
        try:
            return cls(proc.stdout, proc.stdin, owner_path=owner_path, proc=proc, name=name)
        except BaseException:
            proc.kill()
            raise

    # -- asking -------------------------------------------------------------------------------------------------------
    def call(self, op: str, *args, cid: int = 0):
        """One request and its answer: (result, state). An error there is raised here as what it was."""
        if self.dead:
            raise sqlite3.OperationalError(self._gone())
        rid, wait = next(self._ids), _Wait()
        with self._lock:
            self._waiting[rid] = wait
        try:
            with self._write_lock:
                _write(self._out, (rid, op, cid, args))
        except (OSError, ValueError) as e:
            self._end(f"its pipe closed ({e})")
            raise sqlite3.OperationalError(self._gone()) from None
        wait.event.wait()
        if self.dead and wait.state is None:
            raise sqlite3.OperationalError(self._gone())
        if not wait.ok:
            raise _raised(*wait.result)
        return wait.result, wait.state

    def _gone(self) -> str:
        return (f"the link to {self.name} is gone ({self.dead}): this process cannot reach its databases any more, "
                "and is not connected again (what it held open there ended with the link); it must be started again")

    def _listen(self) -> None:
        why = "the helper ended"
        try:
            while True:
                msg = _read(self._in)
                if msg is None:
                    break
                rid, ok, result, state = msg
                if state and state[0]:
                    self.skew, self.heard = float(state[0]) - _here(), time.monotonic()
                with self._lock:
                    wait = self._waiting.pop(rid, None)
                if wait is not None:
                    wait.ok, wait.result, wait.state = ok, result, state
                    wait.event.set()
        except (LinkError, pickle.UnpicklingError, EOFError, OSError, ValueError) as e:
            why = f"its pipe gave something that is not a frame ({e})"
        self._end(why)

    def _end(self, why: str) -> None:
        if not self.dead:
            self.dead = why
        with self._lock:
            waiting, self._waiting = list(self._waiting.values()), {}
        for wait in waiting:
            wait.event.set()

    # -- what it is for -----------------------------------------------------------------------------------------------
    def open(self, path, **kw) -> "Connection":
        """A file there, opened by the helper: a connection shaped like sqlite3's."""
        there = self.owner_path(str(path))
        if there is None:
            raise LinkError(f"{path}: no name for it on {self.name}")
        cid = self.call("open", there, kw)[0]
        return Connection(self, cid, str(path), kw.get("isolation_level", ""))

    def saved(self, names) -> dict:
        """The user's saved settings on the files' own system, by name (the keys among them): told to this process,
        kept nowhere here."""
        return dict(self.call("saved", tuple(names))[0])

    def owner_now(self) -> float:
        """The time by the clock of the system that owns the files (what is stamped into them is stamped by it)."""
        if time.monotonic() - self.heard > 30.0:
            self.call("clock")
        return _here() + self.skew

    def close(self) -> None:
        """The pipe closed: the helper ends, and everything it held open with it."""
        self._end("closed by this process")
        for f in (self._out, self._in):
            try:
                f.close()
            except (OSError, ValueError):
                pass
        if self.proc is not None:
            try:
                self.proc.wait(timeout=10)
            except (subprocess.TimeoutExpired, OSError):
                self.proc.kill()


def _raised(name: str, message: str) -> BaseException:
    cls = getattr(sqlite3, name, None)
    if isinstance(cls, type) and issubclass(cls, sqlite3.Error):
        return cls(message)
    if name == "NotHere":
        return mounts.NotHere(message)
    if name in ("LinkError",):
        return LinkError(message)
    return LinkError(f"{name}: {message}")


class Row(tuple):
    """A row whose values are also had by their columns' names, as sqlite3.Row gives them (the login reads so)."""

    def __new__(cls, names, values):
        self = super().__new__(cls, values)
        self._names = names
        return self

    def keys(self) -> list:
        return list(self._names)

    def __getitem__(self, key):
        if isinstance(key, str):
            for i, name in enumerate(self._names):
                if name == key or name.lower() == key.lower():
                    return tuple.__getitem__(self, i)
            raise IndexError(f"No item with that key: {key}")
        return tuple.__getitem__(self, key)


class Cursor:
    """A statement's results on a linked connection, as sqlite3.Cursor gives them."""

    arraysize = 1

    def __init__(self, connection: "Connection"):
        self.connection = connection
        self.description = None
        self.rowcount = -1
        self.lastrowid = None
        self._names: tuple | None = None
        self._rows: deque = deque()
        self._id = 0
        self._done = True

    def execute(self, sql: str, parameters=()) -> "Cursor":
        self._drop()
        conn = self.connection
        cid, names, rows, done, rowcount, lastrowid = conn._call("exec", sql, conn._bound(sql, parameters))
        self._id, self._done, self._names = cid, done, names
        self.description = tuple((n, None, None, None, None, None, None) for n in names) if names is not None else None
        self._rows = deque(rows)
        self.rowcount, self.lastrowid = rowcount, lastrowid
        return self

    def executemany(self, sql: str, seq_of_parameters) -> "Cursor":
        self._drop()
        conn, total, chunk, sent = self.connection, 0, [], False
        for p in seq_of_parameters:
            chunk.append(_params(p))
            if len(chunk) >= MANY_ROWS:
                total += max(0, conn._call("many", sql, chunk))
                chunk, sent = [], True
        if chunk or not sent:  # with no rows at all the statement still begins its transaction, as sqlite3's does
            total += max(0, conn._call("many", sql, chunk))
        self.description, self._names, self._rows, self._done = None, None, deque(), True
        self.rowcount = total
        return self

    def executescript(self, script: str) -> "Cursor":
        self._drop()
        self.connection._call("script", script)
        self.description, self._names, self._rows, self._done, self.rowcount = None, None, deque(), True, -1
        return self

    def _drop(self) -> None:
        if self._id and not self._done:
            try:
                self.connection._call("drop", self._id)
            except sqlite3.Error:
                pass
        self._id, self._done = 0, True

    def _more(self, n: int = 0) -> None:
        if self._done or not self._id:
            self._done = True
            return
        rows, done = self.connection._call("fetch", self._id, n)
        self._rows.extend(rows)
        self._done = done

    def _row(self, values):
        factory = self.connection.row_factory
        if factory is None:
            return values
        if factory is sqlite3.Row:
            return Row(self._names or (), values)
        return factory(self, values)

    def fetchone(self):
        if not self._rows:
            self._more()
        return self._row(self._rows.popleft()) if self._rows else None

    def fetchmany(self, size: int | None = None) -> list:
        size = self.arraysize if size is None else size
        out: list = []
        while len(out) < size:
            if not self._rows:
                if self._done:
                    break
                self._more()
                if not self._rows:
                    break
            out.append(self._row(self._rows.popleft()))
        return out

    def fetchall(self) -> list:
        out = [self._row(r) for r in self._rows]
        self._rows.clear()
        while not self._done:
            self._more()
            out.extend(self._row(r) for r in self._rows)
            self._rows.clear()
        return out

    def __iter__(self):
        return self

    def __next__(self):
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row

    def close(self) -> None:
        self._drop()
        self._rows.clear()


class Connection:
    """A SQLite file on another system's drive, held open by the helper there: shaped like sqlite3.Connection for
    what this software uses of it. `in_transaction` and `total_changes` are as the last answer said."""

    def __init__(self, link: Link, cid: int, database: str, isolation_level=""):
        self._link, self._cid, self.database = link, cid, database
        self.isolation_level = isolation_level
        self.row_factory = None
        self.in_transaction = False
        self.total_changes = 0
        self._closed = False

    def _call(self, op: str, *args):
        if self._closed:
            raise sqlite3.ProgrammingError("Cannot operate on a closed database.")
        result, state = self._link.call(op, *args, cid=self._cid)
        if state and state[1] is not None:
            self.in_transaction, self.total_changes = state[1], state[2]
        return result

    def _bound(self, sql: str, parameters):
        """The parameters as they cross; an ATTACH's file named as the files' own system names it."""
        params = _params(parameters)
        if sql.lstrip()[:6].upper() == "ATTACH" and isinstance(params, tuple):
            params = tuple(self._there(p) for p in params)
        return params

    def _there(self, value):
        if isinstance(value, str) and value not in ("", ":memory:") and (os.sep in value or "/" in value):
            return self._link.owner_path(value) or value
        return value

    def cursor(self, factory=None) -> Cursor:
        return Cursor(self)

    def execute(self, sql: str, parameters=()) -> Cursor:
        return Cursor(self).execute(sql, parameters)

    def executemany(self, sql: str, seq_of_parameters) -> Cursor:
        return Cursor(self).executemany(sql, seq_of_parameters)

    def executescript(self, script: str) -> Cursor:
        return Cursor(self).executescript(script)

    def commit(self) -> None:
        self._call("commit")

    def rollback(self) -> None:
        self._call("rollback")

    def interrupt(self) -> None:
        self._link.call("interrupt", cid=self._cid)

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._call("close")
        except (sqlite3.Error, LinkError):
            pass  # the link is gone: the helper closed it already
        self._closed = True

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, kind, value, trace) -> bool:
        if kind is None:
            self.commit()
        else:
            self.rollback()
        return False

    def backup(self, *a, **k):
        raise mounts.NotHere("a backup is made by the system that holds the files, not through the link")

    def set_progress_handler(self, handler, n: int = 0) -> None:
        """Only its ending crosses (None): a handler is this process's code. Use time_limit() for a limit."""
        if handler is None:
            self._call("limit", None)
            return
        raise LinkError("a progress handler cannot run on the files' own system: use storage.link.time_limit")

    def create_function(self, *a, **k):
        raise LinkError("a function of this process cannot run on the files' own system")


@contextmanager
def time_limit(conn, seconds: float, clock: Callable[[], float] = time.monotonic) -> Iterator[None]:
    """What `conn` runs inside the block is interrupted once `seconds` have passed (a page's read that must not hang):
    sqlite3's progress handler on a file of this system, the helper's own on a linked one."""
    if isinstance(conn, Connection):
        conn._call("limit", float(seconds))
        try:
            yield
        finally:
            conn._call("limit", None)
        return
    deadline = clock() + seconds
    conn.set_progress_handler(lambda: 1 if clock() >= deadline else 0, 20_000)
    try:
        yield
    finally:
        conn.set_progress_handler(None, 0)


def frame(sql: str, conn, params=None):
    """A query's rows as a DataFrame, on either kind of connection (the arguments in pd.read_sql_query's order):
    pandas' own reader for sqlite3's, as it always was; the same conversion of the same rows for a linked one
    (pandas takes only sqlite3's own class without a warning)."""
    import pandas as pd

    if not isinstance(conn, Connection):
        return pd.read_sql_query(sql, conn, params=params)
    cur = conn.execute(sql, params if params is not None else ())
    names = [d[0] for d in cur.description]
    rows = cur.fetchall()
    if not rows:
        return pd.DataFrame(columns=names)
    return pd.DataFrame.from_records(rows, columns=names, coerce_float=True)


# -- this process's links ----------------------------------------------------------------------------------------------
_links: dict[str, Link] = {}
_links_lock = threading.Lock()


def forced() -> str:
    """LIMINAL_LINK: "loopback" sends every file through a link inside this process (a suite run over the link)."""
    return (os.environ.get(FORCE_VAR) or "").strip().lower()


def helper_command(path) -> str:
    """The helper's command for a file on a Windows drive seen from WSL: LIMINAL_LINK_COMMAND; else the windowless
    Python of the workspace the file's folder is in (<workspace>/app/.venv/Scripts/pythonw.exe -m
    liminal_libs.storage.link), when it is there."""
    named = (os.environ.get(COMMAND_VAR) or "").strip()
    if named:
        return named
    for folder in Path(path).resolve().parents:
        python = folder / "app" / ".venv" / "Scripts" / "pythonw.exe"
        if python.is_file():
            return f"{shlex.quote(str(python))} -m liminal_libs.storage.link"
    raise LinkError(f"{path} is on another system's drive and no helper is named for it: set {COMMAND_VAR} to the "
                    "command that runs `python -m liminal_libs.storage.link` on the system that holds the file")


def link_for(path) -> Link | None:
    """The link a file is reached through, started at its first use; None for a file of this system's own disk."""
    mode = forced()
    if mode == "loopback":
        key = "loopback"
    elif mounts.foreign(path):
        key = "owner"
    else:
        return None
    with _links_lock:
        link = _links.get(key)
        if link is not None and link.dead and key == "loopback":
            link = None
        if link is None:
            if key == "loopback":
                link = Link.loopback(saved=lambda names: {}, anywhere=True)
            else:
                if mounts.owner_path(path) is None:
                    raise LinkError(f"{path} is on another system's drive that no helper can be started for from here "
                                    f"(a {mounts.fstype(path)} mount): its databases are opened only on the system that holds them")
                link = Link.start(helper_command(path), cwd=str(Path(path).resolve().parent),
                                  owner_path=mounts.owner_path, name="Windows")
            _links[key] = link
        return link


MAX_SKEW_S = 1.0  # past this difference between the two systems' clocks, a linked process fetches nothing


def clock_off(path) -> str:
    """Why nothing should be fetched into the database at `path` from here just now, in words: this system's clock
    is more than MAX_SKEW_S off the clock of the system that owns the file (what a run decides by this clock, a
    day's end, a session's open, would not agree with what the other system reads). "" when the file is this
    system's own, or the clocks agree."""
    link = link_for(path)
    if link is None:
        return ""
    link.call("clock")
    if abs(link.skew) <= MAX_SKEW_S:
        return ""
    return (f"this system's clock is {abs(link.skew):.1f} s {'behind' if link.skew > 0 else 'ahead of'} the clock of "
            f"{link.name}, which holds the data: nothing is fetched from here until they agree to within {MAX_SKEW_S:g} s")


def owner_link() -> Link | None:
    """The link to the files' own system, when this process has one (it never starts one)."""
    with _links_lock:
        return _links.get("owner") or _links.get("loopback")


def connect(database, timeout: float = 5.0, isolation_level=_DEFAULT, check_same_thread: bool = True,
            read_only: bool = False, **kw):
    """Open a SQLite file: the one way this software does. On this system's own disk: sqlite3.connect, as always
    (`read_only`: its file opened mode=ro). On another system's drive: through the helper on that system, never
    directly. In memory (":memory:"): here."""
    path = str(database)
    link = None if path in (":memory:", "") else link_for(path)
    if link is None:
        args: dict = {"timeout": timeout, "check_same_thread": check_same_thread, **kw}
        if isolation_level is not _DEFAULT:
            args["isolation_level"] = isolation_level
        if read_only and path not in (":memory:", ""):
            return sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, **args)
        return sqlite3.connect(path, **args)
    args = {"timeout": timeout}
    if isolation_level is not _DEFAULT:
        args["isolation_level"] = isolation_level
    if read_only:
        args["read_only"] = True
    return link.open(path, **args)


def _close_links() -> None:
    with _links_lock:
        links = list(_links.values())
        _links.clear()
    for link in links:
        link.close()


atexit.register(_close_links)


# -- nothing opens another system's file directly ---------------------------------------------------------------------
def _refuse_direct(event: str, args) -> None:
    if event != "sqlite3.connect" or not args or getattr(_helper, "here", False):
        return  # (a helper inside this process, the tests' loopback, is the files' own side: it opens them)
    target = args[0]
    if isinstance(target, bytes):
        target = os.fsdecode(target)
    target = str(target)
    if target.startswith("file:"):
        target = target[5:].split("?", 1)[0]
        while target.startswith("//"):
            target = target[1:]
    if target in ("", ":memory:") or not mounts.foreign(target):
        return
    raise LinkError(f"{target} is on another system's drive: a SQLite file there is opened by that system alone "
                    "(liminal_libs.storage.link.connect reaches it through the helper); it is not opened directly")


_hooked = False


def guard() -> bool:
    """On a system that sees another's drive through a mount (Linux): from now on no code of this process opens a
    SQLite file there directly, whoever tries. Returns whether the guard is on."""
    global _hooked
    if not _hooked and sys.platform.startswith("linux"):
        sys.addaudithook(_refuse_direct)
        _hooked = True
    return _hooked


guard()


# -- the helper's own process ------------------------------------------------------------------------------------------
def main(argv=None) -> int:
    """`python -m liminal_libs.storage.link`: the helper, for the process that started it. Its standard input and
    output are the pipe (binary; nothing else is ever written there); it ends when the pipe closes."""
    if os.name == "nt":
        import msvcrt

        for fd in (0, 1):
            try:
                msvcrt.setmode(fd, os.O_BINARY)
            except OSError:
                pass
    try:
        inp, out = os.fdopen(os.dup(0), "rb"), os.fdopen(os.dup(1), "wb")
    except OSError:  # no such descriptors (a windowless Python given its pipes as handles alone)
        inp, out = sys.stdin.buffer, sys.stdout.buffer
    try:  # whatever prints from now on goes nowhere near the pipe
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, 1)
        sys.stdout = open(os.devnull, "w")
    except OSError:
        pass
    from .. import config, layout

    roots = [layout.data_dir(), Path.home() / ".liminal"]
    named = os.environ.get("LIMINAL_DB")
    if named:
        roots.append(Path(named).expanduser().parent)

    def saved(names: tuple) -> dict:
        return config.UserEnvironment(names=names).saved()

    Server(roots, saved=saved).serve(inp, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
