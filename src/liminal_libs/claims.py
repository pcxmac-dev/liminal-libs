"""Claims: who is working on what, for every process on one database, whichever system it runs on (1.56.0).

The user, 2026-11-15: "If i run integrator on both sides, there cannot be any conflicts, so if one symbol is being
operated on, the other integrator would have to operate on another symbol". Until now a run was kept to itself by a
lock file beside the database naming a process id (proc.py), which only that process's own system can look up: seen
from Windows' side of WSL, or from Linux's, a held lock named a process that "did not exist", so it was taken over
and both sides worked on the same feed. And nothing was claimed by symbol at all.

A claim is a row in the main file's `claims` table, taken in one write transaction (so two takers can never both
have it), naming its key, the instance and the process that hold it:
- the **instance** is one installation of the suite: `windows::NEPTUNE`, `linux::Ubuntu` (instance()); every process
  of an instance may share a claim taken `shared` (a symbol: its feed runs work side by side, as they always did),
  while an exclusive one (a feed's run, the history copy) is one process's;
- a holder of the **same instance** is judged as a lock file's was: by its process, alive or not, so a crashed run
  gives way at once;
- a holder of **another instance** cannot be looked up, so it is judged by its heartbeat (beat(), every BEAT_S). One
  that has been silent for STALE_S is first challenged, and taken over only when it is still silent GRACE_S later:
  a computer asleep wakes every holder with an old heartbeat at once, and each answers its challenge before anyone
  takes anything (a single check would have let both sides take each other over);
- every take of a key has a **token** one higher than the last (claim_tokens): a holder that was taken over while it
  slept finds out with holds() before it writes anything more.
Every time is the database's own clock, read in SQL, never this process's: the two systems' clocks differ (WSL's
jumped ten seconds, back and forth, while the suite's tests ran there).

Keys in use: `feed:<name>` (one run per feed), `symbol:<asset>:<ticker>` (shared inside an instance), `history`,
`post`, `publications`, `live:<feed>`, `plugin:<name>` (a plugin's own fetching: one pass at a time) and
`process:<instance>:<pid>` (present(): a process at work that holds nothing else says it is alive, so another
installation can tell what it left running from what it is still working on: gone()).

Two levels. `Claims` is one connection's claims, with who it is and its clock given (the tests' two instances on one
file). The module's own `take`, `release`, `holds`, `held`, `exclusive` are this process's on a database by its path:
one connection and one heartbeat thread, there only while the process holds something, everything given back when
the process ends.

**The switch-over** (`exclusive(lock=...)`): for one release a holder takes the lock file that kept the key until
now as well, because processes started before this release look at lock files alone. On another system's drive
(mounts.foreign) a lock file cannot be judged, its process id being that system's: none is written there, and one
that is there without a claim is held, since a process from before claims may be behind it.
"""
from __future__ import annotations

import atexit
import os
import platform
import sqlite3
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from . import mounts, proc
from .storage.common import BUSY_TIMEOUT_S, Behind, own_files, read_only, write_transaction
from .storage.schema import CLAIMS as SCHEMA  # the main file's tables are the schema's to say

BEAT_S = 20.0  # a holder says it is alive this often
STALE_S = 90.0  # a holder in another instance silent this long is challenged
GRACE_S = 45.0  # ... and taken over when it is still silent this long after the challenge (two beats and more)
INSTANCE_VAR = "LIMINAL_INSTANCE"  # this installation's name among those on one database, when it is to be said outright
NOW = "(julianday('now') - 2440587.5) * 86400.0"  # unix seconds by the database's own clock
FEED = "feed:"
SYMBOL = "symbol:"
PLUGIN = "plugin:"
PROCESS = "process:"
LIVE = "live"  # the recorder of live trades: one on a database
PUBLICATIONS = "publications"  # the publications' reader: one pass at a time
HISTORY = "history"  # the closed months' copy
POST = "post"  # the pass of composites and derived frames after a sync
READS_ONLY = "nobody: this process reads only (LIMINAL_READONLY) and takes nothing"


def os_name(system: str | None = None) -> str:
    """This system as an instance names it: windows, linux, macos, else its own word (`system`: sys.platform)."""
    p = sys.platform if system is None else system
    return "windows" if p == "win32" else "linux" if p.startswith("linux") else "macos" if p == "darwin" else p


def instance(env=None) -> str:
    """This installation's name among those working on one database: LIMINAL_INSTANCE when set; else its system and
    its name there, `windows::NEPTUNE`, or inside WSL its distribution's, `linux::Ubuntu` (WSL_DISTRO_NAME: the
    machine's name is Windows' own there, and two distributions would share it)."""
    env = os.environ if env is None else env
    named = (env.get(INSTANCE_VAR) or "").strip()
    if named:
        return named
    name = (env.get("WSL_DISTRO_NAME") or "").strip() or platform.node() or "here"
    return f"{os_name()}::{name}"


def feed_key(feed: str) -> str:
    return f"{FEED}{feed}"


def symbol_key(asset: str, ticker: str) -> str:
    return f"{SYMBOL}{asset}:{ticker.upper()}"


def _local_alive(pid: int, started: int) -> bool:
    """Whether a process of this system is the one that took a claim: alive, and started when the claim says."""
    if not proc.pid_alive(pid):
        return False
    now = proc.started(pid)
    return not started or now is None or now == started


@dataclass(frozen=True)
class Claim:
    """A claim held: its key, and the token it was taken with."""

    key: str
    token: int
    instance: str
    pid: int


@dataclass(frozen=True)
class Held:
    """A claim as another reads it: who holds it, since when, and how long ago it was last heard from."""

    key: str
    instance: str
    pid: int
    since: float
    quiet: float
    what: str = ""
    mine: bool = False  # this instance's
    own: bool = False  # this very process's
    shared: bool = False

    def words(self) -> str:
        return f"{self.instance} (process {self.pid})" + (f": {self.what}" if self.what else "")


class Taken(RuntimeError):
    """A key another holds: `holder` says who, in words."""

    def __init__(self, key: str, holder: str):
        super().__init__(f"{key} is held by {holder}")
        self.key, self.holder = key, holder


class Claims:
    """One process's claims on a database, over a connection to its main file.

    `conn`: the connection (check_same_thread=False when a Keeper beats on it; `lock` guards it). `me`, `pid`,
    `started`: who this is (instance(), this process). `alive(pid, started)`: whether a process of this instance
    still runs (a test's stand-in). `clock`: unix seconds, in place of the database's (a test's). `create`: the
    tables made when the file has none (a file from before claims); without it such a file simply holds no claim."""

    def __init__(self, conn: sqlite3.Connection, *, me: str | None = None, pid: int | None = None, started: int | None = None,
                 alive: Callable[[int, int], bool] | None = None, clock: Callable[[], float] | None = None, create: bool = True):
        self.conn = conn
        self.me = me or instance()
        self.pid = os.getpid() if pid is None else int(pid)
        self.started = int(proc.started(self.pid) or 0) if started is None else int(started)
        self._alive = alive or _local_alive
        self._clock = clock
        self.lock = threading.RLock()
        self.held: dict[str, Claim] = {}  # what this object took and has not given back (a taken-over one leaves at a beat)
        self.lost: set[str] = set()  # the keys taken over from it while it was silent, until it takes or releases them
        with self.lock:
            self.tables = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='claim_tokens'").fetchone() is not None
            if create:
                self._make_tables()

    def _make_tables(self) -> None:
        """The claims' tables in a file from before claims: made under the write lock (two processes opening it at
        once both find them missing)."""
        if self.tables:
            return
        with write_transaction(self.conn):
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    self.conn.execute(statement)
        self.tables = True

    @classmethod
    def open(cls, db_path: Path | str, **kw) -> "Claims":
        """Claims on the main file at `db_path`, over a connection of their own (any thread may use it under the lock).
        A file on another system's drive is never given the tables from here (its layout is its owner's): one from
        before claims holds none, and a process that would take one there is told the file is behind (Behind)."""
        from .storage.link import connect

        own, create = own_files(db_path), kw.pop("create", True)
        conn = connect(str(db_path), timeout=BUSY_TIMEOUT_S, check_same_thread=False)
        try:
            claims = cls(conn, create=create and own, **kw)
            if create and not own and not claims.tables and not read_only():
                raise Behind(f"{db_path} is on another system's drive and behind this software (no table claims): its "
                             "tables are brought up to date by the system that holds it (the suite started there on "
                             "this version), and nothing is taken or changed there from here")
            return claims
        except BaseException:
            conn.close()
            raise

    def now(self) -> float:
        """The time, by the database's clock (the same for every instance on it)."""
        if self._clock is not None:
            return float(self._clock())
        return float(self.conn.execute(f"SELECT {NOW}").fetchone()[0])

    # -- taking and giving back ---------------------------------------------------------------------------------------
    def take(self, key: str, *, shared: bool = False, what: str = "") -> Claim | None:
        """The claim on `key`, or None while another holds it. `shared`: every process of this instance that also
        asks `shared` may hold it at once (a symbol); otherwise one process alone (a feed's run). Taken again by its
        holder, it is the same claim. A silent holder of another instance is challenged here and taken over at a
        later take (the module's words)."""
        with self.lock:
            self._make_tables()
            with write_transaction(self.conn):
                now = self.now()
                rows = self.conn.execute("SELECT instance, pid, started, token, beat_at, challenged_at, shared FROM claims "
                                         "WHERE key=?", (key,)).fetchall()
                mine: int | None = None
                held = False
                for inst, pid, started, token, beat, challenged, theirs_shared in rows:
                    if inst == self.me and pid == self.pid:
                        mine = token
                    elif inst == self.me:
                        if not self._alive(pid, started):  # a process of this instance that is gone: it holds nothing
                            self._drop(key, inst, pid)
                        elif not (shared and theirs_shared):
                            held = True
                    elif now - beat < STALE_S:
                        held = True
                    elif challenged is None or beat > challenged:  # silent: asked first, never taken on one look
                        self.conn.execute("UPDATE claims SET challenged_at=?, challenged_by=? WHERE key=? AND instance=? AND pid=?",
                                          (now, self.me, key, inst, pid))
                        held = True
                    elif now - challenged < GRACE_S:
                        held = True
                    else:  # asked, and still silent: gone
                        self._drop(key, inst, pid)
                if held:
                    return None  # (a challenge made, or a gone holder dropped, is written all the same)
                if mine is not None:  # taken again by its holder: the same claim, heard from now
                    self.conn.execute("UPDATE claims SET beat_at=?, challenged_at=NULL, challenged_by=NULL "
                                      "WHERE key=? AND instance=? AND pid=?", (now, key, self.me, self.pid))
                    claim = Claim(key, mine, self.me, self.pid)
                else:
                    token = self._next_token(key)
                    self.conn.execute("INSERT INTO claims (key, instance, pid, started, token, taken_at, beat_at, what, shared) "
                                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                      (key, self.me, self.pid, self.started, token, now, now, what, int(bool(shared))))
                    claim = Claim(key, token, self.me, self.pid)
            self.held[key] = claim
            self.lost.discard(key)
            return claim

    def _drop(self, key: str, inst: str, pid: int) -> None:
        self.conn.execute("DELETE FROM claims WHERE key=? AND instance=? AND pid=?", (key, inst, pid))

    def _next_token(self, key: str) -> int:
        row = self.conn.execute("SELECT token FROM claim_tokens WHERE key=?", (key,)).fetchone()
        token = (row[0] if row else 0) + 1
        self.conn.execute("INSERT OR REPLACE INTO claim_tokens (key, token) VALUES (?, ?)", (key, token))
        return token

    def release(self, claim: Claim | str) -> None:
        """This process's claim on a key given back (one it does not hold: nothing)."""
        key = claim.key if isinstance(claim, Claim) else claim
        with self.lock:
            self.held.pop(key, None)
            self.lost.discard(key)
            if not self.tables:
                return
            with write_transaction(self.conn):
                self._drop(key, self.me, self.pid)

    def release_all(self) -> int:
        """Everything this process holds given back (its end). Returns how many."""
        with self.lock:
            self.held.clear()
            self.lost.clear()
            if not self.tables:
                return 0
            with write_transaction(self.conn):
                return self.conn.execute("DELETE FROM claims WHERE instance=? AND pid=?", (self.me, self.pid)).rowcount

    # -- staying alive, and finding out ------------------------------------------------------------------------------
    def beat(self) -> int:
        """This process's claims heard from now, any challenge to them answered. Returns how many it holds. Holding
        nothing, it writes nothing; a claim taken over since the last beat is this object's no more."""
        with self.lock:
            if not self.held:
                return 0
            with write_transaction(self.conn):
                n = self.conn.execute("UPDATE claims SET beat_at=?, challenged_at=NULL, challenged_by=NULL "
                                      "WHERE instance=? AND pid=?", (self.now(), self.me, self.pid)).rowcount
                if n != len(self.held):
                    still = dict(self.conn.execute("SELECT key, token FROM claims WHERE instance=? AND pid=?", (self.me, self.pid)))
                    self.lost |= {k for k, c in self.held.items() if still.get(k) != c.token}
                    self.held = {k: c for k, c in self.held.items() if still.get(k) == c.token}
            return n

    def holds(self, claim: Claim) -> bool:
        """Whether a claim is still this process's, with the token it was taken with: False once it was taken over
        (asked before writing: a holder that slept through its own takeover must not write on)."""
        with self.lock:
            if not self.tables:
                return False
            row = self.conn.execute("SELECT token FROM claims WHERE key=? AND instance=? AND pid=?",
                                    (claim.key, claim.instance, claim.pid)).fetchone()
        return row is not None and row[0] == claim.token

    def was_lost(self, key: str) -> bool:
        """Whether a key this object took is its own no more: taken over while it was silent. One it never took,
        or gave back: False."""
        with self.lock:
            if key in self.lost:
                return True
            claim = self.held.get(key)
        if claim is None or self.holds(claim):
            return False
        with self.lock:
            self.held.pop(key, None)
            self.lost.add(key)
        return True

    def holders(self, prefix: str = "", elsewhere: bool = False) -> list[Held]:
        """The claims held now on keys starting with `prefix`: this instance's by processes still running, another's
        by those heard from within STALE_S (a challenged one still counts until it is taken over). `elsewhere`: only
        the other instances'."""
        with self.lock:
            if not self.tables:
                return []
            now = self.now()
            rows = self.conn.execute("SELECT key, instance, pid, started, taken_at, beat_at, challenged_at, what, shared FROM claims "
                                     "WHERE key >= ? AND key < ? ORDER BY key, instance, pid",
                                     (prefix, prefix + "\U0010ffff")).fetchall()
        out = []
        for key, inst, pid, started, taken, beat, challenged, what, shared in rows:
            mine = inst == self.me
            own = mine and pid == self.pid
            if mine and (elsewhere or not (own or self._alive(pid, started))):
                continue
            if not mine and now - beat >= STALE_S and challenged is not None and beat <= challenged and now - challenged >= GRACE_S:
                continue  # silent through its challenge: the next take removes it
            out.append(Held(key, inst, pid, taken, max(0.0, now - beat), what or "", mine, own, bool(shared)))
        return out

    def holder(self, key: str) -> Held | None:
        """Who holds `key` now (the first, of a shared one), or None."""
        return next((h for h in self.holders(key) if h.key == key), None)

    def close(self) -> None:
        with self.lock:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass


class Keeper:
    """A process's claims kept alive: a thread that beats every `every` seconds until stopped. The heartbeat has a
    connection of its own (`claims`: made with Claims.open), so a long write on the store's never holds it back."""

    def __init__(self, claims: Claims, every: float = BEAT_S, log: Callable[[str], None] | None = None):
        self.claims, self.every, self.log = claims, float(every), log
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> "Keeper":
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="claims-heartbeat", daemon=True)
            self._thread.start()
        return self

    def _run(self) -> None:
        while not self._stop.wait(self.every):
            try:
                self.claims.beat()
            except sqlite3.Error as e:  # the file busy, or gone: said, and tried again at the next beat
                if self.log:
                    self.log(f"claims: a heartbeat was not written ({e})")

    def stop(self, release: bool = True) -> None:
        """The heartbeat ended; with `release`, what the process holds is given back."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        if release:
            try:
                self.claims.release_all()
            except sqlite3.Error:
                pass


# -- this process's claims, by the database's path ---------------------------------------------------------------------
@dataclass
class _Mine:
    claims: Claims
    keeper: Keeper
    users: int = 0  # the calls at work on it now: it is not closed under them


_process: dict[str, _Mine] = {}
_process_lock = threading.Lock()


def _path_key(db_path) -> str:
    return os.path.normcase(os.path.abspath(str(db_path)))


@contextmanager
def _using(db_path, make: bool, log: Callable[[str], None] | None = None) -> Iterator[Claims | None]:
    """This process's claims on a database for one call: made at its first take (a connection and a heartbeat thread
    of their own), closed again once the process holds nothing there (nothing stays open on a database that is not
    being worked on)."""
    k = _path_key(db_path)
    with _process_lock:
        m = _process.get(k)
        if m is None and make:
            claims = Claims.open(db_path)
            m = _process[k] = _Mine(claims, Keeper(claims, log=log).start())
        if m is not None:
            m.users += 1
    try:
        yield m.claims if m is not None else None
    finally:
        if m is not None:
            with _process_lock:
                m.users -= 1
                done = m.users == 0 and not m.claims.held and not m.claims.lost and _process.get(k) is m
                if done:
                    del _process[k]
            if done:
                m.keeper.stop(release=False)
                m.claims.close()


def take(db_path, key: str, *, shared: bool = False, what: str = "", log: Callable[[str], None] | None = None) -> Claim | None:
    """This process's claim on `key` in the database at `db_path` (Claims.take), kept alive by its heartbeat until it
    is released or the process ends. None while another holds it, and always in a process that reads only
    (LIMINAL_READONLY: nothing of it reaches a file, a claim no more than a bar)."""
    if read_only():
        return None
    with _using(db_path, True, log) as claims:
        return claims.take(key, shared=shared, what=what)


def release(db_path, claim: Claim | str) -> None:
    """A claim of this process's given back (one it does not hold: nothing)."""
    with _using(db_path, False) as claims:
        if claims is not None:
            claims.release(claim)


def holds(db_path, claim: Claim) -> bool:
    """Whether a claim is still this process's (Claims.holds): asked before writing on."""
    with _using(db_path, False) as claims:
        return claims is not None and claims.holds(claim)


def lost(db_path, key: str) -> bool:
    """Whether a key this process took on a database was taken over from it while it was silent (a computer
    asleep for longer than the other installation waited): asked before writing on. One it never took: False,
    and nothing is read."""
    with _using(db_path, False) as claims:
        return claims is not None and claims.was_lost(key)


def mine(db_path) -> dict[str, Claim]:
    """What this process holds on a database now, by key."""
    with _using(db_path, False) as claims:
        if claims is None:
            return {}
        with claims.lock:
            return dict(claims.held)


def held(db_path, prefix: str = "", elsewhere: bool = False) -> list[Held]:
    """The claims held now on a database (Claims.holders): read over this process's connection when it holds
    something there, else over one opened for the moment. No file there, one that cannot be read, or one from
    before claims: none (and none is made by asking)."""
    with _using(db_path, False) as claims:
        if claims is not None:
            return claims.holders(prefix, elsewhere)
    if not Path(db_path).is_file():
        return []
    try:
        reader = Claims.open(db_path, create=False)
    except sqlite3.Error:
        return []
    try:
        return reader.holders(prefix, elsewhere)
    except sqlite3.Error:
        return []
    finally:
        reader.close()


def present(db_path, what: str = "", log: Callable[[str], None] | None = None) -> Claim | None:
    """This process says it is at work on a database: a claim that is its own alone (process:<instance>:<pid>),
    kept alive like any other. Another installation cannot look a process up; it can see this (gone())."""
    return take(db_path, f"{PROCESS}{instance()}:{os.getpid()}", what=what, log=log)


def gone(conn: sqlite3.Connection, owners, *, me: str | None = None, own_files: bool = True,
         alive: Callable[[int], bool] | None = None, now: float | None = None) -> set:
    """Which of these owners of rows, (instance, pid) as a row names the process working on it, are gone: what
    they left running may be taken back; what the others are working on is theirs.
    - no process named: gone;
    - this installation's: the process is looked up. This process itself counts as gone: it asks at the start of
      new work, about what an earlier pass of its own left;
    - unnamed (taken before rows named their installation): this installation's when the files are this
      system's own (`own_files`); on another system's drive only that system can tell: never gone;
    - another installation's: gone unless that process holds a claim heard from within STALE_S (every process
      that fetches holds one: its feed's, its plugin's, or present()'s).
    `conn`: any connection to the main file (the store's own, inside its transaction)."""
    me = me or instance()
    alive = alive or proc.pid_alive
    out: set = set()
    fresh: set | None = None
    for owner in set(owners):
        inst, pid = owner
        if pid is None:
            out.add(owner)
        elif inst == me or (inst is None and own_files):
            if int(pid) == os.getpid() or not alive(int(pid)):
                out.add(owner)
        elif inst is not None:
            if fresh is None:
                fresh = _heard_from(conn, now)
            if (inst, int(pid)) not in fresh:
                out.add(owner)
    return out


def _heard_from(conn: sqlite3.Connection, now: float | None = None) -> set:
    """The (instance, pid) of every process holding a claim heard from within STALE_S, by the database's clock."""
    try:
        if now is None:
            rows = conn.execute(f"SELECT DISTINCT instance, pid FROM claims WHERE {NOW} - beat_at < ?", (STALE_S,))
        else:
            rows = conn.execute("SELECT DISTINCT instance, pid FROM claims WHERE ? - beat_at < ?", (now, STALE_S))
        return {(i, int(p)) for i, p in rows}
    except sqlite3.Error:  # a file from before claims: nobody holds any
        return set()


def _give_back() -> None:
    """The process ends: everything it holds given back, on every database."""
    with _process_lock:
        ending = list(_process.values())
        _process.clear()
    for m in ending:
        try:
            m.keeper.stop(release=True)
        finally:
            m.claims.close()


atexit.register(_give_back)


@dataclass(frozen=True)
class Hold:
    """One process alone on a key: its claim, and the lock file taken beside it (None: none was)."""

    db_path: Path
    claim: Claim
    lock: Path | None = None
    again: bool = False  # taken again by the process that holds it: let_go gives nothing back

    def still(self) -> bool:
        """Whether it is still this process's (False: taken over while it slept; it must not write on)."""
        return holds(self.db_path, self.claim)


def _lock_taken(lock: Path) -> str | None:
    """Who holds a lock file, in words, or None when nobody does. On another system's drive its process id cannot be
    looked up: there, a lock file that exists is held (the switch-over's rule)."""
    if mounts.foreign(lock):
        return f"a lock file another system wrote, which only that system can judge ({lock})" if lock.exists() else None
    pid = proc.holder(lock)
    return f"process {pid} (lock file {lock})" if pid is not None else None


def hold(db_path, key: str, lock: Path | None = None, *, what: str = "",
         log: Callable[[str], None] | None = None) -> Hold:
    """This process alone on `key`, for every process on the database whichever system it runs on: Taken when
    another holds it. `lock`: the lock file that kept the key until claims; taken as well (the switch-over, in the
    module's words), except on another system's drive, where one that exists means Taken. Taken again by the
    process that holds the key, it is the same hold, and giving that one back gives nothing back. Given back
    with let_go (exclusive() does both round a block)."""
    db_path = Path(db_path)
    already = mine(db_path).get(key)
    if already is not None:
        return Hold(db_path, already, None, again=True)
    claim = take(db_path, key, what=what, log=log)
    if claim is None:
        who = READS_ONLY if read_only() else \
            next((h.words() for h in held(db_path, key) if h.key == key and not h.own), "another process")
        raise Taken(key, who)
    try:
        if lock is None:
            return Hold(db_path, claim, None)
        if mounts.foreign(lock):
            who = _lock_taken(lock)
            if who:
                raise Taken(key, who)
            return Hold(db_path, claim, None)
        if proc.acquire(lock):
            return Hold(db_path, claim, lock)
        raise Taken(key, _lock_taken(lock) or f"another process (lock file {lock})")
    except BaseException:
        release(db_path, claim)
        raise


def try_hold(db_path, key: str, lock: Path | None = None, *, what: str = "",
             log: Callable[[str], None] | None = None) -> Hold | None:
    """hold(), or None while another holds the key (where a lock file was tried, and its holder left to it)."""
    try:
        return hold(db_path, key, lock, what=what, log=log)
    except Taken:
        return None


def let_go(held_: Hold | None) -> None:
    """A hold given back: its lock file, then its claim (None, or one taken again by its holder: nothing)."""
    if held_ is None or held_.again:
        return
    if held_.lock is not None:
        proc.release(held_.lock)
    release(held_.db_path, held_.claim)


@contextmanager
def exclusive(db_path, key: str, lock: Path | None = None, *, what: str = "",
              log: Callable[[str], None] | None = None) -> Iterator[Hold]:
    """hold() for the length of a block: Taken when another holds the key; given back at its end, whatever
    ends it. Entered again by the process that holds the key, it gives nothing back when the inner one ends."""
    held_ = hold(db_path, key, lock, what=what, log=log)
    try:
        yield held_
    finally:
        let_go(held_)


def feed_runs(db_path) -> dict[str | None, Held]:
    """The fetching runs going now on a database: {feed: who}, None for the whole database's lock (a move of the
    data: every feed is busy while it is held). From the claims, every instance's, and from the lock files, for the
    processes from before claims (and the whole database's lock, which stays a file: the claims live in the database
    being moved). On another system's drive a lock file's owner cannot be looked up: one there without a claim
    counts as held."""
    db_path = Path(db_path)
    out: dict[str | None, Held] = {}
    for h in held(db_path, FEED):
        out.setdefault(h.key[len(FEED):], h)
    me = instance()
    if mounts.foreign(db_path):
        for feed, path in proc.run_lock_files(db_path).items():
            out.setdefault(feed, Held(feed_key(feed) if feed else "", "another system", 0, 0.0, 0.0,
                                      f"lock file {path.name}, which only that system can judge"))
    else:
        for feed, pid in proc.run_holders(db_path).items():
            out.setdefault(feed, Held(feed_key(feed) if feed else "", me, pid, 0.0, 0.0, "lock file", True, pid == os.getpid()))
    return out
