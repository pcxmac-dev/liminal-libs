"""The auditors (1.64.0): what was fetched is held against what was stored, and every symbol is gone over in turn.

The user, 2026-11-15: "leave the data in cache until an auditor goes over the symbol and checks the data bit by bit to
ensure it was copied successfully, auditors should run if a symbol is updated, or periodically"; "make sure that
auditing goes over all symbols to look for consistency issues or broken connections that fragmented data"; and
2026-11-18: "an auditor plugin, for auditing sources and maintaining the integrity of the feeds".

Two auditors, and what they are held to (`Policy`: the auditor plugin's options, plugin-integrator-auditor; the same
defaults with no plugin installed, so auditing is never off by accident):

**The copy audit** (`audit_pull`). A pull's rows files (storage/pulls.py) are what its writes handed to the database.
Each is read back, its text held against the sha256 kept when it was written, and its rows compared with the feed's
`bars` inside SQLite, every key and every value, by the comparison the write itself uses (`IS`, the rule of
storage/feeds.py's _UPSERT_BAR): the stored form is judged, with the column's own conversions on both sides. A bar
that is stored as the file has it passes. One that a later write replaced passes when the version the file holds is
the one kept as replaced (bar_revisions, replaced at or after this file was stored). A bar of the file that is not
stored at all is put in from the file (`repair`; never one that was moved out as another instrument's:
archived_bars). A bar stored with other values is a finding, nothing stored is overwritten, and the feed is asked
for it again a few at a time (the collector's re-pulls). A pull that passes has its files removed, or kept the days
the policy says; one with a finding keeps them as its evidence. What this proves is that the load from the cache into
the database was exact: not that the feed's data is right (the second-feed audit of audit.py and the sweep look at
that).

**The sweep** (`Sweep`, below): every watched series of every feed in turn, a time budget a run, each under its
symbol's claim.

A bar's values are compared as numbers in their stored form: a float against the float the file's text reads back
to, which is the same float bit for bit but for a negative zero.

**A rows file loaded late** (its run ended between the file and the database: `_load`) is the answer of its own
moment. It puts in what is not stored and replaces only what was stored before it was written; a bar stored since
(the live recorder's, a later run's) is the newer word and stays, and one moved out as another instrument's stays
out. Its audit then takes a bar stored since for what it is, not for a difference.

**One process at a time** audits or recovers a feed's cache (the claim `cache:<feed>`): a feed's run auditing the
pull it just closed, the auditors' process and a run at the cap never read and remove the same files at once. A
pull whose feed is being audited elsewhere is left to that process, or to the next pass.

What "a later write" is rests on the moment each write was stored under, which is this machine's clock. A clock set
back between a write and the one that rightly replaced it can make the replacement look like a difference: the
cost is a finding and one more ask of the feed, never a change to what is stored."""
from __future__ import annotations

import os
import shutil
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterator, Mapping

from . import spool
from .sources.plugin import IntegratorPlugin
from .storage import pulls
from .storage.common import busy, own_files, read_only

Log = Callable[[str], None]

# -- the policy: the auditor plugin's options ---------------------------------------------------------------------------
ON_UPDATE, SWEEP_EVERY, SWEEP_MINUTES = "AUDITOR_ON_UPDATE", "AUDITOR_SWEEP_EVERY", "AUDITOR_SWEEP_MINUTES"
ON_MISMATCH, KEEP_DAYS, CACHE_GB, REPULLS = "AUDITOR_ON_MISMATCH", "AUDITOR_KEEP_DAYS", "AUDITOR_CACHE_GB", "AUDITOR_REPULLS"
# Each option's choices, the default first (the Plugins view draws them; the plugin declares them as its own).
CHOICES: dict[str, tuple[str, ...]] = {
    ON_UPDATE: ("on", "off"),
    SWEEP_EVERY: ("24h", "6h", "7d", "off"),
    SWEEP_MINUTES: ("10", "5", "30", "60"),
    ON_MISMATCH: ("repair", "flag"),
    KEEP_DAYS: ("0", "1", "7", "30"),
    CACHE_GB: ("20", "5", "50", "100"),
    REPULLS: ("5", "0", "20"),
}
ABOUT: dict[str, str] = {
    ON_UPDATE: "Audit when a symbol is updated",
    SWEEP_EVERY: "Sweep every",
    SWEEP_MINUTES: "Minutes per sweep run",
    ON_MISMATCH: "On a mismatch",
    KEEP_DAYS: "Keep verified payloads (days)",
    CACHE_GB: "Cache cap (GB)",
    REPULLS: "Re-pulls per sweep",
}
_HOURS = {"24h": 24.0, "6h": 6.0, "7d": 168.0, "off": None}
FORGET_DAYS = 7  # a pull kept past its audit for the sweep (one that was cut off) is forgotten this long after it
TIDY_PULLS = 2000  # pulls whose files `tidy` removes in one call
SHOWN = 5  # of a finding's bars, the first few are kept with it


@dataclass(frozen=True)
class Policy:
    """What the auditors are held to. The defaults are the ones that apply when nothing is set."""

    on_update: bool = True  # the copy audit runs as each pull closes, and after a symbol's fetch
    sweep_hours: float | None = 24.0  # the sweep's interval (None: no periodic sweep)
    sweep_minutes: int = 10  # one sweep run's time
    repair: bool = True  # a bar the cache has and the database has not is put in from the cache
    keep_days: int = 0  # a verified pull's files are kept this long (0: removed at once)
    cap_gb: int = 20  # unverified cache: at the cap, fetching waits for the auditors
    repulls: int = 5  # bars asked of a feed again, a run

    @classmethod
    def of(cls, variables: Mapping[str, str] | None) -> "Policy":
        """The policy the variables say (each one of its CHOICES; unset: its default). ValueError, naming the
        variable and its choices, for a value that is none of them."""
        got: dict[str, str] = {}
        for name, choices in CHOICES.items():
            value = str((variables or {}).get(name) or "").strip().lower() or choices[0]
            if value not in choices:
                raise ValueError(f"{name}={value!r}: one of {', '.join(choices)}")
            got[name] = value
        return cls(on_update=got[ON_UPDATE] == "on", sweep_hours=_HOURS[got[SWEEP_EVERY]],
                   sweep_minutes=int(got[SWEEP_MINUTES]), repair=got[ON_MISMATCH] == "repair",
                   keep_days=int(got[KEEP_DAYS]), cap_gb=int(got[CACHE_GB]), repulls=int(got[REPULLS]))

    def as_dict(self) -> dict:
        return {"onUpdate": self.on_update, "sweepHours": self.sweep_hours, "sweepMinutes": self.sweep_minutes,
                "repair": self.repair, "keepDays": self.keep_days, "capGb": self.cap_gb, "repulls": self.repulls}


_policy = [Policy()]


def set_policy(policy: Policy | None) -> None:
    """This process's policy from here on (a command sets it once it knows its settings, as it sets read-only).
    None: the defaults."""
    _policy[0] = policy if isinstance(policy, Policy) else Policy()


def policy() -> Policy:
    return _policy[0]


def policy_of(settings) -> Policy:
    """The policy of an app's settings: the auditor plugin's own (Settings.plugin), the defaults without it."""
    own = settings.plugin("auditor") if settings is not None and hasattr(settings, "plugin") else None
    return own if isinstance(own, Policy) else Policy()


class AuditorPlugin(IntegratorPlugin):
    """The auditors' plugin (plugin API 2.4): the integrator's, one an app. It holds the auditors' options and
    nothing else (the user, 2026-11-15: "there needs to be a plugin called auditor and it will manage the
    configuration of auditing data"). `options` are the variables and `plan_choices` each one's choices, its default
    first: a page draws them as it draws any plugin's. Its `settings` hook answers the Policy they make (`policy`
    is the contract's reading of them; a value that is none of the choices is a ConfigError, as any setting's is).

    The auditors themselves are the library's (this module) and run whether or not such a plugin is installed:
    without one they keep to the defaults, so auditing is never off because a package is missing."""

    CONTRACT = True
    KIND = "auditor"
    HOOKS = ("scan", "settings")
    ICON = "scales"  # its icon on a page (icons.js)
    options = tuple(CHOICES)
    plan_choices = CHOICES

    def policy(self, variables: Mapping[str, str]) -> Policy:
        """The Policy the variables make (what a plugin's `settings` answers)."""
        from .config import ConfigError

        try:
            return Policy.of(variables)
        except ValueError as e:
            raise ConfigError(str(e)) from e


CacheFull = spool.CacheFull  # the cache at its cap (the policy's `Cache cap`): fetching waits for the auditors


# -- the copy audit ----------------------------------------------------------------------------------------------------
_KEY = ("ticker", "timespan", "multiplier", "ts")
_VALUES = ("open", "high", "low", "close", "volume", "vwap", "transactions")
_TEMP = ("CREATE TEMP TABLE IF NOT EXISTS pull_rows (ticker TEXT NOT NULL, timespan TEXT NOT NULL, multiplier INTEGER "
         "NOT NULL, ts INTEGER NOT NULL, open REAL, high REAL, low REAL, close REAL, volume REAL, vwap REAL, "
         "transactions INTEGER, PRIMARY KEY (ticker, timespan, multiplier, ts)) WITHOUT ROWID")
_ON = " AND ".join(f"{{o}}.{c}=t.{c}" for c in _KEY)
_IS = " AND ".join(f"{{o}}.{c} IS t.{c}" for c in _VALUES)
_IS_NOT = " OR ".join(f"b.{c} IS NOT t.{c}" for c in _VALUES)
_T = ", ".join(f"t.{c}" for c in (*_KEY, *_VALUES))
_B = ", ".join(f"b.{c}" for c in _VALUES)
_STEP = {"second": 1_000, "minute": 60_000, "hour": 3_600_000, "day": 86_400_000}
_FILL = "INSERT OR REPLACE INTO temp.pull_rows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
# A rows file loaded late: what is not stored is put in, what was stored before the file was written is replaced
# (as its run would have), what was stored since stays. `{moved}`: nor is a bar brought back that was moved out.
_LATE = ("INSERT INTO bars (" + ", ".join((*_KEY, *_VALUES)) + ", stored_at) SELECT " + _T + ", ? FROM temp.pull_rows t "
         "WHERE true{moved} ON CONFLICT (ticker, timespan, multiplier, ts) DO UPDATE SET "
         + ", ".join(f"{c}=excluded.{c}" for c in (*_VALUES, "stored_at"))
         + " WHERE (" + " OR ".join(f"bars.{c} IS NOT excluded.{c}" for c in _VALUES)
         + ") AND COALESCE(bars.stored_at, 0) <= excluded.stored_at")
_NOT_MOVED = " AND NOT EXISTS (SELECT 1 FROM archived_bars a WHERE " + _ON.format(o="a") + ")"
# A trades file (1.82.0: the live recorder's, storage/pulls.py TRADE_COLUMNS) is held against the feed's
# ticks.trades the same way: every key and every value by `IS`, in a table of the same columns and types. A trade
# the file has and the database has not is put in from it, unless the exchange withdrew it since (it is then in
# ticks.archived_trades, where it should be). A trade has no moment of its own write: one stored with other values
# is a difference, except in a file loaded late, where what was stored since is the newer word.
_TKEY = ("ticker", "ts_ns", "seq")
_TVALUES = ("price", "size", "exchange", "conditions", "trade_id", "tape")
_TTEMP = ("CREATE TEMP TABLE IF NOT EXISTS pull_trades (ticker TEXT NOT NULL, ts_ns INTEGER NOT NULL, seq INTEGER "
          "NOT NULL, price REAL NOT NULL, size REAL NOT NULL, exchange INTEGER, conditions TEXT, trade_id TEXT, tape "
          "INTEGER, PRIMARY KEY (ticker, ts_ns, seq)) WITHOUT ROWID")
_TON = " AND ".join(f"{{o}}.{c}=t.{c}" for c in _TKEY)
_TIS_NOT = " OR ".join(f"b.{c} IS NOT t.{c}" for c in _TVALUES)
_TT = ", ".join(f"t.{c}" for c in (*_TKEY, *_TVALUES))
_TB = ", ".join(f"b.{c}" for c in _TVALUES)
_TFILL = "INSERT OR REPLACE INTO temp.pull_trades VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
_TWITHDRAWN = " AND EXISTS (SELECT 1 FROM ticks.archived_trades a WHERE " + _TON.format(o="a") + ")"
FAILURES = 3  # so many pulls whose audit raised are said one by one in a pass; the rest are counted


def cache_on() -> bool:
    """Whether this process keeps a fetch cache at all: not one that reads only, nor with LIMINAL_FETCH_CACHE=off.
    Where it does not, a feed's run neither settles nor audits what an earlier one left: it writes as before 1.64.0,
    and the auditors' own process takes what waits."""
    return pulls.enabled() and not read_only()


# A feed's cache is one thread's at a time, in one process at a time. The claim (claims.py) keeps processes apart
# and is the same claim to every thread of the process that holds it, so the threads of one process are kept apart
# here: the keys this process's threads hold now, and the claims a release could not give back (a database busy
# just then), which are given back at the next chance instead of staying held for as long as the process lives.
_held_here: set[tuple[str, str]] = set()
_owed: set[tuple[str, str]] = set()
_here = threading.Lock()


def _hold(store, feed: str):
    """This thread's hold on a feed's cache, for as long as it audits or recovers a pull of it: this process's
    claim (claims.py: `cache:<feed>`), and the feed's place among this process's own threads. Returns what
    `_let_go` takes back; None where there is nothing to claim on (a store without a file); False while another
    process, or another thread of this one, holds it."""
    from . import claims, collector

    path = collector._claimable(store)
    if path is None:
        return None
    key = (os.path.normcase(os.path.abspath(str(path))), f"cache:{feed}")
    with _here:
        if key in _held_here:
            return False
        _held_here.add(key)
    try:
        _settle_owed(path)
        conn = getattr(store, "conn", None)
        if conn is not None and conn.in_transaction:
            conn.commit()  # the claim is written over a connection of its own: nothing of the store's is left open under it
        claim = claims.take(path, key[1], what="auditing its fetch cache")
    except BaseException:
        with _here:
            _held_here.discard(key)
        raise
    if claim is None:
        with _here:
            _held_here.discard(key)
        return False
    return (key, claim)


def _let_go(store, held) -> None:
    """A feed's cache given back (None or False: nothing was held). It never raises: what the audit found, or what
    went wrong in it, is what its caller hears. A claim the database would not take back just now is owed, and
    given back when a feed's cache is next asked for (`_settle_owed`)."""
    if not held:
        return
    from . import claims

    key, claim = held
    try:
        claims.release(store.path, claim)
    except (sqlite3.Error, OSError):
        with _here:
            _owed.add(key)
    else:
        with _here:
            _owed.discard(key)
    finally:
        with _here:
            _held_here.discard(key)


def _settle_owed(path) -> None:
    """The claims a release could not give back, given back now: those on this database that no thread holds (one
    a thread holds again is that thread's to give back). Each is taken once more, which is the same claim to the
    process whose row it still is, and released: a release by itself has nothing to work with once the process
    held nothing else and its claims were closed."""
    from . import claims

    where = os.path.normcase(os.path.abspath(str(path)))
    with _here:
        owed = [k for k in _owed if k[0] == where]
    for key in owed:
        with _here:
            if key in _held_here:
                continue
            _held_here.add(key)
        try:
            claim = claims.take(path, key[1], what="auditing its fetch cache")
            if claim is not None:
                claims.release(path, claim)
            with _here:
                _owed.discard(key)
        except (sqlite3.Error, OSError):
            pass  # still owed
        finally:
            with _here:
                _held_here.discard(key)


@dataclass
class FileAudit:
    """One rows file held against the database."""

    seq: int
    rows: int = 0
    result: str = "ok"  # ok | repaired | mismatch | damaged
    missing: int = 0  # bars the file has and the database had not
    repaired: int = 0  # of them, put in from the file
    moved: int = 0  # of them, moved out as another instrument's (left alone)
    differing: int = 0  # bars stored with other values, and not as a later write's
    replaced: int = 0  # bars a later write replaced, the file's version kept as replaced
    shown: list = field(default_factory=list)  # the first few differing or missing, as evidence
    why: str = ""


@dataclass
class PullAudit:
    """A pull's audit: what each rows file showed, and what became of its files."""

    pull: str
    feed: str
    ticker: str | None
    result: str = "ok"  # ok | repaired | mismatch
    files: list[FileAudit] = field(default_factory=list)
    loaded_late: int = 0  # rows files loaded by the audit: written, and not in the database when their run ended
    damaged_payloads: int = 0
    removed: int = 0  # files removed

    @property
    def rows(self) -> int:
        return sum(f.rows for f in self.files)

    @property
    def missing(self) -> int:
        return sum(f.missing for f in self.files)

    @property
    def differing(self) -> int:
        return sum(f.differing for f in self.files)

    def words(self) -> str:
        """The audit in a line, for a log."""
        who = f"{self.feed}:{self.ticker}" if self.ticker else self.feed
        if self.result == "ok":
            return f"audit {who}: {self.rows:,} bars of {len(self.files)} cache files match what is stored"
        parts = [f"{self.rows:,} bars of {len(self.files)} cache files"]
        if self.missing:
            parts.append(f"{self.missing:,} were not stored" + (f" ({sum(f.repaired for f in self.files):,} put in "
                                                               "from the cache)" if self.result != "mismatch"
                                                               or any(f.repaired for f in self.files) else ""))
        if self.differing:
            parts.append(f"{self.differing:,} are stored with other values (kept as stored; asked of the feed again)")
        if any(f.result == "damaged" for f in self.files) or self.damaged_payloads:
            parts.append("a cache file is not what was written")
        return f"audit {who}: " + ", ".join(parts)


def _has(conn, table: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def compare(conn, rows: list, stored_at: int | None = None, repair: bool = True, now_ms: int | None = None,
            late: bool = False) -> FileAudit:
    """Bar rows (as a rows file holds them: the key, then the values) held against `bars` on `conn`, a feed's own
    connection: what is missing, what differs, what a later write replaced. With `repair`, the missing are put in.
    `late`: the file was loaded after its run had ended, and left alone whatever was stored since it was written."""
    out = FileAudit(seq=0, rows=len(rows))
    conn.execute(_TEMP)
    with conn:
        conn.execute("DELETE FROM temp.pull_rows")
        # (a key twice in one file: the later row is the one a write stored, and the one kept here)
        conn.executemany(_FILL, rows)
    out.rows = conn.execute("SELECT COUNT(*) FROM temp.pull_rows").fetchone()[0]
    # A bar stored with other values is a later write's when it was stored after this file was (stored_at) and the
    # version the file holds is kept as the one replaced then (bar_revisions). One stored under this file's own
    # moment with other values is nobody's later write: it differs.
    revised = _has(conn, "bar_revisions")
    kept = ("EXISTS (SELECT 1 FROM bar_revisions r WHERE " + _ON.format(o="r") + " AND r.derivation IS NULL AND "
            + _IS.format(o="r") + "{when})")
    args: tuple
    if late and stored_at is not None:
        # loaded late: a bar stored since the file was written was never this file's to replace (no version of the
        # file's was ever stored there to be kept as replaced), and is the newer word
        later, args = " AND NOT (COALESCE(b.stored_at, 0) > ?)", (int(stored_at),)
    elif revised and stored_at is not None:
        later = " AND NOT (COALESCE(b.stored_at, 0) > ? AND " + kept.format(when=" AND r.replaced_at >= ?") + ")"
        args = (int(stored_at), int(stored_at))
    elif revised:
        later, args = " AND NOT " + kept.format(when=""), ()
    else:
        later, args = "", ()
    differs = f"FROM temp.pull_rows t JOIN bars b ON {_ON.format(o='b')} WHERE ({_IS_NOT})"
    out.differing = conn.execute(f"SELECT COUNT(*) {differs}{later}", args).fetchone()[0]
    if later:
        out.replaced = conn.execute(f"SELECT COUNT(*) {differs}", ()).fetchone()[0] - out.differing
    if out.differing:
        for r in conn.execute(f"SELECT {_T}, {_B}, b.stored_at {differs}{later} ORDER BY t.ts LIMIT {SHOWN}", args):
            out.shown.append({"ticker": r[0], "timespan": r[1], "ts": r[3], "cached": list(r[4:11]),
                              "stored": list(r[11:18]), "stored_at": r[18]})
    absent = f"FROM temp.pull_rows t WHERE NOT EXISTS (SELECT 1 FROM bars b WHERE {_ON.format(o='b')})"
    out.missing = conn.execute(f"SELECT COUNT(*) {absent}").fetchone()[0]
    if out.missing:
        moved = f" AND EXISTS (SELECT 1 FROM archived_bars a WHERE {_ON.format(o='a')})" if _has(conn, "archived_bars") else ""
        if moved:
            out.moved = conn.execute(f"SELECT COUNT(*) {absent}{moved}").fetchone()[0]
        left = absent + (moved.replace(" AND EXISTS", " AND NOT EXISTS") if moved else "")
        if out.missing > out.moved:
            for r in conn.execute(f"SELECT {_T} {left} ORDER BY t.ts LIMIT {SHOWN}"):
                out.shown.append({"ticker": r[0], "timespan": r[1], "ts": r[3], "cached": list(r[4:11]), "stored": None})
            if repair:
                at = int(time.time() * 1000) if now_ms is None else int(now_ms)
                with conn:
                    out.repaired = conn.execute(
                        f"INSERT INTO bars ({', '.join((*_KEY, *_VALUES))}, stored_at) SELECT {_T}, ? {left}", (at,)).rowcount
    with conn:
        conn.execute("DELETE FROM temp.pull_rows")
    out.missing -= out.moved  # (a bar moved out as another instrument's is where it should be)
    if out.differing or out.missing > out.repaired:
        out.result = "mismatch"
    elif out.repaired:
        out.result = "repaired"
    return out


def _tick_archive(conn) -> bool:
    """Whether the feed's tick file has its archive of withdrawn trades (made with the first withdrawal)."""
    return conn.execute("SELECT 1 FROM ticks.sqlite_master WHERE type='table' AND name='archived_trades'"
                        ).fetchone() is not None


def compare_trades(conn, rows: list, repair: bool = True, late: bool = False) -> FileAudit:
    """Trades (as a trades file holds them: TRADE_COLUMNS) held against ticks.trades on `conn`, a feed's own
    connection with its tick file attached (1.82.0): what is missing, what differs. With `repair`, the missing are
    put in, never one the exchange withdrew since. `late`: the file was loaded after its run had ended, and a trade
    stored since with other values is the newer word (counted as replaced, not as a difference)."""
    out = FileAudit(seq=0, rows=len(rows))
    conn.execute(_TTEMP)
    with conn:
        conn.execute("DELETE FROM temp.pull_trades")
        conn.executemany(_TFILL, rows)
    out.rows = conn.execute("SELECT COUNT(*) FROM temp.pull_trades").fetchone()[0]
    differs = f"FROM temp.pull_trades t JOIN ticks.trades b ON {_TON.format(o='b')} WHERE ({_TIS_NOT})"
    n = conn.execute(f"SELECT COUNT(*) {differs}").fetchone()[0]
    if late:
        out.replaced = n
    else:
        out.differing = n
        for r in conn.execute(f"SELECT {_TT}, {_TB} {differs} ORDER BY t.ts_ns LIMIT {SHOWN}") if n else ():
            out.shown.append({"ticker": r[0], "timespan": "trades", "ts": r[1] // 1_000_000, "ts_ns": r[1], "seq": r[2],
                              "cached": list(r[3:9]), "stored": list(r[9:15])})
    absent = f"FROM temp.pull_trades t WHERE NOT EXISTS (SELECT 1 FROM ticks.trades b WHERE {_TON.format(o='b')})"
    out.missing = conn.execute(f"SELECT COUNT(*) {absent}").fetchone()[0]
    if out.missing:
        withdrawn = _TWITHDRAWN if _tick_archive(conn) else ""
        if withdrawn:
            out.moved = conn.execute(f"SELECT COUNT(*) {absent}{withdrawn}").fetchone()[0]
        left = absent + (withdrawn.replace(" AND EXISTS", " AND NOT EXISTS") if withdrawn else "")
        if out.missing > out.moved:
            for r in conn.execute(f"SELECT {_TT} {left} ORDER BY t.ts_ns LIMIT {SHOWN}"):
                out.shown.append({"ticker": r[0], "timespan": "trades", "ts": r[1] // 1_000_000, "ts_ns": r[1],
                                  "seq": r[2], "cached": list(r[3:9]), "stored": None})
            if repair:
                with conn:
                    out.repaired = conn.execute(f"INSERT OR IGNORE INTO ticks.trades SELECT {_TT} {left}").rowcount
    with conn:
        conn.execute("DELETE FROM temp.pull_trades")
    out.missing -= out.moved  # (a trade the exchange withdrew is where it should be: in the archive)
    if out.differing or out.missing > out.repaired:
        out.result = "mismatch"
    elif out.repaired:
        out.result = "repaired"
    return out


def _ticks_here(store, feed: str) -> bool:
    """Whether this process may open a feed's tick file (not in bars-only mode, where only the live recorder
    does): a pull with trades files is audited, and its trades loaded late, only where it may."""
    fd = store._feed(feed)
    return fd is not None and bool(getattr(fd, "ticks_allowed", False))


def _load_trades(store, feed: str, rows: list) -> bool:
    """A trades file's trades loaded late: those not stored put in, never one the exchange withdrew since; what was
    stored stays as it is (a trade has no moment of its own write to judge which is newer). False where this
    process may not open the feed's tick file."""
    fd = store._feed(feed, create=True)
    if not getattr(fd, "ticks_allowed", False):
        return False
    fd.attach_ticks()
    conn = fd.conn
    conn.execute(_TTEMP)
    withdrawn = _TWITHDRAWN.replace(" AND EXISTS", " AND NOT EXISTS") if _tick_archive(conn) else ""
    with conn:
        conn.execute("DELETE FROM temp.pull_trades")
        conn.executemany(_TFILL, rows)
        conn.execute(f"INSERT OR IGNORE INTO ticks.trades SELECT {_TT} FROM temp.pull_trades t WHERE true{withdrawn}")
        conn.execute("DELETE FROM temp.pull_trades")
    return True


def _load(store, pull: dict, files: list[dict], folder) -> int:
    """Rows files written and never loaded (their run ended, or failed, between the file and the database): loaded
    now, and for a series' own pull recorded as held in the coverage ledger from their first bar to their last.
    A file loaded so is the answer of the moment it was written: it puts in what is not stored and replaces what was
    stored before it, as its run would have; what was stored since stays as it is (the live recorder's bar, a
    later run's corrected one), and a bar moved out as another instrument's is not brought back. Returns the files
    loaded."""
    done = 0
    for f in files:
        if f["kind"] not in pulls.ROWS_KINDS or f["loaded_at"] or f["removed_at"]:
            continue
        try:
            header, rows, digest = spool.read_rows(folder / f["name"])
        except (OSError, EOFError, ValueError):
            continue  # not readable: its audit says so
        if digest != f["sha256"] or not rows:
            continue
        feed = f["feed"] or header.get("feed") or pull["feed"]
        if f["kind"] == "trades":  # (1.82.0: the live recorder's; left for a process that opens tick files)
            if _load_trades(store, feed, rows):
                store.pull_file_loaded(pull["id"], f["seq"], late=True)
                store._wrote()
                done += 1
            continue
        stored = int(f["stored_at"] or header.get("stored_at") or time.time() * 1000)
        conn = store._feed(feed, create=True).conn
        conn.execute(_TEMP)
        with conn:
            conn.execute("DELETE FROM temp.pull_rows")
            conn.executemany(_FILL, rows)
            conn.execute(_LATE.format(moved=_NOT_MOVED if _has(conn, "archived_bars") else ""), (stored,))
            conn.execute("DELETE FROM temp.pull_rows")
        store.pull_file_loaded(pull["id"], f["seq"], late=True)
        store._wrote()
        step = _STEP.get(pull.get("timespan") or "")
        if pull["kind"] in ("bars", "download", "recheck") and pull.get("ticker") and step and f["lo_ms"] is not None:
            store.add_coverage(feed, pull["ticker"], pull["timespan"], int(f["lo_ms"]), int(f["hi_ms"]) + step)
        done += 1
    return done


def _remove(store, pull: dict, files: list[dict], folder) -> int:
    """A pull's files removed from disk (those still there), its folder with them. Only what is really gone is
    said to be: a file that cannot be removed now (on Windows, one another program holds open) stays in the ledger
    as a file on disk, and `tidy` tries again. Returns the files removed."""
    there = [f for f in files if not f["removed_at"]]
    gone: list[int] = []
    for f in there:
        try:
            os.unlink(folder / f["name"])
        except FileNotFoundError:
            pass
        except OSError:
            continue
        gone.append(f["seq"])
    if gone:
        store.pull_files_removed(pull["id"], gone)
    if len(gone) == len(there):
        shutil.rmtree(folder, ignore_errors=True)  # (with whatever else is in it: a write's unfinished file)
    return len(gone)


def audit_pull(store, pull, policy_: Policy | None = None, log: Log | None = None) -> PullAudit | None:
    """One pull audited (see the module's words): a closed pull not audited yet, by its id or its row. None for one
    that is not there, still open, audited already, in a process that reads only, or while another process audits
    its feed's cache (it is that process's to take, or the next pass's)."""
    with_ = policy_ or policy()
    row = store.pull(pull) if isinstance(pull, str) else pull
    if row is None or row["state"] == "open" or row["audit"] is not None or read_only():
        return None
    held = _hold(store, row["feed"])
    if held is False:
        return None
    try:
        row = store.pull(row["id"])  # as it stands now: the process that just let go may have audited it
        if row is None or row["state"] == "open" or row["audit"] is not None:
            return None
        return _audit(store, row, with_, log)
    finally:
        _let_go(store, held)


def _audit(store, row: dict, with_: Policy, log: Log | None) -> PullAudit | None:
    """audit_pull's work, the feed's cache held."""
    folder = store.pull_folder(row)
    if folder is None:
        return None
    out = PullAudit(row["id"], row["feed"], row["ticker"])
    files = store.pull_files(row["id"])
    trades = [f for f in files if f["kind"] == "trades" and not f["removed_at"]]
    if any(not _ticks_here(store, f["feed"] or row["feed"]) for f in trades):
        return None  # (a process in bars-only mode: the live recorder's own to audit, which opens the tick files)
    out.loaded_late = _load(store, row, files, folder)
    if out.loaded_late:
        files = store.pull_files(row["id"])
    # A trade a later file of the same pull wrote again (the recorder's same trade in the next flush) is that
    # file's to judge: each trades file is held only to the keys no later one of its pull holds.
    later: dict[int, set] = {}
    seen: set = set()
    for f in sorted((f for f in files if f["kind"] == "trades" and not f["removed_at"]), key=lambda f: -f["seq"]):
        later[f["seq"]] = seen
        try:
            seen = seen | {(r[0], r[1], r[2]) for r in spool.read_rows(folder / f["name"])[1]}
        except (OSError, EOFError, ValueError, IndexError, TypeError):
            pass  # (its own audit says it is damaged)
    for f in files:
        if f["removed_at"]:
            continue
        if f["kind"] == "payload":
            try:
                sound = spool.payload_sha256(folder / f["name"]) == f["sha256"]
            except (OSError, EOFError, ValueError):
                sound = False
            if not sound:
                out.damaged_payloads += 1
                store.pull_file_audited(row["id"], f["seq"], "damaged")
            else:
                store.pull_file_audited(row["id"], f["seq"], "ok")
            continue
        one = FileAudit(seq=f["seq"])
        try:
            header, rows, digest = spool.read_rows(folder / f["name"])
        except (OSError, EOFError, ValueError) as e:
            header, rows, digest = {}, [], ""
            one.result, one.why = "damaged", f"{type(e).__name__}: {e}"[:200]
        if one.result != "damaged" and digest != f["sha256"]:
            one.result, one.why = "damaged", "its text is not the one written (sha256)"
        if one.result != "damaged" and not f["loaded_at"]:
            one.result, one.why = "damaged", "its rows were never loaded"
        if one.result != "damaged" and f["kind"] == "trades":
            conn = store._ticks(f["feed"] or header.get("feed") or row["feed"])
            if conn is None:
                one.result, one.why, one.rows, one.missing = "mismatch", "its feed has no tick file", len(rows), len(rows)
            else:
                mine = later.get(f["seq"])
                held = [r for r in rows if (r[0], r[1], r[2]) not in mine] if mine else rows
                got = compare_trades(conn, held, repair=with_.repair, late=bool(f["late"]))
                got.seq = f["seq"]
                one = got
                if one.repaired:
                    store._wrote()
        elif one.result != "damaged":
            conn = store._bars(f["feed"] or header.get("feed") or row["feed"])
            if conn is None:
                one.result, one.why, one.rows, one.missing = "mismatch", "its feed has no file", len(rows), len(rows)
            else:
                got = compare(conn, rows, stored_at=f["stored_at"], repair=with_.repair, late=bool(f["late"]))
                got.seq = f["seq"]
                one = got
                if one.repaired:
                    store._wrote()
        out.files.append(one)
        store.pull_file_audited(row["id"], f["seq"], one.result, one.missing, one.differing)
    bad = [f for f in out.files if f.result in ("mismatch", "damaged")]
    out.result = "mismatch" if bad or out.damaged_payloads else "repaired" if any(f.repaired for f in out.files) else "ok"
    _find(store, row, out)
    store.pull_audited(row["id"], out.result, "" if out.result == "ok" else out.words()[:400])
    if out.result != "mismatch":
        store.cache_verified(pulls=1, files=sum(1 for f in files if not f["removed_at"]), rows=out.rows,
                             size=sum(int(f["bytes"] or 0) for f in files if not f["removed_at"]),
                             repaired=sum(f.repaired for f in out.files))
        if with_.keep_days <= 0:
            out.removed = _remove(store, row, files, folder)
            _forget(store, row)
    if log is not None and (out.result != "ok" or out.loaded_late):
        log(out.words() + (f"; {out.loaded_late} cache files were loaded late" if out.loaded_late else ""))
    return out


def _forget(store, row: dict) -> bool:
    """A pull whose audit passed and of which no file is left, forgotten: the ledger holds what is on disk and what
    is still to be judged, and the pull was counted when it passed. One that was cut off stays: the sweep says when
    the span it asked is held (Sweep._cut_pulls), and it is forgotten then, or FORGET_DAYS after its audit."""
    if row["state"] != "complete" or any(not f["removed_at"] for f in store.pull_files(row["id"])):
        return False
    return bool(store.pull_drop(row["id"]))


def _find(store, row: dict, out: PullAudit) -> None:
    """A pull's audit kept as findings: one for what was missing (repaired or not), one for what differs, one for a
    cache file that is not what was written."""
    span = (row.get("start_ms"), row.get("end_ms"))
    missing, differing = out.missing, out.differing
    repaired = sum(f.repaired for f in out.files)
    shown = [s for f in out.files for s in f.shown]
    if missing:
        store.finding_put("copy-missing", row["feed"], row["ticker"], row["timespan"], *span, pull=row["id"],
                          count=missing, state="repaired" if repaired >= missing else "open",
                          detail={"repaired": repaired, "first": [s for s in shown if s["stored"] is None][:SHOWN]})
    if differing:
        store.finding_put("copy-differs", row["feed"], row["ticker"], row["timespan"], *span, pull=row["id"],
                          count=differing, detail={"first": [s for s in shown if s["stored"] is not None][:SHOWN]})
    damaged = [f for f in out.files if f.result == "damaged"]
    if damaged or out.damaged_payloads:
        store.finding_put("cache-file", row["feed"], row["ticker"], row["timespan"], *span, pull=row["id"],
                          count=len(damaged) + out.damaged_payloads,
                          detail={"rows files": [{"seq": f.seq, "why": f.why} for f in damaged][:SHOWN],
                                  "payloads": out.damaged_payloads})


def audit_pulls(store, feed: str | None = None, ticker: str | None = None, policy_: Policy | None = None,
                log: Log | None = None, budget_s: float | None = None) -> list[PullAudit]:
    """Every closed pull not audited yet (of a feed, of a symbol), the oldest first, for at most `budget_s`. A pull
    whose audit raises (a feed's file that cannot be read, rows that will not be taken) is said and left for a
    later pass, and the ones after it are audited all the same, however many fail: no pull holds up the rest,
    which would fill the cache to its cap behind it. A database that is busy fails them all, each after its wait:
    that ends the pass. The first FAILURES are said one by one, the rest counted."""
    began = time.monotonic()
    out: list[PullAudit] = []
    if read_only() or pulls.cache_dir(store) is None or not hasattr(store, "pulls"):
        return out  # (a store in memory, or a stand-in for one, keeps no pulls)
    waiting = [p for p in reversed(store.pulls(feed=feed, ticker=ticker, audited=False, limit=5000)) if p["state"] != "open"]
    failed = 0
    for row in waiting:
        if budget_s is not None and time.monotonic() - began >= budget_s:
            break
        try:
            got = audit_pull(store, row, policy_, log)
        except (sqlite3.Error, OSError, ValueError, TypeError) as e:
            failed += 1
            if log is not None and failed <= FAILURES:
                who = f"{row['feed']}:{row['ticker']}" if row["ticker"] else row["feed"]
                log(f"audit {who}: a pull's audit is left for later ({type(e).__name__}: {e})"[:300])
            if _busy(e):
                break  # not this pull's trouble: the next would wait as long, and fail the same
            continue
        if got is not None:
            out.append(got)
    if log is not None and failed > FAILURES:
        log(f"audit: {failed - FAILURES} more pulls' audits are left for later")
    return out


def _busy(e: BaseException) -> bool:
    """Whether an error is the database being busy (locked past its wait), not one pull's own trouble."""
    return busy(e)


def recover(store, feed: str | None = None, log: Log | None = None) -> int:
    """The pulls left open by a run that is gone (a crash, a machine switched off): each rows file in its folder is
    entered in the ledger if it is not, its rows loaded if they were not (without asking the feed again: `_load`),
    and the pull closed as cut. One whose process is still at work is left to it, and so is every pull open in this
    process, on whatever thread (pulls.live): only what an earlier pass of this process left is its own to close.
    A feed whose cache another process is on is left to that process. Returns the pulls closed."""
    from . import claims

    if read_only() or pulls.cache_dir(store) is None or not hasattr(store, "pulls"):
        return 0
    held = store.pulls(feed=feed, state="open", limit=5000)
    if not held:
        return 0
    live = pulls.live()
    gone = claims.gone(store.conn, {(p["instance"], p["pid"]) for p in held}, own_files=own_files(store.path))
    closed = 0
    holds: dict[str, object] = {}
    try:
        for row in held:
            if (row["instance"], row["pid"]) not in gone or row["id"] in live:
                continue
            if row["feed"] not in holds:
                holds[row["feed"]] = _hold(store, row["feed"])
            if holds[row["feed"]] is False:
                continue
            row = store.pull(row["id"])  # as it stands now
            if row is None or row["state"] != "open":
                continue
            closed += _recover(store, row, log)
    finally:
        for one in holds.values():
            _let_go(store, one)
    return closed


def _recover(store, row: dict, log: Log | None) -> int:
    """recover's work on one pull, its feed's cache held. Returns 1."""
    folder = store.pull_folder(row)
    entered = store.pull_files(row["id"])
    known = {f["name"] for f in entered}
    last = max([f["seq"] for f in entered] or [0])
    for path in sorted(folder.glob("*" + spool.ROWS_SUFFIX)) if folder.is_dir() else ():
        if path.name in known:
            continue
        try:
            header, rows, digest = spool.read_rows(path)
        except (OSError, EOFError, ValueError):
            continue
        if not rows:
            continue
        number = int(header.get("seq") or 0)  # (a rows file says which of its pull's files it is)
        if not number:
            last += 1
            number = last
        times = pulls.row_times(header.get("table") or "bars", rows)  # (a trades file's: its trades' times)
        store.pull_file_known(row["id"], number, spool.Written(path.name, path.stat().st_size, digest, len(rows)),
                              header, (min(times), max(times)))
    loaded = _load(store, row, store.pull_files(row["id"]), folder)
    since = f"; {loaded} cache files loaded since" if loaded else ""
    store.pull_cut(row["id"], "its run ended without closing it" + since)
    if log is not None:
        who = f"{row['feed']}:{row['ticker']}" if row["ticker"] else row["feed"]
        log(f"cache {who}: a pull left open by a run that is gone was closed" + (
            f", {loaded} of its cache files loaded without asking the feed again" if loaded else ""))
    return 1


def room(store, policy_: Policy | None = None, log: Log | None = None) -> None:
    """Before a new pull: the unverified cache is under its cap. At the cap, what waits is audited at once; still at
    the cap after that (pulls open elsewhere, or findings that are not files' to settle): CacheFull. A process that
    caches nothing (LIMINAL_FETCH_CACHE=off, a copy that reads only, a store in memory) keeps no cap: what an
    earlier run left on disk never stops its fetching."""
    with_ = policy_ or policy()
    if not cache_on() or pulls.cache_dir(store) is None or not _over(store, with_):
        return
    try:
        audit_pulls(store, policy_=with_, log=log)
    except (sqlite3.Error, OSError):
        pass  # (what could not be audited just now is counted below all the same)
    why = _over(store, with_)
    if why:
        raise CacheFull(why)


def _over(store, with_: Policy) -> str:
    """Why nothing more may be asked into the cache: its unverified bytes are at the cap. "" while there is room,
    and when the ledger cannot be read just now (a read that fails never stops a fetch)."""
    counted = getattr(store, "cache_bytes", None)
    if not callable(counted):
        return ""
    try:
        held = counted()
    except sqlite3.Error:
        return ""
    if held < with_.cap_gb * 2**30:
        return ""
    return (f"the fetch cache holds {held / 2**30:.1f} GB not audited yet (its cap: {with_.cap_gb} GB): "
            "fetching waits for the auditors")


@contextmanager
def pull(store, feed: str, kind: str, log: Log | None = None, **facts) -> Iterator[pulls.Pull]:
    """A pull open for the block (storage/pulls.py: pulling), audited as it closes when the policy says so (`Audit
    when a symbol is updated`). An audit that cannot run then (a database busy) is left to the next one. The cap is
    looked at before it opens and again as it grows (Pull.room): at the cap it ends there, cut, and what it loaded
    is audited like any pull's."""
    with_ = policy()
    room(store, with_, log)
    one = None
    try:
        with pulls.pulling(store, feed, kind, **facts) as one:
            if getattr(one, "spools", False):
                one.limit = lambda: _over(store, with_)
            yield one
    finally:
        if one is not None and one.made and with_.on_update:
            try:
                audit_pull(store, one.id, with_, log)
            except (sqlite3.Error, OSError) as e:
                if log is not None:
                    log(f"cache {feed}: a pull's audit is left for later ({type(e).__name__}: {e})")


def held_open(store, feed: str, kind: str, log: Log | None = None, **facts) -> pulls.Pull | None:
    """A pull its caller holds open across many calls (1.82.0: the live recorder's minute of a stream's trades,
    written flush by flush): entered for each write with spool.opened, ended with `end`. The cap is looked at
    before it opens (spool.CacheFull at it) and as it grows, as for `pull`. None where nothing is cached
    (LIMINAL_FETCH_CACHE=off, a process that reads only, a store in memory or a stand-in for one): the caller
    writes as before."""
    if not cache_on() or pulls.cache_dir(store) is None or not callable(getattr(store, "pull_open", None)):
        return None
    with_ = policy()
    room(store, with_, log)
    one = store.pull_open(feed, kind, **facts)
    if one.spools:
        one.limit = lambda: _over(store, with_)
    return one


def end(store, one: pulls.Pull, state: str = "complete", note: str = "", log: Log | None = None) -> PullAudit | None:
    """A pull held open (held_open) ended, and audited as it closes when the policy says so, as `pull` does. An
    audit that cannot run then (a database busy) is left to the next pass."""
    pulls._close(one, state, note)
    with_ = policy()
    if not one.made or not with_.on_update:
        return None
    try:
        return audit_pull(store, one.id, with_, log)
    except (sqlite3.Error, OSError, ValueError, TypeError) as e:  # (as audit_pulls: the pull waits, nothing stops)
        if log is not None:
            log(f"cache {one.feed}: a pull's audit is left for later ({type(e).__name__}: {e})")
        return None


def tidy(store, policy_: Policy | None = None, now: datetime | None = None) -> dict:
    """The cache kept in order: the files of verified pulls whose keeping time is over removed (and those a
    removal could not take the first time), the pulls then forgotten, and the ones kept for the sweep forgotten
    FORGET_DAYS after their audit. At most TIDY_PULLS pulls a call, the oldest first. Returns {"removed",
    "forgotten"}."""
    with_ = policy_ or policy()
    at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    removed = forgotten = 0
    for row in store.pulls_kept_before(at - timedelta(days=with_.keep_days), TIDY_PULLS):
        files = [f for f in store.pull_files(row["id"]) if not f["removed_at"]]
        removed += _remove(store, row, files, store.pull_folder(row))
        forgotten += _forget(store, row)
    return {"removed": removed, "forgotten": forgotten + store.pulls_forget(at - timedelta(days=FORGET_DAYS))}


# -- the sweep -----------------------------------------------------------------------------------------------------------
CURSOR_KEY = "audit:sweep:cursor"  # where the round stands: the series gone over last ("feed\tTICKER")
ROUND_KEY = "audit:sweep:round"  # how many times every series has been gone over
LAST_KEY = "audit:sweep:last"  # the last run, as JSON, for the auditor's page
DAY_MS = 86_400_000
SETTLE_MS = 3 * DAY_MS  # a day this recent is not judged: its bars may still be on their way
MONTH_MS = 31 * DAY_MS
MONTH_ROWS = 60_000  # a month is read whole for its rules only below this many bars (a month of seconds is not)
BASES = ("second", "minute", "day")  # the frames a feed sends; the others are built here
STORAGE_RULES = ("duplicate", "malformed", "missing", "out_of_session")  # of data.py's rules, those kept as findings
HOLE_KINDS = ("hole", "empty-span")
# What 1.64.0 took for an empty span's evidence. It is none: the ledger holds the time before a ticker existed, and
# rightly nothing is there (1.64.1; the first sweep of the user's data found 56 such spans and nothing else).
LEDGER_ONLY = "the ledger says it is held"


@dataclass
class Visit:
    """One series gone over by the sweep."""

    feed: str
    ticker: str
    pulls: int = 0  # of its pulls, audited now
    days: int = 0  # session days looked at
    holes: int = 0  # holes found now (with evidence that bars should be there)
    absent: int = 0  # holes the feed was asked for again and has nothing for: remembered, not asked again
    closed: int = 0  # findings that are no longer so
    rules: int = 0  # bars a storage rule caught in the month read
    skipped: str = ""


class Sweep:
    """Every watched series of every feed in turn, a time budget a run, each under its symbol's claim (the user:
    "make sure that auditing goes over all symbols to look for consistency issues or broken connections that
    fragmented data").

    A series' visit: its pulls not audited yet are audited; a pull that was cut off is kept as a finding until the
    span it asked is held; for each frame the feed sends (second, minute, day), every session day inside a span the
    coverage ledger says the feed holds is looked for in its bars, and the month the round has come to is read whole
    and put to data.py's rules (assess, integrity).

    A day without a single bar is a **hole** only with evidence that bars should be there that very day (1.77.0: a
    run of missing days is never judged by evidence elsewhere in it): the feed's own daily bar of that day shows it
    traded (or its own finer bars do, for a missing daily bar), another feed of the same market
    holds bars that day, the feed's ticks do, or a pull that was cut off covers it. A thin stock's quiet days and a
    market's closed hours are no holes. A span said to be held that holds no bar at all is an **empty span**, and a
    finding by the same rule: only with evidence that bars should be there. The ledger's word is no such evidence:
    it holds the time before a company took its ticker too, and nothing is there to be had (1.64.1). Both are
    asked of the feed again by its next run, a few a run (the collector's re-pulls: `repulls`); one asked again
    and still empty is **absent**, remembered and not asked a third time. Nothing is ever deleted or overwritten
    here, and coverage is never withdrawn."""

    def __init__(self, store, feeds: Mapping | None = None, policy_: Policy | None = None, log: Log | None = None,
                 now_ms: int | None = None, data_for: Callable | None = None, clock: Callable[[], float] = time.monotonic):
        self.store, self.feeds, self.policy = store, dict(feeds or {}), policy_ or policy()
        self.log = log or (lambda _line: None)
        self.now_ms = int(time.time() * 1000) if now_ms is None else int(now_ms)
        self._data_for = data_for or _data_for
        self.clock = clock

    # -- a run ---------------------------------------------------------------------------------------------------
    def run(self, budget_s: float | None = None, only: set | None = None) -> dict:
        """One run: what waits in the cache first, then the series in turn from where the last run stopped, for
        `budget_s` (the policy's minutes). `only`: these (feed, ticker) alone, out of turn (an audit asked for a
        symbol). Returns the run in numbers, kept for the page too (LAST_KEY)."""
        import json

        store, began = self.store, self.clock()
        budget = self.policy.sweep_minutes * 60.0 if budget_s is None else float(budget_s)
        out = {"at": datetime.fromtimestamp(self.now_ms / 1000, timezone.utc).isoformat(timespec="seconds"),
               "series": 0, "pulls": 0, "days": 0, "holes": 0, "absent": 0, "closed": 0, "rules": 0, "skipped": 0,
               "complete": False, "only": sorted(f"{f}:{t}" for f, t in only) if only else None}
        if read_only():
            out["note"] = "this copy reads only: nothing is audited from here"
            return out
        recover(store, None, self.log)
        out["pulls"] += len(audit_pulls(store, policy_=self.policy, log=self.log, budget_s=budget / 4))
        out["closed"] += self._ledger_only()
        rows = [r for r in store.watchlist() if only is None or (r["source"], r["ticker"]) in only]
        last = (rows[-1]["source"], rows[-1]["ticker"]) if rows else None  # the end of the line, in its order
        if only is None and rows:
            cursor = tuple((store.kv_get(CURSOR_KEY) or "\t").split("\t", 1))
            start = next((i for i, r in enumerate(rows) if (r["source"], r["ticker"]) > cursor), 0)
            rows = rows[start:] + rows[:start]
        done = 0
        for row in rows:
            if self.clock() - began >= budget:
                break
            visit = self.series(row)
            done += 1
            for name in ("pulls", "days", "holes", "absent", "closed", "rules"):
                out[name] += getattr(visit, name)
            out["skipped"] += 1 if visit.skipped else 0
            if only is None:
                store.kv_set(CURSOR_KEY, f"{row['source']}\t{row['ticker']}")
                if (row["source"], row["ticker"]) == last:  # every series has had its turn: the round is whole,
                    store.kv_set(ROUND_KEY, str(self.round() + 1))  # however many runs it took
        out["series"] = done
        out["complete"] = done == len(rows)  # this run went over everything it was to
        kept = tidy(store, self.policy, datetime.fromtimestamp(self.now_ms / 1000, timezone.utc))
        out.update(seconds=round(self.clock() - began, 1), round=self.round(), removed=kept["removed"],
                   forgotten=kept["forgotten"], watched=len(rows) if only is None else None)
        if only is None:
            store.kv_set(LAST_KEY, json.dumps(out))
        return out

    def round(self) -> int:
        try:
            return int(self.store.kv_get(ROUND_KEY) or 0)
        except ValueError:
            return 0

    def _ledger_only(self) -> int:
        """The empty spans 1.64.0 kept as findings on the ledger's word alone, judged again by the rule every hole
        is held to. One that something says should hold bars stays, now saying what; one nothing speaks for is
        closed: nothing was missing there (the time before a ticker existed). Returns those closed. Once done there
        are none left to judge: no finding is made on that word any more."""
        store, closed = self.store, 0
        for f in store.findings(kind="empty-span", limit=5000):
            if f["state"] not in ("open", "asked") or (f.get("detail") or {}).get("evidence") != LEDGER_ONLY:
                continue
            why = ""
            try:
                watched = store.watchlist(f["feed"], f["ticker"])
                conn = store._bars(f["feed"])
                if watched and conn is not None and f["timespan"] and f["start_ms"] is not None:
                    cut = [p for p in store.pulls(feed=f["feed"], ticker=f["ticker"], state="cut", limit=500)
                           if p["start_ms"] is not None and p["end_ms"] is not None and p["timespan"]]
                    why = self._evidence(conn, watched[0], f["timespan"], f["start_ms"], f["end_ms"], cut)
            except (sqlite3.Error, OSError, ValueError) as e:
                self.log(f"audit {f['feed']}:{f['ticker']}: an empty span is judged again next run ({type(e).__name__}: {e})"[:300])
                continue
            if why:
                store.finding_set(f["id"], f["state"], detail={**f["detail"], "evidence": why})
            else:
                store.finding_set(f["id"], "closed", detail={**f["detail"], "evidence": "",
                                                             "settled": "nothing says bars should be there"})
                closed += 1
        if closed:
            self.log(f"audit: {closed} empty spans kept on the ledger's word alone are closed: nothing says bars should "
                     "be there (the time before a ticker existed)")
        return closed

    # -- a series ------------------------------------------------------------------------------------------------
    def series(self, row: dict) -> Visit:
        """One series gone over, its symbol claimed meanwhile (held by another installation: left for the next run)."""
        from . import collector

        store, feed, ticker, asset = self.store, row["source"], row["ticker"], row.get("asset") or "stock"
        visit = Visit(feed, ticker)
        claim = collector.take_symbol(store, asset, ticker, "the auditors")
        if claim is collector.ELSEWHERE:
            visit.skipped = "another installation is working on it"
            return visit
        try:
            visit.pulls = len(audit_pulls(store, feed=feed, ticker=ticker, policy_=self.policy, log=self.log))
            cut = self._cut_pulls(feed, ticker, visit)
            data = self._data_for(feed, asset)
            conn = store._bars(feed)
            if data is None or conn is None or asset == "future":  # (a future's days are its contracts': not judged here)
                return visit
            exchange = row.get("exchange") if asset == "stock" else None
            for timespan in BASES:
                spans = store.coverage(ticker, timespan, source=feed, received_only=True).get(feed, [])
                if not spans:
                    continue
                self._days(conn, row, timespan, spans, data, exchange, cut, visit)
                self._month(conn, row, timespan, spans, data, exchange, visit)
        except (sqlite3.Error, OSError, ValueError) as e:  # this series' own trouble: said, and the round goes on
            visit.skipped = f"{type(e).__name__}: {e}"[:200]
            self.log(f"audit {feed}:{ticker}: left for the next round ({visit.skipped})")
        finally:
            collector.give_symbol(store, claim)
        return visit

    def _cut_pulls(self, feed: str, ticker: str, visit: Visit) -> list[dict]:
        """The series' pulls that were cut off: each a finding while the span it asked is not held (by bars, or by
        the feed having nothing there). Returns those still so: evidence for a hole. A finding whose pull the
        ledger has forgotten since (FORGET_DAYS after its audit) is judged by the span kept with the finding
        itself, so it is closed when that span is held and does not stay open for good."""
        store, still = self.store, []
        cut = store.pulls(feed=feed, ticker=ticker, state="cut", limit=500)
        known = {p["id"] for p in cut}
        for f in store.findings(feed=feed, ticker=ticker, kind="cut-pull"):
            if f["state"] == "closed" or f["pull"] in known or f["start_ms"] is None or f["end_ms"] is None or not f["timespan"]:
                continue
            held = _joined(store.coverage(ticker, f["timespan"], source=feed, include_none=True).get(feed, []))
            if any(a <= f["start_ms"] and b >= f["end_ms"] for a, b in held):
                store.finding_set(f["id"], "closed")
                visit.closed += 1
            else:
                still.append({"id": f["pull"], "timespan": f["timespan"], "start_ms": f["start_ms"], "end_ms": f["end_ms"]})
        for p in cut:
            if p["start_ms"] is None or p["end_ms"] is None or not p["timespan"]:
                continue
            # what it holds and what it was asked and has nothing for, joined: the spans of each kind are kept apart
            held = _joined(store.coverage(ticker, p["timespan"], source=feed, include_none=True).get(feed, []))
            whole = any(a <= p["start_ms"] and b >= p["end_ms"] for a, b in held)
            was = [f for f in store.findings(feed=feed, ticker=ticker, kind="cut-pull") if f["pull"] == p["id"]]
            if whole:
                for f in was:
                    if f["state"] != "closed":
                        store.finding_set(f["id"], "closed")
                        visit.closed += 1
                # what it asked is held: there is nothing more to judge it by, and once its audit has passed and its
                # files are gone it is forgotten (it was counted when it passed)
                if p["audit"] in ("ok", "repaired") and not any(not f["removed_at"] for f in store.pull_files(p["id"])):
                    store.pull_drop(p["id"])
            else:
                still.append(p)
                if not was:
                    store.finding_put("cut-pull", feed, ticker, p["timespan"], p["start_ms"], p["end_ms"], pull=p["id"],
                                      detail={"why": p["note"], "kind": p["kind"]})
        return still

    @staticmethod
    def _has_bar(conn, ticker: str, timespan: str, lo: int, hi: int, traded: bool = False) -> bool:
        sql = "SELECT 1 FROM bars WHERE ticker=? AND timespan=? AND multiplier=1 AND ts >= ? AND ts < ?"
        return conn.execute(sql + (" AND volume > 0" if traded else "") + " LIMIT 1",
                            (ticker, timespan, int(lo), int(hi))).fetchone() is not None

    def _evidence(self, conn, row: dict, timespan: str, lo: int, hi: int, cut: list[dict]) -> str:
        """Why bars should be in [lo, hi) of the series, in a few words; "" when nothing says so."""
        feed, ticker, asset = row["source"], row["ticker"], row.get("asset") or "stock"
        if timespan == "day":
            if any(self._has_bar(conn, ticker, finer, lo, hi) for finer in ("minute", "second")):
                return "its own finer bars are there"
        elif self._has_bar(conn, ticker, "day", lo, hi, traded=True):
            return "its own daily bar shows it traded"
        if any(p["timespan"] == timespan and p["start_ms"] < hi and p["end_ms"] > lo for p in cut):
            return "a pull that was cut off"
        from .coverage import same_market

        for other in self.feeds:
            if other != feed and same_market(self.feeds, other, feed, asset):
                theirs = self.store._bars(other)
                if theirs is not None and theirs.execute(
                        "SELECT 1 FROM bars WHERE ticker=? AND ts >= ? AND ts < ? LIMIT 1", (ticker, lo, hi)).fetchone():
                    return f"{other} holds bars there"
        held = self.store._feed(feed)
        if held is not None and held.has_ticks() and conn.execute(
                "SELECT 1 FROM ticks.trades WHERE ticker=? AND ts_ns >= ? AND ts_ns < ? LIMIT 1",
                (ticker, lo * 1_000_000, hi * 1_000_000)).fetchone():
            return "its own ticks are there"
        return ""

    @staticmethod
    def _runs(missing: list[int], days: list[int]) -> list[list[int]]:
        """The missing days in runs of session days next to each other (`days`: every session day, in order)."""
        place = {d: i for i, d in enumerate(days)}
        out: list[list[int]] = []
        for d in missing:
            if out and place[d] == place[out[-1][-1]] + 1:
                out[-1].append(d)
            else:
                out.append([d])
        return out

    def _witnessed(self, conn, row: dict, timespan: str, days: list[int], cut: list[dict]) -> list[tuple[list[int], str]]:
        """Of a run of session days next to each other that hold no bar, the runs of those days that each have a
        witness of their own, with what witnesses them: [(days, why)]. A day is judged by that very day's evidence,
        never by evidence somewhere else in the run (1.77.0: one bar of another feed anywhere in 5,612 missing days
        had made all of them one finding). The run as a whole is asked first: with nothing anywhere in it, no day of
        it can have a witness, and the days are not asked one by one."""
        if not days:
            return []
        whole = self._evidence(conn, row, timespan, days[0], days[-1] + DAY_MS, cut)
        if not whole:
            return []
        if len(days) == 1:
            return [(days, whole)]
        out: list[tuple[list[int], str]] = []
        run: list[int] = []
        whys: list[str] = []
        for d in [*days, None]:
            why = self._evidence(conn, row, timespan, d, d + DAY_MS, cut) if d is not None else ""
            if why:
                run.append(d)
                if why not in whys:
                    whys.append(why)
            elif run:
                out.append((run, "; ".join(whys)))
                run, whys = [], []
        return out

    def _days(self, conn, row: dict, timespan: str, spans: list, data, exchange, cut: list[dict], visit: Visit) -> None:
        """Every session day inside the spans the feed is said to hold, looked for in its bars; the holes and the
        empty spans kept as findings, and the findings of before brought up to date. A missing day is a hole only if
        that same day has a witness (`_witnessed`); a span is an empty span only if every day of it has one."""
        store, feed, ticker = self.store, row["source"], row["ticker"]
        horizon = self.now_ms - SETTLE_MS
        runs: list[tuple[list[int], str]] = []  # (the days, kind)
        for a, b in spans:
            b = min(b, horizon)
            days = [int(d) for d in data.slots("day", a, b, exchange=exchange) if a <= d and d + DAY_MS <= b]
            if not days:
                continue
            visit.days += len(days)
            missing = [d for d in days if not self._has_bar(conn, ticker, timespan, d, d + DAY_MS)]
            if len(missing) == len(days):
                runs.append((days, "empty-span"))
            else:
                runs.extend((run, "hole") for run in self._runs(missing, days))
        known: list[dict] = []
        for f in [f for kind in HOLE_KINDS for f in store.findings(feed=feed, ticker=ticker, kind=kind)
                  if f["timespan"] == timespan and f["state"] != "closed"]:
            known.extend(self._judged_again(conn, row, timespan, f, data, exchange, cut, visit))
        for f in known:  # asked again and still empty
            if f["state"] == "asked":
                store.finding_set(f["id"], "absent")
                visit.absent += 1
        for days, kind in runs:
            lo, hi = days[0], days[-1] + DAY_MS
            if any(f["start_ms"] < hi and f["end_ms"] > lo for f in known):
                continue  # known already: open, asked or absent
            for some, why in self._witnessed(conn, row, timespan, days, cut):
                # (nothing witnessing a day: a quiet day, the time before a ticker existed)
                n = len(some)
                store.finding_put(kind if some == days else "hole", feed, ticker, timespan, some[0], some[-1] + DAY_MS,
                                  count=n, detail={"days": n, "evidence": why})
                visit.holes += 1

    def _judged_again(self, conn, row: dict, timespan: str, f: dict, data, exchange, cut: list[dict],
                      visit: Visit) -> list[dict]:
        """A finding of before, judged by today's rule on the days of it still without a bar: filled since, it is
        closed; still so, it stays; wider than the days that have a witness (a finding kept before 1.77.0, judged as
        a whole run), it is closed and the runs that do have one are kept in its place, in its state. Returns what
        stands for it now (each as the store keeps a finding)."""
        store, feed, ticker = self.store, row["source"], row["ticker"]
        days = [int(d) for d in data.slots("day", f["start_ms"], f["end_ms"], exchange=exchange)]
        empty = [d for d in days if not self._has_bar(conn, ticker, timespan, d, d + DAY_MS)]
        if not empty:
            store.finding_set(f["id"], "closed")
            visit.closed += 1
            return []
        found = [w for run in self._runs(empty, days) for w in self._witnessed(conn, row, timespan, run, cut)]
        if len(found) == 1 and found[0][0][0] == f["start_ms"] and found[0][0][-1] + DAY_MS == f["end_ms"]:
            return [f]
        had = (f.get("detail") or {}).get("days") or len(days)
        witnessed = sum(len(some) for some, _ in found)
        store.finding_set(f["id"], "closed", detail={**(f.get("detail") or {}), "settled": (
            f"judged day by day: {witnessed:,} of its {had:,} days have a witness of their own" if found
            else "judged day by day: no day of it has a witness of its own")})
        visit.closed += 1
        out = []
        for some, why in found:
            n = len(some)
            kind = "empty-span" if f["kind"] == "empty-span" and n == len(days) else "hole"
            new = store.finding_put(kind, feed, ticker, timespan, some[0], some[-1] + DAY_MS, pull=f.get("pull"),
                                    count=n, state=f["state"], detail={"days": n, "evidence": why, "from": f["id"]})
            out.append({**f, "id": new, "kind": kind, "start_ms": some[0], "end_ms": some[-1] + DAY_MS, "count": n})
        return out

    def _month(self, conn, row: dict, timespan: str, spans: list, data, exchange, visit: Visit) -> None:
        """The month the round has come to, of this series, read whole and put to data.py's rules. The newest month
        on the first round, one further back each round after. What a storage rule catches (STORAGE_RULES) is kept
        as a finding; a month that comes back clean closes the one kept for it before."""
        store, feed, ticker = self.store, row["source"], row["ticker"]
        newest = min(max(b for _, b in spans), self.now_ms - SETTLE_MS)
        oldest = min(a for a, _ in spans)
        months = max(1, int((newest - oldest) // MONTH_MS) + 1)
        hi = newest - (self.round() % months) * MONTH_MS
        lo = max(oldest, hi - MONTH_MS)
        if hi <= lo:
            return
        n = conn.execute("SELECT COUNT(*) FROM bars WHERE ticker=? AND timespan=? AND multiplier=1 AND ts >= ? AND ts < ?",
                         (ticker, timespan, lo, hi)).fetchone()[0]
        if not n or n > MONTH_ROWS:
            return
        import pandas as pd

        frame = pd.DataFrame(store.bar_rows(feed, ticker, timespan, lo, hi),
                             columns=["ts", "open", "high", "low", "close", "volume", "vwap", "transactions"])
        found = data.integrity(frame, timespan=timespan, exchange=exchange)
        caught = {rule: count for rule, count in found.by_rule().items() if rule in STORAGE_RULES}
        was = [f for f in store.findings(feed=feed, ticker=ticker, kind="integrity")
               if f["timespan"] == timespan and f["start_ms"] == lo and f["end_ms"] == hi]
        if caught:
            state = data.assess(frame, lo, hi, timespan=timespan, exchange=exchange)
            store.finding_put("integrity", feed, ticker, timespan, lo, hi, count=sum(caught.values()), detail={
                "rules": caught, "first": [f.as_dict() for f in found.findings if f.rule in STORAGE_RULES][:SHOWN],
                "completeness": state.completeness, "rows": int(n)})
            visit.rules += sum(caught.values())
        else:
            for f in was:
                if f["state"] != "closed":
                    store.finding_set(f["id"], "closed")
                    visit.closed += 1


def _joined(spans) -> list[tuple[int, int]]:
    """Spans [start, end) joined where they touch or overlap, in order."""
    out: list[list[int]] = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


def _data_for(feed: str, asset: str):
    """A feed's data class for an asset class (its plugin's own, else the contract's for the class); None for a
    class the library has none for."""
    from .sources.data import default_series
    from .sources.registry import providers

    plugin = providers().get(feed)
    try:
        if plugin is not None:
            return plugin.data_for(asset)
        cls = default_series(asset)
        return cls(feed=feed) if cls is not None else None
    except ValueError:
        return None


def repulls(store, feed: str, ticker: str, limit: int) -> list[dict]:
    """What a feed's run is to ask it again for a symbol, the oldest finding first, at most `limit` spans: each
    {"finding", "timespan", "start_ms", "end_ms"}. A hole or an empty span as it was found; a bar stored with other
    values than its cache file's, by the bars kept with the finding. (The collector asks, stores what comes as any
    answer is stored, and marks the findings asked: mark_asked.) An empty span 1.64.0 kept on the ledger's word
    alone is not asked: a feed is asked again only with evidence, and the next sweep judges it by that."""
    out: list[dict] = []
    if limit <= 0 or not hasattr(store, "findings"):
        return out
    for f in reversed(store.findings(state="open", feed=feed, ticker=ticker, limit=200)):
        if len(out) >= limit:
            break
        if (f.get("detail") or {}).get("evidence") == LEDGER_ONLY:
            continue
        if f["kind"] in HOLE_KINDS and f["timespan"] and f["start_ms"] is not None:
            out.append({"finding": f["id"], "timespan": f["timespan"], "start_ms": f["start_ms"], "end_ms": f["end_ms"]})
        elif f["kind"] == "copy-differs" and f["timespan"] in _STEP:
            for bar in ((f.get("detail") or {}).get("first") or [])[:max(0, limit - len(out))]:
                out.append({"finding": f["id"], "timespan": f["timespan"], "start_ms": int(bar["ts"]),
                            "end_ms": int(bar["ts"]) + _STEP[f["timespan"]]})
    return out


def mark_asked(store, finding_ids) -> None:
    """Findings whose spans a feed was asked for again: `asked` (the next sweep says what became of them)."""
    for finding_id in dict.fromkeys(finding_ids):
        store.finding_set(finding_id, "asked")


def overview(store, policy_: Policy | None = None, findings: int = 100) -> dict:
    """The auditors for their page: the policy, the cache by state and size (what is on disk and what is still to
    be judged), the pulls verified so far (counted, not kept), the last sweep, where the round stands, and the
    latest findings."""
    import json

    with_ = policy_ or policy()
    try:
        last = json.loads(store.kv_get(LAST_KEY) or "null")
    except ValueError:
        last = None
    cursor = (store.kv_get(CURSOR_KEY) or "").replace("\t", ":")
    counts = store.finding_counts()
    return {"policy": with_.as_dict(),
            "cache": {"folder": str(pulls.cache_dir(store) or ""), "on": pulls.enabled(), "states": store.cache_summary(),
                      "unverifiedBytes": store.cache_bytes(), "keptBytes": store.cache_bytes(unverified_only=False),
                      "capBytes": with_.cap_gb * 2**30, "verified": store.cache_verified()},
            "sweep": {"last": last, "cursor": cursor, "round": Sweep(store, policy_=with_).round()},
            "findings": {"counts": counts, "open": counts.get("open", 0), "latest": store.findings(limit=findings)}}
