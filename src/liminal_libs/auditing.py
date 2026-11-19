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
to, which is the same float bit for bit but for a negative zero."""
from __future__ import annotations

import os
import shutil
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterator, Mapping

from . import spool
from .sources.plugin import IntegratorPlugin
from .storage import pulls
from .storage.common import own_files, read_only

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
FORGET_DAYS = 7  # an audited pull whose files are gone stays in the ledger this long, for its page
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


class CacheFull(spool.CacheFailed):
    """The cache holds as much unverified data as its cap allows, and auditing what waits freed too little: fetching
    waits for the auditors."""


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


def compare(conn, rows: list, stored_at: int | None = None, repair: bool = True, now_ms: int | None = None) -> FileAudit:
    """Bar rows (as a rows file holds them: the key, then the values) held against `bars` on `conn`, a feed's own
    connection: what is missing, what differs, what a later write replaced. With `repair`, the missing are put in."""
    out = FileAudit(seq=0, rows=len(rows))
    conn.execute(_TEMP)
    with conn:
        conn.execute("DELETE FROM temp.pull_rows")
        # (a key twice in one file: the later row is the one a write stored, and the one kept here)
        conn.executemany("INSERT OR REPLACE INTO temp.pull_rows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    out.rows = conn.execute("SELECT COUNT(*) FROM temp.pull_rows").fetchone()[0]
    # A bar stored with other values is a later write's when it was stored after this file was (stored_at) and the
    # version the file holds is kept as the one replaced then (bar_revisions). One stored under this file's own
    # moment with other values is nobody's later write: it differs.
    revised = _has(conn, "bar_revisions")
    kept = ("EXISTS (SELECT 1 FROM bar_revisions r WHERE " + _ON.format(o="r") + " AND r.derivation IS NULL AND "
            + _IS.format(o="r") + "{when})")
    if revised and stored_at is not None:
        later = " AND NOT (COALESCE(b.stored_at, 0) > ? AND " + kept.format(when=" AND r.replaced_at >= ?") + ")"
        args: tuple = (int(stored_at), int(stored_at))
    elif revised:
        later, args = " AND NOT " + kept.format(when=""), ()
    else:
        later, args = "", ()
    differs = f"FROM temp.pull_rows t JOIN bars b ON {_ON.format(o='b')} WHERE ({_IS_NOT})"
    out.differing = conn.execute(f"SELECT COUNT(*) {differs}{later}", args).fetchone()[0]
    if revised:
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


def _load(store, pull: dict, files: list[dict], folder) -> int:
    """Rows files written and never loaded (their run ended, or failed, between the file and the database): loaded
    now, as the run would have, and for a series' own pull recorded as held in the coverage ledger from their first
    bar to their last. Returns the files loaded."""
    from .storage.feeds import _UPSERT_BAR

    done = 0
    for f in files:
        if f["kind"] != "rows" or f["loaded_at"] or f["removed_at"]:
            continue
        try:
            header, rows, digest = spool.read_rows(folder / f["name"])
        except (OSError, ValueError):
            continue  # not readable: its audit says so
        if digest != f["sha256"] or not rows:
            continue
        feed = f["feed"] or header.get("feed") or pull["feed"]
        stored = int(f["stored_at"] or header.get("stored_at") or time.time() * 1000)
        conn = store._feed(feed, create=True).conn
        with conn:
            conn.executemany(_UPSERT_BAR, [(*r, stored) for r in rows])
        store.pull_file_loaded(pull["id"], f["seq"])
        store._wrote()
        step = _STEP.get(pull.get("timespan") or "")
        if pull["kind"] in ("bars", "download", "recheck") and pull.get("ticker") and step and f["lo_ms"] is not None:
            store.add_coverage(feed, pull["ticker"], pull["timespan"], int(f["lo_ms"]), int(f["hi_ms"]) + step)
        done += 1
    return done


def _remove(store, pull: dict, files: list[dict], folder) -> int:
    """A pull's files removed from disk (those still there), its folder with them."""
    seqs = [f["seq"] for f in files if not f["removed_at"]]
    for f in files:
        if not f["removed_at"]:
            try:
                os.unlink(folder / f["name"])
            except OSError:
                pass
    shutil.rmtree(folder, ignore_errors=True)
    if seqs:
        store.pull_files_removed(pull["id"], seqs)
    return len(seqs)


def audit_pull(store, pull, policy_: Policy | None = None, log: Log | None = None) -> PullAudit | None:
    """One pull audited (see the module's words): a closed pull not audited yet, by its id or its row. None for one
    that is not there, still open, audited already, or in a process that reads only."""
    with_ = policy_ or policy()
    row = store.pull(pull) if isinstance(pull, str) else pull
    if row is None or row["state"] == "open" or row["audit"] is not None or read_only():
        return None
    folder = store.pull_folder(row)
    if folder is None:
        return None
    out = PullAudit(row["id"], row["feed"], row["ticker"])
    files = store.pull_files(row["id"])
    out.loaded_late = _load(store, row, files, folder)
    if out.loaded_late:
        files = store.pull_files(row["id"])
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
        if one.result != "damaged":
            conn = store._bars(f["feed"] or header.get("feed") or row["feed"])
            if conn is None:
                one.result, one.why, one.rows, one.missing = "mismatch", "its feed has no file", len(rows), len(rows)
            else:
                got = compare(conn, rows, stored_at=f["stored_at"], repair=with_.repair)
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
    if out.result != "mismatch" and with_.keep_days <= 0:
        out.removed = _remove(store, row, files, folder)
    if log is not None and (out.result != "ok" or out.loaded_late):
        log(out.words() + (f"; {out.loaded_late} cache files were loaded late" if out.loaded_late else ""))
    return out


def _find(store, row: dict, out: PullAudit) -> None:
    """A pull's audit kept as findings: one for what was missing (repaired or not), one for what differs, one for a
    cache file that is not what was written."""
    span = (row.get("start_ms"), row.get("end_ms"))
    missing, differing = out.missing, out.differing
    repaired = sum(f.repaired for f in out.files)
    if missing:
        store.finding_put("copy-missing", row["feed"], row["ticker"], row["timespan"], *span, pull=row["id"], count=missing,
                          state="repaired" if repaired >= missing else "open",
                          detail={"repaired": repaired, "first": [s for f in out.files for s in f.shown if s["stored"] is None][:SHOWN]})
    if differing:
        store.finding_put("copy-differs", row["feed"], row["ticker"], row["timespan"], *span, pull=row["id"], count=differing,
                          detail={"first": [s for f in out.files for s in f.shown if s["stored"] is not None][:SHOWN]})
    damaged = [f for f in out.files if f.result == "damaged"]
    if damaged or out.damaged_payloads:
        store.finding_put("cache-file", row["feed"], row["ticker"], row["timespan"], *span, pull=row["id"],
                          count=len(damaged) + out.damaged_payloads,
                          detail={"rows files": [{"seq": f.seq, "why": f.why} for f in damaged][:SHOWN],
                                  "payloads": out.damaged_payloads})


def audit_pulls(store, feed: str | None = None, ticker: str | None = None, policy_: Policy | None = None,
                log: Log | None = None, budget_s: float | None = None) -> list[PullAudit]:
    """Every closed pull not audited yet (of a feed, of a symbol), the oldest first, for at most `budget_s`."""
    began = time.monotonic()
    out: list[PullAudit] = []
    if read_only() or pulls.cache_dir(store) is None or not hasattr(store, "pulls"):
        return out  # (a store in memory, or a stand-in for one, keeps no pulls)
    waiting = [p for p in reversed(store.pulls(feed=feed, ticker=ticker, audited=False, limit=5000)) if p["state"] != "open"]
    for row in waiting:
        if budget_s is not None and time.monotonic() - began >= budget_s:
            break
        got = audit_pull(store, row, policy_, log)
        if got is not None:
            out.append(got)
    return out


def recover(store, feed: str | None = None, log: Log | None = None) -> int:
    """The pulls left open by a run that is gone (a crash, a machine switched off): each rows file in its folder is
    entered in the ledger if it is not, its rows loaded if they were not (without asking the feed again), and the
    pull closed as cut. One whose process is still at work is left to it. Returns the pulls closed."""
    from . import claims

    if read_only() or pulls.cache_dir(store) is None or not hasattr(store, "pulls"):
        return 0
    held = store.pulls(feed=feed, state="open", limit=5000)
    if not held:
        return 0
    mine = spool.current()
    gone = claims.gone(store.conn, {(p["instance"], p["pid"]) for p in held}, own_files=own_files(store.path))
    closed = 0
    for row in held:
        if (row["instance"], row["pid"]) not in gone or (mine is not None and getattr(mine, "id", None) == row["id"]):
            continue
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
            times = [r[3] for r in rows]
            store.pull_file_known(row["id"], number, spool.Written(path.name, path.stat().st_size, digest, len(rows)),
                                  header, (min(times), max(times)))
        loaded = _load(store, row, store.pull_files(row["id"]), folder)
        store.pull_cut(row["id"], "its run ended without closing it" + (f"; {loaded} cache files loaded since" if loaded else ""))
        closed += 1
        if log is not None:
            who = f"{row['feed']}:{row['ticker']}" if row["ticker"] else row["feed"]
            log(f"cache {who}: a pull left open by a run that is gone was closed" + (
                f", {loaded} of its cache files loaded without asking the feed again" if loaded else ""))
    return closed


def room(store, policy_: Policy | None = None, log: Log | None = None) -> None:
    """Before a new pull: the unverified cache is under its cap. At the cap, what waits is audited at once; still at
    the cap after that (pulls open elsewhere, or findings that are not files' to settle): CacheFull."""
    with_ = policy_ or policy()
    cap = with_.cap_gb * 2**30
    counted = getattr(store, "cache_bytes", None)
    if not callable(counted) or counted() < cap:
        return
    audit_pulls(store, policy_=with_, log=log)
    held = counted()
    if held >= cap:
        raise CacheFull(f"the fetch cache holds {held / 2**30:.1f} GB not audited yet (its cap: {with_.cap_gb} GB): "
                        "fetching waits for the auditors")


@contextmanager
def pull(store, feed: str, kind: str, log: Log | None = None, **facts) -> Iterator[pulls.Pull]:
    """A pull open for the block (storage/pulls.py: pulling), audited as it closes when the policy says so (`Audit
    when a symbol is updated`). An audit that cannot run then (a database busy) is left to the next one."""
    with_ = policy()
    room(store, with_, log)
    one = None
    try:
        with pulls.pulling(store, feed, kind, **facts) as one:
            yield one
    finally:
        if one is not None and one.made and with_.on_update:
            try:
                audit_pull(store, one.id, with_, log)
            except (sqlite3.Error, OSError) as e:
                if log is not None:
                    log(f"cache {feed}: a pull's audit is left for later ({type(e).__name__}: {e})")


def tidy(store, policy_: Policy | None = None, now: datetime | None = None) -> dict:
    """The cache kept in order: the files of verified pulls whose keeping time is over removed, and the pulls long
    audited forgotten. Returns {"removed", "forgotten"}."""
    with_ = policy_ or policy()
    at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    removed = 0
    before = (at - timedelta(days=with_.keep_days)).isoformat(timespec="seconds")
    for row in store.pulls(audited=True, limit=5000):
        if row["audit"] == "mismatch" or (row["audited_at"] or "") > before:
            continue
        files = [f for f in store.pull_files(row["id"]) if not f["removed_at"]]
        if files:
            removed += _remove(store, row, files, store.pull_folder(row))
    return {"removed": removed, "forgotten": store.pulls_forget(at - timedelta(days=FORGET_DAYS))}


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

    A day without a single bar is a **hole** only with evidence that bars should be there: the feed's own daily bar
    of that day shows it traded (or its own finer bars do, for a missing daily bar), another feed of the same market
    holds bars that day, the feed's ticks do, or a pull that was cut off covers it. A thin stock's quiet days and a
    market's closed hours are no holes. A span said to be held that holds no bar at all is an **empty span**. Both
    are asked of the feed again by its next run, a few a run (the collector's re-pulls: `repulls`); one asked again
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
        the feed having nothing there). Returns those still so: evidence for a hole."""
        store, still = self.store, []
        for p in store.pulls(feed=feed, ticker=ticker, state="cut", limit=500):
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

    def _days(self, conn, row: dict, timespan: str, spans: list, data, exchange, cut: list[dict], visit: Visit) -> None:
        """Every session day inside the spans the feed is said to hold, looked for in its bars; the holes and the
        empty spans kept as findings, and the findings of before brought up to date."""
        store, feed, ticker = self.store, row["source"], row["ticker"]
        horizon = self.now_ms - SETTLE_MS
        runs: list[tuple[int, int, int, str]] = []  # (from, to, days, kind)
        for a, b in spans:
            b = min(b, horizon)
            days = [int(d) for d in data.slots("day", a, b, exchange=exchange) if a <= d and d + DAY_MS <= b]
            if not days:
                continue
            visit.days += len(days)
            missing = [d for d in days if not self._has_bar(conn, ticker, timespan, d, d + DAY_MS)]
            if len(missing) == len(days):
                runs.append((days[0], days[-1] + DAY_MS, len(days), "empty-span"))
                continue
            place = {d: i for i, d in enumerate(days)}
            run: list[int] = []
            for d in [*missing, None]:
                if run and (d is None or place[d] != place[run[-1]] + 1):  # the run of days next to each other ends
                    runs.append((run[0], run[-1] + DAY_MS, len(run), "hole"))
                    run = []
                if d is not None:
                    run.append(d)
        known = [f for kind in HOLE_KINDS for f in store.findings(feed=feed, ticker=ticker, kind=kind)
                 if f["timespan"] == timespan and f["state"] != "closed"]
        for f in known:  # a finding of before: filled since, or asked again and still empty
            empty = [d for d in data.slots("day", f["start_ms"], f["end_ms"], exchange=exchange)
                     if not self._has_bar(conn, ticker, timespan, int(d), int(d) + DAY_MS)]
            if not empty:
                store.finding_set(f["id"], "closed")
                visit.closed += 1
            elif f["state"] == "asked":
                store.finding_set(f["id"], "absent")
                visit.absent += 1
        for lo, hi, n, kind in runs:
            if any(f["start_ms"] < hi and f["end_ms"] > lo for f in known):
                continue  # known already: open, asked or absent
            why = "the ledger says it is held" if kind == "empty-span" else self._evidence(conn, row, timespan, lo, hi, cut)
            if not why:
                continue  # nothing says bars should be there: a quiet day, not a hole
            store.finding_put(kind, feed, ticker, timespan, lo, hi, count=n, detail={"days": n, "evidence": why})
            visit.holes += 1

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
    answer is stored, and marks the findings asked: mark_asked.)"""
    out: list[dict] = []
    if limit <= 0 or not hasattr(store, "findings"):
        return out
    for f in reversed(store.findings(state="open", feed=feed, ticker=ticker, limit=200)):
        if len(out) >= limit:
            break
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
    """The auditors for their page: the policy, the cache by state and size, the last sweep, where the round
    stands, and the latest findings."""
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
                      "capBytes": with_.cap_gb * 2**30},
            "sweep": {"last": last, "cursor": cursor, "round": Sweep(store, policy_=with_).round()},
            "findings": {"counts": counts, "open": counts.get("open", 0), "latest": store.findings(limit=findings)}}
