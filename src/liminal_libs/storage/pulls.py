"""The fetch cache's ledger (1.64.0): which pulls there are, the files each wrote, and what the auditors found.

The user, 2026-11-15: "when the integrator goes to a source and pulls the data, make sure that the data is stored in a
temporary cache (not on ram), until it can be read in to the symbol database. leave the data in cache until an auditor
goes over the symbol and checks the data bit by bit to ensure it was copied successfully, auditors should run if a
symbol is updated, or periodically."

A **pull** is one thing asked of a feed: a gap of a series (`bars`), a future's contract (`future`), a whole market's
day (`market_day`, `grouped_day`), a download by hand (`download`), a bar asked a second time (`recheck`). While it is
open (`pulling`; spool.py says which pull is), every answer the HTTP client receives is written into its folder
(cache/<feed>/<pull>/ beside the main file) and every write of bars is made from a rows file written there first. A
pull knows how it ended: `complete` (its pages ended), or `cut` (a stop, an error, a crash: a fragment, and known to
be one). Its files stay until the copy audit (auditing.py) has held every rows file against the database.

Nothing is made for a pull that writes nothing: its row and its folder appear with its first file, so the many pulls
of a run that find nothing to ask leave no trace. With the data folder in memory, in a process that reads only, or
with LIMINAL_FETCH_CACHE=off, a pull is open in name only and everything is written as before 1.64.0.

The tables (schema.py: `pulls`, `pull_files`, `audit_findings`) are the main file's. A finding is what an auditor
could not put right by itself, or put right and says so: kept with what it is about, and its state (open, repaired,
asked again, absent at the feed, closed)."""
from __future__ import annotations

import json
import os
import secrets
import shutil
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from .. import spool
from .common import _now, read_only, write_transaction

CACHE = "cache"  # the folder, beside the main file
SWITCH = "LIMINAL_FETCH_CACHE"  # off: nothing is cached (the step's switch)
KINDS = ("bars", "future", "market_day", "grouped_day", "download", "recheck")
ROW_COLUMNS = ("ticker", "timespan", "multiplier", "ts", "open", "high", "low", "close", "volume", "vwap",
               "transactions")  # a rows file's columns: a bar as it is stored, without when
FINDING_STATES = ("open", "repaired", "asked", "absent", "closed")
_PULL = ("id", "feed", "kind", "ticker", "asset", "timespan", "start_ms", "end_ms", "state", "audit", "opened_at",
         "closed_at", "audited_at", "instance", "pid", "note")
_FILE = ("pull", "seq", "kind", "name", "bytes", "sha256", "written_at", "path", "status", "feed", "rows", "lo_ms",
         "hi_ms", "stored_at", "loaded_at", "audited_at", "result", "missing", "differing", "removed_at")
_FINDING = ("id", "at", "kind", "feed", "ticker", "timespan", "start_ms", "end_ms", "pull", "count", "detail", "state",
            "updated_at")


def enabled() -> bool:
    """Whether pulls are cached in this process (LIMINAL_FETCH_CACHE: on unless it says off)."""
    from ..config import setting

    return (setting(SWITCH) or "on").strip().lower() not in ("off", "0", "no", "false")


def cache_dir(store) -> Path | None:
    """The cache's folder for a store: cache/ beside its main file; None for a store in memory."""
    path = getattr(store, "path", None)
    if path is None or str(path) == ":memory:":
        return None
    return Path(path).with_name(CACHE)


def new_id(now: datetime | None = None) -> str:
    """A pull's id, which is its folder's name: when it was opened (UTC), and eight random characters."""
    at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return f"{at:%Y%m%dT%H%M%S}-{secrets.token_hex(4)}"


class _Payload:
    """An answer on its way into a pull: written piece by piece, then kept (recorded, and read back) or abandoned."""

    def __init__(self, pull: "Pull", seq: int, writer: spool.PayloadWriter, path: str, status: int):
        self._pull, self._seq, self._writer, self._path, self._status = pull, seq, writer, path, status

    def write(self, piece: bytes) -> None:
        self._writer.write(piece)

    def keep(self) -> bytes:
        """The answer whole on disk and in the ledger; its body as read back from the file."""
        written = self._writer.close()
        self._pull._record(self._seq, "payload", written, path=self._path, status=self._status)
        try:
            return spool.read_payload(self._writer.path)
        except OSError as e:
            raise spool.CacheFailed(f"the fetch cache could not be read back ({self._writer.path}: {e})") from e

    def abandon(self) -> None:
        self._writer.abandon()


class Pull:
    """One pull while it is open. `spools`: whether anything of it goes to disk (see the module's words). The HTTP
    client asks it for `payload`; a store's write of bars for `rows`, then says `loaded`."""

    def __init__(self, store, feed: str, kind: str, folder: Path | None, facts: dict):
        self.store, self.feed, self.kind, self.facts = store, feed, kind, facts
        self.id = new_id()
        self.folder = folder / feed / self.id if folder is not None else None
        self.spools = self.folder is not None
        self.made = False  # its row and its folder exist (with its first file)
        self.closed = False
        self.unspooled = 0  # writes made without a rows file: values a rows file cannot hold
        self.rows_files = 0
        self._seq = 0
        self._notes: list[str] = []

    def _make(self) -> None:
        if self.made:
            return
        try:
            self.folder.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise spool.CacheFailed(f"the fetch cache's folder could not be made ({self.folder}: {e})") from e
        self.store._pull_made(self)
        self.made = True

    def _record(self, seq: int, kind: str, written: spool.Written, **facts) -> None:
        self.store._pull_file(self.id, seq, kind, written, **facts)

    def _name(self, suffix: str) -> tuple[int, str]:
        self._seq += 1
        return self._seq, f"{self._seq:05d}{suffix}"

    # -- an answer ---------------------------------------------------------------------------------------------
    def payload(self, path: str, status: int) -> _Payload | None:
        """Where an answer is written (None: this pull keeps nothing on disk). `path`: the request's path alone,
        never its query (a key may be in it)."""
        if not self.spools or self.closed:
            return None
        self._make()
        seq, name = self._name(spool.PAYLOAD_SUFFIX)
        return _Payload(self, seq, spool.PayloadWriter(self.folder, name), path[:300], int(status))

    # -- a write of bars -----------------------------------------------------------------------------------------
    def rows(self, feed: str, rows: list[tuple], stored_at: int) -> tuple[list[tuple], int | None]:
        """Bar rows on their way into `feed`'s file (as _UPSERT_BAR takes them, when stored last): written to a
        rows file, read back, and handed on as read. Returns the rows to write and the file's number (None: no
        file was made, and the rows are the ones given)."""
        if not self.spools or self.closed or not rows:
            return rows, None
        self._make()
        seq, name = self._name(spool.ROWS_SUFFIX)
        header = {"pull": self.id, "seq": seq, "feed": feed, "table": "bars", "columns": list(ROW_COLUMNS),
                  "stored_at": int(stored_at)}
        try:
            written = spool.write_rows(self.folder, name, header, [list(r[:len(ROW_COLUMNS)]) for r in rows])
        except spool.Unspoolable as e:
            self.unspooled += 1
            self._notes.append(f"{len(rows)} rows written without a rows file ({e})")
            return rows, None
        times = [r[3] for r in rows]
        self._record(seq, "rows", written, feed=feed, rows=len(rows), lo_ms=min(times), hi_ms=max(times),
                     stored_at=int(stored_at))
        try:
            _, back, digest = spool.read_rows(self.folder / name)
        except (OSError, ValueError) as e:
            raise spool.CacheFailed(f"the fetch cache could not be read back ({self.folder / name}: {e})") from e
        if digest != written.sha256 or len(back) != len(rows):
            raise spool.CacheFailed(f"a rows file read back is not what was written ({self.folder / name})")
        self.rows_files += 1
        return [(*r, stored_at) for r in back], seq

    def loaded(self, seq: int | None) -> None:
        """The rows of file `seq` are in the database (committed)."""
        if seq is not None:
            self.store._pull_loaded(self.id, seq)

    # -- its end -------------------------------------------------------------------------------------------------
    def close(self, state: str = "complete", note: str = "") -> None:
        """The pull ended: `complete`, or `cut` with why. One that wrote nothing leaves nothing; one that is
        complete and loaded no rows had nothing to check, and its files go at once."""
        if self.closed:
            return
        self.closed = True
        if not self.made:
            return
        words = "; ".join(w for w in (note, *self._notes) if w)[:400]
        if state == "complete" and not self.rows_files and not self.unspooled:
            self.store.pull_drop(self.id)
            return
        self.store._pull_closed(self.id, state, words)


class PullStore:
    """Store methods: the fetch cache's ledger (see the module's docstring)."""

    # -- pulls ---------------------------------------------------------------------------------------------------
    def pull_open(self, feed: str, kind: str, ticker: str | None = None, asset: str | None = None,
                  timespan: str | None = None, start_ms: int | None = None, end_ms: int | None = None) -> Pull:
        """A pull, open (not yet in the ledger: Pull says when it is)."""
        if kind not in KINDS:
            raise ValueError(f"not a kind of pull: {kind!r}")
        folder = cache_dir(self) if enabled() and not read_only() else None
        return Pull(self, feed, kind, folder, {
            "ticker": ticker.upper() if ticker else None, "asset": asset, "timespan": timespan,
            "start_ms": None if start_ms is None else int(start_ms), "end_ms": None if end_ms is None else int(end_ms)})

    def _pull_made(self, pull: Pull) -> None:
        from ..claims import instance

        f = pull.facts
        with self.conn:
            self.conn.execute(
                "INSERT INTO pulls (id, feed, kind, ticker, asset, timespan, start_ms, end_ms, state, opened_at, instance, "
                "pid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
                (pull.id, pull.feed, pull.kind, f["ticker"], f["asset"], f["timespan"], f["start_ms"], f["end_ms"], _now(),
                 instance(), os.getpid()))

    def _pull_file(self, pull_id: str, seq: int, kind: str, written: spool.Written, path: str | None = None,
                   status: int | None = None, feed: str | None = None, rows: int | None = None,
                   lo_ms: int | None = None, hi_ms: int | None = None, stored_at: int | None = None) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO pull_files (pull, seq, kind, name, bytes, sha256, written_at, path, status, feed, rows, lo_ms, "
                "hi_ms, stored_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (pull_id, seq, kind, written.name, written.bytes, written.sha256, _now(), path, status, feed, rows, lo_ms,
                 hi_ms, stored_at))

    def _pull_loaded(self, pull_id: str, seq: int) -> None:
        with self.conn:
            self.conn.execute("UPDATE pull_files SET loaded_at=? WHERE pull=? AND seq=?", (_now(), pull_id, seq))

    def _pull_closed(self, pull_id: str, state: str, note: str = "") -> None:
        with self.conn:
            self.conn.execute("UPDATE pulls SET state=?, closed_at=?, note=NULLIF(?, '') WHERE id=? AND state='open'",
                              (state, _now(), note, pull_id))

    def pull(self, pull_id: str) -> dict | None:
        r = self.conn.execute(f"SELECT {', '.join(_PULL)} FROM pulls WHERE id=?", (pull_id,)).fetchone()
        return dict(zip(_PULL, r)) if r else None

    def pulls(self, feed: str | None = None, ticker: str | None = None, state: str | None = None,
              audited: bool | None = None, limit: int = 200) -> list[dict]:
        """The pulls in the ledger, the newest first: of a feed, of a symbol, in a state (open, complete, cut),
        audited or not yet."""
        where, args = [], []
        for column, value in (("feed", feed), ("ticker", ticker.upper() if ticker else None), ("state", state)):
            if value is not None:
                where.append(f"{column}=?")
                args.append(value)
        if audited is not None:
            where.append("audit IS NOT NULL" if audited else "audit IS NULL")
        sql = f"SELECT {', '.join(_PULL)} FROM pulls" + (" WHERE " + " AND ".join(where) if where else "")
        return [dict(zip(_PULL, r)) for r in self.conn.execute(sql + " ORDER BY opened_at DESC, id DESC LIMIT ?",
                                                               (*args, int(limit)))]

    def pull_files(self, pull_id: str, kind: str | None = None) -> list[dict]:
        sql = f"SELECT {', '.join(_FILE)} FROM pull_files WHERE pull=?" + (" AND kind=?" if kind else "")
        return [dict(zip(_FILE, r)) for r in self.conn.execute(sql + " ORDER BY seq", (pull_id, kind) if kind else (pull_id,))]

    def pull_folder(self, pull: dict | str) -> Path | None:
        """Where a pull's files are (None for a store in memory)."""
        row = self.pull(pull) if isinstance(pull, str) else pull
        folder = cache_dir(self)
        return folder / row["feed"] / row["id"] if folder is not None and row else None

    def pull_silent(self, older_than_s: float, feed: str | None = None, now: datetime | None = None) -> list[dict]:
        """The pulls still open whose last file was written more than `older_than_s` ago: their run ended without
        closing them (a crash), or is stuck. The oldest first."""
        before = ((now or datetime.now(timezone.utc)).astimezone(timezone.utc)
                  - timedelta(seconds=older_than_s)).isoformat(timespec="seconds")
        sql = (f"SELECT {', '.join('p.' + c for c in _PULL)} FROM pulls p WHERE p.state='open' AND "
               "COALESCE((SELECT MAX(f.written_at) FROM pull_files f WHERE f.pull=p.id), p.opened_at) < ?")
        args: list = [before]
        if feed is not None:
            sql += " AND p.feed=?"
            args.append(feed)
        return [dict(zip(_PULL, r)) for r in self.conn.execute(sql + " ORDER BY p.opened_at, p.id", args)]

    def pull_cut(self, pull_id: str, note: str) -> None:
        """An open pull whose run is gone, closed as cut."""
        self._pull_closed(pull_id, "cut", note[:400])

    def pull_file_loaded(self, pull_id: str, seq: int) -> None:
        self._pull_loaded(pull_id, seq)

    def pull_file_known(self, pull_id: str, seq: int, written: spool.Written, header: dict, times: tuple[int, int]) -> None:
        """A rows file found in a pull's folder that the ledger did not have (its run ended between the file and
        its row): entered as it is."""
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO pull_files (pull, seq, kind, name, bytes, sha256, written_at, feed, rows, lo_ms, hi_ms, "
                "stored_at) VALUES (?, ?, 'rows', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (pull_id, seq, written.name, written.bytes, written.sha256, _now(), header.get("feed"), written.rows,
                 times[0], times[1], header.get("stored_at")))

    # -- what the audit says ---------------------------------------------------------------------------------------
    def pull_file_audited(self, pull_id: str, seq: int, result: str, missing: int = 0, differing: int = 0) -> None:
        with self.conn:
            self.conn.execute("UPDATE pull_files SET audited_at=?, result=?, missing=?, differing=? WHERE pull=? AND seq=?",
                              (_now(), result, int(missing), int(differing), pull_id, seq))

    def pull_audited(self, pull_id: str, audit: str, note: str = "") -> None:
        """A pull's audit: ok, repaired or mismatch, with what was found in words."""
        with self.conn:
            self.conn.execute("UPDATE pulls SET audit=?, audited_at=?, note=COALESCE(NULLIF(?, ''), note) WHERE id=?",
                              (audit, _now(), note[:400], pull_id))

    def pull_files_removed(self, pull_id: str, seqs: list[int]) -> None:
        with self.conn:
            self.conn.executemany("UPDATE pull_files SET removed_at=? WHERE pull=? AND seq=?",
                                  [(_now(), pull_id, s) for s in seqs])

    def pull_drop(self, pull_id: str) -> None:
        """A pull forgotten, its files with it (one that had nothing to check, or one long audited)."""
        folder = self.pull_folder(pull_id)
        with write_transaction(self.conn):
            self.conn.execute("DELETE FROM pull_files WHERE pull=?", (pull_id,))
            self.conn.execute("DELETE FROM pulls WHERE id=?", (pull_id,))
        if folder is not None:
            shutil.rmtree(folder, ignore_errors=True)

    def pulls_forget(self, before: datetime) -> int:
        """The pulls audited before `before` whose files are all gone, forgotten (the ledger does not grow without
        end). One with a file still kept (a mismatch's evidence, a payload kept some days) stays."""
        at = before.astimezone(timezone.utc).isoformat(timespec="seconds")
        with write_transaction(self.conn):
            gone = self.conn.execute(
                "SELECT p.id, p.feed FROM pulls p WHERE p.audit IS NOT NULL AND p.audited_at < ? AND NOT EXISTS "
                "(SELECT 1 FROM pull_files f WHERE f.pull=p.id AND f.removed_at IS NULL)", (at,)).fetchall()
            self.conn.executemany("DELETE FROM pull_files WHERE pull=?", [(i,) for i, _ in gone])
            self.conn.executemany("DELETE FROM pulls WHERE id=?", [(i,) for i, _ in gone])
        folder = cache_dir(self)
        if folder is not None:
            for pull_id, feed in gone:  # (an emptied folder may be left behind by a file's removal: taken away here)
                shutil.rmtree(folder / feed / pull_id, ignore_errors=True)
        return len(gone)

    def cache_bytes(self, unverified_only: bool = True) -> int:
        """Bytes of the cache's files on disk: those of the pulls not audited yet (what the cap counts: a
        mismatch's kept files do not), or of every file kept."""
        sql = ("SELECT COALESCE(SUM(f.bytes), 0) FROM pull_files f JOIN pulls p ON p.id=f.pull WHERE f.removed_at IS NULL"
               + (" AND p.audit IS NULL" if unverified_only else ""))
        return int(self.conn.execute(sql).fetchone()[0])

    def cache_summary(self) -> list[dict]:
        """The cache by state, for its page: pulls, files kept, bytes kept and rows, for each state and audit."""
        sql = ("SELECT p.state, p.audit, COUNT(DISTINCT p.id), COUNT(CASE WHEN f.removed_at IS NULL THEN f.seq END), "
               "COALESCE(SUM(CASE WHEN f.removed_at IS NULL THEN f.bytes END), 0), "
               "COALESCE(SUM(CASE WHEN f.kind='rows' THEN f.rows END), 0), MIN(p.opened_at), MAX(p.opened_at) "
               "FROM pulls p LEFT JOIN pull_files f ON f.pull=p.id GROUP BY p.state, p.audit ORDER BY p.state, p.audit")
        keys = ("state", "audit", "pulls", "files", "bytes", "rows", "oldest", "newest")
        return [dict(zip(keys, r)) for r in self.conn.execute(sql)]

    # -- findings --------------------------------------------------------------------------------------------------
    def finding_put(self, kind: str, feed: str, ticker: str | None = None, timespan: str | None = None,
                    start_ms: int | None = None, end_ms: int | None = None, pull: str | None = None,
                    detail: dict | None = None, state: str = "open", count: int = 1) -> int:
        """A finding kept: a new one, or the one already kept for the same thing (same kind, series, span and
        pull) brought up to date. Returns its id."""
        if state not in FINDING_STATES:
            raise ValueError(f"not a finding's state: {state!r}")
        ticker = ticker.upper() if ticker else None
        text = json.dumps(detail, separators=(",", ":"), default=str)[:4000] if detail is not None else None
        at = _now()
        with write_transaction(self.conn):
            was = self.conn.execute(
                "SELECT id FROM audit_findings WHERE kind=? AND feed=? AND ticker IS ? AND timespan IS ? AND start_ms IS ? "
                "AND end_ms IS ? AND pull IS ? ORDER BY id LIMIT 1", (kind, feed, ticker, timespan, start_ms, end_ms, pull)
            ).fetchone()
            if was is not None:
                self.conn.execute("UPDATE audit_findings SET count=?, detail=COALESCE(?, detail), state=?, updated_at=? "
                                  "WHERE id=?", (int(count), text, state, at, was[0]))
                return int(was[0])
            return int(self.conn.execute(
                "INSERT INTO audit_findings (at, kind, feed, ticker, timespan, start_ms, end_ms, pull, count, detail, state, "
                "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (at, kind, feed, ticker, timespan, start_ms, end_ms, pull, int(count), text, state, at)).lastrowid)

    def finding_set(self, finding_id: int, state: str, detail: dict | None = None) -> None:
        if state not in FINDING_STATES:
            raise ValueError(f"not a finding's state: {state!r}")
        text = json.dumps(detail, separators=(",", ":"), default=str)[:4000] if detail is not None else None
        with self.conn:
            self.conn.execute("UPDATE audit_findings SET state=?, detail=COALESCE(?, detail), updated_at=? WHERE id=?",
                              (state, text, _now(), int(finding_id)))

    def findings(self, state: str | None = None, feed: str | None = None, ticker: str | None = None,
                 kind: str | None = None, limit: int = 200) -> list[dict]:
        """The findings, the latest first, each with its detail read back."""
        where, args = [], []
        for column, value in (("state", state), ("feed", feed), ("ticker", ticker.upper() if ticker else None),
                              ("kind", kind)):
            if value is not None:
                where.append(f"{column}=?")
                args.append(value)
        sql = f"SELECT {', '.join(_FINDING)} FROM audit_findings" + (" WHERE " + " AND ".join(where) if where else "")
        out = []
        for r in self.conn.execute(sql + " ORDER BY updated_at DESC, id DESC LIMIT ?", (*args, int(limit))):
            row = dict(zip(_FINDING, r))
            try:
                row["detail"] = json.loads(row["detail"]) if row["detail"] else None
            except ValueError:
                pass
            out.append(row)
        return out

    def finding_counts(self) -> dict[str, int]:
        return {state: n for state, n in self.conn.execute("SELECT state, COUNT(*) FROM audit_findings GROUP BY state")}


@contextmanager
def pulling(store, feed: str, kind: str, **facts) -> Iterator[Pull]:
    """A pull open for the block: complete when the block ends, cut (with why) when it is left by an error or a
    stop. A store that keeps no pulls (a stand-in in a test) is given one that spools nothing."""
    opener = getattr(store, "pull_open", None)
    pull = opener(feed, kind, **facts) if callable(opener) else Pull(store, feed, kind, None, dict(facts))
    try:
        with spool.opened(pull):
            yield pull
    except BaseException as e:
        pull.close("cut", f"{type(e).__name__}: {e}")
        raise
    else:
        pull.close("complete")
