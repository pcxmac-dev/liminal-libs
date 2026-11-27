"""Audits (a second feed's copy of a stored span, compared) and quality scores."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import sqlite3

from .common import _now, _now_precise


class AuditStore:
    """Store methods: audits (a second feed's copy of a stored span, compared) and quality scores."""

    def set_quality(self, subject: str, asset: str, score: float, details: dict | None = None,
                    derivation: int | None = None) -> None:
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO quality (subject, asset, score, details, updated, derivation) "
                              "VALUES (?, ?, ?, ?, ?, ?)",
                              (subject, asset, float(score), json.dumps(details or {}), _now(), derivation))

    def quality(self, subject: str, asset: str) -> dict | None:
        row = self.conn.execute("SELECT score, details, updated, derivation FROM quality WHERE subject=? AND asset=?",
                                (subject, asset)).fetchone()
        return {"score": row[0], "details": json.loads(row[1] or "{}"), "updated": row[2],
                "derivation": row[3]} if row else None

    def qualities(self) -> list[dict]:
        return [{"subject": s, "asset": a, "score": sc, "details": json.loads(d or "{}"), "updated": u}
                for s, a, sc, d, u in self.conn.execute(
                    "SELECT subject, asset, score, details, updated FROM quality ORDER BY asset, score DESC")]

    # -- audits -------------------------------------------------------------

    def save_audit(self, row: dict) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO audits (at, ticker, asset, timespan, start_ms, end_ms, owner, auditor, reason, verdict, "
                "matched, only_owner, only_auditor, report, derivation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (row.get("at") or _now(), row["ticker"].upper(), row.get("asset"), row["timespan"], row["start_ms"],
                 row["end_ms"], row["owner"], row["auditor"], row.get("reason"), row["verdict"], row.get("matched"),
                 row.get("only_owner"), row.get("only_auditor"), json.dumps(row.get("report") or {}),
                 row.get("derivation")))
            return cur.lastrowid

    def audits(self, limit: int = 50, ticker: str | None = None) -> list[dict]:
        sql = ("SELECT id, at, ticker, asset, timespan, start_ms, end_ms, owner, auditor, reason, verdict, matched, "
               "only_owner, only_auditor, report FROM audits")
        args: list = []
        if ticker:
            sql += " WHERE ticker=?"
            args.append(ticker.upper())
        cols = ("id", "at", "ticker", "asset", "timespan", "start_ms", "end_ms", "owner", "auditor", "reason",
                "verdict", "matched", "only_owner", "only_auditor", "report")
        out = []
        for r in self.conn.execute(sql + " ORDER BY id DESC LIMIT ?", (*args, limit)):
            d = dict(zip(cols, r))
            d["report"] = json.loads(d["report"] or "{}")
            out.append(d)
        return out

    def audit_scores(self, days: int = 90) -> dict[str, dict]:
        """Per feed, over recent audits it took part in: how many and the share that passed.
        Two feeds that disagree score alike (an audit cannot say which is right); a third feed
        makes the scores differ."""
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        out: dict[str, dict] = {}
        for owner, auditor, verdict in self.conn.execute(
                "SELECT owner, auditor, verdict FROM audits WHERE at >= ? AND verdict != 'no-data'", (since,)):
            for feed in (owner, auditor):
                s = out.setdefault(feed, {"audits": 0, "passed": 0})
                s["audits"] += 1
                s["passed"] += verdict == "pass"
        for s in out.values():
            s["accuracy"] = s["passed"] / s["audits"] if s["audits"] else None
        return out

    def queue_audit(self, ticker: str, timespan: str, start_ms: int, end_ms: int, owner: str) -> None:
        """Queue [start, end) of a series for another feed's audit. One entry per series and owner
        waits at a time: a row added per fetch per symbol grew the queue to a week of backlog, some
        10^5 rows, read whole on every audit pass. A span queued while another still waits widens it
        to cover both, from the lower start to the higher end (1.81.0; the review of 2026-11-21,
        Monday list item 4: the newer replaced the older, so a span downloaded and not yet audited
        was never audited, and a wider wait could become a narrower one). The entry's time is the
        newest queuing's (QUEUE_MAX_AGE expires it a week after the last download it covers). The
        old entry is taken out and the new one put in in one transaction (DELETE ... RETURNING)."""
        with self.conn:
            for lo, hi in self.conn.execute(
                    "DELETE FROM audit_queue WHERE ticker=? AND timespan=? AND owner=? RETURNING start_ms, end_ms",
                    (ticker.upper(), timespan, owner)).fetchall():
                start_ms, end_ms = min(start_ms, lo), max(end_ms, hi)
            self.conn.execute("INSERT OR REPLACE INTO audit_queue VALUES (?, ?, ?, ?, ?, ?)",
                              (ticker.upper(), timespan, start_ms, end_ms, owner, _now()))

    def audit_queue(self, exclude_owner: str | None = None, auditor: str | None = None) -> list[dict]:
        """The queued audits, the oldest queuing first. With `auditor` (1.109.0, item 14), as that feed takes them:
        those it has not tried first, then those it tried and could not run (audit_tried), the oldest try first,
        each with its `tried_at` (None: not tried)."""
        cols = ("ticker", "timespan", "start_ms", "end_ms", "owner", "queued_at")
        where, args = ("", ()) if exclude_owner is None else (" WHERE q.owner != ?", (exclude_owner,))
        plain = f"SELECT {', '.join('q.' + c for c in cols)} FROM audit_queue q{where} ORDER BY q.queued_at"
        if auditor is None:
            return [dict(zip(cols, r)) for r in self.conn.execute(plain, args)]
        sql = (f"SELECT {', '.join('q.' + c for c in cols)}, t.tried_at FROM audit_queue q LEFT JOIN audit_tries t "
               "ON t.ticker=q.ticker AND t.timespan=q.timespan AND t.start_ms=q.start_ms AND t.owner=q.owner "
               f"AND t.auditor=?{where} ORDER BY t.tried_at IS NOT NULL, t.tried_at, q.queued_at")
        try:
            rows = self.conn.execute(sql, (auditor, *args)).fetchall()
        except sqlite3.OperationalError as e:  # a file without the table (another system's, behind): none tried
            if "no such table" not in str(e):
                raise
            return [{**dict(zip(cols, r)), "tried_at": None} for r in self.conn.execute(plain, args)]
        return [dict(zip((*cols, "tried_at"), r)) for r in rows]

    def audit_tried(self, ticker: str, timespan: str, start_ms: int, owner: str, auditor: str) -> None:
        """1.109.0 (item 14): a queued audit `auditor` could not run (its feed refused it, or did not answer) put
        behind the ones it has not tried (audit_queue): it stays queued, for this feed's later passes and for the
        other feeds, until it is audited or QUEUE_MAX_AGE ends it."""
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO audit_tries (ticker, timespan, start_ms, owner, auditor, tried_at) "
                              "VALUES (?, ?, ?, ?, ?, ?)", (ticker.upper(), timespan, start_ms, owner, auditor,
                                                            _now_precise()))

    def audit_queue_count(self) -> int:
        """Entries waiting in the audit queue (a count, not the rows)."""
        return self.conn.execute("SELECT COUNT(*) FROM audit_queue").fetchone()[0]

    def expire_audits(self, before: datetime) -> int:
        """Drop queued audits older than `before` (one statement). Returns entries dropped."""
        with self.conn:
            dropped = self.conn.execute("DELETE FROM audit_queue WHERE queued_at < ?",
                                        (before.astimezone(timezone.utc).isoformat(timespec="seconds"),)).rowcount
            self._tries_left(self.conn)
            return dropped

    @staticmethod
    def _tries_left(conn) -> None:
        """The tries of entries no longer queued forgotten (1.109.0; a file without the table has none)."""
        try:
            conn.execute("DELETE FROM audit_tries WHERE NOT EXISTS (SELECT 1 FROM audit_queue q WHERE "
                         "q.ticker=audit_tries.ticker AND q.timespan=audit_tries.timespan AND "
                         "q.start_ms=audit_tries.start_ms AND q.owner=audit_tries.owner)")
        except sqlite3.OperationalError as e:
            if "no such table" not in str(e):
                raise

    def dequeue_audit(self, ticker: str, timespan: str, start_ms: int, owner: str, end_ms: int | None = None) -> None:
        """The entry audited taken off the queue. With `end_ms`, only while it is still the span that was audited:
        one widened meanwhile (queue_audit, another process's download) waits on (1.81.0)."""
        sql, args = "DELETE FROM audit_queue WHERE ticker=? AND timespan=? AND start_ms=? AND owner=?", \
            (ticker.upper(), timespan, start_ms, owner)
        if end_ms is not None:
            sql, args = sql + " AND end_ms=?", (*args, end_ms)
        with self.conn:
            self.conn.execute(sql, args)
            self._tries_left(self.conn)
