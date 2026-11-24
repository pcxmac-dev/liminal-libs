"""Audits (a second feed's copy of a stored span, compared) and quality scores."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from .common import _now


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

    def audit_queue(self, exclude_owner: str | None = None) -> list[dict]:
        sql = "SELECT ticker, timespan, start_ms, end_ms, owner, queued_at FROM audit_queue"
        args: tuple = ()
        if exclude_owner is not None:
            sql, args = sql + " WHERE owner != ?", (exclude_owner,)
        cols = ("ticker", "timespan", "start_ms", "end_ms", "owner", "queued_at")
        return [dict(zip(cols, r)) for r in self.conn.execute(sql + " ORDER BY queued_at", args)]

    def audit_queue_count(self) -> int:
        """Entries waiting in the audit queue (a count, not the rows)."""
        return self.conn.execute("SELECT COUNT(*) FROM audit_queue").fetchone()[0]

    def expire_audits(self, before: datetime) -> int:
        """Drop queued audits older than `before` (one statement). Returns entries dropped."""
        with self.conn:
            return self.conn.execute("DELETE FROM audit_queue WHERE queued_at < ?",
                                     (before.astimezone(timezone.utc).isoformat(timespec="seconds"),)).rowcount

    def dequeue_audit(self, ticker: str, timespan: str, start_ms: int, owner: str, end_ms: int | None = None) -> None:
        """The entry audited taken off the queue. With `end_ms`, only while it is still the span that was audited:
        one widened meanwhile (queue_audit, another process's download) waits on (1.81.0)."""
        sql, args = "DELETE FROM audit_queue WHERE ticker=? AND timespan=? AND start_ms=? AND owner=?", \
            (ticker.upper(), timespan, start_ms, owner)
        if end_ms is not None:
            sql, args = sql + " AND end_ms=?", (*args, end_ms)
        with self.conn:
            self.conn.execute(sql, args)
