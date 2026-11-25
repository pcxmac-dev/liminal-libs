"""The network database (1.96.0; service-containers-networking-2026-11-23.md §9): what a firewall plugin's network part
(machines/segments.py's NetworkHost) keeps of this machine's container networks, in place of the stand-ins' MemoryBook.
The user, 2026-11-23: "the firewall app will know it's domain, and have name resolution to each container, reverse
lookup for all containers, and contain DHCP records for dynamically assigned addresses".

One small SQLite file for each system, beside the hosts database: network/network.db in the data folder (`path`). Its
tables:
- `allocations`: each prefix handed out (or found and reserved) for a service, with its addresses, its route and the
  ports opened to your network (the Allocation as JSON beside its key columns), its state (made, removed, gone, freed)
  and when; a freed row is kept, marked freed, never handed back as one in use;
- `addresses`: the DHCP records, one row per address on every segment the container plugins read: the segment, the
  container, its service and part, its IPv4, MAC and hostname, who gave it, since when, its lease's end where a server
  keeps one, when last seen, whether it runs, and its state (current, gone): a record that ends is marked gone, with
  when, and only Forget… (forget_members) or a service's Delete its data… takes it away;
- `changes`: each change in words, its plan and owner, never a secret's value (the last 2,000 kept).

A prefix held by a plan not yet carried out is kept in memory alone (a plan lives ten minutes, in memory: a restart
forgets it and frees what it held). Each call opens the file and closes it, so nothing holds it open while unused, and
a call that only reads makes no file. The file is this system's own: on a folder of another system's drive (WSL's
/mnt/c, a share: geo.foreign) nothing is made, read or written, and a write is refused in words. Off Windows the folder
is made for this account alone (0700) and the file too (0600): it lists this machine's containers' addresses."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import fields
from pathlib import Path

from . import geo, layout
from .instances import Refusal

FOLDER, FILE = "network", "network.db"
CHANGES = 2000
SCHEMA = (
    "CREATE TABLE IF NOT EXISTS allocations (sid TEXT PRIMARY KEY, prefix TEXT, stack TEXT, segment TEXT, plugin TEXT, "
    "platform TEXT, state TEXT, made REAL, freed REAL, data TEXT)",
    "CREATE TABLE IF NOT EXISTS addresses (segment TEXT, address TEXT, container TEXT, sid TEXT, part TEXT, mac TEXT, "
    "hostname TEXT, assigned TEXT, since REAL, until REAL, seen REAL, running INTEGER, state TEXT, gone REAL, "
    "PRIMARY KEY (segment, address))",
    "CREATE TABLE IF NOT EXISTS changes (at REAL, plan TEXT, owner TEXT, action TEXT, words TEXT)",
)


def path() -> Path:
    """The network database's file: network/network.db in the data folder (layout.data_dir()), one for each system."""
    return layout.data_dir() / FOLDER / FILE


def foreign(p=None) -> str:
    """Why the network database at `p` is not kept from here, in words ("" when it is): another system's drive."""
    return geo.foreign(p if p is not None else path(), "Keeping the network database")


def _own() -> Path:
    return path()


class NetBook:
    """A NetworkHost's allocations and DHCP records in this system's network database (the same calls as
    segments.MemoryBook: of_sid, all, put, free, note, seen, members, forget_members)."""

    def __init__(self, file: Path | str | None = None, clock=time.time):
        self._file = Path(file) if file is not None else None  # None: the data folder's, read at each call
        self.lock = threading.RLock()
        self._held: dict = {}  # sid -> Allocation held by a plan not carried out yet: memory alone
        self._clock = clock

    @property
    def path(self) -> Path:
        return self._file if self._file is not None else _own()

    # -- the file -------------------------------------------------------------------------------------------------------
    def elsewhere(self) -> str:
        return foreign(self.path)

    def _open(self, write: bool):
        """The file opened for this call, or None for a read when there is no file (a read makes none)."""
        away = self.elsewhere()
        if away:
            if write:
                raise Refusal(away)
            return None
        if not self.path.exists():
            if not write:
                return None
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(self.path.parent, 0o700)
        db = sqlite3.connect(str(self.path), timeout=10)
        try:
            for s in SCHEMA:
                db.execute(s)
        except Exception:
            db.close()
            raise
        if os.name != "nt":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        return db

    def _read(self, sql: str, args=()) -> list:
        with self.lock:
            db = self._open(False)
            if db is None:
                return []
            try:
                return db.execute(sql, args).fetchall()
            finally:
                db.close()

    def _write(self, *statements) -> None:
        with self.lock:
            db = self._open(True)
            try:
                with db:
                    for sql, args in statements:
                        db.execute(sql, args)
            finally:
                db.close()

    # -- allocations ----------------------------------------------------------------------------------------------------
    @staticmethod
    def _allocation(data: str):
        from .machines.segments import Allocation

        d = json.loads(data)
        known = {f.name for f in fields(Allocation)}
        return Allocation(**{k: v for k, v in d.items() if k in known})

    def of_sid(self, sid: str):
        with self.lock:
            if sid in self._held:
                return self._held[sid]
            rows = self._read("SELECT data FROM allocations WHERE sid = ? AND state != 'freed'", (sid,))
        return self._allocation(rows[0][0]) if rows else None

    def all(self) -> list:
        with self.lock:
            held = dict(self._held)
            rows = self._read("SELECT sid, data FROM allocations WHERE state != 'freed' ORDER BY prefix")
        out = [self._allocation(d) for sid, d in rows if sid not in held]
        return [*out, *held.values()]

    def put(self, a) -> None:
        with self.lock:
            if a.state == "held":
                self._held[a.sid] = a
                return
            self._held.pop(a.sid, None)
            self._write(("INSERT INTO allocations (sid, prefix, stack, segment, plugin, platform, state, made, freed, data)"
                         " VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?) ON CONFLICT(sid) DO UPDATE SET prefix = excluded.prefix,"
                         " stack = excluded.stack, segment = excluded.segment, plugin = excluded.plugin, platform ="
                         " excluded.platform, state = excluded.state, made = excluded.made, freed = NULL, data ="
                         " excluded.data", (a.sid, a.prefix, a.stack, a.segment, a.plugin, a.platform, a.state,
                                             a.made, json.dumps(a.as_dict()))))

    def free(self, sid: str) -> None:
        """A prefix freed: a held one forgotten; a kept one marked freed (never deleted), its DHCP records forgotten."""
        with self.lock:
            if self._held.pop(sid, None) is not None:
                return
            if not self._read("SELECT 1 FROM allocations WHERE sid = ?", (sid,)):
                return
            self._write(("UPDATE allocations SET state = 'freed', freed = ? WHERE sid = ?", (self._clock(), sid)),
                        ("DELETE FROM addresses WHERE sid = ?", (sid,)))

    def note(self, at: float, plan: str, owner: str, action: str, words: str) -> None:
        self._write(("INSERT INTO changes (at, plan, owner, action, words) VALUES (?, ?, ?, ?, ?)",
                     (at, plan, owner, action, str(words)[:2000])),
                    ("DELETE FROM changes WHERE rowid NOT IN (SELECT rowid FROM changes ORDER BY at DESC LIMIT ?)",
                     (CHANGES,)))

    def changes(self, most: int = 50) -> list[dict]:
        rows = self._read("SELECT at, plan, owner, action, words FROM changes ORDER BY at DESC LIMIT ?", (int(most),))
        return [dict(zip(("at", "plan", "owner", "action", "words"), r)) for r in rows]

    # -- the DHCP records -------------------------------------------------------------------------------------------------
    def seen(self, rows, segments, now: float) -> None:
        """A read of the container plugins' segments: each (segment, Member) in `rows` recorded as current, and every
        record of a segment in `segments` (those read whole) not among them marked gone, with when."""
        statements = []
        keys = set()
        for segment, m in rows:
            if not m.ipv4:
                continue
            keys.add((segment, m.ipv4))
            statements.append((
                "INSERT INTO addresses (segment, address, container, sid, part, mac, hostname, assigned, since, until, "
                "seen, running, state, gone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'current', NULL) "
                "ON CONFLICT(segment, address) DO UPDATE SET container = excluded.container, sid = excluded.sid, "
                "part = excluded.part, mac = excluded.mac, hostname = excluded.hostname, assigned = excluded.assigned, "
                "until = excluded.until, seen = excluded.seen, running = excluded.running, state = 'current', gone = NULL,"
                " since = CASE WHEN addresses.state = 'gone' OR addresses.mac != excluded.mac THEN excluded.since "
                "ELSE addresses.since END",
                (segment, m.ipv4, m.container, m.sid, m.part, m.mac, m.hostname, m.assigned, now, m.until, now,
                 int(bool(m.running)))))
        with self.lock:
            for seg in set(segments):
                for (address,) in self._read("SELECT address FROM addresses WHERE segment = ? AND state = 'current'",
                                             (seg,)):
                    if (seg, address) not in keys:
                        statements.append(("UPDATE addresses SET state = 'gone', gone = ?, running = 0 WHERE segment = ?"
                                           " AND address = ?", (now, seg, address)))
            if statements:
                self._write(*statements)

    def members(self, segment: str = "") -> list[dict]:
        cols = ("segment", "address", "container", "sid", "part", "mac", "hostname", "assigned", "since", "until",
                "seen", "running", "state", "gone")
        sql = f"SELECT {', '.join(cols)} FROM addresses" + (" WHERE segment = ?" if segment else "") + \
            " ORDER BY segment, address"
        return [dict(zip(cols, r)) for r in self._read(sql, (segment,) if segment else ())]

    def forget_members(self, segment: str = "") -> int:
        """The records marked gone taken away (Forget… on the Networks tab): all of them, or one segment's."""
        with self.lock:
            gone = [m for m in self.members(segment) if m["state"] == "gone"]
            if gone:
                self._write(*(("DELETE FROM addresses WHERE segment = ? AND address = ? AND state = 'gone'",
                               (m["segment"], m["address"])) for m in gone))
        return len(gone)

    def describe(self) -> dict:
        away = self.elsewhere()
        if away:
            return {"path": str(self.path), "elsewhere": away, "rows": 0}
        rows = self._read("SELECT COUNT(*) FROM allocations") if self.path.exists() else []
        return {"path": str(self.path), "elsewhere": "", "rows": int(rows[0][0]) if rows else 0,
                "made": self.path.exists()}


__all__ = ["NetBook", "path", "foreign", "FOLDER", "FILE"]
