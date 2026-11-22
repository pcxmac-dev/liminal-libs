"""The composite database of the firewalls' World Wide Web tab (1.71.0; the user, 2026-11-22: "maybe we need to create
a composite database", "we need real world infrastructure to pair against real/virtual network maps", "so we need both
sides to build a composite database"; "if it is unknown, any segment with in the route, then lets keep that in a queue
of places/segments to lookup").

Both sides and their pairing in one SQLite file, composite.db, kept beside the infrastructure layers (the data folder's
infrastructure/, this system's own: a folder on another system's drive is never written):
- the network's side: what the routes traced here say of each router (its address, the hop it answered at, the one
  before it and the time to it), and, as more sources come, the published maps (BGP's paths, backbones' maps,
  router-level maps);
- the real world's side: the places each source gives a router (the GeoIP file on this machine today; routers' names,
  RIPE Atlas, PeeringDB and the rest as they come, each behind its switch or its download), and the installed layers'
  lines the legs are found on (network.py);
- the pairing: every source's claim kept row by row with its source, its licence and when it was first and last seen
  (`evidence`), and for each router a best estimate of its place with a confidence (`estimates`): the claims that
  agree (within AGREE_KM) make one cluster, the heaviest cluster wins, and its confidence is one less the chance that
  every source in it is wrong (each source's own weight: SOURCES). The lookup queue (`queue`) holds what is not known
  yet: a router with no place, a leg with no way along the lines; with why, and the sources left to try. A row is done
  when its place or way is found, kept for the record.

Nothing is asked of anyone here, and nothing runs when unused: the tab's asks write what is new, a batch an ask, each
row written again at most every REWRITE_S (its `last`); the file is open only while a batch is written."""
from __future__ import annotations

import json
import math
import sqlite3
import threading
import time
from pathlib import Path

from . import infrastructure

FILE = "composite.db"
VERSION = 1  # the schema's (PRAGMA user_version)
AGREE_KM = 50.0  # two claims of a place this near agree
REWRITE_S = 300.0  # a row seen again is written again (its `last`) at most this often
MAX_MEMO = 20_000  # rows remembered as written, in this process
# a source's weight, the chance its claim of a router's place is right, and what it is
SOURCES = {
    "geoip": (0.3, "the GeoIP file on this machine: often the network's home rather than the router itself"),
}
PLACE_LEFT = ("routers' names (reverse DNS: your switch)", "RIPE IPmap (your switch)", "PeeringDB (your switch)",
              "CAIDA's router-level map (your download)")
SEGMENT_LEFT = ("more lines installed (cables, lines on land, backbones)",
                "roads and railways as a stand-in (your download)", "AfTerFibre, TopoHub (your download)")
SCHEMA = (
    "CREATE TABLE IF NOT EXISTS entities (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL,"
    " first REAL NOT NULL, last REAL NOT NULL, UNIQUE (kind, key))",
    "CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, entity INTEGER NOT NULL REFERENCES entities(id),"
    " source TEXT NOT NULL, licence TEXT NOT NULL, claim TEXT NOT NULL, first REAL NOT NULL, last REAL NOT NULL,"
    " UNIQUE (entity, source, claim))",
    "CREATE TABLE IF NOT EXISTS estimates (entity INTEGER PRIMARY KEY REFERENCES entities(id), lat REAL, lon REAL,"
    " label TEXT NOT NULL, confidence REAL NOT NULL, sources INTEGER NOT NULL, at REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS queue (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL,"
    " what TEXT NOT NULL, why TEXT NOT NULL, left TEXT NOT NULL, tries INTEGER NOT NULL DEFAULT 0,"
    " first REAL NOT NULL, last REAL NOT NULL, done REAL, UNIQUE (kind, key))",
)


def _km(a, b) -> float:
    p1, p2 = math.radians(a[0]), math.radians(b[0])
    h = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(b[1] - a[1]) / 2) ** 2
    return 2 * 6371.0088 * math.asin(min(1.0, math.sqrt(h)))


def path() -> Path:
    """Where the composite database is: beside the infrastructure layers."""
    return infrastructure.folder() / FILE


class Composite:
    """The composite database (the module's docstring): `where` its file (path() when not given), `clock` the wall
    clock its times are said in. Thread-safe; it keeps no file open between batches."""

    def __init__(self, where=None, clock=time.time):
        self._where = None if where is None else Path(where)
        self.clock = clock
        self._lock = threading.Lock()
        self._memo: dict[tuple, tuple[float, str]] = {}  # a row's key -> (when it was written, what it said)
        self.closed = False
        self.counts = {"routers": 0, "claims": 0, "placed": 0, "waiting": 0}
        self.problem = ""

    @property
    def path(self) -> Path:
        return self._where if self._where is not None else path()

    def close(self) -> None:
        """Nothing more is written (the plugin detached)."""
        with self._lock:
            self.closed = True
            self._memo.clear()

    def _fresh(self, key: tuple, said: str, now: float) -> bool:
        """Whether a row is to be written now: new, changed, or not written within REWRITE_S."""
        was = self._memo.get(key)
        if was is not None and was[1] == said and now - was[0] < REWRITE_S:
            return False
        if len(self._memo) >= MAX_MEMO:
            self._memo.clear()
        self._memo[key] = (now, said)
        return True

    def _open(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        if conn.execute("PRAGMA user_version").fetchone()[0] != VERSION:
            for statement in SCHEMA:
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version={VERSION}")
        return conn

    @staticmethod
    def _entity(conn, kind: str, key: str, now: float) -> int:
        conn.execute("INSERT INTO entities (kind, key, first, last) VALUES (?, ?, ?, ?) ON CONFLICT (kind, key) DO"
                     " UPDATE SET last = excluded.last", (kind, key, now, now))
        return conn.execute("SELECT id FROM entities WHERE kind = ? AND key = ?", (kind, key)).fetchone()[0]

    @staticmethod
    def _wait(conn, kind: str, key: str, what: str, why: str, left, now: float) -> None:
        conn.execute("INSERT INTO queue (kind, key, what, why, left, first, last) VALUES (?, ?, ?, ?, ?, ?, ?)"
                     " ON CONFLICT (kind, key) DO UPDATE SET what = excluded.what, why = excluded.why,"
                     " left = excluded.left, last = excluded.last, done = NULL",
                     (kind, key, what, why, json.dumps(list(left)), now, now))

    @staticmethod
    def _done(conn, kind: str, key: str, now: float) -> None:
        conn.execute("UPDATE queue SET done = ?, last = ? WHERE kind = ? AND key = ? AND done IS NULL",
                     (now, now, kind, key))

    @staticmethod
    def _estimate(conn, entity: int, now: float) -> None:
        """A router's best place from its claims (the module's docstring)."""
        claims = []
        for source, claim in conn.execute("SELECT source, claim FROM evidence WHERE entity = ?", (entity,)):
            try:
                said = json.loads(claim)
            except ValueError:
                continue
            if isinstance(said, dict) and isinstance(said.get("lat"), (int, float)) and isinstance(
                    said.get("lon"), (int, float)):
                claims.append((source, SOURCES.get(source, (0.1, ""))[0], said))
        if not claims:
            return
        best = None
        for _, _, said in claims:
            near = [(s, w, c) for s, w, c in claims if _km((said["lat"], said["lon"]), (c["lat"], c["lon"])) <= AGREE_KM]
            weights = {}
            for s, w, _ in near:
                weights[s] = max(weights.get(s, 0.0), w)
            confidence = 1.0 - math.prod(1.0 - w for w in weights.values())
            lead = max(near, key=lambda x: x[1])[2]
            if best is None or confidence > best[0]:
                best = (confidence, lead, len(weights))
        confidence, lead, sources = best
        conn.execute("INSERT INTO estimates (entity, lat, lon, label, confidence, sources, at) VALUES (?, ?, ?, ?, ?, ?,"
                     " ?) ON CONFLICT (entity) DO UPDATE SET lat = excluded.lat, lon = excluded.lon, label ="
                     " excluded.label, confidence = excluded.confidence, sources = excluded.sources, at = excluded.at",
                     (entity, lead["lat"], lead["lon"], str(lead.get("label") or ""), round(confidence, 4), sources,
                      now))

    def record(self, routers=(), legs=None, licence: str = "", claims=()) -> bool:
        """One batch, from a tab's ask: `routers` [{"address", "n", "ms", "after", "lat", "lon", "label"}] as the
        routes traced here and the GeoIP file say them (lat None: no place); `legs` {key: (what, why)} as the network
        found them ("" why: on the lines); `licence` the GeoIP file's words; `claims` more sources' [(address, source,
        licence, {"lat", "lon", "label"})]. Only what is new, changed or not written within REWRITE_S is written.
        False when nothing could be written (closed, another system's folder, a file that will not open: `problem`)."""
        now = self.clock()
        with self._lock:
            if self.closed:
                return False
            elsewhere = infrastructure.foreign(self.path.parent)
            if elsewhere:
                self.problem = elsewhere
                return False
            rows = []  # (what to do, its arguments), the fresh ones only
            for r in routers:
                address = str(r.get("address") or "")
                if not address:
                    continue
                if r.get("lat") is not None and r.get("lon") is not None:
                    claim = json.dumps({"lat": round(float(r["lat"]), 4), "lon": round(float(r["lon"]), 4),
                                        "label": str(r.get("label") or "")[:80]}, sort_keys=True)
                    if self._fresh(("geoip", address), claim, now):
                        rows.append(("claim", (address, "geoip", licence or "the GeoIP file's own", claim)))
                elif self._fresh(("place", address), "waiting", now):
                    rows.append(("wait", ("place", address, f"router {address}", "the GeoIP file has no place for it",
                                          PLACE_LEFT)))
                if r.get("ms") is not None:
                    seen = json.dumps({"n": r.get("n"), "after": r.get("after") or "", "ms": round(float(r["ms"]), 1)},
                                      sort_keys=True)
                    if self._fresh(("trace", address, seen), seen, now):
                        rows.append(("claim", (address, "trace", "measured here", seen)))
            for address, source, words, said in claims:
                claim = json.dumps(said, sort_keys=True)
                if self._fresh((source, address), claim, now):
                    rows.append(("claim", (str(address), source, words, claim)))
            for key, (what, why) in (legs or {}).items():
                if self._fresh(("segment", key), why, now):
                    rows.append(("wait", ("segment", key, what, why, SEGMENT_LEFT)) if why
                                else ("done", ("segment", key)))
            if not rows:
                return True
            try:
                conn = self._open()
            except (OSError, sqlite3.Error) as e:
                self.problem = f"{type(e).__name__}: {e}"
                self._memo.clear()  # written again at the next ask
                return False
            try:
                conn.execute("BEGIN")
                touched = set()
                for do, args in rows:
                    if do == "claim":
                        address, source, words, claim = args
                        entity = self._entity(conn, "router", address, now)
                        conn.execute("INSERT INTO evidence (entity, source, licence, claim, first, last) VALUES (?, ?,"
                                     " ?, ?, ?, ?) ON CONFLICT (entity, source, claim) DO UPDATE SET last ="
                                     " excluded.last", (entity, source, words, claim, now, now))
                        if source != "trace":
                            touched.add(entity)
                            self._done(conn, "place", address, now)
                    elif do == "wait":
                        kind, key, what, why, left = args
                        if kind == "place":
                            self._entity(conn, "router", key, now)
                        self._wait(conn, kind, key, what, why, left, now)
                    else:
                        self._done(conn, *args, now)
                for entity in touched:
                    self._estimate(conn, entity, now)
                self.counts = {
                    "routers": conn.execute("SELECT COUNT(*) FROM entities WHERE kind = 'router'").fetchone()[0],
                    "claims": conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
                    "placed": conn.execute("SELECT COUNT(*) FROM estimates").fetchone()[0],
                    "waiting": conn.execute("SELECT COUNT(*) FROM queue WHERE done IS NULL").fetchone()[0]}
                conn.execute("COMMIT")
                self.problem = ""
                return True
            except sqlite3.Error as e:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                self.problem = f"{type(e).__name__}: {e}"
                self._memo.clear()
                return False
            finally:
                conn.close()

    def queue(self, limit: int = 100) -> list[dict]:
        """What waits to be looked up, the longest waiting first: [{"kind", "key", "what", "why", "left", "tries",
        "first", "last"}]."""
        with self._lock:
            if not self.path.exists():
                return []
            conn = sqlite3.connect(str(self.path), timeout=10)
            try:
                rows = conn.execute("SELECT kind, key, what, why, left, tries, first, last FROM queue WHERE done IS"
                                    " NULL ORDER BY first, id LIMIT ?", (int(limit),)).fetchall()
            except sqlite3.Error:
                return []
            finally:
                conn.close()
        return [{"kind": k, "key": key, "what": what, "why": why, "left": json.loads(left), "tries": tries,
                 "first": first, "last": last} for k, key, what, why, left, tries, first, last in rows]

    def estimate(self, address) -> dict | None:
        """A router's best place: {"lat", "lon", "label", "confidence", "sources"}, or None."""
        with self._lock:
            if not self.path.exists():
                return None
            conn = sqlite3.connect(str(self.path), timeout=10)
            try:
                row = conn.execute("SELECT e.lat, e.lon, e.label, e.confidence, e.sources FROM estimates e JOIN"
                                   " entities n ON n.id = e.entity WHERE n.kind = 'router' AND n.key = ?",
                                   (str(address),)).fetchone()
            except sqlite3.Error:
                return None
            finally:
                conn.close()
        return None if row is None else dict(zip(("lat", "lon", "label", "confidence", "sources"), row))
