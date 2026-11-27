"""The infrastructure kept in the plugin's own database (1.104.0, Monday list item 27; the user, 2026-11-23: "Kept here,
from my downloads"): infrastructure.db, SQLite, in the data folder's infrastructure/ (each system's own: a folder on
another system's drive is never read or written from here, as infrastructure.foreign says), filled only by the user's
downloads (infrastructure.install) and read by area, so the globe asks for what it shows.

- `sets`: each data set downloaded, with the words the user accepted and when; `features`: each point and each line
  (a line longer than PIECE vertices kept as pieces of one name, each ending where the next begins), its box and its
  vertices packed as the layers' files pack them (little-endian int32 pairs, longitude and latitude in 1e-5 degrees),
  and a line's coarse copy (thinned to COARSE degrees) for the whole globe's view; `cells`: which features cross which
  1-degree cell, the reads by area; `orbits` and `probes`: the satellites' elements and RIPE Atlas's probes (items 32
  and 28), written with their sets; `answers`: the last answer that was not OK of a set whose maker asks to be left
  alone after one (CelesTrak's), kept until it is downloaded again (infrastructure.held_back and refresh_due read it).
- A set is written in one transaction, its older rows replaced: a write that fails leaves the older copy as it was.
- The file is opened only while a write or a read is made, and closed after each (it can be removed right after, on
  Windows too); no thread, no timer. Thread-safe."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import sqlite3
import sys
import threading
import time
from array import array
from collections.abc import Mapping
from pathlib import Path

from . import infrastructure as infra

FILE = "infrastructure.db"
USER_VERSION = 1
PIECE = 256  # vertices a line's piece holds at most: a cell's read then reads little more than it shows
POINT, LINE, PIECE_KIND = 0, 1, 2  # a feature's kind: a point, a line (its first piece), a line's further piece
COARSE = 0.25  # degrees between a coarse line's kept vertices (the whole globe's view)
SAMPLE = 0.5  # degrees between the points a long segment's cells are found at
CELLS = 360 * 180
TIMEOUT_S = 10.0  # how long a write waits for another's lock
CHUNK = 500  # cells asked in one query of points (1.106.0): within the oldest SQLite's 999 parameters

SCHEMA = """
CREATE TABLE IF NOT EXISTS sets (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, source TEXT NOT NULL, url TEXT NOT NULL,
  licence_name TEXT NOT NULL, licence TEXT NOT NULL, accepted REAL NOT NULL,
  credit_text TEXT NOT NULL, credit_url TEXT NOT NULL, fetched REAL NOT NULL,
  features INTEGER NOT NULL, dropped INTEGER NOT NULL, bytes INTEGER NOT NULL,
  stand_in INTEGER NOT NULL DEFAULT 0, version TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS features (
  id INTEGER PRIMARY KEY, set_id TEXT NOT NULL REFERENCES sets(id) ON DELETE CASCADE,
  layer TEXT NOT NULL, kind INTEGER NOT NULL, name TEXT NOT NULL, sub TEXT NOT NULL,
  w INTEGER NOT NULL, s INTEGER NOT NULL, e INTEGER NOT NULL, n INTEGER NOT NULL,
  count INTEGER NOT NULL, xy BLOB NOT NULL, coarse BLOB);
CREATE INDEX IF NOT EXISTS features_by_layer ON features (layer, set_id);
CREATE TABLE IF NOT EXISTS cells (
  cell INTEGER NOT NULL, feature INTEGER NOT NULL REFERENCES features(id) ON DELETE CASCADE,
  PRIMARY KEY (cell, feature)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cells_by_feature ON cells (feature);
CREATE TABLE IF NOT EXISTS orbits (
  norad INTEGER PRIMARY KEY, set_id TEXT NOT NULL REFERENCES sets(id) ON DELETE CASCADE,
  constellation TEXT NOT NULL, name TEXT NOT NULL, epoch REAL NOT NULL, omm TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS probes (
  id INTEGER PRIMARY KEY, set_id TEXT NOT NULL REFERENCES sets(id) ON DELETE CASCADE,
  lat REAL NOT NULL, lon REAL NOT NULL, country TEXT NOT NULL, asn4 INTEGER, asn6 INTEGER,
  anchor INTEGER NOT NULL, connected INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS imported (file TEXT PRIMARY KEY, stamp TEXT NOT NULL);
"""
# the user, 2026-11-26 (CelesTrak's "Refresh by itself"): a set's last answer that was not OK, by its id (no foreign
# key: a first download that failed has no set yet); made by the writes that use it too, so an older file gains it
ANSWERS = ("CREATE TABLE IF NOT EXISTS answers (set_id TEXT PRIMARY KEY, code INTEGER NOT NULL, at REAL NOT NULL, "
           "said TEXT NOT NULL)")
SET_COLUMNS = ("id", "title", "source", "url", "licence_name", "licence", "accepted", "credit_text", "credit_url",
               "fetched", "features", "dropped", "bytes", "stand_in", "version")


class StoreError(Exception):
    """The database could not be read or written: what was kept before stays."""


def cell_of(lon: float, lat: float) -> int:
    """A place's 1-degree cell: (floor(lat) + 90) * 360 + (floor(lon) + 180), the poles' and the antimeridian's
    edges in the cells beside them."""
    row = min(179, max(0, math.floor(lat) + 90))
    col = min(359, max(0, math.floor(lon) + 180))
    return row * 360 + col


def _unit(lon: float, lat: float) -> tuple[float, float, float]:
    a, b = math.radians(lat), math.radians(lon)
    return math.cos(a) * math.cos(b), math.cos(a) * math.sin(b), math.sin(a)


def _cells(points: list[tuple[float, float]]) -> set[int]:
    """The cells a line's points (lon, lat) and the great circles between them cross: a segment longer than SAMPLE
    degrees is looked at every SAMPLE degrees along its great circle."""
    found = {cell_of(*p) for p in points}
    for (lon0, lat0), (lon1, lat1) in zip(points, points[1:]):
        if abs(lon1 - lon0) <= SAMPLE and abs(lat1 - lat0) <= SAMPLE:
            continue
        p, q = _unit(lon0, lat0), _unit(lon1, lat1)
        dot = max(-1.0, min(1.0, sum(a * b for a, b in zip(p, q))))
        angle = math.acos(dot)
        steps = max(1, math.ceil(math.degrees(angle) / SAMPLE))
        sin = math.sin(angle)
        for i in range(1, steps):
            t = i / steps
            if sin < 1e-9:
                v = p
            else:
                k0, k1 = math.sin((1 - t) * angle) / sin, math.sin(t * angle) / sin
                v = tuple(k0 * a + k1 * b for a, b in zip(p, q))
            found.add(cell_of(math.degrees(math.atan2(v[1], v[0])),
                              math.degrees(math.asin(max(-1.0, min(1.0, v[2]))))))
    return found


def _blob(values) -> bytes:
    xy = array(infra._I32, values)
    if sys.byteorder == "big":
        xy.byteswap()
    return xy.tobytes()


def _ints(blob: bytes) -> array:
    xy = array(infra._I32)
    xy.frombytes(blob)
    if sys.byteorder == "big":
        xy.byteswap()
    return xy


def _thin(points: list[tuple[int, int]], step: int) -> list[tuple[int, int]]:
    out = [points[0]]
    for p in points[1:-1]:
        if abs(p[0] - out[-1][0]) >= step or abs(p[1] - out[-1][1]) >= step:
            out.append(p)
    if points[-1] != out[-1] or len(out) == 1:
        out.append(points[-1])
    return out


def _version(ident: str, fetched: float, count: int) -> str:
    said = f"{ident}|{fetched!r}|{count}|{time.time_ns()}"
    return hashlib.sha1(said.encode("utf-8")).hexdigest()[:12]


def area_of(area) -> tuple[float, float, float, float] | None:
    """An area (west, south, east, north) in degrees as numbers on the globe, west greater than east across the
    antimeridian; None for none. ValueError for one that is not."""
    if area is None:
        return None
    if (not isinstance(area, (list, tuple)) or len(area) != 4
            or any(isinstance(v, bool) or not isinstance(v, (int, float)) or v != v for v in area)):
        raise ValueError("an area is [west, south, east, north] in degrees")
    w, s, e, n = (float(v) for v in area)
    if not (-180 <= w <= 180 and -180 <= e <= 180 and -90 <= s <= n <= 90):
        raise ValueError("an area is [west, south, east, north] in degrees, on the globe")
    return w, s, e, n


def _ranges(area: tuple[float, float, float, float]) -> list[tuple[int, int]]:
    """The cells' ranges (first, last) an area covers, a row of the grid at a time."""
    w, s, e, n = area
    rows = range(min(179, max(0, math.floor(s) + 90)), min(179, max(0, math.floor(n) + 90)) + 1)
    cols = [(cell_of(w, 0) % 360, cell_of(e, 0) % 360)] if w <= e else [(cell_of(w, 0) % 360, 359),
                                                                       (0, cell_of(e, 0) % 360)]
    return [(r * 360 + c0, r * 360 + c1) for r in rows for c0, c1 in cols]


def points_sql(cells: int, pairs: int) -> str:
    """Store.points' query for `cells` cells and `pairs` (layer, set) pairs: (cell, layer, name, sub, xy) of the points
    in them, by cell, LIMIT its last parameter. The review of 1.106.0: it starts from the cells (CROSS JOIN keeps them
    the outer loop, read by their key) and finds each feature by its id; a plain JOIN let SQLite start from
    features_by_layer instead, visiting every feature of the feeding sets for each chunk of cells."""
    fed = " OR ".join("(f.layer = ? AND f.set_id = ?)" for _ in range(pairs))
    return ("SELECT c.cell, f.layer, f.name, f.sub, f.xy FROM cells c CROSS JOIN features f ON f.id = c.feature "
            f"WHERE c.cell IN ({', '.join('?' * cells)}) AND f.kind = {POINT} AND ({fed}) "
            "ORDER BY c.cell, c.feature LIMIT ?")


class Store:
    """The database of a plugin's infrastructure, in `folder` (the data folder's infrastructure/ when not given)."""

    def __init__(self, folder=None, clock=time.time):
        self._given = None if folder is None else Path(folder)
        self.clock = clock
        self._lock = threading.Lock()

    @property
    def folder(self) -> Path:
        return infra._resolved(self._given)

    @property
    def path(self) -> Path:
        return self.folder / FILE

    def elsewhere(self) -> str:
        return infra.foreign(self.folder)

    def exists(self) -> bool:
        return not self.elsewhere() and self.path.is_file()

    def _open(self, write: bool) -> sqlite3.Connection:
        why = self.elsewhere()
        if why:
            raise ValueError(why)
        if write:
            self.folder.mkdir(parents=True, exist_ok=True)
        elif not self.path.is_file():
            raise FileNotFoundError(self.path)
        con = sqlite3.connect(self.path, timeout=TIMEOUT_S, isolation_level=None)
        try:
            con.execute("PRAGMA foreign_keys = ON")
            if write:
                con.execute("PRAGMA journal_mode = WAL")
                if con.execute("PRAGMA user_version").fetchone()[0] == 0:
                    con.executescript(SCHEMA)
                    con.execute(ANSWERS)
                    con.execute(f"PRAGMA user_version = {USER_VERSION}")
        except BaseException:
            con.close()
            raise
        return con

    def _read(self, work):
        with self._lock:
            try:
                con = self._open(write=False)
            except FileNotFoundError:
                return None
            except sqlite3.Error as e:
                raise StoreError(f"{self.path} could not be read: {e}") from None
            try:
                return work(con)
            except sqlite3.Error as e:
                raise StoreError(f"{self.path} could not be read: {e}") from None
            finally:
                con.close()

    def _write(self, work):
        with self._lock:
            try:
                con = self._open(write=True)
            except sqlite3.Error as e:
                raise StoreError(f"{self.path} could not be opened: {e}") from None
            try:
                con.execute("BEGIN IMMEDIATE")
                try:
                    out = work(con)
                except BaseException:
                    con.execute("ROLLBACK")
                    raise
                con.execute("COMMIT")
                return out
            except (sqlite3.Error, ValueError, TypeError, OverflowError) as e:  # a row that does not fit: none kept
                raise StoreError(f"{self.path} could not be written: {e}") from None
            finally:
                con.close()

    # -- writes ---------------------------------------------------------------------------------------------------
    def put(self, dataset, features: Mapping, fetched: float, accepted: float | None = None, size: int = 0,
            orbits=(), probes=(), imported: tuple[str, str] | None = None) -> dict:
        """One data set's features (infrastructure.parse's) written in one transaction, its older rows replaced (a
        write that fails leaves them): {"set", "features", "version", "counts"}. `orbits`: rows (norad, constellation,
        name, epoch, omm dict); `probes`: rows (id, lat, lon, country, asn4, asn6, anchor, connected); `imported`:
        (an older file's name, its stamp), noted with it so that file is read in once alone."""
        dataset = infra.DataSet.of(dataset)
        layers = features.get("layers") if isinstance(features, Mapping) else None
        layers = layers if isinstance(layers, Mapping) else {}
        known = {name for name, *_ in infra.LAYERS}
        rows = []  # (layer, kind, name, sub, box, count, xy, coarse, cells)
        for layer, got in layers.items():
            if layer not in known or not isinstance(got, Mapping):
                continue
            for point in got.get("points") or ():
                x, y = round(point[0] * infra.SCALE), round(point[1] * infra.SCALE)
                rows.append((layer, 0, infra._name(point[2]) if len(point) > 2 else "",
                             infra._name(point[3]) if len(point) > 3 else "", (x, y, x, y), 1, _blob((x, y)), None,
                             {cell_of(point[0], point[1])}))
            for vertices, name in got.get("lines") or ():
                spots = [(round(lon * infra.SCALE), round(lat * infra.SCALE)) for lon, lat in vertices]
                for at in range(0, max(1, len(spots) - 1), PIECE - 1):
                    piece = spots[at:at + PIECE]
                    if len(piece) < 2:
                        break
                    xs, ys = [p[0] for p in piece], [p[1] for p in piece]
                    coarse = _thin(piece, round(COARSE * infra.SCALE))
                    # the review: a line's first piece is its line (kind LINE), each further one a piece (PIECE_KIND)
                    # whose count leaves out the vertex it shares with the one before, so the line's vertices are
                    # counted as they were kept, once each
                    first = at == 0
                    rows.append((layer, LINE if first else PIECE_KIND, infra._name(name), "",
                                 (min(xs), min(ys), max(xs), max(ys)), len(piece) if first else len(piece) - 1,
                                 _blob(v for p in piece for v in p), _blob(v for p in coarse for v in p),
                                 _cells([(x / infra.SCALE, y / infra.SCALE) for x, y in piece])))
        count = int(features.get("features") or len(rows)) if isinstance(features, Mapping) else len(rows)
        dropped = features.get("dropped") if isinstance(features, Mapping) else 0
        dropped = sum(int(n) for n in dropped.values()) if isinstance(dropped, Mapping) else int(dropped or 0)
        version = _version(dataset.id, fetched, count)
        accepted = self.clock() if accepted is None else accepted

        def work(con):
            con.execute("DELETE FROM sets WHERE id = ?", (dataset.id,))
            con.execute(ANSWERS)
            con.execute("DELETE FROM answers WHERE set_id = ?", (dataset.id,))  # downloaded: what failed before is past
            con.execute(f"INSERT INTO sets ({', '.join(SET_COLUMNS)}) VALUES ({', '.join('?' * len(SET_COLUMNS))})",
                        (dataset.id, dataset.title, dataset.source, dataset.url, dataset.licence_name, dataset.licence,
                         float(accepted), dataset.credit["text"], dataset.credit["url"], float(fetched), count,
                         dropped, int(size), int(dataset.stand_in), version))
            for layer, kind, name, sub, (w, s, e, n), many, xy, coarse, cells in rows:
                cur = con.execute("INSERT INTO features (set_id, layer, kind, name, sub, w, s, e, n, count, xy, coarse)"
                                  " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                  (dataset.id, layer, kind, name, sub, w, s, e, n, many, xy, coarse))
                con.executemany("INSERT OR IGNORE INTO cells (cell, feature) VALUES (?, ?)",
                                [(c, cur.lastrowid) for c in cells])
            con.executemany("INSERT OR REPLACE INTO orbits (norad, set_id, constellation, name, epoch, omm) VALUES "
                            "(?, ?, ?, ?, ?, ?)",
                            [(int(r[0]), dataset.id, r[1], r[2], float(r[3]), json.dumps(r[4], separators=(",", ":")))
                             for r in orbits])
            con.executemany("INSERT OR REPLACE INTO probes (id, set_id, lat, lon, country, asn4, asn6, anchor, "
                            "connected) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            [(int(r[0]), dataset.id, *r[1:]) for r in probes])
            if imported is not None:
                con.execute("INSERT OR REPLACE INTO imported (file, stamp) VALUES (?, ?)", imported)
        self._write(work)
        return {"set": dataset.id, "features": count, "version": version, "counts": self.counts(dataset.id)}

    def remove(self, set_id: str) -> bool:
        """A set's rows removed (its features' cells with them): whether it was there."""
        if not self.exists():
            return False
        def work(con):
            con.execute(ANSWERS)
            con.execute("DELETE FROM answers WHERE set_id = ?", (set_id,))
            return con.execute("DELETE FROM sets WHERE id = ?", (set_id,)).rowcount
        return bool(self._write(work))

    def answered(self, set_id: str, code: int, at: float, said: str) -> None:
        """A set's answer that was not OK kept (the HTTP code, 0 for none: no answer came; when, seconds since 1970;
        its words), in place of any older one: until it is downloaded again, it is not refreshed by itself, and after
        a 500 or 503 nothing is asked of its host for its `pause` (infrastructure.held_back)."""
        def work(con):
            con.execute(ANSWERS)
            con.execute("INSERT OR REPLACE INTO answers (set_id, code, at, said) VALUES (?, ?, ?, ?)",
                        (str(set_id), int(code or 0), float(at), str(said)[:infra.TEXT]))
        self._write(work)

    # -- reads ----------------------------------------------------------------------------------------------------
    def sets(self) -> dict[str, dict]:
        """Each set kept, by its id: its columns (no geometry is read)."""
        def work(con):
            return {row[0]: dict(zip(SET_COLUMNS, row))
                    for row in con.execute(f"SELECT {', '.join(SET_COLUMNS)} FROM sets")}
        return self._read(work) or {}

    def answers(self) -> dict[str, dict]:
        """Each set's last answer that was not OK, by its id: {"code", "at", "said"}; none in a database without the
        table yet."""
        def work(con):
            try:
                rows = con.execute("SELECT set_id, code, at, said FROM answers").fetchall()
            except sqlite3.OperationalError:  # no such table: an older file, nothing kept
                return {}
            return {r[0]: {"code": r[1], "at": r[2], "said": r[3]} for r in rows}
        return self._read(work) or {}

    def imported(self) -> dict[str, str]:
        """The older files read in already, and their stamps: each is read in once alone."""
        return self._read(lambda con: dict(con.execute("SELECT file, stamp FROM imported"))) or {}

    def stamp(self) -> tuple:
        """The database's files' sizes and times: what changes with every write."""
        out = []
        for name in (FILE, FILE + "-wal"):
            try:
                found = (self.folder / name).stat()
                out.append((found.st_size, found.st_mtime_ns))
            except OSError:
                out.append(None)
        return tuple(out)

    def counts(self, set_id: str | None = None) -> dict:
        """Each set's layers' counts: {set: {layer: {"points", "lines", "vertices"}}}, or one set's alone: a line kept
        as pieces is one line, and the vertex its pieces share is counted once, as the parse kept it."""
        def work(con):
            out: dict = {}
            sql = "SELECT set_id, layer, kind, COUNT(*), SUM(count) FROM features"
            args: tuple = ()
            if set_id is not None:
                sql, args = sql + " WHERE set_id = ?", (set_id,)
            for sid, layer, kind, n, vertices in con.execute(sql + " GROUP BY set_id, layer, kind", args):
                entry = out.setdefault(sid, {}).setdefault(layer, {"points": 0, "lines": 0, "vertices": 0})
                if kind == POINT:
                    entry["points"] += n
                else:
                    entry["lines"] += n if kind == LINE else 0
                    entry["vertices"] += int(vertices or 0)
            return out
        found = self._read(work) or {}
        return found.get(set_id, {}) if set_id is not None else found

    def layer(self, layer_id: str, sets=None, area=None, coarse: bool = False) -> dict:
        """One layer's features as the page draws them, by set, in `sets`' order (each set's id; all when None):
        {set_id: {"points"?: {"n", "xy", "names", "subs"}, "lines"?: {"n", "offsets", "xy", "names"}, "cut": bool}},
        `xy` and `offsets` packed as infrastructure.pack packs them. `area` (west, south, east, north; across the
        antimeridian when west is greater): only the features crossing its cells; `coarse`: the lines' coarse copies.
        At most infrastructure.MAX_POINTS points and MAX_VERTICES vertices in all ("cut" says where more were)."""
        box = area_of(area)

        def work(con):
            conditions, args = ["f.layer = ?"], [layer_id]
            if box is not None:
                ranges = _ranges(box)
                conditions.append("f.id IN (SELECT feature FROM cells WHERE "
                                  + " OR ".join("cell BETWEEN ? AND ?" for _ in ranges) + ")")
                args += [v for r in ranges for v in r]
            if sets is not None:
                ids = list(sets)
                if not ids:
                    return {}
                conditions.append(f"f.set_id IN ({', '.join('?' * len(ids))})")
                args += ids
            sql = ("SELECT f.set_id, f.kind, f.name, f.sub, f.count, "
                   + ("COALESCE(f.coarse, f.xy)" if coarse else "f.xy")
                   + " FROM features f WHERE " + " AND ".join(conditions) + " ORDER BY f.set_id, f.id")
            out: dict = {}
            points = vertices = 0
            for sid, kind, name, sub, count, blob in con.execute(sql, args):
                part = out.setdefault(sid, {"cut": False, "_p": [], "_l": []})
                if kind == 0:
                    if points >= infra.MAX_POINTS:
                        part["cut"] = True
                        continue
                    points += 1
                    part["_p"].append((blob, name, sub))
                else:  # a piece's vertex shared with the one before is not counted again (its count leaves it out)
                    n = min(int(count), len(blob) // 8)
                    if vertices + n > infra.MAX_VERTICES:
                        part["cut"] = True
                        continue
                    vertices += n
                    part["_l"].append((blob, name))
            for sid, part in out.items():
                ps, ls = part.pop("_p"), part.pop("_l")
                if ps:
                    part["points"] = {"n": len(ps), "xy": base64.b64encode(b"".join(b for b, _, _ in ps)).decode(),
                                      "names": [n for _, n, _ in ps], "subs": [s for _, _, s in ps]}
                if ls:
                    offsets, at = array(infra._U32, [0]), 0
                    for b, _ in ls:
                        at += len(b) // 8
                        offsets.append(at)
                    part["lines"] = {"n": len(ls), "offsets": infra._packed(offsets),
                                     "xy": base64.b64encode(b"".join(b for b, _ in ls)).decode(),
                                     "names": [n for _, n in ls]}
            if sets is not None:
                return {sid: out[sid] for sid in sets if sid in out}
            return out
        return self._read(work) or {}

    def points(self, layers: Mapping, cells, most: int) -> tuple[list[tuple[str, float, float, str, str]], int | None]:
        """The points of some layers in some cells (1.106.0, Monday list item 27: the hubs a route passes): `layers`
        {layer: the ids of the sets feeding it}, `cells` 1-degree cells (cell_of); (the points as (layer, lon, lat,
        name, sub), `most` at most, by cell and then in the features' order; and where a read was cut, the first cell
        not read whole, else None). The review of 1.106.0: one more is asked than kept, so a cut is known, and every
        cell before the one it fell in was read whole. Read through the cells' index alone, CHUNK cells a query
        (points_sql): no layer is read whole, and a point is in one cell, so none comes twice."""
        cells = sorted({int(c) for c in cells if 0 <= int(c) < CELLS})
        pairs = [(str(layer), str(sid)) for layer, sids in layers.items() for sid in sids]
        if not cells or not pairs:
            return [], None
        if most <= 0:
            return [], cells[0]

        def work(con):
            out: list = []
            taken = 0  # rows read, a malformed one too: what the LIMIT counts
            for at in range(0, len(cells), CHUNK):
                chunk = cells[at:at + CHUNK]
                rows = con.execute(points_sql(len(chunk), len(pairs)),
                                   [*chunk, *(v for p in pairs for v in p), most - taken + 1])
                for cell, layer, name, sub, blob in rows:
                    if taken >= most:  # one more than kept: cut in this cell
                        return out, cell
                    taken += 1
                    xy = _ints(blob)
                    if len(xy) >= 2:
                        out.append((layer, xy[0] / infra.SCALE, xy[1] / infra.SCALE, name, sub))
            return out, None
        return self._read(work) or ([], None)

    def orbits(self, constellation: str | None = None) -> list[dict]:
        """The satellites' elements kept (item 32): [{"norad", "set", "constellation", "name", "epoch", "omm"}]."""
        def work(con):
            sql, args = "SELECT norad, set_id, constellation, name, epoch, omm FROM orbits", ()
            if constellation is not None:
                sql, args = sql + " WHERE constellation = ?", (constellation,)
            return [{"norad": r[0], "set": r[1], "constellation": r[2], "name": r[3], "epoch": r[4],
                     "omm": json.loads(r[5])} for r in con.execute(sql + " ORDER BY norad", args)]
        return self._read(work) or []

    def probes(self, anchors: bool = False) -> list[dict]:
        """RIPE Atlas's probes kept (item 28): [{"id", "lat", "lon", "country", "asn4", "asn6", "anchor",
        "connected"}], the anchors alone when asked."""
        def work(con):
            sql = "SELECT id, lat, lon, country, asn4, asn6, anchor, connected FROM probes"
            if anchors:
                sql += " WHERE anchor = 1"
            keys = ("id", "lat", "lon", "country", "asn4", "asn6", "anchor", "connected")
            return [dict(zip(keys, r)) for r in con.execute(sql + " ORDER BY id")]
        return self._read(work) or []

    def close(self) -> None:
        """Nothing is held open between calls: kept for the callers' symmetry."""
