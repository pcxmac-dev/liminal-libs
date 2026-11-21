"""The physical network under the routes of the firewalls' World Wide Web globe, and the routes drawn over it as a heat
map (1.69.0; the user, 2026-11-20: "so for the routes, they should try to mirror their physical routing on the map, ie
undersea cables, fiber runs, etc... also, they should look like a heat map, but the actual route between pt a and pt b,
doesn't change so more traffic over this and that, the brighter it gets, lets keep grey scale to white").

- The graph (Graph.of): the lines of the installed infrastructure layers that have them (LINES: submarine cables,
  backbones, telecom lines on land), read from this machine's files (infrastructure.Index.layer). Their points are
  merged by place on the files' own grid (GRID degrees: infrastructure.STEP) into vertices; two points that follow on
  a line are an edge, its length their great circle in km. Each line's end is joined to the nearest point within
  JOIN_KM of a line not connected to it (a cable to the land line at its landing, two backbones in one city), and a
  loose end to the nearest point within it of any other line. A run of a line with no branch is one edge between its
  ends (junctions): the ways are searched between junctions and drawn through every point of their runs.
- A leg of a route (home, its placed hops, the host: each a GeoIP point) is snapped to the graph: the nearest junction
  to each of its ends within SNAP_KM, and the shortest way between them (A*, the great circle to the far end its
  heuristic), taken when the whole of it, the snaps included, is no longer than DETOUR times the leg's great circle;
  else, and where no layer is installed, the leg is its great circle. A leg shorter than CITY_KM is one city's: its
  great circle, never snapped. A hop met by the network on both its legs is passed through at its junction. The ways
  are cached by their two junctions (MAX_WAYS) and the snaps by their points (MAX_SNAPS), with the graph they are on.
- The heat (Network.onto): each stretch a route uses gains its place's traffic once, however often the route passes
  it (the place's bytes where the capture counted any on the page, else its connections): the edges of the graph by
  edge, the great circles by their ends. The page gets them as runs of one weight each, the heaviest kept first,
  MAX_RUNS runs and MAX_POINTS points at most: globe["heat"] = [{"points": [[lat, lon], ...], "w"}], globe["heat_by"]
  ("bytes" or "connections") and each placed origin's "last" ([lat, lon]: where its route leaves the network, else its
  last hop, else home), where the stretch its light travels to it begins.
- Nothing runs when unused: the graph is built when a page asks for the heat and its layers' versions changed, held
  until they change again or the plugin is detached (Network.clear); no thread, no timer, nothing read but the files."""
from __future__ import annotations

import base64
import heapq
import math
import threading
from collections import OrderedDict
from collections.abc import Mapping

import numpy as np

LINES = ("cables", "backbones", "lines")  # the infrastructure layers whose lines a route may follow
GRID = 0.02  # degrees: points on one cell of this grid are one vertex (infrastructure.STEP)
SCALE = 100_000  # a file's coordinates are in 1e-5 degrees (infrastructure.SCALE)
JOIN_KM = 25.0  # a line's end is joined to a point of another line this near
SNAP_KM = 150.0  # a leg's end is snapped to a junction this near, at most
DETOUR = 2.5  # a leg follows the network when its way there is no longer than this times its great circle
CITY_KM = 30.0  # a leg shorter than this is within one city: its great circle
TINY_KM = 1.0  # a stretch shorter than this is drawn as none
MAX_EXPAND = 50_000  # junctions a way's search looks on from, at most: past this, the leg is its great circle
MAX_WAYS = 4096  # ways kept, the least recently asked let go first
MAX_SNAPS = 4096  # snaps kept, likewise
MAX_RUNS = 4000  # runs of heat on a page, the heaviest kept
MAX_POINTS = 200_000  # their points in all
EARTH_KM = 6371.0088  # the mean radius
KM_PER_DEGREE = math.pi * EARTH_KM / 180
SNAP_CELL = 1.0  # degrees: the snaps' search grid
PAIRS = 1 << 18  # pairs of a line's end and a point near it weighed at once (the joins'), some 40 MB


def _km(lat1, lon1, lat2, lon2):
    """The great circle between points given in degrees, in km (numbers or numpy arrays)."""
    p1, p2 = np.radians(lat1), np.radians(lat2)
    h = np.sin((p2 - p1) / 2) ** 2 + np.cos(p1) * np.cos(p2) * np.sin(np.radians(np.subtract(lon2, lon1)) / 2) ** 2
    return 2 * EARTH_KM * np.arcsin(np.sqrt(np.clip(h, 0.0, 1.0)))


def km(a, b) -> float:
    """The great circle between two places (lat, lon) in degrees, in km."""
    p1, p2 = math.radians(a[0]), math.radians(b[0])
    h = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(b[1] - a[1]) / 2) ** 2
    return 2 * EARTH_KM * math.asin(min(1.0, math.sqrt(h)))


class _Cells:
    """Points on a grid of `cell` degrees, sorted by their cell, for those near a place: one search a row of cells."""

    def __init__(self, lat: np.ndarray, lon: np.ndarray, cell: float):
        self.cell, self.cols = cell, round(360 / cell)
        key = np.floor(lat / cell).astype(np.int64) * self.cols + np.floor(lon / cell).astype(np.int64) % self.cols
        self.order = np.argsort(key, kind="stable")
        self.keys = key[self.order]

    def near(self, lat: float, lon: float, within: float) -> np.ndarray:
        """The indices of the points in the cells that reach within `within` km of (lat, lon): those and a few more."""
        c, dlat = self.cell, within / KM_PER_DEGREE
        cos = math.cos(math.radians(min(90.0, abs(lat) + dlat)))
        if cos < 1e-6 or within / (KM_PER_DEGREE * cos) >= 180:
            spans = [(0, self.cols - 1)]
        else:
            dlon = within / (KM_PER_DEGREE * cos)
            c0, c1 = math.floor((lon - dlon) / c), math.floor((lon + dlon) / c)
            if c1 - c0 + 1 >= self.cols:
                spans = [(0, self.cols - 1)]
            else:
                c0, c1 = c0 % self.cols, c1 % self.cols
                spans = [(c0, c1)] if c0 <= c1 else [(0, c1), (c0, self.cols - 1)]
        found = []
        for row in range(math.floor((lat - dlat) / c), math.floor((lat + dlat) / c) + 1):
            for a, b in spans:
                lo = int(np.searchsorted(self.keys, row * self.cols + a, "left"))
                hi = int(np.searchsorted(self.keys, row * self.cols + b, "right"))
                if hi > lo:
                    found.append(self.order[lo:hi])
        return np.concatenate(found) if found else np.empty(0, np.int64)


def _degrees(u: np.ndarray, v: np.ndarray, count: int) -> np.ndarray:
    """Each vertex's neighbours, by the edges (u, v) given, each two vertices counted once."""
    lo, hi = np.minimum(u, v), np.maximum(u, v)
    pairs = np.unique(lo * count + hi)
    return np.bincount(pairs // count, minlength=count) + np.bincount(pairs % count, minlength=count)


def _pieces(inv, line, start, end, degree) -> tuple[np.ndarray, np.ndarray]:
    """The runs of the lines between their ends and the junctions on them (a vertex of other than two neighbours):
    each run's first and last point, in the points' order."""
    cut = degree[inv] != 2
    cut[start] = True
    cut[end - 1] = True
    at = np.flatnonzero(cut)
    same = line[at[:-1]] == line[at[1:]]
    return at[:-1][same], at[1:][same]


def _components(inv, p0, p1, count: int) -> np.ndarray:
    """Each vertex's part of the network: the vertices one can go between along the lines share one number."""
    n = len(p0)
    ends, idx = np.unique(np.concatenate((inv[p0], inv[p1])), return_inverse=True)
    idx = idx.reshape(-1)
    parent = list(range(len(ends)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for x, y in zip(idx[:n].tolist(), idx[n:].tolist()):
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry
    root = np.array([find(x) for x in range(len(ends))], dtype=np.int64)
    piece = np.searchsorted(p0, np.arange(len(inv)), side="right") - 1  # each point's run: the last begun by it
    out = np.full(count, -1, dtype=np.int64)
    out[inv] = root[idx[:n]][np.maximum(piece, 0)]
    return out


def _nearest_each(who: np.ndarray, what: np.ndarray, d: np.ndarray) -> np.ndarray:
    """Of pairs (who, what) at distances d, the index of each `who`'s nearest pair."""
    order = np.lexsort((d, who))
    first = np.ones(len(order), dtype=bool)
    first[1:] = who[order][1:] != who[order][:-1]
    return order[first]


def _joins(inv, line, start, end, vlat, vlon, vline, degree, part) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """The joins at the lines' ends (the module's docstring): (from, to, km), vertices. Every end at once: the points
    on a grid of cubes on the unit sphere as wide as JOIN_KM, each end against the points of the 27 cubes round its
    own, as many ends at a time as have PAIRS of them (one end at least)."""
    at = np.concatenate((start, end - 1))
    ends, first = np.unique(inv[at], return_index=True)
    eline = line[at[first]]  # an end's line: the first that ends there
    p, q = np.radians(vlat), np.radians(vlon)
    xyz = np.column_stack((np.cos(p) * np.cos(q), np.cos(p) * np.sin(q), np.sin(p)))
    side = JOIN_KM / EARTH_KM  # a chord is shorter than its arc: a point within JOIN_KM is in a cube next to the end's
    cube = np.floor(xyz / side).astype(np.int64)
    span = int(cube.max()) - int(cube.min()) + 3
    low = int(cube.min()) - 1

    def keyed(c: np.ndarray) -> np.ndarray:
        c = c - low
        return (c[..., 0] * span + c[..., 1]) * span + c[..., 2]
    key = keyed(cube)
    order = np.argsort(key, kind="stable")
    keys = key[order]
    offsets = np.array([(x, y, z) for x in (-1, 0, 1) for y in (-1, 0, 1) for z in (-1, 0, 1)], dtype=np.int64)
    around = keyed(cube[ends][:, None, :] + offsets[None, :, :])  # each end's 27 cubes
    los, his = np.searchsorted(keys, around, "left"), np.searchsorted(keys, around, "right")
    upto = np.cumsum((his - los).sum(axis=1))  # the pairs of the ends up to each
    ju, jv, jkm = [], [], []
    b0 = 0
    while b0 < len(ends):
        b1 = max(b0 + 1, int(np.searchsorted(upto, (upto[b0 - 1] if b0 else 0) + PAIRS, "right")))
        mine = np.arange(b0, min(b1, len(ends)))
        b0 = mine[-1] + 1
        lo, hi = los[mine].reshape(-1), his[mine].reshape(-1)
        n = hi - lo
        if not n.sum():
            continue
        who = np.repeat(np.repeat(mine, len(offsets)), n)
        what = order[np.repeat(lo, n) + np.arange(n.sum()) - np.repeat(np.cumsum(n) - n, n)]
        v = ends[who]
        d = 2 * EARTH_KM * np.arcsin(np.clip(np.linalg.norm(xyz[v] - xyz[what], axis=1) / 2, 0.0, 1.0))
        near = (d <= JOIN_KM) & (what != v)
        apart = near & (part[what] != part[v])  # a line not connected to this one
        loose = near & (degree[v] == 1) & (vline[what] != eline[who])  # a loose end: any other line's point
        for mask in (apart, loose):
            sel = np.flatnonzero(mask)
            if sel.size:
                sel = sel[_nearest_each(who[sel], what[sel], d[sel])]
                ju.append(v[sel])
                jv.append(what[sel])
                jkm.append(d[sel])
    if not ju:
        return np.empty(0, dtype=np.int64), np.empty(0, dtype=np.int64), np.empty(0, dtype=float)
    return np.concatenate(ju), np.concatenate(jv), np.concatenate(jkm)


class Graph:
    """The lines of the infrastructure layers as one graph (the module's docstring): junctions joined by edges, each a
    run of a line's points with no branch between its ends, or a join. Made by of(); read-only once made, but for the
    ways and snaps found on it, kept with it (Network)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._ways: OrderedDict = OrderedDict()
        self._snaps: OrderedDict = OrderedDict()

    @classmethod
    def of(cls, parts) -> "Graph | None":
        """The graph of lines given as the files keep them: each part (xy, offsets), `xy` the points as int32 pairs
        (longitude, latitude, in 1e-5 degrees), `offsets` where each line begins in them and where the last one ends.
        A part whose offsets do not read is passed over, a line of fewer than two points too; None when none is left."""
        lons, lats, sizes = [], [], []
        for xy, offsets in parts:
            xy, off = np.asarray(xy, dtype=np.int64), np.asarray(offsets, dtype=np.int64)
            if xy.ndim != 1 or xy.size % 2 or off.ndim != 1 or off.size < 2:
                continue
            xy = xy.reshape(-1, 2)
            n = np.diff(off)
            if off[0] != 0 or off[-1] != len(xy) or (n < 0).any():
                continue
            keep = n >= 2
            if keep.any():
                points = np.repeat(keep, n)
                lons.append(xy[points, 0])
                lats.append(xy[points, 1])
                sizes.append(n[keep])
        if not sizes:
            return None
        lon_i = np.clip(np.concatenate(lons), -180 * SCALE, 180 * SCALE)
        lat_i = np.clip(np.concatenate(lats), -90 * SCALE, 90 * SCALE)
        size = np.concatenate(sizes)
        end = np.cumsum(size)
        start = end - size
        step, cols = round(GRID * SCALE), round(360 / GRID)
        key = np.rint(lat_i / step).astype(np.int64) * cols + np.rint(lon_i / step).astype(np.int64) % cols
        _, first, inv = np.unique(key, return_index=True, return_inverse=True)
        inv = inv.reshape(-1)
        vlat, vlon, count = lat_i[first] / SCALE, lon_i[first] / SCALE, len(first)
        line = np.repeat(np.arange(len(size)), size)
        a, b = inv[:-1], inv[1:]
        seg = (line[:-1] == line[1:]) & (a != b)
        seg_km = np.zeros(len(a))
        seg_km[seg] = _km(vlat[a[seg]], vlon[a[seg]], vlat[b[seg]], vlon[b[seg]])
        along = np.concatenate(([0.0], np.cumsum(seg_km)))  # km from the first point, the lines end to end
        su, sv = a[seg], b[seg]
        degree = _degrees(su, sv, count)
        p0, p1 = _pieces(inv, line, start, end, degree)
        ju, jv, jkm = _joins(inv, line, start, end, vlat, vlon, line[first], degree, _components(inv, p0, p1, count))
        p0, p1 = _pieces(inv, line, start, end, _degrees(np.concatenate((su, ju)), np.concatenate((sv, jv)), count))
        eu, ev = np.concatenate((inv[p0], ju)), np.concatenate((inv[p1], jv))
        ekm = np.concatenate((along[p1] - along[p0], jkm))
        ea, eb = np.concatenate((p0, ju)), np.concatenate((p1, jv))  # a run's first and last point; a join's vertices
        joined = np.concatenate((np.zeros(len(p0), dtype=bool), np.ones(len(ju), dtype=bool)))
        pair = np.minimum(eu, ev) * count + np.maximum(eu, ev)
        order = np.lexsort((ekm, pair))  # of the edges between two vertices, the shortest kept
        order = order[eu[order] != ev[order]]
        keep = np.ones(len(order), dtype=bool)
        keep[1:] = pair[order][1:] != pair[order][:-1]
        order = order[keep]
        if not len(order):
            return None
        eu, ev, ekm, ea, eb, joined = (x[order] for x in (eu, ev, ekm, ea, eb, joined))
        nodes, idx = np.unique(np.concatenate((eu, ev)), return_inverse=True)
        idx = idx.reshape(-1)
        edges = len(eu)
        nu, nv = idx[:edges], idx[edges:]
        src = np.concatenate((nu, nv))
        arcs = np.argsort(src, kind="stable")
        g = cls()
        g.inv, g.vlat, g.vlon = inv.astype(np.int32), vlat, vlon
        g.ea, g.eb, g.joined = ea, eb, joined
        g.eu, g.ev, g.ekm = nu.tolist(), nv.tolist(), ekm.tolist()
        g.nlat, g.nlon = vlat[nodes], vlon[nodes]
        g._rlat, g._rlon = np.radians(g.nlat).tolist(), np.radians(g.nlon).tolist()
        g._clat = np.cos(np.radians(g.nlat)).tolist()
        g._start = np.searchsorted(src[arcs], np.arange(len(nodes) + 1)).tolist()
        g._dst = np.concatenate((nv, nu))[arcs].tolist()
        g._edge = np.concatenate((np.arange(edges), np.arange(edges)))[arcs].tolist()
        g._akm = [g.ekm[e] for e in g._edge]
        g._cells = _Cells(g.nlat, g.nlon, SNAP_CELL)
        g.points, g.vertices, g.joins = len(inv), count, int(joined.sum())
        return g

    @property
    def nodes(self) -> int:
        return len(self._rlat)

    @property
    def edges(self) -> int:
        return len(self.eu)

    def place(self, n: int) -> tuple[float, float]:
        """Junction n's place, (lat, lon)."""
        return float(self.nlat[n]), float(self.nlon[n])

    def nearest(self, lat: float, lon: float, within: float = SNAP_KM) -> tuple[int, float] | None:
        """The junction nearest (lat, lon) within `within` km, and how far it is; None without one."""
        near = self._cells.near(lat, lon, within)
        if not near.size:
            return None
        d = _km(lat, lon, self.nlat[near], self.nlon[near])
        j = int(np.argmin(d))
        return (int(near[j]), float(d[j])) if d[j] <= within else None

    def way(self, a: int, b: int, limit: float) -> tuple[float, list[tuple[int, int]]] | None:
        """The shortest way from junction a to junction b, if one is no longer than `limit` km: (its km, [(edge, the
        junction it is gone along from), ...]). None without one, or when the search looked on from more than MAX_EXPAND
        junctions (A*: the great circle to b never overstates what is left, so what is cut off by the limit is none)."""
        if a == b:
            return 0.0, []
        rlat, rlon, clat = self._rlat, self._rlon, self._clat
        glat, glon, gcos = rlat[b], rlon[b], clat[b]
        sin, asin, sqrt = math.sin, math.asin, math.sqrt

        def h(n: int) -> float:
            x = sin((rlat[n] - glat) / 2) ** 2 + clat[n] * gcos * sin((rlon[n] - glon) / 2) ** 2
            return 2 * EARTH_KM * asin(min(1.0, sqrt(x)))
        if h(a) > limit:
            return None
        start, dst, akm, edge = self._start, self._dst, self._akm, self._edge
        best, came, heap, looked = {a: 0.0}, {}, [(h(a), 0.0, a)], 0
        while heap:
            _, g, n = heapq.heappop(heap)
            if g > best.get(n, math.inf):
                continue
            if n == b:
                break
            looked += 1
            if looked > MAX_EXPAND:
                return None
            for arc in range(start[n], start[n + 1]):
                m, ng = dst[arc], g + akm[arc]
                if ng >= best.get(m, math.inf):
                    continue
                f = ng + h(m)
                if f > limit:
                    continue
                best[m], came[m] = ng, arc
                heapq.heappush(heap, (f, ng, m))
        else:
            return None
        steps, n = [], b
        while n != a:
            e = edge[came[n]]
            n = self.eu[e] if self.ev[e] == n else self.ev[e]
            steps.append((e, n))
        steps.reverse()
        return best[b], steps

    def line(self, e: int, at: int) -> list[tuple[float, float]]:
        """Edge e's points, (lat, lon), from its end at junction `at`."""
        verts = (np.array([self.ea[e], self.eb[e]]) if self.joined[e]
                 else self.inv[int(self.ea[e]):int(self.eb[e]) + 1])
        keep = np.ones(len(verts), dtype=bool)
        keep[1:] = verts[1:] != verts[:-1]
        verts = verts[keep]
        points = list(zip(self.vlat[verts].tolist(), self.vlon[verts].tolist()))
        return points if at == self.eu[e] else points[::-1]

    def runs(self, weights: Mapping[int, float]) -> list[tuple[list[tuple[float, float]], float]]:
        """The edges weighed (edge: weight) as runs: each run goes on through a junction where its edge meets one other
        weighed edge alone, of the same weight; as (its points, its weight), the heaviest first."""
        at: dict[int, list[int]] = {}
        for e in weights:
            at.setdefault(self.eu[e], []).append(e)
            at.setdefault(self.ev[e], []).append(e)

        def onward(e: int, n: int) -> int | None:
            es = at[n]
            if len(es) != 2:
                return None
            o = es[1] if es[0] == e else es[0]
            return o if o != e and weights[o] == weights[e] else None

        def across(e: int, n: int) -> int:
            return self.ev[e] if self.eu[e] == n else self.eu[e]
        done, out = set(), []
        for e0 in sorted(weights, key=lambda e: (-weights[e], e)):
            if e0 in done:
                continue
            e, n = e0, self.eu[e0]  # back to the run's first edge: n its outer end
            while True:
                o = onward(e, n)
                if o is None or o in done or o == e0:
                    break
                n, e = across(o, n), o
            points: list = []
            while True:
                done.add(e)
                piece = self.line(e, n)
                points.extend(piece[1:] if points else piece)
                n = across(e, n)
                o = onward(e, n)
                if o is None or o in done:
                    break
                e = o
            out.append((points, weights[e0]))
        return out


def _unpacked(text, dtype: str) -> np.ndarray:
    """A file's packed numbers (base64 of little-endian ones: infrastructure.pack) as an array."""
    if not isinstance(text, str):
        raise TypeError("not packed numbers")
    return np.frombuffer(base64.b64decode(text), dtype=dtype)


def _point(o) -> tuple[float, float] | None:
    """A place's (lat, lon) from its mapping, or None for one with no point of the globe."""
    if not isinstance(o, Mapping):
        return None
    lat, lon = o.get("lat"), o.get("lon")
    for v in (lat, lon):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
            return None
    return (float(lat), float(lon)) if -90 <= lat <= 90 and -180 <= lon <= 180 else None


def _number(v) -> float:
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v > 0 else 0


def _stretch(p, q) -> tuple:
    """A great circle's key: its two ends to about ten metres, the lesser first (one stretch whichever way it goes)."""
    a, b = (round(p[0], 4), round(p[1], 4)), (round(q[0], 4), round(q[1], 4))
    return (a, b) if a <= b else (b, a)


class Network:
    """The graph of a plugin's installed line layers, made again when their versions change (graph()), and the heat
    of a page's routes over it (onto). Thread-safe; nothing kept once cleared (the plugin detached)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._key: tuple | None = None
        self._graph: Graph | None = None
        self.built = 0  # graphs made

    def clear(self) -> None:
        with self._lock:
            self._key, self._graph = None, None

    def graph(self, index) -> Graph | None:
        """The graph of the line layers `index` (an infrastructure.Index) has installed, as made for their versions;
        made again when they changed, read from their files then. None without any."""
        try:
            listed = index.layers() if index is not None else []
        except Exception:  # noqa: BLE001 - a folder that cannot be read: no layer, the great circles
            listed = []
        layers = [x for x in listed if isinstance(x, Mapping) and x.get("id") in LINES and x.get("kind") == "lines"]
        key = tuple((str(x["id"]), str(x.get("version") or "")) for x in layers)
        with self._lock:
            if key == self._key:
                return self._graph
            parts = []
            for x in layers:
                try:
                    got = index.layer(x["id"])
                except (LookupError, OSError, ValueError):
                    continue  # gone since it was listed: the next look says so
                for part in got.get("parts") or () if isinstance(got, Mapping) else ():
                    lines = part.get("lines") if isinstance(part, Mapping) else None
                    if isinstance(lines, Mapping):
                        try:
                            parts.append((_unpacked(lines.get("xy"), "<i4"), _unpacked(lines.get("offsets"), "<u4")))
                        except (TypeError, ValueError):
                            continue
            self._graph, self._key = Graph.of(parts) if parts else None, key
            self.built += 1
            return self._graph

    @staticmethod
    def _snap(graph: Graph, p) -> tuple[int, float] | None:
        key = (round(p[0], 4), round(p[1], 4))
        with graph._lock:
            if key in graph._snaps:
                graph._snaps.move_to_end(key)
                return graph._snaps[key]
        found = graph.nearest(p[0], p[1])
        with graph._lock:
            graph._snaps[key] = found
            while len(graph._snaps) > MAX_SNAPS:
                graph._snaps.popitem(last=False)
        return found

    @staticmethod
    def _way(graph: Graph, a: int, b: int, limit: float):
        with graph._lock:
            kept = graph._ways.get((a, b))
            if kept is not None:
                graph._ways.move_to_end((a, b))
        if kept is not None:
            searched, found = kept
            if found is not None:
                return found if found[0] <= limit else None
            if limit <= searched:
                return None
        found = graph.way(a, b, limit)
        with graph._lock:
            graph._ways[(a, b)] = (limit, found)
            while len(graph._ways) > MAX_WAYS:
                graph._ways.popitem(last=False)
        return found

    def leg(self, graph: Graph | None, s, e):
        """A leg from s to e (lat, lon) on the network: (its first junction and how far from s, its last and how far
        from e, its way: [(edge, from junction), ...]); None where it is its great circle (the module's docstring)."""
        if graph is None:
            return None
        gc = km(s, e)
        if gc < CITY_KM:
            return None
        a, b = self._snap(graph, s), self._snap(graph, e)
        if a is None or b is None or a[0] == b[0]:
            return None
        limit = DETOUR * gc - a[1] - b[1]
        found = self._way(graph, a[0], b[0], limit) if limit > 0 else None
        return None if found is None else (a, b, found[1])

    def onto(self, globe: dict, index) -> dict:
        """The heat of the routes on a page's globe (the module's docstring): its "heat", "heat_by" and each placed
        origin's "last" set; the globe given back. The origins' `via` (Routes.onto) are read, never changed."""
        origins = globe.get("origins") if isinstance(globe.get("origins"), list) else []
        home = _point(globe.get("home"))
        places = [o for o in origins if isinstance(o, dict) and _point(o) is not None]
        by = "bytes" if any(_number(o.get("bytes")) for o in places) else "connections"
        graph = self.graph(index) if home is not None and places else None
        edges: dict[int, float] = {}
        loose: dict[tuple, list] = {}
        for o in places if home is not None else ():
            w = _number(o.get("bytes" if by == "bytes" else "count"))
            hops = [p for p in (_point(v) for v in (o.get("via") or ()) if isinstance(v, Mapping)) if p is not None]
            stops = [home, *hops, _point(o)]
            legs = [(s, e, self.leg(graph, s, e)) for s, e in zip(stops, stops[1:])]
            mine, stretches, last = set(), {}, home
            for k, (s, e, on) in enumerate(legs):
                if on is None:
                    stretches[_stretch(s, e)] = (s, e)
                    last = s
                    continue
                (a, _), (b, _), steps = on
                pa, pb = graph.place(a), graph.place(b)
                before = legs[k - 1][2] if k else None
                if before is None or before[1][0] != a:  # a hop the leg before met at this junction: passed through
                    stretches[_stretch(s, pa)] = (s, pa)
                after = legs[k + 1][2] if k + 1 < len(legs) else None
                if after is None or after[0][0] != b:
                    stretches[_stretch(pb, e)] = (pb, e)
                mine.update(edge for edge, _ in steps)
                last = pb
            o["last"] = [round(last[0], 5), round(last[1], 5)]
            for edge in mine:
                edges[edge] = edges.get(edge, 0) + w
            for key, (p, q) in stretches.items():
                if km(p, q) >= TINY_KM:
                    kept = loose.setdefault(key, [p, q, 0])
                    kept[2] += w
        runs = graph.runs(edges) if graph is not None and edges else []
        runs += [([p, q], w) for p, q, w in loose.values()]
        runs.sort(key=lambda r: -r[1])
        heat, total = [], 0
        for points, w in runs:
            if len(heat) >= MAX_RUNS:
                break
            if total + len(points) > MAX_POINTS:
                continue
            heat.append({"points": [[round(lat, 4), round(lon, 4)] for lat, lon in points], "w": w})
            total += len(points)
        globe["heat"], globe["heat_by"] = heat, by
        return globe
