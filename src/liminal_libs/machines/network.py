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
  heuristic), taken when the whole of it, the snaps included, is no longer than DETOUR times the leg's great circle.
  1.70.0: else, and where no layer is installed, the leg is not drawn at all (never a straight line): it waits, with
  why. A leg shorter than CITY_KM is one city's and needs no line. The stretch from a junction to a hop or a host is
  not drawn either: those are named points (the globe's script). The ways are cached by their two junctions
  (MAX_WAYS) and the snaps by their points (MAX_SNAPS), with the graph they are on.
- The heat (Network.onto): each edge a route uses gains its place's connections once, however often the route passes
  it (how often traffic goes there: 1.70.0). The page gets the edges as runs of one weight each, the heaviest kept
  first, MAX_RUNS runs and MAX_POINTS points at most: globe["heat"] = [{"points": [[lat, lon], ...], "w"}],
  globe["heat_by"] ("connections"), globe["waiting"] (the legs not known on the lines: [{"from", "to", "why", "km"}],
  WAITING at most) and each placed origin's "links" (1.106.0, below).
- 1.104.0 (Monday list item 24): fibre on land is a line layer too, and the major roads and railways are stand-ins for
  fibre where none is mapped (STAND_INS). A way is searched by its weighed km, a stand-in's edge STAND_IN_COST times
  its own, so a way on cables, backbones, fibre or telecom lines wins where one is near enough; its detour is still
  measured in km. A leg found along stand-ins alone is said so (STAND_IN_WORDS, in the composite's legs), and so is a
  run of heat on them alone (its "stand_in": true).
- 1.106.0 (Monday list item 27; the user, 2026-11-22: "the straightlines are meaningless, they need to show the cities
  that the lines go to, the hubs, the fiber bones, etc."). The lights: only on the short link from the network's end
  into a host, each origin's "links" ([[from, to], ...], each [lat, lon], towards home): from the place to the
  junction its way along the lines ends at, where it is reached on them, and from the junction its way begins at to
  home, each only when it is at most LINK_KM; a longer one is not drawn (the place, or home, shows its dot), and a
  place its way does not reach on the lines has no link. It replaces 1.70.0's "tail" (a light along the last 250 km
  of the lines). The hubs: the places of the installed infrastructure a route passes (HUB_LAYERS: the landing
  stations, exchange points, data centres, backbones' points of presence and cities its lines run within HUB_KM of),
  globe["hubs"] = [{"id", "lat", "lon", "kind", "what", "name", "sub", "w", "routes"}] (the routes' connections
  through each, and how many routes; MAX_HUBS, the busiest kept) and each origin's "hubs" (their ids in its way's
  order, ROUTE_HUBS at most). Each stretch's hubs are read by the cells its line crosses (Index.points), never a
  layer whole, and kept with the graph and the hub layers' versions (MAX_HUB_EDGES).
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

LINES = ("cables", "backbones", "lines", "fibre", "roads", "railways")  # the infrastructure layers whose lines a route
# may follow (1.104.0: fibre on land, and the roads and railways as stand-ins for it)
STAND_INS = ("roads", "railways")  # the layers that stand in for fibre where none is mapped
STAND_IN_COST = 1.5  # a stand-in's km weigh this much more in a way's search: real fibre first where it is near enough
STAND_IN_WORDS = "along roads and railways (a stand-in: no fibre is mapped here)"
GRID = 0.02  # degrees: points on one cell of this grid are one vertex (infrastructure.STEP)
SCALE = 100_000  # a file's coordinates are in 1e-5 degrees (infrastructure.SCALE)
JOIN_KM = 25.0  # a line's end is joined to a point of another line this near
SNAP_KM = 150.0  # a leg's end is snapped to a junction this near, at most
DETOUR = 2.5  # a leg follows the network when its way there is no longer than this times its great circle
CITY_KM = 30.0  # a leg shorter than this is within one city: it needs no line
WAITING = 200  # legs waiting for a line, listed at most (1.70.0)
LINK_KM = 150.0  # 1.106.0: the short link from the network's end into a host is lit only this long at most (the user's)
HUB_LAYERS = {  # 1.106.0: the infrastructure's places a route is named by where it passes them, and what each one is
    "landings": "a cable landing station", "exchanges": "an exchange point", "datacentres": "a data centre",
    "pops": "a backbone's point of presence", "modelcities": "a backbone model's city", "cities": "a city"}
HUB_KM = 10.0  # a route passes a hub where its lines run this near it (at a vertex of theirs)
EDGE_HUBS = 3  # of each kind, the nearest so many to one stretch of the lines (a city's data centres are many)
ROUTE_HUBS = 32  # hubs a route names at most, in its order (as many as its hops: routes.py's MAX_VIA)
MAX_HUBS = 400  # hubs on a page at most, the busiest kept
MAX_HUB_EDGES = 16384  # stretches whose hubs are kept, the least recently asked let go first
HUB_READ = 20_000  # points read for one page's new stretches at most
MAX_EXPAND = 50_000  # junctions a way's search looks on from, at most: past this, the leg waits
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
        (longitude, latitude, in 1e-5 degrees), `offsets` where each line begins in them and where the last one ends,
        and (1.104.0) a third item true for a part of stand-ins for fibre (STAND_INS). A part whose offsets do not read
        is passed over, a line of fewer than two points too; None when none is left."""
        lons, lats, sizes, stands = [], [], [], []
        for given in parts:
            xy, offsets = given[0], given[1]
            stand = bool(given[2]) if len(given) > 2 else False
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
                stands.append(np.full(int(keep.sum()), stand, dtype=bool))
        if not sizes:
            return None
        lon_i = np.clip(np.concatenate(lons), -180 * SCALE, 180 * SCALE)
        lat_i = np.clip(np.concatenate(lats), -90 * SCALE, 90 * SCALE)
        size = np.concatenate(sizes)
        lstand = np.concatenate(stands)  # each line's: a stand-in for fibre
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
        stand = np.concatenate((lstand[line[p0]], np.zeros(len(ju), dtype=bool)))  # a join is no stand-in's
        cost = np.where(stand, ekm * STAND_IN_COST, ekm)
        pair = np.minimum(eu, ev) * count + np.maximum(eu, ev)
        order = np.lexsort((cost, pair))  # of the edges between two vertices, the cheapest kept
        order = order[eu[order] != ev[order]]
        keep = np.ones(len(order), dtype=bool)
        keep[1:] = pair[order][1:] != pair[order][:-1]
        order = order[keep]
        if not len(order):
            return None
        eu, ev, ekm, ea, eb, joined, stand, cost = (x[order] for x in (eu, ev, ekm, ea, eb, joined, stand, cost))
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
        g.stand, g.stands = stand.tolist(), bool(stand.any())  # 1.104.0: each edge's, and whether any is
        g.ecost = cost.tolist()
        g.nlat, g.nlon = vlat[nodes], vlon[nodes]
        g._rlat, g._rlon = np.radians(g.nlat).tolist(), np.radians(g.nlon).tolist()
        g._clat = np.cos(np.radians(g.nlat)).tolist()
        g._start = np.searchsorted(src[arcs], np.arange(len(nodes) + 1)).tolist()
        g._dst = np.concatenate((nv, nu))[arcs].tolist()
        g._edge = np.concatenate((np.arange(edges), np.arange(edges)))[arcs].tolist()
        g._akm = [g.ecost[e] for e in g._edge]  # what the search weighs: a stand-in's km STAND_IN_COST times
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
        junctions (A*: the great circle to b never overstates what is left, so what is cut off by the limit is none).
        1.104.0: its km are weighed, a stand-in's STAND_IN_COST times its own (never less: the great circle still
        understates), and so is `limit`; a graph without stand-ins weighs them as they are."""
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
        return [(points, w) for points, w, _ in self.runs_of(weights)]

    def km_of(self, steps) -> float:
        """A way's km as they are, not weighed (1.104.0)."""
        return sum(self.ekm[e] for e, _ in steps)

    def stand_in(self, edges) -> bool:
        """Whether edges (1.104.0) are along stand-ins for fibre alone: one of them at least, and no other line's (a
        join is neither)."""
        found = False
        for e in edges:
            if self.stand[e]:
                found = True
            elif not self.joined[e]:
                return False
        return found

    def runs_of(self, weights: Mapping[int, float]) -> list[tuple[list[tuple[float, float]], float, list[int]]]:
        """runs(), each with its edges (1.104.0)."""
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
            mine: list[int] = []
            while True:
                done.add(e)
                mine.append(e)
                piece = self.line(e, n)
                points.extend(piece[1:] if points else piece)
                n = across(e, n)
                o = onward(e, n)
                if o is None or o in done:
                    break
                e = o
            out.append((points, weights[e0], mine))
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


def _name(o) -> str:
    """A stop's name in words: its place's label, city or country, else its address or id."""
    for key in ("label", "city", "country", "address", "id"):
        value = o.get(key) if isinstance(o, Mapping) else None
        if isinstance(value, str) and value.strip():
            return value.strip()[:80]
    return ""


def _spot(p) -> list[float]:
    return [round(p[0], 5), round(p[1], 5)]


def _cells_near(lat: np.ndarray, lon: np.ndarray, within: float) -> set[int]:
    """The 1-degree cells (infrastore.cell_of's numbering) of everything within `within` km of the points (lat, lon):
    each point's own and those its box's corners fall in (the box is far smaller than a cell, so they are all)."""
    dlat = within / KM_PER_DEGREE
    dlon = dlat / np.maximum(np.cos(np.radians(np.minimum(89.0, np.abs(lat) + dlat))), 0.01)
    found: set[int] = set()
    for a in (-1, 0, 1):
        for b in (-1, 0, 1):
            y = np.clip(lat + a * dlat, -90.0, 90.0)
            x = (lon + b * dlon + 180.0) % 360.0 - 180.0
            row = np.clip(np.floor(y) + 90, 0, 179).astype(np.int64)
            col = np.clip(np.floor(x) + 180, 0, 359).astype(np.int64)
            found.update((row * 360 + col).tolist())
    return found


def _hub_id(layer: str, lat: float, lon: float) -> str:
    return f"{layer}:{lat:.3f},{lon:.3f}"


def _read_hubs(graph: Graph, index, layers, edges) -> tuple[dict[int, list], set[int]]:
    """The hubs of edges (Network.hubs' shape), read now: the points of `layers` in the cells within HUB_KM of the
    edges' lines (one read, HUB_READ points at most), each kept for an edge whose line runs within HUB_KM of it; and
    the edges whose cells were all read whole (the review of 1.106.0: a read cut at HUB_READ reads the cells in order,
    so the edges reaching the cell it was cut in, or one after it, may have missed hubs, and are not kept)."""
    lines, cells, every = {}, {}, set()
    for e in edges:
        pts = graph.line(e, graph.eu[e])
        lat, lon = np.array([p[0] for p in pts]), np.array([p[1] for p in pts])
        lines[e] = (lat, lon)
        cells[e] = _cells_near(lat, lon, HUB_KM)
        every |= cells[e]
    try:
        got = index.points(list(layers), every, HUB_READ) if every else ([], None)
    except Exception:  # noqa: BLE001 - a database that does not read: no hubs named this time
        got = ([], None)
    # (the points, the first cell not read whole); a plain list is an older index's, read whole
    found, short = got if isinstance(got, tuple) and len(got) == 2 else (got or [], None)
    whole = set(lines) if short is None else {e for e in lines if max(cells[e], default=-1) < short}
    by_cell: dict[int, list] = {}
    for item in found:
        try:
            layer, lon, lat, name, sub = item
            lat, lon = float(lat), float(lon)
        except (TypeError, ValueError):
            continue
        if layer in HUB_LAYERS and -90 <= lat <= 90 and -180 <= lon <= 180:
            cell = min(179, max(0, math.floor(lat) + 90)) * 360 + min(359, max(0, math.floor(lon) + 180))
            by_cell.setdefault(cell, []).append((layer, lat, lon, str(name or "")[:80], str(sub or "")[:80]))
    out: dict[int, list] = {}
    for e, (lat, lon) in lines.items():
        near = [h for c in cells[e] for h in by_cell.get(c, ())]
        if not near:
            out[e] = []
            continue
        hl, hn = np.array([h[1] for h in near]), np.array([h[2] for h in near])
        far, at = np.empty(len(near)), np.empty(len(near), dtype=np.int64)
        step = max(1, PAIRS // max(1, len(lat)))  # hubs weighed against the line's points at once, within PAIRS
        for i in range(0, len(near), step):
            d = _km(hl[i:i + step, None], hn[i:i + step, None], lat[None, :], lon[None, :])
            far[i:i + step], at[i:i + step] = d.min(axis=1), d.argmin(axis=1)
        kinds: dict[str, list] = {}
        for k in np.flatnonzero(far <= HUB_KM).tolist():
            kinds.setdefault(near[k][0], []).append((not near[k][3], float(far[k]), k))  # the named first
        chosen, ids = [], set()
        for items in kinds.values():
            for _, _, k in sorted(items)[:EDGE_HUBS]:
                layer, hlat, hlon, name, sub = near[k]
                ident = _hub_id(layer, hlat, hlon)
                if ident not in ids:
                    ids.add(ident)
                    chosen.append((int(at[k]) / max(1, len(lat) - 1), (ident, layer, hlat, hlon, name, sub)))
        chosen.sort(key=lambda x: (x[0], x[1][0]))
        out[e] = chosen
    return out, whole


class Network:
    """The graph of a plugin's installed line layers, made again when their versions change (graph()), and the heat
    of a page's routes over it (onto). Thread-safe; nothing kept once cleared (the plugin detached)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._key: tuple | None = None
        self._graph: Graph | None = None
        self.built = 0  # graphs made
        self.legs: dict[str, tuple[str, str]] = {}  # 1.71.0: the last page's legs, {key: (what, why)}
        self._hub_key: tuple | None = None  # 1.106.0: the graph and the hub layers' versions the kept hubs are of
        self._hub_edges: OrderedDict = OrderedDict()  # each stretch's hubs, {edge: [(along, hub), ...]}
        self.hubs_read = 0  # 1.106.0: reads of hubs made

    def clear(self) -> None:
        with self._lock:
            self._key, self._graph = None, None
            self._hub_key, self._hub_edges = None, OrderedDict()

    def graph(self, index) -> Graph | None:
        """The graph of the line layers `index` (an infrastructure.Index) has installed, as made for their versions;
        made again when they changed, read from their files then. None without any."""
        try:
            listed = index.layers() if index is not None else []
        except Exception:  # noqa: BLE001 - a folder that cannot be read: no layer, every leg waits
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
                stand = x["id"] in STAND_INS or x.get("stand_in") is True
                for part in got.get("parts") or () if isinstance(got, Mapping) else ():
                    lines = part.get("lines") if isinstance(part, Mapping) else None
                    if isinstance(lines, Mapping):
                        try:
                            parts.append((_unpacked(lines.get("xy"), "<i4"), _unpacked(lines.get("offsets"), "<u4"),
                                          stand))
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

    def leg(self, graph: Graph | None, s, e, names=("", "")):
        """A leg from s to e (lat, lon) on the network: ((its first junction and how far from s, its last and how far
        from e, its way: [(edge, from junction), ...], whether it is along stand-ins for fibre alone), "") or (None, why
        it is not, in words: "" for a leg within one city, which needs no line). `names`: its ends' names, for the
        words. 1.104.0: the way is searched by weighed km (way()), and its own km held to the detour."""
        gc = km(s, e)
        if gc < CITY_KM:
            return None, ""
        if graph is None:
            return None, "no line layer is installed"
        a, b = self._snap(graph, s), self._snap(graph, e)
        for end, name in ((a, names[0]), (b, names[1])):
            if end is None:
                return None, f"no line within {SNAP_KM:g} km of {name or 'its end'}"
        if a[0] == b[0]:
            return None, "both ends are nearest the same junction of the lines"
        limit = DETOUR * gc - a[1] - b[1]
        weighed = limit * (STAND_IN_COST if getattr(graph, "stands", False) else 1.0)
        found = self._way(graph, a[0], b[0], weighed) if limit > 0 else None
        if found is not None and graph.km_of(found[1]) > limit:
            found = None
        if found is None:
            return None, f"no way along the lines within {DETOUR:g} times its distance"
        return (a, b, found[1], graph.stand_in(e for e, _ in found[1])), ""

    def hubs(self, graph: Graph, index, edges) -> dict[int, list]:
        """Each edge's hubs (1.106.0): {edge: [(where along its line from its first junction, 0 to 1, (id, layer, lat,
        lon, name, sub)), ...]} in that order, EDGE_HUBS of each kind at most, the nearest its line, the named first.
        The edges not kept are read (_read_hubs) by the cells their lines cross; none without a hub layer installed,
        or of an index that cannot read points by cells. Kept with the graph and the hub layers' versions."""
        try:
            listed = index.layers() if index is not None else []
        except Exception:  # noqa: BLE001 - a folder that cannot be read: no hubs
            listed = []
        kinds = [x for x in listed if isinstance(x, Mapping) and x.get("id") in HUB_LAYERS and x.get("kind") == "points"]
        if not kinds or not callable(getattr(index, "points", None)):
            return {}
        key = (graph, tuple((str(x["id"]), str(x.get("version") or "")) for x in kinds))
        out: dict[int, list] = {}
        with self._lock:
            if self._hub_key != key:
                self._hub_key, self._hub_edges = key, OrderedDict()
            for e in edges:
                if e in self._hub_edges:
                    self._hub_edges.move_to_end(e)
                    out[e] = self._hub_edges[e]
        new = [e for e in edges if e not in out]
        if new:
            found, whole = _read_hubs(graph, index, [x["id"] for x in kinds], new)
            with self._lock:
                self.hubs_read += 1
                if self._hub_key == key:  # those a cut read may have missed hubs of are read again next time
                    self._hub_edges.update((e, hs) for e, hs in found.items() if e in whole)
                    while len(self._hub_edges) > MAX_HUB_EDGES:
                        self._hub_edges.popitem(last=False)
            out.update(found)
        return out

    def onto(self, globe: dict, index) -> dict:
        """The heat of the routes on a page's globe (the module's docstring): its "heat", "heat_by", "waiting" and
        "hubs", and each placed origin's "links" and "hubs" set (1.106.0); the globe given back. The origins' `via`
        (Routes.onto) are read, never changed.

        1.70.0 (the user, 2026-11-22: "the vector should literally follow a detailed route based on geographic data,
        if it is unknown, any segment with in the route, then lets keep that in a queue of places/segments to lookup";
        "all known routes should have their temperature change (color) based on traffic frequency"): only the lines'
        own runs are drawn, never a straight stretch; a leg not known on them is left out and waits, with why
        (`waiting`, WAITING at most); and the weight is how often, each place's connections."""
        origins = globe.get("origins") if isinstance(globe.get("origins"), list) else []
        home = _point(globe.get("home"))
        home_name = (globe.get("home") or {}).get("label") if isinstance(globe.get("home"), Mapping) else ""
        places = [o for o in origins if isinstance(o, dict) and _point(o) is not None]
        graph = self.graph(index) if home is not None and places else None
        edges: dict[int, float] = {}
        waiting: dict[tuple, dict] = {}
        legs: dict[str, tuple[str, str]] = {}
        walked: list[tuple[dict, float, list]] = []  # 1.106.0: each origin, its weight and its way's steps in order
        for o in places if home is not None else ():
            w = _number(o.get("count"))
            hops = [(p, _name(v)) for v in (o.get("via") or ()) if isinstance(v, Mapping)
                    for p in (_point(v),) if p is not None]
            stops = [(home, str(home_name or "this machine")), *hops, (_point(o), _name(o))]
            mine, order, links = set(), [], []
            begun, end = False, None  # 1.106.0: whether its home side is told; the junction its way on the lines ends at
            for (s, sn), (e, en) in zip(stops, stops[1:]):
                on, why = self.leg(graph, s, e, (sn, en))
                if why or on is not None:  # 1.71.0: for the composite database's queue (a city's leg is none)
                    what = f"{sn} to {en}" + (f", {STAND_IN_WORDS}" if on is not None and on[3] else "")
                    legs[f"{s[0]:.3f},{s[1]:.3f}>{e[0]:.3f},{e[1]:.3f}"] = (what, why)
                if on is None:
                    if why:  # a leg within one city needs no line: the way before it still leads into the place
                        begun, end = True, None  # one waiting: the way does not reach on through it
                        if len(waiting) < WAITING:
                            waiting.setdefault((sn, en, why), {"from": sn, "to": en, "why": why, "km": round(km(s, e))})
                    continue
                if not begun:  # 1.106.0: its first leg on the lines, from home's side: home's short link into them
                    begun, j = True, graph.place(on[0][0])
                    if km(j, home) <= LINK_KM:
                        links.append([_spot(j), _spot(home)])
                mine.update(edge for edge, _ in on[2])
                order.extend(on[2])
                end = on[1][0]
            for gone in ("last", "tail"):  # 1.106.0: an older release's light ways, never sent again
                o.pop(gone, None)
            if end is not None:  # 1.106.0: reached along the lines: its short link from the network's end into it
                j = graph.place(end)
                if km(_point(o), j) <= LINK_KM:
                    links.insert(0, [_spot(_point(o)), _spot(j)])
            if links:
                o["links"] = links
            else:
                o.pop("links", None)
            walked.append((o, w, order))
            for edge in mine:
                edges[edge] = edges.get(edge, 0) + w
        runs = graph.runs_of(edges) if graph is not None and edges else []
        runs.sort(key=lambda r: -r[1])
        heat, total = [], 0
        for points, w, mine in runs:
            if len(heat) >= MAX_RUNS:
                break
            if total + len(points) > MAX_POINTS:
                continue
            heat.append({"points": [[round(lat, 4), round(lon, 4)] for lat, lon in points], "w": w,
                         **({"stand_in": True} if graph.stands and graph.stand_in(mine) else {})})
            total += len(points)
        globe["heat"], globe["heat_by"], globe["waiting"] = heat, "connections", list(waiting.values())
        globe["hubs"] = self._named(graph, index, edges, walked)
        self.legs = legs
        return globe

    def _named(self, graph: Graph | None, index, edges: Mapping, walked) -> list[dict]:
        """The hubs the routes pass (1.106.0): each origin's "hubs" set (their ids in its way's order, ROUTE_HUBS at
        most, those on the page alone), and the page's list, the busiest MAX_HUBS: each hub's connections through it
        (each route's once) and how many routes pass it."""
        found = self.hubs(graph, index, list(edges)) if graph is not None and edges else {}
        through: dict[str, list] = {}  # id -> [hub, connections, routes]
        named: list[tuple[dict, list[str]]] = []
        for o, w, order in walked:
            mine: list[str] = []
            seen: set[str] = set()
            for edge, at in order:
                hs = found.get(edge, ())
                for _, hub in (hs if at == graph.eu[edge] else reversed(hs)):
                    if hub[0] in seen:  # a route passes a hub once, however often its way goes by it
                        continue
                    seen.add(hub[0])
                    mine.append(hub[0])
                    entry = through.setdefault(hub[0], [hub, 0, 0])
                    entry[1] += w
                    entry[2] += 1
            named.append((o, mine))
        kept = sorted(through.values(), key=lambda x: (-x[1], x[0][0]))[:MAX_HUBS]
        ids = {hub[0] for hub, _, _ in kept}
        for o, mine in named:
            mine = [h for h in mine if h in ids][:ROUTE_HUBS]
            if mine:
                o["hubs"] = mine
            else:
                o.pop("hubs", None)
        return [{"id": ident, "lat": round(lat, 5), "lon": round(lon, 5), "kind": layer, "what": HUB_LAYERS[layer],
                 "name": name, "sub": sub, "w": w, "routes": n}
                for (ident, layer, lat, lon, name, sub), w, n in kept]
