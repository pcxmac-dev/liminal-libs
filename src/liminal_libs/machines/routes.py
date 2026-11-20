"""Every connection's route on the firewalls' World Wide Web globe (1.67.0; the user, 2026-11-19: "also use traceroute
or find the routes that the traffic is being used", then "no, trace all connections"). While the tab is shown, every
public address this machine has a connection open with is traced in turn (netpath.trace: on Windows through its ICMP
API, every hop of a wave asked at once, about a second a route; elsewhere through traceroute or tracepath), one at a
time on one thread, and each hop placed by the GeoIP file on this machine. A place's line on the globe then runs from
home through its route's placed hops (`via`) instead of straight to it, and the routes are tabled.

A route is kept in memory for an hour (KEEP_S), never on disk, and traced again after that while its connection is
still open. Nothing is traced while the tab is not shown: the thread ends once nothing waits or the tab has not been
asked for TIMEOUT_S, and for good when the plugin is detached (close). A router's place is where the GeoIP file puts
its address, often its network's home rather than the router itself."""
from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from typing import Iterable

from .. import netpath

KEEP_S = 3600.0  # a route is traced again after this long, while its connection is still open
MAX_KEPT = 1024  # routes kept, the least recently traced let go first
MAX_WAITING = 512  # addresses waiting to be traced at most: the rest are asked for again at the tab's next ask
GAP_S = 0.25  # the pause between two routes
TIMEOUT_S = 20.0  # tracing stops this long after the tab was last asked (as the watching: world.TIMEOUT_S)
MAX_VIA = 32  # placed hops a place's line runs through at most
TABLE_ROWS = 40  # routes in the table, the most hops placed first
WAY = 6  # places a route's way names in the table, the first ones
TITLE = "Routes"


def _key(lat, lon) -> tuple[float, float] | None:
    """A place as the globe's dots are matched to routes: its point to about a hundred metres."""
    if lat is None or lon is None:
        return None
    return round(float(lat), 3), round(float(lon), 3)


class Routes:
    """The routes of one plugin's World Wide Web tab: what waits to be traced, what was, and the thread tracing."""

    def __init__(self, *, tracer=None, clock=None, sleep=None, timeout: float = TIMEOUT_S, start=None):
        self._tracer = tracer or netpath.trace
        self.clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self.timeout = timeout
        self._start = start or self._thread
        self._lock = threading.Lock()
        self._kept: OrderedDict[str, tuple[float, netpath.Trace]] = OrderedDict()
        self._waiting: OrderedDict[str, None] = OrderedDict()
        self._busy = ""
        self._running = False
        self._asked = -math.inf
        self.closed = False
        self.traced = 0

    @staticmethod
    def _thread(work) -> None:
        threading.Thread(target=work, name="liminal-routes", daemon=True).start()

    def want(self, addresses: Iterable) -> None:
        """The tab was asked, and these are the remote addresses of the connections open now: each public one not
        traced within KEEP_S waits to be (the others are left: a name, the local network); the thread is started
        when it is not running."""
        now = self.clock()
        with self._lock:
            if self.closed:
                return
            self._asked = now
            for a in addresses:
                try:
                    a = netpath.traceable(a)
                except ValueError:
                    continue
                kept = self._kept.get(a)
                if (kept is not None and now - kept[0] < KEEP_S) or a in self._waiting or a == self._busy:
                    continue
                if len(self._waiting) >= MAX_WAITING:
                    break
                self._waiting[a] = None
            start = bool(self._waiting) and not self._running
            if start:
                self._running = True
        if start:
            self._start(self._loop)

    def step(self) -> bool:
        """The oldest address waiting traced and its route kept. False, tracing nothing, when none waits, the tab was
        not asked within the timeout, or the routes were closed."""
        with self._lock:
            if self.closed or not self._waiting or self.clock() - self._asked > self.timeout:
                return False
            address, _ = self._waiting.popitem(last=False)
            self._busy = address
        try:
            route = self._tracer(address)
        except Exception as e:  # noqa: BLE001 - a trace that failed is kept as such, in words, and tried again later
            route = netpath.Trace(address, error=f"{type(e).__name__}: {e}")
        with self._lock:
            self._busy = ""
            if self.closed:
                return False
            self._kept[address] = (self.clock(), route)
            self._kept.move_to_end(address)
            while len(self._kept) > MAX_KEPT:
                self._kept.popitem(last=False)
            self.traced += 1
        return True

    def _loop(self) -> None:
        try:
            while self.step():
                self._sleep(GAP_S)
        finally:
            with self._lock:
                self._running = False

    def route(self, address) -> netpath.Trace | None:
        with self._lock:
            kept = self._kept.get(str(address))
        return kept[1] if kept else None

    def close(self) -> None:
        """Detached: nothing more is traced (a trace under way is let finish and forgotten), and nothing is kept."""
        with self._lock:
            self.closed = True
            self._waiting.clear()
            self._kept.clear()

    def describe(self) -> dict:
        with self._lock:
            return {"kept": len(self._kept), "waiting": len(self._waiting), "tracing": self._busy,
                    "running": self._running, "traced": self.traced}

    # -- the tab's page -------------------------------------------------------------------------------------------
    def _way(self, route: netpath.Trace, geoip, home) -> list[dict]:
        """The route's hops that have a place, from home outward: the hops at home's place or the target's left out,
        a hop at the place of the one before it left out, MAX_VIA at most."""
        end = None
        try:
            found = geoip.lookup(route.target) if geoip is not None else None
            end = _key(getattr(found, "lat", None), getattr(found, "lon", None))
        except Exception:  # noqa: BLE001 - a lookup that fails places nothing
            pass
        last, points = home, []
        for hop in route.hops:
            if hop.address is None or hop.address == route.target:
                continue
            try:
                place = geoip.lookup(hop.address) if geoip is not None else None
            except Exception:  # noqa: BLE001
                place = None
            key = _key(getattr(place, "lat", None), getattr(place, "lon", None))
            if key is None or key == last or key == end or key == home:
                continue
            points.append({"lat": place.lat, "lon": place.lon, "label": place.label, "address": hop.address,
                           "n": hop.n, "ms": hop.ms})
            last = key
            if len(points) >= MAX_VIA:
                break
        return points

    def onto(self, page: dict, geoip, addresses: Iterable) -> dict:
        """The routes on the tab's page: each dot of the globe at a place a route ends gets that route's placed hops
        (`via`: the route with the most of them, where several end there), and the table of the routes of the
        connections open now (`addresses`, their order kept)."""
        globe = page.get("globe") if isinstance(page.get("globe"), dict) else None
        home_place = (globe or {}).get("home") or {}
        home = _key(home_place.get("lat"), home_place.get("lon")) if isinstance(home_place, dict) else None
        wanted = []  # the addresses open now that have a route: public ones, as they are traced
        for a in addresses:
            try:
                wanted.append(netpath.traceable(a))
            except ValueError:
                continue
        wanted = list(dict.fromkeys(wanted))
        with self._lock:
            kept = {a: self._kept[a] for a in wanted if a in self._kept}
            waiting, busy, traced = len(self._waiting), self._busy, self.traced
        rows, by_place = [], {}
        now = self.clock()
        for address, (at, route) in kept.items():
            way = self._way(route, geoip, home)
            try:
                found = geoip.lookup(address) if geoip is not None else None
            except Exception:  # noqa: BLE001
                found = None
            key = _key(getattr(found, "lat", None), getattr(found, "lon", None))
            if key is not None and way and len(way) > len(by_place.get(key, ())):
                by_place[key] = way
            answered = sum(1 for h in route.hops if h.address)
            rows.append((len(way), address, found, route, way, answered, now - at))
        if globe is not None:
            for origin in globe.get("origins") or ():
                if isinstance(origin, dict):
                    way = by_place.get(_key(origin.get("lat"), origin.get("lon")))
                    if way:
                        origin["via"] = way
        rows.sort(key=lambda r: (-r[0], r[1]))
        table_rows = []
        for placed, address, found, route, way, answered, age in rows[:TABLE_ROWS]:
            where = getattr(found, "label", "") if found is not None else ""
            names = [p["label"] or p["address"] for p in way[:WAY]] + (["…"] if len(way) > WAY else [])
            if route.error:
                said = route.error
            else:
                said = (f"{answered} of {len(route.hops)} hops answered"
                        + (", the address reached" if route.reached else ", the address itself did not answer"))
            table_rows.append([{"text": address, "sub": where} if where else address, said,
                               " → ".join(names) if names else "no hop placed",
                               f"{round(age / 60)} min ago" if age >= 60 else "just now"])
        tracing = f" Tracing {busy} now." if busy else ""
        note = (f"Every connection open now to an address on the internet has its route traced in turn while this tab "
                f"is shown, and a place's line on the globe runs through its route's placed hops: {len(kept)} of "
                f"{len(wanted)} traced, {waiting} waiting.{tracing} On Windows each route is asked through its ICMP API "
                "(small echo probes, about 16 at once, no administrator); elsewhere through traceroute or tracepath. "
                "Nothing is traced while the tab is not shown; a route is kept an hour, in memory only. A router's "
                "place is where the GeoIP file puts its address, often its network's home rather than the router.")
        table = {"title": TITLE, "note": note, "empty": ("No route traced yet." if wanted else
                                                         "No connection to the internet is open."),
                 "columns": [{"title": "To"}, {"title": "Hops"}, {"title": "The way, from here"},
                             {"title": "Traced"}],
                 "rows": table_rows, "traced": traced}
        tables = page.get("tables")
        if isinstance(tables, list):
            tables.insert(1 if tables else 0, table)
        else:
            page["tables"] = [table]
        return page
