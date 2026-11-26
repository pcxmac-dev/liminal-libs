"""Every connection's route on the firewalls' World Wide Web globe (1.67.0; the user, 2026-11-19: "also use traceroute
or find the routes that the traffic is being used", then "no, trace all connections"). While the tab is shown, every
public address this machine has a connection open with is traced in turn (netpath.trace: on Windows through its ICMP
API, every hop of a wave asked at once, about a second a route; elsewhere through traceroute or tracepath), one at a
time on one thread, and each hop placed by the GeoIP file on this machine. A place's line on the globe then runs from
home through its route's placed hops (`via`) instead of straight to it, and the routes are tabled.

A route is kept in memory for an hour (KEEP_S), never on disk, and traced again after that while its connection is
still open. Nothing is traced while the tab is not shown: the thread ends once nothing waits or the tab has not been
asked for TIMEOUT_S, and for good when the plugin is detached (close). A router's place is where the GeoIP file puts
its address, often its network's home rather than the router itself.

1.69.0: the routes follow the installed cables, backbones and lines on land where they can (machines/network.py), and
the page gets them as a heat map, each stretch as bright as the traffic over it (globe["heat"]), each place's light
on its last stretch alone ("last")."""
from __future__ import annotations

import math
import re
import threading
import time
from collections import OrderedDict
from typing import Iterable

from .. import netpath
from . import composite as composite_module, lookups as lookups_module, names as names_module
from . import network as network_module

KEEP_S = 3600.0  # a route that failed is traced again after this long, while its connection is still open
# 1.74.0 (the user, 2026-11-22: "make sure all route checks only happen once, to conclusion, and not every packet
# or connection, if there are multiple routes to a host, record all applicable routes"): a host traced to its end is
# not traced again (nor after a restart: the hosts database's routes say which were); a check traces it CHECKS times,
# each to its end, and keeps every distinct route found (a balancer between two paths gives both)
CHECKS = 3
MAX_DONE = 100_000  # hosts remembered as traced, in this process
MAX_KEPT = 1024  # routes kept, the least recently traced let go first
# 1.74.1: the hosts traced before (not traced again) whose routes the hosts database keeps are read back from it
# as they are wanted, once each, this many at one ask at most
ROUTES_READ = 256
MAX_WAITING = 512  # addresses waiting to be traced at most: the rest are asked for again at the tab's next ask
GAP_S = 0.25  # the pause between two routes
TIMEOUT_S = 20.0  # tracing stops this long after the tab was last asked (as the watching: world.TIMEOUT_S)
MAX_VIA = 32  # placed hops a place's line runs through at most
TABLE_ROWS = 40  # routes in the table, the most hops placed first
WAY = 6  # places a route's way names in the table, the first ones
TITLE = "Routes"
WAITING_TITLE = "Legs waiting for a line"  # 1.70.0
# 1.74.0 (the user, 2026-11-22: "for each traceroute show every hop in order with it's IP, round trip time, reverse
# DNS name, ASN, network operator, hostname, show RDAP ownership keep missing hops visible. finally highlight where it
# crosses between network operators"): every hop of each route, HOP_ROWS rows at most, the routes as tabled
HOPS_TITLE = "Routes, hop by hop"
# (the user: "also for trace routes, with the local ISP, and how they connect to an exchange or private link (between
# routers), also identify the carrier links (major hauls)"): two hops of one operator further apart than HAUL_KM, or
# whose times differ by more than HAUL_MS, are joined by a carrier's long haul
HAUL_KM = 500.0
HAUL_MS = 10.0
# 1.74.3: two hops' distance is believed only where their times allow it: a round trip's added time bounds the
# fibre between them (KM_PER_MS a ms, as names.py bounds a name's place, and SLACK_KM for the places' own error).
# GeoIP puts many routers at their network's home, thousands of km from where they are: on this PC's routes 267
# of 335 links 1.74.0 called carrier links were between hops whose times rule their distance out
KM_PER_MS = 100.0
SLACK_KM = 300.0
LINK_RULE = 2  # in each link's claim: the claims kept before it (1.74.0-1.74.2, no rule) used the distance alone
# 1.74.0 (the user: "for trace routes, identify exchange IPs, where operators change, try to identify the operator
# backbone, if it can be proved"): a hop is an exchange point's, or a backbone's, only where its registry's words
# (RDAP) or its own name say so, and what says it is shown
EXCHANGE_WORDS = re.compile(r"(?i)(?:^|[^a-z])(?:ix|ixp|ixf|exchange|de-?cix|ams-?ix|linx|any2|nyiix|six|torix|"
                            r"france-?ix|bcix|ecix|netnod|mix-?it|nl-?ix|jpnap|hkix|bbix|equinix-?ix|ix-?br)"
                            r"(?:[^a-z]|$)")
BACKBONE_WORDS = re.compile(r"(?i)(?:^|[^a-z])(?:bb|bbr|core|cr|ccr|backbone|bckbn)\d*(?:[^a-z]|$)")
HOP_ROWS = 600
WAITING_ROWS = 60
WAITING_NOTE = ("A leg of a route is drawn only along a line installed below: a cable, a line on land or a backbone. "
                "These legs are not known on any yet, so they are not drawn; their ends are named on the globe. They "
                "are looked up again at each ask, and as more lines are installed.")


# 1.75.0: the words that end a company's name, left out when two operators' names are compared
LEGAL = frozenset({"inc", "incorporated", "llc", "ltd", "limited", "corp", "corporation", "co", "company",
                   "plc", "gmbh", "ag", "sa", "sas", "srl", "spa", "bv", "nv", "pty", "lp", "llp", "ab",
                   "oy", "kk", "as", "asa", "aps", "the"})


def _said(v) -> str:
    """A cell's words, its sub after them in brackets (a cell is text or {text, sub})."""
    if isinstance(v, dict):
        return str(v.get("text", "")) + (f" ({v['sub']})" if v.get("sub") else "")
    return str(v or "")


def _operator(name: str) -> str:
    """An operator's name as two are compared (1.75.0): lower case, words alone, the legal words at its end left
    out ("Charter Communications, Inc." and "Charter Communications LLC" are one); "" for no name."""
    words = re.sub(r"[^0-9a-z]+", " ", str(name or "").lower()).split()
    while len(words) > 1 and words[-1] in LEGAL:
        words.pop()
    while len(words) > 1 and words[0] == "the":
        words.pop(0)
    return " ".join(words)


def _ago(seconds: float) -> str:
    """How long ago a route was traced, in words (1.74.1: a route read back may be days old)."""
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{round(seconds / 60)} min ago"
    if seconds < 2 * 86_400:
        return f"{round(seconds / 3600)} h ago"
    return f"{round(seconds / 86_400)} days ago"


def _key(lat, lon) -> tuple[float, float] | None:
    """A place as the globe's dots are matched to routes: its point to about a hundred metres."""
    if lat is None or lon is None:
        return None
    return round(float(lat), 3), round(float(lon), 3)


class Routes:
    """The routes of one plugin's World Wide Web tab: what waits to be traced, what was, and the thread tracing."""

    def __init__(self, *, tracer=None, clock=None, sleep=None, timeout: float = TIMEOUT_S, start=None, keep=None,
                 wall=None, bootstrap=(), known=None, stored=None):
        # the system's tracers, stopped once the tab is left or the routes closed (review: none outlives them)
        self._tracer = tracer or (lambda address: netpath.trace(address, stop=self._stopping))
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
        # 1.68.0: each route traced kept in the hosts database once it is placed (`keep(remote, traced, reached, how,
        # hops, way)`: hostbook.HostBook.keep_route), the wall clock its time is said in, the routes kept so
        self._keep = keep
        self._wall = wall or time.time
        self._saved: set[tuple] = set()
        # 1.74.0: the hosts traced to their end (asked of `known`, the hosts database's, once), and every distinct
        # route of each check: {address: [routes]}
        self._known = known
        self._done: set[str] | None = None
        self._alternates: dict[str, list] = {}
        # 1.74.1: their routes read back (`stored(addresses)`: the hosts database's, HostBook.routes_of), once each
        self._stored = stored
        self._loaded: set[str] = set()
        # 1.69.0: the network the routes are drawn on, made from the plugin's installed layers when the page asks
        self.network = network_module.Network()
        # 1.71.0: both sides kept and paired, the lookup queue with them (machines/composite.py)
        self.composite = composite_module.Composite()
        # 1.72.0: each router's name (reverse DNS) and network (RDAP), within each source's limits, into it
        self.lookups = lookups_module.Lookups(
            bootstrap=bootstrap,  # 1.72.1: RDAP's bootstrap addresses, the plugin's
            claims=lambda address, source, words, said: self.composite.record(claims=[(address, source, words, said)]))
        self.lookups.decode = self._decode
        self._seeded = False  # 1.75.1: what the lookups found before a restart put back, once (_seed_lookups)
        self._composed: set[tuple] = set()
        # 1.73.0: routers' names read for their places, with the installed airports and cities (names.py)
        self.names = names_module.Names()
        self._index = None
        self._home = None
        self._read_with = None  # the lists every known name was last read with
        self._seen: OrderedDict[str, tuple[float | None, str]] = OrderedDict()  # address -> (its time, country)

    def _seed_lookups(self) -> None:
        """1.75.1: once, at the tab's first ask: the routers' names and networks found before (the composite
        database's evidence within lookups.KEEP_S) put back, so a restart asks no registry again for them and the
        hop table has them at once. A read that fails puts nothing back: they are looked up again."""
        if self._seeded:
            return
        self._seeded = True
        try:
            wall = self.composite.clock()
            self.lookups.seed(self.composite.lookups(wall - lookups_module.KEEP_S), wall)
        except Exception:  # noqa: BLE001 - nothing put back costs the tab nothing
            pass

    def _stopping(self) -> bool:
        """Whether a trace under way stops: only the routes closed (1.74.0: a trace begun runs to its end; the tab
        left, no other is begun)."""
        return self.closed

    @staticmethod
    def _thread(work) -> None:
        threading.Thread(target=work, name="liminal-routes", daemon=True).start()

    def want(self, addresses: Iterable) -> None:
        """The tab was asked, and these are the remote addresses of the connections open now: each public one not
        traced within KEEP_S waits to be (the others are left: a name, the local network); the thread is started
        when it is not running."""
        now = self.clock()
        if self._done is None:  # the hosts traced before (the hosts database's), asked once
            try:
                done = set(self._known()) if self._known is not None else set()
            except Exception:  # noqa: BLE001 - none known: traced again, once
                done = set()
            with self._lock:
                if self._done is None:
                    self._done = done
        wanted = []
        for a in addresses:
            try:
                wanted.append(netpath.traceable(a))
            except ValueError:
                continue
        back: list[str] = []
        with self._lock:
            if self.closed:
                return
            self._asked = now
            if self._stored is not None:  # 1.74.1: the hosts traced before, their routes not in memory yet
                back = [a for a in dict.fromkeys(wanted) if a in self._done and a not in self._kept
                        and a not in self._loaded][:ROUTES_READ]
                if len(self._loaded) + len(back) > MAX_DONE:
                    self._loaded.clear()
                self._loaded.update(back)
            for a in wanted:
                kept = self._kept.get(a)
                if a in self._done or (kept is not None and now - kept[0] < KEEP_S) or a in self._waiting \
                        or a == self._busy:
                    continue
                if len(self._waiting) >= MAX_WAITING:
                    break
                self._waiting[a] = None
            start = bool(self._waiting) and not self._running
            if start:
                self._running = True
        if back:
            self._read_back(back)
        if start:
            try:
                self._start(self._loop)
            except Exception:  # noqa: BLE001 - no thread: started again at the next ask
                with self._lock:
                    self._running = False

    def step(self) -> bool:
        """The oldest address waiting traced and its route kept. False, tracing nothing, when none waits, the tab was
        not asked within the timeout, or the routes were closed."""
        with self._lock:
            if self.closed or not self._waiting or self.clock() - self._asked > self.timeout:
                self._running = False  # in the hold that decides it: a want() after this starts a thread again
                return False
            address, _ = self._waiting.popitem(last=False)
            self._busy = address
        found: list = []  # 1.74.0: CHECKS traces, each to its end; every distinct route kept
        for _ in range(CHECKS):
            try:
                one = self._tracer(address)
            except Exception as e:  # noqa: BLE001 - a trace that failed is kept as such, in words, tried again later
                one = netpath.Trace(address, error=f"{type(e).__name__}: {e}")
            if one.error and found:
                break
            if not any(tuple(h.address for h in one.hops) == tuple(h.address for h in f.hops) for f in found):
                found.append(one)
            if one.error or self.closed:
                break
        route = max(found, key=lambda f: (not f.error, sum(1 for h in f.hops if h.address)))
        with self._lock:
            self._busy = ""
            if self.closed:
                return False
            self._kept[address] = (self.clock(), route)
            self._kept.move_to_end(address)
            self._alternates[address] = [f for f in found if f is not route and not f.error]
            if not route.error:
                if len(self._done) >= MAX_DONE:
                    self._done.clear()
                self._done.add(address)
            while len(self._kept) > MAX_KEPT:
                gone, _ = self._kept.popitem(last=False)
                self._alternates.pop(gone, None)
                self._loaded.discard(gone)  # 1.74.1: read back again when wanted again
            self.traced += 1
        return True

    def _read_back(self, addresses: list[str]) -> None:
        """1.74.1: the routes the hosts database keeps of these hosts (traced before, so not traced again) put
        back in memory as their last check found them: drawn and tabled as if traced now, their age their own,
        never saved again. A read that fails leaves them out (read again after a restart)."""
        try:
            found = self._stored(addresses) or {}
        except Exception:  # noqa: BLE001 - nothing read back: none of them drawn, nothing else lost
            return
        now, wall = self.clock(), self._wall()
        with self._lock:
            if self.closed:
                return
            for address in addresses:
                rows = found.get(address) or ()
                if address in self._kept:
                    continue
                routes, traced = [], None
                for row in rows:
                    try:
                        when = float(row["traced"])
                        hops = tuple(netpath.Hop(int(h["n"]), str(h["address"]) if h.get("address") else None,
                                                 float(h["ms"]) if h.get("ms") is not None else None)
                                     for h in row.get("hops") or ())
                    except (KeyError, TypeError, ValueError, AttributeError):
                        continue
                    routes.append(netpath.Trace(address, hops, bool(row.get("reached")), str(row.get("how") or "")))
                    traced = when
                if not routes or traced is None:
                    continue
                at = now - max(0.0, wall - traced)  # the drawn one's age (the last row's), in this clock
                self._kept[address] = (at, routes[-1])
                self._alternates[address] = routes[:-1]
                self._saved.add((address, at))  # kept already: never saved again
            while len(self._kept) > MAX_KEPT:
                gone, _ = self._kept.popitem(last=False)
                self._alternates.pop(gone, None)
                self._loaded.discard(gone)

    def _loop(self) -> None:
        try:
            while self.step():
                self._sleep(GAP_S)
        except BaseException:  # step() clears the flag itself when it ends the loop; this is for the unexpected
            with self._lock:
                self._running = False
            raise

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
        self.network.clear()
        self.composite.close()
        self.lookups.close()
        self.names.clear()

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
            lat, lon, label = getattr(place, "lat", None), getattr(place, "lon", None), getattr(place, "label", "")
            best, by = self.composite.best(hop.address), ""
            if best and best["confidence"] > composite_module.SOURCES["geoip"][0] + 1e-9:  # 1.73.0: surer
                lat, lon, label, by = best["lat"], best["lon"], best["label"], best["by"]
            key = _key(lat, lon)
            if key is None or key == last or key == end or key == home:
                continue
            point = {"lat": lat, "lon": lon, "label": label, "address": hop.address, "n": hop.n, "ms": hop.ms}
            if by:
                point["placed_by"] = by
            known = self.lookups.known(hop.address)  # 1.72.0: its name and network, once looked up
            if known.get("name"):
                point["name"] = known["name"]
            if known.get("network") or known.get("org"):
                point["network"] = ", ".join(x for x in (known.get("network"), known.get("org"),
                                                       known.get("country")) if x)
            points.append(point)
            last = key
            if len(points) >= MAX_VIA:
                break
        return points

    def _decode(self, address: str, name: str) -> dict | None:
        """Where a router's name says it is (names.Gazetteer.place), bounded by the trace's time to it from home and
        its country first (its network's, else the GeoIP file's); None without the lists."""
        gazetteer = self.names.gazetteer(self._index)
        if gazetteer is None:
            return None
        ms, country = self._seen.get(address, (None, ""))
        country = self.lookups.known(address).get("country") or country
        return gazetteer.place(name, home=self._home, ms=ms, country=country)

    def _routers(self, kept: dict, geoip) -> list[dict]:
        """The routers of the routes not yet given to the composite database, each once a trace: its address,
        its hop, the one before it and the time to it, and the GeoIP file's place for it (lat None: none)."""
        out = []
        for address, (at, route) in kept.items():
            if (address, at) in self._composed:
                continue
            if len(self._composed) >= 2 * MAX_KEPT:
                self._composed.clear()
            self._composed.add((address, at))
            before = ""
            for hop in route.hops:
                if not hop.address or hop.address == route.target:
                    continue
                try:
                    place = geoip.lookup(hop.address) if geoip is not None else None
                except Exception:  # noqa: BLE001 - a lookup that fails places nothing
                    place = None
                lat, lon = getattr(place, "lat", None), getattr(place, "lon", None)
                was = self._seen.get(hop.address, (None, ""))[0]
                ms = hop.ms if was is None or (hop.ms is not None and hop.ms < was) else was
                self._seen[hop.address] = (ms, str(getattr(place, "country", "") or ""))
                while len(self._seen) > 4 * MAX_KEPT:
                    self._seen.popitem(last=False)
                out.append({"address": hop.address, "n": hop.n, "ms": hop.ms, "after": before,
                            "lat": lat, "lon": lon, "label": getattr(place, "label", "") if lat is not None else ""})
                before = hop.address
        return out

    def _hops_table(self, rows: list, geoip) -> dict:
        """Every hop of each route, in order (the routes as the Routes table has them): its number, its address (a
        hop that did not answer kept, as *), its time, its name by reverse DNS, its network's number and operator
        as the GeoIP file has them, its holder by RDAP; where the operator is another than the hop's before, the
        crossing said in the last column. The host's own name beside it, on its route's first row."""
        from ..apps.tabs import detail

        out, links, details = [], [], []
        for _placed, address, _found, route, _way, _answered, _age in rows:
            name = self.lookups.known(address).get("name", "")
            first, last_op, last_who = True, "", ""
            isp, before = "", None  # the first operator met (this machine's ISP); the last hop that answered
            for hop in route.hops:
                if len(out) >= HOP_ROWS:
                    break
                to = ({"text": address, "sub": name} if name else address) if first else ""
                first = False
                if not hop.address:
                    out.append([to, str(hop.n), {"text": "*", "sub": "no answer"}, "–", "", "", "", "", "", "",
                                ""])
                    details.append(detail(f"Hop {hop.n} to {address}", [("Answered", "no")],
                                          note="This hop did not answer, so nothing more is known of it."))
                    continue
                known = self.lookups.known(hop.address)
                try:
                    place = geoip.lookup(hop.address) if geoip is not None else None
                except Exception:  # noqa: BLE001 - a lookup that fails says nothing
                    place = None
                asn = str(getattr(place, "asn", "") or "")
                asn = f"AS{asn}" if asn.isdigit() else asn
                org = str(getattr(place, "org", "") or "")
                holder = ", ".join(x for x in (known.get("network"), known.get("org"), known.get("country")) if x)
                who = org or known.get("org") or asn
                # 1.75.0: operators compared by their names (one company runs several AS numbers, and the ASN file
                # and the registry spell its name apart: "Charter Communications Inc", "... LLC"), the number alone
                # where no name is known
                op = _operator(org or known.get("org") or "") or asn
                kind = ""
                rdap = " ".join(x for x in (known.get("network"), known.get("org")) if x)
                ptr = known.get("name", "")
                if rdap and EXCHANGE_WORDS.search(rdap):
                    kind = {"text": "exchange point", "sub": f"its registry: {rdap}"}
                elif ptr and EXCHANGE_WORDS.search(ptr.split(".", 1)[-1] if "." in ptr else ptr):
                    kind = {"text": "exchange point", "sub": f"its name: {ptr}"}
                elif ptr and BACKBONE_WORDS.search(ptr):
                    kind = {"text": f"{who}'s backbone" if who else "backbone", "sub": f"its name: {ptr}"}
                best = self.composite.best(hop.address)
                if best and best["confidence"] > composite_module.SOURCES["geoip"][0] + 1e-9:
                    where = (best["lat"], best["lon"])
                else:
                    lat, lon = getattr(place, "lat", None), getattr(place, "lon", None)
                    where = (lat, lon) if lat is not None and lon is not None else None
                isp = isp or op
                exchange = bool(kind) and kind["text"] == "exchange point"
                link = self._link(before, (hop.address, op, who, where, hop.ms, exchange), isp)
                if link and before is not None:  # 1.74.2: your ISP's is a word, the others a record
                    said = link if isinstance(link, dict) else {"text": str(link)}
                    links.append((f"{before[0]}>{hop.address}", {"type": said["text"], "from": before[0],
                                                                    "to": hop.address, "words": said.get("sub", ""),
                                                                    "rule": LINK_RULE}))
                before = (hop.address, op, who, where, hop.ms, exchange)
                crosses = ""
                if op and last_op and op != last_op:
                    at = " at an exchange point" if kind and kind["text"] == "exchange point" else ""
                    crosses = {"text": f"⇄ {who}", "sub": f"from {last_who}{at}"}
                if op:
                    last_op, last_who = op, who
                out.append([to, str(hop.n), hop.address, f"{hop.ms:.1f} ms" if hop.ms is not None else "–",
                            known.get("name", ""), asn, org, holder, kind, link, crosses])
                # 1.105.0 (Monday list item 31): the router picked, told in full in the right-hand menu: where the
                # composite database puts it, with how sure and from what
                placed_at = [("Where", f"{where[0]:.2f}, {where[1]:.2f}" if where else "not placed")]
                if best:
                    placed_at += [("Its label", str(best.get("label") or "")), ("Confidence", f"{best['confidence']:.2f}"),
                                  ("Sources agreeing", str(best.get("sources") or "")), ("Led by", str(best.get("by") or ""))]
                details.append(detail(hop.address, [
                    ("On the route to", address), ("Hop", str(hop.n)),
                    ("Time", f"{hop.ms:.1f} ms" if hop.ms is not None else ""), ("Name", known.get("name", "")),
                    ("ASN", asn), ("Operator", org), ("Holder (RDAP)", holder), ("What it is", _said(kind)),
                    ("Link from the hop before", _said(link)), ("Crosses", _said(crosses))],
                    sections=[("Its place", placed_at)]))
        if links:  # the links, as evidence of the infrastructure, for the map (the composite database)
            try:
                self.composite.record(links=links)
            except Exception:  # noqa: BLE001 - the links not kept cost the tab nothing
                pass
        note = ("Every hop of each route in order, the routes as tabled above: a hop that did not answer is kept, as *. "
                "Its name is its reverse DNS, its network's number and operator are the ASN file's (where it is "
                "installed beside the GeoIP file, else the GeoIP file's), its holder is "
                "its registry's (RDAP); they fill in as each router is looked up. Where the operator is another than "
                "the hop's before, the route crosses between networks: said in the last column (⇄). A hop is called "
                "an exchange point's or a backbone's only where its registry's words or its own name say so, and "
                "what says it is shown beneath. The link from the hop before is your ISP's (inside the first "
                "network met), an exchange point's or a private link (where networks meet: an exchange point where "
                "one is proved, else a private link between their routers) or a carrier's long haul (inside one "
                f"network: its round trip over {HAUL_MS:g} ms longer, or its hops over {HAUL_KM:g} km apart where the "
                f"times allow it, about {KM_PER_MS:g} km a ms, as a GeoIP file often puts a router at its network's "
                "home); each is kept in the composite database for the map.")
        return {"title": HOPS_TITLE, "note": note, "empty": "No route traced yet.",
                "columns": [{"title": "To"}, {"title": "Hop"}, {"title": "Address"}, {"title": "Time"},
                            {"title": "Name"}, {"title": "ASN"}, {"title": "Operator"}, {"title": "Holder (RDAP)"},
                            {"title": "What it is"}, {"title": "Link"}, {"title": "Crosses"}],
                "rows": out, "details": details}

    @staticmethod
    def _link(before, this, isp: str) -> dict | str:
        """What joins a hop to the last one that answered (each (address, operator, its name, its place, its time,
        whether it is an exchange point's)): "" for the first; your ISP's; an exchange point's or a private link
        where the operators differ; a carrier link where one operator's two hops are far apart: their round trip
        over HAUL_MS longer, or their places over HAUL_KM apart where the times allow it (1.74.3)."""
        if before is None:
            return ""
        _, op0, who0, where0, ms0, ix0 = before
        _, op1, who1, where1, ms1, ix1 = this
        if op0 and op1 and op0 != op1:
            if ix0 or ix1:
                return {"text": "exchange point", "sub": f"{who0} to {who1}"}
            return {"text": "private link", "sub": f"{who0} to {who1}, no exchange point seen"}
        far = network_module.km(where0, where1) if where0 and where1 else 0.0
        jump = (ms1 - ms0) if ms0 is not None and ms1 is not None else 0.0
        allowed = far <= KM_PER_MS * max(jump, 0.0) + SLACK_KM  # the times allow the places this far apart
        if jump > HAUL_MS or (far > HAUL_KM and allowed):
            said = ", ".join(x for x in (f"about {far:,.0f} km" if far and allowed else "",
                                        f"{jump:+.1f} ms" if jump else "", who1 or who0) if x)
            return {"text": "carrier link", "sub": said}
        if op1 and op1 == isp:
            return "your ISP"
        return {"text": "inside", "sub": who1} if who1 else ""

    @staticmethod
    def _hops(route: netpath.Trace, geoip) -> list[dict]:
        """A route's hops as the hosts database keeps them: each with the place the GeoIP file gives it."""
        hops = []
        for hop in route.hops:
            item = {"n": hop.n, "address": hop.address, "ms": hop.ms}
            try:
                place = geoip.lookup(hop.address) if geoip is not None and hop.address else None
            except Exception:  # noqa: BLE001 - a lookup that fails places nothing
                place = None
            if place is not None and getattr(place, "lat", None) is not None:
                item.update(label=place.label, lat=place.lat, lon=place.lon)
            hops.append(item)
        return hops

    def _save(self, address: str, at: float, route: netpath.Trace, way: list, geoip, now: float) -> None:
        """A route kept in the hosts database once (1.68.0): every hop with the place the GeoIP file gives it, the
        places on its way in words. A keeper that fails is passed over: the route is kept at its next trace."""
        if self._keep is None or (address, at) in self._saved or address in self._loaded:  # 1.74.1: read back
            return
        traced = self._wall() - (now - at)
        try:  # 1.74.0: every other route of the check its own row first, the one drawn last (the host's newest)
            for other in self._alternates.get(address, ()):
                hops = self._hops(other, geoip)
                words = " → ".join(dict.fromkeys(h["label"] for h in hops if h.get("label")))
                self._keep(address, traced, other.reached, other.how, hops, words)
            words = " → ".join(p["label"] or p["address"] for p in way)
            self._keep(address, traced, route.reached, route.how, self._hops(route, geoip), words)
        except Exception:  # noqa: BLE001 - kept at its next trace
            return
        if len(self._saved) >= 2 * MAX_KEPT:
            self._saved.clear()
        self._saved.add((address, at))

    def onto(self, page: dict, geoip, addresses: Iterable, index=None, licence: str = "") -> dict:
        """The routes on the tab's page: each dot of the globe at a place a route ends gets that route's placed hops
        (`via`: the route with the most of them, where several end there), and the table of the routes of the
        connections open now (`addresses`, their order kept). 1.69.0: then the routes' heat on the network of the
        line layers `index` (the plugin's infrastructure.Index) has installed (network.Network.onto: globe["heat"],
        "heat_by", "waiting", each place's "tail"); a heat that fails is left out. 1.70.0: never a straight line; the
        legs not known on the lines are tabled after the routes, with why (WAITING_TITLE, WAITING_ROWS at most)."""
        globe = page.get("globe") if isinstance(page.get("globe"), dict) else None
        home_place = (globe or {}).get("home") or {}
        self._index = index  # 1.73.0: for the names' lists
        self._seed_lookups()  # 1.75.1
        try:  # the lists installed (or changed) since: every name known now read with them at once, asking no one
            gazetteer = self.names.gazetteer(index)
            if gazetteer is not None and gazetteer is not self._read_with:
                self._read_with = gazetteer
                claims = [(a, "name", lookups_module.NAME_WORDS, p) for a, n in self.lookups.names()
                          for p in (self._decode(a, n),) if p]
                if claims:
                    self.composite.record(claims=claims)
        except Exception:  # noqa: BLE001 - names not read cost the tab nothing
            pass
        if isinstance(home_place, dict) and home_place.get("lat") is not None and home_place.get("lon") is not None:
            self._home = (float(home_place["lat"]), float(home_place["lon"]))
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
            closed = [(a, at, route) for a, (at, route) in self._kept.items()
                      if a not in kept and (a, at) not in self._saved]
            waiting, busy, traced = len(self._waiting), self._busy, self.traced
        # 1.74.0: every route traced saved, those of connections closed since the last ask too (once each)
        for address, at, route in closed:
            self._save(address, at, route, self._way(route, geoip, home), geoip, self.clock())
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
            self._save(address, at, route, way, geoip, now)
        if globe is not None and isinstance(globe.get("origins"), list):
            # copies: the hosts view hands out the places it keeps, and a route's hops are this page's alone
            globe["origins"] = [dict(o) if isinstance(o, dict) else o for o in globe["origins"]]
            for origin in globe["origins"]:
                if isinstance(origin, dict):
                    way = by_place.get(_key(origin.get("lat"), origin.get("lon")))
                    if way:
                        origin["via"] = way
            try:
                self.network.onto(globe, index)
            except Exception:  # noqa: BLE001 - the heat never costs the tab its page: the routes drawn as before
                globe.pop("heat", None)
        try:  # 1.72.0: every router of the routes kept looked up, its name and network (the lookups' own thread)
            self.lookups.want([*(h.address for _, route in kept.values() for h in route.hops
                                 if h.address and h.address != route.target),
                               *kept])  # 1.74.0: and the hosts themselves, for their names
        except Exception:  # noqa: BLE001 - the lookups never cost the tab its page
            pass
        try:  # 1.71.0: what the routes say of each router, its place by the GeoIP file, and the legs waiting
            self.composite.record(self._routers(kept, geoip), self.network.legs, licence)
        except Exception:  # noqa: BLE001 - the composite never costs the tab its page
            pass
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
                               _ago(age)])
        tracing = f" Tracing {busy} now." if busy else ""
        note = (f"Every connection open now to an address on the internet has its route traced in turn while this tab "
                f"is shown, and a place's line on the globe runs through its route's placed hops: {len(kept)} of "
                f"{len(wanted)} traced, {waiting} waiting.{tracing} On Windows each route is asked through its ICMP API "
                "(small echo probes, about 16 at once, no administrator); elsewhere through traceroute or tracepath. "
                "Nothing is traced while the tab is not shown. A host is traced once, to its end (each check "
                f"{CHECKS} traces, every distinct route kept), and its routes are kept in the hosts database: after a "
                "restart they are read back from it, not traced again. A router's "
                "place is where the GeoIP file puts its address, often its network's home rather than the router. "
                "Each leg follows the cables, backbones and lines on land installed below where its way along them "
                f"is at most {network_module.DETOUR:g} times its straight distance; else it is not drawn, and waits "
                "(the next table). A route's colour runs from violet to red with how often traffic goes over it.")
        table = {"title": TITLE, "note": note, "empty": ("No route traced yet." if wanted else
                                                         "No connection to the internet is open."),
                 "columns": [{"title": "To"}, {"title": "Hops"}, {"title": "The way, from here"},
                             {"title": "Traced"}],
                 "rows": table_rows, "traced": traced}
        tables = page.get("tables")
        if not isinstance(tables, list):
            tables = page["tables"] = []
        tables.append(table)
        tables.append(self._hops_table(rows, geoip))  # 1.74.0
        legs = (globe or {}).get("waiting")
        if isinstance(legs, list):  # 1.70.0: the legs no line is known for yet, and why
            c = self.composite.counts
            kept_words = (f" Kept in the composite database ({composite_module.FILE}, beside the layers): "
                          f"{c['routers']} routers, {c['claims']} claims of them, {c['placed']} placed, "
                          f"{c['waiting']} waiting to be looked up.")
            if self.composite.problem:
                kept_words += f" Not written now: {self.composite.problem}."
            tables.append({"title": WAITING_TITLE, "note": WAITING_NOTE + kept_words,
                           "empty": "None: every leg is on the lines.",
                           "columns": [{"title": "From"}, {"title": "To"}, {"title": "Why"}, {"title": "Straight"}],
                           "rows": [[x["from"], x["to"], x["why"], f"{x['km']:,} km"] for x in legs[:WAITING_ROWS]]})
        return page
