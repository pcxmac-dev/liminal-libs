"""Traffic counted while a tab is looked at, for the firewalls' World Wide Web tab (the user, 2026-11-14: "a 'world wide
web view' that shows the globe and the routes incoming all traffic, as well as monitoring port traffic stats"). A
TrafficBook adds up the packets a capture hands it (capture.Packet): per port (bytes and packets each way, new
connections, attempts nobody answered), per remote group (an IPv4 /24, an IPv6 /48: the same, with when it was first
and last seen, its latest addresses and the ports it used) and a ring of the latest flow starts. Counters, never
packets: every collection is capped, and the entry seen longest ago is folded into "other" when a new one needs room.

A port is the service's end of a flow: a port of this machine's that others connected to ("ports": what inbound
rules are about), or a port elsewhere this machine connected to ("remote_ports": 443 for the web). A client's passing
port is no port of its own: its traffic counts under the service it reached. Who started a flow is known from its
SYN, or for UDP from its first datagram; for a connection already open when watching began, the port that looks like
a service's is taken (one under 1024 over one above it, one under 32768 over a passing one above it, else the lower).

"Unanswered" (the design, 2026-11-14: Windows firewall logging stays off, so a dropped attempt is known by its
silence): an inbound SYN with no SYN-ACK back from the same local port, to the same remote end, within 3 s, judged
once it is older than that (an attempt refused with an RST is unanswered too: no SYN-ACK came). An inbound UDP
datagram that starts a flow is judged the same way (any datagram back) and counted apart; one to a broadcast or
multicast address asks no one to answer (the adapters' own broadcast addresses, as the capture gathers them, and any
ending in .255). An attempt no answer can be matched to any more (pushed out by a crowd of others, or too young when
watching paused) is counted "unjudged", on its port and group too. A Watcher keeps a capture going while it is asked
(touch()) and stops it after its timeout (the user's decision, 2026-11-14: watching runs only while the user looks), on
stop() and when its source fails: one daemon thread while it runs, reading the capture itself, none after."""
from __future__ import annotations

import functools
import ipaddress
import threading
import time
from collections import OrderedDict, deque

from . import netpath
from .capture import ACK, FIN, RST, SYN, bits_of

ANSWER_S = 3.0  # an inbound attempt with nothing back for this long is unanswered
FLOW_IDLE_S = 60.0  # a flow with no packet for this long is forgotten: the same ends later start a new one
MAX_FLOWS = 4096  # flows followed at once, for their starts and answers
GROUP_PORTS = 16  # service ports kept per remote group
GROUP_ADDRESSES = 4  # addresses kept per remote group, the latest first
EPHEMERAL = 32768  # ports from here up are taken for passing ones (Linux's start from 32768, Windows' from 49152)
QUICK_S = 0.005  # a source answering "nothing yet" faster than this does not wait for packets itself ...
PACE_S = 0.05  # ... and is waited for this long before it is asked again (a capture waits TIMEOUT_MS itself)
COUNTS = ("in_bytes", "out_bytes", "in_packets", "out_packets", "new_in", "new_out", "unanswered", "unanswered_udp",
          "unjudged")
KINDS = ("allowed", "unanswered", "outbound")  # a flow start's kind, as the globe draws them
RING_KEYS = ("time", "proto", "dir", "kind", "local", "local_port", "remote", "remote_port")
TABLES = ("ports", "remote_ports", "groups")


@functools.lru_cache(maxsize=4096)
def group_of(address: str) -> str:
    """The remote group an address belongs to: its IPv4 /24 or IPv6 /48 ("203.0.113.0/24", "2001:db8:1::/48"; an
    IPv4 address written as IPv6 is taken as IPv4); what is no address is a group of its own."""
    try:
        ip = ipaddress.ip_address(str(address).split("%")[0])
    except ValueError:
        return str(address)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 48}", strict=False))


def service(local_port: int, remote_port: int, started: str | None = None) -> tuple[str, int]:
    """Which end of a flow is the service's: ("local", the port here) for one started from elsewhere ("in"),
    ("remote", the port there) for one started here ("out"); when that is not known, the port that looks like a
    service's (one under 1024 over one above it, one under EPHEMERAL over a passing one, else the lower; here when
    both are the same)."""
    if started == "in":
        return "local", local_port
    if started == "out":
        return "remote", remote_port
    if (local_port < 1024) != (remote_port < 1024):
        return ("local", local_port) if local_port < 1024 else ("remote", remote_port)
    if (local_port >= EPHEMERAL) != (remote_port >= EPHEMERAL):
        return ("remote", remote_port) if local_port >= EPHEMERAL else ("local", local_port)
    return ("local", local_port) if local_port <= remote_port else ("remote", remote_port)


def _gathering(address: str, broadcast=frozenset()) -> bool:
    """A broadcast or multicast address: heard by many, asked of no one machine (IPv6 ff00::/8; IPv4 from 224 up, one
    of `broadcast` (the adapters' own, as libpcap lists them with their netmasks) and any ending in .255, a /24
    network's broadcast, when they are not known)."""
    if ":" in address:
        return address.lower().startswith("ff")
    first = address.split(".", 1)[0]
    return (first.isdigit() and int(first) >= 224) or address in broadcast or address.endswith(".255")


class _Tally:
    """A port's, a group's or all traffic's counters: bytes and packets each way, flows started each way, attempts
    nobody answered (TCP, UDP) and ones no answer could be matched to any more, when first and last seen."""
    __slots__ = COUNTS + ("first", "last")

    def __init__(self, at: float | None = None):
        for name in COUNTS:
            setattr(self, name, 0)
        self.first = self.last = at

    def count(self, inbound: bool, size: int, at: float) -> None:
        if inbound:
            self.in_bytes += size
            self.in_packets += 1
        else:
            self.out_bytes += size
            self.out_packets += 1
        self.seen(at)

    def seen(self, at: float) -> None:
        if self.first is None or at < self.first:
            self.first = at
        if self.last is None or at > self.last:
            self.last = at

    def fold(self, other: _Tally) -> None:
        for name in COUNTS:
            setattr(self, name, getattr(self, name) + getattr(other, name))
        for at in (other.first, other.last):
            if at is not None:
                self.seen(at)

    @property
    def bytes(self) -> int:
        return self.in_bytes + self.out_bytes

    def as_dict(self) -> dict:
        return {**{name: getattr(self, name) for name in COUNTS}, "bytes": self.bytes,
                "packets": self.in_packets + self.out_packets, "first": self.first, "last": self.last}


class _Group(_Tally):
    """A remote group's counters, with its latest addresses, the service ports it used and what kind of network it is
    (netpath.kind: public, private, shared ...: only public ones have a place on the globe)."""
    __slots__ = ("group", "family", "network", "addresses", "ports")

    def __init__(self, group: str, address: str, at: float):
        super().__init__(at)
        self.group, self.family, self.network = group, 6 if ":" in group else 4, netpath.kind(address)
        self.addresses: list[str] = [address]
        self.ports: dict[int, int] = {}

    def note(self, address: str, port: int) -> None:
        if address != self.addresses[0]:
            if address in self.addresses:
                self.addresses.remove(address)
            self.addresses.insert(0, address)
            del self.addresses[GROUP_ADDRESSES:]
        if port in self.ports:
            self.ports[port] += 1
        elif len(self.ports) < GROUP_PORTS:
            self.ports[port] = 1

    def as_dict(self) -> dict:
        ports = sorted(self.ports, key=lambda p: (-self.ports[p], p))
        return {"group": self.group, "family": self.family, "network": self.network, "address": self.addresses[0],
                "addresses": list(self.addresses), "ports": ports, **super().as_dict()}


class TrafficBook:
    """Packets added up (add), read back as plain dicts (snapshot): at most `max_ports` ports here and as many
    elsewhere, `max_origins` remote groups, the last `ring` flow starts and `max_flows` flows followed for their starts
    and answers. Thread-safe: a capture's thread adds while a page's request reads. `clock`: the time attempts are
    judged at when a snapshot is taken (the packets' own times while they come). `broadcast`: the adapters' broadcast
    addresses (a capture's, handed on by a Watcher), datagrams to which ask no one to answer."""

    def __init__(self, max_ports: int = 256, max_origins: int = 512, ring: int = 2000, *, max_flows: int = MAX_FLOWS,
                 clock=time.time, broadcast=()):
        self.max_ports, self.max_origins = max(1, int(max_ports)), max(1, int(max_origins))
        self.ring, self.max_flows = max(0, int(ring)), max(1, int(max_flows))
        self.clock = clock
        self.broadcast: frozenset[str] = frozenset(broadcast)
        self._lock = threading.Lock()
        self._clear()

    def _clear(self) -> None:
        self._tables: dict[str, OrderedDict] = {name: OrderedDict() for name in TABLES}
        self._other = {name: _Tally() for name in TABLES}  # what entries folded away to make room had counted
        self._evicted = dict.fromkeys((*TABLES, "flows"), 0)
        self._flows: OrderedDict[tuple, list] = OrderedDict()  # (proto, local, lport, remote, rport) -> [state, first, last]
        self._pending: deque[tuple[float, tuple]] = deque()  # (first, flow) awaiting an answer, the oldest first
        self._recent: deque[tuple] = deque(maxlen=self.ring)
        self._totals = _Tally()
        self._local = [0, 0]  # packets and bytes between two of this machine's own addresses
        self._unknown = 0  # packets whose direction was not judged
        self._unjudged = 0  # attempts no answer could be matched to any more (watching paused, or no room)
        self._since: float | None = None
        self._now = 0.0

    def reset(self) -> None:
        """Every count forgotten."""
        with self._lock:
            self._clear()

    def add(self, packet) -> None:
        """One packet counted (a capture.Packet, or anything with its fields: at, src, sport, dst, dport, flags,
        proto, length, dir)."""
        with self._lock:
            self._add(packet)

    def _add(self, p) -> None:
        at = float(p.at)
        if self._since is None:
            self._since = at
        self._now = max(self._now, at)
        self._judge(self._now)
        size = max(0, int(p.length or 0))
        if p.dir == "local":
            self._local[0] += 1
            self._local[1] += size
            return
        if p.dir not in ("in", "out"):
            self._unknown += 1
            return
        inbound, proto = p.dir == "in", p.proto
        if inbound:
            local, lport, remote, rport = p.dst, int(p.dport), p.src, int(p.sport)
        else:
            local, lport, remote, rport = p.src, int(p.sport), p.dst, int(p.dport)
        bits = bits_of(p.flags) if proto == "tcp" else 0
        started = self._follow((proto, local, lport, remote, rport), inbound, bits, at)
        side, port = service(lport, rport, started)
        tally = self._entry("ports" if side == "local" else "remote_ports", (proto, port), at)
        group = self._group(remote, at)
        group.note(remote, port)
        for t in (tally, group, self._totals):
            t.count(inbound, size, at)

    # -- flows: their starts and answers ----------------------------------------------------------------------

    def _follow(self, key: tuple, inbound: bool, bits: int, at: float) -> str | None:
        """The packet's flow followed (its start noted, its answer matched): who started it, "in" or "out"; None when
        that is not known (a connection open before watching began)."""
        flows, proto = self._flows, key[0]
        flow = flows.get(key)
        if flow is not None:
            flows.move_to_end(key)
            flow[2] = at
            if flow[0] == "pending" and not inbound and (proto == "udp" or bits & (SYN | ACK) == SYN | ACK):
                flow[0] = "allowed"
                self._started(key, flow[1], "allowed")
            state = flow[0]
            if proto == "tcp" and bits & (FIN | RST) and state in ("outbound", "allowed"):
                del flows[key]  # closed: the same ends again later are a new connection
            return "out" if state == "outbound" else "in"
        if proto == "tcp":
            if bits & (SYN | ACK) != SYN:
                return None
            if inbound:
                self._open(key, "pending", at)
                return "in"
            self._open(key, "outbound", at)
            self._started(key, at, "outbound")
            return "out"
        if not inbound:
            self._open(key, "outbound", at)
            self._started(key, at, "outbound")
            return "out"
        _, local, lport, _, rport = key
        if _gathering(local, self.broadcast):  # a broadcast or multicast datagram: nobody is asked to answer it
            self._open(key, "heard", at)
            return "in"
        if service(lport, rport)[0] == "remote":  # an answer to a question asked before watching began
            self._open(key, "outbound", at)
            return "out"
        self._open(key, "pending", at)
        return "in"

    def _open(self, key: tuple, state: str, at: float) -> None:
        flows = self._flows
        while flows:  # flows idle too long forgotten, and room made
            oldest_key = next(iter(flows))
            oldest, full = flows[oldest_key], len(flows) >= self.max_flows
            if not full and oldest[2] >= at - FLOW_IDLE_S:
                break
            del flows[oldest_key]
            if full:
                self._evicted["flows"] += 1
            if oldest[0] == "pending":
                oldest[0] = "unjudged"
                self._lost(oldest_key, oldest[1])
        flows[key] = [state, at, at]
        if state == "pending":
            if len(self._pending) >= self.max_flows:
                self._unjudge(*self._pending.popleft())
            self._pending.append((at, key))

    def _unjudge(self, first: float, key: tuple) -> None:
        flow = self._flows.get(key)
        if flow is not None and flow[0] == "pending" and flow[1] == first:
            flow[0] = "unjudged"
            self._lost(key, first)

    def _lost(self, key: tuple, at: float) -> None:
        """An attempt no answer can be matched to any more: counted on its port here, its remote group and in all."""
        proto, _, lport, remote, _ = key
        for t in (self._entry("ports", (proto, lport), at), self._group(remote, at), self._totals):
            t.unjudged += 1
        self._unjudged += 1

    def _judge(self, now: float) -> None:
        """Attempts older than ANSWER_S with no answer: unanswered."""
        pending, flows = self._pending, self._flows
        while pending and pending[0][0] < now - ANSWER_S:
            first, key = pending.popleft()
            flow = flows.get(key)
            if flow is not None and flow[0] == "pending" and flow[1] == first:
                flow[0] = "unanswered"
                self._started(key, first, "unanswered")

    def _started(self, key: tuple, at: float, kind: str) -> None:
        """A flow start counted (on its service port, its remote group and in all) and put in the ring."""
        proto, local, lport, remote, rport = key
        if kind == "outbound":
            tally, name = self._entry("remote_ports", (proto, rport), at), "new_out"
        else:
            tally = self._entry("ports", (proto, lport), at)
            name = "new_in" if kind == "allowed" else "unanswered" if proto == "tcp" else "unanswered_udp"
        for t in (tally, self._group(remote, at), self._totals):
            setattr(t, name, getattr(t, name) + 1)
        self._recent.append((at, proto, "out" if kind == "outbound" else "in", kind, local, lport, remote, rport))

    # -- the capped tables --------------------------------------------------------------------------------------

    def _room(self, name: str) -> None:
        table = self._tables[name]
        if len(table) >= (self.max_origins if name == "groups" else self.max_ports):
            _, old = table.popitem(last=False)
            self._other[name].fold(old)
            self._evicted[name] += 1

    def _entry(self, name: str, key: tuple, at: float) -> _Tally:
        table = self._tables[name]
        tally = table.get(key)
        if tally is None:
            self._room(name)
            tally = table[key] = _Tally(at)
        else:
            table.move_to_end(key)
        return tally

    def _group(self, address: str, at: float) -> _Group:
        key, table = group_of(address), self._tables["groups"]
        group = table.get(key)
        if group is None:
            self._room("groups")
            group = table[key] = _Group(key, address, at)
        else:
            table.move_to_end(key)
        return group

    # -- reading it back ------------------------------------------------------------------------------------------

    def settle(self, now: float | None = None) -> None:
        """Watching paused: the attempts older than ANSWER_S judged, the younger ones left unjudged (no answer to them
        can be seen any more)."""
        with self._lock:
            self._judge(max(float(self.clock() if now is None else now), self._now))
            while self._pending:
                self._unjudge(*self._pending.popleft())

    def snapshot(self, now: float | None = None) -> dict:
        """What was counted, in plain dicts and lists: the totals; each port here ("ports") and elsewhere
        ("remote_ports") and each remote group, the most bytes first; the latest flow starts, the newest first; what
        the caps folded away ("other", "evicted"); the attempts still awaiting an answer ("pending"), the ones no answer
        could be matched to any more ("unjudged") and the flows followed ("flows"). Attempts older than ANSWER_S at
        `now` (the clock's when not given) are judged first."""
        with self._lock:
            now = max(float(self.clock() if now is None else now), self._now)
            self._judge(now)
            flows = self._flows

            def ports(name: str) -> list[dict]:
                rows = [{"proto": proto, "port": port, **t.as_dict()} for (proto, port), t in self._tables[name].items()]
                return sorted(rows, key=lambda r: (-r["bytes"], r["port"], r["proto"]))

            groups = sorted((g.as_dict() for g in self._tables["groups"].values()), key=lambda r: (-r["bytes"], r["group"]))
            recent = sorted(({**dict(zip(RING_KEYS, e)), "group": group_of(e[6])} for e in reversed(self._recent)),
                            key=lambda r: -r["time"])  # by when each started (an unanswered one is known 3 s later)
            return {
                "since": self._since, "updated": now,
                "totals": {**self._totals.as_dict(), "local_packets": self._local[0], "local_bytes": self._local[1],
                           "unknown_packets": self._unknown},
                "ports": ports("ports"), "remote_ports": ports("remote_ports"), "groups": groups, "recent": recent,
                "other": {name: t.as_dict() for name, t in self._other.items()},
                "evicted": dict(self._evicted),
                "pending": sum(1 for first, key in self._pending
                               if (f := flows.get(key)) is not None and f[0] == "pending" and f[1] == first),
                "unjudged": self._unjudged, "flows": len(flows),
                "caps": {"ports": self.max_ports, "origins": self.max_origins, "ring": self.ring, "flows": self.max_flows},
            }


class Watcher:
    """A capture kept going while it is asked for (the user's decision, 2026-11-14: watching runs only while the user
    looks). touch() starts it, or keeps it going: a source made by `source_factory` (a callable returning a
    capture.Capture, not started: the Watcher opens it, reads it and closes it; or anything with the same open(),
    next() and close()) is opened there, so a capture.CaptureError reaches the caller (and is kept in `error`), and
    read on one daemon thread, each packet handed to `book` (a TrafficBook, made when not given) and to each of
    `observers` (a names.NameBook's observe ...), the source's broadcast addresses (a capture's `broadcast`) to the
    book as they are gathered. It stops after `timeout` seconds without a touch, on stop() (the plugin's detach), and
    when reading fails (its words kept in `error`: the adapter gone); then the source is closed, the book settled
    (attempts too young to judge left unjudged) and no thread is left. A touch after that starts it anew: the same book
    counts on. `clock`: the seconds the timeout is counted in (a test's own). A read returns within the capture's own
    wait (TIMEOUT_MS) whether a packet came or not, on Linux too, so the timeout and a stop are seen soon."""

    def __init__(self, source_factory, timeout: float = 20.0, *, book: TrafficBook | None = None, observers=(),
                 clock=time.monotonic):
        self.source_factory = source_factory
        self.timeout = float(timeout)
        self.book = book if book is not None else TrafficBook()
        self._broadcast = self.book.broadcast  # the book's own broadcast addresses ...
        self._heard = None  # ... and the source's, as it last handed them
        self.observers = tuple(observers)
        self.clock = clock
        self.error = ""  # why watching could not start, or why it last ended early
        self.fault = ""  # the last packet the book or an observer failed on, in words
        self.faults = 0
        self.packets = 0  # packets read, in all
        self.started: float | None = None  # when watching last began and ended (seconds since 1970)
        self.stopped: float | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last = 0.0

    def _alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    @property
    def running(self) -> bool:
        with self._lock:
            return self._alive()

    def touch(self) -> bool:
        """Watching asked for: kept going, or started (its source made and opened here). True when it was already
        running, False when it started now; capture.CaptureError (or what the factory raised) when it cannot start."""
        with self._lock:
            self._last = self.clock()
            if self._alive():
                return True
            self._begin()
            return False

    def _begin(self) -> None:
        source = None
        try:
            source = self.source_factory()
            source.open()
        except Exception as e:
            self.error = str(e) or type(e).__name__
            if source is not None:  # whatever it opened before it failed is closed
                self._close(source)
            raise
        self._hear(source)
        stop = threading.Event()
        thread = threading.Thread(target=self._run, args=(source, stop), name="traffic-watcher", daemon=True)
        self._stop, self._thread = stop, thread
        self.error, self.started, self.stopped = "", time.time(), None
        try:
            thread.start()
        except RuntimeError as e:  # no thread to read on: nothing is left open
            stop.set()
            self._thread, self.error, self.stopped = None, f"watching could not start: {e}", time.time()
            self._close(source)
            raise

    def _due(self, stop: threading.Event) -> bool:
        """Whether watching ends now (stopped, or no touch for `timeout`); once due, it is due for good."""
        if not stop.is_set() and self.clock() - self._last < self.timeout:
            return False
        with self._lock:  # a touch that came meanwhile keeps it going
            if not stop.is_set() and self.clock() - self._last < self.timeout:
                return False
            stop.set()
            return True

    def _run(self, source, stop: threading.Event) -> None:
        try:
            while not self._due(stop):
                began = time.monotonic()
                try:
                    packet = source.next()
                except Exception as e:  # noqa: BLE001 - the adapter gone (CaptureError), or a source's own fault
                    with self._lock:
                        self.error = str(e) or type(e).__name__
                        stop.set()
                    break
                if packet is None:
                    if time.monotonic() - began < QUICK_S:
                        stop.wait(PACE_S)
                    continue
                self.packets += 1
                self._hear(source)
                self._packet(packet)
        finally:
            self._close(source)
            with self._lock:
                current = self._thread is threading.current_thread()
                if current:
                    self.stopped = time.time()
            if current:
                self.book.settle()

    def _hear(self, source) -> None:
        """The source's broadcast addresses (gathered when it opened, and again while it stays open) handed to the
        book, with the book's own."""
        heard = getattr(source, "broadcast", None)
        if heard and heard is not self._heard:
            self._heard = heard
            self.book.broadcast = frozenset(self._broadcast) | frozenset(heard)

    def _close(self, source) -> None:
        try:
            source.close()
        except Exception as e:  # noqa: BLE001 - said; the watching is over all the same
            self.error = self.error or f"the capture did not close cleanly: {type(e).__name__}: {e}"

    def stop(self, wait: float = 3.0) -> None:
        """Watching ended now: the capture closed, its thread gone (waited for up to `wait` seconds)."""
        with self._lock:
            self._stop.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(wait)

    def _packet(self, packet) -> None:
        for take in (self.book.add, *self.observers):
            try:
                take(packet)
            except Exception as e:  # noqa: BLE001 - one packet passed over, said; the watching goes on
                self.faults += 1
                self.fault = f"{type(e).__name__}: {e}"

    def status(self) -> dict:
        """Whether it is watching, since and until when (seconds since 1970), why it stopped early, the packets read
        and the ones the book or an observer failed on."""
        with self._lock:
            return {"running": self._alive(), "started": self.started, "stopped": self.stopped, "timeout": self.timeout,
                    "error": self.error, "packets": self.packets, "faults": self.faults, "fault": self.fault}
