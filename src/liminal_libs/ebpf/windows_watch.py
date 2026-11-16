"""The Windows watch backend (the design, 2026-11-14: "NpcapEtwWatch (Windows): Npcap for net through
capture.py, and ETW for process, file, registry and net attribution through machines/etw.py"). Every eBPF for
Windows build is test-signed and this PC runs HVCI, so that runtime cannot load; this backend does the same
job behind the same `Watch` interface an eBPF backend would use, and the eBPF plugin says as much.

What it watches, by kind:
  - net: packets from `liminal_libs.capture` (the extended Packet, with its direction, protocol and length),
    aggregated into flows and joined to a process by an ETW Kernel-Network record so the connection carries a
    pid and a program;
  - process, file and registry: ETW records from `machines/etw.py`.

It is a `Watch` like `BpftraceWatch`: the base holds the bounded ring, the sequence, `read`, `touch`, `stop`
and the self-stop after the viewing timeout; this subclass only opens the sources in `_begin`, closes them in
`_end`, and turns each ETW record and each flow of packets into an event through `_emit`. One pump thread drains
ETW and the captured packets, so the attribution tables are touched from that thread alone. Capture and ETW are
built on `start()` for the real thing; a test injects stand-ins for both, so nothing is captured and no ETW
session is started.

Net events are per flow, not per packet: a start event (its direction) once the flow is attributed or a short
hold has passed, and a close event on FIN/RST or after the flow goes idle, carrying the bytes and packet count.
A download of thousands of packets is thus a couple of events, not thousands, so it cannot flood the shared ring
and evict the rare process, file and registry events."""
from __future__ import annotations

import collections
import threading
import time

from .watch import Watch, DEFAULT_RING, DEFAULT_TIMEOUT
from .. import capture as capturemod
from ..machines import etw as etwmod

KINDS = frozenset({"net", "process", "file", "registry"})
DEFAULT_POLL = 0.2       # how often the pump drains ETW and the captured packets
MIN_POLL = 0.05          # a spec may not drive the pump faster than this
PACKET_QUEUE = 8192      # raw packets waiting for the pump (bounded; the oldest drops under a flood)
MAX_PACKET_QUEUE = PACKET_QUEUE * 4
MAP_CAP = 1024           # attribution entries kept per table, and flows tracked at once
FLOW_IDLE = 5.0          # a flow with no packet for this long is closed and emitted
ATTR_HOLD = 1.5          # a new flow's start event waits at most this long for its ETW attribution to arrive
_ETW_ONLY_KINDS = frozenset({"process", "file", "registry"})

# Which ETW providers a set of kinds needs. "net" needs Kernel-Network for the connection's pid and
# Kernel-Process for that pid's program name, even when "process" is not itself an emitted kind.
_PROVIDER_FOR = {"process": ("process",), "file": ("file",), "registry": ("registry",),
                 "net": ("network", "process")}

# A decoded ETW event's id mapped to a plain action word, per provider. Unknown ids fall back to "event-<id>".
# Kernel-Process: 1 start, 2 stop, 5 image load, 6 image unload, 15 rundown (a process already running).
_PROCESS_ACTION = {1: "start", 2: "stop", 5: "image", 6: "image-unload", 15: "present"}
_FILE_ACTION = {12: "create", 30: "create", 26: "delete", 15: "read", 16: "write", 19: "rename", 29: "rename"}
_REGISTRY_ACTION = {1: "create", 2: "open", 3: "delete", 5: "set", 6: "delete-value", 7: "query"}

# Kernel-Process events that authoritatively name a pid: start (1) and rundown (15). Both carry the subject
# process in the ProcessID property (the EVENT_HEADER pid is the creator for a start, so it must not be used).
_PROCESS_NAME_EVENTS = frozenset({1, 15})
_IMAGE_EVENTS = frozenset({5, 6})  # image load/unload: the DLL is the ImageName, not the process's own program


def _basename(path) -> str:
    """A program's name without its folder (either kind of slash); "" for nothing."""
    if not path:
        return ""
    return str(path).replace("\\", "/").rsplit("/", 1)[-1] or str(path)


def _image_path(props: dict) -> str:
    return props.get("ImageName") or props.get("ImageFileName") or ""


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _subject_pid(rec):
    """The pid a Kernel-Process record is really about. For start (1) and rundown (15) that is the ProcessID
    property (the new or enumerated process), not the EVENT_HEADER pid (the creator, for a start)."""
    if rec.event_id in _PROCESS_NAME_EVENTS:
        pid = _int(rec.props.get("ProcessID") or rec.props.get("ProcessId"))
        if pid is not None:
            return pid
    return int(rec.pid) if rec.pid else None


def _port_key(port):
    """A port for sorting a connection key: its number, or -1 when it is not known (so None never meets an int
    in a sort)."""
    p = _int(port)
    return -1 if p is None else p


def _net_key(ip1, port1, ip2, port2):
    """A connection key that is the same whichever end is the local one (both orientations canonicalised)."""
    a, b = (str(ip1), _int(port1)), (str(ip2), _int(port2))
    return tuple(sorted((a, b), key=lambda e: (e[0], _port_key(e[1]))))


def _fmt(endpoint) -> str:
    """An (address, port) endpoint as "address:port" (or just the address when the port is not known); "" for no
    address."""
    ip, port = endpoint
    if ip is None:
        return ""
    return f"{ip}:{port}" if port is not None else str(ip)


def _endpoints(packet):
    """(local, remote, action) for a packet, from its direction (local is this machine's end)."""
    direction = getattr(packet, "dir", None)
    src = (getattr(packet, "src", None), getattr(packet, "sport", None))
    dst = (getattr(packet, "dst", None), getattr(packet, "dport", None))
    if direction == "in":
        return dst, src, "in"
    if direction == "out":
        return src, dst, "out"
    return src, dst, (direction or "local")


class Attribution:
    """Who owns a connection, learned from ETW while a tab is watched: a pid's program name from Kernel-Process
    records, and a connection's pid and program from Kernel-Network records. Every table is capped and the
    least-recently-used entry falls out, so the memory is bounded. Touched from the pump thread alone."""

    def __init__(self, cap: int = MAP_CAP):
        self.cap = max(1, int(cap))
        self._program: collections.OrderedDict = collections.OrderedDict()   # pid -> program
        self._conn: collections.OrderedDict = collections.OrderedDict()      # net key -> (pid, program)
        self._endpoint: collections.OrderedDict = collections.OrderedDict()  # (ip, port) -> (pid, program)

    def _put(self, table, key, value) -> None:
        if key in table:
            table.move_to_end(key)
        table[key] = value
        while len(table) > self.cap:
            table.popitem(last=False)

    def note_process(self, rec) -> None:
        """Name a pid from a Kernel-Process record. Only start (1) and rundown (15) records name a pid, and they
        name their ProcessID property, so a creator is not renamed after its child and a process is not renamed
        after a DLL it loads (an image record does neither)."""
        if rec.event_id not in _PROCESS_NAME_EVENTS:
            return
        pid = _subject_pid(rec)
        program = _basename(_image_path(rec.props))
        if pid and program:
            self._put(self._program, int(pid), program)

    def program_of(self, pid) -> str:
        if pid is None:
            return ""
        program = self._program.get(int(pid))
        if program is not None:
            self._program.move_to_end(int(pid))
            return program
        return ""

    def note_network(self, rec) -> None:
        p = rec.props
        pid = _int(p.get("PID")) if p.get("PID") is not None else (int(rec.pid) if rec.pid else None)
        saddr, sport, daddr, dport = p.get("saddr"), p.get("sport"), p.get("daddr"), p.get("dport")
        program = self.program_of(pid) or None
        if None not in (saddr, sport, daddr, dport):
            self._put(self._conn, _net_key(saddr, sport, daddr, dport), (pid, program))
        if saddr is not None and sport is not None:
            self._put(self._endpoint, (str(saddr), _int(sport)), (pid, program))
        if daddr is not None and dport is not None:
            self._put(self._endpoint, (str(daddr), _int(dport)), (pid, program))

    def for_packet(self, local, remote):
        """(pid, program) for a packet's endpoints, (None, None) when the flow was never seen on ETW. The exact
        connection is tried first, then this machine's own (local) endpoint. The remote endpoint is never used as
        a fallback: a popular server ip:port is shared by many flows and would attribute one to another's pid."""
        if local[0] is None or remote[0] is None:
            return None, None
        key = _net_key(local[0], local[1], remote[0], remote[1])
        hit = self._conn.get(key)
        if hit is not None:
            self._conn.move_to_end(key)
            return hit
        hit = self._endpoint.get((str(local[0]), _int(local[1])))
        return hit if hit is not None else (None, None)


def _proc_extra(props: dict) -> dict:
    extra = {}
    if props.get("CommandLine"):
        extra["command_line"] = props["CommandLine"]
    if props.get("ExitCode") is not None:
        extra["exit_code"] = props["ExitCode"]
    return extra


def event_fields_from_etw(rec, attribution: Attribution) -> dict | None:
    """The Event fields (kind, action and the rest, but not seq or time) for one ETW record, or None when the
    record is only used for attribution (a Kernel-Network record)."""
    if rec.provider == "process":
        action = _PROCESS_ACTION.get(rec.event_id, f"event-{rec.event_id}")
        if rec.event_id in _IMAGE_EVENTS:  # an image load/unload belongs to the loading process; the DLL is the path
            loader = int(rec.pid) if rec.pid else None
            return {"kind": "process", "action": action, "pid": loader, "ppid": None,
                    "program": attribution.program_of(loader), "path": _image_path(rec.props), "local": "",
                    "remote": "", "proto": "", "bytes": 0, "extra": {}}
        pid = _subject_pid(rec)
        image = _image_path(rec.props)
        program = _basename(image) or attribution.program_of(pid)
        return {"kind": "process", "action": action, "pid": pid,
                "ppid": _int(rec.props.get("ParentProcessID") or rec.props.get("ParentProcessId")),
                "program": program, "path": image, "local": "", "remote": "", "proto": "", "bytes": 0,
                "extra": _proc_extra(rec.props)}
    if rec.provider == "file":
        return {"kind": "file", "action": _FILE_ACTION.get(rec.event_id, "open"),
                "pid": int(rec.pid) if rec.pid else None, "ppid": None,
                "program": attribution.program_of(rec.pid), "path": rec.props.get("FileName") or "", "local": "",
                "remote": "", "proto": "", "bytes": 0, "extra": {}}
    if rec.provider == "registry":
        extra = {"value": rec.props["ValueName"]} if rec.props.get("ValueName") else {}
        return {"kind": "registry", "action": _REGISTRY_ACTION.get(rec.event_id, f"event-{rec.event_id}"),
                "pid": int(rec.pid) if rec.pid else None, "ppid": None,
                "program": attribution.program_of(rec.pid),
                "path": rec.props.get("KeyName") or rec.props.get("RelativeName") or "", "local": "", "remote": "",
                "proto": "", "bytes": 0, "extra": extra}
    return None  # network records attribute packets; they are not emitted on their own


def event_fields_from_packet(packet, attribution: Attribution) -> dict:
    """The Event fields for one captured packet, with its pid and program filled from the ETW attribution when
    the flow is known. (Kept for callers that want a single packet's fields; the watch itself aggregates into
    flows, see `_Flow`.)"""
    local, remote, action = _endpoints(packet)
    pid, program = attribution.for_packet(local, remote)
    extra = {}
    flags = getattr(packet, "flags", None)
    if flags:
        extra["flags"] = int(flags)
    return {"kind": "net", "action": action, "pid": pid, "ppid": None, "program": program or "", "path": "",
            "local": _fmt(local), "remote": _fmt(remote), "proto": getattr(packet, "proto", "") or "",
            "bytes": int(getattr(packet, "length", 0) or 0), "extra": extra}


_TCP_TEARDOWN = capturemod.FIN | capturemod.RST


class _Flow:
    """A connection being aggregated: its endpoints and direction, bytes and packet count, the TCP flags seen so
    far, and whether its start event has been emitted yet (deferred until it is attributed or `ATTR_HOLD` has
    passed, so a flow's first packets are not given to the wrong process before its ETW record arrives)."""

    __slots__ = ("local", "remote", "dir", "proto", "first", "last", "bytes", "packets", "flags",
                 "started", "pid", "program")

    def __init__(self, local, remote, direction, proto, now, length, flags):
        self.local, self.remote, self.dir, self.proto = local, remote, direction, proto
        self.first = self.last = now
        self.bytes = int(length)
        self.packets = 1
        self.flags = int(flags)
        self.started = False
        self.pid = None
        self.program = ""


class NpcapEtwWatch(Watch):
    """The Windows backend of the eBPF watch service, a `Watch` over the kinds in {net, process, file, registry}.
    `spec` carries the capture target (`address`, `ports`), the `tag` for the ETW session, and may override
    `poll`, the capture queue, `flow_idle` and `attr_hold`. `capture_factory()` and `etw_factory(providers)`
    stand in for Npcap and ETW in tests; nothing real is opened unless they are left to their defaults. Event
    times are the watch's clock (monotonic, so the self-stop timer is immune to a wall-clock step), the same
    shape `BpftraceWatch` emits."""

    system = "windows"

    def __init__(self, kinds, spec: dict | None = None, *, capture_factory=None, etw_factory=None,
                 timeout: float = DEFAULT_TIMEOUT, ring: int = DEFAULT_RING, clock=time.monotonic):
        super().__init__(kinds, spec, timeout=timeout, ring=ring, clock=clock)
        self._poll = min(5.0, max(MIN_POLL, float(self.spec.get("poll", DEFAULT_POLL))))
        self._flow_idle = min(60.0, max(0.5, float(self.spec.get("flow_idle", FLOW_IDLE))))
        self._attr_hold = min(10.0, max(0.0, float(self.spec.get("attr_hold", ATTR_HOLD))))
        self._providers = self._providers_for(self.kinds)
        self._capture_factory = capture_factory or self._default_capture
        self._etw_factory = etw_factory or self._default_etw
        self._attr = Attribution()
        self._flows: collections.OrderedDict = collections.OrderedDict()  # flow key -> _Flow (bounded)
        self._packets: collections.deque = collections.deque(maxlen=self._queue_size())
        self._packets_dropped = 0
        self._etw = None
        self._capture = None
        self._pump_thread: threading.Thread | None = None
        self._src_lock = threading.Lock()  # guards opening the sources in _begin and tearing them down in _end
        self._torn = False

    def _queue_size(self) -> int:
        try:
            size = int(self.spec.get("queue", PACKET_QUEUE))
        except (TypeError, ValueError):
            size = PACKET_QUEUE
        return min(MAX_PACKET_QUEUE, max(1, size))

    @staticmethod
    def _providers_for(kinds) -> tuple[str, ...]:
        provs: set[str] = set()
        for kind in kinds:
            provs.update(_PROVIDER_FOR.get(kind, ()))
        return tuple(sorted(provs))

    def _default_capture(self):
        # The Filter tab needs UDP (DNS, QUIC on 443) and IPv6, and the payload bytes the plugin reads names from,
        # so UDP and payloads are on and the capture is not pinned to one address family (host=False). The spec may
        # override each; an explicit address is still used to choose the adapter.
        return capturemod.Capture(
            self.spec.get("address"), self.spec.get("ports", ()),
            udp=bool(self.spec.get("udp", True)), payloads=bool(self.spec.get("payloads", True)),
            host=bool(self.spec.get("host", False)))

    def _default_etw(self, providers):
        return etwmod.EtwConsumer(self.spec.get("tag", "watch"), providers=tuple(providers))

    # -- lifecycle (the base calls these) --------------------------------------------------------------------

    def _begin(self) -> None:
        """Open ETW for the kinds that need it and Npcap for net, then start the one pump thread. A failure to
        open either is said in `error` and stops the watch rather than raising, as BpftraceWatch does. The open and
        the teardown share one lock, and the open is skipped once a stop has arrived, so a stop() that races the
        open never leaves a source running behind it."""
        with self._src_lock:
            if self._stop.is_set() or self._torn:  # stop() already arrived: open nothing
                return
            try:
                if self._providers:
                    self._etw = self._etw_factory(self._providers)
                    self._etw.start()
                if "net" in self.kinds:
                    self._capture = self._capture_factory()
                    self._capture.on_packet = self._queue_packet
                    self._capture.start()
            except Exception as e:  # noqa: BLE001 - no Npcap, no adapter, no ETW session: said, and the watch stops
                self.error = str(e) or type(e).__name__
                self._teardown_locked()
                self._stop.set()
                return
            self._pump_thread = threading.Thread(target=self._pump, name="npcap-etw-watch", daemon=True)
            self._pump_thread.start()

    def _end(self) -> None:
        """Close the sources and wait for the pump. Called once by the base on stop() or the self-stop."""
        self._teardown_sources()
        thread = self._pump_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=4.0)

    def _teardown_sources(self) -> None:
        with self._src_lock:
            self._teardown_locked()

    def _teardown_locked(self) -> None:
        """Stop whatever sources are open, once. Called with `_src_lock` held, so a teardown racing the open in
        `_begin` either runs after the sources are up (and stops them) or marks the watch torn before they open
        (and `_begin` then opens nothing)."""
        if self._torn:
            return
        self._torn = True
        if self._capture is not None:
            try:
                self._capture.stop()
            except Exception:  # noqa: BLE001 - already gone
                pass
        if self._etw is not None:
            try:
                self._etw.stop()
            except Exception:  # noqa: BLE001
                pass

    # -- the pump --------------------------------------------------------------------------------------------

    def _queue_packet(self, packet) -> None:
        """A captured packet from the capture thread: queued (never attributed here, so the attribution tables
        stay the pump thread's alone). The bounded queue drops the oldest under a flood, and the drop is counted."""
        if self._packets.maxlen is not None and len(self._packets) >= self._packets.maxlen:
            self._packets_dropped += 1
        self._packets.append(packet)

    def _pump(self) -> None:
        """Drain ETW and the queued packets into events until the watch stops, then once more so the last events
        are not lost, and close the open flows. One thread; it exits the moment the watch is stopped from anywhere."""
        try:
            while not self._stop.is_set():
                self._pump_once()
                self._stop.wait(self._poll)
            self._pump_once()
            if "net" in self.kinds:
                self._sweep_flows(final=True)
        except Exception:  # noqa: BLE001 - the pump never takes the process down
            pass

    def _pump_once(self) -> None:
        if self._etw is not None:
            for rec in self._etw.drain():
                if rec.provider == "process":
                    self._attr.note_process(rec)
                elif rec.provider == "network":
                    self._attr.note_network(rec)
                fields = event_fields_from_etw(rec, self._attr)
                if fields is not None and fields["kind"] in self.kinds:
                    self._emit(fields.pop("kind"), fields.pop("action"), **fields)
        if "net" in self.kinds:
            while True:
                try:
                    packet = self._packets.popleft()
                except IndexError:
                    break
                self._on_packet(packet)
            self._sweep_flows()

    # -- flow aggregation (net) ------------------------------------------------------------------------------

    def _on_packet(self, packet) -> None:
        """Fold one packet into its flow. A new flow is remembered (and its start deferred); a known flow only
        grows its counters. A TCP FIN or RST closes the flow at once."""
        local, remote, action = _endpoints(packet)
        if local[0] is None and remote[0] is None:
            return
        proto = getattr(packet, "proto", "") or ""
        key = (_net_key(local[0], local[1], remote[0], remote[1]), proto)
        now = self._clock()
        length = int(getattr(packet, "length", 0) or 0)
        flags = int(getattr(packet, "flags", 0) or 0)
        flow = self._flows.get(key)
        if flow is None:
            flow = _Flow(local, remote, action, proto, now, length, flags)
            self._flows[key] = flow
            self._flows.move_to_end(key)
            while len(self._flows) > MAP_CAP:  # bounded: the oldest flow is closed out and dropped
                _old_key, old = self._flows.popitem(last=False)
                self._emit_flow_end(old)
        else:
            flow.last = now
            flow.bytes += length
            flow.packets += 1
            flow.flags |= flags
            self._flows.move_to_end(key)
        if proto == "tcp" and (flags & _TCP_TEARDOWN):
            self._emit_flow_end(flow)
            self._flows.pop(key, None)

    def _emit_flow_start(self, flow: _Flow, force: bool = False) -> None:
        """Emit a flow's start event, once. Held back until the flow is attributed or (force, or `attr_hold` old)
        so it is not given to the wrong process; then attributed from one lookup for the whole flow."""
        if flow.started:
            return
        pid, program = self._attr.for_packet(flow.local, flow.remote)
        if pid is None and not force and (self._clock() - flow.first) < self._attr_hold:
            return
        flow.started = True
        flow.pid, flow.program = pid, (program or "")
        extra = {"packets": flow.packets}
        if flow.flags:
            extra["flags"] = flow.flags
        self._emit("net", flow.dir, pid=pid, ppid=None, program=flow.program, path="",
                   local=_fmt(flow.local), remote=_fmt(flow.remote), proto=flow.proto, bytes=flow.bytes,
                   extra=extra)

    def _emit_flow_end(self, flow: _Flow) -> None:
        """Emit a flow's close event with its totals (starting it first if it never emitted, so a one-off
        connection is never lost)."""
        self._emit_flow_start(flow, force=True)
        extra = {"packets": flow.packets, "duration": max(0.0, flow.last - flow.first)}
        if flow.flags:
            extra["flags"] = flow.flags
        self._emit("net", "close", pid=flow.pid, ppid=None, program=flow.program, path="",
                   local=_fmt(flow.local), remote=_fmt(flow.remote), proto=flow.proto, bytes=flow.bytes,
                   extra=extra)

    def _sweep_flows(self, final: bool = False) -> None:
        """Each pump: start the flows now attributable or aged, and close the ones gone idle (or all of them on the
        final pump)."""
        now = self._clock()
        for key in list(self._flows.keys()):
            flow = self._flows.get(key)
            if flow is None:
                continue
            self._emit_flow_start(flow)
            if final or (now - flow.last) >= self._flow_idle:
                self._emit_flow_end(flow)
                self._flows.pop(key, None)

    # -- loss / health ---------------------------------------------------------------------------------------

    def stats(self) -> dict:
        """What has been dropped, so a page can say so (the design: losses are not silent). `packets_dropped` are
        packets the capture handed in faster than the pump drained; `etw_dropped` the consumer's own oldest-dropped
        count; `etw_events_lost` ETW's own loss counter at stop."""
        etw = self._etw
        return {"packets_dropped": self._packets_dropped,
                "etw_dropped": int(getattr(etw, "drops", 0)) if etw is not None else 0,
                "etw_events_lost": int(getattr(etw, "events_lost", 0)) if etw is not None else 0,
                "flows_open": len(self._flows)}


def available() -> tuple[bool, str]:
    """Whether this backend can watch here (Npcap for net and an ETW session), and why not."""
    cap_ok, cap_why = capturemod.available()
    etw_ok, etw_why = etwmod.available()
    if cap_ok and etw_ok:
        return True, "Npcap and ETW"
    return (False, cap_why) if not cap_ok else (False, etw_why)
