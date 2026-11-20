"""This machine's way out to the internet, for the platform's hw-stats plugin's path check (the user, 2026-11-08: "i
have this computer as DMZ host so, basically the check needs to validate the computer, the router/gateway to the
computer, then the internet to the computer"): its address on the local network and its gateway (`local_route`), a
ping (`ping`), the first routers on the way to an address (`hops`) and what kind of address each is (`kind`: a
private or a carrier's shared address after the home router means another NAT stands between it and the internet).
1.67.0: a whole route (`trace`), for every connection's route on the firewalls' globe (machines/routes.py): on
Windows through its ICMP API (iphlpapi's IcmpSendEcho, no administrator; every hop asked at once), elsewhere and for
IPv6 the system's tracert, traceroute or tracepath; only to a public address given as one, never a name.
The system's ping and tracert/traceroute run windowless; nothing here names an outside host: the caller gives the
address to trace to (the router's UPnP answer is the plugin's: it speaks a protocol with namespaces of its own)."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

NO_ROUTE_PROBE = "192.0.2.1"  # TEST-NET-1: a UDP socket "connected" to it shows the address the default route uses (nothing is sent)
SHARED = ipaddress.ip_network("100.64.0.0/10")  # carriers' NAT (RFC 6598)


@dataclass(frozen=True)
class Route:
    """This machine on its local network: the address it goes out from, its gateway (the router), the interface."""
    address: str | None
    gateway: str | None
    interface: str = ""


def _no_window() -> dict:
    return {"creationflags": 0x08000000} if os.name == "nt" else {}  # CREATE_NO_WINDOW


def _run(args: list[str], timeout: float) -> str | None:
    try:
        return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                              stdin=subprocess.DEVNULL, **_no_window()).stdout
    except (OSError, subprocess.SubprocessError):
        return None


def kind(address: str | None) -> str:
    """What an address is: public, private (a home or office network), shared (a carrier's NAT, 100.64/10),
    loopback, link-local, or unknown."""
    try:
        ip = ipaddress.ip_address(str(address))
    except ValueError:
        return "unknown"
    if ip.version == 4 and ip in SHARED:
        return "shared"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    return "public" if ip.is_global else "unknown"


def lan_address(probe: str = NO_ROUTE_PROBE) -> str | None:
    """The address this machine goes out from (the default route's): a UDP socket "connected" to `probe` says it."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((probe, 9))
            address = s.getsockname()[0]
    except OSError:
        return None
    return None if address.startswith("0.") else address


def _gateway_windows(probe: str) -> tuple[str | None, str]:
    import ctypes
    from ctypes import wintypes as w

    class Row(ctypes.Structure):
        _fields_ = [(n, w.DWORD) for n in ("dest", "mask", "policy", "next_hop", "if_index", "type", "proto", "age",
                                           "next_hop_as", "m1", "m2", "m3", "m4", "m5")]
    try:
        get = ctypes.WinDLL("iphlpapi").GetBestRoute
    except (OSError, AttributeError):
        return None, ""
    get.argtypes = [w.DWORD, w.DWORD, ctypes.POINTER(Row)]
    row = Row()
    if get(struct.unpack("<I", socket.inet_aton(probe))[0], 0, ctypes.byref(row)) != 0:
        return None, ""
    hop = socket.inet_ntoa(struct.pack("<I", row.next_hop))
    return (None if hop == "0.0.0.0" else hop), str(row.if_index)


def _gateway_linux(table: str | None = None) -> tuple[str | None, str]:
    if table is None:
        try:
            with open("/proc/net/route", encoding="ascii") as f:
                table = f.read()
        except OSError:
            return None, ""
    best = None
    for line in table.splitlines()[1:]:
        f = line.split()
        if len(f) < 8 or f[1] != "00000000" or not int(f[3], 16) & 0x2:  # the default route, through a gateway
            continue
        metric = int(f[6]) if f[6].isdigit() else 0
        if best is None or metric < best[0]:
            best = (metric, socket.inet_ntoa(struct.pack("<I", int(f[2], 16))), f[0])
    return (best[1], best[2]) if best else (None, "")


def local_route(probe: str = NO_ROUTE_PROBE) -> Route:
    """This machine's address on its network and its gateway (Windows: GetBestRoute; Linux: /proc/net/route)."""
    gateway, interface = _gateway_windows(probe) if sys.platform == "win32" else _gateway_linux()
    return Route(lan_address(probe), gateway, interface)


def ping(host: str, timeout: float = 1.0, run=None) -> float | None:
    """The round trip to `host` in milliseconds (the system's ping, one echo), None when it did not answer."""
    run = run or _run
    if sys.platform == "win32":
        out = run(["ping", "-n", "1", "-w", str(int(timeout * 1000)), host], timeout + 5)
        answered = out is not None and "TTL=" in out.upper()
    else:
        out = run(["ping", "-c", "1", "-W", str(max(1, round(timeout))), host], timeout + 5)
        answered = out is not None and "ttl=" in out.lower()
    if not answered:
        return None
    m = re.search(r"time\s*([=<])\s*(\d+(?:\.\d+)?)\s*ms", out, flags=re.I)
    return (float(m.group(2)) / (2 if m.group(1) == "<" else 1)) if m else 0.0


def hops(target: str, count: int = 3, wait_ms: int = 700, run=None) -> list[str | None] | None:
    """The first `count` routers on the way to `target` (an address), each hop's address or None when it did not
    answer; None when no tracer could run (Windows: tracert; elsewhere traceroute, else tracepath)."""
    run = run or _run
    if sys.platform == "win32":
        out = run(["tracert", "-d", "-h", str(count), "-w", str(wait_ms), target], count * 3 * wait_ms / 1000 + 10)
    else:
        out = run(["traceroute", "-n", "-m", str(count), "-q", "1", "-w", str(max(1, round(wait_ms / 1000))), target],
                  count * wait_ms / 1000 + 10)
        if out is None:
            out = run(["tracepath", "-n", "-m", str(count), target], count * 3 + 10)
    if out is None:
        return None
    found: dict[int, str | None] = {}
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+)[:?]?\s+(.*)$", line)
        if not m or int(m.group(1)) < 1 or int(m.group(1)) > count:
            continue
        n = int(m.group(1))
        addresses = [a for a in re.findall(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", m.group(2)) if a != target or n == count]
        if n not in found or found[n] is None:
            found[n] = addresses[-1] if addresses else None
    return [found.get(n) for n in range(1, count + 1)] if found else None


# -- a whole route (1.67.0) ----------------------------------------------------------------------------------------
TRACE_HOPS = 30  # routers asked at most: the tracers' own default
TRACE_WAIT_MS = 1000  # how long a probe waits for its answer (Windows' ICMP API, traceroute)
TRACERT_WAIT_MS = 500  # tracert's, which asks each hop three times in turn: 45 s at most for 30 hops
WAVE = 16  # hops asked at once through the ICMP API: the next ones only when the target did not answer within them
IP_SUCCESS = 0  # the ICMP API's status for the target's own echo reply
IP_TTL_EXPIRED = 11013  # ... and for a router on the way whose time to live ran out: the route goes on past it
ANSWERED = (IP_SUCCESS, 11002, 11003, 11004, 11005, 11013)  # replies naming who sent them: unreachables, time exceeded
REPLY_BYTES = 256  # the reply buffer: an ICMP_ECHO_REPLY (40 bytes at most), the 32 bytes sent back, an error's 8
PAYLOAD = bytes(32)  # what each probe carries, as tracert's
_RTT = re.compile(r"(<)?\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.I)
_HOP = re.compile(r"^\s*(\d+)\??:?\s+(.*)$")


@dataclass(frozen=True)
class Hop:
    """One router on a route: its number (1: this network's gateway), the address that answered (None when nothing did
    within the wait) and the quickest round trip to it in milliseconds (None when nothing answered)."""
    n: int
    address: str | None
    ms: float | None = None


@dataclass(frozen=True)
class Trace:
    """A route traced to `target`: its hops in order, the target's own last when it answered (`reached`); how it was
    traced ("icmp": Windows' ICMP API; else "tracert", "traceroute" or "tracepath"); and why nothing was, when nothing
    could be (`error`)."""
    target: str
    hops: tuple[Hop, ...] = ()
    reached: bool = False
    how: str = ""
    error: str = ""


def traceable(address) -> str:
    """`address` as a route is traced to it: a public IPv4 or IPv6 address (an IPv4 one carried in IPv6 as itself).
    ValueError, in words, for anything else: a name is never looked up, and the local network's addresses have no
    route on the internet."""
    try:
        ip = ipaddress.ip_address(str(address).split("%")[0].strip())
    except ValueError:
        raise ValueError(f"{str(address)[:60]!r} is no address: a route is traced to an address, never to a name") from None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_multicast or ip.is_reserved or getattr(ip, "is_site_local", False) or kind(str(ip)) != "public":
        raise ValueError(f"{ip} is not on the internet ({kind(str(ip))}): only a public address has a route traced")
    return str(ip)


def _address_in(token: str) -> str | None:
    try:
        return str(ipaddress.ip_address(token.strip("()[],").split("%")[0]))
    except ValueError:
        return None


def parse_trace(text: str | None, target: str, max_hops: int = TRACE_HOPS) -> tuple[Hop, ...]:
    """The hops a tracer's words list (tracert's, traceroute's, tracepath's lines that begin with a hop's number; the
    rest of what they say is left), in order: each its address (the last its line names) and its quickest round trip
    ("<1 ms" counted as half a millisecond). A hop no line names did not answer; the hops past the target are left
    out."""
    found: dict[int, Hop] = {}
    for line in (text or "").splitlines():
        m = _HOP.match(line)
        if not m or not 1 <= int(m.group(1)) <= max_hops:
            continue
        n, rest = int(m.group(1)), m.group(2)
        addresses = [a for a in map(_address_in, rest.split()) if a]
        times = [float(v.replace(",", ".")) / (2 if lt else 1) for lt, v in _RTT.findall(rest)]
        hop = Hop(n, addresses[-1] if addresses else None, min(times) if times and addresses else None)
        if n not in found or (found[n].address is None and hop.address is not None):  # tracepath's "1?:" then "1:"
            found[n] = hop
    hops = [found.get(n, Hop(n, None)) for n in range(1, max(found) + 1)] if found else []
    for i, h in enumerate(hops):
        if h.address == target:
            return tuple(hops[:i + 1])
    return tuple(hops)


def _commands(target: str, max_hops: int, windows: bool) -> list[tuple[str, list[str], float]]:
    """The system's tracers for `target`, in the order tried: (name, its words, how long it may take)."""
    six = ["-6"] if ":" in target else []
    if windows:
        return [("tracert", ["tracert", "-d", "-h", str(max_hops), "-w", str(TRACERT_WAIT_MS), *(six or ["-4"]), target],
                 max_hops * 3 * TRACERT_WAIT_MS / 1000 + 15)]
    wait = max(1, round(TRACE_WAIT_MS / 1000))
    return [("traceroute", ["traceroute", "-n", "-q", "1", "-w", str(wait), "-m", str(max_hops), *six, target],
             max_hops * wait + 15),
            ("tracepath", ["tracepath", "-n", "-m", str(max_hops), *six, target], max_hops * 3 + 15)]


def _trace_run(args: list[str], timeout: float, stop=None) -> tuple[str | None, str]:
    """A tracer run windowless: (what it wrote, the first line of its errors). What it wrote so far when it ran past
    `timeout` or `stop()` turned true: it is killed then, so no tracer outlives the tab or the plugin. None when it
    could not start."""
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                text=True, encoding="utf-8", errors="replace", **_no_window())
    except (OSError, ValueError):
        return None, ""
    deadline = time.monotonic() + timeout
    while True:
        try:
            out, err = proc.communicate(timeout=0.25)
            break
        except subprocess.TimeoutExpired:
            if time.monotonic() >= deadline or (stop is not None and stop()):
                proc.kill()
                out, err = proc.communicate()
                break
    lines = (err or "").strip().splitlines()
    return out or "", lines[0][:200] if lines else ""


def _tool_trace(target: str, max_hops: int, run, windows: bool, stop=None) -> Trace:
    """The system's tracers in turn: the first that lists a hop gives the route (its silent hops past the last that
    answered left out when it did not reach the target, as the ICMP path leaves them); one that is not here, or that
    lists none (it says why, or nothing), hands over to the next. `stop()` true: no more is run."""
    said = []
    for name, args, timeout in _commands(target, max_hops, windows):
        if stop is not None and stop():
            break
        out, err = run(args, timeout, stop)
        if out is None:
            said.append(f"{name} is not here")
            continue
        hops = parse_trace(out, target, max_hops)
        if not hops:
            said.append(f"{name}: {err or 'it listed no hop'}")
            continue
        reached = hops[-1].address == target
        while not reached and hops and hops[-1].address is None:
            hops = hops[:-1]
        return Trace(target, hops, reached, name)
    return Trace(target, error=("no tracer traced it here: " + "; ".join(said)) if said else "stopped")


_ICMP = None


def _icmp_api():
    """iphlpapi's ICMP functions with their types (Windows), loaded once."""
    global _ICMP
    if _ICMP is None:
        import ctypes
        from ctypes import wintypes
        api = ctypes.WinDLL("iphlpapi", use_last_error=True)
        api.IcmpCreateFile.restype = wintypes.HANDLE
        api.IcmpCreateFile.argtypes = []
        api.IcmpCloseHandle.restype = wintypes.BOOL
        api.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        api.IcmpSendEcho.restype = wintypes.DWORD
        api.IcmpSendEcho.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD, ctypes.c_void_p,
                                     ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        _ICMP = api
    return _ICMP


def _icmp_probe(target: str, ttl: int, wait_ms: int) -> tuple[str | None, float | None, int | None]:
    """One ICMP echo to `target` (IPv4) with this time to live, through Windows' ICMP API (no administrator): who
    answered, the round trip in milliseconds, and the API's status (IP_SUCCESS: the target's own echo reply;
    IP_TTL_EXPIRED: a router on the way; else an unreachable); (None, None, None) when nothing answered. OSError when
    the API cannot be used."""
    import ctypes

    class Options(ctypes.Structure):  # IP_OPTION_INFORMATION, as this process's own width lays it out
        _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                    ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]
    api = _icmp_api()
    handle = api.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "IcmpCreateFile failed")
    try:
        options = Options(Ttl=ttl)
        reply = ctypes.create_string_buffer(REPLY_BYTES)
        data = ctypes.create_string_buffer(PAYLOAD, len(PAYLOAD))
        began = time.perf_counter()
        api.IcmpSendEcho(handle, struct.unpack("<I", socket.inet_aton(target))[0], data, len(PAYLOAD),
                         ctypes.byref(options), reply, REPLY_BYTES, wait_ms)
        took = (time.perf_counter() - began) * 1000
        # Address, Status and RoundTripTime lead ICMP_ECHO_REPLY in either width (the 32-bit layout too)
        address, status, rtt = struct.unpack_from("<III", reply.raw, 0)
    finally:
        api.IcmpCloseHandle(handle)
    if not address or status not in ANSWERED:
        return None, None, None
    return (socket.inet_ntoa(struct.pack("<I", address)), float(rtt) if status == IP_SUCCESS and rtt else round(took, 1),
            status)


def _icmp_trace(target: str, max_hops: int, wait_ms: int, probe, stop=None) -> Trace:
    """Every hop of a wave of WAVE asked at once (about a second a wave); the next wave only when no answer within
    this one ended the route. A route ends at the first hop that answers other than "time exceeded" (the target's
    echo reply, or an unreachable: from the target, or from a router that passes it no further) or that is the target
    itself; `reached` when that answer is the target's. A route that did not end leaves out its hops past the last
    that answered. `stop()` true between two waves: no more is asked."""
    answers: dict[int, tuple] = {}
    failures = 0
    end = 0
    for first in range(1, max_hops + 1, WAVE):
        if first > 1 and stop is not None and stop():
            break
        ttls = list(range(first, min(max_hops, first + WAVE - 1) + 1))
        with ThreadPoolExecutor(max_workers=len(ttls), thread_name_prefix="liminal-trace") as pool:
            futures = {ttl: pool.submit(probe, target, ttl, wait_ms) for ttl in ttls}
        for ttl, f in futures.items():
            try:
                answers[ttl] = f.result()
            except OSError:
                failures += 1
                answers[ttl] = (None, None, None)
        if failures == len(answers):  # the API could not be used at all
            raise OSError("Windows' ICMP API could not be used")
        end = min((ttl for ttl, (who, _ms, status) in answers.items()
                   if who and (status != IP_TTL_EXPIRED or who == target)), default=0)
        if end:
            break
    last = end or max((ttl for ttl, a in answers.items() if a[0]), default=0)
    hops = tuple(Hop(ttl, answers[ttl][0], answers[ttl][1]) for ttl in range(1, last + 1))
    reached = bool(end) and (answers[end][2] == IP_SUCCESS or answers[end][0] == target)
    return Trace(target, hops, reached, "icmp")


def trace(target, max_hops: int = TRACE_HOPS, wait_ms: int = TRACE_WAIT_MS, *, probe=None, run=None,
          windows: bool | None = None, stop=None) -> Trace:
    """The route to `target`, a public address (ValueError otherwise, before anything is sent: traceable). On Windows
    an IPv4 route is traced through its ICMP API (`probe`: one echo with a time to live), every hop of a wave asked at
    once; IPv6, and a Windows whose ICMP API cannot be used, through tracert; elsewhere through traceroute, else
    tracepath (`run(args, timeout, stop)`: the system's command, windowless, killed once `stop()` turns true). Each
    hop's address and quickest round trip; nothing is looked up by name."""
    target = traceable(target)
    windows = sys.platform == "win32" if windows is None else windows
    if windows and ":" not in target:
        try:
            return _icmp_trace(target, max_hops, wait_ms, probe or _icmp_probe, stop)
        except OSError:
            pass
    return _tool_trace(target, max_hops, run or _trace_run, windows, stop)
