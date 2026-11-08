"""This machine's way out to the internet, for the platform's hw-stats plugin's path check (the user, 2026-11-08: "i
have this computer as DMZ host so, basically the check needs to validate the computer, the router/gateway to the
computer, then the internet to the computer"): its address on the local network and its gateway (`local_route`), a
ping (`ping`), the first routers on the way to an address (`hops`) and what kind of address each is (`kind`: a
private or a carrier's shared address after the home router means another NAT stands between it and the internet).
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

