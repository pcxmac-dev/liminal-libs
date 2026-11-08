"""Packets on a port, watched for a while: a tcpdump in Python (the user, 2026-11-08: "if there is a python-tcpdump
that would be good ... as a listener"), for the platform's hw-stats plugin's path check. Through libpcap by ctypes,
no package: Npcap's wpcap.dll on Windows (with Wireshark or on its own; non-administrators may capture unless Npcap
was installed for administrators only), libpcap on Linux (root or CAP_NET_RAW). The adapter holding an address is
opened (not in promiscuous mode), a filter keeps TCP on the ports asked, and each packet's addresses, ports and
flags are kept (no payload). Packets are seen at the adapter, before the machine's firewall decides: a connection
the firewall drops still shows as its SYN arriving."""
from __future__ import annotations

import ctypes
import ctypes.util
import ipaddress
import os
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass

NPCAP = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
SNAPLEN = 128  # the headers alone: Ethernet, IP (with options), TCP
TIMEOUT_MS = 150  # a read's wait, so a stop is seen soon
MAX_PACKETS = 2000  # kept per capture
NETMASK_UNKNOWN = 0xFFFFFFFF
FLAGS = ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"))
LINK_ETHERNET, LINK_NULL, LINK_LOOP, LINK_RAW, LINK_RAW_ALT, LINK_LINUX_SLL = 1, 0, 108, 12, 101, 113


class CaptureError(Exception):
    """Packets cannot be watched here: no libpcap, no rights, no adapter with the address."""


@dataclass(frozen=True)
class Packet:
    """One TCP packet seen: when, from where to where, its flags ("SYN", "SYN ACK", "RST ACK" ...)."""
    at: float
    src: str
    sport: int
    dst: str
    dport: int
    flags: str

    @property
    def syn(self) -> bool:
        return self.flags.split()[:1] == ["SYN"] and "ACK" not in self.flags  # a connection asked for

    def as_dict(self) -> dict:
        return {"at": self.at, "src": self.src, "sport": self.sport, "dst": self.dst, "dport": self.dport, "flags": self.flags}


def tcp_flags(bits: int) -> str:
    return " ".join(name for bit, name in FLAGS if bits & bit) or "none"


def parse(frame: bytes, link: int, at: float = 0.0) -> Packet | None:
    """A captured frame's TCP packet (IPv4 or IPv6), None for anything else. `link`: the adapter's link type
    (Ethernet, BSD loopback, raw IP, Linux cooked)."""
    data = bytes(frame)
    if link == LINK_ETHERNET:
        if len(data) < 14:
            return None
        kind, at_ip = struct.unpack("!H", data[12:14])[0], 14
        while kind in (0x8100, 0x88A8) and len(data) >= at_ip + 4:  # VLAN tags
            kind, at_ip = struct.unpack("!H", data[at_ip + 2:at_ip + 4])[0], at_ip + 4
        version = {0x0800: 4, 0x86DD: 6}.get(kind)
        data = data[at_ip:]
    elif link in (LINK_NULL, LINK_LOOP):
        if len(data) < 4:
            return None
        family = struct.unpack("<I", data[:4])[0] if link == LINK_NULL else struct.unpack("!I", data[:4])[0]
        version, data = (4 if family == 2 else 6 if family in (10, 23, 24, 28, 30) else None), data[4:]
    elif link == LINK_LINUX_SLL:
        if len(data) < 16:
            return None
        version, data = {0x0800: 4, 0x86DD: 6}.get(struct.unpack("!H", data[14:16])[0]), data[16:]
    elif link in (LINK_RAW, LINK_RAW_ALT):
        version = (data[0] >> 4) if data else None
    else:
        return None
    if version == 4 and len(data) >= 20:
        head = (data[0] & 0x0F) * 4
        if data[9] != 6 or len(data) < head + 14:
            return None
        src, dst, tcp = socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20]), data[head:]
    elif version == 6 and len(data) >= 40:
        if data[6] != 6 or len(data) < 54:
            return None
        src = str(ipaddress.IPv6Address(data[8:24]))
        dst = str(ipaddress.IPv6Address(data[24:40]))
        tcp = data[40:]
    else:
        return None
    sport, dport = struct.unpack("!HH", tcp[:4])
    return Packet(at, src, sport, dst, dport, tcp_flags(tcp[13]))


def bpf(ports, address: str | None = None) -> str:
    """The filter for TCP on `ports` (both ways), to or from `address` when given."""
    wanted = " or ".join(f"port {int(p)}" for p in ports)
    return f"tcp and ({wanted})" + (f" and host {address}" if address else "")


# -- libpcap through ctypes ---------------------------------------------------------------------------------

class _Sockaddr(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort), ("data", ctypes.c_ubyte * 14)]


class _PcapAddr(ctypes.Structure):
    pass


_PcapAddr._fields_ = [("next", ctypes.POINTER(_PcapAddr)), ("addr", ctypes.POINTER(_Sockaddr)),
                      ("netmask", ctypes.POINTER(_Sockaddr)), ("broadaddr", ctypes.POINTER(_Sockaddr)),
                      ("dstaddr", ctypes.POINTER(_Sockaddr))]


class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [("next", ctypes.POINTER(_PcapIf)), ("name", ctypes.c_char_p), ("description", ctypes.c_char_p),
                    ("addresses", ctypes.POINTER(_PcapAddr)), ("flags", ctypes.c_uint)]


class _Timeval(ctypes.Structure):
    _fields_ = [("sec", ctypes.c_long), ("usec", ctypes.c_long)]


class _PktHdr(ctypes.Structure):
    _fields_ = [("ts", _Timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint), ("insns", ctypes.c_void_p)]


def load_pcap():
    """libpcap: Npcap's wpcap.dll on Windows, the system's libpcap on Linux; CaptureError when there is none."""
    if sys.platform == "win32":
        dll = os.path.join(NPCAP, "wpcap.dll")
        if not os.path.exists(dll):
            raise CaptureError("Npcap is not installed (npcap.com; Wireshark installs it): packets cannot be watched")
        try:
            os.add_dll_directory(NPCAP)  # its Packet.dll beside it
            lib = ctypes.CDLL(dll)
        except OSError as e:
            raise CaptureError(f"Npcap's wpcap.dll could not be loaded: {e}") from None
    else:
        name = ctypes.util.find_library("pcap")
        if not name:
            raise CaptureError("libpcap is not installed (libpcap0.8 or libpcap): packets cannot be watched")
        try:
            lib = ctypes.CDLL(name)
        except OSError as e:
            raise CaptureError(f"libpcap could not be loaded: {e}") from None
    lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_PcapIf)), ctypes.c_char_p]
    lib.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]
    lib.pcap_open_live.restype = ctypes.c_void_p
    lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
    lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram)]
    lib.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]
    lib.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_PktHdr)), ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    lib.pcap_datalink.argtypes = [ctypes.c_void_p]
    lib.pcap_close.argtypes = [ctypes.c_void_p]
    lib.pcap_geterr.restype = ctypes.c_char_p
    lib.pcap_geterr.argtypes = [ctypes.c_void_p]
    return lib


class PcapSource:
    """The adapter holding an address, opened through libpcap, read packet by packet (what Capture reads)."""

    def __init__(self, lib=None):
        self.lib = lib
        self.handle = None
        self.link = LINK_ETHERNET

    def device_of(self, address: str) -> str:
        """The adapter (its pcap name) holding `address`."""
        lib, err = self.lib, ctypes.create_string_buffer(256)
        found = ctypes.POINTER(_PcapIf)()
        if lib.pcap_findalldevs(ctypes.byref(found), err) != 0:
            raise CaptureError(f"the adapters could not be listed: {err.value.decode(errors='replace')}")
        try:
            dev = found
            while dev:
                a = dev.contents.addresses
                while a:
                    sa = a.contents.addr
                    if sa and sa.contents.family == socket.AF_INET and socket.inet_ntoa(bytes(sa.contents.data[2:6])) == address:
                        return dev.contents.name.decode()
                    a = a.contents.next
                dev = dev.contents.next
        finally:
            if found:
                lib.pcap_freealldevs(found)
        raise CaptureError(f"no adapter holds {address} (as libpcap lists them)")

    def open(self, address: str, ports) -> None:
        self.lib = self.lib or load_pcap()
        lib, err = self.lib, ctypes.create_string_buffer(256)
        device = self.device_of(address)
        handle = lib.pcap_open_live(device.encode(), SNAPLEN, 0, TIMEOUT_MS, err)
        if not handle:
            words = err.value.decode(errors="replace")
            raise CaptureError(f"the adapter could not be opened: {words}" + (
                " (packets are watched as root, or with CAP_NET_RAW)" if sys.platform != "win32" else ""))
        program = _BpfProgram()
        if lib.pcap_compile(handle, ctypes.byref(program), bpf(ports, address).encode(), 1, NETMASK_UNKNOWN) != 0 \
                or lib.pcap_setfilter(handle, ctypes.byref(program)) != 0:
            words = (lib.pcap_geterr(handle) or b"").decode(errors="replace")
            lib.pcap_close(handle)
            raise CaptureError(f"the filter could not be set: {words}")
        lib.pcap_freecode(ctypes.byref(program))
        self.handle, self.link = handle, lib.pcap_datalink(handle)

    def next(self) -> tuple[float, bytes] | None:
        """The next packet (its time, its first bytes), None when none came within the read's wait."""
        header, data = ctypes.POINTER(_PktHdr)(), ctypes.POINTER(ctypes.c_ubyte)()
        got = self.lib.pcap_next_ex(self.handle, ctypes.byref(header), ctypes.byref(data))
        if got == 1:
            h = header.contents
            return h.ts.sec + h.ts.usec / 1e6, ctypes.string_at(ctypes.cast(data, ctypes.c_void_p).value, min(h.caplen, SNAPLEN))
        if got == 0:
            return None
        raise CaptureError(f"reading stopped: {(self.lib.pcap_geterr(self.handle) or b'').decode(errors='replace')}")

    def close(self) -> None:
        if self.handle:
            self.lib.pcap_close(self.handle)
            self.handle = None


def available() -> tuple[bool, str]:
    """Whether packets can be watched here, and why not."""
    try:
        load_pcap()
    except CaptureError as e:
        return False, str(e)
    return True, "Npcap" if sys.platform == "win32" else "libpcap"


class Capture:
    """TCP packets on `ports` at the adapter holding `address`, watched on a thread of its own from start() to stop()
    (a source stands in for libpcap in a test)."""

    def __init__(self, address: str, ports, source=None, clock=time.time):
        self.address, self.ports = address, tuple(int(p) for p in ports)
        self.source = source if source is not None else PcapSource()
        self.clock = clock
        self._packets: list[Packet] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.error = ""  # what stopped the reading early

    def start(self) -> None:
        """The adapter opened (CaptureError when it cannot be), then read until stop()."""
        self.source.open(self.address, self.ports)
        self._thread = threading.Thread(target=self._read, name=f"capture-{'-'.join(map(str, self.ports))}", daemon=True)
        self._thread.start()

    def _read(self) -> None:
        try:
            while not self._stop.is_set():
                got = self.source.next()
                if got is None:
                    continue
                packet = parse(got[1], self.source.link, got[0])
                if packet is not None:
                    with self._lock:
                        if len(self._packets) < MAX_PACKETS:
                            self._packets.append(packet)
        except CaptureError as e:
            self.error = str(e)
        finally:
            self.source.close()

    def stop(self, wait: float = 2.0) -> list[Packet]:
        """The reading ended, the adapter closed; every packet seen."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(wait)
        return self.packets

    @property
    def packets(self) -> list[Packet]:
        with self._lock:
            return list(self._packets)
