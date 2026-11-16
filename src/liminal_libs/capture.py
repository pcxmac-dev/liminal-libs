"""Packets on a port, watched for a while: a tcpdump in Python (the user, 2026-11-08: "if there is a python-tcpdump
that would be good ... as a listener"), for the platform's hw-stats plugin's path check; and every packet at an
adapter, for the firewalls' World Wide Web tab (the user, 2026-11-14: "a 'world wide web view' that shows the globe
and the routes incoming all traffic, as well as monitoring port traffic stats"; traffic.py counts them, names.py reads
the names in them). Through libpcap by ctypes, no package: Npcap's wpcap.dll on Windows (with Wireshark or on its own;
non-administrators may capture unless Npcap was installed for administrators only), libpcap on Linux (root or
CAP_NET_RAW), loaded once in a process. The adapter holding an address (IPv4 or IPv6) is opened (not in promiscuous
mode) and a filter keeps TCP, and UDP when asked, on the ports asked (every port when none are). Each read waits
TIMEOUT_MS at most, so a stop is seen soon: Npcap's reads wait that long themselves; on Linux the adapter is read
without blocking and its socket waited on (libpcap's own wait there ends only once a packet passed the filter). Each
packet's addresses, ports, TCP flags, IP version, protocol and size on the wire are kept, and its direction judged
against this machine's own addresses (every adapter's, as libpcap lists them when a capture opens, and again every
REFRESH_S while it stays open, sooner when a frame its adapter sent comes from an address not known: an address gained
meanwhile, a temporary IPv6 one, a new lease). Bytes after the TCP or UDP header are kept only where a name is said in
clear, and only when asked: a DNS message (port 53, UDP or TCP), MAX_PAYLOAD bytes at most, and a TLS ClientHello to
port 443, up to its record's length and MAX_HELLO bytes at most (a whole one from Chrome or Edge, with its post-quantum
key share; one longer than its TCP segment is joined with the segment after it); the path check keeps the headers
alone. Packets are seen at the adapter, before the machine's firewall decides: a connection the firewall drops still
shows as its SYN arriving."""
from __future__ import annotations

import ctypes
import ctypes.util
import functools
import ipaddress
import math
import os
import select
import socket
import struct
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field, replace

NPCAP = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
SNAPLEN = 128  # the headers alone: Ethernet, IP (with options), TCP
HEADROOM = 142  # the headers before a payload at most: Ethernet, two VLAN tags (22), IPv4 and TCP with options (60 each)
MAX_PAYLOAD = 512  # bytes kept of a DNS message
# Bytes kept of a ClientHello. Chrome and Edge send about 1.8 KB: an X25519MLKEM768 key share and an X25519 one (1,267
# bytes), an ECH extension (190 to 286), a dozen more (about 230, a long server name 262) and 114 bytes before them,
# their order shuffled for each connection, the server_name anywhere among them (only a pre_shared_key, last, comes
# after it). 2,560 holds every one of those with room to spare, and a first segment (1,460 bytes) and the rest after it.
MAX_HELLO = 2560
PAYLOAD_SNAPLEN = HEADROOM + MAX_HELLO  # a ClientHello sent as one frame (segmentation offload) kept whole
TIMEOUT_MS = 150  # a read's wait, so a stop is seen soon
MAX_PACKETS = 2000  # kept per capture (none when each is handed on as it comes, or pulled)
PASS_S = TIMEOUT_MS / 1000  # frames that are no TCP or UDP packet passed over in one pull for this long at most
STEP_S = 0.01  # a read again after this long, where there is no socket to wait on
REFRESH_S = 30.0  # this machine's addresses read again this often while a capture stays open ...
HINT_S = 5.0  # ... and sooner, once in this long at most, for a frame its adapter sent from an address not known
MAX_MACS = 8  # the adapter's own hardware addresses learned (from frames sent from its known addresses)
SPLIT_S = 2.0  # a ClientHello's next segment awaited this long (the packets' own time)
MAX_SPLIT = 64  # ClientHellos awaiting their next segment at once
SEQ = 0xFFFFFFFF  # TCP's sequence numbers wrap
NETMASK_UNKNOWN = 0xFFFFFFFF
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
FLAGS = ((SYN, "SYN"), (ACK, "ACK"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH"), (URG, "URG"), (ECE, "ECE"), (CWR, "CWR"))
LINK_ETHERNET, LINK_NULL, LINK_LOOP, LINK_RAW, LINK_RAW_ALT, LINK_LINUX_SLL = 1, 0, 108, 12, 101, 113
TCP, UDP = 6, 17
DNS_PORT, TLS_PORT = 53, 443
IPV6_OPTIONS = (0, 43, 60)  # hop-by-hop, routing and destination options headers, stepped over
IPV6_FRAGMENT, IPV6_AH = 44, 51
IPV6_HEADERS = 8  # extension headers stepped over at most


class CaptureError(Exception):
    """Packets cannot be watched here: no libpcap, no rights, no adapter with the address."""


def _windows() -> bool:
    return sys.platform == "win32"


def tcp_flags(bits: int) -> str:
    return " ".join(name for bit, name in FLAGS if bits & bit) or "none"


def bits_of(value) -> int:
    """TCP flags as the header's bits: an int as it is, words ("SYN ACK") by their names, Flags by theirs."""
    if isinstance(value, Flags):
        return value.bits
    if isinstance(value, int):
        return int(value) & 0xFF
    names = {name: bit for bit, name in FLAGS}
    bits = 0
    for word in str(value or "").upper().split():
        bits |= names.get(word, 0)
    return bits


class Flags(str):
    """A TCP packet's flags, read either way: as words, as before ("SYN ACK", "ACK RST", "none": what the hw-stats
    plugin reads and shows, and what a page's JSON carries), and as the header's bits, an int (flags & 0x02,
    int(flags), flags == 0x12, f"{flags:#04x}"; false when no flag is set). Made from either; one is made per value.
    Equal to an int by its bits and to a str by its words, so a dict or set keyed by ints does not find it by its bits:
    use int(flags) there."""

    bits: int
    _made: dict = {}

    def __new__(cls, value=0):
        bits = bits_of(value)
        made = cls._made.get(bits)
        if made is None:
            made = super().__new__(cls, tcp_flags(bits))
            made.bits = bits
            cls._made[bits] = made
        return made

    def __int__(self) -> int:
        return self.bits

    __index__ = __int__

    def __bool__(self) -> bool:
        return self.bits != 0

    @staticmethod
    def _int(other):
        return other.bits if isinstance(other, Flags) else other if isinstance(other, int) else None

    def __and__(self, other):
        o = self._int(other)
        return NotImplemented if o is None else self.bits & o

    def __or__(self, other):
        o = self._int(other)
        return NotImplemented if o is None else self.bits | o

    def __xor__(self, other):
        o = self._int(other)
        return NotImplemented if o is None else self.bits ^ o

    __rand__, __ror__, __rxor__ = __and__, __or__, __xor__

    def __eq__(self, other):
        if isinstance(other, int):
            return self.bits == other
        return str.__eq__(self, other)

    def __ne__(self, other):
        same = self.__eq__(other)
        return same if same is NotImplemented else not same

    __hash__ = str.__hash__

    def __format__(self, spec: str) -> str:
        if spec and spec[-1] in "bdoxXn":
            return format(self.bits, spec)
        return str.__format__(self, spec)


@dataclass(frozen=True)
class Packet:
    """One packet seen: when, from where to where, its TCP flags ("SYN", "SYN ACK", "ACK RST" ... as words, the bits
    as an int: Flags; none for UDP), its IP version (4, 6), protocol ("tcp", "udp"), size on the wire (`length`: bytes,
    libpcap's len, a packet cut short when kept still counted whole), direction (`dir`: "in" to this machine, "out" from
    it, "local" between two of its own addresses, "" when not judged) and, for DNS and a ClientHello only, the first
    bytes after its TCP or UDP header (`payload`: a DNS message's first MAX_PAYLOAD; a ClientHello's record, MAX_HELLO
    at most, and when the record runs into the next segment of its connection, that segment's packet carries the
    ClientHello joined, from its start). Flags may be given as an int or as words; the IP version is the address's when
    not given. Two packets are the same whatever their sizes on the wire say."""
    at: float
    src: str
    sport: int
    dst: str
    dport: int
    flags: Flags = Flags()
    family: int = 0
    proto: str = "tcp"
    length: int = field(default=0, compare=False)
    dir: str = ""
    payload: bytes = field(default=b"", repr=False)

    def __post_init__(self):
        if not isinstance(self.flags, Flags):
            object.__setattr__(self, "flags", Flags(self.flags))
        if self.family not in (4, 6):
            object.__setattr__(self, "family", 6 if ":" in str(self.src) else 4)

    @property
    def syn(self) -> bool:
        return self.proto == "tcp" and self.flags.bits & (SYN | ACK) == SYN  # a connection asked for

    @property
    def ends(self) -> tuple[str, int, str, int]:
        """(this machine's address, its port, the other end's address, its port), by the packet's direction (a
        packet not judged is taken as arriving)."""
        if self.dir == "out":
            return self.src, self.sport, self.dst, self.dport
        return self.dst, self.dport, self.src, self.sport

    def as_dict(self) -> dict:
        """The packet for a page: its flags as words (and as `bits`); its payload left out."""
        return {"at": self.at, "src": self.src, "sport": self.sport, "dst": self.dst, "dport": self.dport,
                "flags": str(self.flags), "bits": self.flags.bits, "family": self.family, "proto": self.proto,
                "length": self.length, "dir": self.dir}


@functools.lru_cache(maxsize=4096)
def _v6(raw: bytes) -> str:
    return str(ipaddress.IPv6Address(raw))


def canonical(address) -> str | None:
    """An address as packets name it (an IPv6 address in its short form, its zone and brackets dropped); None when
    it is no address."""
    try:
        return str(ipaddress.ip_address(str(address).strip().strip("[]").split("%")[0]))
    except ValueError:
        return None


def own_addresses(addresses) -> frozenset[str]:
    """This machine's addresses as packets name them, the ones that are no address left out."""
    return frozenset(a for a in map(canonical, addresses) if a)


def _loopback(address: str) -> bool:
    return address.startswith("127.") or address == "::1"


def judge(src: str, dst: str, local) -> str:
    """A packet's direction against this machine's addresses (`local`, as own_addresses gives them; loopback ones
    are always its own): "out" from one of them, "local" from one to one, "in" otherwise (to one of them, or to a
    broadcast or multicast address it hears)."""
    if src in local or _loopback(src):
        return "local" if dst in local or _loopback(dst) else "out"
    return "in"


def client_hello_starts(data: bytes, at: int = 0, end: int | None = None) -> bool:
    """Whether the bytes at `at` begin a TLS record holding a ClientHello (a handshake record, TLS 3.x, message type
    1)."""
    end = len(data) if end is None else min(end, len(data))
    return end - at >= 6 and data[at] == 0x16 and data[at + 1] == 3 and data[at + 5] == 1


class Hellos:
    """ClientHellos longer than the TCP segment they began in, awaiting the rest (a Capture keeps one and hands it to
    parse): per connection (its client's address and port, then the server's), the bytes so far, the sequence number
    the next segment must begin at and the bytes the record needs (MAX_HELLO at most). `cap` connections at most (the
    one waiting longest makes room), each for `wait` seconds of the packets' own time; a segment out of order or sent
    again is not joined. Bounded: `cap` times MAX_HELLO bytes in all."""

    def __init__(self, cap: int = MAX_SPLIT, wait: float = SPLIT_S):
        self.cap, self.wait = max(1, int(cap)), float(wait)
        self._open: OrderedDict[tuple, tuple[bytes, int, int, float]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._open)

    def __contains__(self, key) -> bool:
        return key in self._open

    def begin(self, key: tuple, seq: int, kept: bytes, need: int, at: float) -> None:
        """A ClientHello begun on `key` and cut by its segment's end: `kept` so far, the next segment due at `seq`."""
        self._open.pop(key, None)
        while self._open:  # the ones waited for too long dropped, and room made
            oldest = next(iter(self._open.values()))
            if len(self._open) < self.cap and at - oldest[3] <= self.wait:
                break
            self._open.popitem(last=False)
        self._open[key] = (kept, seq & SEQ, need, at)

    def more(self, key: tuple, seq: int, data: bytes, whole: bool, at: float) -> bytes:
        """The ClientHello so far, from its start, when `data` (a segment captured whole or not, beginning at `seq`) is
        the next one of the hello begun on `key`; b"" when it is not."""
        entry = self._open.get(key)
        if entry is None:
            return b""
        kept, expected, need, began = entry
        if at - began > self.wait:
            del self._open[key]
            return b""
        if seq & SEQ != expected:
            return b""
        joined = kept + data[:need - len(kept)]
        if len(joined) >= need or not whole:  # all of it, or no more can be joined (this segment was cut short)
            del self._open[key]
        else:
            self._open[key] = (joined, (expected + len(data)) & SEQ, need, began)
        return joined


def parse(frame: bytes, link: int, at: float = 0.0, length: int | None = None, local=None,
          payloads: bool = True, hellos: Hellos | None = None) -> Packet | None:
    """A captured frame's TCP or UDP packet (IPv4 or IPv6), None for anything else (ARP, ICMP, a fragment after the
    first, a header cut short). `link`: the adapter's link type (Ethernet, BSD loopback, raw IP, Linux cooked).
    `length`: its size on the wire (libpcap's len; when not given, the link header and the IP header's own length).
    `local`: this machine's addresses (own_addresses), to judge its direction by; not judged when None. `payloads`:
    whether a DNS message's or a ClientHello's first bytes are kept. `hellos`: ClientHellos awaiting their next segment
    (a Capture's Hellos), so one longer than its segment is joined with the next one; each segment kept alone when
    None."""
    data = bytes(frame)
    if link == LINK_ETHERNET:
        if len(data) < 14:
            return None
        kind, start = struct.unpack("!H", data[12:14])[0], 14
        while kind in (0x8100, 0x88A8) and len(data) >= start + 4:  # VLAN tags
            kind, start = struct.unpack("!H", data[start + 2:start + 4])[0], start + 4
        version = {0x0800: 4, 0x86DD: 6}.get(kind)
    elif link in (LINK_NULL, LINK_LOOP):
        if len(data) < 4:
            return None
        family = struct.unpack("<I", data[:4])[0] if link == LINK_NULL else struct.unpack("!I", data[:4])[0]
        version, start = (4 if family == 2 else 6 if family in (10, 23, 24, 28, 30) else None), 4
    elif link == LINK_LINUX_SLL:
        if len(data) < 16:
            return None
        version, start = {0x0800: 4, 0x86DD: 6}.get(struct.unpack("!H", data[14:16])[0]), 16
    elif link in (LINK_RAW, LINK_RAW_ALT):
        version, start = ((data[0] >> 4) if data else None), 0
    else:
        return None
    size = len(data) - start  # the IP packet's bytes captured
    short = length is not None and int(length) > len(data)  # the frame was cut when captured (its snap length)
    if version == 4 and size >= 20:
        head = (data[start] & 0x0F) * 4
        if head < 20 or size < head + 8:
            return None
        if struct.unpack_from("!H", data, start + 6)[0] & 0x1FFF:  # a fragment after the first: no ports in it
            return None
        number, total = data[start + 9], struct.unpack_from("!H", data, start + 2)[0]
        src, dst = socket.inet_ntoa(data[start + 12:start + 16]), socket.inet_ntoa(data[start + 16:start + 20])
        top = start + head
        end = start + total if head <= total <= size else len(data)  # past the IP packet: the link's padding
        whole = total if total >= head else size  # 0 from a segmentation offload: what was captured
        cut = total > size if total >= head else short  # the IP packet not all there
    elif version == 6 and size >= 40:
        number, top, payload_size = data[start + 6], start + 40, struct.unpack_from("!H", data, start + 4)[0]
        for _ in range(IPV6_HEADERS):
            if number not in (*IPV6_OPTIONS, IPV6_FRAGMENT, IPV6_AH):
                break
            if len(data) < top + 8:
                return None
            if number == IPV6_FRAGMENT:
                if struct.unpack_from("!H", data, top + 2)[0] & 0xFFF8:  # a fragment after the first
                    return None
                number, top = data[top], top + 8
            elif number == IPV6_AH:
                number, top = data[top], top + (data[top + 1] + 2) * 4
            else:
                number, top = data[top], top + (data[top + 1] + 1) * 8
        src, dst = _v6(data[start + 8:start + 24]), _v6(data[start + 24:start + 40])
        end = start + 40 + payload_size if payload_size and 40 + payload_size <= size else len(data)
        whole = 40 + payload_size if payload_size else size
        cut = 40 + payload_size > size if payload_size else short
    else:
        return None
    seq = 0
    if number == TCP:
        if end - top < 14:
            return None
        sport, dport, seq = struct.unpack_from("!HHI", data, top)
        bits, proto, offset = data[top + 13], "tcp", (data[top + 12] >> 4) * 4
        body = top + offset if offset >= 20 else end
    elif number == UDP:
        if end - top < 8:
            return None
        sport, dport, datagram = struct.unpack_from("!HHH", data, top)
        if datagram < 8:  # no UDP datagram is shorter than its header
            return None
        bits, proto, body = 0, "udp", top + 8
        end = min(end, top + datagram)
    else:
        return None
    kept = b""
    if payloads and body < end:
        if DNS_PORT in (sport, dport):
            kept = data[body:min(end, body + MAX_PAYLOAD)]
        elif proto == "tcp" and dport == TLS_PORT:
            first = (seq + 1) & SEQ if bits & SYN else seq  # a SYN's own data (TCP Fast Open) begins after it
            if client_hello_starts(data, body, end):
                need = min(MAX_HELLO, 5 + struct.unpack_from("!H", data, body + 3)[0])  # the record, its header too
                kept = data[body:min(end, body + need)]
                if hellos is not None and len(kept) < need and not cut:  # the rest is in the next segment
                    hellos.begin((src, sport, dst, dport), first + (end - body), kept, need, at)
            elif hellos and (src, sport, dst, dport) in hellos:
                kept = hellos.more((src, sport, dst, dport), first, data[body:end], not cut, at)
    wire = int(length) if length is not None else start + whole
    direction = "" if local is None else judge(src, dst, local)
    return Packet(at, src, sport, dst, dport, Flags(bits), version, proto, wire, direction, kept)


def bpf(ports=(), address: str | None = None, udp: bool = False) -> str:
    """The filter for TCP (and UDP when asked) on `ports` (both ways; every port when none are given), to or from
    `address` when given."""
    wanted = " or ".join(f"port {int(p)}" for p in ports)
    host = str(address).strip("[]").split("%")[0] if address else ""
    return ("(tcp or udp)" if udp else "tcp") + (f" and ({wanted})" if wanted else "") + (f" and host {host}" if host else "")


# -- libpcap through ctypes ---------------------------------------------------------------------------------

class _Sockaddr(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort), ("data", ctypes.c_ubyte * 14)]


class _Sockaddr6(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort), ("port", ctypes.c_ushort), ("flowinfo", ctypes.c_uint32),
                ("addr", ctypes.c_ubyte * 16), ("scope_id", ctypes.c_uint32)]


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


_PCAP = None  # libpcap once loaded: one load in a process, however often it is asked for
_PCAP_LOCK = threading.Lock()


def load_pcap():
    """libpcap: Npcap's wpcap.dll on Windows, the system's libpcap on Linux; CaptureError when there is none. Loaded
    once in a process and kept (a load that failed is tried again when asked again). No folder is added to the
    process's DLL search path: wpcap.dll is loaded by its full path, so Windows looks for the Packet.dll it imports in
    its own folder (each folder added stays for the process's life, and the search path's room runs out)."""
    global _PCAP
    lib = _PCAP
    if lib is not None:
        return lib
    with _PCAP_LOCK:
        if _PCAP is None:
            _PCAP = _declared(_loaded())
        return _PCAP


def _loaded():
    if _windows():
        dll = os.path.join(NPCAP, "wpcap.dll")
        if not os.path.exists(dll):
            raise CaptureError("Npcap is not installed (npcap.com; Wireshark installs it): packets cannot be watched")
        try:
            return ctypes.CDLL(dll)  # a full path: its own folder searched for its Packet.dll
        except OSError as e:
            raise CaptureError(f"Npcap's wpcap.dll could not be loaded: {e}") from None
    name = ctypes.util.find_library("pcap")
    if not name:
        raise CaptureError("libpcap is not installed (libpcap0.8 or libpcap): packets cannot be watched")
    try:
        return ctypes.CDLL(name)
    except OSError as e:
        raise CaptureError(f"libpcap could not be loaded: {e}") from None


def _declared(lib):
    """libpcap's functions the capture calls, their arguments and results declared."""
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
    if not _windows():  # read without blocking, its socket waited on (Npcap's reads wait TIMEOUT_MS themselves)
        try:
            lib.pcap_setnonblock.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
            lib.pcap_get_selectable_fd.argtypes = [ctypes.c_void_p]
        except AttributeError:  # a libpcap without them: PcapSource.open says so
            pass
    return lib


def _readable(fd: int, seconds: float) -> bool:
    """Whether the file `fd` (a capture's socket) became readable within `seconds` (an error on it counts: the read
    says what it is); True after a short step when there is no file to wait on (-1) or it cannot be waited on."""
    seconds = max(0.0, seconds)
    if fd >= 0:
        try:
            if hasattr(select, "poll"):  # no limit on the file's number, unlike select
                waiting = select.poll()
                waiting.register(fd, select.POLLIN | select.POLLPRI)
                return bool(waiting.poll(math.ceil(seconds * 1000)))
            ready, _, broken = select.select([fd], [], [fd], seconds)
            return bool(ready or broken)
        except (OSError, ValueError):
            pass
    time.sleep(min(seconds, STEP_S))
    return True


def _address_of(sa) -> str | None:
    """An adapter's address as packets name it (IPv4 or IPv6), None for another kind (a link-layer address)."""
    if not sa:
        return None
    family = sa.contents.family
    if family == socket.AF_INET:
        return socket.inet_ntoa(bytes(sa.contents.data[2:6]))
    if family == socket.AF_INET6:
        return _v6(bytes(ctypes.cast(sa, ctypes.POINTER(_Sockaddr6)).contents.addr))
    return None


class PcapSource:
    """The adapter holding an address, opened through libpcap, read packet by packet (what Capture reads). `snaplen`:
    the bytes kept of each packet; `expression`: the filter (bpf(ports, address) when not given). Once open, `local`
    holds every address of every adapter libpcap lists: this machine's own (and `broadcast` their IPv4 broadcast
    addresses), read again by refresh(). Each read waits TIMEOUT_MS at most: Npcap's read waits that long itself;
    elsewhere the handle is read without blocking and its socket waited on (`waits`: the socket's file, -1 for none:
    read again in short steps; None where the read waits itself), for a blocking read of Linux's libpcap would wait
    until a packet passed the filter: on a quiet adapter, for ever."""

    def __init__(self, lib=None, snaplen: int = SNAPLEN, expression: str | None = None):
        self.lib = lib
        self.handle = None
        self.link = LINK_ETHERNET
        self.snaplen, self.expression = int(snaplen), expression
        self.local: frozenset[str] = frozenset()
        self.broadcast: frozenset[str] = frozenset()
        self.waits: int | None = None

    def _listed(self) -> list[tuple[str, tuple[str, ...], tuple[str, ...]]]:
        """Every adapter libpcap lists: its pcap name, its IPv4 and IPv6 addresses and its IPv4 broadcast addresses."""
        lib, err = self.lib, ctypes.create_string_buffer(256)
        found = ctypes.POINTER(_PcapIf)()
        if lib.pcap_findalldevs(ctypes.byref(found), err) != 0:
            raise CaptureError(f"the adapters could not be listed: {err.value.decode(errors='replace')}")
        out = []
        try:
            dev = found
            while dev:
                addresses, heard, a = [], [], dev.contents.addresses
                while a:
                    text = _address_of(a.contents.addr)
                    if text:
                        addresses.append(text)
                        broadcast = _address_of(a.contents.broadaddr) if "." in text else None  # IPv4 has them
                        if broadcast and "." in broadcast and broadcast != text:
                            heard.append(broadcast)
                    a = a.contents.next
                out.append(((dev.contents.name or b"").decode(errors="replace"), tuple(addresses), tuple(heard)))
                dev = dev.contents.next
        finally:
            if found:
                lib.pcap_freealldevs(found)
        return out

    def adapters(self) -> list[tuple[str, tuple[str, ...]]]:
        """Every adapter libpcap lists: its pcap name and its IPv4 and IPv6 addresses."""
        return [(name, addresses) for name, addresses, _ in self._listed()]

    def _gather(self, listed) -> None:
        self.local = own_addresses(a for _, held, _ in listed for a in held)
        self.broadcast = own_addresses(b for _, _, heard in listed for b in heard)

    def refresh(self) -> frozenset[str]:
        """This machine's addresses read again (`local`, and `broadcast`): an address an adapter gained or lost since
        they were read (a new temporary IPv6 address, a lease renewed to another). CaptureError when they cannot be."""
        self.lib = self.lib or load_pcap()
        self._gather(self._listed())
        return self.local

    @staticmethod
    def holding(address: str, adapters) -> str:
        """The adapter of `adapters` (as adapters() gives them) holding `address`, IPv4 or IPv6 (its zone and
        brackets dropped)."""
        wanted = canonical(address)
        if wanted is None:
            raise CaptureError(f"no adapter can be chosen: {address!r} is no address")
        for name, addresses in adapters:
            if wanted in addresses:
                return name
        raise CaptureError(f"no adapter holds {address} (as libpcap lists them)")

    def device_of(self, address: str) -> str:
        """The adapter (its pcap name) holding `address`, IPv4 or IPv6."""
        return self.holding(address, self.adapters())

    def open(self, address: str, ports) -> None:
        self.lib = self.lib or load_pcap()
        lib, err = self.lib, ctypes.create_string_buffer(256)
        listed = self._listed()  # read once here: the adapter to open, and this machine's addresses
        device = self.holding(address, [(name, held) for name, held, _ in listed])
        self._gather(listed)
        handle = lib.pcap_open_live(device.encode(), self.snaplen, 0, TIMEOUT_MS, err)
        if not handle:
            words = err.value.decode(errors="replace")
            raise CaptureError(f"the adapter could not be opened: {words}" + (
                " (packets are watched as root, or with CAP_NET_RAW)" if not _windows() else ""))
        program = _BpfProgram()
        expression = self.expression if self.expression is not None else bpf(ports, address)
        if lib.pcap_compile(handle, ctypes.byref(program), expression.encode(), 1, NETMASK_UNKNOWN) != 0 \
                or lib.pcap_setfilter(handle, ctypes.byref(program)) != 0:
            words = (lib.pcap_geterr(handle) or b"").decode(errors="replace")
            lib.pcap_close(handle)
            raise CaptureError(f"the filter could not be set: {words}")
        lib.pcap_freecode(ctypes.byref(program))
        try:
            waits = self._waiting(handle)
        except CaptureError:
            lib.pcap_close(handle)
            raise
        self.handle, self.link, self.waits = handle, lib.pcap_datalink(handle), waits

    def _waiting(self, handle) -> int | None:
        """How a read waits here: None where libpcap's read waits TIMEOUT_MS itself (Npcap). Elsewhere it need not:
        Linux's libpcap (TPACKET_V3) wakes a reader only once a packet passed the filter, so a read on a quiet adapter
        would hold its thread, and a stop, until one did. There the handle is made non-blocking and its socket waited
        on (pcap_get_selectable_fd: its file; -1 when it has none). CaptureError when it cannot be made non-blocking."""
        if _windows():
            return None
        lib, err = self.lib, ctypes.create_string_buffer(256)
        try:
            refused = lib.pcap_setnonblock(handle, 1, err) != 0
        except AttributeError:  # a libpcap too old to have it
            refused, err.value = True, b"this libpcap cannot read without blocking"
        if refused:
            raise CaptureError(f"the adapter could not be read without blocking: {err.value.decode(errors='replace')}")
        try:
            fd = int(lib.pcap_get_selectable_fd(handle))
        except AttributeError:
            fd = -1
        return fd if fd >= 0 else -1

    def _read(self) -> tuple[float, bytes, int] | None:
        header, data = ctypes.POINTER(_PktHdr)(), ctypes.POINTER(ctypes.c_ubyte)()
        got = self.lib.pcap_next_ex(self.handle, ctypes.byref(header), ctypes.byref(data))
        if got == 1:
            h = header.contents
            kept = ctypes.string_at(ctypes.cast(data, ctypes.c_void_p).value, min(h.caplen, self.snaplen))
            return h.ts.sec + h.ts.usec / 1e6, kept, int(h.len)
        if got == 0:
            return None
        raise CaptureError(f"reading stopped: {(self.lib.pcap_geterr(self.handle) or b'').decode(errors='replace')}")

    def next(self) -> tuple[float, bytes, int] | None:
        """The next packet (its time, its first bytes, its size on the wire), None when none came within the read's
        wait (TIMEOUT_MS)."""
        if not self.handle:  # libpcap is never handed a handle closed or never opened
            raise CaptureError("reading stopped: the adapter is not open")
        got = self._read()
        if got is not None or self.waits is None:
            return got
        deadline = time.monotonic() + TIMEOUT_MS / 1000
        while True:  # non-blocking: the socket waited on, then read whether it said so or not (as pcap(3PCAP) asks)
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            ready = _readable(self.waits, left)
            got = self._read()
            if got is not None or not ready:
                return got
            if self.waits >= 0:  # readable, yet nothing passed libpcap's own filter: not asked again at once
                time.sleep(min(STEP_S, max(0.0, deadline - time.monotonic())))

    def close(self) -> None:
        if self.handle:
            self.lib.pcap_close(self.handle)
            self.handle = None
        self.waits = None


def available() -> tuple[bool, str]:
    """Whether packets can be watched here, and why not."""
    try:
        load_pcap()
    except CaptureError as e:
        return False, str(e)
    return True, "Npcap" if _windows() else "libpcap"


class Capture:
    """Packets at the adapter holding `address`, read on a thread of its own from start() to stop(), or pulled one by
    one from open() to close() on the caller's (a traffic.Watcher pulls them: its one thread reads them, the capture
    starts none); a source stands in for libpcap in a test. As the path check asks: TCP on `ports`, to or from
    `address`, the headers alone, each packet kept (the first MAX_PACKETS) for `packets`. Asked more: `udp` adds UDP;
    no `ports` means every port; `host=False` keeps every packet the adapter sees (IPv4 and IPv6, to and from any of
    its addresses); `payloads` keeps the first bytes of DNS and of a ClientHello (one longer than its TCP segment
    joined with the next: Hellos); `on_packet` is handed each packet read on the thread instead of it being kept.
    Directions are judged against this machine's addresses: every adapter's as libpcap lists them, `address`, and
    `local` (any more), gathered when it opens and again every `refresh` seconds while it stays open (None or 0: never),
    sooner (once in HINT_S at most) when a frame the adapter itself sent comes from an address not known (on Ethernet,
    from one of its own hardware addresses, learned from what it sent from its known ones; on Linux's cooked link, as
    the kernel marks it): the packet that showed it is judged again. `ticks`: the seconds that is timed in (a test's
    own). `broadcast`: the adapters' IPv4 broadcast addresses, gathered with them."""

    def __init__(self, address: str, ports=(), source=None, clock=time.time, *, udp: bool = False,
                 payloads: bool = False, host: bool = True, on_packet=None, local=(),
                 refresh: float | None = REFRESH_S, ticks=time.monotonic):
        self.address, self.ports = address, tuple(int(p) for p in ports)
        self.udp, self.payloads, self.host = bool(udp), bool(payloads), bool(host)
        self.source = source if source is not None else PcapSource(
            snaplen=PAYLOAD_SNAPLEN if self.payloads else SNAPLEN,
            expression=bpf(self.ports, address if self.host else None, self.udp))
        self.clock = clock
        self.on_packet = on_packet
        self.refresh, self.ticks = max(0.0, float(refresh or 0.0)), ticks
        self.local: frozenset[str] = frozenset()  # this machine's addresses, once open
        self.broadcast: frozenset[str] = frozenset()
        self._more = tuple(local)
        self._hellos: Hellos | None = None
        self._macs: dict[bytes, None] = {}  # the adapter's own hardware addresses, as its frames say them
        self._gathered = 0.0
        self._hinted: float | None = None
        self._packets: list[Packet] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.error = ""  # what stopped the reading early

    def open(self) -> None:
        """The adapter opened (CaptureError when it cannot be) and this machine's addresses gathered, for next()."""
        self.source.open(self.address, self.ports)
        self._hellos = Hellos() if self.payloads else None
        self._gather(self.ticks())

    def _gather(self, now: float) -> None:
        self._gathered = now
        self.local = own_addresses((self.address, *self._more, *(getattr(self.source, "local", ()) or ())))
        self.broadcast = own_addresses(getattr(self.source, "broadcast", ()) or ())

    def _regather(self, now: float) -> None:
        """This machine's addresses read again (the source's refresh(), where it has one)."""
        refresh = getattr(self.source, "refresh", None)
        if callable(refresh):
            try:
                refresh()
            except (CaptureError, OSError):  # not listed this time: the addresses known stand, read again later
                pass
        self._gather(now)

    def next(self) -> Packet | None:
        """The next TCP or UDP packet read (once open), None when none came within the read's wait (what is no such
        packet is passed over: ARP, ICMP, a later fragment, a frame cut short; for PASS_S at most in one pull, however
        many come, so a stream of them neither ends a pull at once nor holds it); CaptureError when reading stopped
        (the adapter gone)."""
        until = None
        while True:
            got = self.source.next()
            if got is None:
                return None
            try:
                packet = parse(got[1], self.source.link, got[0], got[2] if len(got) > 2 else None, self.local,
                               self.payloads, self._hellos)
            except (IndexError, ValueError, struct.error):  # a frame no guard foresaw: passed over
                packet = None
            if packet is not None:
                return self._judged(packet, got[1])
            now = time.monotonic()
            if until is None:
                until = now + PASS_S
            elif now >= until:
                return None

    def _judged(self, packet: Packet, frame) -> Packet:
        """The packet, judged again when this machine's addresses were read again first (their time had come, or the
        frame was the adapter's own from an address not known)."""
        if not self.refresh:
            return packet
        now = self.ticks()
        due = now - self._gathered >= self.refresh
        if not due:
            if packet.dir == "out":
                self._learn(frame)
            elif packet.dir == "in" and self._sent_here(frame) and (
                    self._hinted is None or now - self._hinted >= HINT_S):
                self._hinted, due = now, True
        if not due:
            return packet
        self._regather(now)
        direction = judge(packet.src, packet.dst, self.local)
        return packet if direction == packet.dir else replace(packet, dir=direction)

    def _learn(self, frame) -> None:
        """An Ethernet frame sent from one of this machine's addresses: its source is the adapter's own."""
        if self.source.link == LINK_ETHERNET and len(frame) >= 12 and len(self._macs) < MAX_MACS:
            mac = bytes(frame[6:12])
            if mac not in self._macs and any(mac) and not mac[0] & 1:  # not zeros, not a group's
                self._macs[mac] = None

    def _sent_here(self, frame) -> bool:
        """Whether the adapter itself sent the frame: from one of its own hardware addresses (Ethernet), or marked
        outgoing by the kernel (Linux's cooked link)."""
        link = self.source.link
        if link == LINK_ETHERNET:
            return len(frame) >= 12 and bytes(frame[6:12]) in self._macs
        if link == LINK_LINUX_SLL:
            return len(frame) >= 2 and frame[0] == 0 and frame[1] == 4  # PACKET_OUTGOING
        return False

    def close(self) -> None:
        """The adapter closed (libpcap's handle once: closing it again does nothing)."""
        self.source.close()

    def start(self) -> None:
        """The adapter opened (CaptureError when it cannot be), then read on a thread of its own until stop()."""
        self.open()
        name = "-".join(map(str, self.ports)) or "every-port"
        thread = threading.Thread(target=self._read, name=f"capture-{name}", daemon=True)
        try:
            thread.start()
        except RuntimeError:  # no thread to read on: the adapter is not left open
            self.close()
            raise
        self._thread = thread

    def _read(self) -> None:
        try:
            while not self._stop.is_set():
                packet = self.next()
                if packet is None:
                    continue
                handler = self.on_packet
                if handler is not None:
                    try:
                        handler(packet)
                    except Exception as e:  # noqa: BLE001 - said, and the reading ended
                        self.error = f"reading stopped: a packet's handler failed: {type(e).__name__}: {e}"
                        break
                    continue
                with self._lock:
                    if len(self._packets) < MAX_PACKETS:
                        self._packets.append(packet)
        except CaptureError as e:
            self.error = str(e)
        finally:
            self.close()

    def stop(self, wait: float = 2.0) -> list[Packet]:
        """The reading ended, the adapter closed; every packet kept."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(wait)
        return self.packets

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def packets(self) -> list[Packet]:
        with self._lock:
            return list(self._packets)
