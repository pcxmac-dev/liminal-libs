"""Names for the addresses this machine talks to, read from its own traffic as it passes, for the firewalls' Filter tab
(the user, 2026-11-14: "classifying traffic as potential advert/monitoring sites that track users, etc"): the answers
of DNS (port 53, UDP or TCP: each address with the name a program asked for and every CNAME on the way to it, so a
tracker behind a first party's name is still seen) and the name a TLS ClientHello asks for (its server_name).
Nothing is asked of anyone: no lookup, no PTR (the design: peers' addresses never go to any outside service). No
length in a packet is trusted before it is checked against the bytes there are; compression pointers are followed
only backwards, a few at most, and a name is at most 255 bytes. An answer names only what is on its question's way
(the name asked for and the CNAMEs from it); a NameBook believes an answer only when this machine asked that
question of that resolver, from that port, with that id, a moment before, and a ClientHello only when this machine
sent it. It keeps the names of the latest addresses, capped, the most recent first. What is said in clear is all
there is: a resolver asked over HTTPS or TLS answers unseen, an answer to a question asked before watching began is not
believed, and a ClientHello with its name encrypted (ECH) says only the name of the server in front."""
from __future__ import annotations

import functools
import ipaddress
import socket
import struct
import threading
from collections import OrderedDict

from .dns import valid_name

MAX_NAME = 255  # bytes of a name as DNS writes it, its length bytes and the root's counted
MAX_LABEL = 63
MAX_HOST = 253  # characters of a host name as text
MAX_JUMPS = 32  # compression pointers followed in one name
MAX_QUESTIONS = 4
MAX_RECORDS = 64  # answers read of one message
MAX_CHAIN = 16  # names leading to one address through CNAMEs
MAX_INPUT = 65537  # bytes read of what is given: DNS over TCP's longest message and its two length bytes
NAMES_PER_IP = 8
MAX_ASKED = 1024  # questions from this machine awaiting their answer at once
ASKED_S = 10.0  # an answer is believed this long after its question went out (the packets' own time)
A, CNAME, AAAA, IN = 1, 5, 28, 1
DNS_PORT, TLS_PORT = 53, 443


def _bytes(payload) -> bytes:
    """What was given as bytes (MAX_INPUT at most); b"" for what is no bytes (an int is not taken as a size)."""
    if isinstance(payload, bytes):
        return payload[:MAX_INPUT]
    if isinstance(payload, (bytearray, memoryview)):
        return bytes(payload[:MAX_INPUT])
    return b""


def _name(msg: bytes, at: int, end: int | None = None) -> tuple[str | None, int]:
    """The name at `at` and where what follows it begins. Its labels are read up to `end` (its record's end) until a
    compression pointer leads back into the message; each pointer must point before the place the name or the last
    pointer led to (so none loops), MAX_JUMPS at most, MAX_NAME bytes in all. (None, at) for a malformed one: a
    pointer forward or to itself, a label cut short or of a kind answers do not use, too long; ("", next) for one
    well formed that is no host name (the root, odd characters)."""
    limit = len(msg) if end is None else min(end, len(msg))
    labels, size, jumps, after, pos, floor, odd = [], 1, 0, None, at, at, False
    while True:
        if pos >= limit:
            return None, at
        n = msg[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if pos + 1 >= limit:
                return None, at
            target = ((n & 0x3F) << 8) | msg[pos + 1]
            jumps += 1
            if target >= floor or jumps > MAX_JUMPS:
                return None, at
            if after is None:
                after = pos + 2
            pos = floor = target
            limit = len(msg)
            continue
        if n & 0xC0:  # 0x40 and 0x80: kinds of label no answer uses
            return None, at
        if pos + 1 + n > limit:
            return None, at
        size += n + 1
        if size > MAX_NAME:
            return None, at
        label = msg[pos + 1:pos + 1 + n]
        odd = odd or b"." in label
        labels.append(label)
        pos += 1 + n
    text = b".".join(labels).decode("latin-1").lower()
    return ("" if odd or valid_name(text) != text else text), (after if after is not None else pos)


def _asked(msg: bytes) -> tuple[int, int, list[str], int, int] | None:
    """A standard DNS message's id, flags, the host names it asks for (each as _name reads it: "" for one that is no
    host name), where its answers begin and how many it says there are; None for anything else (not a standard query
    or its answer, more questions than any resolver asks, a question cut short)."""
    if len(msg) < 12:
        return None
    ident, flags, questions, answers = struct.unpack_from("!HHHH", msg)
    if flags & 0x7800 or questions > MAX_QUESTIONS:  # not a standard query's (its opcode), or odd
        return None
    at, names = 12, []
    for _ in range(questions):
        name, at = _name(msg, at)
        if name is None or at + 4 > len(msg):
            return None
        names.append(name)
        at += 4  # its type and class
    return ident, flags, names, at, answers


def _records(msg: bytes, at: int, answers: int) -> tuple[list[tuple[str, str, int]], dict[str, tuple[str, int]]]:
    """An answer's A and AAAA records (owner, address, ttl) and its CNAMEs (owner -> (target, ttl)), MAX_RECORDS at
    most (a record cut short ends the reading: those before it stand)."""
    cnames: dict[str, tuple[str, int]] = {}
    addresses: list[tuple[str, str, int]] = []
    for _ in range(min(answers, MAX_RECORDS)):
        owner, at = _name(msg, at)
        if owner is None or at + 10 > len(msg):
            break
        rtype, rclass, ttl, size = struct.unpack_from("!HHIH", msg, at)
        start, end = at + 10, at + 10 + size
        if end > len(msg):
            break  # cut short: the answers before it stand
        at = end
        if rclass & 0x7FFF != IN or not owner:
            continue
        ttl = ttl if ttl < 0x80000000 else 0  # RFC 2181: a TTL with its top bit set counts as 0
        if rtype == A and size == 4:
            addresses.append((owner, socket.inet_ntoa(msg[start:end]), ttl))
        elif rtype == AAAA and size == 16:
            addresses.append((owner, str(ipaddress.IPv6Address(msg[start:end])), ttl))
        elif rtype == CNAME:
            target, _ = _name(msg, start, end)
            if target and owner not in cnames:
                cnames[owner] = (target, ttl)
    return addresses, cnames


def _chains(asked, addresses, cnames) -> list[tuple[str, str, int]]:
    """Each address on an asked name's way (the name itself, then each CNAME's target from it: MAX_CHAIN names at
    most, a loop ending it) with every name from the asked one to the address's own, the asked one first, each name's
    TTL the least from it to the address. What is on no asked name's way is not taken: a resolver puts nothing else
    in an answer (one that does is not believed)."""
    out, said = [], set()
    for start in dict.fromkeys(n for n in asked if n):
        way, links, name = [start], [], start  # the names in order, and each CNAME's TTL to the next
        while name in cnames and len(way) < MAX_CHAIN:
            name, ttl = cnames[name]
            if name in way:  # a loop
                break
            way.append(name)
            links.append(ttl)
        place = {n: i for i, n in enumerate(way)}
        for owner, address, ttl in addresses:
            k = place.get(owner)
            if k is None:
                continue
            ttls = [0] * (k + 1)
            ttls[k] = ttl
            for i in range(k - 1, -1, -1):  # back from the address's own name: the least along the way
                ttls[i] = min(links[i], ttls[i + 1])
            for i in range(k + 1):  # the name asked for first, the address's own name last
                if (way[i], address) not in said:
                    said.add((way[i], address))
                    out.append((way[i], address, ttls[i]))
    return out


def _answer(msg: bytes) -> tuple[int, list[str], list[tuple[str, str, int]], dict[str, tuple[str, int]]] | None:
    """A standard query's answer: its id, the host names asked for, its address records and its CNAMEs; None for
    anything else (a query, an odd or malformed message)."""
    head = _asked(msg)
    if head is None or not head[1] & 0x8000:
        return None
    ident, _, asked, at, answers = head
    return (ident, [n for n in asked if n], *_records(msg, at, answers))


def _query(msg: bytes) -> tuple[int, list[str]] | None:
    """A standard query's id and the host names it asks for; None for anything else."""
    head = _asked(msg)
    if head is None or head[1] & 0x8000:
        return None
    names = [n for n in head[2] if n]
    return (head[0], names) if names else None


def _message(payload, tcp: bool) -> bytes:
    """The DNS message in a payload (over TCP, after its two length bytes)."""
    data = _bytes(payload)
    if tcp:
        if len(data) < 2:
            return b""
        data = data[2:2 + struct.unpack_from("!H", data)[0]]
    return data


def parse_dns(payload: bytes, tcp: bool = False) -> list[tuple[str, str, int]]:
    """A DNS response's addresses as (name, address, ttl): each A and AAAA answer on the way of a name asked for (that
    name, then the CNAMEs from it), with the name asked for and every CNAME between them, the name asked for first
    (its TTL the least along the way); a record on no question's way is not taken; [] for a query, a malformed message
    or no answer (answers cut short end the reading; those before stand). `tcp`: the message follows DNS over TCP's two
    length bytes. Never raises; what is no bytes is no answer."""
    try:
        read = _answer(_message(payload, tcp))
        return _chains(read[1], read[2], read[3]) if read else []
    except (IndexError, ValueError, TypeError, struct.error):  # a guard missed is still no answer
        return []


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _host_name(ext: bytes) -> str | None:
    """The host_name of a server_name extension's list."""
    if len(ext) < 2:
        return None
    at, end = 2, min(len(ext), 2 + struct.unpack_from("!H", ext)[0])
    while end - at >= 3:
        kind, size = ext[at], struct.unpack_from("!H", ext, at + 1)[0]
        at += 3
        if at + size > end:
            return None
        if kind == 0:  # host_name
            try:
                name = ext[at:at + size].decode("ascii").lower()
            except UnicodeDecodeError:
                return None
            name = name[:-1] if name.endswith(".") else name
            if not name or len(name) > MAX_HOST or valid_name(name) != name or _is_address(name) \
                    or any(len(label) > MAX_LABEL for label in name.split(".")):
                return None
            return name
        at += size
    return None


def _sni(data: bytes) -> str | None:
    at, end = 0, len(data)
    if end >= 5 and data[0] == 0x16:  # a TLS record holding a handshake
        if data[1] != 3:
            return None
        at, end = 5, min(end, 5 + struct.unpack_from("!H", data, 3)[0])
    if end - at < 4 or data[at] != 1:  # not a ClientHello
        return None
    at, end = at + 4, min(end, at + 4 + int.from_bytes(data[at + 1:at + 4], "big"))
    if end - at < 35 or data[at] != 3:  # its version and random, then its session id's length
        return None
    at += 34
    session = data[at]
    if session > 32 or end - at < 1 + session + 2:
        return None
    at += 1 + session
    suites = struct.unpack_from("!H", data, at)[0]
    if suites < 2 or suites % 2 or end - at < 2 + suites + 1:
        return None
    at += 2 + suites
    methods = data[at]
    if methods < 1 or end - at < 1 + methods + 2:
        return None
    at += 1 + methods
    stop = min(end, at + 2 + struct.unpack_from("!H", data, at)[0])
    at += 2
    while stop - at >= 4:
        kind, size = struct.unpack_from("!HH", data, at)
        at += 4
        if kind == 0:  # server_name
            return _host_name(data[at:at + size]) if at + size <= stop else None
        at += size
    return None


def parse_sni(payload: bytes) -> str | None:
    """The host name a TLS ClientHello asks for (its server_name extension), from its first bytes: a TLS record, or
    the handshake message alone (as QUIC carries it). None for anything else, for a malformed one, and when the name
    lies past the bytes there are (a capture keeps a ClientHello's record, capture.MAX_HELLO bytes at most: enough for
    Chrome's and Edge's, whatever their extensions' order). Every length is checked against the bytes there are and
    against the length around it. Never raises; what is no bytes names nothing."""
    try:
        return _sni(_bytes(payload))
    except (IndexError, ValueError, TypeError, struct.error):
        return None


@functools.lru_cache(maxsize=4096)
def _ip(text: str) -> str:
    """An address as a NameBook keeps it ("" for what is no address): its short form, an IPv4 address written as IPv6
    as IPv4."""
    try:
        ip = ipaddress.ip_address(str(text).strip().strip("[]").split("%")[0])
    except ValueError:
        return ""
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def _read_dns(payload, tcp: bool, read):
    """`read` (_answer or _query) of a payload: over TCP a message follows its two length bytes, unless they came in a
    segment of their own. None when it reads nothing; never raises."""
    try:
        got = read(_message(payload, True)) if tcp else None
        return got if got is not None else read(_message(payload, False))
    except (IndexError, ValueError, TypeError, struct.error):
        return None


class NameBook:
    """The names of the addresses this machine talks to, as its traffic says them: observe() each packet (a
    capture.Packet with its payload kept: the capture's `payloads`, its direction judged), or add() a name another
    source said (an ETW or eBPF event). A DNS answer is believed only when it answers a question this machine sent
    (out) a moment before (`wait` seconds of the packets' own time): from the resolver asked, to the port it was asked
    from, with the question's id and name, the first answer only; and only for what is on that question's way (the name
    asked for and the CNAMEs from it). The questions awaiting their answer are capped (`max_asked`, the oldest go
    first). A ClientHello is believed only when this machine sent it (out), for the address it went to. The latest
    `max_ips` addresses, each with its latest `per_ip` names, the most recent first; of one DNS answer, the name a
    program asked for comes before the CNAMEs behind it. `read` counts the answers and ClientHellos that named
    something, and the answers to no question seen ("unasked": unsolicited, or asked before watching began).
    Thread-safe."""

    def __init__(self, max_ips: int = 4096, per_ip: int = NAMES_PER_IP, *, max_asked: int = MAX_ASKED,
                 wait: float = ASKED_S):
        self.max_ips, self.per_ip = max(1, int(max_ips)), max(1, int(per_ip))
        self.max_asked, self.wait = max(1, int(max_asked)), float(wait)
        self._names: OrderedDict[str, list[str]] = OrderedDict()
        self._asked: OrderedDict[tuple, list[tuple[str, float]]] = OrderedDict()  # (proto, resolver, here, port, id)
        self._lock = threading.Lock()
        self.read = {"dns": 0, "sni": 0, "unasked": 0}

    def observe(self, packet) -> int:
        """The names one packet says: how many were noted. A question this machine sends to port 53 (UDP or TCP) is
        remembered; an answer from port 53 to this machine is read for the question it answers; a ClientHello this
        machine sends to port 443 names the address it goes to."""
        payload = getattr(packet, "payload", b"")
        if not payload:
            return 0
        tcp = getattr(packet, "proto", "tcp") == "tcp"
        direction = getattr(packet, "dir", "")
        if packet.dport == DNS_PORT and direction in ("out", "local") and self._ask(packet, payload, tcp):
            return 0
        if packet.sport == DNS_PORT and direction in ("in", "local"):
            return self._answered(packet, payload, tcp)
        if tcp and packet.dport == TLS_PORT and direction == "out":
            name = parse_sni(payload)
            if name:
                self.add(name, packet.dst)
                self._count("sni")
                return 1
        return 0

    @staticmethod
    def _key(tcp: bool, resolver, here, port, ident: int) -> tuple:
        """A question's place: its protocol, the resolver asked, this machine's address and port it was asked from,
        its id."""
        return "tcp" if tcp else "udp", _ip(resolver), _ip(here), int(port), int(ident)

    def _ask(self, packet, payload, tcp: bool) -> bool:
        """A question this machine sent, remembered for its answer (the oldest forgotten once there are max_asked):
        whether it was one."""
        query = _read_dns(payload, tcp, _query)
        if query is None:
            return False
        ident, names = query
        key, at = self._key(tcp, packet.dst, packet.src, packet.sport, ident), float(packet.at)
        with self._lock:
            asked = self._asked.pop(key, [])
            asked = [(n, t) for n, t in asked if at - t <= self.wait and n not in names][-MAX_QUESTIONS:]
            self._asked[key] = asked + [(n, at) for n in names]
            while len(self._asked) > self.max_asked:
                self._asked.popitem(last=False)
            while self._asked:  # the questions waited on too long forgotten
                oldest = next(iter(self._asked.values()))
                if not oldest or at - max(t for _, t in oldest) > self.wait:
                    self._asked.popitem(last=False)
                    continue
                break
        return True

    def _answered(self, packet, payload, tcp: bool) -> int:
        """An answer to this machine: its names noted when it answers a question this machine asked."""
        read = _read_dns(payload, tcp, _answer)
        if read is None:
            return 0
        ident, asked, addresses, cnames = read
        key, at = self._key(tcp, packet.src, packet.dst, packet.dport, ident), float(packet.at)
        with self._lock:
            waiting = self._asked.get(key, [])
            matched = {n for n, t in waiting if n in asked and at - t <= self.wait}
            if not matched:
                self.read["unasked"] += 1
                return 0
            left = [(n, t) for n, t in waiting if n not in matched]  # each question believed answered once
            if left:
                self._asked[key] = left
            else:
                del self._asked[key]
        found = _chains([n for n in asked if n in matched], addresses, cnames)
        for name, address, _ in reversed(found):  # the name asked for noted last: the most recent
            self.add(name, address)
        if found:
            self._count("dns")
        return len(found)

    def _count(self, kind: str) -> None:
        with self._lock:
            self.read[kind] += 1

    def add(self, name: str, ip: str) -> None:
        """`name` noted as the most recent of `ip`'s (what is no host name, or no address, is passed over)."""
        text = str(name or "")
        key, name = _ip(ip), valid_name(text) if len(text) <= MAX_HOST + 8 else ""  # room for a last dot, spaces
        if not key or not name or len(name) > MAX_HOST:
            return
        with self._lock:
            names = self._names.get(key)
            if names is None:
                if len(self._names) >= self.max_ips:
                    self._names.popitem(last=False)
                self._names[key] = [name]
                return
            self._names.move_to_end(key)
            if names[0] != name:
                if name in names:
                    names.remove(name)
                names.insert(0, name)
                del names[self.per_ip:]

    def names_of(self, ip: str) -> list[str]:
        """`ip`'s names, the most recent first ([] when none was seen)."""
        with self._lock:
            return list(self._names.get(_ip(ip), ()))

    def name_of(self, ip: str) -> str | None:
        """`ip`'s most recent name, None when none was seen."""
        with self._lock:
            names = self._names.get(_ip(ip))
            return names[0] if names else None

    def __len__(self) -> int:
        with self._lock:
            return len(self._names)
