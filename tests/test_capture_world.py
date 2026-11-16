"""Every packet at an adapter (liminal_libs.capture, extended for the firewalls' World Wide Web tab; the user,
2026-11-14: "a 'world wide web view' that shows the globe and the routes incoming all traffic, as well as monitoring
port traffic stats"): TCP and UDP over IPv4 and IPv6 read with their IP version, protocol, size on the wire, flags
(as words and as bits) and direction against this machine's own addresses (read again while it watches); the bytes
after the header kept only for DNS (512 at most) and a ClientHello (its record, MAX_HELLO at most, joined with the
next segment when it runs into it); IPv6 extension headers stepped over, later fragments and malformed frames passed
over without a fault, however many; the filter covering UDP and every port; adapters listed with their IPv6 and
broadcast addresses; libpcap loaded once; a read off Windows waiting its timeout and no longer. libpcap is stood in
for three times: by a source handing frames, by the very ctypes structures libpcap hands back, and by a library that
counts its loads. Nothing is captured, nothing is opened, nothing leaves this machine."""
from __future__ import annotations

import ctypes
import json
import os
import random
import select
import socket
import struct
import sys
import threading
import time
import types

import pytest

from liminal_libs import capture
from liminal_libs.capture import (ACK, FIN, PSH, RST, SYN, Capture, CaptureError, Flags, LINK_ETHERNET, LINK_LINUX_SLL,
                                  LINK_LOOP, LINK_NULL, LINK_RAW, Packet, bpf, judge, own_addresses, parse)
from liminal_libs.names import NameBook
from liminal_libs.traffic import TrafficBook

LAN, LAN6, LINK6 = "192.168.1.20", "2001:db8:1::20", "fe80::20"
PEER, PEER6 = "81.2.69.142", "2a02:1810:4d0a::7"
ROUTER = "192.168.1.1"
LOCAL = own_addresses([LAN, LAN6, f"{LINK6}%12"])


# -- frames written by hand -------------------------------------------------------------------------------------------
def ipv4(src, dst, proto, body, *, frag=0, total=None, options=b"", ihl=None) -> bytes:
    head = 20 + len(options)
    words = head // 4 if ihl is None else ihl
    size = head + len(body) if total is None else total
    return struct.pack("!BBHHHBBH4s4s", 0x40 | words, 0, size, 1, frag, 64, proto, 0, socket.inet_aton(src),
                       socket.inet_aton(dst)) + options + body


def ipv6(src, dst, next_header, body, *, ext=b"", payload_length=None) -> bytes:
    size = len(ext) + len(body) if payload_length is None else payload_length
    return struct.pack("!IHBB16s16s", 0x60000000, size, next_header, 64, socket.inet_pton(socket.AF_INET6, src),
                       socket.inet_pton(socket.AF_INET6, dst)) + ext + body


def tcp(sport, dport, flags=SYN, body=b"", options=b"", seq=1) -> bytes:
    words = (20 + len(options)) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, words << 4, flags, 64240, 0, 0) + options + body


def udp(sport, dport, body=b"", length=None) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(body) if length is None else length, 0) + body


def ethernet(packet, kind=0x0800, vlans=0, pad=0) -> bytes:
    tags = b"".join(struct.pack("!HH", 0x8100 if i else 0x88A8, 42) for i in range(vlans))
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + tags + struct.pack("!H", kind) + packet + b"\x00" * pad


def hello_record(size: int) -> bytes:
    """A TLS record of `size` bytes holding a ClientHello (what the capture looks for: its first six bytes)."""
    head = b"\x16\x03\x01" + struct.pack("!H", size - 5) + b"\x01" + (size - 9).to_bytes(3, "big")
    return (head + bytes(range(256)) * (size // 256 + 1))[:size]


def test_tcp_and_udp_over_ipv4_and_ipv6_say_their_version_protocol_size_and_flags():
    syn = parse(ethernet(ipv4(PEER, LAN, 6, tcp(51000, 8765, SYN))), LINK_ETHERNET, at=5.0, length=74)
    assert (syn.at, syn.src, syn.sport, syn.dst, syn.dport) == (5.0, PEER, 51000, LAN, 8765)
    assert (syn.family, syn.proto, syn.length, syn.flags, int(syn.flags), syn.syn) == (4, "tcp", 74, "SYN", SYN, True)
    assert parse(ethernet(ipv4(PEER, LAN, 6, tcp(51000, 8765))), LINK_ETHERNET).length == 14 + 40  # not given: the frame's
    answer = parse(ethernet(ipv4(ROUTER, LAN, 17, udp(53, 53000, b"x" * 30))), LINK_ETHERNET, length=80)
    assert (answer.proto, answer.family, answer.sport, answer.dport, answer.length) == ("udp", 4, 53, 53000, 80)
    assert answer.flags == 0 and answer.flags == "none" and not answer.flags and not answer.syn  # UDP has no flags

    v6 = parse(ethernet(ipv6(PEER6, LAN6, 6, tcp(443, 50000, SYN | ACK)), 0x86DD), LINK_ETHERNET)
    assert (v6.family, v6.proto, v6.src, v6.dst, v6.flags, v6.length) == (6, "tcp", PEER6, LAN6, "SYN ACK", 14 + 40 + 20)
    assert v6.flags == SYN | ACK and not v6.syn  # an answer, not an ask
    v6udp = parse(ethernet(ipv6(LAN6, PEER6, 17, udp(50000, 443, b"q" * 100)), 0x86DD), LINK_ETHERNET)
    assert (v6udp.family, v6udp.proto, v6udp.sport, v6udp.dport, v6udp.length) == (6, "udp", 50000, 443, 14 + 40 + 108)
    full = "2001:0db8:0001:0000:0000:0000:0000:0020"
    assert parse(ipv6(full, PEER6, 17, udp(1, 2)), LINK_RAW).src == LAN6  # in its short form

    # each link the adapters give: loopback (BSD's and libpcap's own), raw IP, Linux cooked, two VLAN tags
    assert parse(struct.pack("<I", 2) + ipv4(LAN, LAN, 17, udp(5000, 6000)), LINK_NULL).proto == "udp"
    assert parse(struct.pack("<I", 23) + ipv6("::1", "::1", 6, tcp(5000, 6000)), LINK_NULL).family == 6  # Windows' AF_INET6
    assert parse(struct.pack("!I", 30) + ipv6("::1", "::1", 17, udp(1, 2)), LINK_LOOP).family == 6
    assert parse(ipv6(PEER6, LAN6, 17, udp(1, 2)), LINK_RAW).proto == "udp"
    cooked = b"\x00" * 14 + struct.pack("!H", 0x86DD) + ipv6(PEER6, LAN6, 6, tcp(443, 50000, ACK))
    assert parse(cooked, LINK_LINUX_SLL).flags == "ACK"
    assert parse(ethernet(ipv4(PEER, LAN, 17, udp(1, 2)), vlans=2), LINK_ETHERNET).dport == 2


def test_extension_headers_are_stepped_over_and_later_fragments_passed_over():
    hop_by_hop = bytes([6, 0]) + b"\x01\x04\x00\x00\x00\x00"  # PadN: 8 bytes, then TCP
    options = bytes([17, 1]) + b"\x01\x0c" + b"\x00" * 12  # destination options: 16 bytes, then UDP
    authentication = bytes([6, 4]) + b"\x00\x00" + b"\x00\x00\x01\x00" + b"\x00\x00\x00\x07" + b"\xaa" * 12  # 24 bytes
    assert parse(ipv6(PEER6, LAN6, 0, tcp(443, 50000, ACK), ext=hop_by_hop), LINK_RAW).sport == 443
    assert parse(ipv6(PEER6, LAN6, 60, udp(53, 50000), ext=options), LINK_RAW).proto == "udp"
    assert parse(ipv6(PEER6, LAN6, 51, tcp(22, 50000, ACK), ext=authentication), LINK_RAW).sport == 22
    chained = bytes([60, 0]) + b"\x01\x04\x00\x00\x00\x00" + options
    assert parse(ipv6(PEER6, LAN6, 0, udp(123, 123), ext=chained), LINK_RAW).dport == 123

    first = struct.pack("!BBHI", 17, 0, 0 << 3 | 1, 7)  # offset 0, more to come: the ports are in it
    later = struct.pack("!BBHI", 17, 0, 185 << 3, 7)
    assert parse(ipv6(PEER6, LAN6, 44, udp(53, 50000, b"a" * 40), ext=first), LINK_RAW).sport == 53
    assert parse(ipv6(PEER6, LAN6, 44, b"\x00" * 48, ext=later), LINK_RAW) is None
    assert parse(ipv4(PEER, LAN, 17, udp(53, 50000, b"a" * 40), frag=0x2000), LINK_RAW).sport == 53  # first: MF, offset 0
    assert parse(ipv4(PEER, LAN, 17, b"\x00" * 48, frag=0x2000 | 185), LINK_RAW) is None
    assert parse(ipv4(PEER, LAN, 6, tcp(51000, 80), frag=0x4000), LINK_RAW).dport == 80  # don't fragment

    pad = b"\x01\x04\x00\x00\x00\x00"
    eight = (bytes([0, 0]) + pad) * 7 + bytes([6, 0]) + pad  # eight headers, the last leading to TCP: stepped over
    assert parse(ipv6(PEER6, LAN6, 0, tcp(1, 2), ext=eight), LINK_RAW).dport == 2
    nine = (bytes([0, 0]) + pad) * 8 + bytes([6, 0]) + pad  # nine: more than are ever stepped over
    assert parse(ipv6(PEER6, LAN6, 0, tcp(1, 2), ext=nine), LINK_RAW) is None
    assert parse(ipv6(PEER6, LAN6, 0, b"", ext=bytes([6, 0, 1, 4])), LINK_RAW) is None  # a header cut short
    assert parse(ipv6(PEER6, LAN6, 0, b"", ext=bytes([6, 200]) + b"\x00" * 6), LINK_RAW) is None  # one past the end
    assert parse(ipv6(PEER6, LAN6, 58, b"\x80\x00" + b"\x00" * 6), LINK_RAW) is None  # ICMPv6


def test_cut_short_and_malformed_frames_are_passed_over_and_never_fault():
    frames = [ethernet(ipv4(PEER, LAN, 6, tcp(51000, 443, ACK, b"x" * 40, options=b"\x01" * 12), options=b"\x01" * 8)),
              ethernet(ipv6(PEER6, LAN6, 0, udp(53, 50000, b"y" * 30), ext=bytes([17, 0]) + b"\x01\x04" + b"\x00" * 4),
                       0x86DD, vlans=1),
              b"\x00" * 14 + struct.pack("!H", 0x0800) + ipv4(PEER, LAN, 17, udp(53, 50000, b"z" * 10))]
    links = [LINK_ETHERNET, LINK_ETHERNET, LINK_LINUX_SLL]
    for frame, link in zip(frames, links):
        whole = parse(frame, link, local=LOCAL)
        assert whole is not None
        for cut in range(len(frame)):
            got = parse(frame[:cut], link, local=LOCAL)
            assert got is None or isinstance(got, Packet)
    rng = random.Random(20261114)
    for _ in range(3000):  # bytes of every kind: none faults
        frame = bytearray(frames[rng.randrange(3)])
        for _ in range(rng.randrange(1, 8)):
            frame[rng.randrange(len(frame))] = rng.randrange(256)
        for link in (LINK_ETHERNET, LINK_RAW, LINK_NULL, LINK_LINUX_SLL):
            got = parse(bytes(frame), link, local=LOCAL)
            assert got is None or got.proto in ("tcp", "udp")
        parse(bytes(rng.randrange(256) for _ in range(rng.randrange(80))), LINK_RAW)

    assert parse(ipv4(PEER, LAN, 6, tcp(1, 2), ihl=4), LINK_RAW) is None  # a header shorter than twenty bytes
    assert parse(ipv4(PEER, LAN, 17, udp(1, 2, length=7)), LINK_RAW) is None  # no datagram is shorter than its header
    assert parse(ipv4(PEER, LAN, 1, b"\x08\x00" + b"\x00" * 30), LINK_RAW) is None  # ICMP
    assert parse(ethernet(b"\x00" * 28, 0x0806), LINK_ETHERNET) is None  # ARP
    assert parse(ethernet(b"", 0x8100), LINK_ETHERNET) is None  # a VLAN tag with nothing after it
    assert parse(ipv4(PEER, LAN, 6, tcp(1, 2)), 9999) is None and parse(b"", LINK_RAW) is None
    assert parse(b"\x01\x02", LINK_NULL) is None and parse(b"\x00" * 15, LINK_LINUX_SLL) is None


def test_the_direction_is_judged_against_this_machines_own_addresses():
    assert LOCAL == {LAN, LAN6, LINK6}
    assert own_addresses([" 192.168.1.20 ", "[2001:DB8:1::20]", "not an address", None]) == {LAN, LAN6}
    inbound = parse(ethernet(ipv4(PEER, LAN, 6, tcp(51000, 8765))), LINK_ETHERNET, local=LOCAL)
    outbound = parse(ethernet(ipv6(LAN6, PEER6, 6, tcp(50000, 443)), 0x86DD), LINK_ETHERNET, local=LOCAL)
    assert (inbound.dir, outbound.dir) == ("in", "out")
    assert inbound.ends == (LAN, 8765, PEER, 51000) and outbound.ends == (LAN6, 50000, PEER6, 443)
    assert parse(ipv4(LAN, LAN, 17, udp(1, 2)), LINK_RAW, local=LOCAL).dir == "local"
    assert parse(struct.pack("<I", 2) + ipv4("127.0.0.1", "127.0.0.1", 6, tcp(1, 2)), LINK_NULL, local=frozenset()).dir == "local"
    assert parse(ipv6("::1", LAN6, 6, tcp(1, 2)), LINK_RAW, local=LOCAL).dir == "local"  # loopback is always its own
    assert parse(ipv4("192.168.1.5", "255.255.255.255", 17, udp(68, 67)), LINK_RAW, local=LOCAL).dir == "in"  # heard
    assert parse(ipv4(LAN, "224.0.0.251", 17, udp(5353, 5353)), LINK_RAW, local=LOCAL).dir == "out"
    assert parse(ipv6("fe80::1", "ff02::1", 17, udp(547, 546)), LINK_RAW, local=LOCAL).dir == "in"
    assert parse(ipv4(PEER, LAN, 6, tcp(1, 2)), LINK_RAW).dir == ""  # no addresses given: not judged
    assert judge(LINK6, "ff02::fb", LOCAL) == "out" and judge(PEER, ROUTER, LOCAL) == "in"


def test_bytes_after_the_header_are_kept_only_for_dns_and_a_client_hello():
    def kept(packet: bytes, payloads=True) -> bytes:
        return parse(ethernet(packet), LINK_ETHERNET, payloads=payloads).payload

    question = b"\x12\x34\x01\x00\x00\x01" + b"\x00" * 6 + b"\x04shop\x07example\x00\x00\x01\x00\x01"
    assert kept(ipv4(LAN, ROUTER, 17, udp(53000, 53, question))) == question  # a question, UDP/53
    assert kept(ipv4(ROUTER, LAN, 17, udp(53, 53000, question + b"\xaa" * 900))) == (question + b"\xaa" * 900)[:512]
    framed = struct.pack("!H", len(question)) + question
    assert kept(ipv4(ROUTER, LAN, 6, tcp(53, 53000, PSH | ACK, framed))) == framed  # DNS over TCP
    assert kept(ipv4(LAN, PEER, 6, tcp(50000, 443, PSH | ACK, hello_record(700)))) == hello_record(700)  # its record
    assert kept(ipv4(LAN, PEER, 6, tcp(50000, 443, PSH | ACK, hello_record(200) + b"\x17" * 50))) == hello_record(200)
    big = hello_record(9000)  # a record longer than any ClientHello: MAX_HELLO kept of it
    assert kept(ipv4(LAN, PEER, 6, tcp(50000, 443, PSH | ACK, big))) == big[:capture.MAX_HELLO]
    assert kept(ipv4(LAN, PEER, 6, tcp(50000, 443, PSH | ACK, hello_record(200), options=b"\x01" * 12))) == hello_record(200)
    assert parse(ethernet(ipv6(LAN6, PEER6, 6, tcp(50000, 443, PSH | ACK, hello_record(300))), 0x86DD),
                 LINK_ETHERNET).payload == hello_record(300)

    application = b"\x17\x03\x03\x00\x40" + b"\x00" * 64
    server_hello = b"\x16\x03\x03\x00\x40\x02" + b"\x00" * 63
    assert kept(ipv4(LAN, PEER, 6, tcp(50000, 443, PSH | ACK, application))) == b""  # an encrypted record
    assert kept(ipv4(PEER, LAN, 6, tcp(443, 50000, PSH | ACK, server_hello))) == b""  # the server's answer
    assert kept(ipv4(LAN, PEER, 6, tcp(50000, 443, PSH | ACK, server_hello))) == b""  # no ClientHello in it
    assert kept(ipv4(LAN, PEER, 17, udp(50000, 443, hello_record(300)))) == b""  # QUIC: UDP/443
    assert kept(ipv4(LAN, PEER, 6, tcp(50000, 80, PSH | ACK, b"GET / HTTP/1.1\r\n"))) == b""  # the web in clear: no
    assert kept(ipv4(LAN, PEER, 6, tcp(50000, 8443, PSH | ACK, hello_record(300)))) == b""  # another port
    assert kept(ipv4(ROUTER, LAN, 17, udp(53, 53000, question)), payloads=False) == b""  # as the path check asks

    # the IP packet's own length ends it: Ethernet's padding and what the UDP length leaves out are not kept
    padded = parse(ethernet(ipv4(ROUTER, LAN, 17, udp(53, 53000, b"\x01\x02\x03\x04")), pad=14), LINK_ETHERNET)
    assert padded.payload == b"\x01\x02\x03\x04" and padded.length == 14 + 32
    short = parse(ipv4(ROUTER, LAN, 17, udp(53, 53000, b"abcdefgh", length=12)), LINK_RAW)
    assert short.payload == b"abcd"
    assert repr(padded).count("payload") == 0  # never shown


def test_flags_read_as_words_and_as_the_headers_bits():
    f = Flags(SYN | ACK)
    assert f == "SYN ACK" and f == 0x12 and int(f) == 0x12 and f.bits == 0x12 and f != "SYN" and f != 0x02
    assert f & SYN == SYN and SYN & f == SYN and f | FIN == 0x13 and f ^ ACK == SYN and bool(f)
    assert Flags("ack syn") is f and Flags(f) is f and Flags(0x112) is f  # one made per value, the header's byte
    assert f"{f:#04x}" == "0x12" and f"{f:08b}" == "00010010" and f"{f}" == "SYN ACK" and f"{f:>9}" == "  SYN ACK"
    assert hex(f) == "0x12" and "RST" in Flags(ACK | RST) and Flags(ACK | RST).startswith("ACK")
    assert not Flags() and Flags() == "none" and Flags() == 0 and Flags("none") is Flags(0)
    assert capture.tcp_flags(FIN | SYN | RST | PSH | ACK | 0x20 | 0x40 | 0x80) == "SYN ACK FIN RST PSH URG ECE CWR"
    assert capture.bits_of("syn rst whatever") == SYN | RST and capture.bits_of(Flags(FIN)) == FIN
    assert json.dumps({"flags": f}) == '{"flags": "SYN ACK"}' and type(str(f)) is str

    words, bits = Packet(1.0, PEER, 1, LAN, 2, "SYN"), Packet(1.0, PEER, 1, LAN, 2, SYN)  # the path check's, the bits
    assert words == bits and words.flags is bits.flags and words.family == 4 and words.proto == "tcp" and words.syn
    assert Packet(1.0, PEER6, 1, LAN6, 2, "SYN", length=60) == Packet(1.0, PEER6, 1, LAN6, 2, "SYN", length=99)
    assert Packet(1.0, PEER6, 1, LAN6, 2).family == 6 and Packet(1.0, PEER, 1, LAN, 2, proto="udp").syn is False
    seen = parse(ethernet(ipv4(PEER, LAN, 6, tcp(51000, 8765, SYN))), LINK_ETHERNET, at=7.0, length=74, local=LOCAL)
    assert seen.as_dict() == {"at": 7.0, "src": PEER, "sport": 51000, "dst": LAN, "dport": 8765, "flags": "SYN",
                              "bits": SYN, "family": 4, "proto": "tcp", "length": 74, "dir": "in"}
    assert json.loads(json.dumps(seen.as_dict())) == seen.as_dict()


def test_the_filter_covers_udp_and_every_port_when_asked():
    assert bpf([8765, 443]) == "tcp and (port 8765 or port 443)"  # as the path check always had it
    assert bpf([25], LAN) == "tcp and (port 25) and host 192.168.1.20"
    assert bpf((), None, udp=True) == "(tcp or udp)"
    assert bpf([53], LAN6, udp=True) == "(tcp or udp) and (port 53) and host 2001:db8:1::20"
    assert bpf((), f"[{LINK6}%12]") == "tcp and host fe80::20"
    checked = Capture(LAN, [8765])  # made, never opened: libpcap is not even loaded
    assert checked.source.expression == "tcp and (port 8765) and host 192.168.1.20"
    assert checked.source.snaplen == capture.SNAPLEN and checked.source.lib is None
    world = Capture(LAN, udp=True, payloads=True, host=False)
    assert world.source.expression == "(tcp or udp)" and world.source.snaplen == capture.PAYLOAD_SNAPLEN
    assert capture.PAYLOAD_SNAPLEN >= 14 + 8 + 60 + 60 + capture.MAX_HELLO > capture.MAX_PAYLOAD  # two tags, options
    assert capture.MAX_HELLO >= 2048 and capture.PAYLOAD_SNAPLEN >= 1514  # a whole frame, a whole Chromium hello


# -- libpcap's own structures, handed back by a stand-in ----------------------------------------------------------------
class Lib:
    """libpcap as a stand-in: its adapters made of the very structures pcap_findalldevs hands back (IPv4, IPv6 and a
    link-layer address each; an (address, broadcast) pair for one with its broadcast address), an open and a filter
    that record what they were asked, packets handed as pcap_next_ex hands them. `block`: a blocking read with no
    packet waits that long (as Linux's TPACKET_V3 reads do, for ever, until a packet passes the filter) before it says
    nothing came; a non-blocking one (pcap_setnonblock) says so at once. `fd`: the socket's file pcap_get_selectable_fd
    gives (-1: none). Nothing is opened."""

    def __init__(self, adapters, frames=(), fail_list=False, fail_open=False, fail_filter=False, block=0.0,
                 fail_nonblock=False):
        self.adapters, self.frames = adapters, list(frames)
        self.fail_list, self.fail_open, self.fail_filter = fail_list, fail_open, fail_filter
        self.block, self.fail_nonblock, self.fd = block, fail_nonblock, -1
        self.listed = self.freed = self.reads = self.blocked = 0
        self.opened, self.filters, self.closed, self.nonblocking, self._keep = [], [], [], [], []
        self.arrived = threading.Event()

    def _sockaddr(self, address):
        if address == "link":
            sa = capture._Sockaddr(family=17)  # AF_PACKET's: an adapter's hardware address, no IP
        elif ":" in address:
            sa6 = capture._Sockaddr6(family=socket.AF_INET6)
            sa6.addr[:] = list(socket.inet_pton(socket.AF_INET6, address))
            self._keep.append(sa6)
            return ctypes.cast(ctypes.pointer(sa6), ctypes.POINTER(capture._Sockaddr))
        else:
            sa = capture._Sockaddr(family=socket.AF_INET)
            sa.data[2:6] = list(socket.inet_aton(address))
        self._keep.append(sa)
        return ctypes.pointer(sa)

    def pcap_findalldevs(self, found, err):
        self.listed += 1
        if self.fail_list:
            err.value = b"no adapters for you"
            return -1
        nxt = None
        for name, addresses in reversed(self.adapters):
            dev = capture._PcapIf(name=name.encode())
            node = None
            for address in reversed(addresses):
                address, broadcast = address if isinstance(address, tuple) else (address, None)
                a = capture._PcapAddr(addr=self._sockaddr(address))
                if broadcast:
                    a.broadaddr = self._sockaddr(broadcast)
                if node is not None:
                    a.next = ctypes.pointer(node)
                self._keep.append(a)
                node = a
            if node is not None:
                dev.addresses = ctypes.pointer(node)
            if nxt is not None:
                dev.next = ctypes.pointer(nxt)
            self._keep.append(dev)
            nxt = dev
        found._obj.contents = nxt  # the list's head, where libpcap writes it
        return 0

    def pcap_freealldevs(self, found):
        self.freed += 1

    def pcap_open_live(self, device, snaplen, promiscuous, wait, err):
        self.opened.append((device.decode(), snaplen, promiscuous, wait))
        if self.fail_open:
            err.value = b"access denied"
            return None
        return 0x5EED

    def pcap_compile(self, handle, program, expression, optimize, netmask):
        self.filters.append(expression.decode())
        return -1 if self.fail_filter else 0

    def pcap_setfilter(self, handle, program):
        return 0

    def pcap_freecode(self, program):
        pass

    def pcap_datalink(self, handle):
        return LINK_ETHERNET

    def pcap_geterr(self, handle):
        return b"syntax error in filter expression"

    def pcap_close(self, handle):
        self.closed.append(handle)

    def pcap_setnonblock(self, handle, nonblock, err):
        if self.fail_nonblock:
            err.value = b"fcntl failed"
            return -1
        self.nonblocking.append(nonblock)
        return 0

    def pcap_get_selectable_fd(self, handle):
        return self.fd

    def pcap_next_ex(self, handle, header, data):
        self.reads += 1
        if not self.frames and self.block and not (self.nonblocking and self.nonblocking[-1]):
            self.blocked += 1  # a blocking read: held until a packet comes
            self.arrived.wait(self.block)
        if not self.frames:
            return 0  # the read's wait ended with nothing
        at, frame, wire = self.frames.pop(0)
        h = capture._PktHdr(caplen=len(frame))
        h.len, h.ts.sec, h.ts.usec = wire, int(at), round((at - int(at)) * 1e6)
        buf = (ctypes.c_ubyte * len(frame))(*frame)
        self._keep += [h, buf]
        header._obj.contents = h
        data._obj.contents = ctypes.c_ubyte.from_buffer(buf)
        return 1


ADAPTERS = [(r"\Device\NPF_{4A1B}", [LAN, "link", LINK6, LAN6]), (r"\Device\NPF_Loopback", ["127.0.0.1", "::1"]),
            ("bluetooth0", [])]


def test_adapters_are_listed_with_their_ipv6_addresses_and_found_by_either():
    lib = Lib(ADAPTERS)
    src = capture.PcapSource(lib)
    assert src.adapters() == [(r"\Device\NPF_{4A1B}", (LAN, LINK6, LAN6)), (r"\Device\NPF_Loopback", ("127.0.0.1", "::1")),
                              ("bluetooth0", ())]
    assert src.device_of(LAN) == src.device_of(LAN6) == src.device_of(f"[{LINK6}%12]") == r"\Device\NPF_{4A1B}"
    assert src.device_of("0:0:0:0:0:0:0:1") == r"\Device\NPF_Loopback"
    with pytest.raises(CaptureError, match="no adapter holds 2001:db8:9::1"):
        src.device_of("2001:db8:9::1")
    with pytest.raises(CaptureError, match="is no address"):
        src.device_of("nowhere")
    assert lib.listed == lib.freed == 7  # each list freed, found or not
    with pytest.raises(CaptureError, match="could not be listed: no adapters for you"):
        capture.PcapSource(Lib(ADAPTERS, fail_list=True)).adapters()


def test_an_opened_adapter_gathers_this_machines_addresses_once_and_hands_packets_with_their_size():
    syn = ethernet(ipv4(PEER, LAN, 6, tcp(51000, 8765, SYN), options=b"\x01" * 40)) + b"\xee" * 900
    lib = Lib(ADAPTERS, frames=[(1_800_000_000.25, syn, 1514)])
    src = capture.PcapSource(lib, snaplen=capture.SNAPLEN, expression="(tcp or udp)")
    src.open(LAN6, ())
    assert lib.opened == [(r"\Device\NPF_{4A1B}", capture.SNAPLEN, 0, capture.TIMEOUT_MS)] and lib.listed == 1
    assert lib.filters == ["(tcp or udp)"] and src.link == LINK_ETHERNET
    assert src.local == {LAN, LINK6, LAN6, "127.0.0.1", "::1"}  # every adapter's: this machine's own
    at, kept, wire = src.next()
    assert (at, kept, wire) == (1_800_000_000.25, syn[:capture.SNAPLEN], 1514) and src.next() is None
    src.close()
    src.close()
    assert lib.closed == [0x5EED]  # once
    with pytest.raises(CaptureError, match="not open"):
        src.next()  # libpcap is never handed a closed handle

    plain = capture.PcapSource(lib)
    plain.open(LAN, [8765])
    assert lib.filters[-1] == "tcp and (port 8765) and host 192.168.1.20"  # the path check's, as before
    with pytest.raises(CaptureError, match="could not be opened: access denied"):
        capture.PcapSource(Lib(ADAPTERS, fail_open=True)).open(LAN, [80])
    refused = Lib(ADAPTERS, fail_filter=True)
    with pytest.raises(CaptureError, match="filter could not be set: syntax error"):
        capture.PcapSource(refused).open(LAN, [80])
    assert refused.closed == [0x5EED]


# -- a capture over a source standing in for libpcap ---------------------------------------------------------------------
class Frames:
    """libpcap as a stand-in source: the frames given ((time, bytes[, size on the wire])), then nothing yet; this
    machine's addresses as an opened adapter lists them; a fault when asked."""

    link = LINK_ETHERNET

    def __init__(self, frames, local=(), fail_after=None):
        self.frames, self.addresses, self.fail_after = list(frames), tuple(local), fail_after
        self.local, self.opened, self.closed = frozenset(), [], 0

    def open(self, address, ports):
        self.opened.append((address, tuple(ports)))
        self.local = own_addresses(self.addresses)

    def next(self):
        if self.frames:
            return self.frames.pop(0)
        if self.fail_after:
            raise CaptureError(self.fail_after)
        time.sleep(0.001)  # a read's wait
        return None

    def close(self):
        self.closed += 1


def wait_for(condition, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.005)
    return condition()


def test_a_capture_pulled_packet_by_packet_judges_each_against_the_addresses_gathered_when_it_opened():
    frames = [(1.0, ethernet(b"\x00" * 28, 0x0806), 60),  # ARP: passed over
              (1.1, ethernet(ipv4(PEER, LAN, 6, tcp(51000, 8765, SYN))), 74),
              (1.2, ethernet(ipv6(LAN6, PEER6, 17, udp(50000, 53, b"q" * 20)), 0x86DD)),  # as older sources hand them
              (1.3, ethernet(ipv4("10.8.0.2", PEER, 6, tcp(40000, 443, SYN)))),
              (1.4, ethernet(ipv4(PEER, "10.9.0.9", 6, tcp(443, 40000, ACK))))]
    before = set(threading.enumerate())
    source = Frames(frames, local=[LAN6])
    cap = Capture(LAN, source=source, udp=True, payloads=True, host=False, local=["10.8.0.2"])
    cap.open()
    assert source.opened == [(LAN, ())] and cap.local == {LAN, LAN6, "10.8.0.2"}
    got = [cap.next() for _ in range(4)]
    assert [(p.at, p.dir, p.proto, p.family) for p in got] == [(1.1, "in", "tcp", 4), (1.2, "out", "udp", 6),
                                                               (1.3, "out", "tcp", 4), (1.4, "in", "tcp", 4)]
    assert got[0].length == 74 and got[1].length == 14 + 40 + 28 and got[1].payload == b"q" * 20
    assert cap.next() is None and cap.packets == []  # pulled packets are the caller's: none kept
    cap.close()
    assert source.closed == 1 and set(threading.enumerate()) <= before  # pulling starts no thread

    junk = Frames([(2.0, b"\x00" * 3)] * 500 + [(2.1, ethernet(ipv4(PEER, LAN, 6, tcp(51000, 8765, SYN))))])
    pulled = Capture(LAN, source=junk)
    pulled.open()
    assert pulled.next().at == 2.1 and junk.frames == []  # all of it passed over in one pull, while it kept coming
    failing = Capture(LAN, source=Frames([], fail_after="reading stopped: the adapter went away"))
    failing.open()
    with pytest.raises(CaptureError, match="went away"):
        failing.next()


def test_a_capture_on_its_own_thread_hands_each_packet_on_or_keeps_the_first_ones(monkeypatch):
    frames = [(float(i), ethernet(ipv4(PEER, LAN, 6, tcp(51000 + i, 8765, SYN))), 74) for i in range(5)]
    handed = []
    cap = Capture(LAN, [8765], source=Frames(frames), on_packet=handed.append)
    cap.start()
    assert wait_for(lambda: len(handed) == 5) and cap.running
    assert cap.stop() == [] and not cap.running and cap.source.closed == 1  # handed on, none kept
    assert [p.sport for p in handed] == [51000, 51001, 51002, 51003, 51004] and {p.dir for p in handed} == {"in"}

    def refuse(packet):
        raise RuntimeError("no room")
    broken = Capture(LAN, [8765], source=Frames(frames), on_packet=refuse)
    broken.start()
    assert wait_for(lambda: not broken.running)
    assert broken.error == "reading stopped: a packet's handler failed: RuntimeError: no room" and broken.source.closed == 1

    monkeypatch.setattr(capture, "MAX_PACKETS", 3)
    kept = Capture(LAN, [8765], source=Frames(frames))
    kept.start()
    assert wait_for(lambda: not kept.source.frames)
    assert [p.sport for p in kept.stop()] == [51000, 51001, 51002]  # the first ones, capped
    assert not kept.running and kept.source.closed == 1


# -- libpcap loaded once in a process (review F1) ------------------------------------------------------------------------
def test_libpcap_is_loaded_once_in_a_process_and_no_dll_folder_is_added(monkeypatch, tmp_path):
    """(Review F1) Each load added Npcap's folder to the process's DLL search path, never removed: after about 1,260 (a
    World tab asking every 2 s for 42 minutes while its capture could not open) Npcap failed with WinError 206, and so
    did every DLL loaded after (_ssl, _sqlite3). Now wpcap.dll is loaded once, by its full path, no folder added."""
    (tmp_path / "wpcap.dll").write_bytes(b"MZ")
    loads, added = [], []

    class Loaded:
        """ctypes.CDLL as a stand-in: each load counted, any function's arguments declarable."""

        def __init__(self, path, *args, **kwargs):
            loads.append(path)

        def __getattr__(self, name):
            if not name.startswith("pcap_"):
                raise AttributeError(name)
            made = types.SimpleNamespace()
            setattr(self, name, made)
            return made

    monkeypatch.setattr(capture, "sys", types.SimpleNamespace(platform="win32"))
    monkeypatch.setattr(capture, "NPCAP", str(tmp_path))
    monkeypatch.setattr(capture, "_PCAP", None, raising=False)
    monkeypatch.setattr(capture.ctypes, "CDLL", Loaded)
    monkeypatch.setattr(capture.os, "add_dll_directory", lambda path: added.append(path), raising=False)
    first = capture.load_pcap()
    for _ in range(1500):
        assert capture.load_pcap() is first and capture.available() == (True, "Npcap")
    assert loads == [os.path.join(str(tmp_path), "wpcap.dll")] and added == []
    assert first.pcap_next_ex.argtypes and first.pcap_geterr.restype is ctypes.c_char_p
    assert capture.PcapSource().lib is None  # a source made loads nothing; opened, it takes the one loaded

    def refuse(path, *args, **kwargs):
        loads.append(path)
        raise OSError("[WinError 126] The specified module could not be found")
    monkeypatch.setattr(capture, "_PCAP", None)
    monkeypatch.setattr(capture.ctypes, "CDLL", refuse)
    for _ in range(50):  # a load that failed is tried again when asked again, and adds nothing either
        ok, why = capture.available()
        assert not ok and why.startswith("Npcap's wpcap.dll could not be loaded: [WinError 126]")
    assert len(loads) == 51 and added == [] and capture._PCAP is None
    monkeypatch.setattr(capture, "NPCAP", str(tmp_path / "nowhere"))
    assert capture.available() == (False, "Npcap is not installed (npcap.com; Wireshark installs it): packets cannot "
                                          "be watched") and len(loads) == 51


@pytest.mark.skipif(sys.platform != "win32" or not os.path.exists(os.path.join(capture.NPCAP, "wpcap.dll")),
                    reason="Npcap on Windows")
def test_npcaps_library_is_one_object_however_often_it_is_asked_for():
    """The real wpcap.dll, loaded by its full path (its Packet.dll found beside it); no adapter is opened."""
    ok, why = capture.available()
    assert ok, why
    assert capture.load_pcap() is capture.load_pcap() is capture._PCAP


# -- a read off Windows waits its timeout, not for a packet (review F2) ---------------------------------------------------
@pytest.fixture
def linux(monkeypatch):
    """The capture as on Linux (its reads non-blocking, its socket waited on); a pipe's end as the socket where poll is
    there to wait on it, none (short steps) elsewhere. Nothing is captured."""
    monkeypatch.setattr(capture, "sys", types.SimpleNamespace(platform="linux"))
    ends = os.pipe() if hasattr(select, "poll") else None
    yield ends
    if ends:
        for end in ends:
            os.close(end)


def test_a_read_off_windows_waits_its_timeout_and_no_longer_when_no_packet_comes(linux):
    """(Review F2) Linux's libpcap returns from a blocking read only once a packet passed the filter (TPACKET_V3 wakes
    a reader only then), so a quiet adapter held the reading thread, its stop and the open handle until one did. The
    handle is now read without blocking and its socket waited on, TIMEOUT_MS at most."""
    lib = Lib(ADAPTERS, block=5.0)
    if linux:
        lib.fd = linux[0]
    src = capture.PcapSource(lib, expression="(tcp or udp)")
    src.open(LAN, ())
    assert lib.nonblocking == [1] and src.waits == (linux[0] if linux else -1)
    began = time.monotonic()
    assert src.next() is None
    took = time.monotonic() - began
    assert capture.TIMEOUT_MS / 1000 * 0.8 <= took < 1.5 and lib.blocked == 0  # its own wait, never libpcap's
    lib.frames.append((5.0, ethernet(ipv4(PEER, LAN, 6, tcp(51000, 8765))), 54))
    if linux:
        os.write(linux[1], b"x")  # the socket says a packet is there
    assert src.next()[0] == 5.0
    src.close()
    assert lib.closed == [0x5EED] and src.waits is None

    refused = Lib(ADAPTERS, fail_nonblock=True)
    with pytest.raises(CaptureError, match="could not be read without blocking: fcntl failed"):
        capture.PcapSource(refused).open(LAN, [80])
    assert refused.closed == [0x5EED]  # not left open


@pytest.mark.skipif(sys.platform != "win32", reason="Npcap's way: Windows only")
def test_npcap_reads_wait_by_themselves():
    """On Windows the handle is left as Npcap opens it: its read waits TIMEOUT_MS itself."""
    lib = Lib(ADAPTERS)
    src = capture.PcapSource(lib)
    src.open(LAN, [8765])
    assert lib.nonblocking == [] and src.waits is None and src.next() is None


def test_a_capture_on_its_own_thread_stops_soon_on_a_quiet_linux_adapter(linux):
    """(Review F2) stop() returned after its wait with the thread still held in libpcap's read and the adapter open."""
    lib = Lib(ADAPTERS, block=5.0)
    if linux:
        lib.fd = linux[0]
    cap = Capture(LAN, [8765], source=capture.PcapSource(lib))
    cap.start()
    assert wait_for(lambda: lib.reads > 0)
    began = time.monotonic()
    cap.stop(wait=2.0)
    assert not cap.running and time.monotonic() - began < 1.0 and lib.closed == [0x5EED] and lib.blocked == 0


# -- a stream of frames passed over (review F3) ---------------------------------------------------------------------------
class Endless:
    """A source that always has a frame waiting (a full buffer): `frame` again and again, never "nothing yet"."""

    link = LINK_ETHERNET

    def __init__(self, frame):
        self.frame, self.local, self.handed = frame, frozenset(), 0

    def open(self, address, ports):
        self.local = own_addresses([address])

    def next(self):
        self.handed += 1
        return 1.0, self.frame, len(self.frame)

    def close(self):
        pass


def test_a_pull_passes_over_frames_while_they_come_for_its_time_at_most():
    """(Review F3) A pull ended after 64 frames passed over, as if nothing had come, and a Watcher then slept: a
    stream of later fragments (which "(tcp or udp)" lets through) held its reading to about 1,600 frames a second.
    Now a pull passes over frames for PASS_S at most, however many come, and hands the next packet at once."""
    later = ethernet(ipv4(PEER, LAN, 17, b"\x00" * 48, frag=185))
    assert parse(later, LINK_ETHERNET) is None
    frames = [(1.0, later, 82)] * 1000 + [(1.5, ethernet(ipv4(PEER, LAN, 6, tcp(40000, 8765, SYN))), 74)]
    cap = Capture(LAN, source=Frames(frames), udp=True, host=False)
    cap.open()
    assert cap.next().sport == 40000 and cap.source.frames == []  # a thousand passed over in one pull
    endless = Capture(LAN, source=Endless(later), udp=True, host=False)
    endless.open()
    began = time.monotonic()
    assert endless.next() is None
    took = time.monotonic() - began
    assert capture.PASS_S * 0.9 <= took < capture.PASS_S + 1.0 and endless.source.handed > 1000


# -- a ClientHello longer than its segment (review F5) ---------------------------------------------------------------------
def segments(src, dst, payload: bytes, *, mss: int = 1460, seq: int = 7_000_000, v6: bool = False, sport: int = 52000):
    """A client's bytes to port 443 as TCP sends them: `mss` bytes a segment, each frame with its sequence number."""
    out = []
    for at in range(0, len(payload), mss):
        body = tcp(sport, 443, PSH | ACK, payload[at:at + mss], seq=(seq + at) & 0xFFFFFFFF)
        out.append(ethernet(ipv6(src, dst, 6, body), 0x86DD) if v6 else ethernet(ipv4(src, dst, 6, body)))
    return out


def named(frames) -> tuple[list[Packet], NameBook]:
    """The frames through a capture keeping payloads, each packet handed to a NameBook."""
    source = Frames([(1.0 + i / 1000, f, len(f)) for i, f in enumerate(frames)], local=[LAN, LAN6])
    cap, book = Capture(LAN, source=source, udp=True, payloads=True, host=False), NameBook()
    cap.open()
    got = []
    while (p := cap.next()) is not None:
        got.append(p)
        book.observe(p)
    return got, book


LATE = (0x0033, 0xFE0D, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x0005, 0x000D, 0x0012, 0x002D, 0x002B,
        0x001B, 0x44CD, 0x0000)  # a Chromium ClientHello's extensions: the key share first, the server_name last


def test_a_chromium_client_hello_split_over_two_segments_is_joined_and_named():
    """(Review F5) Chromium shuffles its extensions for each connection and sends a key share of 1.2 KB: half its
    ClientHellos had their server_name past byte 512, four in ten past the first segment, which starts no record and
    was never kept. Now the record is kept, MAX_HELLO at most, joined with the segment after it."""
    from test_names import chromium_hello
    rng = random.Random(20261115)
    whole = chromium_hello(b"www.bank.example", rng, order=LATE)
    assert whole.index(b"www.bank.example") > 1460  # in the second segment
    for v6, (src, dst) in ((False, (LAN, PEER)), (True, (LAN6, PEER6))):
        got, book = named(segments(src, dst, whole, v6=v6))
        assert book.name_of(dst) == "www.bank.example" and book.read["sni"] == 1
        assert [len(p.payload) for p in got] == [1460, len(whole)]  # the second carries the hello joined, from its start
        assert got[1].payload == whole and len(whole) <= capture.MAX_HELLO
    for mss in (536, 1220):  # smaller segments (four, then two), and sequence numbers that wrap: joined all the same
        got, book = named(segments(LAN, PEER, whole, mss=mss, seq=0xFFFFFF00))
        assert got[-1].payload == whole and book.name_of(PEER) == "www.bank.example"
    lso = bytearray(ethernet(ipv4(LAN, PEER, 6, tcp(52000, 443, PSH | ACK, whole))))  # sent as one frame (offload):
    lso[16:18] = b"\x00\x00"  # the IP header's length 0, as segmentation offload leaves it
    got, book = named([bytes(lso)])
    assert got[0].payload == whole and book.name_of(PEER) == "www.bank.example"
    found = 0
    for _ in range(300):  # random orders, as Chromium sends them: every one named
        got, book = named(segments(LAN, PEER, chromium_hello(b"api.shop.example", rng)))
        found += book.name_of(PEER) == "api.shop.example"
    assert found == 300


def test_only_the_next_segment_of_the_same_connection_is_joined_and_what_waits_is_bounded():
    whole = hello_record(2000)
    first, second = segments(LAN, PEER, whole)
    other = segments(LAN, PEER, whole, sport=52001)[1]  # another connection's
    again = segments(LAN, PEER, whole, seq=7_000_001)[1]  # a sequence number not the one awaited
    got, _ = named([first, other, again, second])
    assert [len(p.payload) for p in got] == [1460, 0, 0, 2000]
    third = ethernet(ipv4(LAN, PEER, 6, tcp(52000, 443, PSH | ACK, b"\x17" * 100, seq=7_002_000)))
    got, _ = named([first, second, third])  # the hello whole: what follows is not kept
    assert [len(p.payload) for p in got] == [1460, 2000, 0]
    answer = ethernet(ipv4(PEER, LAN, 6, tcp(443, 52000, PSH | ACK, b"\x16" * 100, seq=7_001_460)))
    got, _ = named([first, answer, second])  # the server's bytes are no part of it
    assert [len(p.payload) for p in got] == [1460, 0, 2000]
    got, _ = named([first[:600], second])  # the first segment cut short when captured: no rest can be joined to it
    assert 0 < len(got[0].payload) < 600 and got[1].payload == b""

    waits = capture.Hellos(cap=3, wait=2.0)
    for i in range(10):
        waits.begin(("a", i, "b", 443), 100, b"x" * 1460, capture.MAX_HELLO, float(i) / 10)
    assert len(waits) == 3 and ("a", 9, "b", 443) in waits and ("a", 0, "b", 443) not in waits
    assert waits.more(("a", 9, "b", 443), 100, b"y" * 5000, True, 1.0) == b"x" * 1460 + b"y" * (capture.MAX_HELLO - 1460)
    assert ("a", 9, "b", 443) not in waits  # all it needed: done
    assert waits.more(("a", 8, "b", 443), 100, b"y", True, 9.0) == b"" and ("a", 8, "b", 443) not in waits  # too late
    cut = capture.Hellos()
    cut.begin(("a", 1, "b", 443), 0, b"x" * 1000, 2000, 0.0)
    assert cut.more(("a", 1, "b", 443), 0, b"y" * 300, False, 0.0) == b"x" * 1000 + b"y" * 300 and len(cut) == 0


# -- this machine's addresses read again while it watches (review F6) ----------------------------------------------------
HERE_MAC, ROUTER_MAC = b"\x02\x11\x22\x33\x44\x55", b"\x02\xaa\xbb\xcc\xdd\xee"
NEW6, NEW4 = "2001:db8:1::abcd", "192.168.1.77"


def framed(packet: bytes, src_mac: bytes, kind: int = 0x0800) -> bytes:
    """An Ethernet frame from `src_mac` (to the other of this machine's and the router's)."""
    other = ROUTER_MAC if src_mac == HERE_MAC else HERE_MAC
    return other + src_mac + struct.pack("!H", kind) + packet


class Moving(Frames):
    """An adapter whose addresses change while it is watched: refresh() reads them again (as libpcap would list
    them), each read counted."""

    def __init__(self, frames, local=()):
        super().__init__(frames, local)
        self.refreshed = 0

    def refresh(self):
        self.refreshed += 1
        self.local = own_addresses(self.addresses)
        return self.local


class Ticks:
    def __init__(self, t: float = 100.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_an_address_gained_while_watching_is_learned_soon_and_its_traffic_judged_outbound():
    """(Review F6) The addresses were read once when the capture opened: a temporary IPv6 address (or a new lease)
    gained while the World tab stayed open made this machine's own connections from it look like unanswered attempts
    on a local port 443 from its own /48. Now they are read again every REFRESH_S, and at once (HINT_S at most) when a
    frame the adapter itself sent comes from an address not known."""
    out_syn = framed(ipv6(NEW6, PEER6, 6, tcp(50000, 443, SYN)), HERE_MAC, 0x86DD)
    answer = framed(ipv6(PEER6, NEW6, 6, tcp(443, 50000, SYN | ACK)), ROUTER_MAC, 0x86DD)
    frames = [(1.0, framed(ipv4(LAN, PEER, 6, tcp(49000, 443, SYN)), HERE_MAC), 74),  # from a known one: its MAC
              (2.0, out_syn, 94), (2.05, answer, 94)]
    source = Moving(frames, local=[LAN, LAN6])
    cap = Capture(LAN, source=source, udp=True, host=False)
    cap.open()
    source.addresses += (NEW6,)  # the adapter gains a temporary address
    book = TrafficBook()
    got = []
    while (p := cap.next()) is not None:
        got.append(p)
        book.add(p)
    assert [p.dir for p in got] == ["out", "out", "in"] and source.refreshed == 1 and NEW6 in cap.local
    snap = book.snapshot(now=10.0)
    assert snap["ports"] == [] and snap["totals"]["unanswered"] == 0  # no attempt on a port here
    assert [(r["proto"], r["port"], r["new_out"]) for r in snap["remote_ports"]] == [("tcp", 443, 2)]
    assert {g["group"] for g in snap["groups"]} == {"81.2.69.0/24", "2a02:1810:4d0a::/48"}  # its own /48 is none

    # a frame from elsewhere, from an address not known, reads nothing again; a hint is taken once in HINT_S
    source, ticks = Moving([(1.0, framed(ipv4(LAN, PEER, 6, tcp(49000, 443, SYN)), HERE_MAC), 74)], local=[LAN]), Ticks()
    cap = Capture(LAN, source=source, udp=True, host=False, ticks=ticks)
    cap.open()
    assert cap.next().dir == "out"  # its hardware address learned
    source.frames = [(3.0, framed(ipv4("192.168.1.5", LAN, 6, tcp(1, 2)), ROUTER_MAC), 60),
                     (3.1, framed(ipv4(NEW4, PEER, 6, tcp(3, 443)), HERE_MAC), 60),
                     (3.2, framed(ipv4("192.168.1.78", PEER, 6, tcp(4, 443)), HERE_MAC), 60)]
    source.addresses += (NEW4,)
    assert cap.next().dir == "in" and source.refreshed == 0
    ticks.t += 1.0
    assert cap.next().dir == "out" and source.refreshed == 1  # read again: the new lease is this machine's
    ticks.t += 1.0
    assert cap.next().dir == "in" and source.refreshed == 1  # a hint again so soon is not taken (a router's, a spoof)
    source.addresses += ("192.168.1.78",)  # every REFRESH_S, whatever the frames say
    source.frames = [(4.0, ethernet(ipv4("192.168.1.78", PEER, 6, tcp(5, 443))), 60),
                     (4.1, framed(ipv4("192.168.1.79", PEER, 6, tcp(6, 443)), HERE_MAC), 60)]
    ticks.t += capture.REFRESH_S
    assert cap.next().dir == "out" and source.refreshed == 2
    ticks.t += capture.HINT_S  # a hint's time come again: taken
    assert cap.next().dir == "in" and source.refreshed == 3  # read again; the address is still no one's here


def test_addresses_are_read_again_on_a_raw_link_by_time_and_on_linux_cooked_by_the_kernels_word():
    raw = [(1.0, ipv4(NEW4, PEER, 6, tcp(1, 443)), 40), (2.0, ipv4(NEW4, PEER, 6, tcp(2, 443)), 40)]
    source, ticks = Moving(raw, local=[LAN]), Ticks()
    source.link = LINK_RAW
    cap = Capture(LAN, source=source, ticks=ticks, refresh=10.0)
    cap.open()
    source.addresses += (NEW4,)
    assert cap.next().dir == "in" and source.refreshed == 0  # no frame says who sent it on a raw link
    ticks.t += 10.0
    assert cap.next().dir == "out" and source.refreshed == 1
    sent = struct.pack("!HHH", 4, 1, 6) + HERE_MAC + b"\x00\x00" + struct.pack("!H", 0x0800)  # PACKET_OUTGOING
    cooked = Moving([(1.0, sent + ipv4(NEW4, PEER, 6, tcp(1, 443)), 56)], local=[LAN])
    cooked.link = LINK_LINUX_SLL
    cap = Capture(LAN, source=cooked, ticks=Ticks())
    cap.open()
    cooked.addresses += (NEW4,)
    assert cap.next().dir == "out" and cooked.refreshed == 1
    never = Moving(list(raw), local=[LAN])
    never.link = LINK_RAW
    cap = Capture(LAN, source=never, refresh=None, ticks=Ticks())
    cap.open()
    never.addresses += (NEW4,)
    assert cap.next().dir == "in" and never.refreshed == 0  # asked never to read them again


def test_an_opened_source_reads_this_machines_addresses_again_and_their_broadcast_addresses():
    adapters = [(r"\Device\NPF_{4A1B}", [(LAN, "192.168.1.127"), "link", LINK6, LAN6]),
                (r"\Device\NPF_Loopback", ["127.0.0.1", "::1"])]
    lib = Lib(adapters)
    src = capture.PcapSource(lib, expression="(tcp or udp)")
    src.open(LAN, ())
    assert src.broadcast == {"192.168.1.127"} and NEW6 not in src.local and lib.listed == 1
    adapters[0][1].append(NEW6)
    assert NEW6 in src.refresh() and src.local == {LAN, LINK6, LAN6, NEW6, "127.0.0.1", "::1"} and lib.listed == 2
    assert lib.freed == 2 and src.adapters()[0] == (r"\Device\NPF_{4A1B}", (LAN, LINK6, LAN6, NEW6))
    cap = Capture(LAN, source=capture.PcapSource(Lib(adapters)), udp=True, host=False)
    cap.open()
    assert cap.broadcast == {"192.168.1.127"} and NEW6 in cap.local
    failing = Lib(adapters)
    moving = capture.PcapSource(failing)
    moving.open(LAN, ())
    failing.fail_list = True
    with pytest.raises(CaptureError, match="could not be listed"):
        moving.refresh()
    assert NEW6 in moving.local  # what was known stands
