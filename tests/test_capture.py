"""Packets on a port (liminal_libs.capture): frames parsed as tcpdump would (Ethernet with or without a VLAN tag,
IPv4 and IPv6, loopback, raw IP, Linux cooked), the filter, and a capture over a stand-in for libpcap (nothing is
opened: the real adapter is read only by the Windows test below, on its loopback, when Npcap is there)."""
from __future__ import annotations

import socket
import struct
import sys

import pytest

from liminal_libs import capture
from liminal_libs.capture import Capture, CaptureError, Packet, bpf, parse


def ipv4_tcp(src="203.0.113.7", dst="192.168.1.20", sport=51000, dport=8765, flags=0x02, options=b"") -> bytes:
    head = 20 + len(options)
    ip = struct.pack("!BBHHHBBH4s4s", 0x40 | head // 4, 0, head + 20, 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst)) + options
    return ip + struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 64240, 0, 0)


def ethernet(payload: bytes, kind=0x0800, vlan=False) -> bytes:
    head = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
    return head + (struct.pack("!HH", 0x8100, 42) if vlan else b"") + struct.pack("!H", kind) + payload


def test_frames_are_read_as_tcpdump_would():
    syn = parse(ethernet(ipv4_tcp()), capture.LINK_ETHERNET, at=5.0)
    assert syn == Packet(5.0, "203.0.113.7", 51000, "192.168.1.20", 8765, "SYN") and syn.syn
    reply = parse(ethernet(ipv4_tcp("192.168.1.20", "203.0.113.7", 8765, 51000, 0x12), vlan=True), capture.LINK_ETHERNET)
    assert reply.flags == "SYN ACK" and not reply.syn and reply.sport == 8765  # behind a VLAN tag too
    assert parse(ethernet(ipv4_tcp(flags=0x14, options=b"\x01" * 8)), capture.LINK_ETHERNET).flags == "ACK RST"  # IP options
    v6 = struct.pack("!IHBB16s16s", 0x60000000, 20, 6, 64, socket.inet_pton(socket.AF_INET6, "2001:db8::7"),
                     socket.inet_pton(socket.AF_INET6, "2001:db8::20")) + struct.pack("!HHIIBBHHH", 51000, 443, 1, 0, 0x50, 0x02, 1, 0, 0)
    assert parse(ethernet(v6, 0x86DD), capture.LINK_ETHERNET) == Packet(0.0, "2001:db8::7", 51000, "2001:db8::20", 443, "SYN")
    assert parse(struct.pack("<I", 2) + ipv4_tcp(), capture.LINK_NULL).dport == 8765  # Npcap's loopback adapter
    assert parse(ipv4_tcp(), capture.LINK_RAW).src == "203.0.113.7"
    assert parse(b"\x00" * 14 + struct.pack("!H", 0x0800) + ipv4_tcp(), capture.LINK_LINUX_SLL).flags == "SYN"
    udp = bytearray(ipv4_tcp())
    udp[9] = 17
    assert parse(ethernet(bytes(udp)), capture.LINK_ETHERNET) is None and parse(ethernet(b"\x00" * 4, 0x0806), capture.LINK_ETHERNET) is None
    assert parse(b"\x01", capture.LINK_ETHERNET) is None and parse(ipv4_tcp(), 9999) is None
    assert bpf([8765, 443]) == "tcp and (port 8765 or port 443)" and bpf([25], "192.168.1.20") == "tcp and (port 25) and host 192.168.1.20"
    assert capture.tcp_flags(0) == "none" and syn.as_dict()["flags"] == "SYN"


class Source:
    """libpcap as a stand-in: the frames given, then nothing (each read's wait), then a fault when asked."""

    def __init__(self, frames, fail_open=None, fail_after=False):
        self.frames, self.fail_open, self.fail_after = list(frames), fail_open, fail_after
        self.link, self.opened, self.closed = capture.LINK_ETHERNET, None, False

    def open(self, address, ports):
        if self.fail_open:
            raise CaptureError(self.fail_open)
        self.opened = (address, tuple(ports))

    def next(self):
        if self.frames:
            return self.frames.pop(0)
        if self.fail_after:
            raise CaptureError("reading stopped: the adapter went away")
        return None

    def close(self):
        self.closed = True


def test_a_capture_keeps_each_packet_until_stopped():
    src = Source([(1.0, ethernet(ipv4_tcp())), (1.1, ethernet(b"\x00" * 10, 0x0806)),
                  (1.2, ethernet(ipv4_tcp("192.168.1.20", "203.0.113.7", 8765, 51000, 0x14)))])
    cap = Capture("192.168.1.20", [8765], source=src)
    cap.start()
    found = []
    for _ in range(200):
        found = cap.packets
        if len(found) == 2:
            break
        import time
        time.sleep(0.01)
    got = cap.stop()
    assert src.opened == ("192.168.1.20", (8765,)) and src.closed and [p.flags for p in got] == ["SYN", "ACK RST"]
    with pytest.raises(CaptureError, match="no adapter"):
        Capture("10.9.9.9", [80], source=Source([], fail_open="no adapter holds 10.9.9.9")).start()
    broken = Capture("192.168.1.20", [80], source=Source([], fail_after=True))
    broken.start()
    assert broken.stop() == [] and broken.error == "reading stopped: the adapter went away"


def test_whether_packets_can_be_watched_here_is_said():
    ok, why = capture.available()
    assert isinstance(ok, bool) and why


@pytest.mark.skipif(sys.platform != "win32" or not capture.available()[0], reason="Npcap on Windows")
def test_npcaps_adapters_are_listed_and_a_missing_address_said():
    with pytest.raises(CaptureError, match="no adapter holds 192.0.2.99"):
        capture.PcapSource(capture.load_pcap()).device_of("192.0.2.99")
