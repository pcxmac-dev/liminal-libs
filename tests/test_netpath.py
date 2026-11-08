"""This machine's way out (liminal_libs.netpath): what kind each address is, the default route read from Linux's
table, a ping's answer and a trace's first hops read from Windows' and Linux's own words, over stand-ins (no ping,
no trace is run)."""
from __future__ import annotations

from liminal_libs import netpath

TRACERT = """
Tracing route to 1.1.1.1 over a maximum of 3 hops

  1     4 ms     5 ms     3 ms  192.168.50.1
  2    13 ms    12 ms    12 ms  172.29.152.1
  3     *        *        *     Request timed out.

Trace complete.
"""
TRACEROUTE = """traceroute to 1.1.1.1 (1.1.1.1), 3 hops max, 60 byte packets
 1  192.168.1.1  0.512 ms
 2  100.64.0.1  9.871 ms
 3  203.0.113.9  11.2 ms
"""
PING_WINDOWS = "Pinging 192.168.50.1 with 32 bytes of data:\nReply from 192.168.50.1: bytes=32 time=3ms TTL=64\n"
PING_FAST = "Reply from 192.168.50.1: bytes=32 time<1ms TTL=64\n"
PING_LINUX = "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.412 ms\n"
UNREACHABLE = "Reply from 192.168.50.228: Destination host unreachable.\n"


def test_what_kind_each_address_is():
    assert [netpath.kind(a) for a in ("192.168.50.1", "172.29.152.1", "10.0.0.1", "100.64.3.4", "159.111.243.70",
                                      "127.0.0.1", "169.254.1.1", "nonsense", None)] == \
        ["private", "private", "private", "shared", "public", "loopback", "link-local", "unknown", "unknown"]


def test_the_default_route_from_linuxs_table():
    table = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
             "eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
             "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
             "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
    assert netpath._gateway_linux(table) == ("192.168.2.1", "eth0")  # the default route with the lowest metric
    assert netpath._gateway_linux("Iface\tDestination\n") == (None, "")
    assert netpath.lan_address() is None or netpath.kind(netpath.lan_address()) in ("private", "public", "shared", "link-local")


def test_a_ping_and_a_traces_first_hops_read_from_either_systems_words(monkeypatch):
    asked = []

    def answering(words):
        def run(args, timeout):
            asked.append(args)
            return words
        return run
    monkeypatch.setattr(netpath.sys, "platform", "win32")
    assert netpath.ping("192.168.50.1", run=answering(PING_WINDOWS)) == 3.0 and asked[-1][:3] == ["ping", "-n", "1"]
    assert netpath.ping("192.168.50.1", run=answering(PING_FAST)) == 0.5
    assert netpath.ping("192.168.50.1", run=answering(UNREACHABLE)) is None and netpath.ping("x", run=answering(None)) is None
    assert netpath.hops("1.1.1.1", run=answering(TRACERT)) == ["192.168.50.1", "172.29.152.1", None]
    assert asked[-1] == ["tracert", "-d", "-h", "3", "-w", "700", "1.1.1.1"]
    monkeypatch.setattr(netpath.sys, "platform", "linux")
    assert netpath.ping("192.168.1.1", run=answering(PING_LINUX)) == 0.412 and asked[-1][:3] == ["ping", "-c", "1"]
    assert netpath.hops("1.1.1.1", run=answering(TRACEROUTE)) == ["192.168.1.1", "100.64.0.1", "203.0.113.9"]

    def no_traceroute(args, timeout):
        asked.append(args)
        return None if args[0] == "traceroute" else " 1?: [LOCALHOST]  pmtu 1500\n 1:  192.168.1.1  0.4ms\n 2:  no reply\n"
    assert netpath.hops("1.1.1.1", run=no_traceroute) == ["192.168.1.1", None, None] and asked[-1][0] == "tracepath"
    assert netpath.hops("1.1.1.1", run=answering(None)) is None
