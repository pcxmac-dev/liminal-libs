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



# -- a whole route (1.67.0) -----------------------------------------------------------------------------------------
TRACERT_FULL = """
Tracing route to 81.2.69.142 over a maximum of 30 hops

  1    <1 ms    <1 ms    <1 ms  192.168.50.1
  2     *        *        *     Request timed out.
  3    12 ms    11 ms    13 ms  62.0.0.3
  4     9 ms     *       10 ms  81.2.69.142

Trace complete.
"""
TRACEPATH = """ 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.1.1                                           0.389ms
 1:  192.168.1.1                                           0.401ms
 2:  no reply
 3:  2606:4700::1111                                       9.871ms reached
     Resume: pmtu 1500 hops 3 back 3
"""
TRACEROUTE_STARS = """traceroute to 81.2.69.142 (81.2.69.142), 30 hops max, 60 byte packets
 1  192.168.1.1  0.512 ms
 2  *
 3  62.0.0.3  8.1 ms
"""


def test_a_routes_hops_read_from_each_tracers_words():
    assert netpath.parse_trace(TRACERT_FULL, "81.2.69.142") == (
        netpath.Hop(1, "192.168.50.1", 0.5), netpath.Hop(2, None), netpath.Hop(3, "62.0.0.3", 11.0),
        netpath.Hop(4, "81.2.69.142", 9.0))
    assert netpath.parse_trace(TRACEPATH, "2606:4700::1111") == (
        netpath.Hop(1, "192.168.1.1", 0.389), netpath.Hop(2, None), netpath.Hop(3, "2606:4700::1111", 9.871))
    assert netpath.parse_trace(TRACEROUTE_STARS, "81.2.69.142") == (
        netpath.Hop(1, "192.168.1.1", 0.512), netpath.Hop(2, None), netpath.Hop(3, "62.0.0.3", 8.1))
    assert netpath.parse_trace("", "81.2.69.142") == () and netpath.parse_trace(None, "81.2.69.142") == ()


def test_only_a_public_address_is_traced_and_never_a_name():
    assert netpath.traceable(" 81.2.69.142 ") == "81.2.69.142"
    assert netpath.traceable("::ffff:81.2.69.142") == "81.2.69.142"
    assert netpath.traceable("2606:4700::1111") == "2606:4700::1111"
    for bad in ("example.com", "192.168.1.1", "100.64.0.1", "127.0.0.1", "224.0.0.1", "fe80::1", "", None):
        try:
            netpath.traceable(bad)
        except ValueError as e:
            assert "name" in str(e) or "not on the internet" in str(e)
        else:
            raise AssertionError(f"{bad!r} was taken")


def _probe(distance: int, asked: list, silent=()):
    def probe(target, ttl, wait_ms):
        asked.append(ttl)
        if ttl in silent:
            return None, None, False
        if ttl >= distance:
            return target, 20.0, True
        return f"62.0.0.{ttl}", float(ttl), False
    return probe


def test_on_windows_an_ipv4_route_is_asked_a_wave_at_a_time_through_the_icmp_api():
    asked: list = []
    t = netpath.trace("81.2.69.142", probe=_probe(5, asked, silent={2}), run=lambda *a: None, windows=True)
    assert t.how == "icmp" and t.reached and sorted(asked) == list(range(1, 17))  # one wave: the target answered in it
    assert t.hops == (netpath.Hop(1, "62.0.0.1", 1.0), netpath.Hop(2, None, None), netpath.Hop(3, "62.0.0.3", 3.0),
                      netpath.Hop(4, "62.0.0.4", 4.0), netpath.Hop(5, "81.2.69.142", 20.0))
    far: list = []
    t = netpath.trace("81.2.69.142", probe=_probe(20, far), windows=True)
    assert sorted(far) == list(range(1, 31)) and t.reached and len(t.hops) == 20  # a second wave, then reached


def test_a_route_that_never_reaches_its_address_ends_at_its_last_answer():
    asked: list = []
    t = netpath.trace("81.2.69.142", probe=_probe(99, asked, silent=set(range(8, 31))), windows=True)
    assert not t.reached and len(t.hops) == 7 and t.hops[-1].address == "62.0.0.7" and sorted(asked) == list(range(1, 31))


def test_windows_without_its_icmp_api_and_ipv6_go_to_tracert_and_linux_to_traceroute_then_tracepath():
    ran = []

    def run(args, timeout):
        ran.append(args)
        return {"tracert": TRACERT_FULL, "tracepath": TRACEPATH}.get(args[0])

    def broken(target, ttl, wait_ms):
        raise OSError("IcmpCreateFile failed")
    t = netpath.trace("81.2.69.142", probe=broken, run=run, windows=True)
    assert t.how == "tracert" and t.reached and ran[-1][:2] == ["tracert", "-d"] and "-4" in ran[-1]
    t = netpath.trace("2606:4700::1111", probe=broken, run=run, windows=True)
    assert t.how == "tracert" and "-6" in ran[-1]
    ran.clear()
    t = netpath.trace("2606:4700::1111", run=run, windows=False)
    assert [a[0] for a in ran] == ["traceroute", "tracepath"] and t.how == "tracepath" and t.reached
    assert "-6" in ran[0] and "-n" in ran[0] and "-6" in ran[1]
    t = netpath.trace("81.2.69.142", run=lambda *a: None, windows=False)
    assert t.error.startswith("no tracer could run here") and t.hops == ()


def test_a_name_or_a_local_address_is_refused_before_anything_is_sent():
    asked: list = []
    for bad in ("example.com", "192.168.1.1"):
        try:
            netpath.trace(bad, probe=_probe(3, asked), run=lambda *a: asked.append(a), windows=True)
        except ValueError:
            pass
        else:
            raise AssertionError(bad)
    assert asked == []
