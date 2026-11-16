"""Traffic counted while a tab is looked at (liminal_libs.traffic), for the firewalls' World Wide Web tab (the user,
2026-11-14: "a 'world wide web view' that shows the globe and the routes incoming all traffic, as well as monitoring
port traffic stats"): packets judged against this machine's addresses and counted by the service's port and the remote
group (an IPv4 /24, an IPv6 /48), bytes and packets each way; an inbound SYN with no SYN-ACK back within 3 s counted
unanswered, and one no answer can be matched to any more counted on its port and group; datagrams to the adapters' own
broadcast addresses asking no one; every table, the ring and the flows followed capped; snapshots plain data. A Watcher
with a stand-in capture and a clock of the test's own: started by a touch, kept going by touches, stopped by itself
after its timeout and by stop() (on a quiet Linux adapter too), one daemon thread while it runs and none after, not
slowed by frames passed over. Nothing is captured, nothing leaves this machine."""
from __future__ import annotations

import json
import socket
import struct
import threading
import time
import types
from collections import deque

import pytest

from liminal_libs import capture
from liminal_libs.capture import ACK, FIN, PSH, RST, SYN, Capture, CaptureError, Packet
from liminal_libs.names import NameBook
from liminal_libs.traffic import TrafficBook, Watcher, group_of, service

LAN, LAN6, ROUTER = "192.168.1.20", "2001:db8:1::20", "192.168.1.1"
PEER, PEER2, PEER6 = "81.2.69.142", "81.2.69.160", "2a02:1810:4d0a:1::7"
LOCAL = capture.own_addresses([LAN, LAN6])


def pk(at, src, sport, dst, dport, flags=0, proto="tcp", length=60, payload=b"") -> Packet:
    """A packet as a capture hands it, its direction judged against this machine's addresses."""
    return Packet(at, src, sport, dst, dport, flags, 0, proto, length, capture.judge(src, dst, LOCAL), payload)


def rows(snap: dict, table: str) -> dict:
    return {(r["proto"], r["port"]): r for r in snap[table]}


def test_a_connection_from_elsewhere_counts_on_its_port_here_and_its_remote_group():
    book = TrafficBook()
    book.add(pk(10.0, PEER, 51000, LAN, 8765, SYN, length=74))
    book.add(pk(10.1, LAN, 8765, PEER, 51000, SYN | ACK, length=74))
    book.add(pk(10.2, PEER, 51000, LAN, 8765, ACK, length=66))
    book.add(pk(10.3, PEER, 51000, LAN, 8765, PSH | ACK, length=566))
    book.add(pk(10.4, LAN, 8765, PEER, 51000, PSH | ACK, length=1466))
    book.add(pk(10.5, PEER, 51000, LAN, 8765, FIN | ACK, length=66))
    snap = book.snapshot(now=11.0)
    port = rows(snap, "ports")[("tcp", 8765)]
    assert (port["in_bytes"], port["out_bytes"], port["in_packets"], port["out_packets"]) == (772, 1540, 4, 2)
    assert (port["new_in"], port["unanswered"], port["bytes"], port["packets"]) == (1, 0, 2312, 6)
    assert (port["first"], port["last"]) == (10.0, 10.5)
    assert snap["remote_ports"] == []  # the client's passing port is no port of its own
    [group] = snap["groups"]
    assert (group["group"], group["family"], group["network"], group["address"], group["ports"]) == (
        "81.2.69.0/24", 4, "public", PEER, [8765])
    assert (group["in_bytes"], group["out_bytes"], group["new_in"], group["first"], group["last"]) == (772, 1540, 1, 10.0, 10.5)
    assert snap["recent"] == [{"time": 10.0, "proto": "tcp", "dir": "in", "kind": "allowed", "local": LAN,
                               "local_port": 8765, "remote": PEER, "remote_port": 51000, "group": "81.2.69.0/24"}]
    totals = snap["totals"]
    assert (totals["bytes"], totals["packets"], totals["new_in"], totals["new_out"], totals["unanswered"]) == (2312, 6, 1, 0, 0)
    assert (snap["since"], snap["updated"], snap["pending"], snap["unjudged"]) == (10.0, 11.0, 0, 0)


def test_a_connection_from_here_counts_under_the_service_it_reached():
    book = TrafficBook()
    book.add(pk(20.0, LAN6, 52000, PEER6, 443, SYN, length=94))
    book.add(pk(20.05, PEER6, 443, LAN6, 52000, SYN | ACK, length=94))
    book.add(pk(20.1, LAN6, 52000, PEER6, 443, PSH | ACK, length=600))
    book.add(pk(20.2, PEER6, 443, LAN6, 52000, PSH | ACK, length=1400))
    book.add(pk(20.3, LAN6, 52000, PEER6, 443, RST | ACK, length=74))
    snap = book.snapshot(now=21.0)
    assert snap["ports"] == []  # nothing here was a service
    web = rows(snap, "remote_ports")[("tcp", 443)]
    assert (web["new_out"], web["new_in"], web["out_bytes"], web["in_bytes"], web["packets"]) == (1, 0, 768, 1494, 5)
    [group] = snap["groups"]
    assert (group["group"], group["family"], group["network"], group["ports"]) == ("2a02:1810:4d0a::/48", 6, "public", [443])
    assert [(e["kind"], e["dir"], e["local_port"], e["remote_port"]) for e in snap["recent"]] == [("outbound", "out", 52000, 443)]
    # closed by its RST: the same ends again are a new connection, counted again
    book.add(pk(30.0, LAN6, 52000, PEER6, 443, SYN))
    assert rows(book.snapshot(now=31.0), "remote_ports")[("tcp", 443)]["new_out"] == 2


def test_an_inbound_syn_with_no_syn_ack_back_within_three_seconds_is_unanswered():
    book = TrafficBook()
    book.add(pk(0.0, PEER, 40001, LAN, 3389, SYN))
    book.add(pk(1.0, PEER, 40001, LAN, 3389, SYN))  # sent again: the same attempt
    book.add(pk(1.5, LAN, 3389, PEER2, 40009, SYN | ACK))  # an answer to someone else answers nothing here
    early = book.snapshot(now=2.9)
    assert rows(early, "ports")[("tcp", 3389)]["unanswered"] == 0 and early["pending"] == 1 and early["recent"] == []
    late = book.snapshot(now=3.5)
    rdp = rows(late, "ports")[("tcp", 3389)]
    assert (rdp["unanswered"], rdp["new_in"], rdp["in_packets"]) == (1, 0, 2) and late["pending"] == 0
    assert [(e["kind"], e["time"], e["remote"]) for e in late["recent"]] == [("unanswered", 0.0, PEER)]
    assert late["totals"]["unanswered"] == 1 and late["groups"][0]["unanswered"] == 1

    book.add(pk(10.0, PEER, 40002, LAN, 3389, SYN))
    book.add(pk(12.9, LAN, 3389, PEER, 40002, SYN | ACK))  # in time: allowed
    book.add(pk(20.0, PEER, 40003, LAN, 3389, SYN))
    book.add(pk(23.5, LAN, 3389, PEER, 40003, SYN | ACK))  # too late: already judged unanswered
    book.add(pk(30.0, PEER, 40004, LAN, 3389, SYN))
    book.add(pk(30.01, LAN, 3389, PEER, 40004, RST | ACK))  # refused: no SYN-ACK came, so unanswered as well
    book.add(pk(40.0, PEER, 40005, LAN, 22, SYN))
    book.add(pk(44.0, PEER2, 5000, LAN, 8080, ACK))  # a later packet's time judges what came before it
    snap = book.snapshot(now=0.0)  # a clock behind the packets: their own time stands
    assert rows(snap, "ports")[("tcp", 3389)]["unanswered"] == 3 and rows(snap, "ports")[("tcp", 3389)]["new_in"] == 1
    assert rows(snap, "ports")[("tcp", 22)]["unanswered"] == 1 and snap["updated"] == 44.0
    assert [e["kind"] for e in snap["recent"]] == ["unanswered", "unanswered", "unanswered", "allowed", "unanswered"]


def test_udp_flows_are_judged_by_any_datagram_back_and_counted_apart():
    book = TrafficBook()
    book.add(pk(0.0, "192.168.1.5", 5353, "224.0.0.251", 5353, proto="udp"))  # heard by all: no one is asked
    book.add(pk(0.0, "192.168.1.5", 137, "192.168.1.255", 137, proto="udp"))  # the network's broadcast: the same
    book.add(pk(0.0, "fe80::5", 546, "ff02::1:2", 547, proto="udp"))
    book.add(pk(0.1, PEER, 51820, LAN, 51820, proto="udp"))  # to a port here, nothing back
    book.add(pk(0.2, PEER2, 40000, LAN, 1194, proto="udp"))
    book.add(pk(0.3, LAN, 1194, PEER2, 40000, proto="udp"))  # answered
    book.add(pk(0.4, LAN, 53000, ROUTER, 53, proto="udp"))  # a question from here ...
    book.add(pk(0.45, ROUTER, 53, LAN, 53000, proto="udp"))  # ... and its answer
    book.add(pk(0.5, ROUTER, 53, LAN, 53001, proto="udp"))  # the answer to a question asked before watching began
    snap = book.snapshot(now=5.0)
    here, there = rows(snap, "ports"), rows(snap, "remote_ports")
    assert (here[("udp", 51820)]["unanswered_udp"], here[("udp", 51820)]["unanswered"]) == (1, 0)
    assert (here[("udp", 1194)]["new_in"], here[("udp", 1194)]["unanswered_udp"]) == (1, 0)
    for port in (5353, 137, 547):
        assert (here[("udp", port)]["new_in"], here[("udp", port)]["unanswered_udp"]) == (0, 0)
    assert (there[("udp", 53)]["new_out"], there[("udp", 53)]["in_packets"], there[("udp", 53)]["out_packets"]) == (1, 2, 1)
    assert (snap["totals"]["unanswered_udp"], snap["totals"]["unanswered"], snap["totals"]["new_in"]) == (1, 0, 1)
    groups = {g["group"]: g for g in snap["groups"]}
    assert groups["192.168.1.0/24"]["network"] == "private" and groups["fe80::/48"]["network"] == "link-local"


def test_a_connection_open_before_watching_began_counts_where_its_ports_say():
    book = TrafficBook()
    book.add(pk(1.0, PEER, 51000, LAN, 22, ACK, length=100))  # ssh here, open already
    book.add(pk(1.1, LAN, 22, PEER, 51000, PSH | ACK, length=200))
    book.add(pk(1.2, LAN, 50000, PEER2, 443, ACK, length=80))  # the web, there
    book.add(pk(1.3, LAN, 8080, PEER2, 50001, ACK, length=80))  # a service under 32768 over a passing port
    snap = book.snapshot(now=2.0)
    assert rows(snap, "ports")[("tcp", 22)]["bytes"] == 300 and rows(snap, "ports")[("tcp", 8080)]["out_packets"] == 1
    assert rows(snap, "remote_ports")[("tcp", 443)]["out_bytes"] == 80
    assert snap["recent"] == [] and snap["totals"]["new_in"] == snap["totals"]["new_out"] == 0  # no start was seen
    assert service(8765, 51000, "in") == ("local", 8765) and service(51000, 443, "out") == ("remote", 443)
    assert service(51000, 443) == ("remote", 443) and service(22, 50000) == ("local", 22)
    assert service(50000, 3478) == ("remote", 3478) and service(8080, 50000) == ("local", 8080)
    assert service(5000, 6000) == ("local", 5000) and service(6000, 5000) == ("remote", 5000)
    assert service(51820, 51820) == ("local", 51820)


def test_remote_groups_are_ipv4_24s_and_ipv6_48s_with_their_latest_addresses():
    assert group_of(PEER) == "81.2.69.0/24" and group_of("::ffff:81.2.69.142") == "81.2.69.0/24"
    assert group_of(PEER6) == "2a02:1810:4d0a::/48" and group_of("fe80::1%12") == "fe80::/48"
    assert group_of("nowhere") == "nowhere"
    book = TrafficBook()
    book.add(pk(1.0, "2a02:1810:4d0a:1::7", 51000, LAN6, 443, SYN))
    book.add(pk(2.0, "2a02:1810:4d0a:ffff::9", 51001, LAN6, 443, SYN))
    for i in range(6):
        book.add(pk(3.0 + i, f"81.2.69.{10 + i}", 40000 + i, LAN, 8765, SYN))
    for i in range(20):
        book.add(pk(10.0 + i, "100.64.7.9", 41000 + i, LAN, 2000 + i, SYN))
    groups = {g["group"]: g for g in book.snapshot(now=40.0)["groups"]}
    v6 = groups["2a02:1810:4d0a::/48"]
    assert v6["addresses"] == ["2a02:1810:4d0a:ffff::9", "2a02:1810:4d0a:1::7"] and v6["family"] == 6
    v4 = groups["81.2.69.0/24"]
    assert v4["addresses"] == ["81.2.69.15", "81.2.69.14", "81.2.69.13", "81.2.69.12"] and v4["address"] == "81.2.69.15"
    assert (v4["first"], v4["last"], v4["unanswered"]) == (3.0, 8.0, 6)
    shared = groups["100.64.7.0/24"]
    assert shared["network"] == "shared" and len(shared["ports"]) == 16 and shared["ports"][0] == 2000


def test_packets_between_its_own_addresses_or_not_judged_are_counted_apart():
    book = TrafficBook()
    book.add(Packet(1.0, LAN, 5000, LAN, 6000, SYN, 4, "tcp", 60, "local"))
    book.add(Packet(1.0, "127.0.0.1", 5000, "127.0.0.1", 6000, ACK, 4, "tcp", 40, "local"))
    book.add(Packet(1.0, PEER, 5000, LAN, 6000, SYN, 4, "tcp", 60, ""))  # no direction judged
    snap = book.snapshot(now=2.0)
    assert (snap["totals"]["local_packets"], snap["totals"]["local_bytes"], snap["totals"]["unknown_packets"]) == (2, 100, 1)
    assert snap["ports"] == snap["remote_ports"] == snap["groups"] == snap["recent"] == [] and snap["totals"]["packets"] == 0


def test_every_table_the_ring_and_the_flows_followed_are_capped():
    book = TrafficBook(max_ports=2, max_origins=2, ring=3, max_flows=4)
    for i in range(10):
        book.add(pk(float(i), f"81.2.{i}.7", 40000 + i, LAN, 1000 + i, SYN, length=100))
        book.add(pk(i + 0.1, LAN, 1000 + i, f"81.2.{i}.7", 40000 + i, SYN | ACK, length=100))
        book.add(pk(i + 0.2, LAN, 50000 + i, f"81.2.{i}.8", 3000 + i, SYN, length=50))
    snap = book.snapshot(now=20.0)
    assert sorted(r["port"] for r in snap["ports"]) == [1008, 1009] and len(snap["remote_ports"]) == 2
    assert len(snap["groups"]) == 2 and len(snap["recent"]) == 3 and snap["flows"] <= 4
    assert [(e["kind"], e["local_port"]) for e in snap["recent"]] == [("outbound", 50009), ("allowed", 1009), ("outbound", 50008)]
    assert snap["evicted"] == {"ports": 8, "remote_ports": 8, "groups": 8, "flows": 16}
    assert snap["caps"] == {"ports": 2, "origins": 2, "ring": 3, "flows": 4}
    # what was folded away still adds up: nothing counted is lost
    for table in ("ports", "remote_ports", "groups"):
        assert sum(r["bytes"] for r in snap[table]) + snap["other"][table]["bytes"] == (
            2000 if table == "ports" else 500 if table == "remote_ports" else 2500)
    assert sum(r["new_in"] for r in snap["ports"]) + snap["other"]["ports"]["new_in"] == 10 == snap["totals"]["new_in"]
    assert snap["totals"]["bytes"] == 2500 and snap["unjudged"] == 0

    crowded = TrafficBook(max_flows=2)  # attempts pushed out before they could be judged
    for i in range(3):
        crowded.add(pk(i / 10, PEER, 40000 + i, LAN, 22, SYN))
    snap = crowded.snapshot(now=10.0)
    assert (rows(snap, "ports")[("tcp", 22)]["unanswered"], snap["unjudged"], snap["evicted"]["flows"]) == (2, 1, 1)


def test_a_snapshot_is_plain_data():
    book = TrafficBook()
    book.add(pk(1.0, PEER, 51000, LAN, 8765, SYN))
    book.add(pk(1.0, PEER6, 51000, LAN6, 443, SYN))
    book.add(pk(1.2, LAN, 53000, ROUTER, 53, proto="udp", payload=b"\x00" * 30))
    snap = book.snapshot(now=9.0)

    def plain(value) -> bool:
        if isinstance(value, dict):
            return all(type(k) is str and plain(v) for k, v in value.items())
        if isinstance(value, list):
            return all(plain(v) for v in value)
        return value is None or type(value) in (str, int, float, bool)
    assert plain(snap) and json.loads(json.dumps(snap)) == snap
    assert snap is not book.snapshot(now=9.0) and snap["ports"][0] is not book.snapshot(now=9.0)["ports"][0]


def test_settling_judges_what_is_old_enough_and_leaves_the_rest_unjudged():
    book = TrafficBook(clock=lambda: 10.0)
    book.add(pk(5.0, PEER, 40001, LAN, 22, SYN))
    book.add(pk(9.0, PEER2, 40002, LAN, 22, SYN))  # the first judged by now: 4 s with no answer
    book.settle()  # watching paused at 10.0: the second is 1 s old, too young to judge
    snap = book.snapshot(now=60.0)
    assert (rows(snap, "ports")[("tcp", 22)]["unanswered"], snap["unjudged"], snap["pending"]) == (1, 1, 0)
    book.reset()
    assert book.snapshot(now=61.0)["totals"]["packets"] == 0 and book.snapshot(now=61.0)["since"] is None


def test_a_book_counts_on_one_thread_while_another_reads_it():
    book = TrafficBook()

    def add():
        for i in range(3000):
            book.add(pk(i / 1000, f"81.2.{i % 200}.7", 40000 + i % 5000, LAN, 8765, SYN if i % 3 == 0 else ACK))
    t = threading.Thread(target=add)
    t.start()
    while t.is_alive():
        json.dumps(book.snapshot(now=0.0))
    t.join()
    assert book.snapshot(now=100.0)["totals"]["packets"] == 3000


# -- a Watcher over a stand-in capture -----------------------------------------------------------------------------------
class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class Feed:
    """A capture as a stand-in, pulled as a Watcher pulls one: opened, the packets given, then nothing yet at once (the
    Watcher paces a source that does not wait), closed; a fault when asked."""

    def __init__(self, packets=(), fail_open=None, fail_next=None):
        self.packets, self.fail_open, self.fail_next = deque(packets), fail_open, fail_next
        self.opened = self.closed = 0

    def open(self):
        if self.fail_open:
            raise CaptureError(self.fail_open)
        self.opened += 1

    def next(self):
        if self.packets:
            return self.packets.popleft()
        if self.fail_next:
            raise CaptureError(self.fail_next)
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


def watching() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "traffic-watcher"]


def test_a_watcher_starts_on_a_touch_and_stops_itself_once_no_touch_came_for_its_timeout():
    clock, feeds, seen = Clock(), [], []

    def factory():
        feeds.append(Feed([pk(1.0, PEER, 51000, LAN, 8765, SYN), pk(1.1, LAN, 8765, PEER, 51000, SYN | ACK)]))
        return feeds[-1]
    w = Watcher(factory, timeout=20.0, observers=[seen.append], clock=clock)
    assert not w.running and watching() == [] and feeds == []  # nothing runs before it is asked
    assert w.touch() is False and w.running  # started now
    assert wait_for(lambda: len(seen) == 2) and feeds[0].opened == 1
    [thread] = watching()
    assert thread.daemon and w.book.snapshot(now=2.0)["totals"]["new_in"] == 1 and w.status()["packets"] == 2
    clock.t += 15
    assert w.touch() is True  # kept going
    clock.t += 15
    time.sleep(0.15)
    assert w.running  # 15 s since the last touch: still watching
    clock.t += 6  # 21 s since it
    assert wait_for(lambda: not w.running) and wait_for(lambda: watching() == [])
    status = w.status()
    assert feeds[0].closed == 1 and status["stopped"] is not None and status["error"] == "" and not status["running"]

    # asked again: it starts anew, on a capture of its own, the same book counting on
    assert w.touch() is False and len(feeds) == 2 and feeds[1].opened == 1
    assert wait_for(lambda: len(seen) == 4) and len(watching()) == 1
    w.stop()
    assert not w.running and watching() == [] and feeds[1].closed == 1
    assert w.book.snapshot(now=5.0)["totals"]["packets"] == 4
    w.stop()  # again: nothing more to stop


def test_a_watcher_that_cannot_start_says_why_and_leaves_nothing_running():
    w = Watcher(lambda: Feed(fail_open="Npcap is not installed (npcap.com; Wireshark installs it)"), clock=Clock())
    with pytest.raises(CaptureError, match="Npcap is not installed"):
        w.touch()
    assert not w.running and w.error.startswith("Npcap is not installed") and watching() == []

    def factory():
        raise ValueError("no address to watch")
    w2 = Watcher(factory, clock=Clock())
    with pytest.raises(ValueError):
        w2.touch()
    assert w2.error == "no address to watch" and watching() == []


def test_a_watcher_ends_when_its_capture_fails_and_settles_its_book():
    feed = Feed([pk(1.0, PEER, 40001, LAN, 22, SYN)], fail_next="reading stopped: the adapter went away")
    w = Watcher(lambda: feed, book=TrafficBook(clock=lambda: 2.0), clock=Clock())
    w.touch()
    assert wait_for(lambda: not w.running) and wait_for(lambda: watching() == [])
    assert w.error == "reading stopped: the adapter went away" and feed.closed == 1
    snap = w.book.snapshot(now=10.0)  # the attempt was 1 s old when watching ended: no answer could be seen after
    assert (snap["unjudged"], rows(snap, "ports")[("tcp", 22)]["unanswered"]) == (1, 0)


def test_a_packet_an_observer_fails_on_is_counted_and_watching_goes_on():
    def picky(packet):
        if packet.dport == 9:
            raise ValueError("not this one")
    names = NameBook()
    w = Watcher(lambda: Feed([pk(1.0, PEER, 1, LAN, 9, SYN), pk(1.1, PEER, 1, LAN, 10, SYN)]),
                observers=[picky, names.observe], clock=Clock())
    w.touch()
    assert wait_for(lambda: w.status()["packets"] == 2)
    status = w.status()
    assert status["faults"] == 1 and status["fault"] == "ValueError: not this one" and status["running"]
    assert w.book.snapshot(now=2.0)["totals"]["packets"] == 2
    w.stop()
    assert watching() == []


class Frames:
    """libpcap as a stand-in under a real Capture: frames handed as an opened adapter hands them."""

    link = capture.LINK_ETHERNET

    def __init__(self, frames):
        self.frames, self.local, self.closed = list(frames), frozenset(), 0

    def open(self, address, ports):
        self.local = capture.own_addresses([address])

    def next(self):
        if self.frames:
            return self.frames.pop(0)
        time.sleep(0.001)  # a read's wait
        return None

    def close(self):
        self.closed += 1


def frame(src, dst, proto, sport, dport, body=b"", flags=SYN) -> bytes:
    l4 = (struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 64240, 0, 0) if proto == 6
          else struct.pack("!HHHH", sport, dport, 8 + len(body), 0)) + body
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip + l4


def test_a_watcher_reads_a_capture_on_its_own_one_thread_and_hands_the_names_on():
    question = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07tracker\x07example\x00" + struct.pack("!HH", 1, 1)
    answer = (struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + b"\x07tracker\x07example\x00" + struct.pack("!HH", 1, 1)
              + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(PEER2))
    frames = [(0.9, frame(LAN, ROUTER, 17, 53000, 53, question), 75),  # this machine's question, then its answer
              (1.0, frame(ROUTER, LAN, 17, 53, 53000, answer), 110), (1.1, frame(LAN, PEER2, 6, 52000, 443), 74)]
    source, names, before = Frames(frames), NameBook(), set(threading.enumerate())
    w = Watcher(lambda: Capture(LAN, source=source, udp=True, payloads=True, host=False), observers=[names.observe],
                clock=Clock())
    w.touch()
    assert wait_for(lambda: w.status()["packets"] == 3) and names.name_of(PEER2) == "tracker.example"
    assert [t for t in threading.enumerate() if t not in before] == watching()  # the capture starts none of its own
    w.stop()
    assert source.closed == 1 and watching() == []
    snap = w.book.snapshot(now=5.0)
    there = rows(snap, "remote_ports")
    assert there[("tcp", 443)]["new_out"] == 1 and there[("udp", 53)]["in_bytes"] == 110


# -- a Watcher over a quiet Linux adapter (review F2), over a stream of frames passed over (review F3) ---------------------
def test_a_watcher_on_a_quiet_linux_adapter_ends_on_its_timeout_and_on_stop(monkeypatch):
    """(Review F2) On Linux libpcap's read returned only once a packet passed the filter: on a quiet adapter neither
    the viewing timeout nor stop() was seen, and the thread and the root-opened handle stayed. Its reads now wait the
    capture's own TIMEOUT_MS at most, so both are seen within it."""
    from test_capture_world import ADAPTERS, Lib
    monkeypatch.setattr(capture, "sys", types.SimpleNamespace(platform="linux"))
    lib, clock = Lib(ADAPTERS, block=5.0), Clock()
    w = Watcher(lambda: Capture(LAN, source=capture.PcapSource(lib, expression="(tcp or udp)"), udp=True, host=False),
                clock=clock)
    w.touch()
    assert wait_for(lambda: lib.reads > 0) and w.running
    clock.t += 21  # nobody has looked for longer than its timeout
    assert wait_for(lambda: not w.running, 1.5) and wait_for(lambda: watching() == [], 1.5)
    assert lib.closed == [0x5EED] and lib.blocked == 0 and w.status()["error"] == ""
    w.touch()  # looked at again, then left: the plugin's detach
    reads = lib.reads
    assert wait_for(lambda: lib.reads > reads)
    began = time.monotonic()
    w.stop(wait=2.0)
    assert watching() == [] and time.monotonic() - began < 1.0 and lib.closed == [0x5EED, 0x5EED]


def later_fragment(src: str, dst: str) -> bytes:
    """An IPv4 fragment after the first (a UDP datagram's): "(tcp or udp)" lets it through; it has no ports."""
    data = bytearray(frame(src, dst, 17, 1, 2, b"\x00" * 40))
    data[20:22] = struct.pack("!H", 185)  # its offset, past the first
    return bytes(data)


def test_a_stream_of_frames_passed_over_does_not_slow_a_watcher():
    """(Review F3) A pull gave up after 64 frames passed over and the Watcher, taking that for a source that does not
    wait, slept 50 ms: 100 later fragments for each real packet held it to about 1,600 frames a second, and the kernel's
    buffer dropped the rest (the inbound SYNs among them). Now the frames are passed over while they come."""
    frames = []
    for i in range(20):
        frames += [(1.0 + i, later_fragment(PEER, LAN), 82)] * 200
        frames.append((1.0 + i, frame(PEER, LAN, 6, 40000 + i, 8765), 74))
    source = Frames(frames)
    w = Watcher(lambda: Capture(LAN, source=source, udp=True, host=False), clock=Clock())
    began = time.monotonic()
    w.touch()
    assert wait_for(lambda: w.status()["packets"] == 20, 2.0) and time.monotonic() - began < 1.0
    w.stop()
    assert rows(w.book.snapshot(now=100.0), "ports")[("tcp", 8765)]["unanswered"] == 20 and source.frames == []


# -- attempts no answer can be matched to, broadcast addresses (review, minor) ------------------------------------------
def test_attempts_no_answer_can_be_matched_to_are_counted_on_their_port_and_group():
    """(Review, minor) During a scan, attempts pushed out of the flows followed were only a number in all."""
    crowded = TrafficBook(max_flows=3)
    for i in range(10):  # a scan: more attempts at once than flows are followed
        crowded.add(pk(i / 100, f"81.2.{i}.7", 40000 + i, LAN, 22, SYN))
    snap = crowded.snapshot(now=10.0)
    ssh = rows(snap, "ports")[("tcp", 22)]
    assert (ssh["unanswered"], ssh["unjudged"]) == (3, 7) and snap["unjudged"] == snap["totals"]["unjudged"] == 7
    assert sorted(g["unjudged"] for g in snap["groups"]) == [0] * 3 + [1] * 7
    paused = TrafficBook(clock=lambda: 10.0)
    paused.add(pk(9.0, PEER2, 40002, LAN, 3389, SYN))
    paused.settle()  # too young to judge when watching paused
    snap = paused.snapshot(now=60.0)
    assert rows(snap, "ports")[("tcp", 3389)]["unjudged"] == 1 and snap["groups"][0]["unjudged"] == 1


class Heard(Frames):
    """A capture's source whose adapter has a /25: its broadcast address does not end in .255."""

    broadcast = frozenset({"192.168.1.127"})


def test_datagrams_to_an_adapters_own_broadcast_address_ask_no_one():
    """(Review, minor) Only an address ending in .255 was taken for a broadcast; the adapters' own (libpcap lists
    them) are now handed from the capture to the book."""
    guessed, told = TrafficBook(), TrafficBook(broadcast={"192.168.1.127"})
    for book in (guessed, told):
        book.add(pk(0.0, "192.168.1.5", 137, "192.168.1.127", 137, proto="udp"))
    assert rows(guessed.snapshot(now=9.0), "ports")[("udp", 137)]["unanswered_udp"] == 1  # taken for one asked of it
    assert rows(told.snapshot(now=9.0), "ports")[("udp", 137)]["unanswered_udp"] == 0
    source = Heard([(1.0, frame("192.168.1.5", "192.168.1.127", 17, 137, 137, b"\x00" * 50), 92)])
    w = Watcher(lambda: Capture(LAN, source=source, udp=True, host=False), book=TrafficBook(broadcast={"10.0.0.255"}),
                clock=Clock())
    w.touch()
    assert wait_for(lambda: w.status()["packets"] == 1)
    w.stop()
    assert w.book.broadcast == {"192.168.1.127", "10.0.0.255"}  # the capture's, and the book's own
    snap = w.book.snapshot(now=10.0)
    assert rows(snap, "ports")[("udp", 137)]["unanswered_udp"] == 0 and snap["totals"]["unanswered_udp"] == 0
