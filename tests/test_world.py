"""The firewalls' World Wide Web tab (liminal_libs.machines.world, and the Firewall base's world, world_geoip and detach;
the user, 2026-11-14: "so for the firewall's both are going to get a 'world wide web view' that shows the globe and the
routes incoming all traffic, as well as monitoring port traffic stats"). The tab's page from the traffic counted: each
public network a place on the globe with its kind, count, bytes and ports, placed by the GeoIP file; the local network's
peers summed apart, never placed; the busiest ports here charted from the second sample, their lines broken across a
pause; the ports and the places tabled; at most 300 places drawn, the rest summed as "more". Watching starts with an ask
and stops by itself after the viewing timeout (a clock of the test's own), and on detach. Home is the place the user set
through the login, else this network's public address placed by the GeoIP file, else none. A capture that cannot run
says why and how, never asking for a password. The GeoIP file is installed only once its licence is accepted, through a
refusal the platform asks as a second confirmation, falling back to last month's file on a 404.

Nothing is captured, nothing is downloaded and no name server is asked: the capture, the fetch and the lookup are
stand-ins, the GeoIP files are tiny ones written here (test_geo's writer), and the real ones fail the test if reached."""
from __future__ import annotations

import email.message
import gzip
import http.client
import io
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import urllib.response
from collections import deque
from datetime import datetime, timezone

import pytest

from liminal_libs import capture, dns, geo, netpath
from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.apps.tabs import Tab
from liminal_libs.capture import ACK, PSH, SYN, CaptureError, Packet
from liminal_libs.machines import world
from liminal_libs.machines.firewall import Firewall
from liminal_libs.machines.netstat import NetstatView
from liminal_libs.machines.world import (ACCEPT_LICENCE, MAX_DRAWN, RETRY_S, SETTING_S, LicenceRefused, RedirectRefused,
                                         WorldView, capture_help, home_place, servers_of)
from liminal_libs.sources.conformance import problems
from liminal_libs.traffic import TrafficBook

from test_firewall import FakeFirewall
from test_geo import NOVEMBER, OCTOBER, city, mmdb, needs_reader

FETCH_URL = world.fetch_url  # the real one, run over stand-in protocols only (each test's fixture refuses it otherwise)
# the real ones, for the tests of their own: each test's fixture says "not inside WSL" and "no init known" otherwise, so the
# suite reads alike inside a WSL distribution, on a Linux of any init and on Windows
UNDER_WSL, INIT = world.under_wsl, world._init

LAN, LAN6, ROUTER = "192.168.1.20", "2001:db8:1::20", "192.168.1.1"
LONDON, LONDON2 = "81.2.69.142", "81.2.69.160"  # one /24
CHANGCHUN, NUREMBERG6, AUSSIE, NOWHERE = "175.16.199.5", "2a01:4f8:c17:1::5", "1.2.3.4", "5.6.7.8"
PUBLIC = "8.8.8.8"  # this network's public address, as the stand-in name server says it
OWN = capture.own_addresses([LAN, LAN6])
URL = "https://geoip.example/dbip-city-lite-{year}-{month}.mmdb.gz"
LICENCE = ("The IP to City Lite database is licensed under the Creative Commons Attribution 4.0 International License: "
           "credit its maker wherever its data is shown.")
MARK = {"text": "IP Geolocation by DB-IP", "url": "https://db-ip.com"}
SERVERS = (("myip.example", "a", "203.0.113.53", "Example DNS"), ("myip.example", "aaaa", "2001:db8::53", "Example DNS"))
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc).timestamp()
PLACES = [("81.2.69.0/24", city("GB", "United Kingdom", "London", 51.5142, -0.0931)),
          ("175.16.199.0/24", city("CN", "China", "Changchun", 43.88, 125.3228)),
          ("2a01:4f8::/32", city("DE", "Germany", "Nuremberg", 49.4478, 11.0683)),
          ("8.8.8.0/24", city("US", "United States", "Mountain View", 37.386, -122.0838)),
          ("1.2.3.0/24", {"country": {"iso_code": "AU", "names": {"en": "Australia"}}})]  # its country, not where in it


def pk(at, src, sport, dst, dport, flags=0, proto="tcp", length=60) -> Packet:
    """A packet as a capture hands it, its direction judged against this machine's addresses."""
    return Packet(at, src, sport, dst, dport, flags, 0, proto, length, capture.judge(src, dst, OWN))


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class Feed:
    """A capture as a stand-in, pulled as a Watcher pulls one: opened, its packets handed, then nothing yet; closed."""

    def __init__(self, packets=(), address=LAN, fail_open=None):
        self.packets, self.address, self.fail_open = deque(packets), address, fail_open
        self.opened = self.closed = 0

    def open(self):
        if self.fail_open:
            raise CaptureError(self.fail_open)
        self.opened += 1

    def next(self):
        return self.packets.popleft() if self.packets else None

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


def downloading() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.endswith("-geoip-download")]


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch, tmp_path):
    """Nothing real is reached: no libpcap loaded, no route asked, no name server, no download, not this machine's data
    folder (each reach is noted, so one inside a thread is seen too). Each WorldView a test makes is stopped after it,
    and no watching thread is left. The socket table, the hosts database and the layers' folder are the suite's own
    guard's (tests/conftest.py, no_real_hosts: the real reader refused, the two in tmp_path)."""
    reached: list[str] = []

    def refusing(name):
        def refuse(*args, **kwargs):
            reached.append(name)
            raise AssertionError(f"a test reached the real {name}")
        return refuse
    for module, name in ((capture, "load_pcap"), (netpath, "lan_address"), (world, "route_address"), (dns, "query"),
                         (world, "fetch_url"), (urllib.request, "urlopen")):
        monkeypatch.setattr(module, name, refusing(name))
    monkeypatch.setattr(geo, "data_folder", lambda: tmp_path / "data" / "geoip")
    monkeypatch.setattr(world, "under_wsl", lambda *args, **kwargs: None)  # not this machine's WSL, if it is one
    monkeypatch.setattr(world, "_init", lambda: "")  # nor its init: both ways to the right to capture told
    made: list[WorldView] = []
    init = WorldView.__init__

    def tracked(self, *args, **kwargs):
        init(self, *args, **kwargs)
        made.append(self)
    monkeypatch.setattr(WorldView, "__init__", tracked)
    yield made
    for view in made:
        view.stop()
    assert wait_for(lambda: watching() == []), "a watching thread was left"
    assert wait_for(lambda: not [t for t in threading.enumerate() if t.name.endswith("-public-address")])
    assert wait_for(lambda: downloading() == []), "a download's thread was left"
    assert reached == []


@pytest.fixture
def geo_folder(tmp_path):
    folder = tmp_path / "geoip"
    folder.mkdir()
    (folder / "dbip-city-lite-2026-11.mmdb").write_bytes(mmdb(PLACES, built=NOVEMBER))
    return folder


def traffic_of(book: TrafficBook) -> None:
    """A few minutes of a machine's traffic, one of each thing the page shows."""
    for p in (
        # London: a connection to this machine's 8765, answered, with data
        pk(10.0, LONDON, 51000, LAN, 8765, SYN, length=74), pk(10.1, LAN, 8765, LONDON, 51000, SYN | ACK, length=74),
        pk(10.2, LONDON, 51000, LAN, 8765, PSH | ACK, length=566), pk(10.3, LAN, 8765, LONDON, 51000, PSH | ACK, length=1466),
        # Changchun: two attempts at 3389, never answered
        pk(11.0, CHANGCHUN, 40001, LAN, 3389, SYN), pk(11.5, CHANGCHUN, 40002, LAN, 3389, SYN),
        # Nuremberg, over IPv6: this machine to its 443
        pk(12.0, LAN6, 52000, NUREMBERG6, 443, SYN, length=94), pk(12.05, NUREMBERG6, 443, LAN6, 52000, SYN | ACK, length=94),
        pk(12.1, LAN6, 52000, NUREMBERG6, 443, PSH | ACK, length=600),
        pk(12.2, NUREMBERG6, 443, LAN6, 52000, PSH | ACK, length=1400),
        # a public address the file has no place for: this machine to its 443
        pk(13.0, LAN, 52001, NOWHERE, 443, SYN),
        # a network the file knows only the country of: a connection to this machine's 22, answered
        pk(14.0, AUSSIE, 41000, LAN, 22, SYN), pk(14.1, LAN, 22, AUSSIE, 41000, SYN | ACK),
        # the local network: a question to the router and its answer, and mDNS to its multicast group
        pk(15.0, LAN, 53000, ROUTER, 53, proto="udp", length=80), pk(15.05, ROUTER, 53, LAN, 53000, proto="udp", length=120),
        pk(16.0, LAN, 5353, "224.0.0.251", 5353, proto="udp", length=100),
    ):
        book.add(p)


def socket_table(*rows, at: float = NOW) -> dict:
    """This machine's socket table as sockets.read answers it, of the rows given (none by default): a stand-in, so the
    tab's every ask, which also reads the socket table for the hosts database (1.65.0), reads nothing real."""
    return {"system": "windows", "at": at, "awake": 100.0, "took": 0.004, "root": False, "starts": True,
            "read": ("tcp4", "tcp6", "udp4", "udp6"), "cut": False, "rows": list(rows), "notes": []}


class Walled(FakeFirewall):
    """A stand-in firewall naming its GeoIP download, its places' attribution and its name servers, its WorldView
    watching through the test's stand-ins, and its NetstatView reading a stand-in socket table (1.65.0: the tab's ask
    reads it for the hosts database; the suite's guard refuses the real one, and keeps the database in tmp_path)."""

    name = "walled-firewall"
    GEOIP_URL, GEOIP_LICENCE, ATTRIBUTION, PUBLIC_DNS = URL, LICENCE, MARK, SERVERS

    def __init__(self, **view):
        super().__init__()
        view.setdefault("resolve", lambda version, servers: (None, "no name server answers in a test"))
        self.view, self.made, self.readings = view, 0, 0

    def make_world_view(self) -> WorldView:
        self.made += 1
        return WorldView(self.name, **self.view)

    def make_netstat_view(self) -> NetstatView:
        def reader() -> dict:
            self.readings += 1
            return socket_table()
        return NetstatView(self.name, reader=reader, names={}, login_of=lambda: getattr(self, "login", None),
                           clock=self.view.get("clock", time.monotonic), wall=self.view.get("wall", time.time))


# -- the tab as the Firewall base declares it ----------------------------------------------------------------------------
def test_every_firewall_has_the_world_wide_web_tab_its_hooks_and_its_setting():
    fw = FakeFirewall()
    # 1.65.0: the Netstat tab after it, asked every three seconds while it is shown
    assert Firewall.TABS == (Tab("world", "World Wide Web", "world", 2.0), Tab("netstat", "Netstat", "netstat", 3.0))
    assert fw.TABS == Firewall.TABS
    hooks = fw.interface()["hooks"]
    # asked by name (Plugin.ask): the tab's hook with no arguments, the install with the one its form sets, and the log
    # the platform hands a job (the install runs as one: JOB_HOOKS, its progress in the plugin's panel)
    assert hooks["world"].startswith("() ") and hooks["world_geoip"].startswith("(accept_licence=False, log=None) ")
    assert hooks["netstat"].startswith("() ") and hooks["world_layer_get"].startswith(
        "(dataset, accept_licence=False, log=None) ")  # a data set's download: a job too, which the page may cancel
    assert Firewall.JOB_HOOKS == ("world_geoip", "world_layer_get", "world_asn", "world_geoip_get")  # 1.102.0
    assert fw.JOB_HOOKS == Firewall.JOB_HOOKS
    assert hooks["world_asn"].startswith("(accept_licence=False, log=None) ")  # 1.75.0: the ASN file's, a job too
    assert (Firewall.GEOIP_ASN_URL, Firewall.GEOIP_ASN_LICENCE) == ("", "")  # none unless the plugin names one
    assert Firewall.CANCEL_HOOKS == ("world_layer_get", "world_geoip_get") and Firewall.INFRASTRUCTURE == ()
    assert Firewall.PAGE_ONLY_HOOKS == ("world_geoip_get", "world_geoip_use", "world_geoip_remove",  # 1.102.0
                                        "world_geoip", "world_asn", "world_layer_get")  # the user's 11b
    assert Firewall.GEOIP_SOURCES == ()
    assert {"allow", "remove", "move_rules"} <= set(hooks)  # what was there stays
    assert (Firewall.GEOIP_URL, Firewall.GEOIP_LICENCE, Firewall.ATTRIBUTION, Firewall.PUBLIC_DNS) == ("", "", {}, ())
    # the home on the globe, when the hosts are recorded and (1.74.0) when the traffic is watched, set on the plugin's
    # page and kept through the login
    [home, recording, watching] = fw.keys
    assert (home.name, home.secret, home.pair) == ("LIMINAL_HOME_PLACE", False, "liminal-home-place")
    assert (recording.name, recording.secret, recording.pair) == ("LIMINAL_HOSTS_RECORDING", False,
                                                                  "liminal-hosts-recording")
    assert (watching.name, watching.secret, watching.pair) == ("LIMINAL_TRAFFIC_WATCHING", False,
                                                            "liminal-traffic-watching")
    assert all(k.hint.startswith("optional") for k in (home, recording, watching))
    assert problems(fw) == [] and problems(Walled()) == []
    assert ACCEPT_LICENCE.isidentifier() and LicenceRefused.accept == ACCEPT_LICENCE and issubclass(LicenceRefused, ValueError)


# -- the page ---------------------------------------------------------------------------------------------------------------
@needs_reader
def test_the_page_places_each_network_by_its_kind_and_sums_the_local_network_apart(geo_folder):
    book = TrafficBook(clock=lambda: 50.0)
    view = WorldView("walled-firewall", capture_factory=Feed, geo_folder=geo_folder, clock=Clock(), wall=Clock(NOW), book=book)
    traffic_of(book)
    page = view.page(attribution=MARK, licence=LICENCE, source=URL)
    assert json.loads(json.dumps(page, allow_nan=False)) == page  # plain data, as the platform sends it
    assert page["title"] == "World Wide Web" and "no address is sent anywhere" in page["note"]
    g = page["globe"]
    assert g["home"] is None and "This machine is not placed" in g["note"]  # no place set, no name server named
    assert g["attribution"] == MARK and g["updated"] == "2026-11-15T12:00:00+00:00"
    by = {o["id"]: o for o in g["origins"]}
    assert list(by) == ["175.16.199.0/24", "2a01:4f8:c17::/48", "81.2.69.0/24", "1.2.3.0/24", "5.6.7.0/24"]  # most first
    london = by["81.2.69.0/24"]
    assert (london["kind"], london["count"], london["bytes"], london["ports"]) == ("allowed", 1, 2180, [8765])
    assert (london["lat"], london["lon"], london["label"], london["country"], london["code"], london["city"]) == (
        51.5142, -0.0931, "London, United Kingdom", "United Kingdom", "GB", "London")
    assert (by["175.16.199.0/24"]["kind"], by["175.16.199.0/24"]["count"], by["175.16.199.0/24"]["ports"]) == (
        "unanswered", 2, [3389])  # two attempts nobody answered within 3 s
    assert (by["2a01:4f8:c17::/48"]["kind"], by["2a01:4f8:c17::/48"]["city"], by["2a01:4f8:c17::/48"]["family"]) == (
        "outbound", "Nuremberg", 6)
    assert (by["1.2.3.0/24"]["country"], by["1.2.3.0/24"]["lat"], by["1.2.3.0/24"]["kind"]) == ("Australia", None, "allowed")
    assert (by["5.6.7.0/24"]["lat"], by["5.6.7.0/24"]["label"], by["5.6.7.0/24"]["kind"]) == (None, "", "outbound")
    # the router and the multicast group: the local network's, never placed, never looked up
    assert g["local"] == {"count": 2, "bytes": 300, "places": 2, "packets": 0}
    assert g["more"] == {"places": 0, "count": 0, "bytes": 0}
    here, places, there = page["tables"]
    assert (here["title"], places["title"], there["title"]) == ("Busiest ports here", "Places", "Ports elsewhere")
    assert [c["title"] for c in here["columns"]] == ["Port", "In", "Out", "Packets", "New connections", "Unanswered"]
    assert here["rows"] == [["8765/tcp", "640 B", "1.5 KB", "4", "1", "0"], ["22/tcp", "60 B", "60 B", "2", "1", "0"],
                            ["3389/tcp", "120 B", "0 B", "2", "0", "2"]]
    assert [c["title"] for c in places["columns"]] == ["Country", "City", "Network", "Count", "Bytes", "Kind"]
    assert places["rows"][0] == ["China", "Changchun", {"text": "175.16.199.0/24"}, "2", "120 B", "unanswered in"]
    assert places["rows"][2] == ["United Kingdom", "London", {"text": "81.2.69.0/24"}, "1", "2.1 KB", "allowed in"]
    assert places["rows"][-1] == ["–", "–", {"text": "the local network", "sub": "never placed"}, "2", "300 B", "local"]
    assert "IP Geolocation by DB-IP, https://db-ip.com" in places["note"]  # wherever places are
    assert [r[0] for r in there["rows"]] == ["443/tcp", "53/udp", "5353/udp"]
    assert "charts" not in page  # they begin with the second sample
    assert "forms" not in page and "actions" not in page  # this month's GeoIP file is installed
    assert page["watching"]["running"] is False and page["watching"]["since"] == "1970-01-01T00:00:10+00:00"


def test_without_a_geoip_file_nothing_is_placed_and_its_install_is_offered(tmp_path):
    view = WorldView("walled-firewall", capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW),
                     book=TrafficBook(clock=lambda: 50.0))
    traffic_of(view.book)
    page = view.page(attribution=MARK, licence=LICENCE, source=URL)
    g = page["globe"]
    assert all(o["lat"] is None and o["label"] == "" for o in g["origins"]) and len(g["origins"]) == 5
    assert g["attribution"] is None and "No GeoIP file is installed" in g["note"]  # no place drawn: nothing to credit
    [form] = page["forms"]
    assert (form["id"], form["hook"], form["title"]) == ("world-geoip", "world_geoip", "Install the GeoIP file")
    assert form["fields"] == [{"name": "accept_licence", "type": "accept", "title": "Accept the GeoIP file's licence?",
                               "words": LICENCE, "yes": "Accept it and download"}]
    words = form["confirm"]["words"]
    assert "geoip.example" in words and str(tmp_path / "geoip") in words and "about 60 MB" in words
    assert words.index(LICENCE) < words.index("You are asked to accept it next")  # the licence first, then the download
    assert page["actions"] == [{"form": "world-geoip", "title": "Install the GeoIP file…",
                                "note": "Downloads it once you accept its licence"}]
    assert "forms" not in view.page(can_install=False)  # a plugin naming no download offers none
    assert "This plugin offers no GeoIP file to download" in view.page(can_install=False)["globe"]["note"]


@needs_reader
def test_a_file_built_before_this_month_is_offered_for_an_update(tmp_path):
    folder = tmp_path / "geoip"
    folder.mkdir()
    (folder / "dbip-city-lite-2026-10.mmdb").write_bytes(mmdb(PLACES, built=OCTOBER))
    view = WorldView("w", capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW))
    page = view.page(licence=LICENCE, source=URL)
    assert page["forms"][0]["title"] == "Update the GeoIP file" and page["actions"][0]["title"] == "Update the GeoIP file…"


def test_at_most_300_places_are_drawn_and_the_rest_summed_as_more(tmp_path):
    book = TrafficBook(clock=lambda: 9999.0)
    for i in range(400):  # 400 networks; the first 100 tried twice
        peer = f"81.{i // 250}.{i % 250}.7"
        book.add(pk(float(i), peer, 40000, LAN, 22, SYN))
        if i < 100:
            book.add(pk(i + 0.5, peer, 40001, LAN, 22, SYN))
    view = WorldView("w", capture_factory=Feed, geo_folder=tmp_path, clock=Clock(), wall=Clock(NOW), book=book)
    g = view.page()["globe"]
    assert len(g["origins"]) == MAX_DRAWN == 300 and all(o["kind"] == "unanswered" for o in g["origins"])
    assert [o["count"] for o in g["origins"][:100]] == [2] * 100  # the most connections drawn first
    assert g["more"] == {"places": 100, "count": 100, "bytes": 6000}
    assert "100 more places not drawn (100 connections, 5.9 KB): the 300 with the most connections are" in g["note"]
    places = view.page()["tables"][1]
    assert len(places["rows"]) == 52 and places["rows"][50][2] == {"text": "250 more places", "sub": "drawn on the globe"}
    assert places["rows"][51][2] == {"text": "100 more places", "sub": "not drawn"}


def test_the_busiest_ports_are_tabled_and_the_rest_summed(tmp_path):
    book = TrafficBook(clock=lambda: 9999.0)
    for port in range(1000, 1030):
        book.add(pk(1.0, LONDON, 40000 + port, LAN, port, SYN, length=port))
    view = WorldView("w", capture_factory=Feed, geo_folder=tmp_path, clock=Clock(), wall=Clock(NOW), book=book)
    [here, _, _] = view.page()["tables"]
    rows = here["rows"]
    assert len(rows) == 26 and rows[0][0] == "1029/tcp" and rows[-1] == ["5 more ports", "4.9 KB", "0 B", "5", "0", "5"]


# -- the charts ---------------------------------------------------------------------------------------------------------
class Ticks:
    """The time of day and the view's own clock going on together (as they do, until the wall clock is set)."""

    def __init__(self, wall: Clock, clock: Clock):
        self.wall, self.clock = wall, clock

    def __call__(self, seconds: float) -> None:
        self.wall.t += seconds
        self.clock.t += seconds


def test_the_busiest_ports_here_are_charted_from_the_second_sample_and_break_across_a_pause(tmp_path):
    wall, clock, book = Clock(NOW), Clock(), TrafficBook(clock=lambda: 9999.0)
    later = Ticks(wall, clock)
    view = WorldView("w", capture_factory=Feed, geo_folder=tmp_path, clock=clock, wall=wall, book=book, timeout=20.0)
    flow = 0

    def moved(port: int, inbound: int, outbound: int) -> None:
        nonlocal flow
        flow += 1
        book.add(pk(wall.t, LONDON, 30000 + flow, LAN, port, ACK, length=inbound))
        book.add(pk(wall.t, LAN, port, LONDON, 30000 + flow, ACK, length=outbound))
    moved(8765, 100, 100)
    assert "charts" not in view.page()  # the first ask: where counting starts
    for port in (8765, 22, 3389, 80, 25, 53):
        moved(port, 1000 * port % 7919 + 10, 10)
    later(2.0)
    assert "charts" not in view.page()  # one sample
    moved(8765, 4000, 2000)
    later(0.2)
    assert "charts" not in view.page()  # asked again at once: the same sample
    later(1.8)
    [spec] = view.page()["charts"]
    assert spec["span"] == "recent" and spec["t"] == [NOW + 2.0, NOW + 4.0]
    keys = [c["key"] for c in spec["charts"]]
    assert len(keys) == 4 and keys[0] == "world-tcp-8765" and all(k.startswith("world-") for k in keys)  # the tab's own ids
    web = spec["charts"][0]
    assert web["unit"] == "bytes/s" and web["title"] == "Port 8765/tcp here"
    assert web["lines"] == [{"key": "in", "name": "in", "values": [round((1000 * 8765 % 7919 + 10) / 2, 1), 2000.0]},
                            {"key": "out", "name": "out", "values": [5.0, 1000.0]}]
    # nobody asked for a minute: watching stopped meanwhile, so the line breaks there, and goes on after
    moved(8765, 20000, 0)
    later(60.0)
    [spec] = view.page()["charts"]
    assert spec["t"][-2:] == [NOW + 24.0, NOW + 44.0] and spec["charts"][0]["lines"][0]["values"][-2:] == [1000.0, None]
    later(2.0)
    moved(8765, 600, 0)
    [spec] = view.page()["charts"]
    assert spec["charts"][0]["lines"][0]["values"][-1] == 300.0
    # over ten minutes on: what is older than that is let go, the break with it, and the charts begin again
    later(700.0)
    moved(8765, 700, 0)
    assert "charts" not in view.page() and list(view._samples) == []
    later(2.0)
    moved(8765, 800, 0)
    assert "charts" not in view.page()
    later(2.0)
    [spec] = view.page()["charts"]
    assert spec["t"] == [NOW + 768.0, NOW + 770.0] and [c["key"] for c in spec["charts"]] == ["world-tcp-8765"]
    assert spec["charts"][0]["lines"][0]["values"] == [400.0, 0.0]


# -- watching: while the tab is asked, and no longer --------------------------------------------------------------------
def test_an_ask_starts_the_watching_which_stops_by_itself_after_its_timeout(tmp_path):
    clock, feeds = Clock(), []

    def factory():
        feeds.append(Feed([pk(1.0, LONDON, 51000, LAN, 8765, SYN), pk(1.1, LAN, 8765, LONDON, 51000, SYN | ACK)]))
        return feeds[-1]
    fw = Walled(capture_factory=factory, geo_folder=tmp_path, clock=clock, wall=Clock(NOW), timeout=20.0)
    assert feeds == [] and watching() == []  # nothing runs before the tab is asked
    page = fw.ask("world")  # the platform asks it so, every two seconds while the tab is shown
    view = fw.world_view()
    assert view.running and feeds[0].opened == 1 and len(watching()) == 1 and fw.made == 1
    assert "Watching every packet at this machine's network adapter (192.168.1.20)" in page["note"]
    assert wait_for(lambda: view.watcher.status()["packets"] == 2)
    clock.t += 15
    fw.world()  # asked again: kept going, on the same capture and the same view
    assert view.running and len(feeds) == 1 and fw.world_view() is view and fw.made == 1
    clock.t += 15
    time.sleep(0.15)
    assert view.running  # 15 s since the last ask
    clock.t += 6  # 21 s: nobody looked for longer than the timeout
    assert wait_for(lambda: not view.running) and wait_for(lambda: watching() == []) and feeds[0].closed == 1
    page = view.page()
    assert page["watching"]["running"] is False and page["watching"]["packets"] == 2
    assert page["globe"]["origins"][0]["id"] == "81.2.69.0/24"  # what was counted stays
    fw.world()  # looked at again: a capture of its own, the same book counting on
    assert view.running and len(feeds) == 2 and feeds[1].opened == 1
    fw.detach()
    assert not view.running and feeds[1].closed == 1 and watching() == []


def test_detach_ends_the_watching_lets_the_geoip_file_go_and_forgets_it(geo_folder):
    feed = Feed()
    fw = Walled(capture_factory=lambda: feed, geo_folder=geo_folder, clock=Clock(), wall=Clock(NOW))
    fw.attach(object(), EnvironmentLogin(env={}))
    fw.world()
    view = fw.world_view()
    geoip = view.geoip()
    assert view.running and (geoip is None or geoip.describe()["open"])
    fw.detach()
    assert not view.running and feed.closed == 1 and watching() == [] and "_world" not in fw.__dict__
    assert geoip is None or geoip.describe()["open"] is False  # the file let go: nothing kept open while unused
    assert fw.app is None and fw.login is None  # and detached as every plugin is
    fw.detach()  # again: nothing to stop
    # an ask still under way as it was detached, on the view it held: nothing starts again, nothing is opened
    assert view.closed and view.touch() is False and not view.running and feed.opened == 1
    assert view.page() == {"title": "World Wide Web", "note": "Nothing is watched now: the plugin was detached."}
    assert view.geoip() is None and watching() == []
    fw.world()  # asked again once attached again: a new view of its own
    assert fw.world_view() is not view and fw.world_view().running and fw.made == 2
    fw.detach()


def test_a_capture_that_cannot_run_says_why_and_how_and_is_tried_again_later(tmp_path):
    clock, tries = Clock(), []
    words = "Npcap is not installed (npcap.com; Wireshark installs it): packets cannot be watched"

    def factory():
        tries.append(clock.t)
        return Feed(fail_open=words)
    view = WorldView("w", capture_factory=factory, geo_folder=tmp_path, clock=clock, wall=Clock(NOW))
    assert view.touch() is False and view.error == words and not view.running and watching() == []
    note = view.page()["note"]
    assert note.startswith(f"Traffic cannot be watched here: {words}. {capture_help(words)}")
    assert "password" not in note.lower()
    clock.t += RETRY_S - 1
    assert view.touch() is False and len(tries) == 1  # asked every two seconds: not tried again so soon
    clock.t += 1
    assert view.touch() is False and len(tries) == 2
    # put right: watching starts at the next try
    clock.t += RETRY_S
    view.capture_factory = lambda: Feed()
    assert view.touch() is True and view.error == "" and view.running
    view.stop()
    assert not view.running


def test_how_watching_is_made_possible_is_said_for_each_system():
    npcap = capture_help("Npcap is not installed (npcap.com; Wireshark installs it): packets cannot be watched", windows=True)
    assert "Install Npcap" in npcap and "Administrators only" in npcap
    admins = capture_help("the adapter could not be opened: Error opening adapter: Access is denied.", windows=True)
    assert "administrators only" in admins
    lib = capture_help("libpcap is not installed (libpcap0.8 or libpcap): packets cannot be watched", windows=False)
    assert "libpcap0.8" in lib
    root = capture_help("the adapter could not be opened: socket: Operation not permitted (packets are watched as root, "
                        "or with CAP_NET_RAW)", windows=False, root=False)
    assert "AmbientCapabilities=CAP_NET_RAW" in root and "cap_net_admin" not in root.lower()  # that one right, no more
    off = capture_help("this machine has no network to watch: no default route", windows=True)
    assert off == "Connect this machine to a network, then show this tab again."
    only = capture_help(capture.ADMIN_ONLY, windows=True)  # Npcap for administrators only: never opened from here
    assert "Restrict Npcap driver's access to Administrators only" in only and "run the platform as an administrator" in only
    for words in (npcap, admins, lib, root, off, only, capture_help("something else", windows=False)):
        assert "password" not in words.lower() and "sudo" not in words


def test_the_default_capture_is_every_packet_tcp_and_udp_the_headers_alone(monkeypatch):
    monkeypatch.setattr(world, "route_address", lambda: LAN)
    cap = world.default_capture()  # made, never opened: libpcap is not even loaded
    assert (cap.address, cap.ports, cap.udp, cap.payloads, cap.host) == (LAN, (), True, False, False)
    assert cap.source.expression == "(tcp or udp)" and cap.source.snaplen == capture.SNAPLEN
    monkeypatch.setattr(world, "route_address", lambda: None)
    with pytest.raises(CaptureError, match="no network to watch"):
        world.default_capture()


def test_a_firewall_not_for_this_machine_watches_nothing():
    made = []
    fw = Walled(capture_factory=lambda: made.append(1) or Feed())
    fw.not_for_here = lambda: "for a native Linux machine"
    assert fw.world() == {"title": "World Wide Web", "note": "Not for this machine: for a native Linux machine. "
                                                             "Nothing is watched here."}
    with pytest.raises(ValueError, match="not for this machine"):
        fw.world_geoip(True)
    assert made == [] and fw.made == 0 and "_world" not in fw.__dict__ and watching() == []


# -- home ---------------------------------------------------------------------------------------------------------------
def test_a_home_is_a_place_in_degrees():
    assert home_place("48.86,2.35,Paris") == {"lat": 48.86, "lon": 2.35, "label": "Paris"}
    assert home_place(" -33.87 , 151.21 , Sydney, Australia ") == {"lat": -33.87, "lon": 151.21, "label": "Sydney, Australia"}
    assert home_place("0,0") == {"lat": 0.0, "lon": 0.0, "label": "the place you set"}
    assert home_place({"lat": 1, "lon": 2, "label": "x"}) == {"lat": 1.0, "lon": 2.0, "label": "x"}
    assert home_place((10, -20)) == {"lat": 10.0, "lon": -20.0, "label": "the place you set"}
    assert home_place(None) is None and home_place("  ") is None
    for bad in ("91,0", "0,181", "north,east", "12", "nan,0", "0,inf", (True, 0), [1], {"lat": 1}):
        with pytest.raises(ValueError):
            home_place(bad)


def absolute(entry: tuple) -> tuple:
    """A name server as it is asked: its name absolute (a trailing dot)."""
    return (entry[0] + ".", *entry[1:])


def test_the_servers_asked_for_the_public_address_go_by_their_ip_version():
    # each name made absolute, so nslookup appends none of this machine's DNS search suffixes to it (Windows' does,
    # sending them to the server asked: review, minor)
    assert servers_of(SERVERS, 4) == (absolute(SERVERS[0]),) and servers_of(SERVERS, 6) == (absolute(SERVERS[1]),)
    named = ("myip.example", "txt", "ns1.example", "Example")  # a server named, not numbered: asked for either
    assert servers_of((named, "junk", (1, 2)), 6) == (absolute(named),)
    assert servers_of({4: (SERVERS[0],)}, 4) == (absolute(SERVERS[0]),) and servers_of({4: (SERVERS[0],)}, 6) == ()
    assert servers_of({4: (absolute(SERVERS[0]), "junk")}, 4) == (absolute(SERVERS[0]),)  # absolute already: kept so
    assert servers_of((), 4) == () and servers_of(None, 4) == ()


class Counting(EnvironmentLogin):
    """The user's settings as a login keeps them, counting what is read."""

    def __init__(self, env):
        super().__init__(env=env)
        self.reads = 0

    def vector(self, name):
        self.reads += 1
        return super().vector(name)


@needs_reader
def test_the_place_the_user_set_wins_read_through_the_login_now_and_then(geo_folder):
    clock, asked = Clock(), []
    fw = Walled(capture_factory=Feed, geo_folder=geo_folder, clock=clock, wall=Clock(NOW),
                resolve=lambda version, servers: asked.append(version) or (PUBLIC, "Example DNS"))
    login = Counting({"LIMINAL_HOME_PLACE": "48.86,2.35,Paris"})
    fw.attach(object(), login)
    home = fw.world()["globe"]["home"]
    assert home == {"lat": 48.86, "lon": 2.35, "label": "Paris"} and asked == []  # the user's place: nobody asked
    fw.world()
    clock.t += SETTING_S - 1
    fw.world()
    assert login.reads == 1  # asked every two seconds, the login read every thirty
    login.env["LIMINAL_HOME_PLACE"] = "north,east"
    clock.t += 1
    g = fw.world()["globe"]
    assert login.reads == 2 and "LIMINAL_HOME_PLACE is not a place" in g["note"]  # passed over: the public address then
    login.env["LIMINAL_HOME_PLACE"] = "-33.87,151.21,Sydney"
    fw.settings_changed()  # kept on its page: read anew at once
    assert fw.world()["globe"]["home"]["label"] == "Sydney" and login.reads == 3
    fw.detach()


@needs_reader
def test_without_a_place_set_home_is_where_the_geoip_file_puts_the_public_address(geo_folder):
    asked = []

    def resolve(version, servers):
        asked.append((version, servers))
        return PUBLIC, "Example DNS"
    fw = Walled(capture_factory=Feed, geo_folder=geo_folder, clock=Clock(), wall=Clock(NOW), resolve=resolve)
    first = fw.world()["globe"]
    assert first["home"] is None and "being asked for" in first["note"]  # asked on a thread of its own
    assert wait_for(lambda: fw.world_view()._public["address"] == PUBLIC)
    home = fw.world()["globe"]["home"]
    assert home == {"lat": 37.386, "lon": -122.0838, "label": "Mountain View, United States"}
    fw.world()
    assert asked == [(4, (absolute(SERVERS[0]),))]  # once, for the view's life: its IPv4 server only, found there
    fw.detach()


def test_no_name_server_is_asked_before_a_geoip_file_could_place_the_answer(tmp_path):
    asked = []
    fw = Walled(capture_factory=Feed, geo_folder=tmp_path, clock=Clock(), wall=Clock(NOW),
                resolve=lambda version, servers: asked.append(version) or (PUBLIC, "x"))
    g = fw.world()["globe"]
    assert g["home"] is None and "placed once a GeoIP file is installed" in g["note"]
    time.sleep(0.05)
    assert asked == [] and not [t for t in threading.enumerate() if t.name.endswith("-public-address")]
    fw.detach()


@needs_reader
def test_a_public_address_not_given_is_asked_for_again_only_much_later(geo_folder):
    clock, asked = Clock(), []
    view = WorldView("w", capture_factory=Feed, geo_folder=geo_folder, clock=clock, wall=Clock(NOW),
                     resolve=lambda version, servers: asked.append(version) or (None, "Example DNS did not answer"))
    view.page(public=SERVERS)
    assert wait_for(lambda: asked == [4, 6] and not view._public["running"])
    g = view.page(public=SERVERS)["globe"]
    assert g["home"] is None and "Example DNS did not answer" in g["note"]
    clock.t += world.HOME_RETRY_S - 1
    view.page(public=SERVERS)
    time.sleep(0.05)
    assert asked == [4, 6]
    clock.t += 1
    view.page(public=SERVERS)
    assert wait_for(lambda: asked == [4, 6, 4, 6])


# -- the GeoIP file's install: on the user's word, its licence accepted -----------------------------------------------------
class Downloads:
    """The GeoIP downloads as a stand-in: each address asked for, and what it gives (bytes, or an error raised)."""

    def __init__(self, answers):
        self.answers, self.asked = dict(answers), []

    def __call__(self, url, timeout):
        self.asked.append((url, timeout))
        got = self.answers.get(url, urllib.error.HTTPError(url, 404, "Not Found", {}, None))
        if isinstance(got, BaseException):
            raise got
        return io.BytesIO(got)


@needs_reader
def test_the_geoip_file_is_installed_only_once_its_licence_is_accepted(tmp_path):
    folder = tmp_path / "geoip"
    november = "https://geoip.example/dbip-city-lite-2026-11.mmdb.gz"
    downloads = Downloads({november: gzip.compress(mmdb(PLACES, built=NOVEMBER))})
    fw = Walled(capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW), fetch=downloads)
    page = fw.world()
    form = page["forms"][0]
    assert form["hook"] in fw.interface()["hooks"]  # a hook the platform may ask
    # the platform's page asks it with the form's fields in order: the accept field false until its own confirmation
    with pytest.raises(LicenceRefused) as refused:
        fw.ask(form["hook"], False)
    assert refused.value.accept == "accept_licence" == form["fields"][0]["name"]  # what the second confirmation sets
    assert str(refused.value) == "The GeoIP file is downloaded only once you accept its licence."
    for almost in (None, 1, "true", "yes", [True], {"accept": True}):
        with pytest.raises(LicenceRefused):
            fw.world_geoip(almost)
    assert downloads.asked == [] and not folder.exists()  # nothing downloaded, nothing written
    out = fw.ask(form["hook"], True)  # accepted, in so many words
    assert downloads.asked == [(november, world.READ_S)]
    assert out["ok"] is True and out["said"] == "installed dbip-city-lite-2026-11.mmdb (built 2026-11-01, " \
        f"{world.size_words((folder / 'dbip-city-lite-2026-11.mmdb').stat().st_size)})"
    assert out["lines"][0] == "downloaded from geoip.example" and out["file"]["date"] == "2026-11-01"
    assert [p.name for p in folder.iterdir()] == ["dbip-city-lite-2026-11.mmdb"]
    page = fw.world()  # placed from now on, and nothing more offered
    assert "forms" not in page and page["globe"]["attribution"] == MARK
    again = fw.world_geoip(True)  # this month's is there already: not downloaded again
    assert again["said"].startswith("dbip-city-lite-2026-11.mmdb is installed already") and len(downloads.asked) == 1
    fw.detach()


@needs_reader
def test_last_months_file_is_installed_while_this_months_is_not_out(tmp_path):
    folder = tmp_path / "geoip"
    october = "https://geoip.example/dbip-city-lite-2026-10.mmdb.gz"
    downloads = Downloads({october: gzip.compress(mmdb(PLACES, built=OCTOBER))})  # November's: a 404
    view = WorldView("w", capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW), fetch=downloads)
    out = view.install(URL)
    assert [u for u, _ in downloads.asked] == ["https://geoip.example/dbip-city-lite-2026-11.mmdb.gz", october]
    assert out["said"].startswith("installed dbip-city-lite-2026-10.mmdb (built 2026-10-01")
    assert out["lines"][0] == "downloaded from geoip.example: this month's file is not out yet, so last month's"
    assert view.geoip().describe()["file"] == "dbip-city-lite-2026-10.mmdb"
    january = WorldView("w", capture_factory=Feed, geo_folder=folder, fetch=Downloads({}),
                        wall=Clock(datetime(2027, 1, 3, tzinfo=timezone.utc).timestamp()))
    with pytest.raises(geo.GeoError, match="neither this month's nor last month's"):
        january.install(URL)
    assert [u for u, _ in january._fetch.asked] == ["https://geoip.example/dbip-city-lite-2027-01.mmdb.gz",
                                                    "https://geoip.example/dbip-city-lite-2026-12.mmdb.gz"]
    assert [p.name for p in folder.iterdir()] == ["dbip-city-lite-2026-10.mmdb"]  # the current file as it was


@needs_reader
def test_a_download_that_fails_leaves_the_current_file_and_says_why(geo_folder):
    november = "https://geoip.example/dbip-city-lite-2026-11.mmdb.gz"
    (geo_folder / "dbip-city-lite-2026-11.mmdb").unlink()
    (geo_folder / "dbip-city-lite-2026-10.mmdb").write_bytes(mmdb(PLACES, built=OCTOBER))
    before = (geo_folder / "dbip-city-lite-2026-10.mmdb").read_bytes()
    refused = WorldView("w", capture_factory=Feed, geo_folder=geo_folder, wall=Clock(NOW),
                        fetch=Downloads({november: urllib.error.HTTPError(november, 503, "Service Unavailable", {}, None)}))
    with pytest.raises(geo.GeoError, match="could not be downloaded from geoip.example: HTTP 503 Service Unavailable"):
        refused.install(URL)
    broken = WorldView("w", capture_factory=Feed, geo_folder=geo_folder, wall=Clock(NOW),
                       fetch=Downloads({november: gzip.compress(b"no GeoIP file at all " * 50)}))
    with pytest.raises(geo.GeoError, match="was not installed"):
        broken.install(URL)
    offline = WorldView("w", capture_factory=Feed, geo_folder=geo_folder, wall=Clock(NOW),
                        fetch=Downloads({november: urllib.error.URLError("no route to the host")}))
    with pytest.raises(geo.GeoError, match="no route to the host"):
        offline.install(URL)
    assert [p.name for p in geo_folder.iterdir()] == ["dbip-city-lite-2026-10.mmdb"]
    assert (geo_folder / "dbip-city-lite-2026-10.mmdb").read_bytes() == before


def test_a_download_is_refused_without_https_an_address_or_a_reader(tmp_path, monkeypatch):
    downloads = Downloads({})
    view = WorldView("w", capture_factory=Feed, geo_folder=tmp_path, wall=Clock(NOW), fetch=downloads)
    with pytest.raises(ValueError, match="https only"):
        view.install("http://geoip.example/dbip-city-lite-{year}-{month}.mmdb.gz")
    with pytest.raises(ValueError, match="names none"):
        view.install("")
    with pytest.raises(ValueError, match="offers no GeoIP file"):
        FakeFirewall().world_geoip(True)  # a firewall naming no download
    monkeypatch.setattr(geo, "available", lambda: (False, "maxminddb is not installed in this Python"))
    with pytest.raises(ValueError, match="maxminddb is not installed"):
        view.install(URL)
    page = view.page(licence=LICENCE, source=URL)
    assert "forms" not in page and "Places cannot be read here: maxminddb is not installed" in page["globe"]["note"]
    assert downloads.asked == []


def test_one_download_at_a_time(tmp_path):
    gate, entered = threading.Event(), threading.Event()

    def slow(url, timeout):
        entered.set()
        gate.wait(3)
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
    view = WorldView("w", capture_factory=Feed, geo_folder=tmp_path, wall=Clock(NOW), fetch=slow)
    first = threading.Thread(target=lambda: pytest.raises(geo.GeoError, view.install, URL), daemon=True)
    first.start()
    assert entered.wait(3)
    with pytest.raises(ValueError, match="being downloaded already"):
        view.install(URL)
    assert "A GeoIP file is being downloaded." in view.page(source=URL)["note"] and "forms" not in view.page(source=URL)
    gate.set()
    first.join(3)
    assert not first.is_alive()


def test_the_months_tried_and_the_names_installed():
    assert world.months(NOW) == [(2026, 11), (2026, 10)]
    assert world.months(datetime(2027, 1, 1, tzinfo=timezone.utc).timestamp()) == [(2027, 1), (2026, 12)]
    assert world.month_url(URL, 2026, 3) == "https://geoip.example/dbip-city-lite-2026-03.mmdb.gz"
    assert world.file_stem("https://geoip.example/dbip-city-lite-2026-03.mmdb.gz", 2026, 3) == "dbip-city-lite-2026-03"
    assert world.file_stem("https://geoip.example/download?month=3", 2026, 3) == "download"
    assert world.file_stem("https://geoip.example/", 2026, 3) == "geoip-2026-03"
    assert world.size_words(512) == "512 B" and world.size_words(1536) == "1.5 KB" and world.size_words(150 * 2**20) == "150 MB"


# -- the review's findings, put right (phase 2) ----------------------------------------------------------------------------
NOVEMBER_URL = "https://geoip.example/dbip-city-lite-2026-11.mmdb.gz"
PROGRESS = re.compile(r"[\d.]+ [KMG]?B of [\d.]+ [KMG]?B \(\d+%\)")


def raised(call, *args, **kwargs):
    """What `call` raised; None when it returned."""
    try:
        call(*args, **kwargs)
    except BaseException as e:  # noqa: BLE001 - the test looks at it
        return e
    return None


class Held:
    """A download's connection socket as a stand-in, its server sending a header byte within each socket timeout: what
    reads on it is held until the socket is shut (shutdown(), as an install shuts its download's sockets)."""

    def __init__(self):
        self.shut = threading.Event()
        self.how: list[int] = []

    def shutdown(self, how):
        self.how.append(how)
        self.shut.set()

    def fetch(self, entered: threading.Event):
        """A fetch that hands this socket to the install it runs for, as the real https connection does, and is held on it."""
        def held(url, timeout):
            world._handed(self)
            entered.set()
            self.shut.wait(10)
            raise urllib.error.URLError(ConnectionAbortedError("the connection's socket was shut"))
        return held


# F3, the blocker: one deadline for all of the install, the fetch included
@needs_reader
def test_one_deadline_bounds_the_whole_install_its_fetch_included(tmp_path, monkeypatch):
    """(Review F3, the blocker) geo.install_mmdb's half-hour began only once the fetch had returned: a server sending a
    header byte within each 60 s socket timeout held the install, a request thread and the tab's "being downloaded" for
    good. One deadline now covers all of it (geo.INSTALL_S, on the install's clock): the fetch runs on a thread of its
    own, the install says so the moment its time is up, and the connection's socket is shut, so that thread ends too.
    Nothing is installed, and the install is offered again."""
    now = [0.0]
    monkeypatch.setattr(geo, "_clock", lambda: now[0])
    sock, entered = Held(), threading.Event()
    folder = tmp_path / "geoip"
    view = WorldView("w", capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW), fetch=sock.fetch(entered))
    lines, out = [], {}
    install = threading.Thread(target=lambda: out.update(error=raised(view.install, URL, log=lines.append)), daemon=True)
    install.start()
    assert entered.wait(3) and "A GeoIP file is being downloaded." in view.page(source=URL)["note"]
    now[0] = geo.INSTALL_S - 1
    time.sleep(3 * world.POLL_S)
    assert install.is_alive() and not sock.shut.is_set()  # a second before the time is up: it goes on
    now[0] = geo.INSTALL_S  # half an hour on the install's clock, the headers still coming
    install.join(3)
    assert not install.is_alive() and sock.how == [socket.SHUT_RDWR]  # its socket shut: its thread ends as well
    assert isinstance(out["error"], geo.GeoError) and str(out["error"]) == (
        "the download took more than 1,800 s, the most an install may take, so it was stopped: nothing was installed")
    assert wait_for(lambda: downloading() == []) and not folder.exists()  # nothing written
    assert lines == ["asking geoip.example for dbip-city-lite-2026-11.mmdb.gz"]
    assert "forms" in view.page(source=URL) and not view._installing.locked()  # offered again


@needs_reader
def test_a_fetch_that_answers_after_the_deadline_or_a_body_that_dribbles_installs_nothing(tmp_path, monkeypatch):
    """(Review F3) What the probe found: a fetch whose status line and headers took two hours on the install's clock
    installed all the same. The same deadline holds for the body: one read of the stream at a time (read1), the time
    looked at before each, so a byte every 50 s is stopped at the half hour. The stream is closed either way."""
    now = [0.0]
    monkeypatch.setattr(geo, "_clock", lambda: now[0])
    data = gzip.compress(mmdb(PLACES, built=NOVEMBER))
    step, streams = [0.0], []

    class Answer(io.BytesIO):
        given = 0

        def read1(self, n=-1):
            now[0] += step[0]  # each read takes this long on the install's clock
            got = super().read1(min(n, 1))
            self.given += len(got)
            return got

    def slow(url, timeout):
        now[0] += 7200.0  # its status line and headers came over two hours, each read within its timeout
        streams.append(Answer(data))
        return streams[-1]
    folder = tmp_path / "late"
    with pytest.raises(geo.GeoError, match="took more than 1,800 s"):
        WorldView("w", capture_factory=Feed, geo_folder=folder, wall=Clock(NOW), fetch=slow).install(URL)
    assert streams[0].closed and not list(folder.glob("*")) and not list(folder.glob(".*"))

    def dribbling(url, timeout):
        step[0] = 50.0  # a byte every 50 s
        streams.append(Answer(data))
        return streams[-1]
    now[0], folder = 0.0, tmp_path / "dribbled"
    with pytest.raises(geo.GeoError, match="took more than 1,800 s"):
        WorldView("w", capture_factory=Feed, geo_folder=folder, wall=Clock(NOW), fetch=dribbling).install(URL)
    assert streams[1].closed and streams[1].given == 36 and now[0] == geo.INSTALL_S  # 36 bytes in the half hour
    assert not list(folder.glob("*")) and not list(folder.glob(".*"))  # its part file removed


def test_a_detach_stops_an_install_under_way(tmp_path):
    """(Review, minor) close() left an install under way downloading after the detach, for up to half an hour: the
    plugin's detach now stops it, its socket shut, nothing installed."""
    sock, entered = Held(), threading.Event()
    fw = Walled(capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW), fetch=sock.fetch(entered))
    out = {}
    job = threading.Thread(target=lambda: out.update(error=raised(fw.world_geoip, True)), daemon=True)
    job.start()
    assert entered.wait(3)
    fw.detach()  # the platform lets the plugin go meanwhile
    job.join(3)
    assert not job.is_alive() and sock.shut.is_set()
    assert isinstance(out["error"], geo.GeoError) and str(out["error"]) == world.DETACHED
    assert wait_for(lambda: downloading() == []) and not (tmp_path / "geoip").exists()


def test_a_downloads_connections_hand_their_sockets_to_its_install_which_shuts_them(monkeypatch):
    """How a held download is stopped: each https connection hands its sockets (the plain one as it connects, the TLS one
    once made) to the install its thread runs for; stopped, the install shuts them (a read waiting on one then ends), and
    one opened after the stop is shut at once. Once the stream was read to its end, nothing is stopped: what is left is
    this machine's own. Nothing is connected here."""
    connection, https, _ = world._transport()

    class Sock:
        def __init__(self):
            self.how = []

        def shutdown(self, how):
            self.how.append(how)

        def setsockopt(self, *args):
            pass
    raw, tls = Sock(), Sock()
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: raw)  # nothing connected ...
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", lambda self: setattr(self, "sock", tls))  # ... no TLS
    cutoff = world._Cutoff()
    world._WORLD_DOWNLOADS.cutoff = cutoff
    try:
        conn = connection("geoip.example", timeout=5)
        assert conn._create_connection(("geoip.example", 443), 5, None) is raw  # as HTTPConnection.connect makes it
        conn.connect()
        assert cutoff.sockets == [raw, tls]
    finally:
        world._WORLD_DOWNLOADS.cutoff = None
    assert cutoff.stop("its time is up") is True and raw.how == tls.how == [socket.SHUT_RDWR]
    late = Sock()
    cutoff.hand(late)
    assert late.how == [socket.SHUT_RDWR] and cutoff.why == "its time is up" and cutoff.sockets == []
    ended, kept = world._Cutoff(), Sock()
    ended.hand(kept)
    ended.ended = True  # its stream read to its end
    assert ended.stop("too late") is False and kept.how == [] and ended.why == ""
    world._handed(Sock())  # on a thread that runs no install: handed to none
    assert issubclass(https, urllib.request.HTTPSHandler)


# F1: https on every hop, from the plugin's own host
class Body(io.BytesIO):
    """An answer's body as http.client gives it: once closed, a read gives nothing; the reads while open counted."""

    def __init__(self, data=b""):
        super().__init__(data)
        self.reads = 0

    def read(self, n=-1):
        if self.closed:
            return b""
        self.reads += 1
        return super().read(n)

    def read1(self, n=-1):
        if self.closed:
            return b""
        self.reads += 1
        return super().read1(n)


class Web(urllib.request.HTTPSHandler):
    """https as a stand-in: each address asked answered from `pages` ({url: (code, headers, body)}), else 404; nothing is
    connected."""

    def __init__(self, pages):
        super().__init__()
        self.pages, self.asked, self.bodies = dict(pages), [], []

    def https_open(self, req):
        self.asked.append(req.full_url)
        code, headers, data = self.pages.get(req.full_url, (404, {}, b""))
        said = email.message.Message()
        for k, v in headers.items():
            said[k] = v
        self.bodies.append(Body(data))
        answer = urllib.response.addinfourl(self.bodies[-1], said, req.full_url, code)
        answer.msg = http.client.responses.get(code, "")
        return answer


class Plain(urllib.request.HTTPHandler):
    """http as a stand-in that fails the test when a download reaches it."""

    def __init__(self):
        super().__init__()
        self.asked = []

    def http_open(self, req):
        self.asked.append(req.full_url)
        raise AssertionError(f"a download went to {req.full_url}")


class Ftp(urllib.request.FTPHandler):
    def __init__(self):
        super().__init__()
        self.asked = []

    def ftp_open(self, req):
        self.asked.append(req.full_url)
        raise AssertionError(f"a download went to {req.full_url}")


def over(web, *more):
    """The real fetch_url over stand-in protocols: (the fetch, the http and ftp stand-ins)."""
    plain, ftp = Plain(), Ftp()
    return (lambda url, timeout: FETCH_URL(url, timeout, handlers=(web, plain, ftp, *more))), plain, ftp


@needs_reader
def test_a_download_is_https_on_every_hop_from_the_plugins_own_host(tmp_path):
    """(Review F1) https held for the first request alone: urllib followed a redirect to http, ftp or another host, and
    the file was installed and credited to the first host. A redirect is now followed to the same host over https alone
    (its body never read), any other refused before anything is asked of it, and the address the answer came from is
    checked again; the words name the host it came from. No socket is opened."""
    data = gzip.compress(mmdb(PLACES, built=NOVEMBER))
    for n, where in enumerate(("http://mirror.example/dbip.mmdb.gz", "ftp://ftp.mirror.example/dbip.mmdb.gz",
                               "https://cdn.other.example/dbip.mmdb.gz", "https://geoip.example.evil.example/dbip.mmdb.gz")):
        web = Web({NOVEMBER_URL: (302, {"Location": where}, b"the redirect's own body"),
                   where: (200, {"Content-Length": str(len(data))}, data)})
        fetch, plain, ftp = over(web)
        folder = tmp_path / f"refused-{n}"
        view = WorldView("w", capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW), fetch=fetch)
        with pytest.raises(geo.GeoError) as refused:
            view.install(URL)
        scheme, host = where.split("://")[0], where.split("/")[2]
        assert str(refused.value) == (f"the GeoIP file could not be downloaded from geoip.example: it was sent on to "
                                      f"{scheme}://{host}, and a GeoIP file comes over https from geoip.example alone")
        assert web.asked == [NOVEMBER_URL] and plain.asked == ftp.asked == []  # never followed
        assert web.bodies[0].reads == 0 and not folder.exists()  # nothing read of it, nothing written
    # the same host, over https: followed (a relative address too), its body never read, the host named
    mirror = "https://geoip.example/mirror/dbip-city-lite-2026-11.mmdb.gz"
    web = Web({NOVEMBER_URL: (302, {"Location": "/mirror/dbip-city-lite-2026-11.mmdb.gz"}, b"moved"),
               mirror: (200, {"Content-Length": str(len(data))}, data)})
    view = WorldView("w", capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW),
                     fetch=over(web)[0])
    out = view.install(URL)
    assert web.asked == [NOVEMBER_URL, mirror] and web.bodies[0].reads == 0 and web.bodies[1].reads > 0
    assert out["ok"] is True and out["lines"][0] == "downloaded from geoip.example"
    # no more than MAX_REDIRECTS of them
    hops = {f"https://geoip.example/{i}": (302, {"Location": f"https://geoip.example/{i + 1}"}, b"") for i in range(9)}
    hops[NOVEMBER_URL] = (302, {"Location": "https://geoip.example/0"}, b"")
    web = Web(hops)
    with pytest.raises(geo.GeoError, match="HTTP 302"):
        WorldView("w", capture_factory=Feed, geo_folder=tmp_path / "loop", wall=Clock(NOW), fetch=over(web)[0]).install(URL)
    assert len(web.asked) == 1 + world.MAX_REDIRECTS
    # fetch_url itself: https only from the start, and a hop elsewhere refused in its own words
    with pytest.raises(ValueError, match="https only"):
        FETCH_URL("http://geoip.example/dbip.mmdb.gz", 5, handlers=(Web({}),))
    with pytest.raises(RedirectRefused, match="sent on to http://mirror.example"):
        FETCH_URL(NOVEMBER_URL, 5, handlers=(Web({NOVEMBER_URL: (302, {"Location": "http://mirror.example/x"}, b"")}),))

    class Moved(io.BytesIO):
        """A stand-in fetch's answer that says it came from elsewhere."""
        def geturl(self):
            return "http://mirror.example/dbip-city-lite-2026-11.mmdb.gz"
    view = WorldView("w", capture_factory=Feed, geo_folder=tmp_path / "moved", wall=Clock(NOW),
                     fetch=lambda url, timeout: Moved(data))
    with pytest.raises(geo.GeoError, match="came from http://mirror.example, not over https from geoip.example"):
        view.install(URL)
    assert not (tmp_path / "moved").exists()


# F2: an attempt not answered yet, or never judged, is not "allowed in"
def test_an_attempt_not_answered_yet_or_never_judged_is_not_drawn_as_allowed_in(tmp_path):
    """(Review F2) A place with no start counted was drawn "allowed in" when its ports were this machine's: a SYN the
    firewall drops, younger than 3 s, at every ask (the tab is asked every 2 s), and for good when watching paused
    before it was judged. Nothing went back to that network, so it is unanswered; a connection open before watching
    began (something went back) is still allowed in."""
    now = [10.5]
    book = TrafficBook(clock=lambda: now[0])
    view = WorldView("w", capture_factory=Feed, geo_folder=tmp_path, clock=Clock(), wall=Clock(NOW), book=book)

    def place(group: str) -> dict:
        return next(o for o in view.page()["globe"]["origins"] if o["id"] == group)
    book.add(pk(10.0, CHANGCHUN, 40001, LAN, 3389, SYN))  # a scan the firewall drops, half a second old
    assert (place("175.16.199.0/24")["kind"], place("175.16.199.0/24")["count"]) == ("unanswered", 1)
    now[0] = 12.0
    assert place("175.16.199.0/24")["kind"] == "unanswered"
    now[0] = 13.5  # 3 s on: judged unanswered, as it was drawn
    judged = place("175.16.199.0/24")
    assert (judged["kind"], judged["count"], judged["starts"]["unanswered"]) == ("unanswered", 1, 1)
    # watching paused before an attempt could be judged: never judged, never allowed in
    book.add(pk(20.0, AUSSIE, 41000, LAN, 22, SYN))
    book.settle(now=21.0)
    lost = place("1.2.3.0/24")
    assert (lost["kind"], lost["count"], lost["unjudged"]) == ("unanswered", 1, 1)
    row = next(r for r in view.page()["tables"][1]["rows"] if r[2]["text"] == "1.2.3.0/24")
    assert row[5] == "unanswered in" and row[2]["sub"] == "1 not judged"
    # open before watching began, to a service here: something went back, so allowed in
    book.add(pk(30.0, LONDON, 51000, LAN, 8765, PSH | ACK, length=566))
    book.add(pk(30.1, LAN, 8765, LONDON, 51000, PSH | ACK, length=1466))
    assert place("81.2.69.0/24")["kind"] == "allowed"
    book.add(pk(40.0, NOWHERE, 42000, LAN, 8765, SYN))  # answered: allowed in
    book.add(pk(40.1, LAN, 8765, NOWHERE, 42000, SYN | ACK))
    assert place("5.6.7.0/24")["kind"] == "allowed"


# F4 (and fw-linux's F1 and F2): the right to capture on Linux
def test_on_linux_the_right_to_capture_is_cap_net_raw_for_the_platform_alone_and_only_when_it_is_missing(monkeypatch):
    """(Review F4; fw-linux F1, the blocker, and F2) The tab told an administrator to give CAP_NET_RAW and CAP_NET_ADMIN
    to the realpath of the venv's python: the system's interpreter, which every account and script runs, so any of them
    could flush the firewall this plugin manages. It said so for every libpcap failure, as root too, for the library's
    own hint follows each. Now: CAP_NET_RAW alone, for the platform alone (its system unit, or its own copy of Python),
    never the system's Python; only when libpcap says the right is missing, and only when the platform is not root."""
    hint = world.LIBRARY_HINT
    denied = ("the adapter could not be opened: eth0: You don't have permission to capture on that device (socket: "
              "Operation not permitted)" + hint)
    monkeypatch.setattr(world, "_python", lambda: ("/usr/bin/python3.13", False))  # a venv's python: the system's
    shared = capture_help(denied, windows=False, root=False)
    assert "AmbientCapabilities=CAP_NET_RAW under [Service]" in shared and "liminal-platform-boot.service" in shared
    assert "Never give it to the system's Python (/usr/bin/python3.13)" in shared
    assert "setcap cap_net_raw=ep /usr/bin/python3.13" not in shared and "setcap cap_net_raw=ep on that copy's" in shared
    monkeypatch.setattr(world, "_python", lambda: ("/opt/liminal/.venv/bin/python3", True))  # the platform's own copy
    own = capture_help(denied, windows=False, root=False)
    assert "setcap cap_net_raw=ep /opt/liminal/.venv/bin/python3" in own and "chmod 0750" in own
    for words in (shared, own):
        assert "cap_net_admin" not in words.lower() and "sudo" not in words and "password" not in words.lower()
    for why in ("socket: Operation not permitted", "Attempt to create packet socket failed - CAP_NET_RAW may be required",
                "Permission denied"):  # libpcap's other words for it
        assert "AmbientCapabilities" in capture_help(f"the adapter could not be opened: eth0: {why}{hint}", windows=False,
                                                     root=False)
    as_root = capture_help(denied, windows=False, root=True)  # root has the right already: nothing to give
    assert "setcap" not in as_root and "Ambient" not in as_root and as_root.startswith("The platform runs as root")
    for why in ("wg0: No such device exists (SIOCGIFINDEX: No such device)", "wlan0: That device is not up",
                "eth0: Packet capture is not supported on that device", "eth0: can't mmap rx ring: Cannot allocate memory"):
        error = f"the adapter could not be opened: {why}{hint}"  # the library's hint is no word that the right is missing
        assert capture_help(error, windows=False, root=False) == "Show this tab again once that is put right."
        assert world._shown_error(error) == f"the adapter could not be opened: {why}"  # nor shown with it
    assert world._shown_error(denied) == denied


def test_an_adapter_libpcap_does_not_list_is_said_so_not_taken_for_no_network():
    """(Review, minor) "no adapter holds" was told as "Connect this machine to a network"."""
    held = "no adapter holds 192.168.1.20 (as libpcap lists them)"
    on_windows, on_linux = capture_help(held, windows=True), capture_help(held, windows=False, root=False)
    assert on_windows.startswith("Npcap lists no adapter holding this machine's address (192.168.1.20)")
    assert on_linux.startswith("libpcap lists no adapter holding this machine's address (192.168.1.20)")
    assert "Connect this machine" not in on_windows + on_linux


# fw-windows F1: Npcap installed for administrators only
def test_npcap_for_administrators_only_is_never_opened_from_the_tab_and_its_page_says_why_and_how(tmp_path, monkeypatch):
    """(fw-windows review F1) With Npcap's AdminOnly on, opening it from a process that is no administrator's starts its
    NpcapHelper with "runas": a UAC prompt from a tab that only reads. The capture is not opened then (its option read
    from the registry, read-only), the page says why and how (Npcap's installer option, or the platform run as an
    administrator), and it is looked at again no more than every RETRY_S, never asking anyone anything."""
    looked = []
    monkeypatch.setattr(capture, "_windows", lambda: True)
    monkeypatch.setattr(capture, "npcap_admin_only", lambda: looked.append(1) or True)
    monkeypatch.setattr(capture, "administrator", lambda: False)

    class Untouched:
        """libpcap as a stand-in that fails the test when anything is asked of it."""

        def __getattr__(self, name):
            raise AssertionError(f"Npcap was asked {name}")
    clock = Clock()
    view = WorldView("w", capture_factory=lambda: capture.Capture(LAN, udp=True, host=False,
                                                                  source=capture.PcapSource(Untouched())),
                     geo_folder=tmp_path, clock=clock, wall=Clock(NOW))
    assert view.touch() is False and view.error == capture.ADMIN_ONLY and looked == [1] and watching() == []
    note = view.page()["note"]
    assert note.startswith(f"Traffic cannot be watched here: {capture.ADMIN_ONLY}. Npcap was installed for administrators "
                           "only, and opening it would ask for an administrator, so it is not opened.")
    assert "Restrict Npcap driver's access to Administrators only" in note and "run the platform as an administrator" in note
    clock.t += RETRY_S - 1
    assert view.touch() is False and looked == [1]  # asked every two seconds: not looked at again so soon
    clock.t += 1
    assert view.touch() is False and looked == [1, 1]
    monkeypatch.setattr(capture, "administrator", lambda: True)  # the platform run as an administrator: Npcap is asked
    clock.t += RETRY_S
    assert view.touch() is False and view.error == "Npcap was asked pcap_findalldevs"  # (the stand-in's refusal)


# the builders' three: the GeoIP file let go, the view read without making one, the install as a job
@needs_reader
def test_the_geoip_file_is_let_go_once_watching_stops_by_itself_and_opened_again_at_the_next_ask(geo_folder):
    """(Phase 2) The GeoIP file stayed mapped after watching stopped by itself (the viewing timeout): it is let go then,
    and on stop(), still said for the plugin's card (describe), and opened again at the next ask."""
    clock = Clock()
    fw = Walled(capture_factory=Feed, geo_folder=geo_folder, clock=clock, wall=Clock(NOW), timeout=20.0)
    fw.world()
    view = fw.world_view()
    first = view.geoip()
    assert view.running and first.describe()["open"]
    clock.t += 21  # nobody looked for longer than the timeout
    assert wait_for(lambda: not view.running) and wait_for(lambda: first.describe()["open"] is False)
    assert view._geoip is None
    said = view.describe()["geoip"]
    assert (said["file"], said["date"], said["open"]) == ("dbip-city-lite-2026-11.mmdb", "2026-11-01", False)
    fw.world()  # looked at again: watching starts, and the file is opened again for the places
    again = view._geoip
    assert view.running and again is not None and again is not first and again.describe()["open"]
    view.stop()
    assert again.describe()["open"] is False and view.describe()["geoip"]["open"] is False
    fw.detach()


@needs_reader
def test_while_nothing_can_watch_the_geoip_file_is_let_go_after_each_ask(geo_folder):
    words = "Npcap is not installed (npcap.com; Wireshark installs it): packets cannot be watched"
    fw = Walled(capture_factory=lambda: Feed(fail_open=words), geo_folder=geo_folder, clock=Clock(), wall=Clock(NOW))
    traffic_of(fw.world_view().book)
    page = fw.world()
    assert [o["city"] for o in page["globe"]["origins"] if o["lat"] is not None]  # placed ...
    assert fw.world_view()._geoip is None  # ... then let go: nobody watches, nothing is left mapped
    fw.detach()


def test_the_tabs_view_is_read_without_making_one():
    """(Phase 2) The plugins read the base's private __dict__['_world'] for their cards' facts: world_view(make=False)
    gives the view there is, or None, and never makes one."""
    fw = Walled(capture_factory=Feed)
    assert fw.world_view(make=False) is None and fw.made == 0 and "_world" not in fw.__dict__
    fw.settings_changed()  # nothing to tell: nothing made for it
    assert fw.made == 0
    view = fw.world_view()
    assert fw.world_view(make=False) is view and fw.world_view() is view and fw.made == 1
    fw.detach()
    assert fw.world_view(make=False) is None


@needs_reader
def test_the_geoip_install_is_a_job_saying_its_progress_at_most_every_two_seconds(tmp_path, monkeypatch):
    """(Phase 2) The 60 MB download ran inside the ask and held the form's dialog: the install is a job now (JOB_HOOKS,
    the form's `job`), each step and the bytes downloaded with their percent said to its log at most every PROGRESS_S,
    the tab's note saying how far it is. Its licence is refused before the job says anything, which is how the platform
    carries that refusal back to the page as a second confirmation."""
    now = [0.0]
    monkeypatch.setattr(geo, "_clock", lambda: now[0])
    data = gzip.compress(mmdb(PLACES, built=NOVEMBER))
    notes, lines = [], []

    class Paced(io.BytesIO):
        """The answer, its size said, each read half a second on the install's clock."""
        headers = {"Content-Length": str(len(data))}
        reads = 0

        def read1(self, n=-1):
            now[0] += 0.5
            Paced.reads += 1
            if Paced.reads == 12:  # the tab, asked meanwhile
                notes.append(fw.world_view().page(source=URL)["note"])
            return super().read1(min(n, 16))

    def fetch(url, timeout):
        if url != NOVEMBER_URL:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return Paced(data)
    fw = Walled(capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW), fetch=fetch)
    [form] = fw.world()["forms"]
    assert form["job"] is True and form["hook"] in fw.JOB_HOOKS  # run by the platform as a job, its lines followed
    assert "its progress shows in the panel below" in form["confirm"]["words"]
    with pytest.raises(LicenceRefused):
        fw.ask("world_geoip", False, log=lines.append)
    assert lines == []  # refused before its first line
    out = fw.ask("world_geoip", True, log=lambda line: lines.append((now[0], line)))
    assert out["ok"] is True and out["said"].startswith("installed dbip-city-lite-2026-11.mmdb")
    said = [line for _, line in lines]
    assert said[:2] == ["asking geoip.example for dbip-city-lite-2026-11.mmdb.gz",
                        f"downloading dbip-city-lite-2026-11.mmdb.gz from geoip.example: {world.size_words(len(data))}"]
    progress = lines[2:-1]
    assert len(progress) >= 3 and all(PROGRESS.fullmatch(line) for _, line in progress)
    assert all(b[0] - a[0] >= world.PROGRESS_S for a, b in zip(progress, progress[1:]))  # at most every 2 s
    percents = [int(re.search(r"\((\d+)%\)", line).group(1)) for _, line in progress]
    assert percents == sorted(percents) and 0 < percents[-1] <= 100
    assert said[-1] == f"{world.size_words(len(data))} downloaded: unpacking and checking it"
    assert len(notes) == 1 and re.search(r"A GeoIP file is being downloaded\. So far: [\d.]+ [KMG]?B of [\d.]+ [KMG]?B "
                                         r"\(\d+%\)\.", notes[0])
    fw.detach()


@needs_reader
def test_without_nslookup_the_home_lookup_says_nslookup_is_missing(geo_folder, monkeypatch):
    """(Phase 2) On a Linux machine without nslookup the home lookup said that the name servers did not answer."""
    monkeypatch.setattr(world, "nslookup_path", lambda: None)
    view = WorldView("w", capture_factory=Feed, geo_folder=geo_folder, clock=Clock(), wall=Clock(NOW))  # the default lookup
    view.page(public=SERVERS)
    assert wait_for(lambda: view._public["at"] is not None and not view._public["running"])
    note = view.page(public=SERVERS)["globe"]["note"]
    assert "nslookup is not installed here" in note and "answered" not in note  # and no name server was asked
    assert "dnsutils on Debian and Ubuntu, bind-utils on Fedora, bind-tools on Arch and Alpine" in world.nslookup_missing(
        windows=False)


def test_a_home_that_is_no_place_is_shown_back_cut_short_and_decimal_commas_are_refused(tmp_path):
    """(Review, minor) A home that is no place was echoed whole into each page's note; 48,86,2,35 was read as a place."""
    for bad in ("x" * 5000, "1" * 5000 + ",2", "0," + "9" * 5000):
        with pytest.raises(ValueError) as said:
            home_place(bad)
        assert len(str(said.value)) < 160 and "…" in str(said.value)
    for commas in ("48,86,2,35", "48,86,2", "-33,87,151,21"):
        with pytest.raises(ValueError, match="decimal point, not a comma"):
            home_place(commas)
    assert home_place("48.86,2.35,Paris, 75001") == {"lat": 48.86, "lon": 2.35, "label": "Paris, 75001"}
    view = WorldView("w", capture_factory=Feed, geo_folder=tmp_path, clock=Clock(), wall=Clock(NOW))
    note = view.page(home="x" * 5000)["globe"]["note"]
    assert "x" * (world.SHOWN + 1) not in note and "LIMINAL_HOME_PLACE is not a place" in note


def test_the_charts_go_on_when_the_wall_clock_is_set_back(tmp_path):
    """(Review, minor) Samples were timed by the wall clock: set back, the charts froze until it caught up. They are
    timed by the view's own clock now, the wall clock saying only their times of day."""
    wall, clock, book = Clock(NOW), Clock(), TrafficBook(clock=lambda: 9999.0)
    later = Ticks(wall, clock)
    view = WorldView("w", capture_factory=Feed, geo_folder=tmp_path, clock=clock, wall=wall, book=book)
    flow = 0

    def moved(n: int) -> None:
        nonlocal flow
        flow += 1
        book.add(pk(1.0, LONDON, 30000 + flow, LAN, 8765, ACK, length=n))
    for n in (100, 1000, 2000):
        moved(n)
        view.page()
        later(2.0)
    wall.t -= 3600  # the wall clock set back an hour: the view's own clock goes on
    moved(4000)
    [spec] = view.page()["charts"]
    assert spec["charts"][0]["lines"][0]["values"] == [500.0, 1000.0, 2000.0]  # the newest sample made, not frozen
    assert spec["t"] == [wall.t - 4.0, wall.t - 2.0, wall.t]  # its times of day as the wall clock says them now


# -- after the phase-2 fixes' checks, and the user's WSL rule (2026-11-15) -----------------------------------------------------
def test_the_platforms_own_python_is_told_from_the_systems(tmp_path):
    """(The F4 check's residuals) _python() itself was run by no test (each stood in for it), and a venv's python hard
    linked to the system's interpreter, the very same file, would have been taken for the platform's own copy. Only a
    venv's own file is: in a venv, inside it, and no link to the system's interpreter, symbolic or hard."""
    usr = tmp_path / "usr"
    (usr / "bin").mkdir(parents=True)
    system = usr / "bin" / "python3.13"
    system.write_bytes(b"\x7fELF the system's")
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    copy = venv / "bin" / "python3"
    copy.write_bytes(b"\x7fELF its own")
    real, own = world._python(str(copy), str(venv), str(usr))
    assert own and real == os.path.realpath(copy)  # python3 -m venv --copies: the platform's own
    assert world._python(str(system), str(usr), str(usr)) == (os.path.realpath(system), False)  # no venv: the system's
    elsewhere = tmp_path / "opt" / "python3"
    elsewhere.parent.mkdir()
    elsewhere.write_bytes(b"\x7fELF")
    assert world._python(str(elsewhere), str(venv), str(usr))[1] is False  # a venv's, yet a file outside it
    hard = venv / "bin" / "python3-hard"
    os.link(system, hard)
    assert world._python(str(hard), str(venv), str(usr))[1] is False  # the system's interpreter by another name
    try:
        os.symlink(system, venv / "bin" / "python3-link")
    except (OSError, NotImplementedError):  # no symbolic links here (Windows without the right): Linux's CI makes them
        return
    real, own = world._python(str(venv / "bin" / "python3-link"), str(venv), str(usr))
    assert real == os.path.realpath(system) and own is False  # a venv's usual python: a link to the system's


def test_under_openrc_or_another_init_the_right_goes_on_the_platforms_own_python():
    """(The phase-2 fixers' follow-up) The advice named a systemd unit's AmbientCapabilities= under any init: under OpenRC
    (Gentoo, Alpine) the platform's boot service is an init script, and under another init none is made, so there the
    right goes on the platform's own copy of Python alone. Off Linux nothing says which: both ways are told."""
    shared, own = ("/usr/bin/python3.13", False), ("/opt/liminal/.venv/bin/python3", True)
    for init in ("openrc", "other"):
        words = world._capability_help(shared, init=init)
        assert "Ambient" not in words and ".service" not in words and "python3 -m venv --copies" in words
        assert "Never give it to the system's Python (/usr/bin/python3.13)" in words
        mine = world._capability_help(own, init=init)
        assert "alone: as this Python (/opt/liminal/.venv/bin/python3) is the platform's own copy" in mine
        assert "setcap cap_net_raw=ep /opt/liminal/.venv/bin/python3" in mine and "Ambient" not in mine
    for init in ("systemd", ""):
        assert "AmbientCapabilities=CAP_NET_RAW under [Service]; or run the platform from a copy" in world._capability_help(
            shared, init=init)
        assert "under [Service]; or, since this Python (/opt/liminal/.venv/bin/python3)" in world._capability_help(own, init=init)
    for words in (world._capability_help(p, init=i) for p in (shared, own) for i in ("systemd", "openrc", "other", "")):
        assert "cap_net_admin" not in words.lower() and "password" not in words.lower() and "sudo" not in words
    assert INIT() == "" if not sys.platform.startswith("linux") else INIT() in ("systemd", "openrc", "other")


def test_inside_wsl_the_tab_says_what_wsl_changes_for_it(monkeypatch, tmp_path):
    """The user, 2026-11-15: "wsl and firewall linux should always work under linux, if wsl prevents or misses some
    capability this should reflect in the plugin". Inside a WSL distribution (machines.linux.wsl names it, once the
    library has it) the tab's page ends with a table, Under WSL: the adapter watched is the distribution's own, Windows'
    own traffic is the Windows firewall's tab's, nothing comes in from the internet but through Windows, and under WSL 1
    no packet can be watched at all. None on a machine of its own, nor with a library from before the Linux plugins
    worked in WSL (there a WSL kernel is refused before the tab is drawn)."""
    from liminal_libs.machines import linux

    monkeypatch.delattr(linux, "wsl", raising=False)
    assert UNDER_WSL() is None and UNDER_WSL("6.6.87.2-microsoft-standard-WSL2", {"WSL_DISTRO_NAME": "Ubuntu"}) is None
    monkeypatch.setattr(linux, "wsl", lambda release=None, env=None: "" if "generic" in (release or "") else "Ubuntu",
                        raising=False)
    monkeypatch.setattr(linux, "wsl_generation", lambda release=None: 1 if (release or "").endswith("-Microsoft") else 2,
                        raising=False)
    assert UNDER_WSL("6.8.0-48-generic", {}) is None  # a machine of its own
    two = UNDER_WSL("6.6.87.2-microsoft-standard-WSL2", {"WSL_DISTRO_NAME": "Ubuntu"})
    assert two["title"] == "Under WSL" and [r[0] for r in two["rows"]] == ["This Linux", "Watched", "From the internet", "Home"]
    assert two["rows"][0][1] == "WSL 2: Ubuntu" and "the Windows firewall plugin's World Wide Web tab" in two["rows"][1][2]
    assert "netsh interface portproxy" in two["rows"][2][2] and "networkingMode=mirrored" in two["rows"][2][2]
    assert [c["title"] for c in two["columns"]] == ["What", "Here", "What it means"]
    one = UNDER_WSL("4.4.0-19041-Microsoft", {})
    assert one["rows"][0][1] == "WSL 1: Ubuntu" and one["rows"][1][1] == "nothing"
    assert "wsl --set-version Ubuntu 2" in one["rows"][1][2]
    monkeypatch.setattr(linux, "wsl", lambda release=None, env=None: "WSL", raising=False)  # a distribution not named
    assert "wsl --set-version <its name> 2" in UNDER_WSL("4.4.0-19041-Microsoft", {})["rows"][1][2]
    monkeypatch.setattr(linux, "wsl", lambda release=None, env=None: 1 / 0, raising=False)
    assert UNDER_WSL("anything", {}) is None  # a check that cannot say: nothing said
    # the Firewall base's tab: the table after its own, only where it is given
    fw = Walled(capture_factory=Feed, geo_folder=tmp_path, clock=Clock(), wall=Clock(NOW))
    assert "Under WSL" not in [t["title"] for t in fw.world()["tables"]]  # the fixture's: not inside WSL
    monkeypatch.setattr(world, "under_wsl", lambda: two)
    titles = [t["title"] for t in fw.world()["tables"]]
    assert titles[-1] == "Under WSL" and titles.count("Under WSL") == 1
    fw.detach()


@needs_reader
def test_a_file_whose_check_takes_too_long_is_said_to_go_in_place_still(tmp_path, monkeypatch):
    """(The F3 check's residual) A file read to its end, whose check here then took longer than LOCAL_S, was said "not
    put in place in time", and was put in place all the same: the words now say it still goes in place if it passes."""
    now = [0.0]
    monkeypatch.setattr(geo, "_clock", lambda: now[0])
    monkeypatch.setattr(world, "LOCAL_S", 0.05)
    placed, real = threading.Event(), geo.install_mmdb

    def slow_check(*args, **kwargs):
        path = real(*args, **kwargs)  # read to its end, and put in place ...
        now[0] = geo.INSTALL_S + 1.0  # ... the install's time up meanwhile ...
        time.sleep(0.4)  # ... and its checks still taking their time
        placed.set()
        return path
    monkeypatch.setattr(geo, "install_mmdb", slow_check)
    data = gzip.compress(mmdb(PLACES, built=NOVEMBER))
    view = WorldView("w", capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW),
                     fetch=lambda url, timeout: io.BytesIO(data))
    with pytest.raises(geo.GeoError, match=r"checking it here took more than 0\.05 s: it is still put in place if it passes"):
        view.install(URL)
    assert placed.wait(3) and wait_for(lambda: downloading() == [])
    assert (tmp_path / "geoip" / "dbip-city-lite-2026-11.mmdb").exists()


@needs_reader
def test_geoip_files_on_another_systems_drive_are_that_systems(tmp_path, monkeypatch):
    """1.58.0, for the suite run a second time inside WSL: each system's platform keeps its own GeoIP files. A data
    folder on another system's drive (mounts.foreign) holds that system's: the tab maps none of its files (mapped, one
    would keep that system's own update from replacing it), says why, offers no install, and an install asked anyway,
    its licence accepted, is refused in words before anything is fetched. Its own folder again: placed, and the
    install offered as ever."""
    from liminal_libs import mounts

    theirs = tmp_path / "theirs"
    theirs.mkdir()
    (theirs / "dbip-city-lite-2026-10.mmdb").write_bytes(mmdb(PLACES, built=OCTOBER))  # last month's: Update... if read
    monkeypatch.setattr(mounts, "foreign", lambda path, table=None: str(path).startswith(str(theirs)))
    fetched: list = []
    fw = Walled(capture_factory=Feed, geo_folder=theirs, clock=Clock(), wall=Clock(NOW),
                fetch=lambda url, timeout: fetched.append(url))
    traffic_of(fw.world_view().book)
    page = fw.world()
    view = fw.world_view()
    assert view.geoip() is None and view._geoip is None and view.elsewhere().startswith("Reading the GeoIP files: ")
    assert "forms" not in page and "actions" not in page  # no install offered, nor an update
    assert [o for o in page["globe"]["origins"] if o["lat"] is not None] == []  # nothing placed
    note = page["globe"]["note"]
    assert "No place is known here. Reading the GeoIP files: " in note
    assert "is on another system's drive, and that is done from that system, not from here." in note
    with pytest.raises(ValueError, match=r"^Installing a GeoIP file: .* is on another system's drive"):
        fw.world_geoip(True)  # asked anyway, the licence accepted
    assert fetched == [] and view.describe()["geoip"] is None and downloading() == []
    monkeypatch.setattr(mounts, "foreign", lambda path, table=None: False)  # the folder this machine's own after all
    page = fw.world()
    assert [o["city"] for o in page["globe"]["origins"] if o["lat"] is not None]  # placed
    assert [a["title"] for a in page["actions"]] == ["Update the GeoIP file…"]  # October's file, in November
    fw.detach()


@needs_reader
def test_the_data_folder_itself_on_another_systems_drive_is_that_systems(monkeypatch):
    """(1.58.0's review) A firewall's view is made with no folder of its own (Firewall.make_world_view): it judges the
    data folder's geoip/ (geo.data_folder(), here the fixture's), the case the guard is for. Its files are not read, no
    install is offered, an install asked anyway is refused before anything is fetched; and a plugin that names no
    download is never told the tab offers one."""
    from liminal_libs import mounts

    theirs = geo.data_folder()
    theirs.mkdir(parents=True)
    (theirs / "dbip-city-lite-2026-10.mmdb").write_bytes(mmdb(PLACES, built=OCTOBER))
    there = os.path.realpath(theirs)
    monkeypatch.setattr(mounts, "foreign", lambda path, table=None: str(path).startswith(there))
    fetched: list = []
    fw = Walled(capture_factory=Feed, clock=Clock(), wall=Clock(NOW), fetch=lambda url, timeout: fetched.append(url))
    traffic_of(fw.world_view().book)
    page = fw.world()
    assert fw.world_view().folder == theirs and fw.world_view().geoip() is None
    assert "forms" not in page and "actions" not in page
    note = page["globe"]["note"]
    assert "No place is known here. Reading the GeoIP files: " in note and "the tab offers its install." in note
    with pytest.raises(ValueError, match=r"^Installing a GeoIP file: .* is on another system's drive"):
        fw.world_geoip(True)
    assert fetched == []
    bare = fw.world_view().page(can_install=False)["globe"]["note"]  # a plugin that names no download
    assert "This plugin offers no GeoIP file to download." in bare and "offers its install" not in bare
    fw.detach()


@needs_reader
def test_the_asn_file_is_offered_once_the_geoip_file_is_in_and_installed_beside_it_on_its_licence(tmp_path):
    """1.75.0 (the user, 2026-11-22: "Yes, do it", asked whether to fill the hop table's empty ASN and Operator
    columns from DB-IP's free ASN file): offered once the GeoIP file is in, downloaded only once its licence is
    accepted, kept in geoip/asn/ beside the GeoIP file (neither install removes the other's), each place's network
    read from it from then on, and a month's file never downloaded twice."""
    from test_geo import ASNS
    folder = tmp_path / "geoip"
    city_url = "https://geoip.example/dbip-city-lite-2026-11.mmdb.gz"
    november = "https://geoip.example/dbip-asn-lite-2026-11.mmdb.gz"
    downloads = Downloads({city_url: gzip.compress(mmdb(PLACES, built=NOVEMBER)),
                           november: gzip.compress(mmdb(ASNS, built=NOVEMBER, kind="DBIP-ASN-Lite"))})

    class Named(Walled):
        GEOIP_ASN_URL = "https://geoip.example/dbip-asn-lite-{year}-{month}.mmdb.gz"
        GEOIP_ASN_LICENCE = "the ASN file's licence, in words"
    fw = Named(capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW), fetch=downloads)
    assert [f["id"] for f in fw.world()["forms"]] == ["world-geoip"]  # the GeoIP file first: no ASN file without it
    fw.world_geoip(True)
    page = fw.world()
    form = next(f for f in page["forms"] if f["id"] == "world-asn")
    assert form["hook"] == "world_asn" and form["hook"] in fw.interface()["hooks"] and form["job"] is True
    assert "the ASN file's licence, in words" in form["confirm"]["words"] and "geoip.example" in form["confirm"]["words"]
    assert {"form": "world-asn", "title": "Install the ASN file…",
            "note": "Each network's number and operator, once you accept its licence"} in page["actions"]
    with pytest.raises(LicenceRefused) as refused:
        fw.ask(form["hook"], False)
    assert refused.value.accept == "accept_licence" == form["fields"][0]["name"] and len(downloads.asked) == 1
    out = fw.ask(form["hook"], True)  # accepted, in so many words
    assert downloads.asked[-1] == (november, world.READ_S) and out["ok"] is True
    assert out["said"].startswith("installed dbip-asn-lite-2026-11.mmdb (built 2026-11-01")
    assert out["lines"][1] == f"kept in {folder / 'asn'}, beside the GeoIP file, in place of any older ASN file"
    assert [p.name for p in folder.iterdir() if p.is_file()] == ["dbip-city-lite-2026-11.mmdb"]  # the GeoIP file kept
    assert [p.name for p in (folder / "asn").iterdir()] == ["dbip-asn-lite-2026-11.mmdb"]
    assert "forms" not in fw.world()  # nothing more offered
    london = fw.world_view().geoip().lookup(LONDON)
    assert (london.city, london.asn, london.org) == ("London", 20712, "Andrews & Arnold Ltd")
    again = fw.world_asn(True)  # this month's is there already: not downloaded again
    assert again["said"].startswith("dbip-asn-lite-2026-11.mmdb is installed already") and len(downloads.asked) == 2
    fw.detach()


@needs_reader
def test_an_asn_file_from_before_this_month_is_offered_its_update(tmp_path):
    from test_geo import ASNS
    folder = tmp_path / "geoip"
    (folder / "asn").mkdir(parents=True)
    (folder / "dbip-city-lite-2026-11.mmdb").write_bytes(mmdb(PLACES, built=NOVEMBER))
    (folder / "asn" / "dbip-asn-lite-2026-10.mmdb").write_bytes(mmdb(ASNS, built=OCTOBER, kind="DBIP-ASN-Lite"))

    class Named(Walled):
        GEOIP_ASN_URL = "https://geoip.example/dbip-asn-lite-{year}-{month}.mmdb.gz"
    fw = Named(capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW), fetch=Downloads({}))
    assert [f["title"] for f in fw.world()["forms"]] == ["Update the ASN file"]
    with pytest.raises(ValueError, match="offers no ASN file"):
        Walled(capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW)).world_asn(True)
    fw.detach()


# -- 1.102.0 (Monday list item 20): the hosts a source names, and failures in fixed words ----------------------------------
KEYED = "https://maker.example/data/lite.mmdb"


@pytest.mark.usefixtures("no_outside")
def test_a_redirect_goes_to_a_host_the_plugin_names_and_nowhere_else():
    signed = "https://storage.example/signed/lite.mmdb?X-Sig=abc"
    web = Web({KEYED: (302, {"Location": signed}, b"moved"), signed: (200, {}, b"the file")})
    got = FETCH_URL(KEYED, 5, handlers=(web,), hosts=("storage.example",))
    assert got.read() == b"the file" and web.asked == [KEYED, signed] and web.bodies[0].reads == 0
    elsewhere = "https://other.example/signed/lite.mmdb?X-Sig=abc"
    web = Web({KEYED: (302, {"Location": elsewhere}, b"moved"), elsewhere: (200, {}, b"the file")})
    with pytest.raises(RedirectRefused) as refused:
        FETCH_URL(KEYED, 5, handlers=(web,), hosts=("storage.example",))
    said = str(refused.value)
    assert "https://other.example" in said and "X-Sig" not in said and "/signed/" not in said
    assert web.asked == [KEYED]  # never asked
    # with no hosts named (the infrastructure's data sets), the same host alone, as before
    web = Web({KEYED: (302, {"Location": signed}, b"moved"), signed: (200, {}, b"the file")})
    with pytest.raises(RedirectRefused, match="maker.example alone"):
        FETCH_URL(KEYED, 5, handlers=(web,))
    assert web.asked == [KEYED]


@pytest.mark.usefixtures("no_outside")
def test_the_answers_host_is_checked_against_the_same_hosts():
    class Moved(io.BytesIO):
        def __init__(self, data, where):
            super().__init__(data)
            self.where = where

        def geturl(self):
            return self.where
    assert world._came_from(Moved(b"", "https://storage.example/x?t=1"), KEYED, ("storage.example",)).startswith(
        "https://storage.example/")
    with pytest.raises(geo.GeoError) as refused:
        world._came_from(Moved(b"", "https://other.example/x?token=Secret_123456"), KEYED, ("storage.example",))
    assert "Secret_123456" not in str(refused.value) and "other.example" in str(refused.value)
    with pytest.raises(geo.GeoError, match="an address that is none"):
        world._came_from(Moved(b"", "not an address ?token=Secret_123456"), KEYED, ("storage.example",))
    assert world._site("no host ?token=Secret_123456") == "an address that is none"


@pytest.mark.usefixtures("no_outside")
def test_a_keyed_downloads_failure_is_said_in_fixed_words():
    def answered(code, url):
        return urllib.error.HTTPError(url, code, "words of the server's own", {}, io.BytesIO(b""))
    canary = "Canary_Token-0123456789"
    keyed = f"{KEYED}?token={canary}"
    own = ("maker.example",)
    assert "the key was refused" in world._fixed(answered(401, keyed), keyed, own)
    assert "the key was refused" in world._fixed(answered(403, keyed), keyed, own)
    storage = world._fixed(answered(403, f"https://storage.example/x?sig={canary}"), keyed, own)
    assert "storage host refused the signed address" in storage and "key" not in storage
    assert "storage.example" in storage
    assert "limit was reached" in world._fixed(answered(429, keyed), keyed, own)
    assert world._fixed(answered(500, keyed), keyed, own) == "HTTP 500 from maker.example: nothing was installed"
    tab = http.client.InvalidURL(f"URL can't contain control characters. '/data/lite.mmdb?token={canary}\\t'")
    for e in (tab, OSError(keyed), ValueError(repr(keyed)), geo.GeoError(keyed),
              RedirectRefused("it was sent on to https://other.example, and a GeoIP file comes over https from "
                              "maker.example alone")):
        said = world._fixed(e, keyed, own)
        assert canary not in said and "token" not in said and "?" not in said, said


# -- 1.102.0 (Monday list item 20): the view over GeoIP sources -----------------------------------------------------------
from liminal_libs.machines import geosources  # noqa: E402

SA = "https://creativecommons.org/licenses/by-sa/4.0/"
BY = "https://creativecommons.org/licenses/by/4.0/"
TOKEN = "Canary_Token-0123456789abcdef"
LITE = "https://maker.example/data/lite.mmdb"
SUMS = "https://maker.example/data/lite.mmdb/checksums"
SIGNED = "https://storage.example/signed/lite.mmdb?X-Sig=abc"
NETWORKS = [("81.2.69.0/24", {"asn": "AS20712", "as_name": "Andrews & Arnold Ltd"}),
            ("1.1.1.0/24", {"asn": "AS13335", "as_name": "Cloudflare, Inc."})]


def _licence(url, pair):
    return {"words": f"A summary. {geosources.pointer(url)}", "name": "CC", "pair": pair, "version": "CC 4.0",
            "url": url}


def source_dicts(offered=True, max_age=0):
    dbip = {"id": "dbip", "title": "DB-IP", "maker": "DB-IP", "hosts": ["geoip.example"], "files": [
        {"role": "places", "title": "City Lite", "url": URL, "packing": "mmdb.gz", "size": "about 60 MB",
         "licence": _licence(BY, "dbip-lite"), "credit": MARK},
        {"role": "networks", "title": "ASN Lite", "url": "https://geoip.example/dbip-asn-lite-{year}-{month}.mmdb.gz",
         "packing": "mmdb.gz", "size": "about 5 MB", "licence": _licence(BY, "dbip-asn-lite"), "credit": MARK}]}
    ipinfo = {"id": "ipinfo", "title": "IPinfo Lite", "maker": "IPinfo", "hosts": ["maker.example"],
              "keys": {"IPINFO_TOKEN": "token"}, "sends": "query", "query": "token", "offered": offered, "files": [
                  {"role": "networks", "title": "IPinfo Lite", "url": LITE, "packing": "mmdb", "shape": "ipinfo-lite",
                   "stem": "ipinfo-lite", "size": "about 24 MB", "sent_on": ["storage.example"],
                   "checksum": "ipinfo-checksums", "checksum_url": SUMS, "every_days": 7, "max_age_days": max_age,
                   "licence": _licence(SA, "ipinfo-lite"),
                   "credit": {"text": "IP address data powered by IPinfo", "url": "https://maker.example"}}]}
    return [dbip, ipinfo]


def sourced_view(folder, web=None, choice=None, wall=None, offered=True, max_age=0, fetch=None):
    read, refused = geosources.read(source_dicts(offered, max_age), ["IPINFO_TOKEN"])
    picked = choice if choice is not None else {}
    if fetch is None and web is not None:
        def fetch(url, timeout, hosts=()):
            return FETCH_URL(url, timeout, handlers=(web,), hosts=hosts)
    return WorldView("w", capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=wall or Clock(NOW),
                     fetch=fetch or (lambda url, timeout: (_ for _ in ()).throw(AssertionError(url))),
                     sources=(read, refused, lambda: picked))


def dbip_installed(folder):
    geo.install_mmdb(mmdb(PLACES, built=NOVEMBER), folder, "dbip-city-lite-2026-11")
    geo.install_mmdb(mmdb(NETWORKS, built=NOVEMBER, kind="DBIP-ASN-Lite"), geo.asn_folder(folder),
                     "dbip-asn-lite-2026-11")


def sums(data):
    import hashlib
    return json.dumps({"checksums": {"md5": "x", "sha1": "y", "sha256": hashlib.sha256(data).hexdigest()}}).encode()


@needs_reader
@pytest.mark.usefixtures("no_outside")
def test_a_source_not_offered_has_its_row_and_no_button(tmp_path):
    folder = tmp_path / "geoip"
    dbip_installed(folder)
    view = sourced_view(folder, offered=False)
    page = view.page(attribution=MARK, keys=set())
    table = page["tables"][-1]
    assert table["title"] == world.SOURCES_TITLE
    rows = {r[0]["text"]: r for r in table["rows"]}
    assert rows["IPinfo Lite"][3:] == ["not asked", "not offered: waiting for your word", "", "", ""]
    assert rows["City Lite"][4]["text"] == "built 2026-11-01; used for places"
    assert rows["City Lite"][5] == "" and rows["City Lite"][7]["title"] == "Remove…"
    ids = {f["id"] for f in page.get("forms", [])}
    assert not any("ipinfo" in i for i in ids) and "actions" not in page  # no Install the GeoIP file… either
    assert ids == {world.REMOVE_FORM + "dbip-places", world.REMOVE_FORM + "dbip-networks"}
    assert page["globe"]["origins"] == [] and view.stamp(view.geoip()) == "2026-11-01"  # the default pair's stamp
    view.close()


@needs_reader
@pytest.mark.usefixtures("no_outside")
def test_a_fixed_address_file_comes_by_its_checksum_and_is_named_from_its_build(tmp_path):
    folder = tmp_path / "geoip"
    dbip_installed(folder)
    data = mmdb(NETWORKS, built=NOVEMBER, kind="ipinfo lite")
    keyed, keyed_sums = f"{LITE}?token={TOKEN}", f"{SUMS}?token={TOKEN}"
    web = Web({keyed_sums: (200, {}, sums(data)), keyed: (302, {"Location": SIGNED}, b"moved"),
               SIGNED: (200, {"Content-Length": str(len(data))}, data)})
    view = sourced_view(folder, web, choice={"networks": "ipinfo"})
    rows = {r[0]["text"]: r for r in view.sources_table(keys={"IPINFO_TOKEN"})[0]["rows"]}
    assert rows["IPinfo Lite"][3] == "set in your login store" and rows["IPinfo Lite"][6]["title"] == "Download…"
    unset = {r[0]["text"]: r for r in view.sources_table(keys=set())[0]["rows"]}["IPinfo Lite"]
    assert unset[3]["text"] == "not set in your login store" and unset[6] == ""
    lines = []
    out = view.get("ipinfo", "networks", {"IPINFO_TOKEN": TOKEN}, log=lines.append)
    assert web.asked == [keyed_sums, keyed, SIGNED]
    path = folder / "ipinfo" / "asn" / "ipinfo-lite-2026-11-01.mmdb"
    assert out["ok"] and out["said"] == f"installed {path.name}" and path.exists()
    notes = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
    assert set(notes) == {"source", "role", "sha256", "installed"} and TOKEN not in json.dumps(notes)
    assert TOKEN not in json.dumps([out, lines]) and any("storage.example" in line for line in lines)
    g = view.geoip()  # the chosen networks file, read beside DB-IP's places
    assert g.lookup("81.2.69.142").asn == 20712 and view.stamp(g) == "#dbip:2026-11-01+ipinfo:2026-11-01"
    assert view.credits()["networks"]["text"] == "IP address data powered by IPinfo"
    again = view.get("ipinfo", "networks", {"IPINFO_TOKEN": TOKEN})
    assert "installed already" in again["said"] and web.asked[-1] == keyed_sums and len(web.asked) == 4
    view.close()


@needs_reader
@pytest.mark.usefixtures("no_outside")
def test_a_checksum_that_is_not_the_makers_downloads_nothing(tmp_path):
    folder = tmp_path / "geoip"
    for answer in (b"{\"checksums\": {\"sha256\": NaN}}", b"not json", b"{\"checksums\": {}}", b"x" * 5000):
        web = Web({f"{SUMS}?token={TOKEN}": (200, {}, answer)})
        view = sourced_view(folder, web)
        with pytest.raises(geo.GeoError, match="nothing was downloaded|not installed"):
            view.get("ipinfo", "networks", {"IPINFO_TOKEN": TOKEN})
        assert web.asked == [f"{SUMS}?token={TOKEN}"] and not (folder / "ipinfo").exists()
        view.close()


@pytest.mark.usefixtures("no_outside")
def test_a_key_never_reaches_an_error_its_cause_or_its_lines(tmp_path):
    folder = tmp_path / "geoip"
    from urllib.parse import quote, quote_plus

    def refusing(url, timeout, hosts=()):
        raise http.client.InvalidURL(f"URL can't contain control characters. {url.partition('?')[2] + chr(9)!r} {url}")

    def denied(url, timeout, hosts=()):
        raise urllib.error.HTTPError(url, 401, f"no: {url}", {}, io.BytesIO(b""))
    for fetch, words in ((refusing, "failed (InvalidURL)"), (denied, "the key was refused")):
        lines = []
        view = sourced_view(folder, fetch=fetch)
        with pytest.raises(geo.GeoError) as e:
            view.get("ipinfo", "networks", {"IPINFO_TOKEN": TOKEN}, log=lines.append)
        said = " ".join([f"{type(e.value).__name__}: {e.value}", repr(e.value), *lines])
        for form in (TOKEN, quote(TOKEN, safe=""), quote_plus(TOKEN)):
            assert form not in said
        assert words in str(e.value)
        assert e.value.__cause__ is None and e.value.__context__ is None
        view.close()


@needs_reader
@pytest.mark.usefixtures("no_outside")
def test_cancel_installs_nothing_and_one_download_runs_at_a_time(tmp_path):
    folder = tmp_path / "geoip"
    data = mmdb(NETWORKS, built=NOVEMBER)
    web = Web({f"{SUMS}?token={TOKEN}": (200, {}, sums(data)), f"{LITE}?token={TOKEN}": (200, {}, data)})
    view = sourced_view(folder, web)
    with pytest.raises(geo.GeoError, match="cancelled"):
        view.get("ipinfo", "networks", {"IPINFO_TOKEN": TOKEN}, cancel=lambda: True)
    assert not list((folder / "ipinfo" / "asn").glob("*.mmdb")) if (folder / "ipinfo" / "asn").exists() else True
    assert view._installing.acquire(blocking=False)
    try:
        with pytest.raises(ValueError, match="being downloaded already"):
            view.get("ipinfo", "networks", {"IPINFO_TOKEN": TOKEN})
        with pytest.raises(ValueError, match="being downloaded"):
            view.remove("ipinfo", "networks")
    finally:
        view._installing.release()
    view.close()


@needs_reader
@pytest.mark.usefixtures("no_outside")
def test_a_choice_falls_back_to_the_default_and_says_why(tmp_path):
    folder = tmp_path / "geoip"
    dbip_installed(folder)
    view = sourced_view(folder, choice={"networks": "ipinfo", "places": "nobody"})
    chosen = view.chosen()
    assert chosen["networks"]["source"] == "dbip" and "IPinfo Lite is not installed" in chosen["networks"]["words"]
    assert chosen["places"]["source"] == "dbip" and "nobody gives no places file" in chosen["places"]["words"]
    assert view.stamp(view.geoip()) == "2026-11-01"
    table = view.sources_table(keys=set())[0]
    assert "IPinfo Lite is not installed, so ASN Lite is used for networks" in table["note"]
    off = sourced_view(tmp_path / "other", choice={"networks": "ipinfo"}, offered=False)
    geo.install_mmdb(mmdb(NETWORKS), off.file_folder("ipinfo", "networks"), "ipinfo-lite-2026-11-01")
    assert off.chosen()["networks"]["source"] is None  # a source not offered: its file stays, unread
    view.close()
    off.close()


@needs_reader
@pytest.mark.usefixtures("no_outside")
def test_a_file_past_its_days_is_let_go_at_the_next_ask_without_reading_it(tmp_path, monkeypatch):
    folder = tmp_path / "geoip"
    dbip_installed(folder)
    wall = Clock(NOVEMBER + 86400)
    view = sourced_view(folder, choice={"networks": "ipinfo"}, wall=wall, max_age=30)
    geo.install_mmdb(mmdb(NETWORKS, built=NOVEMBER, kind="ipinfo lite"), view.file_folder("ipinfo", "networks"),
                     "ipinfo-lite-2026-11-01")
    g = view.geoip()
    assert g.asn.describe()["file"] == "ipinfo-lite-2026-11-01.mmdb" and view.stamp(g).endswith("+ipinfo:2026-11-01")
    opened = []
    real = geo._opened
    monkeypatch.setattr(geo, "_opened", lambda *a, **k: opened.append(a[0]) or real(*a, **k))
    assert view.geoip() is g and opened == []  # asked again: no file read for the check
    wall.t = NOVEMBER + 30 * 86400
    view._geo_looked = None
    again = view.geoip()
    assert again is not g and g.describe()["open"] is False  # let go at once
    assert again.asn.describe()["file"] == "dbip-asn-lite-2026-11.mmdb"  # the default's, by the fallback
    rows = {r[0]["text"]: r for r in view.sources_table(keys={"IPINFO_TOKEN"})[0]["rows"]}
    assert "too old" in rows["IPinfo Lite"][4]["sub"] and rows["IPinfo Lite"][5] == ""  # no Use… for it
    view.close()


@needs_reader
@pytest.mark.usefixtures("no_outside")
def test_a_removal_takes_the_file_and_its_notes_or_says_it_could_not(tmp_path, monkeypatch):
    folder = tmp_path / "geoip"
    dbip_installed(folder)
    view = sourced_view(folder, choice={"networks": "ipinfo"})
    path = geo.install_mmdb(mmdb(NETWORKS), view.file_folder("ipinfo", "networks"), "ipinfo-lite-2026-11-01")
    path.with_suffix(".json").write_text("{}", encoding="utf-8")
    assert view.geoip().asn.path == path
    monkeypatch.setattr(geo, "_remove", lambda p: False)
    out = view.remove("ipinfo", "networks")
    assert out["ok"] is False and "could not be removed" in out["said"] and path.exists()
    assert view.geoip().asn.path.name == "dbip-asn-lite-2026-11.mmdb"  # unread meanwhile
    monkeypatch.undo()
    out = view.remove("ipinfo", "networks")
    assert out["ok"] is True and not path.exists() and not path.with_suffix(".json").exists()
    assert view.remove("ipinfo", "networks")["said"] == "IPinfo Lite is not installed here"
    view.close()


def test_the_sources_forms_say_what_goes_where():
    read, _ = geosources.read(source_dicts(), ["IPINFO_TOKEN"])
    ipinfo = read[1]
    f = ipinfo.file("networks")
    get = world.get_form(ipinfo, f, "C:/data/geoip/ipinfo/asn")
    assert get["hook"] == world.GEOIP_GET_HOOK and get["job"] is True
    assert [x["name"] for x in get["fields"]] == ["source", "role", ACCEPT_LICENCE]
    words = get["confirm"]["words"]
    assert "maker.example" in words and "storage.example" in words and "IPINFO_TOKEN goes to maker.example alone" in words
    assert f.licence.words in words and TOKEN not in json.dumps(get)
    remove = world.remove_form(ipinfo, f, "C:/data/geoip/ipinfo/asn")
    assert remove["fields"][-1]["name"] == world.ACCEPT_REMOVAL == geosources.RemovalRefused.accept
    use = world.use_form(ipinfo, f)
    assert use["hook"] == world.GEOIP_USE_HOOK and use["id"] == world.USE_FORM + "ipinfo-networks"
    for made in (get, remove, use):
        assert json.loads(json.dumps(made, allow_nan=False)) == made
