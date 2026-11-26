"""What a firewall offers the World Wide Web plugin (1.105.0, Monday list item 33: the tab is
plugin-platform-worldwideweb's, and what only a firewall knows it asks through the platform): the socket table's reading
(netstat_seen), the hosts database's answers (hosts_found, hosts_routes), the changes only another plugin may ask
(hosts_keep_route, hosts_keep_places, hosts_clear_places) and the rules covering a port (rules_covering). Each refuses
on a machine the plugin is not for. Beside them, a NetstatView in the globe's mode (records=False) records nothing, and
the hosts database names the hosts its next `place` would look up (HostBook.unplaced_hosts, place's `only`).

Nothing real is read: the socket table is a stand-in, and the hosts database is in the test's own folder."""
from __future__ import annotations

import json

import pytest

from liminal_libs import hostbook, internal
from liminal_libs.apps import asking
from liminal_libs.machines import firewall as firewall_module
from liminal_libs.machines.firewall import Rule
from liminal_libs.machines.netstat import NetstatView

from test_firewall import FakeFirewall
from test_netstat import LONDON, NOW, NOWHERE, PLACES, V6WEB, WEB, WEB2, Clock, reading

pytestmark = pytest.mark.usefixtures("no_outside")


class Netted(FakeFirewall):
    """A stand-in firewall reading a stand-in socket table into the test's own hosts database."""

    name = "netted-firewall"

    def __init__(self, rows=None, **kw):
        super().__init__(**kw)
        self.clock, self.readings, self.rows = Clock(), 0, rows

    def make_netstat_view(self) -> NetstatView:
        def reader():
            self.readings += 1
            return reading(self.rows)
        return NetstatView(self.name, reader=reader, names={}, clock=self.clock, wall=lambda: NOW)


def test_the_services_are_declared_hooks_and_sound():
    fw = Netted()
    hooks = set(fw.interface()["hooks"])
    assert set(firewall_module.SERVICES) <= hooks and internal.problems(fw) == []
    assert set(internal.declared(fw, "SERVICE_HOOKS")) >= set(firewall_module.SERVICES)
    assert set(internal.declared(fw, "READ_HOOKS")) >= set(firewall_module.SERVICE_READS)
    assert set(internal.plugin_only(fw)) == set(firewall_module.SERVICE_CHANGES)
    for change in firewall_module.SERVICE_CHANGES:  # never the page's, never the plugin's own
        assert "only by another plugin" in asking.refusal(fw, change, asking.PAGE)
        assert asking.refusal(fw, change, "worldwideweb") == ""
    for read in firewall_module.SERVICE_READS:
        assert asking.refusal(fw, read, asking.PAGE) == ""


def test_the_reading_is_the_netstat_tabs_and_plain_json():
    fw = Netted()
    seen = fw.netstat_seen()
    assert json.loads(json.dumps(seen)) == seen and seen["error"] == ""
    remotes = {r["remote"] for r in seen["rows"] if r.get("remote")}
    assert {WEB, V6WEB} <= remotes and fw.readings == 1
    assert fw.netstat_seen()["rows"] == seen["rows"] and fw.readings == 1  # one reading shared, as the tabs share it
    assert fw.netstat_view().book.describe()["rows"] >= 2  # fed to the hosts database: recorded, as a tab shown is


def test_the_hosts_found_answer_what_the_hosts_view_asks():
    fw = Netted()
    fw.netstat_seen()
    fw.netstat_view().book.flush()
    facts = fw.hosts_found("describe")
    assert facts["mode"] == "shown" and facts["elsewhere"] == "" and facts["rows"] >= 2
    assert fw.hosts_found("changes") == facts["changes"]
    assert fw.hosts_found("unplaced", {"stamp": "2026-11"}) >= 2
    hosts = fw.hosts_found("unplaced_hosts", {"stamp": "2026-11"})
    assert set(hosts) >= {WEB, V6WEB} and len(hosts) == len(set(hosts))
    drawn, rest = fw.hosts_found("places", {"most": 10})
    assert isinstance(drawn, list) and isinstance(rest, dict)
    assert {p["program"] for p in fw.hosts_found("programs", {"limit": 5})} >= {"msedge.exe"}
    assert fw.hosts_found("ports", {"proto": "tcp", "port": 443})[0]["port"] == 443
    assert {h["host"] for h in fw.hosts_found("hosts", {"direction": "out"})} >= {WEB, V6WEB}
    assert fw.hosts_found("sums", {"program": "msedge.exe"})["hosts"] >= 2
    for bad, query in (("drop", None), ("hosts", {"sql": "x"})):
        with pytest.raises(ValueError):
            fw.hosts_found(bad, query)


def test_places_handed_in_are_kept_for_those_hosts_alone():
    fw = Netted()
    fw.netstat_seen()
    book = fw.netstat_view().book
    book.flush()
    asked = fw.hosts_found("unplaced_hosts", {"stamp": "2026-11"})
    london = {"country": LONDON.country, "country_name": LONDON.country_name, "city": LONDON.city,
              "lat": LONDON.lat, "lon": LONDON.lon}
    said = fw.hosts_keep_places("2026-11", {WEB: london})  # V6WEB not handed: left for a later call
    assert said == {"ok": True, "placed": 1}
    left = fw.hosts_found("unplaced_hosts", {"stamp": "2026-11"})
    assert WEB not in left and V6WEB in left and set(left) < set(asked)
    placed = {h["host"]: h for h in fw.hosts_found("hosts", {})}
    assert placed[WEB]["city"] == "London"
    assert fw.hosts_clear_places("places", "2026-11%")["ok"] is True
    with pytest.raises(ValueError):
        fw.hosts_keep_places("2026-11", [WEB])
    with pytest.raises(ValueError):
        fw.hosts_clear_places("everything", "%")


def test_a_route_is_kept_and_read_back():
    fw = Netted()
    fw.netstat_seen()
    hops = [{"n": 1, "address": "192.168.1.1", "ms": 1.0}, {"n": 2, "address": WEB, "ms": 12.0, "label": "London"}]
    assert fw.hosts_keep_route(WEB, NOW, True, "icmp", hops, "London") == {"ok": True}
    fw.netstat_view().book.flush()
    assert fw.hosts_routes() == [WEB]
    routes = fw.hosts_routes([WEB, NOWHERE])
    assert list(routes) == [WEB] and routes[WEB][-1]["hops"][1]["address"] == WEB
    for bad in ((WEB, NOW, True, "icmp", "not hops", ""), ("", NOW, True, "icmp", hops, ""),
                (WEB, "now", True, "icmp", hops, ""), (WEB, NOW, True, "icmp", [{}] * 65, "")):
        with pytest.raises(ValueError):
            fw.hosts_keep_route(*bad)
    with pytest.raises(ValueError):
        fw.hosts_routes("not a list")


def test_the_rules_covering_a_port():
    fw = Netted()
    fw.rules = {"web": Rule("web", ports=(443,), protocol="tcp"), "dns": Rule("dns", ports=(53,), protocol="udp"),
                "all": Rule("Every port", owned=False, protocol="any")}
    covering = fw.rules_covering(443)
    assert [r["name"] for r in covering] == ["web", "Every port"]
    assert covering[0]["why"] == "port 443/tcp" and covering[1]["why"] == "every port"
    assert [r["name"] for r in fw.rules_covering(53, "udp")] == ["dns", "Every port"]
    for bad in ((0,), ("443",), (True,), (443, "icmp")):
        with pytest.raises(ValueError):
            fw.rules_covering(*bad)


def test_every_service_refuses_where_the_plugin_is_not_for(monkeypatch):
    fw = Netted()
    monkeypatch.setattr(fw, "not_for_here", lambda: "for a native Linux machine")
    for hook, args in (("netstat_seen", ()), ("hosts_found", ("describe",)), ("hosts_routes", ()),
                       ("hosts_keep_route", (WEB, NOW, True, "icmp", [], "")), ("hosts_keep_places", ("x", {})),
                       ("hosts_clear_places", ("places", "x%")), ("rules_covering", (443,))):
        with pytest.raises(ValueError, match="not for this machine"):
            getattr(fw, hook)(*args)
    assert fw.readings == 0 and fw.__dict__.get("_netstat") is None  # nothing read, no view made


def test_the_globes_mode_records_nothing_and_says_who_does():
    asked = []

    class Via:
        owner = "firewall-windows"
        changes = 0

        def mode(self):
            return "always"

        def elsewhere(self):
            return ""

        def flush(self, keep_open=False):
            asked.append("flush")

    def reader():
        asked.append("read")
        return {"reading": {"system": "windows", "at": NOW}, "rows": [{"remote": WEB, "where": "internet"}], "error": ""}
    clock = Clock()
    view = NetstatView("worldwideweb", reader=reader, book=Via(), records=False, clock=clock, wall=lambda: NOW)
    seen = view.touch()
    assert seen["rows"] == [{"remote": WEB, "where": "internet"}] and seen["error"] == ""
    assert view.touch() == seen and asked == ["read"]  # kept READ_S, as a reading is
    assert view.mode() == "always" and view.elsewhere() == ""
    view.follow()
    assert not view.recording() and view._thread is None
    for refused in (lambda: view.set_mode("always"), lambda: view.forget(True)):
        with pytest.raises(ValueError, match="recorded by firewall-windows"):
            refused()
    clock.t += 60

    def broken():
        raise LookupError("no firewall")
    view._reader = broken
    again = view.touch()
    assert again["rows"] == seen["rows"] and "no firewall" in again["error"]  # the last one kept, and why


def test_the_hosts_a_place_would_take(tmp_path):
    book = hostbook.HostBook(tmp_path / "hosts.db", clock=lambda: NOW)
    from liminal_libs import sockets
    rows = sockets.judge(reading(), names={})
    book.feed(rows, NOW, starts=True)
    book.flush()
    hosts = book.unplaced_hosts("2026-11")
    assert set(hosts) >= {WEB, V6WEB} and book.unplaced_hosts("2026-11", most=0) == []
    assert book.place(PLACES.get, "2026-11", only={WEB}) >= 1
    assert WEB not in book.unplaced_hosts("2026-11") and V6WEB in book.unplaced_hosts("2026-11")
    assert WEB2 not in hosts or WEB2 in book.unplaced_hosts("2026-11")  # only WEB was placed
