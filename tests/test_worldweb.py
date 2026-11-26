"""The World Wide Web tab as a plugin's base of its own (1.105.0, liminal_libs.machines.worldweb, Monday list item 33),
over a real app (apps.App) with a stand-in firewall attached beside it: the firewall serving the tab is the one named by
LIMINAL_WWW_FIREWALL, else the first that answers, chosen again after a refusal; with none, the tab draws the traffic
captured alone and says why; the hosts view runs through hostsvia.HostsVia, the routes are kept in the firewall's hosts
database, and Linux's words on what an XDP program drops come from the firewall; no lock of either plugin is held while
the other is asked; `places` caps its input and places nothing private; a firewall's Netstat tab places its hosts
through PlacesVia; the settings keep their names; internal.problems is empty.

Nothing real is reached (test_world's guard: no capture, no route asked, no name server, no download); the socket table
is a stand-in and the hosts database is in the test's own folder."""
from __future__ import annotations

import json
import threading

import pytest

from liminal_libs import internal
from liminal_libs.apps import App, asking
from liminal_libs import sockets
from liminal_libs.machines import firewall as firewall_module, routes as routes_module, worldweb
from liminal_libs.machines.hostsvia import GeoVia, HostsVia, PlacesVia
from liminal_libs.machines.firewall import Rule
from liminal_libs.machines.netstat import NetstatView
from liminal_libs.machines.standins import login as standin_login
from liminal_libs.machines.world import HOME_PLACE_VAR, WorldView
from liminal_libs.machines.worldweb import FIREWALL_VAR, NO_FIREWALL, WorldWideWeb
from liminal_libs.sources.conformance import problems
from liminal_libs.traffic import TrafficBook

from test_firewall import FakeFirewall
from test_netstat import LONDON, NOW as NET_NOW, V6WEB, WEB, Clock as NetClock, reading
from test_world import NOW, Clock, Feed, _nothing_real, geo_folder, traffic_of  # noqa: F401 - the guard and the files
from test_geo import needs_reader

pytestmark = pytest.mark.usefixtures("no_outside")


class Wall(FakeFirewall):
    """A stand-in firewall over a stand-in socket table, its hosts database in the test's own folder. `held`: a lock
    a service hook holds while it answers (so a test sees whether the World Wide Web plugin waits on one of its own)."""

    def __init__(self, name="stand-in-wall", refuse="", unseen=""):
        super().__init__()
        self.name, self.refuse, self.unseen, self.readings = name, refuse, unseen, 0
        self.held = threading.Lock()
        self.asked_while: list[bool] = []

    def make_netstat_view(self) -> NetstatView:
        def reader():
            self.readings += 1
            return reading()
        return NetstatView(self.name, reader=reader, names={}, clock=NetClock(), wall=lambda: NET_NOW)

    def netstat_seen(self) -> dict:
        """The socket table's reading now, as the Netstat tab has it (the stand-in's)."""
        if self.refuse:
            raise ValueError(f"not for this machine: {self.refuse}")
        with self.held:
            web = self.app._plugins.get("www") if getattr(self, "app", None) else None
            self.asked_while.append(bool(web is not None and web.locked()))
            return super().netstat_seen()


class LinuxWall(Wall):
    HOOKS = (*Wall.HOOKS, worldweb.UNSEEN_HOOK)
    READ_HOOKS = (worldweb.UNSEEN_HOOK,)
    SERVICE_HOOKS = (worldweb.UNSEEN_HOOK,)

    def capture_unseen(self, address) -> str:
        """What an XDP program drops before the capture sees it at the adapter of `address` (the stand-in's)."""
        return self.unseen if address else ""


class Web(WorldWideWeb):
    """The plugin under test, watching through the test's stand-ins: its capture Feed's, its GeoIP files the test's."""

    name = "www"
    title = "World Wide Web"
    about = "the traffic at this machine's adapter on a globe"
    api = "2.1"
    order = 960

    def __init__(self, folder=None, **view):
        self.view = {"capture_factory": Feed, "clock": Clock(), "wall": Clock(NOW), "book": TrafficBook(clock=lambda: 50.0),
                     "resolve": lambda version, servers: (None, "no name server answers in a test"), **view}
        if folder is not None:
            self.view["geo_folder"] = folder
        self.lock = threading.Lock()

    def present(self) -> bool:
        return True

    def locked(self) -> bool:
        return worldweb._WORLD_LOCK.locked() or worldweb._NETSTAT_LOCK.locked() or self.lock.locked()

    def make_world_view(self) -> WorldView:
        return WorldView(self.name, **self.view)

    def make_world_routes(self) -> routes_module.Routes:
        """The base's Routes, its tracer a stand-in and its work never started: nothing is traced."""
        self.traced = []
        return routes_module.Routes(tracer=self.traced.append, start=lambda work: None, keep=self._keep_route,
                                    known=self._routed, stored=self._stored_routes)


class Frame(App):
    NAME = "frame"


def framed(*firewalls, pairs=None, folder=None):
    app = Frame(log=lambda m: None, login=standin_login(pairs))
    for fw in firewalls:
        app.attach(fw)
    web = Web(folder)
    app.attach(web)
    return app, web


def page_ask(app, name, hook, *args):
    with asking.asking(asking.PAGE):
        return app.ask(name, hook, *args)


def test_it_declares_its_tab_its_asks_and_its_service_soundly():
    web = Web()
    assert problems(web) == [] and internal.problems(web) == []
    assert [t.id for t in web.TABS] == ["world"] and web.TABS[0].every == 2.0
    assert (web.ICON, web.SECTION) == ("globe", "os")
    assert set(internal.declared(web, "SERVICE_HOOKS")) == {"places"}
    assert {row[1] for row in web.ASKS} >= {"netstat_seen", "hosts_found", "hosts_keep_route", "capture_unseen",
                                          "rules_covering"}
    assert all(row[0] == "" for row in web.ASKS)  # whichever firewall offers it
    assert [k.name for k in web.keys] == [HOME_PLACE_VAR, firewall_module.WATCH_VAR, FIREWALL_VAR]


def test_the_firewall_serving_it_is_the_first_that_answers_and_another_after_a_refusal(monkeypatch):
    monkeypatch.setattr(sockets, "READ_S", 0.0)  # each ask reads anew
    first, second = Wall("first-wall", refuse="for a native Linux machine"), Wall("second-wall")
    app, web = framed(first, second)
    assert web.firewalls() == ["first-wall", "second-wall"] and web.firewall() == ""
    page = page_ask(app, "www", "world")
    assert web.firewall() == "second-wall" and second.readings == 1 and NO_FIREWALL not in page["note"]
    first.refuse, second.refuse = "", "gone"
    page_ask(app, "www", "world")  # the one serving refuses now: the other is asked, and serves from then on
    assert web.firewall() == "first-wall"


def test_a_firewall_named_by_the_setting_serves_first():
    first, second = Wall("first-wall"), Wall("second-wall")
    app, web = framed(first, second, pairs={FIREWALL_VAR: "second-wall"})
    assert web.firewalls() == ["second-wall", "first-wall"]
    page_ask(app, "www", "world")
    assert web.firewall() == "second-wall" and first.readings == 0


def test_with_no_firewall_the_tab_draws_the_traffic_alone_and_says_why():
    app, web = framed()
    page = page_ask(app, "www", "world")
    assert page["title"] == "World Wide Web" and NO_FIREWALL in page["note"]
    assert web.firewall() == "" and "globe" in page
    page_ask(app, "www", "world_show", "hosts")
    again = page_ask(app, "www", "world")  # no hosts recorded to show: the traffic, and why
    assert NO_FIREWALL in again["note"] and web.netstat_view().shows() == "traffic"


def test_no_lock_of_the_plugin_is_held_while_a_firewall_is_asked():
    wall = Wall()
    app, web = framed(wall)
    page_ask(app, "www", "world")
    page_ask(app, "www", "world_show", "hosts")
    page_ask(app, "www", "world")
    assert wall.asked_while and not any(wall.asked_while)


def test_the_hosts_view_runs_through_the_firewalls_hosts_database():
    wall = Wall()
    app, web = framed(wall)
    page_ask(app, "www", "world")  # the reading recorded there
    wall.netstat_view().book.flush()
    page_ask(app, "www", "world_show", "hosts")
    page = page_ask(app, "www", "world")
    assert isinstance(web.netstat_view().book, HostsVia) and web.netstat_view().records is False
    assert page["globe"]["showing"].startswith("Hosts recorded")
    titles = [t.get("title") for t in page["tables"]]
    assert "What the globe shows" in titles
    assert "recorded only while" in page["note"] and "hosts recorded" in page["note"]
    with pytest.raises(ValueError, match="recorded by stand-in-wall"):
        web.netstat_view().forget(True)


def test_a_route_traced_is_kept_in_the_firewalls_hosts_database():
    wall = Wall()
    app, web = framed(wall)
    page_ask(app, "www", "world")  # the firewall chosen
    hops = [{"n": 1, "address": "192.168.1.1", "ms": 1.0}, {"n": 2, "address": WEB, "ms": 9.0}]
    web._keep_route(WEB, NET_NOW, True, "icmp", hops, "London")
    wall.netstat_view().book.flush()
    assert web._routed() == {WEB} and WEB in web._stored_routes([WEB])


def test_linuxs_words_on_what_the_capture_cannot_see_come_from_the_firewall(monkeypatch):
    wall = LinuxWall(unseen="An XDP program at eth0 drops packets before the capture sees them.")
    app, web = framed(wall)
    page_ask(app, "www", "world")
    view = web.world_view()
    monkeypatch.setattr(view, "address", "192.168.1.20")
    page = page_ask(app, "www", "world")
    assert page["note"].endswith("An XDP program at eth0 drops packets before the capture sees them.")


@needs_reader
def test_places_are_capped_and_nothing_private_is_placed(geo_folder):
    app, web = framed(folder=geo_folder)
    got = web.places(["81.2.69.142", "192.168.1.20", "127.0.0.1", "not an address", 7])
    assert got["stamp"] and got["why"] == ""
    assert got["places"]["81.2.69.142"]["city"] == "London"
    assert got["places"]["192.168.1.20"] is None and got["places"]["127.0.0.1"] is None
    assert got["places"]["not an address"] is None and 7 not in got["places"]
    assert json.loads(json.dumps(got)) == got
    many = web.places([f"81.2.69.{i % 250}" for i in range(5000)] + [f"1.2.{i // 250}.{i % 250}" for i in range(3000)])
    assert len(many["places"]) <= worldweb.PLACES_MOST
    with pytest.raises(ValueError):
        web.places("81.2.69.142")


def test_without_a_geoip_file_nothing_is_placed_and_why(tmp_path):
    app, web = framed(folder=tmp_path / "none")
    got = web.places(["81.2.69.142"])
    assert got["places"] == {} and got["stamp"] == "" and "no GeoIP file" in got["why"]


def test_a_firewalls_netstat_places_through_placesvia():
    asked = []

    def ask(addresses):
        asked.append(list(addresses))
        return {"places": {WEB: {"country": "GB", "country_name": "United Kingdom", "city": "London", "lat": 51.5,
                                 "lon": -0.09}}, "stamp": "2026-11", "why": ""}
    via = PlacesVia(ask, lambda: [WEB, V6WEB])
    geoip = via.geoip()
    assert isinstance(geoip, GeoVia) and via.geoip() is geoip and asked == [[WEB, V6WEB]]  # one ask a page
    assert geoip.lookup(WEB).city == "London" and geoip.lookup(V6WEB) is None and via.stamp(geoip) == "2026-11"
    assert geoip.known == {WEB}
    none = PlacesVia(lambda a: {"places": {}, "stamp": "", "why": "no GeoIP file"}, [WEB])
    assert none.geoip() is None and none.why == "no GeoIP file"

    def refused(addresses):
        raise LookupError("no plugin 'worldwideweb' is attached")
    gone = PlacesVia(refused, [WEB])
    assert gone.geoip() is None and "worldwideweb" in gone.why


def test_hostsvia_answers_nothing_with_no_firewall_and_says_why():
    def ask(hook, *args):
        raise LookupError(NO_FIREWALL)
    via = HostsVia(ask, lambda: "")
    assert via.places(most=10) == ([], {}) and via.programs() == [] and via.hosts() == [] and via.routed() == set()
    assert via.describe()["rows"] == 0 and NO_FIREWALL in via.describe()["problem"]
    assert via.unplaced("2026-11") == 0 and via.place(lambda h: LONDON, "2026-11") == 0 and via.changes == -1
    via.keep_route(WEB, NET_NOW, True, "icmp", [], "")  # not kept: said, never raised
    assert NO_FIREWALL in via.problem
    with pytest.raises(ValueError, match="the firewall"):
        via.forget()


def test_the_settings_keep_their_names_and_are_read_through_the_same_login():
    lone = Web()
    lone.login = standin_login({firewall_module.WATCH_VAR: "always"})  # as kept for a firewall's tab until 1.105.0
    assert lone.world_watch_mode(fresh=True) == "always"  # read here as it was, by its own name
    wall = Wall()
    app, web = framed(wall, pairs={HOME_PLACE_VAR: "-33.87,151.21,Sydney"})
    page = page_ask(app, "www", "world")
    assert page["globe"]["home"]["label"] == "Sydney"
    web.detach()


def ports_page(*keys):
    """A page as the tab draws it: Busiest ports here with a pick for each key (here:<port>/<proto>, None for none)."""
    return {"tables": [{"title": "Busiest ports here", "rows": [[k or "more"] for k in keys],
                        "details": [{"key": k, "title": k, "facts": [], "sections": [{"title": "Counted", "facts": []}]}
                                    if k else None for k in keys]},
                       {"title": "Ports elsewhere", "rows": [["443/tcp"]], "details": [{"key": "there:443/tcp", "title": "x"}]}]}


def test_a_port_picked_is_told_the_firewall_rules_covering_it(monkeypatch):
    """Monday list item 31: the busiest ports here are each told, in their pick, the serving firewall's rules covering
    them (rules_covering, asked through the platform), those naming the port first; a port no rule covers says so; the
    far end's ports are not asked (a firewall's rules cover this machine's ports)."""
    wall = Wall()
    wall.rules = {"web": Rule("web", ports=(443,), protocol="tcp"),
                  "all": Rule("Every port", owned=False, protocol="any", action="block")}
    app, web = framed(wall)
    page_ask(app, "www", "world")  # the firewall serving chosen
    asked = []
    real = worldweb.asks.ask
    monkeypatch.setattr(worldweb.asks, "ask", lambda me, name, hook, *a: (asked.append((name, hook, a)), real(me, name, hook, *a))[1])
    page = ports_page("here:443/tcp", "here:22/tcp", None)
    web._rules_onto(page)
    d443, d22 = page["tables"][0]["details"][:2]
    told = d443["sections"][-1]
    assert told["title"] == "Firewall rules covering it (2, stand-in-wall)"
    assert [f[0] for f in told["facts"]] == [r["label"] or r["name"] for r in wall.rules_covering(443)]
    assert told["facts"][1][0] == "Every port" and "Liminal's" in told["facts"][0][1]
    assert "port 443/tcp" in told["facts"][0][1] and "block" in told["facts"][1][1] and "every port" in told["facts"][1][1]
    assert [f[0] for f in d22["sections"][-1]["facts"]] == ["Every port"]
    assert "sections" not in page["tables"][1]["details"][0]
    assert [(n, h, a) for n, h, a in asked] == [("stand-in-wall", "rules_covering", (443, "tcp")),
                                                ("stand-in-wall", "rules_covering", (22, "tcp"))]
    web._rules_onto(ports_page("here:443/tcp"))  # kept a while: not asked again every two seconds
    assert len(asked) == 2
    wall.rules = {}
    monkeypatch.setattr(worldweb, "RULES_S", 0.0)
    again = ports_page("here:8080/tcp")
    web._rules_onto(again)
    assert again["tables"][0]["details"][0]["note"] == "No rule of stand-in-wall covers it."


def test_the_rules_are_asked_on_every_page_and_never_cost_it(monkeypatch):
    wall = Wall()
    app, web = framed(wall)
    seen = []
    monkeypatch.setattr(web, "_rules_onto", lambda page: seen.append(page))
    page = page_ask(app, "www", "world")
    assert seen == [page]
    monkeypatch.setattr(web, "_rules_onto", lambda page: 1 / 0)
    assert page_ask(app, "www", "world")["title"] == "World Wide Web"  # a failure never costs the page
    lone, web2 = framed()
    monkeypatch.setattr(web2, "_rules_onto", lambda page: seen.append("alone"))
    page_ask(lone, "www", "world")
    assert "alone" not in seen  # no firewall serving: nothing asked


def test_a_firewall_that_refuses_its_rules_is_not_asked_again_at_once(monkeypatch):
    wall = Wall()
    app, web = framed(wall)
    page_ask(app, "www", "world")
    calls = []

    def refused(*a):
        calls.append(a)
        raise ValueError("not for this machine: a stand-in")
    monkeypatch.setattr(wall, "rules_covering", refused)
    for _ in range(3):
        page = ports_page("here:443/tcp")
        web._rules_onto(page)
        assert page["tables"][0]["details"][0]["sections"][-1]["title"] == "Counted"
    assert len(calls) == 1
