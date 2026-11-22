"""Each router's name and network (liminal_libs.machines.lookups, 1.72.0): reverse DNS and RDAP within their limits,
the registries' 429s and redirects, ranges kept, and what the page gets; over stand-ins of the resolver, the https
GET, the clock and the thread (the suite's guard refuses the real ones)."""
from __future__ import annotations

import pytest

from liminal_libs import netpath
from liminal_libs.machines import lookups
from liminal_libs.machines.lookups import Limit, Lookups, network_of
from liminal_libs.machines.routes import Routes


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


BOOT4 = {"services": [[["62.0.0.0/8"], ["https://rdap.db.ripe.net/"]],
                      [["200.0.0.0/8"], ["http://rdap.lacnic.net/rdap/", "https://rdap.lacnic.net/rdap/"]]]}
BOOT6 = {"services": [[["2001:600::/23"], ["https://rdap.db.ripe.net/"]]]}


def answer(name, start, end, org="Example Carrier", country="NL"):
    return {"name": name, "handle": name + "-H", "country": country, "startAddress": start, "endAddress": end,
            "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                                              ["fn", {}, "text", org]]]}]}


@pytest.fixture
def net(monkeypatch):
    """The resolver and the registries, stood in: the names and answers given, every question noted."""
    asked = {"ptr": [], "get": []}
    names = {"62.0.0.1": "ae-1.r20.amstnl02.nl.bb.example.net", "62.0.0.2": ""}
    answers = {"https://rdap.db.ripe.net/ip/62.0.0.1": (200, answer("EXAMPLE-NET", "62.0.0.0", "62.0.255.255")),
               "https://rdap.lacnic.net/rdap/ip/200.1.1.1": (429, None)}

    def ptr(address):
        asked["ptr"].append(address)
        return names.get(address, "")

    def get(url):
        asked["get"].append(url)
        if url == lookups.BOOTSTRAP[0]:
            return 200, {}, BOOT4, ""
        if url == lookups.BOOTSTRAP[1]:
            return 200, {}, BOOT6, ""
        status, doc = answers.get(url, (404, None))
        headers = {"Retry-After": "120"} if status == 429 else {}
        return status, headers, doc, answers.get(url + "#location", "")
    monkeypatch.setattr(lookups, "_ptr", ptr)
    monkeypatch.setattr(lookups, "_get", get)
    return asked, answers


def test_a_limit_holds_to_so_many_a_window_and_waits_out_a_refusal():
    clock = Clock()
    limit = Limit(((10, 60.0), (1000, 3600.0)), clock)
    for _ in range(10):
        assert limit.wait() == 0
        limit.take()
    assert limit.wait() == 60.0  # the eleventh waits for the first to leave the minute
    clock.now += 60
    assert limit.wait() == 0
    limit.hold(120)
    assert limit.wait() == 120
    limit.hold(1e9)
    assert limit.wait() == lookups.MAX_RETRY_AFTER_S  # a Retry-After past an hour is taken as an hour


def test_a_router_gets_its_name_and_network_once_and_the_composite_its_claims(net):
    asked, _ = net
    claims = []
    lk = Lookups(claims=lambda *c: claims.append(c), clock=Clock(), sleep=lambda s: None, start=lambda work: None)
    lk.want(["62.0.0.1", "62.0.0.1", "not an address"])
    assert lk.describe()["waiting"] == 1
    assert lk.step() and not lk.step()
    assert lk.known("62.0.0.1") == {"name": "ae-1.r20.amstnl02.nl.bb.example.net", "network": "EXAMPLE-NET",
                                    "handle": "EXAMPLE-NET-H", "org": "Example Carrier", "country": "NL",
                                    "range": "62.0.0.0 - 62.0.255.255"}
    assert [c[1] for c in claims] == ["ptr", "rdap"] and claims[1][2] == lookups.RDAP_WORDS
    assert asked["get"] == [*lookups.BOOTSTRAP, "https://rdap.db.ripe.net/ip/62.0.0.1"]
    lk.want(["62.0.0.1"])  # looked up within the day: not again
    assert lk.describe()["waiting"] == 0


def test_a_router_within_a_range_known_asks_the_registry_nothing(net):
    asked, _ = net
    lk = Lookups(clock=Clock(), sleep=lambda s: None, start=lambda work: None)
    lk.want(["62.0.0.1", "62.0.0.2"])
    while lk.step():
        pass
    assert lk.known("62.0.0.2")["network"] == "EXAMPLE-NET" and lk.known("62.0.0.2")["name"] == ""
    assert sum(1 for u in asked["get"] if "/ip/" in u) == 1 and lk.describe()["asked_rdap"] == 1


def test_a_registry_that_answers_429_is_not_asked_again_for_its_retry_after(net):
    asked, _ = net
    clock = Clock()
    lk = Lookups(clock=clock, sleep=lambda s: None, start=lambda work: None)
    lk.want(["200.1.1.1"])
    assert lk.step()  # asked: 429, the router put back to wait
    assert lk.describe()["waiting"] == 1 and lk.known("200.1.1.1") == {"name": ""}
    lk.want(["200.1.1.1"])
    assert lk.step()
    assert sum(1 for u in asked["get"] if "lacnic" in u) == 1  # held for its Retry-After: not asked again
    clock.now += 121
    lk.want(["200.1.1.1"])  # the tab asked again meanwhile
    assert lk.step()
    assert sum(1 for u in asked["get"] if "lacnic" in u) == 2


def test_redirects_only_to_the_registries_own_hosts_and_nothing_for_a_private_address(net):
    asked, answers = net
    answers["https://rdap.db.ripe.net/ip/62.0.0.9"] = (302, None)
    answers["https://rdap.db.ripe.net/ip/62.0.0.9#location"] = "https://evil.example/ip/62.0.0.9"
    lk = Lookups(clock=Clock(), sleep=lambda s: None, start=lambda work: None)
    lk.want(["62.0.0.9", "192.168.1.1"])
    while lk.step():
        pass
    assert not any("evil" in u for u in asked["get"])
    assert lk.known("62.0.0.9")["network"] == "" and lk.known("192.168.1.1")["network"] == ""
    assert not any("192.168" in u for u in asked["get"]) and "192.168.1.1" in asked["ptr"]


def test_nothing_is_looked_up_once_closed_nor_after_the_tab_was_left():
    clock = Clock()
    started = []
    lk = Lookups(clock=clock, sleep=lambda s: None, start=started.append)
    lk.want(["62.0.0.1"])
    lk.want(["62.0.0.3"])
    assert len(started) == 1  # one thread, asked for once
    clock.now += lookups.TIMEOUT_S + 1
    assert lk.step() is False  # the tab left: nothing more
    lk.close()
    lk.want(["62.0.0.4"])
    assert lk.describe()["waiting"] == 0


def test_network_of_reads_an_answer_and_none():
    assert network_of(None) == {}
    assert network_of({"name": "X", "entities": [{"roles": ["technical"], "vcardArray": []}]})["org"] == ""


def test_the_routes_page_asks_for_its_routers_and_shows_their_names_and_networks(net):
    target = "81.2.69.142"

    def tracer(address):
        return netpath.Trace(address, (netpath.Hop(1, "62.0.0.1", 1.0), netpath.Hop(2, target, 2.0)), True, "stand-in")

    class Place:
        def __init__(self, lat, lon, label):
            self.lat, self.lon, self.label = lat, lon, label

    class Geo:
        def lookup(self, address):
            return {"62.0.0.1": Place(52.37, 4.9, "Amsterdam"), target: Place(51.5, -0.12, "London")}.get(address)
    r = Routes(tracer=tracer, start=lambda work: None)
    r.want([target])
    while r.step():
        pass
    page = {"globe": {"home": {"lat": 45.6, "lon": -121.2}, "origins": [{"id": "l", "lat": 51.5, "lon": -0.12}]}}
    r.onto(page, Geo(), [target])
    assert r.lookups.describe()["waiting"] == 1  # the router, not the target
    r.lookups.clock = Clock()
    r.lookups._asked = r.lookups.clock()
    while r.lookups.step():
        pass
    r.onto(page, Geo(), [target])
    (hop,) = page["globe"]["origins"][0]["via"]
    assert hop["name"] == "ae-1.r20.amstnl02.nl.bb.example.net"
    assert hop["network"] == "EXAMPLE-NET, Example Carrier, NL"
    assert [c for c in r.composite.queue() if c["kind"] == "place"] == []  # its place known: it waits for none
    r.close()
