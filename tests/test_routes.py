"""Every connection's route on the World Wide Web globe (liminal_libs.machines.routes, 1.67.0): what waits, what is
traced and kept, and what the page gets; over a stand-in tracer, clock, thread and GeoIP file (nothing is traced,
nothing runs on its own)."""
from __future__ import annotations

from dataclasses import dataclass

from liminal_libs import netpath
from liminal_libs.machines import routes as routes_module
from liminal_libs.machines.routes import Routes

HOME = {"lat": 51.5, "lon": -0.12, "label": "London"}


@dataclass
class Place:
    lat: float | None
    lon: float | None
    label: str = ""


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Geo:
    """A GeoIP file that knows a few addresses."""

    def __init__(self, places):
        self.places = places

    def lookup(self, address):
        return self.places.get(address)


def tracer_of(table):
    asked = []

    def tracer(address):
        asked.append(address)
        hops = table.get(address)
        if isinstance(hops, Exception):
            raise hops
        return netpath.Trace(address, tuple(netpath.Hop(i + 1, a, 1.0 + i) for i, a in enumerate(hops or ())),
                             bool(hops) and hops[-1] == address, "stand-in")
    return tracer, asked


def test_only_public_addresses_wait_once_each_and_the_thread_is_asked_for_once():
    tracer, asked = tracer_of({})
    started = []
    r = Routes(tracer=tracer, clock=Clock(), start=started.append)
    r.want(["81.2.69.142", "192.168.1.1", "81.2.69.142", "example.com", "100.64.0.1", "::ffff:81.2.69.160", "", None])
    assert r.describe()["waiting"] == 2 and len(started) == 1 and asked == []  # nothing traced by want itself
    r.want(["81.2.69.142", "2606:4700::1111"])
    assert r.describe()["waiting"] == 3 and len(started) == 1  # still running: not asked for again


def test_a_route_traced_to_its_end_is_not_traced_again_and_one_that_failed_is_after_an_hour():
    """1.74.0 (the user: "make sure all route checks only happen once, to conclusion"): one check, CHECKS traces of the
    host each to its end; then never again, however long its connection stays open. A check that failed is tried
    again KEEP_S on."""
    tracer, asked = tracer_of({"81.2.69.142": ["192.168.1.1", "81.2.69.142"], "81.2.69.160": RuntimeError("no")})
    clock, started = Clock(), []
    r = Routes(tracer=tracer, clock=clock, start=started.append)
    r.want(["81.2.69.142", "81.2.69.160"])
    assert r.step() and r.step() and not r.step()
    assert asked == ["81.2.69.142"] * routes_module.CHECKS + ["81.2.69.160"]  # a failed trace ends its check
    assert r.route("81.2.69.142").reached and r.route("81.2.69.142").hops[-1].address == "81.2.69.142"
    clock.now += routes_module.KEEP_S + 1
    r.want(["81.2.69.142", "81.2.69.160"])
    assert r.describe()["waiting"] == 1  # the failed one alone


def test_a_host_the_hosts_database_has_a_route_to_is_not_traced_again_after_a_restart():
    tracer, asked = tracer_of({})
    r = Routes(tracer=tracer, clock=Clock(), start=lambda work: None, known=lambda: {"81.2.69.142"})
    r.want(["81.2.69.142", "81.2.69.160"])
    assert r.describe()["waiting"] == 1


def test_every_distinct_route_of_a_check_is_saved_its_own_row_the_drawn_one_last():
    """1.74.0 (the user: "if there are multiple routes to a host, record all applicable routes")."""
    target, ways = "81.2.69.142", iter([["62.0.0.1", "81.2.69.142"], ["62.0.0.2", "81.2.69.142"],
                                        ["62.0.0.1", "81.2.69.142"]])

    def tracer(address):
        hops = next(ways)
        return netpath.Trace(address, tuple(netpath.Hop(i + 1, a, 1.0 + i) for i, a in enumerate(hops)), True, "x")
    saved = []
    r = Routes(tracer=tracer, clock=Clock(), start=lambda work: None, keep=lambda *a: saved.append(a))
    r.want([target])
    r.step()
    r.onto({"globe": {"home": HOME, "origins": []}}, Geo({}), [target])
    assert [[h["address"] for h in s[4]] for s in saved] == [["62.0.0.2", target], ["62.0.0.1", target]]


def test_nothing_is_traced_once_the_tab_is_left_and_nothing_after_close():
    tracer, asked = tracer_of({})
    clock = Clock()
    r = Routes(tracer=tracer, clock=clock, start=lambda work: None, timeout=20.0)
    r.want(["81.2.69.142", "81.2.69.160"])
    clock.now += 21  # the tab not asked since
    assert not r.step() and asked == [] and r.describe()["waiting"] == 2
    r.want([])  # asked again: tracing goes on
    assert r.step() and asked == ["81.2.69.142"] * routes_module.CHECKS
    r.close()
    assert not r.step() and r.describe()["waiting"] == 0 and r.describe()["kept"] == 0
    r.want(["81.2.69.160"])
    assert r.describe()["waiting"] == 0  # closed: nothing waits again


def test_the_loop_ends_when_nothing_waits_and_a_new_want_starts_it_again():
    tracer, asked = tracer_of({})
    started, slept = [], []
    r = Routes(tracer=tracer, clock=Clock(), sleep=slept.append, start=started.append)
    r.want(["81.2.69.142", "81.2.69.160"])
    started.pop()()  # the thread's work, run here: both traced, a pause after each, then it ends
    n = routes_module.CHECKS
    assert asked == ["81.2.69.142"] * n + ["81.2.69.160"] * n and slept == [routes_module.GAP_S] * 2
    assert not r.describe()["running"]
    r.want(["5.6.7.8"])
    assert len(started) == 1  # ended, so asked for again


def test_a_trace_that_fails_is_kept_in_words_and_the_waiting_are_capped(monkeypatch):
    tracer, _asked = tracer_of({"81.2.69.142": OSError("no tracer")})
    r = Routes(tracer=tracer, clock=Clock(), start=lambda work: None)
    r.want(["81.2.69.142"])
    assert r.step() and r.route("81.2.69.142").error == "OSError: no tracer"
    monkeypatch.setattr(routes_module, "MAX_WAITING", 2)
    r.want(["5.6.7.8", "5.6.7.9", "5.6.7.10"])
    assert r.describe()["waiting"] == 2


def test_a_place_on_the_globe_gets_its_routes_placed_hops_from_home_outward():
    """The hops at home's place, at the target's place, at the place of the hop before, and those with no place (the
    local network, an address the file does not know) are left out; where two routes end at one place, the one with
    the most placed hops is drawn."""
    target, other = "81.2.69.142", "81.2.69.160"
    tracer, _asked = tracer_of({
        target: ["192.168.1.1", "62.0.0.1", "62.0.0.2", "62.0.0.3", "62.0.0.4", "62.0.0.5", target],
        other: ["192.168.1.1", "62.0.0.3", other]})
    geo = Geo({"62.0.0.1": Place(51.5, -0.12, "London"), "62.0.0.2": Place(52.37, 4.9, "Amsterdam"),
               "62.0.0.3": Place(52.37, 4.9, "Amsterdam"), "62.0.0.4": Place(50.11, 8.68, "Frankfurt"),
               "62.0.0.5": Place(48.2, 16.37, "Vienna"), target: Place(48.2, 16.37, "Vienna"),
               other: Place(48.2, 16.37, "Vienna")})
    r = Routes(tracer=tracer, clock=Clock(), start=lambda work: None)
    r.want([target, other])
    while r.step():
        pass
    page = {"globe": {"home": HOME, "origins": [{"id": "v", "lat": 48.2, "lon": 16.37}, {"id": "x", "lat": 1, "lon": 2},
                                                  {"id": "u", "lat": None, "lon": None}]},
            "tables": [{"title": "What the globe shows"}, {"title": "Internet infrastructure"}]}
    r.onto(page, geo, [target, other, "192.168.1.1"])
    via = page["globe"]["origins"][0]["via"]
    assert [(p["label"], p["n"]) for p in via] == [("Amsterdam", 3), ("Frankfurt", 5)]
    assert "via" not in page["globe"]["origins"][1] and "via" not in page["globe"]["origins"][2]
    assert [t["title"] for t in page["tables"]] == ["What the globe shows", "Internet infrastructure", "Routes",
                                                   "Routes, hop by hop", "Legs waiting for a line"]  # 1.74.0
    table = next(t for t in page["tables"] if t["title"] == "Routes")
    assert [row[0]["text"] for row in table["rows"]] == [target, other]  # the most hops placed first
    assert table["rows"][0][1] == "7 of 7 hops answered, the address reached"
    assert table["rows"][0][2] == "Amsterdam → Frankfurt" and table["rows"][1][2] == "Amsterdam"
    assert "2 of 2 traced, 0 waiting." in table["note"]


def test_the_page_without_a_globe_or_a_geoip_file_still_gets_its_table():
    tracer, _asked = tracer_of({"81.2.69.142": ["192.168.1.1", "81.2.69.142"]})
    r = Routes(tracer=tracer, clock=Clock(), start=lambda work: None)
    r.want(["81.2.69.142"])
    r.step()
    page = r.onto({}, None, ["81.2.69.142"])
    assert page["tables"][0]["rows"] == [["81.2.69.142", "2 of 2 hops answered, the address reached", "no hop placed",
                                          "just now"]]
    assert r.onto({"tables": []}, None, [])["tables"][0]["empty"] == "No connection to the internet is open."



def test_a_thread_that_will_not_start_is_asked_for_again_and_the_flag_is_cleared_where_the_loop_ends():
    tracer, _asked = tracer_of({})
    tries = []

    def start(work):
        tries.append(work)
        if len(tries) == 1:
            raise RuntimeError("can't start new thread")
    r = Routes(tracer=tracer, clock=Clock(), start=start)
    r.want(["81.2.69.142"])
    assert not r.describe()["running"]
    r.want([])  # asked again: started again
    assert len(tries) == 2 and r.describe()["running"]
    while r.step():
        pass
    assert not r.describe()["running"]  # cleared in the hold that ended the loop


def test_the_page_gets_copies_of_its_places_and_the_tracer_is_stopped_with_the_tab(monkeypatch):
    target = "81.2.69.142"
    tracer, _asked = tracer_of({target: ["62.0.0.2", target]})
    r = Routes(tracer=tracer, clock=Clock(), start=lambda work: None)
    r.want([target])
    r.step()
    kept = {"id": "v", "lat": 48.2, "lon": 16.37}
    page = {"globe": {"home": HOME, "origins": [kept]}}
    r.onto(page, Geo({"62.0.0.2": Place(52.37, 4.9, "Amsterdam"), target: Place(48.2, 16.37, "Vienna")}), [target])
    assert page["globe"]["origins"][0]["via"] and "via" not in kept  # the hosts view's own place left as it was
    seen = {}
    monkeypatch.setattr(routes_module.netpath, "trace", lambda address, **kw: seen.update(kw) or netpath.Trace(address))
    clock = Clock()
    plain = Routes(clock=clock, start=lambda work: None, timeout=20.0)
    plain.want([target])
    plain.step()
    assert not seen["stop"]()  # the tab is shown: the tracer goes on
    clock.now += 21
    assert not seen["stop"]()  # 1.74.0: left, a trace begun runs to its end (no other is begun)
    plain.close()
    assert seen["stop"]()  # detached: stopped


def test_a_route_is_kept_once_in_the_hosts_database_with_every_hop_and_its_place():
    """1.68.0: once a route is on the page, it is handed to the keeper once (the hosts database), with every hop, each
    with the place the GeoIP file gives it, the places on its way, and when it was traced by the wall clock."""
    target = "81.2.69.142"
    tracer, _asked = tracer_of({target: ["192.168.1.1", "62.0.0.2", target]})
    kept = []
    clock = Clock()
    r = Routes(tracer=tracer, clock=clock, start=lambda work: None, keep=lambda *a: kept.append(a),
               wall=lambda: 1_800_000_000.0)
    r.want([target])
    r.step()
    clock.now += 30
    geo = Geo({"62.0.0.2": Place(52.37, 4.9, "Amsterdam"), target: Place(48.2, 16.37, "Vienna")})
    for _ in range(3):  # asked every two seconds: kept once
        r.onto({"globe": {"home": HOME, "origins": []}}, geo, [target])
    assert len(kept) == 1
    remote, traced, reached, how, hops, way = kept[0]
    assert (remote, traced, reached, how, way) == (target, 1_800_000_000.0 - 30, True, "stand-in", "Amsterdam")
    assert hops[0] == {"n": 1, "address": "192.168.1.1", "ms": 1.0}  # the local network: no place
    assert hops[1] == {"n": 2, "address": "62.0.0.2", "ms": 2.0, "label": "Amsterdam", "lat": 52.37, "lon": 4.9}


def test_a_route_whose_connection_closed_is_saved_all_the_same_once():
    """1.74.0 (the user: "all routes need to be saved in a database for now"): a route traced is kept in the hosts
    database even when its connection closed before the tab's next ask, and once."""
    target = "81.2.69.142"
    tracer, _asked = tracer_of({target: ["62.0.0.1", target]})
    saved = []
    r = Routes(tracer=tracer, clock=Clock(), start=lambda work: None, keep=lambda *a: saved.append(a))
    r.want([target])
    while r.step():
        pass
    geo = Geo({"62.0.0.1": Place(52.37, 4.9, "Amsterdam"), target: Place(48.2, 16.37, "Vienna")})
    r.onto({"globe": {"home": HOME, "origins": []}}, geo, [])  # the connection closed: none open now
    r.onto({"globe": {"home": HOME, "origins": []}}, geo, [])
    assert [s[0] for s in saved] == [target] and saved[0][5] == "Amsterdam"


def test_every_hop_of_each_route_is_tabled_in_order_the_missing_kept_and_each_crossing_said():
    """1.74.0 (the user: "for each traceroute show every hop in order with it's IP, round trip time, reverse DNS name,
    ASN, network operator, hostname, show RDAP ownership keep missing hops visible. finally highlight where it crosses
    between network operators")."""
    target = "81.2.69.142"
    tracer, _asked = tracer_of({target: ["62.0.0.1", None, "62.0.0.2", target]})

    class Hop:
        def __init__(self, lat, lon, label, asn, org):
            self.lat, self.lon, self.label, self.asn, self.org = lat, lon, label, asn, org

    class Geo:
        def lookup(self, address):
            return {"62.0.0.1": Hop(47.6, -122.3, "Seattle", 20115, "Charter"),
                    "62.0.0.2": Hop(41.9, -87.6, "Chicago", 6461, "Zayo"),
                    target: Hop(48.2, 16.37, "Vienna", 6461, "Zayo")}.get(address)
    r = Routes(tracer=tracer, clock=Clock(), start=lambda work: None)
    r.want([target])
    while r.step():
        pass
    r.lookups._known["62.0.0.1"] = (r.lookups.clock(), {"name": "lag-1.bbr01sttlwa.example.net",
                                                        "network": "NET-A", "org": "Charter", "country": "US"})
    r.lookups._known[target] = (r.lookups.clock(), {"name": "host.example.net"})
    page = {"globe": {"home": HOME, "origins": []}}
    r.onto(page, Geo(), [target])
    hops = next(t for t in page["tables"] if t["title"] == "Routes, hop by hop")
    rows = hops["rows"]
    assert [row[1] for row in rows] == ["1", "2", "3", "4"]  # every hop, in order
    assert rows[0][0] == {"text": target, "sub": "host.example.net"} and rows[1][0] == ""
    assert rows[0][2:8] == ["62.0.0.1", "1.0 ms", "lag-1.bbr01sttlwa.example.net", "AS20115", "Charter",
                            "NET-A, Charter, US"]
    assert rows[1][2] == {"text": "*", "sub": "no answer"}  # the missing hop kept
    assert rows[2][10] == {"text": "⇄ Zayo", "sub": "from Charter"} and rows[3][10] == ""  # crossed once
    assert rows[0][9] == "" and rows[2][9] == {"text": "private link", "sub": "Charter to Zayo, no exchange point seen"}
    assert rows[3][9] == {"text": "inside", "sub": "Zayo"}  # Chicago to Vienna in 1 ms: the times rule it out
    import sqlite3
    con = sqlite3.connect(str(r.composite.path))
    try:  # each link kept for the map
        assert con.execute("SELECT COUNT(*) FROM entities WHERE kind = 'link'").fetchone()[0] == 2
    finally:
        con.close()
    assert rows[0][8] == {"text": "Charter's backbone", "sub": "its name: lag-1.bbr01sttlwa.example.net"}
    r.lookups._known["62.0.0.2"] = (r.lookups.clock(), {"name": "ae-3.zayo.de-cix.fra.example.net", "network": "",
                                                        "org": ""})
    page = {"globe": {"home": HOME, "origins": []}}
    r.onto(page, Geo(), [target])
    rows = next(t for t in page["tables"] if t["title"] == "Routes, hop by hop")["rows"]
    assert rows[2][8] == {"text": "exchange point", "sub": "its name: ae-3.zayo.de-cix.fra.example.net"}
    assert rows[2][10] == {"text": "⇄ Zayo", "sub": "from Charter at an exchange point"}
    assert rows[2][9] == {"text": "exchange point", "sub": "Charter to Zayo"}


def test_a_host_traced_before_has_its_kept_routes_read_back_not_traced_or_saved_again():
    """1.74.1: after a restart the hosts database's routes are drawn and tabled again, read back once each."""
    tracer, asked = tracer_of({})
    target = "81.2.69.142"
    drawn = [{"n": 1, "address": "62.0.0.1", "ms": 1.0}, {"n": 2, "address": None, "ms": None},
             {"n": 3, "address": target, "ms": 9.0}]
    other = [{"n": 1, "address": "62.0.0.2", "ms": 2.0}, {"n": 2, "address": target, "ms": 8.0}]
    reads, saved = [], []

    def stored(addresses):
        reads.append(list(addresses))
        return {target: [{"traced": 1_000.0, "reached": True, "how": "icmp", "hops": other},
                         {"traced": 1_000.0, "reached": True, "how": "icmp", "hops": drawn}]}
    r = Routes(tracer=tracer, clock=Clock(), start=lambda work: None, known=lambda: {target, "81.2.69.160"},
               stored=stored, keep=lambda *a: saved.append(a), wall=lambda: 1_000.0 + 3 * 3600)
    r.want([target, "81.2.69.160", "10.0.0.1"])
    assert reads == [[target, "81.2.69.160"]] and r.describe()["waiting"] == 0  # read back, nothing to trace
    route = r.route(target)
    assert [h.address for h in route.hops] == ["62.0.0.1", None, target] and route.reached and route.how == "icmp"
    assert [[h.address for h in f.hops] for f in r._alternates[target]] == [["62.0.0.2", target]]
    page = {"globe": {"home": HOME, "origins": []}}
    r.onto(page, Geo({}), [target, "81.2.69.160"])
    table = next(t for t in page["tables"] if t["title"] == routes_module.TITLE)
    assert [row[0] for row in table["rows"]] == [target] and table["rows"][0][3] == "3 h ago"
    assert "read back" in table["note"]
    hops = next(t for t in page["tables"] if t["title"] == routes_module.HOPS_TITLE)
    assert [row[2] if isinstance(row[2], str) else row[2]["text"] for row in hops["rows"]] == ["62.0.0.1", "*", target]
    r.want([target, "81.2.69.160"])
    r.onto(page, Geo({}), [])  # the connection closed: kept already, never saved again
    assert reads == [[target, "81.2.69.160"]] and saved == [] and asked == []


def test_a_read_back_that_fails_draws_none_and_costs_the_tab_nothing():
    def stored(addresses):
        raise OSError("the disk is gone")
    r = Routes(tracer=tracer_of({})[0], clock=Clock(), start=lambda work: None, known=lambda: {"81.2.69.142"},
               stored=stored)
    r.want(["81.2.69.142"])
    assert r.route("81.2.69.142") is None and r.describe()["waiting"] == 0


def test_how_long_ago_a_route_was_traced_in_words():
    assert [routes_module._ago(s) for s in (5, 61, 3599, 3600, 7200, 86_400 * 2, 86_400 * 9)] == [
        "just now", "1 min ago", "60 min ago", "1 h ago", "2 h ago", "2 days ago", "9 days ago"]


def test_a_link_inside_your_isp_is_said_so_and_kept_for_the_map_with_the_table_made():
    """1.74.2: two hops of the first network met, near each other, are joined by your ISP's link (a word, not a
    record): the hop table is made and the link kept for the map with the others (1.74.0 failed the whole table)."""
    import json
    import sqlite3
    target = "81.2.69.142"
    tracer, _asked = tracer_of({target: ["62.0.0.1", "62.0.0.3", "62.0.0.2", target]})

    class Hop:
        def __init__(self, lat, lon, label, asn, org):
            self.lat, self.lon, self.label, self.asn, self.org = lat, lon, label, asn, org

    class Geo:
        def lookup(self, address):
            return {"62.0.0.1": Hop(47.6, -122.3, "Seattle", 20115, "Charter"),
                    "62.0.0.3": Hop(47.48, -122.21, "Renton", 20115, "Charter"),
                    "62.0.0.2": Hop(41.9, -87.6, "Chicago", 6461, "Zayo"),
                    target: Hop(48.2, 16.37, "Vienna", 6461, "Zayo")}.get(address)
    r = Routes(tracer=tracer, clock=Clock(), start=lambda work: None)
    r.want([target])
    while r.step():
        pass
    page = {"globe": {"home": HOME, "origins": []}}
    r.onto(page, Geo(), [target])
    titles = [t["title"] for t in page["tables"]]
    assert titles[-2:] == [routes_module.HOPS_TITLE, routes_module.WAITING_TITLE]  # made, and the table after it
    rows = page["tables"][-2]["rows"]
    assert [row[9] if isinstance(row[9], str) else row[9]["text"] for row in rows] == [
        "", "your ISP", "private link", "inside"]  # 1.74.3: Chicago to Vienna in 1 ms is no haul
    con = sqlite3.connect(str(r.composite.path))
    try:
        kept = [json.loads(c)["type"] for (c,) in con.execute(
            "SELECT v.claim FROM evidence v JOIN entities e ON e.id = v.entity WHERE e.kind = 'link'")]
    finally:
        con.close()
    assert sorted(kept) == ["inside", "private link", "your ISP"]
    r.close()


def test_a_carrier_link_only_where_the_times_allow_its_distance():
    """1.74.3: GeoIP puts many routers at their network's home; two hops' distance is believed only where their round
    trips allow it (about 100 km a ms, and 300 km for the places' own error), and a long added time is a haul alone.
    Each case is one seen on this PC's routes."""
    from liminal_libs.machines import network as network_module
    seattle, kennewick_said, boise, chicago = (47.6, -122.3), (38.6, -90.2), (43.6, -116.2), (41.9, -87.6)

    def link(where0, ms0, where1, ms1, op="Charter"):
        return Routes._link(("62.0.0.1", op, op, where0, ms0, False), ("62.0.0.2", op, op, where1, ms1, False),
                            "Charter")
    # two Kennewick routers, one placed by GeoIP at its network's home 2,600 km away, 0.3 ms apart: your ISP's
    assert network_module.km(seattle, kennewick_said) > routes_module.HAUL_KM
    assert link(seattle, 14.4, kennewick_said, 14.1) == "your ISP"
    # a long added time is a haul however near the places are said to be (and its distance not said when ruled out)
    got = link(seattle, 14.1, kennewick_said, 37.2)
    assert got["text"] == "carrier link" and "km" not in got["sub"] and "+23.1 ms" in got["sub"]
    # a distance the times allow: a haul, its distance said
    got = link(seattle, 10.0, boise, 15.0)
    assert 500 < network_module.km(seattle, boise) < 800 and got["text"] == "carrier link" and "km" in got["sub"]
    # far apart in 1 ms, another operator than the ISP: inside its network, no haul
    assert link(chicago, 3.0, (48.2, 16.37), 4.0, op="Zayo") == {"text": "inside", "sub": "Zayo"}
    assert routes_module.LINK_RULE == 2


def test_operators_are_compared_by_their_names_one_company_with_several_numbers_crossing_nothing():
    """1.75.0: with the ASN file, a route through two of Charter's AS numbers, its name spelt two ways, crosses no
    operator there; its ASN column says each number."""
    assert routes_module._operator("Charter Communications, Inc.") == "charter communications"
    assert routes_module._operator("Charter Communications LLC") == "charter communications"
    assert routes_module._operator("The Zayo Group") == "zayo group" and routes_module._operator("") == ""
    target = "81.2.69.142"
    tracer, _asked = tracer_of({target: ["62.0.0.1", "62.0.0.3", "62.0.0.2", target]})

    class Hop:
        def __init__(self, lat, lon, label, asn, org):
            self.lat, self.lon, self.label, self.asn, self.org = lat, lon, label, asn, org

    class Geo:
        def lookup(self, address):
            return {"62.0.0.1": Hop(47.6, -122.3, "Seattle", 20115, "Charter Communications Inc"),
                    "62.0.0.3": Hop(47.48, -122.21, "Renton", 7843, "Charter Communications LLC"),
                    "62.0.0.2": Hop(41.9, -87.6, "Chicago", 6461, "Zayo Bandwidth"),
                    target: Hop(48.2, 16.37, "Vienna", 6461, "Zayo Bandwidth")}.get(address)
    r = Routes(tracer=tracer, clock=Clock(), start=lambda work: None)
    r.want([target])
    while r.step():
        pass
    page = {"globe": {"home": HOME, "origins": []}}
    r.onto(page, Geo(), [target])
    rows = next(t for t in page["tables"] if t["title"] == routes_module.HOPS_TITLE)["rows"]
    assert [row[5] for row in rows] == ["AS20115", "AS7843", "AS6461", "AS6461"]
    assert [bool(row[10]) for row in rows] == [False, False, True, False]  # one crossing: Charter to Zayo
    assert rows[1][9] == "your ISP" and rows[2][10]["text"] == "⇄ Zayo Bandwidth"
    r.close()
