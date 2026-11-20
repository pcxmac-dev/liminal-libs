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


def test_a_route_is_kept_an_hour_then_traced_again_while_its_connection_is_open():
    tracer, asked = tracer_of({"81.2.69.142": ["192.168.1.1", "81.2.69.142"]})
    clock, started = Clock(), []
    r = Routes(tracer=tracer, clock=clock, start=started.append)
    r.want(["81.2.69.142"])
    assert r.step() and not r.step() and asked == ["81.2.69.142"]
    assert r.route("81.2.69.142").reached and r.route("81.2.69.142").hops[-1].address == "81.2.69.142"
    clock.now += routes_module.KEEP_S - 1
    r.want(["81.2.69.142"])
    assert r.describe()["waiting"] == 0
    clock.now += 2
    r.want(["81.2.69.142"])
    assert r.describe()["waiting"] == 1 and r.step() and asked == ["81.2.69.142"] * 2


def test_nothing_is_traced_once_the_tab_is_left_and_nothing_after_close():
    tracer, asked = tracer_of({})
    clock = Clock()
    r = Routes(tracer=tracer, clock=clock, start=lambda work: None, timeout=20.0)
    r.want(["81.2.69.142", "81.2.69.160"])
    clock.now += 21  # the tab not asked since
    assert not r.step() and asked == [] and r.describe()["waiting"] == 2
    r.want([])  # asked again: tracing goes on
    assert r.step() and asked == ["81.2.69.142"]
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
    assert asked == ["81.2.69.142", "81.2.69.160"] and slept == [routes_module.GAP_S] * 2
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
    assert [t["title"] for t in page["tables"]] == ["What the globe shows", "Internet infrastructure", "Routes"]
    table = page["tables"][-1]
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
    assert seen["stop"]()  # left: the tracer is stopped
    plain.close()
    assert seen["stop"]()


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
