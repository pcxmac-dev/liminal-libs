"""The composite database of the World Wide Web tab (liminal_libs.machines.composite, 1.71.0): both sides kept and
paired, each claim with its source and licence, a best estimate with a confidence, and the lookup queue; written in
the test's own folder (the suite's guard moves the layers' folder there). Nothing is asked of anyone."""
from __future__ import annotations

import sqlite3

from liminal_libs import netpath
from liminal_libs.machines import composite, infrastructure
from liminal_libs.machines.composite import Composite
from liminal_libs.machines.routes import Routes


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


def rows(c: Composite, sql: str) -> list:
    conn = sqlite3.connect(str(c.path))
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


SEATTLE = {"address": "62.0.0.1", "n": 3, "ms": 12.5, "after": "62.0.0.9", "lat": 47.6, "lon": -122.3,
           "label": "Seattle, United States"}


def test_a_routers_place_is_kept_with_its_source_and_licence_and_estimated():
    c = Composite(clock=Clock())
    assert c.path == infrastructure.folder() / composite.FILE  # beside the layers
    assert c.record([SEATTLE], {}, "CC BY 4.0")
    assert c.estimate("62.0.0.1") == {"lat": 47.6, "lon": -122.3, "label": "Seattle, United States",
                                      "confidence": 0.3, "sources": 1}
    assert rows(c, "SELECT source, licence FROM evidence ORDER BY source") == [("geoip", "CC BY 4.0"),
                                                                              ("trace", "measured here")]
    assert c.counts == {"routers": 1, "claims": 2, "placed": 1, "waiting": 0}


def test_sources_that_agree_raise_the_confidence_and_one_far_off_stands_apart(monkeypatch):
    monkeypatch.setitem(composite.SOURCES, "name", (0.6, "the router's own name"))
    monkeypatch.setitem(composite.SOURCES, "far", (0.5, "a stand-in"))
    c = Composite(clock=Clock())
    c.record([SEATTLE], {}, "CC BY 4.0")
    c.record(claims=[("62.0.0.1", "name", "measured here", {"lat": 47.45, "lon": -122.31, "label": "SEA"}),
                     ("62.0.0.1", "far", "a stand-in's", {"lat": 40.7, "lon": -74.0, "label": "New York"})])
    est = c.estimate("62.0.0.1")
    assert est["confidence"] == 0.72 and est["sources"] == 2  # 1 - 0.7 * 0.4: Seattle's two, 17 km apart
    assert est["label"] == "SEA" and est["lat"] == 47.45  # the heaviest claim of the cluster leads it


def test_a_router_with_no_place_waits_and_is_done_once_placed():
    c = Composite(clock=Clock())
    c.record([{"address": "62.0.0.2", "n": 4, "ms": None, "lat": None, "lon": None}], {}, "")
    (waiting,) = c.queue()
    assert waiting["kind"] == "place" and waiting["what"] == "router 62.0.0.2"
    assert waiting["why"] == "the GeoIP file has no place for it" and waiting["left"] == list(composite.PLACE_LEFT)
    c.record([{"address": "62.0.0.2", "lat": 51.5, "lon": -0.1, "label": "London"}], {}, "")
    assert c.queue() == [] and c.counts["waiting"] == 0 and c.estimate("62.0.0.2")["label"] == "London"


def test_a_leg_waits_with_why_and_is_done_once_found_on_the_lines():
    c = Composite(clock=Clock())
    key = "45.600,-121.200>47.600,-122.300"
    c.record(legs={key: ("this machine to Seattle", "no line layer is installed")})
    (waiting,) = c.queue()
    assert (waiting["kind"], waiting["key"], waiting["what"]) == ("segment", key, "this machine to Seattle")
    assert waiting["left"] == list(composite.SEGMENT_LEFT)
    c.record(legs={key: ("this machine to Seattle", "")})
    assert c.queue() == [] and rows(c, "SELECT done IS NOT NULL FROM queue") == [(1,)]  # kept, for the record


def test_nothing_is_written_again_within_its_time_nor_once_closed_nor_on_another_systems_drive(monkeypatch):
    clock = Clock()
    c = Composite(clock=clock)
    c.record([SEATTLE], {}, "CC BY 4.0")
    first = rows(c, "SELECT last FROM evidence WHERE source = 'geoip'")
    clock.now += 60
    c.record([SEATTLE], {}, "CC BY 4.0")
    assert rows(c, "SELECT last FROM evidence WHERE source = 'geoip'") == first  # not written again so soon
    clock.now += composite.REWRITE_S
    c.record([SEATTLE], {}, "CC BY 4.0")
    assert rows(c, "SELECT last FROM evidence WHERE source = 'geoip'") == [(clock.now,)]
    c.close()
    assert c.record([SEATTLE], {}, "CC BY 4.0") is False
    elsewhere = Composite(clock=clock, where=infrastructure.folder() / "other" / composite.FILE)
    monkeypatch.setattr(infrastructure, "foreign", lambda p=None: "another system's drive")
    assert elsewhere.record([SEATTLE], {}, "") is False and elsewhere.problem == "another system's drive"
    assert not elsewhere.path.exists()


def test_the_routes_page_fills_the_composite_and_says_what_it_holds():
    target = "81.2.69.142"

    def tracer(address):
        return netpath.Trace(address, (netpath.Hop(1, "62.0.0.1", 1.0), netpath.Hop(2, "62.0.0.2", 3.0),
                                       netpath.Hop(3, target, 9.0)), True, "stand-in")

    class Place:
        def __init__(self, lat, lon, label):
            self.lat, self.lon, self.label = lat, lon, label

    class Geo:
        def lookup(self, address):
            return {"62.0.0.1": Place(47.6, -122.3, "Seattle"), target: Place(40.7, -74.0, "New York")}.get(address)
    r = Routes(tracer=tracer, start=lambda work: None)
    r.want([target])
    while r.step():
        pass
    page = {"globe": {"home": {"lat": 45.6, "lon": -121.2},
                      "origins": [{"id": "ny", "lat": 40.7, "lon": -74.0, "count": 2}]}}
    r.onto(page, Geo(), [target], licence="the GeoIP file's licence")
    assert r.composite.estimate("62.0.0.1")["label"] == "Seattle"
    assert [(w["kind"], w["what"]) for w in r.composite.queue()] == [("place", "router 62.0.0.2"),
                                                                    ("segment", "this machine to Seattle"),
                                                                    ("segment", "Seattle to ny")]
    note = page["tables"][-1]["note"]
    assert "Kept in the composite database (composite.db, beside the layers): 2 routers" in note
    assert "1 placed, 3 waiting to be looked up." in note
    r.close()
    assert r.composite.closed
