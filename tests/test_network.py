"""The network under the routes and their heat (liminal_libs.machines.network, 1.69.0): the graph of the line layers,
each leg snapped onto it within its detour limit or left a great circle, the heat summed by stretch, and the page's
shape and caps; over stand-in layers (nothing is read from this machine's files, nothing is traced)."""
from __future__ import annotations

from array import array

import pytest

from liminal_libs import netpath
from liminal_libs.machines import infrastructure, network
from liminal_libs.machines.network import Graph, Network, km
from liminal_libs.machines.routes import Routes


def run(a, b, n=20):
    """A line from a to b (lat, lon) through n - 1 points between them, straight in degrees."""
    return [(a[0] + (b[0] - a[0]) * i / n, a[1] + (b[1] - a[1]) * i / n) for i in range(n + 1)]


def packed(lines) -> dict:
    """Lines of (lat, lon) points as a layer's file keeps them (infrastructure.pack)."""
    xy, offsets = array(infrastructure._I32), array(infrastructure._U32, [0])
    for line in lines:
        for lat, lon in line:
            xy.extend((round(lon * 1e5), round(lat * 1e5)))
        offsets.append(len(xy) // 2)
    return {"n": len(lines), "offsets": infrastructure._packed(offsets), "xy": infrastructure._packed(xy),
            "names": [""] * len(lines)}


class Index:
    """An infrastructure.Index of a few line layers given by their lines ({layer: [line, ...]})."""

    def __init__(self, layers):
        self.given, self.version, self.read = dict(layers), 1, 0

    def layers(self):
        return [{"id": k, "kind": "lines", "version": f"v{self.version}"} for k in self.given]

    def layer(self, layer_id):
        if layer_id not in self.given:
            raise LookupError(layer_id)
        self.read += 1
        return {"id": layer_id, "version": f"v{self.version}",
                "parts": [{"set": "t", "lines": packed(self.given[layer_id])}]}


def graph_of(*lines) -> Graph:
    g = Network().graph(Index({"cables": list(lines)}))
    assert g is not None
    return g


def way_km(g: Graph, a, b, limit=1e9):
    na, nb = g.nearest(*a), g.nearest(*b)
    assert na is not None and nb is not None
    found = g.way(na[0], nb[0], limit)
    return None if found is None else found[0]


def test_ends_near_another_line_are_joined_and_far_ones_are_not():
    g = graph_of(run((0, 0), (0, 10)), run((0, 10.1), (0, 20)), run((0, 20.5), (0, 30)))  # 11 km apart, then 55 km
    assert g.joins >= 1
    assert way_km(g, (0, 0), (0, 20)) == pytest.approx(km((0, 0), (0, 20)), rel=0.01)
    assert way_km(g, (0, 0), (0, 30)) is None  # the third line is on its own


def test_points_on_one_cell_of_the_grid_are_one_vertex_and_lines_cross_there():
    g = graph_of(run((0, 0), (10, 10), 10), run((10, 0), (0, 10), 10))  # both through (5, 5)
    assert g.vertices == 21  # 22 points, the crossing one vertex
    assert way_km(g, (0, 0), (0, 10)) == pytest.approx(2 * km((0, 0), (5, 5)), rel=0.01)


def ends(heat) -> set:
    return {tuple(heat["points"][0]), tuple(heat["points"][-1])}


def globe(origins, home=(0, 0)):
    return {"home": {"lat": home[0], "lon": home[1]}, "origins": origins}


U = [run((0, 0), (10, 0)), run((10, 0), (10, 10)), run((10, 10), (0, 10))]  # up, across and down: 3 times the leg


def test_a_leg_follows_the_network_within_its_detour_and_waits_past_it(monkeypatch):
    """Past its detour a leg is not drawn at all (1.70.0: never a straight line) and waits, with why."""
    index = Index({"cables": U})
    page = Network().onto(globe([{"id": "p", "lat": 0, "lon": 10, "count": 3}]), index)
    assert page["heat"] == [] and page["heat_by"] == "connections"
    assert page["waiting"] == [{"from": "this machine", "to": "p", "km": 1112,
                                "why": "no way along the lines within 2.5 times its distance"}]
    assert "links" not in page["origins"][0]  # 1.106.0: not reached on the lines: its dot, and no light
    monkeypatch.setattr(network, "DETOUR", 3.5)
    page = Network().onto(globe([{"id": "p", "lat": 0, "lon": 10, "count": 3}]), index)
    (heat,) = page["heat"]  # the three lines, one weight: one run
    assert ends(heat) == {(0, 0), (0, 10)} and [10, 5] in heat["points"] and len(heat["points"]) == 61
    assert heat["w"] == 3 and page["waiting"] == []
    # 1.106.0: its lights only on the short links from the network's ends into it and into home, towards home (here
    # both ends are on the lines' own ends); never along the lines (1.70.0's tail is gone)
    assert page["origins"][0]["links"] == [[[0, 10], [0, 10]], [[0, 0], [0, 0]]] and "tail" not in page["origins"][0]


def test_an_end_beyond_the_snap_waits_and_a_leg_within_one_city_needs_no_line():
    index = Index({"cables": U})
    far = {"id": "f", "lat": -5, "lon": 5, "count": 1}  # some 780 km from the nearest junction
    near = {"id": "n", "lat": 0, "lon": 0.1, "count": 1}  # 11 km from home
    page = Network().onto(globe([far, near]), index)
    assert page["heat"] == []
    assert page["waiting"] == [{"from": "this machine", "to": "f", "why": "no line within 150 km of f", "km": 786}]
    assert "links" not in far and "links" not in near


T = [run((0, 0), (0, 10)), run((0, 10), (0, 20)), run((0, 10), (2, 10), 4)]  # east, on east, and a branch north


def test_stretches_shared_by_routes_are_summed_by_connections_and_a_route_counts_one_once():
    index = Index({"cables": T})
    branch = {"id": "b", "lat": 2, "lon": 10, "bytes": 100, "count": 1}
    east = {"id": "e", "lat": 0, "lon": 20, "bytes": 50, "count": 9}
    page = Network().onto(globe([branch, east]), index)
    weights = sorted((h["w"], ends(h)) for h in page["heat"])
    assert page["heat_by"] == "connections"  # how often, never how much (1.70.0)
    assert [w for w, _ in weights] == [1, 9, 10] and weights[2][1] == {(0, 0), (0, 10)}
    # out east first and back to the branch: the stretch from (0, 10) to (0, 20) is gone twice, counted once
    there_and_back = {"id": "t", "lat": 2, "lon": 10, "count": 7, "via": [{"lat": 0, "lon": 20}]}
    page = Network().onto(globe([there_and_back]), index)
    assert sorted(h["w"] for h in page["heat"]) == [7, 7, 7]  # three runs (they meet at a branch), each once


def test_a_hop_met_by_the_network_on_both_legs_is_passed_through_at_its_junction():
    index = Index({"cables": T})
    o = {"id": "e", "lat": 0, "lon": 20, "count": 2, "via": [{"lat": 0.5, "lon": 10}]}  # 55 km off the line
    page = Network().onto(globe([o]), index)
    (heat,) = page["heat"]
    assert [0.5, 10] not in heat["points"]  # no spike out to the router's place and back
    assert ends(heat) == {(0, 0), (0, 20)} and len(heat["points"]) == 41 and page["waiting"] == []


STAR = [run((0, 0), (5 * a, 5 * b)) for a, b in ((1, 1), (-1, 1), (1, -1), (-1, -1), (1, 0))]  # five ways out


def test_the_heaviest_runs_are_kept_within_the_caps(monkeypatch):
    index = Index({"cables": STAR})
    places = [{"id": str(i), "lat": line[-1][0], "lon": line[-1][1], "count": i} for i, line in enumerate(STAR, 1)]
    monkeypatch.setattr(network, "MAX_RUNS", 2)
    page = Network().onto(globe(places), index)
    assert [h["w"] for h in page["heat"]] == [5, 4]
    monkeypatch.setattr(network, "MAX_RUNS", 10)
    monkeypatch.setattr(network, "MAX_POINTS", 45)
    page = Network().onto(globe(places), index)
    assert [h["w"] for h in page["heat"]] == [5, 4]  # 21 points each


def test_legs_waiting_are_listed_once_by_their_ends_and_why():
    hop = {"lat": 0, "lon": 50, "label": "Somewhere, Far"}
    places = [{"id": "a", "lat": 10, "lon": 50, "count": 1, "via": [hop]},
              {"id": "b", "lat": -10, "lon": 50, "count": 1, "via": [hop]}]
    page = Network().onto(globe(places), Index({}))
    assert [(x["from"], x["to"]) for x in page["waiting"]] == [("this machine", "Somewhere, Far"),
                                                                 ("Somewhere, Far", "a"), ("Somewhere, Far", "b")]
    assert {x["why"] for x in page["waiting"]} == {"no line layer is installed"}


def test_the_graph_is_made_again_when_a_layer_changes_or_goes():
    index, net = Index({"cables": U}), Network()
    first = net.graph(index)
    assert net.graph(index) is first and net.built == 1 and index.read == 1  # the same versions: kept
    index.version = 2
    assert net.graph(index) is not first and net.built == 2
    index.given = {}
    assert net.graph(index) is None
    page = net.onto(globe([{"id": "p", "lat": 0, "lon": 10, "count": 1}]), index)
    assert page["heat"] == [] and page["waiting"][0]["why"] == "no line layer is installed"
    net.graph(Index({"cables": U}))
    net.clear()
    assert net._graph is None and net._key is None


def test_lines_that_do_not_read_are_passed_over():
    assert Graph.of([]) is None
    assert Graph.of([(array("i", [0, 0, 100, 100]), array("I", [0, 3]))]) is None  # offsets past the points
    assert Graph.of([(array("i", [0, 0]), array("I", [0, 1]))]) is None  # a line of one point
    index = Index({"cables": U})
    index.layer = lambda layer_id: {"parts": [{"lines": {"xy": "not base64!", "offsets": 7}}]}
    assert Network().graph(index) is None


def test_the_routes_page_gets_the_heat_each_places_links_and_the_legs_waiting():
    target = "81.2.69.142"

    def tracer(address):
        return netpath.Trace(address, (netpath.Hop(1, "62.0.0.1", 1.0), netpath.Hop(2, target, 2.0)), True, "stand-in")

    class Geo:
        def lookup(self, address):
            return {"62.0.0.1": Place(0, 10, "Hop"), target: Place(0, 20, "Host")}.get(address)
    r = Routes(tracer=tracer, start=lambda work: None)
    r.want([target])
    while r.step():
        pass
    page = {"globe": {"home": {"lat": 0, "lon": 0}, "origins": [{"id": "h", "lat": 0, "lon": 20, "count": 4}]}}
    r.onto(page, Geo(), [target], index=Index({"cables": T}))
    g = page["globe"]
    assert g["origins"][0]["via"][0]["label"] == "Hop" and g["origins"][0]["links"] == [[[0, 20], [0, 20]],
                                                                                         [[0, 0], [0, 0]]]
    assert g["hubs"] == []  # 1.106.0: a stand-in that reads no points by cells names no hub
    assert g["heat_by"] == "connections" and [h["w"] for h in g["heat"]] == [4]
    assert ends(g["heat"][0]) == {(0, 0), (0, 20)}
    assert [t["title"] for t in page["tables"]] == ["Routes", "Routes, hop by hop", "Legs waiting for a line"]
    assert "times its straight distance" in page["tables"][0]["note"] and page["tables"][-1]["rows"] == []
    assert "at most 150 km" in page["tables"][0]["note"] and "within 10 km of its lines" in page["tables"][0]["note"]
    r.close()
    assert r.network._graph is None


class Place:
    def __init__(self, lat, lon, label=""):
        self.lat, self.lon, self.label = lat, lon, label


def test_a_heat_that_fails_leaves_an_empty_heat_never_none(monkeypatch):
    """1.106.0 (Monday list item 27: "the straightlines are meaningless"): a page without a heat is drawn with straight
    lines (an older server's), so a heat that fails leaves an empty one, no hubs and no links: no route drawn."""
    target = "81.2.69.142"

    def tracer(address):
        return netpath.Trace(address, (netpath.Hop(1, "62.0.0.1", 1.0), netpath.Hop(2, target, 2.0)), True, "stand-in")

    class Geo:
        def lookup(self, address):
            return {"62.0.0.1": Place(0, 10, "Hop"), target: Place(0, 20, "Host")}.get(address)
    r = Routes(tracer=tracer, start=lambda work: None)
    r.want([target])
    while r.step():
        pass

    def broken(globe, index):
        globe["origins"][0]["links"] = [[[0, 20], [0, 20]]]  # half way when it failed
        raise RuntimeError("a stand-in's failure")
    r.network.legs = {"0,0>0,10": ("the page before's", "")}  # what an earlier page left
    monkeypatch.setattr(r.network, "onto", broken)
    page = {"globe": {"home": {"lat": 0, "lon": 0}, "origins": [{"id": "h", "lat": 0, "lon": 20, "count": 4}]}}
    r.onto(page, Geo(), [target], index=Index({"cables": T}))
    g = page["globe"]
    assert (g["heat"], g["heat_by"], g["hubs"]) == ([], "connections", []) and "links" not in g["origins"][0]
    # the review: said, and the legs of the page before are not this one's (nor kept in the composite as such)
    assert g["heat_error"] == "RuntimeError: a stand-in's failure"
    assert "No route is drawn this time: their heat failed (RuntimeError: a stand-in's failure)." in \
        page["tables"][0]["note"]
    assert r.network.legs == {}
    r.close()
