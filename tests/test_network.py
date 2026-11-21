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


def test_a_leg_follows_the_network_within_its_detour_and_is_a_great_circle_past_it(monkeypatch):
    index = Index({"cables": U})
    page = Network().onto(globe([{"id": "p", "lat": 0, "lon": 10, "count": 3}]), index)
    assert [h["points"] for h in page["heat"]] == [[[0, 0], [0, 10]]]  # past 2.5 times: straight
    assert page["heat"][0]["w"] == 3 and page["heat_by"] == "connections"
    assert page["origins"][0]["last"] == [0, 0]  # never on the network: its light from home
    monkeypatch.setattr(network, "DETOUR", 3.5)
    page = Network().onto(globe([{"id": "p", "lat": 0, "lon": 10, "count": 3}]), index)
    (heat,) = page["heat"]  # the three lines, one weight: one run
    assert ends(heat) == {(0, 0), (0, 10)} and [10, 5] in heat["points"]
    assert len(heat["points"]) == 61
    assert page["origins"][0]["last"] == [0, 10]  # it leaves the network at the host itself


def test_an_end_beyond_the_snap_and_a_leg_within_one_city_are_great_circles():
    index = Index({"cables": U})
    far = {"id": "f", "lat": -5, "lon": 5, "count": 1}  # some 780 km from the nearest junction
    near = {"id": "n", "lat": 0, "lon": 0.1, "count": 1}  # 11 km from home
    page = Network().onto(globe([far, near]), index)
    assert sorted(h["points"] for h in page["heat"]) == [[[0, 0], [-5, 5]], [[0, 0], [0, 0.1]]]
    assert far["last"] == [0, 0] and near["last"] == [0, 0]


T = [run((0, 0), (0, 10)), run((0, 10), (0, 20)), run((0, 10), (2, 10), 4)]  # east, on east, and a branch north


def test_stretches_shared_by_routes_are_summed_and_a_route_counts_a_stretch_once():
    index = Index({"cables": T})
    branch = {"id": "b", "lat": 2, "lon": 10, "bytes": 100, "count": 1}
    east = {"id": "e", "lat": 0, "lon": 20, "bytes": 50, "count": 9}
    page = Network().onto(globe([branch, east]), index)
    weights = sorted((h["w"], h["points"][0], h["points"][-1]) for h in page["heat"])
    assert page["heat_by"] == "bytes"
    assert [w for w, _, _ in weights] == [50, 100, 150]
    assert ([0, 0] in (weights[2][1], weights[2][2])) and ([0, 10] in (weights[2][1], weights[2][2]))
    # out east first and back to the branch: the stretch from (0, 10) to (0, 20) is gone twice, counted once
    there_and_back = {"id": "t", "lat": 2, "lon": 10, "bytes": 7, "via": [{"lat": 0, "lon": 20}]}
    page = Network().onto(globe([there_and_back]), index)
    assert sorted(h["w"] for h in page["heat"]) == [7, 7, 7]  # three runs (they meet at a branch), each once


def test_a_hop_met_by_the_network_on_both_legs_is_passed_through_at_its_junction():
    index = Index({"cables": T})
    o = {"id": "e", "lat": 0, "lon": 20, "count": 2, "via": [{"lat": 0.5, "lon": 10}]}  # 55 km off the line
    page = Network().onto(globe([o]), index)
    (heat,) = page["heat"]
    assert [0.5, 10] not in heat["points"]  # no spike out to the router's place and back
    assert ends(heat) == {(0, 0), (0, 20)} and len(heat["points"]) == 41


def test_the_heaviest_runs_are_kept_within_the_caps(monkeypatch):
    index = Index({})
    places = [{"id": str(i), "lat": 0, "lon": 10 * i, "count": i} for i in range(1, 6)]
    monkeypatch.setattr(network, "MAX_RUNS", 2)
    page = Network().onto(globe(places), index)
    assert [h["w"] for h in page["heat"]] == [5, 4]
    monkeypatch.setattr(network, "MAX_RUNS", 10)
    monkeypatch.setattr(network, "MAX_POINTS", 5)
    page = Network().onto(globe(places), index)
    assert [h["w"] for h in page["heat"]] == [5, 4]  # two points each


def test_the_graph_is_made_again_when_a_layer_changes_or_goes():
    index, net = Index({"cables": U}), Network()
    first = net.graph(index)
    assert net.graph(index) is first and net.built == 1 and index.read == 1  # the same versions: kept
    index.version = 2
    assert net.graph(index) is not first and net.built == 2
    index.given = {}
    assert net.graph(index) is None
    page = net.onto(globe([{"id": "p", "lat": 0, "lon": 10, "count": 1}]), index)
    assert [h["points"] for h in page["heat"]] == [[[0, 0], [0, 10]]]  # no layer: the great circle
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


def test_the_routes_page_gets_the_heat_and_each_place_where_its_light_begins():
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
    assert g["origins"][0]["via"][0]["label"] == "Hop" and g["origins"][0]["last"] == [0, 20]
    assert g["heat_by"] == "connections" and [h["w"] for h in g["heat"]] == [4]
    assert ends(g["heat"][0]) == {(0, 0), (0, 20)}
    assert "times its great circle" in page["tables"][-1]["note"]
    r.close()
    assert r.network._graph is None


class Place:
    def __init__(self, lat, lon, label=""):
        self.lat, self.lon, self.label = lat, lon, label
