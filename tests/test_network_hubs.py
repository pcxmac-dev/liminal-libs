"""The routes' short lit links and the hubs they pass (liminal_libs.machines.network, 1.106.0, Monday list item 27; the
user, 2026-11-22: "the straightlines are meaningless, they need to show the cities that the lines go to, the hubs, the
fiber bones, etc."). The lights only on the short link from the network's end into a host, LINK_KM at most, none for a
place its way does not reach on the lines; the landing stations, exchange points, data centres, backbones' cities and
cities each route passes, in its way's order, weighed by the connections through them, read by the cells the lines
cross and kept with the graph. Over stand-in layers and a stand-in index; the store's read by cells on the test's own
folder (nothing downloaded, nothing traced)."""
from __future__ import annotations

import pytest

from liminal_libs.machines import network
from liminal_libs.machines.infrastore import Store, cell_of
from liminal_libs.machines.infrastructure import Index as RealIndex
from liminal_libs.machines.network import Network, km

from test_network import Index as LineIndex, globe, run


class Index(LineIndex):
    """test_network's stand-in index of line layers, with point layers read by cells as infrastructure.Index.points
    reads them ({layer: [(lat, lon, name, sub), ...]}), and what it was asked."""

    def __init__(self, layers, points=None):
        super().__init__(layers)
        self.points_given, self.hub_version, self.asked = dict(points or {}), 1, []

    def layers(self):
        return super().layers() + [{"id": k, "kind": "points", "version": f"h{self.hub_version}"}
                                   for k in self.points_given]

    def points(self, layers, cells, most):
        cells = set(cells)
        self.asked.append((sorted(layers), cells))
        return [(layer, lon, lat, name, sub) for layer in layers
                for lat, lon, name, sub in self.points_given.get(layer, ()) if cell_of(lon, lat) in cells][:most]


LINE = [run((0, 1), (0, 10))]  # a cable from 1 to 10 degrees east along the equator, a point every 0.45 degrees


def test_the_lights_are_on_the_short_links_into_the_hosts_and_none_past_link_km(monkeypatch):
    """A place reached on the lines has its link from the network's end (the junction its way ends at) into it, and
    home its link from where the way begins, each towards home; a place its way cannot reach has none: its dot."""
    index = Index({"cables": LINE})
    reached = {"id": "r", "lat": 0, "lon": 11.2, "count": 2}  # 133 km past the cable's end; home 111 km before it
    stranded = {"id": "s", "lat": -5, "lon": 5, "count": 1}  # some 550 km off the cable: its leg waits
    page = Network().onto(globe([reached, stranded]), index)
    assert reached["links"] == [[[0, 11.2], [0, 10]], [[0, 1], [0, 0]]]
    assert "links" not in stranded and page["waiting"][0]["to"] == "s"
    assert km((0, 11.2), (0, 10)) == pytest.approx(133.4, abs=0.1) and km((0, 1), (0, 0)) == pytest.approx(111.2, abs=0.1)
    monkeypatch.setattr(network, "LINK_KM", 120.0)  # the place's link now longer than a link is lit: not drawn
    Network().onto(globe([reached]), index)
    assert reached["links"] == [[[0, 1], [0, 0]]]
    monkeypatch.setattr(network, "LINK_KM", 100.0)  # and home's too: no light at all, the dots alone
    Network().onto(globe([reached]), index)
    assert "links" not in reached


def test_a_link_reaching_on_through_a_city_leg_is_measured_from_the_networks_end():
    """A leg within one city (under CITY_KM) after the lines' last leg needs no line: the link is from the junction
    the way left the lines at to the place itself, and lit only within LINK_KM of it (the snap alone is never more)."""
    index = Index({"cables": LINE})
    hop = {"lat": 0, "lon": 11.2, "label": "Hop"}  # 133 km past the cable's end, where the way leaves the lines
    far = {"id": "f", "lat": 0, "lon": 11.4, "count": 1, "via": [hop]}  # 22 km on: 155.7 km from the junction
    near = {"id": "n", "lat": 0, "lon": 11.3, "count": 1, "via": [hop]}  # 11 km on: 144.6 km from it
    page = Network().onto(globe([far, near]), index)
    assert page["waiting"] == []
    assert far["links"] == [[[0, 1], [0, 0]]]  # home's alone
    assert near["links"] == [[[0, 11.3], [0, 10]], [[0, 1], [0, 0]]]


def test_a_last_leg_that_waits_leaves_the_place_without_a_link():
    """The way's end is the network's only while no later leg waits: here the last leg waits (the hop and the place
    are nearest one junction, 133 km from the place), so the place shows its dot alone, though that junction is near."""
    index = Index({"cables": LINE})
    o = {"id": "q", "lat": 1.2, "lon": 10, "count": 1, "via": [{"lat": 0, "lon": 10.2, "label": "Hop"}]}
    page = Network().onto(globe([o]), index)
    assert [x["to"] for x in page["waiting"]] == ["q"] and o["links"] == [[[0, 1], [0, 0]]]  # home's alone


def test_a_first_leg_that_waits_leaves_home_without_a_link():
    """Home's link is drawn only where its route begins on the lines: here its first leg waits (both its ends are
    nearest one junction), so home shows its dot alone, and the place, reached on the lines, has its own link."""
    index = Index({"cables": LINE})
    o = {"id": "w", "lat": 0, "lon": 10.5, "count": 1, "via": [{"lat": 0, "lon": 1.5, "label": "Near"}]}
    page = Network().onto(globe([o]), index)
    assert [x["why"] for x in page["waiting"]] == ["both ends are nearest the same junction of the lines"]
    assert o["links"] == [[[0, 10.5], [0, 10]]]


E = [run((0, 0), (0, 10)), run((0, 10), (0, 20)), run((0, 10), (2, 10), 4)]  # east, on east, and a branch north
HUBS = {
    # Alpha 5.6 km off the first stretch; Eta 5.6 km south of the second, in the row of cells below the line's
    "landings": [(0.05, 2.5, "Alpha", "a landing"), (-0.05, 12.5, "Eta", "")],
    "exchanges": [(0.05, 7.5, "Delta", ""), (0.03, 15, "Beta", "")],
    # Gamma 111 km off the lines and Zeta 15 km: neither passed (HUB_KM)
    "cities": [(0, 10.05, "Epsilon", "XX-01 · 1,000"), (1.0, 5, "Gamma", ""), (0.135, 5, "Zeta", "")],
    # by the branch's end: two named at 2 and 3 km, four with no name nearer (0.6, 1.1, 1.7 km) and further (5.6):
    # EDGE_HUBS of a kind kept, the named first
    "datacentres": [(2.02, 10, "DC One", ""), (2.0, 10.03, "DC Two", ""), (2.005, 10, "", ""), (2.01, 10, "", ""),
                    (2.015, 10, "", ""), (2.05, 10, "", "")],
}
ALPHA, DELTA, BETA = "landings:0.050,2.500", "exchanges:0.050,7.500", "exchanges:0.030,15.000"
ETA = "landings:-0.050,12.500"
EPSILON = "cities:0.000,10.050"
DCS = ["datacentres:2.000,10.030", "datacentres:2.005,10.000", "datacentres:2.020,10.000"]


def places():
    return [{"id": "east", "lat": 0, "lon": 20, "count": 9}, {"id": "branch", "lat": 2, "lon": 10, "count": 1}]


def test_each_route_names_the_hubs_it_passes_in_its_order_weighed_by_the_traffic_through_them():
    index = Index({"cables": E}, HUBS)
    east, branch = places()
    page = Network().onto(globe([east, branch]), index)
    assert east["hubs"] == [ALPHA, DELTA, EPSILON, ETA, BETA]  # in its way's order, a hub at a junction named once
    assert branch["hubs"] == [ALPHA, DELTA, EPSILON, *DCS]  # the two named data centres and the nearest unnamed one
    hubs = {h["id"]: h for h in page["hubs"]}
    assert [h["id"] for h in page["hubs"]] == [EPSILON, DELTA, ALPHA, BETA, ETA, *DCS]  # the busiest first
    assert (hubs[ALPHA]["w"], hubs[ALPHA]["routes"], hubs[BETA]["w"], hubs[BETA]["routes"]) == (10, 2, 9, 1)
    assert hubs[ALPHA] == {"id": ALPHA, "lat": 0.05, "lon": 2.5, "kind": "landings", "what": "a cable landing station",
                           "name": "Alpha", "sub": "a landing", "w": 10, "routes": 2}
    assert hubs[EPSILON]["what"] == "a city" and hubs[EPSILON]["sub"] == "XX-01 · 1,000"
    assert "cities:1.000,5.000" not in hubs and "cities:0.135,5.000" not in hubs  # Gamma, Zeta: never within HUB_KM
    back = {"id": "back", "lat": 0, "lon": 0, "count": 3}  # the other way along the same lines: the order reversed
    Network().onto(globe([back], home=(0, 20)), index)
    assert back["hubs"] == [BETA, ETA, EPSILON, DELTA, ALPHA]


def test_the_hubs_are_read_by_the_cells_the_lines_cross_and_kept_with_the_graph():
    index, net = Index({"cables": E}, HUBS), Network()
    net.onto(globe(places()), index)
    ((layers, cells),) = index.asked
    assert layers == sorted(HUBS) and cell_of(2.5, 0.05) in cells and cell_of(5, 1.0) not in cells
    assert len(cells) <= 50  # the cells along the lines' 32 degrees alone (two rows), never a layer whole
    net.onto(globe(places()), index)
    assert len(index.asked) == 1 and net.hubs_read == 1  # asked again: nothing new read
    index.hub_version = 2  # a hub layer downloaded again
    net.onto(globe(places()), index)
    assert len(index.asked) == 2
    index.version = 2  # a line layer: a new graph, its stretches' hubs read again
    net.onto(globe(places()), index)
    assert len(index.asked) == 3
    net.clear()
    assert net._hub_key is None and not net._hub_edges


def test_the_hubs_are_bounded_on_the_page_and_on_each_route(monkeypatch):
    index = Index({"cables": E}, HUBS)
    monkeypatch.setattr(network, "MAX_HUBS", 2)
    east, branch = places()
    page = Network().onto(globe([east, branch]), index)
    assert [h["id"] for h in page["hubs"]] == [EPSILON, DELTA]
    assert east["hubs"] == [DELTA, EPSILON] and branch["hubs"] == [DELTA, EPSILON]  # those on the page alone
    monkeypatch.setattr(network, "MAX_HUBS", 400)
    monkeypatch.setattr(network, "ROUTE_HUBS", 2)
    east, branch = places()
    page = Network().onto(globe([east, branch]), index)
    assert east["hubs"] == [ALPHA, DELTA] and len(page["hubs"]) == 8  # the page still has every hub passed


def test_no_hubs_without_a_hub_layer_or_an_index_that_reads_points():
    east, branch = places()
    page = Network().onto(globe([east, branch]), LineIndex({"cables": E}))  # no `points`: an older index
    assert page["hubs"] == [] and "hubs" not in east
    page = Network().onto(globe(places()), Index({"cables": E}, {}))
    assert page["hubs"] == []
    page = Network().onto(globe(places()), Index({}, HUBS))  # no line layer: no way, no hubs
    assert page["hubs"] == [] and page["heat"] == []


SET = {"id": "test-hubs", "title": "Cables and landings", "format": "geojson", "layer": "cables",
       "url": "https://data.example/cables.geojson", "size": 1000, "source": "A test",
       "licence_name": "Public domain", "licence": "Public domain.", "credit": {"text": "A test", "url": ""}}


def kept(folder):
    """A set of a cable along E's first stretch and three landing stations, kept in a real infrastructure.db."""
    features = {"layers": {"cables": {"points": [], "lines": [([(lon, lat) for lat, lon in E[0]], "A cable")]},
                           "landings": {"points": [(2.5, 0.05, "Alpha", "a landing"), (5.0, 1.0, "Gamma", ""),
                                                   (2.55, 0.05, "Beside", "")], "lines": []}},
                "features": 4, "dropped": {}}
    Store(folder).put(SET, features, fetched=1.0)
    return RealIndex(folder, [SET])


def test_the_index_reads_points_by_cells_alone_within_its_bound(tmp_path):
    index = kept(tmp_path)
    alpha, beside = ("landings", 2.5, 0.05, "Alpha", "a landing"), ("landings", 2.55, 0.05, "Beside", "")
    assert index.points(["landings"], {cell_of(2.5, 0.05)}) == [alpha, beside]
    assert index.points(["landings"], {cell_of(2.5, 0.05)}, most=1) == [alpha]
    assert index.points(["landings"], set(range(1200)) | {cell_of(5.0, 1.0)}) == [("landings", 5.0, 1.0, "Gamma", "")]
    assert index.points(["landings"], {cell_of(100, 10)}) == [] and index.points(["exchanges"], {cell_of(2.5, 0)}) == []
    assert index.points(["cables"], {cell_of(2.5, 0)}) == []  # lines are never points


def test_a_route_over_a_kept_database_names_its_hubs(tmp_path):
    index = kept(tmp_path)
    o = {"id": "p", "lat": 0, "lon": 10, "count": 4}
    page = Network().onto(globe([o]), index)
    assert [h["name"] for h in page["hubs"]] == ["Alpha", "Beside"] and o["hubs"] == [h["id"] for h in page["hubs"]]
    assert page["heat"][0]["w"] == 4


def test_the_points_query_starts_from_the_cells_and_finds_each_feature_by_its_id(tmp_path):
    """The review of 1.106.0: Store.points' query is planned from the cells' key, each feature found by its id (never
    by features_by_layer, which visits every feature of the feeding sets for each chunk of cells), in the cells' order
    (no sort of its own), and limited."""
    import sqlite3

    from liminal_libs.machines import infrastore
    kept(tmp_path)
    con = sqlite3.connect(tmp_path / infrastore.FILE)
    try:
        for pairs in (1, 3):
            sql = infrastore.points_sql(500, pairs)
            plan = [row[-1] for row in con.execute("EXPLAIN QUERY PLAN " + sql,
                                                   [*range(500), *(["landings", SET["id"]] * pairs), 10])]
            assert "features_by_layer" not in " ".join(plan), plan
            (c,) = [i for i, p in enumerate(plan) if p.startswith("SEARCH c USING PRIMARY KEY (cell=?)")]
            (f,) = [i for i, p in enumerate(plan) if p.startswith("SEARCH f USING INTEGER PRIMARY KEY (rowid=?)")]
            assert c < f and not any("TEMP B-TREE" in p for p in plan), plan
            assert sql.endswith("LIMIT ?")
    finally:
        con.close()
