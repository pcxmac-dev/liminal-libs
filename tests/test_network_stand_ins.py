"""1.104.0 (Monday list item 24): fibre on land as a line layer, and the roads and railways as stand-ins for fibre where
none is mapped (machines/network.py): real fibre is taken where it is near enough, a stand-in where it is not, and a
leg or a run of heat along stand-ins alone is said so. Over stand-in layers (test_network's)."""
from __future__ import annotations

from liminal_libs.machines import network
from liminal_libs.machines.network import Network

from test_network import Index, globe, run


def test_the_line_layers_in_order():
    assert network.LINES == ("cables", "backbones", "lines", "fibre", "roads", "railways")
    assert network.STAND_INS == ("roads", "railways") and network.STAND_IN_COST == 1.5


def test_fibre_beside_a_shorter_road_is_taken():
    # the road is straight, the fibre bends north a little: 1.04 times as long, cheaper than 1.5 times the road
    road = run((0, 0), (0, 10))
    fibre = run((0, 0), (1.5, 5), 10)[:-1] + run((1.5, 5), (0, 10), 10)
    index = Index({"fibre": [fibre], "roads": [road]})
    net = Network()
    page = net.onto(globe([{"id": "p", "lat": 0, "lon": 10, "count": 2}]), index)
    (heat,) = page["heat"]
    assert [1.5, 5] in heat["points"] and "stand_in" not in heat
    assert all(", along roads" not in what for what, _ in net.legs.values())


def test_the_road_is_taken_where_no_fibre_is_and_said_so():
    index = Index({"roads": [run((0, 0), (0, 10))], "cables": [run((20, 20), (20, 30))]})
    net = Network()
    page = net.onto(globe([{"id": "p", "lat": 0, "lon": 10, "count": 1}]), index)
    (heat,) = page["heat"]
    assert heat["stand_in"] is True and page["waiting"] == []
    (what, why), = net.legs.values()
    assert what == f"this machine to p, {network.STAND_IN_WORDS}" and why == ""


def test_a_road_way_within_the_detour_in_km_is_not_refused_for_its_weight():
    # the road's way is 1.9 times the leg: weighed 2.8 times, yet within the 2.5 times its km may be
    road = run((0, 0), (8, 5), 10)[:-1] + run((8, 5), (0, 10), 10)
    page = Network().onto(globe([{"id": "p", "lat": 0, "lon": 10, "count": 1}]), Index({"roads": [road]}))
    assert len(page["heat"]) == 1 and page["heat"][0]["stand_in"] is True
