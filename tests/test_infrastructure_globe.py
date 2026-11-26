"""The globe's data sets of 1.104.0 (Monday list items 24, 27, 28, 29, 32; machines/infrastructure.py): the new keys of
a plugin's data set, Natural Earth's roads and railways as shapefiles (made here, tests/shapes.py), their stand-ins for
fibre said, a redirect to the hosts a data set names. Nothing is downloaded: the fetch is a stand-in, and the real
fetch_url runs over stand-in protocols only (test_infrastructure's fixture, used here as there)."""
from __future__ import annotations

import re

import pytest

from liminal_libs.machines import infrastructure
from liminal_libs.machines.infrastructure import DataSet, Index, InfrastructureError, install, pack, parse

import shapes as S
from test_infrastructure import Clock, Downloads, Web, _nothing_real, over, places  # noqa: F401 - the fixture, used

pytestmark = pytest.mark.usefixtures("no_outside")

PD = "Natural Earth's data is in the public domain: no permission is needed to use it."
NE = {"format": "shapefile", "source": "Natural Earth", "licence_name": "Public domain", "licence": PD,
      "credit": {"text": "Made with Natural Earth", "url": "https://www.naturalearth.example/"},
      "hosts": ["cdn.ne.example"]}
ROADS = {**NE, "id": "ne-roads", "title": "Major roads (a stand-in for fibre)", "layer": "roads", "stand_in": True,
         "url": "https://www.naturalearth.example/download/10m/cultural/ne_10m_roads.zip", "size": 8_660_000,
         "member": "ne_10m_roads", "drop": {"featurecla": ["Ferry"]}, "step": 0.05}
RAILWAYS = {**NE, "id": "ne-railways", "title": "Railways (a stand-in for fibre)", "layer": "railways",
            "stand_in": True, "url": "https://www.naturalearth.example/download/10m/cultural/ne_10m_railroads.zip",
            "size": 14_420_000, "drop": {"featurecla": ["Railroad ferry"]}}
FIELDS = [("featurecla", "C", 16), ("type", "C", 20), ("name", "C", 20)]


def roads_zip() -> bytes:
    records = [(3, [[(8.0, 50.0), (8.01, 50.01), (8.2, 50.1), (8.5, 50.3)]]),
               (3, [[(9.0, 54.0), (10.0, 55.0)]]),
               (3, [[(-1.0, 51.0), (0.0, 51.5)], [(0.0, 51.5), (1.0, 52.0)]])]
    rows = [["Road", "Major Highway", "A 5"], ["Ferry", "Ferry Route", "Puttgarden"], ["Road", "Secondary Highway", ""]]
    return S.zipped("ne_10m_roads", shp_bytes=S.shp(records), dbf_bytes=S.dbf(FIELDS, rows))


def test_the_new_keys_of_a_data_set_are_read_and_what_is_wrong_is_said():
    roads = DataSet.of(ROADS)
    assert (roads.layer, roads.member, roads.stand_in, roads.step, roads.hosts) == (
        "roads", "ne_10m_roads", True, 0.05, ("cdn.ne.example",))
    assert roads.drop == (("featurecla", ("Ferry",)),) and roads.keep == ()
    plain = DataSet.of({**RAILWAYS, "hosts": []})
    assert (plain.stand_in, plain.step, plain.hosts, plain.member) == (True, infrastructure.STEP, (), "")
    assert hash(roads) == hash(DataSet.of(dict(ROADS)))
    for change, words in (({"layer": "motorways"}, "layer is one of the globe's"),
                          ({"layer": ""}, "is a shapefile and names no layer"),
                          ({"stand_in": "yes"}, "stand_in is true or false"),
                          ({"step": 0}, "step is a number of degrees from 0.001 to 1"),
                          ({"step": True}, "step is a number of degrees"),
                          ({"hosts": ["cdn ne"]}, "hosts are the names a redirect may go to"),
                          ({"hosts": "cdn.ne.example"}, "hosts are the names"),
                          ({"member": "../x"}, "member is a shapefile's stem"),
                          ({"drop": {"featurecla": "Ferry"}}, "drop is {field: [values]}"),
                          ({"keep": ["Road"]}, "keep is {field: [values]}")):
        with pytest.raises(ValueError, match=re.escape(words)):
            DataSet.of({**ROADS, **change})


def test_a_shapefile_set_is_read_into_its_layer_its_drop_and_step_applied():
    got = parse(ROADS, roads_zip())
    lines = got["layers"]["roads"]["lines"]
    assert [name for _, name in lines] == ["A 5", "Secondary Highway", "Secondary Highway"]  # the ferry left out
    assert lines[0][0] == [(8.0, 50.0), (8.2, 50.1), (8.5, 50.3)]  # 8.01 is nearer than its step, 0.05
    assert got["dropped"] == {"of no kind asked for": 1}
    kept = parse({**ROADS, "drop": None, "keep": {"type": ["Ferry Route"]}}, roads_zip())
    assert [name for _, name in kept["layers"]["roads"]["lines"]] == ["Puttgarden"]
    with pytest.raises(InfrastructureError, match="not WGS 84"):
        parse(ROADS, S.zipped("ne_10m_roads", shp_bytes=S.shp([(3, [[(0, 0), (1, 1)]])]),
                              dbf_bytes=S.dbf(FIELDS, [["Road", "", ""]]), prj=S.MERCATOR_PRJ))
    with pytest.raises(InfrastructureError, match="no ne_10m_roads.shp"):
        parse(ROADS, S.zipped("other", shp_bytes=S.shp([]), dbf_bytes=S.dbf(FIELDS, [])))


def test_a_stand_in_is_kept_so_and_said_in_its_layer(tmp_path):
    folder = tmp_path / "layers"
    packed = pack(ROADS, parse(ROADS, roads_zip()), 0)
    assert packed["stand_in"] is True and "stand_in" not in pack({**ROADS, "stand_in": False},
                                                                 parse(ROADS, roads_zip()), 0)
    at = DataSet.of(ROADS).address()
    out = install(ROADS, folder, accept_licence=True, fetch=Downloads({at: roads_zip()}), clock=Clock())
    assert out["ok"] is True and out["file"]["layers"] == {"roads": 3}
    listed = Index(folder, [ROADS, RAILWAYS]).layers()
    assert [(e["id"], e["mark"], e.get("stand_in")) for e in listed] == [("roads", "dash", True)]
    assert places(Index(folder, [ROADS]).layer("roads")["parts"][0]["lines"])[:3] == [(8.0, 50.0), (8.2, 50.1),
                                                                                       (8.5, 50.3)]


def test_a_redirect_goes_to_the_hosts_a_data_set_names_and_no_other(tmp_path):
    at = DataSet.of(ROADS).address()
    there = "https://cdn.ne.example/naturalearth/10m/cultural/ne_10m_roads.zip"
    web = Web({at: (302, {"Location": there}, b""), there: (200, {}, roads_zip())})
    assert install(ROADS, tmp_path / "a", accept_licence=True, fetch=over(web), clock=Clock())["ok"] is True
    assert web.asked == [at, there]
    other = "https://cdn.other.example/ne_10m_roads.zip"
    web = Web({at: (302, {"Location": other}, b""), other: (200, {}, roads_zip())})
    with pytest.raises(InfrastructureError, match="sent on to https://cdn.other.example"):
        install(ROADS, tmp_path / "b", accept_licence=True, fetch=over(web), clock=Clock())
    assert web.asked == [at]
    asked = Downloads({at: roads_zip()})
    install(ROADS, tmp_path / "c", accept_licence=True, fetch=asked, clock=Clock())
    assert asked.asked[0][2]["hosts"] == ("cdn.ne.example",)
    plain = Downloads({DataSet.of({**RAILWAYS, "hosts": []}).address(): roads_zip()})
    with pytest.raises(InfrastructureError, match="every feature was left out"):  # the zip's one .shp, all dropped
        install({**RAILWAYS, "hosts": [], "layer": "railways", "drop": {"type": ["Major Highway", "Ferry Route",
                                                                                 "Secondary Highway"]}},
                tmp_path / "d", accept_licence=True, fetch=plain, clock=Clock())
    assert "hosts" not in plain.asked[0][2]  # none named: fetch is told nothing more than before


# -- AfTerFibre's fibre as map tiles (item 24, piece 4) ----------------------------------------------------------------
AFTERFIBRE = {"id": "afterfibre", "title": "Africa's terrestrial fibre", "format": "mvt", "layer": "fibre",
              "url": "https://tiles.afterfibre.example/africa-fiber/{z}/{x}/{y}.mvt", "member": "fiber",
              "tiles": {"zoom": 5, "bounds": [-17.42, -34.50, 55.74, 36.87]}, "size": 3_000_000,
              "source": "AfTerFibre (NSRC)", "licence_name": "CC BY 4.0",
              "licence": "AfTerFibre's data is free under Creative Commons Attribution 4.0.",
              "credit": {"text": "AfTerFibre, NSRC", "url": "https://afterfibre.example/"}}
PEOPLE = {"contributor": "A Person", "contrib_email": "a.person@mail.example"}


def fibre_tile(*lines, live=True) -> bytes:
    import tiles as T
    return T.tile(T.layer("fiber", [(2, [line], {"operator_name": "Liquid", "live": live, **PEOPLE}) for line in lines]),
                  T.layer("undersea", [(2, [[(0, 0), (4096, 4096)]], {"operator_name": "Somebody's cable"})]))


def test_map_tiles_are_named_and_asked_one_by_one_and_their_people_never_kept(tmp_path):
    fibre = DataSet.of(AFTERFIBRE)
    assert len(fibre.tiles) == 56 and fibre.tiles[0] == (5, 14, 12) and fibre.address() == fibre.addresses()[0]
    assert fibre.addresses()[0] == "https://tiles.afterfibre.example/africa-fiber/5/14/12.mvt"
    form = infrastructure.form(fibre, tmp_path)
    assert "in 56 requests, one after another" in form["confirm"]["words"]
    assert "in one request" in infrastructure.form(ROADS, tmp_path)["confirm"]["words"]
    first, second = fibre.addresses()[0], fibre.addresses()[1]
    asked = Downloads({first: fibre_tile([(0, 0), (2048, 2048)]), second: fibre_tile([(0, 2048), (100, 2048)],
                                                                                    live=False)})
    out = install(AFTERFIBRE, tmp_path / "f", accept_licence=True, fetch=asked, clock=Clock())
    assert out["ok"] is True and out["file"]["layers"] == {"fibre": 2}  # 54 tiles not there: nothing in them
    assert [a[0] for a in asked.asked] == fibre.addresses()
    text = (tmp_path / "f" / "afterfibre.json").read_text(encoding="ascii")
    assert "Person" not in text and "mail.example" not in text and "Somebody" not in text  # the undersea layer too
    part = Index(tmp_path / "f", [AFTERFIBRE]).layer("fibre")["parts"][0]["lines"]
    assert part["names"] == ["Liquid", "Liquid (planned)"]
    (lon0, lat0), (lon1, lat1) = places(part)[:2]
    assert (lon0, lat0) == pytest.approx((-22.5, 40.97990), abs=1e-4)  # tile 14/12's corner
    assert (lon1, lat1) == pytest.approx((-16.875, 36.59789), abs=1e-4)  # its middle


def test_a_tile_that_fails_stops_the_install_with_nothing_kept(tmp_path):
    import urllib.error
    fibre = DataSet.of(AFTERFIBRE)
    first, third = fibre.addresses()[0], fibre.addresses()[2]
    asked = Downloads({first: fibre_tile([(0, 0), (2048, 2048)]),
                       third: urllib.error.HTTPError(third, 403, "Forbidden", {}, None)})
    with pytest.raises(InfrastructureError, match="Forbidden|403"):
        install(AFTERFIBRE, tmp_path / "f", accept_licence=True, fetch=asked, clock=Clock())
    assert len(asked.asked) == 3 and not (tmp_path / "f" / "afterfibre.json").exists()
    with pytest.raises(InfrastructureError, match="tile 5/14/12 is not the data asked for"):
        install(AFTERFIBRE, tmp_path / "g", accept_licence=True, fetch=Downloads({first: b"\x1a\xff"}), clock=Clock())
    for change, words in (({"url": "https://tiles.afterfibre.example/africa-fiber.mvt"}, "holds {z}, {x} and {y}"),
                          ({"tiles": {"zoom": 9, "bounds": [-17.42, -34.50, 55.74, 36.87]}}, "more than the 128"),
                          ({"tiles": {"zoom": 5, "bounds": [10, 0, 5, 1]}}, "bounds: [west"),
                          ({"layer": ""}, "names no layer its lines go to")):
        with pytest.raises(ValueError, match=re.escape(words)):
            DataSet.of({**AFTERFIBRE, **change})
