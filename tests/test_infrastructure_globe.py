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
    kept = b"".join(p.read_bytes() for p in (tmp_path / "f").iterdir())  # the database, every file of it
    assert b"Person" not in kept and b"mail.example" not in kept and b"Somebody" not in kept  # the undersea layer too
    assert b"Liquid" in kept
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


# -- item 27: the database, and an older file read in once ------------------------------------------------------------
def test_an_older_file_is_read_into_the_database_once_and_then_left(tmp_path, monkeypatch):
    import json
    import os
    from liminal_libs.machines import infrastore
    folder = tmp_path / "layers"
    folder.mkdir()
    older = pack(ROADS, parse(ROADS, roads_zip()), 1_763_294_400.0)  # 1.103.0's file of a download made then
    (folder / "ne-roads.json").write_text(json.dumps(older), encoding="ascii")
    os.utime(folder / "ne-roads.json", (1_763_300_000, 1_763_300_000))
    index = Index(folder, [ROADS], clock=Clock())
    (row,) = index.sets()
    assert row["installed"] is True and row["fetched"] == "2025-11-16T12:00:00+00:00" and row["features"] == 3
    kept = infrastore.Store(folder).sets()["ne-roads"]
    assert kept["accepted"] == 1_763_300_000 and kept["licence"] == PD  # accepted: when its file was written
    assert (folder / "ne-roads.json").exists()  # left where it is
    got = Index(folder, [ROADS], clock=Clock()).layer("roads")["parts"][0]["lines"]
    assert got == older["layers"]["roads"]["lines"]
    reads = []
    kept_of = infrastructure._kept
    monkeypatch.setattr(infrastructure, "_kept", lambda path, ident: reads.append(ident) or kept_of(path, ident))
    infrastructure._changed()
    assert Index(folder, [ROADS], clock=Clock()).sets()[0]["installed"] is True and reads == []  # not read again
    assert infrastructure.remove(ROADS, folder)["said"] == "removed Major roads (a stand-in for fibre)"
    assert not (folder / "ne-roads.json").exists() and Index(folder, [ROADS], clock=Clock()).sets()[0][
        "installed"] is False


def test_a_layer_is_read_by_area_and_coarse_below_its_zoom(tmp_path):
    folder = tmp_path / "layers"
    at = DataSet.of(ROADS).address()
    install(ROADS, folder, accept_licence=True, fetch=Downloads({at: roads_zip()}), clock=Clock())
    index = Index(folder, [ROADS], clock=Clock())
    near = index.layer("roads", area=[7.0, 49.0, 9.0, 51.0], zoom=8)
    assert near["parts"][0]["lines"]["names"] == ["A 5"] and near["area"] == [7.0, 49.0, 9.0, 51.0]
    assert index.layer("roads", area=[100.0, 0.0, 110.0, 10.0], zoom=8)["parts"] == []  # nothing there: none
    coarse = index.layer("roads", area=[7.0, 49.0, 9.0, 51.0], zoom=2)  # below COARSE_ZOOM: the whole, coarse
    assert coarse["parts"][0]["lines"]["n"] == 3 and "area" not in coarse
    assert places(coarse["parts"][0]["lines"])[:2] == [(8.0, 50.0), (8.5, 50.3)]  # 8.2 nearer than 0.25 degrees
    for wrong in ({"area": [0, 0, 1]}, {"area": ["0", 0, 1, 1]}, {"area": [0, 0, 1, 99]}, {"zoom": 0},
                  {"zoom": True}):
        with pytest.raises(ValueError):
            index.layer("roads", **wrong)


# -- items 28 and 29: TopoHub's backbones and RIPE Atlas, sources of the composite database ---------------------------
TOPOHUB = {"id": "topohub-world", "title": "The world's backbones, a model (TopoHub)", "format": "topohub",
           "url": "https://raw.topohub.example/topohub/master/data/backbone/world.json", "size": 1_040_000,
           "source": "TopoHub", "licence_name": "MIT (the repository's)",
           "licence": "TopoHub's repository is under the MIT licence; no licence is stated for its data.",
           "credit": {"text": "TopoHub (P. Jurkiewicz)", "url": "https://topohub.example/"}}
ATLAS_TERMS = "RIPE Atlas's data, for non-commercial use on this PC: commercial use needs the RIPE NCC's permission."
PROBES = {"id": "atlas-probes", "title": "RIPE Atlas probes and anchors", "format": "atlas-probes",
          "url": "https://ftp.atlas.example/ripe/atlas/probes/archive/meta-latest", "size": 2_000_000,
          "source": "RIPE Atlas (RIPE NCC)", "licence_name": "RIPE Atlas terms 3.5 (non-commercial)",
          "licence": ATLAS_TERMS, "credit": {"text": "RIPE Atlas (RIPE NCC)", "url": "https://atlas.example/"}}
LATEST = {**PROBES, "id": "atlas-traceroutes", "title": "RIPE Atlas traceroutes from its anchors",
          "format": "atlas-latest", "url": "https://atlas.example/api/v2/measurements/5151/latest/",
          "query": "format=json", "size": 5_000_000, "needs": "atlas-probes"}
WORLD = {"directed": False, "multigraph": False, "graph": {},
         "nodes": [{"id": 0, "pos": [-0.13, 51.51], "type": "City", "name": "London"},
                   {"id": 1, "pos": [2.35, 48.86], "type": "City", "name": "Paris"},
                   {"id": 2, "pos": [-5.55, 50.12], "type": "Seacable Landing Point", "name": "Porthcurno"},
                   {"id": 3, "type": "City", "name": "Nowhere"}],
         "links": [{"source": 0, "target": 1, "dist": 343.5, "type": "land"},
                   {"source": 0, "target": 2, "dist": 400.1, "type": "seacable"},
                   {"source": 1, "target": 3, "dist": 10.0}]}


def test_topohubs_model_is_read_into_its_layers_and_the_composite_database(tmp_path):
    import json
    import sqlite3
    from liminal_libs.machines import composite
    got = parse(TOPOHUB, json.dumps(WORLD).encode())
    assert [p[2] for p in got["layers"]["pops"]["points"]] == ["London", "Paris"]  # a city alone: no landing point
    assert [name for _, name in got["layers"]["models"]["lines"]] == ["London to Paris", "Porthcurno to London"]
    assert got["layers"]["models"]["lines"][1][0] == [(-5.55, 50.12), (-0.13, 51.51)]  # its seacable edge: a model's
    assert "cables" not in got["layers"] and got["dropped"] == {"with no place": 1, "between points not drawn": 1}
    folder = tmp_path / "layers"
    out = install(TOPOHUB, folder, accept_licence=True,
                  fetch=Downloads({DataSet.of(TOPOHUB).address(): json.dumps(WORLD).encode()}), clock=Clock())
    assert "given to the composite database: 2 places, 2 links" in out["lines"]
    with sqlite3.connect(folder / composite.FILE) as con:
        rows = con.execute("SELECT n.kind, n.key, e.source FROM evidence e JOIN entities n ON n.id = e.entity "
                           "ORDER BY n.kind, n.key").fetchall()
    assert rows == [("link", "topohub:London|51.51,-0.13>Paris|48.86,2.35", "topohub"),
                    ("link", "topohub:Porthcurno|50.12,-5.55>London|51.51,-0.13", "topohub"),
                    ("place", "London|51.51,-0.13", "topohub"), ("place", "Paris|48.86,2.35", "topohub")]
    assert composite.SOURCES["topohub"][0] == 0.3 and composite.SOURCES["atlas"][0] == 0.7


def probes_file() -> bytes:
    import bz2
    import json
    objects = [{"id": 6001, "is_anchor": True, "status": {"id": 1, "name": "Connected"}, "country_code": "nl",
                "asn_v4": 3333, "asn_v6": 3333, "geometry": {"type": "Point", "coordinates": [4.89, 52.37]},
                "description": "Someone's own words", "tags": [{"name": "home"}]},
               {"id": 6002, "is_anchor": True, "status": {"id": 2, "name": "Disconnected"}, "country_code": "DE",
                "geometry": {"type": "Point", "coordinates": [13.4, 52.5]}},
               {"id": 7, "is_anchor": False, "status": 1, "country_code": "FR", "asn_v4": 12322,
                "geometry": {"type": "Point", "coordinates": [2.35, 48.86]}},
               {"id": 8, "is_anchor": False, "status": 1, "geometry": None}]
    return bz2.compress(json.dumps({"meta": {}, "objects": objects}).encode())


def test_ripe_atlas_probes_are_kept_without_their_owners_words(tmp_path):
    from liminal_libs.machines.infrastore import Store
    folder = tmp_path / "layers"
    out = install(PROBES, folder, accept_licence=True, fetch=Downloads({DataSet.of(PROBES).address(): probes_file()}),
                  clock=Clock())
    assert out["file"]["layers"] == {"probes": 3}
    rows = Store(folder).probes()
    assert [(p["id"], p["country"], p["anchor"], p["connected"]) for p in rows] == [
        (7, "FR", 0, 1), (6001, "NL", 1, 1), (6002, "DE", 1, 0)]
    part = Index(folder, [PROBES]).layer("probes")["parts"][0]["points"]
    assert part["names"] == ["Anchor 6001", "Anchor 6002", "Probe 7"]
    assert part["subs"] == ["NL · AS3333", "DE · not connected", "FR · AS12322"]
    kept = b"".join(p.read_bytes() for p in folder.iterdir())
    assert b"Someone" not in kept and b"home" not in kept


def test_ripe_atlas_traceroutes_need_the_probes_and_place_routers_near_an_anchor(tmp_path):
    import json
    import sqlite3
    import urllib.error
    from liminal_libs.machines import composite
    folder = tmp_path / "layers"
    with pytest.raises(ValueError, match="read with the data set atlas-probes: download that first"):
        install(LATEST, folder, accept_licence=True, fetch=Downloads({}), clock=Clock())
    index = Index(folder, [PROBES, LATEST], clock=Clock())
    assert [f["id"] for f in index.forms()] == ["world-layer-atlas-probes"]  # not offered before the probes
    assert index.table()["rows"][1][4] == {"text": "needs RIPE Atlas probes and anchors"}
    install(PROBES, folder, accept_licence=True, fetch=Downloads({DataSet.of(PROBES).address(): probes_file()}),
            clock=Clock())
    at = "https://atlas.example/api/v2/measurements/5151/latest/?format=json&probe_ids=6001"
    assert DataSet.of(LATEST).addresses(range(1, 701))[2].endswith("probe_ids=" + ",".join(map(str, range(601, 701))))
    result = [{"prb_id": 6001, "from": "192.0.2.7", "result": [
        {"hop": 1, "result": [{"from": "10.0.0.1", "rtt": 0.2}]},  # private: never kept
        {"hop": 2, "result": [{"from": "193.0.0.1", "rtt": 0.8}, {"from": "193.0.0.1", "rtt": 0.6}]},
        {"hop": 3, "result": [{"x": "*"}]},
        {"hop": 4, "result": [{"from": "8.8.4.1", "rtt": 9.5}]},
        {"hop": 5, "result": [{"from": "8.8.8.8", "rtt": 10.1}]}]},
        {"prb_id": 999, "result": []}]  # a probe not in the table: left out
    out = install(LATEST, folder, accept_licence=True, fetch=Downloads({at: json.dumps(result).encode()}),
                  clock=Clock())
    assert out["ok"] is True and "given to the composite database: 1 router placed, 1 link" in out["lines"]
    with sqlite3.connect(folder / composite.FILE) as con:
        claims = con.execute("SELECT n.key, e.source, e.claim FROM evidence e JOIN entities n ON n.id = e.entity "
                             "WHERE n.kind = 'router'").fetchall()
        links = con.execute("SELECT n.key FROM entities n WHERE n.kind = 'link'").fetchall()
    (address, source, claim), = claims
    assert (address, source) == ("193.0.0.1", "atlas")
    assert json.loads(claim) == {"lat": 52.37, "lon": 4.89, "ms": 0.6, "within_km": 30.0,
                                 "label": "near RIPE Atlas anchor 6001"}
    assert links == [("8.8.4.1>8.8.8.8",)]  # the hops on either side of a silent one are not linked
    refused = Downloads({at: urllib.error.HTTPError(at, 403, "Forbidden", {}, None)})
    with pytest.raises(InfrastructureError, match="it asks for credentials, and none is ever sent from here"):
        install(LATEST, folder, accept_licence=True, fetch=refused, clock=Clock())
