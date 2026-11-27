"""Street maps on the globe (1.108.0, Monday list item 25; machines/infrastructure.py): the countries' and the states'
names at the label points of Natural Earth's records (its shapes never read), the states' boundaries, GeoNames' towns
and its counties named at the middle of their towns, and a region's major roads, buildings and counties' boundaries
from OpenStreetMap through the Overpass API, its box asked a piece at a time and each piece's XML read as it comes;
each feature's zoom, the layers read by area and zoom, the regions round home and those added. Nothing is downloaded:
the fetch is a stand-in, the files are made here (tests/shapes.py, a zip and XML of a few lines)."""
from __future__ import annotations

import io
import math
import re
import zipfile

import pytest

from liminal_libs.machines import infrastructure
from liminal_libs.machines.infrastore import Store
from liminal_libs.machines.infrastructure import DataSet, Index, InfrastructureError, Packed, install, parse

import shapes as S
from test_infrastructure import Clock, Downloads, _nothing_real, places  # noqa: F401 - the fixture, used

pytestmark = pytest.mark.usefixtures("no_outside")

PD = "Natural Earth's data is in the public domain: no permission is needed to use it."
NE = {"format": "shapefile", "source": "Natural Earth", "licence_name": "Public domain", "licence": PD,
      "credit": {"text": "Made with Natural Earth", "url": "https://www.naturalearth.example/"}}
COUNTRIES = {**NE, "id": "ne-countries", "title": "Countries' names", "layer": "countrynames",
             "url": "https://www.naturalearth.example/ne_10m_admin_0_countries.zip", "size": 4_700_000,
             "label": {"lon": "LABEL_X", "lat": "LABEL_Y", "rank": "MIN_LABEL"}}
STATE_LINES = {**NE, "id": "ne-state-lines", "title": "States' boundaries", "layer": "states", "step": 0.01,
               "url": "https://www.naturalearth.example/ne_10m_admin_1_states_provinces_lines.zip", "size": 5_720_000}
CC_BY = "GeoNames' data is free under the Creative Commons Attribution 4.0 licence."
PLACES = {"id": "geonames-places", "title": "Cities, towns and counties", "format": "geonames-places",
          "url": "https://download.geonames.example/export/dump/cities500.zip", "also": ["admin2Codes.txt"],
          "source": "GeoNames", "licence_name": "CC BY 4.0", "licence": CC_BY, "size": 15_600_000,
          "most": 48 << 20, "credit": {"text": "GeoNames", "url": "https://www.geonames.example/"}}
ODBL = "OpenStreetMap's data is free under the Open Database License 1.0."
QUERY = ('[out:xml][timeout:120][bbox:{bbox}];(way["highway"~"^(motorway|trunk|primary|secondary|tertiary)'
         '(_link)?$"];way["building"];way["boundary"="administrative"]["admin_level"="6"];);out tags geom qt;')
STREETS = {"id": "osm-streets", "title": "Major roads and buildings", "format": "osm-xml",
           "url": "https://overpass.example/api/interpreter", "query": QUERY, "region": {"km": 20, "piece": 0.1},
           "source": "OpenStreetMap, through the Overpass API", "licence_name": "ODbL 1.0", "licence": ODBL,
           "size": 60_000_000, "most": 128 << 20, "step": 0.00002, "wait": 150,
           "credit": {"text": "© OpenStreetMap contributors", "url": "https://www.openstreetmap.example/copyright"}}
NE_FIELDS = [("NAME", "C", 30), ("LABEL_X", "F", 12), ("LABEL_Y", "F", 12), ("MIN_LABEL", "F", 6)]


def countries_zip(rows=None, fields=NE_FIELDS) -> bytes:
    rows = rows if rows is not None else [["France", 2.55, 46.69, 3.0], ["Andorra", 1.54, 42.55, 7.0],
                                          ["", 0.0, 0.0, 1.0], ["Nowhere", 500.0, 0.0, 2.0]]
    return S.zipped("ne_10m_admin_0_countries", shp_bytes=b"never read", dbf_bytes=S.dbf(fields, rows))


def test_names_are_read_from_the_records_label_points_each_from_the_zoom_its_rank_says():
    got = parse(COUNTRIES, countries_zip())
    points = got["layers"]["countrynames"]["points"]
    assert [p[2] for p in points] == ["France", "Andorra"]  # no name, and a place off the globe, left out
    assert points[0][:2] == (2.55, 46.69) and points[0][4] == 1.0  # rank 3: from the start (2^(3 - 3.67) is 0.63)
    assert infrastructure._rank_zoom(4.67) == 2.0 and infrastructure._rank_zoom(None) == 1.0  # never before the start
    assert points[1][4] == round(2 ** (7.0 - infrastructure.WEB_ZOOM - infrastructure.LABEL_EARLY), 2)  # some 10x
    assert got["dropped"] == {"of no kind asked for": 1, "off the globe": 1}
    with pytest.raises(InfrastructureError, match="hold no LABEL_X and LABEL_Y"):
        parse(COUNTRIES, countries_zip([["France", "x"]], [("NAME", "C", 30), ("OTHER", "C", 4)]))
    for change, words in (({"layer": "states"}, "of a layer of points"), ({"label": {"lon": "X"}}, "label is"),
                          ({"label": {"lon": "X", "lat": "Y", "rank": "no spaces"}}, "label is"),
                          ({"format": "geojson", "layer": "countrynames"}, "label is")):
        with pytest.raises(ValueError, match=re.escape(words)):
            DataSet.of({**COUNTRIES, **change})


def test_a_by_area_layer_holds_more_than_a_layer_drawn_whole_and_its_lines_packed(monkeypatch):
    monkeypatch.setattr(infrastructure, "MAX_POINTS", 1)
    monkeypatch.setattr(infrastructure, "MAX_VERTICES", 2)
    lines = [(3, [[(1.0, 45.0), (1.5, 45.5), (2.0, 46.0)]]), (3, [[(1.0, 45.0), (1.5, 45.5), (2.0, 46.0)]])]
    data = S.zipped("lines", shp_bytes=S.shp(lines), dbf_bytes=S.dbf([("name", "C", 4)], [["a"], ["b"]]))
    got = parse(STATE_LINES, data)["layers"]["states"]["lines"]
    assert len(got) == 2 and isinstance(got[0][0], Packed)  # over MAX_VERTICES, and the same line twice: both kept
    assert list(got[0][0]) == [(1.0, 45.0), (1.5, 45.5), (2.0, 46.0)] and len(got[0][0]) == 3
    roads = parse({**STATE_LINES, "id": "x", "layer": "roads"}, data)  # a layer drawn whole keeps its bounds
    assert "roads" not in roads["layers"] and roads["dropped"] == {"over the most a layer keeps": 2}


def places_zip(lines: list[str]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("cities500.txt", "\n".join(lines) + "\n")
    return out.getvalue()


def town(gid, name, lat, lon, country, a1, a2, people) -> str:
    f = [""] * 19
    f[0], f[1], f[2], f[4], f[5], f[8], f[10], f[11], f[14] = (str(gid), name, name, str(lat), str(lon), country, a1,
                                                               a2, str(people))
    return "\t".join(f)


TOWNS = [town(1, "Paris", 48.8566, 2.3522, "FR", "11", "75", 2_138_551),
         town(2, "Boulogne-Billancourt", 48.8333, 2.25, "FR", "11", "92", 120_071),
         town(3, "Nanterre", 48.8924, 2.2071, "FR", "11", "92", 96_277),
         town(4, "Sceaux", 48.7779, 2.2905, "FR", "11", "92", 19_679),
         town(5, "Hameau", 45.0, 5.0, "FR", "84", "", 600)]
CODES = "FR.11.75\tParis\tParis\t2968815\nFR.11.92\tHauts-de-Seine\tHauts-de-Seine\t3013657\nFR.11.93\tSeine\tSeine\t9\n"


def test_geonames_towns_from_the_zoom_their_people_say_and_counties_at_the_middle_of_their_towns():
    got = parse(PLACES, [(0, places_zip(TOWNS)), (1, CODES.encode())])
    towns = got["layers"]["towns"]["points"]
    assert [(t[2], t[4]) for t in towns] == [("Paris", 32.0), ("Boulogne-Billancourt", 32.0), ("Nanterre", 64.0),
                                             ("Sceaux", 64.0), ("Hameau", 256.0)]  # the most people first
    assert towns[0][3] == "FR-11 · 2,138,551"
    counties = {c[2]: c for c in got["layers"]["counties"]["points"]}
    assert set(counties) == {"Paris", "Hauts-de-Seine"} and got["dropped"] == {"with no place": 1}  # Seine: no town
    lon, lat = counties["Hauts-de-Seine"][:2]
    assert lon == pytest.approx((2.25 + 2.2071 + 2.2905) / 3, abs=1e-3)
    assert lat == pytest.approx((48.8333 + 48.8924 + 48.7779) / 3, abs=1e-3)
    assert counties["Paris"][3] == "FR-11" and counties["Paris"][4] == infrastructure.COUNTY_ZOOM
    one = DataSet.of(PLACES)
    assert one.addresses() == ["https://download.geonames.example/export/dump/cities500.zip",
                               "https://download.geonames.example/export/dump/admin2Codes.txt"]
    with pytest.raises(ValueError, match="names its divisions' file"):
        DataSet.of({**PLACES, "also": []})
    with pytest.raises(ValueError, match="also are the files beside"):
        DataSet.of({**PLACES, "also": ["../admin2Codes.txt"]})
    with pytest.raises(InfrastructureError, match="the cities' zip, the divisions' file"):
        parse(PLACES, b"one answer")


def test_geonames_places_are_installed_from_both_files_on_one_click(tmp_path):
    one = DataSet.of(PLACES)
    asked = Downloads({one.addresses()[0]: places_zip(TOWNS), one.addresses()[1]: CODES.encode()})
    out = install(PLACES, tmp_path, accept_licence=True, fetch=asked, clock=Clock())
    assert out["ok"] is True and out["file"]["layers"] == {"counties": 2, "towns": 5}
    assert [a[0] for a in asked.asked] == one.addresses()
    index = Index(tmp_path, [PLACES])
    assert index.layer("towns", area=(2.0, 48.5, 2.5, 49.0), zoom=16)["parts"][0]["points"]["names"] == [
        "Paris", "Boulogne-Billancourt"]  # from 32x: twice 16x
    assert index.layer("towns", zoom=1) == {"id": "towns", "version": index.layer("towns", zoom=1)["version"],
                                            "parts": []}  # a ranked layer with nothing yet: no parts, no refusal


def way(ident, points, **tags) -> str:
    nd = "".join(f'<nd lat="{lat}" lon="{lon}"/>' for lon, lat in points)
    tag = "".join(f'<tag k="{k.replace("_", ":") if k.startswith("addr") else k}" v="{v}"/>' for k, v in tags.items())
    return f'<way id="{ident}">{nd}{tag}</way>'


def answer(*ways, remark="") -> bytes:
    body = "".join(ways) + (f"<remark>{remark}</remark>" if remark else "")
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<osm version="0.6" generator="Overpass API">'
            f'<note>The data included in this document is from www.openstreetmap.org.</note>{body}</osm>').encode()


def test_a_regions_roads_buildings_and_counties_boundaries_are_read_by_their_tags():
    big = [(2.30, 48.85), (2.31, 48.85), (2.31, 48.86), (2.30, 48.86), (2.30, 48.85)]  # some 1.1 km across
    small = [(2.3, 48.8), (2.302, 48.8), (2.302, 48.802), (2.3, 48.8)]  # some 220 m
    xml = answer(way(1, [(2.0, 48.0), (2.1, 48.1)], highway="motorway", ref="A 6"),
                 way(2, [(2.0, 48.2), (2.1, 48.3)], highway="tertiary_link", name="Rue de Vaugirard"),
                 way(3, [(2.0, 48.4), (2.1, 48.5)], highway="residential", name="not major"),
                 way(4, big, building="yes", name="Halle"), way(5, small, building="house", addr_street="Rue X"),
                 way(6, small, building="no"),
                 way(7, [(2.2, 48.6), (2.3, 48.7)], boundary="administrative", admin_level="6", name="Paris"),
                 way(8, [(2.2, 48.6), (2.3, 48.7)], boundary="administrative", admin_level="8"))
    got = parse(STREETS, xml)
    streets = got["layers"]["streets"]["lines"]
    assert [(s[1], s[2]) for s in streets] == [("A 6", 64.0), ("Rue de Vaugirard", 128.0)]
    buildings = got["layers"]["buildings"]["lines"]
    assert buildings[0][1] == "Halle" and buildings[0][2] == 64.0  # large: from 64x, the soonest
    assert buildings[1][2] == pytest.approx(infrastructure.BUILDING_PX * infrastructure.PIXEL_M / 221.1, rel=0.02)
    tiny = parse(STREETS, answer(way(9, [(2.3, 48.8), (2.3001, 48.8)], building="yes")))["layers"]["buildings"]
    assert tiny["lines"][0][2] == 1024.0  # under a pixel even at 1024x: drawn there, never nearer out
    assert len(list(buildings[0][0])) == 5  # its ring, closed
    assert got["layers"]["countylines"]["lines"][0][1:] == ("Paris", infrastructure.COUNTY_ZOOM)
    assert got["dropped"] == {"of no kind asked for": 3}
    assert b"Rue X" not in repr(got).encode()  # only the name and the ref of a way are kept
    with pytest.raises(InfrastructureError, match="could not finish the query"):
        parse(STREETS, answer(remark="runtime error: Query timed out in \"query\" at line 1 after 121 seconds."))
    with pytest.raises(InfrastructureError, match="declares a document type"):
        parse(STREETS, b'<?xml version="1.0"?><!DOCTYPE osm [<!ENTITY a "aaaa">]><osm>&a;</osm>')
    with pytest.raises(InfrastructureError, match="its XML does not read"):
        parse(STREETS, b"<osm><way>")
    with pytest.raises(InfrastructureError, match="not osm"):
        parse(STREETS, b"<html></html>")


def test_a_region_is_its_templates_round_a_place_asked_in_pieces():
    template = DataSet.of(STREETS)
    assert template.pieces() == [] and template.addresses() == []  # round no place yet
    home = template.placed(48.85661, 2.35222, "Paris")
    assert home.id == "osm-streets-n4886e00235" and home.title == "Major roads and buildings round Paris"
    assert home.place == (48.86, 2.35, "Paris")
    s, w, n, e = home.box()
    assert (n - s) * 110.574 == pytest.approx(20, abs=0.01) and (e - w) * 111.32 * math.cos(math.radians(48.86)) == (
        pytest.approx(20, abs=0.01))
    assert len(home.pieces()) == 2 * 3 and all(b[2] - b[0] <= 0.1 + 1e-9 and b[3] - b[1] <= 0.1 + 1e-9
                                               for b in home.pieces())
    first = ",".join(f"{v:g}" for v in home.pieces()[0])
    assert home.addresses()[0].count("bbox%3A" + first.replace(",", "%2C") + "%5D") == 1 and len(home.addresses()) == 6
    south = template.placed(-33.86, -151.2)
    assert south.id == "osm-streets-s3386w15120" and south.title.endswith("round -33.86, -151.20")
    assert infrastructure.REGION_ID.fullmatch(south.id).group(1) == "osm-streets"
    for change, words in (({"region": {"km": 500, "piece": 0.1}}, "region is {km: 2 to 100"),
                          ({"region": {"km": 100, "piece": 0.01}}, "more than 100"),
                          ({"query": "[out:xml];way;out;"}, "holds {bbox}"), ({"region": None}, "says no region"),
                          ({"format": "overpass"}, "region is {km")):
        with pytest.raises(ValueError, match=re.escape(words)):
            DataSet.of({k: v for k, v in {**STREETS, **change}.items() if v is not None})
    with pytest.raises(ValueError, match="asked of no region"):
        DataSet.of(COUNTRIES).placed(1, 2)
    with pytest.raises(ValueError, match="on the globe"):
        template.placed(95, 0)


def test_a_regions_pieces_are_each_read_as_they_come_and_a_way_across_two_kept_once(tmp_path):
    home = DataSet.of(STREETS).placed(48.85661, 2.35222, "Paris")
    pieces, order = home.pieces(), []
    first, second = pieces[0], pieces[1]  # side by side, west to east
    across = way(10, [((first[1] + first[3]) / 2, first[0] + 0.01), ((second[1] + second[3]) / 2, second[0] + 0.01)],
                 highway="primary", name="across two pieces")
    from_outside = way(11, [(first[1] - 0.2, first[0] + 0.02), (first[1] + 0.01, first[0] + 0.02),
                            (second[1] + 0.01, second[0] + 0.02)], highway="trunk", name="from outside")
    answers = {a: answer(across, from_outside) if i < 2 else answer() for i, a in enumerate(home.addresses())}
    real = infrastructure._osm_piece

    def piece(raw, kept, host, *more):
        order.append(("read", len(order)))
        return real(raw, kept, host, *more)

    class Asked(Downloads):
        def __call__(self, url, timeout, **said):
            order.append(("asked", len(order)))
            return super().__call__(url, timeout, **said)
    asked = Asked(answers)
    import unittest.mock
    with unittest.mock.patch.object(infrastructure, "_osm_piece", piece):
        out = install(home, tmp_path, accept_licence=True, fetch=asked, clock=Clock())
    assert [what for what, _ in order] == ["asked", "read"] * 6  # each piece read before the next is asked
    assert out["ok"] is True and out["file"]["layers"] == {"streets": 2}  # each way once
    kept = Store(tmp_path).layer("streets")[home.id]["lines"]
    assert sorted(kept["names"]) == ["across two pieces", "from outside"] and kept["zooms"] == [64, 64]
    with pytest.raises(ValueError, match="names none yet"):
        install(STREETS, tmp_path, accept_licence=True, fetch=asked, clock=Clock())


def test_the_index_lists_the_regions_round_home_and_those_added_and_keeps_those_kept(tmp_path):
    index = Index(tmp_path, [COUNTRIES, STREETS])
    assert [d.id for d in index.datasets] == ["ne-countries", "osm-streets"]  # round no place: the template
    table = index.table()
    assert table["rows"][1][4] == {"text": "needs a place", "sub": infrastructure.REGION_NO_PLACE}
    assert table["rows"][2][0]["text"] == "Another region: Major roads and buildings"
    assert table["rows"][2][4] == {"form": "world-region-osm-streets", "title": "Add a region…"}
    assert [f["id"] for f in index.forms()] == ["world-layer-ne-countries"]  # nothing to download round no place
    assert [f["id"] for f in index.region_forms()] == ["world-region-osm-streets"]
    index.place_regions({"lat": 48.85661, "lon": 2.35222, "label": "Paris"}, [(51.5, -0.12, "London")])
    ids = [d.id for d in index.datasets]
    assert ids == ["ne-countries", "osm-streets-n4886e00235", "osm-streets-n5150w00012"]
    forms = [f["id"] for f in index.forms()]
    assert "world-layer-osm-streets-n4886e00235" in forms
    assert "world-layer-remove-osm-streets-n5150w00012" in forms  # added, not downloaded: forgotten on Remove…
    assert "world-layer-remove-osm-streets-n4886e00235" not in forms  # home's: nothing to remove yet
    home = index.dataset("osm-streets-n4886e00235")
    Store(tmp_path).put(home, {"layers": {"streets": {"points": [], "lines": [([(2.3, 48.8), (2.4, 48.9)], "A",
                                                                              64.0)]}}}, fetched=1.0)
    infrastructure._changed()
    index.place_regions({"lat": 40.71, "lon": -74.01, "label": "New York"}, [])  # home moved, London forgotten
    assert [d.id for d in index.datasets] == ["ne-countries", "osm-streets-n4071w07401"]
    index.sets()  # the look finds Paris's region kept
    assert [d.id for d in index.datasets] == ["ne-countries", "osm-streets-n4071w07401", "osm-streets-n4886e00235"]
    layers = {x["id"]: x for x in index.layers()}
    assert layers["streets"]["from"] == 64.0 and layers["streets"]["ranked"] is True
    assert layers["streets"]["credits"] == [STREETS["credit"]]
    assert index.layer("streets", area=(2.0, 48.5, 2.5, 49.0), zoom=16)["parts"] == []  # drawn from 64x: twice 16x
    assert index.layer("streets", area=(2.0, 48.5, 2.5, 49.0), zoom=32)["parts"][0]["lines"]["names"] == ["A"]
    assert "remove" in index.forms()[-1]["id"]  # a kept region can be removed


def test_a_by_area_layer_is_never_left_out_as_full(tmp_path, monkeypatch):
    store = Store(tmp_path)
    store.put(STATE_LINES, {"layers": {"states": {"points": [], "lines": [([(0, 0), (1, 1), (2, 2)], "a")]}}},
              fetched=1.0)
    monkeypatch.setattr(infrastructure, "MAX_VERTICES", 2)
    listed = Index(tmp_path, [STATE_LINES]).layers()
    assert [x["id"] for x in listed] == ["states"] and "left out" not in listed[0]["note"]


# -- the review of 1.108.0 ---------------------------------------------------------------------------------------------
def test_a_pieces_xml_is_read_by_its_handlers_holding_one_ways_points_at_most():
    """Item 1: nothing of an element but a way's is held, and a way's points WAY_POINTS at most (a longer way is left
    out), PIECE_POINTS in a piece."""
    import tracemalloc
    body = b"<osm>" + b"<x/>" * 500_000 + b"</osm>"  # 2 MB of elements that are no way
    long = (b'<osm><way id="1">' + b'<nd lat="1.0" lon="1.0"/>' * 100_000 + b'<tag k="highway" v="primary"/></way>'
            + way(2, [(1.0, 1.0), (1.001, 1.001)], highway="primary", name="kept").encode() + b"</osm>")
    peaks = []
    for raw in (body, long):
        kept = infrastructure._Kept(None)
        tracemalloc.start()
        try:
            infrastructure._osm_piece(raw, kept, "h")
            peaks.append(tracemalloc.get_traced_memory()[1])
        finally:
            tracemalloc.stop()
    assert peaks[0] < 2 << 20 and peaks[1] < 2 << 20, peaks  # a tree held them: some 60 MB and 15 MB
    assert kept.dropped == {infrastructure.LONG: 1} and [n for _, n, _ in kept.layers["streets"]["lines"]] == ["kept"]


def test_a_piece_of_more_points_than_the_most_is_refused(monkeypatch):
    monkeypatch.setattr(infrastructure, "PIECE_POINTS", 5)
    xml = answer(*(way(i, [(2.0, 48.0), (2.1, 48.1)], highway="primary") for i in range(3)))
    with pytest.raises(InfrastructureError, match="more than 5 points in one piece"):
        parse(STREETS, xml)


def test_a_document_type_or_an_entity_is_refused_by_the_parser_whatever_the_answers_encoding():
    """Item 2: a UTF-16 answer declaring an entity was read and the entity expanded: the parser itself refuses it."""
    doc = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE osm [<!ENTITY a "AAAAAAAAAA">]><osm><way id="1">'
           '<nd lat="1" lon="1"/><nd lat="1.001" lon="1.001"/><tag k="highway" v="primary"/><tag k="name" v="&a;"/>'
           '</way></osm>')
    for raw in (doc.encode("utf-16"), doc.encode("utf-16-le"), doc.replace("UTF-16", "UTF-8").encode()):
        with pytest.raises(InfrastructureError, match="not the data asked for"):
            parse(STREETS, raw)
    entity = b'<?xml version="1.0"?><osm><way id="1"><tag k="name" v="&a;"/></way></osm>'  # undeclared: no read
    with pytest.raises(InfrastructureError, match="its XML does not read"):
        parse(STREETS, entity)


def test_a_regions_limit_is_held_across_its_pieces_as_each_is_read(tmp_path, monkeypatch):
    """Item 3: a piece is asked with what is left of the set's limit, cut off as it passes it, never read whole."""
    monkeypatch.setattr(infrastructure, "MAX_ANSWER", 1_000)  # every set's: this one raises its own to 5,000
    home = DataSet.of({**STREETS, "most": 5_000, "size": 4_000}).placed(48.85661, 2.35222, "Paris")

    class Dribble:  # a piece's answer a thousand bytes a read, as many as it is asked for
        def __init__(self, total):
            self.total, self.given = total, 0

        def read1(self, n):
            if self.given >= self.total:
                return b""
            self.given += 1000
            return b" " * 1000

        read = read1

        def close(self):
            pass
    first, endless = answer(way(1, [(2.3, 48.8), (2.31, 48.81)], highway="primary")), Dribble(10 << 20)
    answers = {a: [first] if i == 0 else [endless] for i, a in enumerate(home.addresses()[:2])}
    with pytest.raises(InfrastructureError, match=r"its answers are larger than .* in all, the most this data set"):
        install(home, tmp_path, accept_licence=True, fetch=Downloads(answers), clock=Clock())
    assert endless.given <= 5_000 + 1000  # what was left of the limit, and the read that passed it


def test_a_region_too_near_a_pole_for_its_pieces_is_refused_where_it_is_placed(tmp_path, monkeypatch):
    """Item 4: the pieces counted where the region is (the equator has the fewest), when it is placed and again before
    its download asks anything."""
    template = DataSet.of({**STREETS, "region": {"km": 20, "piece": 0.05}})
    assert len(template.placed(0, 10).pieces()) == 16 and len(template.placed(60, 10).pieces()) == 32
    with pytest.raises(ValueError, match="asked in 168 pieces, more than the 100 a region may be"):
        template.placed(85, 10)
    home = DataSet.of(STREETS).placed(48.85661, 2.35222, "Paris")  # 6 pieces
    monkeypatch.setattr(infrastructure, "REGION_PIECES", 5)
    asked = Downloads({})
    with pytest.raises(InfrastructureError, match="asked in 6 pieces, more than 5: nothing was asked"):
        install(home, tmp_path, accept_licence=True, fetch=asked, clock=Clock())
    assert asked.asked == []


def test_a_way_on_the_edge_two_pieces_share_is_kept_once(tmp_path):
    """Item 13: a piece is half-open (its north and east edges the next one's), its last row and column closed."""
    home = DataSet.of(STREETS).placed(48.85661, 2.35222, "Paris")
    pieces = home.pieces()
    edge = pieces[0][3]  # the first piece's east edge, the second's west
    on = way(20, [(edge, pieces[0][0] + 0.01), (edge + 0.01, pieces[0][0] + 0.02)], highway="primary", name="on it")
    last = way(21, [(pieces[-1][3], pieces[-1][2]), (pieces[-1][3] - 0.01, pieces[-1][2] - 0.01)],
               highway="primary", name="the far corner")
    answers = {a: answer(on, last) for a in home.addresses()}
    out = install(home, tmp_path, accept_licence=True, fetch=Downloads(answers), clock=Clock())
    assert out["file"]["layers"] == {"streets": 2}  # each once: neither left out, neither twice
    assert sorted(Store(tmp_path).layer("streets")[home.id]["lines"]["names"]) == ["on it", "the far corner"]


def test_a_files_json_is_packed_from_lines_that_carry_their_zoom():
    """Item 14: pack() reads a line's vertices and its name whatever follows them."""
    got = infrastructure.pack(STREETS, {"layers": {"streets": {"points": [], "lines": [
        ([(2.3, 48.8), (2.4, 48.9)], "A", 64.0), ([(2.5, 48.8), (2.6, 48.9)], "B")]}}}, 1.0)
    assert got["layers"]["streets"]["lines"]["names"] == ["A", "B"] and got["features"] == 2


def test_a_regions_form_says_a_dense_city_may_be_larger_and_is_refused_past_its_limit(tmp_path):
    """Item 15: its size an estimate; past its limit refused, nothing kept."""
    home = DataSet.of(STREETS).placed(48.85661, 2.35222, "Paris")
    words = infrastructure.form(home, tmp_path)["confirm"]["words"]
    assert f"A dense city may be larger: past {infrastructure.size_words(128 << 20)} it is refused, nothing kept." in (
        words)
    assert "dense city" not in infrastructure.form(PLACES, tmp_path)["confirm"]["words"]
