"""liminal_libs.shapefile (1.104.0): shapefiles read from a zip in memory, on hand-made files (tests/shapes.py)."""
from __future__ import annotations

import struct

import pytest

from liminal_libs import shapefile
from liminal_libs.shapefile import ShapefileError

import shapes as S

FIELDS = [("name", "C", 20), ("type", "C", 16), ("scalerank", "N", 4), ("toll", "L", 1), ("edited", "D", 8)]


def roads(**more) -> bytes:
    records = [(3, [[(10.0, 50.0), (10.5, 50.2)], [(11.0, 50.0), (11.2, 49.8), (11.4, 49.9)]]),
               (0, []),
               (1, [[(12.0, 48.0)]]),
               (15, [[(1.0, 1.0), (2.0, 1.0), (2.0, 2.0), (1.0, 1.0)]]),
               (3, [[(13.0, 47.0), (13.1, 47.1)]])]
    rows = [["A 8", "Major Highway", 3, "T", "20120101"], ["", "", None, "", ""], ["Mainz", "", 5, "F", ""],
            ["Ring", "Road", 7, "", ""], ["Gone", "Road", 8, "", ""]]
    return S.zipped(shp_bytes=S.shp(records), dbf_bytes=S.dbf(FIELDS, rows, deleted={4}), **more)


def test_a_shapefiles_shapes_are_read_in_order_with_their_records():
    got = list(shapefile.read(roads()))
    assert [g.kind for g in got] == ["line", "point", "polygon"]  # the null shape and the deleted row left out
    line = got[0]
    assert line.parts == [[(10.0, 50.0), (10.5, 50.2)], [(11.0, 50.0), (11.2, 49.8), (11.4, 49.9)]]
    assert line.record == {"name": "A 8", "type": "Major Highway", "scalerank": 3, "toll": True, "edited": "2012-01-01"}
    assert got[1].parts == [[(12.0, 48.0)]] and got[1].record["toll"] is False
    assert got[2].parts == [[(1.0, 1.0), (2.0, 1.0), (2.0, 2.0), (1.0, 1.0)]]  # a PolygonZ read as its polygon


def test_the_fields_asked_for_alone_are_kept_and_a_stem_is_found_in_a_folder():
    data = roads(folder="10m_cultural/")
    got = list(shapefile.read(data, "NE_10M_ROADS", fields=["Name", "scalerank"]))
    assert got[0].record == {"name": "A 8", "scalerank": 3}


def test_a_cpg_says_the_records_code_page():
    rows = [["Gießen", "Road", 1, "", ""]]
    data = S.zipped(shp_bytes=S.shp([(3, [[(8.6, 50.5), (8.7, 50.6)]])]),
                    dbf_bytes=S.dbf(FIELDS, rows, encoding="latin-1"), cpg="ISO-8859-1")
    assert next(shapefile.read(data)).record["name"] == "Gießen"
    data = S.zipped(shp_bytes=S.shp([(3, [[(8.6, 50.5), (8.7, 50.6)]])]),
                    dbf_bytes=S.dbf(FIELDS, rows, encoding="cp1252"), cpg="1252")
    assert next(shapefile.read(data)).record["name"] == "Gießen"
    data = S.zipped(shp_bytes=S.shp([(3, [[(8.6, 50.5), (8.7, 50.6)]])]), dbf_bytes=S.dbf(FIELDS, rows), cpg=None)
    assert next(shapefile.read(data)).record["name"] == "Gießen"  # none named: UTF-8


def one(records, rows=None, **more) -> bytes:
    rows = rows if rows is not None else [["x", "", 1, "", ""] for _ in records]
    return S.zipped(shp_bytes=S.shp(records), dbf_bytes=S.dbf(FIELDS, rows), **more)


def refused(data, **more) -> str:
    with pytest.raises(ShapefileError) as e:
        list(shapefile.read(data, **more))
    return str(e.value)


def test_what_is_not_wgs84_longitude_and_latitude_is_refused():
    line = [(3, [[(0, 0), (1, 1)]])]
    assert "not WGS 84" in refused(one(line, prj=S.MERCATOR_PRJ))
    assert "not WGS 84" in refused(one(line, prj='GEOGCS["GCS_North_American_1927"]'))
    assert "no ne_10m_roads.prj" in refused(one(line, prj=None))


def test_records_that_do_not_fit_are_refused_in_words():
    good = S.content(3, [[(0, 0), (1, 1)]])
    assert "does not fit" in refused(S.zipped(shp_bytes=S.shp([good])[:-8], dbf_bytes=S.dbf(FIELDS, [["x"] * 5])))
    many = bytearray(good)
    struct.pack_into("<i", many, 40, 9)  # nine points said, two held
    assert "more points than it holds" in refused(one([bytes(many)]))
    past = bytearray(S.content(3, [[(0, 0), (1, 1)], [(2, 2), (3, 3)]]))
    struct.pack_into("<i", past, 48, 7)  # the second part begins past the points
    assert "begin past its points" in refused(one([bytes(past)]))
    assert "they do not match" in refused(one([(3, [[(0, 0), (1, 1)]])], rows=[["x"] * 5, ["y"] * 5]))
    assert "type 31" in refused(one([struct.pack("<i", 31) + b"\x00" * 4]))


def test_what_is_larger_than_may_be_is_refused():
    line = [(3, [[(0, 0), (1, 1)]])] * 3
    assert "more than the 100 a shapefile's member may be" in refused(one(line), most_bytes=100)
    assert "more than 2 records" in refused(one(line), most_records=2)
    assert "it is no zip" in refused(b"not a zip")
    two = one(line, more={"other.shp": b"", "other.dbf": b"", "other.prj": S.WGS84_PRJ})
    assert "2 shapefiles" in refused(two)
    assert len(list(shapefile.read(two, "ne_10m_roads"))) == 3


def test_the_shapes_are_read_one_at_a_time_after_every_record_is_checked(monkeypatch):
    # 1.108.0 (Monday list item 25): the states' boundaries hold millions of points; none is read before it is asked
    read = []
    real = shapefile._parts
    monkeypatch.setattr(shapefile, "_parts", lambda *a, **k: (read.append(k.get("read", True)), real(*a, **k))[1])
    unpacked = []  # the review of 1.108.0: no coordinate unpacked while the records are checked

    class Struct:
        def __getattr__(self, name):
            return getattr(struct, name)

        def unpack_from(self, fmt, *args):
            unpacked.append(fmt)
            return struct.unpack_from(fmt, *args)
    monkeypatch.setattr(shapefile, "struct", Struct())
    got = shapefile.read(roads())
    assert read == [False, False, False]  # the three records with parts checked, none of their points read
    assert not [f for f in unpacked if f.endswith("d")]  # no coordinate (a double) unpacked yet
    first = next(got)
    assert first.kind == "line" and read[3:] == [True]  # the first shape's points read once it is asked for
    assert [g.kind for g in got] == ["point", "polygon"] and read[3:] == [True, True]  # the deleted one never read
    bad = bytearray(S.content(3, [[(0, 0), (1, 1)], [(2, 2), (3, 3)]]))
    struct.pack_into("<i", bad, 48, 7)
    with pytest.raises(ShapefileError, match="begin past its points"):  # a later record's fault, before the first
        shapefile.read(one([(3, [[(0, 0), (1, 1)]]), bytes(bad)]))


def test_the_records_alone_are_read_without_the_shapes():
    data = S.zipped(shp_bytes=b"not a shapefile at all", dbf_bytes=S.dbf(FIELDS, [["A 8", "x", 3, "T", ""],
                                                                                 ["Gone", "", 1, "", ""]], deleted={1}))
    assert shapefile.records(data, fields=["name", "scalerank"]) == [{"name": "A 8", "scalerank": 3}]
    assert "not WGS 84" in str(pytest.raises(ShapefileError, shapefile.records, S.zipped(
        shp_bytes=b"", dbf_bytes=S.dbf(FIELDS, []), prj=S.MERCATOR_PRJ)).value)
    with pytest.raises(ShapefileError, match="more than 1 records"):
        shapefile.records(roads(), most_records=1)


def test_more_records_than_the_most_are_refused_before_any_row_is_made(monkeypatch):
    # the review of 1.108.0: from the .dbf's header, by read() and by records() alike
    made = []
    real = shapefile._value
    monkeypatch.setattr(shapefile, "_value", lambda *a: (made.append(a), real(*a))[1])
    for reader in (shapefile.records, shapefile.read):
        with pytest.raises(ShapefileError, match="more than 1 records"):
            reader(roads(), most_records=1)
    assert made == []
    with pytest.raises(ShapefileError, match="it is no zip"):
        shapefile.records(b"nothing")
