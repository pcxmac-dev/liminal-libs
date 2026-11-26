"""The infrastructure kept in the plugin's own database (1.104.0, Monday list item 27: machines/infrastore.py): a set
put, read whole and by area (a box across the antimeridian, a box with nothing), replaced, removed with its cells; a
write that fails midway leaves the older set; a long line kept as pieces; a folder on another system's drive refused;
the file closed after each call. On the test's own folder: nothing is downloaded."""
from __future__ import annotations

import base64
import sqlite3
import struct

import pytest

from liminal_libs.machines import infrastore, infrastructure
from liminal_libs.machines.infrastore import Store, StoreError, cell_of

SET = {"id": "ne-roads", "title": "Major roads", "format": "shapefile", "layer": "roads", "stand_in": True,
       "url": "https://www.naturalearth.example/ne_10m_roads.zip", "size": 1000, "source": "Natural Earth",
       "licence_name": "Public domain", "licence": "Natural Earth's data is in the public domain.",
       "credit": {"text": "Made with Natural Earth", "url": ""}}


def features(lines=(), points=(), layer="roads") -> dict:
    return {"layers": {layer: {"points": list(points), "lines": list(lines)}},
            "features": len(lines) + len(points), "dropped": {"repeated": 2}}


def xy(part: dict) -> list[tuple[float, float]]:
    raw = base64.b64decode(part["xy"])
    v = struct.unpack(f"<{len(raw) // 4}i", raw)
    return [(v[i] / 1e5, v[i + 1] / 1e5) for i in range(0, len(v), 2)]


def test_a_set_is_put_and_read_whole_and_by_area(tmp_path):
    store = Store(tmp_path)
    europe = ([(8.0, 50.0), (9.0, 50.5), (10.0, 51.0)], "A 5")
    pacific = ([(179.5, -17.0), (-179.5, -17.5)], "across the antimeridian")
    out = store.put(SET, features([europe, pacific], [(13.4, 52.5, "Berlin", "DE")], layer="roads"), fetched=1000.0,
                    accepted=999.0, size=1234)
    assert out["counts"] == {"roads": {"points": 1, "lines": 2, "vertices": 5}} and out["features"] == 3
    (row,) = store.sets().values()
    assert (row["title"], row["accepted"], row["fetched"], row["dropped"], row["bytes"], row["stand_in"]) == (
        "Major roads", 999.0, 1000.0, 2, 1234, 1)
    whole = store.layer("roads")["ne-roads"]
    assert whole["lines"]["names"] == ["A 5", "across the antimeridian"] and whole["points"]["names"] == ["Berlin"]
    assert xy(whole["lines"])[:3] == [(8.0, 50.0), (9.0, 50.5), (10.0, 51.0)] and whole["cut"] is False
    near = store.layer("roads", area=(7.5, 49.5, 8.5, 50.5))["ne-roads"]
    assert near["lines"]["names"] == ["A 5"] and "points" not in near
    across = store.layer("roads", area=(179.0, -18.0, -179.0, -17.0))["ne-roads"]  # west greater than east
    assert across["lines"]["names"] == ["across the antimeridian"]
    assert store.layer("roads", area=(-60.0, -10.0, -50.0, 0.0)) == {}
    assert store.layer("cables") == {}


def test_a_long_segment_is_found_in_the_cells_it_crosses_and_a_long_line_kept_in_pieces(tmp_path, monkeypatch):
    store = Store(tmp_path)
    store.put(SET, features([([(0.0, 0.0), (20.0, 0.0)], "long")]), fetched=1.0)
    assert store.layer("roads", area=(10.2, -0.5, 10.4, 0.5))["ne-roads"]["lines"]["names"] == ["long"]
    line = [(i * 0.1, 0.0) for i in range(600)]
    out = store.put(SET, features([(line, "pieces")]), fetched=2.0)
    # kept in 3 pieces (256, then 256 more from the last one's end, then the rest), and counted as the one line of 600
    # vertices it is (the review: each piece's shared vertex was counted twice, and each piece as a line)
    assert out["counts"]["roads"] == {"points": 0, "lines": 1, "vertices": 600}
    got = xy(store.layer("roads")["ne-roads"]["lines"])
    assert len(got) == 256 + 256 + 90 and got[255] == got[256]
    monkeypatch.setattr(infrastructure, "MAX_VERTICES", 600)  # a layer full to its last vertex is drawn whole
    assert store.layer("roads")["ne-roads"]["cut"] is False
    monkeypatch.setattr(infrastructure, "MAX_VERTICES", 599)
    assert store.layer("roads")["ne-roads"]["cut"] is True
    assert cell_of(180.0, 90.0) == 179 * 360 + 359 and cell_of(-180.0, -90.0) == 0


def test_a_set_put_again_replaces_its_rows_and_a_failed_write_leaves_the_older(tmp_path, monkeypatch):
    store = Store(tmp_path)
    store.put(SET, features([([(0, 0), (1, 1)], "old")]), fetched=1.0)
    store.put(SET, features([([(5, 5), (6, 6)], "new")]), fetched=2.0)
    assert store.layer("roads")["ne-roads"]["lines"]["names"] == ["new"]
    with pytest.raises(StoreError):  # the orbits' rows break midway: nothing of it is kept
        store.put(SET, features([([(7, 7), (8, 8)], "broken")]), fetched=3.0, orbits=[(1, "x", "y", "no epoch", {})])
    assert store.layer("roads")["ne-roads"]["lines"]["names"] == ["new"]
    assert store.sets()["ne-roads"]["fetched"] == 2.0
    with sqlite3.connect(tmp_path / infrastore.FILE) as con:
        assert con.execute("SELECT COUNT(*) FROM cells").fetchone()[0] == 2
    assert store.remove("ne-roads") is True and store.remove("ne-roads") is False
    with sqlite3.connect(tmp_path / infrastore.FILE) as con:
        assert [con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("sets", "features", "cells")] == [
            0, 0, 0]


def test_orbits_and_probes_are_kept_with_their_set(tmp_path):
    store = Store(tmp_path)
    store.put({**SET, "id": "celestrak-oneweb"}, features(), fetched=1.0,
              orbits=[(44057, "oneweb", "ONEWEB-0012", 1.7e9, {"NORAD_CAT_ID": 44057})],
              probes=[(6001, 52.37, 4.89, "NL", 3333, None, 1, 1)])
    assert store.orbits("oneweb") == [{"norad": 44057, "set": "celestrak-oneweb", "constellation": "oneweb",
                                       "name": "ONEWEB-0012", "epoch": 1.7e9, "omm": {"NORAD_CAT_ID": 44057}}]
    assert store.probes(anchors=True)[0]["country"] == "NL"
    store.remove("celestrak-oneweb")
    assert store.orbits() == [] and store.probes() == []


def test_the_file_is_closed_after_each_call_and_another_systems_folder_refused(tmp_path, monkeypatch):
    store = Store(tmp_path)
    store.put(SET, features([([(0, 0), (1, 1)], "x")]), fetched=1.0)
    store.layer("roads", area=(0, 0, 1, 1))
    for name in (infrastore.FILE, infrastore.FILE + "-wal", infrastore.FILE + "-shm"):
        (tmp_path / name).unlink(missing_ok=True)  # removable at once: nothing holds it open
    assert Store(tmp_path / "none").sets() == {} and Store(tmp_path / "none").layer("roads") == {}
    monkeypatch.setattr(infrastructure, "foreign", lambda p=None: "Keeping the infrastructure layers is Windows' own")
    with pytest.raises(ValueError, match="Windows' own"):
        Store(tmp_path / "elsewhere").put(SET, features(), fetched=1.0)
    assert not (tmp_path / "elsewhere").exists() and Store(tmp_path).exists() is False
    with pytest.raises(ValueError, match="an area is"):
        Store(tmp_path).layer("roads", area=(0, 0, 1))
