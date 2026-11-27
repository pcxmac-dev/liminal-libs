"""The review of 2026-11-26, item 14 (1.110.0): the library's P3 findings the builder took, each pinned by a test that
fails on 1.109.0. Every process, fetch and clock here is a stand-in: nothing is started or downloaded."""
from __future__ import annotations

import json

import pytest

from liminal_libs.machines import infrastructure
from liminal_libs.machines.infrastructure import DataSet, install

from test_infrastructure import Clock, Downloads, _nothing_real  # noqa: F401 - the fixture, used by name
from test_infrastructure_globe import LATEST, PROBES, probes_file

pytestmark = pytest.mark.usefixtures("no_outside")


# -- libs-world P3-1: an atlas-latest install leaves the Index's own DataSet as it was --------------------------------

def test_an_atlas_latest_install_keeps_no_probes_on_the_data_set_it_was_given(tmp_path):
    folder = tmp_path / "layers"
    install(PROBES, folder, accept_licence=True, fetch=Downloads({DataSet.of(PROBES).address(): probes_file()}),
            clock=Clock())
    held = DataSet.of(LATEST)  # the object an Index holds for the plugin's life
    at = "https://atlas.example/api/v2/measurements/5151/latest/?format=json&probe_ids=6001"
    result = [{"prb_id": 6001, "from": "192.0.2.7", "result": [{"hop": 1, "result": [{"from": "193.0.0.1",
                                                                                       "rtt": 0.8}]}]}]
    out = install(held, folder, accept_licence=True, fetch=Downloads({at: json.dumps(result).encode()}),
                  clock=Clock())
    assert out["ok"] is True
    assert not hasattr(held, "probes_by_id") and not hasattr(held, "asked")
    assert infrastructure.DataSet.of(held) is held


# -- libs-world P3-2: orbits kept by set and number, so one set's download takes no other's satellites ----------------

def _omm_set(ident: str, constellation: str) -> dict:
    from test_infrastructure_globe import CELESTRAK
    return {**CELESTRAK, "id": ident, "title": ident, "constellation": constellation, "query": "GROUP=x&FORMAT=csv",
            "size": 1000}


def _orbit_row(norad: int, constellation: str, epoch: float = 1.0) -> tuple:
    return (norad, constellation, f"SAT-{norad}", epoch, {"NORAD_CAT_ID": norad})


def test_a_satellite_two_sets_hold_stays_with_the_first_when_the_second_is_removed(tmp_path):
    from liminal_libs.machines.infrastore import Store
    store = Store(tmp_path)
    group, one = _omm_set("celestrak-group", "oneweb"), _omm_set("celestrak-one", "oneweb")
    point = {"layers": {}, "features": 1}
    store.put(group, point, 1.0, orbits=[_orbit_row(44057, "oneweb"), _orbit_row(44058, "oneweb")])
    store.put(one, point, 2.0, orbits=[_orbit_row(44057, "oneweb", 2.0)])
    assert [(o["norad"], o["set"]) for o in store.orbits("oneweb")] == [(44057, "celestrak-one"),
                                                                         (44058, "celestrak-group")]  # one row each
    assert store.remove("celestrak-one")
    assert [(o["norad"], o["set"]) for o in store.orbits("oneweb")] == [(44057, "celestrak-group"),
                                                                         (44058, "celestrak-group")]


def test_a_file_whose_orbits_are_kept_by_number_alone_is_keyed_by_set_at_its_next_write(tmp_path):
    import sqlite3
    from liminal_libs.machines import infrastore
    from liminal_libs.machines.infrastore import Store
    old = infrastore.ORBITS.replace("norad INTEGER NOT NULL", "norad INTEGER PRIMARY KEY").replace(
        ",\n  PRIMARY KEY (set_id, norad)", "")
    assert "PRIMARY KEY (set_id" not in old
    with sqlite3.connect(tmp_path / infrastore.FILE) as con:  # 1.109.0's file
        con.executescript(infrastore.SCHEMA.replace(infrastore.ORBITS, old))
        con.execute(infrastore.ANSWERS)
        con.execute("PRAGMA user_version = 2")
        con.execute("INSERT INTO sets VALUES ('celestrak-group','t','s','u','l','w',1,'c','',1,1,0,0,0,'v')")
        con.execute("INSERT INTO orbits VALUES (44057, 'celestrak-group', 'oneweb', 'SAT', 1.0, '{}')")
    con.close()
    store = Store(tmp_path)
    store.put(_omm_set("celestrak-one", "oneweb"), {"layers": {}, "features": 1}, 2.0,
              orbits=[_orbit_row(44057, "oneweb", 2.0)])
    with sqlite3.connect(tmp_path / infrastore.FILE) as con:
        assert con.execute("PRAGMA user_version").fetchone()[0] == infrastore.USER_VERSION == 3
        assert sorted(con.execute("SELECT set_id, norad FROM orbits")) == [("celestrak-group", 44057),
                                                                           ("celestrak-one", 44057)]
    con.close()


# -- libs-world P3-4: a refresh no one clicked is named when it holds the user's Download back --------------------------

def test_a_download_asked_while_a_set_refreshes_by_itself_is_refused_naming_the_refresh(tmp_path):
    import io
    import threading
    from liminal_libs.machines.infrastructure import Index
    from liminal_libs.machines.netstat import NetstatView
    from test_infrastructure_globe import ONEWEB
    from test_infrastructure_refresh import AT, REFRESHED, T0, answer
    folder = tmp_path / "layers"
    install(REFRESHED, folder, accept_licence=True, fetch=Downloads({AT: answer()}), clock=Clock(), wall=Clock(T0))
    gate, entered = threading.Event(), threading.Event()

    def slow(url, timeout, **said):
        entered.set()
        gate.wait(10)
        return io.BytesIO(answer())
    wall = Clock(T0 + 7200)
    index = Index(folder, [REFRESHED, PROBES], clock=Clock(), wall=wall)
    view = NetstatView("fw", reader=lambda: {}, names={}, fetch=slow, agent="fw 1.0", index=index, wall=wall)
    try:
        assert view.refresh() == "celestrak-oneweb" and entered.wait(5)
        with pytest.raises(ValueError, match=r"^Eutelsat OneWeb's orbits is being downloaded again by itself \(its "
                                             r"refresh, as its maker allows\): wait for it to finish, then ask again$"):
            install(PROBES, folder, accept_licence=True, fetch=Downloads({}), clock=Clock())
        table = index.table()
        assert [row[3] for row in table["rows"]][0] == "being downloaded again by itself"
        assert table["note"].endswith("Eutelsat OneWeb's orbits is being downloaded again by itself, as its maker "
                                      "allows: the buttons come back when it ends.")
    finally:
        gate.set()
        view._refreshing.join(10)
        view.close()
    assert ONEWEB["title"] == "Eutelsat OneWeb's orbits" and infrastructure._by_itself() == ""


# -- libs-world P3-5: an answer the database could not keep (its lock held by a long write) is never lost silently ----

def test_an_answer_the_locked_database_could_not_keep_is_logged_and_still_stops_the_refreshing(tmp_path, monkeypatch,
                                                                                                caplog):
    import logging
    import sqlite3
    from liminal_libs.machines import infrastore
    from liminal_libs.machines.infrastructure import Index, InfrastructureError
    from test_infrastructure_refresh import AT, REFRESHED, T0, answer
    folder = tmp_path / "layers"
    install(REFRESHED, folder, accept_licence=True, fetch=Downloads({AT: answer()}), clock=Clock(), wall=Clock(T0))
    monkeypatch.setattr(infrastore, "TIMEOUT_S", 0.05)  # a write's wait, short: the lock below is never let go in it
    holder = sqlite3.connect(folder / infrastore.FILE, isolation_level=None)
    try:
        holder.execute("BEGIN IMMEDIATE")  # a long region write, as another Store's put holds it
        refused = InfrastructureError("celestrak.example answered HTTP 503")
        refused.code = 503
        with caplog.at_level(logging.WARNING, logger=infrastructure.__name__):
            infrastructure._answered(DataSet.of(REFRESHED), folder, refused, T0 + 7200)
        assert "celestrak-oneweb: its answer (503) could not be kept in" in caplog.text
        index = Index(folder, [REFRESHED], clock=Clock(), wall=Clock(T0 + 7260))
        assert index.refresh_due() == []  # not downloaded again at every look (P2-1's loop)
        assert index.table()["rows"][0][4]["text"] == "Update later"  # its 15 minutes' pause held too
        assert infrastructure.held_back(DataSet.of(REFRESHED), folder, T0 + 7260)
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    later = Clock(T0 + 7200 + 900)
    install(REFRESHED, folder, accept_licence=True, fetch=Downloads({AT: answer()}), clock=Clock(), wall=later)
    assert infrastructure._unkept(folder) == {}  # downloaded: what failed before is past


# -- libs-world P3-6: a shapefile read copies what it reads of the download, never the whole answer -------------------

def test_a_shapefile_read_does_not_copy_the_download_it_is_given(tmp_path):
    import os
    import tracemalloc
    from liminal_libs import shapefile
    import shapes as S
    from test_shapefile import FIELDS
    big = os.urandom(4 << 20)  # a member not asked for: the bulk of the answer, as the roads' are of North America's
    answer = bytearray(S.zipped(shp_bytes=S.shp([(3, [[(10.0, 50.0), (10.5, 50.2)]])]),
                                dbf_bytes=S.dbf(FIELDS, [["A 8", "Major Highway", 3, "T", "20120101"]]),
                                more={"readme.bin": big}))
    del big
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        got = list(shapefile.read(answer))
        rows = shapefile.records(answer)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert [g.record["name"] for g in got] == ["A 8"] and [r["name"] for r in rows] == ["A 8"]
    assert peak < len(answer) // 4, f"{peak:,} bytes at peak for an answer of {len(answer):,}"
    answer.append(0)  # the answer is let go of: no view of it is held after the read
