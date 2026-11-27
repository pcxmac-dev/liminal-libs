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
