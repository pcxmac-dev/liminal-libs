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
