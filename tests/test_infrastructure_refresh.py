"""CelesTrak's orbits refreshed by themselves (1.104.0; the user, 2026-11-26: "Refresh by itself"): after the user's
first yes, a data set whose `refresh` is true is downloaded again once its `every` has passed, asked by the World Wide
Web tab's page while it is open and by nothing else; any answer but OK stops it until the user's own Update succeeds,
and after a 500 or 503 nothing is asked of its host for its `pause`. Nothing is downloaded: the fetch is a stand-in."""
from __future__ import annotations

import gzip
import re
import urllib.error

import pytest

from liminal_libs.apps.asking import PAGE, asking
from liminal_libs.apps import as_user
from liminal_libs.machines import infrastructure, world
from liminal_libs.machines.infrastructure import DataSet, Index, InfrastructureError, install
from liminal_libs.machines.infrastore import Store
from liminal_libs.machines.netstat import NetstatView

from test_infrastructure import Clock, Downloads, _nothing_real  # noqa: F401 - the fixture, used
from test_infrastructure_globe import HEAD, ONEWEB, orbit

pytestmark = pytest.mark.usefixtures("no_outside")

T0 = 1_795_000_000.0
REFRESHED = {**ONEWEB, "refresh": True, "pause": 900}
AT = DataSet.of(ONEWEB).address()


def answer() -> bytes:
    return gzip.compress((HEAD + orbit("ONEWEB-0012", 44057)).encode())


def busy(code: int = 503) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(AT, code, "Service Unavailable", {}, None)


def at(t: float) -> str:
    return world._iso(t)[11:16]


def test_the_keys_are_read_and_what_is_wrong_is_said():
    d = DataSet.of(REFRESHED)
    assert (d.refresh, d.pause, d.every) == (True, 900.0, 7200.0)
    plain = DataSet.of(ONEWEB)
    assert (plain.refresh, plain.pause) == (False, 0.0)
    for change, words in (({"refresh": "yes"}, "refresh is true or false"),
                          ({"every": 1800}, "refreshed by itself only with an every of 3600 s or more"),
                          ({"pause": -1}, "pause is the seconds nothing is asked"),
                          ({"pause": True}, "pause is the seconds")):
        with pytest.raises(ValueError, match=re.escape(words)):
            DataSet.of({**REFRESHED, **change})


def test_a_set_is_due_again_once_its_every_has_passed_and_the_tab_says_when(tmp_path):
    folder = tmp_path / "layers"
    assert Index(folder, [REFRESHED], clock=Clock(), wall=Clock(T0)).refresh_due() == []  # never downloaded: no yes
    install(REFRESHED, folder, accept_licence=True, fetch=Downloads({AT: answer()}), clock=Clock(), wall=Clock(T0))
    soon = Index(folder, [REFRESHED], clock=Clock(), wall=Clock(T0 + 3600))
    assert soon.refresh_due() == []
    here = soon.table()["rows"][0][3]["sub"]
    assert f"refreshed by itself every 2 hours while this tab is open: next due at {at(T0 + 7200)} UTC" in here
    plain = {**ONEWEB, "id": "plain-oneweb"}
    install(plain, folder, accept_licence=True, fetch=Downloads({AT: answer()}), clock=Clock(), wall=Clock(T0))
    later = Index(folder, [REFRESHED, plain], clock=Clock(), wall=Clock(T0 + 7200))
    assert [d.id for d in later.refresh_due()] == ["celestrak-oneweb"]  # a set not refreshed by itself never is
    # its licence's words changed since they were accepted: not refreshed by itself, and the tab says so
    changed = Index(folder, [{**REFRESHED, "licence": "Other words."}], clock=Clock(), wall=Clock(T0 + 7200))
    assert changed.refresh_due() == []
    assert "its licence's words changed since you accepted them" in changed.table()["rows"][0][3]["sub"]


def test_an_answer_that_is_not_ok_stops_it_and_a_503_pauses_every_ask_for_15_minutes(tmp_path):
    folder = tmp_path / "layers"
    install(REFRESHED, folder, accept_licence=True, fetch=Downloads({AT: answer()}), clock=Clock(), wall=Clock(T0))
    refused = Downloads({AT: busy(503)})
    with pytest.raises(InfrastructureError, match="answered HTTP 503"):
        install(REFRESHED, folder, accept_licence=True, fetch=refused, clock=Clock(), wall=Clock(T0 + 7200))
    assert len(refused.asked) == 1  # asked once: no second try
    kept = Store(folder).answers()["celestrak-oneweb"]
    assert kept["code"] == 503 and kept["at"] == T0 + 7200 and "answered HTTP 503" in kept["said"]
    # 15 minutes: nothing asked, not by the user's Update either, and the tab says until when
    paused = Index(folder, [REFRESHED], clock=Clock(), wall=Clock(T0 + 7260))
    assert paused.refresh_due() == [] and [f["id"] for f in paused.forms()] == ["world-layer-remove-celestrak-oneweb"]
    cell = paused.table()["rows"][0][4]
    assert cell["text"] == "Update later" and f"can be asked again from {at(T0 + 7200 + 900)} UTC" in cell["sub"]
    with pytest.raises(ValueError, match="for 15 minutes after that"):
        install(REFRESHED, folder, accept_licence=True, fetch=refused, clock=Clock(), wall=Clock(T0 + 7260))
    assert len(refused.asked) == 1
    # after them the user's Update is offered again; it is still not refreshed by itself, and the tab says why
    after = Index(folder, [REFRESHED], clock=Clock(), wall=Clock(T0 + 8200))
    assert "world-layer-celestrak-oneweb" in [f["id"] for f in after.forms()] and after.refresh_due() == []
    assert f"not refreshed by itself since {at(T0 + 7200)} UTC: " in after.table()["rows"][0][3]["sub"]
    # the user's own Update that succeeds starts it again
    install(REFRESHED, folder, accept_licence=True, fetch=Downloads({AT: answer()}), clock=Clock(),
            wall=Clock(T0 + 8200))
    assert Store(folder).answers() == {}
    assert [d.id for d in Index(folder, [REFRESHED], clock=Clock(),
                                wall=Clock(T0 + 8200 + 7200)).refresh_due()] == ["celestrak-oneweb"]


def test_a_first_download_that_got_a_503_is_paused_too(tmp_path):
    folder = tmp_path / "layers"
    with pytest.raises(InfrastructureError):
        install(REFRESHED, folder, accept_licence=True, fetch=Downloads({AT: busy(500)}), clock=Clock(),
                wall=Clock(T0))
    index = Index(folder, [REFRESHED], clock=Clock(), wall=Clock(T0 + 60))
    assert index.forms() == [] and index.table()["rows"][0][4]["text"] == "Download later"
    other = Downloads({AT: busy(404)})  # any other code: not paused, but kept
    with pytest.raises(InfrastructureError):
        install(REFRESHED, tmp_path / "b", accept_licence=True, fetch=other, clock=Clock(), wall=Clock(T0))
    assert Store(tmp_path / "b").answers()["celestrak-oneweb"]["code"] == 404
    assert [f["id"] for f in Index(tmp_path / "b", [REFRESHED], clock=Clock(), wall=Clock(T0 + 60)).forms()] == [
        "world-layer-celestrak-oneweb"]


def test_the_view_refreshes_one_set_at_a_time_on_a_thread_of_its_own_and_nothing_once_closed(tmp_path):
    folder = tmp_path / "layers"
    install(REFRESHED, folder, accept_licence=True, fetch=Downloads({AT: answer()}), clock=Clock(), wall=Clock(T0))
    wall = Clock(T0 + 3600)
    fetched = Downloads({AT: answer()})
    view = NetstatView("fw", reader=lambda: {}, names={}, fetch=fetched, agent="fw 1.0",
                       index=Index(folder, [REFRESHED], clock=Clock(), wall=wall), wall=wall)
    assert view.refresh() == "" and fetched.asked == []  # not due
    wall.t = T0 + 7200
    assert view.refresh() == "celestrak-oneweb"
    view._refreshing.join(10)
    assert len(fetched.asked) == 1 and fetched.asked[0][2]["encodings"] == ("gzip",)
    assert Store(folder).sets()["celestrak-oneweb"]["fetched"] > T0  # downloaded again (install's own wall clock)
    view.close()
    wall.t = T0 + 30_000
    assert view.refresh() == "" and len(fetched.asked) == 1


def test_the_tab_refreshes_only_for_a_person_at_the_page(tmp_path, monkeypatch):
    from test_firewall_geoip import Store as Login
    from test_worldweb_sky import Skied
    asked = []
    monkeypatch.setattr(NetstatView, "refresh", lambda self: asked.append(self.name) or "")
    fw = Skied(tmp_path)
    fw.world()
    with asking("another-plugin"), as_user(Login("bob")):
        fw.world()
    assert asked == []
    with asking(PAGE), as_user(Login()):
        fw.world()
    assert asked == [fw.name]
    fw.detach()
