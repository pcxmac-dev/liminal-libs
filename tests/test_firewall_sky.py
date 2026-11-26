"""The firewall's sky hooks (1.104.0, Monday list item 32): the sgp4 package's download and removal are the page's
alone, as a data set's download is (the user's 11b), and its licence accepted at the page is kept in the person's own
login store, as a data set's is (13a). The package's download is a stand-in: nothing is fetched."""
from __future__ import annotations

import json

import pytest

from liminal_libs import internal
from liminal_libs.apps import EnvironmentLogin, as_user
from liminal_libs.apps.asking import PAGE, asking
from liminal_libs.apps.authorization import LICENCE
from liminal_libs.machines import geosources, satellites as S, world
from liminal_libs.machines.infrastructure import Index
from liminal_libs.machines.netstat import NetstatView

from test_firewall import FakeFirewall
from test_firewall_geoip import Sourced, Store, licences  # noqa: F401 - the licences file's fixture
from test_satellites import SETS, pin
from test_world import NOW, Clock, socket_table


class Skied(Sourced):
    """A firewall naming two constellations and pinning the sgp4 package, its download a stand-in."""

    INFRASTRUCTURE = SETS
    SKY_PACKAGE = pin(b"x")

    def __init__(self, tmp_path):
        super().__init__(tmp_path / "geoip", None)
        self.tmp = tmp_path

    def make_netstat_view(self):
        view = NetstatView(self.name, reader=lambda: socket_table(), names={}, login_of=lambda: self.login,
                           index=Index(self.tmp / "layers", self.INFRASTRUCTURE), clock=Clock(), wall=Clock(NOW))
        view.sky = S.SkyView(view.index, self.SKY_PACKAGE, data_dir=self.tmp / "data")
        return view


@pytest.fixture
def installs(monkeypatch):
    asked = []

    def install(package, data_dir=None, *, accept_licence=False, log=None, cancel=None, opener=None):
        if accept_licence is not True:
            raise world.LicenceRefused("The sgp4 package is downloaded only once you accept its licence.")
        asked.append((package.version, accept_licence))
        return {"said": f"installed the sgp4 package {package.version}", "ok": True, "lines": []}
    monkeypatch.setattr(S, "install_package", install)
    return asked


def test_the_packages_download_and_removal_are_the_pages_alone_in_the_base():
    plain = FakeFirewall()
    assert {"world_sky_get", "world_sky_remove"} <= set(internal.page_only(plain))
    assert "world_sky" not in internal.page_only(plain)  # the places, a read the page and others may ask
    assert internal.problems(plain) == []


@pytest.mark.parametrize("who", ["nobody", "a plugin", "the platform's login"])
def test_the_package_asked_by_anyone_but_a_person_at_the_page_is_refused_with_nothing_fetched(tmp_path, installs,
                                                                                              who):
    fw = Skied(tmp_path)
    into = S.package_folder("2.27", tmp_path / "data")
    (into / "sgp4").mkdir(parents=True)
    if who == "nobody":
        with pytest.raises(geosources.NotAsked):
            fw.world_sky_get(True)
        with pytest.raises(geosources.NotAsked):
            fw.world_sky_remove()
    elif who == "a plugin":
        with asking("another-plugin"), as_user(Store("bob")):
            with pytest.raises(geosources.NotAsked):
                fw.world_sky_get(True)
            with pytest.raises(geosources.NotAsked):
                fw.world_sky_remove()
    else:
        with asking(PAGE), as_user(EnvironmentLogin(env={})):
            with pytest.raises(geosources.NotAsked):
                fw.world_sky_get(True)
    assert installs == [] and into.is_dir()
    fw.detach()


def test_the_package_asked_at_the_page_is_downloaded_and_removed(tmp_path, installs):
    fw = Skied(tmp_path)
    with asking(PAGE), as_user(Store()):
        out = fw.world_sky_get(True)
        assert out["ok"] and installs == [("2.27", True)]
        assert fw.world_sky_remove()["ok"]
    fw.detach()


def test_the_packages_licence_accepted_at_the_page_is_kept_as_its_pair_and_nowhere_else(tmp_path, installs, licences):
    fw = Skied(tmp_path)
    keeps = dict(fw.KEEPS)  # one pair a version (the user, 2026-11-26): a new version's licence is asked again
    assert keeps["licence-sgp4-2.27"].startswith("your acceptance of the sgp4 package 2.27's licence")
    assert "licence-sgp4" not in keeps
    alice = Store()
    with asking(PAGE), as_user(alice):
        with pytest.raises(world.LicenceRefused):
            fw.world_sky_get(False)
        assert alice.pairs == {}
        out = fw.world_sky_get(True)
    assert out["ok"] and installs[-1] == ("2.27", True) and "kept in your own login store" in out["lines"][-1]
    assert set(alice.pairs) == {"licence-sgp4-2.27"}
    kind, raw = alice.pairs["licence-sgp4-2.27"]
    record = json.loads(raw)
    assert kind == LICENCE and record["title"] == "The sgp4 package 2.27" and record["version"] == "MIT"
    assert record["acceptedBy"] == "alice" and record["words"].startswith("MIT License")
    assert not licences.exists()
    fw.detach()


def test_a_new_version_pinned_is_kept_under_its_own_pair(tmp_path, installs, licences):
    fw = Skied(tmp_path)
    fw.SKY_PACKAGE = {**fw.SKY_PACKAGE, "version": "2.28"}
    assert "licence-sgp4-2.28" in dict(fw.KEEPS) and "licence-sgp4-2.27" not in dict(fw.KEEPS)
    fw.detach()


def test_a_store_that_refuses_the_packages_licence_ends_it_with_nothing_fetched(tmp_path, installs, licences):
    fw = Skied(tmp_path)
    with asking(PAGE), as_user(Store(refuse=True)):
        with pytest.raises(ValueError, match="sgp4 package's licence could not be kept in your login store"):
            fw.world_sky_get(True)
    assert installs == [] and not licences.exists()
    fw.detach()
