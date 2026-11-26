"""The firewall base's GeoIP sources (1.102.0, Monday list item 20): the three hooks only a person signed in at the
platform's page may ask, each refusing any other ask itself; the licence's acceptance kept in that person's own login
store, or nothing downloaded, and the licences file never written; DB-IP's two old installs downloading as before, with
no record, for any other asker; a source not offered refused before anything is read; the choice kept through the
plugin's login. Every download is a stand-in's; the canary key is never a real one."""
from __future__ import annotations

import gzip
import json

import pytest

from liminal_libs import geo, internal
from liminal_libs.apps import EnvironmentLogin, Login, Unauthorized, as_user
from liminal_libs.apps.asking import PAGE, asking
from liminal_libs.apps.authorization import LICENCE
from liminal_libs.machines import geosources, world
from liminal_libs.machines.firewall import Firewall
from liminal_libs.machines.infrastructure import Index
from liminal_libs.machines.netstat import NetstatView
from liminal_libs.machines.world import LicenceRefused, WorldView
from liminal_libs.sources.keys import KeyVar

from test_firewall import FakeFirewall
from test_geo import NOVEMBER, mmdb, needs_reader
from test_infrastructure import AT, CENTRES as DATACENTRES, CENTRES_ANSWER as DATACENTRES_ANSWER, Downloads
from test_world import NOW, PLACES, Clock, Feed, socket_table, source_dicts

pytestmark = pytest.mark.usefixtures("no_outside")
CITY = "https://geoip.example/dbip-city-lite-2026-11.mmdb.gz"
TOKEN = "Canary_Token-0123456789abcdef"


class Store(Login):
    """A person's own login store, as the login app's session is: their pairs, settings kept."""

    keeps_settings = True

    def __init__(self, name="alice", pairs=None, refuse=False):
        self.name, self.pairs, self.refuse, self.asked = name, dict(pairs or {}), refuse, []

    def user(self):
        return {"name": self.name}

    def vector(self, name):
        self.asked.append(name)
        if name not in self.pairs:
            raise Unauthorized("no such pair", 404)
        return self.pairs[name][1]

    def names(self):
        return set(self.pairs)

    def setting(self, name):
        kept = self.pairs.get(name)
        return json.loads(kept[1]) if kept else None

    def keep_setting(self, name, value, kind="preference", label=""):
        if self.refuse:
            raise Unauthorized("the vault is closed", 401)
        self.pairs[name] = (kind, json.dumps(value))
        return {"name": name, "kind": kind}


class Fetches:
    def __init__(self, pages):
        self.pages, self.asked = dict(pages), []

    def __call__(self, url, timeout):
        self.asked.append(url)
        import io
        if url not in self.pages:
            import urllib.error
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b""))
        return io.BytesIO(self.pages[url])


class Sourced(FakeFirewall):
    name = "sourced-firewall"
    GEOIP_SOURCES = tuple(source_dicts(offered=False))

    def __init__(self, folder, fetch, **more):
        super().__init__(**more)
        self.folder, self.fetch = folder, fetch
        self.login = EnvironmentLogin(env={})

    def make_world_view(self):
        return WorldView(self.name, capture_factory=Feed, geo_folder=self.folder, clock=Clock(), wall=Clock(NOW),
                         fetch=self.fetch, sources=self.world_sources(),
                         resolve=lambda version, servers: (None, "no name server answers in a test"))

    def make_netstat_view(self):
        return NetstatView(self.name, reader=lambda: socket_table(), names={}, login_of=lambda: self.login,
                           clock=Clock(), wall=Clock(NOW))


@pytest.fixture
def licences(tmp_path, monkeypatch):
    path = tmp_path / "licences.json"
    monkeypatch.setenv("LIMINAL_LICENCES_FILE", str(path))
    return path


def firewall(tmp_path):
    fetch = Fetches({CITY: gzip.compress(mmdb(PLACES, built=NOVEMBER))})
    return Sourced(tmp_path / "geoip", fetch), fetch


def test_the_three_hooks_are_the_pages_alone():
    fw = Sourced(None, None)
    assert {"world_geoip_get", "world_geoip_use", "world_geoip_remove"} <= set(internal.page_only(fw))
    assert {"world_geoip_get", "world_geoip_use", "world_geoip_remove"} <= set(fw.interface()["hooks"])
    assert "world_geoip_get" in fw.JOB_HOOKS and "world_geoip_get" in fw.CANCEL_HOOKS
    assert internal.problems(fw) == []
    names = dict(fw.KEEPS)
    assert geosources.VAR in names and "licence-dbip-lite" in names and "licence-ipinfo-lite" not in names
    assert Firewall.GEOIP_SOURCES == () and Firewall.world_sources(FakeFirewall()) is None


@needs_reader
def test_an_acceptance_is_kept_in_the_persons_store_and_nowhere_else(tmp_path, licences):
    fw, fetch = firewall(tmp_path)
    alice = Store()
    with asking(PAGE), as_user(alice):
        with pytest.raises(LicenceRefused) as refused:
            fw.world_geoip_get("dbip", "places", False)
        assert refused.value.accept == "accept_licence" and fetch.asked == []
        out = fw.world_geoip_get("dbip", "places", True)
    assert out["ok"] and fetch.asked == [CITY] and "kept in your own login store" in out["lines"][-1]
    kind, raw = alice.pairs["licence-dbip-lite"]
    record = json.loads(raw)
    assert kind == LICENCE and record["title"] == "City Lite, 2026-11" and record["version"] == "CC 4.0"
    assert record["acceptedBy"] == "alice" and record["url"].startswith("https://creativecommons.org/")
    assert not licences.exists()
    fw.detach()


@needs_reader
@pytest.mark.parametrize("who", ["nobody", "a plugin", "the platform's login"])
def test_any_other_ask_is_refused_before_anything_is_read(tmp_path, licences, who):
    fw, fetch = firewall(tmp_path)
    if who == "nobody":
        call = lambda: fw.world_geoip_get("dbip", "places", True)  # noqa: E731
    elif who == "a plugin":
        def call():
            with asking("another-plugin"), as_user(Store()):
                return fw.world_geoip_get("dbip", "places", True)
    else:
        def call():
            with asking(PAGE), as_user(EnvironmentLogin(env={})):
                return fw.world_geoip_get("dbip", "places", True)
    for ask in (call, lambda: fw.world_geoip_use("dbip", "places"), lambda: fw.world_geoip_remove("dbip", "places", True)):
        with pytest.raises(geosources.NotAsked, match="sign in"):
            ask() if ask is call else ask()
    assert fetch.asked == [] and not licences.exists() and not (tmp_path / "geoip").exists()
    fw.detach()


@needs_reader
def test_a_store_that_refuses_ends_the_download_with_nothing_fetched(tmp_path, licences):
    fw, fetch = firewall(tmp_path)
    with asking(PAGE), as_user(Store(refuse=True)):
        with pytest.raises(ValueError, match="could not be kept in your login store"):
            fw.world_geoip_get("dbip", "places", True)
    assert fetch.asked == [] and not licences.exists()
    fw.detach()


@needs_reader
def test_the_old_install_downloads_as_before_for_another_asker_and_records_nothing(tmp_path, licences):
    fw, fetch = firewall(tmp_path)
    with pytest.raises(LicenceRefused):
        fw.world_geoip(False)
    out = fw.world_geoip(True)  # no asker: a program, a script
    assert out["ok"] and fetch.asked == [CITY] and not licences.exists()
    alice = Store()
    with asking(PAGE), as_user(alice):
        fw.world_geoip(True)  # a person at the page: recorded in their store (installed already: nothing fetched)
    assert "licence-dbip-lite" in alice.pairs and fetch.asked == [CITY] and not licences.exists()
    fw.detach()


def test_a_source_not_offered_is_refused_before_any_key_is_read(tmp_path, licences):
    fw, fetch = firewall(tmp_path)
    alice = Store(pairs={"ipinfo-token": ("key", TOKEN)})
    with asking(PAGE), as_user(alice):
        with pytest.raises(ValueError, match="not offered: waiting for your word"):
            fw.world_geoip_get("ipinfo", "networks", True)
        with pytest.raises(ValueError, match="not offered"):
            fw.world_geoip_use("ipinfo", "networks")
        with pytest.raises(ValueError, match="names no"):
            fw.world_geoip_get("nobody", "places", True)
    assert alice.asked == [] and fetch.asked == []
    fw.detach()


def test_an_offered_sources_missing_key_is_named_and_its_value_never_read(tmp_path, licences):
    class Keyed(Sourced):
        GEOIP_SOURCES = tuple(source_dicts(offered=True))
        keys = (*Sourced.keys, KeyVar("IPINFO_TOKEN", label="IPinfo token", personal=True))
    fw = Keyed(tmp_path / "geoip", Fetches({}))
    alice = Store()
    with asking(PAGE), as_user(alice):
        with pytest.raises(ValueError, match="IPINFO_TOKEN is not set in your login store"):
            fw.world_geoip_get("ipinfo", "networks", True)
    assert alice.asked == [] and fw.fetch.asked == []
    fw.detach()


@needs_reader
def test_use_keeps_the_choice_through_the_plugins_login_and_remove_is_asked_twice(tmp_path, licences):
    fw, _ = firewall(tmp_path)
    geo.install_mmdb(mmdb(PLACES, built=NOVEMBER), tmp_path / "geoip", "dbip-city-lite-2026-11")
    with asking(PAGE), as_user(Store()):
        out = fw.world_geoip_use("dbip", "places")
        assert out["ok"] and json.loads(fw.login.env[geosources.VAR]) == {"places": "dbip"}
        assert fw.geoip_choice(fresh=True) == {"places": "dbip"}
        with pytest.raises(ValueError, match="not installed"):
            fw.world_geoip_use("dbip", "networks")
        with pytest.raises(geosources.RemovalRefused) as twice:
            fw.world_geoip_remove("dbip", "places")
        assert twice.value.accept == "accept_removal"
        assert (tmp_path / "geoip" / "dbip-city-lite-2026-11.mmdb").exists()
        gone = fw.world_geoip_remove("dbip", "places", True)
    assert gone["ok"] and not (tmp_path / "geoip" / "dbip-city-lite-2026-11.mmdb").exists()
    fw.detach()


@needs_reader
def test_the_tab_draws_the_sources_table_and_the_places_credit_in_use(tmp_path):
    fw, _ = firewall(tmp_path)
    geo.install_mmdb(mmdb(PLACES, built=NOVEMBER), tmp_path / "geoip", "dbip-city-lite-2026-11")
    fw.ATTRIBUTION = {"text": "not this one", "url": ""}
    page = fw.world()
    assert any(t.get("title") == world.SOURCES_TITLE for t in page["tables"])
    assert page["globe"]["attribution"]["text"] == "IP Geolocation by DB-IP"
    assert not any(a.get("form") in (world.FORM, world.ASN_FORM) for a in page.get("actions", []))
    fw.detach()


@needs_reader
@pytest.mark.parametrize("role", ["places", "networks"])
def test_removing_the_default_sources_file_clears_what_it_placed(tmp_path, licences, role):
    """Review finding: the default source's places are stamped with the places file's bare date, as before 1.102.0, so
    a pattern of #dbip:... never met them and removing DB-IP's file kept every place it gave."""
    from liminal_libs.hostbook import HostBook
    from test_geo import ASNS
    from test_hostbook import NUREMBERG, T0, WEB, atlas, row, win
    book = HostBook(tmp_path / "hosts" / "hosts.db")

    class Booked(Sourced):
        def make_netstat_view(self):
            return NetstatView(self.name, reader=lambda: socket_table(), names={}, login_of=lambda: self.login,
                               book=book, clock=Clock(), wall=Clock(NOW))
    fw = Booked(tmp_path / "geoip", Fetches({}))
    geo.install_mmdb(mmdb(PLACES, built=NOVEMBER), tmp_path / "geoip", "dbip-city-lite-2026-11")
    geo.install_mmdb(mmdb(ASNS, kind="DBIP-ASN-Lite"), geo.asn_folder(tmp_path / "geoip"), "dbip-asn-lite-2026-11")
    win(book, T0, row(started=T0))
    book.flush()
    stamp = geosources.stamp(("dbip", "2026-11-01"), ("dbip", "2026-11-01"), "dbip")
    assert stamp == "2026-11-01"  # the default pair's stamp: the bare date
    book.place(atlas({WEB: NUREMBERG}), stamp)
    assert {(h["country"], h["asn"]) for h in book.hosts()} == {("Germany", 64500)}
    fw.netstat_view()  # made, as the tab's page the remove is asked from made it
    with asking(PAGE), as_user(Store()):
        assert fw.world_geoip_remove("dbip", role, True)["ok"]
    (host,) = book.hosts()
    if role == "places":
        assert (host["country"], host["lat"], host["placed"]) == ("", None, "")
    else:
        assert (host["asn"], host["org"], host["placed"]) == (None, "", "")
    gone = "country" if role == "places" else "asn"
    assert all(c[gone] in (None, "") for c in book.connections())
    fw.detach()


@needs_reader
def test_the_hosts_recorded_view_keeps_the_sources_table_and_its_buttons(tmp_path):
    """Review finding: the hosts view's frame threw every table of the traffic page away, the GeoIP sources' too, so
    its forms were kept with no button pointing at them and DB-IP's file could not be updated from that view."""
    fw, _ = firewall(tmp_path)
    geo.install_mmdb(mmdb(PLACES, built=NOVEMBER), tmp_path / "geoip", "dbip-city-lite-2026-11")
    fw.world_show("hosts")
    page = fw.world()
    (table,) = [t for t in page["tables"] if t.get("title") == world.SOURCES_TITLE]
    buttons = [b for r in table["rows"] for b in r[5:] if b]
    assert {b["title"] for b in buttons} >= {"Download…", "Remove…"}  # the ASN file to download, the city file's remove
    forms = {f["id"] for f in page.get("forms", ())}
    assert {b["form"] for b in buttons} <= forms
    fw.detach()


# -- the user's 11b and 13a: the older installs and a data set's download are the page's alone, by the base; a data
# set's licence accepted at the page is kept as DB-IP's are ---------------------------------------------------------------
def test_the_older_installs_and_a_data_sets_download_are_the_pages_alone_in_the_base():
    plain = FakeFirewall()  # names none of its own: the base's alone
    assert {"world_geoip", "world_asn", "world_layer_get"} <= set(Firewall.PAGE_ONLY_HOOKS)
    assert {"world_geoip", "world_asn", "world_layer_get", "world_geoip_get", "world_geoip_use",
            "world_geoip_remove"} <= set(internal.page_only(plain))
    assert internal.problems(plain) == [] and internal.problems(Sourced(None, None)) == []


class Layered(Sourced):
    """A firewall naming one data set, downloaded from a stand-in into tmp_path."""

    INFRASTRUCTURE = (DATACENTRES,)

    def __init__(self, folder, fetch, downloads, layers):
        super().__init__(folder, fetch)
        self.downloads, self.layers = downloads, layers

    def make_netstat_view(self):
        return NetstatView(self.name, reader=lambda: socket_table(), names={}, login_of=lambda: self.login,
                           index=Index(self.layers, self.INFRASTRUCTURE), fetch=self.downloads,
                           clock=Clock(), wall=Clock(NOW))


def layered(tmp_path):
    downloads = Downloads({AT["osm-datacentres"]: DATACENTRES_ANSWER})
    return Layered(tmp_path / "geoip", Fetches({}), downloads, tmp_path / "layers"), downloads


def test_a_data_sets_licence_accepted_at_the_page_is_kept_as_its_pair_and_nowhere_else(tmp_path, licences):
    fw, downloads = layered(tmp_path)
    assert dict(fw.KEEPS)["licence-osm-datacentres"].startswith("your acceptance of Data centres's licence")
    alice = Store()
    with asking(PAGE), as_user(alice):
        with pytest.raises(LicenceRefused):
            fw.world_layer_get("osm-datacentres", False)
        assert downloads.asked == [] and alice.pairs == {}
        out = fw.world_layer_get("osm-datacentres", True)
    assert out["ok"] and len(downloads.asked) == 1 and "kept in your own login store" in out["lines"][-1]
    kind, raw = alice.pairs["licence-osm-datacentres"]
    record = json.loads(raw)
    assert kind == LICENCE and record["title"] == "Data centres" and record["version"] == "ODbL 1.0"
    assert record["acceptedBy"] == "alice" and record["words"].startswith("OpenStreetMap's data is free")
    assert not licences.exists()
    fw.detach()


@pytest.mark.parametrize("who", ["nobody", "a plugin", "the platform's login"])
def test_a_data_sets_download_asked_otherwise_records_nothing(tmp_path, licences, who):
    fw, downloads = layered(tmp_path)
    bob = Store("bob")
    if who == "nobody":
        out = fw.world_layer_get("osm-datacentres", True)  # a program, a script: downloads as before
    elif who == "a plugin":
        with asking("another-plugin"), as_user(bob):
            out = fw.world_layer_get("osm-datacentres", True)
    else:
        with asking(PAGE), as_user(EnvironmentLogin(env={})):
            out = fw.world_layer_get("osm-datacentres", True)
    assert out["ok"] and len(downloads.asked) == 1 and bob.pairs == {} and not licences.exists()
    assert "kept in your own login store" not in " ".join(out["lines"])
    fw.detach()


def test_a_store_that_refuses_a_data_sets_licence_ends_it_with_nothing_fetched(tmp_path, licences):
    fw, downloads = layered(tmp_path)
    with asking(PAGE), as_user(Store(refuse=True)):
        with pytest.raises(ValueError, match="Data centres's licence could not be kept in your login store"):
            fw.world_layer_get("osm-datacentres", True)
    assert downloads.asked == [] and not licences.exists() and not (tmp_path / "layers").exists()
    fw.detach()
