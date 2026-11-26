"""machines/geosources.py (1.101.0, Monday list item 20): the GeoIP sources a firewall plugin names, read and refused in
words, their folders, when a file is due, the stamps of the places they give, and their keys checked and kept out of
every word. Every host here is a stand-in of the test's own; the canary keys are never a real one."""
import base64
import copy
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, quote_plus

import pytest

from liminal_libs.apps.authorization import Login, Unauthorized
from liminal_libs.machines import geosources as gs
from liminal_libs.sources.keys import KeyVar

pytestmark = pytest.mark.usefixtures("no_outside")

CC_BY = "https://creativecommons.org/licenses/by/4.0/"
CC_BY_SA = "https://creativecommons.org/licenses/by-sa/4.0/"


def words(url: str, text: str = "Free to use as long as the maker is credited.") -> str:
    return f"{text} {gs.pointer(url)}"


def dbip() -> dict:
    return {"id": "dbip", "title": "DB-IP Lite", "maker": "DB-IP", "hosts": ["download.example.test"], "files": [
        {"role": "places", "title": "DB-IP IP to City Lite", "packing": "mmdb.gz", "size": "about 60 MB",
         "url": "https://download.example.test/free/dbip-city-lite-{year}-{month}.mmdb.gz",
         "licence": {"words": words(CC_BY), "name": "CC BY 4.0", "pair": "dbip-lite", "version": "CC BY 4.0",
                     "url": CC_BY},
         "credit": {"text": "IP Geolocation by DB-IP", "url": "https://maker.example.test"}},
        {"role": "networks", "title": "DB-IP IP to ASN Lite", "packing": "mmdb.gz", "size": "about 5 MB",
         "url": "https://download.example.test/free/dbip-asn-lite-{year}-{month}.mmdb.gz",
         "licence": {"words": words(CC_BY), "name": "CC BY 4.0", "pair": "dbip-asn-lite", "version": "CC BY 4.0",
                     "url": CC_BY},
         "credit": {"text": "IP Geolocation by DB-IP", "url": "https://maker.example.test"}}]}


def ipinfo(offered=False) -> dict:
    return {"id": "ipinfo", "title": "IPinfo Lite", "maker": "IPinfo", "hosts": ["maker.example.test"],
            "keys": {"IPINFO_TOKEN": "token"}, "sends": "query", "query": "token", "offered": offered, "files": [
                {"role": "networks", "title": "IPinfo Lite", "packing": "mmdb", "shape": "ipinfo-lite",
                 "url": "https://maker.example.test/data/ipinfo_lite.mmdb", "stem": "ipinfo-lite",
                 "size": "about 24 MB", "sent_on": ["storage.example.test", "dl.example.test"],
                 "checksum": "ipinfo-checksums",
                 "checksum_url": "https://maker.example.test/data/ipinfo_lite.mmdb/checksums", "every_days": 7,
                 "licence": {"words": words(CC_BY_SA), "name": "CC BY-SA 4.0", "pair": "ipinfo-lite",
                             "version": "CC BY-SA 4.0", "url": CC_BY_SA},
                 "credit": {"text": "IP address data powered by IPinfo", "url": "https://maker.example.test"}}]}


def test_the_two_sources_read():
    d = gs.of(dbip())
    assert d.id == "dbip" and d.roles == ("places", "networks") and d.offered and not d.keys
    assert d.file("places").monthly and d.file("places").licence.pair == "dbip-lite"
    assert d.file("networks").key == "dbip-networks"
    i = gs.of(ipinfo())
    assert not i.offered and i.keys == {"IPINFO_TOKEN": "token"} and i.file("places") is None
    f = i.file("networks")
    assert f.sent_on == ("storage.example.test", "dl.example.test") and f.every_days == 7 and not f.monthly
    assert gs.of(d) is d


def test_an_offered_source_needs_its_keys_declared():
    with pytest.raises(ValueError, match="does not declare"):
        gs.of(ipinfo(offered=True))
    assert gs.of(ipinfo(offered=True), [KeyVar("IPINFO_TOKEN")]).offered
    assert gs.of(ipinfo(offered=True), ["IPINFO_TOKEN"]).offered


def _with(make, path, value):
    said = copy.deepcopy(make())
    where = said
    for step in path[:-1]:
        where = where[step]
    if value is KeyError:
        del where[path[-1]]
    else:
        where[path[-1]] = value
    return said


@pytest.mark.parametrize("path, value, words", [
    (("id",), "asn", "never asn"),
    (("id",), "DBIP", "lowercase"),
    (("id",), "x" * 33, "lowercase"),
    (("title",), "", "title and its maker"),
    (("hosts",), [], "own hosts"),
    (("hosts",), ["a.test", "b.test", "c.test", "d.test"], "own hosts"),
    (("hosts",), ["not a host"], "plain host"),
    (("files",), [], "no file"),
    (("files", 0, "url"), "http://download.example.test/free/x-{year}-{month}.mmdb.gz", "https only"),
    (("files", 0, "url"), "https://user:pw@download.example.test/{year}-{month}.mmdb.gz", "user name or password"),
    (("files", 0, "url"), "https://other.example.test/{year}-{month}.mmdb.gz", "own hosts"),
    (("files", 0, "url"), "https://download.example.test/{year}.mmdb.gz", "both"),
    (("files", 0, "url"), "https://download.example.test/{year}-{month}.mmdb.gz?k=1", "no query"),
    (("files", 0, "url"), "https://download.example.test:8443/{year}-{month}.mmdb.gz", "plain name"),
    (("files", 0, "role"), "points", "role"),
    (("files", 0, "packing"), "tar.gz", "packing"),
    (("files", 0, "shape"), "csv", "shape"),
    (("files", 0, "shape"), "ipinfo-lite", "networks alone"),
    (("files", 0, "checksum"), "md5", "checksum"),
    (("files", 0, "size"), "", "no size"),
    (("files", 0, "every_days"), -1, "days"),
    (("files", 0, "every_days"), True, "days"),
    (("files", 0, "licence", "words"), "x" * 1501, "1,500"),
    (("files", 0, "licence", "words"), "Free to use.", "summary"),
    (("files", 0, "licence", "url"), "http://creativecommons.org/licenses/by/4.0/", "https only"),
    (("files", 0, "licence", "pair"), "licence-dbip", "pair"),
    (("files", 0, "licence", "version"), "", "version"),
    (("files", 0, "credit"), {"text": "x" * 161}, "160"),
    (("files", 0, "credit"), {}, "no credit"),
    (("files", 1, "role"), "places", "one file a role"),
    (("keys",), {"IPINFO_TOKEN": "token"}, "sends no key"),
])
def test_what_a_source_cannot_be(path, value, words):
    with pytest.raises(ValueError, match=words):
        gs.of(_with(dbip, path, value))


@pytest.mark.parametrize("path, value, words", [
    (("query",), "", "parameter"),
    (("keys",), {"PATH": "token"}, "Windows'"),
    (("keys",), {"IPINFO_TOKEN": "token", "IPINFO_OTHER": "token"}, "one key"),
    (("keys",), {"IPINFO_TOKEN": "words"}, "form"),
    (("sends",), "basic", "way"),
    (("files", 0, "stem"), "", "stem"),
    (("files", 0, "sent_on"), ["a.test", "b.test", "c.test", "d.test"], "3 hosts"),
    (("files", 0, "checksum_url"), "https://elsewhere.example.test/c", "own hosts"),
    (("files", 0, "checksum_url"), "", "https only"),
])
def test_what_a_keyed_source_cannot_be(path, value, words):
    with pytest.raises(ValueError, match=words):
        gs.of(_with(ipinfo, path, value))


def test_read_leaves_out_and_says():
    bad = _with(dbip, ("id",), "asn")
    sources, refused = gs.read([dbip(), bad, dbip(), ipinfo(), "nonsense"])
    assert [s.id for s in sources] == ["dbip", "ipinfo"]
    assert len(refused) == 3 and any("named twice" in r for r in refused) and any("never asn" in r for r in refused)
    assert gs.read(()) == ([], [])


def test_folders_by_source():
    base = Path("geoip")
    assert gs.folder(base, "dbip", "places", "dbip") == base
    assert gs.folder(base, "dbip", "networks", "dbip") == base / "asn"
    assert gs.folder(base, "ipinfo", "networks", "dbip") == base / "ipinfo" / "asn"
    assert gs.folder(base, "maker", "places", "dbip") == base / "maker"


def _at(y, m, d):
    return datetime(y, m, d, 12, tzinfo=timezone.utc)


def test_due_by_month_by_days_and_expired():
    monthly = gs.of(dbip()).file("places")
    built = _at(2026, 11, 1).timestamp()
    assert gs.due(monthly, built, _at(2026, 11, 30)) == "fresh"
    assert gs.due(monthly, built, _at(2026, 12, 1)) == "update"
    weekly = gs.of(ipinfo()).file("networks")
    assert gs.due(weekly, _at(2026, 11, 20), _at(2026, 11, 26)) == "fresh"
    assert gs.due(weekly, _at(2026, 11, 19), _at(2026, 11, 26)) == "update"
    aging = gs.of(_with(ipinfo, ("files", 0, "max_age_days"), 30)).file("networks")
    assert gs.due(aging, _at(2026, 11, 1), _at(2026, 11, 30)) == "update"
    assert gs.due(aging, _at(2026, 11, 1), _at(2026, 12, 1)) == "expired"
    assert gs.due(monthly, None, _at(2026, 11, 1)) == "update"
    now = [_at(2026, 11, 30)]
    test = gs.usable(aging, lambda: now[0])
    assert test(Path("x.mmdb"), _at(2026, 11, 1).timestamp())
    now[0] = _at(2026, 12, 1)
    assert not test(Path("x.mmdb"), _at(2026, 11, 1).timestamp())
    assert gs.usable(monthly, lambda: now[0])(Path("x.mmdb"), 0)


def test_stamps_and_what_a_role_clears():
    assert gs.stamp(("dbip", "2026-11-01"), ("dbip", "2026-11-01"), "dbip") == "2026-11-01"
    assert gs.stamp(("dbip", "2026-11-01"), None, "dbip") == "2026-11-01"
    assert gs.stamp(("dbip", "2026-11-01"), ("ipinfo", "2026-11-24"), "dbip") == "#dbip:2026-11-01+ipinfo:2026-11-24"
    assert gs.stamp(None, ("ipinfo", "2026-11-24"), "dbip") == "#none+ipinfo:2026-11-24"
    assert gs.stamp(None, None, "dbip") == ""
    assert gs.stamp(("dbip", "2026-11-01"), ("dbip", "2026-11-01"), "dbip") < "2026-12-01"
    assert "#" < "0"  # an older library's `placed < ?` takes every # row as older, and places it again
    assert gs.cleared("places", "maker") == "#maker:%"
    assert gs.cleared("networks", "ipinfo") == "%+ipinfo:%"


CANARY = "Canary_Token-0123456789abcdef"


@pytest.mark.parametrize("value", [f"Can ary{CANARY}", f"Can\tary{CANARY}", f"Can%ary{CANARY}", f"Can&ary{CANARY}",
                                   f"Can#ary{CANARY}", f"Canäry{CANARY}", "short", "x" * 129, "", "\n"])
def test_a_key_that_cannot_be_sent_is_refused_in_words_without_it(value):
    with pytest.raises(ValueError) as e:
        gs.checked("IPINFO_TOKEN", value, "token")
    said = f"{e.value} {e.value!r}"
    assert "IPINFO_TOKEN" in said and "login's page" in said
    assert (value.strip() or "\0") not in said and CANARY not in said
    assert e.value.__cause__ is None and (e.value.__context__ is None or e.value.__suppress_context__)


def test_a_key_that_can_be_sent():
    assert gs.checked("IPINFO_TOKEN", f"  {CANARY} ", "token") == CANARY
    assert gs.checked("MAKER_ACCOUNT_ID", "123456", "digits") == "123456"
    with pytest.raises(ValueError, match="digits"):
        gs.checked("MAKER_ACCOUNT_ID", "12a", "digits")


def test_redact_takes_every_form_out():
    other = "Account_9876543210"
    secrets = {"IPINFO_TOKEN": "Can ary%&#ä" + CANARY, "OTHER": other}
    value = secrets["IPINFO_TOKEN"]
    text = " | ".join([value, quote(value, safe=""), quote(value), quote_plus(value), repr(value),
                       repr(value.encode("utf-8")), base64.b64encode(f"{other}:{value}".encode()).decode(),
                       base64.b64encode(f"{value}:{other}".encode()).decode(), other, "kept words"])
    out = gs.redact(text, secrets)
    assert CANARY not in out and other not in out and "kept words" in out
    for form in (quote(value, safe=""), quote_plus(value), base64.b64encode(f"{other}:{value}".encode()).decode()):
        assert form not in out
    assert gs.redact("nothing", {}) == "nothing"


class Store(Login):
    """A person's stand-in login: its variables asked once, by name."""

    def __init__(self, values=None, fail=False):
        self.values, self.fail, self.asked = dict(values or {}), fail, []

    def user(self):
        return {"name": "someone"}

    def vector(self, name):
        raise Unauthorized("no", 401)

    def variables(self, wanted):
        self.asked.append(list(wanted))
        if self.fail:
            raise Unauthorized("closed", 401)
        return {k: v for k, v in self.values.items() if k in wanted}


def test_credentials_read_once_and_refused_in_words():
    source = gs.of(ipinfo(offered=True), ["IPINFO_TOKEN"])
    empty = Store()
    with pytest.raises(ValueError, match="not set in your login store") as e:
        gs.credentials(source, empty)
    assert empty.asked == [["IPINFO_TOKEN"]]
    assert "IPINFO_TOKEN" in str(e.value)
    with pytest.raises(ValueError, match="could not be read"):
        gs.credentials(source, Store(fail=True))
    with pytest.raises(gs.NotAsked):
        gs.credentials(source, None)
    bad = Store({"IPINFO_TOKEN": f"Can\tary{CANARY}"})
    with pytest.raises(ValueError) as e:
        gs.credentials(source, bad)
    assert CANARY not in str(e.value)
    good = Store({"IPINFO_TOKEN": CANARY})
    assert gs.credentials(source, good) == {"IPINFO_TOKEN": CANARY} and good.asked == [["IPINFO_TOKEN"]]
    assert gs.credentials(gs.of(dbip()), None) == {}


def test_the_address_carries_the_key_in_its_query_alone():
    source = gs.of(ipinfo())
    f = source.file("networks")
    assert gs.address(f, source, {"IPINFO_TOKEN": CANARY}) == f"{f.url}?token={CANARY}"
    assert gs.address(f, source, {"IPINFO_TOKEN": CANARY}, checksum=True) == f"{f.checksum_url}?token={CANARY}"
    d = gs.of(dbip())
    assert gs.address(d.file("places"), d, {}) == d.file("places").url


def test_the_licence_record_words():
    f = gs.of(dbip()).file("places")
    said = gs.licence_of(f, "2026-11")
    assert said == {"name": "dbip-lite", "title": "DB-IP IP to City Lite, 2026-11", "version": "CC BY 4.0",
                    "url": CC_BY, "words": f.licence.words}
    assert said["words"].endswith(gs.pointer(CC_BY))
    assert gs.RemovalRefused.accept == "accept_removal"
    assert "sign in" in str(gs.NotAsked())
