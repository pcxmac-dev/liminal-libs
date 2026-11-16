"""What a name is known for (liminal_libs.classify), over small lists written here in each one's own format:
EasyList's and EasyPrivacy's adblock rules with their section markers, a hosts file, hagezi's domain lists and AdGuard
companiesdb's trackers.json with its company names. Only the rules for a whole domain are taken; a name is matched by
its own labels and its parents', one label of each kind; the lists are read from their folder by the manifest and
kept there one copy each. A hostile list costs its length alone, in time and in RAM. Nothing is downloaded: the lists
are text made here."""
from __future__ import annotations

import json
import re
import stringprep
import time
import tracemalloc
from pathlib import Path
from unicodedata import ucd_3_2_0

import pytest

from liminal_libs import classify
from liminal_libs.classify import (Classifier, Label, install_list, parse_abp, parse_adguard_companies, parse_domains,
                                   parse_hosts, read_manifest, section_kind)

IDN = "xn--e1afmkfd.example"  # "пример.example" as DNS carries it

EASYLIST = r"""[Adblock Plus 2.0]
! Version: 202611140819
! Title: EasyList
! Expires: 4 days (update frequency)
! *** easylist:easylist/easylist_general_block.txt ***
-banner-ad-
||ads.example^$third-party
example.org##.ad-box
##.sponsored
example.org#@#.ad-box
example.org#?#div:has(> .ad)
example.org#$#body { margin: 0 }
@@||ads.example^$domain=friend.example
/banner[0-9]+\.gif/
||adserver.example/serve/
||wild.example^*.js
||*.star.example^
||sites-only.example^$domain=news.example|blog.example
||all-but.example^$third-party,domain=~news.example
||rewritten.example^$csp=script-src 'none'
||redirected.example^$redirect=noopjs
||com^
||turned-off.example^$third-party
||turned-off.example^$third-party,badfilter
||UPPER.Example^
||203.0.113.7^
||пример.example^
||port.example:8080^
! *** easylist:easylist/easylist_adservers.txt ***
||adnet.example^$third-party
! *** easylist:easylist/easylist_adservers_popup.txt ***
||popunder.example^$popup,third-party
"""

EASYPRIVACY = r"""[Adblock Plus 2.0]
! Title: EasyPrivacy
||before-any-marker.example^
!-----------------General tracking systems-----------------!
! *** easylist:easyprivacy/easyprivacy_general.txt ***
||general.example^$third-party
/pixel.gif?
! *** easylist:easyprivacy/easyprivacy_trackingservers_general.txt ***
||tracker.example^
||metrics.tracker2.example^$third-party
||collect.example^|
@@||allowed.example^
||also-mining.example^
! *** easylist:easyprivacy/easyprivacy_trackingservers_mining.txt ***
||coin-miner.example^$third-party
||also-mining.example^$third-party
! *** easylist:easyprivacy/easyprivacy_general_emailtrackers.txt ***
||mailopen.example^$image
||coin-miner.example^
! *** easylist:easyprivacy/easyprivacy_specific_cname_adobe.txt ***
||smetrics.brand.example^
! *** easylist:easyprivacy/easyprivacy_trackingservers_notifications.txt ***
||push.example^$third-party
! *** easylist:easyprivacy/easyprivacy_allowlist.txt ***
@@||cdn.allowed.example^$script
"""

HOSTS = """# Title: a hosts list
# Updated: 2026-11-14
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
255.255.255.255 broadcasthost
::1 localhost ip6-localhost ip6-loopback
fe80::1%lo0 localhost
0.0.0.0 0.0.0.0
0.0.0.0 telemetry.vendor.example
0.0.0.0 a.tracker.example b.tracker.example  # two names on a line
127.0.0.1\tTABBED.Example.
:: v6-blocked.example
lonely.example
0.0.0.0 not_a_name!
0.0.0.0 single
"""

DOMAINS = """# Title: HaGeZi's Microsoft Tracker DNS Blocklist (a sample)
# Number of entries: 9
#
events.data.vendor.example
*.telemetry.vendor.example
.wild-dot.vendor.example
||adblock-style.vendor.example^
0.0.0.0 hosts-style.vendor.example
plain.vendor.example # a note after it
! an adblock comment
; a zone file's comment
[Adblock Plus]
not a name at all
ads.*.vendor.example
198.51.100.9
UPPER.Vendor.Example.
"""

TRACKERS = {
    "timeUpdated": "2026-11-13T00:12:39.735Z",
    "categories": {"0": "audio_video_player", "1": "comments", "4": "advertising", "5": "essential",
                   "6": "site_analytics", "7": "social_media", "8": "misc", "9": "cdn", "10": "hosting",
                   "13": "email", "14": "consent", "15": "telemetry", "101": "mobile_analytics"},
    "trackers": {
        "adco": {"name": "AdCo Exchange", "categoryId": 4, "url": None, "companyId": "adco"},
        "measure": {"name": "Measure Analytics", "categoryId": 6, "url": None, "companyId": "bigco"},
        "appstats": {"name": "AppStats SDK", "categoryId": 101, "url": None, "companyId": "bigco"},
        "phonehome": {"name": "PhoneHome", "categoryId": 15, "url": None, "companyId": "devco"},
        "fastcdn": {"name": "FastCDN", "categoryId": 9, "url": None, "companyId": "fastco"},
        "cloudhost": {"name": "CloudHost", "categoryId": 10, "url": None, "companyId": None},
        "likes": {"name": "Like Button", "categoryId": 7, "url": None, "companyId": "socialco"},
        "talk": {"name": "Talk Comments", "categoryId": 1, "url": None, "companyId": "talkco"},
        "mailpixel": {"name": "MailPixel", "categoryId": 13, "url": None, "companyId": "mailco"},
        "needed": {"name": "Needed Fonts", "categoryId": 5, "url": None, "companyId": "bigco"},
        "cookiebar": {"name": "Cookie Bar", "categoryId": 14, "url": None, "companyId": "cbco"},
        "player": {"name": "Video Player", "categoryId": 0, "url": None, "companyId": "vidco"},
    },
    "trackerDomains": {
        "adco.example": "adco", "ads.adco.example": "adco", "adnet.example": "adco", "measure.example": "measure",
        "sdk.appstats.example": "appstats", "phonehome.example": "phonehome", "fastcdn.example": "fastcdn",
        "cloudhost.example": "cloudhost", "likes.example": "likes", "talk.example": "talk",
        "mailpixel.example": "mailpixel", "needed.example": "needed", "cookiebar.example": "cookiebar",
        "player.example": "player", "orphan.example": "nobody", "Not A Domain": "adco",
    },
}
COMPANIES = {"timeUpdated": "2026-11-13T00:12:39.735Z", "companies": {
    "adco": {"name": "AdCo Inc.", "websiteUrl": None, "description": "An advertising exchange."},
    "bigco": {"name": "BigCo"}, "devco": {"name": "DevCo"}, "fastco": {"name": "FastCo"},
    "socialco": {"name": "SocialCo"}, "talkco": {"name": "TalkCo"}, "mailco": {"name": "MailCo"}}}


def kinds(rules: dict) -> dict:
    return {name: label.kind for name, label in rules.items()}


# -- the parsers --------------------------------------------------------------------------------------------------

def test_an_adblock_list_gives_its_rules_for_whole_domains_only():
    rules = parse_abp(EASYLIST, "ads", "EasyList")
    assert kinds(rules) == {"ads.example": "ads", "all-but.example": "ads", "upper.example": "ads",
                            "203.0.113.7": "ads", IDN: "ads", "adnet.example": "ads", "popunder.example": "ads"}
    # skipped: cosmetic rules and their exceptions, the exception for ads.example on one site, a regular expression,
    # a rule for a path, wildcards, a rule for some sites only, rules that rewrite or redirect, a whole top-level
    # domain, a rule a badfilter turns off, and a name with a port
    assert all(r.source == "EasyList" and r.company is None for r in rules.values())
    assert len({id(r) for r in rules.values()}) == 1  # one label for all the names of a kind
    assert parse_abp(EASYLIST, "ads", limit=3).keys() == {"ads.example", "all-but.example", "upper.example"}
    assert parse_abp(("\ufeff" + EASYLIST).encode("utf-8"), "ads").keys() == rules.keys()  # bytes, a byte-order mark
    assert parse_abp(EASYLIST.replace("\n", "\r\n"), "ads").keys() == rules.keys()  # Windows' line ends
    assert parse_abp("", "ads") == {} and parse_abp("! only comments\n", "ads") == {}
    with pytest.raises(ValueError, match="no kind of label"):
        parse_abp(EASYLIST, "adverts")


def test_the_section_markers_give_the_kinds_of_the_rules_after_them():
    rules = parse_abp(EASYPRIVACY, "tracking", "EasyPrivacy")
    assert kinds(rules) == {
        "before-any-marker.example": "tracking",  # before any marker: the list's own kind
        "general.example": "tracking",  # a section no marker names: the list's own kind
        "tracker.example": "tracking", "metrics.tracker2.example": "tracking", "collect.example": "tracking",
        "also-mining.example": "cryptomining",  # in a tracking section and in the miners': the miners' kind
        "coin-miner.example": "cryptomining",  # then in the email trackers': the first section's own kind stays
        "mailopen.example": "email",
        "smetrics.brand.example": "cname-tracker",
        "push.example": "tracking",  # the push servers are tracking servers
    }
    # the same markers in a list of another kind: a section they do not name keeps that list's kind
    assert kinds(parse_abp(EASYPRIVACY, "social"))["general.example"] == "social"
    assert kinds(parse_abp(EASYPRIVACY, "social"))["tracker.example"] == "tracking"


@pytest.mark.parametrize("marker, kind", [
    ("easylist:easyprivacy/easyprivacy_trackingservers.txt", "tracking"),
    ("easylist:easyprivacy/easyprivacy_trackingservers_thirdparty.txt", "tracking"),
    ("easylist:easyprivacy/easyprivacy_trackingservers_mining.txt", "cryptomining"),
    ("easylist:easyprivacy\\easyprivacy_trackingservers_mining.txt", "cryptomining"),
    ("easylist:easyprivacy/easyprivacy_general_emailtrackers.txt", "email"),
    ("easylist:easyprivacy/easyprivacy_specific_cname_criteo.txt", "cname-tracker"),
    ("easylist:easylist/easylist_adservers.txt", "ads"),
    ("easylist:easylist/easylist_adservers_popup.txt", "ads"),
    ("EASYLIST:EASYPRIVACY/EASYPRIVACY_TRACKINGSERVERS_MINING.TXT", "cryptomining"),
    ("easylist:easyprivacy/easyprivacy_general.txt", "analytics"),  # no section of its own: the default
    ("easylist:easylist/easylist_specific_block.txt", "analytics"),
])
def test_a_markers_file_names_its_sections_kind(marker, kind):
    assert section_kind(marker, "analytics") == kind


def test_a_hosts_list_gives_its_names_never_a_hosts_files_own():
    rules = parse_hosts(HOSTS, "telemetry", "a hosts list")
    assert kinds(rules) == {"telemetry.vendor.example": "telemetry", "a.tracker.example": "telemetry",
                            "b.tracker.example": "telemetry", "tabbed.example": "telemetry",
                            "v6-blocked.example": "telemetry", "lonely.example": "telemetry"}
    assert {r.source for r in rules.values()} == {"a hosts list"}
    assert len(parse_hosts(HOSTS, "ads", limit=2)) == 2
    with pytest.raises(ValueError):
        parse_hosts(HOSTS, "nonsense")


def test_a_domain_list_gives_plain_names_wildcards_and_addresses_without_its_comments():
    rules = parse_domains(DOMAINS, "telemetry", "hagezi native.winoffice")
    assert kinds(rules) == {"events.data.vendor.example": "telemetry", "telemetry.vendor.example": "telemetry",
                            "wild-dot.vendor.example": "telemetry", "adblock-style.vendor.example": "telemetry",
                            "hosts-style.vendor.example": "telemetry", "plain.vendor.example": "telemetry",
                            "198.51.100.9": "telemetry", "upper.vendor.example": "telemetry"}
    assert parse_domains(DOMAINS.encode("utf-8"), "telemetry").keys() == rules.keys()
    assert parse_domains("*.пример.example\n", "ads").keys() == {IDN}


def test_adguard_companiesdb_gives_each_domain_its_company_and_its_trackers_category_as_a_kind():
    rules = parse_adguard_companies(json.dumps(TRACKERS), json.dumps(COMPANIES))
    seen = {name: (label.kind, label.company) for name, label in rules.items()}
    assert seen == {
        "adco.example": ("ads", "AdCo Inc."), "ads.adco.example": ("ads", "AdCo Inc."),
        "adnet.example": ("ads", "AdCo Inc."),
        "measure.example": ("analytics", "BigCo"), "sdk.appstats.example": ("analytics", "BigCo"),  # site and mobile
        "phonehome.example": ("telemetry", "DevCo"), "fastcdn.example": ("cdn", "FastCo"),
        "cloudhost.example": ("hosting", "CloudHost"),  # no company known: the tracker's name
        "likes.example": ("social", "SocialCo"), "talk.example": ("social", "TalkCo"),  # comment widgets are social
        "mailpixel.example": ("email", "MailCo"),
    }  # no label: essential, consent, a video player; a tracker the file does not hold; a domain that is no name
    assert {r.source for r in rules.values()} == {"AdGuard companiesdb"}
    assert rules["adco.example"] is rules["ads.adco.example"]  # one label for a tracker's domains

    alone = parse_adguard_companies(json.dumps(TRACKERS).encode("utf-8"))  # bytes, without companies.json
    assert alone["adco.example"] == Label("ads", "AdGuard companiesdb", "AdCo Exchange")
    assert alone.keys() == rules.keys()

    by_name = dict(TRACKERS, categories={name: int(i) for i, name in TRACKERS["categories"].items()})
    assert kinds(parse_adguard_companies(by_name)) == kinds(rules)  # categories written name -> id
    assert kinds(parse_adguard_companies({k: v for k, v in TRACKERS.items() if k != "categories"})) == kinds(rules)
    assert len(parse_adguard_companies(TRACKERS, limit=2)) == 2
    for wrong in ("[]", "{}", json.dumps({"trackers": {}}), "not json"):
        with pytest.raises(ValueError):
            parse_adguard_companies(wrong)


# -- the classifier ---------------------------------------------------------------------------------------------

def test_a_name_is_matched_by_its_own_labels_and_its_parents_one_label_of_each_kind():
    c = Classifier()
    c.add(parse_abp("||example.test^\n||ads.example.test^", "ads", "EasyList"))
    c.add(parse_domains("example.test", "telemetry", "hagezi"))
    c.add(parse_abp("||ads.example.test^\n||example.test^", "tracking", "EasyPrivacy"))
    c.add(parse_domains("ads.example.test", "ads", "another list"))  # ads.example.test has an ads label: the first's
    labels = c.classify("WWW.Ads.Example.Test.")
    assert [(l.kind, l.source) for l in labels] == [("ads", "EasyList"), ("tracking", "EasyPrivacy"),
                                                     ("telemetry", "hagezi")]
    assert [l.kind for l in c.classify("example.test")] == ["ads", "telemetry", "tracking"]
    for other in ("notexample.test", "example.test.other.invalid", "test", "", None, "example.test:443", "a" * 300,
                  ".".join(["a"] * 130) + ".example.test", "bad name.example.test"):
        assert c.classify(other) == [], other
    assert len(c) == 2


def test_an_address_is_matched_as_itself_only():
    c = Classifier()
    c.add(parse_domains("198.51.100.9\n2001:db8::9\n", "telemetry", "addresses"))
    assert [l.kind for l in c.classify("198.51.100.9")] == ["telemetry"]
    assert [l.kind for l in c.classify("::ffff:198.51.100.9")] == ["telemetry"]  # IPv4 written as IPv6
    assert [l.kind for l in c.classify("2001:0db8:0:0::9")] == ["telemetry"]
    assert c.classify("198.51.100.10") == [] and c.classify("51.100.9") == [] and c.classify("100.9") == []


def test_a_name_is_looked_up_in_the_form_dns_carries_it():
    c = Classifier()
    c.add(parse_domains("пример.example", "ads", "a list"))
    assert [l.kind for l in c.classify(IDN)] == ["ads"]
    assert [l.kind for l in c.classify("www.пример.example")] == ["ads"]
    assert [l.kind for l in c.classify("WWW." + IDN.upper())] == ["ads"]


def test_a_peer_known_by_several_names_has_each_names_labels():
    c = Classifier()
    c.add(parse_abp("||tracker.test^", "tracking", "EasyPrivacy"))
    c.add(parse_abp("! *** easylist:easyprivacy/easyprivacy_specific_cname_adobe.txt ***\n||smetrics.brand.test^",
                    "tracking", "EasyPrivacy"))
    c.add(parse_domains("brand.test", "analytics", "a list"))
    chain = ["shop.brand.test", "smetrics.brand.test", "brand.tracker.test"]  # a CNAME chain, the asked name first
    assert [l.kind for l in c.classify_names(chain)] == ["analytics", "cname-tracker", "tracking"]
    assert c.classify_names([]) == [] and c.classify_names(None) == []
    many = [f"n{i}.other.test" for i in range(classify.MAX_NAMES)] + ["x.tracker.test"]
    assert c.classify_names(many) == []  # at most MAX_NAMES names are looked up


def test_the_names_kept_are_capped():
    c = Classifier(max_rules=3)
    assert c.add(parse_domains("a.test\nb.test\nc.test\nd.test\ne.test", "ads", "one")) == 3
    assert len(c) == 3 and c.capped == 2 and c.classify("d.test") == []
    assert c.add(parse_domains("a.test", "telemetry", "two")) == 1  # a name kept takes a label of another kind
    assert [l.kind for l in c.classify("a.test")] == ["ads", "telemetry"]
    assert c.describe()["names"] == 3 and c.describe()["capped"] == 2


# -- the folder ---------------------------------------------------------------------------------------------------

def write_lists(folder: Path) -> list:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "easylist.txt").write_text(EASYLIST, encoding="utf-8")
    (folder / "easyprivacy.txt").write_text(EASYPRIVACY, encoding="utf-8")
    (folder / "hosts.txt").write_text(HOSTS, encoding="utf-8")
    (folder / "native.winoffice.txt").write_text(DOMAINS, encoding="utf-8")
    (folder / "trackers.json").write_text(json.dumps(TRACKERS), encoding="utf-8")
    (folder / "trackers.companies.json").write_text(json.dumps(COMPANIES), encoding="utf-8")
    manifest = [
        {"file": "easylist.txt", "format": "abp", "kind": "ads", "source": "EasyList"},
        {"file": "easyprivacy.txt", "format": "abp", "kind": "tracking", "source": "EasyPrivacy"},
        {"file": "hosts.txt", "format": "hosts", "kind": "telemetry", "source": "a hosts list"},
        {"file": "native.winoffice.txt", "format": "wildcard", "kind": "telemetry", "source": "hagezi"},
        {"file": "trackers.json", "format": "adguard_companies", "source": "AdGuard companiesdb",
         "companies": "trackers.companies.json"},
        {"file": "missing.txt", "format": "domains", "kind": "ads", "source": "not here"},
        {"file": "odd.txt", "format": "csv", "kind": "ads"},
        {"file": "../outside.txt", "format": "domains", "kind": "ads"},
        {"file": "easylist.txt", "format": "abp", "kind": "adverts"},
        "not an entry",
    ]
    (folder / "lists.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def test_the_lists_are_read_from_their_folder_by_the_manifest_the_first_lists_label_first(tmp_path):
    folder = tmp_path / "lists"
    write_lists(folder)
    c = Classifier.from_folder(folder)
    assert c.classify("ads.example") == [Label("ads", "EasyList")]
    assert c.classify("adnet.example") == [Label("ads", "EasyList")]  # EasyList before companiesdb
    assert c.classify("x.coin-miner.example") == [Label("cryptomining", "EasyPrivacy")]
    assert c.classify("telemetry.vendor.example") == [Label("telemetry", "a hosts list")]  # before hagezi's
    assert c.classify("v10.events.data.vendor.example") == [Label("telemetry", "hagezi")]
    assert c.classify("ads.adco.example") == [Label("ads", "AdGuard companiesdb", "AdCo Inc.")]
    assert c.classify("fastcdn.example") == [Label("cdn", "AdGuard companiesdb", "FastCo")]
    d = c.describe()
    assert d["folder"] == str(folder) and d["error"] is None and d["names"] == len(c)
    easylist, easyprivacy, hosts, hagezi, companiesdb, missing, odd, outside, adverts, no_entry = d["lists"]
    assert easylist["names"] == 7 and easylist["error"] is None and easylist["source"] == "EasyList"
    assert easylist["size"] == (folder / "easylist.txt").stat().st_size
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00", easylist["modified"])
    assert easyprivacy["names"] == 10 and hosts["names"] == 6 and hagezi["names"] == 8
    assert hagezi["format"] == "domains"  # "wildcard" is a domain list
    assert companiesdb["names"] == 11 and companiesdb["note"] is None and companiesdb["kind"] is None
    assert missing["error"] == "not downloaded yet (missing.txt)"
    assert "no list format" in odd["error"]
    assert "not in the lists' folder" in outside["error"]
    assert "no kind of label" in adverts["error"] and "no object" in no_entry["error"]
    assert len(c) == 7 + 10 + 6 + 8 + 11 - 2  # adnet.example and telemetry.vendor.example are in two lists each


def test_no_manifest_is_no_lists_and_one_that_cannot_be_read_says_so(tmp_path, monkeypatch):
    monkeypatch.setenv("LIMINAL_HOME", str(tmp_path))
    assert classify.lists_dir() == tmp_path / "store" / "data" / "lists"
    c = Classifier.from_folder()  # the data folder's lists/, not made yet
    assert len(c) == 0 and c.lists == [] and c.error is None and c.folder == classify.lists_dir()
    folder = tmp_path / "broken"
    folder.mkdir()
    (folder / "lists.json").write_text("{not json", encoding="utf-8")
    broken = Classifier.from_folder(folder)
    assert len(broken) == 0 and broken.error.startswith("lists.json could not be read")
    (folder / "lists.json").write_text(json.dumps({"lists": [{"file": "a.txt", "format": "domains",
                                                              "kind": "ads"}]}), encoding="utf-8")
    (folder / "a.txt").write_text("a.example\n", encoding="utf-8")
    assert [l.kind for l in Classifier.from_folder(folder).classify("a.example")] == ["ads"]  # {"lists": [...]}
    (folder / "lists.json").write_text(json.dumps({"lists": "no"}), encoding="utf-8")
    assert "not a list of the lists" in Classifier.from_folder(folder).error


def test_without_its_company_names_companiesdb_names_the_trackers(tmp_path):
    folder = tmp_path / "lists"
    folder.mkdir()
    (folder / "trackers.json").write_text(json.dumps(TRACKERS), encoding="utf-8")
    (folder / "lists.json").write_text(json.dumps([{"file": "trackers.json", "format": "companiesdb",
                                                    "companies": "gone.json"}]), encoding="utf-8")
    c = Classifier.from_folder(folder)
    assert c.classify("adco.example") == [Label("ads", "trackers", "AdCo Exchange")]  # no source named: the file's
    assert "company names not read" in c.lists[0]["note"] and c.lists[0]["error"] is None
    (folder / "gone.json").write_text("[]", encoding="utf-8")
    assert "no company names" in Classifier.from_folder(folder).lists[0]["note"]


def test_a_file_bigger_than_a_list_is_not_read(tmp_path, monkeypatch):
    folder = tmp_path / "lists"
    write_lists(folder)
    monkeypatch.setattr(classify, "MAX_FILE", (folder / "hosts.txt").stat().st_size)
    c = Classifier.from_folder(folder)
    assert "more than a list is read" in c.lists[0]["error"] and c.classify("ads.example") == []
    assert c.classify("lonely.example") == [Label("telemetry", "a hosts list")]  # the small ones are read
    with pytest.raises(ValueError, match="more than a list is read"):
        install_list(EASYLIST, folder, "easylist.txt", "abp", "ads", "EasyList")
    assert (folder / "easylist.txt").read_text(encoding="utf-8") == EASYLIST  # nothing changed


def test_a_list_is_kept_one_copy_and_named_in_the_manifest_in_its_place(tmp_path):
    folder = tmp_path / "lists"
    path = install_list(EASYLIST.encode("utf-8"), folder, "easylist.txt", "abp", "ads", "EasyList",
                        licence="GPLv3 or CC BY-SA 3.0")
    assert path == folder / "easylist.txt" and path.read_bytes() == EASYLIST.encode("utf-8")
    install_list(DOMAINS, folder, "native.winoffice.txt", "wildcard", "telemetry", "hagezi")
    entries = read_manifest(folder)
    assert [e["file"] for e in entries] == ["easylist.txt", "native.winoffice.txt"]
    assert entries[0]["format"] == "abp" and entries[0]["licence"] == "GPLv3 or CC BY-SA 3.0"
    assert entries[1]["format"] == "domains" and entries[1]["kind"] == "telemetry" and entries[1]["installed"]

    install_list("||newer.example^\n", folder, "easylist.txt", "abp", "ads", "EasyList")  # again: replaced, in place
    assert [e["file"] for e in read_manifest(folder)] == ["easylist.txt", "native.winoffice.txt"]
    assert (folder / "easylist.txt").read_text(encoding="utf-8") == "||newer.example^\n"
    assert sorted(p.name for p in folder.iterdir()) == ["easylist.txt", "lists.json", "native.winoffice.txt"]

    before = (folder / "lists.json").read_bytes()
    refused = [
        ("<html>a page, not a list</html>", "easylist.txt", "abp", "ads"),  # nothing read from it
        ("a.example", "../a.txt", "domains", "ads"), ("a.example", "sub/a.txt", "domains", "ads"),
        ("a.example", "lists.json", "domains", "ads"), ("a.example", "a.txt", "domains", "adverts"),
        ("a.example", "a.txt", "csv", "ads"), ("a.example", "", "domains", "ads"),
    ]
    for data, file, fmt, kind in refused:
        with pytest.raises(ValueError):
            install_list(data, folder, file, fmt, kind)
    assert (folder / "lists.json").read_bytes() == before
    assert sorted(p.name for p in folder.iterdir()) == ["easylist.txt", "lists.json", "native.winoffice.txt"]

    c = Classifier.from_folder(folder)
    assert c.classify("newer.example") == [Label("ads", "EasyList")]
    assert c.classify("x.telemetry.vendor.example") == [Label("telemetry", "hagezi")]

    (folder / "lists.json").write_text("{broken", encoding="utf-8")  # a manifest that cannot be read starts again
    install_list(DOMAINS, folder, "native.winoffice.txt", "domains", "telemetry", "hagezi")
    assert [e["file"] for e in read_manifest(folder)] == ["native.winoffice.txt"]


def test_companiesdb_is_kept_with_its_company_names_beside_it(tmp_path):
    folder = tmp_path / "lists"
    install_list(json.dumps(TRACKERS), folder, "companiesdb.json", "adguard_companies", source="AdGuard companiesdb",
                 companies=json.dumps(COMPANIES).encode("utf-8"))
    entry = read_manifest(folder)[0]
    assert entry["companies"] == "companiesdb.companies.json" and entry["kind"] is None
    assert json.loads((folder / "companiesdb.companies.json").read_text(encoding="utf-8")) == COMPANIES
    assert Classifier.from_folder(folder).classify("adco.example")[0].company == "AdCo Inc."

    install_list(json.dumps(TRACKERS), folder, "companiesdb.json", "adguard_companies", source="AdGuard companiesdb")
    assert read_manifest(folder)[0]["companies"] == "companiesdb.companies.json"  # installed again: the names stay
    assert Classifier.from_folder(folder).classify("adco.example")[0].company == "AdCo Inc."

    for names in (b"{}", b"not json", "[]"):
        with pytest.raises(ValueError, match="company names"):
            install_list(json.dumps(TRACKERS), folder, "companiesdb.json", "adguard_companies", companies=names)
    with pytest.raises(ValueError, match="companiesdb"):  # company names go with companiesdb only
        install_list(EASYLIST, folder, "easylist.txt", "abp", "ads", companies=json.dumps(COMPANIES))
    assert sorted(p.name for p in folder.iterdir()) == ["companiesdb.companies.json", "companiesdb.json", "lists.json"]


def test_a_label_says_its_kind_in_plain_words():
    label = Label("cname-tracker", "EasyPrivacy")
    assert label.as_dict() == {"kind": "cname-tracker", "source": "EasyPrivacy", "company": None,
                               "words": "tracks from behind a site's own name (a CNAME)"}
    assert set(classify.KINDS) == {"ads", "tracking", "analytics", "telemetry", "cryptomining", "email",
                                   "cname-tracker", "social", "cdn", "hosting"}
    assert set(classify.ADGUARD_KINDS.values()) <= set(classify.KINDS)
    assert {kind for _, kind in classify.SECTIONS} <= set(classify.KINDS)


def test_the_module_names_no_outside_host():
    source = Path(classify.__file__).read_text(encoding="utf-8")
    assert not re.search(r"\b(?:https?|wss?)://", source)


# -- hostile lists: what a list costs is its length --------------------------------------------------------------

def quick(call, within: float = 1.0):
    """`call`'s result, which must take less than `within` seconds: a hostile list costs its length, never its
    length squared or cubed. The old readers took seconds to hours on these inputs; the fixed ones take milliseconds,
    so the bound is generous for a slow CI machine."""
    start = time.perf_counter()
    out = call()
    took = time.perf_counter() - start
    assert took < within, f"took {took:.2f} s"
    return out


def cjk(n: int, offset: int = 0) -> str:
    """`n` distinct CJK characters: what makes the idna codec's work grow with a name's length times its distinct
    characters."""
    return "".join(chr(0x4E00 + (offset + i) % 20000) for i in range(n))


def test_a_comment_line_full_of_blanks_costs_its_length_alone():
    # "!***" then blanks no "***" closes: the old section-marker expression tried every split of the run before it
    # gave up (2,400 blanks took some 10 s, 3,200 some 30 s), the whole list's reading held there
    for blank in (" ", "\t"):
        text = "!***" + blank * 2400 + "a\n||after.example^\n"
        assert quick(lambda: parse_abp(text, "ads")) == {"after.example": Label("ads", "adblock list")}
    many = ("!***" + " " * 400 + "a\n") * 1000 + "||after.example^\n"  # many short ones add up as well (old: ~50 s)
    assert quick(lambda: parse_abp(many, "ads")).keys() == {"after.example"}
    # a marker still names its section, blanks and all, and a comment that only looks like one changes nothing
    text = ("!   ***   easylist:easyprivacy/easyprivacy_trackingservers_mining.txt   ***\n||miner.example^\n"
            "! *** not closed\n||still-miner.example^\n!*******\n||default.example^\n"
            "! ***easylist:easylist/easylist_adservers.txt***\n||ad.example^\n")
    assert kinds(parse_abp(text, "tracking")) == {"miner.example": "cryptomining", "default.example": "tracking",
                                                   "still-miner.example": "cryptomining", "ad.example": "ads"}
    assert classify._marker("! *** a.txt ***") == "a.txt" and classify._marker("!******") is None


def test_a_badfilter_rule_full_of_blanks_costs_its_length_alone():
    # blanks after a badfilter rule, the line not ending there: the old badfilter expression scanned the run again at
    # each of its characters (40,000 blanks took some 7 s, a megabyte an hour), over the whole list
    for blank in (" ", "\t"):
        text = "||a.example^$badfilter" + blank * 40_000 + "x\n||b.example^\n"
        assert quick(lambda: parse_abp(text, "ads")).keys() == {"b.example"}
    text = "||a.example^$" + "badfilter" * 3000 + " " * 30_000 + "x\ry\n||b.example^\n"
    assert "b.example" in quick(lambda: parse_abp(text, "ads"))
    # what a badfilter turns off is still turned off: its own options, in any case, blanks around them
    text = ("||off.example^$third-party\n||off.example^$third-party, BadFilter \n||on.example^$script\n"
            "||on.example^$third-party,badfilter\n||plain.example^\n  ||plain.example^$badfilter\r\n")
    assert parse_abp(text, "ads").keys() == {"on.example"}
    assert classify._badfilters("||x.example^$domain=badfilter.example\n") == set()  # a word, not the option


def test_the_rules_a_list_turns_off_are_capped(monkeypatch):
    monkeypatch.setattr(classify, "MAX_BADFILTERS", 3)
    text = "".join(f"||n{i}.example^$badfilter\n" for i in range(10))
    assert len(classify._badfilters(text)) == 3  # the old set held every one a list gave


def test_a_long_name_in_unicode_is_measured_before_it_is_encoded():
    # one token of 8,000 distinct CJK characters: the old reader encoded it (idna's nameprep and punycode cost its
    # length times its distinct characters: some 4 s a token) before it found it too long for a name
    token = cjk(8000) + ".example"
    assert quick(lambda: classify._rule_name(token)) == ""
    for parse, text in ((parse_domains, token + "\n"), (parse_hosts, "0.0.0.0 " + token + "\n"),
                        (parse_abp, "||" + token + "^\n")):
        assert quick(lambda: parse(text, "ads")) == {}
    trackers = {"trackerDomains": {token: "adco", "ads.adco.example": "adco"}, "trackers": TRACKERS["trackers"]}
    assert quick(lambda: parse_adguard_companies(json.dumps(trackers))).keys() == {"ads.adco.example"}
    assert classify._rule_name(cjk(64) + ".example") == ""  # a label longer than DNS allows
    assert classify._rule_name("пример.example") == IDN  # a name DNS can carry still is
    assert classify._rule_name(" " * 5000 + "a.example") == ""  # a token longer than any name, blanks and all


def test_a_list_encodes_at_most_max_idn_names_in_unicode(monkeypatch):
    encoded = []
    real = classify._ascii
    monkeypatch.setattr(classify, "_ascii", lambda name: encoded.append(name) or real(name))
    monkeypatch.setattr(classify, "MAX_IDN", 5)
    text = "".join(f"пример{i}.example\n" for i in range(20)) + "plain.example\n"
    rules = parse_domains(text, "ads")
    assert len(encoded) == 5 and len(rules) == 6 and "plain.example" in rules  # the plain names are all read
    encoded.clear()
    parse_hosts("".join(f"0.0.0.0 пример{i}.example\n" for i in range(20)), "ads")
    assert len(encoded) == 5  # each list its own count
    encoded.clear()
    c = Classifier()
    c.add(rules)
    assert [bool(c.classify(f"пример{i}.example")) for i in range(10)] == [True] * 5 + [False] * 5
    assert len(encoded) == 10  # a lookup is no list's reading: never counted


def test_a_list_made_of_costly_names_in_unicode_is_read_fast(monkeypatch):
    monkeypatch.setattr(classify, "MAX_IDN", 100)
    # names within DNS's lengths, twelve labels the idna codec takes (some 0.7 ms each): past MAX_IDN they are skipped
    names = [".".join(cjk(20, 37 * (k * 12 + j)) for j in range(12)) for k in range(3000)]
    assert quick(lambda: parse_domains("\n".join(names), "ads"), within=2.0) == {}


FDFA = "\ufdfa"  # an Arabic ligature that nameprep makes 18 characters, right to left from its first to its last
# The skeptic's costliest label (2026-11-15): 63 characters, most of them U+FDFA, the others ones nameprep lengthens
# too, right to left from end to end so the codec's bidi check holds and its punycode is reached: 793 characters once
# mapped, some 4 ms a name through the codec
SKEPTIC = "".join(chr(int(h, 16)) for h in (
    "FDFA FDFA FDFA FDFA FDFA FDF3 FDFA 0F77 FDFA FB2C FDFA FCF2 FD51 FDFA FDFA FDFA FDFA FDFA 0385 FDFA 1FCD FDFA "
    "1FDF FD6A FDFA FDF1 FDFA FDFA 0677 FDFA 0F93 0FB9 FDFA 2ADC FDFA FB1D FDFA FB1F FDFA FB2F FB4B FDFA FB4C FDFA "
    "FBEC FDFA FC5B FC77 FDFA FDFA FDFA FDFA FDFA FDFA FDFA FDFA FDFA FDFA FDFA FDFA FDFA FDFA FDFA").split())


def rtl(n: int) -> str:
    """`n` distinct right-to-left letters, Hebrew's then Arabic's (63 at most): a label of them keeps the codec's bidi
    check, so its punycode is reached."""
    letters = "".join(chr(c) for c in (*range(0x5D0, 0x5EB), *range(0x621, 0x63B), *range(0x641, 0x64B)))
    assert n <= len(letters)
    return letters[:n]


def test_a_label_is_measured_as_nameprep_maps_it_before_the_codec_is_handed_it():
    # nameprep lengthens a label before its punycode (U+FDFA becomes 18 characters, ᾳ two once case folded): the old
    # reader measured a label before it, so 63 characters reached punycode as up to 1,134
    assert len(classify._mapped(FDFA * 63)) == 1134 and len(classify._mapped(SKEPTIC)) == 793
    assert len(classify._mapped("\u1fb3" * 63)) == 126
    for label in (FDFA * 63, SKEPTIC, FDFA * 4, FDFA + rtl(46), "\u1fb3" * 32):
        assert len(label) <= classify.MAX_LABEL < len(classify._mapped(label)), label
        assert classify._rule_name(label + ".example") == ""
    assert classify._rule_name(".".join([FDFA] * 14)) == ""  # each label 18 characters once mapped: 265 in all
    # character by character, the measure is never shorter than what the codec makes of a label (each character of the
    # blocks it maps most); only rare letter-and-mark pairs compose in the measure and not in the codec (see _mapped)
    for c in map(chr, (*range(0xA0, 0x250), *range(0x1F00, 0x2000), *range(0x2100, 0x2500), *range(0x3300, 0x3400),
                       *range(0xFB00, 0xFE00), *range(0xFE70, 0xFFF0), *classify._NOTHING)):
        codec = "".join(stringprep.map_table_b2(x) for x in c.lower() if not stringprep.in_table_b1(x))
        assert len(classify._mapped(c.lower())) >= len(ucd_3_2_0.normalize("NFKC", codec)), hex(ord(c))
    assert set(classify._NOTHING) == {cp for cp in range(0x10000) if stringprep.in_table_b1(chr(cp))}
    # what nameprep maps to nothing is not counted, and a label longer than DNS allows only before it is mapped (one
    # written decomposed) is a name DNS carries, as it is mapped
    assert classify._rule_name("bücher" + "\u00ad" * 60 + ".example") == "xn--bcher-kva.example"
    decomposed = "e\u0301" * 30 + "abcd.example"
    assert len(decomposed.split(".")[0]) > classify.MAX_LABEL
    assert classify._rule_name(decomposed) == ("\u00e9" * 30 + "abcd.example").encode("idna").decode("ascii")
    assert classify._rule_name(cjk(63) + ".example") == ""  # 63 once mapped: the codec's to refuse (its punycode)


def test_lists_of_the_costliest_names_in_unicode_are_read_fast_at_the_real_max_idn(tmp_path):
    # the skeptic's lists (2026-11-15), MAX_IDN names and a thousand more: its label alone, and three labels the codec
    # takes (fullwidth letters) before it. Through the codec they cost some 4 ms a name: 8 s a list at the old MAX_IDN
    # of 2,048, 24 s for three lists. Measured once mapped, they are refused before the codec
    n = classify.MAX_IDN + 1000
    full = "\uff41" * 63
    names = [f"x{i}.{SKEPTIC}.example" if i % 2 else f"x{i}{full[len(str(i)) + 1:]}.{full}.{full}.{SKEPTIC[:60]}{FDFA}"
             for i in range(n)]
    assert all(len(name) <= classify.MAX_NAME for name in names)
    text = "\n".join(names) + "\nplain.example\n"
    assert quick(lambda: parse_domains(text, "ads")).keys() == {"plain.example"}
    folder = tmp_path / "lists"
    for k in range(3):
        install_list(text, folder, f"vendor{k}.txt", "domains", "telemetry", f"vendor {k}")
    c = quick(lambda: Classifier.from_folder(folder))
    assert len(c) == 1 and [info["names"] for info in c.lists] == [1, 1, 1]
    # the costliest names still handed to the codec: four labels it takes (41 distinct katakana each), then one it
    # refuses only once its punycode is done (U+FDFA and 45 right-to-left letters, 63 characters once mapped, right
    # to left from end to end): some 1 ms a name here, MAX_IDN of them a list
    takes = "".join(chr(0x30A1 + i) for i in range(41))
    assert classify._rule_name(takes + ".example").startswith("xn--")
    last = FDFA + rtl(45)
    assert len(classify._mapped(last)) == classify.MAX_LABEL and classify._rule_name(last + ".example") == ""
    names = [".".join([f"x{i}", takes, takes, takes, takes, last]) for i in range(n)]
    text = "\n".join(names) + "\nplain.example\n"
    assert quick(lambda: parse_domains(text, "ads"), within=3.0).keys() == {"plain.example"}


def test_a_name_idna_2003_would_put_in_another_form_than_browsers_is_left_out():
    # Python's idna codec (IDNA 2003) maps ß to ss, ς to σ and the zero-width joiners to nothing; browsers (IDNA 2008)
    # keep them: the rule for faß.example is for xn--fa-hia.example, never for fass.example, another domain
    zwj = chr(0x200D)
    rules = parse_domains(f"faß.example\nSTRAẞE.example\nοδος.example\na{zwj}b.example\nbücher.example\n", "ads")
    assert rules.keys() == {"xn--bcher-kva.example"}
    c = Classifier()
    c.add(rules)
    assert c.classify("fass.example") == [] and c.classify("strasse.example") == [] and c.classify("ab.example") == []


DEEP = "[" * 100_000 + "]" * 100_000  # nested past what the JSON parser's stack allows


def test_json_nested_too_deeply_is_refused_as_any_other_bad_file(tmp_path):
    deep_trackers = '{"trackerDomains": {"a.example": "t"}, "categories": ' + DEEP + "}"
    with pytest.raises(ValueError, match="nested too deeply"):  # the old parser's RecursionError, no ValueError
        parse_adguard_companies(deep_trackers)
    assert classify._company_names(DEEP) == {}
    folder = tmp_path / "lists"
    with pytest.raises(ValueError, match="nested too deeply"):
        install_list(deep_trackers, folder, "trackers.json", "adguard_companies")
    with pytest.raises(ValueError, match="company names"):
        install_list(json.dumps(TRACKERS), folder, "trackers.json", "adguard_companies", companies=DEEP)
    assert not folder.exists()  # refused: nothing changed

    folder.mkdir()
    (folder / "easylist.txt").write_text("||ads.example^\n", encoding="utf-8")
    (folder / "deep.json").write_text(deep_trackers, encoding="utf-8")
    (folder / "good.json").write_text(json.dumps(TRACKERS), encoding="utf-8")
    (folder / "good.companies.json").write_text(DEEP, encoding="utf-8")
    (folder / "lists.json").write_text(json.dumps([
        {"file": "easylist.txt", "format": "abp", "kind": "ads", "source": "EasyList"},
        {"file": "deep.json", "format": "adguard_companies"},
        {"file": "good.json", "format": "adguard_companies", "companies": "good.companies.json"}]), encoding="utf-8")
    c = Classifier.from_folder(folder)  # the deep files say so; the other lists load
    easylist, deep, good = c.lists
    assert c.classify("ads.example") == [Label("ads", "EasyList")] and easylist["error"] is None
    assert "nested too deeply" in deep["error"] and deep["names"] == 0
    assert good["error"] is None and "no company names" in good["note"]
    assert c.classify("adco.example") == [Label("ads", "good", "AdCo Exchange")]

    (folder / "lists.json").write_text(DEEP, encoding="utf-8")  # the manifest itself
    broken = Classifier.from_folder(folder)
    assert "nested too deeply" in broken.error and len(broken) == 0
    with pytest.raises(ValueError, match="nested too deeply"):
        read_manifest(folder)
    install_list("||ads.example^\n", folder, "easylist.txt", "abp", "ads")  # a manifest that cannot be read: anew
    assert [e["file"] for e in read_manifest(folder)] == ["easylist.txt"]
    nested = "[" * 500 + "]" * 500  # deep, yet within what the parser reads
    (folder / "lists.json").write_text(f'[{{"file": {nested}, "format": {nested}, "kind": {{"a": 1}}}}, '
                                       f'{{"file": "a.txt", "format": {nested}}}, "{"x" * 5000}"]', encoding="utf-8")
    no_file, no_format, no_entry = Classifier.from_folder(folder).lists  # shown in short, as words or nothing
    assert no_file["file"] is None and no_file["format"] is None and no_file["kind"] is None
    assert "no file" in no_file["error"] and "no list format" in no_format["error"] and no_format["file"] == "a.txt"
    assert len(no_format["error"]) < 200 and len(no_entry["error"]) < 200


def test_a_list_bigger_than_its_format_is_read_is_refused(tmp_path):
    # the old cap was 32 MB for every format: a text list some 4 times that in RAM while it was read, a JSON some 8
    folder = tmp_path / "lists"
    big = "||ads.example^\n" + "!" * (9 * 2**20)
    with pytest.raises(ValueError, match="more than a list is read"):
        install_list(big, folder, "easylist.txt", "abp", "ads")
    trackers = json.dumps(dict(TRACKERS, padding="x" * (5 * 2**20)))
    with pytest.raises(ValueError, match="more than a list is read"):
        install_list(trackers, folder, "trackers.json", "adguard_companies")
    with pytest.raises(ValueError, match="more than a list is read"):
        install_list(json.dumps(TRACKERS), folder, "trackers.json", "adguard_companies", companies=trackers)
    assert not folder.exists()

    folder.mkdir()
    (folder / "easylist.txt").write_text(big, encoding="utf-8")
    (folder / "trackers.json").write_text(trackers, encoding="utf-8")
    (folder / "small.json").write_text(json.dumps(TRACKERS), encoding="utf-8")
    (folder / "small.companies.json").write_text(trackers, encoding="utf-8")
    (folder / "hosts.txt").write_text(HOSTS, encoding="utf-8")
    (folder / "lists.json").write_text(json.dumps([
        {"file": "easylist.txt", "format": "abp", "kind": "ads"}, {"file": "trackers.json", "format": "companiesdb"},
        {"file": "small.json", "format": "companiesdb", "companies": "small.companies.json"},
        {"file": "hosts.txt", "format": "hosts", "kind": "telemetry"}]), encoding="utf-8")
    easylist, companiesdb, small, hosts = Classifier.from_folder(folder).lists
    assert "more than a list is read" in easylist["error"] and "more than a list is read" in companiesdb["error"]
    assert small["error"] is None and "company names not read" in small["note"] and hosts["names"] == 6


def test_a_line_longer_than_any_lists_is_skipped_without_being_split():
    # one hosts line of 200,000 names (some 3 MB): the old readers split it into all its fields at once (a 32 MB
    # line cost half a gigabyte); no list's line is that long, so it is skipped, measured before it is copied
    text = "0.0.0.0 " + " ".join(f"n{i:x}.example" for i in range(200_000)) + "\nkept.example\n"
    for parse, given in ((parse_hosts, text), (parse_domains, text),
                         (parse_abp, text.replace("kept.example", "||kept.example^"))):
        tracemalloc.start()
        try:
            rules = parse(given, "ads")
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        assert rules.keys() == {"kept.example"}, parse.__name__
        assert peak < 2**20, (parse.__name__, peak)
    line = "0.0.0.0 " + " ".join(f"n{i}.example" for i in range(3000))  # a long line within MAX_LINE is read
    assert len(parse_hosts(line, "ads")) == 3000 and len(parse_hosts(line, "ads", limit=7)) == 7


def test_a_list_reaching_its_limit_is_read_no_further(monkeypatch):
    read = []
    real = classify._name
    monkeypatch.setattr(classify, "_name", lambda *a, **k: read.append(a[0]) or real(*a, **k))
    text = "".join(f"n{i}.example\n" for i in range(1000))
    assert len(parse_domains(text, "ads", limit=10)) == 10 and len(read) == 10
    read.clear()
    assert len(parse_hosts("0.0.0.0 " + text.replace("\n", " "), "ads", limit=10)) == 10 and len(read) == 10
    read.clear()
    trackers = {"trackerDomains": {f"n{i}.example": "adco" for i in range(1000)}, "trackers": TRACKERS["trackers"]}
    assert len(parse_adguard_companies(trackers, limit=10)) == 10 and len(read) == 10


def test_a_lists_file_name_never_folds_onto_another_file(tmp_path):
    # Windows folds a name's case and drops its trailing dots and blanks: LISTS.JSON and "lists.json." are the
    # manifest there, so a list is kept under a plain name, lowercased, never another list's or its company names'
    folder = tmp_path / "lists"
    install_list(EASYLIST, folder, "EasyList.TXT", "abp", "ads", "EasyList")
    assert [e["file"] for e in read_manifest(folder)] == ["easylist.txt"] and (folder / "easylist.txt").is_file()
    install_list("||newer.example^\n", folder, "easylist.txt", "abp", "ads", "EasyList")  # the same list, in its place
    assert [e["file"] for e in read_manifest(folder)] == ["easylist.txt"]
    install_list(json.dumps(TRACKERS), folder, "trackers.json", "adguard_companies", companies=json.dumps(COMPANIES))
    install_list("a.example\n", folder, "x.companies.json", "domains", "ads")  # a list may have such a name
    before = sorted(p.name for p in folder.iterdir())
    manifest = (folder / "lists.json").read_bytes()
    for name in ("LISTS.JSON", "lists.json.", "Lists.Json", "easylist.txt.", "easylist.txt ..", "nul.txt", "CON",
                 "com1.txt", "LPT9", "a b.txt", "-a.txt", "a.txt.part", "a.PART", "sub/a.txt", "sub\a.txt", "..",
                 "x" * 200, "trackers.companies.json", "TRACKERS.Companies.json", "list" + chr(0xE9) + ".txt"):
        with pytest.raises(ValueError):
            install_list("a.example\n", folder, name, "domains", "ads")
    with pytest.raises(ValueError, match="another list is kept in it"):  # its company names in another list's file
        install_list(json.dumps(TRACKERS), folder, "x.json", "adguard_companies", companies=json.dumps(COMPANIES))
    assert sorted(p.name for p in folder.iterdir()) == before and (folder / "lists.json").read_bytes() == manifest
