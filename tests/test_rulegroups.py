"""A firewall's rules in groups (the user: "for both firewalls, i need to have groups, like system or application and then
unassociated rules not tied to a specific application or system process can be in an other, i can create labels, like
system or application, as well and move the rules in to that"): each rule's own group as its plugin finds it, the user's
labels and moves kept through the plugin's login (a stand-in's variables here: nothing written to this machine), and the
grouped table the platform draws with (+) and (−)."""
from __future__ import annotations

import json

import pytest

from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.machines.firewall import Firewall
from liminal_libs.machines.rulegroups import (AUTO_IDS, MAX_LABEL, Grouping, RuleGroups, Sorted, clean_label, key_of,
                                              keys_of)

VAR = "FIREWALL_TEST_GROUPS"


def store(env=None):
    login = EnvironmentLogin(env={} if env is None else env)
    return RuleGroups(VAR, lambda: login), login


def kept(login) -> dict:
    return json.loads(login.env[VAR])


A, B, C = key_of("a"), key_of("b"), key_of("c")
OWN = {A: Sorted("system", "the service Dnscache"), B: Sorted("application", r"C:\Games\server.exe"), C: Sorted("other", "a port alone")}


def test_a_rules_key_and_its_group():
    assert key_of("CoreNet-DNS-Out-UDP") == key_of("CoreNet-DNS-Out-UDP") and len(A) == 10 and A != B
    assert int(A, 16) >= 0
    with pytest.raises(ValueError, match="system, application or other"):
        Sorted("games")
    assert keys_of(f"{A}, {B} {A}") == [A, B] and keys_of([A.upper()]) == [A]
    with pytest.raises(ValueError, match="ten hex digits"):
        keys_of(["{GUID}"])


def test_labels_are_made_renamed_and_removed_through_the_login_alone():
    groups, login = store()
    assert groups.read().labels == [] and VAR not in login.env
    said = groups.new_label("  Games   room ")
    assert said["ok"] and "Games room" in said["said"] and said["lines"] == ["kept in the login's variables"]
    assert kept(login) == {"v": 1, "labels": ["Games room"], "moved": {}}
    for bad, words in (("", "needs a name"), ("system", "one of the groups"), ("Other", "one of the groups"), ("own", "one of the groups"),
                       ("games ROOM", "there is a label Games room"), ("x" * (MAX_LABEL + 1), "characters at most"), ("a\tb\x07", "control")):
        with pytest.raises(ValueError, match=words):
            groups.new_label(bad)
    groups.move([B], "label:games room", OWN)
    assert groups.rename_label("games room", "Games")["said"] == "the label Games room is Games now"
    assert kept(login) == {"v": 1, "labels": ["Games"], "moved": {"Games": [B]}}  # its rules follow it
    assert groups.rename_label("Games", "games")["ok"]  # its own name in another case
    with pytest.raises(LookupError):
        groups.rename_label("Nothing", "x")
    out = groups.remove_label("GAMES")
    assert out["said"] == "the label games removed: its 1 rule back in their own groups"
    assert VAR not in login.env  # nothing left to keep: the variable forgotten


def test_rules_are_moved_to_a_label_another_group_or_back_to_their_own():
    groups, login = store()
    groups.new_label("Office")
    assert groups.move([A, C], "Office", OWN)["said"] == "2 rules moved to Office"
    g = groups.read()
    assert g.group_of(A, "system") == "Office" and g.group_of(B, "application") == "application"
    assert groups.move(C, "application", OWN)["said"] == "1 rule moved to Application"
    assert groups.read().moved == {A: "Office", C: "application"}
    groups.move([A], "system", OWN)  # its own group: simply back there, nothing kept for it
    assert groups.read().moved == {C: "application"}
    gone = key_of("gone")
    said = groups.move([C, gone], "own", OWN)
    assert said["said"] == "1 rule moved to their own groups; 1 no longer read, left as they were" and groups.read().moved == {}
    with pytest.raises(LookupError, match="none of those rules is read now"):
        groups.move([gone], "Office", OWN)
    with pytest.raises(LookupError, match="no label"):
        groups.move([A], "Nowhere", OWN)
    with pytest.raises(ValueError, match="no rule chosen"):
        groups.move([], "Office", OWN)


def test_without_a_login_nothing_is_kept_and_a_bad_value_is_started_again():
    nobody = RuleGroups(VAR, lambda: None)
    assert nobody.read() == Grouping()
    with pytest.raises(ValueError, match="platform's login"):
        nobody.new_label("Games")
    groups, login = store({VAR: "{not json"})
    assert "could not be read" in groups.read().problem
    groups.new_label("Games")  # the change starts it again
    assert kept(login)["labels"] == ["Games"]
    odd = Grouping.of(json.dumps({"labels": ["A", "a", "B", 3], "moved": {"A": [A, "bad"], "Z": [B], "other": [C]}}))
    assert odd.labels == ["A", "B"] and odd.moved == {A: "A", C: "other"}


def test_what_is_kept_stays_under_an_environment_variables_size():
    groups, login = store()
    groups.new_label("Many")
    own = {key_of(i): Sorted("other") for i in range(3000)}
    with pytest.raises(ValueError, match="too many rules moved by hand"):
        groups.move(list(own), "Many", own)
    assert kept(login)["moved"] == {}  # the refused move kept nothing


def test_the_grouped_table_the_platform_draws():
    groups, login = store()
    groups.new_label("Games")
    groups.move([B], "Games", OWN)
    rows = [(A, OWN[A], ["dns"]), (B, OWN[B], ["server"]), (C, OWN[C], ["port 9"]), (key_of("d"), Sorted("other"), ["port 10"])]
    base = {"title": "Rules", "note": "4 shown", "columns": [{"title": "Rule"}], "actions": [{"form": "find", "title": "Find…"}]}
    t = groups.table(base, rows, per_group=1, notes={"system": "Windows' own"})
    assert [(g["id"], g["title"], g["kind"], g["count"], g["listed"]) for g in t["groups"]] == [
        ("system", "System", "auto", 1, 1), ("application", "Application", "auto", 0, 0), ("other", "Other", "auto", 2, 1),
        ("label:Games", "Games", "label", 1, 1)]
    by = {g["id"]: g for g in t["groups"]}
    assert by["system"]["note"] == "Windows' own" and by["other"]["note"].endswith("the first 1 of 2 listed: Find narrows them")
    assert [a["form"] for a in by["label:Games"]["actions"]] == ["label-rename", "label-remove"]
    assert [(r["key"], r["group"], r["own"], r.get("moved", False)) for r in t["rows"]] == [
        (A, "system", "system", False), (B, "label:Games", "application", True), (C, "other", "other", False)]
    assert t["rows"][0]["why"] == "the service Dnscache" and t["rows"][0]["cells"] == ["dns"]
    assert t["move"]["hook"] == "move_rules" and [c["value"] for c in t["move"]["choices"]] == [*AUTO_IDS, "label:Games", "own"]
    assert [a["title"] for a in t["actions"]] == ["Find…", "New label…"] and base["actions"] == [{"form": "find", "title": "Find…"}]
    assert {f["id"]: f["hook"] for f in RuleGroups.forms()} == {"label-new": "new_label", "label-rename": "rename_label",
                                                               "label-remove": "remove_label"}


def test_system_and_application_are_grouped_again_by_their_names():
    """The user: "try best to organize under system and applications. Like system has 'core networking' ... or Remote
    Assistance or network discovery ... applications has like starcraft or edge"; "try to group the system by 'services'"."""
    groups, login = store()
    groups.new_label("Games")
    k = [key_of(i) for i in range(8)]
    rows = [(k[0], Sorted("system", "Windows' own rule group", "Network Discovery"), ["Network Discovery (WSD-In)"]),
            (k[1], Sorted("system", "Windows' own rule group", "Core Networking"), ["Core Networking - DNS (UDP-Out)"]),
            (k[2], Sorted("system", "Windows' own rule group", "network   Discovery "), ["Network Discovery (UPnP-In)"]),
            (k[3], Sorted("application", "the program", "StarCraft II"), ["StarCraft II"]),
            (k[4], Sorted("application", "the program", "Microsoft Edge"), ["Microsoft Edge (mDNS-In)"]),
            (k[5], Sorted("system", "one of Windows' own rules"), ["no name"]),
            (k[6], Sorted("other", "a port alone"), ["port 9"]),
            (k[7], Sorted("application", "the program", "StarCraft II"), ["StarCraft II (UDP)"])]
    groups.move([k[3]], "Games", {x: s for x, s, _ in rows})
    groups.move([k[4]], "system", {x: s for x, s, _ in rows})
    t = groups.table({"title": "Rules", "columns": [{"title": "Rule"}]}, rows, per_group=2)
    by = {g["id"]: g for g in t["groups"]}
    assert [(c["id"], c["title"], c["count"], c["listed"]) for c in by["system"]["children"]] == [
        ("system:core networking", "Core Networking", 1, 1), ("system:microsoft edge", "Microsoft Edge", 1, 1),
        ("system:network discovery", "Network Discovery", 2, 2)]  # a name in any case is one heading, as first spelled
    assert (by["system"]["count"], by["system"]["listed"]) == (5, 5) and "with no service" not in by["system"]["note"]
    assert [(c["id"], c["count"], c["listed"], c.get("note", "")) for c in by["application"]["children"]] == [
        ("application:starcraft ii", 1, 1, "")]  # the other StarCraft II rule is in the label Games
    assert "children" not in by["other"] and "children" not in by["label:Games"]
    rows_by = {r["key"]: r for r in t["rows"]}
    assert rows_by[k[0]]["sub"] == rows_by[k[2]]["sub"] == "system:network discovery" and "sub" not in rows_by[k[5]]
    assert rows_by[k[4]]["sub"] == "system:microsoft edge" and rows_by[k[4]]["moved"]  # moved: it keeps its own name
    assert rows_by[k[3]]["group"] == "label:Games" and "sub" not in rows_by[k[3]]  # a label is one list
    t1 = groups.table({"title": "Rules"}, rows + [(key_of("y"), Sorted("system", "no name either"), ["also none"])], per_group=1)
    sys1 = {g["id"]: g for g in t1["groups"]}["system"]
    assert [(c["id"], c["count"], c["listed"]) for c in sys1["children"]][-1] == ("system:network discovery", 2, 1)
    assert sys1["children"][-1]["note"] == "the first 1 of 2 listed: Find narrows them"
    assert sys1["note"].endswith("the first 1 of 2 with no service listed: Find narrows them") and sys1["listed"] == 4
    assert {g["id"]: g for g in t1["groups"]}["other"]["note"].endswith("tied to no program or service: a port or an address alone")
    assert Sorted("system", name=None).name == "" and Sorted("other").name == ""
    off = groups.table({"title": "Rules"}, [(k[0], rows[0][1], ["a"], {"off": True}), (k[1], rows[1][1], ["b"], {})])["rows"]
    assert [r.get("off", False) for r in off] == [True, False]  # a rule turned off is listed, marked to be shown dimmed


class _Wall(Firewall):
    name = "firewall-test"

    def sorted_rules(self):
        return dict(OWN)


def test_every_firewall_offers_the_groups_hooks_kept_under_its_own_variable():
    wall = _Wall()
    assert {"move_rules", "new_label", "rename_label", "remove_label"} <= set(Firewall.HOOKS)
    assert wall.groups.variable == "FIREWALL_TEST_GROUPS"
    login = EnvironmentLogin(env={})
    wall.login = login
    wall.new_label("Games")
    assert wall.move_rules([A, B], "Games")["said"] == "2 rules moved to Games"
    assert json.loads(login.env["FIREWALL_TEST_GROUPS"])["moved"] == {"Games": sorted([A, B])}
    assert wall.remove_label("Games")["ok"] and "FIREWALL_TEST_GROUPS" not in login.env
    assert clean_label("label:Work", Grouping()) == "Work"
