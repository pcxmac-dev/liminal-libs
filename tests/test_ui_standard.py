"""The page standard's rules (liminal_libs.ui.standard over ui/static/standard.json; docs/PAGES.md; Monday list item 31,
the user, 2026-11-22: "each app has rules of which tools can be selected at the same time", a requirement asserted,
written and tested). The cases are tests/data/ui_standard_cases.json, which the headless Edge check of side.js runs too."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

from liminal_libs.ui import STATIC, standard

HERE = Path(__file__).parent
CASES = json.loads((HERE / "data" / "ui_standard_cases.json").read_text(encoding="utf-8"))
PAGES = (HERE.parent / "docs" / "PAGES.md").read_text(encoding="utf-8")


def test_the_file_is_sound():
    assert standard.check() == []
    assert set(standard.RULES["apps"]) == {"platform", "login", "integrator", "charts"}
    assert standard.RULES == json.loads((STATIC / "standard.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES["picks"], ids=[c["why"] for c in CASES["picks"]])
def test_each_pick_leaves_what_the_cases_say(case):
    if case.get("refused"):
        with pytest.raises(ValueError):
            standard.after(case["app"], case["state"], case["group"], case["value"])
        return
    got = standard.after(case["app"], case["state"], case["group"], case["value"])
    assert got == case["after"]
    assert standard.problems(case["app"], got) == []


@pytest.mark.parametrize("case", CASES["states"], ids=[c["why"] for c in CASES["states"]])
def test_each_state_has_the_problems_the_cases_say(case):
    assert len(standard.problems(case["app"], case["state"])) == case["problems"], standard.problems(case["app"], case["state"])


def test_every_app_has_its_cases():
    for app in standard.RULES["apps"]:
        assert any(c["app"] == app for c in CASES["picks"]), app
    # every at_once word is played at least once
    kinds = {next(g for g in standard.groups(c["app"]) if g["id"] == c["group"])["at_once"] for c in CASES["picks"]}
    assert kinds == set(standard.AT_ONCE)


def test_a_pick_never_changes_the_state_it_was_given():
    state = {"tool": ["plugin"], "tab": ["world"], "pick": ["0:3"]}
    kept = copy.deepcopy(state)
    standard.after("platform", state, "tool", "machine")
    assert state == kept


def test_one_replaces_any_toggles_and_what_depends_goes():
    s = standard.after("charts", {}, "drawing", "segment")
    assert s["drawing"] == ["segment"]
    assert standard.after("charts", s, "drawing", "rayLine")["drawing"] == ["rayLine"]
    s = standard.after("charts", {"view": ["analysis"]}, "overhead", "replay")
    s = standard.after("charts", s, "overhead", "unfiltered")
    assert s["overhead"] == ["replay", "unfiltered"]
    assert standard.after("charts", s, "overhead", "replay")["overhead"] == ["unfiltered"]
    s = standard.after("charts", dict(s, pick=["bar:3"]), "view", "stock")
    assert s["pick"] == [] and s["overhead"] == ["unfiltered"]


def test_an_unsound_file_is_told():
    bad = copy.deepcopy(standard.RULES)
    p = bad["apps"]["platform"]
    p["groups"][0]["default"] = "nothing"
    p["groups"][1]["of"] = "nowhere"
    p["groups"][2]["space"] = "elsewhere"
    p["right"] = ["tool", "else"]
    bad["apps"]["charts"]["groups"][1]["tools"].append("stock")  # a tool in two groups
    said = " | ".join(standard.check(bad))
    for words in ("its default 'nothing'", "of names another group", "no space 'elsewhere'", "tells 'else'",
                  "'stock' is in view and drawing"):
        assert words in said, words


def test_pages_md_names_every_app_and_group():
    for app, a in standard.RULES["apps"].items():
        assert f"### The {app}" in PAGES, app
        section = PAGES.split(f"### The {app}", 1)[1].split("\n## ", 1)[0].split("\n### ", 1)[0]
        for g in a["groups"]:
            assert f"`{g['id']}` ({g['space']}, " in section, (app, g["id"])
    for space in standard.SPACES:
        assert f"(`{space}`)" in PAGES, space


def test_the_charts_lists_are_named_as_their_page_has_them():
    """The charts' drawing tools and views are app.js's TOOLS and panels.js's VIEWS; the charts' own test holds the file
    to those lists, and this one keeps the file's own lists whole (nothing named twice, the default among them)."""
    c = {g["id"]: g for g in standard.groups("charts")}
    assert c["drawing"]["tools"][0] == "cursor" == c["drawing"]["default"]
    assert set(c["view"]["chart"]) <= set(c["view"]["tools"])
    i = {g["id"]: g for g in standard.groups("integrator")}
    assert set(i["view"]["tools"]) == set(c["view"]["tools"]) - set(c["view"]["chart"])


def test_side_js_holds_no_rule_of_its_own():
    """side.js reads standard.json (relative, caught) and keeps, until it has, only the platform's three groups."""
    side = (STATIC / "side.js").read_text(encoding="utf-8") if (STATIC / "side.js").exists() else None
    if side is None:
        pytest.skip("side.js comes with the next piece")
    assert "fetch('standard.json'" in side and ".catch(" in side
    fallback = json.loads(re.search(r"const FALLBACK = (\{.*?\});\s*// end of FALLBACK", side, re.S).group(1))
    assert fallback == {"v": 1, "spaces": standard.RULES["spaces"], "apps": {"platform": standard.RULES["apps"]["platform"]}}
