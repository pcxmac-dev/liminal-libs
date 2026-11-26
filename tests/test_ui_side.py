"""side.js, the right-hand menu alike in every app (liminal-libs 1.105.0; docs/PAGES.md; Monday list item 31). Text
assertions, as test_ui_static's: the library's tests start no process, so the script itself is run in headless Edge on
stand-ins (the side check, which also runs tests/data/ui_standard_cases.json against its twin of ui.standard)."""
from __future__ import annotations

from liminal_libs.ui import STATIC


def read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


SIDE = read("side.js")


def body(name: str) -> str:
    """One function's text: from its head to the first line closing at its own indentation."""
    head = SIDE.index(f"function {name}(")
    indent = SIDE.rfind("\n", 0, head) + 1
    pad = SIDE[indent:head]
    return SIDE[head:SIDE.index(f"\n{pad}}}", head)]


def test_its_one_global_and_what_it_offers():
    api = SIDE.split("window.LiminalSide = {", 1)[1]
    for name in ("panel, rows, fromRow, html", "standard: {", "get rules()", "ready", "FALLBACK", "after:", "problems:",
                 "groups:"):
        assert name in api, name
    panel = body("panel")
    for name in ("get picked()", "get scope()", "get slots()", "tool(newScope, markup)", "pick,", "unpick:", "refresh(find)"):
        assert name in panel, name


def test_a_plugins_words_are_text_never_markup():
    """Every word of a pick (a plugin's) goes through esc, and only the page's own markup is set as HTML."""
    assert "window.LiminalIcons.esc" in SIDE
    html = body("html")
    assert "esc(words(s.sub))" in html and "esc(words(sec.title))" in html and "esc(words(s.note))" in html
    assert "esc(words(k))" in SIDE and "esc(words(v))" in SIDE
    draw = body("draw")
    assert "esc(title)" in draw and "esc(gone)" in draw
    # the only markup set whole: the page's own tool slot, and the pick drawn from escaped words
    assert SIDE.count(".innerHTML = ") == 3  # the tool slot, the pick drawn, the pick emptied


def test_the_tool_slot_is_drawn_again_alone_and_a_new_scope_lets_the_pick_go():
    tool = SIDE.split("tool(newScope, markup) {", 1)[1].split("\n      },", 1)[0]
    assert "if (s !== scope) { if (picked) unpick(false); scope = s; }" in tool
    assert "el.tool.innerHTML = m" in tool and "el.pick" not in tool
    assert "if (m !== toolHtml)" in tool  # nothing redrawn when nothing changed (a status every few seconds)


def test_rows_pick_by_click_enter_space_and_never_from_a_control_inside():
    rows = body("rows")
    assert "'click'" in rows and "'keydown'" in rows
    assert "e.key === 'Enter' || e.key === ' '" in rows
    assert "NOT_PICKING" in rows and "e.target !== tr" in rows  # a field in a row keeps its own keys
    assert "button, a, input, select, textarea, summary, label" in SIDE
    assert "p.picked.key === key) { p.unpick(); return; }" in rows  # a second click lets go
    assert "mouseover" not in SIDE and "mouseenter" not in SIDE and "pointerover" not in SIDE  # a hover never picks


def test_escape_gives_the_focus_back_to_the_row():
    assert "e.key === 'Escape' && picked" in SIDE and "unpick(true)" in SIDE
    unpick = body("unpick")
    assert "rowOf(key)" in unpick and "row.focus" in unpick


def test_a_row_gone_is_kept_and_marked():
    refresh = SIDE.split("refresh(find) {", 1)[1].split("\n      },", 1)[0]
    assert "else if (!gone) gone = clock();" in refresh
    assert "No longer shown as of" in SIDE


def test_the_rules_are_fetched_relative_and_caught():
    assert "fetch('standard.json', { cache: 'no-cache' })" in SIDE
    assert ".catch(() => rules)" in SIDE
    assert "fetch('/" not in SIDE  # relative: a page served under a prefix (/platform/) finds its own


def test_a_phone_gets_back_to_the_row():
    assert "'(max-width: 700px)'" in SIDE and "Back to the row" in SIDE and "prefers-reduced-motion: reduce" in SIDE


def test_its_styles_are_on_the_themes_variables():
    css = read("liminal.css")
    for rule in (".side-pick {", ".side-pick-head {", ".side-unpick {", "tr[data-pick] { cursor: pointer; }", "tr.picked td {",
                 "tr[data-pick]:focus-visible"):
        assert rule in css, rule
    block = css.split("/* The right-hand menu (side.js", 1)[1].split("/* Phones", 1)[0]
    assert "#" not in block.split("*/", 1)[1]  # no colour of its own: the themes' variables only
    coarse = css.split("@media (any-pointer: coarse) {", 1)[1].split("\n}", 1)[0]
    assert "tr[data-pick] td { height: 44px; }" in coarse  # a finger's target, in the one block of a touch screen's rules
