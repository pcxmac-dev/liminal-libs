"""The apps' shared page files (liminal_libs.ui, 1.23.0): the charts and the context menu beside the icons, the
switch, and the categorical slots validated against the page (the dataviz validator, 2026-11-07)."""
from __future__ import annotations

from liminal_libs.ui import STATIC


def read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def test_the_charts_and_the_menu_are_there_for_every_app():
    charts, menu = read("charts.js"), read("menu.js")
    assert "window.LiminalCharts = { cards, draw, update" in charts and "window.LiminalMenu = { open" in menu
    assert "textContent = ln.name" in charts and "innerHTML = ln.name" not in charts  # a plugin's names never as markup
    assert "textContent = it.label" in menu and "textContent = title" in menu
    for role in ("gui", "integrator", "platform", "login", "sync", "live"):  # every program the monitor reports keeps its colour
        assert f"{role}: " in charts.split("const SLOTS = {", 1)[1].split("};", 1)[0]


def test_the_slots_the_switch_and_the_menu_in_the_stylesheet():
    css = read("liminal.css")
    dark = css.split(":root { --series-1:", 1)[1].split("}", 1)[0]
    light = css.split("body.light { --series-1:", 1)[1].split("}", 1)[0]
    assert dark.startswith(" #3987e5;") and light.startswith(" #2a78d6;")
    assert all(f"--series-{n}:" in dark and f"--series-{n}:" in light for n in range(2, 8)) and "--series-8" not in css
    for rule in ('.switch[aria-checked="true"]::after', ".menu {", ".chart-tip {", ".charts.loading", ".chart .dot { stroke: var(--card)"):
        assert rule in css


def _blocks(css: str, head: str) -> list[tuple[int, int]]:
    """Where each `head { ... }` block of the stylesheet (its comments taken out) starts and ends."""
    spans, at = [], css.find(head)
    while at >= 0:
        depth, i = 0, css.index("{", at)
        for j in range(i, len(css)):
            depth += {"{": 1, "}": -1}.get(css[j], 0)
            if depth == 0:
                spans.append((at, j))
                break
        at = css.find(head, at + 1)
    return spans


def test_touch_is_there_for_every_page():
    """touch.js (1.42.0; the user, 2026-11-10: "I want to support touch as well as mouse clicking on the interface ...
    We'll make sure it works across all apps"; "Support for virtual keyboard on tablets and phones"): its one global,
    the long press, the bubble's words never as markup, a keyboard for every kind of field, the keyboard's room."""
    touch = read("touch.js")
    assert "window.LiminalTouch = {" in touch and "(any-pointer: coarse)" in touch and "classList.toggle('touch'" in touch
    for name in ("onLongPress", "tip", "hideTip", "keyboard", "setKeyboard", "KEYBOARDS", "typing", "whenIdle", "autofocus",
                 "raiseKeyboard", "get longPressing()", "get keyboardOpen()"):
        assert name in touch.split("window.LiminalTouch = {", 1)[1], name
    assert "b.textContent = words" in touch and "innerHTML" not in touch  # a title may be a plugin's name
    assert "data-touch-own" in touch and "input, textarea, select" in touch  # never in an area of its own, nor a field
    table = touch.split("const KEYBOARDS = {", 1)[1].split("\n  };", 1)[0]
    for kind in ("ticker", "search", "number", "decimal", "signed", "secret", "plain", "name", "username", "email", "url",
                 "password", "code", "text", "terminal"):
        assert f"\n    {kind}: {{" in table, kind
    assert "KEYBOARDS.key = KEYBOARDS.secret" in touch
    assert "autocomplete: 'off'" in touch and "'data-1p-ignore'" in table  # a secret kept out of password managers
    assert "'--vvh'" in touch and "visualViewport" in touch and "scrollIntoView" in touch
    # the rail's menus open by a long press with no wiring in the apps, and the plots' gestures are their own
    menu, charts = read("menu.js"), read("charts.js")
    assert "longPress(document, '#rail button')" in menu and "touch.onLongPress(" in menu and "longPress, get shown()" in menu
    assert 'data-touch-own role="img"' in charts and "pointercancel" in charts and "show(f.svg, indexAt(f.svg, x), x, y, true)" in charts
    assert "dataLabel" in read("icons.js").split("window.LiminalIcons = {", 1)[1]


def test_a_long_press_finds_words_as_a_hover_does_and_typing_on_screen_stays_a_fingers():
    """The words of a button a finger holds by its logo; a link to an address keeps its menu, one to nowhere has words;
    a keyboard on screen (its Go included) is still the finger's, so no field is focused by code after it; a lift never
    seen is over at the next tap; a kind of keyboard set in place of another; a field in a frame counts as the page's."""
    touch = read("touch.js")
    walk = touch.split("function tipOf(target) {", 1)[1].split("\n  }\n", 1)[0]
    assert "img" not in walk and "target.closest(OWN_MENU)" in walk  # a picture inside a button: on to the button's words
    assert 'a[href]:not([href=""]):not([href="#"]):not([href^="javascript:"]), video[controls], audio[controls]' in touch
    assert ":is(${reg.selector}) * {" in touch  # no callout on a picture inside what a long press serves
    keys = touch.split("document.addEventListener('keydown', (e) => {", 1)[1].split("}, true);", 1)[0]
    assert keys.lstrip().startswith("if (!e.isTrusted) return;") and "e.keyCode === 229" in keys and "e.isComposing" in keys
    assert "!fingered() || !textField(e.target) || HARD_KEY.test(e.key)" in keys
    down = touch.split("document.addEventListener('pointerdown', (e) => {", 1)[1].split("}, { capture: true", 1)[0]
    assert down.lstrip().startswith("if (!e.isTrusted) return;") and "10000" not in down
    assert "e.isPrimary && (e.pointerType === press.type || e.pointerType === 'mouse')" in down
    assert "Math.hypot(e.clientX - press.x, e.clientY - press.y) > NEAR" in touch  # another finger's tap goes through
    assert "get holding()" in touch.split("window.LiminalTouch = {", 1)[1]
    setk = touch.split("function setKeyboard(el, kind, more) {", 1)[1].split("\n  }\n", 1)[0]
    assert "KEYBOARD_ATTRS" in setk and "el.removeAttribute(n)" in setk
    assert "el.contentDocument" in touch and "el.localName === 'iframe'" in touch and "follow(doc)" in touch
    room = touch.split("function measure() {", 1)[1].split("\n  }\n", 1)[0]
    assert "if (!field || innerWidth !== wide) { tall = innerHeight; wide = innerWidth; }" in room
    assert "fingered() && innerHeight < tall - 120" in room
    menu = read("menu.js")
    assert "window.LiminalTouch.holding" in menu and "whenLifted" not in menu
    assert "if (!hold()) later(hold);" in menu and "console.warn(" in menu  # touch.js later on the page still found
    assert "(dx > dy && dx > 4)" in read("charts.js")  # the start of a swipe up or down shows nothing


def test_the_stylesheets_touch_rules():
    """Every hover highlight is a mouse's ((hover: hover)), a finger's targets and the fields' words are sized on a
    touch screen, the bubble is styled, the keyboard's room kept, and a phone's page is one column."""
    import re

    css = re.sub(r"/\*.*?\*/", "", read("liminal.css"), flags=re.S)
    hovers = _blocks(css, "@media (hover: hover)")
    assert hovers and all(any(a < m.start() < b for a, b in hovers) for m in re.finditer(r":hover", css))
    coarse = _blocks(css, "@media (any-pointer: coarse)")
    assert len(coarse) == 1
    inside = css[coarse[0][0]:coarse[0][1]]
    for rule in ("min-height: 40px", "font-size: max(16px, 1em)", ":root textarea", ".switch { width: 48px", ".menu button { min-height: 44px"):
        assert rule in inside, rule
    assert "touch-action: manipulation" in css and "touch-action: pan-y pinch-zoom" in css and ".touch-tip {" in css
    assert "html.keyboard body { height: var(--vvh, 100%); }" in css
    narrow = _blocks(css, "@media (max-width: 700px)")
    assert len(narrow) == 1 and "grid-template-columns: minmax(0, 1fr)" in css[narrow[0][0]:narrow[0][1]]
    assert narrow[0][0] > css.index("@media (max-width: 1100px)")  # after the wider break, so it wins below 700 px


def test_every_field_typed_into_looks_alike():
    """1.42.1: an email field had no border and no background (the base rule makes an input's border transparent), so
    the login's first-user form seemed to have no Email box; email, url, tel and number fields are drawn as text,
    password and search fields are, in the dark themes and the light ones."""
    import re

    css = re.sub(r"/\*.*?\*/", "", read("liminal.css"), flags=re.S)
    kinds = ("text", "password", "search", "email", "url", "tel", "number")
    field = re.search(r'\ninput\[type="text"\][^{]*\{([^}]*)\}', css)
    assert field and "border-color: var(--border)" in field.group(1) and "background: var(--bg)" in field.group(1)
    assert all(f'input[type="{k}"]' in field.group(0) for k in kinds)
    light = re.search(r'\nbody\.light input\[type="text"\][^{]*\{([^}]*)\}', css)
    assert light and "background: var(--field)" in light.group(1)
    assert all(f'body.light input[type="{k}"]' in light.group(0) for k in kinds)


def test_the_uis_preferences_one_file_for_every_app(tmp_path, monkeypatch):
    import json

    import pytest

    from liminal_libs import ui
    from liminal_libs.apps import App

    f = tmp_path / "ui.json"
    p = ui.preferences(f)
    assert (p["theme"], p["base"]) == ("dark", "dark") and [t["name"] for t in p["themes"]] == ["dark", "midnight", "graphite", "light", "paper"]
    assert ui.save_preferences(f, theme="paper")["base"] == "light" and json.loads(f.read_text(encoding="utf-8")) == {"theme": "paper"}
    with pytest.raises(ValueError):
        ui.save_preferences(f, theme="neon")
    with pytest.raises(ValueError):
        ui.save_preferences(f, colour="x")
    f.write_text("{not json", encoding="utf-8")
    assert ui.preferences(f)["theme"] == "dark"  # a broken file: the default, never an error on a page
    # every app's frame answers them (GET /api/ui), from LIMINAL_UI_FILE here
    monkeypatch.setenv(ui.UI_VAR, str(tmp_path / "shared.json"))
    ui.save_preferences(theme="graphite")

    class Tiny(App):
        NAME, TITLE, ICON, PORT, STATIC = "tiny", "Tiny", "chip", 0, tmp_path
    status, body = Tiny(log=lambda m: None).api(None, "GET", "/api/ui", {}, None)
    assert status == 200 and body["theme"] == "graphite" and ui.preferences_file() == tmp_path / "shared.json"
    # each theme is in the stylesheet (the dark and light bases as the variables' roots) and the page applies it
    css, js = read("liminal.css"), read("theme.js")
    for name, t in ui.THEMES.items():
        assert name in ("dark", "light") or f'[data-theme="{name}"]' in css
        assert f"{name}: '{t['base']}'" in js and t["swatch"][0] in css
    assert "fetch('api/ui'" in js and "window.LiminalTheme" in js
