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
