"""The graphics the apps share (the user, 2026-11-04: the library holds "the framework for the
graphics. The common themes and drawing methods"): `static/icons.js` (the rail's icons, a symbol's
logo, the data-state icons; `LiminalIcons.icon(name, size)`), `static/liminal.css` (the themes'
variables, the base controls, the rail, a small app's page, the charts, the switch, the menu),
`static/charts.js` (line charts), `static/menu.js` (a context menu), `static/theme.js` (the UI's
theme on the page) and `static/touch.js` (touch screens and the on-screen keyboard, 1.42.0: a long
press for a right click's menu and for a tooltip's words, a field's keyboard, the room the keyboard
leaves; `LiminalTouch`, loaded right after theme.js). An app serves them beside its own files
(apps.App through web.static_file: its folder first, then STATIC here).

The UI's preferences (the user, 2026-11-07: "add a preferences plugin for the 'UI' and add the different
themes"): one file for every app on this machine, the data folder's ui.json (LIMINAL_UI_FILE names another),
written by the platform's Preferences plugin, read by every app's frame (`GET /api/ui`) and applied by
theme.js. The themes are liminal.css's, as the charts app's Preferences offers them."""
from __future__ import annotations

import json
import os
from pathlib import Path

STATIC = Path(__file__).parent / "static"
UI_VAR = "LIMINAL_UI_FILE"
DEFAULT_THEME = "dark"
# each theme's base (a light-based one also gets body.light) and its page, card, accent and text colours (liminal.css)
THEMES = {
    "dark": {"title": "Dark", "base": "dark", "swatch": ("#131722", "#1e222d", "#2962ff", "#d1d4dc")},
    "midnight": {"title": "Midnight", "base": "dark", "swatch": ("#0b1020", "#131b31", "#5b8cff", "#e1e7f5")},
    "graphite": {"title": "Graphite", "base": "dark", "swatch": ("#1c1e22", "#25282d", "#6b9bf2", "#dcdee2")},
    "light": {"title": "Light", "base": "light", "swatch": ("#e4e7ed", "#f3f4f7", "#1f4fd8", "#0f1219")},
    "paper": {"title": "Paper", "base": "light", "swatch": ("#efe8da", "#f9f5ec", "#8a4a12", "#241e14")},
}


def preferences_file(path: Path | None = None) -> Path:
    """The UI's preferences: `path`, else LIMINAL_UI_FILE, else the data folder's ui.json."""
    if path is not None:
        return Path(path)
    named = (os.environ.get(UI_VAR) or "").strip()
    if named:
        return Path(named).expanduser()
    from .. import layout

    return layout.data_dir() / "ui.json"


def preferences(path: Path | None = None) -> dict:
    """What every app's page applies: the theme (the default when none is saved or the saved one is unknown), its
    base, and the themes there are (for a page offering them)."""
    try:
        saved = json.loads(preferences_file(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        saved = {}
    theme = saved.get("theme") if isinstance(saved, dict) and saved.get("theme") in THEMES else DEFAULT_THEME
    return {"theme": theme, "base": THEMES[theme]["base"],
            "themes": [{"name": n, "title": t["title"], "base": t["base"], "swatch": list(t["swatch"])} for n, t in THEMES.items()]}


def save_preferences(path: Path | None = None, **changes) -> dict:
    """The UI's preferences changed (`theme`: one of THEMES; ValueError otherwise), kept in the file; returns them."""
    theme = changes.pop("theme", None)
    if changes:
        raise ValueError(f"no such UI preference: {', '.join(sorted(changes))}")
    if theme is not None and theme not in THEMES:
        raise ValueError(f"no theme named {theme!r}: {', '.join(THEMES)}")
    file = preferences_file(path)
    try:
        saved = json.loads(file.read_text(encoding="utf-8"))
        saved = saved if isinstance(saved, dict) else {}
    except (OSError, ValueError):
        saved = {}
    if theme is not None:
        saved["theme"] = theme
    file.parent.mkdir(parents=True, exist_ok=True)
    part = file.with_name(file.name + ".part")
    part.write_text(json.dumps(saved, indent=1), encoding="utf-8")
    os.replace(part, file)
    return preferences(path)
