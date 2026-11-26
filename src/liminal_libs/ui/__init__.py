"""The graphics the apps share (the user, 2026-11-04: the library holds "the framework for the
graphics. The common themes and drawing methods"): `static/icons.js` (the rail's icons, a symbol's
logo, the data-state icons; `LiminalIcons.icon(name, size)`), `static/liminal.css` (the themes'
variables, the base controls, the rail, a small app's page, the charts, the switch, the menu),
`static/charts.js` (line charts), `static/menu.js` (a context menu), `static/theme.js` (the UI's
theme on the page) and `static/touch.js` (touch screens and the on-screen keyboard, 1.42.0: a long
press for a right click's menu and for a tooltip's words, a field's keyboard, the room the keyboard
leaves; `LiminalTouch`, loaded right after theme.js) and `static/apis.js` (1.49.0: the API a plugin attaches to, drawn
on its page: `LiminalApis.html(apis, facts)`, its own styles on the themes' variables). An app serves them beside its own files
(apps.App through web.static_file: its folder first, then STATIC here).

The UI's preferences (the user, 2026-11-07: "add a preferences plugin for the 'UI' and add the different
themes"): one file for every app on this machine, the data folder's ui.json (LIMINAL_UI_FILE names another),
written by the platform's Preferences plugin, read by every app's frame (`GET /api/ui`) and applied by
theme.js. The themes are liminal.css's, as the charts app's Preferences offers them.

1.88.0 (Monday list item 21; the user, 2026-11-19: "preferences, keys, licenses all get stored in the individual's
login db"): the theme is the signed-in user's, a preference pair of their login's store (THEME_PAIR, `ui-theme`),
read and kept through the login given or, when none is, the login of the person whose request is being answered
(apps.authorization.asking_login: every app's frame names it from the browser's session). A login that keeps none
(an EnvironmentLogin, or nobody signed in) reads and writes ui.json as before; a user's store holding no theme yet
is given the file's, once, and the file is left as it was.

1.105.0 (Monday list item 31; the user, 2026-11-22: "a global interface standard"): the page standard, written down in
docs/PAGES.md: the five spaces (the controller menu, the left-hand menu, the main screen, the tools overhead, the
right-hand menu), each app's, and which of its tools can be picked at the same time. Those rules are data,
`static/standard.json`, read by the pages and by `ui.standard` (after, problems, check), both run on one table of cases."""
from __future__ import annotations

import json
import os
from pathlib import Path

STATIC = Path(__file__).parent / "static"
UI_VAR = "LIMINAL_UI_FILE"
DEFAULT_THEME = "dark"
THEME_PAIR = "ui-theme"  # the theme as a preference pair of the signed-in user's login store (1.88.0)
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


def _file_theme(path: Path | None) -> str | None:
    """The theme ui.json keeps, None when it keeps none (or one not among THEMES, or the file is broken)."""
    try:
        saved = json.loads(preferences_file(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    theme = saved.get("theme") if isinstance(saved, dict) else None
    return theme if theme in THEMES else None


def _write_file_theme(path: Path | None, theme: str) -> None:
    file = preferences_file(path)
    try:
        saved = json.loads(file.read_text(encoding="utf-8"))
        saved = saved if isinstance(saved, dict) else {}
    except (OSError, ValueError):
        saved = {}
    saved["theme"] = theme
    file.parent.mkdir(parents=True, exist_ok=True)
    part = file.with_name(file.name + ".part")
    part.write_text(json.dumps(saved, indent=1), encoding="utf-8")
    os.replace(part, file)


def _login_of(login):
    """The login given, else the asking person's (apps.authorization.asking_login), else None (the file)."""
    if login is not None:
        return login
    from ..apps.authorization import asking_login

    return asking_login()


def preferences(path: Path | None = None, login=None) -> dict:
    """What every app's page applies: the theme (the default when none is saved or the saved one is unknown), its
    base, the themes there are (for a page offering them), and where it is kept (`store`: "login" or "file").
    The theme is the user's that `login` serves, else the asking person's; the file's when that login keeps none."""
    from ..apps.authorization import keeps, recall

    who = _login_of(login)
    theme = recall(who, THEME_PAIR, lambda: _file_theme(path), label="the UI's theme")
    theme = theme if isinstance(theme, str) and theme in THEMES else DEFAULT_THEME
    return {"theme": theme, "base": THEMES[theme]["base"],
            "themes": [{"name": n, "title": t["title"], "base": t["base"], "swatch": list(t["swatch"])} for n, t in THEMES.items()],
            "store": "login" if keeps(who) else "file"}


def save_preferences(path: Path | None = None, login=None, **changes) -> dict:
    """The UI's preferences changed (`theme`: one of THEMES; ValueError otherwise), kept in the store of the user
    `login` serves (else the asking person's), or in the file when that login keeps none; returns them."""
    from ..apps.authorization import keep

    theme = changes.pop("theme", None)
    if changes:
        raise ValueError(f"no such UI preference: {', '.join(sorted(changes))}")
    if theme is not None and theme not in THEMES:
        raise ValueError(f"no theme named {theme!r}: {', '.join(THEMES)}")
    who = _login_of(login)
    if theme is not None:
        keep(who, THEME_PAIR, theme, lambda value: _write_file_theme(path, value), label="the UI's theme")
    return preferences(path, who)
