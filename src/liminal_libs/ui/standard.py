"""The page standard's rules (docs/PAGES.md; Monday list item 31, the user, 2026-11-22: "each app has rules of which
tools can be selected at the same time", a requirement asserted, written and tested). The rules are data, in
static/standard.json, which every app's page reads through side.js (`LiminalSide.standard`); this module reads the same
file for the tests and for any Python that wants to know what a pick leaves. The standard library only.

An app has groups of tools. A group sits in one of the five spaces (controller, left, main, overhead, right) and says
how many of it are picked at once (`at_once`):

- `one`: exactly one; a new pick replaces the old, and unpicking goes back to its `default`;
- `one-or-none`: a new pick replaces the old, a second pick of the same one unpicks it, and so does unpicking;
- `any`: each pick toggles.

A group names its members (`tools`), or says in words what they are when the page gives them at run time (`open`: a
plugin's tabs, a row of a table). `of` names the group it belongs to: when that group changes, this one goes back to its
default (a tab to the first, a pick away). `with` ({group: [values] or the name of a list of that group}) says a group
holds anything but its default only while that other group holds one of those (the charts' drawing tools only on a chart
view); `only` says the same of one of its tools ({tool: {group: [values]}}: Replay only on Analysis). `right` is what the
right-hand menu tells, from its top: the tool picked on the left first, then the one picked in the middle.

A state is {group: [values]}: a `one` group holds one value, a `one-or-none` group none or one, an `any` group any of
its tools. `after(app, state, group, value)` is the state a pick leaves (value None: unpicked), `problems(app, state)`
what in a state the rules refuse, in words, and `check(rules)` that the file itself is sound. side.js carries a twin of
`after` and `problems`; both are run on tests/data/ui_standard_cases.json, pytest here, headless Edge there."""
from __future__ import annotations

import json
from pathlib import Path

FILE = Path(__file__).parent / "static" / "standard.json"
SPACES = ("controller", "left", "main", "overhead", "right")
AT_ONCE = ("one", "one-or-none", "any")


def load(path: Path | None = None) -> dict:
    """standard.json read (or the file at `path`)."""
    return json.loads(Path(path or FILE).read_text(encoding="utf-8"))


RULES = load()


def _app(app: str, rules: dict | None = None) -> dict:
    apps = (rules or RULES)["apps"]
    if app not in apps:
        raise ValueError(f"no app named {app!r} in the page standard: {', '.join(apps)}")
    return apps[app]


def groups(app: str, rules: dict | None = None) -> list[dict]:
    """The app's groups, in the file's order."""
    return list(_app(app, rules)["groups"])


def _group(app: str, gid: str, rules: dict | None) -> dict:
    for g in groups(app, rules):
        if g["id"] == gid:
            return g
    raise ValueError(f"{app} has no group named {gid!r}")


def _allowed(spec, other: dict) -> list:
    """`with`/`only`'s values for the other group: a list, or the name of a list the other group keeps."""
    return list(other.get(spec, [])) if isinstance(spec, str) else list(spec)


def _start(g: dict) -> list:
    return [g["default"]] if "default" in g else []


def _fits(app: str, state: dict, g: dict, value, rules: dict | None) -> str:
    """Why `value` may not be in group `g` with the rest of `state` as it is: "" when it may."""
    if value == g.get("default"):
        return ""
    for other_id, spec in (g.get("with") or {}).items():
        other = _group(app, other_id, rules)
        held = state.get(other_id) or _start(other)
        if not any(v in _allowed(spec, other) for v in held):
            return f"{g['id']} {value!r} only while {other_id} is {spec if isinstance(spec, str) else ' or '.join(spec)}"
    for other_id, spec in ((g.get("only") or {}).get(value) or {}).items():
        other = _group(app, other_id, rules)
        held = state.get(other_id) or _start(other)
        if not any(v in _allowed(spec, other) for v in held):
            return f"{g['id']} {value!r} only while {other_id} is {' or '.join(spec)}"
    return ""


def _settle(app: str, state: dict, changed: set, rules: dict | None) -> dict:
    """The groups that depend on a group changed (`of`) back to their start, and what `with`/`only` no longer allows let
    go, until nothing more changes."""
    gs, done = groups(app, rules), set()
    while changed:
        done |= changed
        now = set()
        for g in gs:
            gid = g["id"]
            if g.get("of") in changed and gid not in done:  # what belongs to a group changed starts again, and so on down
                state[gid] = _start(g)
                now.add(gid)
            kept = [v for v in state.get(gid, _start(g)) if not _fits(app, state, g, v, rules)]
            if kept != state.get(gid, _start(g)):
                state[gid] = kept or _start(g)
                now.add(gid)
        changed = now - done
    return state


def after(app: str, state: dict, group: str, value=None, rules: dict | None = None) -> dict:
    """The state a pick of `value` in `group` leaves (None: the group's pick let go). A value not among a group's named
    tools, a pick in a group whose `of` holds nothing, and a pick `with`/`only` refuse, raise ValueError."""
    g = _group(app, group, rules)
    new = {k: list(v) for k, v in state.items()}
    for x in groups(app, rules):
        new.setdefault(x["id"], _start(x))
    was = list(new[group])
    if value is not None:
        if "tools" in g and value not in g["tools"]:
            raise ValueError(f"{app}'s {group} has no {value!r}: {', '.join(g['tools'])}")
        if g.get("of") and not new.get(g["of"]):
            raise ValueError(f"{app}'s {group} is picked only with its {g['of']}")
        why = _fits(app, new, g, value, rules)
        if why:
            raise ValueError(f"{app}: {why}")
    if value is None:
        new[group] = _start(g)
    elif g["at_once"] == "one":
        new[group] = [value]
    elif g["at_once"] == "one-or-none":
        new[group] = [] if was == [value] else [value]
    else:
        new[group] = [v for v in was if v != value] if value in was else was + [value]
    return _settle(app, new, {group} if new[group] != was else set(), rules)


def problems(app: str, state: dict, rules: dict | None = None) -> list[str]:
    """What in `state` the rules refuse, in words: none when it is a state a page may be in."""
    out = []
    known = {g["id"] for g in groups(app, rules)}
    for gid in state:
        if gid not in known:
            out.append(f"{app} has no group named {gid!r}")
    for g in groups(app, rules):
        gid, held = g["id"], list(state.get(g["id"], _start(g)))
        if len(set(map(json.dumps, held))) != len(held):
            out.append(f"{gid} holds one value twice")
        if g["at_once"] == "one" and len(held) != 1:
            out.append(f"{gid} holds {len(held)}, exactly one is picked")
        if g["at_once"] == "one-or-none" and len(held) > 1:
            out.append(f"{gid} holds {len(held)}, one or none is picked")
        if "tools" in g:
            out.extend(f"{gid} has no {v!r}" for v in held if v not in g["tools"])
        if g.get("of") and held != _start(g) and not state.get(g["of"], _start(_group(app, g["of"], rules))):
            out.append(f"{gid} is picked without its {g['of']}")
        for v in held:
            why = _fits(app, state, g, v, rules)
            if why:
                out.append(why)
    return out


def check(rules: dict | None = None) -> list[str]:
    """What is wrong with the rules file itself, in words: none when it is sound."""
    rules = rules if rules is not None else RULES
    out = []
    if rules.get("v") != 1:
        out.append(f"the standard's version is {rules.get('v')!r}, this reads 1")
    if tuple(rules.get("spaces") or ()) != SPACES:
        out.append(f"the spaces are {', '.join(SPACES)}")
    for app, a in (rules.get("apps") or {}).items():
        if not a.get("controller") or a["controller"][0] != app:
            out.append(f"{app}: its controller names itself first")
        ids = [g.get("id") for g in a.get("groups") or ()]
        if len(set(ids)) != len(ids):
            out.append(f"{app}: a group's id is used twice")
        seen: dict = {}
        for g in a.get("groups") or ():
            gid = g.get("id")
            if g.get("space") not in SPACES:
                out.append(f"{app}.{gid}: no space {g.get('space')!r}")
            if g.get("at_once") not in AT_ONCE:
                out.append(f"{app}.{gid}: at_once is one of {', '.join(AT_ONCE)}")
            if ("tools" in g) == ("open" in g):
                out.append(f"{app}.{gid}: either its tools are named or it says in words what they are (open)")
            tools = g.get("tools") or []
            if len(set(tools)) != len(tools):
                out.append(f"{app}.{gid}: a tool is named twice")
            for t in tools:
                if t in seen:
                    out.append(f"{app}: {t!r} is in {seen[t]} and {gid}")
                seen[t] = gid
            if "default" in g and "tools" in g and g["default"] not in tools:
                out.append(f"{app}.{gid}: its default {g['default']!r} is not among its tools")
            if g.get("at_once") == "one" and "default" not in g:
                out.append(f"{app}.{gid}: a group of exactly one has a default")
            if g.get("of") is not None and (g["of"] not in ids or g["of"] == gid):
                out.append(f"{app}.{gid}: of names another group of {app}")
            for other, spec in list((g.get("with") or {}).items()) + [
                    (o, s) for per in (g.get("only") or {}).values() for o, s in per.items()]:
                og = next((x for x in a.get("groups") or () if x.get("id") == other), None)
                if og is None or other == gid:
                    out.append(f"{app}.{gid}: with names another group of {app}")
                    continue
                values = og.get(spec) if isinstance(spec, str) else spec
                if not isinstance(values, list) or ("tools" in og and any(v not in og["tools"] for v in values)):
                    out.append(f"{app}.{gid}: with {other} names tools of {other}")
            for t in g.get("only") or {}:
                if t not in tools:
                    out.append(f"{app}.{gid}: only names {t!r}, not among its tools")
        for r in a.get("right") or ():
            if r not in ids:
                out.append(f"{app}: the right-hand menu tells {r!r}, not a group")
        if not a.get("right"):
            out.append(f"{app}: the right-hand menu tells something")
    return out
