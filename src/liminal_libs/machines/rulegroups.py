"""A firewall's rules in groups (the user, 2026-11-08: "for both firewalls, i need to have groups, like system or
application and then unassociated rules not tied to a specific application or system process can be in an other, i can
create labels, like system or application, as well and move the rules in to that"; "just use basic expansion like a
(+) to open and close labels").

Every rule a firewall plugin reads has a group of its own, which the plugin finds and says why (`Sorted`): System (the
operating system's own: its services, its programs, its networking), Application (a program's: one installed, or one
that makes rules of its own) or Other (tied to no program or service: a port or an address alone). The user may make
labels of their own and move rules into them, or into another of the three; a moved rule stays where it was put until it
is moved again, moved back to its own group, or its label is removed. The labels and the moves are the user's, kept
through the plugin's login (`Login.save`: one value under the plugin's variable, FIREWALL_WINDOWS_GROUPS ...), never in a
file; nothing of them changes the firewall. A rule is known by its key: ten hex digits of what names it (`key_of`), the
same from one read to the next while the rule is.

The platform draws such a table (`RuleGroups.table`, liminal-platform 0.11.0): a heading per group with (+) to open it
and (−) to close it, a box to choose each rule (a group's box choosing every rule it lists), and Move to."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

AUTO = (("system", "System"), ("application", "Application"), ("other", "Other"))
AUTO_IDS = tuple(a for a, _ in AUTO)
AUTO_TITLES = dict(AUTO)
NOTES = {  # what each of the three holds, a plugin's own words taking their place
    "system": "the operating system's own: its services, its programs and its networking",
    "application": "a program's: one installed, or one that makes rules of its own",
    "other": "tied to no program or service: a port or an address alone",
}
OWN = "own"  # Move to "Its own group": back where the plugin sorts it
LABEL = "label:"  # a label's group id in a table: label:Games
MAX_LABELS = 30
MAX_LABEL = 40  # characters in a label's name
MAX_KEPT = 30000  # characters of the value kept: an environment variable holds 32,767
KEY = re.compile(r"^[0-9a-f]{10}$")
MOVE_HOOK = "move_rules"


@dataclass(frozen=True)
class Sorted:
    """The group a plugin finds for one of its rules (system, application or other) and why, in words."""

    group: str
    why: str = ""

    def __post_init__(self):
        if self.group not in AUTO_IDS:
            raise ValueError(f"a rule's own group is system, application or other, not {self.group!r}")


def key_of(*parts) -> str:
    """A rule's key: ten hex digits of what names it (its id; or where it is and its words)."""
    return hashlib.sha1("\x1f".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()[:10]


def keys_of(keys) -> list[str]:
    """The keys a move names: a list, or words separated by commas or spaces (the command line's); each ten hex digits."""
    raw = keys if isinstance(keys, (list, tuple, set)) else re.split(r"[,\s]+", str(keys or ""))
    out = [str(k).strip().lower() for k in raw if str(k).strip()]
    bad = [k for k in out if not KEY.match(k)]
    if bad:
        raise ValueError(f"a rule's key is ten hex digits, not {bad[0]!r}")
    return list(dict.fromkeys(out))


@dataclass
class Grouping:
    """The user's labels, in the order made, and the rules moved by hand (key -> a label's name, or system, application
    or other). `problem`: the value kept could not be read (a change starts it again)."""

    labels: list = field(default_factory=list)
    moved: dict = field(default_factory=dict)
    problem: str = ""

    def label(self, name) -> str | None:
        """The label of that name as the user spelled it (any case); None when there is none."""
        n = " ".join(str(name or "").split()).casefold()
        if n.startswith(LABEL):
            n = n[len(LABEL):].strip()
        return next((x for x in self.labels if x.casefold() == n), None)

    def group_of(self, key: str, own: str) -> str:
        """Where a rule is shown: the group it was moved to, else its own."""
        return self.moved.get(key, own)

    def text(self) -> str:
        """The value kept: {"v": 1, "labels": [...], "moved": {group: [keys]}} (the keys by group: shorter)."""
        by: dict = {}
        for k, g in sorted(self.moved.items()):
            by.setdefault(g, []).append(k)
        return json.dumps({"v": 1, "labels": self.labels, "moved": by}, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def of(cls, text) -> "Grouping":
        """A value kept, read back: a label or a key it cannot hold left out."""
        if not text:
            return cls()
        try:
            data = json.loads(text)
            labels = []
            for x in data.get("labels") or []:
                if isinstance(x, str) and x.strip() and x.casefold() not in [y.casefold() for y in labels]:
                    labels.append(x)
            labels = labels[:MAX_LABELS]
            moved = {}
            for g, keys in (data.get("moved") or {}).items():
                group = g if g in AUTO_IDS else (g if g in labels else None)
                if group is None or not isinstance(keys, list):
                    continue
                for k in keys:
                    if isinstance(k, str) and KEY.match(k):
                        moved[k] = group
            return cls(labels, moved)
        except (ValueError, AttributeError, TypeError) as e:
            return cls(problem=f"the labels kept could not be read ({type(e).__name__}): a change starts them again")


def clean_label(name, g: Grouping, but: str | None = None) -> str:
    """A label's name as typed, its spaces made single: refused (ValueError) when empty, too long, a control character in
    it, one of the three groups' names, or another label's (any case)."""
    label = " ".join(str(name or "").split())
    if label.casefold().startswith(LABEL):
        label = label[len(LABEL):].strip()
    if not label:
        raise ValueError("a label needs a name")
    if len(label) > MAX_LABEL:
        raise ValueError(f"a label's name is {MAX_LABEL} characters at most")
    if any(ord(c) < 32 or ord(c) == 127 for c in label):
        raise ValueError("a label's name has no control characters")
    if label.casefold() in {a for a in AUTO_IDS} | {OWN}:
        raise ValueError(f"{label} is one of the groups already: a label needs a name of its own")
    other = g.label(label)
    if other is not None and other != but:
        raise ValueError(f"there is a label {other} already")
    return label


class RuleGroups:
    """A firewall plugin's labels and moves, read and kept through its login under `variable` (`login_of`: the plugin's
    login now, None when it has none: then nothing is kept)."""

    def __init__(self, variable: str, login_of):
        self.variable = variable
        self._login_of = login_of

    # -- read and kept ----------------------------------------------------------------------------------------------
    def read(self) -> Grouping:
        """The labels and moves kept for the signed-in user; none when the plugin has no login."""
        login = self._login_of()
        if login is None:
            return Grouping()
        try:
            text = login.variables([self.variable]).get(self.variable, "")
        except Exception as e:  # noqa: BLE001 - a login that cannot say: no labels, said
            return Grouping(problem=f"the labels could not be read: {e}")
        return Grouping.of(text)

    def _current(self) -> Grouping:
        g = self.read()
        return Grouping() if g.problem else g  # a value that cannot be read is started again by the change

    def keep(self, g: Grouping) -> str:
        """`g` kept through the login (nothing kept when there is no label and no move); where, in words."""
        login = self._login_of()
        if login is None:
            raise ValueError("labels are kept through the platform's login, and this plugin has none: open it on the platform")
        text = g.text() if (g.labels or g.moved) else None
        if text is not None and len(text) > MAX_KEPT:
            raise ValueError(f"too many rules moved by hand to keep ({len(g.moved)}): move some back to their own groups first")
        return login.save(self.variable, text)

    # -- the hooks' work -------------------------------------------------------------------------------------------
    def new_label(self, name) -> dict:
        g = self._current()
        if len(g.labels) >= MAX_LABELS:
            raise ValueError(f"{MAX_LABELS} labels at most: remove one first")
        label = clean_label(name, g)
        g.labels.append(label)
        where = self.keep(g)
        return {"said": f"the label {label} made: choose rules, then Move to {label}", "ok": True, "lines": [f"kept in {where}"]}

    def rename_label(self, name, to) -> dict:
        g = self._current()
        old = g.label(name)
        if old is None:
            raise LookupError(f"there is no label {name!r}")
        new = clean_label(to, g, but=old)
        if new == old:
            return {"said": f"the label is {old} already", "ok": True}
        g.labels[g.labels.index(old)] = new
        g.moved = {k: (new if v == old else v) for k, v in g.moved.items()}
        where = self.keep(g)
        return {"said": f"the label {old} is {new} now", "ok": True, "lines": [f"kept in {where}"]}

    def remove_label(self, name) -> dict:
        g = self._current()
        old = g.label(name)
        if old is None:
            raise LookupError(f"there is no label {name!r}")
        back = [k for k, v in g.moved.items() if v == old]
        g.labels.remove(old)
        for k in back:
            del g.moved[k]
        where = self.keep(g)
        return {"said": f"the label {old} removed" + (f": its {_rules(len(back))} back in their own groups" if back else ""),
                "ok": True, "lines": [f"kept in {where}"]}

    def move(self, keys, group, own: dict) -> dict:
        """The rules named by `keys` (those read now: `own`, key -> Sorted) moved to `group`: a label (its name, or
        label:<name>), system, application or other, or own (back to the group the plugin finds for each). A rule moved
        to its own group is simply back there."""
        wanted = keys_of(keys)
        if not wanted:
            raise ValueError("no rule chosen: choose rules first")
        known = [k for k in wanted if k in own]
        if not known:
            raise LookupError("none of those rules is read now: Refresh, then choose them again")
        g = self._current()
        target = str(group or "").strip()
        low = target.casefold()
        if low in ("", OWN, "its own group"):
            dest, title = None, "their own groups"
        elif low in AUTO_IDS or low in (t.casefold() for t in AUTO_TITLES.values()):
            dest = next(a for a, t in AUTO if low in (a, t.casefold()))
            title = AUTO_TITLES[dest]
        else:
            dest = g.label(target)
            if dest is None:
                raise LookupError(f"there is no label {target!r}: New label… makes one")
            title = dest
        for k in known:
            if dest is None or dest == own[k].group:
                g.moved.pop(k, None)
            else:
                g.moved[k] = dest
        where = self.keep(g)
        left = len(wanted) - len(known)
        return {"said": f"{_rules(len(known))} moved to {title}" + (f"; {left} no longer read, left as they were" if left else ""),
                "ok": True, "lines": [f"kept in {where}"]}

    # -- what the page draws ----------------------------------------------------------------------------------------
    def table(self, base: dict, rows, *, per_group: int = 100, notes: dict | None = None, grouping: Grouping | None = None) -> dict:
        """`base` (a status table: its title, note, columns, options, actions, empty) with `rows` ((key, Sorted, cells),
        in the order listed) grouped: `groups` in order (System, Application, Other, then the user's labels), each {id,
        title, kind (auto | label), count, listed, note, actions}; every row {cells, key, group, own, why, moved};
        `move` {hook, title, choices}: what the page needs for a heading per group with (+) and (−), a box per rule and
        Move to. Each group lists its first `per_group` rules; `actions` gains New label…."""
        g = grouping if grouping is not None else self.read()
        words = {**NOTES, **(notes or {})}
        order = [(a, AUTO_TITLES[a], "auto") for a in AUTO_IDS] + [(LABEL + x, x, "label") for x in g.labels]
        counts: dict = {}
        listed: dict = {}
        out_rows = []
        for key, s, cells in rows:
            moved = g.group_of(key, s.group)
            where = moved if moved in AUTO_IDS else LABEL + moved
            counts[where] = counts.get(where, 0) + 1
            if listed.get(where, 0) >= per_group:
                continue
            listed[where] = listed.get(where, 0) + 1
            row = {"cells": list(cells), "key": key, "group": where, "own": s.group, "why": s.why}
            if where != s.group:
                row["moved"] = True
            out_rows.append(row)
        groups = []
        for gid, title, kind in order:
            n, shown = counts.get(gid, 0), listed.get(gid, 0)
            note = words.get(gid, "") if kind == "auto" else "your label"
            if n > shown:
                note += f"; the first {shown} of {n} listed: Find narrows them"
            item = {"id": gid, "title": title, "kind": kind, "count": n, "listed": shown, "note": note}
            if kind == "label":
                item["actions"] = [{"form": "label-rename", "title": "Rename…", "values": {"name": title}, "label": f"Rename the label {title}"},
                                   {"form": "label-remove", "title": "Remove…", "values": {"name": title}, "label": f"Remove the label {title}"}]
            groups.append(item)
        out = dict(base)
        out["rows"] = out_rows
        out["groups"] = groups
        out["move"] = {"hook": MOVE_HOOK, "title": "Move to",
                       "choices": [{"value": gid, "title": title} for gid, title, _ in order]
                       + [{"value": OWN, "title": "Its own group", "note": "back where it is sorted"}]}
        out["actions"] = [*(base.get("actions") or []), {"form": "label-new", "title": "New label…"}]
        if g.problem:
            out["note"] = "; ".join(x for x in (base.get("note", ""), g.problem) if x)
        return out

    @staticmethod
    def forms() -> list[dict]:
        """The forms a grouped table's buttons open: a new label, a label renamed, a label removed."""
        return [
            {"id": "label-new", "hook": "new_label", "title": "New label", "confirm": False,
             "note": ("A group of your own for the rules you move into it (choose them, then Move to). It changes nothing in "
                      "the firewall, and is kept for you through the platform's login."),
             "fields": [{"name": "name", "label": "Label", "type": "text", "required": True, "placeholder": "Games, Office, Backups",
                         "note": f"{MAX_LABEL} characters at most"}],
             "submit": "Make the label"},
            {"id": "label-rename", "hook": "rename_label", "title": "Rename a label", "confirm": False,
             "fields": [{"name": "name", "label": "Label", "type": "fixed"},
                        {"name": "to", "label": "New name", "type": "text", "required": True}],
             "submit": "Rename"},
            {"id": "label-remove", "hook": "remove_label", "title": "Remove a label",
             "fields": [{"name": "name", "label": "Label", "type": "fixed"}],
             "confirm": {"title": "Remove the label {name}?", "words": "Its rules go back to their own groups. Nothing in the firewall changes.",
                         "yes": "Remove the label", "danger": True}},
        ]


def _rules(n: int) -> str:
    return f"{n} rule" + ("" if n == 1 else "s")
