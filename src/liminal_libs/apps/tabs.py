"""A plugin's own tabs on its page (the user, 2026-11-14: "so for the firewall's both are going to get a 'world wide web
view' that shows the globe and the routes incoming all traffic, as well as monitoring port traffic stats"; "on top of the
monitoring there needs to be a way to 'filter' (another tab) that allows you to monitor send and receive traffic"). A
plugin's page has Main, External API and Internal API (liminal-platform 0.32.0; Main and API before it); a machine
plugin declares more in its `TABS` (machines/plugin.py), each a `Tab`:

- `id`: the tab in the page's address (#name/<id>), so a reload or a link keeps it. It is url-safe: letters, digits, "-"
  and "_" (RFC 4648's URL and filename alphabet), at most MAX_ID long. The platform leaves out a tab whose id is one of
  the page's own, whatever its case ("main", "external", "internal", and "api", whose old addresses open External API),
  or another tab's; a Tab refuses none of them itself: the app whose page draws the tabs decides;
- `title`: the words on the tab ("World Wide Web", "Filter");
- `hook`: one of the plugin's hooks (listed in its HOOKS like any it answers), asked with no arguments, answering the page
  the tab draws. It is a read: the platform notes it as one in who talks to whom, never as a change, and keeps it out of
  its log as it keeps a status. So it only reads (what it watches starts as it is asked, and stops by itself once it is
  not), and a tab whose hook is a setup, a command, the settings, the scan or a job is left out;
- `every`: the seconds between asks while the tab is shown (at least MIN_EVERY). Nothing is asked while the tab is not
  shown, or while the page is not visible.

What travels is `as_dict()`, in the plugin's status (`tabs`).

The page a tab's hook answers is a dict, every key optional:
- `title` and `note`: words at its head;
- `globe`: what ui/static/liminal-globe.js draws, every key optional: `home` ({lat, lon, label}, or none); `origins`,
  the places, each {id, lat, lon, label, country, city, asn, org, count, bytes, kind, ports}, and where a plugin
  records hosts also its `hosts`, `programs` and `seconds` connected; `local`, the local peers, never placed ({count,
  bytes, hosts}); `attribution`, the places' ({text, url}); `updated` and `note` (its first 1,200 characters drawn);
  `kinds`, the kinds its legend lists; `showing`, the filter in words; `layers`, the infrastructure layers it may draw
  (machines/infrastructure.py's `Index.layers()`), and `layer_hook`, the read hook the page asks with a layer's id for
  that layer's geometry (`Index.layer()`);
- `flows`: a table of connections, {title, note, empty, columns, rows, filters}, drawn with filter controls, the flagged
  rows first. A row: {id, time (epoch seconds or ISO), since (that time in words), dir ("in", "out", or "local": both
  its ends on this machine), proto, local, remote, name, program, state, labels: [{kind, source, company}], flags:
  [{id, words}], bytes, packets, duration (seconds), unread (what of it could not be read, in words)}; `columns` the
  row's keys to show (a key, or {key, title, num}; the usual ones when it names none); `filters` what the controls
  offer and start at: {dir: [the directions], flagged: bool, labels: [the kinds], search: str}, the "Flagged only"
  switch drawn only where `flagged` is named (liminal-platform 0.33.0; the Netstat tab names none: nothing of it is
  flagged);
- `charts`: a LiminalCharts spec ({span, t, charts}: ui/static/charts.js), or a list of them, drawn apart from the Main
  tab's (the page keys them by the tab's id);
- `tables`, `forms` and `actions`: in the shapes a status has, drawn as the Main tab draws them. A table may also carry
  (1.105.0, Monday list item 31: a row picked in the middle is told in full in the right-hand menu, docs/PAGES.md)
  `details`, a list beside its `rows` and as long, each what that row picked tells (`detail()` makes one: {key, title,
  sub, facts: [[label, value]], sections: [{title, facts}], note}; its key what the row is whatever its counts, so a
  pick stays on it as the rows move) or None for a row told by its cells; and `pick`: False
  to keep its rows from being picked (a table of buttons). A page drawn by an older platform ignores both."""
from __future__ import annotations

import keyword
import math
import re
from dataclasses import asdict, dataclass

MAX_ID = 40
ID = re.compile(rf"[A-Za-z0-9_-]{{1,{MAX_ID}}}")  # url-safe, as the page's address carries it
MIN_EVERY = 1.0  # seconds: no tab is asked more often than this
# what a row picked tells, at most (detail()): a page asked every few seconds stays small
DETAIL_TITLE = 120  # characters of its title (and of a section's, and of a label)
DETAIL_FACTS = 40  # facts, in all its sections together
DETAIL_VALUE = 400  # characters of a fact's value, of its sub and of its note
DETAIL_SECTIONS = 8


@dataclass(frozen=True)
class Tab:
    """One tab a plugin adds to its page: its id in the address, its title, the read hook answering its page, and the
    seconds between asks while it is shown. Anything else is refused when it is made (ValueError), so a plugin that
    declares a bad tab fails as it loads, not on the page."""

    id: str  # url-safe: "world", "filter", "compare"
    title: str  # "World Wide Web", "Filter"
    hook: str  # a read hook the plugin answers with a page (no arguments)
    every: float = 5.0  # seconds between asks while the tab is shown (at least MIN_EVERY)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not ID.fullmatch(self.id):
            raise ValueError(f"a tab's id is url-safe: letters, digits, - and _, 1 to {MAX_ID} of them (not {self.id!r})")
        if not isinstance(self.title, str) or not self.title.strip():
            raise ValueError(f"tab {self.id!r} has no title")
        if not isinstance(self.hook, str) or not self.hook.isidentifier() or keyword.iskeyword(self.hook):
            raise ValueError(f"tab {self.id!r}: its hook is the name of one of the plugin's hooks (not {self.hook!r})")
        if isinstance(self.every, bool) or not isinstance(self.every, (int, float)):
            raise ValueError(f"tab {self.id!r}: every is a number of seconds (not {self.every!r})")
        if not math.isfinite(self.every) or self.every < MIN_EVERY:
            raise ValueError(f"tab {self.id!r}: every is at least {MIN_EVERY:g} second, and finite (not {self.every!r})")
        object.__setattr__(self, "every", float(self.every))

    def as_dict(self) -> dict:
        return asdict(self)


def _cut(value, most: int) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError(f"a detail's words are text or a number (not {type(value).__name__})")
    text = value if isinstance(value, str) else f"{value:,}" if isinstance(value, int) else f"{value:g}"
    return text if len(text) <= most else text[: most - 1] + "…"


def detail(title, facts=(), *, key: str = "", sub: str = "", note: str = "", sections=()) -> dict:
    """What a row picked tells in the right-hand menu (a table's `details`), as plain JSON: its key (what the row is,
    whatever its counts: the page keeps a pick on it as the rows move; its title when none is given), its title, a line
    under it, its facts ((label, value) pairs; a value None or "" left out), its sections ((title, facts)), and a note. Each is cut
    at the caps (DETAIL_TITLE, DETAIL_VALUE; DETAIL_FACTS facts in all, DETAIL_SECTIONS sections); a value that is not
    text or a number is refused (ValueError), so nothing but words travels."""
    budget = [DETAIL_FACTS]

    def pairs(given) -> list:
        out = []
        for pair in given or ():
            if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                raise ValueError(f"a fact is a (label, value) pair (not {pair!r})")
            label, value = pair
            if value is None or value == "":
                continue
            if budget[0] <= 0:
                break
            budget[0] -= 1
            out.append([_cut(label, DETAIL_TITLE), _cut(value, DETAIL_VALUE)])
        return out

    spec = {"key": _cut(key or title, DETAIL_VALUE), "title": _cut(title, DETAIL_TITLE), "facts": pairs(facts)}
    if sub:
        spec["sub"] = _cut(sub, DETAIL_VALUE)
    secs = []
    for section in list(sections or ())[:DETAIL_SECTIONS]:
        if not isinstance(section, (tuple, list)) or len(section) != 2:
            raise ValueError(f"a section is a (title, facts) pair (not {section!r})")
        got = pairs(section[1])
        if got:
            secs.append({"title": _cut(section[0], DETAIL_TITLE), "facts": got})
    if secs:
        spec["sections"] = secs
    if note:
        spec["note"] = _cut(note, DETAIL_VALUE)
    return spec
