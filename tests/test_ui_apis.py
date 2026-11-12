"""The pages' API cards (ui/static/apis.js, 1.49.0) and the clouds' marks (icons.js)."""
from __future__ import annotations

import re

from liminal_libs.ui import STATIC


def read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def test_the_api_cards_are_there_for_every_page():
    js = read("apis.js")
    exported = js.split("window.LiminalApis = {", 1)[1]
    assert all(name in exported for name in ("html", "card", "style"))
    assert 'target="_blank" rel="noopener noreferrer"' in js  # the maker's pages open in a tab of their own
    assert "^https:\\/\\/" in js  # an address drawn as a link only when it is an https one
    assert "liminal-apis-style" in js and "var(--border)" in js and "var(--accent)" in js  # its look on the themes' variables
    assert "opened.has(key)" in js  # a "more of the API" box opened stays open across a redraw
    for words in ("Parts of the API", "Calls:", "more part", "more call", "Checked", "against the maker's pages"):
        assert words in js


def test_the_api_cards_fold_to_a_line_each_when_asked():
    """1.50.0 (the user, 2026-11-11: "on the APIs organize each API description so that they can expand and contract so
    they take up less space, kind of like the firewall"): with {fold: true} an API is a line that opens, its parts and
    its calls two more inside it; closed at first but a plugin's only API; what was opened is kept."""
    js = read("apis.js")
    assert "folded" in js.split("window.LiminalApis = {", 1)[1]
    assert "opts.fold ? folded(a, (facts || {})[a.name], opts.owner || '', list.length === 1)" in js  # the only one: open
    assert ": card(a, (facts || {})[a.name], opts.owner || '')" in js  # not asked: the card as it was
    assert '<details class="api-card api-fold" data-key="${esc(key)}:card"${isOpen(`${key}:card`, first) ? \' open\' : \'\'}>' in js
    assert '<details class="api-section api-fold" data-key="${esc(key)}"${isOpen(key, false) ? \' open\' : \'\'}>' in js
    assert 'if (!fold) return `<div class="api-section"><h4>${esc(head)}</h4>${body}</div>`;' in js
    assert "areasHtml(api, key, true) + callsHtml(api, key, true)" in js and "areasHtml(api, key) + callsHtml(api, key)" in js
    assert "parts` : ''" in js and "calls` : ''" in js and "used here</span>" in js  # the line says how much is used here
    # the (+) and the (−), round, the open one in the accent: as the firewall's groups have them
    for part in (".api-pm::before{content:'+'}", ".api-fold[open]>summary>.api-pm::before{content:'\u2212'}",
                 ".api-fold[open]>summary>.api-pm{border-color:var(--accent);color:var(--accent)}", "border-radius:50%",
                 ".api-fold>summary::-webkit-details-marker{display:none}"):
        assert part in js, part
    # kept across a redraw and in this browser; a line drawn again as it was is not written again
    assert "const FOLDS_KEY = 'liminal:apis:folds';" in js and "localStorage.setItem(FOLDS_KEY" in js
    assert "if (folds.get(d.dataset.key) !== d.open) { folds.set(d.dataset.key, d.open); keepFolds(); }" in js
    assert "const isOpen = (key, first) => (folds.has(key) ? folds.get(key) === true : first);" in js


def test_the_clouds_have_their_makers_marks():
    icons = read("icons.js")
    paths = icons.split("const PATHS = {", 1)[1].split("\n  };", 1)[0]
    for name in ("digitalocean", "linode", "ec2", "vultr", "azure", "googlecloud"):
        assert re.search(rf"^\s+{name}: '", paths, re.M), name
