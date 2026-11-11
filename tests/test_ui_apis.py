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


def test_the_clouds_have_their_makers_marks():
    icons = read("icons.js")
    paths = icons.split("const PATHS = {", 1)[1].split("\n  };", 1)[0]
    for name in ("digitalocean", "linode", "ec2", "vultr", "azure", "googlecloud"):
        assert re.search(rf"^\s+{name}: '", paths, re.M), name
