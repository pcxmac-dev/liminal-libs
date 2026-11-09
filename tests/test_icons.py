"""The icons every page draws (liminal_libs/ui/static/icons.js): each one's markup well formed, the platform's plugins
there by their makers' marks, a name the set lacks drawn as the plug."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from liminal_libs.ui import STATIC

MARKS = ("ubuntu", "fedora", "gentoo", "wallfire", "wallglobe", "namecheap", "claude", "openai", "grok", "copilot",
         "docker", "kubernetes", "lxd", "hyperv", "libvirt")


def _paths() -> dict[str, str]:
    """Each icon's markup by its name, its quoted pieces joined (`name: '...' + '...'`)."""
    text = (STATIC / "icons.js").read_text(encoding="utf-8")
    body = text.split("const PATHS = {", 1)[1].split("\n  };", 1)[0]
    piece = re.compile(r"'((?:[^'\\]|\\.)*)'")
    out: dict[str, str] = {}
    name = None
    for line in body.splitlines():
        stripped = line.strip()
        named = re.match(r"([a-z]+):\s*(.*)$", stripped)
        if named:
            name = named.group(1)
            out[name] = "".join(piece.findall(named.group(2)))
        elif name and stripped.startswith("+"):
            out[name] += "".join(piece.findall(stripped))
    return {k: v.replace('\\"', '"') for k, v in out.items()}


def test_every_icon_is_well_formed_and_the_plugins_marks_are_there():
    paths = _paths()
    assert set(MARKS) <= set(paths) and len(paths) >= 50
    assert "tuxbricks" not in paths and "windowsbricks" not in paths  # the firewalls' marks the user replaced (1.34.0)
    for name, markup in paths.items():
        assert markup, name
        ET.fromstring(f"<svg>{markup}</svg>")  # a tag left open or an attribute unquoted raises
    js = (STATIC / "icons.js").read_text(encoding="utf-8")
    assert "SVG(PATHS[name] || PATHS.plug, cls, size)" in js  # a name it lacks: the plug, not an empty square
