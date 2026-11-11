"""The icons every page draws (liminal_libs/ui/static/icons.js): each one's markup well formed, the platform's plugins
there by their makers' marks, a name the set lacks drawn as the plug."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from liminal_libs.ui import STATIC

MARKS = ("ubuntu", "fedora", "gentoo", "wallfire", "wallglobe", "namecheap", "claude", "openai", "grok", "copilot",
         "cursor", "docker", "kubernetes", "lxd", "hyperv", "libvirt",
         "digitalocean", "linode", "ec2", "vultr", "azure", "googlecloud")  # the clouds (1.49.0)


def _paths() -> dict[str, str]:
    """Each icon's markup by its name, its quoted pieces joined (`name: '...' + '...'`)."""
    text = (STATIC / "icons.js").read_text(encoding="utf-8")
    body = text.split("const PATHS = {", 1)[1].split("\n  };", 1)[0]
    piece = re.compile(r"'((?:[^'\\]|\\.)*)'")
    out: dict[str, str] = {}
    name = None
    for line in body.splitlines():
        stripped = line.strip()
        named = re.match(r"([a-z][a-z0-9]*):\s*(.*)$", stripped)  # ec2 too
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


def test_liminals_sign_is_the_brushed_lambda():
    """1.44.0 (the user, 2026-11-10: "the liminal icon is the italic lambda"; "replace all user icons (login app) with the
    lambda sign"; written with a horse-hair brush): one filled outline in the 24-unit box, its dry-brush streaks cut out
    of it (evenodd), no stroke of its own, no font needed; the user icon stays for whoever means a user."""
    paths = _paths()
    lam = paths["lambda"]
    assert lam.startswith('<path fill="currentColor" stroke="none" fill-rule="evenodd" d="M') and "<text" not in lam
    nums = [float(v) for v in re.findall(r"-?\d*\.?\d+", lam.split(' d="', 1)[1])]
    assert nums and min(nums) >= 0 and max(nums) <= 24 and lam.count("Z") >= 2  # in the box; the outline and its streaks
    assert len(lam) < 6000 and "user" in paths
