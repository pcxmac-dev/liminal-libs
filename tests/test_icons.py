"""The icons every page draws (liminal_libs/ui/static/icons.js): each one's markup well formed, the platform's plugins
there by their makers' marks, a name the set lacks drawn as the plug."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from liminal_libs.ui import STATIC

MARKS = ("ubuntu", "fedora", "gentoo", "wallfire", "wallglobe", "namecheap", "claude", "openai", "grok", "copilot",
         "cursor", "docker", "kubernetes", "lxd", "hyperv", "libvirt",
         "digitalocean", "linode", "ec2", "vultr", "azure", "googlecloud",  # the clouds (1.49.0)
         "ebpf",  # eBPF's bee (1.60.0)
         "llamacpp", "ollama", "vllm", "opencode", "aider", "continuedev",  # the local AI plugins (1.62.0)
         "lmdeploy", "codexcli", "pi", "cline", "goose", "mcp")  # the new top-four tools and MCP (2026-11-18)
TOP_FOUR_AND_MCP = MARKS[-6:]


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


_TOKEN = re.compile(r"[A-Za-z]|-?(?:\d+\.?\d*|\.\d+)")
_ARGS = {"M": 2, "L": 2, "H": 1, "V": 1, "Q": 4, "A": 7}


def _pieces(d: str) -> list[tuple[str, tuple[float, float], tuple[float, float], list[tuple[float, float]]]]:
    """A path's pieces made absolute: (command, from, to, control points). Only the commands the marks use (M, L, H,
    V, Q, A and Z, in either case); a move is a piece that draws nothing, and pairs after a move are lines."""
    tokens = _TOKEN.findall(d)
    out: list[tuple[str, tuple[float, float], tuple[float, float], list[tuple[float, float]]]] = []
    x = y = x0 = y0 = 0.0
    cmd, i = "", 0
    while i < len(tokens):
        if tokens[i].isalpha():
            cmd, i = tokens[i], i + 1
            if cmd in "Zz":
                out.append(("Z", (x, y), (x0, y0), []))
                x, y = x0, y0
            continue
        up, rel = cmd.upper(), cmd.islower()
        n = _ARGS[up]
        args = [float(t) for t in tokens[i:i + n]]
        i += n
        ox, oy = (x, y) if rel else (0.0, 0.0)
        if up == "H":
            points = [(args[0] + ox, y)]
        elif up == "V":
            points = [(x, args[0] + oy)]
        elif up == "A":
            points = [(args[5] + ox, args[6] + oy)]  # its radii, turn and flags are not points
        else:
            points = [(args[k] + ox, args[k + 1] + oy) for k in range(0, n, 2)]
        out.append((up, (x, y), points[-1], points[:-1]))
        x, y = points[-1]
        if up == "M":
            x0, y0 = x, y
            cmd = "l" if rel else "L"
    return out


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


def test_the_local_ai_plugins_marks_llamacpps_drawn_anew_and_opencodes_filled():
    """1.62.0 (the user, 2026-11-16: "i need 3 plugins for inference serving local models on the platform, :: lama.cpp,
    ollama and vLLM, i also need 3 harness plugins for the platform :: OpenCode, Aider, and Continue"): six makers'
    marks in the set's own line. Two are held to more than being there. llama.cpp's is drawn anew from its description,
    two slanted bars of straight lines, and is not its maker's path (two of that one's corners are rounded; its brand
    files are CC BY-NC). OpenCode's is filled shapes, an even-odd frame, never an outline: its brand page asks that the
    logo is not outlined."""
    local = ("llamacpp", "ollama", "vllm", "opencode", "aider", "continuedev")
    paths = _paths()
    js = (STATIC / "icons.js").read_text(encoding="utf-8")
    assert set(local) <= set(MARKS)
    for name in local:
        assert f"    {name}: '" in js, name  # as a plugin's ICON is looked for in the file
    assert "continue" not in paths  # a word of the page's language: the plugin's icon is named continuedev
    bars = paths["llamacpp"]
    drawn = bars.split(' d="', 1)[1].split('"', 1)[0]
    assert bars.count("<path") == 1 and drawn.count("z") == 2 and not re.search(r"[CcSsQqTtAa]", drawn)  # no curve
    assert 'fill="' not in bars  # outlined, in the set's line
    frame = paths["opencode"]
    assert frame.startswith('<g fill="currentColor" stroke="none"><path fill-rule="evenodd" d="M4 2h16v20H4z')
    assert re.findall(r'stroke="([^"]*)"', frame) == ["none"] and "stroke-width" not in frame  # nothing is stroked


def test_the_ai_plugins_of_2026_11_18_and_mcp_have_their_makers_marks_drawn_anew():
    """The user, 2026-11-18: "now i need an MCP plugin for platform, basically a protocol plugin that mediates MCP
    connections to resources by local AI agents"; "top 4 inference engines, top 4 agentic harnesses (open source)".
    Six makers' marks, each drawn anew in the set's line from what the mark shows, never traced from its maker's
    files. Each is found as a plugin's ICON is, in the page's one colour, with a stroke width of its own, inside the
    24-unit box. Codex CLI's is Codex's own mark, a cloud with its prompt, not the OpenAI knot the Codex plugin draws.
    MCP's runs all keep its one slant; Pi's blocks have square ends; LMDeploy's bolt is straight, its rings round it.
    goose's is there too, though its plugin waits on the user's word."""
    paths = _paths()
    js = (STATIC / "icons.js").read_text(encoding="utf-8")
    assert TOP_FOUR_AND_MCP == ("lmdeploy", "codexcli", "pi", "cline", "goose", "mcp")
    drawn: dict[str, list] = {}
    for name in TOP_FOUR_AND_MCP:
        assert f"    {name}: '" in js, name  # as a plugin's ICON is looked for in the file
        markup = paths[name]
        tree = ET.fromstring(f"<svg>{markup}</svg>")
        colours = {v for el in tree.iter() for k, v in el.attrib.items() if k in ("fill", "stroke")}
        assert colours <= {"currentColor", "none"}, name  # the page's own colour, light or dark
        assert "stroke-width=" in markup, name  # a stroke width of its own, as every maker's mark here
        drawn[name] = [piece for el in tree.iter("path") for piece in _pieces(el.get("d"))]
        points = [p for c, start, end, controls in drawn[name]  # a move's start is only where the pen was
                  for p in ((end,) if c == "M" else (start, end, *controls))]
        points += [(float(c.get("cx")) + side * float(c.get("r")), float(c.get("cy")) + side * float(c.get("r")))
                   for c in tree.iter("circle") for side in (-1, 1)]  # a circle's box
        assert points and all(0.5 <= v <= 23.5 for p in points for v in p), name  # inside the box
    cloud = paths["codexcli"]
    assert "<rect" not in cloud and "rotate(" not in cloud and cloud != paths["openai"]  # not the knot's three links
    outline, prompt = [el.get("d") for el in ET.fromstring(f"<svg>{cloud}</svg>").iter("path")]
    lobes = re.findall(r"(?<![\d.])(\d+(?:\.\d+)?) \1 0 0 1 ", outline)
    assert len(lobes) == 6 and len(set(lobes)) == 1 and outline.endswith("z")  # six round lobes of one size, closed
    assert {c for c, *_ in _pieces(prompt)} <= {"M", "L", "H"}  # >_ in straight strokes
    runs = [(a, b) for c, a, b, _ in drawn["mcp"] if c == "L"]
    assert len(runs) == 7 and all(abs(abs(b[0] - a[0]) - abs(b[1] - a[1])) < .03 for a, b in runs)  # one slant
    assert [c for c, *_ in drawn["mcp"]].count("M") == 3  # three strokes of one line
    assert 'stroke-linecap="square"' in paths["pi"] and {c for c, *_ in drawn["pi"]} == {"M", "H", "V"}
    bolt, rings = [_pieces(el.get("d")) for el in ET.fromstring(f"<svg>{paths['lmdeploy']}</svg>").iter("path")]
    assert {c for c, *_ in bolt} <= {"M", "L", "H", "Z"} and len({end for _, _, end, _ in bolt}) == 6  # six corners
    assert [c for c, *_ in rings].count("A") == 3  # three rings swept round it
