"""The globe every app's page can draw (ui/static/liminal-globe.js; the user, 2026-11-14: "so for the firewall's both
are going to get a 'world wide web view' that shows the globe and the routes incoming all traffic, as well as monitoring
port traffic stats"), and the map beside it (ui/static/vendor/world/: world-atlas 2.0.2, its LICENSE and VERSION).

The charts app checks its pages' scripts by their words, not by running them, and so do these: the one global and its
handle, decodeTopo, the frames only while seen and a still one under prefers-reduced-motion, the screen's pixel ratio,
the themes' colours read again, the kinds and their routes' widths, the 1:50m map only past 2.5x, the attribution a link
only when it is an https one, the table beside the canvas, and no markup from a plugin's words. The phase-1 review's
fixes (2026-11-15) the same way: an update changes the words in place (the table's box, its scroll and rows, the
attribution's link and its focus stay; the rows' reorder is ported and checked), an origin without a known point is
counted, said and tabled, the origins past what is read are said, a keyboard's step is said to a screen reader, and the
tooltip wraps a long label. The map's files are checked as data: there, whole, the ones VERSION names, under
world-atlas's licence, and in the package data a wheel or an sdist is built with.

The firewalls' globe (liminal-libs 1.65.0; the user, 2026-11-16: "The globe should have the same kind of geography
associated with the exchanges globe, but the firewall globe should instead of exchanges, have all the
backbones,ibones, major internet infrastructure, (as many as possible) datacenter locations") the same way: a plugin's
infrastructure layers asked of the page (opts.load) and their switches kept in this browser (opts.key, inside try
only), each switch turning its layer on and off every time, the layers' bounds, nothing fetched but the map, the
layers' paint kept apart from the places' updates and their names drawn with the places', no day and night, clusters
kept in their cells, every line a cell is crossed by found by the pointer, the focus kept on a credit or a button
when another leaves, a layer the page does not answer for not waited on for good, and the `globe` line of
apps/tabs.py naming what the script reads. Where the page's own work is ported (the cells' marks, the lines' lists),
the port is checked as the page has it."""
from __future__ import annotations

import bisect
import glob
import hashlib
import json
import math
import os
import random
import re
from pathlib import Path

import pytest

from liminal_libs.ui import STATIC

WORLD = STATIC / "vendor" / "world"
MAPS = ("countries-110m.json", "countries-50m.json")
ROOT = Path(__file__).resolve().parents[1]  # the checkout: its pyproject.toml and src/


@pytest.fixture(scope="module")
def js() -> str:
    return (STATIC / "liminal-globe.js").read_text(encoding="utf-8")


def _body(js: str, head: str) -> str:
    """The text of the function (or block) that starts with `head`, to its closing brace."""
    at = js.index(head)
    depth, i = 0, js.index("{", at)
    for j in range(i, len(js)):
        depth += {"{": 1, "}": -1}.get(js[j], 0)
        if depth == 0:
            return js[at:j + 1]
    raise AssertionError(f"{head} is not closed")


def test_one_global_draws_a_globe_and_hands_back_update_and_destroy(js):
    """The design's API: LiminalGlobe.draw(el, spec, {theme}) -> {update(spec), destroy()}; drawn into the same element
    again, the same globe is updated in place and the same handle comes back."""
    assert js.rstrip().endswith("window.LiminalGlobe = { draw, decodeTopo };\n})();".rstrip())
    assert js.count("window.LiminalGlobe") == 1 and "window.Globe" not in js  # the charts app's own global stays its own
    draw = _body(js, "function draw(el, spec, opts) {")
    assert "throw new TypeError(" in draw  # no element, no globe
    assert "there.update(spec, opts || {});" in draw and "return there.handle;" in draw and "return g.handle;" in draw
    assert "if (g.left()) g.destroy();" in draw  # a globe whose element left the page goes with the next draw
    assert "const handle = { update: (next) => update(next), destroy };" in js
    destroy = _body(js, "function destroy() {")
    for gone in ("cancelAnimationFrame(raf)", "seenBy.disconnect()", "sized.disconnect()", "themed.disconnect()",
                 "unlisten(motion, onMotion)", "unlisten(scheme, recolour)", "unlisten(dpr, onRatio)",
                 "document.removeEventListener('visibilitychange', onVisibility)",
                 "document.removeEventListener('scroll', onScroll, { capture: true })", "tip.remove()", "root.remove()",
                 "globes.delete(self)", "if (!globes.size) maps.fine = null;"):
        assert gone in destroy, gone  # nothing runs, listens or holds the 1:50m map once the last globe is destroyed
    assert _body(js, "function update(next, more) {").split("\n")[1].strip() == "if (destroyed) return;"


def test_decode_topo_reads_quantized_and_plain_arcs(js):
    """globe.js's decodeTopo, exported: a quantized topology's arcs are steps from the point before, a plain one's the
    points themselves; and the vendored maps decode, as the page does, into places on the Earth."""
    decode = _body(js, "function decodeTopo(t) {")
    assert "const quantized = !!t.transform;" in decode
    assert "if (quantized) { x += dx; y += dy; } else { x = dx; y = dy; }" in decode
    assert "return [x * sx + tx, y * sy + ty];" in decode
    for name in MAPS:
        topo = json.loads((WORLD / name).read_text(encoding="utf-8"))
        assert topo["type"] == "Topology" and {"countries", "land"} <= set(topo["objects"])
        lines = _decode(topo)
        lons = [p[0] for line in lines for p in line]
        lats = [p[1] for line in lines for p in line]
        assert -180.000001 <= min(lons) and max(lons) <= 180.000001 and -90.000001 <= min(lats) and max(lats) <= 90.000001


def _decode(topo: dict) -> list[list[tuple[float, float]]]:
    """decodeTopo, as the page has it."""
    quantized = "transform" in topo
    (sx, sy), (tx, ty) = (topo["transform"]["scale"], topo["transform"]["translate"]) if quantized else ((1, 1), (0, 0))
    out = []
    for arc in topo["arcs"]:
        x = y = 0
        line = []
        for dx, dy in arc:
            x, y = (x + dx, y + dy) if quantized else (dx, dy)
            line.append((x * sx + tx, y * sy + ty))
        out.append(line)
    return out


def _rings(topo: dict, lines) -> list[tuple[int, list[tuple[float, float]]]]:
    """The land's rings as the page joins them (an arc after the first starts where the one before it ended), each with
    its place in its polygon (0 the outer ring, then its holes)."""
    out = []
    for geometry in topo["objects"]["land"]["geometries"]:
        polygons = geometry["arcs"] if geometry["type"] == "MultiPolygon" else [geometry["arcs"]]
        for polygon in polygons:
            for k, ring in enumerate(polygon):
                points: list[tuple[float, float]] = []
                for n, i in enumerate(ring):
                    arc = lines[~i][::-1] if i < 0 else lines[i]
                    points.extend(arc if n == 0 else arc[1:])
                out.append((k, points))
    return out


def test_the_land_is_cut_at_the_horizon_and_closed_its_own_way_round(js):
    """The land is filled as the map has it from any side: each ring cut where it goes behind the globe and closed
    along the rim the way round its own outline goes (turnOf, worked out from the ring, not taken on trust). The map's
    rings close on themselves, as the cut needs, and go round as turnOf expects: the outer ones clockwise seen from
    outside the globe, the holes (the Caspian Sea's) the other way."""
    assert "for (const ring of map.land) ringPath(b, ring, g, fr);" in js and "b.fill('evenodd');" in js
    clip = _body(js, "function ringPath(c, ring, g, fr) {")
    assert "c.arc(g.cx, g.cy, g.r, to, to + turn * best, turn < 0);" in clip  # along the rim, the ring's way round
    assert "return d > TAU - 1e-9 ? 0 : d;" in clip  # the two sides of a cut meeting on the rim are one point
    assert "return area < 0 ? 1 : -1;" in _body(js, "function turnOf(v) {")
    for name in MAPS:
        topo = json.loads((WORLD / name).read_text(encoding="utf-8"))
        rings = _rings(topo, _decode(topo))
        assert rings and all(points[0] == points[-1] for _, points in rings)
        outer = [_turn(points) for k, points in rings if k == 0]
        holes = [_turn(points) for k, points in rings if k > 0]
        assert outer and all(t == 1 for t in outer) and all(t == -1 for t in holes), name


def _turn(points: list[tuple[float, float]]) -> int:
    """turnOf, as the page has it: +1 for a ring clockwise seen from outside the globe (its area's sign negative)."""
    rad = math.pi / 180
    v = [(math.cos(lat * rad) * math.cos(lon * rad), math.cos(lat * rad) * math.sin(lon * rad), math.sin(lat * rad))
         for lon, lat in points[:-1]]
    m = [sum(p[k] for p in v) for k in range(3)]
    norm = math.sqrt(sum(c * c for c in m)) or 1
    mx, my, mz = (c / norm for c in m)
    area = 0.0
    for (ax, ay, az), (bx, by, bz) in zip(v, v[1:] + v[:1]):
        cx, cy, cz = ay * bz - az * by, az * bx - ax * bz, ax * by - ay * bx
        area += math.atan2(mx * cx + my * cy + mz * cz,
                           1 + mx * ax + my * ay + mz * az + ax * bx + ay * by + az * bz + bx * mx + by * my + bz * mz)
    return 1 if area < 0 else -1


def test_it_moves_only_while_seen_and_stands_still_under_reduced_motion(js):
    """The design: "the animation runs only while visible, with a still frame under prefers-reduced-motion". A frame is
    asked for only while the globe is on screen and the page shown; under reduced motion no light travels, no dash
    crawls, no ring widens from home, and a turn to a place is a jump, not a glide; the query's change is followed."""
    assert "matchMedia('(prefers-reduced-motion: reduce)')" in js and "listen(motion, onMotion);" in js
    assert "const moving = () => !reduced && routes.length > 0;" in js
    assert "if (destroyed || raf || !visible || document.hidden) return;" in _body(js, "function schedule() {")
    frame = _body(js, "function frame(now) {")
    assert "if (destroyed || !visible || document.hidden) return;" in frame
    assert "render(lights ? now : 0);" in frame and "if (glide || lights) raf = requestAnimationFrame(frame);" in frame
    routes = _body(js, "function drawRoutes(g, fr, now) {")
    assert "if (!now) return;  // still: no lights" in routes
    assert "ctx.lineDashOffset = dash.length && now ?" in routes
    assert "if (now) {" in _body(js, "function drawHome(g, now) {")
    assert "if (reduced) { view = { lon: to.lon, lat: to.lat }; zoom = to.zoom; glide = null; changed(); return; }" in js
    seen = _body(js, "const seenBy = 'IntersectionObserver' in window ? new IntersectionObserver((entries) => {")
    assert "visible = entries[entries.length - 1].isIntersecting;" in seen  # the latest word on it
    assert "document.addEventListener('visibilitychange', onVisibility);" in js


def test_sharp_at_the_screens_pixel_ratio_on_one_2d_canvas_and_no_library(js):
    render = _body(js, "function render(now) {")
    assert "const ratio = window.devicePixelRatio || 1;" in render
    assert "const W = Math.max(1, Math.round(g.w * ratio)), H = Math.max(1, Math.round(g.h * ratio));" in render
    assert "ctx.setTransform(ratio, 0, 0, ratio, 0, 0);" in render
    assert "matchMedia(`(resolution: ${window.devicePixelRatio || 1}dppx)`)" in js  # a window moved to another screen
    assert "canvas.getContext('2d')" in js and "webgl" not in js.lower()
    assert not re.search(r"\b(import|require)\s*\(", js) and "<script" not in js
    assert "fetch(`${HERE}vendor/world/${name}`, { credentials: 'same-origin' })" in js  # the map beside this file only


def test_the_colours_are_the_themes_variables_read_again(js):
    """--series-1..7 (the kinds on slots 1 to 3), --accent, --muted, --text and --frame, read again when the theme
    changes; and the fallbacks for a page without liminal.css are liminal.css's own values."""
    colours = _body(js, "function readColours(node, theme) {")
    for name in ("`--series-${i + 1}`", "'--accent'", "'--muted'", "'--text'", "'--frame'"):
        assert name in colours, name
    assert "themed.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'data-theme', 'style'] });" in js
    assert "listen(scheme, recolour);" in js and "matchMedia('(prefers-color-scheme: dark)')" in js
    assert "if (more && more.theme !== undefined && more.theme !== theme) { theme = more.theme; recolour(); }" in js
    css = (STATIC / "liminal.css").read_text(encoding="utf-8")
    dark, light = _variables(css, ":root"), _variables(css, "body.light")
    want = {
        "dark": ([dark[f"--series-{n}"] for n in range(1, 8)],
                 {"accent": dark["--accent"], "muted": dark["--muted"], "text": dark["--text"], "frame": dark["--border"],
                  "surface": dark["--bg"]}),
        "light": ([light[f"--series-{n}"] for n in range(1, 8)],
                  {"accent": light["--accent"], "muted": light["--muted"], "text": light["--text"], "frame": light["--frame"],
                   "surface": light["--card"]}),
    }
    fallback = js.split("const FALLBACK = {", 1)[1].split("\n  };", 1)[0]
    for base, (series, named) in want.items():
        part = fallback.split(f"{base}: {{", 1)[1].split("},", 1)[0]
        assert re.findall(r"'(#[0-9a-f]{6})'", part.split("]", 1)[0]) == series, base
        got = dict(re.findall(r"(\w+): '(#[0-9a-f]{6})'", part))
        assert all(got[k] == v for k, v in named.items()), (base, got, named)


def _variables(css: str, selector: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in re.finditer(re.escape(selector) + r"\s*\{([^}]*)\}", css):
        out.update((k, v.strip()) for k, v in re.findall(r"(--[\w-]+):\s*([^;]+);", m.group(1)))
    return out


def test_the_kinds_their_routes_and_the_legend(js):
    """Great-circle routes from each origin to home, 1.2 + min(3.6, 1.3 log10(count + 1)) wide; the kinds allowed,
    unanswered (dashed) and outbound, named in a legend; a dot sized by its count; home a marked point."""
    assert "const routeWidth = (count) => 1.2 + Math.min(3.6, 1.3 * Math.log10(count + 1));" in js
    assert "width: routeWidth(o.count)" in js
    assert "width = rt.width + (on ? 1 : 0);" in _body(js, "function drawRoutes(g, fr, now) {")  # as it is; the picked a px wider
    kinds = js.split("const KINDS = {", 1)[1].split("\n  };", 1)[0]
    assert re.search(r"allowed: \{ slot: 1, dash: null, words: 'Allowed in'", kinds)
    assert re.search(r"unanswered: \{ slot: 3, dash: \[5, 4\], words: 'Unanswered in'", kinds)
    assert re.search(r"outbound: \{ slot: 2, dash: null, words: 'Out'", kinds)
    assert "kind: own(KINDS, o.kind) ? o.kind : 'allowed'" in js  # only a kind it knows, by its own name
    assert "slerp(a, b, w, t)" in js  # the great circle between them
    legend = _body(js, "function renderLegend() {")
    assert "for (const [kind, k] of Object.entries(KINDS))" in legend and "item('home', 'home', 'This machine'" in legend
    assert "never placed" in legend  # the local network's peers counted, never on the globe
    assert "const dotRadius = (count) => 4 + Math.min(5, 1.5 * Math.log10(count + 1));" in js
    home = _body(js, "function drawHome(g, now) {")
    assert "ctx.strokeStyle = css(colours.accent)" in home and "ctx.fillStyle = css(colours.accent)" in home


def test_the_fine_map_only_past_two_and_a_half_times(js):
    assert "const FINE_ZOOM = 2.5;" in js
    assert "if (zoom > FINE_ZOOM && !maps.fine) loadFine();" in _body(js, "function render(now) {")
    assert "const map = zoom > FINE_ZOOM && maps.fine ? maps.fine : maps.coarse;" in js
    assert "const loadCoarse = mapLoader('countries-110m.json', 'coarse');" in js
    assert "const loadFine = mapLoader('countries-50m.json', 'fine');" in js
    assert "if (key === 'fine' && !globes.size) return true;" in js  # every globe went meanwhile: not kept
    assert "if (busy || Date.now() < next) return;" in _body(js, "function loader(fn) {")  # globe.js's loader


def test_the_attribution_the_table_and_no_markup_from_a_plugin(js):
    """The attribution is a link only when the spec's address is an https one; the places are a table beside the canvas
    for a screen reader; a plugin's words are text, never markup. Since 1.65.0 the attribution is a list (the places'
    and each layer shown's credits), every credit made safe by creditOf: its address kept only through safeUrl."""
    assert "const safeUrl = (u) => (/^https:\\/\\/[^\\s\"'<>]+$/i.test(" in js
    credit = _body(js, "function creditOf(a) {")
    assert "{ text: text(a.text), url: safeUrl(a.url) }" in credit
    assert "return c && (c.text || c.url) ? c : null;" in credit
    assert "attribution: creditOf(s.attribution)," in _body(js, "function normal(spec) {")  # the places'
    assert ".map(creditOf).filter(Boolean)" in _body(js, "function layersOf(list) {")  # a layer's, from its spec
    assert "credits: parts.map((p) => creditOf(p.credit))" in _body(js, "function prepareLayer(answer) {")  # its parts'
    attribution = _body(js, "function renderAttribution() {")
    assert "node.href = a.url;" in attribution and "node.rel = 'noopener noreferrer';" in attribution
    # no address (or not an https one): its words only, in a span
    assert "node = document.createElement(a.url ? 'a' : 'span');" in attribution
    assert "setText(node, a.text || a.url);" in attribution
    table = _body(js, "function renderTable() {")
    assert "t.createCaption()" in table and "th.scope = 'col';" in table and "for (const o of list)" in table
    assert "canvas.setAttribute('role', 'img');" in js and "canvas.setAttribute('aria-label'," in js
    assert "tip.setAttribute('aria-hidden', 'true');" in js  # the table carries the tooltip's words
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in js, sink
    assert not re.search(r"https?://[A-Za-z0-9]", js)  # no outside host: the page's own files only
    assert "const MAX_ORIGINS = 512;" in js and "const LIGHTS = 64;" in js  # bounded however many places a spec has


def test_the_map_is_vendored_with_its_licence_and_version():
    """world-atlas 2.0.2's countries-110m.json and countries-50m.json, as the charts app has them, with world-atlas's
    ISC licence and a VERSION naming the release, the data's source and each file's size and sha256 (counted with
    LF line ends, as a checkout that turns them to CRLF would otherwise differ)."""
    licence = (WORLD / "LICENSE").read_text(encoding="utf-8")
    assert "Copyright 2013-2019 Michael Bostock" in licence
    assert "Permission to use, copy, modify, and/or distribute this software for any purpose" in licence
    version = (WORLD / "VERSION").read_text(encoding="utf-8")
    assert version.startswith("world-atlas 2.0.2 (ISC)") and "Natural Earth (public domain)" in version
    for name in MAPS:
        data = (WORLD / name).read_bytes().replace(b"\r\n", b"\n")
        assert f"{name}: {len(data):,} bytes, sha256 {hashlib.sha256(data).hexdigest()}" in version, name
    assert sorted(p.name for p in WORLD.iterdir()) == ["LICENSE", "VERSION", *MAPS]


# -- the phase-1 review's fixes (2026-11-15) ------------------------------------------------------------------------------
def _shipped(package: Path, patterns: list[str]) -> set[str]:
    """The files setuptools' build_py puts in a wheel (and an sdist) for these package-data globs: each globbed,
    recursively, under the package's folder, files only. A folder a glob matches is dropped, never walked: so
    "ui/static/*" takes ui/static's own files and nothing in vendor/world."""
    out: set[str] = set()
    for pattern in patterns:
        for hit in glob.glob(os.path.join(str(package), *pattern.split("/")), recursive=True):
            if os.path.isfile(hit):
                out.add(Path(hit).relative_to(package).as_posix())
    return out


def test_every_file_beside_the_page_is_in_the_package_data():
    """Any install that is not editable (the platform's CI, a pip install from git) is built from the package data: it
    carries every file under ui/static, the globe's map and its licence among them. Without them the World tab draws an
    ocean with no land, and asks for the map again every minute while it is shown."""
    tomllib = pytest.importorskip("tomllib")
    pyproject, package = ROOT / "pyproject.toml", ROOT / "src" / "liminal_libs"
    if not pyproject.is_file() or not (package / "ui" / "static").is_dir():
        pytest.skip("not a checkout: no pyproject.toml and src/ beside the tests")
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))["tool"]["setuptools"]["package-data"]
    patterns = [*data.get("", []), *data.get("liminal_libs", [])]
    files = {p.relative_to(package).as_posix() for p in (package / "ui" / "static").rglob("*")
             if p.is_file() and "__pycache__" not in p.parts and not p.name.startswith(".")}
    world = {f"ui/static/vendor/world/{name}" for name in ("LICENSE", "VERSION", *MAPS)}
    assert world <= files
    assert files - _shipped(package, patterns) == set(), "not shipped: add a glob for them to [tool.setuptools.package-data]"
    # the one glob 1.53.0 had takes ui/static's own files and none of the map's (setuptools drops the folders it matches)
    assert "ui/static/liminal-globe.js" in _shipped(package, ["ui/static/*"]) and not world & _shipped(package, ["ui/static/*"])


def test_an_update_changes_the_words_in_place(js):
    """The platform gives the globe each answer of the tab's hook, a new object every few seconds with its words mostly
    the same: the table's box (and so where it is scrolled to), its rows and what a screen reader is reading in them,
    and the attribution's link with the focus on it, all stay; only the words that changed are written."""
    set_text = _body(js, "function setText(el, words) {")
    assert "if (el.textContent === words) return;" in set_text and "t.data = words;" in set_text  # its own text node kept
    table = _body(js, "function renderTable() {")
    assert "replaceWith(" not in table and "body.insertRow()" not in table  # never a new box, never every row made again
    assert "if (!box) {" in table  # the box made only while there is none: the table opened, or its first places came
    assert "const key = `${nth}|${o.id}`;" in table and "let tr = rows.get(key);" in table  # a place keeps its row
    assert ".forEach((words, c) => setText(tr.cells[c], words));" in table
    assert "for (const [key, tr] of rows) if (!kept.has(key)) tr.remove();" in table  # the rows of the places gone
    assert "const stay = steady(order.map((tr) => (now.has(tr) ? now.get(tr) : -1)));" in table
    assert "if (!stay.has(i)) body.insertBefore(order[i], ref);" in table  # only a row out of its order moves
    attribution = _body(js, "function renderAttribution() {")
    assert "attribution.replaceChildren();" not in attribution  # 1.53.0's: emptied and its link made again, every time
    # a credit keeps its node (its link, and the focus on it) while it is listed; the nodes of the credits gone are
    # taken out first, and the rest are put in order by arrange (steady): one already in order never moves
    assert "let node = credits.get(key);" in attribution and "setText(node, a.text || a.url);" in attribution
    gone = "for (const [key, node] of credits) if (!kept.has(key)) node.remove();"
    assert gone in attribution and "insertBefore" not in attribution
    assert attribution.index(gone) < attribution.index("arrange(attribution, [...kept.values()]);")
    legend = _body(js, "function renderLegend() {")
    assert "legend.replaceChildren()" not in js and "let it = legendItems.get(id);" in legend and "setText(it.w, words);" in legend
    assert "setText(note, parts.join(" in _body(js, "function renderNote() {")
    describe = _body(js, "function describe() {")
    assert "if (canvas.getAttribute('aria-label') !== words) canvas.setAttribute('aria-label', words);" in describe
    assert "setText(summary, n ?" in table
    assert "renderWords();" in _body(js, "function update(next, more) {")  # every update, each part now in place


def _steady(seq: list[int]) -> set[int]:
    """steady(), as the page has it: the indexes of a longest increasing run in `seq` (-1: a row not there yet)."""
    tails: list[int] = []
    prev = [-1] * len(seq)
    for i, v in enumerate(seq):
        if v < 0:
            continue
        lo, hi = 0, len(tails)
        while lo < hi:
            mid = (lo + hi) >> 1
            if seq[tails[mid]] < v:
                lo = mid + 1
            else:
                hi = mid
        if lo > 0:
            prev[i] = tails[lo - 1]
        tails[lo:lo + 1] = [i]
    out, i = set(), tails[-1] if tails else -1
    while i >= 0:
        out.add(i)
        i = prev[i]
    return out


def _reorder(page: list[str], order: list[str]) -> tuple[list[str], int]:
    """renderTable's rows put in their new order, as the page does it: the rows of the places gone taken out, the
    longest run of rows already in order left where they stand, and each other row (or a new one) put before the row
    after it, from the last up. The rows after it, and how many were put (moved or new)."""
    page = [k for k in page if k in order]
    now = {k: i for i, k in enumerate(page)}
    stay = _steady([now.get(k, -1) for k in order])
    put, ref = 0, None
    for i in range(len(order) - 1, -1, -1):
        if i not in stay:  # body.insertBefore(order[i], ref): taken from where it was, put before ref (or last)
            if order[i] in page:
                page.remove(order[i])
            page.insert(len(page) if ref is None else page.index(ref), order[i])
            put += 1
        ref = order[i]
    return page, put


def _longest_run(seq: list[int]) -> int:
    """The length of a longest increasing run, worked out apart (bisect), to check _steady by."""
    tails: list[int] = []
    for v in seq:
        k = bisect.bisect_left(tails, v)
        tails[k:k + 1] = [v]
    return len(tails)


def test_a_place_keeps_its_row_and_only_rows_out_of_their_order_move(js):
    """The table's reorder, ported (renderTable and steady): whatever the update, its rows end in the new order; the
    longest run of rows already in order never moves, so a place overtaken by all the others moves its own row and not
    theirs (a screen reader on one of them stays on it); a new place's row is put in and a gone one's taken out, and
    nothing else moves."""
    assert "tails[lo] = i;" in _body(js, "function steady(seq) {") and "prev = new Int32Array(seq.length).fill(-1)" in js
    assert _reorder(list("abcde"), list("abcde")) == (list("abcde"), 0)
    assert _reorder(list("abcde"), list("bcdea")) == (list("bcdea"), 1)  # a overtaken by them all: a alone moves
    assert _reorder(list("abcde"), list("eabcd")) == (list("eabcd"), 1)  # e past them all: e alone moves
    assert _reorder(list("abcde"), list("acde")) == (list("acde"), 0)  # b gone: nothing moves
    assert _reorder(list("abc"), list("axbc")) == (list("axbc"), 1)  # x new: put in, nothing moves
    assert _reorder([], list("ab")) == (list("ab"), 2) and _reorder(list("ab"), []) == ([], 0)
    rnd = random.Random(20261115)
    for _ in range(400):
        keys = [f"k{i}" for i in range(rnd.randint(0, 40))]
        page = rnd.sample(keys, rnd.randint(0, len(keys)))
        order = rnd.sample(keys, rnd.randint(0, len(keys)))
        got, put = _reorder(page, order)
        assert got == order
        there = [k for k in page if k in order]
        new = sum(k not in page for k in order)
        assert put == new + len(there) - _longest_run([there.index(k) for k in order if k in there])  # as few as can be


def test_origins_without_a_known_point_are_counted_said_and_tabled(js):
    """geo.Place has lat = lon = None when the file knows the country but not the point, so a World tab passing GeoIP's
    places on sends such origins as a matter of course: each is in its kind's totals, the legend says how many places
    and how much traffic are not on the globe, the canvas's label says so, and the table lists it with no point. Only
    the globe leaves it out. What is not an object is no origin at all."""
    normal = _body(js, "function normal(spec) {")
    assert "if (!p) return;" not in normal  # 1.53.0's: dropped before anything counted it
    assert "if (!o || typeof o !== 'object' || Array.isArray(o)) return;" in normal
    assert "placed: !!p, lat: p ? p.lat : null, lon: p ? p.lon : null," in normal
    assert "for (const o of all) { add(totals[o.kind], o); if (!o.placed) add(unplaced[o.kind], o); }" in normal
    assert "origins: listed.filter((o) => o.placed), listed," in normal  # drawn: those with a point; tabled: every one
    assert "without a known point, not on the globe: " in _body(js, "function unplacedWords() {")
    assert "item('unplaced', null, unplacedWords());" in _body(js, "function renderLegend() {")
    assert "of them without a known point and not drawn" in _body(js, "function describe() {")
    table = _body(js, "function renderTable() {")
    assert "const list = data.listed, n = list.length;" in table
    # each column carries its words for a place (1.65.0): the last, where on the globe its dot is, or no known point
    assert "columns.map(([, , cell]) => cell(o)).forEach((words, c) => setText(tr.cells[c], words));" in table
    assert "['On the globe', false, pointOf]" in js and ": 'no known point');" in js
    # the globe draws, routes and finds only the places with a point, and the keyboard steps through those
    for head in ("function buildRoutes() {", "function drawPlaces(c, g) {", "function hitAt(clientX, clientY, by) {"):
        assert "for (const o of data.origins)" in _body(js, head), head
    assert "const list = data.origins;" in _body(js, "canvas.addEventListener('keydown', (e) => {")


def test_the_origins_past_what_is_read_are_said(js):
    """A spec's list is read to MAX_READ: the rest are not counted, and the note says how many there were, so the
    totals are not taken for all of them."""
    normal = _body(js, "function normal(spec) {")
    assert "given.slice(0, MAX_READ)" in normal and "unread: Math.max(0, given.length - MAX_READ)" in normal
    note = _body(js, "function renderNote() {")
    assert "if (data.unread) {" in note and "places were read, and the totals are theirs" in note


def test_a_keyboard_step_is_said_to_a_screen_reader(js):
    """The canvas's label says the arrow keys step through the places: each step (and a zoom, and Home) is said in a
    polite live region, the tooltip being hidden from a reader; the same words twice are said twice; they go when the
    step is put away or the focus leaves."""
    assert "said.setAttribute('aria-live', 'polite');" in js and "said.setAttribute('aria-atomic', 'true');" in js
    assert "stage.append(canvas, controls, attribution, said);" in js
    keys = _body(js, "canvas.addEventListener('keydown', (e) => {")
    assert "say(stepWords(o, list));" in keys and "{ zoomBy(1.6); sayZoom(); }" in keys and "say('Back to this machine" in keys
    assert "said.textContent === words ? `${words}\\u00a0` : words;" in _body(js, "function say(words) {")
    assert "`; ${list.indexOf(o) + 1} of ${list.length}`" in _body(js, "function stepWords(o, list) {")
    assert "if (was && was.by === 'keys') said.textContent = '';" in _body(js, "function setPick(p) {")
    assert "said.textContent = '';" in _body(js, "canvas.addEventListener('blur', () => {")


def test_the_tooltip_wraps_a_long_unbroken_label(js):
    """A place's name is a plugin's, up to 200 characters, maybe without a space: every line of the tooltip wraps
    within its 320 px, so none runs past it or off the screen's edge."""
    tip = js.split("\n.lg-tip{", 1)[1].split("}", 1)[0]
    assert "overflow-wrap:anywhere" in tip and "max-width:min(320px,calc(100vw - 16px))" in tip


# -- the firewalls' globe (1.65.0): a plugin's infrastructure layers --------------------------------------------------
CELL = 24  # px: the screen grid a layer's points are gathered on (the script's CELL, checked below)


def test_the_layers_are_asked_of_the_page_and_their_switches_kept_in_this_browser(js):
    """draw(el, spec, {theme, load, key}): `load` is the page's way to a layer's geometry (the globe itself asks for
    nothing but its map), `key` the name its switches are kept under in this browser; the handle stays {update,
    destroy}. Without a loader every layer stays off, and its button, the layers' row and a click on it say why."""
    create = _body(js, "function create(el, spec, opts) {")
    assert "let load = typeof opts.load === 'function' ? opts.load : null;" in create
    assert "let storeName = typeof opts.key === 'string' ? text(opts.key, 200) : '';" in create
    assert "let chosen = recall(storeName);" in create
    update = _body(js, "function update(next, more) {")
    assert "if (more && typeof more.load === 'function') load = more.load;" in update
    assert "chosen = recall(storeName);" in update  # drawn again under another key: the switches kept there
    assert "const isOn = (l) => !!load && (chosen.has(l.id) ? chosen.get(l.id) : l.on);" in js
    assert "for (const l of data.layers) if (isOn(l)) askLayer(l, load);" in _body(js, "function render(now) {")
    ask = _body(js, "function askLayer(l, load) {")
    assert "try { asked = Promise.resolve(load(l.id)); } catch (e) { asked = Promise.reject(e); }" in ask
    assert "const NO_LOADER = 'this page gives the globe no way to load it';" in js
    layers = _body(js, "function renderLayers() {")
    assert "attr(it.b, 'aria-disabled', load ? null : 'true');" in layers
    assert "why.unshift('These layers stay off: this page gives the globe no way to load them');" in layers
    assert "if (!load) { say(`${l.title}: ${NO_LOADER}`); return; }" in _body(js, "function switchLayer(id) {")


def _switches(switch: str, on_at_first: bool, clicks: int) -> list[bool]:
    """switchLayer's steps on the choices, run in the order the page has them (the statements it is made of, read from
    it): the layer's state after each click. isOn is the choice kept here, else the spec's `on`."""
    chosen: dict[str, bool] = {}
    seen = []
    for _ in range(clicks):
        names: dict[str, bool] = {}
        for line in switch.split("\n"):
            step = line.split("//", 1)[0].strip()
            if step == "const next = !isOn(l);":
                names["next"] = not chosen.get("x", on_at_first)
            elif step == "chosen.delete(id);":
                chosen.pop("x", None)
            elif step == "chosen.set(id, next);":
                chosen["x"] = names["next"]
            elif step == "chosen.set(id, !isOn(l));":
                chosen["x"] = not chosen.get("x", on_at_first)
        seen.append(chosen.get("x", on_at_first))
    return seen


def test_a_layers_switch_turns_it_on_and_off_every_time(js):
    """The legend's layer items are buttons, pressed while the layer is on. A click reads the layer's state before its
    choice is taken out to be put last (the oldest go first past 64): read after it, the state was the spec's `on`
    every time, so a layer on at first could be switched off once and never on again, one off at first on once and
    never off, and the choice kept made it last across reloads (the 1.65.0 review). The choice is kept under the
    page's key."""
    switch = _body(js, "function switchLayer(id) {")
    assert "chosen.set(id, !isOn(l))" not in switch
    steps = ("const next = !isOn(l);", "chosen.delete(id);", "chosen.set(id, next);")
    read, out, put = (switch.index(s) for s in steps)
    assert read < out < put
    assert _switches(switch, True, 4) == [False, True, False, True]
    assert _switches(switch, False, 4) == [True, False, True, False]
    assert "while (chosen.size > 64) chosen.delete(chosen.keys().next().value);" in switch
    assert switch.index("chosen.set(id, next);") < switch.index("remember(storeName, chosen);")
    assert "layersShown = null;" in switch and "renderWords();" in switch and "changed();" in switch
    layers = _body(js, "function renderLayers() {")
    assert "it.b.type = 'button';" in layers and "it.b.addEventListener('click', () => switchLayer(l.id));" in layers
    assert "on = isOn(l);" in layers and "attr(it.b, 'aria-pressed', String(on));" in layers
    assert '.lg-layer[aria-pressed="false"]{opacity:.55}' in js  # a layer switched off reads as off


def test_the_page_storage_is_touched_only_inside_try(js):
    """A private window, blocked site data or a full store throws on localStorage: each use is inside try, and the
    switches then last as long as the globe does. Only switches are read back: a layer's id, on or off, 64 at most."""
    uses = [line for line in js.split("\n") if "localStorage" in line and not line.lstrip().startswith("//")]
    assert len(uses) == 2 and all(line.lstrip().startswith("try {") and "} catch (e) {" in line for line in uses)
    recall = _body(js, "function recall(name) {")
    assert "localStorage.getItem(STORE + name)" in recall and "Object.keys(kept).slice(0, 64)" in recall
    assert "if (typeof kept[id] === 'boolean') chosen.set(text(id, 40), kept[id]);" in recall
    assert "localStorage.setItem(STORE + name, words)" in _body(js, "function remember(name, chosen) {")
    assert "const STORE = 'liminal-globe-layers:';" in js


def test_nothing_is_fetched_but_the_map(js):
    """The globe asks for nothing itself but the map beside it: a layer's geometry comes through the page's `load`."""
    assert len(re.findall(r"\bfetch\(", js)) == 1
    for other in ("XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "importScripts", "new Worker"):
        assert other not in js, other


def test_the_layers_are_bounded(js):
    """At most MAX_LAYERS 8 layers listed (more counted and said), 20,000 points and 400,000 line vertices a layer (as
    machines/infrastructure.py keeps at most), 16 parts an answer, 12 names on the map at once; no DOM node a feature
    (they are thousands: the plugin's own tables count them)."""
    for line in ("const MAX_LAYERS = 8;", "const MAX_LAYER_POINTS = 20000;", "const MAX_LAYER_VERTICES = 400000;",
                 "const MAX_PARTS = 16;", "const LAYER_NAMES = 12;", "const NAME = 80;", "const LINE_CELL = 8;",
                 f"const CELL = {CELL};"):
        assert f"  {line}  // " in js, line
    # the library's own bounds, read from its file (not imported: its words, not its working, are what is checked)
    infrastructure = (STATIC.parents[1] / "machines" / "infrastructure.py").read_text(encoding="utf-8")
    kept = {name: int(value.replace("_", "")) for name, value in
            re.findall(r"^(MAX_POINTS|MAX_VERTICES|NAME) = ([\d_]+)\b", infrastructure, re.MULTILINE)}
    assert kept == {"MAX_POINTS": 20000, "MAX_VERTICES": 400000, "NAME": 80}
    layers_of = _body(js, "function layersOf(list) {")
    assert "if (layers.length >= MAX_LAYERS) continue;  // counted (ids), not listed" in layers_of
    assert "return { layers, unlisted: ids.size - layers.length };" in layers_of
    prepare = _body(js, "function prepareLayer(answer) {")
    assert "answer.parts.slice(0, MAX_PARTS)" in prepare
    assert "if (points.n >= MAX_LAYER_POINTS) { cut += n - i; break; }" in prepare
    assert "if (ln + m > MAX_LAYER_VERTICES) { cut++; continue; }" in prepare
    names = _body(js, "function nameLayers(c, g, boxes, shown) {")
    assert "if (put >= LAYER_NAMES || tried++ >= LAYER_NAMES * 4) break;" in names
    for head in ("function paintLines(c, g, fr, l, geo, names) {", "function paintPoints(c, g, fr, l, geo, names) {",
                 "function nameLayers(c, g, boxes, shown) {", "function featureAt(x, y, by) {",
                 "function prepareLayer(answer) {"):
        assert "createElement" not in _body(js, head), head


def test_the_layers_paint_is_kept_apart_from_the_places_updates(js):
    """The plan's critique, S8: the layers' marks and lines are a third offscreen layer between the map and the
    routes, painted again only when the view, the layers on, their versions or the colours change, never for an update
    of the places (every few seconds); their names are drawn with the places' names, which are painted at each update
    anyway, and never over a place's dot or name."""
    infra = _body(js, "function infraLayer(g, fr, ratio, W, H) {")
    assert "`${viewKey(g, W, H, ratio)}|${layersKey}`" in infra and "version" not in infra
    assert "layersKey = layersShown.map(({ l }) => `${l.key} ${l.mark} ${l.slot} ${l.namesFrom}`)" in js
    # a layer's key holds its version
    assert "id, key: `${id}\\n${version}`, version," in _body(js, "function layersOf(list) {")
    assert "stamp].join('|');" in js.split("const viewKey = ", 1)[1].split("\n", 1)[0]  # the view, and the colours
    places = _body(js, "function placesLayer(g, ratio, W, H) {")
    assert "const key = `${viewKey(g, W, H, ratio)}|${version}|${picked}|${infraStamp}`;" in places
    assert "nameLayers(c, g, boxes, shown);" in _body(js, "function drawLabels(c, g, shown) {")
    names = _body(js, "function nameLayers(c, g, boxes, shown) {")
    assert "boxes.push({ x: p.x - r, y: p.y - r, w: 2 * r, h: 2 * r });" in names  # a place's dot is kept clear
    render = _body(js, "function render(now) {")
    steps = ("baseLayer(g, fr, ratio, W, H)", "infraLayer(g, fr, ratio, W, H)", "drawRoutes(g, fr, now);",
             "placesLayer(g, ratio, W, H)")
    assert [render.index(s) for s in steps] == sorted(render.index(s) for s in steps)


def test_no_day_and_night_and_the_equator_stressed(js):
    """The plan's critique, S9: day and night, the sun's mark, a `sun` key and their switch are left out of this
    version. The stressed equator stays: the graticule's sixth parallel from -75 degrees, after its 24 meridians, drawn
    again more strongly."""
    for word in (r"\bsubsolar", r"\btwilight", r"\bterminator", r"\bnight\b", r"day and night"):
        assert not re.search(word, js, re.IGNORECASE), word
    code = "\n".join(line.split("//", 1)[0] for line in js.split("\n"))  # the comments left out: "as globe.js's sun"
    for word in (r"\bsun\b", r"\bsubsolar\b"):
        assert not re.search(word, code, re.IGNORECASE), word
    assert "...Array.from({ length: 24 }, (_, m) =>" in js and "[-180 + i * 2, -75 + p * 15]" in js
    assert "const EQUATOR = 24 + 5;" in js and -75 + (29 - 24) * 15 == 0
    base = _body(js, "function baseLayer(g, fr, ratio, W, H) {")
    assert "b.beginPath(); polyline(b, graticuleLines()[EQUATOR], g);" in base
    assert base.index("graticuleLines()[EQUATOR]") < base.index("b.strokeStyle = css(k.muted, 0.3); b.stroke();")


def _marks(points: list[tuple[float, float]], mark: str) -> list[tuple[float, float, int]]:
    """paintPoints' marks for points on the screen, as the page has it: the points of each cell of the grid gathered,
    and a cell with more than one marked at their middle, kept in its cell by as far as its mark and ring reach
    (markPath: a diamond's points at 1.25 times its size). (x, y, how many) a mark."""
    cells: dict[tuple[int, int], list[tuple[float, float]]] = {}
    for x, y in points:
        cells.setdefault((math.floor(x / CELL), math.floor(y / CELL)), []).append((x, y))
    out = []
    for (col, row), got in cells.items():
        n = len(got)
        r = 3.5 if n == 1 else 6 if n < 10 else 7.5 if n < 100 else 9.5 if n < 1000 else 11
        pad = 0 if n == 1 else min(CELL / 2, (r + 1.5) * (1.25 if mark == "diamond" else 1))
        x, y = sum(p[0] for p in got) / n, sum(p[1] for p in got) / n
        out.append((min(max(x, col * CELL + pad), col * CELL + CELL - pad),
                    min(max(y, row * CELL + pad), row * CELL + CELL - pad), n))
    return sorted(out)


def test_a_clusters_mark_stays_in_its_cell(js):
    """A cell's mark is at the middle of its features, kept in its cell by as much as the mark and its ring reach: the
    marks of two cells side by side, their features either side of the grid line, then do not lie on each other and
    their counts stay apart (they were 2 px apart, their counts printed over each other: the 1.65.0 review). The
    largest, which reach past half a cell, stay at its middle, a cell from their neighbour's."""
    points = _body(js, "function paintPoints(c, g, fr, l, geo, names) {")
    assert "const n = count[cell], r = n === 1 ? 3.5 : n < 10 ? 6 : n < 100 ? 7.5 : n < 1000 ? 9.5 : 11;" in points
    assert "const wide = l.mark === 'diamond' ? 1.25 : 1;" in points
    assert "const pad = n === 1 ? 0 : Math.min(CELL / 2, (r + 1.5) * wide);  // one feature is where it is" in points
    assert "const x = clamp(sx[cell] / n, left + pad, left + CELL - pad);" in points
    assert "const y = clamp(sy[cell] / n, top + pad, top + CELL - pad);" in points
    assert "for (const m of mine) markPath(c, l.mark, m.x, m.y, m.r + 1.5);" in points  # its ring
    path = _body(js, "function markPath(c, mark, x, y, r) {")
    assert "c.moveTo(x, y - r * 1.25); c.lineTo(x + r * 1.25, y);" in path  # a diamond reaches further
    assert "c.rect(x - r * 0.9, y - r * 0.9," in path
    # the review's case, measured in Edge on its stand-ins: ten points either side of the grid line at x = 720
    west = [(718.4 + i * 0.1, 252 + (i % 3) - 1) for i in range(10)]
    east = [(720.6 + i * 0.1, 252 + (i % 3) - 1) for i in range(10)]
    (a, _, n), (b, _, m) = _marks(west + east, "circle")
    assert (n, m) == (10, 10) and b - a == 18  # 2.2 px apart before
    (a, _, _), (b, _, _) = _marks(west + east, "diamond")
    assert b - a == 22.5
    for mark in ("circle", "square", "diamond"):
        for each in (2, 9, 10, 99, 100, 999, 1000, 5000):
            (a, _, n), (b, _, m) = _marks([(719.99, 252.0)] * each + [(720.01, 252.0)] * each, mark)
            r = 3.5 if each == 1 else 6 if each < 10 else 7.5 if each < 100 else 9.5 if each < 1000 else 11
            reach = (r + 1.5) * (1.25 if mark == "diamond" else 1)
            assert b - a >= min(2 * reach, CELL) and b - a >= 15, (mark, each, b - a)  # apart, and their counts


class _Cells:
    """paintLines' lists of the lines through each cell, as the page has them: `cross(line, k)` as its `cell(x, y)` is
    told a point of line `line` (an id from 1) in cell k; `at(k)` the lines (from 0) cell k lists, as featureAt reads
    them."""

    def __init__(self, size: int, most: int = 8):
        self.head, self.last, self.held = [-1] * size, [0] * size, [0] * size
        self.next: list[int] = []
        self.line: list[int] = []
        self.most = most

    def cross(self, line: int, k: int) -> None:
        if self.last[k] == line or self.held[k] >= self.most:
            return
        self.last[k] = line
        self.held[k] += 1
        self.next.append(self.head[k])
        self.line.append(line - 1)
        self.head[k] = len(self.line) - 1

    def at(self, k: int) -> list[int]:
        out, e = [], self.head[k]
        while e >= 0:
            out.append(self.line[e])
            e = self.next[e]
        return out


def test_every_line_through_a_cell_is_found_by_the_pointer(js):
    """A line leaves its number in each cell it crosses, in a list each cell keeps (LINE_CELL at most; where more cross
    it, the cells round it hold them), and the pointer takes the nearest of every line the nine cells round it list.
    A cell kept one line before, the last painted: a line that another crossed later in the same cells was named as
    that other, or not found at all (the 1.65.0 review)."""
    lines = _body(js, "function paintLines(c, g, fr, l, geo, names) {")
    assert "cells[Math.floor(y / CELL) * grid.cols + Math.floor(x / CELL)] = id" not in lines
    for step in ("const head = new Int32Array(size).fill(-1), last = new Int32Array(size),",
                 "if (last[k] === id || held[k] >= LINE_CELL) return;", "last[k] = id;", "held[k]++;",
                 "next.push(head[k]);", "line.push(id - 1);", "head[k] = line.length - 1;",
                 "lineCells.push({ l, geo, head, next, line });"):
        assert step in lines, step
    found = _body(js, "function featureAt(x, y, by) {")
    assert "for (const cell of round) for (let e = head[cell]; e >= 0; e = next[e]) lines.add(line[e]);" in found
    assert "if (near.d >= LINE_REACH[by] || near.d >= bestD) continue;" in found  # the nearest within reach
    cells = _Cells(4)
    for k in (0, 1, 2, 1):  # line 1 through cells 0, 1 and 2, and back into 1
        cells.cross(1, k)
    for k in (1, 2, 3):  # line 2, painted after it, through 1, 2 and 3
        cells.cross(2, k)
    assert [cells.at(k) for k in range(4)] == [[0], [1, 0], [1, 0], [1]]  # each line once a cell, both found
    many = _Cells(1)
    for line in range(1, 13):
        many.cross(line, 0)
    assert many.at(0) == [7, 6, 5, 4, 3, 2, 1, 0] and "const LINE_CELL = 8;" in js  # a full cell keeps its first


def test_the_focus_stays_when_an_earlier_credit_or_button_leaves(js):
    """A credit's link or a layer's button keeps its node while it is listed. Those no longer listed are taken out
    first, and arrange moves only what is out of order (steady, as the table's rows): an update that takes an earlier
    one away moves none of the others, so the focus on one stays (it fell to the page's body when an earlier credit
    or button left: the 1.65.0 review)."""
    arrange = _body(js, "function arrange(box, nodes, end = null) {")
    assert "node && node !== end; node = node.nextSibling) now.set(node, i++);" in arrange  # where each stands now
    assert "const stay = steady(nodes.map((node) => (now.has(node) ? now.get(node) : -1)));" in arrange
    assert "if (!stay.has(k)) box.insertBefore(nodes[k], ref);" in arrange
    layers = _body(js, "function renderLayers() {")
    gone = "for (const [id, it] of layerButtons) if (!kept.has(id)) it.b.remove();"
    assert gone in layers and "insertBefore" not in layers and "let it = layerButtons.get(l.id);" in layers
    assert layers.index(gone) < layers.index("arrange(layerBar, [...kept.values()].map((it) => it.b), layerWhy);")
    assert "layerBar.append(layerHead, layerWhy);" in js  # the buttons stand between the row's head and its words
    # as the page has it (_reorder is the table's, the same steps): an earlier one gone, nothing moves; one put in,
    # it alone; a reorder, the fewest
    assert _reorder(list("abc"), list("bc")) == (list("bc"), 0)
    assert _reorder(list("bc"), list("abc")) == (list("abc"), 1)
    assert _reorder(list("abc"), list("cba")) == (list("cba"), 2)


def test_a_layer_the_page_does_not_answer_for_is_not_waited_on_for_good(js):
    """A load whose promise never settles (a request that hangs) left its layer "loading…" for good and never asked
    for again (the 1.65.0 review): after LOAD_MS it is not loaded, says why, and is asked for again RETRY_MS later; an
    answer that comes after the deadline is still taken. Its timer goes with the layer (pruneLayers), and so with the
    last globe: nothing runs after destroy."""
    assert "const LOAD_MS = 60_000;" in js and "const RETRY_MS = 60_000;" in js
    ask = _body(js, "function askLayer(l, load) {")
    assert "entry.timer = setTimeout(() => {" in ask and "}, LOAD_MS);" in ask
    words = "settle(null, `the page gave no answer for it within ${LOAD_MS / 1000} s`);"
    assert f"if (entry.state === 'loading') {words}" in ask
    assert "clearTimeout(entry.timer);" in ask  # an answer in time: no deadline left behind
    assert "if (was && (was.state !== 'failed' || Date.now() < was.retry)) return;" in ask
    assert "retry: Date.now() + RETRY_MS" in ask
    prune = _body(js, "function pruneLayers() {")
    assert "if (!listed.has(key)) { clearTimeout(entry.timer); layerData.delete(key); }" in prune
    assert "pruneLayers();" in _body(js, "function destroy() {")


def test_the_few_are_painted_over_the_many(js):
    """Of the lines, then of the marks, the layer with the most features is painted first, so the few stay on top of
    the many: an exchange point's diamond over the data centres round it (it was under them: seen in Edge, 1.65.0), a
    cable over the lines on land; layers as many keep the spec's order (a stable sort)."""
    paint = _body(js, "function paintLayers(c, g, fr, list) {")
    most = "const most = (kind) => list.filter(({ geo }) => geo[kind]).sort((a, b) => b.geo[kind].n - a.geo[kind].n);"
    assert most in paint
    assert paint.index("of most('lines')) paintLines(") < paint.index("of most('points')) paintPoints(")


def test_the_tabs_globe_line_names_what_the_script_reads(js):
    """apps/tabs.py says what a tab page's `globe` may hold: the script reads each key it names (normal, placeOf), the
    layers' through layersOf; `layer_hook` is the page's to ask, as the script's own words say. No address in it."""
    from liminal_libs.apps import tabs

    line = tabs.__doc__.split("- `globe`:", 1)[1].split("\n- `flows`:", 1)[0]
    assert not re.search(r"\w+://", line) and "liminal-globe.js" in line
    normal = _body(js, "function normal(spec) {")
    for key in ("home", "origins", "local", "attribution", "updated", "note", "kinds", "showing", "layers"):
        assert f"`{key}`" in line and f"s.{key}" in normal, key
    for key in ("hosts", "programs", "seconds"):
        assert f"`{key}`" in line and f"o.{key}" in normal, key
    for key in ("id", "label", "country", "city", "asn", "org", "count", "bytes", "kind", "ports"):
        assert re.search(rf"\b{key}\b", line) and f"o.{key}" in normal, key
    assert re.search(r"\blat, lon\b", line) and "const p = placeOf(o)" in normal  # an origin's point, as home's
    assert "{count,\n  bytes, hosts}" in line and "num(l.hosts)" in normal  # the local peers' sum
    assert "`layer_hook`" in line and "layer_hook}" in js.split("(() => {", 1)[0]
    assert "`Index.layers()`" in line and "`Index.layer()`" in line


LAYERS_CODE = ("function arrange(box, nodes, end = null) {", "function markPath(c, mark, x, y, r) {",
               "function prepareLayer(answer) {", "function pruneLayers() {", "function askLayer(l, load) {",
               "function recall(name) {", "function remember(name, chosen) {", "function creditOf(a) {",
               "function layersOf(list) {", "function shownLayers() {", "function forgetMarks() {",
               "function infraLayer(g, fr, ratio, W, H) {", "function paintLayers(c, g, fr, list) {",
               "function paintLines(c, g, fr, l, geo, names) {", "function paintPoints(c, g, fr, l, geo, names) {",
               "function nearLine(L, j, x, y, g, fr) {", "function featureAt(x, y, by) {",
               "function placesLayer(g, ratio, W, H) {", "function nameLayers(c, g, boxes, shown) {",
               "function featureTip(f, line) {", "function renderLayers() {", "function switchLayer(id) {",
               "function renderAttribution() {", "function renderTable() {", "function update(next, more) {",
               "function draw(el, spec, opts) {")


def test_the_layers_code_keeps_lines_within_120_characters(js):
    """The project's rule, lines at most 120 characters, kept by what 1.65.0 added or changed in the script: its head
    comment and the functions of the layers (the lines elsewhere it did not touch are 1.63.0's)."""
    head = js.split("(() => {", 1)[0]
    assert max(len(line) for line in head.split("\n")) <= 120
    for name in LAYERS_CODE:
        long = [line for line in _body(js, name).split("\n") if len(line) > 120]
        assert not long, (name, long)
