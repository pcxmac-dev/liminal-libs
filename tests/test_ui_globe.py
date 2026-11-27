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
the port is checked as the page has it.

The 96x zoom (the user, 2026-11-19: "i need to zoom in a few more times maybe 96x") the same way: MAX_ZOOM 96 by the
wheel, two fingers and the keys; the 1:10m map past 12x and GSHHG's coast tiles past 24x, read as their builder wrote
them, only those on the canvas asked for, the nearest first and no more than are kept, each once and TILE_LOADS at a
time, none while the globe glides, MAX_TILES kept and every one let go with the last globe; GSHHG credited while it is
drawn, with its notice and both licences it names beside the tiles; and what keeps 96x smooth and right:
the pieces skipped out of sight (their reach holds every point), the runs off the canvas cut short (nothing on the
canvas changes, filled or stroked: checked point by point), the view's key and the 4-byte points far under a pixel."""
from __future__ import annotations

import bisect
import glob
import hashlib
import json
import math
import os
import random
import re
import struct
from array import array
from pathlib import Path

import pytest

from liminal_libs.ui import STATIC

WORLD = STATIC / "vendor" / "world"
MAPS = ("countries-110m.json", "countries-50m.json", "countries-10m.json")
COAST = WORLD / "coast-h"  # GSHHG 2.3.7's coasts and borders in tiles (liminal-charts' tools/build_coastlines.py)
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
    assert js.rstrip().endswith("window.LiminalGlobe = { draw, decodeTopo, describe };\n})();".rstrip())
    assert js.count("window.LiminalGlobe") == 1 and "window.Globe" not in js  # the charts app's own global stays its own
    draw = _body(js, "function draw(el, spec, opts) {")
    assert "throw new TypeError(" in draw  # no element, no globe
    assert "there.update(spec, opts || {});" in draw and "return there.handle;" in draw and "return g.handle;" in draw
    assert "if (g.left()) g.destroy();" in draw  # a globe whose element left the page goes with the next draw
    # 1.105.0: the handle's update takes the draw's options too (the platform's loaders handed again with the spec)
    assert "const handle = { update: (next, more) => update(next, more), destroy, describe: (key) =>" in js
    destroy = _body(js, "function destroy() {")
    for gone in ("cancelAnimationFrame(raf)", "seenBy.disconnect()", "sized.disconnect()", "themed.disconnect()",
                 "unlisten(motion, onMotion)", "unlisten(scheme, recolour)", "unlisten(dpr, onRatio)",
                 "document.removeEventListener('visibilitychange', onVisibility)",
                 "document.removeEventListener('scroll', onScroll, { capture: true })", "tip.remove()", "root.remove()",
                 "globes.delete(self)"):
        assert gone in destroy, gone  # nothing runs or listens once the last globe is destroyed
    # nor holds the 1:50m and 1:10m maps or a coast tile (the 1:110m are small)
    last = destroy.split("if (!globes.size) {", 1)[1].split("}", 1)[0]
    assert all(step in last for step in ("maps.fine = null;", "maps.finest = null;", "forgetCoast();"))
    assert _body(js, "function update(next, more) {").split("\n")[1].strip() == "if (destroyed) return;"


def test_decode_topo_reads_quantized_and_plain_arcs(js):
    """globe.js's decodeTopo, exported: a quantized topology's arcs are steps from the point before, a plain one's the
    points themselves; and the vendored maps decode, as the page does, into places on the Earth."""
    decode = _body(js, "function decodeTopo(t) {")
    assert "const quantized = !!t.transform;" in decode
    assert "if (quantized) { x += dx; y += dy; } else { x = dx; y = dy; }" in decode
    assert "return [x * sx + tx, y * sy + ty];" in decode
    # the page's own maps are read alike, straight into unit vectors (the 1:10m's 477,000 points not made pairs first)
    prepare = _body(js, "function prepare(t) {")
    assert "const quantized = !!t.transform;" in prepare and "decodeTopo(" not in prepare
    assert "if (quantized) { x += dx; y += dy; } else { x = dx; y = dy; }" in prepare
    assert "const lon = x * sx + tx, lat = y * sy + ty, c = Math.cos(lat * rad);" in prepare
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
    outside the globe, the holes (the Caspian Sea's) the other way. The 1:10m map's are so but for 14 atolls of a few
    points, flat as they are rounded (the Maldives' and others, 0.04 km² at most, under a pixel at 96x): turnOf works
    out their own way round, and where the 1:10m map is drawn (past 12x) the horizon is off the canvas and a ring that
    does not reach the canvas's sight is skipped, so none of them is ever closed along it."""
    land = "for (const ring of map.land) if (inSight(ring.cap, 0, fr.C, sight)) ringPath(pen, ring, g, fr);"
    assert land in js and "b.fill('evenodd');" in js
    clip = _body(js, "function ringPath(c, ring, g, fr) {")
    assert "c.arc(g.cx, g.cy, g.r, to, to + turn * best, turn < 0);" in clip  # along the rim, the ring's way round
    assert "return d > TAU - 1e-9 ? 0 : d;" in clip  # the two sides of a cut meeting on the rim are one point
    assert "return area < 0 ? 1 : -1;" in _body(js, "function turnOf(v) {")
    assert "return { v: kept, turn: turnOf(v), cap: capOf(kept) };" in _body(js, "function landRing(ring, arcs) {")
    for name in MAPS:
        topo = json.loads((WORLD / name).read_text(encoding="utf-8"))
        rings = _rings(topo, _decode(topo))
        assert rings and all(points[0] == points[-1] for _, points in rings)
        against = [(k, points) for k, points in rings if _turn(points) != (1 if k == 0 else -1)]
        if name != "countries-10m.json":
            assert not against, name
            continue
        assert len(against) == 14 and all(k == 0 and len(points) <= 5 for k, points in against)
        assert max(abs(_area(points)) * 2 * 6371.0 ** 2 for _, points in against) < 0.05  # km²: under a pixel at 96x


def _area(points: list[tuple[float, float]]) -> float:
    """The signed area turnOf sums for a ring (steradians, as the page's atan2 terms add up to half of it)."""
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
    return area


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
    assert "if (!now) return;  // still: no lights" in _body(js, "function drawLights(picked, now) {")
    assert routes.count("drawLights(picked, now);") == 2  # with the heat (1.69.0) and without it
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
    assert "zoom > FINE_ZOOM && maps.fine ? maps.fine" in js.split("const mapNow = () => (", 1)[1].split(";", 1)[0]
    assert "const loadCoarse = mapLoader('countries-110m.json', 'coarse');" in js
    assert "const loadFine = mapLoader('countries-50m.json', 'fine');" in js
    assert "if (key !== 'coarse' && !globes.size) return true;" in js  # every globe went meanwhile: not kept
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
    """world-atlas 2.0.2's countries-110m.json, countries-50m.json and countries-10m.json, as the charts app has them,
    with world-atlas's ISC licence and a VERSION naming the release, the data's source and each file's size and sha256
    (counted with LF line ends, as a checkout that turns them to CRLF would otherwise differ). And coast-h/, the
    charts' GSHHG tiles: GSHHG 2.3.7's notice and the words of the two licences it names beside them (the LGPL-3.0's,
    and the GPL-3.0's it builds on: the Free Software Foundation's text, verbatim), and VERSION naming GSHHG, its
    licence, its source and its builder, each text file's size and sha256 and a sha256 over the tiles."""
    licence = (WORLD / "LICENSE").read_text(encoding="utf-8")
    assert "Copyright 2013-2019 Michael Bostock" in licence
    assert "Permission to use, copy, modify, and/or distribute this software for any purpose" in licence
    version = (WORLD / "VERSION").read_text(encoding="utf-8")
    assert version.startswith("world-atlas 2.0.2 (ISC)") and "Natural Earth (public domain)" in version
    for name in MAPS:
        data = (WORLD / name).read_bytes().replace(b"\r\n", b"\n")
        assert f"{name}: {len(data):,} bytes, sha256 {hashlib.sha256(data).hexdigest()}" in version, name
    assert sorted(p.name for p in WORLD.iterdir()) == sorted(["LICENSE", "VERSION", "coast-h", *MAPS])
    # GSHHG's tiles: its notice, the licence's words, and VERSION's words for them
    notice = (COAST / "LICENSE.TXT").read_text(encoding="utf-8")
    assert "GSHHG is distributed under the GNU Lesser General Public" in notice and "version 3 or later" in notice
    lgpl = (COAST / "COPYING.LESSERv3").read_text(encoding="utf-8")
    assert lgpl.lstrip().startswith("GNU LESSER GENERAL PUBLIC LICENSE") and "Version 3, 29 June 2007" in lgpl
    assert "Refer to the files COPYINGv3 and COPYING.LESSERv3." in " ".join(notice.split())  # the two it names
    gpl = (COAST / "COPYINGv3").read_bytes().replace(b"\r\n", b"\n")
    assert gpl.lstrip().startswith(b"GNU GENERAL PUBLIC LICENSE") and b"Version 3, 29 June 2007" in gpl
    # the FSF's text as it publishes it (gpl-3.0.txt), byte for byte: a licence's words are never changed
    assert hashlib.sha256(gpl).hexdigest() == "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
    for words in ("GSHHG 2.3.7 (Wessel and Smith)", "LGPL-3.0", "tools/build_coastlines.py", "gshhg-bin-2.3.7.zip",
                  "coast-h/LICENSE.TXT is GSHHG's notice", "coast-h/COPYING.LESSERv3 the licence's words",
                  "coast-h/COPYINGv3 is the GNU General Public License version 3's words"):
        assert words in " ".join(version.split()), words
    for name in ("index.json", "LICENSE.TXT", "COPYING.LESSERv3", "COPYINGv3"):
        data = (COAST / name).read_bytes().replace(b"\r\n", b"\n")
        assert f"coast-h/{name}: {len(data):,} bytes, sha256 {hashlib.sha256(data).hexdigest()}" in version, name
    tiles = sorted(p.name for p in COAST.iterdir() if p.suffix == ".bin")
    digest = hashlib.sha256("".join(f"{n} {hashlib.sha256((COAST / n).read_bytes()).hexdigest()}\n" for n in tiles)
                            .encode()).hexdigest()
    total = sum((COAST / n).stat().st_size for n in tiles)
    assert f"coast-h/*.bin: {len(tiles)} files, {total:,} bytes;" in version and f"sha256 {digest}" in version
    index = json.loads((COAST / "index.json").read_text(encoding="utf-8"))
    assert sorted(f"{n}.bin" for n in index["tiles"]) == tiles and len(tiles) == 433
    assert index["source"].startswith("GSHHG 2.3.7 high resolution (LGPL-3.0)")
    assert sorted(p.name for p in COAST.iterdir() if p.suffix != ".bin") == ["COPYING.LESSERv3", "COPYINGv3",
                                                                              "LICENSE.TXT", "index.json"]


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
    coast = {f"ui/static/vendor/world/coast-h/{name}" for name in ("index.json", "LICENSE.TXT", "COPYING.LESSERv3",
                                                                   "COPYINGv3", "50_10.bin")}
    assert world | coast <= files
    assert files - _shipped(package, patterns) == set(), "not shipped: add a glob for them to [tool.setuptools.package-data]"
    # the one glob 1.53.0 had takes ui/static's own files and none of the map's (setuptools drops the folders it matches)
    assert "ui/static/liminal-globe.js" in _shipped(package, ["ui/static/*"]) and not world & _shipped(package, ["ui/static/*"])
    # and vendor/world's glob none of the coast tiles: they need theirs
    assert not coast & _shipped(package, ["ui/static/vendor/world/*"])


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
    render = _body(js, "function render(now) {")
    assert "askLayer(l, load, byArea ? { zoom: 1 } : undefined);" in render
    ask = _body(js, "function askLayer(l, load, more) {")
    assert ("try { asked = Promise.resolve(more ? load(l.id, more) : load(l.id)); } catch (e) { asked = "
            "Promise.reject(e); }") in ask
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
    """The globe asks for nothing itself but the map beside it (its maps, the coast tiles' index and a tile, all
    through `world`): a layer's geometry comes through the page's `load`."""
    assert len(re.findall(r"\bfetch\(", js)) == 1
    assert "const world = (name) => fetch(`${HERE}vendor/world/${name}`, { credentials: 'same-origin' });" in js
    asked = re.findall(r"\bworld\(([^)]*)\)", js.split("const world = ", 1)[1])
    assert asked == ["name", "'coast-h/index.json'", "`coast-h/${t.name}.bin`"], asked
    for other in ("XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "importScripts", "new Worker"):
        assert other not in js, other


def test_the_layers_are_bounded(js):
    """At most MAX_LAYERS 16 layers listed (1.104.0: 13 and more to come) (more counted and said), 20,000 points and 400,000 line vertices a layer (as
    machines/infrastructure.py keeps at most), 16 parts an answer, 12 names on the map at once; no DOM node a feature
    (they are thousands: the plugin's own tables count them)."""
    for line in ("const MAX_LAYERS = 16;", "const MAX_LAYER_POINTS = 20000;", "const MAX_LAYER_VERTICES = 400000;",
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
    steps = ("baseLayer(g, fr, ratio, W, H, tiles)", "infraLayer(g, fr, ratio, W, H)", "drawRoutes(g, fr, now);",
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
    base = _body(js, "function baseLayer(g, fr, ratio, W, H, tiles) {")
    assert "b.beginPath(); polyline(pen, graticuleLines()[EQUATOR], g); pen.done();" in base
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
    ask = _body(js, "function askLayer(l, load, more) {")
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
               "function prepareLayer(answer) {", "function pruneLayers() {", "function askLayer(l, load, more) {",
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
    for name in LAYERS_CODE + ZOOM_CODE:
        long = [line for line in _body(js, name).split("\n") if len(line) > 120]
        assert not long, (name, long)
    # and every line naming what the zoom added
    words = ("FINEST_ZOOM", "COAST_ZOOM", "MAX_TILE", "TILE_LOADS", "TILE_REACH", "PIECE", "PEN_MARGIN", "COAST_CREDIT",
             "coast.", "inSight", "facing", "mapNow", "loadFinest", "const world")
    long = [line for line in js.split("\n") if any(w in line for w in words) and len(line) > 120]
    assert not long, long


# -- the 96x zoom (2026-11-19) ----------------------------------------------------------------------------------------
ZOOM_CODE = ("function capOf(v, from = 0, to = v.length) {", "function piecesOf(lines) {", "function sightOf(g) {",
             "function trimmed(c, w, h) {", "function landRing(ring, arcs) {", "function prepare(t) {",
             "function coastIndex(d) {", "function prepareTile(buf, t, index) {", "function keepTiles() {",
             "function askTiles(want) {", "function forgetCoast() {", "function strokePieces(c, P, g, fr, sight) {",
             "function baseLayer(g, fr, ratio, W, H, tiles) {", "function coastTiles(g, fr, ask) {",
             "function render(now) {", "function destroy() {")


def _radius(zoom: float, w: float = 1240, h: float = 520) -> float:
    """geometry()'s radius of the globe, as the page has it (a canvas 520 px high at most: .lg-canvas's clamp)."""
    return max(40, (min(w, h) / 2 - 12) * 0.88) * zoom


def _unit(lon: float, lat: float) -> tuple[float, float, float]:
    rad = math.pi / 180
    return (math.cos(lat * rad) * math.cos(lon * rad), math.cos(lat * rad) * math.sin(lon * rad), math.sin(lat * rad))


def _angle(a, b) -> float:
    """Degrees between two unit vectors."""
    return math.degrees(math.acos(max(-1.0, min(1.0, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]))))


def _f32(values) -> list[float]:
    """Numbers as a Float32Array keeps them (4-byte floats)."""
    return array("f", values).tolist()


def test_it_zooms_to_96x_by_the_wheel_two_fingers_and_the_keys(js):
    """The user, 2026-11-19: "i need to zoom in a few more times maybe 96x". MAX_ZOOM is 96, and every way in goes
    through zoomAt, which holds it there: the wheel and a trackpad's pinch, two fingers, + and − and their buttons
    (ten presses of + from the whole globe). Its words say "96×"; at its nearest a wheel's notch scrolls the page."""
    assert "  const MAX_ZOOM = 1024;\n" in js and "const MAX_ZOOM = 96;" not in js  # 1024x since 1.68.1
    assert "i need zoom up to 1024x" in js
    assert "i need to zoom in a few more times maybe 96x" in js.split("(() => {", 1)[0]
    assert "const next = clamp(want, 1, MAX_ZOOM);" in _body(js, "function zoomAt(clientX, clientY, want) {")
    assert "zoomAt(r.left + r.width / 2, r.top + r.height / 2, zoom * f);" in _body(js, "function zoomBy(f) {")
    assert "zoomAt(x, y, zoom * (d / pinch.d));" in _body(js, "function pinchMove() {")
    wheel = _body(js, "canvas.addEventListener('wheel', (e) => {")
    assert "if (zoomAt(e.clientX, e.clientY, zoom * Math.exp(-dy * (e.ctrlKey ? 0.01 : 0.0015))) || e.ctrlKey)" in wheel
    keys = _body(js, "canvas.addEventListener('keydown', (e) => {")
    assert "{ zoomBy(1.6); sayZoom(); }" in keys and "{ zoomBy(1 / 1.6); sayZoom(); }" in keys
    assert "button('+', 'Zoom in', () => { zoomBy(1.6); sayZoom(); });" in js
    assert 1.6 ** 14 < 1024 < 1.6 ** 15  # fifteen presses (ten took it to 96x)
    assert "zoom >= 10 ? zoom.toFixed(0) : zoom.toFixed(1)" in _body(js, "function zoomText() {")
    assert f"{1024:.0f}×" == "1024×" and 223_000 < _radius(1024) < 224_000  # some 30 m a pixel (6,371 km)
    assert 6371e3 / _radius(1024) < 30


def test_the_finest_map_only_past_twelve_times(js):
    """The 1:10m outlines (3.7 MB) are asked for only once a globe is zoomed past 12x and drawn from then on; one copy
    for every globe on the page, not kept when every globe went while it came, let go with the last globe."""
    assert "  const FINEST_ZOOM = 12;  // " in js
    assert "if (zoom > FINEST_ZOOM && !maps.finest) loadFinest();" in _body(js, "function render(now) {")
    assert "const loadFinest = mapLoader('countries-10m.json', 'finest');" in js
    assert js.split("const mapNow = () => (", 1)[1].startswith("zoom > FINEST_ZOOM && maps.finest ? maps.finest")
    base = _body(js, "function baseLayer(g, fr, ratio, W, H, tiles) {")
    assert "const map = mapNow();" in base and "map === maps.finest ? 'finest'" in base  # its paint keyed by its map
    assert "const maps = { coarse: null, fine: null, finest: null };" in js


class _Tiles:
    """askTiles, keepTiles and forgetCoast as the page has them, run on names: `tiles` in the Map's order (the least
    lately drawn first), a token (an object) while a tile is on its way, else its points; `asked` what was sent for."""

    def __init__(self, most: int = 120, points: int = 1_000_000, loads: int = 4, retry: float = 60.0):
        self.tiles: dict[str, object] = {}
        self.failed: dict[str, float] = {}
        self.loading = self.points = 0
        self.most, self.most_points, self.loads, self.retry = most, points, loads, retry
        self.asked: list[tuple[str, object]] = []

    def ask(self, want: list[str], now: float) -> None:
        for name in want:
            had = self.tiles.get(name)
            if had is not None:  # here, or on its way: put last, the latest drawn
                del self.tiles[name]
                self.tiles[name] = had
                continue
            if self.loading >= self.loads or now < self.failed.get(name, 0):
                continue
            token = object()
            self.tiles[name] = token
            self.loading += 1
            self.asked.append((name, token))

    def settle(self, name: str, token: object, points: int | None, now: float) -> None:
        """Its answer, a tile of `points` points or None (it could not be had); then `.finally`."""
        if self.tiles.get(name) is token:
            if points is not None:
                self.tiles[name] = points
                self.points += points
                self.keep()
            else:
                del self.tiles[name]
                self.failed[name] = now + self.retry
        self.loading -= 1

    def keep(self) -> None:
        for name, t in list(self.tiles.items()):
            if len(self.tiles) <= self.most and self.points <= self.most_points:
                return
            if not isinstance(t, int):  # on its way
                continue
            del self.tiles[name]
            self.points -= t

    def forget(self) -> None:
        self.tiles.clear()
        self.failed.clear()
        self.points = 0

    def token(self, name: str) -> object:
        return next(t for n, t in reversed(self.asked) if n == name)


def test_the_coast_tiles_are_asked_for_once_a_few_at_a_time_and_kept_within_bounds(js):
    """Past COAST_ZOOM a globe asks for the tiles on its canvas and draws those here, the map's own coasts and borders
    under them until every one is in: a tile on its way is not asked for again, TILE_LOADS at most are on their way
    from every globe, one that could not be had is not asked for again before RETRY_MS, MAX_TILES (and MAX_TILE_POINTS
    of their points) are kept, the least lately drawn let go first and never one on its way, and none is asked for at
    24x or nearer, or while the globe glides. All go with the last globe, and an answer that comes after is not kept.
    Checked by the page's statements and by their port, run."""
    for line in ("const COAST_ZOOM = 24;", "const MAX_TILES = 120;", "const MAX_TILE_POINTS = 1_000_000;",
                 "const TILE_LOADS = 4;"):
        assert f"  {line}  // " in js, line
    tiles = _body(js, "function coastTiles(g, fr, ask) {")
    assert tiles.split("\n")[1].strip() == "if (zoom <= COAST_ZOOM) return null;"
    assert "if (!coast.index) { if (ask) loadCoast(); return null; }" in tiles and "if (ask) askTiles(want);" in tiles
    # whole: every tile on the canvas here, not only those picked (the map's lines stay under the ones left out)
    assert "return { drawn, whole: drawn.length === round.length, key: names.join(' ') };" in tiles
    assert "const tiles = coastTiles(g, fr, !glide);" in _body(js, "function render(now) {")  # not while it glides
    base = _body(js, "function baseLayer(g, fr, ratio, W, H, tiles) {")
    assert "under = !!map && !(tiles && tiles.whole)" in base and "if (under) strokePieces(pen, map[kind], g," in base
    assert "for (const tile of tiles ? tiles.drawn : []) strokePieces(pen, tile[kind], g, fr, sight);" in base
    assert "|${which}|${tiles ? `${tiles.whole} ${tiles.key}` : ''}`;" in base  # painted again as tiles come
    ask = _body(js, "function askTiles(want) {")
    for step in ("if (had) { coast.tiles.delete(t.name); coast.tiles.set(t.name, had); continue; }",
                 "if (coast.loading >= TILE_LOADS || Date.now() < (coast.failed.get(t.name) || 0)) continue;",
                 "coast.tiles.set(t.name, token);", "coast.loading++;", "coast.points += tile.points;",
                 "if (coast.tiles.get(t.name) !== token) return;  // let go meanwhile, with the last globe",
                 "coast.failed.set(t.name, Date.now() + RETRY_MS);", ".finally(() => { coast.loading--; });"):
        assert step in ask, step
    keep = _body(js, "function keepTiles() {")
    for step in ("if (coast.tiles.size <= MAX_TILES && coast.points <= MAX_TILE_POINTS) return;",
                 "if (t.loading) continue;", "coast.tiles.delete(name);", "coast.points -= t.points;"):
        assert step in keep, step
    forget = _body(js, "function forgetCoast() {")
    assert all(s in forget for s in ("coast.index = null;", "coast.tiles.clear();", "coast.failed.clear();"))
    # the port, run: each once, a few at a time
    c = _Tiles()
    c.ask(["a"], 0)
    c.ask(["a", "a"], 0)  # drawn again (and by another globe) while it is on its way, below TILE_LOADS
    assert [n for n, _ in c.asked] == ["a"] and c.loading == 1
    c = _Tiles()
    c.ask(list("abcdef"), 0)
    assert [n for n, _ in c.asked] == list("abcd") and c.loading == 4
    c.ask(list("abcdef"), 1)  # drawn again while they are on their way: none asked twice, none more
    assert len(c.asked) == 4
    c.settle("a", c.token("a"), 1000, 2)
    c.settle("b", c.token("b"), None, 2)  # it could not be had
    c.ask(list("abef"), 3)
    assert [n for n, _ in c.asked][4:] == ["e", "f"] and "b" not in c.tiles  # b not asked again yet...
    c.ask(["b"], 2 + 59)
    assert len(c.asked) == 6
    c.settle("c", c.token("c"), 10, 62)
    c.ask(["b"], 2 + 60)
    assert [n for n, _ in c.asked][-1] == "b"  # ...but RETRY_MS later
    # bounded: the least lately drawn go first
    c = _Tiles(most=3)
    for k, name in enumerate("pqrst"):
        c.ask([name], k)
        c.settle(name, c.token(name), 10, k)
    assert list(c.tiles) == ["r", "s", "t"]
    c.ask(["r"], 9)  # r drawn again: the latest
    c.ask(["u"], 9)
    c.settle("u", c.token("u"), 10, 9)
    assert list(c.tiles) == ["t", "r", "u"] and c.points == 30
    c = _Tiles(points=25)  # and by their points
    for k, name in enumerate("vwx"):
        c.ask([name], k)
        c.settle(name, c.token(name), 10, k)
    assert list(c.tiles) == ["w", "x"] and c.points == 20
    c = _Tiles(most=1)  # never one on its way
    c.ask(["y", "z"], 0)
    c.settle("y", c.token("y"), 10, 0)
    assert list(c.tiles) == ["z"] and c.points == 0
    # the last globe goes while a tile is on its way: its answer is not kept, and the count of those on their way holds
    c.forget()
    c.settle("z", c.token("z"), 10, 1)
    assert c.tiles == {} and c.loading == 0 and c.points == 0


def _sight(w: float, h: float, zoom: float) -> float:
    """sightOf(): how far round from the middle of the view a canvas w by h shows, in radians and a little more."""
    r, half = _radius(zoom, w, h), math.hypot(w / 2, h / 2)
    return (math.asin(half / r) if r > half else math.pi / 2) + 0.01


def _pick(middles: list[tuple[str, tuple, int]], c, sight: float, most: int = 120, most_points: int = 1_000_000):
    """coastTiles' choice, as the page has it: the tiles (name, middle, the index's count of points) whose middle is
    within the sight and 0.85 of a tile (10 degrees) of the view's middle `c`, the nearest first (a stable sort, by
    the angle only); then as many of them as the cache keeps, MAX_TILES and MAX_TILE_POINTS by those counts."""
    near = sight + math.radians(8.5)
    round_ = []
    for name, middle, points in middles:
        d = math.acos(max(-1.0, min(1.0, middle[0] * c[0] + middle[1] * c[1] + middle[2] * c[2])))
        if d <= near:
            round_.append((d, name, points))
    round_.sort(key=lambda t: t[0])
    want, total = [], 0
    for _, name, points in round_:
        if len(want) >= most or total + points > most_points:
            break
        want.append((name, points))
        total += points
    return round_, want


def test_the_coast_tiles_on_the_canvas_are_picked_nearest_first_and_no_more_than_are_kept(js):
    """coastTiles asks for the tiles on the canvas nearest the middle of the view first, and only as many as the cache
    keeps (MAX_TILES, and MAX_TILE_POINTS by the index's counts, which are each tile's own: prepareTile counts its
    points so): a tile coming in then never lets go of another one on the canvas. Without it a canvas wide enough
    (or a view by a pole) wants more than is kept, and each tile in pushes out one wanted, asked for again, without
    end. Checked by the page's statements and by their port, run: on any screen up to 3,840 px wide (the canvas 520 px
    high) every tile on the canvas is picked, at 24x and nearer, from any view; on a canvas 9,000 px wide by the North
    Pole they are more than the cache keeps, the nearest are picked within its bounds and, drawn again and again, are
    each asked for once and kept, where all of them would be asked for again without end."""
    tiles = _body(js, "function coastTiles(g, fr, ask) {")
    for step in ("round.sort((a, b) => a.d - b.d);", "for (const { t } of round) {",
                 "if (want.length >= MAX_TILES || points + t.points > MAX_TILE_POINTS) break;",
                 "want.push(t);", "points += t.points;"):
        assert step in tiles, step
    assert tiles.index("round.sort(") < tiles.index("if (ask) askTiles(want);")
    index_js = _body(js, "function coastIndex(d) {")
    assert "points: count(said.shore) + count(said.borders) });" in index_js
    assert "count = (v) => Math.max(0, num(v) || 0);" in index_js
    prepare = _body(js, "function prepareTile(buf, t, index) {")
    assert "points += n;" in prepare and "return { coasts, borders, points };" in prepare
    assert "coast.points += tile.points;" in _body(js, "function askTiles(want) {")
    index = json.loads((COAST / "index.json").read_text(encoding="utf-8"))
    middles = []
    for name, counts in index["tiles"].items():
        lat0, lon0 = map(int, name.split("_"))
        middles.append((name, _unit(lon0 + 5, lat0 + 5), counts["shore"] + counts["borders"]))
    # the page's own screens: never cut (the widest canvas, at the furthest the tiles are drawn: the most on it)
    sight, most = _sight(3840, 520, 24.0001), 0
    for lat in range(-88, 89, 4):
        for lon in range(-180, 180, 6):
            round_, want = _pick(middles, _unit(lon, lat), sight)
            assert len(want) == len(round_), (lon, lat)
            most = max(most, len(round_))
    assert 60 < most <= 120
    # a canvas wider than any screen, by the North Pole: more tiles on it than are kept
    view = _unit(-40, 88)
    round_, want = _pick(middles, view, _sight(9000, 520, 24.0001))
    assert len(round_) > 120 or sum(p for *_, p in round_) > 1_000_000
    assert 0 < len(want) <= 120 and sum(p for _, p in want) <= 1_000_000
    picked = {name for name, _ in want}
    assert max(d for d, name, _ in round_ if name in picked) <= min(d for d, name, _ in round_ if name not in picked)

    def drawn(names: list[str], points: dict[str, int], times: int) -> _Tiles:
        """A globe drawn `times` times on one view: each draw asks, then what is on its way comes in."""
        c, now = _Tiles(), 0.0
        for _ in range(times):
            before = len(c.asked)
            c.ask(names, now)
            for name, token in c.asked[before:]:
                c.settle(name, token, points[name], now)
            now += 0.016
        return c

    points = {name: p for _, name, p in round_}
    kept = drawn([name for name, _ in want], points, 60)
    asked = len(kept.asked)
    assert asked == len(want) and all(isinstance(kept.tiles[name], int) for name, _ in want)
    kept.ask([name for name, _ in want], 99.0)
    assert len(kept.asked) == asked  # settled: nothing asked again
    every = drawn([name for _, name, _ in round_], points, 200)  # all of them: asked again and again, without end
    asked = len(every.asked)
    every.ask([name for _, name, _ in round_], 99.0)
    assert asked > 2 * len(round_) and len(every.asked) > asked


def _read_tile(data: bytes) -> tuple[list[list[array]], int] | None:
    """prepareTile's reading, as the page has it: "GSH1", then two sections, each a uint32 count of lines and each line
    a uint32 count of points and as many uint16 pairs (lon, lat), little-endian; None for what is not a tile. Each
    line's steps, and where the reading ended."""
    end = len(data)
    if end < 12 or data[:4] != b"GSH1":
        return None
    off, sections = 4, []
    for _ in range(2):
        if off + 4 > end:
            return None
        (count,), lines = struct.unpack_from("<I", data, off), []
        off += 4
        for _ in range(count):
            if off + 4 > end:
                return None
            (n,) = struct.unpack_from("<I", data, off)
            if off + 4 + n * 4 > end:
                return None
            off += 4
            steps = array("H")
            steps.frombytes(data[off:off + n * 4])
            if struct.pack("=H", 1) != struct.pack("<H", 1):
                steps.byteswap()
            lines.append(steps)
            off += n * 4
        sections.append(lines)
    return sections, off


def test_the_coast_tiles_read_whole_and_reach_no_further_than_the_page_looks(js):
    """Every vendored tile reads whole as prepareTile reads it (its two sections end where the file does), and every
    point of it is within TILE_REACH of a tile from its middle, which is how far coastTiles looks when it picks the
    tiles that can be on the canvas: GSHHG's lines run on past a tile's edge into its neighbour's margin (some 2
    degrees at most), so a tile's own box (7.07 degrees from its middle at most) is not enough; 0.85 of a tile is (the
    furthest point is 0.796 of one away). Every name in the index is one coastIndex keeps; what is not a tile reads as
    none."""
    prepare = _body(js, "function prepareTile(buf, t, index) {")
    for step in ('if (end < 12 || dv.getUint32(0) !== 0x47534831) return null;  // "GSH1"',
                 "step = (index.tile + 2 * index.margin) / 65535;",
                 "const count = dv.getUint32(off, true), lines = [];",
                 "const lon0 = t.lon0 - index.margin, lat0 = t.lat0 - index.margin;",
                 "if (off + 4 + n * 4 > end) return null;",
                 "const lon = (lon0 + dv.getUint16(off, true) * step) * rad;",
                 "const lat = (lat0 + dv.getUint16(off + 2, true) * step) * rad, c = Math.cos(lat);",
                 "for (let s = 0; s < 2; s++) {", "sections.push(piecesOf(lines));", "points += n;"):
        assert step in prepare, step
    index_js = _body(js, "function coastIndex(d) {")
    assert "/^(-?\\d{1,2})_(-?\\d{1,3})$/.exec(name)" in index_js
    assert "const whole = lat0 >= -90 && lat0 + tile <= 90 && lon0 >= -180 && lon0 + tile <= 180;" in index_js
    assert "if (!whole || lat0 % tile || lon0 % tile) continue;" in index_js
    assert "const TILE_REACH = 0.85;" in js and "reach: TILE_REACH * tile * rad" in index_js
    tiles = _body(js, "function coastTiles(g, fr, ask) {")
    assert "const d = Math.acos(clamp(t.c[0] * C[0] + t.c[1] * C[1] + t.c[2] * C[2], -1, 1));" in tiles
    assert "if (d <= near) round.push({ t, d });" in tiles
    assert "const C = fr.C, near = sightOf(g) + coast.index.reach, round = [];" in tiles
    index = json.loads((COAST / "index.json").read_text(encoding="utf-8"))
    tile, margin = index["tile"], index["margin"]
    assert (tile, margin) == (10, 5)
    step, reach = (tile + 2 * margin) / 65535, 0.85 * tile
    lo, hi = margin / step, (margin + tile) / step  # the steps within a tile's own box
    furthest, points = 0.0, 0
    for name, counts in index["tiles"].items():
        assert re.fullmatch(r"(-?\d{1,2})_(-?\d{1,3})", name)
        lat0, lon0 = map(int, name.split("_"))
        assert -90 <= lat0 and lat0 + tile <= 90 and -180 <= lon0 and lon0 + tile <= 180
        assert lat0 % tile == 0 and lon0 % tile == 0
        data = (COAST / f"{name}.bin").read_bytes()
        read = _read_tile(data)
        assert read is not None and read[1] == len(data), name  # whole, to its last byte
        (shores, borders), _ = read
        assert sum(len(q) // 2 for q in shores) == counts["shore"]  # the index's counts
        assert sum(len(q) // 2 for q in borders) == counts["borders"]
        middle = _unit(lon0 + tile / 2, lat0 + tile / 2)
        box = max(_angle(middle, _unit(lon0 + dx, min(90, lat0 + dy))) for dx in (0, tile / 2, tile)
                  for dy in (0, tile / 2, tile))
        furthest = max(furthest, box)
        for q in shores + borders:
            points += len(q) // 2
            for k in range(0, len(q), 2):
                if lo <= q[k] <= hi and lo <= q[k + 1] <= hi:
                    continue  # in its own box: no further than its corners
                lon, lat = lon0 - margin + q[k] * step, lat0 - margin + q[k + 1] * step
                furthest = max(furthest, _angle(middle, _unit(lon, lat)))
    assert points == 2_025_667 and 7.9 < furthest <= reach, furthest
    assert _read_tile(b"GSH2" + bytes(8)) is None and _read_tile(b"GSH1" + struct.pack("<II", 1, 5)) is None
    # an app serves them beside the page as it serves the maps (web.static_file: its own folder, then ui/static)
    from liminal_libs import web

    for rel in ("vendor/world/coast-h/index.json", "vendor/world/coast-h/50_10.bin", "vendor/world/countries-10m.json"):
        assert web.static_target(rel, (None, STATIC)) == (STATIC / rel).resolve(), rel


def _cap(v: list[float], start: int, end: int) -> list[float]:
    """capOf, as the page has it: the mean of the points (unit vectors) made a unit vector, and the angle (radians) to
    the point furthest from it; a line with no middle reaches everywhere. Kept in 4-byte floats, as caps are."""
    mx, my, mz = sum(v[start:end:3]), sum(v[start + 1:end:3]), sum(v[start + 2:end:3])
    length, reach = math.sqrt(mx * mx + my * my + mz * mz), math.pi
    if length > 1e-6:
        least = min((mx * v[i] + my * v[i + 1] + mz * v[i + 2]) / length for i in range(start, end, 3))
        reach = math.acos(max(-1.0, min(1.0, least)))
    return _f32([mx / (length or 1), my / (length or 1), mz / (length or 1), reach])


def _pieces(lines: list[list[float]], piece: int = 128) -> tuple[list[float], list[int], list[list[float]]]:
    """piecesOf, as the page has it: the points of every line of two or more in one array of 4-byte floats, cut into
    pieces of `piece` points at most, each starting where the one before it ended, with its cap."""
    v: list[float] = []
    starts: list[int] = []
    caps: list[list[float]] = []
    for line in lines:
        m = len(line) // 3
        if m < 2:
            continue
        for s in range(0, m - 1, piece - 1):
            e = min(m, s + piece)
            starts.append(len(v) // 3)
            v.extend(_f32(line[s * 3:e * 3]))
            caps.append(_cap(v, starts[-1] * 3, len(v)))
    starts.append(len(v) // 3)
    return v, starts, caps


def test_a_piece_out_of_sight_has_no_point_on_the_canvas(js):
    """The map's lines and the tiles' are kept in pieces of PIECE points with their middle and their reach, and so is
    each ring of the land; a piece (or a ring) is skipped while its middle is further from the middle of the view than
    the canvas's sight and its reach (inSight). The sight is how far round the canvas shows: asin(its half-diagonal /
    the globe's radius), the whole half in front while the globe is smaller. Run on the 1:110m map's coasts, borders
    and rings as the page cuts them and on views at random: no point of a skipped piece is within the sight, a point
    within it is never skipped, and the pieces of a line join end to end, no gap."""
    assert "  const PIECE = 128;  // " in js
    pieces = _body(js, "function piecesOf(lines) {")
    for step in ("for (let s = 0; s < m - 1; s += PIECE - 1, j++) {", "const e = Math.min(m, s + PIECE);",
                 "v.set(l.subarray(s * 3, e * 3), at * 3);", "caps.set(capOf(v, at * 3, (at + e - s) * 3), j * 4);",
                 "const v = new Float32Array(points * 3), starts = new Uint32Array(n + 1),"):
        assert step in pieces, step
    cap = _body(js, "function capOf(v, from = 0, to = v.length) {")
    assert "least = Math.min(least, (mx * v[i] + my * v[i + 1] + mz * v[i + 2]) / len);" in cap
    assert "reach = Math.acos(clamp(least, -1, 1));" in cap and "let mx = 0, my = 0, mz = 0, reach = Math.PI;" in cap
    sight = _body(js, "function sightOf(g) {")
    assert "return (g.r > half ? Math.asin(half / g.r) : Math.PI / 2) + 0.01;" in sight
    in_sight = js.split("const inSight = (caps, q, C, sight) => ", 1)[1].split(";", 1)[0]
    assert " ".join(in_sight.split()) == ("Math.acos(clamp(caps[q] * C[0] + caps[q + 1] * C[1] + caps[q + 2] * C[2], "
                                          "-1, 1)) <= sight + caps[q + 3]")
    strokes = _body(js, "function strokePieces(c, P, g, fr, sight) {")
    assert "if (inSight(P.caps, j * 4, fr.C, sight)) strokeUnits(" in strokes
    prepare = _body(js, "function prepare(t) {")
    assert "return { land, coasts: piecesOf(coasts), borders: piecesOf(borders), byId };" in prepare  # 1.104.0
    assert "const [coasts, borders] = sections;" in _body(js, "function prepareTile(buf, t, index) {")
    topo = json.loads((WORLD / "countries-110m.json").read_text(encoding="utf-8"))
    lines = [[c for lon, lat in line for c in _unit(lon, lat)] for line in _decode(topo)]
    rnd = random.Random(20261119)
    for _ in range(40):  # wandering lines of every length, some longer than a piece
        lon, lat, line = rnd.uniform(-180, 180), rnd.uniform(-80, 80), []
        for _ in range(rnd.choice([1, 2, 3, 127, 128, 129, 255, 256, 400])):
            line.extend(_unit(lon, lat))
            lon, lat = lon + rnd.uniform(-0.3, 0.3), max(-89.0, min(89.0, lat + rnd.uniform(-0.2, 0.2)))
        lines.append(line)
    v, starts, caps = _pieces(lines)
    assert all(starts[j + 1] - starts[j] <= 128 for j in range(len(caps)))
    joined = 0
    for line in lines:  # each line is its pieces, end to end
        m = len(line) // 3
        joined += m + max(0, math.ceil((m - 1) / 127)) - 1 if m >= 2 else 0
    assert len(v) // 3 == joined
    rings = [[c for lon, lat in points[:-1] for c in _unit(lon, lat)] for _, points in _rings(topo, _decode(topo))]
    caps += [_cap(_f32(ring), 0, len(ring)) for ring in rings]
    spans = [(v, starts[j] * 3, starts[j + 1] * 3) for j in range(len(starts) - 1)]
    spans += [(_f32(ring), 0, len(ring)) for ring in rings]
    for k in range(60):
        lon0, lat0, zoom = rnd.uniform(-180, 180), rnd.uniform(-85, 85), rnd.choice([1, 2, 3, 12, 24, 40, 96])
        c, r, half = _unit(lon0, lat0), _radius(zoom), math.hypot(620, 260)
        sight = (math.asin(half / r) if r > half else math.pi / 2) + 0.01
        for (pts, start, end), (mx, my, mz, reach) in zip(spans, caps):
            skipped = math.acos(max(-1.0, min(1.0, mx * c[0] + my * c[1] + mz * c[2]))) > sight + reach
            if not skipped:
                continue
            for i in range(start, end, 3):  # every point of a skipped piece is out of sight
                d = pts[i] * c[0] + pts[i + 1] * c[1] + pts[i + 2] * c[2]
                assert math.acos(max(-1.0, min(1.0, d))) > sight - 0.01 + 1e-9, (k, lon0, lat0, zoom)


def _trim(steps: list[tuple], w: float, h: float, m: float = 16) -> list[list[tuple[float, float]]]:
    """trimmed(), as the page has it, on a path's steps: ("M", x, y), ("L", x, y), ("A", [points]) (an arc, as the
    canvas draws it: a line to its start, then along it, never cut) and ("Z",). The subpaths it puts on the canvas."""
    def side(x: float, y: float) -> int:
        return (1 if x < -m else 2 if x > w + m else 0) | (4 if y < -m else 8 if y > h + m else 0)

    out: list[list[tuple[float, float]]] = []
    held: tuple[float, float, int] | None = None
    last = 0  # the side of the last point put

    def put() -> None:
        nonlocal held, last
        if held is not None:
            out[-1].append(held[:2])
            last, held = held[2], None

    for step in steps:
        if step[0] == "M":
            put()
            out.append([step[1:]])
            last = side(*step[1:])
        elif step[0] == "L":
            s = side(*step[1:])
            if not (held is not None and last & held[2] & s):
                put()
            held = (step[1], step[2], s)
        elif step[0] == "A":
            put()
            out[-1].extend(step[1])
            last = side(*step[1][-1])
        else:
            put()
    put()
    return out


def _windings(subpaths: list[list[tuple[float, float]]], xs: list[float], ys: list[float]) -> list[list[int]]:
    """How many times the subpaths (each closed, as a fill closes it) wind round each point of the grid xs by ys (both
    rising): of a ray from the point to the right, a line crossing it going down (y rising) counts one and going up
    minus one. Row by row, each line adding its count to the points left of where it crosses the row."""
    rows = [[0] * (len(xs) + 1) for _ in ys]
    for sub in subpaths:
        for (x1, y1), (x2, y2) in zip(sub, sub[1:] + sub[:1]):
            if y1 == y2:
                continue
            s, lo, hi = (1, y1, y2) if y1 < y2 else (-1, y2, y1)
            for j in range(bisect.bisect_left(ys, lo), bisect.bisect_left(ys, hi)):
                at = x1 + (x2 - x1) * (ys[j] - y1) / (y2 - y1)
                rows[j][0] += s
                rows[j][bisect.bisect_left(xs, at)] -= s
    out = []
    for row in rows:
        n, line = 0, []
        for k in range(len(xs)):
            n += row[k]
            line.append(n)
        out.append(line)
    return out


def test_a_run_off_the_canvas_is_cut_short_and_nothing_on_it_changes(js):
    """trimmed() puts a path on the canvas with its runs beyond an edge cut short: of three points in a row beyond the
    same edge (PEN_MARGIN px out), the middle one is left out, so a coast running on for thousands of points off a
    globe zoomed 96x is a few points. Nothing on the canvas changes: what is left out and the line put for it lie
    beyond that edge, so every point of the canvas is wound round as often (the land's fill, even-odd or not), and
    every line put that the path did not have lies beyond an edge (a stroke). Checked on paths at random that wander
    far off the canvas and back, round its corners and round it, with arcs of a rim far larger than it."""
    assert "  const PEN_MARGIN = 16;  // " in js
    pen = _body(js, "function trimmed(c, w, h) {")
    for step in ("const m = PEN_MARGIN, side = (x, y) => (x < -m ? 1 : x > w + m ? 2 : 0) | (y < -m ? 4 : y > h + m",
                 "const put = () => { if (held) { c.lineTo(hx, hy); ls = hs; held = false; } };",
                 "moveTo(x, y) { put(); c.moveTo(x, y); ls = side(x, y); },",
                 "if (!(held && (ls & hs & s))) put();", "held = true; hx = x; hy = y; hs = s;",
                 "c.arc(x, y, r, a, b, ccw);", "ls = side(x + r * Math.cos(b), y + r * Math.sin(b));",
                 "closePath() { put(); c.closePath(); },", "done: put,"):
        assert step in pen, step
    base = _body(js, "function baseLayer(g, fr, ratio, W, H, tiles) {")
    assert "const pen = trimmed(b, g.w, g.h), sight = sightOf(g)" in base
    assert base.index("pen.done();") < base.index("b.fill('evenodd');")  # its last point put before the fill
    lines = _body(js, "function paintLines(c, g, fr, l, geo, names) {")
    assert "pen = trimmed(c, g.w, g.h);" in lines and "strokeUnits(pen, L.v," in lines
    assert lines.index("pen.done();") < lines.index("c.stroke();")
    w, h, rnd = 800, 500, random.Random(20261119)
    xs = [0.31 + 4.01 * i for i in range(200)]  # the canvas, every 4 px, to its edges
    ys = [0.17 + 3.97 * j for j in range(126)]
    kept = total = 0
    for case in range(300):
        steps: list[tuple] = []
        for _ in range(rnd.randint(1, 3)):
            x, y = rnd.uniform(-3000, 3800), rnd.uniform(-3000, 3500)
            steps.append(("M", x, y))
            for _ in range(rnd.randint(3, 400)):
                pick = rnd.random()
                if pick < 0.03:  # an arc of a rim far larger than the canvas, from where it is
                    cx, cy, r = w / 2, h / 2, rnd.uniform(900, 6000)
                    a = rnd.uniform(0, 2 * math.pi)
                    arc = [(cx + r * math.cos(a + t / 12), cy + r * math.sin(a + t / 12)) for t in range(13)]
                    steps.append(("A", arc))
                    x, y = arc[-1]
                    continue
                if pick < 0.08:  # back into the canvas
                    x, y = rnd.uniform(0, w), rnd.uniform(0, h)
                else:  # on, along wherever it is
                    x, y = x + rnd.gauss(0, 250), y + rnd.gauss(0, 250)
                steps.append(("L", x, y))
            steps.append(("Z",))
        whole = []
        for step in steps:
            if step[0] == "M":
                whole.append([step[1:]])
            elif step[0] == "L":
                whole[-1].append(step[1:])
            elif step[0] == "A":
                whole[-1].extend(step[1])
        cut = _trim(steps, w, h)
        assert [sub[0] for sub in cut] == [sub[0] for sub in whole]
        assert _windings(cut, xs, ys) == _windings(whole, xs, ys), case
        had = {(a, b) for sub in whole for a, b in zip(sub, sub[1:])}

        def side(x: float, y: float) -> int:
            return (1 if x < -16 else 2 if x > w + 16 else 0) | (4 if y < -16 else 8 if y > h + 16 else 0)
        for sub in cut:
            for a, b in zip(sub, sub[1:]):
                assert (a, b) in had or side(*a) & side(*b), (case, a, b)
        kept += sum(len(sub) for sub in cut)
        total += sum(len(sub) for sub in whole)
    assert kept < total * 0.8  # a good part of these paths is cut
    # a coast that runs on for 10,000 points along beyond one edge: a few points
    run = [("M", 400.0, 250.0)] + [("L", -100.0 - k * 0.37, 250.0 + 2000 * math.sin(k / 900)) for k in range(10000)]
    assert len(_trim(run + [("L", 400.0, 300.0), ("Z",)], w, h)[0]) < 12


def test_the_layers_and_the_places_stay_right_at_96x(js):
    """At 96x the globe's radius is some 21,000 px (a canvas 520 px high). The view a layer was painted for is keyed to
    1e-5 degrees (facing), at most 0.004 px off the routes and home, drawn every frame (to 1e-3 degrees, as before, it
    was 0.37 px); a 4-byte unit vector (the map's and the tiles' pieces, a layer's points and lines) is within 0.002 px
    of its point, and a layer's point packed to 1e-5 degrees within 0.004 px; a layer's line, a chord between points
    FILL degrees apart at most, strays from its great circle on the canvas by its sagitta times the sine of how far
    from the middle of the view it is: under half a pixel on a canvas 2,560 px wide, at any zoom. Its marks, lines and
    the places' dots are projected from those points as at 1x, and found by the pointer as they are drawn."""
    r = _radius(96)
    assert "const facing = () => `${view.lon.toFixed(5)},${view.lat.toFixed(5)}`;" in js
    assert "facing(), stamp].join('|');" in js.split("const viewKey = ", 1)[1].split("\n", 1)[0]
    assert r * math.radians(1e-5) < 0.004 < 0.3 < r * math.radians(1e-3)
    rnd = random.Random(96)
    worst = 0.0
    for _ in range(20000):
        p = _unit(rnd.uniform(-180, 180), rnd.uniform(-90, 90))
        q = _f32(p)
        worst = max(worst, math.dist(p, q))
    assert worst * r < 0.002
    assert "pv.push(...unit(lon, lat));" in js and "points.v = Float32Array.from(pv);" in js  # a layer's points
    fill = float(re.search(r"const FILL = ([\d.]+);", js).group(1))
    assert fill == 3
    half = math.hypot(2560 / 2, 520 / 2)
    assert half * (1 - math.cos(math.radians(fill / 2))) < 0.5
    # the marks and the dots: the same projection at every zoom (the canvas's own px), clipped to the canvas
    points = _body(js, "function paintPoints(c, g, fr, l, geo, names) {")
    assert "const px = g.cx + g.r * (x * E[0] + y * E[1] + z * E[2]), py = g.cy - g.r * (x * N[0]" in points
    assert "if (px < 0 || py < 0 || px >= g.w || py >= g.h) continue;" in points
    assert "const p = project(o.lon, o.lat, g);" in _body(js, "function drawPlaces(c, g) {")


def test_gshhg_is_credited_while_its_coasts_are_drawn(js):
    """The project's rule, a data set's credit drawn wherever its features are: while any coast tile is drawn, GSHHG
    2.3.7 and its licence are named with the other credits over the map (in words: no outside host in the script); at
    24x or nearer, or before a tile is here, not."""
    assert "const COAST_CREDIT = { text: 'Coasts and borders: GSHHG 2.3.7 (LGPL-3.0)', url: '' };" in js
    render = _body(js, "function render(now) {")
    assert "const credited = !!(tiles && tiles.drawn.length);" in render
    assert "if (credited !== coastCredited) { coastCredited = credited; renderAttribution(); }" in render
    assert "if (coastCredited) list.push(COAST_CREDIT);" in _body(js, "function renderAttribution() {")
    assert "let coastCredited = false;" in js


def test_a_places_line_runs_through_the_hops_of_its_traced_route(js):
    """1.67.0: a place may carry `via`, the placed hops of the route traced to it from home outward (read as places,
    MAX_VIA at most, what is no place dropped); its line runs from the place through them to home, leg by leg on great
    circles, rising once over the whole way, with a small grey-blue dot at each hop."""
    assert "via: (Array.isArray(o.via) ? o.via.slice(0, MAX_VIA) : []).map(hopOf).filter(Boolean)," in js  # 1.69.1
    build = _body(js, "function buildRoutes() {")
    assert "...o.via.slice().reverse().map((p) => unit(p.lon, p.lat)), b];" in build
    assert "lift * Math.sin((Math.PI * (gone + l.d * t)) / w)" in build and "if (l.hop) hops.push(k - 1);" in build
    assert "if (d < 1e-3) continue;" in build  # a hop within a few kilometres of the stop before it: no leg
    assert "mid: Math.PI - d < 1e-3 ? perpendicular(s) : null" in build  # the detour only for a leg nearly opposite
    assert "if (most > MAX_ROUTE_POINTS) counts = counts.map(" in build  # a route's points capped, whatever its hops
    draw = _body(js, "function drawRoutes(g, fr, now) {")
    assert "for (const j of rt.hops) {" in draw and "if (!rt.screen[j * 3 + 2]) continue;" in draw
    assert "ctx.fillStyle = css(colours.network, picked ? 0.45 : 0.9);" in draw



def test_the_routes_are_a_heat_map_and_the_lights_travel_only_the_last_stretch(js):
    """1.69.0 (the user, 2026-11-20: "they should look like a heat map ... the brighter it gets, lets keep grey scale to
    white but don't use the current method of dots flying over existing infrastructure, just use that to the end
    points/hosts"): the page's heat runs are drawn grey to white by their weight on a log scale, 1 to 3 px, in a layer
    of their own over the infrastructure; the lights travel each place's last stretch alone (from `last` to it); a page
    with no heat (an older server's) keeps the routes and their lights as they were."""
    normal = _body(js, "function normal(spec) {")
    assert "heat: Array.isArray(s.heat) ? heatOf(s.heat) : null," in normal
    assert "last: Array.isArray(o.last) ? placeOf({ lat: o.last[0], lon: o.last[1] }) : null," in normal
    heat = _body(js, "function heatOf(list) {")
    assert "list.slice(0, MAX_HEAT_RUNS)" in heat and "points + one.length / 3 >= MAX_HEAT_POINTS" in heat
    assert "Math.ceil(d / fill)" in heat and "runs.sort((x, y) => x.w - y.w);" in heat  # filled in, the brightest last
    build = _body(js, "function buildRoutes() {")
    stretch = _body(build, "if (data.heat) {")
    # 1.106.0: its short links; an older server's page its tail (1.70.0), else its straight last stretch (1.69.0)
    assert ": o.tail.length >= 2 ? [o.tail.map((p) => unit(p.lon, p.lat))]" in stretch and "return;" in stretch
    assert "const path = wayOf(pts);" in stretch
    assert "hops: []" in stretch  # no hop dots: the network is the heat's
    draw = _body(js, "function drawRoutes(g, fr, now) {")
    assert "for (const rt of routes) onScreen(rt, g, fr);\n        drawLinks(picked);" in draw
    assert "drawLights(picked, now);\n        return;" in draw
    paint = _body(js, "function paintHeat(c, g, fr, h) {")
    assert "Math.log1p(h.most)" in paint and "(Math.log1p(r.w) / top) * (HEAT_STEPS - 1)" in paint
    # 1.70.0: violet (270 degrees) to red (0), the routes only, wider as it rises (the scale reads without colour too)
    assert "c.strokeStyle = heatColour(t, 0.92);" in paint and "c.lineWidth = 1.5 + 3 * t;" in paint
    assert "hsla(${Math.round(270 * (1 - t))}" in _body(js, "function heatColour(t, alpha) {")
    assert "heat: base === 'light' ? { s: 80, l: 40 } : { s: 90, l: 62 }," in js
    legend = _body(js, "function renderLegend() {")
    assert "item('heat', 'heat', heat ? 'Routes by how often: connections' : ''," in legend and ".lg-k-heat{" in js
    way = _body(js, "function wayOf(pts) {")
    assert "if (Math.PI - d < 1e-3) return null;" in way and "Math.min(out.length, MAX_ROUTE_POINTS)" in way
    render = _body(js, "function render(now) {")
    assert render.index("infraLayer(g, fr, ratio, W, H)") < render.index("heatLayer(g, fr, ratio, W, H)") \
        < render.index("drawRoutes(g, fr, now);")


def test_the_routers_places_the_routes_bend_at_are_drawn_named_and_told_on_hover(js):
    """1.69.1 (the user, 2026-11-22: "there appears to be verticies without location names or cities, please address
    that"): with the heat, every router's place a route passes is drawn once, however many routes pass it, named on
    the map with the places' names (the busiest first, more of them as the globe comes nearer) and told on hover:
    its place, its hops and addresses, its nearest time, the places it is on the way to and what placed it."""
    normal = _body(js, "function normal(spec) {")
    assert ".map(hopOf).filter(Boolean)," in normal and "hops: hopsOf(listed)," in normal
    hop = _body(js, "function hopOf(p) {")
    assert "label: text(p.label, 80), address: text(p.address, 64)" in hop
    hops = _body(js, "function hopsOf(origins) {")
    assert "const id = `${p.lat.toFixed(3)},${p.lon.toFixed(3)}`;" in hops  # one a place, as routes.py's _key
    assert "if (!h.to.includes(o)) { h.to.push(o); h.count += o.count; }" in hops and ".slice(0, MAX_HOPS)" in hops
    places = _body(js, "function drawPlaces(c, g) {")
    assert places.index("for (const h of data.hops) {") < places.index("for (const o of data.origins) {")  # under them
    labels = _body(js, "function drawLabels(c, g, shown) {")
    assert "HOP_NAMES.find(([upto]) => zoom < upto)[1]" in labels and "put(text(hopName(h), 32)" in labels
    # the review of 1.106.0: only the names placed count against the budget
    assert "if (put(text(hopName(h), 32), p.x, p.y, 4, false)) left--;" in labels
    assert "return true;" in labels and "return false;" in labels
    assert labels.index("put(text(nameOf(o), 40)") < labels.index("put(text(hopName(h), 32)")  # places named first
    hit = _body(js, "function hitAt(clientX, clientY, by) {")
    assert "if (!best && data.heat) {" in hit and "best = { h }; bestD = d;" in hit
    tip = _body(js, "function hopTip(h, line) {")
    assert "a router on the way" in tip and "placed by the GeoIP file on this machine" in tip
    assert "if (p.h) { hopTip(p.h, line); return; }" in _body(js, "function tipLines(p, line) {")
    assert "tipLines(p, (cls, words, kind) => {" in _body(js, "function fillTip(p) {")
    assert "was.h !== p.h" in _body(js, "function setPick(p) {")
    assert "pick.h ? project(pick.h.lon, pick.h.lat, g)" in _body(js, "function anchorTip(g) {")
    assert "const h = data.heat ? data.hops.find((x) => x.id === pick.h.id) : null;" in _body(js, "function update(next, more) {")


def test_a_routers_names_and_networks_are_told_on_its_hover(js):
    """1.72.0 (the user, 2026-11-22: "using reverse lookups, and whois to figure out as much info as possible on the
    nodes"): a hop's name (its reverse DNS) and its network (RDAP) are read with it, gathered by its place, and said on
    its hover after its addresses."""
    hop = _body(js, "function hopOf(p) {")
    assert "name: text(p.name, 120)" in hop and "network: text(p.network, 160)" in hop
    hops = _body(js, "function hopsOf(origins) {")
    assert "if (p.name && h.names.length < 4 && !h.names.includes(p.name)) h.names.push(p.name);" in hops
    assert "h.networks.push(p.network)" in hops
    tip = _body(js, "function hopTip(h, line) {")
    assert "for (const n of h.names) line('', n);" in tip and "line('lg-tip-sub', `network: ${n}`)" in tip


def test_a_layer_is_asked_by_the_views_area_past_its_zoom(js):
    """1.104.0 (Monday list item 27): where the spec says layer_area, the whole layer is asked coarse ({zoom: 1}) and,
    past AREA_ZOOM (the library's COARSE_ZOOM), the view's area rounded out to AREA_TILE degrees, once a view, never
    while the globe glides; the area's answer is drawn once it is in, the whole layer's until then; the area's entries
    go as the view leaves them (pruneLayers)."""
    from liminal_libs.machines import infrastructure
    assert "  const AREA_ZOOM = 6;  // " in js and "  const AREA_TILE = 10;  // " in js
    assert infrastructure.COARSE_ZOOM == 6.0
    render = _body(js, "function render(now) {")
    # the review: by area only with a loader that takes the area (its second argument); today's platform loader takes
    # the id alone and answers the whole layer, which would be fetched again for every new area
    assert "const byArea = data.layerArea && typeof load === 'function' && load.length >= 2;" in render
    assert "if (!byArea && areaKey) { areaKey = ''; area = null; layersShown = null; pruneLayers(); }" in render
    assert "if (byArea && !glide) {" in render and "data.layerArea && !glide" not in render
    assert "if (key !== areaKey) { areaKey = key; area = want; layersShown = null; pruneLayers(); }" in render
    assert "if (areaKey) askLayer(areaLayer(l), load, { area, zoom });" in render
    shown = _body(js, "function shownLayers() {")
    assert "const e = near && near.state === 'ready' ? near : isOn(l) ? layerData.get(l.key) : null;" in shown
    assert "layerArea: s.layer_area === true," in _body(js, "function normal(spec) {")
    box = _body(js, "function areaOf(g) {")
    assert "if (s <= -90 || n >= 90 || across >= 180) return [-180, s, 180, n];" in box
    assert "return [w < -180 ? w + 360 : w, s, e > 180 ? e - 360 : e, n];" in box


def test_the_sky_is_drawn_as_one_merged_area_a_constellation_with_its_faint_band_outside(js):
    """1.104.0 (Monday list item 32): each constellation's footprints are one path filled once in its colour (never a
    stack), the band stroked in a very faint pink and then the area taken out of it (destination-out), a geostationary
    satellite's beams the countries it names cut to its cap; the places asked of the page's own loader alone, once a
    minute at most, moved between their two moments once a second (every ten under reduced motion)."""
    assert "  const SKY_PINK = 'rgba(255,105,180,0.10)';  // " in js and "  const SKY_RING = 48;  // " in js
    assert "  const SKY_TICK_MS = 1000;  // " in js and "  const SKY_TICK_REDUCED_MS = 10_000;  // " in js
    paint = _body(js, "function paintSky(c, g, fr, t, W, H, ratio) {")
    assert paint.count("o.fill(area);") == 2  # the destination-out, then the colour: once each
    stroke, out = paint.index("o.stroke(area);"), paint.index("o.globalCompositeOperation = 'destination-out';")
    fill = paint.index("o.fill(area);  // once: the union")
    assert stroke < out < fill and "o.globalCompositeOperation = 'source-over';" in paint[out:fill]
    assert "m.clip(cap);" in paint and "m.fill(lands);" in paint  # the beams: the countries within the cap
    # the review: a footprint over the horizon is closed along the rim, so the band is drawn within the globe's disk
    # alone (its half outside the rim would ring the limb), and the clip is taken off before the next constellation
    clip = paint.index("o.arc(g.cx, g.cy, g.r, 0, TAU);\n        o.clip();")
    assert clip < paint.index("o.stroke(lands);") < stroke and clip < paint.index("o.stroke(cap);")
    assert fill < paint.index("o.restore();  // the disk's clip off") < paint.index("c.drawImage(own, 0, 0);")
    # the review: the orbits' credit (CelesTrak's) kept from the spec and drawn while its footprints are, the credits
    # made again when the places come
    assert "beams, credit: creditOf(c.credit) });" in _body(js, "function skyOf(s) {")
    credits = _body(js, "function renderAttribution() {")
    assert "if (s && s.n && k.credit) list.push(k.credit);" in credits
    assert "sky = skyPlaces(answer); tickSky(); renderAttribution(); changed();" in _body(js, "function askSky() {")
    ask = _body(js, "function askSky() {")
    assert "if (!data.sky || data.sky.needs || !skyLoad || Date.now() - skyAsked < data.sky.every * 1000) return;" in ask
    assert "fetch(" not in _body(js, "function skyLayer(g, fr, ratio, W, H) {") and "fetch(" not in ask
    assert "skyTimer = setTimeout(() => { changed(); tickSky(); }, reduced ? SKY_TICK_REDUCED_MS : SKY_TICK_MS);" in js
    assert "clearTimeout(skyTimer);  // 1.104.0: the sky's tick goes with the globe" in _body(js, "function destroy() {")


def test_a_click_a_tap_or_enter_picks_and_a_hover_never_does(js):
    """1.105.0 (Monday list item 31; docs/PAGES.md): onPick tells the page what a click, a tap or Enter picked, as side.js
    tells it, and null when it is let go (Escape, a click on nothing); the pointer's move only shows the tooltip. The
    tooltip's words and the pick's are one (tipLines), and describe(key) tells a pick anew from the spec drawn now."""
    assert "let onPick = typeof opts.onPick === 'function' ? opts.onPick : null;" in js
    assert "if (more && typeof more.onPick === 'function') onPick = more.onPick;" in js  # kept through an update
    click = _body(js, "canvas.addEventListener('click', (e) => {")
    assert "tellPick(hit);" in click and "tellPick(again ? null : { home: true });" in click
    move = _body(js, "canvas.addEventListener('pointermove', (e) => {")
    assert "tellPick" not in move and "onPick" not in move
    keys = _body(js, "canvas.addEventListener('keydown', (e) => {")
    assert "if (pinned && keyOfPick(pick) === pinned) tellPick(null); else tellPick(pick);" in keys  # Enter: again lets go
    assert "{ setPick(null); tellPick(null); }" in keys  # Escape: let go, and the step with it
    tell = _body(js, "function tellPick(p) {")
    assert "if (!onPick || key === pinned) return;" in tell and "onPick(p ? pickOf(p) : null)" in tell
    pick = _body(js, "function pickOf(p) {")
    assert "tipLines(p, (cls, words) => {" in pick  # the tooltip's own words, in full
    for kind in ("'place'", "'home'", "'hop'", "'feature'"):
        assert kind in pick, kind
    key = _body(js, "function keyOfPick(p) {")
    for k in ("globe:home", "globe:place:", "globe:hop:", "globe:feature:"):
        assert k in key, k
    assert "describe: (key) => (destroyed ? null : describeKey(key))" in js and "unpick: () => { pinned = ''; }" in js
    assert "const describe = (item) =>" in js
    # nothing of a pick is markup: the tooltip's lines are textContent, and side.js escapes what it is given
    assert "b.textContent = words[0];" in _body(js, "function fillTip(p) {")


def test_a_second_pick_of_the_same_lets_it_go_as_a_table_rows_does(js):
    """1.105.0 (the user, 2026-11-26, answering the build's question): a second click or tap on the place, router,
    feature or home picked lets it go (onPick(null)), as a second click on a table row does (side.js); Enter on what is
    picked lets it go too. A pick of something else still replaces it."""
    click = _body(js, "canvas.addEventListener('click', (e) => {")
    assert "const again = !!(hit && pinned && keyOfPick(hit) === pinned);" in click
    assert click.index("const again") < click.index("if (hit && hit.home)")
    assert "if (again) { setPick(null); tellPick(null); return; }" in click
    assert "tellPick(again ? null : { home: true });" in click
    assert click.index("if (again) { setPick(null)") < click.index("tellPick(hit);")
    tell = _body(js, "function tellPick(p) {")
    assert "if (!onPick || key === pinned) return;" in tell  # the same told once: so `again` is checked before it
    # Enter on it again lets it go and keeps it stepped to, so Enter once more picks it again (a table row's Enter)
    keys = _body(js, "else if (e.key === 'Enter' && pick) {")
    assert "if (pinned && keyOfPick(pick) === pinned) tellPick(null); else tellPick(pick);" in keys
    assert "setPick(null)" not in keys


def test_a_routes_light_travels_only_its_short_links_lit_and_an_older_page_keeps_its_tail(js):
    """1.106.0 (Monday list item 27; the user, 2026-11-22: "the straightlines are meaningless"): with the heat, a place's
    `links` (machines/network.py: its short links from the network's ends into it and into home, LINK_KM at most) are
    the only lines a route draws off the network: each a route of its own, stroked lit in the lights' glow, still or
    moving, and travelled by its light; a link within a kilometre is not drawn. A page with no `links` (an older
    server's) keeps 1.70.0's tail."""
    from liminal_libs.machines import network
    normal = _body(js, "function normal(spec) {")
    assert "links: Array.isArray(o.links) ? o.links.slice(0, 2).map(linkOf).filter(Boolean) : null," in normal
    link = _body(js, "function linkOf(l) {")
    assert "l.length !== 2" in link and "return a && b ? [a, b] : null;" in link
    stretch = _body(_body(js, "function buildRoutes() {"), "if (data.heat) {")
    assert "const ways = o.links ? o.links.map(([a, b]) => [unit(a.lon, a.lat), unit(b.lon, b.lat)])" in stretch
    assert "for (const pts of ways) {" in stretch and "link: !!o.links," in stretch
    assert "if (!path) continue;  // a link within a kilometre or so: the dot alone" in stretch
    assert "if (gone < 2e-4 || out.length < 2) return null;" in _body(js, "function wayOf(pts) {")
    links = _body(js, "function drawLinks(picked) {")
    assert "if (!rt.link) continue;" in links and "ctx.strokeStyle = css(glow, picked && picked !== rt.o ? 0.25 : 0.8);" in links
    assert "const glow = mix(colours.network, colours.text, 0.35);" in links  # the lights' own glow
    draw = _body(js, "function drawRoutes(g, fr, now) {")
    heat = _body(draw, "if (data.heat) {")
    assert heat.index("onScreen(rt, g, fr)") < heat.index("drawLinks(picked);") < heat.index("drawLights(picked, now);")
    assert "if (!now) return;" not in links  # still under reduced motion too: lit, not moving
    legend = _body(js, "function renderLegend() {")
    assert f"{network.LINK_KM:g} km at most" in legend and "routes.some((rt) => rt.link)" in legend


def test_the_hubs_the_routes_pass_are_drawn_larger_and_brighter_by_their_traffic_and_named(js):
    """1.106.0 (the user: "they need to show the cities that the lines go to, the hubs"): the page's `hubs`
    (machines/network.py) read safely, MAX_HUBS at most, the busiest first, each with the places whose routes pass it;
    drawn under the routers' places with its layer's mark, larger and brighter by the connections through it on a log
    scale (and the routers' places so too); named after the routers' places by the same placing (never over another
    name), fewer of them, an unnamed one and one its own layer names now left out."""
    from liminal_libs.machines import network
    assert f"  const MAX_HUBS = {network.MAX_HUBS};" in js and f"  const HUB_WAY = {network.ROUTE_HUBS};" in js
    assert f"  const HUB_KM = {network.HUB_KM:g};" in js and "  const HUB_NAMES = [[2, 4], [6, 12], [Infinity, 32]];" in js
    normal = _body(js, "function normal(spec) {")
    assert "hubs: hubsOf(s.hubs, listed)," in normal
    assert "hubs: (Array.isArray(o.hubs) ? o.hubs.slice(0, HUB_WAY) : []).map((x) => text(x, 64)).filter(Boolean)," in normal
    hubs = _body(js, "function hubsOf(list, origins) {")
    assert "list.slice(0, MAX_HUBS)" in hubs and "if (!id || by.has(id)) continue;" in hubs
    assert "if (u && !u.to.includes(o)) u.to.push(o);" in hubs and "sort((a, b) => b.w - a.w" in hubs
    places = _body(js, "function drawPlaces(c, g) {")
    assert places.index("for (const u of data.hubs) {") < places.index("for (const h of data.hops) {") \
        < places.index("for (const o of data.origins) {")  # the hubs under the routers' places, under the places
    assert "const t = Math.log1p(u.w) / top, r = 2.2 + 2.6 * t" in places
    assert "css(mix(colours.network, colours.text, t), u === hub ? 1 : 0.5 + 0.45 * t)" in places
    assert "const t = Math.log1p(h.count) / most, r = h === hop ? 4.5 : 2 + 1.8 * t;" in places
    assert "css(colours.text, h === hop ? 1 : 0.55 + 0.4 * t)" in places
    assert "return l && MARKS[l.mark] === 'points' ? l.mark : 'circle';" in _body(js, "function markOf(kind) {")
    labels = _body(js, "function drawLabels(c, g, shown) {")
    assert labels.index("put(text(hopName(h), 32)") < labels.index("put(text(u.name, 32)")  # the routers' first
    assert "left = HUB_NAMES.find(([upto]) => zoom < upto)[1];" in labels
    assert "if (!u.name || layerNames(u.kind)) continue;" in labels
    assert "if (put(text(u.name, 32), p.x, p.y, 5, false)) left--;" in labels  # the review: placed names alone
    assert "const layerNames = (id) => data.layers.some((l) => l.id === id && isOn(l) && zoom >= l.namesFrom);" in js
    legend = _body(js, "function renderLegend() {")
    assert "'Hubs on the routes, larger and brighter with the connections through them'" in legend


def test_a_hub_is_hovered_and_picked_and_a_route_picked_tells_its_way_and_its_hubs(js):
    """1.106.0 (and docs/PAGES.md's right-hand menu): a hub is under the pointer where no place or home is nearer (the
    nearer of it and a router's place), told on hover (its name, what it is, the connections through it, its routes,
    the places it is on the way to, why it is named) and picked whole by a click, a tap or Enter, as side.js tells a
    pick; a place picked tells its way through its routers' places and the hubs it passes, in its order. Kept through
    an update while a route still passes it, let go when none does."""
    hit = _body(js, "function hitAt(clientX, clientY, by) {")
    assert "for (const u of data.hubs) {" in _body(hit, "if (!best && data.heat) {")
    assert "best = { hub: u }; bestD = d;" in hit
    assert "if (p.hub) { hubTip(p.hub, line); return; }" in _body(js, "function tipLines(p, line) {")
    tip = _body(js, "function hubTip(u, line) {")
    assert "many(u.w, 'connection')} through it, on ${many(u.routes, 'route')}" in tip and "HUB_KM" in tip
    assert "if (p.hub) return `globe:hub:${p.hub.id}`;" in _body(js, "function keyOfPick(p) {")
    pick = _body(js, "function pickOf(p) {")
    assert "spec.kind = 'hub';" in pick and "['On the way to', u.to.map(nameOf).join(', ')]" in pick
    assert "['Its way', o.via.length ? wayWords(o) : '']," in pick and "['Passes', o.hubs.map(" in pick
    way = _body(js, "function wayWords(o) {")
    assert "const names = ['This machine'];" in way and "names[names.length - 1] !== n" in way
    assert "return names.join(' → ');" in way
    assert "if (u) return pickOf({ hub: u });" in _body(js, "function describeKey(key) {")
    assert "was.hub !== p.hub" in _body(js, "function setPick(p) {")
    assert "pick.hub ? project(pick.hub.lon, pick.hub.lat, g)" in _body(js, "function anchorTip(g) {")
    update = _body(js, "function update(next, more) {")
    assert "const u = data.heat ? data.hubs.find((x) => x.id === pick.hub.id) : null;" in update
    assert "pick = { ...pick, hub: u };" in update
    assert "pick.hub ? `hub ${pick.hub.id}`" in _body(js, "function placesLayer(g, ratio, W, H) {")
