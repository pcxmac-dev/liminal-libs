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
world-atlas's licence, and in the package data a wheel or an sdist is built with."""
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
    for a screen reader; a plugin's words are text, never markup."""
    assert "const safeUrl = (u) => (/^https:\\/\\/[^\\s\"'<>]+$/i.test(" in js
    attribution = _body(js, "function renderAttribution() {")
    assert "link.href = a.url;" in attribution and "link.rel = 'noopener noreferrer';" in attribution
    assert "setText(attribution, a ? a.text : '');" in attribution  # no address (or not an https one): its words only
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
    assert "if (!link || link.parentNode !== attribution) {" in attribution and "attribution.replaceChildren(link);" in attribution
    assert "if (link.getAttribute('href') !== a.url) link.href = a.url;" in attribution
    assert "setText(link, a.text || a.url);" in attribution
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
    assert "const list = data.listed, n = list.length;" in table and "pointOf(o)" in table
    assert "['On the globe', false]" in js and ": 'no known point');" in js
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
