// The globe every app's page can draw (liminal-libs ui/static, for the plugins' World Wide Web tabs, 2026-11-14): the
// places this machine's traffic comes from and goes to, each a dot with its route to this machine. The user,
// 2026-11-14: "so for the firewall's both are going to get a 'world wide web view' that shows the globe and the routes
// incoming all traffic, as well as monitoring port traffic stats". And, 2026-11-16: "the firewall app should also have
// a globe that can be zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time they are
// connected to *this *computer"; "the globe-firewall should allow filtering, so i can view apps connected to hosts all
// across the globe, or ports talking to all hosts. The globe should have the same kind of geography associated with
// the exchanges globe, but the firewall globe should instead of exchanges, have all the backbones,ibones, major
// internet infrastructure, (as many as possible) datacenter locations." The math and the gestures are the charts
// app's (globe.js, its Markets view): the orthographic projection, project / unproject / polyline broken on the far
// side, decodeTopo and its loader, a drag past a slop, the wheel and two fingers zooming about the point under them,
// a double click (or two taps) back home. One 2D canvas, sharp at the screen's pixel ratio; no libraries.
//
//   const globe = LiminalGlobe.draw(el, spec, {theme, load, key})   el: the element it fills (drawn into again: it
//   globe.update(spec)                                               is updated in place, its view kept)
//   globe.destroy()
//   spec: a tab page's "globe" (apps/tabs.py): {home: {lat, lon, label} | null, origins: [{id, lat, lon, label,
//     country, city, asn, org, count, bytes, kind, ports, hosts, programs, seconds}], local: {count, bytes, hosts},
//     attribution: {text, url} | null, updated, note, kinds: [the kinds its legend lists], showing: the filter in
//     words, layers: [{id, title, kind: "points" | "lines", mark: "circle" | "square" | "diamond" | "line" | "dash",
//     slot: 4 to 7, on, names_from, count, version, credits: [{text, url}], note}], layer_hook}
//   theme: the page's theme or its base ("dark", "paper", ...), for the colours of a page without liminal.css's
//     variables
//   load: (layerId) => a Promise of that layer's geometry, as machines/infrastructure.py's Index.layer answers it:
//     {id, version, parts: [{set, credit: {text, url}, points: {n, xy, names, subs}, lines: {n, offsets, xy, names}}]},
//     xy the base64 of little-endian int32 pairs (lon, lat in 1e-5 degrees), offsets the base64 of n + 1 little-endian
//     uint32 (where each line's vertices begin). The page gives it, and asks the spec's layer_hook with it: the globe
//     itself asks for nothing but its map. Without it every layer stays off, and its switch says why.
//   key: a name the layers' switches are remembered under in this browser (localStorage); without it they last as
//     long as the globe does.
//
// - The map is world-atlas 2.0.2 (Natural Earth, public domain) beside this file: vendor/world/countries-110m.json,
//   countries-50m.json only once a globe is zoomed past 2.5x and countries-10m.json past 12x; one copy serves every
//   globe on the page, and the finer two go with the last globe. The land is cut where it goes behind the globe and
//   closed along the rim the way round its own outline goes, so a coast on the horizon is land to the rim and the sea
//   round it stays sea, from any side.
// - It zooms to MAX_ZOOM, 96x (the user, 2026-11-19: "i need to zoom in a few more times maybe 96x"), by the wheel,
//   two fingers, + and −. Past 24x its coasts and borders are GSHHG's, points some 200 m apart (vendor/world/coast-h/,
//   LGPL-3.0, credited while they are drawn), in tiles of 10 degrees: only the tiles on the canvas are asked for, the
//   nearest the middle first and no more than are kept, each once, TILE_LOADS at a time and none while the globe
//   glides; MAX_TILES are kept for every globe on the page (the least lately drawn go first) and all go with the last
//   globe; the map's own coasts and borders are drawn under them until every tile on the canvas is in. The map's
//   lines and the tiles' are kept in pieces with their reach, and a piece out of the canvas's sight is skipped, as is
//   a ring of the land; a run of points beyond an edge of the canvas is cut short (trimmed): so a globe zoomed 96x
//   draws what is on its canvas, not the half of the Earth facing it.
// - Each origin is a dot sized by its count, with a great-circle route to home 1.2 + min(3.6, 1.3 log10(count + 1)) px
//   wide, by its kind: allowed in, unanswered in (dashed: no answer seen within 3 s) and out, named in the legend
//   beneath. Private and local peers are never placed: the legend counts them. A place without a known point
//   (geo.Place's lat = lon = None: its country known, not where in it) is not drawn either: it is in its kind's totals,
//   the legend says how many and how much, and the table lists it. Where a plugin's places are hosts it recorded, a
//   place also says its hosts, the programs that talked to them and the time connected; its bytes are said only where
//   there are any; `kinds` names the kinds the legend lists, and `showing` (the filter, in words) stands top left over
//   the map.
// - The layers are a plugin's infrastructure (exchange points, data centres, cables: MAX_LAYERS at most), drawn where
//   the exchanges globe draws its exchanges, with its marks (a circle, a square, a diamond), its clusters and its name
//   boxes. A layer's points are gathered on a screen grid of 24 px: a cell with one is its mark, a cell with more one
//   mark and their count, kept in its cell. Its lines are stroked as the map's, a segment longer than 3 degrees filled
//   in along its great circle when it is made ready, a vertex less than a pixel from the last one drawn left out. Its
//   geometry is asked of the page once a version (not waited for past a minute) and kept as unit vectors, one copy for
//   every globe on the page, let go with the last globe that lists it. The marks and lines are a third layer between
//   the map and the routes, the layer with the most features painted first (the few on top of the many), painted
//   again only when the view, the layers on, their versions or the colours change; their names (LAYER_NAMES at most,
//   from the zoom each layer says) are drawn with the places' names, never over one. A mark or a line under the
//   pointer says its name, its layer, its operator and its credit; a cluster its count and five names. Each layer is a
//   button in the legend, its choice remembered; each layer shown is credited beside the places' attribution. The
//   features have no table (they are thousands): the plugin's own tables count them.
// - The equator is stressed, as on the exchanges globe.
// - The colours are the themes' variables (--series-1..7: the kinds on slots 1 to 3, the layers on 4 to 7; --accent for
//   home, --muted, --text, --frame), read again when the theme changes (the class or data-theme of <html> or <body>,
//   the system's light or dark, or a theme given to update).
// - A mouse hovers a dot, a finger taps it, the keyboard steps through them (the arrows; Home turns back home): its
//   words show, and a keyboard's step is said to a screen reader (a polite live region; the tooltip is not read). The
//   same places are a table beneath, for a screen reader and for reading the numbers. An update changes the words in
//   place (the legend's, the table's rows, the credits' links, the layers' buttons): where the table is scrolled to,
//   what is being read or selected and the focus stay, though a page is asked again every few seconds.
// - It moves (a light travels each of the busiest routes) only while it is on screen and the page is shown, and stands
//   still under prefers-reduced-motion. A frame redraws only the routes and their lights: the map, the layers and the
//   dots are drawn again only when the view, what they show or the colours change. Nothing runs once it is destroyed;
//   a globe whose element left the page is destroyed when the next one is drawn.
// Names come from plugins: every text is set with textContent, and an address is a link only when it is an https one.
(() => {
  'use strict';

  const rad = Math.PI / 180;
  const TAU = 2 * Math.PI;
  const RETRY_MS = 60_000;  // a map that did not load is not asked for again before this (globe.js)
  const FINE_ZOOM = 2.5;  // past it the 1:50m outlines are loaded and drawn
  const FINEST_ZOOM = 12;  // past it the 1:10m outlines
  const COAST_ZOOM = 24;  // past it GSHHG's coasts and borders, the tiles of them on the canvas (vendor/world/coast-h/)
  const MAX_ZOOM = 96;  // GSHHG's detail (about 200 m): some 300 m a pixel at 96x on a globe 520 px high
  const MAX_TILES = 120;  // the coast tiles kept, the least lately drawn let go first (globe.js's)
  const MAX_TILE_POINTS = 1_000_000;  // and their points at most (some 12 MB as unit vectors)
  const TILE_LOADS = 4;  // the coast tiles on their way at once, from every globe on the page (globe.js's)
  // how far a coast tile's points reach from its middle at most, in tiles (GSHHG 2.3.7's furthest: 0.796 of a tile,
  // its lines running on past its edge into the next one's margin)
  const TILE_REACH = 0.85;
  const PIECE = 128;  // points: the map's and the tiles' lines are kept in pieces this long, each skipped out of sight
  const PEN_MARGIN = 16;  // px round the canvas a path is drawn as it is (beyond it a run is cut short: trimmed)
  const COAST_CREDIT = { text: 'Coasts and borders: GSHHG 2.3.7 (LGPL-3.0)', url: '' };  // while its tiles are drawn
  const MAX_ORIGINS = 512;  // the places tabled (and drawn: those with a point), the most connections first (traffic.TrafficBook keeps 512)
  const MAX_READ = 20000;  // the most of a spec's list read at all (the note says how many more there were)
  // a spec's note, cut past this: the GeoIP file's words, the home's and, where it shows the hosts recorded, theirs
  // (machines/netstat.py), with a path or a library's error in them, fit whole
  const MAX_NOTE = 1200;
  const FRAME_MS = 33;  // about 30 frames a second while the lights move
  const GLIDE_MS = 700;
  const LABELS = 5;  // the busiest places named on the map (the table and the tooltips carry every one)
  const LIGHTS = 64;  // the busiest routes a light travels (the rest stand still: a frame stays cheap)
  const MAX_LAYERS = 8;  // the infrastructure layers of a spec that are listed (how many more there were is said)
  const MAX_LAYER_POINTS = 20000;  // a layer's points kept (machines/infrastructure.py packs as many a layer at most)
  const MAX_LAYER_VERTICES = 400000;  // a layer's line vertices kept, the ones filled in among them
  const MAX_PARTS = 16;  // the parts (one a data set) of a layer's answer that are read
  const LAYER_NAMES = 12;  // the layers' names on the map at once (a mark's words carry every one)
  const NAME = 80;  // a feature's name or operator, cut (as infrastructure.NAME)
  const CELL = 24;  // px: the screen grid a layer's points are gathered on: a cell is one mark, or one mark and a count
  const LINE_CELL = 8;  // the lines a cell keeps for the pointer (where more cross it, the cells round it hold them)
  const FILL = 3;  // degrees: a line's segment longer than this is filled in along its great circle (the routes' step)
  const THIN = 0.75;  // px: a line's vertex nearer than this to the last one drawn is left out
  const LOAD_MS = 60_000;  // a layer the page has not answered for within this is not loaded (and asked again later)
  const MAX_VIA = 32;  // hops a place's line runs through at most (machines/routes.py's MAX_VIA)
  const MAX_ROUTE_POINTS = 128;  // points a route's line is drawn with at most, whatever its hops
  const LAYER_SLOTS = [4, 5, 6, 7];  // the themes' series slots the kinds leave free
  // a layer's mark, and what it marks: the exchanges globe's circle, square and diamond for points; for lines a plain
  // stroke or a dashed one
  const MARKS = { circle: 'points', square: 'points', diamond: 'points', line: 'lines', dash: 'lines' };
  const DASH = [4, 3];
  const STORE = 'liminal-globe-layers:';  // and opts.key after it: where this browser remembers the layers' switches
  const NO_LOADER = 'this page gives the globe no way to load it';
  // Each kind keeps its slot (the charts' in and out are slots 1 and 2); the first three slots are the ones that tell
  // every pair apart (the dataviz validator, all pairs, both bases), and the dash says "unanswered" without colour.
  const KINDS = {
    allowed: { slot: 1, dash: null, words: 'Allowed in', noun: 'connection', tip: 'allowed in: this machine answered' },
    unanswered: { slot: 3, dash: [5, 4], words: 'Unanswered in', noun: 'attempt', tip: 'unanswered in: no answer seen within 3 s' },
    outbound: { slot: 2, dash: null, words: 'Out', noun: 'connection', tip: 'out: this machine reached it' },
  };
  const BASES = { dark: 'dark', midnight: 'dark', graphite: 'dark', light: 'light', paper: 'light' };
  const FALLBACK = {  // liminal.css's own values, for a page without its variables
    dark: { series: ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9'], accent: '#2962ff',
      muted: '#787b86', text: '#d1d4dc', frame: '#2a2e39', surface: '#131722',
      land: '#3edb65', network: '#8fa3bf' },
    light: { series: ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6'], accent: '#1f4fd8',
      muted: '#474c59', text: '#0f1219', frame: '#cdd3dd', surface: '#f3f4f7',
      land: '#2e8b57', network: '#5b6f8a' },
  };
  // 1.66.1 (the user, 2026-11-19: "the land borders should be green", "lets use faint grey-green, (matrix green)",
  // "use grey blue for the routes, hubs, bones, underwater cables", "only end points of routes are colored"): the
  // coasts and borders are drawn in --globe-land, the routes and every layer in --globe-network; a kind's colour
  // marks only a route's ends (its place's dot) and the legend's kinds.
  // the map beside this file (vendor/world/), wherever the page is served from (a front proxying an app's pages too)
  const HERE = (() => {
    try { return new URL('.', (document.currentScript && document.currentScript.src) || location.href).href; } catch (e) { return ''; }
  })();
  // a file of the map's beside this file (a map, the coast tiles' index, a tile): all the globe itself asks for
  const world = (name) => fetch(`${HERE}vendor/world/${name}`, { credentials: 'same-origin' });

  const own = (o, k) => typeof k === 'string' && Object.prototype.hasOwnProperty.call(o, k);  // a kind or a theme by name only
  const text = (v, max = 200) => (v == null ? '' : String(v).slice(0, max));
  const num = (v) => (typeof v === 'number' ? (Number.isFinite(v) ? v : null)
    : typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v)) ? Number(v) : null);
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const wrap = (d) => ((((d + 180) % 360) + 360) % 360) - 180;
  const safeUrl = (u) => (/^https:\/\/[^\s"'<>]+$/i.test(String(u ?? '').trim()) ? String(u).trim() : '');
  const unit = (lon, lat) => [Math.cos(lat * rad) * Math.cos(lon * rad), Math.cos(lat * rad) * Math.sin(lon * rad), Math.sin(lat * rad)];
  const dotRadius = (count) => 4 + Math.min(5, 1.5 * Math.log10(count + 1));  // 8 px across at least, larger with its count
  const routeWidth = (count) => 1.2 + Math.min(3.6, 1.3 * Math.log10(count + 1));
  const smooth = (a, b, x) => { const t = clamp((x - a) / (b - a), 0, 1); return t * t * (3 - 2 * t); };
  const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  function bytes(n) {  // as charts.js
    if (n == null || !Number.isFinite(n)) return '–';
    let v = Math.abs(n), i = 0;
    while (v >= 1024 && i < UNITS.length - 1) { v /= 1024; i++; }
    return `${i === 0 || v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${UNITS[i]}`;
  }
  const many = (n, noun) => `${Math.round(n).toLocaleString()} ${noun}${Math.round(n) === 1 ? '' : 's'}`;
  function duration(s) {  // a time connected, in two units at most: "45 s", "12 min 5 s", "3 h 20 min", "2 d 4 h"
    const n = Math.round(s), two = (a, first, b, second) => (b ? `${a} ${first} ${b} ${second}` : `${a} ${first}`);
    if (n < 60) return `${n} s`;
    if (n < 3600) return two(Math.floor(n / 60), 'min', n % 60, 's');
    if (n < 86400) return two(Math.floor(n / 3600), 'h', Math.floor((n % 3600) / 60), 'min');
    return two(Math.floor(n / 86400), 'd', Math.floor((n % 86400) / 3600), 'h');
  }
  // a cluster's count on its mark, in four characters at most
  const short = (n) => (n < 1000 ? String(n) : n < 9950 ? `${(n / 1000).toFixed(1)}k` : `${Math.round(n / 1000)}k`);
  const cut = (s, max) => (s.length > max ? `${s.slice(0, max - 1)}…` : s);
  // the point a part `t` of the way along the great circle from a to b, unit vectors `w` apart
  function slerp(a, b, w, t) {
    const s = Math.sin(w), p = Math.sin((1 - t) * w) / s, q = Math.sin(t * w) / s;
    return [p * a[0] + q * b[0], p * a[1] + q * b[1], p * a[2] + q * b[2]];
  }
  // An element's words set only when they change, and then in its own text node: a selection in it, or the place a
  // screen reader is reading, stays through an update that changed nothing there.
  function setText(el, words) {
    if (el.textContent === words) return;
    const t = el.firstChild;
    if (words && t && t.nodeType === 3 && !t.nextSibling) t.data = words;
    else el.textContent = words;
  }
  const show = (el, on) => { if (el.hidden === on) el.hidden = !on; };  // shown or hidden, touched only when it changes
  // The indexes of a longest increasing run in `seq` (where each row stands now; -1 for a row not there yet): the rows
  // that need not move for the rest to be put in order round them (patience sorting, O(n log n)).
  function steady(seq) {
    const tails = [], prev = new Int32Array(seq.length).fill(-1), out = new Set();
    for (let i = 0; i < seq.length; i++) {
      const v = seq[i];
      if (v < 0) continue;
      let lo = 0, hi = tails.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (seq[tails[mid]] < v) lo = mid + 1; else hi = mid; }
      if (lo > 0) prev[i] = tails[lo - 1];
      tails[lo] = i;
    }
    for (let i = tails.length ? tails[tails.length - 1] : -1; i >= 0; i = prev[i]) out.add(i);
    return out;
  }
  // `nodes` put in their order in `box`, before `end` (a child of it, or null: at its end): the longest run of them
  // already in their order stays where it is (steady) and only the others move. The caller takes the nodes no longer
  // listed out first, so the focus on one that stays, or a click, stays through an update that took another away or
  // put one in.
  function arrange(box, nodes, end = null) {
    const now = new Map();
    let i = 0;
    for (let node = box.firstChild; node && node !== end; node = node.nextSibling) now.set(node, i++);
    const stay = steady(nodes.map((node) => (now.has(node) ? now.get(node) : -1)));
    let ref = end;
    for (let k = nodes.length - 1; k >= 0; k--) {
      if (!stay.has(k)) box.insertBefore(nodes[k], ref);
      ref = nodes[k];
    }
  }
  // a media query's changes, by addEventListener (or addListener: Safari before 14, as touch.js has it)
  const listen = (q, fn) => { if (q && q.addEventListener) q.addEventListener('change', fn); else if (q && q.addListener) q.addListener(fn); };
  const unlisten = (q, fn) => { if (q && q.removeEventListener) q.removeEventListener('change', fn); else if (q && q.removeListener) q.removeListener(fn); };
  function seedOf(s) {  // a route's own phase, from its id: the lights do not move in step
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return ((h >>> 0) % 10007) / 10007;
  }

  // -- what is drawn only where it can be seen: pieces with their reach, the canvas's sight, paths cut short ----------
  // A line's middle and how far it reaches from it: [x, y, z, radians], the mean of its points (unit vectors, `from` to
  // `to` of `v`) made a unit vector, and the angle to its point furthest from it. A line with no middle (it goes right
  // round) reaches everywhere: it is never skipped.
  function capOf(v, from = 0, to = v.length) {
    let mx = 0, my = 0, mz = 0, reach = Math.PI;
    for (let i = from; i < to; i += 3) { mx += v[i]; my += v[i + 1]; mz += v[i + 2]; }
    const len = Math.hypot(mx, my, mz);
    if (len > 1e-6) {
      let least = 1;
      for (let i = from; i < to; i += 3) least = Math.min(least, (mx * v[i] + my * v[i + 1] + mz * v[i + 2]) / len);
      reach = Math.acos(clamp(least, -1, 1));
    }
    return [mx / (len || 1), my / (len || 1), mz / (len || 1), reach];
  }
  // Lines of unit vectors (each a typed array of x, y, z a point) kept as one set: their points in one array of 4-byte
  // numbers (some 0.4 m on the Earth, a hundredth of a pixel at 96x), cut into pieces of PIECE points at most (a piece
  // starts where the one before it ended, so a line has no gap), each with its middle and its reach (capOf), to be
  // skipped while it is out of sight. {n, v, starts, caps}: piece j is v's points starts[j] to starts[j + 1].
  function piecesOf(lines) {
    let points = 0, n = 0;
    for (const l of lines) {
      const m = l.length / 3, p = Math.ceil((m - 1) / (PIECE - 1));
      if (m >= 2) { points += m + p - 1; n += p; }
    }
    const v = new Float32Array(points * 3), starts = new Uint32Array(n + 1), caps = new Float32Array(n * 4);
    let at = 0, j = 0;
    for (const l of lines) {
      const m = l.length / 3;
      if (m < 2) continue;  // no line
      for (let s = 0; s < m - 1; s += PIECE - 1, j++) {
        const e = Math.min(m, s + PIECE);  // its points s to e - 1, the last of them the next piece's first
        starts[j] = at;
        v.set(l.subarray(s * 3, e * 3), at * 3);
        caps.set(capOf(v, at * 3, (at + e - s) * 3), j * 4);
        at += e - s;
      }
    }
    starts[n] = at;
    return { n, v, starts, caps };
  }
  // How far round from the middle of the view the canvas shows, in radians and a little more: the whole half of the
  // globe in front while the globe is no larger than the canvas's diagonal, less the nearer it is zoomed.
  function sightOf(g) {
    const half = Math.hypot(g.w / 2, g.h / 2);
    return (g.r > half ? Math.asin(half / g.r) : Math.PI / 2) + 0.01;
  }
  // Whether a piece can be on the canvas: its middle (caps[q] to caps[q + 2]) within the sight and its reach of the
  // middle of the view C. A piece out of it has every point (and every short step between them) off the canvas.
  const inSight = (caps, q, C, sight) => Math.acos(clamp(caps[q] * C[0] + caps[q + 1] * C[1] + caps[q + 2] * C[2],
    -1, 1)) <= sight + caps[q + 3];
  // A path put on a canvas (its moveTo, lineTo, arc and closePath) with its runs off the canvas cut short: of three
  // points in a row beyond the same edge of it, PEN_MARGIN px out, the middle one is left out. The path left out and
  // the line put for it lie beyond that edge, so what is filled (any rule) or stroked on the canvas is the same, and a
  // coast that runs on for thousands of points off a globe zoomed 96x is a few points here. done() puts the last one.
  function trimmed(c, w, h) {
    const m = PEN_MARGIN, side = (x, y) => (x < -m ? 1 : x > w + m ? 2 : 0) | (y < -m ? 4 : y > h + m ? 8 : 0);
    let held = false, hx = 0, hy = 0, hs = 0, ls = 0;  // the point held back and its side; the side of the last put
    const put = () => { if (held) { c.lineTo(hx, hy); ls = hs; held = false; } };
    return {
      moveTo(x, y) { put(); c.moveTo(x, y); ls = side(x, y); },
      lineTo(x, y) {
        const s = side(x, y);
        if (!(held && (ls & hs & s))) put();  // else the one held is left out: it, the last put and this one are out
        held = true; hx = x; hy = y; hs = s;
      },
      arc(x, y, r, a, b, ccw) {
        put();
        c.arc(x, y, r, a, b, ccw);
        ls = side(x + r * Math.cos(b), y + r * Math.sin(b));  // where it ends
      },
      closePath() { put(); c.closePath(); },
      done: put,
    };
  }

  // -- the map: loaded once for every globe on the page -----------------------------------------------------------
  // A loader the drawing may call every frame: one request at a time, and after a failure none again for RETRY_MS.
  // `fn` resolves true when it loaded.
  function loader(fn) {
    let busy = false, next = 0;
    return () => {
      if (busy || Date.now() < next) return;
      busy = true;
      fn().then((ok) => { if (!ok) next = Date.now() + RETRY_MS; }, () => { next = Date.now() + RETRY_MS; })
        .finally(() => { busy = false; });
    };
  }

  // TopoJSON arcs -> polylines in degrees (each shared border drawn once). A quantized topology's arcs are steps from
  // the point before (world-atlas's are); a plain one's are the points themselves.
  function decodeTopo(t) {
    const quantized = !!t.transform;
    const [sx, sy] = quantized ? t.transform.scale : [1, 1];
    const [tx, ty] = quantized ? t.transform.translate : [0, 0];
    return t.arcs.map((arc) => {
      let x = 0, y = 0;
      return arc.map(([dx, dy]) => {
        if (quantized) { x += dx; y += dy; } else { x = dx; y = dy; }
        return [x * sx + tx, y * sy + ty];
      });
    });
  }

  // Which way a ring of unit vectors goes round, seen from outside the globe: the sign of its area, the sum of the
  // triangles from the middle of its points to each of its edges (Van Oosterom and Strackee's solid angle). The data's
  // outer rings go clockwise, the land on their right, and so they do on the screen (east to the right, north up); its
  // holes go the other way. A ring cut by the horizon is closed along the rim the same way round: +1 the way the
  // canvas's angles grow (clockwise on the screen), -1 against it. Worked out here, not taken on trust from the data.
  function turnOf(v) {
    let mx = 0, my = 0, mz = 0;
    for (let i = 0; i < v.length; i += 3) { mx += v[i]; my += v[i + 1]; mz += v[i + 2]; }
    const n = Math.hypot(mx, my, mz) || 1;
    mx /= n; my /= n; mz /= n;
    let area = 0;
    for (let i = 0; i < v.length; i += 3) {
      const j = (i + 3) % v.length;  // the last point back to the first
      const ax = v[i], ay = v[i + 1], az = v[i + 2], bx = v[j], by = v[j + 1], bz = v[j + 2];
      const cx = ay * bz - az * by, cy = az * bx - ax * bz, cz = ax * by - ay * bx;  // a × b
      area += Math.atan2(mx * cx + my * cy + mz * cz,
        1 + mx * ax + my * ay + mz * az + ax * bx + ay * by + az * bz + bx * mx + by * my + bz * mz);
    }
    return area < 0 ? 1 : -1;
  }
  // A ring of the land (arc indexes, ~i: arc i backwards) as one line of unit vectors, its closing point (its first again)
  // dropped, with its turn and its middle and reach (capOf: a ring out of sight is skipped, its land with it, as all of
  // it is on the side its turn closes it round, within its reach); null for a ring of fewer than three points or one
  // naming an arc the map lacks. It is drawn from 4-byte numbers; its turn is worked out from the 8-byte ones.
  function landRing(ring, arcs) {
    const pts = [];
    for (let n = 0; n < ring.length; n++) {
      const i = ring[n], v = arcs[i < 0 ? ~i : i];
      if (!v) return null;
      const count = v.length / 3;
      for (let s = n === 0 ? 0 : 1; s < count; s++) {  // an arc after the first starts where the one before it ended
        const k = (i < 0 ? count - 1 - s : s) * 3;
        pts.push(v[k], v[k + 1], v[k + 2]);
      }
    }
    let m = pts.length;
    if (m >= 6 && pts[0] === pts[m - 3] && pts[1] === pts[m - 2] && pts[2] === pts[m - 1]) m -= 3;
    if (m < 9) return null;
    const v = new Float64Array(m);
    for (let k = 0; k < m; k++) v[k] = pts[k];
    const kept = new Float32Array(v);
    return { v: kept, turn: turnOf(v), cap: capOf(kept) };
  }

  // The map ready to draw: the lines stroked as unit vectors (x, y, z a point: the coasts, and the borders two countries
  // share), without the data's cut lines along the antimeridian and round the South Pole, in pieces (piecesOf); and the
  // land's rings. Its arcs are read as decodeTopo reads them, straight into unit vectors: the 1:10m map's 477,000
  // points are not made into pairs first.
  function prepare(t) {
    const quantized = !!t.transform;
    const [sx, sy] = quantized ? t.transform.scale : [1, 1];
    const [tx, ty] = quantized ? t.transform.translate : [0, 0];
    const seam = (lon1, lat1, lon2, lat2) => (Math.abs(lon1) > 179.99 && Math.abs(lon2) > 179.99)
      || (lat1 < -89.9 && lat2 < -89.9);
    const arcs = [], cuts = [];  // each arc's points as unit vectors, and where the data's cut lines are in it
    for (const arc of t.arcs) {
      const v = new Float64Array(arc.length * 3), at = [];
      let x = 0, y = 0, lon0 = 0, lat0 = 0;
      for (let i = 0; i < arc.length; i++) {
        const [dx, dy] = arc[i];
        if (quantized) { x += dx; y += dy; } else { x = dx; y = dy; }
        const lon = x * sx + tx, lat = y * sy + ty, c = Math.cos(lat * rad);
        v[i * 3] = c * Math.cos(lon * rad); v[i * 3 + 1] = c * Math.sin(lon * rad); v[i * 3 + 2] = Math.sin(lat * rad);
        if (i && seam(lon0, lat0, lon, lat)) at.push(i);
        lon0 = lon; lat0 = lat;
      }
      arcs.push(v);
      cuts.push(at);
    }
    const objects = t.objects || {};
    const polygons = (collection, each) => {
      for (const g of (collection && collection.geometries) || []) {
        if (g.type === 'Polygon') each(g.arcs);
        else if (g.type === 'MultiPolygon') g.arcs.forEach(each);
      }
    };
    const uses = new Uint8Array(arcs.length);  // how many countries' rings take each arc: two make it a border
    polygons(objects.countries, (poly) => poly.forEach((ring) => ring.forEach((i) => {
      const k = i < 0 ? ~i : i;
      if (k < uses.length && uses[k] < 2) uses[k]++;
    })));
    const land = [];
    polygons(objects.land || objects.countries, (poly) => poly.forEach((ring) => {
      const r = landRing(ring, arcs);
      if (r) land.push(r);
    }));
    const coasts = [], borders = [];
    arcs.forEach((v, k) => {  // each arc cut where the data's cut lines are, a border where two countries take it
      const piece = (from, to) => {
        if (to - from > 1) (uses[k] >= 2 ? borders : coasts).push(v.subarray(from * 3, to * 3));
      };
      let start = 0;
      for (const i of cuts[k]) { piece(start, i); start = i; }
      piece(start, v.length / 3);
    });
    return { land, coasts: piecesOf(coasts), borders: piecesOf(borders) };
  }

  const maps = { coarse: null, fine: null, finest: null };  // 1:110m, 1:50m and 1:10m
  const globes = new Set();  // the globes drawn now (each redrawn when a map comes)
  const mapLoader = (name, key) => loader(async () => {
    try {
      const res = await world(name);
      if (!res.ok) return false;
      const map = prepare(await res.json());
      if (key !== 'coarse' && !globes.size) return true;  // every globe went meanwhile: not kept
      maps[key] = map;
      globes.forEach((g) => g.mapArrived());
      return true;
    } catch (e) { return false; }  // the coarser outlines meanwhile, or the sphere and its graticule alone
  });
  const loadCoarse = mapLoader('countries-110m.json', 'coarse');
  const loadFine = mapLoader('countries-50m.json', 'fine');
  const loadFinest = mapLoader('countries-10m.json', 'finest');

  // -- the coasts past COAST_ZOOM: GSHHG's, in tiles, loaded for every globe on the page ------------------------------
  // liminal-charts' tools/build_coastlines.py made them from GSHHG 2.3.7's high resolution: coast-h/index.json names
  // the tiles there are, their size and their margin; a tile, <lat0>_<lon0>.bin by its south-west corner, is "GSH1"
  // and two sections, its shorelines (land, lakes, the Antarctic ice front and grounding line) and its national
  // borders, each a uint32 count of lines, each line a uint32 count of points and as many uint16 pairs (lon, lat): from
  // the tile's corner less its margin, across the tile and both margins in 65,535 steps; little-endian. In `tiles` a
  // tile is a token while it is on its way, then its lines; one that could not be had is not asked for again before
  // RETRY_MS.
  const coast = { index: null, tiles: new Map(), failed: new Map(), loading: 0, points: 0 };
  // The index made safe: the size of a tile (degrees, a divisor of 180), its margin, and each tile it names that is a
  // tile of the globe, with its middle as a unit vector and its points (its shorelines' and its borders', as the index
  // counts them: 0 where it does not); null for what is not an index.
  function coastIndex(d) {
    const tile = num(d && d.tile), margin = num(d && d.margin);
    if (tile == null || tile <= 0 || tile > 90 || 180 % tile !== 0 || margin == null || margin < 0 || margin > tile
      || !d.tiles || typeof d.tiles !== 'object' || Array.isArray(d.tiles)) return null;
    const list = [], count = (v) => Math.max(0, num(v) || 0);
    for (const name of Object.keys(d.tiles).slice(0, (180 / tile) * (360 / tile))) {
      const m = /^(-?\d{1,2})_(-?\d{1,3})$/.exec(name), lat0 = m ? Number(m[1]) : NaN, lon0 = m ? Number(m[2]) : NaN;
      const whole = lat0 >= -90 && lat0 + tile <= 90 && lon0 >= -180 && lon0 + tile <= 180;
      if (!whole || lat0 % tile || lon0 % tile) continue;  // not one of the globe's tiles of this size
      const said = d.tiles[name] && typeof d.tiles[name] === 'object' ? d.tiles[name] : {};
      list.push({ name, lat0, lon0, c: unit(lon0 + tile / 2, lat0 + tile / 2),
        points: count(said.shore) + count(said.borders) });
    }
    return list.length ? { tile, margin, reach: TILE_REACH * tile * rad, list } : null;
  }
  const loadCoast = loader(async () => {
    try {
      const res = await world('coast-h/index.json');
      const index = res.ok ? coastIndex(await res.json()) : null;
      if (!index) return false;
      if (!globes.size) return true;  // every globe went meanwhile: not kept
      coast.index = index;
      globes.forEach((g) => g.mapArrived());
      return true;
    } catch (e) { return false; }  // the map's own coasts meanwhile
  });
  // A tile made ready to draw: its shorelines and its borders, each as pieces of unit vectors (piecesOf), and how many
  // points it has (as the index counts them: coastTiles picks the tiles to draw by those); null for what is not a tile
  // (no "GSH1" at its head, or a count that runs on past its end).
  function prepareTile(buf, t, index) {
    const dv = new DataView(buf), end = dv.byteLength, step = (index.tile + 2 * index.margin) / 65535;
    const lon0 = t.lon0 - index.margin, lat0 = t.lat0 - index.margin;
    if (end < 12 || dv.getUint32(0) !== 0x47534831) return null;  // "GSH1"
    let off = 4, points = 0;
    const sections = [];
    for (let s = 0; s < 2; s++) {
      if (off + 4 > end) return null;
      const count = dv.getUint32(off, true), lines = [];
      off += 4;
      for (let i = 0; i < count; i++) {
        if (off + 4 > end) return null;
        const n = dv.getUint32(off, true);
        if (off + 4 + n * 4 > end) return null;
        off += 4;
        points += n;
        const v = new Float32Array(n * 3);
        for (let k = 0; k < n * 3; k += 3, off += 4) {
          const lon = (lon0 + dv.getUint16(off, true) * step) * rad;
          const lat = (lat0 + dv.getUint16(off + 2, true) * step) * rad, c = Math.cos(lat);
          v[k] = c * Math.cos(lon); v[k + 1] = c * Math.sin(lon); v[k + 2] = Math.sin(lat);
        }
        lines.push(v);
      }
      sections.push(piecesOf(lines));
    }
    const [coasts, borders] = sections;
    return { coasts, borders, points };
  }
  // The tiles kept within MAX_TILES and MAX_TILE_POINTS: the least lately drawn go first, never one on its way.
  function keepTiles() {
    for (const [name, t] of coast.tiles) {
      if (coast.tiles.size <= MAX_TILES && coast.points <= MAX_TILE_POINTS) return;
      if (t.loading) continue;
      coast.tiles.delete(name);
      coast.points -= t.points;
    }
  }
  // The tiles a globe has on its canvas: each here is touched (put last: the least lately drawn are let go first);
  // each not here asked for, once (its token stands for it while it is on its way), TILE_LOADS at a time from every
  // globe, and every globe told when it came or could not. One that comes when every globe went is not kept.
  function askTiles(want) {
    for (const t of want) {
      const had = coast.tiles.get(t.name);
      if (had) { coast.tiles.delete(t.name); coast.tiles.set(t.name, had); continue; }
      if (coast.loading >= TILE_LOADS || Date.now() < (coast.failed.get(t.name) || 0)) continue;
      const token = { loading: true }, index = coast.index;
      coast.tiles.set(t.name, token);
      coast.loading++;
      const settle = (tile) => {
        if (coast.tiles.get(t.name) !== token) return;  // let go meanwhile, with the last globe
        if (tile) {
          coast.tiles.set(t.name, tile);
          coast.points += tile.points;
          keepTiles();
        } else {
          coast.tiles.delete(t.name);
          coast.failed.set(t.name, Date.now() + RETRY_MS);
        }
        globes.forEach((g) => g.mapArrived());
      };
      world(`coast-h/${t.name}.bin`).then((res) => (res.ok ? res.arrayBuffer() : null)).then((buf) => {
        let tile = null;
        try { tile = buf ? prepareTile(buf, t, index) : null; } catch (e) { tile = null; }
        settle(tile);
      }, () => settle(null)).finally(() => { coast.loading--; });
    }
  }
  // Every tile, the index and the tiles that failed let go (the last globe went): a tile on its way is then not kept.
  function forgetCoast() {
    coast.index = null;
    coast.tiles.clear();
    coast.failed.clear();
    coast.points = 0;
  }

  // the graticule every 15 degrees (globe.js), made once
  let graticule = null;
  const graticuleLines = () => graticule || (graticule = [
    ...Array.from({ length: 24 }, (_, m) => Array.from({ length: 91 }, (__, i) => [-180 + m * 15, -90 + i * 2])),
    ...Array.from({ length: 11 }, (_, p) => Array.from({ length: 181 }, (__, i) => [-180 + i * 2, -75 + p * 15])),
  ]);
  const EQUATOR = 24 + 5;  // which of them is the equator: after the 24 meridians, the sixth parallel from -75

  // -- the layers: a plugin's infrastructure, loaded once for every globe on the page ---------------------------------
  // base64 -> its bytes (a layer's packed numbers); null for what is not base64
  function bytesOf(b64) {
    let s = '';
    try { s = atob(typeof b64 === 'string' ? b64 : ''); } catch (e) { return null; }
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  // A mark's path, as the exchanges globe's markers: a circle, a square or a diamond `r` large (the caller fills it).
  function markPath(c, mark, x, y, r) {
    if (mark === 'square') c.rect(x - r * 0.9, y - r * 0.9, r * 1.8, r * 1.8);
    else if (mark === 'diamond') {
      c.moveTo(x, y - r * 1.25); c.lineTo(x + r * 1.25, y); c.lineTo(x, y + r * 1.25); c.lineTo(x - r * 1.25, y);
      c.closePath();
    } else { c.moveTo(x + r, y); c.arc(x, y, r, 0, TAU); }
  }
  // A layer's answer (machines/infrastructure.py's Index.layer) made ready to draw: its points and its lines as unit
  // vectors (x, y, z a point, as the map's), each feature with its name and the part (so the credit) it came from. xy
  // is little-endian int32 pairs, lon and lat in 1e-5 degrees; offsets little-endian uint32, where each line begins.
  // Kept: the first MAX_LAYER_POINTS points, and whole lines while they fit in MAX_LAYER_VERTICES; `cut` counts the
  // features left out. A line's segment longer than FILL degrees is filled in along its great circle, so a cable of
  // few vertices bends with the globe; each line has its middle and its reach, to be skipped while it is out of sight.
  function prepareLayer(answer) {
    if (!answer || typeof answer !== 'object' || !Array.isArray(answer.parts)) return null;
    const parts = answer.parts.slice(0, MAX_PARTS).map((p) => (p && typeof p === 'object' ? p : {}));
    const within = (lon, lat) => Math.abs(lat) <= 90 && Math.abs(lon) <= 180;  // a point of the globe
    const pv = [], points = { n: 0, v: null, names: [], subs: [], part: [] };
    let cut = 0;
    parts.forEach((p, k) => {
      const given = p.points && typeof p.points === 'object' ? p.points : null, raw = given ? bytesOf(given.xy) : null;
      if (!raw) return;
      const xy = new DataView(raw.buffer), n = Math.min(Math.max(0, num(given.n) ?? 0), Math.floor(raw.length / 8));
      const names = Array.isArray(given.names) ? given.names : [], subs = Array.isArray(given.subs) ? given.subs : [];
      for (let i = 0; i < n; i++) {
        const lon = xy.getInt32(i * 8, true) / 1e5, lat = xy.getInt32(i * 8 + 4, true) / 1e5;
        if (!within(lon, lat)) continue;
        if (points.n >= MAX_LAYER_POINTS) { cut += n - i; break; }
        pv.push(...unit(lon, lat));
        points.names.push(text(names[i], NAME));
        points.subs.push(text(subs[i], NAME));
        points.part.push(k);
        points.n++;
      }
    });
    points.v = Float32Array.from(pv);
    let lv = new Float32Array(3 * 4096), ln = 0;  // the lines' vertices, the array grown as they come
    const lines = { n: 0, v: null, starts: [0], caps: null, names: [], part: [] }, fill = FILL * rad;
    parts.forEach((p, k) => {
      const given = p.lines && typeof p.lines === 'object' ? p.lines : null;
      const raw = given ? bytesOf(given.xy) : null, offs = given ? bytesOf(given.offsets) : null;
      if (!raw || !offs) return;
      const xy = new DataView(raw.buffer), at = new DataView(offs.buffer), all = Math.floor(raw.length / 8);
      const n = Math.min(Math.max(0, num(given.n) ?? 0), Math.floor(offs.length / 4) - 1);
      const names = Array.isArray(given.names) ? given.names : [];
      for (let j = 0; j < n; j++) {
        const from = at.getUint32(j * 4, true), to = Math.min(all, at.getUint32(j * 4 + 4, true)), one = [];
        let a = null;
        for (let i = from; i < to && one.length <= MAX_LAYER_VERTICES * 3; i++) {
          const lon = xy.getInt32(i * 8, true) / 1e5, lat = xy.getInt32(i * 8 + 4, true) / 1e5;
          if (!within(lon, lat)) continue;
          const b = unit(lon, lat);
          if (a) {
            const w = 2 * Math.asin(Math.min(1, Math.hypot(b[0] - a[0], b[1] - a[1], b[2] - a[2]) / 2));
            if (w < 1e-9) continue;  // the same point again
            const steps = w > fill && Math.sin(w) > 1e-6 ? Math.ceil(w / fill) : 1;
            for (let s = 1; s < steps; s++) one.push(...slerp(a, b, w, s / steps));
          }
          one.push(b[0], b[1], b[2]);
          a = b;
        }
        const m = one.length / 3;
        if (m < 2) continue;  // no line
        if (ln + m > MAX_LAYER_VERTICES) { cut++; continue; }
        if ((ln + m) * 3 > lv.length) {
          const grown = new Float32Array(Math.min(MAX_LAYER_VERTICES * 3, Math.max(lv.length * 2, (ln + m) * 3)));
          grown.set(lv.subarray(0, ln * 3));
          lv = grown;
        }
        lv.set(one, ln * 3);
        ln += m;
        lines.starts.push(ln);
        lines.names.push(text(names[j], NAME));
        lines.part.push(k);
        lines.n++;
      }
    });
    lines.v = lv.slice(0, ln * 3);
    lines.caps = new Float32Array(lines.n * 4);  // a line's middle (a unit vector) and its reach from it (radians)
    for (let j = 0; j < lines.n; j++) lines.caps.set(capOf(lv, lines.starts[j] * 3, lines.starts[j + 1] * 3), j * 4);
    return { points: points.n ? points : null, lines: lines.n ? lines : null,
      credits: parts.map((p) => creditOf(p.credit)), cut };
  }
  const featuresOf = (geo) => (geo.points ? geo.points.n : 0) + (geo.lines ? geo.lines.n : 0);

  // A layer's geometry by its id and version ("<id>\n<version>": a layer's `key`) -> {state: 'loading' | 'ready' |
  // 'failed', geo, why, retry, timer}: one copy for every globe on the page, as the maps.
  const layerData = new Map();
  // What no globe lists any more is let go, and so is a load still on its way (its deadline with it); with the last
  // globe, everything.
  function pruneLayers() {
    const listed = new Set();
    globes.forEach((g) => g.layerKeys().forEach((key) => listed.add(key)));
    for (const [key, entry] of [...layerData]) {
      if (!listed.has(key)) { clearTimeout(entry.timer); layerData.delete(key); }
    }
  }
  // A layer asked of the page's loader, once a version: every globe is told when it came or could not. An answer that
  // does not come within LOAD_MS is not waited for: the layer is not loaded, and says so (one that comes later is
  // still taken). After a failure it is not asked again before RETRY_MS (as the map).
  function askLayer(l, load) {
    const was = layerData.get(l.key);
    if (was && (was.state !== 'failed' || Date.now() < was.retry)) return;
    const entry = { state: 'loading', geo: null, why: '', retry: 0, timer: 0 };
    layerData.set(l.key, entry);
    const settle = (geo, why) => {
      if (layerData.get(l.key) !== entry) return;  // no globe lists it any more: not kept
      clearTimeout(entry.timer);
      Object.assign(entry, geo ? { state: 'ready', geo } : { state: 'failed', why, retry: Date.now() + RETRY_MS });
      globes.forEach((g) => g.layerArrived());
    };
    entry.timer = setTimeout(() => {
      if (entry.state === 'loading') settle(null, `the page gave no answer for it within ${LOAD_MS / 1000} s`);
    }, LOAD_MS);
    let asked = null;
    try { asked = Promise.resolve(load(l.id)); } catch (e) { asked = Promise.reject(e); }
    asked.then((answer) => {
      let geo = null;
      try { geo = prepareLayer(answer); } catch (e) { geo = null; }
      settle(geo, 'the page answered with no geometry for it');
    }, (e) => settle(null, text((e && e.message) || e || 'the page could not load it', 200)));
  }
  // The layers' switches as this browser remembers them under `name`: a layer's id -> on or off. Nothing kept, no
  // storage here or what is there not being ours: no switch is remembered, and each layer starts as its spec says.
  function recall(name) {
    const chosen = new Map();
    let kept = null;
    try { kept = name ? JSON.parse(localStorage.getItem(STORE + name) || 'null') : null; } catch (e) { kept = null; }
    if (kept && typeof kept === 'object' && !Array.isArray(kept)) {
      for (const id of Object.keys(kept).slice(0, 64)) {
        if (typeof kept[id] === 'boolean') chosen.set(text(id, 40), kept[id]);
      }
    }
    return chosen;
  }
  function remember(name, chosen) {
    const words = JSON.stringify(Object.fromEntries(chosen));
    try { if (name) localStorage.setItem(STORE + name, words); } catch (e) { /* not kept: it holds for this page */ }
  }

  // -- colours: the themes' variables ---------------------------------------------------------------------------------
  let probe = null;  // a canvas the browser writes any CSS colour out on as #rrggbb or rgba()
  function rgbOf(value, fallback) {
    probe = probe || document.createElement('canvas').getContext('2d');
    for (const c of [value, fallback]) {
      if (!c || !probe) continue;
      probe.fillStyle = '#010203';
      probe.fillStyle = c;
      const s = String(probe.fillStyle);
      if (s === '#010203' && c.trim().toLowerCase() !== '#010203') continue;  // not a colour the browser knows
      const hex = /^#([0-9a-f]{6})$/i.exec(s);
      if (hex) { const n = parseInt(hex[1], 16); return [n >> 16, (n >> 8) & 255, n & 255, 1]; }
      const m = /^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)$/.exec(s);
      if (m) return [+m[1], +m[2], +m[3], m[4] == null ? 1 : +m[4]];
    }
    return [136, 136, 136, 1];
  }
  const mix = (a, b, t) => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t, 1];
  const css = (c, alpha = 1) => `rgba(${Math.round(c[0])},${Math.round(c[1])},${Math.round(c[2])},${+(alpha * c[3]).toFixed(3)})`;
  const luminance = (c) => (0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]) / 255;
  function baseOf(theme) {
    const name = theme && typeof theme === 'object' ? theme.base || theme.theme : theme;
    return own(BASES, name) ? BASES[name] : null;
  }
  // The colour behind the globe: the first element up from it with a background of its own.
  function surfaceOf(node) {
    for (let n = node; n && n.nodeType === 1; n = n.parentElement) {
      const c = rgbOf(getComputedStyle(n).backgroundColor, 'rgba(0, 0, 0, 0)');
      if (c[3] > 0.5) return c;
    }
    return null;
  }
  function readColours(node, theme) {
    const cs = getComputedStyle(node);
    const v = (name) => cs.getPropertyValue(name).trim();
    const surface = surfaceOf(node);
    const base = baseOf(theme) || (surface ? (luminance(surface) > 0.5 ? 'light' : 'dark')
      : document.body && document.body.classList.contains('light') ? 'light' : 'dark');
    const fb = FALLBACK[base];
    return {
      series: fb.series.map((f, i) => rgbOf(v(`--series-${i + 1}`), f)),
      accent: rgbOf(v('--accent'), fb.accent), muted: rgbOf(v('--muted'), fb.muted), text: rgbOf(v('--text'), fb.text),
      frame: rgbOf(v('--frame'), fb.frame), surface: surface || rgbOf(v('--card') || v('--bg'), fb.surface),
      land: rgbOf(v('--globe-land'), fb.land), network: rgbOf(v('--globe-network'), fb.network),
      font: cs.fontFamily || 'system-ui, sans-serif', detached: !node.isConnected,
    };
  }

  // -- what a spec says, made safe to draw ------------------------------------------------------------------------------
  function placeOf(p) {
    if (!p || typeof p !== 'object') return null;
    const lat = num(p.lat), lon = num(p.lon);
    if (lat == null || lon == null || Math.abs(lat) > 90 || Math.abs(lon) > 540) return null;
    return { lat, lon: wrap(lon) };
  }
  // A credit: its words, and its address only when it is an https one; null for one that says nothing.
  function creditOf(a) {
    const c = a && typeof a === 'object' ? { text: text(a.text), url: safeUrl(a.url) } : null;
    return c && (c.text || c.url) ? c : null;
  }
  // The layers a spec lists, made safe: MAX_LAYERS at most, each an id of its own, a mark that fits its kind and one
  // of the slots the kinds leave free. What a layer does not say is the careful answer: off at first, no names on the
  // map.
  function layersOf(list) {
    const layers = [], ids = new Set();
    for (const l of Array.isArray(list) ? list.slice(0, 64) : []) {
      const id = l && typeof l === 'object' && !Array.isArray(l) ? text(l.id, 40) : '';
      if (!id || ids.has(id)) continue;
      ids.add(id);
      if (layers.length >= MAX_LAYERS) continue;  // counted (ids), not listed
      const kind = l.kind === 'lines' ? 'lines' : 'points', version = text(l.version, 40);
      const slot = num(l.slot), from = num(l.names_from), count = num(l.count);
      layers.push({
        id, key: `${id}\n${version}`, version, title: text(l.title, 80) || id, kind,
        mark: own(MARKS, l.mark) && MARKS[l.mark] === kind ? l.mark : kind === 'lines' ? 'line' : 'circle',
        slot: LAYER_SLOTS.includes(slot) ? slot : LAYER_SLOTS[layers.length % LAYER_SLOTS.length],
        on: l.on === true, namesFrom: from != null && from >= 1 ? from : Infinity,
        count: count != null && count >= 0 ? Math.round(count) : null,
        credits: (Array.isArray(l.credits) ? l.credits.slice(0, 8) : []).map(creditOf).filter(Boolean),
        note: text(l.note, 200),
      });
    }
    return { layers, unlisted: ids.size - layers.length };
  }
  function normal(spec) {
    let s = spec && typeof spec === 'object' ? spec : {};
    if (s.globe && typeof s.globe === 'object' && !Array.isArray(s.origins)) s = s.globe;  // a whole tab page given
    const h = placeOf(s.home);
    const given = Array.isArray(s.origins) ? s.origins : [];
    // Every origin read, the most connections first: one with its point, drawn, or one without (geo.Place's lat = lon =
    // None: its country known, not where in it), counted, tabled and said, never drawn. What is not an object is no origin.
    const all = [];
    given.slice(0, MAX_READ).forEach((o, i) => {
      if (!o || typeof o !== 'object' || Array.isArray(o)) return;
      const p = placeOf(o), hosts = num(o.hosts), seconds = num(o.seconds);
      all.push({
        id: text(o.id) || (p ? `${p.lat},${p.lon}#${i}` : `#${i}`), placed: !!p, lat: p ? p.lat : null, lon: p ? p.lon : null,
        label: text(o.label), country: text(o.country),
        city: text(o.city), asn: o.asn == null ? '' : text(o.asn, 40), org: text(o.org), count: Math.max(0, num(o.count) ?? 1),
        bytes: Math.max(0, num(o.bytes) ?? 0), kind: own(KINDS, o.kind) ? o.kind : 'allowed',
        ports: (Array.isArray(o.ports) ? o.ports.slice(0, 64) : []).map(num).filter((n) => n != null && n >= 0 && n <= 65535),
        // a plugin's recorded hosts: how many at this place, the programs that talked to them, the seconds connected
        hosts: hosts != null && hosts >= 0 ? Math.round(hosts) : null,
        seconds: seconds != null && seconds >= 0 ? seconds : null,
        programs: (Array.isArray(o.programs) ? o.programs.slice(0, 8) : []).map((w) => text(w, 80)).filter(Boolean),
        // 1.67.0: the route traced to it, its placed hops from home outward: its line runs through them
        via: (Array.isArray(o.via) ? o.via.slice(0, MAX_VIA) : []).map(placeOf).filter(Boolean),
      });
    });
    all.sort((a, b) => b.count - a.count || b.bytes - a.bytes);
    // each kind's totals over every origin read, and apart the part of them that has no known point
    const totals = {}, unplaced = {};
    for (const kind of Object.keys(KINDS)) {
      totals[kind] = { places: 0, count: 0, bytes: 0 };
      unplaced[kind] = { places: 0, count: 0, bytes: 0 };
    }
    const add = (t, o) => { t.places++; t.count += o.count; t.bytes += o.bytes; };
    for (const o of all) { add(totals[o.kind], o); if (!o.placed) add(unplaced[o.kind], o); }
    const listed = all.slice(0, MAX_ORIGINS);  // the table's rows; the globe draws those of them with a point
    const l = s.local && typeof s.local === 'object' ? s.local : null;
    // which of the facts a place may say some place here does say: the table has a column for each that is said
    const has = { hosts: listed.some((o) => o.hosts != null), programs: listed.some((o) => o.programs.length > 0),
      seconds: listed.some((o) => o.seconds != null), bytes: listed.some((o) => o.bytes > 0) };
    const kinds = Object.keys(KINDS).filter((kind) => Array.isArray(s.kinds) && s.kinds.includes(kind));
    const localHosts = l ? num(l.hosts) : null;
    return {
      home: h ? { ...h, label: text(s.home.label, 80) } : null, origins: listed.filter((o) => o.placed), listed,
      more: Math.max(0, all.length - MAX_ORIGINS), unread: Math.max(0, given.length - MAX_READ), totals, unplaced,
      local: l ? { count: Math.max(0, num(l.count) ?? 0), bytes: Math.max(0, num(l.bytes) ?? 0),
        hosts: localHosts != null && localHosts >= 0 ? Math.round(localHosts) : null } : null,
      attribution: creditOf(s.attribution), updated: text(s.updated, 40), note: text(s.note, MAX_NOTE),
      // the kinds the legend lists (all of them when the spec names none it knows), the filter in words, the layers
      kinds: kinds.length ? kinds : Object.keys(KINDS), showing: text(s.showing, 200), has, ...layersOf(s.layers),
    };
  }
  const unplacedOf = (d) => Object.keys(KINDS).reduce((n, kind) => n + d.unplaced[kind].places, 0);  // places without a point
  const nameOf = (o) => o.label || o.city || o.country || o.id;
  const whereOf = (o) => [o.city, o.country].filter(Boolean).join(', ');
  const networkOf = (o) => [o.asn ? (/^\d+$/.test(o.asn) ? `AS${o.asn}` : o.asn) : '', o.org].filter(Boolean).join(' · ');
  const portsOf = (ports) => (ports.length > 8 ? `${ports.slice(0, 8).join(', ')} and ${ports.length - 8} more` : ports.join(', '));
  const pointOf = (o) => (o.placed  // where on the globe its dot is, for the table
    ? `${Math.abs(o.lat).toFixed(1)}° ${o.lat < 0 ? 'S' : 'N'}, ${Math.abs(o.lon).toFixed(1)}° ${o.lon < 0 ? 'W' : 'E'}` : 'no known point');
  function clock(iso) {
    const t = new Date(iso);
    return Number.isNaN(t.getTime()) ? iso : t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }

  // -- one globe ----------------------------------------------------------------------------------------------------------
  function create(el, spec, opts) {
    const root = document.createElement('div');
    root.className = 'lg-globe';
    const stage = document.createElement('div');
    stage.className = 'lg-stage';
    const canvas = document.createElement('canvas');
    canvas.className = 'lg-canvas';
    canvas.setAttribute('data-touch-own', '');  // its gestures are its own (touch.js: no long-press bubble on it)
    canvas.setAttribute('role', 'img');
    canvas.tabIndex = 0;
    const controls = document.createElement('div');
    controls.className = 'lg-controls';
    const zoomWords = document.createElement('span');
    zoomWords.className = 'lg-zoom';
    zoomWords.hidden = true;
    controls.appendChild(zoomWords);
    const showing = document.createElement('div');  // the filter in words (the spec's `showing`), top left over the map
    showing.className = 'lg-showing';
    showing.hidden = true;
    const attribution = document.createElement('div');
    attribution.className = 'lg-attr';
    const said = document.createElement('div');  // a keyboard's step, said to a screen reader (the tooltip is not read)
    said.className = 'lg-sr';
    said.setAttribute('aria-live', 'polite');
    said.setAttribute('aria-atomic', 'true');
    const legend = document.createElement('div');
    legend.className = 'lg-legend';
    const layerBar = document.createElement('div');  // the layers' switches, a row of their own at the legend's foot
    layerBar.className = 'lg-layers';
    layerBar.hidden = true;
    const layerHead = document.createElement('span'), layerWhy = document.createElement('span');
    layerHead.textContent = 'Layers';
    layerBar.append(layerHead, layerWhy);
    const note = document.createElement('div');
    note.className = 'lg-note';
    const table = document.createElement('details');
    table.className = 'lg-table';
    const summary = document.createElement('summary');
    table.appendChild(summary);
    stage.append(canvas, controls, attribution, said);
    stage.insertBefore(showing, controls);
    root.append(stage, legend, note, table);
    el.appendChild(root);
    const tip = document.createElement('div');
    tip.className = 'lg-tip';
    tip.hidden = true;
    tip.setAttribute('aria-hidden', 'true');  // the table beneath carries the same words
    (document.body || document.documentElement).appendChild(tip);
    const ctx = canvas.getContext('2d');

    let data = normal(spec);
    let version = 0;  // counts the specs drawn: the dots' layer is drawn again for a new one
    let theme = opts.theme;
    let colours = readColours(root, theme), stamp = JSON.stringify(colours);
    let view = homeView();  // the point the globe is turned to face
    let zoom = 1;  // 1 = the whole globe; the wheel or a pinch zooms in up to MAX_ZOOM
    let follow = true;  // the view stays on home until the globe is turned: a home moved in an update turns it there
    let aimed = aimKey();
    let glide = null;  // {from: {lon, lat, zoom}, to, start}
    let pick = null;  // what the tooltip is about: {o} a place or {home: true}, by 'mouse', 'finger' or 'keys'
    let anchor = '';  // where an anchored tooltip was put last
    let routes = [];
    let load = typeof opts.load === 'function' ? opts.load : null;  // the page's way to a layer's geometry, or none
    let storeName = typeof opts.key === 'string' ? text(opts.key, 200) : '';  // what the switches are remembered under
    let chosen = recall(storeName);  // a layer's id -> switched on or off here; a layer not in it is as its spec says
    let layersShown = null, layersKey = '';  // the layers drawn now and what tells them apart: made again when null
    // What the layers' paint leaves behind: its grid, the marks by their cell and the lines' cells (for the pointer), a
    // line's words while the pointer is on it, the names to draw with the places', and a count of the paints.
    let grid = { cols: 1, rows: 1 }, markCells = new Map(), lineCells = [], lineHits = new Map();
    let infraNames = [], infraStamp = 0;
    let coastCredited = false;  // GSHHG's coasts are drawn now: its credit is listed with the others
    let visible = !('IntersectionObserver' in window);
    let seen = root.isConnected;  // on the page once: after that, a globe that left it is destroyed with the next draw
    let destroyed = false, dirty = true, raf = 0, lastFrame = -Infinity;
    // offscreen layers, drawn again only when what they show changes: the sphere, the land and its lines; a plugin's
    // infrastructure (its marks and lines); the dots and the names
    const layers = { base: { canvas: null, key: '' }, infra: { canvas: null, key: '' },
      places: { canvas: null, key: '' } };
    const motion = window.matchMedia ? matchMedia('(prefers-reduced-motion: reduce)') : null;
    const scheme = window.matchMedia ? matchMedia('(prefers-color-scheme: dark)') : null;
    let reduced = !!(motion && motion.matches);
    let dpr = null;  // the query that says the screen's pixel ratio changed (the window moved to another screen)

    function homeView() {
      if (data.home) return { lon: data.home.lon, lat: clamp(data.home.lat, -85, 85) };
      const o = data.origins[0];
      return o ? { lon: o.lon, lat: clamp(o.lat, -85, 85) } : { lon: 0, lat: 20 };
    }
    function aimKey() { return data.home ? `home ${data.home.lat},${data.home.lon}` : data.origins.length ? 'a place' : 'none'; }

    // -- projection (globe.js) ------------------------------------------------------------------------------------
    function geometry() {
      const w = canvas.clientWidth || 300, h = canvas.clientHeight || 300;
      const r = Math.max(40, (Math.min(w, h) / 2 - 12) * 0.88) * zoom;  // room for the routes rising off the globe
      return { w, h, cx: w / 2, cy: h / 2, r };
    }
    // The camera: C points from the Earth's centre at the viewer, E to screen-right, N up.
    function camera() {
      const l = view.lon * rad, p = view.lat * rad;
      return { C: [Math.cos(p) * Math.cos(l), Math.cos(p) * Math.sin(l), Math.sin(p)],
               E: [-Math.sin(l), Math.cos(l), 0], N: [-Math.sin(p) * Math.cos(l), -Math.sin(p) * Math.sin(l), Math.cos(p)] };
    }
    function project(lon, lat, g) {
      const l = (lon - view.lon) * rad, p = lat * rad, p0 = view.lat * rad;
      const cosc = Math.sin(p0) * Math.sin(p) + Math.cos(p0) * Math.cos(p) * Math.cos(l);
      const x = Math.cos(p) * Math.sin(l);
      const y = Math.cos(p0) * Math.sin(p) - Math.sin(p0) * Math.cos(p) * Math.cos(l);
      return { x: g.cx + g.r * x, y: g.cy - g.r * y, visible: cosc >= 0, depth: cosc };
    }
    function unproject(px, py, g) {
      const x = (px - g.cx) / g.r, y = (g.cy - py) / g.r;
      const rho = Math.hypot(x, y);
      if (rho > 1) return null;
      const c = Math.asin(rho), p0 = view.lat * rad;
      const lat = rho ? Math.asin(Math.cos(c) * Math.sin(p0) + (y * Math.sin(c) * Math.cos(p0)) / rho) : p0;
      const lon = view.lon * rad + Math.atan2(x * Math.sin(c), rho * Math.cos(c) * Math.cos(p0) - y * Math.sin(c) * Math.sin(p0));
      return { lon: lon / rad, lat: lat / rad };
    }
    function polyline(c, points, g) {
      let drawing = false;
      for (const [lon, lat] of points) {
        const p = project(lon, lat, g);
        if (!p.visible) { drawing = false; continue; }
        if (!drawing) { c.moveTo(p.x, p.y); drawing = true; } else c.lineTo(p.x, p.y);
      }
    }
    // Where the great circle from a (depth da, in front) to b (depth db, behind) meets the horizon: [east, north] of it.
    function horizon(ax, ay, az, da, bx, by, bz, db, fr) {
      const t = da / (da - db);
      let x = ax + (bx - ax) * t, y = ay + (by - ay) * t, z = az + (bz - az) * t;
      const n = Math.hypot(x, y, z) || 1;
      x /= n; y /= n; z /= n;
      return [x * fr.E[0] + y * fr.E[1] + z * fr.E[2], x * fr.N[0] + y * fr.N[1] + z * fr.N[2]];
    }
    // polyline for a line of unit vectors (the map's coasts and borders, a layer's lines): broken on the far side, its
    // ends at the horizon where it goes behind. `from` and `to` take one line out of `v`; with `thin` (a chord's
    // square) a vertex nearer than that to the last one drawn is left out, never a line's last; `seen(x, y)` is told
    // each point drawn.
    function strokeUnits(c, v, g, fr, from = 0, to = v.length, thin = 0, seen = null) {
      const { C, E, N } = fr;
      let pen = false, px = 0, py = 0, pz = 0, pd = -1, kx = 2, ky = 2, kz = 2;
      for (let i = from; i < to; i += 3) {
        const x = v[i], y = v[i + 1], z = v[i + 2];
        if (thin && i < to - 3 && (x - kx) * (x - kx) + (y - ky) * (y - ky) + (z - kz) * (z - kz) < thin) continue;
        kx = x; ky = y; kz = z;
        const d = x * C[0] + y * C[1] + z * C[2];
        if (d >= 0) {
          const sx = g.cx + g.r * (x * E[0] + y * E[1] + z * E[2]), sy = g.cy - g.r * (x * N[0] + y * N[1] + z * N[2]);
          if (pen) c.lineTo(sx, sy);
          else {
            if (i > from) {  // it comes round the horizon: from there
              const h = horizon(x, y, z, d, px, py, pz, pd, fr);
              c.moveTo(g.cx + g.r * h[0], g.cy - g.r * h[1]);
              c.lineTo(sx, sy);
            } else c.moveTo(sx, sy);
            pen = true;
          }
          if (seen) seen(sx, sy);
        } else if (pen) {
          const h = horizon(px, py, pz, pd, x, y, z, d, fr);
          c.lineTo(g.cx + g.r * h[0], g.cy - g.r * h[1]);
          pen = false;
        }
        px = x; py = y; pz = z; pd = d;
      }
    }
    // A ring of the land as closed paths of what of it is in front. Each run in front starts and ends where it crosses
    // the horizon; the rim joins each run's end to the nearest run's start the ring's own way round (its turn), as a
    // polygon is cut by a round window. So a country cut by the horizon is land to the rim, and a sea whose coast
    // reaches round behind the globe stays sea, from any side. A ring wholly behind draws nothing; one wholly in front
    // is drawn as it is. Filled even-odd with the others, a hole takes its lake out of the land round it.
    function ringPath(c, ring, g, fr) {
      const { C, E, N } = fr, v = ring.v, n = v.length / 3;
      const depth = (k) => v[k] * C[0] + v[k + 1] * C[1] + v[k + 2] * C[2];
      const X = (k) => g.cx + g.r * (v[k] * E[0] + v[k + 1] * E[1] + v[k + 2] * E[2]);
      const Y = (k) => g.cy - g.r * (v[k] * N[0] + v[k + 1] * N[1] + v[k + 2] * N[2]);
      let start = -1;
      for (let i = 0; i < n; i++) if (depth(i * 3) < 0) { start = i; break; }
      if (start < 0) {  // wholly in front
        c.moveTo(X(0), Y(0));
        for (let k = 3; k < v.length; k += 3) c.lineTo(X(k), Y(k));
        c.closePath();
        return;
      }
      const runs = [];  // {xy: [x, y, ...] from the horizon to the horizon, from: its start's bearing on the rim, to: its end's}
      let run = null, pk = start * 3, pd = depth(pk);
      for (let s = 1; s <= n; s++) {  // from a point behind round to it again: every run in front ends
        const k = ((start + s) % n) * 3, d = depth(k);
        if (d >= 0) {
          if (!run) {
            const h = horizon(v[k], v[k + 1], v[k + 2], d, v[pk], v[pk + 1], v[pk + 2], pd, fr);
            run = { xy: [g.cx + g.r * h[0], g.cy - g.r * h[1]], from: Math.atan2(-h[1], h[0]), to: 0 };
          }
          run.xy.push(X(k), Y(k));
        } else if (run) {
          const h = horizon(v[pk], v[pk + 1], v[pk + 2], pd, v[k], v[k + 1], v[k + 2], d, fr);
          run.xy.push(g.cx + g.r * h[0], g.cy - g.r * h[1]);
          run.to = Math.atan2(-h[1], h[0]);
          runs.push(run);
          run = null;
        }
        pk = k;
        pd = d;
      }
      if (!runs.length) return;  // wholly behind
      const turn = ring.turn;
      // along the rim from bearing a to bearing b, the ring's way round, in [0, 2π); a start a hair before an end is the
      // same point (the two sides of a cut meet there), not a whole turn of the rim away
      const gap = (a, b) => {
        let d = (turn * (b - a)) % TAU;
        if (d < 0) d += TAU;
        return d > TAU - 1e-9 ? 0 : d;
      };
      const used = new Uint8Array(runs.length);
      for (let first = 0; first < runs.length; first++) {
        if (used[first]) continue;
        let r = first;
        c.moveTo(runs[r].xy[0], runs[r].xy[1]);
        for (let step = 0; step < runs.length; step++) {
          used[r] = 1;
          const { xy, to } = runs[r];
          for (let i = 2; i < xy.length; i += 2) c.lineTo(xy[i], xy[i + 1]);
          let next = first, best = Infinity;
          for (let q = 0; q < runs.length; q++) {
            const d = gap(to, runs[q].from);
            if (d < best) { best = d; next = q; }
          }
          c.arc(g.cx, g.cy, g.r, to, to + turn * best, turn < 0);
          if (used[next]) break;  // round to where this path began
          r = next;
        }
        c.closePath();
      }
    }

    // -- the routes: great circles from each place to home, rising a little off the globe --------------------------------
    function buildRoutes() {
      routes = [];
      if (!data.home) return;
      const b = unit(data.home.lon, data.home.lat);
      for (const o of data.origins) {
        // from the place to home: straight, or through the hops of the route traced to it (1.67.0), each leg a great
        // circle, the whole line rising a little off the globe and down again
        const stops = [unit(o.lon, o.lat), ...o.via.slice().reverse().map((p) => unit(p.lon, p.lat)), b];
        const legs = [];
        let w = 0;
        for (let i = 0; i + 1 < stops.length; i++) {
          const s = stops[i], e = stops[i + 1];
          const d = Math.acos(clamp(s[0] * e[0] + s[1] * e[1] + s[2] * e[2], -1, 1));
          if (d < 1e-3) continue;  // a hop within a few kilometres of the stop before it: no leg of its own
          // nearly opposite, any great circle will do: by a point a quarter of the way round
          legs.push({ s, e, d, mid: Math.PI - d < 1e-3 ? perpendicular(s) : null, hop: i + 1 < stops.length - 1 });
          w += d;
        }
        if (w < 0.002) continue;  // at home's own place: its dot, no route
        const lift = Math.min(0.22, 0.04 + (0.18 * Math.min(w, Math.PI)) / Math.PI);
        let counts = legs.map((l) => clamp(Math.ceil(l.d / rad / 3), legs.length > 1 ? 1 : 8, 64));
        const most = counts.reduce((x, y) => x + y, 0);
        if (most > MAX_ROUTE_POINTS) counts = counts.map((c) => Math.max(1, Math.floor((c * MAX_ROUTE_POINTS) / most)));
        const n = counts.reduce((x, y) => x + y, 0), path = new Float64Array((n + 1) * 4), hops = [];
        let k = 0, gone = 0;
        legs.forEach((l, j) => {
          for (let i = j ? 1 : 0; i <= counts[j]; i++, k++) {
            const t = i / counts[j];
            const q = l.mid ? (t < 0.5 ? slerp(l.s, l.mid, Math.PI / 2, 2 * t) : slerp(l.mid, l.e, Math.PI / 2, 2 * t - 1))
              : slerp(l.s, l.e, l.d, t);
            path.set([q[0], q[1], q[2], lift * Math.sin((Math.PI * (gone + l.d * t)) / w)], k * 4);
          }
          gone += l.d;
          if (l.hop) hops.push(k - 1);  // where a hop is on the line: a small dot there
        });
        const seed = seedOf(o.id);
        routes.push({ o, path, hops, screen: new Float64Array((n + 1) * 3), width: routeWidth(o.count), seed, period: 2400 + seed * 1600 });
      }
      routes.sort((x, y) => x.o.count - y.o.count);  // the busiest drawn last, on top
    }
    function perpendicular(a) {
      const o = Math.abs(a[2]) < 0.9 ? [0, 0, 1] : [1, 0, 0];
      const c = [a[1] * o[2] - a[2] * o[1], a[2] * o[0] - a[0] * o[2], a[0] * o[1] - a[1] * o[0]];
      const n = Math.hypot(...c);
      return [c[0] / n, c[1] / n, c[2] / n];
    }
    // A route on screen, (x, y, shown) a point: a point off the globe is hidden only where the globe stands before it.
    function onScreen(rt, g, fr) {
      const p = rt.path, s = rt.screen, { C, E, N } = fr;
      for (let i = 0, j = 0; i < p.length; i += 4, j += 3) {
        const x = p[i], y = p[i + 1], z = p[i + 2], up = 1 + p[i + 3];
        const d = x * C[0] + y * C[1] + z * C[2];
        s[j] = g.cx + g.r * up * (x * E[0] + y * E[1] + z * E[2]);
        s[j + 1] = g.cy - g.r * up * (x * N[0] + y * N[1] + z * N[2]);
        s[j + 2] = d >= 0 || up * up * (1 - d * d) >= 1 ? 1 : 0;
      }
      return s;
    }
    // the point a fraction `t` along a route on screen; null where that part of it is behind the globe
    function along(s, t) {
      const n = s.length / 3, f = clamp(t, 0, 1) * (n - 1), i = Math.min(n - 2, Math.floor(f)), u = f - i;
      if (!s[i * 3 + 2] || !s[i * 3 + 5]) return null;
      return [s[i * 3] + (s[i * 3 + 3] - s[i * 3]) * u, s[i * 3 + 1] + (s[i * 3 + 4] - s[i * 3 + 1]) * u];
    }

    // -- drawing ------------------------------------------------------------------------------------------------------
    const moving = () => !reduced && routes.length > 0;

    // An offscreen layer as large as the canvas, drawn again only when its key changes; `paint(c)` draws in CSS pixels.
    function layer(slot, key, W, H, ratio, paint) {
      if (slot.canvas && slot.key === key) return slot.canvas;
      const c = slot.canvas || (slot.canvas = document.createElement('canvas'));
      if (c.width !== W || c.height !== H) { c.width = W; c.height = H; }
      const b = c.getContext('2d');
      b.setTransform(1, 0, 0, 1, 0, 0);
      b.clearRect(0, 0, W, H);
      b.setTransform(ratio, 0, 0, ratio, 0, 0);
      paint(b);
      slot.key = key;
      return c;
    }
    // where the view faces, to 1e-5 degrees: a layer painted for it is at most some 0.004 px off at 96x
    const facing = () => `${view.lon.toFixed(5)},${view.lat.toFixed(5)}`;
    const viewKey = (g, W, H, ratio) => [W, H, ratio, g.r.toFixed(2), facing(), stamp].join('|');
    // A set of lines in pieces (piecesOf) put on one path, the pieces out of sight skipped.
    function strokePieces(c, P, g, fr, sight) {
      for (let j = 0; j < P.n; j++) {
        if (inSight(P.caps, j * 4, fr.C, sight)) strokeUnits(c, P.v, g, fr, P.starts[j] * 3, P.starts[j + 1] * 3);
      }
    }
    // The finest map loaded for the zoom: the 1:10m past FINEST_ZOOM, the 1:50m past FINE_ZOOM, else the 1:110m.
    const mapNow = () => (zoom > FINEST_ZOOM && maps.finest ? maps.finest : zoom > FINE_ZOOM && maps.fine ? maps.fine
      : maps.coarse);

    // The sphere, the land and its lines: the map's, and past COAST_ZOOM the coast tiles on the canvas (`tiles`, from
    // coastTiles), over the map's own coasts and borders until every one of them is in, then in their place. Only what
    // can be on the canvas is drawn: a ring or a piece of a line out of sight is skipped, and the runs off the canvas
    // are cut short (trimmed), so a globe zoomed 96x costs what is on its canvas.
    function baseLayer(g, fr, ratio, W, H, tiles) {
      const map = mapNow();
      const which = map === maps.finest ? 'finest' : map === maps.fine ? 'fine' : map ? 'coarse' : 'none';
      const key = `${viewKey(g, W, H, ratio)}|${which}|${tiles ? `${tiles.whole} ${tiles.key}` : ''}`;
      return layer(layers.base, key, W, H, ratio, (b) => {
        const k = colours, ocean = mix(k.surface, k.frame, 0.6), land = mix(ocean, k.text, 0.1);
        const pen = trimmed(b, g.w, g.h), sight = sightOf(g), under = !!map && !(tiles && tiles.whole);
        b.beginPath(); b.arc(g.cx, g.cy, g.r, 0, TAU);
        b.fillStyle = css(ocean); b.fill();
        if (map) {  // the land: every ring in one path, so the cuts along the antimeridian leave no seam
          b.beginPath();
          for (const ring of map.land) if (inSight(ring.cap, 0, fr.C, sight)) ringPath(pen, ring, g, fr);
          pen.done();
          b.fillStyle = css(land); b.fill('evenodd');
        }
        b.beginPath();
        for (const line of graticuleLines()) polyline(pen, line, g);
        pen.done();
        b.strokeStyle = css(k.muted, 0.18); b.lineWidth = 0.7; b.stroke();
        b.beginPath(); polyline(pen, graticuleLines()[EQUATOR], g); pen.done();  // stressed, as the exchanges globe's
        b.strokeStyle = css(k.muted, 0.3); b.stroke();
        const lines = (kind) => {  // the borders or the coasts: the map's under the tiles' (or alone), then the tiles'
          b.beginPath();
          if (under) strokePieces(pen, map[kind], g, fr, sight);
          for (const tile of tiles ? tiles.drawn : []) strokePieces(pen, tile[kind], g, fr, sight);
          pen.done();
        };
        lines('borders');
        b.strokeStyle = css(k.land, 0.3); b.lineWidth = 0.6; b.stroke();
        lines('coasts');
        b.strokeStyle = css(k.land, 0.55); b.lineWidth = 0.8; b.stroke();
        b.beginPath(); b.arc(g.cx, g.cy, g.r, 0, TAU);
        b.strokeStyle = css(k.muted, 0.7); b.lineWidth = 1; b.stroke();
      });
    }
    // The coast tiles to draw past COAST_ZOOM: the tiles whose middle is within the canvas's sight and their reach (on
    // the canvas), the nearest the middle of the view first and as many as the cache keeps (MAX_TILES, and
    // MAX_TILE_POINTS by the index's counts), so that a tile coming in never lets go of another one wanted here (a
    // canvas wide enough, or a view by a pole, could want more: each tile in would push out one on the canvas, to be
    // asked for again, without end). Of them those here (`drawn`), `whole` when every tile on the canvas is (the map's
    // own coasts and borders are then not drawn under them), and their names, the key they are painted under. The
    // ones not here are asked for, and the index first (`ask`: not while the globe glides, past places it only goes
    // by). Null at COAST_ZOOM or nearer, and without the index.
    function coastTiles(g, fr, ask) {
      if (zoom <= COAST_ZOOM) return null;
      if (!coast.index) { if (ask) loadCoast(); return null; }
      const C = fr.C, near = sightOf(g) + coast.index.reach, round = [];
      for (const t of coast.index.list) {
        const d = Math.acos(clamp(t.c[0] * C[0] + t.c[1] * C[1] + t.c[2] * C[2], -1, 1));
        if (d <= near) round.push({ t, d });
      }
      round.sort((a, b) => a.d - b.d);
      const want = [];
      let points = 0;
      for (const { t } of round) {
        if (want.length >= MAX_TILES || points + t.points > MAX_TILE_POINTS) break;
        want.push(t);
        points += t.points;
      }
      if (ask) askTiles(want);
      const drawn = [], names = [];
      for (const t of want) {
        const tile = coast.tiles.get(t.name);
        if (tile && !tile.loading) { drawn.push(tile); names.push(t.name); }
      }
      return { drawn, whole: drawn.length === round.length, key: names.join(' ') };
    }

    // -- the layers: a plugin's infrastructure, between the map and the routes ---------------------------------------
    // Without a loader every layer is off; else a layer is as it was switched here, or as its spec says.
    const isOn = (l) => !!load && (chosen.has(l.id) ? chosen.get(l.id) : l.on);
    // The layers switched on whose geometry is here, in the spec's order: [{l, geo}]. Worked out again only after the
    // spec, a switch or what is loaded changed (layersShown = null).
    function shownLayers() {
      if (!layersShown) {
        layersShown = [];
        for (const l of data.layers) {
          const e = isOn(l) ? layerData.get(l.key) : null;
          if (e && e.state === 'ready') layersShown.push({ l, geo: e.geo });
        }
        layersKey = layersShown.map(({ l }) => `${l.key} ${l.mark} ${l.slot} ${l.namesFrom}`).join('|');
      }
      return layersShown;
    }
    // What a paint of the layers left behind goes with it: the marks and the lines' cells, the names, and the words
    // of a mark or a line the pointer was on (a cluster is made again with the view).
    function forgetMarks() {
      markCells = new Map();
      lineCells = [];
      lineHits = new Map();
      infraNames = [];
      infraStamp++;
      if (pick && pick.f) { pick = null; anchor = ''; tip.hidden = true; }
    }
    // The layers' marks and lines. Its key leaves out the spec's version: an update of the places, every few seconds,
    // does not paint it again; only the view, the layers on, their versions or the colours do. No layer shown: no
    // canvas kept for it.
    function infraLayer(g, fr, ratio, W, H) {
      const list = shownLayers(), slot = layers.infra;
      if (!list.length) {
        if (slot.canvas) {
          slot.canvas.width = 0; slot.canvas.height = 0;
          slot.canvas = null; slot.key = '';
          forgetMarks();
        }
        return null;
      }
      return layer(slot, `${viewKey(g, W, H, ratio)}|${layersKey}`, W, H, ratio, (c) => paintLayers(c, g, fr, list));
    }
    // Every layer's lines, then every layer's marks over them; of each, the layer with the most features first, so that
    // the few stay on top of the many (an exchange point's diamond over the data centres round it, a cable over the
    // lines on land), the spec's order among layers as many.
    function paintLayers(c, g, fr, list) {
      forgetMarks();
      grid = { cols: Math.ceil(g.w / CELL), rows: Math.ceil(g.h / CELL) };
      const names = [];
      const most = (kind) => list.filter(({ geo }) => geo[kind]).sort((a, b) => b.geo[kind].n - a.geo[kind].n);
      for (const { l, geo } of most('lines')) paintLines(c, g, fr, l, geo, names);
      for (const { l, geo } of most('points')) paintPoints(c, g, fr, l, geo, names);
      infraNames = names.sort((a, b) => a.d - b.d);  // the nearest the middle of the view first
    }
    // A layer's lines as one path, each stroked as the map's (strokeUnits): a line wholly out of sight is skipped by
    // its middle and its reach, and a vertex nearer than THIN px to the last one drawn is left out. As it is painted a
    // line leaves its number in each cell it crosses (for the pointer: every line a cell is crossed by, LINE_CELL at
    // most, so that a line another one crosses later is still found there) and, from the zoom its layer names, where
    // its name goes: by its point nearest the middle of the view, a name once however many lines carry it.
    function paintLines(c, g, fr, l, geo, names) {
      const L = geo.lines, C = fr.C, sight = sightOf(g), pen = trimmed(c, g.w, g.h);  // its runs off the canvas cut
      const thin = (THIN / g.r) ** 2, size = grid.cols * grid.rows;
      // the lines through each cell, as lists: a cell's last one in `head`, the one before each in `next`, and its
      // line in `line`; `last` the line that came to a cell last (a line is in a cell's list once), `held` how many
      const head = new Int32Array(size).fill(-1), last = new Int32Array(size), held = new Uint8Array(size);
      const next = [], line = [];
      const naming = zoom >= l.namesFrom, named = new Map();
      let id = 0, first = true, lx = 0, ly = 0, best = Infinity, bx = 0, by = 0;
      const cell = (x, y) => {
        if (x < 0 || y < 0 || x >= g.w || y >= g.h) return;
        const k = Math.floor(y / CELL) * grid.cols + Math.floor(x / CELL);
        if (last[k] === id || held[k] >= LINE_CELL) return;  // this line is there already, or the cell is full
        last[k] = id;
        held[k]++;
        next.push(head[k]);
        line.push(id - 1);
        head[k] = line.length - 1;
      };
      const seen = (x, y) => {  // a point of line `id` drawn: the cells from the last point to it, how near the middle
        if (!first) {
          const steps = Math.min(64, Math.ceil(Math.hypot(x - lx, y - ly) / (CELL / 2)));
          for (let s = 1; s < steps; s++) cell(lx + ((x - lx) * s) / steps, ly + ((y - ly) * s) / steps);
        }
        cell(x, y);
        lx = x; ly = y; first = false;
        if (!naming || x < 0 || y < 0 || x >= g.w || y >= g.h) return;
        const d = (x - g.cx) ** 2 + (y - g.cy) ** 2;
        if (d < best) { best = d; bx = x; by = y; }
      };
      c.beginPath();
      for (let j = 0; j < L.n; j++) {
        const q = j * 4, d = L.caps[q] * C[0] + L.caps[q + 1] * C[1] + L.caps[q + 2] * C[2];
        if (Math.acos(clamp(d, -1, 1)) > sight + L.caps[q + 3]) continue;  // wholly out of sight
        id = j + 1; first = true; best = Infinity;
        strokeUnits(pen, L.v, g, fr, L.starts[j] * 3, L.starts[j + 1] * 3, thin, seen);
        const name = best < Infinity ? L.names[j] : '', was = name ? named.get(name) : null;
        if (name && (!was || best < was.d)) {
          named.set(name, { x: bx, y: by, r: 2, words: cut(name, 28), slot: l.slot, d: best });
        }
      }
      pen.done();
      c.strokeStyle = css(colours.network, 0.9);
      c.lineWidth = 1.3;
      c.lineJoin = 'round';
      c.setLineDash(l.mark === 'dash' ? DASH : []);
      c.stroke();
      c.setLineDash([]);
      lineCells.push({ l, geo, head, next, line });
      for (const m of named.values()) names.push(m);
    }
    // A layer's points, gathered on the screen's grid of CELL px: a cell with one is its mark (the layer's circle,
    // square or diamond) where it is; a cell with more is one larger mark and their count, at the middle of them but
    // kept in its cell by as much as the mark and its ring reach, so that the marks of two cells side by side do not
    // lie on each other and their counts stay apart (the largest, reaching past half a cell, meet at their edges).
    // Every mark of the layer is one path (and one more for the ring that keeps it apart from the map): no fill a
    // feature. Each mark is kept by its cell for the pointer, with the first five of its features; from the zoom its
    // layer names, its name is one to draw.
    function paintPoints(c, g, fr, l, geo, names) {
      const P = geo.points, v = P.v, { C, E, N } = fr, size = grid.cols * grid.rows;
      const count = new Uint16Array(size), sx = new Float32Array(size), sy = new Float32Array(size);
      const firsts = new Int32Array(size * 5), cells = [];
      for (let i = 0, k = 0; i < P.n; i++, k += 3) {
        const x = v[k], y = v[k + 1], z = v[k + 2];
        if (x * C[0] + y * C[1] + z * C[2] < 0) continue;  // behind the globe
        const px = g.cx + g.r * (x * E[0] + y * E[1] + z * E[2]), py = g.cy - g.r * (x * N[0] + y * N[1] + z * N[2]);
        if (px < 0 || py < 0 || px >= g.w || py >= g.h) continue;
        const cell = Math.floor(py / CELL) * grid.cols + Math.floor(px / CELL), m = count[cell]++;
        if (!m) cells.push(cell);
        if (m < 5) firsts[cell * 5 + m] = i;
        sx[cell] += px; sy[cell] += py;
      }
      const colour = colours.network, naming = zoom >= l.namesFrom, mine = [];
      const wide = l.mark === 'diamond' ? 1.25 : 1;  // how far a mark reaches for its size: a diamond's points, further
      for (const cell of cells) {
        const n = count[cell], r = n === 1 ? 3.5 : n < 10 ? 6 : n < 100 ? 7.5 : n < 1000 ? 9.5 : 11;
        const left = (cell % grid.cols) * CELL, top = Math.floor(cell / grid.cols) * CELL;
        const pad = n === 1 ? 0 : Math.min(CELL / 2, (r + 1.5) * wide);  // one feature is where it is
        const x = clamp(sx[cell] / n, left + pad, left + CELL - pad);
        const y = clamp(sy[cell] / n, top + pad, top + CELL - pad);
        const m = { l, geo, n, x, y, r, first: Array.from(firsts.subarray(cell * 5, cell * 5 + Math.min(n, 5))) };
        mine.push(m);
        const there = markCells.get(cell);
        if (there) there.push(m); else markCells.set(cell, [m]);
        const name = naming ? m.first.map((i) => P.names[i]).find(Boolean) : '';
        if (!name) continue;
        const words = n > 1 ? `${cut(name, 24)} +${n - 1}` : cut(name, 28);
        names.push({ x, y, r: r + 1.5, words, slot: l.slot, d: (x - g.cx) ** 2 + (y - g.cy) ** 2 });
      }
      c.beginPath();
      for (const m of mine) markPath(c, l.mark, m.x, m.y, m.r + 1.5);
      c.fillStyle = css(colours.surface, 0.9); c.fill();  // a ring in the surface colour: a mark apart from the map
      c.beginPath();
      for (const m of mine) markPath(c, l.mark, m.x, m.y, m.r);
      c.fillStyle = css(colour); c.fill();
      c.font = `600 9px ${colours.font}`;
      c.textAlign = 'center'; c.textBaseline = 'middle';
      c.fillStyle = luminance(colour) > 0.5 ? 'rgba(0,0,0,0.85)' : 'rgba(255,255,255,0.95)';  // readable on its mark
      for (const m of mine) if (m.n > 1) c.fillText(short(m.n), m.x, m.y + 0.5);
      c.textAlign = 'start'; c.textBaseline = 'alphabetic';
    }
    // How near a point is to line `j` of a layer as it is drawn now, and the point of the line nearest it.
    function nearLine(L, j, x, y, g, fr) {
      const { C, E, N } = fr, v = L.v;
      let best = Infinity, bx = 0, by = 0, px = 0, py = 0, pen = false;
      for (let i = L.starts[j] * 3; i < L.starts[j + 1] * 3; i += 3) {
        const a = v[i], b = v[i + 1], c = v[i + 2];
        if (a * C[0] + b * C[1] + c * C[2] < 0) { pen = false; continue; }
        const sx = g.cx + g.r * (a * E[0] + b * E[1] + c * E[2]), sy = g.cy - g.r * (a * N[0] + b * N[1] + c * N[2]);
        if (pen) {
          const ux = sx - px, uy = sy - py, len = ux * ux + uy * uy;
          const along = len ? clamp(((x - px) * ux + (y - py) * uy) / len, 0, 1) : 0;
          const qx = px + ux * along, qy = py + uy * along, d = Math.hypot(qx - x, qy - y);
          if (d < best) { best = d; bx = qx; by = qy; }
        }
        px = sx; py = sy; pen = true;
      }
      return { d: best, x: bx, y: by };
    }
    // The layers' mark or line under a point (canvas px), `by` a mouse or a finger: the nearest mark within its reach,
    // else the nearest line; found through the cells the last paint left, never by going through every feature.
    function featureAt(x, y, by) {
      if (!markCells.size && !lineCells.length) return null;
      const cx = Math.floor(x / CELL), cy = Math.floor(y / CELL), round = [];
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          const X = cx + dx, Y = cy + dy;
          if (X >= 0 && Y >= 0 && X < grid.cols && Y < grid.rows) round.push(Y * grid.cols + X);
        }
      }
      let best = null, bestD = Infinity;
      for (const cell of round) {
        for (const m of markCells.get(cell) || []) {
          const d = Math.hypot(m.x - x, m.y - y);
          if (d < Math.max(PLACE_REACH[by], m.r + 4) && d < bestD) { best = m; bestD = d; }
        }
      }
      if (best) return best;
      const g = geometry(), fr = camera();
      for (const { l, geo, head, next, line } of lineCells) {
        const lines = new Set();  // every line through the cells round the point, once
        for (const cell of round) for (let e = head[cell]; e >= 0; e = next[e]) lines.add(line[e]);
        for (const j of lines) {
          const near = nearLine(geo.lines, j, x, y, g, fr);
          if (near.d >= LINE_REACH[by] || near.d >= bestD) continue;
          const key = `${l.id}\n${j}`;  // the same words while the pointer goes along the line
          best = lineHits.get(key) || { l, geo, line: j, n: 1, r: 0, x: 0, y: 0 };
          lineHits.set(key, best);
          best.x = near.x; best.y = near.y;
          bestD = near.d;
        }
      }
      return best;
    }

    // The dots and the names on the map, over the routes and their lights; the layers' names with them, and a ring
    // round the mark the pointer is on.
    function placesLayer(g, ratio, W, H) {
      const f = pick && pick.f, at = f && f.line == null ? `${f.x.toFixed(1)},${f.y.toFixed(1)}` : '';
      const picked = !pick ? '' : pick.home ? 'home' : f ? `${f.l.id} ${at || f.line}` : pick.o.id;
      const key = `${viewKey(g, W, H, ratio)}|${version}|${picked}|${infraStamp}`;
      return layer(layers.places, key, W, H, ratio, (c) => {
        if (at) {
          c.beginPath(); c.arc(f.x, f.y, f.r + 4, 0, TAU);
          c.strokeStyle = css(colours.text, 0.9); c.lineWidth = 1.5; c.stroke();
        }
        drawLabels(c, g, drawPlaces(c, g));
      });
    }

    // Every route, the routes alike (a kind, a width and whether the one picked) stroked as one path; then a light along
    // each of the busiest, in towards home or out from it, its tail thinning behind it.
    function drawRoutes(g, fr, now) {
      const picked = pick && pick.o, groups = new Map();
      for (const rt of routes) {
        const on = picked === rt.o, level = on ? 2 : picked ? 0 : 1, width = rt.width + (on ? 1 : 0);
        const key = `${level}|${width}|${rt.o.kind}`;
        let group = groups.get(key);
        if (!group) groups.set(key, (group = { level, width, kind: rt.o.kind, lines: [] }));
        group.lines.push(onScreen(rt, g, fr));
      }
      const order = [...groups.values()].sort((a, b) => a.level - b.level || a.width - b.width);  // the busiest on top
      for (const group of order) {
        const k = KINDS[group.kind];
        ctx.beginPath();
        for (const s of group.lines) {
          let pen = false;
          for (let j = 0; j < s.length; j += 3) {
            if (!s[j + 2]) { pen = false; continue; }
            if (pen) ctx.lineTo(s[j], s[j + 1]); else { ctx.moveTo(s[j], s[j + 1]); pen = true; }
          }
        }
        const dash = k.dash ? k.dash.map((d) => d * Math.max(1, group.width / 2)) : [];
        ctx.setLineDash(dash);
        ctx.lineDashOffset = dash.length && now ? -((now / 60) % (dash[0] + dash[1])) : 0;  // in towards home
        ctx.strokeStyle = css(colours.network, group.level === 2 ? 0.95 : group.level === 0 ? 0.2 : 0.65);
        ctx.lineWidth = group.width;
        ctx.stroke();
      }
      ctx.setLineDash([]);
      ctx.lineDashOffset = 0;
      ctx.beginPath();  // the hops of the routes traced: a small grey-blue dot each, where it stands before the globe
      for (const rt of routes) {
        for (const j of rt.hops) {
          if (!rt.screen[j * 3 + 2]) continue;
          ctx.moveTo(rt.screen[j * 3] + 1.8, rt.screen[j * 3 + 1]);
          ctx.arc(rt.screen[j * 3], rt.screen[j * 3 + 1], 1.8, 0, TAU);
        }
      }
      ctx.fillStyle = css(colours.network, picked ? 0.45 : 0.9);
      ctx.fill();
      if (!now) return;  // still: no lights
      ctx.lineCap = 'round';
      for (let i = Math.max(0, routes.length - LIGHTS); i < routes.length; i++) {
        const rt = routes[i], out = rt.o.kind === 'outbound';
        let t = (now / rt.period + rt.seed) % 1;
        if (out) t = 1 - t;
        const fade = rt.o.kind === 'unanswered' ? 1 - smooth(0.6, 0.9, t) : 1;  // it knocks, and no answer comes
        const head = fade > 0 ? along(rt.screen, t) : null;
        if (!head) continue;
        const dim = picked && picked !== rt.o ? 0.25 : 1;
        const glow = mix(colours.network, colours.text, 0.35);
        let end = head;
        ctx.beginPath();
        ctx.moveTo(head[0], head[1]);
        for (let j = 1; j <= 6; j++) {  // its tail: back along the route
          const q = along(rt.screen, t + (out ? 0.14 : -0.14) * (j / 6));
          if (!q) break;
          ctx.lineTo(q[0], q[1]);
          end = q;
        }
        if (end !== head) {
          const tail = ctx.createLinearGradient(head[0], head[1], end[0], end[1]);
          tail.addColorStop(0, css(glow, fade * dim * 0.8));
          tail.addColorStop(1, css(glow, 0));
          ctx.strokeStyle = tail;
          ctx.lineWidth = rt.width + 1.2;
          ctx.stroke();
        }
        ctx.beginPath();
        ctx.arc(head[0], head[1], rt.width / 2 + 1.6, 0, TAU);
        ctx.fillStyle = css(glow, fade * dim);
        ctx.fill();
      }
      ctx.lineCap = 'butt';
    }

    function drawPlaces(c, g) {
      const picked = pick && pick.o, shown = [];
      for (const o of data.origins) {
        const p = project(o.lon, o.lat, g);
        if (p.visible) shown.push([o, p]);
      }
      shown.sort((a, b) => (a[0] === picked) - (b[0] === picked) || a[0].count - b[0].count);  // the busiest and the picked on top
      for (const [o, p] of shown) {
        const r = dotRadius(o.count) + (o === picked ? 1.5 : 0);
        c.beginPath(); c.arc(p.x, p.y, r + 2, 0, TAU);
        c.fillStyle = css(colours.surface); c.fill();  // a 2px ring in the surface colour keeps it apart from its neighbours
        c.beginPath(); c.arc(p.x, p.y, r, 0, TAU);
        c.fillStyle = css(colours.series[KINDS[o.kind].slot - 1], picked && o !== picked ? 0.45 : 1); c.fill();
      }
      return shown;
    }

    function drawHome(g, now) {  // this machine: a ring and its dot in the accent, a slow ring widening from it while it moves
      if (!data.home) return;
      const p = project(data.home.lon, data.home.lat, g);
      if (!p.visible) return;
      if (now) {
        const ph = (now / 2200) % 1;
        ctx.beginPath(); ctx.arc(p.x, p.y, 8 + 12 * ph, 0, TAU);
        ctx.strokeStyle = css(colours.accent, 0.55 * (1 - ph)); ctx.lineWidth = 1.5; ctx.stroke();
      }
      ctx.beginPath(); ctx.arc(p.x, p.y, 9.5, 0, TAU);
      ctx.fillStyle = css(colours.surface); ctx.fill();
      ctx.beginPath(); ctx.arc(p.x, p.y, 7, 0, TAU);
      ctx.strokeStyle = css(colours.accent); ctx.lineWidth = 2; ctx.stroke();
      ctx.beginPath(); ctx.arc(p.x, p.y, 3, 0, TAU);
      ctx.fillStyle = css(colours.accent); ctx.fill();
    }

    // Names on the map, sparingly: home's, and the busiest places in view; one never over another, nor over home's mark.
    function drawLabels(c, g, shown) {
      c.font = `12px ${colours.font}`;
      c.textBaseline = 'middle';
      c.lineJoin = 'round';
      const boxes = [];
      const put = (words, x, y, r, strong) => {
        const w = c.measureText(words).width;
        for (const [lx, ly] of [[x + r + 4, y], [x - r - 4 - w, y], [x - w / 2, y - r - 9], [x - w / 2, y + r + 9]]) {
          const box = { x: lx - 3, y: ly - 8, w: w + 6, h: 16 };
          if (box.x < 2 || box.y < 2 || box.x + box.w > g.w - 2 || box.y + box.h > g.h - 2) continue;
          if (boxes.some((o) => box.x < o.x + o.w && o.x < box.x + box.w && box.y < o.y + o.h && o.y < box.y + box.h)) continue;
          boxes.push(box);
          c.lineWidth = 3; c.strokeStyle = css(colours.surface, 0.85); c.strokeText(words, lx, ly);
          c.fillStyle = css(colours.text, strong ? 1 : 0.85); c.fillText(words, lx, ly);
          return;
        }
      };
      const home = data.home ? project(data.home.lon, data.home.lat, g) : null;
      if (home && home.visible) {
        boxes.push({ x: home.x - 10, y: home.y - 10, w: 20, h: 20 });
        put(text(data.home.label || 'This machine', 40), home.x, home.y, 9, true);
      }
      const busiest = shown.filter(([, p]) => p.depth > 0.12).sort((a, b) => b[0].count - a[0].count).slice(0, LABELS);
      for (const [o, p] of busiest) put(text(nameOf(o), 40), p.x, p.y, dotRadius(o.count) + 2, false);
      nameLayers(c, g, boxes, shown);
      c.textBaseline = 'alphabetic';
    }
    // The layers' names, drawn here with the places' names (this layer is painted at every update anyway; the third
    // one then is not): each in a box as the exchanges globe's, beside its mark where it fits, else a little further
    // out with a line to it. Never over a place's name or its dot, over home, or over another box; the nearest the
    // middle of the view first, LAYER_NAMES at most.
    function nameLayers(c, g, boxes, shown) {
      if (!infraNames.length) return;
      for (const [o, p] of shown) {
        const r = dotRadius(o.count) + 2;
        boxes.push({ x: p.x - r, y: p.y - r, w: 2 * r, h: 2 * r });
      }
      c.font = `11px ${colours.font}`;
      let put = 0, tried = 0;
      for (const m of infraNames) {
        if (put >= LAYER_NAMES || tried++ >= LAYER_NAMES * 4) break;
        const w = c.measureText(m.words).width + 10, h = 16, gap = m.r + 4;
        const fits = ([x, y]) => x >= 2 && y >= 2 && x + w <= g.w - 2 && y + h <= g.h - 2
          && !boxes.some((b) => x < b.x + b.w + 2 && b.x < x + w + 2 && y < b.y + b.h + 2 && b.y < y + h + 2);
        const near = [[m.x + gap, m.y - h / 2], [m.x - gap - w, m.y - h / 2],
          [m.x - w / 2, m.y - gap - h], [m.x - w / 2, m.y + gap]];
        const far = [[1, -1], [1, 1], [-1, -1], [-1, 1], [1, 0], [-1, 0], [0, -1], [0, 1]].map(([dx, dy]) => [
          m.x + dx * 30 - (dx < 0 ? w : dx === 0 ? w / 2 : 0), m.y + dy * 24 - (dy < 0 ? h : dy === 0 ? h / 2 : 0)]);
        const beside = near.find(fits), spot = beside || far.find(fits);
        if (!spot) continue;
        const [x, y] = spot;
        if (!beside) {  // further out: a line from its mark to its box
          c.beginPath(); c.moveTo(m.x, m.y); c.lineTo(clamp(m.x, x, x + w), clamp(m.y, y, y + h));
          c.strokeStyle = css(colours.muted, 0.7); c.lineWidth = 1; c.stroke();
        }
        c.fillStyle = css(colours.surface, 0.86); c.fillRect(x, y, w, h);
        c.strokeStyle = css(colours.network, 0.7); c.lineWidth = 1;
        c.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
        c.fillStyle = css(colours.text, 0.95); c.fillText(m.words, x + 5, y + h / 2 + 0.5);
        boxes.push({ x, y, w, h }, { x: m.x - m.r, y: m.y - m.r, w: 2 * m.r, h: 2 * m.r });
        put++;
      }
    }

    function render(now) {
      const ratio = window.devicePixelRatio || 1;
      const g = geometry(), fr = camera();
      const W = Math.max(1, Math.round(g.w * ratio)), H = Math.max(1, Math.round(g.h * ratio));
      if (canvas.width !== W || canvas.height !== H) { canvas.width = W; canvas.height = H; }
      if (!maps.coarse) loadCoarse();
      if (zoom > FINE_ZOOM && !maps.fine) loadFine();  // the 1:50m outlines only once zoomed past 2.5x
      if (zoom > FINEST_ZOOM && !maps.finest) loadFinest();  // the 1:10m only past 12x
      const tiles = coastTiles(g, fr, !glide);  // GSHHG's only past 24x, and only the tiles on the canvas
      const credited = !!(tiles && tiles.drawn.length);
      if (credited !== coastCredited) { coastCredited = credited; renderAttribution(); }  // GSHHG's, while drawn
      for (const l of data.layers) if (isOn(l)) askLayer(l, load);  // a layer switched on: asked of the page, once
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, W, H);
      ctx.drawImage(baseLayer(g, fr, ratio, W, H, tiles), 0, 0);
      const infra = infraLayer(g, fr, ratio, W, H);  // the layers: over the map, under the routes
      if (infra) ctx.drawImage(infra, 0, 0);
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      drawRoutes(g, fr, now);
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.drawImage(placesLayer(g, ratio, W, H), 0, 0);
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      drawHome(g, now);
      anchorTip(g);
      const words = zoomText();
      if (zoomWords.textContent !== words) { zoomWords.textContent = words; zoomWords.hidden = !words; }
    }
    function zoomText() { return zoom > 1.01 ? `${zoom >= 10 ? zoom.toFixed(0) : zoom.toFixed(1)}×` : ''; }

    // -- frames: only while it is seen and something moves ---------------------------------------------------------
    // One frame after a change, frames while the lights move (never under prefers-reduced-motion) or while it glides home,
    // and none at all while it is off screen or the page is hidden: what changed meanwhile is drawn once it is seen.
    function schedule() {
      if (destroyed || raf || !visible || document.hidden) return;
      if (dirty || glide || moving()) raf = requestAnimationFrame(frame);
    }
    function frame(now) {
      raf = 0;
      if (destroyed || !visible || document.hidden) return;
      if (root.isConnected) seen = true;
      if (colours.detached && root.isConnected) recolour();
      if (glide) {
        const k = Math.min(1, (now - glide.start) / GLIDE_MS), ease = 1 - Math.pow(1 - k, 3), { from, to } = glide;
        view = { lon: wrap(from.lon + wrap(to.lon - from.lon) * ease), lat: from.lat + (to.lat - from.lat) * ease };
        zoom = from.zoom + (to.zoom - from.zoom) * ease;
        dirty = true;
        if (k >= 1) glide = null;
      }
      const lights = moving();
      if (dirty || !lights || now - lastFrame >= FRAME_MS) {
        render(lights ? now : 0);
        lastFrame = now;
        dirty = false;
      }
      if (glide || lights) raf = requestAnimationFrame(frame);
    }
    function changed() { dirty = true; schedule(); }
    function glideTo(to) {
      if (reduced) { view = { lon: to.lon, lat: to.lat }; zoom = to.zoom; glide = null; changed(); return; }
      glide = { from: { lon: view.lon, lat: view.lat, zoom }, to, start: performance.now() };
      changed();
    }
    function home() {  // back to this machine, the whole globe
      follow = true;
      aimed = aimKey();
      glideTo({ ...homeView(), zoom: 1 });
    }

    // -- the tooltip ---------------------------------------------------------------------------------------------------
    function keyOf(kind) {
      const k = document.createElement('span');
      k.className = `lg-k lg-k-${kind}`;
      k.setAttribute('aria-hidden', 'true');
      return k;
    }
    function fillTip(p) {
      tip.replaceChildren();
      const line = (cls, words) => {
        const d = document.createElement('div');
        if (cls) d.className = cls;
        d.textContent = words;
        tip.appendChild(d);
      };
      if (p.home) {
        line('lg-tip-head', 'This machine');
        if (data.home && data.home.label) line('lg-tip-sub', data.home.label);
        if (data.local) line('', `local network: ${localWords()}, never placed`);
        return;
      }
      if (p.f) { featureTip(p.f, line); return; }
      const o = p.o, k = KINDS[o.kind];
      line('lg-tip-head', nameOf(o));
      const where = whereOf(o);
      if (where && where !== nameOf(o)) line('lg-tip-sub', where);
      const row = document.createElement('div');  // the value first, what it is after it
      row.className = 'lg-tip-row';
      const b = document.createElement('b');
      b.textContent = many(o.count, k.noun);
      const s = document.createElement('span');
      s.textContent = k.tip;
      row.append(keyOf(o.kind), b, s);
      tip.appendChild(row);
      if (o.hosts != null) line('', many(o.hosts, 'host'));
      if (o.seconds != null) line('', `connected ${duration(o.seconds)}`);
      if (o.bytes) line('', bytes(o.bytes));
      if (o.programs.length) line('lg-tip-sub', o.programs.join(', '));
      if (networkOf(o)) line('lg-tip-sub', networkOf(o));
      if (o.ports.length) line('lg-tip-sub', `ports ${portsOf(o.ports)}`);
    }
    // A layer's mark or line: its name, its layer, its operator and the credit of the data set it came from; a cluster:
    // its count, five of its names and their credits.
    function featureTip(f, line) {
      const { l, geo } = f, src = f.line == null ? geo.points : geo.lines;
      const credit = (i) => { const c = geo.credits[src.part[i]]; return c ? c.text || c.url : ''; };
      if (f.n === 1) {
        const i = f.line == null ? f.first[0] : f.line, name = src.names[i];
        line('lg-tip-head', name || l.title);
        line('lg-tip-sub', name ? l.title : 'no name in the data');
        if (src.subs && src.subs[i]) line('', src.subs[i]);
        if (credit(i)) line('lg-tip-sub', credit(i));
        return;
      }
      line('lg-tip-head', `${l.title}: ${f.n.toLocaleString()} here`);
      for (const i of f.first) line('', src.names[i] || 'no name in the data');
      const more = f.n - f.first.length;
      if (more > 0) line('lg-tip-sub', `and ${more.toLocaleString()} more: zoom in to tell them apart`);
      const credits = [...new Set(f.first.map(credit).filter(Boolean))];
      if (credits.length) line('lg-tip-sub', credits.join(' · '));
    }
    // the local network's sum in words: its hosts where a plugin counts them, its bytes only where there are any
    const localWords = () => [data.local.hosts != null ? many(data.local.hosts, 'host') : '',
      many(data.local.count, 'connection'), data.local.bytes ? bytes(data.local.bytes) : ''].filter(Boolean).join(', ');
    function placeTip(px, py, above) {  // charts.js's placing: beside a mouse, above a finger (or the keyboard's dot)
      tip.hidden = false;
      const tw = tip.offsetWidth, th = tip.offsetHeight;
      let left = px + 14, top = py + 14;
      if (above) {
        left = px - tw / 2;
        top = py - 24 - th;
        if (top < 8) {
          top = py - th / 2;
          left = px + 24 + tw <= innerWidth - 8 ? px + 24 : px - 24 - tw;
        }
        left = Math.min(left, innerWidth - 8 - tw);
        top = Math.min(top, innerHeight - 8 - th);
      } else {
        if (left + tw > innerWidth - 8) left = px - 14 - tw;
        if (top + th > innerHeight - 8) top = py - 14 - th;
      }
      tip.style.left = `${Math.max(8, left)}px`;
      tip.style.top = `${Math.max(8, top)}px`;
    }
    // A finger's or the keyboard's tooltip stays on its dot as the globe turns, and goes while the dot is behind it.
    function anchorTip(g) {
      if (!pick || pick.by === 'mouse') return;
      const at = pick.home ? (data.home ? project(data.home.lon, data.home.lat, g) : null)
        : pick.f ? { x: pick.f.x, y: pick.f.y, visible: true } : project(pick.o.lon, pick.o.lat, g);
      if (!at || !at.visible || at.x < 0 || at.y < 0 || at.x > g.w || at.y > g.h) { tip.hidden = true; anchor = ''; return; }
      const r = canvas.getBoundingClientRect(), x = r.left + at.x, y = r.top + at.y;
      const key = `${x.toFixed(1)},${y.toFixed(1)}`;
      if (key === anchor && !tip.hidden) return;
      anchor = key;
      placeTip(x, y, true);
    }
    function setPick(p) {
      const was = pick;
      pick = p;
      anchor = '';
      if (!p) {
        tip.hidden = true;
        if (was && was.by === 'keys') said.textContent = '';  // a step put away (or its place gone): its words go too
        if (was) changed();
        return;
      }
      if (!was || was.o !== p.o || was.f !== p.f || !!was.home !== !!p.home || was.by !== p.by) {
        fillTip(p);
        changed();
      }
      if (p.by === 'mouse') placeTip(p.x, p.y, false);
      else anchorTip(geometry());
    }

    // -- the legend, the note, the table, the attribution and the words a screen reader reads -------------------------------
    // Each is made once and its words set again only where they changed: a page is asked again every few seconds, and
    // where the table is scrolled to, what a screen reader is reading, what is selected and the focus stay through it.
    const legendItems = new Map();  // an item's name -> {s, w, b}: made the first time, in the legend's order
    function renderLegend() {
      const item = (id, kind, words, value) => {  // a key (a kind's line, home's mark) or none, its words, a value after them
        let it = legendItems.get(id);
        if (!it) {
          const s = document.createElement('span'), w = document.createElement('span'), b = document.createElement('b');
          if (kind) s.appendChild(keyOf(kind)); else s.className = 'lg-plain';
          s.append(w, b);
          legend.appendChild(s);
          legendItems.set(id, (it = { s, w, b }));
        }
        setText(it.w, words);
        setText(it.b, value || '');
        show(it.b, !!value);
        show(it.s, !!words);
      };
      for (const [kind, k] of Object.entries(KINDS)) {  // the kinds the spec names, and any other that has places
        const t = data.totals[kind], listed = t.places > 0 || data.kinds.includes(kind);
        const value = t.places ? `${many(t.places, 'place')}, ${many(t.count, k.noun)}` : 'none';
        item(kind, kind, listed ? k.words : '', value);
      }
      item('home', 'home', 'This machine', data.home ? data.home.label || 'placed' : 'not placed yet');
      item('local', null, data.local ? `Local network: ${localWords()}, never placed` : '');
      item('unplaced', null, unplacedWords());
      item('grows', null, 'A dot and its route grow with its connections');
      renderLayers();
    }
    // The layers' switches, a row at the legend's foot: a button each (its mark, its title, how many features, and its
    // state while it loads or where it could not), pressed while its layer is switched on. A button is made once and
    // kept while its layer is listed, and the buttons of the layers gone are taken out before the others are put in
    // order (arrange), so the focus on one stays through an update, and its words change in place. Without a loader
    // each is off and says why, and so does the row.
    let layerButtons = new Map();  // a layer's id -> {b, m, w, n, s}: its button and the parts of it
    const attr = (el, name, value) => {  // an attribute set, or taken off (null), only when it changes
      if (value == null) { if (el.hasAttribute(name)) el.removeAttribute(name); }
      else if (el.getAttribute(name) !== value) el.setAttribute(name, value);
    };
    function renderLayers() {
      if (layerBar.parentNode !== legend) legend.appendChild(layerBar);  // after the legend's own items
      const kept = new Map(), why = [];
      for (const l of data.layers) {
        let it = layerButtons.get(l.id);
        if (!it) {
          it = { b: document.createElement('button'), m: document.createElement('span'),
            w: document.createElement('span'), n: document.createElement('b'), s: document.createElement('span') };
          it.b.type = 'button';
          it.b.className = 'lg-layer';
          it.m.setAttribute('aria-hidden', 'true');
          it.s.className = 'lg-layer-state';
          it.b.append(it.m, it.w, it.n, it.s);
          it.b.addEventListener('click', () => switchLayer(l.id));
        }
        const e = layerData.get(l.key), on = isOn(l);
        const ready = on && !!e && e.state === 'ready', failed = on && !!e && e.state === 'failed';
        const count = l.count != null ? l.count : ready ? featuresOf(e.geo) : null;
        attr(it.m, 'class', `lg-m lg-m-${l.mark} lg-s${l.slot}`);
        setText(it.w, l.title);
        setText(it.n, count == null ? '' : count.toLocaleString());
        setText(it.s, !on ? '' : failed ? 'not loaded' : !ready ? 'loading…' : e.geo.cut ? 'in part' : '');
        attr(it.b, 'aria-pressed', String(on));
        attr(it.b, 'aria-disabled', load ? null : 'true');
        const over = ready ? e.geo.cut : 0;  // its features past what the globe keeps of a layer
        attr(it.b, 'title', !load ? NO_LOADER : failed ? `not loaded: ${e.why}`
          : over ? `${many(over, 'feature')} more than the globe draws of a layer: left out` : l.note || null);
        if (failed) why.push(`${l.title} is not loaded: ${e.why}`);
        kept.set(l.id, it);
      }
      for (const [id, it] of layerButtons) if (!kept.has(id)) it.b.remove();  // the layers gone: their buttons, first
      arrange(layerBar, [...kept.values()].map((it) => it.b), layerWhy);  // between the row's head and its words
      layerButtons = kept;
      if (!load && kept.size) why.unshift('These layers stay off: this page gives the globe no way to load them');
      if (data.unlisted) {
        why.push(`${many(data.unlisted, 'more layer')} not listed: the globe lists ${MAX_LAYERS} at most`);
      }
      setText(layerWhy, why.join(' · '));
      show(layerWhy, why.length > 0);
      show(layerBar, kept.size > 0);
    }
    // A layer switched on or off by its button, the choice remembered under the page's key. Without a loader it stays
    // off, and why is said.
    function switchLayer(id) {
      const l = data.layers.find((x) => x.id === id);
      if (!l) return;
      if (!load) { say(`${l.title}: ${NO_LOADER}`); return; }
      const next = !isOn(l);  // read before its choice is taken out: without it, isOn says what the spec says
      chosen.delete(id);  // put last: the oldest choices go first once there are too many
      chosen.set(id, next);
      while (chosen.size > 64) chosen.delete(chosen.keys().next().value);
      remember(storeName, chosen);
      layersShown = null;
      renderWords();
      changed();
    }
    // The origins without a known point, in their kinds' totals above: how many, and what came from them, by kind.
    function unplacedWords() {
      const kinds = Object.entries(KINDS).filter(([kind]) => data.unplaced[kind].places);
      if (!kinds.length) return '';
      return `${many(unplacedOf(data), 'place')} without a known point, not on the globe: `
        + kinds.map(([kind, k]) => `${many(data.unplaced[kind].count, k.noun)} ${k.words.toLowerCase()}`).join(', ');
    }
    function renderNote() {
      const parts = [];
      if (data.note) parts.push(data.note);
      if (data.more) parts.push(`${many(data.more, 'more place')} not shown: the ${MAX_ORIGINS} with the most connections are`);
      if (data.unread) {
        parts.push(`only the first ${MAX_READ.toLocaleString()} of ${(MAX_READ + data.unread).toLocaleString()} places were read, and the totals are theirs`);
      }
      if (data.updated) parts.push(`updated ${clock(data.updated)}`);
      setText(note, parts.join(' · '));
    }
    // The credits over the map: the places' attribution, then the credit of each layer shown (its spec's and its
    // parts'), each once. A credit is a link only when its address is an https one (creditOf); its node is made once
    // and kept while it is listed, and the nodes of the credits gone are taken out before the others are put in order
    // (arrange), so a keyboard's focus on a link, or a click, stays through an update.
    let credits = new Map();  // a credit (its address and its words) -> its node
    function renderAttribution() {
      const list = data.attribution ? [data.attribution] : [], kept = new Map();
      for (const { l, geo } of shownLayers()) list.push(...l.credits, ...geo.credits.filter(Boolean));
      if (coastCredited) list.push(COAST_CREDIT);  // GSHHG's coasts, while their tiles are drawn
      for (const a of list) {
        const key = `${a.url}\n${a.text}`;
        if (kept.has(key)) continue;
        let node = credits.get(key);
        if (!node) {
          node = document.createElement(a.url ? 'a' : 'span');
          if (a.url) {
            node.target = '_blank';
            node.rel = 'noopener noreferrer';
            node.href = a.url;
          }
        }
        setText(node, a.text || a.url);
        kept.set(key, node);
      }
      for (const [key, node] of credits) if (!kept.has(key)) node.remove();  // the credits gone: their nodes, first
      arrange(attribution, [...kept.values()]);
      credits = kept;
      show(attribution, kept.size > 0);
    }
    // The table, made while it is open and then kept: each place's row (by its id) has its cells' words set again only
    // where they changed, and is moved only when its place in the order is not where it stands.
    // A column: its head, whether its numbers line up right, a place's words in it, and the fact it shows (data.has):
    // a column of a fact no place here says is left out (hosts, programs and time connected where a plugin records
    // hosts; bytes where there are any).
    const placeWords = (o) => {
      const where = whereOf(o);
      return where && where !== nameOf(o) ? `${nameOf(o)} (${where})` : nameOf(o);
    };
    const COLUMNS = [['Place', false, placeWords], ['Kind', false, (o) => KINDS[o.kind].words],
      ['Connections', true, (o) => Math.round(o.count).toLocaleString()],
      ['Hosts', true, (o) => (o.hosts == null ? '–' : o.hosts.toLocaleString()), 'hosts'],
      ['Programs', false, (o) => o.programs.join(', '), 'programs'],
      ['Connected', true, (o) => (o.seconds == null ? '–' : duration(o.seconds)), 'seconds'],
      ['Bytes', true, (o) => (o.bytes ? bytes(o.bytes) : '–'), 'bytes'], ['Network', false, networkOf],
      ['Ports', false, (o) => portsOf(o.ports)], ['On the globe', false, pointOf]];
    let rows = new Map();  // a row's key (which place of its id, and the id) -> its <tr>
    let heads = '';  // the columns the table was made with
    function renderTable() {  // its rows are made only while it is open
      const list = data.listed, n = list.length;
      setText(summary, n ? `The ${many(n, 'place')} as a table` : 'No places yet');
      let box = table.querySelector('.lg-scroll');
      const columns = COLUMNS.filter(([, , , fact]) => !fact || data.has[fact]);
      const names = columns.map(([head]) => head).join('|');
      if (box && names !== heads) { box.remove(); box = null; }  // other columns (what the places say changed): anew
      if (!table.open || !n) { if (box) box.remove(); rows = new Map(); return; }
      if (!box) {
        box = document.createElement('div');
        box.className = 'lg-scroll';
        const t = document.createElement('table');
        t.className = 'list';
        const caption = t.createCaption();
        caption.className = 'lg-sr';
        caption.textContent = "The places this machine's traffic comes from and goes to, the most connections first";
        const head = t.createTHead().insertRow();
        for (const [h, numeric] of columns) {
          const th = document.createElement('th');
          th.scope = 'col';
          th.textContent = h;
          if (numeric) th.className = 'num';
          head.appendChild(th);
        }
        t.createTBody();
        box.appendChild(t);
        table.appendChild(box);
        rows = new Map();
        heads = names;
      }
      const body = box.querySelector('tbody'), kept = new Map(), ids = new Map();
      for (const o of list) {
        const nth = ids.get(o.id) || 0;  // a second place of the same id has a row of its own
        ids.set(o.id, nth + 1);
        const key = `${nth}|${o.id}`;
        let tr = rows.get(key);
        if (!tr) {
          tr = document.createElement('tr');
          for (const [, numeric] of columns) { const td = tr.insertCell(); if (numeric) td.className = 'num'; }
        }
        columns.map(([, , cell]) => cell(o)).forEach((words, c) => setText(tr.cells[c], words));
        kept.set(key, tr);
      }
      for (const [key, tr] of rows) if (!kept.has(key)) tr.remove();  // the places gone: their rows
      // The longest run of rows already in their order stays where it is; each other row (or a new one) is put before
      // the row that follows it, from the last up.
      const order = [...kept.values()], now = new Map();
      for (let node = body.firstChild, i = 0; node; node = node.nextSibling, i++) now.set(node, i);
      const stay = steady(order.map((tr) => (now.has(tr) ? now.get(tr) : -1)));
      let ref = null;
      for (let i = order.length - 1; i >= 0; i--) {
        if (!stay.has(i)) body.insertBefore(order[i], ref);
        ref = order[i];
      }
      rows = kept;
    }
    function describe() {
      const t = data.totals, n = data.listed.length + data.more, away = unplacedOf(data);
      const kinds = Object.entries(KINDS).filter(([kind]) => t[kind].places).map(([kind, k]) => `${t[kind].places} ${k.words.toLowerCase()}`);
      // each layer shown, with how many of its features are drawn
      const shown = shownLayers().map(({ l, geo }) => `${l.title} (${featuresOf(geo).toLocaleString()})`);
      const words = `A globe of the places this machine's traffic comes from and goes to: ${many(n, 'place')}`
        + `${kinds.length ? ` (${kinds.join(', ')})` : ''}${away ? `, ${away.toLocaleString()} of them without a known point and not drawn` : ''}`
        + `; this machine: ${data.home ? data.home.label || 'placed' : 'not placed yet'}.`
        + `${data.showing ? ` Showing: ${data.showing}.` : ''}`
        + `${shown.length ? ` Layers shown: ${shown.join(', ')}.` : ''}`
        + ' The arrow keys step through the places, + and − zoom, Home turns back to this machine; the table below lists them.';
      if (canvas.getAttribute('aria-label') !== words) canvas.setAttribute('aria-label', words);
    }
    function renderShowing() { setText(showing, data.showing); show(showing, !!data.showing); }
    function renderWords() {
      renderLegend(); renderNote(); renderShowing(); renderAttribution(); renderTable(); describe();
    }
    // Said to a screen reader once; the same words again get a no-break space, or a reader would not say them again.
    function say(words) { said.textContent = said.textContent === words ? `${words}\u00a0` : words; }
    function stepWords(o, list) {  // a keyboard's step: the place, what came from it, and which of how many it is
      const k = KINDS[o.kind], name = nameOf(o), where = whereOf(o);
      const place = !where || where === name ? name : where.startsWith(`${name}, `) ? where : `${name}, ${where}`;
      return `${place}: ${many(o.count, k.noun)} ${k.words.toLowerCase()}`
        + `${o.hosts != null ? `, ${many(o.hosts, 'host')}` : ''}`
        + `${o.seconds != null ? `, connected ${duration(o.seconds)}` : ''}${o.bytes ? `, ${bytes(o.bytes)}` : ''}`
        + `; ${list.indexOf(o) + 1} of ${list.length}`;
    }
    const sayZoom = () => say(zoom > 1.01 ? `Zoomed in ${zoomText()}` : 'The whole globe');

    // -- gestures: the charts app's globe.js --------------------------------------------------------------------------
    // A mouse, a pen or fingers (the user, 2026-11-10: "I want to support touch as well as mouse clicking on the
    // interface"). One pointer drags the globe round; two fingers pinch it nearer or further about the point between them
    // and turn it as that point moves, and a finger lifted hands the drag to the one left, so nothing jumps. A mouse
    // hovers a place for its words; a finger taps it, and they stay until its next tap; two quick taps go back home, as
    // a double click does.
    const PLACE_REACH = { mouse: 12, finger: 22 }, HOME_REACH = { mouse: 16, finger: 24 };  // px from the point
    const LINE_REACH = { mouse: 6, finger: 16 };  // px from a layer's line
    // px a press moves before it turns the globe: a fingertip (or a pen's) rolls a little in a tap; a mouse's 3 px
    const DRAG_SLOP = { mouse: 3, finger: 10 };
    const pointers = new Map();  // pointerId -> {x, y}: the pointers down on the globe, in the order they went down
    let dragging = null;  // one pointer turning the globe: {id, x, y, lon, lat, finger, moved}
    let pinch = null;  // two fingers: {d, x, y}: how far apart they were at the last move, and the point between them
    let pressedBy = 'mouse';  // what made the last press on the globe: a 'mouse', or a 'finger' (a touch or a pen)
    let lastTap = null, homedAt = 0;  // a finger's last tap {t, x, y}; when two taps last went home
    let justDragged = false;  // the click that ends a drag (or a pinch) is not a click on a place

    // What is under a point, `by` a mouse or a finger: the nearest of the places (within its reach, or its dot's own size
    // and then some) and home; where neither is, a mark or a line of the layers; {o}, {home: true} or {f}, or null.
    function hitAt(clientX, clientY, by) {
      const g = geometry(), r = canvas.getBoundingClientRect();
      const x = clientX - r.left, y = clientY - r.top;
      let best = null, bestD = Infinity;
      for (const o of data.origins) {
        const p = project(o.lon, o.lat, g);
        const d = Math.hypot(p.x - x, p.y - y);
        if (p.visible && d < Math.max(PLACE_REACH[by], dotRadius(o.count) + 4) && d < bestD) { best = { o }; bestD = d; }
      }
      if (data.home) {
        const p = project(data.home.lon, data.home.lat, g);
        const d = Math.hypot(p.x - x, p.y - y);
        if (p.visible && d < HOME_REACH[by] && d <= bestD) best = { home: true };
      }
      const f = best ? null : featureAt(x, y, by);
      return f ? { f } : best;
    }
    // Zoom to `want` (1x to MAX_ZOOM), turning a little towards the point under (clientX, clientY) so it stays roughly
    // under it: the wheel's, a trackpad's pinch and two fingers' alike. False when it is as near or as far as it goes.
    function zoomAt(clientX, clientY, want) {
      const g = geometry(), r = canvas.getBoundingClientRect();
      const at = unproject(clientX - r.left, clientY - r.top, g);
      const next = clamp(want, 1, MAX_ZOOM);
      if (Math.abs(next - zoom) < 1e-9) return false;
      if (at && next > zoom) {
        const t = 1 - zoom / next;
        view = { lon: wrap(view.lon + wrap(at.lon - view.lon) * t), lat: clamp(view.lat + (at.lat - view.lat) * t, -85, 85) };
        follow = false;
      }
      zoom = next;
      glide = null;
      changed();
      return true;
    }
    function zoomBy(f) {
      const r = canvas.getBoundingClientRect();
      zoomAt(r.left + r.width / 2, r.top + r.height / 2, zoom * f);
    }
    function startPinch() {  // the first two pointers down: a pinch from here, neither a drag nor a tap
      const [a, b] = pointers.values();
      pinch = { d: Math.max(1, Math.hypot(a.x - b.x, a.y - b.y)), x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
      dragging = null;
      justDragged = true;
    }
    function pinchMove() {
      const [a, b] = pointers.values();
      const d = Math.max(1, Math.hypot(a.x - b.x, a.y - b.y)), x = (a.x + b.x) / 2, y = (a.y + b.y) / 2;
      const k = 90 / geometry().r;  // the point between the fingers turns the globe as one finger's drag does
      view = { lon: wrap(view.lon - (x - pinch.x) * k), lat: clamp(view.lat + (y - pinch.y) * k, -85, 85) };
      follow = false;
      zoomAt(x, y, zoom * (d / pinch.d));  // nearer as the fingers part, further as they close
      pinch = { d, x, y };
      changed();
    }
    canvas.addEventListener('pointerdown', (e) => {
      glide = null;
      justDragged = false;  // a finger's drag leaves no click behind it: each press starts afresh
      pressedBy = e.pointerType === 'mouse' ? 'mouse' : 'finger';
      if (e.isPrimary) { pointers.clear(); pinch = null; }  // the first of its kind down: none other is (one missed lifting)
      pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      try { canvas.setPointerCapture(e.pointerId); } catch (err) { /* pointer already gone */ }
      if (pointers.size === 2) startPinch();
      else if (pointers.size === 1) {
        dragging = { id: e.pointerId, x: e.clientX, y: e.clientY, lon: view.lon, lat: view.lat, finger: pressedBy === 'finger' };
      }
    });
    canvas.addEventListener('pointermove', (e) => {
      const at = pointers.get(e.pointerId);
      if (at) { at.x = e.clientX; at.y = e.clientY; }
      if (pinch) { if (at) pinchMove(); return; }
      if (dragging && dragging.id === e.pointerId
          && (dragging.moved || Math.hypot(e.clientX - dragging.x, e.clientY - dragging.y) > DRAG_SLOP[dragging.finger ? 'finger' : 'mouse'])) {
        // a finger's turn starts from where it left its slop, so the globe does not jump by it (a mouse's as before)
        if (!dragging.moved && dragging.finger) Object.assign(dragging, { x: e.clientX, y: e.clientY, lon: view.lon, lat: view.lat });
        dragging.moved = true;
        if (pick && pick.by === 'mouse') setPick(null);
        const k = 90 / geometry().r;
        view = { lon: wrap(dragging.lon - (e.clientX - dragging.x) * k), lat: clamp(dragging.lat + (e.clientY - dragging.y) * k, -85, 85) };
        follow = false;
        glide = null;
        changed();
        return;
      }
      if (e.pointerType === 'touch') return;  // a finger hovers nothing: what it taps is found where it taps
      const hit = hitAt(e.clientX, e.clientY, 'mouse');
      canvas.style.cursor = hit ? 'pointer' : '';
      if (hit) setPick({ ...hit, by: 'mouse', x: e.clientX, y: e.clientY });
      else if (pick && pick.by === 'mouse') setPick(null);
    });
    canvas.addEventListener('pointerleave', (e) => {
      if (e.pointerType !== 'touch' && pick && pick.by === 'mouse') setPick(null);
    });
    function lifted(e) {
      if (!pointers.delete(e.pointerId)) return;  // not down here, or seen already (its capture lost after its lift)
      if (pinch) {
        if (pointers.size >= 2) { startPinch(); return; }  // a third finger was down: the pinch goes on with two
        pinch = null;
        const [id, p] = [...pointers][0] || [];  // the finger left turns the globe on from where it is
        dragging = p ? { id, x: p.x, y: p.y, lon: view.lon, lat: view.lat, finger: true, moved: true } : null;
        justDragged = true;
        return;
      }
      if (!dragging || dragging.id !== e.pointerId) return;
      justDragged = e.type === 'pointerup' && !!dragging.moved;
      dragging = null;
    }
    canvas.addEventListener('pointerup', lifted);
    canvas.addEventListener('pointercancel', lifted);
    canvas.addEventListener('lostpointercapture', lifted);
    // a finger held on the globe is turning it or about to: no browser menu opens under it (a mouse's right click as ever)
    canvas.addEventListener('contextmenu', (e) => {
      if (e.pointerType ? e.pointerType !== 'mouse' : pressedBy === 'finger') e.preventDefault();
    });
    // Two taps of a finger close together in time and place: back home, as a double click (whether a browser makes a
    // dblclick of two taps on the globe is not sure).
    function twoTaps(e) {
      const t = performance.now(), last = lastTap;
      lastTap = { t, x: e.clientX, y: e.clientY };
      if (!last || t - last.t > 350 || Math.hypot(e.clientX - last.x, e.clientY - last.y) > 30) return false;
      lastTap = null;
      homedAt = t;
      setPick(null);
      home();
      return true;
    }
    canvas.addEventListener('dblclick', () => {
      if (homedAt && performance.now() - homedAt < 600) return;  // the two taps did it already
      home();
    });
    // Zoom with the wheel or a trackpad's pinch, towards the point under the pointer; at its nearest or furthest the page
    // scrolls on instead (a pinch, ctrlKey, never zooms the page).
    canvas.addEventListener('wheel', (e) => {
      const dy = e.deltaY * (e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? 400 : 1);
      if (zoomAt(e.clientX, e.clientY, zoom * Math.exp(-dy * (e.ctrlKey ? 0.01 : 0.0015))) || e.ctrlKey) e.preventDefault();
    }, { passive: false });
    canvas.addEventListener('click', (e) => {
      if (justDragged) { justDragged = false; return; }
      const finger = pressedBy === 'finger';
      if (finger && twoTaps(e)) return;
      const hit = hitAt(e.clientX, e.clientY, finger ? 'finger' : 'mouse');
      if (hit && hit.home) {  // as globe.js's sun: a click or a tap on home goes back home (a finger's shows its words too)
        if (finger) setPick({ home: true, by: 'finger' });
        home();
        return;
      }
      if (finger) setPick(hit ? { ...hit, by: 'finger' } : null);  // its words stay until the next tap; a mouse's hover showed them
    });
    // The keyboard: the arrows step through the places (the busiest first), turning the globe to each and showing its
    // words, which a screen reader says; + and − zoom; Home goes back home; Escape puts the words away.
    canvas.addEventListener('keydown', (e) => {
      if (e.altKey || e.ctrlKey || e.metaKey) return;
      const list = data.origins;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown' || e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        if (!list.length) return;
        const by = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : -1;
        const i = pick && pick.o ? list.indexOf(pick.o) : -1;
        const o = list[i < 0 ? (by > 0 ? 0 : list.length - 1) : (i + by + list.length) % list.length];
        follow = false;
        setPick({ o, by: 'keys' });
        glideTo({ lon: o.lon, lat: clamp(o.lat, -85, 85), zoom });
        say(stepWords(o, list));
      } else if (e.key === '+' || e.key === '=') { zoomBy(1.6); sayZoom(); }
      else if (e.key === '-' || e.key === '_') { zoomBy(1 / 1.6); sayZoom(); }
      else if (e.key === 'Home') { setPick(null); home(); say('Back to this machine, the whole globe'); }
      else if (e.key === 'Escape' && pick) setPick(null);
      else return;
      e.preventDefault();
    });
    canvas.addEventListener('blur', () => {
      if (pick && pick.by === 'keys') setPick(null);
      said.textContent = '';  // nothing stale left for a reader that comes across it later (a zoom's words too)
    });
    const button = (label, words, fn) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'lg-button';
      b.textContent = label;
      b.title = words;
      b.setAttribute('aria-label', words);
      b.addEventListener('click', fn);
      controls.appendChild(b);
    };
    button('+', 'Zoom in', () => { zoomBy(1.6); sayZoom(); });
    button('−', 'Zoom out', () => { zoomBy(1 / 1.6); sayZoom(); });
    button('⌂', 'Back to this machine', () => { if (pick && pick.by !== 'mouse') setPick(null); home(); });
    table.addEventListener('toggle', renderTable);

    // -- watching: on screen, the page shown, the theme, the size, the screen's pixel ratio --------------------------------
    function recolour() {
      const next = readColours(root, theme), s = JSON.stringify(next);
      if (s === stamp) return;
      colours = next;
      stamp = s;
      changed();
    }
    const onVisibility = () => schedule();
    const onMotion = () => { reduced = !!(motion && motion.matches); if (reduced && glide) glide.start = -Infinity; changed(); };
    const onScroll = () => {  // the page moved the globe: a finger's or a mouse's words go, the keyboard's follow its dot
      if (!pick) return;
      if (pick.by === 'keys') { anchor = ''; anchorTip(geometry()); } else setPick(null);
    };
    function onRatio() { watchRatio(); changed(); }
    function watchRatio() {  // a query true at this pixel ratio only: its change says the ratio moved, then one for the new
      unlisten(dpr, onRatio);
      dpr = window.matchMedia ? matchMedia(`(resolution: ${window.devicePixelRatio || 1}dppx)`) : null;
      listen(dpr, onRatio);
    }
    // On screen or not (the latest word for it): off screen, its words go with it (a tab switched, the globe scrolled
    // away or taken off the page) and no frame is drawn.
    const seenBy = 'IntersectionObserver' in window ? new IntersectionObserver((entries) => {
      visible = entries[entries.length - 1].isIntersecting;
      if (!visible && pick) setPick(null);
      schedule();
    }) : null;
    if (seenBy) seenBy.observe(stage);
    const sized = 'ResizeObserver' in window ? new ResizeObserver(() => changed()) : null;
    if (sized) sized.observe(stage);
    const themed = new MutationObserver(recolour);  // a theme is a class or data-theme on <html> or <body>
    themed.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'data-theme', 'style'] });
    if (document.body) themed.observe(document.body, { attributes: true, attributeFilter: ['class', 'data-theme', 'style'] });
    listen(scheme, recolour);
    listen(motion, onMotion);
    document.addEventListener('visibilitychange', onVisibility);
    document.addEventListener('scroll', onScroll, { capture: true, passive: true });
    watchRatio();

    function update(next, more) {
      if (destroyed) return;
      if (more && more.theme !== undefined && more.theme !== theme) { theme = more.theme; recolour(); }
      if (more && typeof more.load === 'function') load = more.load;
      if (more && typeof more.key === 'string' && text(more.key, 200) !== storeName) {  // the switches kept elsewhere
        storeName = text(more.key, 200);
        chosen = recall(storeName);
      }
      data = normal(next);
      version++;
      buildRoutes();
      layersShown = null;
      pruneLayers();  // a layer the spec no longer lists, or lists in another version, is let go
      if (pick && !pick.f) {  // the same place in the new list (by its id) keeps its words, with its new numbers
        const o = pick.o ? data.origins.find((x) => x.id === pick.o.id) : null;
        if (pick.o ? !o : !data.home) setPick(null);
        else {
          if (o) pick = { ...pick, o };
          fillTip(pick);
          anchor = '';
          if (pick.by === 'mouse') placeTip(pick.x, pick.y, false);
        }
      }
      if (follow && aimKey() !== aimed) {  // home came or moved (or, with none, the first places came): turn there
        aimed = aimKey();
        glideTo({ ...homeView(), zoom });
      }
      renderWords();
      changed();
    }
    function destroy() {
      if (destroyed) return;
      destroyed = true;
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
      if (seenBy) seenBy.disconnect();
      if (sized) sized.disconnect();
      themed.disconnect();
      unlisten(scheme, recolour);
      unlisten(motion, onMotion);
      unlisten(dpr, onRatio);
      document.removeEventListener('visibilitychange', onVisibility);
      document.removeEventListener('scroll', onScroll, { capture: true });
      tip.remove();
      root.remove();
      for (const slot of Object.values(layers)) {
        if (slot.canvas) { slot.canvas.width = 0; slot.canvas.height = 0; }
        slot.canvas = null;
      }
      canvas.width = 0;
      canvas.height = 0;
      routes = [];
      pointers.clear();
      globes.delete(self);
      pruneLayers();  // the layers' geometry goes with the last globe that listed it
      if (instances.get(el) === self) instances.delete(el);
      if (!globes.size) {  // the 1:50m and 1:10m outlines and the coast tiles go with the last globe (the 1:110m stay)
        maps.fine = null;
        maps.finest = null;
        forgetCoast();
      }
    }

    const handle = { update: (next) => update(next), destroy };
    const self = {
      handle, root, update, destroy,
      mapArrived() { changed(); },
      layerKeys: () => (destroyed ? [] : data.layers.map((l) => l.key)),
      layerArrived() { layersShown = null; renderWords(); changed(); },  // a layer came, or not: its button says so
      left: () => seen && !root.isConnected,
      destroyed: () => destroyed,
    };
    globes.add(self);
    buildRoutes();
    renderWords();
    changed();
    return self;
  }

  // -- the styles: one <style> on the themes' variables (as apis.js), so a page without liminal.css draws it alike ---------
  const STYLE = `
.lg-globe{display:flex;flex-direction:column;gap:6px;min-width:0}
.lg-globe [hidden]{display:none!important}
.lg-stage{position:relative;min-width:0}
.lg-canvas{display:block;width:100%;height:clamp(260px,52vw,520px);cursor:grab;touch-action:none;-webkit-user-select:none;user-select:none;-webkit-touch-callout:none;border-radius:6px}
.lg-canvas:active{cursor:grabbing}
.lg-canvas:focus{outline:none}
.lg-canvas:focus-visible{outline:2px solid var(--accent,#2962ff);outline-offset:2px}
.lg-controls{position:absolute;top:6px;right:6px;display:flex;align-items:center;gap:4px}
.lg-zoom{font-size:11px;color:var(--muted,#787b86);margin-right:4px}
.lg-button{min-width:28px;height:28px;padding:0 6px;border:1px solid var(--border,#2a2e39);border-radius:6px;background:var(--panel,#1e222d);color:var(--text,#d1d4dc);font:inherit;line-height:1;cursor:pointer}
.lg-button:focus-visible{outline:2px solid var(--accent,#2962ff);outline-offset:1px}
@media (hover: hover){.lg-button:hover{background:var(--hover,#2a2e39)}}
@media (any-pointer: coarse){.lg-button{min-width:40px;height:40px}}
.lg-attr{position:absolute;right:6px;bottom:4px;max-width:calc(100% - 12px);font-size:11px;color:var(--muted,#787b86);background:var(--panel,#1e222d);border-radius:4px;padding:1px 6px;opacity:.9}
.lg-attr{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:0 10px}
.lg-attr a{color:inherit}
.lg-showing{position:absolute;left:6px;top:6px;max-width:calc(100% - 150px);box-sizing:border-box;font-size:11px;
  color:var(--muted,#787b86);background:var(--panel,#1e222d);border-radius:4px;padding:1px 6px;opacity:.9;
  pointer-events:none;overflow-wrap:anywhere}
.lg-legend{display:flex;flex-wrap:wrap;align-items:center;gap:4px 14px;font-size:12px;color:var(--muted,#787b86)}
.lg-legend>span{display:inline-flex;align-items:center;gap:5px}
.lg-legend b{color:var(--text,#d1d4dc);font-weight:600}
.lg-note{font-size:12px;color:var(--muted,#787b86)}
.lg-note:empty{display:none}
.lg-k{position:relative;display:inline-block;flex:none;width:20px;height:0;border-top:2px solid;margin:0 2px 0 4px}
.lg-k::before{content:'';position:absolute;left:-4px;top:-5px;width:8px;height:8px;border-radius:50%;background:currentColor}
.lg-k-allowed{color:var(--series-1,#3987e5)}
.lg-k-outbound{color:var(--series-2,#d95926)}
.lg-k-unanswered{color:var(--series-3,#199e70);border-top-style:dashed}
.lg-k-home{width:12px;height:12px;border:2px solid var(--accent,#2962ff);border-radius:50%;box-sizing:border-box;margin:0}
.lg-k-home::before{left:2px;top:2px;width:4px;height:4px;background:var(--accent,#2962ff)}
.lg-layers{display:flex;flex-wrap:wrap;align-items:center;gap:4px 6px;flex-basis:100%}
.lg-layer{display:inline-flex;align-items:center;gap:6px;padding:2px 8px;border:1px solid var(--border,#2a2e39);
  border-radius:7px;background:none;color:inherit;font:inherit;line-height:1.5;cursor:pointer}
.lg-layer[aria-pressed="false"]{opacity:.55}
.lg-layer[aria-disabled="true"]{cursor:default}
.lg-layer:focus-visible{outline:2px solid var(--accent,#2962ff);outline-offset:1px}
@media (hover: hover){.lg-layer:not([aria-disabled="true"]):hover{background:var(--hover,#2a2e39)}}
@media (any-pointer: coarse){.lg-layer{min-height:36px}}
.lg-layer-state:empty{display:none}
.lg-m{display:inline-block;flex:none;width:9px;height:9px;background:currentColor}
.lg-m-circle{border-radius:50%}
.lg-m-diamond{transform:rotate(45deg) scale(.82)}
.lg-m-line,.lg-m-dash{width:18px;height:0;background:none;border-top:2px solid}
.lg-m-dash{border-top-style:dashed}
.lg-s4,.lg-s5,.lg-s6,.lg-s7{color:var(--globe-network,#8fa3bf)}
.lg-table{font-size:12px}
.lg-table summary{cursor:pointer;color:var(--muted,#787b86);padding:2px 0}
.lg-scroll{overflow:auto;max-height:360px}
.lg-scroll table{width:100%;border-collapse:collapse}
.lg-scroll th{text-align:left;color:var(--muted,#787b86);font-weight:500;padding:3px 8px;border-bottom:1px solid var(--border,#2a2e39);white-space:nowrap}
.lg-scroll td{padding:3px 8px;border-bottom:1px solid var(--border,#2a2e39);color:var(--text,#d1d4dc)}
.lg-scroll .num{text-align:right;font-variant-numeric:tabular-nums}
.lg-sr{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
.lg-tip{position:fixed;z-index:55;pointer-events:none;box-sizing:border-box;max-width:min(320px,calc(100vw - 16px));padding:6px 9px;border-radius:6px;font-size:12px;line-height:1.4;overflow-wrap:anywhere;background:var(--panel,#1e222d);color:var(--text,#d1d4dc);border:1px solid var(--border,#2a2e39);box-shadow:0 6px 18px rgba(0,0,0,.3)}
.lg-tip-head{font-weight:600}
.lg-tip-sub{color:var(--muted,#787b86);overflow-wrap:anywhere}
.lg-tip-row{display:flex;align-items:center;gap:6px}
.lg-tip-row b{font-weight:600;white-space:nowrap}
.lg-tip-row span:last-child{color:var(--muted,#787b86)}
`;
  function style() {
    if (document.getElementById('liminal-globe-style')) return;
    const s = document.createElement('style');
    s.id = 'liminal-globe-style';
    s.textContent = STYLE;
    (document.head || document.documentElement).appendChild(s);
  }

  const instances = new WeakMap();  // an element -> the globe drawn in it

  // LiminalGlobe.draw(el, spec, {theme, load, key}) -> {update(spec), destroy()}. Drawn into the same element again, it
  // is the same globe updated in place (its view, zoom and words kept), and the same handle comes back.
  function draw(el, spec, opts) {
    if (!el || el.nodeType !== 1) {
      throw new TypeError('LiminalGlobe.draw(el, spec, {theme, load, key}): el is the element to draw in');
    }
    for (const g of [...globes]) if (g.left()) g.destroy();  // a globe whose element left the page
    const there = instances.get(el);
    if (there && !there.destroyed() && there.root.parentNode === el) {
      there.update(spec, opts || {});
      return there.handle;
    }
    if (there) there.destroy();
    style();
    const g = create(el, spec, opts || {});
    instances.set(el, g);
    return g.handle;
  }

  window.LiminalGlobe = { draw, decodeTopo };
})();
