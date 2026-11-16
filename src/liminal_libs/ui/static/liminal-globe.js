// The globe every app's page can draw (liminal-libs ui/static, for the plugins' World Wide Web tabs, 2026-11-14): the
// places this machine's traffic comes from and goes to, each a dot with its route to this machine. The user,
// 2026-11-14: "so for the firewall's both are going to get a 'world wide web view' that shows the globe and the routes
// incoming all traffic, as well as monitoring port traffic stats". The math and the gestures are the charts app's
// (globe.js, its Markets view): the orthographic projection, project / unproject / polyline broken on the far side,
// decodeTopo and its loader, a drag past a slop, the wheel and two fingers zooming about the point under them, a double
// click (or two taps) back home. One 2D canvas, sharp at the screen's pixel ratio; no libraries.
//
//   const globe = LiminalGlobe.draw(el, spec, {theme})   el: the element it fills (drawn into again: updated in place,
//   globe.update(spec)                                     its view kept); spec: a tab page's "globe" (apps/tabs.py):
//   globe.destroy()                                        {home: {lat, lon, label} | null, origins: [{id, lat, lon,
//                                                          label, country, city, asn, org, count, bytes, kind, ports}],
//                                                          local: {count, bytes}, attribution: {text, url} | null,
//                                                          updated, note}
//   theme: the page's theme or its base ("dark", "paper", ...), for the colours of a page without liminal.css's variables
//
// - The map is world-atlas 2.0.2 (Natural Earth, public domain) beside this file: vendor/world/countries-110m.json, and
//   countries-50m.json only once a globe is zoomed past 2.5x; one copy serves every globe on the page. The land is cut
//   where it goes behind the globe and closed along the rim the way round its own outline goes, so a coast on the
//   horizon is land to the rim and the sea round it stays sea, from any side.
// - Each origin is a dot sized by its count, with a great-circle route to home 1.2 + min(3.6, 1.3 log10(count + 1)) px
//   wide, by its kind: allowed in, unanswered in (dashed: no answer seen within 3 s) and out, named in the legend
//   beneath. Private and local peers are never placed: the legend counts them. A place without a known point (geo.Place's
//   lat = lon = None: its country known, not where in it) is not drawn either: it is in its kind's totals, the legend
//   says how many and how much, and the table lists it.
// - The colours are the themes' variables (--series-1..7, the kinds on slots 1 to 3, --accent for home, --muted, --text,
//   --frame), read again when the theme changes (the class or data-theme of <html> or <body>, the system's light or
//   dark, or a theme given to update).
// - A mouse hovers a dot, a finger taps it, the keyboard steps through them (the arrows; Home turns back home): its words
//   show, and a keyboard's step is said to a screen reader (a polite live region; the tooltip is not read). The same
//   places are a table beneath, for a screen reader and for reading the numbers. An update changes the words in place
//   (the legend's, the table's rows, the attribution's link): where the table is scrolled to, what is being read or
//   selected and the focus stay, though a page is asked again every few seconds.
// - It moves (a light travels each of the busiest routes) only while it is on screen and the page is shown, and stands
//   still under prefers-reduced-motion. A frame redraws only the routes and their lights: the map and the dots are
//   layers drawn again when the view, the places or the colours change. Nothing runs once it is destroyed; a globe whose
//   element left the page is destroyed when the next one is drawn.
// Names come from plugins: every text is set with textContent, and an address is a link only when it is an https one.
(() => {
  'use strict';

  const rad = Math.PI / 180;
  const TAU = 2 * Math.PI;
  const RETRY_MS = 60_000;  // a map that did not load is not asked for again before this (globe.js)
  const FINE_ZOOM = 2.5;  // past it the 1:50m outlines are loaded and drawn
  const MAX_ZOOM = 12;  // the 1:50m outlines' detail
  const MAX_ORIGINS = 512;  // the places tabled (and drawn: those with a point), the most connections first (traffic.TrafficBook keeps 512)
  const MAX_READ = 20000;  // the most of a spec's list read at all (the note says how many more there were)
  const FRAME_MS = 33;  // about 30 frames a second while the lights move
  const GLIDE_MS = 700;
  const LABELS = 5;  // the busiest places named on the map (the table and the tooltips carry every one)
  const LIGHTS = 64;  // the busiest routes a light travels (the rest stand still: a frame stays cheap)
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
      muted: '#787b86', text: '#d1d4dc', frame: '#2a2e39', surface: '#131722' },
    light: { series: ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6'], accent: '#1f4fd8',
      muted: '#474c59', text: '#0f1219', frame: '#cdd3dd', surface: '#f3f4f7' },
  };
  // the map beside this file (vendor/world/), wherever the page is served from (a front proxying an app's pages too)
  const HERE = (() => {
    try { return new URL('.', (document.currentScript && document.currentScript.src) || location.href).href; } catch (e) { return ''; }
  })();

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
  // a media query's changes, by addEventListener (or addListener: Safari before 14, as touch.js has it)
  const listen = (q, fn) => { if (q && q.addEventListener) q.addEventListener('change', fn); else if (q && q.addListener) q.addListener(fn); };
  const unlisten = (q, fn) => { if (q && q.removeEventListener) q.removeEventListener('change', fn); else if (q && q.removeListener) q.removeListener(fn); };
  function seedOf(s) {  // a route's own phase, from its id: the lights do not move in step
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return ((h >>> 0) % 10007) / 10007;
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
  // dropped, with its turn; null for a ring of fewer than three points or one naming an arc the map lacks.
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
    return { v, turn: turnOf(v) };
  }

  // The map ready to draw: the lines stroked as unit vectors (x, y, z a point: the coasts, and the borders two countries
  // share), without the data's cut lines along the antimeridian and round the South Pole, and the land's rings.
  function prepare(t) {
    const lines = decodeTopo(t);
    const arcs = lines.map((line) => {
      const v = new Float64Array(line.length * 3);
      line.forEach(([lon, lat], i) => v.set(unit(lon, lat), i * 3));
      return v;
    });
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
    const seam = ([lon1, lat1], [lon2, lat2]) => (Math.abs(lon1) > 179.99 && Math.abs(lon2) > 179.99) || (lat1 < -89.9 && lat2 < -89.9);
    const coasts = [], borders = [];
    lines.forEach((line, k) => {
      const piece = (from, to) => { if (to - from > 1) (uses[k] >= 2 ? borders : coasts).push(arcs[k].subarray(from * 3, to * 3)); };
      let start = 0;
      for (let i = 1; i < line.length; i++) if (seam(line[i - 1], line[i])) { piece(start, i); start = i; }
      piece(start, line.length);
    });
    return { land, coasts, borders };
  }

  const maps = { coarse: null, fine: null };  // 1:110m and 1:50m
  const globes = new Set();  // the globes drawn now (each redrawn when a map comes)
  const mapLoader = (name, key) => loader(async () => {
    try {
      const res = await fetch(`${HERE}vendor/world/${name}`, { credentials: 'same-origin' });
      if (!res.ok) return false;
      const map = prepare(await res.json());
      if (key === 'fine' && !globes.size) return true;  // every globe went meanwhile: not kept
      maps[key] = map;
      globes.forEach((g) => g.mapArrived());
      return true;
    } catch (e) { return false; }  // the coarse outlines meanwhile, or the sphere and its graticule alone
  });
  const loadCoarse = mapLoader('countries-110m.json', 'coarse');
  const loadFine = mapLoader('countries-50m.json', 'fine');

  // the graticule every 15 degrees (globe.js), made once
  let graticule = null;
  const graticuleLines = () => graticule || (graticule = [
    ...Array.from({ length: 24 }, (_, m) => Array.from({ length: 91 }, (__, i) => [-180 + m * 15, -90 + i * 2])),
    ...Array.from({ length: 11 }, (_, p) => Array.from({ length: 181 }, (__, i) => [-180 + i * 2, -75 + p * 15])),
  ]);

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
      const p = placeOf(o);
      all.push({
        id: text(o.id) || (p ? `${p.lat},${p.lon}#${i}` : `#${i}`), placed: !!p, lat: p ? p.lat : null, lon: p ? p.lon : null,
        label: text(o.label), country: text(o.country),
        city: text(o.city), asn: o.asn == null ? '' : text(o.asn, 40), org: text(o.org), count: Math.max(0, num(o.count) ?? 1),
        bytes: Math.max(0, num(o.bytes) ?? 0), kind: own(KINDS, o.kind) ? o.kind : 'allowed',
        ports: (Array.isArray(o.ports) ? o.ports.slice(0, 64) : []).map(num).filter((n) => n != null && n >= 0 && n <= 65535),
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
    const a = s.attribution && typeof s.attribution === 'object' ? { text: text(s.attribution.text), url: safeUrl(s.attribution.url) } : null;
    return {
      home: h ? { ...h, label: text(s.home.label, 80) } : null, origins: listed.filter((o) => o.placed), listed,
      more: Math.max(0, all.length - MAX_ORIGINS), unread: Math.max(0, given.length - MAX_READ), totals, unplaced,
      local: l ? { count: Math.max(0, num(l.count) ?? 0), bytes: Math.max(0, num(l.bytes) ?? 0) } : null,
      attribution: a && (a.text || a.url) ? a : null, updated: text(s.updated, 40), note: text(s.note, 400),
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
    const attribution = document.createElement('div');
    attribution.className = 'lg-attr';
    const said = document.createElement('div');  // a keyboard's step, said to a screen reader (the tooltip is not read)
    said.className = 'lg-sr';
    said.setAttribute('aria-live', 'polite');
    said.setAttribute('aria-atomic', 'true');
    const legend = document.createElement('div');
    legend.className = 'lg-legend';
    const note = document.createElement('div');
    note.className = 'lg-note';
    const table = document.createElement('details');
    table.className = 'lg-table';
    const summary = document.createElement('summary');
    table.appendChild(summary);
    stage.append(canvas, controls, attribution, said);
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
    let visible = !('IntersectionObserver' in window);
    let seen = root.isConnected;  // on the page once: after that, a globe that left it is destroyed with the next draw
    let destroyed = false, dirty = true, raf = 0, lastFrame = -Infinity;
    // offscreen layers, drawn again only when what they show changes: the sphere, the land and its lines; the dots and
    // the names
    const layers = { base: { canvas: null, key: '' }, places: { canvas: null, key: '' } };
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
    // polyline for a map's line of unit vectors: broken on the far side, its ends at the horizon where it goes behind.
    function strokeUnits(c, v, g, fr) {
      const { C, E, N } = fr;
      let pen = false, px = 0, py = 0, pz = 0, pd = -1;
      for (let i = 0; i < v.length; i += 3) {
        const x = v[i], y = v[i + 1], z = v[i + 2];
        const d = x * C[0] + y * C[1] + z * C[2];
        if (d >= 0) {
          const sx = g.cx + g.r * (x * E[0] + y * E[1] + z * E[2]), sy = g.cy - g.r * (x * N[0] + y * N[1] + z * N[2]);
          if (pen) c.lineTo(sx, sy);
          else {
            if (i > 0) { const h = horizon(x, y, z, d, px, py, pz, pd, fr); c.moveTo(g.cx + g.r * h[0], g.cy - g.r * h[1]); c.lineTo(sx, sy); }
            else c.moveTo(sx, sy);
            pen = true;
          }
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
        const a = unit(o.lon, o.lat);
        const w = Math.acos(clamp(a[0] * b[0] + a[1] * b[1] + a[2] * b[2], -1, 1));
        if (w < 0.002) continue;  // at home's own place: its dot, no route
        const n = clamp(Math.ceil(w / rad / 3), 8, 64);
        const lift = Math.min(0.22, 0.04 + (0.18 * w) / Math.PI);
        // nearly opposite home, any great circle will do: by a point a quarter of the way round
        const mid = Math.sin(w) < 1e-3 ? perpendicular(a) : null;
        const path = new Float64Array((n + 1) * 4);
        for (let i = 0; i <= n; i++) {
          const t = i / n;
          const q = mid ? (t < 0.5 ? slerp(a, mid, Math.PI / 2, 2 * t) : slerp(mid, b, Math.PI / 2, 2 * t - 1)) : slerp(a, b, w, t);
          path.set([q[0], q[1], q[2], lift * Math.sin(Math.PI * t)], i * 4);
        }
        const seed = seedOf(o.id);
        routes.push({ o, path, screen: new Float64Array((n + 1) * 3), width: routeWidth(o.count), seed, period: 2400 + seed * 1600 });
      }
      routes.sort((x, y) => x.o.count - y.o.count);  // the busiest drawn last, on top
    }
    function slerp(a, b, w, t) {
      const s = Math.sin(w), p = Math.sin((1 - t) * w) / s, q = Math.sin(t * w) / s;
      return [p * a[0] + q * b[0], p * a[1] + q * b[1], p * a[2] + q * b[2]];
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
    const viewKey = (g, W, H, ratio) => [W, H, ratio, g.r.toFixed(2), view.lon.toFixed(3), view.lat.toFixed(3), stamp].join('|');

    // The sphere, the land and its lines.
    function baseLayer(g, fr, ratio, W, H) {
      const map = zoom > FINE_ZOOM && maps.fine ? maps.fine : maps.coarse;
      const key = `${viewKey(g, W, H, ratio)}|${map === maps.fine ? 'fine' : map ? 'coarse' : 'none'}`;
      return layer(layers.base, key, W, H, ratio, (b) => {
        const k = colours, ocean = mix(k.surface, k.frame, 0.6), land = mix(ocean, k.text, 0.1);
        b.beginPath(); b.arc(g.cx, g.cy, g.r, 0, TAU);
        b.fillStyle = css(ocean); b.fill();
        if (map) {  // the land: every ring in one path, so the cuts along the antimeridian leave no seam
          b.beginPath();
          for (const ring of map.land) ringPath(b, ring, g, fr);
          b.fillStyle = css(land); b.fill('evenodd');
        }
        b.beginPath();
        for (const line of graticuleLines()) polyline(b, line, g);
        b.strokeStyle = css(k.muted, 0.18); b.lineWidth = 0.7; b.stroke();
        if (map) {
          b.beginPath();
          for (const v of map.borders) strokeUnits(b, v, g, fr);
          b.strokeStyle = css(k.muted, 0.45); b.lineWidth = 0.6; b.stroke();
          b.beginPath();
          for (const v of map.coasts) strokeUnits(b, v, g, fr);
          b.strokeStyle = css(k.muted, 0.85); b.lineWidth = 0.8; b.stroke();
        }
        b.beginPath(); b.arc(g.cx, g.cy, g.r, 0, TAU);
        b.strokeStyle = css(k.muted, 0.7); b.lineWidth = 1; b.stroke();
      });
    }

    // The dots and the names on the map, over the routes and their lights.
    function placesLayer(g, ratio, W, H) {
      const picked = pick ? (pick.home ? 'home' : pick.o.id) : '';
      const key = `${viewKey(g, W, H, ratio)}|${version}|${picked}`;
      return layer(layers.places, key, W, H, ratio, (c) => drawLabels(c, g, drawPlaces(c, g)));
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
        ctx.strokeStyle = css(colours.series[k.slot - 1], group.level === 2 ? 0.95 : group.level === 0 ? 0.2 : 0.55);
        ctx.lineWidth = group.width;
        ctx.stroke();
      }
      ctx.setLineDash([]);
      ctx.lineDashOffset = 0;
      if (!now) return;  // still: no lights
      ctx.lineCap = 'round';
      for (let i = Math.max(0, routes.length - LIGHTS); i < routes.length; i++) {
        const rt = routes[i], k = KINDS[rt.o.kind], out = rt.o.kind === 'outbound';
        let t = (now / rt.period + rt.seed) % 1;
        if (out) t = 1 - t;
        const fade = rt.o.kind === 'unanswered' ? 1 - smooth(0.6, 0.9, t) : 1;  // it knocks, and no answer comes
        const head = fade > 0 ? along(rt.screen, t) : null;
        if (!head) continue;
        const dim = picked && picked !== rt.o ? 0.25 : 1;
        const glow = mix(colours.series[k.slot - 1], colours.text, 0.35);
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
      c.textBaseline = 'alphabetic';
    }

    function render(now) {
      const ratio = window.devicePixelRatio || 1;
      const g = geometry(), fr = camera();
      const W = Math.max(1, Math.round(g.w * ratio)), H = Math.max(1, Math.round(g.h * ratio));
      if (canvas.width !== W || canvas.height !== H) { canvas.width = W; canvas.height = H; }
      if (!maps.coarse) loadCoarse();
      if (zoom > FINE_ZOOM && !maps.fine) loadFine();  // the 1:50m outlines only once zoomed past 2.5x
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, W, H);
      ctx.drawImage(baseLayer(g, fr, ratio, W, H), 0, 0);
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
        if (data.local) line('', `local network: ${many(data.local.count, 'connection')}, ${bytes(data.local.bytes)}, never placed`);
        return;
      }
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
      if (o.bytes) line('', bytes(o.bytes));
      if (networkOf(o)) line('lg-tip-sub', networkOf(o));
      if (o.ports.length) line('lg-tip-sub', `ports ${portsOf(o.ports)}`);
    }
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
      const at = pick.home ? (data.home ? project(data.home.lon, data.home.lat, g) : null) : project(pick.o.lon, pick.o.lat, g);
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
      if (!was || was.o !== p.o || !!was.home !== !!p.home || was.by !== p.by) { fillTip(p); changed(); }
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
      for (const [kind, k] of Object.entries(KINDS)) {
        const t = data.totals[kind];
        item(kind, kind, k.words, t.places ? `${many(t.places, 'place')}, ${many(t.count, k.noun)}` : 'none');
      }
      item('home', 'home', 'This machine', data.home ? data.home.label || 'placed' : 'not placed yet');
      item('local', null, data.local ? `Local network: ${many(data.local.count, 'connection')}, ${bytes(data.local.bytes)}, never placed` : '');
      item('unplaced', null, unplacedWords());
      item('grows', null, 'A dot and its route grow with its connections');
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
    let link = null;  // the attribution's link, kept while the address is one: a keyboard's focus on it, or a click, stays
    function renderAttribution() {
      const a = data.attribution;
      show(attribution, !!a);
      if (a && a.url) {
        if (!link || link.parentNode !== attribution) {
          link = document.createElement('a');
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
          attribution.replaceChildren(link);
        }
        if (link.getAttribute('href') !== a.url) link.href = a.url;
        setText(link, a.text || a.url);
      } else {
        link = null;
        setText(attribution, a ? a.text : '');
      }
    }
    // The table, made while it is open and then kept: each place's row (by its id) has its cells' words set again only
    // where they changed, and is moved only when its place in the order is not where it stands.
    const COLUMNS = [['Place', false], ['Kind', false], ['Connections', true], ['Bytes', true], ['Network', false], ['Ports', false],
      ['On the globe', false]];
    let rows = new Map();  // a row's key (which place of its id, and the id) -> its <tr>
    function renderTable() {  // its rows are made only while it is open
      const list = data.listed, n = list.length;
      setText(summary, n ? `The ${many(n, 'place')} as a table` : 'No places yet');
      let box = table.querySelector('.lg-scroll');
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
        for (const [h, numeric] of COLUMNS) {
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
      }
      const body = box.querySelector('tbody'), kept = new Map(), ids = new Map();
      for (const o of list) {
        const nth = ids.get(o.id) || 0;  // a second place of the same id has a row of its own
        ids.set(o.id, nth + 1);
        const key = `${nth}|${o.id}`;
        let tr = rows.get(key);
        if (!tr) {
          tr = document.createElement('tr');
          for (const [, numeric] of COLUMNS) { const td = tr.insertCell(); if (numeric) td.className = 'num'; }
        }
        const where = whereOf(o);
        [where && where !== nameOf(o) ? `${nameOf(o)} (${where})` : nameOf(o), KINDS[o.kind].words, Math.round(o.count).toLocaleString(),
          o.bytes ? bytes(o.bytes) : '–', networkOf(o), portsOf(o.ports), pointOf(o)].forEach((words, c) => setText(tr.cells[c], words));
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
      const words = `A globe of the places this machine's traffic comes from and goes to: ${many(n, 'place')}`
        + `${kinds.length ? ` (${kinds.join(', ')})` : ''}${away ? `, ${away.toLocaleString()} of them without a known point and not drawn` : ''}`
        + `; this machine: ${data.home ? data.home.label || 'placed' : 'not placed yet'}.`
        + ' The arrow keys step through the places, + and − zoom, Home turns back to this machine; the table below lists them.';
      if (canvas.getAttribute('aria-label') !== words) canvas.setAttribute('aria-label', words);
    }
    function renderWords() { renderLegend(); renderNote(); renderAttribution(); renderTable(); describe(); }
    // Said to a screen reader once; the same words again get a no-break space, or a reader would not say them again.
    function say(words) { said.textContent = said.textContent === words ? `${words}\u00a0` : words; }
    function stepWords(o, list) {  // a keyboard's step: the place, what came from it, and which of how many it is
      const k = KINDS[o.kind], name = nameOf(o), where = whereOf(o);
      const place = !where || where === name ? name : where.startsWith(`${name}, `) ? where : `${name}, ${where}`;
      return `${place}: ${many(o.count, k.noun)} ${k.words.toLowerCase()}${o.bytes ? `, ${bytes(o.bytes)}` : ''}`
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
    // px a press moves before it turns the globe: a fingertip (or a pen's) rolls a little in a tap; a mouse's 3 px
    const DRAG_SLOP = { mouse: 3, finger: 10 };
    const pointers = new Map();  // pointerId -> {x, y}: the pointers down on the globe, in the order they went down
    let dragging = null;  // one pointer turning the globe: {id, x, y, lon, lat, finger, moved}
    let pinch = null;  // two fingers: {d, x, y}: how far apart they were at the last move, and the point between them
    let pressedBy = 'mouse';  // what made the last press on the globe: a 'mouse', or a 'finger' (a touch or a pen)
    let lastTap = null, homedAt = 0;  // a finger's last tap {t, x, y}; when two taps last went home
    let justDragged = false;  // the click that ends a drag (or a pinch) is not a click on a place

    // What is under a point, `by` a mouse or a finger: the nearest of the places (within its reach, or its dot's own size
    // and then some) and home; {o} or {home: true}, or null.
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
      return best;
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
      data = normal(next);
      version++;
      buildRoutes();
      if (pick) {  // the same place in the new list (by its id) keeps its words, with its new numbers
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
      if (instances.get(el) === self) instances.delete(el);
      if (!globes.size) maps.fine = null;  // the 1:50m outlines go with the last globe (the 1:110m are small)
    }

    const handle = { update: (next) => update(next), destroy };
    const self = {
      handle, root, update, destroy,
      mapArrived() { changed(); },
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
.lg-attr a{color:inherit}
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

  // LiminalGlobe.draw(el, spec, {theme}) -> {update(spec), destroy()}. Drawn into the same element again, it is the same
  // globe updated in place (its view, zoom and words kept), and the same handle comes back.
  function draw(el, spec, opts) {
    if (!el || el.nodeType !== 1) throw new TypeError('LiminalGlobe.draw(el, spec, {theme}): el is the element to draw in');
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
