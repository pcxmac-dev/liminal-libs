// The apps' charts (liminal-libs ui/static, 1.23.0): series over time as line charts, by the data-viz rules: 2px
// lines, an end dot ringed in the surface colour, a hairline grid, one axis each (two measures of different scales
// are two charts), a legend with the latest values for two lines or more, the latest value in the head of a
// one-line chart, a crosshair snapping to the nearest sample with one tooltip listing every line at that time, the
// same from the keyboard (focus a chart, then the arrow keys, Home, End), and the latest samples as a table beneath
// (the light themes' paler slots sit below 3:1 against the page: the table and the legend's values carry them).
// The colours are liminal.css's categorical slots --series-1..7, fixed by a line's key (the entity), never by its
// rank. Names come from plugins: every text is escaped or set with textContent.
//
// By a finger too (1.42.0; the user, 2026-11-10: "I want to support touch as well as mouse clicking on the
// interface"): a finger (or a pen) held on a plot, or a tap, shows the crosshair and the tooltip at its time, the
// tooltip above the finger, and a sideways move scrubs through the samples; an upward or downward swipe still scrolls
// the page, nothing shown meanwhile (liminal.css: touch-action pan-y on the plot). The tooltip stays once the finger
// lifts, until a tap elsewhere or a scroll. The plot is marked data-touch-own (touch.js: its long press is the plot's
// own, no bubble there).
//
//   el.innerHTML = LiminalCharts.cards(spec, {id})   spec: {span: recent|day, t: [epoch s], charts: [{key, title,
//   LiminalCharts.draw(el)                            unit: share|bytes|bytes/s, max, of, lines: [{key, name, values}]}]}
//   LiminalCharts.update(el, spec, {id})              new samples for the same charts, drawn in place (false: not the same)
(() => {
  'use strict';

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const BINARY = new Set(['bytes', 'bytes/s']);
  // a line's slot by its key (the entity): the machine's own figures, then the apps' programs by role
  const SLOTS = { cpu: 1, memory: 1, in: 1, out: 2, gui: 1, integrator: 2, platform: 3, login: 4, sync: 5, live: 6, host: 7, other: 7 };
  const H = 150, TOP = 8, BOTTOM = H - 22, LEFT = 58, RIGHT = 10;
  const ROWS = 30;  // the table beneath: the latest samples
  const specs = new Map();  // a chart's id -> {chart, t, span}
  const opened = new Set();  // the tables shown, kept across redraws
  let hover = null;  // {id, x, y, touch}: the pointer over a chart (a finger's, `touch`, stays after it lifts)
  let focused = null;  // {id, t, last}: the sample focused from the keyboard (the newest while `last`)
  let finger = null;  // {svg, id, x0, y0, x, y, timer}: a finger (or a pen) down on a plot, its tooltip due after a moment
  let tip = null;

  function bytes(n) {
    if (n == null || !Number.isFinite(n)) return '–';
    let v = Math.abs(n), i = 0;
    while (v >= 1024 && i < UNITS.length - 1) { v /= 1024; i++; }
    return `${n < 0 ? '−' : ''}${i === 0 || v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${UNITS[i]}`;
  }
  const rate = (n) => (n == null || !Number.isFinite(n) ? '–' : `${bytes(n)}/s`);
  function share(f) {
    if (f == null || !Number.isFinite(f)) return '–';
    const p = Math.abs(f * 100);
    return `${(f * 100).toFixed(p > 0 && p < 1 ? 2 : p < 10 ? 1 : 0)}%`;
  }
  const format = (unit) => (unit === 'bytes' ? bytes : unit === 'bytes/s' ? rate : unit === 'share' ? share : (v) => (v == null ? '–' : String(v)));
  const slot = (key, i) => SLOTS[key] || Math.min(7, i + 1);  // seven slots validated: more lines share the seventh, the legend names them
  function slotsOf(lines) {  // one slot each: a second line of the same key takes the next one free
    const used = new Set();
    return lines.map((ln, i) => {
      let s = slot(ln.key, i);
      for (let n = 0; used.has(s) && n < 7; n++) s = (s % 7) + 1;
      used.add(s);
      return s;
    });
  }
  const lastIndex = (values) => { for (let i = values.length - 1; i >= 0; i--) if (values[i] != null && Number.isFinite(values[i])) return i; return -1; };
  const lastValue = (values) => { const i = lastIndex(values); return i < 0 ? null : values[i]; };
  const lineKey = (s) => `<svg class="key" width="14" height="10" viewBox="0 0 14 10" aria-hidden="true"><line x1="1" y1="5" x2="13" y2="5" style="stroke:var(--series-${s})" stroke-width="2" stroke-linecap="round"/></svg>`;
  const clock = (t, span, long) => new Date(t * 1000).toLocaleString([], span === 'day'
    ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }
    : { hour: '2-digit', minute: '2-digit', second: long ? '2-digit' : undefined, hour12: false });
  const spanWords = (span) => (span === 'day' ? 'over the last day' : 'over the last ten minutes');

  function niceTop(v, unit) {  // the axis's top when the figure has none of its own: 1, 2, 2.5 or 5 of a power of ten
    if (!(v > 0)) return unit === 'share' ? 0.01 : BINARY.has(unit) ? 1024 : 1;
    const base = BINARY.has(unit) ? 1024 ** Math.max(0, Math.floor(Math.log(v) / Math.log(1024))) : 1;
    const x = v / base, e = 10 ** Math.floor(Math.log10(x)), f = x / e;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * e * base;
  }
  function tickFormat(unit, step) {  // a share's ticks with the decimals their step needs
    if (unit !== 'share') return format(unit);
    const p = step * 100;
    const d = [0, 1, 2].find((k) => Math.abs(Math.round(p * 10 ** k) - p * 10 ** k) < 1e-6);
    return (v) => `${(v * 100).toFixed(d ?? 2)}%`;
  }

  // -- the cards: a head (the title, the latest value or a legend), the plot, the table ------------------------
  function table(id, c, t, span, fmt) {
    const rows = [];
    for (let i = t.length - 1; i >= 0 && rows.length < ROWS; i--) {
      rows.push(`<tr><td>${esc(clock(t[i], span, true))}</td>${c.lines.map((ln) => `<td class="num">${esc(fmt(ln.values[i]))}</td>`).join('')}</tr>`);
    }
    return `<details class="chart-table" data-chart="${esc(id)}"${opened.has(id) ? ' open' : ''}><summary>The ${rows.length} latest samples</summary>`
      + `<table class="list"><thead><tr><th>Time</th>${c.lines.map((ln) => `<th class="num">${esc(ln.name)}</th>`).join('')}</tr></thead>`
      + `<tbody>${rows.join('')}</tbody></table></details>`;
  }

  function cards(spec, { id = 'chart' } = {}) {
    if (!spec || !(spec.charts || []).length) return '';
    const t = spec.t || [], span = spec.span || 'recent';
    return spec.charts.map((c) => {
      const key = `${id}:${c.key}`;
      specs.set(key, { chart: c, t, span });
      const fmt = format(c.unit), slots = slotsOf(c.lines), one = c.lines.length === 1;
      const latest = c.lines.map((ln) => lastValue(ln.values));
      const of = c.of ? ` <span class="chart-of">of ${esc(c.of)}</span>` : '';
      const head = `<div class="chart-head"><span class="chart-title">${esc(c.title)}${of}</span>`
        + (one ? `<span class="chart-now">${esc(fmt(latest[0]))}${c.max && c.unit !== 'share' ? ` <span class="chart-of">of ${esc(fmt(c.max))}</span>` : ''}</span>` : '')
        + '</div>';
      const legend = one ? '' : `<div class="chart-legend">${c.lines.map((ln, i) => `<span>${lineKey(slots[i])}${esc(ln.name)} <b>${esc(fmt(latest[i]))}</b></span>`).join('')}</div>`;
      const label = `${c.title}: ${c.lines.map((ln, i) => `${one ? '' : `${ln.name} `}${fmt(latest[i])}`).join(', ')}, ${spanWords(span)}`;
      return `<figure class="chart" data-chart="${esc(key)}">${head}${legend}`
        + `<svg class="plot" data-chart="${esc(key)}" data-touch-own role="img" tabindex="0" aria-label="${esc(label)}" height="${H}"></svg>`
        + `${table(key, c, t, span, fmt)}</figure>`;
    }).join('');
  }

  // -- the plot, at the width it has -------------------------------------------------------------------------
  function geometry(w, c, t) {
    let high = 0;
    c.lines.forEach((ln) => ln.values.forEach((v) => { if (v != null && Number.isFinite(v) && v > high) high = v; }));
    const top = c.max > 0 ? c.max : niceTop(high, c.unit);
    const t0 = t.length ? t[0] : 0, t1 = t.length ? t[t.length - 1] : 1, plotW = w - LEFT - RIGHT;
    return {
      w, top, t0, t1, ticks: [0, top / 2, top], tick: tickFormat(c.unit, top / 2),
      x: (tt) => (t.length > 1 && t1 > t0 ? LEFT + ((tt - t0) / (t1 - t0)) * plotW : LEFT + plotW),
      y: (v) => BOTTOM - (Math.min(Math.max(v, 0), top) / top) * (BOTTOM - TOP),
    };
  }

  function render(svg) {
    const s = specs.get(svg.dataset.chart);
    if (!s) return;
    const { chart: c, t, span } = s;
    const w = Math.max(220, Math.round(svg.getBoundingClientRect().width) || 300);
    const g = geometry(w, c, t), slots = slotsOf(c.lines);
    svg.setAttribute('viewBox', `0 0 ${w} ${H}`);
    svg._g = g;
    let out = '';
    g.ticks.forEach((v) => {
      const y = g.y(v).toFixed(1);
      out += `<line class="grid" x1="${LEFT}" x2="${w - RIGHT}" y1="${y}" y2="${y}"/>`
        + `<text x="${LEFT - 6}" y="${y}" text-anchor="end" dominant-baseline="middle">${esc(g.tick(v))}</text>`;
    });
    if (t.length) {
      const picks = t.length === 1 ? [0] : w < 320 ? [0, t.length - 1] : [0, Math.floor((t.length - 1) / 2), t.length - 1];
      [...new Set(picks)].forEach((i, k, all) => {
        const anchor = all.length === 1 ? 'end' : k === 0 ? 'start' : k === all.length - 1 ? 'end' : 'middle';
        out += `<text x="${g.x(t[i]).toFixed(1)}" y="${H - 6}" text-anchor="${anchor}">${esc(clock(t[i], span, false))}</text>`;
      });
    }
    let washes = '', lines = '', dots = '';
    c.lines.forEach((ln, k) => {
      const color = `var(--series-${slots[k]})`;
      let d = '', pen = false, run = [];
      const flush = () => {  // a one-line chart's wash under each run of samples
        if (c.lines.length === 1 && run.length > 1) {
          washes += `<path class="wash" d="M${run[0][0]} ${BOTTOM}L${run.map(([x, y]) => `${x} ${y}`).join('L')}L${run[run.length - 1][0]} ${BOTTOM}Z" style="fill:${color}"/>`;
        }
        run = [];
      };
      ln.values.forEach((v, i) => {
        if (v == null || !Number.isFinite(v) || i >= t.length) { pen = false; flush(); return; }  // a gap is not joined
        const x = g.x(t[i]).toFixed(1), y = g.y(v).toFixed(1);
        d += `${pen ? 'L' : 'M'}${x} ${y}`;
        pen = true;
        run.push([x, y]);
      });
      flush();
      if (d) lines += `<path class="line" d="${d}" style="stroke:${color}"/>`;
      const last = lastIndex(ln.values);
      if (last >= 0 && last < t.length) dots += `<circle class="dot" r="4" cx="${g.x(t[last]).toFixed(1)}" cy="${g.y(ln.values[last]).toFixed(1)}" style="fill:${color}"/>`;
    });
    out += washes + lines + dots
      + `<g class="cross" visibility="hidden"><line class="cross-x" y1="${TOP}" y2="${BOTTOM}"/>`
      + c.lines.map((ln, k) => `<circle class="dot" r="4" style="fill:var(--series-${slots[k]})"/>`).join('') + '</g>'
      + `<rect class="hit" x="${LEFT}" y="0" width="${Math.max(1, w - LEFT - RIGHT)}" height="${H}" fill="transparent"/>`;
    svg.innerHTML = out;
  }

  // -- the crosshair and the tooltip --------------------------------------------------------------------------
  function nearest(t, at) {
    if (t.length < 2) return t.length - 1;
    let lo = 0, hi = t.length - 1;
    if (at <= t[lo]) return lo;
    if (at >= t[hi]) return hi;
    while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (t[mid] < at) lo = mid; else hi = mid; }
    return at - t[lo] <= t[hi] - at ? lo : hi;
  }
  function indexAt(svg, clientX) {
    const s = specs.get(svg.dataset.chart), g = svg._g;
    if (!s || !g || !s.t.length) return -1;
    const r = svg.getBoundingClientRect(), px = (clientX - r.left) * (g.w / (r.width || g.w));
    return nearest(s.t, g.t0 + ((px - LEFT) / (g.w - LEFT - RIGHT)) * (g.t1 - g.t0));
  }
  function tipElement() {
    if (tip && tip.isConnected) return tip;
    tip = document.createElement('div');
    tip.className = 'chart-tip';
    tip.setAttribute('aria-hidden', 'true');  // the table beneath each chart carries the same values
    tip.hidden = true;
    document.body.appendChild(tip);
    return tip;
  }
  function hide() {
    if (tip) tip.hidden = true;
    document.querySelectorAll('svg.plot g.cross').forEach((x) => x.setAttribute('visibility', 'hidden'));
  }
  function show(svg, i, cx, cy, byFinger = false) {
    const s = specs.get(svg.dataset.chart), g = svg._g;
    if (!s || !g || i < 0 || i >= s.t.length) { hide(); return; }
    const { chart: c, t, span } = s, fmt = format(c.unit), slots = slotsOf(c.lines), x = g.x(t[i]);
    document.querySelectorAll('svg.plot g.cross').forEach((other) => { if (!svg.contains(other)) other.setAttribute('visibility', 'hidden'); });
    const cross = svg.querySelector('g.cross');
    if (cross) {
      cross.setAttribute('visibility', 'visible');
      const v = cross.querySelector('line');
      v.setAttribute('x1', x.toFixed(1));
      v.setAttribute('x2', x.toFixed(1));
      cross.querySelectorAll('circle').forEach((dot, k) => {
        const value = c.lines[k] ? c.lines[k].values[i] : null;
        if (value == null || !Number.isFinite(value)) { dot.setAttribute('visibility', 'hidden'); return; }
        dot.setAttribute('visibility', 'visible');
        dot.setAttribute('cx', x.toFixed(1));
        dot.setAttribute('cy', g.y(value).toFixed(1));
      });
    }
    const box = tipElement();
    box.replaceChildren();
    const when = document.createElement('div');
    when.className = 'when';
    when.textContent = clock(t[i], span, true);
    box.appendChild(when);
    c.lines.forEach((ln, k) => {  // the value first, the line's name after it
      const row = document.createElement('div');
      row.className = 'row';
      row.insertAdjacentHTML('beforeend', lineKey(slots[k]));
      const b = document.createElement('b');
      b.textContent = fmt(ln.values[i]);
      const n = document.createElement('span');
      n.textContent = ln.name;
      row.append(b, n);
      box.appendChild(row);
    });
    box.hidden = false;
    const r = svg.getBoundingClientRect(), scale = (r.width || g.w) / g.w;
    const px = cx ?? r.left + x * scale, py = cy ?? r.top + TOP;
    const tw = box.offsetWidth, th = box.offsetHeight;
    let left = px + 14, top = py + 14;
    if (byFinger) {  // a finger's: above it, centred on it, clear of the fingertip; beside it where there is no room above
      left = px - tw / 2;
      top = py - 32 - th;
      if (top < 8) {
        top = py - th / 2;
        left = px + 32 + tw <= innerWidth - 8 ? px + 32 : px - 32 - tw;
      }
      left = Math.min(left, innerWidth - 8 - tw);
      top = Math.min(top, innerHeight - 8 - th);
    } else {
      if (left + tw > innerWidth - 8) left = px - 14 - tw;
      if (top + th > innerHeight - 8) top = py - 14 - th;
    }
    box.style.left = `${Math.max(8, left)}px`;
    box.style.top = `${Math.max(8, top)}px`;
    svg._shown = i;
  }
  const byId = (id) => document.querySelector(`svg.plot[data-chart="${CSS.escape(id)}"]`);
  function refreshTip() {  // after new samples: the tooltip at the same time (the newest when that was focused)
    if (focused) {
      const svg = byId(focused.id), s = specs.get(focused.id);
      if (svg && s && s.t.length && document.activeElement === svg) { show(svg, focused.last ? s.t.length - 1 : nearest(s.t, focused.t)); return; }
      focused = null;
    }
    if (hover) {
      const svg = byId(hover.id);
      if (svg) { show(svg, indexAt(svg, hover.x), hover.x, hover.y, hover.touch); return; }
      hover = null;
    }
    hide();
  }

  // A finger on a plot: the sample at its time after a moment held (a swipe up or down scrolls the page instead,
  // cancelling it), at once when it moves sideways (it scrubs), or where it lifts (a tap); kept until a tap elsewhere or
  // a scroll.
  const fingerDown = (e) => e.pointerType === 'touch' || (e.pointerType === 'pen' && e.buttons > 0);
  function fingerShow(f, x, y) {
    clearTimeout(f.timer);
    f.timer = 0;
    if (!f.svg.isConnected) return;
    hover = { id: f.svg.dataset.chart, x, y, touch: true };
    show(f.svg, indexAt(f.svg, x), x, y, true);
  }
  document.addEventListener('pointerdown', (e) => {
    const svg = fingerDown(e) && e.isPrimary && e.target instanceof Element ? e.target.closest('svg.plot[data-chart]') : null;
    if (!svg) return;
    if (finger) clearTimeout(finger.timer);
    const f = { svg, id: e.pointerId, x0: e.clientX, y0: e.clientY, x: e.clientX, y: e.clientY, timer: 0 };
    f.timer = setTimeout(() => { if (finger === f) fingerShow(f, f.x, f.y); }, 150);
    finger = f;
    try { svg.setPointerCapture(e.pointerId); } catch (err) { /* lifted already */ }
  }, { passive: true });
  document.addEventListener('pointerup', (e) => {
    if (!finger || e.pointerId !== finger.id) return;
    const f = finger;
    finger = null;
    if (f.timer) fingerShow(f, e.clientX, e.clientY);  // a tap: the tooltip at its time
  }, true);
  document.addEventListener('pointercancel', (e) => {  // the page scrolls instead: no tooltip left behind
    if (!finger || e.pointerId !== finger.id) return;
    clearTimeout(finger.timer);
    finger = null;
    if (hover && hover.touch) { hover = null; refreshTip(); }
  }, true);
  document.addEventListener('scroll', (e) => {  // a finger's tooltip does not stay behind a chart the page moved
    if (!hover || !hover.touch || finger) return;
    const svg = byId(hover.id);
    if (e.target === document || !svg || (e.target instanceof Element && e.target.contains(svg))) { hover = null; refreshTip(); }
  }, { capture: true, passive: true });

  document.addEventListener('pointermove', (e) => {
    if (finger && e.pointerId === finger.id) {
      // it scrubs once shown, or from a move mainly sideways; the start of one up or down (the page's scroll, whose
      // pointercancel follows) and a still finger's tremble show nothing before the moment is up
      const f = finger, dx = Math.abs(e.clientX - f.x0), dy = Math.abs(e.clientY - f.y0);
      f.x = e.clientX;
      f.y = e.clientY;
      if (!f.timer || (dx > dy && dx > 4)) fingerShow(f, e.clientX, e.clientY);
      return;
    }
    const svg = e.target instanceof Element ? e.target.closest('svg.plot[data-chart]') : null;
    if (!svg) { if (hover) { hover = null; refreshTip(); } return; }
    hover = { id: svg.dataset.chart, x: e.clientX, y: e.clientY };
    show(svg, indexAt(svg, e.clientX), e.clientX, e.clientY);
  }, { passive: true });
  document.documentElement.addEventListener('pointerleave', (e) => {
    if (hover && hover.touch && e.pointerType !== 'mouse') return;  // a finger lifting: its tooltip stays
    hover = null;
    refreshTip();
  });
  document.addEventListener('pointerdown', (e) => {  // a click or a right click elsewhere: the tooltip goes
    if (hover && !(e.target instanceof Element && e.target.closest('svg.plot[data-chart]'))) { hover = null; refreshTip(); }
  }, true);
  document.addEventListener('focusin', (e) => {
    const svg = e.target instanceof Element ? e.target.closest('svg.plot[data-chart]') : null;
    const s = svg && specs.get(svg.dataset.chart);
    if (!s || !s.t.length) return;
    // a finger's tap focused it: the time the finger picked stays, not the newest (a key afterwards steps from it)
    if ((finger && finger.svg === svg) || (hover && hover.touch && hover.id === svg.dataset.chart)) return;
    focused = { id: svg.dataset.chart, t: s.t[s.t.length - 1], last: true };
    show(svg, s.t.length - 1);
  });
  document.addEventListener('focusout', (e) => {
    if (e.target instanceof Element && e.target.closest('svg.plot[data-chart]')) { focused = null; refreshTip(); }
  });
  document.addEventListener('keydown', (e) => {
    const svg = e.target instanceof Element ? e.target.closest('svg.plot[data-chart]') : null;
    const s = svg && specs.get(svg.dataset.chart);
    if (!s || !s.t.length) return;
    const n = s.t.length;
    let i = svg._shown ?? n - 1;
    if (e.key === 'ArrowLeft') i -= e.shiftKey ? 10 : 1;
    else if (e.key === 'ArrowRight') i += e.shiftKey ? 10 : 1;
    else if (e.key === 'Home') i = 0;
    else if (e.key === 'End') i = n - 1;
    else if (e.key === 'Escape') { focused = null; hide(); return; }
    else return;
    e.preventDefault();
    i = Math.max(0, Math.min(n - 1, i));
    focused = { id: svg.dataset.chart, t: s.t[i], last: i === n - 1 };
    show(svg, i);
  });
  document.addEventListener('toggle', (e) => {  // a table shown stays shown when the chart is drawn again
    const d = e.target;
    if (!(d instanceof HTMLDetailsElement) || !d.classList.contains('chart-table')) return;
    if (d.open) opened.add(d.dataset.chart); else opened.delete(d.dataset.chart);
  }, true);
  const resized = new ResizeObserver((entries) => {
    entries.forEach((en) => en.target.querySelectorAll('svg.plot[data-chart]').forEach(render));
    refreshTip();
  });

  function draw(root) {  // after cards() went into the page: each plot at its width
    tipElement();
    root.querySelectorAll('svg.plot[data-chart]').forEach(render);
    resized.observe(root);
    refreshTip();
  }

  function update(root, spec, { id = 'chart' } = {}) {
    const figs = [...root.querySelectorAll('figure.chart[data-chart]')];
    const keys = ((spec && spec.charts) || []).map((c) => `${id}:${c.key}`);
    if (!keys.length || figs.length !== keys.length || figs.some((f, i) => f.dataset.chart !== keys[i])) return false;
    spec.charts.forEach((c, i) => {
      const fig = figs[i], scratch = document.createElement('div');
      scratch.innerHTML = cards({ ...spec, charts: [c] }, { id });  // the new head, legend and table (and the spec kept)
      const fresh = scratch.firstElementChild;
      for (const part of ['.chart-head', '.chart-legend', 'details.chart-table summary', 'details.chart-table tbody']) {
        const now = fig.querySelector(part), next = fresh.querySelector(part);
        if (now && next) now.innerHTML = next.innerHTML;
      }
      const svg = fig.querySelector('svg.plot');
      svg.setAttribute('aria-label', fresh.querySelector('svg.plot').getAttribute('aria-label'));
      render(svg);
    });
    refreshTip();
    return true;
  }

  window.LiminalCharts = { cards, draw, update, format, slot, bytes, rate, share, niceTop };
})();
