// The right-hand menu, alike in every app (liminal-libs 1.105.0; Monday list item 31, the user, 2026-11-22: "the right
// hand menu holds the 'tool' selected on the left hand menu in the top portion of it's menu. However, if there is
// amplifying information selected from the main screen (in between) it shows up as amplifying information underneath
// the plugin or tools' info in the right hand menu, this needs to be global for all apps too"). docs/PAGES.md is the
// standard; standard.json its rules, read here once (LiminalSide.standard: after and problems, liminal_libs.ui.standard's
// twin, both run on tests/data/ui_standard_cases.json).
//
//   const panel = LiminalSide.panel(aside, {app: 'platform'})  // one per element, made once
//   panel.tool(scope, html)  // the top: the tool picked on the left; drawn again alone. A new scope lets the pick go
//   panel.pick(spec)         // under it: {key, title, sub, icon, facts: [[label, value]], sections: [{title, facts}],
//                            //   note, from: the element picked}
//   panel.unpick(); panel.picked  // {scope, key} or null
//   panel.refresh(find)      // the middle drawn again: find(key) gives the pick told anew, or null (kept, marked gone)
//   panel.state; panel.problems()  // the app's groups as the standard holds them now (the scope's tool and tab, the
//                            //   pick), and what in them the rules refuse, in words ([] when none)
//   LiminalSide.rows(root, {selector, panel, describe})  // rows picked by a click, Enter, Space or a tap
//   LiminalSide.fromRow(tr); LiminalSide.html(spec)
//
// A plugin gives the words of its rows: every one is set as text or escaped, never as markup. Loaded after icons.js and
// before the app's own script; a page without it draws its right-hand menu as before.
(() => {
  'use strict';
  const esc = (s) => (window.LiminalIcons && window.LiminalIcons.esc ? window.LiminalIcons.esc(s)
    : String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));
  const NARROW = '(max-width: 700px)';  // the page stacked: the pick scrolled into view, with a way back to its row
  const MAX_FACTS = 60, MAX_WORDS = 2000;  // what a pick tells, at most (a server caps its own; these keep a page small)
  const NOT_PICKING = 'button, a, input, select, textarea, summary, label, [contenteditable], [data-no-pick]';

  // the platform's three groups: the rules until standard.json is read (the tests hold this to the file)
  const FALLBACK = {"v": 1, "spaces": ["controller", "left", "main", "overhead", "right"], "apps": {"platform": {
    "controller": ["platform", "login"],
    "groups": [
      {"id": "tool", "space": "left", "at_once": "one", "default": "machine",
       "tools": ["machine", "plugin", "assistant", "database", "connections", "codebase", "own"]},
      {"id": "tab", "space": "main", "at_once": "one", "of": "tool", "default": "main",
       "open": "the tabs of the tool picked: Main, External API, Internal API, a plugin's own"},
      {"id": "pick", "space": "main", "at_once": "one-or-none", "of": "tab",
       "open": "a row of the tab's tables, a place, router or feature on its globe, a part of Connections"}],
    "right": ["tool", "pick"]}}};  // end of FALLBACK

  // -- the rules (liminal_libs.ui.standard's twin) ---------------------------------------------------------------------
  let rules = FALLBACK;
  const ready = (typeof fetch === 'function'
    ? fetch('standard.json', { cache: 'no-cache' }).then((r) => (r.ok ? r.json() : null))
      .then((j) => { if (j && j.v === 1 && j.apps) rules = j; return rules; })
      .catch(() => rules)  // an older server, or none: the fallback
    : Promise.resolve(rules));

  const appOf = (app, given) => {
    const a = ((given || rules).apps || {})[app];
    if (!a) throw new Error(`no app named ${app} in the page standard`);
    return a;
  };
  const groupsOf = (app, given) => appOf(app, given).groups.slice();
  const groupOf = (app, id, given) => {
    const g = groupsOf(app, given).find((x) => x.id === id);
    if (!g) throw new Error(`${app} has no group named ${id}`);
    return g;
  };
  const start = (g) => ('default' in g ? [g.default] : []);
  const allowed = (spec, other) => (typeof spec === 'string' ? [].concat(other[spec] || []) : [].concat(spec));
  const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  const heldIn = (state, g) => (has(state, g.id) ? state[g.id] : start(g));
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

  function fits(app, state, g, value, given) {  // why value may not be in g with the rest of state: '' when it may
    if (value === g.default) return '';
    const said = (spec) => (typeof spec === 'string' ? spec : spec.join(' or '));
    for (const [otherId, spec] of Object.entries(g.with || {})) {
      const other = groupOf(app, otherId, given);
      if (!(state[otherId] && state[otherId].length ? state[otherId] : start(other)).some((v) => allowed(spec, other).includes(v)))
        return `${g.id} ${JSON.stringify(value)} only while ${otherId} is ${said(spec)}`;
    }
    for (const [otherId, spec] of Object.entries((g.only || {})[value] || {})) {
      const other = groupOf(app, otherId, given);
      if (!(state[otherId] && state[otherId].length ? state[otherId] : start(other)).some((v) => allowed(spec, other).includes(v)))
        return `${g.id} ${JSON.stringify(value)} only while ${otherId} is ${said(spec)}`;
    }
    return '';
  }

  function settle(app, state, changed, given) {
    const gs = groupsOf(app, given), done = new Set();
    while (changed.size) {
      changed.forEach((c) => done.add(c));
      const now = new Set();
      for (const g of gs) {
        if (g.of && changed.has(g.of) && !done.has(g.id)) { state[g.id] = start(g); now.add(g.id); }
        const was = heldIn(state, g), kept = was.filter((v) => !fits(app, state, g, v, given));
        if (!same(kept, was)) { state[g.id] = kept.length ? kept : start(g); now.add(g.id); }
      }
      changed = new Set([...now].filter((c) => !done.has(c)));
    }
    return state;
  }

  // the state a pick of value in group leaves (null: let go); a pick the rules refuse throws
  function after(app, state, group, value, given) {
    const g = groupOf(app, group, given), next = {};
    for (const [k, v] of Object.entries(state || {})) next[k] = [].concat(v);
    for (const x of groupsOf(app, given)) if (!has(next, x.id)) next[x.id] = start(x);
    const was = next[group].slice();
    if (value != null) {
      if (g.tools && !g.tools.includes(value)) throw new Error(`${app}'s ${group} has no ${value}`);
      if (g.of && !next[g.of].length) throw new Error(`${app}'s ${group} is picked only with its ${g.of}`);
      const why = fits(app, next, g, value, given);
      if (why) throw new Error(`${app}: ${why}`);
    }
    if (value == null) next[group] = start(g);
    else if (g.at_once === 'one') next[group] = [value];
    else if (g.at_once === 'one-or-none') next[group] = same(was, [value]) ? [] : [value];
    else next[group] = was.includes(value) ? was.filter((v) => v !== value) : was.concat([value]);
    return settle(app, next, same(next[group], was) ? new Set() : new Set([group]), given);
  }

  function problems(app, state, given) {  // what in state the rules refuse, in words
    const out = [], gs = groupsOf(app, given), known = new Set(gs.map((g) => g.id));
    for (const id of Object.keys(state || {})) if (!known.has(id)) out.push(`${app} has no group named ${id}`);
    for (const g of gs) {
      const held = [].concat(heldIn(state || {}, g));
      if (new Set(held.map((v) => JSON.stringify(v))).size !== held.length) out.push(`${g.id} holds one value twice`);
      if (g.at_once === 'one' && held.length !== 1) out.push(`${g.id} holds ${held.length}, exactly one is picked`);
      if (g.at_once === 'one-or-none' && held.length > 1) out.push(`${g.id} holds ${held.length}, one or none is picked`);
      if (g.tools) held.filter((v) => !g.tools.includes(v)).forEach((v) => out.push(`${g.id} has no ${JSON.stringify(v)}`));
      if (g.of && !same(held, start(g)) && !heldIn(state || {}, groupOf(app, g.of, given)).length) out.push(`${g.id} is picked without its ${g.of}`);
      held.forEach((v) => { const why = fits(app, state || {}, g, v, given); if (why) out.push(why); });
    }
    return out;
  }

  // -- a pick's words -----------------------------------------------------------------------------------------------
  const words = (v) => {
    const s = Array.isArray(v) ? v.map((x) => String(x ?? '')).join(', ') : v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
    return s.length > MAX_WORDS ? `${s.slice(0, MAX_WORDS)}…` : s;
  };
  const factsHtml = (facts) => {
    const rows = [].concat(facts || []).filter((f) => Array.isArray(f) && f.length >= 2).slice(0, MAX_FACTS);
    return rows.length ? `<dl class="facts">${rows.map(([k, v]) => `<dt>${esc(words(k))}</dt><dd>${esc(words(v))}</dd>`).join('')}</dl>` : '';
  };
  // the body of a pick, under its head: what is picked, told in full (the head, its title and Unpick, is the panel's)
  function html(spec) {
    const s = spec || {};
    const parts = [];
    if (s.sub) parts.push(`<p class="muted small side-sub">${esc(words(s.sub))}</p>`);
    parts.push(factsHtml(s.facts));
    for (const sec of [].concat(s.sections || []).slice(0, 12)) {
      if (!sec) continue;
      parts.push(`${sec.title ? `<h4>${esc(words(sec.title))}</h4>` : ''}${factsHtml(sec.facts)}${sec.words ? `<p class="small">${esc(words(sec.words))}</p>` : ''}`);
    }
    for (const l of [].concat(s.lines || []).slice(0, MAX_FACTS)) if (l) parts.push(`<p class="small side-line">${esc(words(l))}</p>`);
    if (s.note) parts.push(`<p class="muted small side-note">${esc(words(s.note))}</p>`);
    return parts.join('');
  }

  // a row told by its cells, each under its column's heading (a table whose server gives no details)
  function fromRow(tr) {
    const table = tr && tr.closest ? tr.closest('table') : null;
    const heads = table ? [...table.querySelectorAll('thead th')].map((th) => th.textContent.trim()) : [];
    const cells = tr ? [...tr.cells] : [];
    const text = (c) => c.textContent.replace(/\s+/g, ' ').trim();
    let caption = table && table.caption ? table.caption.textContent : '';  // the table's own heading, else the nearest before it
    for (let n = table; !caption && n && n !== document.body; n = n.parentElement) {
      for (let s = n.previousElementSibling; s && !caption; s = s.previousElementSibling) if (/^H[2-5]$/.test(s.tagName)) caption = s.textContent;
    }
    return {
      title: cells.length ? text(cells[0]) : '',
      sub: caption ? String(caption).trim() : '',
      facts: cells.slice(1).map((c, i) => [heads[i + 1] || `Column ${i + 2}`, text(c)]).filter(([, v]) => v !== ''),
    };
  }

  const clock = () => { const d = new Date(), p = (n) => String(n).padStart(2, '0'); return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`; };
  const reduced = () => !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const narrow = () => !!(window.matchMedia && window.matchMedia(NARROW).matches);

  // -- the panel ----------------------------------------------------------------------------------------------------
  const panels = new WeakMap();

  function panel(aside, opts) {
    if (!aside) throw new Error('LiminalSide.panel: no element');
    if (panels.has(aside)) return panels.get(aside);
    const o = opts || {};
    let scope = null, picked = null, gone = null, toolHtml = null, pickHtml = null;
    const roots = new Set();
    // the standard applied (docs/PAGES.md, standard.json): each scope's tool (its first word, after the app's own
    // name) and tab (after its slash) and each pick are a step of `after`, so a new tool or tab lets the pick go by the
    // rules' `of`, and a pick the rules refuse is not made. An app the rules do not name: no state, nothing refused
    let state = {}, refused = '';
    const named = () => { try { return o.app ? groupsOf(o.app) : null; } catch (e) { return null; } };
    function step(group, value) {
      const gs = named();
      if (!gs || !gs.some((g) => g.id === group)) return true;
      try { state = after(o.app, state, group, value); refused = ''; return true; }
      catch (e) { refused = e.message; return false; }
    }
    function scoped(s) {
      const gs = named();
      if (!gs || !gs.length) return;
      let t = String(s ?? '');
      if (t.startsWith(`${o.app}:`)) t = t.slice(o.app.length + 1);
      const slash = t.indexOf('/'), head = slash < 0 ? t : t.slice(0, slash), tab = slash < 0 ? '' : t.slice(slash + 1);
      const first = gs[0], word = head.split(':')[0];
      if (s == null) { step(first.id, null); return; }
      step(first.id, word);
      const tabs = gs.find((g) => g.id === 'tab' && g.of === first.id);
      if (tabs && !refused) step('tab', tab || (tabs.default ?? null));
    }
    const el = { tool: null, pick: null };

    function ensure() {  // a page that set the aside's markup whole took the slots with it: made again, empty
      if (!el.tool || !aside.contains(el.tool)) {
        el.tool = document.createElement('div'); el.tool.className = 'side-tool';
        aside.prepend(el.tool); toolHtml = null;
      }
      if (!el.pick || !aside.contains(el.pick)) {
        el.pick = document.createElement('section'); el.pick.className = 'side-pick';
        el.pick.setAttribute('aria-live', 'polite'); el.pick.setAttribute('aria-label', 'The one picked'); el.pick.hidden = true;
        el.tool.after(el.pick); pickHtml = null;
        el.pick.addEventListener('click', (e) => {
          if (e.target.closest('.side-unpick')) { unpick(true); return; }
          if (e.target.closest('.side-back')) { e.preventDefault(); back(); }
        });
        el.pick.addEventListener('keydown', (e) => { if (e.key === 'Escape' && picked) { e.stopPropagation(); unpick(true); } });
        if (picked) draw(picked.spec);
      }
    }

    function rowOf(key) {  // the row picked as the middle has it now (it may have been drawn again)
      for (const r of roots) {
        if (!r.root.isConnected) { roots.delete(r); continue; }
        for (const tr of r.root.querySelectorAll(r.selector)) if (tr.dataset.pick === key) return tr;
      }
      return null;
    }

    function mark() {  // aria-selected and .picked on the one row picked, in every root the rows are picked in
      const key = picked ? picked.key : null;
      for (const r of roots) {
        if (!r.root.isConnected) { roots.delete(r); continue; }
        for (const tr of r.root.querySelectorAll(r.selector)) {
          if (!tr.hasAttribute('tabindex')) tr.tabIndex = 0;
          const on = key != null && tr.dataset.pick === key;
          tr.classList.toggle('picked', on);
          tr.setAttribute('aria-selected', on ? 'true' : 'false');
        }
      }
    }

    function draw(spec) {
      const title = words(spec.title || spec.key || 'Picked');
      const iconHtml = spec.icon && window.LiminalIcons && window.LiminalIcons.icon ? window.LiminalIcons.icon(String(spec.icon), 16) : '';
      const markup = `<div class="side-pick-head"><h3>${iconHtml}<span class="side-pick-title">${esc(title)}</span></h3>
        <button type="button" class="side-unpick" aria-label="Unpick" title="Unpick (Esc)">&times;</button></div>
        ${narrow() ? '<p class="side-back-row"><a href="#" class="side-back">Back to the row</a></p>' : ''}
        ${gone ? `<p class="side-gone muted small">No longer shown as of ${esc(gone)}.</p>` : ''}
        <div class="side-pick-body">${html(spec)}</div>`;
      if (markup !== pickHtml) { el.pick.innerHTML = markup; pickHtml = markup; }
      el.pick.hidden = false;
    }

    function tell(changed) {
      try { aside.dispatchEvent(new CustomEvent('liminal:pick', { detail: picked ? { scope: picked.scope, key: picked.key } : null })); }
      catch (e) { /* an old browser: nothing listens */ }
      if (changed && o.onPick) { try { o.onPick(picked ? { scope: picked.scope, key: picked.key } : null); } catch (e) { /* the page's */ } }
    }

    function pick(spec) {
      if (!spec || spec.key == null) return;
      ensure();
      const key = String(spec.key), again = picked && picked.key === key;
      if (!again && !step('pick', key)) return;  // the rules refuse it (refused says why): nothing picked
      picked = { scope, key, spec, from: spec.from || null };
      gone = null;
      draw(spec);
      mark();
      if (!again && narrow()) {
        try { el.pick.scrollIntoView({ block: 'start', behavior: reduced() ? 'auto' : 'smooth' }); } catch (e) { el.pick.scrollIntoView(); }
      }
      tell(!again);
    }

    function unpick(focusRow) {
      if (!picked) return;
      const key = picked.key, from = picked.from;
      picked = null; gone = null;
      if (state.pick && state.pick.length) step('pick', null);
      if (el.pick) { el.pick.hidden = true; el.pick.innerHTML = ''; pickHtml = null; }
      mark();
      if (focusRow) {
        const row = rowOf(key) || (from && from.isConnected ? from : null);
        if (row && row.focus) try { row.focus({ preventScroll: !narrow() }); } catch (e) { row.focus(); }
      }
      tell(true);
    }

    function back() {
      if (!picked) return;
      const row = rowOf(picked.key) || (picked.from && picked.from.isConnected ? picked.from : null);
      if (!row) return;
      try { row.scrollIntoView({ block: 'center', behavior: reduced() ? 'auto' : 'smooth' }); } catch (e) { row.scrollIntoView(); }
      if (row.focus) row.focus({ preventScroll: true });
    }

    const api = {
      get picked() { return picked ? { scope: picked.scope, key: picked.key } : null; },
      get scope() { return scope; },
      get state() { return JSON.parse(JSON.stringify(state)); },
      problems() {
        const gs = named();
        if (!gs) return [];
        return [...(refused ? [refused] : []), ...problems(o.app, state)];
      },
      get slots() { ensure(); return { tool: el.tool, pick: el.pick }; },
      tool(newScope, markup) {
        ensure();
        const s = newScope == null ? null : String(newScope);
        if (s !== scope) {
          if (picked) unpick(false);
          scope = s;
          scoped(s);  // the standard's tool and tab: the pick's `of` reset with them
        }
        const m = markup == null ? '' : String(markup);
        if (m !== toolHtml) { el.tool.innerHTML = m; toolHtml = m; }  // the page's own markup (it escapes a plugin's words)
        return el.tool;
      },
      pick,
      unpick: () => unpick(false),
      refresh(find) {  // the middle drawn again: the pick told anew, or kept and marked gone
        ensure();
        if (picked) {
          let spec = null;
          try { spec = find ? find(picked.key) : null; } catch (e) { spec = null; }
          if (spec) { gone = null; picked.spec = Object.assign({}, spec, { key: picked.key }); }
          else if (!gone) gone = clock();
          draw(picked.spec);
        }
        mark();
      },
      _roots: roots, _mark: mark, _unpickFocus: () => unpick(true),
    };
    panels.set(aside, api);
    ensure();
    return api;
  }

  // -- rows picked ----------------------------------------------------------------------------------------------------
  const wired = new WeakMap();

  // rows of root (selector, each with data-pick, its key) picked into the panel: a click, Enter or Space, a finger's tap.
  // A button, a link, a field or a summary inside a row never picks. Called again after the middle is drawn: the same
  // listeners, the rows marked again. Returns off().
  function rows(root, opts) {
    if (!root || !opts || !opts.panel) return () => {};
    const o = { selector: opts.selector || 'tr[data-pick]', panel: opts.panel, describe: opts.describe || fromRow };
    const entry = { root, selector: o.selector };
    let w = wired.get(root);
    if (w) { Object.assign(w.o, o); w.entry.selector = o.selector; o.panel._mark(); return w.off; }
    const take = (tr) => {
      const key = tr.dataset.pick, p = w.o.panel;
      if (p.picked && p.picked.key === key) { p.unpick(); return; }  // a second click on the same row lets it go
      let spec = null;
      try { spec = w.o.describe(tr, key); } catch (e) { spec = null; }
      p.pick(Object.assign({}, spec || fromRow(tr), { key, from: tr }));
    };
    const onClick = (e) => {
      const tr = e.target.closest ? e.target.closest(w.o.selector) : null;
      if (!tr || !root.contains(tr) || tr.dataset.pick == null) return;
      const inner = e.target.closest(NOT_PICKING);
      if (inner && tr.contains(inner) && inner !== tr) return;
      take(tr);
    };
    const onKey = (e) => {
      const tr = e.target.closest ? e.target.closest(w.o.selector) : null;
      if (!tr || e.target !== tr || tr.dataset.pick == null) return;  // a field in a row keeps its keys
      if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); take(tr); }
      else if (e.key === 'Escape' && w.o.panel.picked && w.o.panel.picked.key === tr.dataset.pick) { e.preventDefault(); w.o.panel._unpickFocus(); }
    };
    root.addEventListener('click', onClick);
    root.addEventListener('keydown', onKey);
    const off = () => {
      root.removeEventListener('click', onClick); root.removeEventListener('keydown', onKey);
      w.o.panel._roots.delete(entry); wired.delete(root);
    };
    w = { o, off, entry };
    wired.set(root, w);
    o.panel._roots.add(entry);
    o.panel._mark();
    return off;
  }

  window.LiminalSide = {
    panel, rows, fromRow, html,
    standard: {
      get rules() { return rules; }, ready, FALLBACK,
      after: (app, state, group, value, given) => after(app, state, group, value, given),  // given: other rules (a check)
      problems: (app, state, given) => problems(app, state, given),
      groups: (app, given) => groupsOf(app, given),
    },
  };
})();
