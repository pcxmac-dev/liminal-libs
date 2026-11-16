// Codebase: the repositories an app is made of, the code in them and how much of it is which language, drawn alike in
// every app (liminal-libs 1.59.0; apps/codebase.py answers it at GET /api/codebase). The user, 2026-11-16: "i want to
// add another functional class called codebase, which has the associated repositories (git/svn/,,,) if there are, also
// the code base, and stats like how much is rust %, javascript %, etc..."; "this class will be added to all the 'apps'
// just like connections"; "it will also say how far it is behind the remote".
//
//   LiminalCodebase.mount(dataEl, sideEl, {get, send, confirm})  ->  the page's two panes filled and kept current: asked
//   once, again every second only while a reading or an asking of the remotes is under way. `get(path)` and
//   `send(path, body)` are the page's own way to ask its app (a JSON answer, an Error when refused); `confirm(words)`
//   answers whether the user said yes (the remotes are asked only then). LiminalCodebase.unmount() when the view is left.
//   LiminalCodebase.html(d, view) and .side(d, view) give the two panes' HTML for a page that draws by itself.
//
// The shares are of the bytes of code and markup, as apps/codebase.py counts them; prose and data are listed with their
// lines and have no share. A language keeps its colour whatever its rank (the themes' --series-1..7, in a fixed order);
// what has no colour of its own, and any sliver under half a percent, is drawn together as "Other" and still named in
// the table beside the bar. The styles come with it (one <style>, on the themes' variables).
(function () {
  'use strict';
  const I = window.LiminalIcons || {};
  const esc = I.esc || ((s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));
  const num = (v) => Number(v || 0).toLocaleString();
  const ORDER = ['Python', 'JavaScript', 'Rust', 'CSS', 'HTML', 'TypeScript', 'Shell'];  // a language's colour, for good
  const colorOf = (name) => { const i = ORDER.indexOf(name); return i < 0 ? 'var(--muted)' : `var(--series-${i + 1})`; };
  const SLIVER = 0.5;  // percent: under it a language is drawn in "Other" (it is named in the table all the same)

  const STYLE = `
.cb-head{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:8px 16px}
.cb-head h2{margin:0}
.cb-tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.cb-line{color:var(--muted);font-size:12px;margin:4px 0 14px}
.cb-box{margin:0 0 20px;min-width:0}
.cb-box>h4{margin:0 0 6px;font-size:12px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);font-weight:600}
.cb-bar{display:flex;gap:2px;height:14px;border-radius:4px;overflow:hidden;background:var(--panel);min-width:0}
.cb-seg{min-width:2px;height:100%}
.cb-legend{display:flex;flex-wrap:wrap;gap:4px 16px;margin:8px 0 0;padding:0;list-style:none;font-size:12px;color:var(--text)}
.cb-legend li{display:flex;align-items:center;gap:6px;white-space:nowrap}
.cb-dot{width:10px;height:10px;border-radius:2px;flex:none}
.cb-legend .pct{color:var(--muted);font-variant-numeric:tabular-nums}
.cb-filters{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 8px}
.cb-filters button[aria-pressed="true"]{border-color:var(--accent);color:var(--text)}
.cb-table{overflow-x:auto;min-width:0}
.cb-table tr[data-cb-repo]{cursor:pointer}
.cb-table tr.picked td{background:var(--hover)}
.cb-table .sub{display:block;color:var(--muted);font-size:11px}
.cb-table td.words{color:var(--muted);font-size:12px}
.cb-behind{font-weight:600;color:var(--text)}
.cb-side dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:8px 0 16px;font-size:12px}
.cb-side dt{color:var(--muted)}
.cb-side dd{margin:0;min-width:0;overflow-wrap:anywhere}
`;
  function ensureStyle() {
    if (document.getElementById('liminal-codebase-style')) return;
    const s = document.createElement('style');
    s.id = 'liminal-codebase-style';
    s.textContent = STYLE;
    document.head.appendChild(s);
  }

  function ago(at) {  // a moment in unix seconds, as how long ago it was
    if (!at) return 'never';
    const s = Math.max(0, Date.now() / 1000 - at);
    if (s < 90) return 'just now';
    if (s < 5400) return `${Math.round(s / 60)} min ago`;
    if (s < 129600) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  }
  const clock = (at) => (at ? new Date(at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '');

  // -- the shares: one bar, its legend, and the table that says every language --------------------------------------
  function parts(languages) {  // the bar's segments: each language with a colour of its own, the rest together
    const counted = (languages || []).filter((l) => l.share !== null && l.share !== undefined);
    const own = counted.filter((l) => ORDER.includes(l.name) && l.share >= SLIVER);
    const rest = counted.filter((l) => !own.includes(l));
    const other = rest.reduce((a, l) => a + l.share, 0);
    const out = own.map((l) => ({ name: l.name, share: l.share, lines: l.lines, files: l.files, color: colorOf(l.name) }));
    if (rest.length) {
      out.push({ name: 'Other', share: other, lines: rest.reduce((a, l) => a + l.lines, 0),
        files: rest.reduce((a, l) => a + l.files, 0), color: 'var(--muted)', of: rest.map((l) => l.name).join(', ') });
    }
    return out;
  }
  // a share in words: one decimal; what is there and rounds to nothing is said to be under a tenth, not "0"
  const pct = (share) => (share > 0 && share < 0.05 ? '< 0.1 %' : `${Math.round(share * 10) / 10} %`);
  function bar(languages, what) {
    const segs = parts(languages);
    if (!segs.length) return '<p class="muted small">No code counted here.</p>';
    const words = segs.map((s) => `${s.name} ${pct(s.share)}`).join(', ');
    return `<div class="cb-bar" role="img" aria-label="${esc(`${what}: ${words}`)}">`
      + segs.map((s) => `<span class="cb-seg" style="flex:${Math.max(s.share, 0.01)} 1 0;background:${s.color}" title="${esc(`${s.name}${s.of ? ` (${s.of})` : ''}: ${pct(s.share)} · ${num(s.lines)} lines · ${num(s.files)} files`)}"></span>`).join('')
      + `</div><ul class="cb-legend">`
      + segs.map((s) => `<li${s.of ? ` title="${esc(s.of)}"` : ''}><span class="cb-dot" style="background:${s.color}"></span>${esc(s.name)} <span class="pct">${esc(pct(s.share))}</span></li>`).join('')
      + '</ul>';
  }
  function languageTable(languages) {
    const rows = languages || [];
    if (!rows.length) return '';
    return `<div class="cb-table"><table class="list" aria-label="Every language counted"><thead><tr><th scope="col">Language</th><th scope="col">Kind</th>`
      + `<th scope="col" class="num">Share</th><th scope="col" class="num">Lines</th><th scope="col" class="num">Files</th></tr></thead><tbody>`
      + rows.map((l) => `<tr><td><span class="cb-dot" style="display:inline-block;margin-right:6px;background:${l.share === null || l.share === undefined ? 'transparent' : colorOf(l.name)}"></span>${esc(l.name)}</td>`
        + `<td class="words">${esc(l.kind)}</td><td class="num">${l.share === null || l.share === undefined ? '' : `${l.share} %`}</td>`
        + `<td class="num">${num(l.lines)}</td><td class="num">${num(l.files)}</td></tr>`).join('')
      + '</tbody></table></div>';
  }

  // -- a repository's words -------------------------------------------------------------------------------------------
  function remoteWords(r) {  // how far it is from its remote, and as of when
    if (r.problem) return { words: r.problem, sub: '' };
    if (!r.kind) return { words: 'no repository', sub: '' };
    if (r.kind !== 'git') return { words: r.remote ? 'not asked here' : 'no remote', sub: r.remote ? `${r.tool || r.kind} asks its server only when told` : '' };
    if (!r.remote) return { words: 'no remote', sub: '' };
    if (!r.upstream) return { words: 'follows no branch there', sub: '' };
    const said = [r.behind ? `<span class="cb-behind">${num(r.behind)} behind</span>` : '', r.ahead ? `${num(r.ahead)} ahead` : ''].filter(Boolean).join(', ');
    return { html: said || 'up to date', sub: `asked ${ago(r.asked)}` };
  }
  function changeWords(r) {
    if (!r.kind) return '';
    const said = [r.changed ? `${num(r.changed)} changed` : '', r.untracked ? `${num(r.untracked)} new` : ''].filter(Boolean).join(', ');
    return said || 'clean';
  }
  const FILTERS = [['all', 'All', () => true], ['behind', 'Behind', (r) => !!r.behind], ['changed', 'Changed', (r) => !!(r.changed || r.untracked)],
    ['mine', 'This app', (r) => (r.used || []).length > 0]];

  function html(d, view) {
    ensureStyle();
    const v = view || {};
    const repos = (d && d.repositories) || [];
    const t = (d && d.totals) || {};
    const reading = !d || d.state === 'reading';
    const f = d && d.fetching;
    const asking = !!(f && !f.ended);
    const state = v.error ? `<span class="error">${esc(v.error)}</span>`
      : asking ? `asking the remotes: ${num(f.done)} of ${num(f.total)}`
        : reading ? `reading${d && d.progress && d.progress.total ? `: ${num(d.progress.done)} of ${num(d.progress.total)} repositories` : '…'}`
          : `${num(t.repositories)} repositories · ${num(t.files)} files · ${num(t.lines)} lines · read at ${esc(clock(d.at))}`;
    const failed = f && f.ended && (f.errors || []).length
      ? `<p class="muted small">Not every remote answered: ${f.errors.map((e) => `${esc(e.name)} (${esc(e.why)})`).join('; ')}</p>` : '';
    const head = `<div class="cb-head"><h2>Codebase</h2><span class="cb-tools">`
      + `<button type="button" class="small" data-cb="fresh"${reading || asking ? ' disabled' : ''}>Read again</button>`
      + `<button type="button" class="small" data-cb="fetch"${reading || asking ? ' disabled' : ''} title="git fetch in every repository that has a remote: what is behind is counted anew. Nothing checked out changes.">Ask the remotes</button>`
      + `</span></div><div class="cb-line" aria-live="polite">${state}</div>${d && d.problem ? `<p class="error">${esc(d.problem)}</p>` : ''}${failed}`;
    if (!repos.length) return head + (reading ? '' : '<p class="muted">No repository and no code of this app was found.</p>');
    const shown = FILTERS.find(([id]) => id === (v.filter || 'all')) || FILTERS[0];
    const kept = repos.filter(shown[2]);
    const filters = `<div class="cb-filters" role="group" aria-label="Which repositories are listed">`
      + FILTERS.map(([id, title, test]) => `<button type="button" class="small" data-cb-filter="${id}" aria-pressed="${id === shown[0]}">${title} ${num(repos.filter(test).length)}</button>`).join('')
      + '</div>';
    const rows = kept.map((r) => {
      const i = repos.indexOf(r);
      const far = remoteWords(r);
      return `<tr data-cb-repo="${i}" tabindex="0"${v.picked === i ? ' class="picked"' : ''}><td>${esc(r.name)}${(r.used || []).length ? `<span class="sub">${esc(r.used.join(', '))} runs from it</span>` : ''}</td>`
        + `<td class="words">${esc(r.kind || 'none')}</td><td>${esc(r.branch || (r.kind === 'git' && r.commit ? 'no branch' : ''))}</td>`
        + `<td>${esc(r.commit)}${r.when ? `<span class="sub">${esc(String(r.when).slice(0, 10))}</span>` : ''}</td>`
        + `<td>${far.html || esc(far.words)}${far.sub ? `<span class="sub">${esc(far.sub)}</span>` : ''}</td>`
        + `<td class="words">${esc(changeWords(r))}</td><td class="num">${num(r.lines)}</td></tr>`;
    }).join('');
    const table = `<div class="cb-table"><table class="list" aria-label="The repositories"><thead><tr><th scope="col">Repository</th><th scope="col">Kind</th>`
      + `<th scope="col">Branch</th><th scope="col">Commit</th><th scope="col">Its remote</th><th scope="col">Not committed</th><th scope="col" class="num">Lines</th></tr></thead>`
      + `<tbody>${rows || `<tr><td colspan="7" class="muted">None ${shown[0] === 'behind' ? 'is behind its remote' : shown[0] === 'changed' ? 'has changes that are not committed' : 'of them'}.</td></tr>`}</tbody></table></div>`;
    return head
      + `<section class="cb-box"><h4>By language, everything in the workspace</h4>${bar(d.languages, 'The workspace by language')}</section>`
      + (d.mine && (d.mine.languages || []).length ? `<section class="cb-box"><h4>By language, what this app runs from</h4>${bar(d.mine.languages, 'What this app runs from, by language')}</section>` : '')
      + `<section class="cb-box"><h4>Repositories</h4>${filters}${table}</section>`
      + `<section class="cb-box"><h4>Every language</h4>${languageTable(d.languages)}</section>`;
  }

  function side(d, view) {
    ensureStyle();
    const v = view || {};
    const repos = (d && d.repositories) || [];
    const r = repos[v.picked];
    const row = (k, val) => (val === '' || val === null || val === undefined ? '' : `<dt>${esc(k)}</dt><dd>${val}</dd>`);
    if (r) {
      const far = remoteWords(r);
      return `<div class="cb-side"><h3>${esc(r.name)}</h3><div class="muted small">${esc(r.kind ? `a ${r.tool || r.kind} working copy` : 'a folder in no repository')}</div><dl>`
        + row('Where', esc(r.path)) + row('Branch', esc(r.branch)) + row('Commit', esc([r.commit, String(r.when || '').slice(0, 16).replace('T', ' ')].filter(Boolean).join(' · ')))
        + row('Its words', esc(r.subject)) + row('Remote', esc(r.remote)) + row('Follows', esc(r.upstream))
        + row('From its remote', far.html || esc(far.words)) + (r.kind === 'git' && r.remote ? row('Last asked', esc(ago(r.asked))) : '')
        + row('Not committed', esc(changeWords(r))) + row('Runs here', esc((r.used || []).join(', ')))
        + row('Counted', `${num(r.files)} files, ${num(r.lines)} lines`) + `</dl><h4>Its languages</h4>${bar(r.languages, `${r.name} by language`)}`
        + `<p><button type="button" class="small" data-cb-repo="">All of it</button></p></div>`;
    }
    const t = (d && d.totals) || {}, left = (d && d.leftOut) || {}, mine = (d && d.mine) || {};
    const used = repos.filter((x) => (x.used || []).length);
    return `<div class="cb-side"><h3>Codebase</h3><div class="muted small">the repositories this software is made of, and their code</div><dl>`
      + row('Workspace', esc((d && d.workspace) || 'none: the code is where it was installed'))
      + row('Repositories', num(t.repositories)) + row('Behind their remote', num(t.behind)) + row('Ahead of it', num(t.ahead))
      + row('With changes', num(t.changed)) + row('Counted', t.files === undefined ? '' : `${num(t.files)} files, ${num(t.lines)} lines`)
      + row('This app runs from', used.length ? `${esc(used.map((x) => x.name).join(', '))} (${num(mine.lines)} lines)` : '')
      + `</dl><h4>Left out of the count</h4><dl>`
      + row('Vendored or generated', num(left.vendored)) + row('Binary', num(left.binary)) + row('Very large', num(left.large))
      + row('No language of the list', num(left.other)) + (left.unread ? row('Could not be read', num(left.unread)) : '')
      + `</dl><p class="muted small">How far behind is what each working copy knew when it last asked its remote. "Ask the remotes" asks them now.</p></div>`;
  }

  // -- a page's two panes kept current ----------------------------------------------------------------------------------
  let M = null;
  const getJson = async (path) => { const r = await fetch(path, { cache: 'no-store', credentials: 'same-origin' }); if (!r.ok) throw new Error(`the app answered ${r.status}`); return r.json(); };
  const sendJson = async (path, body) => {
    const r = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Liminal-Charts': '1' }, body: JSON.stringify(body || {}) });
    if (!r.ok) throw new Error(`the app answered ${r.status}`);
    return r.json();
  };
  function draw() {
    const m = M;
    if (!m) return;
    m.dataEl.innerHTML = html(m.d, m.view);
    if (m.sideEl) m.sideEl.innerHTML = side(m.d, m.view);
  }
  async function load(fresh) {
    const m = M;
    if (!m) return;
    try { m.d = await m.get(`/api/codebase${fresh ? '?fresh=1' : ''}`); m.view.error = ''; } catch (e) { m.view.error = (e && e.message) || String(e); }
    if (M !== m) return;
    draw();
    clearTimeout(m.timer);
    const busy = m.d && (m.d.state === 'reading' || (m.d.fetching && !m.d.fetching.ended));
    if (busy || m.view.error) m.timer = setTimeout(() => load(false), busy ? 1000 : 5000);
  }
  async function clicked(e) {
    const m = M;
    if (!m) return;
    const at = e.target.closest ? e.target : e.target.parentElement;
    const button = at.closest('[data-cb]'), filter = at.closest('[data-cb-filter]'), repo = at.closest('[data-cb-repo]');
    if (e.type === 'keydown' && !(repo && (e.key === 'Enter' || e.key === ' '))) return;
    if (button && button.dataset.cb === 'fresh') { load(true); return; }
    if (button && button.dataset.cb === 'fetch') {
      const yes = await m.confirm('Ask every remote what it has? git fetch runs in each repository that has a remote. Nothing checked out changes.');
      if (!yes || M !== m) return;
      try { await m.send('/api/codebase/fetch', {}); m.view.error = ''; } catch (err) { m.view.error = (err && err.message) || String(err); }
      load(false);
      return;
    }
    if (filter) { m.view.filter = filter.dataset.cbFilter; m.view.picked = undefined; draw(); return; }
    if (repo) {
      if (e.type === 'keydown') e.preventDefault();
      m.view.picked = repo.dataset.cbRepo === '' ? undefined : Number(repo.dataset.cbRepo);
      draw();
    }
  }
  function mount(dataEl, sideEl, opts) {
    unmount();
    const o = opts || {};
    M = { dataEl, sideEl, view: { filter: 'all' }, d: null, timer: 0, get: o.get || getJson, send: o.send || sendJson,
      confirm: o.confirm || ((words) => Promise.resolve(window.confirm(words))) };
    for (const el of [dataEl, sideEl]) {
      if (!el) continue;
      el.addEventListener('click', clicked);
      el.addEventListener('keydown', clicked);
    }
    draw();
    load(false);
  }
  function unmount() {
    const m = M;
    if (!m) return;
    clearTimeout(m.timer);
    for (const el of [m.dataEl, m.sideEl]) {
      if (!el) continue;
      el.removeEventListener('click', clicked);
      el.removeEventListener('keydown', clicked);
    }
    M = null;
  }

  window.LiminalCodebase = { html, side, mount, unmount, colorOf, parts };
})();
