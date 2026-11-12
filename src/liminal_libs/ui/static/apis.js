// The APIs a plugin attaches to, drawn on its page in every app (liminal-libs 1.49.0, plugin API 2.2: sources/apis.py).
// The user, 2026-11-11: "each plugin should reflect the the API its attached to, and present links that provide
// documentation, the plugin interface should more or less contain what it already has, BUT, it should also expose more
// of what the API is about".
//
//   LiminalApis.html(apis, facts, {title, empty})  ->  the cards' HTML: for each API its maker, form and version, the
//   maker's pages as links (each opening in a tab of its own), what the API is about, where it is reached, how a caller
//   proves who it is, its limits and what costs money, the day those facts were read, what the plugin learned of it
//   while it ran (`facts`: {api name: {label: words}}), then the API's parts and calls: the ones the plugin uses first,
//   the rest behind "more of the API" (kept open across a redraw once opened).
//
// The styles come with it (one <style> added to the page once, on the themes' variables), so a page that has not
// liminal.css (the charts app's) draws the cards alike.
//
// 1.50.0 (the user, 2026-11-11: "on the APIs organize each API description so that they can expand and contract so they
// take up less space, kind of like the firewall"): with {fold: true} each API is one line (its (+), its maker, name, form
// and version, how much of it is used here) that opens to its description, and inside it the parts and the calls are two
// more such lines. Closed at first, but a plugin's only API, which is open; what was opened or closed is kept across a
// redraw and in this browser. Without the option the cards are as they were (the charts app's Plugins view).
(function () {
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const safeUrl = (u) => (/^https:\/\/[^\s"'<>]+$/i.test(String(u ?? '').trim()) ? String(u).trim() : '');
  const ORDER = ['docs', 'reference', 'guide', 'auth', 'limits', 'pricing', 'status', 'changelog', 'spec', 'console', 'tool',
    'sdk', 'source', 'terms'];
  const opened = new Set();  // the "more of the API" boxes opened (by key): opened again when the page is redrawn
  // what was opened or closed of the folded cards (1.50.0), by key: an API's line, its parts, its calls; kept in this browser
  const FOLDS_KEY = 'liminal:apis:folds';
  const folds = (() => { try { return new Map(Object.entries(JSON.parse(localStorage.getItem(FOLDS_KEY) || '{}'))); } catch (e) { return new Map(); } })();
  const keepFolds = () => { try { localStorage.setItem(FOLDS_KEY, JSON.stringify(Object.fromEntries([...folds].slice(-600)))); } catch (e) { /* while the page lives */ } };
  const isOpen = (key, first) => (folds.has(key) ? folds.get(key) === true : first);

  const STYLE = `
.api-cards{margin-top:16px;display:flex;flex-direction:column;gap:12px;min-width:0}
.api-cards>h3{margin:0;font-size:12px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);font-weight:600}
.api-card{border:1px solid var(--border);border-radius:8px;padding:12px 14px;background:var(--card,var(--panel));min-width:0}
.api-head{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px 12px}
.api-title{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 8px;font-size:14px;min-width:0}
.api-title strong{color:var(--text)}
.api-maker{color:var(--muted)}
.api-chip{font-size:11px;padding:1px 7px;border:1px solid var(--border);border-radius:10px;color:var(--muted);white-space:nowrap}
.api-links{display:flex;flex-wrap:wrap;gap:6px}
.api-link{font-size:12px;padding:2px 9px;border-radius:12px;border:1px solid var(--border);color:var(--accent);text-decoration:none;white-space:nowrap}
.api-link:hover,.api-link:focus-visible{background:var(--hover);outline:none}
.api-about{margin:8px 0 6px;color:var(--text);line-height:1.45}
.api-facts{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:3px 14px;margin:6px 0 0;font-size:12px}
.api-facts dt{color:var(--muted)}
.api-facts dd{margin:0;overflow-wrap:anywhere;color:var(--text)}
.api-facts dd.api-costs{color:var(--down)}
.api-facts dt.api-live::before{content:'';display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--up);margin-right:6px;vertical-align:1px}
.api-section{margin-top:12px;min-width:0}
.api-section h4{margin:0 0 4px;font-size:12px;color:var(--muted);font-weight:600}
.api-scroll{overflow-x:auto;max-width:100%}
.api-table{width:100%;border-collapse:collapse;font-size:12px}
.api-table th{text-align:left;color:var(--muted);font-weight:500;padding:3px 8px 3px 0;border-bottom:1px solid var(--border);white-space:nowrap}
.api-table td{padding:4px 8px 4px 0;border-bottom:1px solid var(--border);vertical-align:top;color:var(--text)}
.api-table td.api-here{color:var(--up)}
.api-table tr.api-unused td{color:var(--muted)}
.api-table a{color:var(--accent);text-decoration:none}
.api-table a:hover,.api-table a:focus-visible{text-decoration:underline}
.api-tag{display:inline-block;font-size:10px;line-height:15px;padding:0 6px;border-radius:8px;border:1px solid var(--border);color:var(--muted);margin:0 0 0 4px;white-space:nowrap}
.api-tag.api-costs{border-color:var(--down);color:var(--down)}
.api-more{margin-top:4px}
.api-more>summary{cursor:pointer;color:var(--accent);font-size:12px;padding:3px 0}
.api-card code{font-family:ui-monospace,Consolas,"Cascadia Mono",monospace;font-size:11.5px;overflow-wrap:anywhere}
.api-none{color:var(--muted);font-size:12px;margin-top:12px}
.api-fold>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:6px 10px;border-radius:7px}
.api-fold>summary::-webkit-details-marker{display:none}
.api-fold>summary:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.api-pm{flex:none;display:inline-grid;place-items:center;width:20px;height:20px;border-radius:50%;border:1px solid var(--muted);color:var(--muted);font-size:14px;line-height:1}
.api-pm::before{content:'+'}
.api-fold[open]>summary>.api-pm{border-color:var(--accent);color:var(--accent)}
.api-fold[open]>summary>.api-pm::before{content:'−'}
details.api-card{padding:0}
details.api-card>summary{flex-wrap:wrap;padding:9px 12px}
@media (hover:hover){details.api-card>summary:hover{background:var(--hover)}}
.api-gist{color:var(--muted);font-size:12px;margin-left:auto}
.api-body{padding:0 14px 12px}
.api-body>.api-links{margin:2px 0 4px}
details.api-section>summary{padding:3px 0}
details.api-section>summary h4{margin:0}
details.api-section[open]>summary{margin-bottom:4px}
@media (max-width:700px){.api-table td.api-about-cell{display:none}.api-table th.api-about-cell{display:none}}
`;

  function style() {
    if (typeof document === 'undefined' || document.getElementById('liminal-apis-style')) return;
    const s = document.createElement('style');
    s.id = 'liminal-apis-style';
    s.textContent = STYLE;
    (document.head || document.documentElement).appendChild(s);
    document.addEventListener('toggle', (e) => {  // a "more of the API" box opened or closed: kept across redraws
      const d = e.target;
      if (!(d instanceof HTMLElement) || !d.dataset.key) return;
      if (d.classList.contains('api-fold')) {  // a folded line (1.50.0); one drawn again as it was is not kept again
        if (folds.get(d.dataset.key) !== d.open) { folds.set(d.dataset.key, d.open); keepFolds(); }
        return;
      }
      if (!d.classList.contains('api-more')) return;
      if (d.open) opened.add(d.dataset.key); else opened.delete(d.dataset.key);
    }, true);
  }

  function link(url, text, cls = '', title = '') {
    const u = safeUrl(url);
    if (!u) return esc(text);
    return `<a class="${esc(cls)}" href="${esc(u)}" target="_blank" rel="noopener noreferrer"${title ? ` title="${esc(title)}"` : ''}>${esc(text)}</a>`;
  }

  const host = (u) => { try { return new URL(u).host; } catch (e) { return ''; } };

  function linksHtml(api) {
    const links = (api.links || []).slice().sort((a, b) => {
      const x = ORDER.indexOf(a.kind), y = ORDER.indexOf(b.kind);
      return (x < 0 ? 99 : x) - (y < 0 ? 99 : y);
    });
    if (!links.length) return '';
    return `<nav class="api-links" aria-label="${esc(api.name)}: the maker's pages">`
      + links.map((l) => link(l.url, l.title || l.kindWords || l.kind, 'api-link', `${l.kindWords || l.kind}: ${host(l.url)}`)).join('')
      + '</nav>';
  }

  function factsHtml(api, live) {
    const rows = [];
    const row = (term, value, cls = '', dtCls = '') => {
      if (value === undefined || value === null || value === '') return;
      rows.push(`<dt class="${dtCls}">${esc(term)}</dt><dd class="${cls}">${value}</dd>`);
    };
    row('Reached at', api.base ? `<code>${esc(api.base)}</code>` : '');
    row('Version', esc(api.version));
    row('Who asks', esc(api.auth));
    row('Limits', esc(api.limits));
    row('Costs', esc(api.costs), 'api-costs');
    Object.entries(live || {}).forEach(([k, v]) => row(k, esc(v), '', 'api-live'));
    row('Checked', api.verified ? `${esc(api.verified)}, against the maker's pages` : '');
    return rows.length ? `<dl class="api-facts">${rows.join('')}</dl>` : '';
  }

  // a section as it was, or (fold) a line of its own that opens to it, closed at first
  function section(key, head, body, fold) {
    if (!fold) return `<div class="api-section"><h4>${esc(head)}</h4>${body}</div>`;
    return `<details class="api-section api-fold" data-key="${esc(key)}"${isOpen(key, false) ? ' open' : ''}>`
      + `<summary><span class="api-pm" aria-hidden="true"></span><h4>${esc(head)}</h4></summary>${body}</details>`;
  }

  function areasHtml(api, key, fold) {
    const areas = api.areas || [];
    if (!areas.length) return '';
    const used = areas.filter((a) => a.covered), rest = areas.filter((a) => !a.covered);
    const rowOf = (a) => `<tr class="${a.covered ? '' : 'api-unused'}"><td>${a.docs ? link(a.docs, a.name) : esc(a.name)}</td>`
      + `<td class="api-about-cell">${esc(a.about)}</td><td class="${a.covered ? 'api-here' : ''}">${esc(a.covered || '–')}</td></tr>`;
    const table = (rows) => `<div class="api-scroll"><table class="api-table"><thead><tr><th>Part</th><th class="api-about-cell">What it is</th>`
      + `<th>Here</th></tr></thead><tbody>${rows.map(rowOf).join('')}</tbody></table></div>`;
    const head = `Parts of the API: ${used.length} of ${areas.length} used here`;
    const more = rest.length ? more_(`${key}:areas`, `${rest.length} more part${rest.length === 1 ? '' : 's'} of the API, not used here`, table(rest)) : '';
    return section(`${key}:parts`, head, `${used.length ? table(used) : ''}${more}`, fold);
  }

  function callsHtml(api, key, fold) {
    const calls = api.calls || [];
    if (!calls.length) return '';
    const used = calls.filter((c) => c.used), rest = calls.filter((c) => !c.used);
    const tags = (c) => (c.writes ? '<span class="api-tag">changes</span>' : '') + (c.costs ? '<span class="api-tag api-costs">costs</span>' : '');
    const rowOf = (c) => `<tr class="${c.used ? '' : 'api-unused'}"><td><code>${c.docs ? link(c.docs, c.name) : esc(c.name)}</code>${tags(c)}</td>`
      + `<td class="api-about-cell">${esc(c.about)}</td><td class="${c.used ? 'api-here' : ''}">${esc(c.used || '–')}</td></tr>`;
    const table = (rows) => `<div class="api-scroll"><table class="api-table"><thead><tr><th>Call</th><th class="api-about-cell">What it does</th>`
      + `<th>Here</th></tr></thead><tbody>${rows.map(rowOf).join('')}</tbody></table></div>`;
    const head = `Calls: ${used.length} of ${calls.length} made here`;
    const more = rest.length ? more_(`${key}:calls`, `${rest.length} more call${rest.length === 1 ? '' : 's'} the API offers`, table(rest)) : '';
    return section(`${key}:made`, head, `${used.length ? table(used) : ''}${more}`, fold);
  }

  function more_(key, words, body) {
    return `<details class="api-more" data-key="${esc(key)}"${opened.has(key) ? ' open' : ''}><summary>${esc(words)}</summary>${body}</details>`;
  }

  // One API folded to a line (1.50.0): its (+), who makes it, its name, form and version, how much of it is used here;
  // opened: the maker's pages, what it is about, its facts, then its parts and its calls as two more such lines.
  // `first`: open or closed until the user says (a plugin's only API is open).
  function folded(api, live, owner = '', first = false) {
    if (!api) return '';
    const key = `${owner}:${api.name}`;
    const version = api.version ? `<span class="api-chip">${esc(api.version)}</span>` : '';
    const areas = api.areas || [], calls = api.calls || [];
    const gist = [areas.length ? `${areas.filter((a) => a.covered).length} of ${areas.length} parts` : '',
      calls.length ? `${calls.filter((c) => c.used).length} of ${calls.length} calls` : ''].filter(Boolean).join(', ');
    return `<details class="api-card api-fold" data-key="${esc(key)}:card"${isOpen(`${key}:card`, first) ? ' open' : ''}>`
      + `<summary><span class="api-pm" aria-hidden="true"></span><span class="api-title"><span class="api-maker">${esc(api.maker)}</span>`
      + `<strong>${esc(api.name)}</strong><span class="api-chip">${esc(api.kindWords || api.kind)}</span>${version}</span>`
      + (gist ? `<span class="api-gist">${esc(gist)} used here</span>` : '') + '</summary>'
      + `<div class="api-body">${linksHtml(api)}${api.about ? `<p class="api-about">${esc(api.about)}</p>` : ''}`
      + factsHtml(api, live) + areasHtml(api, key, true) + callsHtml(api, key, true) + '</div></details>';
  }

  // One API's card. `owner` keys its "more" boxes (the plugin's name), so two plugins' stay apart.
  function card(api, live, owner = '') {
    if (!api) return '';
    const key = `${owner}:${api.name}`;
    const version = api.version ? `<span class="api-chip">${esc(api.version)}</span>` : '';
    return `<article class="api-card" aria-label="${esc(api.name)}">`
      + `<header class="api-head"><div class="api-title"><span class="api-maker">${esc(api.maker)}</span>`
      + `<strong>${api.docs ? link(api.docs, api.name) : esc(api.name)}</strong><span class="api-chip">${esc(api.kindWords || api.kind)}</span>${version}</div>`
      + `${linksHtml(api)}</header>`
      + (api.about ? `<p class="api-about">${esc(api.about)}</p>` : '')
      + factsHtml(api, live)
      + areasHtml(api, key) + callsHtml(api, key)
      + '</article>';
  }

  // Every API of a plugin, under one heading; `opts.empty`: what to say when it declares none (a plugin written for an
  // older plugin API); `opts.fold` (1.50.0): each a line that opens, closed at first but a plugin's only one.
  function html(apis, facts, opts = {}) {
    style();
    const list = Array.isArray(apis) ? apis : [];
    if (!list.length) return opts.empty ? `<div class="api-none">${esc(opts.empty)}</div>` : '';
    const title = opts.title || (list.length > 1 ? 'The APIs it attaches to' : 'The API it attaches to');
    return `<section class="api-cards"><h3>${esc(title)}</h3>`
      + list.map((a) => (opts.fold ? folded(a, (facts || {})[a.name], opts.owner || '', list.length === 1)
        : card(a, (facts || {})[a.name], opts.owner || ''))).join('') + '</section>';
  }

  window.LiminalApis = { html, card, folded, style, safeUrl };
})();
