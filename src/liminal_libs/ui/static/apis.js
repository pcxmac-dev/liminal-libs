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
(function () {
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const safeUrl = (u) => (/^https:\/\/[^\s"'<>]+$/i.test(String(u ?? '').trim()) ? String(u).trim() : '');
  const ORDER = ['docs', 'reference', 'guide', 'auth', 'limits', 'pricing', 'status', 'changelog', 'spec', 'console', 'tool',
    'sdk', 'source', 'terms'];
  const opened = new Set();  // the "more of the API" boxes opened (by key): opened again when the page is redrawn

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
      if (!(d instanceof HTMLElement) || !d.classList.contains('api-more') || !d.dataset.key) return;
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

  function areasHtml(api, key) {
    const areas = api.areas || [];
    if (!areas.length) return '';
    const used = areas.filter((a) => a.covered), rest = areas.filter((a) => !a.covered);
    const rowOf = (a) => `<tr class="${a.covered ? '' : 'api-unused'}"><td>${a.docs ? link(a.docs, a.name) : esc(a.name)}</td>`
      + `<td class="api-about-cell">${esc(a.about)}</td><td class="${a.covered ? 'api-here' : ''}">${esc(a.covered || '–')}</td></tr>`;
    const table = (rows) => `<div class="api-scroll"><table class="api-table"><thead><tr><th>Part</th><th class="api-about-cell">What it is</th>`
      + `<th>Here</th></tr></thead><tbody>${rows.map(rowOf).join('')}</tbody></table></div>`;
    const head = `<h4>Parts of the API: ${used.length} of ${areas.length} used here</h4>`;
    const more = rest.length ? more_(`${key}:areas`, `${rest.length} more part${rest.length === 1 ? '' : 's'} of the API, not used here`, table(rest)) : '';
    return `<div class="api-section">${head}${used.length ? table(used) : ''}${more}</div>`;
  }

  function callsHtml(api, key) {
    const calls = api.calls || [];
    if (!calls.length) return '';
    const used = calls.filter((c) => c.used), rest = calls.filter((c) => !c.used);
    const tags = (c) => (c.writes ? '<span class="api-tag">changes</span>' : '') + (c.costs ? '<span class="api-tag api-costs">costs</span>' : '');
    const rowOf = (c) => `<tr class="${c.used ? '' : 'api-unused'}"><td><code>${c.docs ? link(c.docs, c.name) : esc(c.name)}</code>${tags(c)}</td>`
      + `<td class="api-about-cell">${esc(c.about)}</td><td class="${c.used ? 'api-here' : ''}">${esc(c.used || '–')}</td></tr>`;
    const table = (rows) => `<div class="api-scroll"><table class="api-table"><thead><tr><th>Call</th><th class="api-about-cell">What it does</th>`
      + `<th>Here</th></tr></thead><tbody>${rows.map(rowOf).join('')}</tbody></table></div>`;
    const head = `<h4>Calls: ${used.length} of ${calls.length} made here</h4>`;
    const more = rest.length ? more_(`${key}:calls`, `${rest.length} more call${rest.length === 1 ? '' : 's'} the API offers`, table(rest)) : '';
    return `<div class="api-section">${head}${used.length ? table(used) : ''}${more}</div>`;
  }

  function more_(key, words, body) {
    return `<details class="api-more" data-key="${esc(key)}"${opened.has(key) ? ' open' : ''}><summary>${esc(words)}</summary>${body}</details>`;
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
  // older plugin API).
  function html(apis, facts, opts = {}) {
    style();
    const list = Array.isArray(apis) ? apis : [];
    if (!list.length) return opts.empty ? `<div class="api-none">${esc(opts.empty)}</div>` : '';
    const title = opts.title || (list.length > 1 ? 'The APIs it attaches to' : 'The API it attaches to');
    return `<section class="api-cards"><h3>${esc(title)}</h3>`
      + list.map((a) => card(a, (facts || {})[a.name], opts.owner || '')).join('') + '</section>';
  }

  window.LiminalApis = { html, card, style, safeUrl };
})();
