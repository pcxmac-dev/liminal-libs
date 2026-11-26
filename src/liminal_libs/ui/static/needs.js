// What a plugin needs of this machine, drawn alike on every app's page (liminal-libs 1.103.0; liminal_libs.needs
// judges, the app's GET /api/needs gives each plugin's answer). The user, 2026-11-18: a plugin whose needs this machine
// cannot meet is not shown in the left-most list, and the Connections view gets a tab of all of the app's plugins, red
// for those that could but do not meet current conditions, shaded for those that never can here.
//
//   LiminalNeeds.table(answer, opts)  ->  a plugin's needs as a table: each row's strength, what it needs and its own
//     words, its state (met, not met now, not for this machine, not known here, not this system's), what was read
//     (`said`) and, for an unmet one, what would meet it (`how`). opts: {unmetOnly}.
//   LiminalNeeds.line(answer)  ->  one line of words for it: "Not for this machine: ...", "Not met now: ...", "Every
//     need met", "It needs nothing of this machine", "It has not said what it needs yet".
//   LiminalNeeds.row(r)  ->  one row of an answer, as the table draws it.
//   LiminalNeeds.style(answer)  ->  the class a plugin's row takes: nd-cannot (shaded: nothing can meet it here),
//     nd-now (red, its words saying so: never colour alone), nd-met, nd-unknown; and its styles added to the page once.
//
// It asks nothing of any server: it draws what it is given. Every word given goes through esc. Its styles are on the
// themes' variables, and a hover rule only under (hover: hover), so a touch screen shows no stuck hover.
(function () {
  'use strict';
  const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ESCAPES[c]);
  const STYLE_ID = 'liminal-needs-style';
  const NOT_SAID = 'It has not said what it needs yet';
  const NOTHING = 'It needs nothing of this machine';
  const CANNOT = 'Not for this machine';
  const NOW = 'Not met now';
  const UNKNOWN = 'not known here';
  const STATE_WORDS = { met: 'met', unmet: '', unknown: UNKNOWN, na: 'not this system’s' };
  const MARKS = { met: '✓', unmet: '✗', unknown: '?', na: '–' };
  const STRENGTH_WORDS = { required: 'needs', part: 'for its parts', preferred: 'prefers' };
  const CSS = `
.nd-table{width:100%;border-collapse:collapse;font-size:12px;color:var(--text);table-layout:fixed}
.nd-table th{text-align:left;font-weight:600;color:var(--muted);padding:4px 6px;border-bottom:1px solid var(--border)}
.nd-table td{padding:5px 6px;border-top:1px solid var(--border);vertical-align:top;overflow-wrap:anywhere}
.nd-table td.nd-mark{width:1.5em;text-align:center}
.nd-cannot{opacity:.45}
.nd-now{border-left:3px solid var(--down)}
.nd-now .nd-state,.nd-now.nd-line{color:var(--down)}
.nd-met .nd-mark{color:var(--up)}
.nd-unknown .nd-mark,.nd-unknown .nd-state{color:var(--muted)}
.nd-how{color:var(--muted)}
.nd-line{margin:0;font-size:12px}
.nd-line.nd-now{padding-left:6px}
@media (hover:hover){.nd-table tbody tr:hover{background:var(--hover)}}
@media (max-width:700px){.nd-table td.nd-said,.nd-table th.nd-said{display:none}}
`;

  const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
  const rows = (answer) => (isObj(answer) && Array.isArray(answer.rows) ? answer.rows.filter(isObj) : []);

  function addStyle() {
    if (typeof document === 'undefined' || document.getElementById(STYLE_ID)) return;
    const el = document.createElement('style');
    el.id = STYLE_ID;
    el.textContent = CSS;
    (document.head || document.documentElement).appendChild(el);
  }

  function style(answer) {
    addStyle();
    if (!isObj(answer)) return 'nd-unknown';
    if (answer.met === false) return answer.sort === 'machine' ? 'nd-cannot' : 'nd-now';
    if (answer.met === true) return 'nd-met';
    return 'nd-unknown';
  }

  function rowClass(r) {
    if (r.state === 'unmet') return r.sort === 'machine' ? 'nd-cannot' : 'nd-now';
    if (r.state === 'met') return 'nd-met';
    return 'nd-unknown';
  }

  function stateWords(r) {
    if (r.state === 'unmet') return r.sort === 'machine' ? CANNOT : NOW;
    return STATE_WORDS[r.state] || UNKNOWN;
  }

  function line(answer) {
    if (!isObj(answer)) return `<p class="nd-line nd-unknown">${esc(NOT_SAID)}</p>`;
    const cls = style(answer);
    if (answer.declared === false && !rows(answer).length) return `<p class="nd-line nd-unknown">${esc(NOT_SAID)}</p>`;
    if (answer.met === false) {
      const head = answer.sort === 'machine' ? CANNOT : NOW;
      return `<p class="nd-line ${cls}">${esc(head)}: ${esc(answer.why || '')}</p>`;
    }
    if (answer.met === true) {
      const words = rows(answer).length ? 'Every need met' : NOTHING;
      return `<p class="nd-line ${cls}">${esc(words)}</p>`;
    }
    return `<p class="nd-line ${cls}">${esc('Some of its needs are ' + UNKNOWN)}</p>`;
  }

  function row(r) {
    if (!isObj(r)) return '';
    const what = r.attribute ? [r.attribute, r.value || ''].join(' ').trim() : 'its own check';
    const how = r.state === 'unmet' && r.how ? `<div class="nd-how">${esc(r.how)}</div>` : '';
    return `<tr class="${rowClass(r)}"><td class="nd-mark" aria-hidden="true">${esc(MARKS[r.state] || '?')}</td>`
      + `<td>${esc(STRENGTH_WORDS[r.strength] || r.strength || '')}</td>`
      + `<td><code>${esc(what)}</code>${r.words ? `<div>${esc(r.words)}</div>` : ''}</td>`
      + `<td class="nd-state">${esc(stateWords(r))}${how}</td>`
      + `<td class="nd-said">${esc(r.said || '')}</td></tr>`;
  }

  function table(answer, opts) {
    addStyle();
    const o = isObj(opts) ? opts : {};
    let list = rows(answer);
    if (o.unmetOnly) list = list.filter((r) => r.state === 'unmet');
    if (!list.length) return line(answer);
    return `${line(answer)}<table class="nd-table"><thead><tr><th class="nd-mark"></th><th>Strength</th><th>What</th>`
      + `<th>State</th><th class="nd-said">Read here</th></tr></thead><tbody>${list.map(row).join('')}</tbody></table>`;
  }

  const api = Object.freeze({ table, line, row, style, NOT_SAID, NOTHING, CANNOT, NOW, UNKNOWN });
  if (typeof window !== 'undefined') window.LiminalNeeds = api;
})();
