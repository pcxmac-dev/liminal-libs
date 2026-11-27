// The Internal API tab, drawn alike on every app's page (liminal-libs 1.63.0; internal.py builds what it draws). The
// user, 2026-11-16: "Also, for all apps, and all plugins, there should be an external api tab, and an internal api
// tab, the internal api is for interfaces the plugin shares with the rest of the app, the external should be all the
// SDKs/APIs the plugin associates with"; 2026-11-17: "also, i asked for a second tab for all plugins which describe
// the internal API like structure that the app code can work with", "all plugins are middleware", "even for other
// plugins", "and then the app object code".
//
// A plugin is middleware: under it the software it wraps (what its External API tab shows: apis.js), over it the
// other plugins and the app's object code, which reach that software only through it. So a plugin's tab leads with
// what kind of middleware it is (the library class it is built on, and so the standard interface it implements) and
// how it is called, then the standard hooks layer by layer, the nearest first (each answered by its own code, by a
// library class's, or left to the contract's default), then its own hooks; each hook with its call, its line, its
// whole docstring folded under it, whether it reads or changes, and who uses it (the app's code, other plugins, both,
// whoever asks it by name, or nothing here); a hook that only other plugins may ask, or only its page, says so (its
// PLUGIN_ONLY_HOOKS and PAGE_ONLY_HOOKS: internal.py's pluginOnly and pageOnly). Then what else the app's code takes
// from it, what it asks of other plugins, the settings it reads and keeps through the login, its steps and its notes.
// An app's own tab says what its code calls on its plugins and what it offers them, then its routes, what it includes
// and links, and its plugins.
//
//   LiminalInternal.html(d, opts)  ->  the tab's HTML. `d`: a plugin's `internal` (internal.internal_of), a list of
//     them (a plugin of several feeds: each a line that opens), an app's (`d.of === 'app'`: internal.app_internal), or
//     null. opts: {owner (keys what was opened), title, app (the app's title: "{app}'s code"), older (the words when
//     there is nothing to draw: a server from before), offers (the plugin API the app offers), seen (an address in the
//     page: '#connections'), pick ((name) => the attributes of a plugin's button in an app's list of its plugins),
//     judged (a plugin's needs as GET /api/needs judged them: each row's state and what was read, in its needs fold)}.
//   LiminalInternal.tabs(list, shown, label)  ->  a row of tabs for a page with none of its own (the charts', the
//     login's): [{id, title}], each a <button role="tab" data-api-tab="ID">; the page answers the click.
//   LiminalInternal.style()  ->  its styles, added to the page once (html and tabs add them).
//   LiminalInternal.KINDS  ->  the kinds a hook is counted by (internal.py's), in the order they are said.
//
// It asks nothing of any server: it draws what it is given, and given nothing it says so. Every word given goes through
// esc. What was opened or closed is kept across a redraw and in this browser (under its own key, 600 at most); its
// styles come with it, on the themes' variables, so a page without liminal.css or apis.js draws it alike.
(function () {
  'use strict';
  const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ESCAPES[c]);
  const STYLE_ID = 'liminal-internal-style';
  const FOLDS_KEY = 'liminal:internal:folds';
  const MOST = 600;  // what was opened or closed, kept in this browser: the latest so many
  const KINDS = Object.freeze(['read', 'tab', 'change', 'job', 'service', 'own']);
  const KIND_WORDS = { read: ['read', 'reads'], tab: ['tab page', 'tab pages'], change: ['change', 'changes'],
    job: ['job', 'jobs'], service: ['service for other plugins', 'services for other plugins'] };
  const KIND_NAMES = { machine: 'a machine plugin', feed: 'a feed plugin', publisher: 'a publisher plugin',
    assistant: 'an AI assistant plugin', database: 'a database plugin' };
  const CALL_WORDS = [['plugins', 'From another plugin', true], ['clients', 'From a client', true],
    ['jobs', 'As a job', true], ['terms', 'Its terms', false]];
  const WHO = { page: 'its page', client: 'a client', plugin: 'a plugin', app: 'another app', login: 'its login' };
  // what an ask of another plugin finds there that will not answer it (internal.py's `here`), drawn as a warning
  const WARN_HERE = /^no plugin offers|offers no |not installed|not said to be a service|only from its page/;
  // the attributes a page may ask for on a plugin's button (opts.pick): data-*, aria-* and title, each quoted
  const SAFE_ATTRS = /^\s*(?:(?:data|aria)-[\w-]+|title)="[^"<>]*"(?:\s+(?:(?:data|aria)-[\w-]+|title)="[^"<>]*")*\s*$/;

  // -- words -------------------------------------------------------------------------------------------------------
  const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
  const list = (v) => (Array.isArray(v) ? v : []);
  const str = (v) => typeof v === 'string' && v !== '';
  const text = (v) => (typeof v === 'string' ? v : typeof v === 'number' && Number.isFinite(v) ? String(v) : '');
  const names = (v) => list(v).filter(str);
  const rowsOf = (v) => list(v).filter(isObj);
  const count = (n, one, many) => String(n) + ' ' + (n === 1 ? one : many || one + 's');
  const and = (xs) => (xs.length < 2 ? xs.join('') : xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1]);
  const article = (w) => (/^[aeiou]/i.test(String(w)) ? 'an' : 'a');
  const squash = (s) => String(s || '').replace(/\s+/g, ' ').trim();
  const seconds = (v) => (Number.isFinite(Number(v)) && Number(v) > 0 ? String(Math.round(Number(v) * 10) / 10) : '');
  const errorWords = (e) => String((e && e.message) || e || 'an error').slice(0, 200);
  const kindWords = (kind, system) => (own(KIND_NAMES, kind) ? KIND_NAMES[kind]
    : str(kind) ? article(kind) + ' ' + kind + ' plugin' : 'a plugin') + (str(system) ? ' of the ' + system : '');
  const addressOf = (v) => (typeof v === 'string' && /^#[\w\-./:]*$/.test(v) ? v : '');
  const isLeft = (h) => h.answered === '';
  function jsonWords(v) {  // a declared value as its JSON, cut short
    let s = '';
    try { s = JSON.stringify(v); } catch (e) { s = ''; }
    s = s === undefined ? String(v) : s;
    return s.length > 120 ? s.slice(0, 119) + '…' : s;
  }

  // -- what was opened or closed, kept across a redraw and in this browser ------------------------------------------
  function readFolds() {
    const out = new Map();
    let kept = null;
    try { kept = JSON.parse(localStorage.getItem(FOLDS_KEY) || '{}'); } catch (e) { kept = null; }
    if (isObj(kept)) Object.entries(kept).forEach(([k, v]) => { if (typeof v === 'boolean') out.set(k, v); });
    return out;
  }
  function keepFolds() {
    const last = Object.fromEntries([...folds].slice(-MOST));
    try { localStorage.setItem(FOLDS_KEY, JSON.stringify(last)); } catch (e) { /* kept while the page lives */ }
  }
  const folds = readFolds();
  const isOpen = (key, first) => (folds.has(key) ? folds.get(key) === true : !!first);

  // -- the pieces every part is drawn with -------------------------------------------------------------------------
  // one part that opens: its round (+), its head and a few words of what is inside; open at first when `first`
  function foldHtml(key, headHtml, gist, bodyHtml, first, cls) {
    const openHtml = isOpen(key, first) ? ' open' : '';
    const gistHtml = str(gist) ? `<span class="in-sum-gist">${esc(gist)}</span>` : '';
    return `<details class="in-fold${esc(cls ? ' ' + cls : '')}" data-in-key="${esc(key)}"`
      + ` data-in-first="${esc(first ? 1 : 0)}"${openHtml}><summary><span class="in-pm" aria-hidden="true"></span>`
      + `${headHtml}${gistHtml}</summary><div class="in-body">${bodyHtml}</div></details>`;
  }
  const titleHtml = (words) => `<span class="in-head">${esc(words)}</span>`;
  const pHtml = (words, cls) => (str(words) ? `<p class="in-p${esc(cls ? ' ' + cls : '')}">${esc(words)}</p>` : '');
  const codeHtml = (w) => (str(w) || typeof w === 'number' ? `<code>${esc(w)}</code>` : '');
  const subHtml = (head, innerHtml) => (innerHtml ? `<h5 class="in-h5">${esc(head)}</h5>${innerHtml}` : '');
  // facts: [term, the value's HTML]; a fact with no value is left out
  function factsHtml(rows) {
    const itemsHtml = rows.filter(([, valueHtml]) => valueHtml)
      .map(([term, valueHtml]) => `<dt>${esc(term)}</dt><dd>${valueHtml}</dd>`).join('');
    return itemsHtml ? `<dl class="in-facts">${itemsHtml}</dl>` : '';
  }
  // a table that scrolls sideways on a narrow page: its heads, and rows of its cells' HTML
  function tableHtml(heads, rows) {
    if (!rows.length) return '';
    const headsHtml = heads.map((h) => `<th>${esc(h)}</th>`).join('');
    const rowHtml = (cells) => '<tr>' + cells.map((cellHtml) => `<td>${cellHtml}</td>`).join('') + '</tr>';
    const bodyHtml = rows.map(rowHtml).join('');
    return `<div class="in-scroll"><table class="in-table"><thead><tr>${headsHtml}</tr></thead>`
      + `<tbody>${bodyHtml}</tbody></table></div>`;
  }
  // methods and the like: {name, args, line}, each its call and its line
  function callsListHtml(rows) {
    const itemHtml = (m) => `<li class="in-hook"><div class="in-sig"><code class="in-call">`
      + `${esc(m.name + text(m.args))}</code></div>${pHtml(text(m.line), 'in-line')}</li>`;
    const itemsHtml = rowsOf(rows).filter((m) => str(m.name)).map(itemHtml).join('');
    return itemsHtml ? `<ul class="in-hooks">${itemsHtml}</ul>` : '';
  }
  // how the app's code, a client and another plugin call it (App.call_words): the calls as code, the terms in words
  function callWordsHtml(w) {
    const known = CALL_WORDS.map(([k]) => k);
    const rows = [...CALL_WORDS.filter(([k]) => str(w[k])),
      ...Object.keys(w).filter((k) => !known.includes(k) && str(w[k])).map((k) => [k, k, false])];
    return factsHtml(rows.map(([k, term, code]) => [term, code ? codeHtml(w[k]) : esc(w[k])]));
  }

  // -- a plugin ------------------------------------------------------------------------------------------------------
  // what every part of a plugin's tab is drawn with: its hooks by layer (the library class that names each), its own
  function contextOf(d, o) {
    const title = text(o.title) || text(d.title) || text(d.name) || 'this plugin';
    const c = { title, app: text(o.app) || 'the app', key: text(o.owner) || text(d.name) || title,
      rows: rowsOf(d.hooks).filter((h) => str(h.name)), tabs: rowsOf(d.tabs), pageAsks: new Set(names(d.pageAsks)),
      offers: text(o.offers) || text(d.offers), seen: addressOf(o.seen),
      clients: isObj(d.calls) && str(d.calls.clients) };  // a route of the app's own asks its hooks by name
    c.judged = isObj(o.judged) ? o.judged : null;  // its needs judged here (GET /api/needs' answer of it), if given
    c.layers = layersOf(c.rows);
    c.own = c.rows.filter((h) => !str(h.layer));
    return c;
  }
  // the standard hooks by the library class whose HOOKS adds them (each row's `layer`), as internal.py sends them: the
  // nearest class first, each class's hooks in the order its HOOKS names them
  function layersOf(rows) {
    const layers = new Map();
    rows.filter((h) => str(h.layer)).forEach((h) => {
      if (!layers.has(h.layer)) layers.set(h.layer, []);
      layers.get(h.layer).push(h);
    });
    return [...layers].map(([cls, mine]) => ({ class: cls, rows: mine }));
  }
  // its hooks counted, as internal.py counts them (`counts`): those it answers and those left to the contract, then
  // those it answers by kind
  function countsWords(d, c) {
    const n = isObj(d.counts) ? d.counts : {}, kinds = isObj(n.kinds) ? n.kinds : {};
    const byKind = KINDS.filter((k) => kinds[k] > 0).map((k) => (k === 'own'
      ? String(kinds[k]) + ' called by ' + c.app + "'s code" : count(kinds[k], ...KIND_WORDS[k])));
    const head = count(n.answered || 0, 'hook answered', 'hooks answered') + ', ' + String(n.left || 0)
      + ' left to the contract';
    return byKind.length ? head + ': ' + byKind.join(', ') : head;
  }

  // 1. what kind of middleware it is: the library class it is built on, the classes above that, its contract, its
  // hooks counted, and what it sits on (its External API tab), which by Liminal's rule the rest of the app reaches
  // through it (said as the rule: an app may reach some of it itself, as its own External API tab then says)
  function whatHtml(d, c) {
    const built = isObj(d.builtOn) ? d.builtOn : {};
    const chain = rowsOf(d.chain).filter((x) => str(x.class));
    const above = chain.length && chain[0].class === built.class ? chain.slice(1) : chain;
    const lineHtml = str(built.line) ? `<div>${esc(built.line)}</div>` : '';
    const builtHtml = str(built.class)
      ? `<code>${esc(built.class)}</code> <span class="in-muted">${esc(text(built.module))}</span>${lineHtml}` : '';
    const chainHtml = (x) => `<code title="${esc(squash(text(x.module) + ': ' + text(x.line)))}">`
      + `${esc(x.class)}</code>`;
    const aboveHtml = above.map(chainHtml).join(' &lt; ');
    const api = text(d.pluginApi);
    const contract = kindWords(d.kind, d.system) + (api ? ', written for plugin API ' + api : '')
      + (c.offers ? '; this app offers plugin API ' + c.offers : '');
    const sits = names(d.sitsOn);
    const sitsHtml = !Array.isArray(d.sitsOn) ? '' : sits.length
      ? pHtml('It sits on ' + and(sits) + ': its External API tab.')
        + pHtml("Liminal's rule: " + c.app + "'s code and its other plugins reach "
          + (sits.length === 1 ? 'it' : 'them') + ' through ' + c.title + ', never around it.')
      : pHtml('It declares no outside API or SDK of its own.', 'in-muted');
    const bodyHtml = factsHtml([['Built on', builtHtml], ['Above it', aboveHtml], ['Contract', esc(contract)],
      ['Hooks', esc(countsWords(d, c))]]) + sitsHtml;
    return foldHtml(c.key + ':what', titleHtml('What it is'), str(built.class) ? 'built on ' + built.class : '',
      bodyHtml, true);
  }
  // 1b. what it needs of this machine (1.103.0: its NEEDS rows as it declares them, internal.py's `needs`; with
  // opts.judged, liminal_libs.needs' answer of it, each row's state and what was read), open while a required one is
  // not met. A server from before says nothing of it: no fold.
  const NEED_STRENGTHS = { required: 'needs', part: 'for its parts', preferred: 'prefers' };
  const NEED_STATES = { met: 'met', unknown: 'not known here', na: 'not this system’s' };
  function needsHtml(d, c) {
    if (d.needs === undefined) return '';
    const head = titleHtml('What it needs of this machine');
    if (!Array.isArray(d.needs)) {
      return foldHtml(c.key + ':needs', head, 'not said', pHtml('It has not said what it needs yet.', 'in-muted'),
        false);
    }
    const rows = d.needs.filter((r) => Array.isArray(r) && r.length >= 2 && r.every(str));
    if (!rows.length) {
      return foldHtml(c.key + ':needs', head, 'nothing', pHtml('It needs nothing of this machine.'), false);
    }
    const judged = c.judged && Array.isArray(c.judged.rows) ? c.judged.rows.filter(isObj) : [];
    const judgedOf = (r) => judged.find((j) => j.attribute === r[0].toLowerCase() && text(j.value).toLowerCase()
      === r[1].toLowerCase()) || null;
    const unmet = judged.some((j) => j.strength === 'required' && j.state === 'unmet');
    const rowHtml = (r) => {
      const j = judgedOf(r);
      const state = !j ? '' : j.state === 'unmet' ? (j.sort === 'machine' ? 'not for this machine' : 'not met now')
        : (NEED_STATES[j.state] || '');
      const said = j && str(j.said) ? ': ' + j.said : '';
      return `<div class="in-hook"><code class="in-call">${esc(r[0])} ${esc(r[1])}</code>`
        + ` <span class="in-tag">${esc(NEED_STRENGTHS[r[2] || 'required'] || r[2])}</span>`
        + (state ? ` <span class="in-tag">${esc(state)}</span>` : '')
        + pHtml(text(r[3]), 'in-meta') + (said ? pHtml(state + said, 'in-meta') : '') + '</div>';
    };
    const gist = count(rows.length, 'row') + (unmet ? ', not met here' : '');
    return foldHtml(c.key + ':needs', head, gist, rows.map(rowHtml).join(''), unmet);
  }
  // 2. how it is called: by another plugin, by a client, as a job, and on what terms (the app's words)
  function howHtml(d, c) {
    const bodyHtml = callWordsHtml(isObj(d.calls) ? d.calls : {});
    if (!bodyHtml) return '';
    return foldHtml(c.key + ':calls', titleHtml('How it is called'), 'through ' + c.app, bodyHtml, true);
  }
  // 3. the standard interface of its kind: a fold for each library class of its line that adds hooks, the nearest
  // first and open
  function standardHtml(d, c) {
    if (!c.layers.length) return '';
    const built = isObj(d.builtOn) && str(d.builtOn.class) ? d.builtOn.class : c.layers[0].class;
    const whose = article(built) + ' ' + built + (/Plugin$/.test(built) ? '' : ' plugin');
    const lineOf = (cls) => { const x = rowsOf(d.chain).find((y) => y.class === cls); return x ? text(x.line) : ''; };
    const layerHtml = (l, i) => {
      const left = l.rows.filter(isLeft).length;
      const gist = count(l.rows.length, 'hook') + (left ? ', ' + String(left) + " left to the contract's default" : '');
      return foldHtml(c.key + ':layer:' + l.class, `<code class="in-head">${esc(l.class)}</code>`, gist,
        pHtml(lineOf(l.class), 'in-muted') + hooksHtml(l.rows, c, true), i === 0, 'in-layer');
    };
    const layersHtml = c.layers.map(layerHtml).join('');
    const lineHtml = pHtml('What every plugin built on it answers: each library class of its line, the nearest first.',
      'in-gist');
    return `<div class="in-std"><h4 class="in-h">${esc('The standard interface of ' + whose)}</h4>${lineHtml}</div>`
      + layersHtml;
  }
  // 4. its own hooks: what it adds to the standard interface
  function ownHtml(d, c) {
    const answeredAny = c.rows.some((h) => !isLeft(h));
    const bodyHtml = c.own.length ? hooksHtml(c.own, c, false)
      : pHtml(answeredAny ? 'None of its own: it answers the standard interface alone.'
        : "It answers no hook of its own: the contract's defaults answer for it.", 'in-muted');
    return foldHtml(c.key + ':own', titleHtml('Its own hooks'), c.own.length ? count(c.own.length, 'hook') : 'none',
      bodyHtml, true);
  }
  // 5. what else the app's code takes from it by name, outside its hooks: the calls, then the names it reads
  function alsoHtml(d, c) {
    const rows = rowsOf(d.also).filter((h) => str(h.name));
    const declares = isObj(d.declares) ? d.declares : {};
    const attrs = [...names(d.attributes), ...Object.keys(declares).filter((k) => !names(d.attributes).includes(k))];
    if (!rows.length && !attrs.length) return '';
    const itemHtml = (h) => {
      const call = h.name + (h.property ? '' : text(h.args));
      const propHtml = h.property ? '<span class="in-tag">a property</span>' : '';
      const used = 'used by ' + c.app + "'s code" + (str(h.how) ? ': ' + h.how : '');
      return `<li class="in-hook"><div class="in-sig"><code class="in-call">${esc(call)}</code>${propHtml}</div>`
        + `${pHtml(text(h.line), 'in-line')}<p class="in-meta"><span class="in-who">${esc(used)}</span></p>`
        + `${docHtml(h, c)}</li>`;
    };
    const itemsHtml = rows.map(itemHtml).join('');
    const listHtml = itemsHtml ? `<ul class="in-hooks">${itemsHtml}</ul>` : '';
    const attrHtml = (n) => codeHtml(own(declares, n) ? n + ' = ' + jsonWords(declares[n]) : n);
    const namesHtml = attrs.map(attrHtml).join(', ');
    const readsHtml = namesHtml ? `<p class="in-p">${esc(c.app + "'s code reads of it by name: ")}${namesHtml}</p>`
      : '';
    const gist = [rows.length ? count(rows.length, 'call') : '',
      attrs.length ? count(attrs.length, 'name') + ' read' : ''].filter(Boolean).join(', ');
    return foldHtml(c.key + ':also', titleHtml('What else ' + c.app + "'s code takes from it"), gist,
      listHtml + readsHtml, false);
  }
  // 6. what it asks of other plugins (its ASKS) and what each finds here (internal.py's `here`)
  function asksHtml(d, c) {
    const rows = rowsOf(d.asks).filter((a) => str(a.hook));
    const hereCls = (w) => (WARN_HERE.test(w) ? 'in-warn'
      : /^offered|^\d+ plugins? offers? it here/.test(w) ? 'in-ok' : 'in-muted');
    const cells = rows.map((a) => [
      str(a.plugin) ? codeHtml(a.plugin) : '<span class="in-muted">whichever answers it</span>', codeHtml(a.hook),
      esc(text(a.why)), `<span class="${esc(hereCls(text(a.here)))}">${esc(text(a.here) || '–')}</span>`]);
    const bodyHtml = rows.length ? tableHtml(['Plugin', 'Hook', 'Why', 'Here'], cells)
      : pHtml('It asks nothing of other plugins.', 'in-muted');
    return foldHtml(c.key + ':asks', titleHtml('What it asks of other plugins'),
      rows.length ? count(rows.length, 'ask') : 'nothing', bodyHtml, false);
  }
  // 7. the settings it reads through the login (its keys), what it keeps there beside them, and its options by name
  function settingsHtml(d, c) {
    const keys = rowsOf(d.settings).filter((k) => str(k.variable));
    const keeps = rowsOf(d.keeps).filter((k) => str(k.variable));
    const options = list(d.options).map((x) => (isObj(x) ? text(x.name) : text(x))).filter(Boolean);
    const pairHtml = (k) => (str(k.pair) ? codeHtml(k.pair) : '–');
    const keyCells = keys.map((k) => [codeHtml(k.variable), pairHtml(k), esc(text(k.label))
      + (k.secret ? ' <span class="in-tag">secret</span>' : '')
      + (str(k.hint) ? ` <span class="in-muted">${esc(k.hint)}</span>` : '')]);
    const keepCells = keeps.map((k) => [codeHtml(k.variable), pairHtml(k),
      esc(text(k.about)) + ' <span class="in-tag">kept by the plugin</span>']);
    const pairsHtml = tableHtml(['Variable', 'Pair', 'What'], [...keyCells, ...keepCells]);
    const optionNamesHtml = options.map(codeHtml).join(', ');
    const optionsHtml = optionNamesHtml ? `<p class="in-p">${esc('Its options, by name: ')}${optionNamesHtml}</p>` : '';
    const none = !keys.length && !keeps.length && !options.length;
    const gist = none ? 'none' : [keys.length ? count(keys.length, 'setting') : '',
      keeps.length ? String(keeps.length) + ' kept' : '', options.length ? count(options.length, 'option') : '']
      .filter(Boolean).join(', ');
    const bodyHtml = none ? pHtml('It reads and keeps nothing through the login.', 'in-muted')
      : pairsHtml + optionsHtml;
    return foldHtml(c.key + ':settings', titleHtml('Settings through the login'), gist, bodyHtml, false);
  }
  // 8. the steps it is set up in, its notes, and where what it says is seen as it happens
  function stepsHtml(d, c) {
    const steps = list(d.steps).map((x) => (isObj(x) ? text(x.name || x.id) : text(x))).filter(Boolean);
    if (!steps.length) return '';
    const itemsHtml = steps.map((s) => `<li><code>${esc(s)}</code></li>`).join('');
    return foldHtml(c.key + ':steps', titleHtml('Set up in steps'), count(steps.length, 'step'),
      `<ol class="in-steps">${itemsHtml}</ol>`, false);
  }
  function notesHtml(d) {
    const itemsHtml = names(d.notes).map((n) => `<p>${esc(n)}</p>`).join('');
    return itemsHtml ? `<div class="in-notes">${itemsHtml}</div>` : '';
  }
  function seenHtml(d, c) {
    if (!c.seen) return '';
    return `<p class="in-seen">${esc('What it says and to whom, as it happens: ')}`
      + `<a href="${esc(c.seen)}">Connections</a></p>`;
  }

  // -- a hook --------------------------------------------------------------------------------------------------------
  function hooksHtml(rows, c, standard) {
    const itemsHtml = rows.map((h) => hookHtml(h, c, standard)).join('');
    return itemsHtml ? `<ul class="in-hooks">${itemsHtml}</ul>` : '';
  }
  // its call, its tags, its line, then on one line who uses it and how it is answered, and its whole docstring
  // folded under it
  function hookHtml(h, c, standard) {
    const call = h.name + (h.property ? '' : text(h.args));
    const lineHtml = str(h.line) ? `<p class="in-line">${esc(h.line)}</p>`
      : '<p class="in-line in-muted">It says nothing of itself.</p>';
    const answered = standard || isLeft(h) ? answeredWords(h) : '';
    const answeredHtml = answered ? `<span class="in-answered">${esc(answered)}</span>` : '';
    const partsHtml = whoHtml(h, c) + answeredHtml;
    const metaHtml = partsHtml ? `<p class="in-meta">${partsHtml}</p>` : '';
    return `<li class="in-hook${esc(isLeft(h) ? ' in-left' : '')}"><div class="in-sig">`
      + `<code class="in-call">${esc(call)}</code>${tagsHtml(h, c)}</div>${lineHtml}${metaHtml}${docHtml(h, c)}</li>`;
  }
  // whether it reads or changes, a job (and whether it can be cancelled), a tab's page, asked twice, who alone may
  // ask it (other plugins, or its page), its page asks it, a property
  function tagsHtml(h, c) {
    const tags = [];
    if (h.reads === true) tags.push(['a read', 'in-read']);
    else if (h.reads === false) tags.push(['a change', '']);
    if (h.job) tags.push(['a job', '']);
    if (h.cancels) tags.push(['can be cancelled', '']);
    const tab = tabWords(h, c);
    if (tab) tags.push([tab, '']);
    const twice = names(h.twice);
    if (twice.length) tags.push(['asked twice: ' + twice.join(', '), 'in-twice']);
    if (h.pluginOnly === true) tags.push(['asked only by other plugins', 'in-only']);
    if (h.pageOnly === true) tags.push(['asked only from its page', 'in-only']);
    const audience = audienceTag(h);
    if (audience) tags.push(audience);
    if (c.pageAsks.has(h.name)) tags.push(['its page asks it', '']);
    if (h.property) tags.push(['a property', '']);
    return tags.map(([w, cls]) => `<span class="in-tag${esc(cls ? ' ' + cls : '')}">${esc(w)}</span>`).join('');
  }
  // who may ask a hook it answers (internal.py's `audience`, liminal-libs 1.107.0: closed by default), where neither
  // word above has said it: anyone here (a read it declares, a tab's page), other plugins and its page (a service),
  // its page alone because it declares the hook for no one, or its route alone. Nothing from an older library
  function audienceTag(h) {
    if (h.pluginOnly === true || h.pageOnly === true || !text(h.answered)) return null;
    switch (h.audience) {
      case 'read': return ['asked by anyone here', 'in-read'];
      case 'plugin': return ['asked by other plugins and its page', ''];
      case 'page': return h.declared === false ? ['asked only from its page: declared for no one', 'in-only'] : null;
      case 'route': return ['asked only through its route', ''];
      default: return null;
    }
  }
  // "tab World Wide Web, every 2 s" for a tab's hook
  function tabWords(h, c) {
    const t = c.tabs.find((x) => (str(h.tab) && x.id === h.tab) || x.hook === h.name);
    if (!t && !str(h.tab)) return '';
    const every = seconds(h.every != null ? h.every : t && t.every);
    return 'tab ' + (text(t && t.title) || text(h.tab)) + (every ? ', every ' + every + ' s' : '');
  }
  // who uses it (internal.py's `users`): the app's code, other plugins (those known here that ask it), both, whoever
  // asks it by name (its page and a client only where the app has a route asking a hook by name: its words' `clients`;
  // else another plugin, through the app's ask), or nothing here
  function whoHtml(h, c) {
    if (typeof h.users !== 'string') return '';
    const how = text(h.how), by = names(h.askedBy);
    // asked by name, yet only from its page (PAGE_ONLY_HOOKS): never another plugin, those that say they ask it too
    if (h.pageOnly === true && h.users === 'named') {
      const pageLines = ['asked by name: from its page alone, never by another plugin'];
      if (by.length) pageLines.push('other plugins here say they ask it, and are refused: ' + and(by));
      return pageLines.map((w) => `<span class="in-who">${esc(w)}</span>`).join('');
    }
    // closed by default (1.107.0): a hook it declares for no one is asked from its page alone all the same
    if (h.audience === 'page' && h.declared === false && h.users === 'named') {
      const closedLines = ['asked by name: from its page alone, as it declares the hook for no one'];
      if (by.length) closedLines.push('other plugins here say they ask it, and are refused: ' + and(by));
      return closedLines.map((w) => `<span class="in-who">${esc(w)}</span>`).join('');
    }
    const app = 'used by ' + c.app + "'s code" + (how ? ': ' + how : '');
    const plugins = 'for other plugins: ' + (by.length ? and(by) : 'none known here');
    const named = c.clients ? 'asked by name: its page, a client or another plugin'
      : 'asked by name: another plugin, through ' + c.app + "'s ask";
    let lines;
    switch (h.users) {
      case 'both': lines = [app, plugins]; break;
      case 'plugins': lines = [plugins]; break;
      case 'app': lines = [app]; break;
      case 'named': lines = [named]; break;
      default: lines = ['not used here'];
    }
    if (by.length && h.users !== 'both' && h.users !== 'plugins') lines.push('asked by other plugins here: ' + and(by));
    return lines.map((w) => `<span class="in-who">${esc(w)}</span>`).join('');
  }
  function answeredWords(h) {
    if (h.answered === 'itself') return 'answered by its own code';
    if (h.answered === '') return "left to the contract's default";
    return str(h.answered) ? 'answered by ' + h.answered + "'s code" : '';
  }
  // the whole docstring, folded under the hook's line, when it says more than that line
  function docHtml(h, c) {
    const doc = text(h.doc).trim();
    if (!doc || squash(doc) === squash(h.line)) return '';
    return foldHtml(c.key + ':doc:' + h.name, '<span class="in-doc-head">The whole docstring</span>', '',
      `<pre class="in-pre">${esc(doc)}</pre>`, false, 'in-doc');
  }

  // the parts of a plugin's tab, in the order they are drawn
  const PLUGIN_PARTS = [whatHtml, needsHtml, howHtml, standardHtml, ownHtml, alsoHtml, asksHtml, settingsHtml,
    stepsHtml, notesHtml, seenHtml];
  // one part drawn; one that cannot be (a shape it does not know) is said in a line, and the others are drawn
  function partHtml(part, d, c) {
    try { return part(d, c); } catch (e) { return pHtml('A part could not be drawn: ' + errorWords(e), 'in-none'); }
  }
  const pluginBodyHtml = (d, c) => PLUGIN_PARTS.map((part) => partHtml(part, d, c)).join('');
  function pluginHtml(d, o) {
    const c = contextOf(d, o);
    return `<section class="in-api" aria-label="${esc(c.title + ': its Internal API')}">`
      + `<h3 class="in-title">${esc('What ' + c.title + ' shares with ' + c.app)}</h3>`
      + `${pluginBodyHtml(d, c)}</section>`;
  }
  // a plugin of several parts (a feed plugin's feeds): each a line that opens to what that part shares
  function manyHtml(items, o) {
    const parts = items.filter(isObj);
    if (parts.length === 1) return pluginHtml(parts[0], o);
    const title = text(o.title) || 'this plugin', app = text(o.app) || 'the app', key = text(o.owner) || title;
    const partFold = (p, i) => {
      const id = text(p.name) || String(i);
      const name = text(p.label) || text(p.title) || text(p.name) || 'part ' + String(i + 1);
      const c = contextOf(p, { ...o, owner: key + ':' + id, title: name });
      return foldHtml(key + ':part:' + id, titleHtml(name), countsWords(p, c), pluginBodyHtml(p, c), false, 'in-part');
    };
    const partsHtml = parts.map(partFold).join('');
    const gist = count(parts.length, 'part') + ', each a plugin of its own to ' + app
      + ': each opens to what it shares.';
    return `<section class="in-api in-many" aria-label="${esc(title + ': its Internal API')}">`
      + `<h3 class="in-title">${esc('What ' + title + ' shares with ' + app)}</h3>${pHtml(gist, 'in-gist')}`
      + `${partsHtml}</section>`;
  }

  // -- an app's own --------------------------------------------------------------------------------------------------
  // its facts: its API, address, port, the plugin API it offers, its login, its routes and plugins counted
  function appFactsHtml(d) {
    const routes = rowsOf(d.routes), ownRoutes = routes.filter((r) => r.own === true).length;
    const login = isObj(d.login) ? d.login : null;
    const loginHtml = login ? esc([text(login.kind), text(login.namespace)].filter(Boolean).join(', ')
      + (login.signedIn ? ': signed in' : ': not signed in')) : d.login === null ? esc('none') : '';
    const portHtml = text(d.port) ? esc(text(d.port)) + (str(d.portVar) ? esc(', or as ') + codeHtml(d.portVar)
      + esc(' sets it') : '') : '';
    return factsHtml([['API', esc(text(d.api))], ['Address', codeHtml(text(d.url))], ['Port', portHtml],
      ['Plugin API', str(d.pluginApi) ? esc('this app offers plugin API ' + d.pluginApi) : ''], ['Login', loginHtml],
      ['Routes', routes.length ? esc(String(routes.length) + ' (' + String(ownRoutes) + ' its own)') : ''],
      ['Plugins', Array.isArray(d.plugins) ? esc(pluginsWords(d)) : '']]);
  }
  // its plugins counted: those it knows, and how many of them are attached now (all, when it does not say)
  function pluginsWords(d) {
    const rows = rowsOf(d.plugins).filter((p) => str(p.name));
    const attached = rows.filter((p) => p.attached !== false).length;
    return !rows.length ? 'none' : attached === rows.length ? count(rows.length, 'attached', 'attached')
      : String(rows.length) + ', ' + String(attached) + ' attached';
  }
  // 1. what its code calls on its plugins, kind by kind (CALLS), what it reads of them by name (ATTRIBUTES), and how
  // it asks any other hook by name (its words)
  function appCallsHtml(d, c) {
    const calls = isObj(d.calls) ? d.calls : {}, attrs = isObj(d.attributes) ? d.attributes : {};
    const words = isObj(d.words) ? d.words : {};
    const flat = Object.values(words).some((v) => typeof v === 'string');
    const kinds = [...new Set([...Object.keys(calls), ...Object.keys(attrs), ...(flat ? [] : Object.keys(words))])];
    const kindHtml = (k) => {
      const rows = isObj(calls[k]) ? Object.entries(calls[k]).filter(([n]) => str(n)) : [];
      const callsHtml = tableHtml(['Name', 'How'], rows.map(([n, how]) => [codeHtml(n), esc(text(how))]));
      const namesHtml = names(attrs[k]).map(codeHtml).join(', ');
      const readsHtml = namesHtml ? `<p class="in-p">${esc('It reads of it by name: ')}${namesHtml}</p>` : '';
      const w = flat ? {} : isObj(words[k]) ? words[k] : {};
      const anyHtml = str(w.plugins) || str(w.clients) ? pHtml('And any other hook by name:') : '';
      return subHtml('On ' + kindWords(k, ''), callsHtml + readsHtml + anyHtml + callWordsHtml(w));
    };
    const readsHtml = names(d.reads).map(codeHtml).join(', ');
    const kindsHtml = kinds.map(kindHtml).join('') + (flat ? subHtml('Any hook by name', callWordsHtml(words)) : '')
      + (readsHtml ? subHtml('Asked as reads, with no line in its log', `<p class="in-p">${readsHtml}</p>`) : '');
    if (!kindsHtml) return '';
    return foldHtml(c.key + ':calls', titleHtml('What ' + c.title + ' calls on its plugins'),
      kinds.length ? count(kinds.length, 'kind') + ' of plugin' : '', kindsHtml, true);
  }
  // 2. what it offers them: the app and a login lent at attach, its methods, the login's, and what code may call
  function appOffersHtml(d, c) {
    const lends = isObj(d.lends) ? d.lends : {};
    const tail = lends.traced === true ? ': one that notes, in Connections, each pair it reads or keeps.'
      : lends.traced === false ? ": the app's own, as it is." : '.';
    const attachHtml = esc('Attached, a plugin is given the app as ') + codeHtml('self.app') + esc(' and a login as ')
      + codeHtml('self.login') + esc(tail);
    const lent = 'The login it lends its plugins' + (str(lends.kind) ? ': ' + lends.kind : '');
    const bodyHtml = `<p class="in-p">${attachHtml}</p>`
      + subHtml('What a plugin or another app may call on it', callsListHtml(d.methods))
      + subHtml(lent, callsListHtml(lends.interface))
      + subHtml('For code in its process', callsListHtml(d.offers));
    return foldHtml(c.key + ':offers', titleHtml('What it offers them'), '', bodyHtml, true);
  }
  // 3. its routes, each with what it does, its class (traffic's word) and whom it is for
  function appRoutesHtml(d, c) {
    const routes = rowsOf(d.routes).filter((r) => str(r.path));
    if (!routes.length) return '';
    const ownRoutes = routes.filter((r) => r.own === true).length;
    const cells = routes.map((r) => [esc(text(r.method) || 'any'),
      codeHtml(r.path) + (r.own === false ? ' <span class="in-tag">the frame\'s</span>' : ''), esc(text(r.about)),
      esc(text(r.kind)), esc(own(WHO, r.who) ? WHO[r.who] : text(r.who))]);
    return foldHtml(c.key + ':routes', titleHtml('Routes: ' + String(routes.length) + ' (' + String(ownRoutes)
      + ' its own)'), '', tableHtml(['Method', 'Path', 'What', 'Class', 'For'], cells), false);
  }
  function appIncludesHtml(d, c) {
    const rows = rowsOf(d.includes).filter((r) => str(r.name));
    if (!rows.length) return '';
    const cells = rows.map((r) => [codeHtml(r.name), esc(r.on === false ? 'off' : 'on'),
      str(r.prefix) ? codeHtml(r.prefix) : '–', str(r.variable) ? codeHtml(r.variable) : '–', esc(text(r.how))]);
    return foldHtml(c.key + ':includes', titleHtml('What it includes'), count(rows.length, 'object'),
      tableHtml(['Name', 'Now', 'Under', 'Switched by', 'How'], cells), false);
  }
  function appLinksHtml(d, c) {
    const rows = rowsOf(d.linked).filter((r) => str(r.name));
    if (!rows.length) return '';
    const cells = rows.map((r) => [codeHtml(r.name), esc(text(r.how)), str(r.variable) ? codeHtml(r.variable) : '–',
      str(r.prefix) ? codeHtml(r.prefix) : '–']);
    return foldHtml(c.key + ':links', titleHtml('The apps it links'), count(rows.length, 'app'),
      tableHtml(['Name', 'How', 'Its address from', 'Under'], cells), false);
  }
  // its plugins (those it knows: attached or not), each with the class it is built on; a button when the page opens
  // one (opts.pick)
  function appPluginsHtml(d, c) {
    if (!Array.isArray(d.plugins)) return '';
    const rows = rowsOf(d.plugins).filter((p) => str(p.name));
    const itemHtml = (p) => {
      const built = isObj(p.builtOn) ? text(p.builtOn.class) : text(p.builtOn);
      const sub = [kindWords(p.kind, p.system), built ? 'built on ' + built : '',
        str(p.pluginApi) ? 'written for plugin API ' + p.pluginApi : ''].filter(Boolean).join(' · ');
      const offHtml = p.attached === false ? '<span class="in-tag">not attached</span>' : '';
      const innerHtml = `<span class="in-head">${esc(text(p.title) || p.name)}</span><code>${esc(p.name)}</code>`
        + `${offHtml}<span class="in-sub">${esc(sub)}</span>`;
      const attrsHtml = pickAttrs(c.pick, p.name);
      return attrsHtml ? `<button type="button" class="in-plugin" ${attrsHtml}>${innerHtml}</button>`
        : `<div class="in-plugin">${innerHtml}</div>`;
    };
    const itemsHtml = rows.map(itemHtml).join('');
    return foldHtml(c.key + ':plugins', titleHtml('Its plugins'), pluginsWords(d),
      itemsHtml || pHtml('It knows no plugin now.', 'in-muted'), false);
  }
  function pickAttrs(pick, name) {
    if (typeof pick !== 'function') return '';
    let out = '';
    try { out = String(pick(name) ?? ''); } catch (e) { out = ''; }
    return SAFE_ATTRS.test(out) ? out.trim() : '';
  }
  // the parts of an app's tab, in the order they are drawn
  const APP_PARTS = [appFactsHtml, appCallsHtml, appOffersHtml, appRoutesHtml, appIncludesHtml, appLinksHtml,
    appPluginsHtml, notesHtml, seenHtml];
  function appHtml(d, o) {
    const title = text(o.title) || text(d.title) || text(d.name) || 'this app';
    const c = { title, key: text(o.owner) || 'app:' + (text(d.name) || title), pick: o.pick, seen: addressOf(o.seen) };
    const partsHtml = APP_PARTS.map((part) => partHtml(part, d, c)).join('');
    return `<section class="in-api in-app" aria-label="${esc(title + ': its Internal API')}">`
      + `<h3 class="in-title">${esc('What ' + title + ' shares with its plugins and other apps')}</h3>`
      + `${partsHtml}</section>`;
  }

  // -- what a page calls -------------------------------------------------------------------------------------------
  const noneHtml = (o) => `<div class="in-none">${esc(text(o.older) || 'Nothing to show.')}</div>`;
  const blank = (d) => !str(d.name) && !str(d.title) && !list(d.hooks).length && !isObj(d.builtOn);
  function html(d, opts) {
    style();
    const o = isObj(opts) ? opts : {};
    try {
      if (Array.isArray(d)) return d.some(isObj) ? manyHtml(d, o) : noneHtml(o);
      if (!isObj(d) || blank(d)) return noneHtml(o);
      return d.of === 'app' ? appHtml(d, o) : pluginHtml(d, o);
    } catch (e) {
      return `<div class="in-none">${esc('The Internal API could not be drawn: ' + errorWords(e))}</div>`;
    }
  }
  // a row of tabs for a page with none of its own: the one shown is `shown` (else the first)
  function tabs(items, shown, label) {
    style();
    const all = rowsOf(items).filter((t) => str(t.id));
    if (!all.length) return '';
    const on = all.some((t) => t.id === shown) ? shown : all[0].id;
    const buttonHtml = (t) => `<button type="button" role="tab" class="in-tab" data-api-tab="${esc(t.id)}"`
      + ` aria-selected="${esc(t.id === on)}" tabindex="${esc(t.id === on ? 0 : -1)}">`
      + `${esc(text(t.title) || t.id)}</button>`;
    const buttonsHtml = all.map(buttonHtml).join('');
    return `<nav class="in-tabs" role="tablist" aria-label="${esc(text(label) || 'Its pages')}">${buttonsHtml}</nav>`;
  }

  // -- its look, and the two things it listens to -------------------------------------------------------------------
  const STYLE = `
.in-api{margin-top:12px;display:flex;flex-direction:column;gap:8px;min-width:0;color:var(--text);line-height:1.45}
.in-api h3.in-title{margin:0;font-size:12px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);
  font-weight:600}
.in-api .in-gist{margin:0;color:var(--muted);font-size:12px}
.in-api .in-muted{color:var(--muted)}
.in-api code{font-family:ui-monospace,Consolas,"Cascadia Mono",monospace;font-size:11.5px;overflow-wrap:anywhere}
.in-fold{border:1px solid var(--border);border-radius:8px;background:var(--card,var(--panel));min-width:0}
.in-fold>summary{list-style:none;cursor:pointer;display:flex;flex-wrap:wrap;align-items:center;gap:4px 10px;
  padding:8px 12px;border-radius:7px}
.in-fold>summary::-webkit-details-marker{display:none}
.in-fold>summary:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
@media (hover:hover){.in-fold>summary:hover{background:var(--hover)}}
.in-pm{flex:none;display:inline-grid;place-items:center;width:20px;height:20px;box-sizing:border-box;border-radius:50%;
  border:1px solid var(--muted);color:var(--muted);font-size:14px;line-height:1}
.in-pm::before{content:'+'}
.in-fold[open]>summary>.in-pm{border-color:var(--accent);color:var(--accent)}
.in-fold[open]>summary>.in-pm::before{content:'−'}
.in-api .in-head{font-weight:600;font-size:13px;color:var(--text)}
.in-sum-gist{margin-left:auto;color:var(--muted);font-size:12px}
.in-body{padding:0 14px 12px;min-width:0}
.in-body>.in-fold{margin-top:8px}
.in-api h4.in-h{margin:6px 0 0;font-size:12px;font-weight:600;color:var(--muted);letter-spacing:0;text-transform:none}
.in-api h5.in-h5{margin:12px 0 4px;font-size:12px;font-weight:600;color:var(--muted)}
.in-api .in-p{margin:6px 0 0}
.in-facts{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:3px 14px;margin:2px 0 0;font-size:12px}
.in-facts dt{color:var(--muted)}
.in-facts dd{margin:0;min-width:0;overflow-wrap:anywhere}
.in-hooks{list-style:none;margin:2px 0 0;padding:0}
.in-hook{padding:7px 0;border-top:1px solid var(--border);min-width:0}
.in-hook:first-child{border-top:0}
.in-sig{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 6px}
.in-api code.in-call{font-size:12px;font-weight:600;color:var(--text)}
.in-api .in-left code.in-call{font-weight:400;color:var(--muted)}
.in-api .in-line{margin:3px 0 0}
.in-api .in-meta{margin:2px 0 0;font-size:12px;color:var(--muted)}
.in-meta>span+span::before{content:' · '}
.in-std .in-h+.in-p{margin:2px 0 0}
.in-tag{display:inline-block;font-size:10px;line-height:15px;padding:0 6px;border-radius:8px;
  border:1px solid var(--border);color:var(--muted);white-space:nowrap}
.in-tag.in-read{border-color:var(--up);color:var(--up)}
.in-tag.in-twice{border-color:var(--down);color:var(--down)}
.in-tag.in-only{border-color:var(--accent);color:var(--accent)}
details.in-doc{border:0;border-radius:0;background:none;margin-top:2px}
details.in-doc>summary{padding:2px 0;gap:6px;font-size:12px;color:var(--accent)}
details.in-doc>summary>.in-pm{width:16px;height:16px;font-size:12px}
details.in-doc>.in-body{padding:2px 0 0}
.in-pre{margin:0;padding:8px 10px;border-radius:6px;background:var(--panel);color:var(--text);white-space:pre-wrap;
  overflow-wrap:anywhere;font:12px/1.45 ui-monospace,Consolas,"Cascadia Mono",monospace}
.in-scroll{overflow-x:auto;max-width:100%}
.in-table{width:100%;border-collapse:collapse;font-size:12px}
.in-table th{text-align:left;color:var(--muted);font-weight:500;padding:3px 8px 3px 0;
  border-bottom:1px solid var(--border);white-space:nowrap}
.in-table td{padding:4px 8px 4px 0;border-bottom:1px solid var(--border);vertical-align:top;color:var(--text)}
.in-api .in-ok{color:var(--up)}
.in-api .in-warn{color:var(--down)}
.in-steps{margin:4px 0 0;padding-left:22px}
.in-notes p{margin:4px 0 0;color:var(--muted);font-size:12px}
.in-seen{margin:0;font-size:12px;color:var(--muted)}
.in-seen a{color:var(--accent)}
.in-none{margin-top:12px;color:var(--muted);font-size:12px}
.in-plugin{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 10px;box-sizing:border-box;width:100%;margin:0;
  padding:6px 4px;border:0;border-top:1px solid var(--border);border-radius:0;background:none;color:inherit;
  font:inherit;text-align:left}
.in-plugin:first-child{border-top:0}
button.in-plugin{cursor:pointer}
@media (hover:hover){button.in-plugin:hover{background:var(--hover)}}
button.in-plugin:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.in-plugin .in-sub{color:var(--muted);font-size:12px}
.in-tabs{display:flex;flex-wrap:wrap;align-items:flex-end;gap:2px;margin:0 0 10px}
.in-tab{margin:0;padding:4px 12px;border:0;border-bottom:2px solid transparent;border-radius:6px 6px 0 0;
  background:none;color:var(--muted);font:inherit;font-size:13px;cursor:pointer}
.in-tab[aria-selected="true"]{color:var(--accent);border-bottom-color:var(--accent)}
@media (hover:hover){.in-tab:hover{color:var(--text);background:var(--hover)}}
.in-tab:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
@media (any-pointer:coarse){.in-fold>summary,.in-tab{min-height:40px;box-sizing:border-box}
  button.in-plugin{min-height:44px}}
@media (max-width:480px){.in-facts{grid-template-columns:minmax(0,1fr);gap:0}.in-facts dd{margin-bottom:6px}
  .in-body{padding:0 10px 10px}}
`;
  let listening = false;
  function style() {
    if (typeof document === 'undefined') return;
    if (!document.getElementById(STYLE_ID)) {
      const s = document.createElement('style');
      s.id = STYLE_ID;
      s.textContent = STYLE;
      (document.head || document.documentElement).appendChild(s);
    }
    if (listening) return;
    listening = true;
    document.addEventListener('toggle', toggled, true);
    document.addEventListener('keydown', keyed);
  }
  // a part opened or closed: kept; one drawn again as it was is not kept again
  function toggled(e) {
    const el = e.target;
    if (!(el instanceof HTMLElement) || !el.classList.contains('in-fold') || !el.dataset.inKey) return;
    const key = el.dataset.inKey;
    if ((folds.has(key) ? folds.get(key) : el.dataset.inFirst === '1') === el.open) return;
    folds.delete(key);
    folds.set(key, el.open);
    while (folds.size > MOST) folds.delete(folds.keys().next().value);
    keepFolds();
  }
  // the arrow keys, Home and End move along a row of tabs (tabs()), each tab taken as it is reached
  function keyed(e) {
    const t = e.target;
    if (!(t instanceof HTMLElement) || !t.classList.contains('in-tab') || !t.parentElement) return;
    const all = [...t.parentElement.querySelectorAll('.in-tab')];
    const at = all.indexOf(t);
    const to = { ArrowRight: at + 1, ArrowLeft: at - 1, Home: 0, End: all.length - 1 }[e.key];
    if (typeof to !== 'number' || at < 0) return;
    e.preventDefault();
    const next = all[(to + all.length) % all.length], id = next.dataset.apiTab || '';
    next.focus();
    next.click();
    setTimeout(() => {  // the page may draw its tabs again on the click: the tab taken keeps the focus
      if (next.isConnected || typeof CSS === 'undefined' || !CSS.escape) return;
      const again = document.querySelector('.in-tab[data-api-tab="' + CSS.escape(id) + '"]');
      if (again) again.focus();
    }, 0);
  }

  window.LiminalInternal = { html, tabs, style, KINDS };
})();
