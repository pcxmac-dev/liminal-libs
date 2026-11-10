// Touch screens and the on-screen keyboard on every app's page (liminal-libs ui/static, 1.42.0; the user, 2026-11-10:
// "let's do an update. I want to support touch as well as mouse clicking on the interface ... We'll make sure it works
// across all apps"; "Support for virtual keyboard on tablets and phones"). No dependencies. Load it right after
// theme.js, before the page's other scripts (menu.js and charts.js look for it):
//   <script src="theme.js"></script>
//   <script src="touch.js"></script>
// A mouse and a hardware keyboard work as they did: everything here answers a finger, a pen or an on-screen keyboard.
//
//   LiminalTouch.touch                       the device has a touch screen ((any-pointer: coarse)), kept current: <html>
//                                            has the class "touch" meanwhile; 'liminal:touch' on window says a change
//   LiminalTouch.onLongPress(root, selector, callback)   a finger or a pen held still about 500 ms on what matches
//                                            `selector` inside `root`: callback(el, {x, y, target, el, pointerType,
//                                            pointerId, down}); returning false declines it (then its words show, as
//                                            anywhere). The click after a long press served is swallowed, and the
//                                            browser's own menu and callout are stopped there. Returns its remover.
//   LiminalTouch.longPressing                the long press being served now (inside a callback), else null
//   LiminalTouch.holding                     a long press served (or its words shown) whose finger is still down
//   LiminalTouch.tip(where, text), hideTip() the bubble a long press shows on whatever has a title (or data-tip), on
//                                            touch screens: never inside [data-touch-own] (an area with gestures of its
//                                            own), nor in a field, nor on a link to an address
//   LiminalTouch.keyboard(kind, more)        a field's keyboard as attributes for markup (the kinds: KEYBOARDS);
//                                            setKeyboard(el, kind, more) sets them in place of a kind set before;
//                                            data-keyboard="kind" in markup fills in only what the field does not say
//   LiminalTouch.typing(root), whenIdle(root, fn)   a field (in root) is typed in; fn now, or once it is left
//   LiminalTouch.autofocus(el, options)      el.focus() unless the user's last move was a finger's (no keyboard unasked)
//   LiminalTouch.raiseKeyboard(el, options)  el focused from a tap so its keyboard comes up, even when it had the focus
//   LiminalTouch.keyboardOpen                an on-screen keyboard lies over the page: <html> has the class "keyboard",
//                                            :root --vvh (the height left above it) and --vv-top; 'liminal:keyboard'
// A field in a frame of the page's own origin (the charts page holds the login's page so) counts as the page's: the
// page holding the frame makes the keyboard's room and holds its redraws for it.
(() => {
  'use strict';

  const html = document.documentElement;
  const HOLD = 500;  // ms a finger is held still for a long press
  const SLOP = 8;  // px it may move meanwhile
  const NEAR = 24;  // px from a finger still held after its long press: a click there is that finger's
  const LAPSE = 400;  // ms after the lift a browser's own long-press menu still counts as the press's (Windows opens it then)
  const GRACE = 800;  // ms after a long press served its click and a browser's late menu are swallowed
  const now = () => performance.now();
  const query = (q) => (window.matchMedia ? window.matchMedia(q) : null);

  // -- a touch screen ---------------------------------------------------------------------------------------------
  const anyCoarse = query('(any-pointer: coarse)');
  const coarsePrimary = query('(pointer: coarse)');  // a phone's or a tablet's: its finger is its only pointer
  let touch = !!(anyCoarse && anyCoarse.matches);
  html.classList.toggle('touch', touch);
  if (anyCoarse) {
    const changed = () => {
      if (anyCoarse.matches === touch) return;
      touch = anyCoarse.matches;
      html.classList.toggle('touch', touch);
      window.dispatchEvent(new CustomEvent('liminal:touch', { detail: { touch } }));
    };
    if (anyCoarse.addEventListener) anyCoarse.addEventListener('change', changed);
    else if (anyCoarse.addListener) anyCoarse.addListener(changed);  // Safari before 14
  }

  // -- the styles this needs on every page, ahead of the page's own sheets so theirs win (the bubble's look is
  //    liminal.css's too, for the pages on it; the charts page has its own sheet) ------------------------------------
  const sheet = document.createElement('style');
  sheet.setAttribute('data-liminal', 'touch.js');
  sheet.textContent = [
    '.touch-tip { position: fixed; z-index: 70; box-sizing: border-box; max-width: min(320px, calc(100vw - 16px));'
      + ' padding: 8px 10px; border-radius: 8px; background: var(--panel, #1e222d); color: var(--text, #d1d4dc);'
      + ' border: 1px solid var(--border, #2a2e39); box-shadow: 0 8px 24px rgba(0, 0, 0, .35); font-size: 13px;'
      + ' line-height: 1.4; white-space: pre-line; overflow-wrap: anywhere; pointer-events: none; }',
    // what a finger holds for its words: no text selected and no callout meanwhile (a picture inside it neither)
    '[data-touch-hold], [data-touch-hold] * { -webkit-user-select: none; user-select: none; -webkit-touch-callout: none; }',
    // words shown on touch screens only, and with a mouse only
    'html:not(.touch) .touch-only, html.touch .mouse-only { display: none !important; }',
  ].join('\n');
  const head = document.head || html;
  head.insertBefore(sheet, head.firstChild);

  // -- fields -----------------------------------------------------------------------------------------------------
  const TYPED = new Set(['text', 'search', 'email', 'url', 'tel', 'password', 'number', 'date', 'datetime-local', 'month',
    'time', 'week']);
  // a field a keyboard types into: this page's, or one in a frame's page (its elements are another window's, so they
  // are known by their names, not by instanceof)
  function textField(el) {
    if (!el || el.nodeType !== 1) return false;
    if (el.isContentEditable) return true;
    if (el.localName === 'textarea') return !el.disabled && !el.readOnly;
    return el.localName === 'input' && TYPED.has(el.type) && !el.disabled && !el.readOnly;
  }
  const inField = (el) => !!el.isContentEditable || !!el.closest('input, textarea, select');

  // -- the long press -----------------------------------------------------------------------------------------------
  const served = [];  // onLongPress's registrations: {root, selector, callback, rule}
  let marks = 0;
  function onLongPress(root, selector, callback) {
    const reg = { root: root || document, selector: String(selector), callback, rule: null };
    served.push(reg);
    // no callout and no text selection there on a touch screen, nor on a picture inside it: a long press is its own
    let scope = 'html.touch';
    if (reg.root !== document && reg.root instanceof Element) {
      const mark = `lp${++marks}`;
      reg.root.setAttribute('data-long-press', `${reg.root.getAttribute('data-long-press') || ''} ${mark}`.trim());
      scope += ` [data-long-press~="${mark}"]`;
    }
    try {
      const rules = sheet.sheet.cssRules;
      sheet.sheet.insertRule(`${scope} :is(${reg.selector}), ${scope} :is(${reg.selector}) * { -webkit-touch-callout: none;`
        + ' -webkit-user-select: none; user-select: none; }', rules.length);
      reg.rule = rules[rules.length - 1];
    } catch (e) { /* a selector the sheet cannot take: the long press works without it */ }
    return () => {
      const i = served.indexOf(reg);
      if (i >= 0) served.splice(i, 1);
      const at = reg.rule && sheet.sheet ? Array.prototype.indexOf.call(sheet.sheet.cssRules, reg.rule) : -1;
      if (at >= 0) sheet.sheet.deleteRule(at);
      reg.rule = null;
    };
  }
  function servedAt(target) {  // the registration a press on target serves and its element (the latest registered first)
    for (let i = served.length - 1; i >= 0; i--) {
      const reg = served[i];
      let el = null;
      try { el = target.closest(reg.selector); } catch (e) { el = null; }
      if (el && (reg.root === document || (reg.root.contains && reg.root.contains(el)))) return { reg, el };
    }
    return null;
  }

  // The words a long press shows: the nearest data-tip or title (an SVG element's <title>), found as a mouse's hover
  // finds them: a picture or an icon inside a button (or anything else with words) shows that button's words. An empty
  // one says none, as for a mouse. Not in an area with gestures of its own ([data-touch-own]: a chart, the globe, a
  // terminal), nor in a field (its long press selects and pastes), nor in a link to an address or a player with its
  // controls, a picture there included (theirs open, copy, save or play); a link to nowhere (href="#": a button in all
  // but name) has words.
  const OWN_MENU = 'a[href]:not([href=""]):not([href="#"]):not([href^="javascript:"]), video[controls], audio[controls]';
  function tipOf(target) {
    if (!(target instanceof Element) || target.closest('[data-touch-own]') || target.closest(OWN_MENU) || inField(target)) {
      return null;
    }
    for (let el = target; el instanceof Element && el !== html; el = el.parentElement) {
      for (const name of ['data-tip', 'title']) {
        const words = el.getAttribute(name);
        if (words != null) return words.trim() ? { el, text: words.trim() } : null;
      }
      if (el instanceof SVGElement) {
        const t = [...el.children].find((c) => c.localName === 'title');
        if (t && t.textContent.trim()) return { el, text: t.textContent.trim() };
      }
    }
    return null;
  }

  // -- the bubble ---------------------------------------------------------------------------------------------------
  let bubble = null, bubbleFor = null, bubbleTimer = 0;
  function hideTip() {
    clearTimeout(bubbleTimer);
    if (bubble) bubble.remove();
    bubble = null;
    bubbleFor = null;
  }
  // above `top` by `above` px where there is room, else below `bottom` by `below` px; inside the part of the page seen
  function place(box, x, top, bottom, above, below) {
    const vv = window.visualViewport;
    const vx = vv ? vv.offsetLeft : 0, vy = vv ? vv.offsetTop : 0;
    const vw = vv ? vv.width : innerWidth, vh = vv ? vv.height : innerHeight;
    const r = box.getBoundingClientRect();
    let y = top - above - r.height;
    if (y < vy + 8) y = bottom + below;
    const left = Math.max(vx + 8, Math.min(x - r.width / 2, vx + vw - r.width - 8));
    box.style.left = `${Math.round(left)}px`;
    box.style.top = `${Math.round(Math.max(vy + 8, Math.min(y, vy + vh - r.height - 8)))}px`;
  }
  // at a point {x, y} (a finger's: clear of the fingertip) or over a box {left, top, width, bottom}
  function showTip(text, at, source, byFinger) {
    hideTip();
    const words = String(text == null ? '' : text).trim();
    if (!words) return false;
    const b = document.createElement('div');
    b.className = 'touch-tip';
    b.setAttribute('aria-hidden', 'true');  // the element's title is its accessible description already
    b.style.position = 'fixed';  // never in the page's flow, whatever the sheets say
    b.style.pointerEvents = 'none';
    b.style.left = '0px';  // measured at the corner: as wide as its words need, up to its most
    b.style.top = '0px';
    b.textContent = words;
    // inside an open modal dialog when the words are its: over the dialog (the top layer), not under it
    const host = (source && source.closest('dialog[open]')) || document.body;
    host.appendChild(b);
    bubble = b;
    bubbleFor = source || null;
    if (byFinger) place(b, at.x, at.y, at.y, 28, 44);
    else place(b, at.left + at.width / 2, at.top, at.bottom, 8, 8);
    bubbleTimer = setTimeout(hideTip, Math.min(10000, 3500 + 45 * words.length));
    return true;
  }
  // the bubble from the page's own code (a tap that explains, say): over an element, with its own words unless `text`
  // is given, or at a point {x, y} with `text`; false when there is nothing to show
  function tip(where, text) {
    if (where instanceof Element) {
      const words = text != null ? text : (where.getAttribute('data-tip') || where.getAttribute('title') || '');
      return showTip(words, where.getBoundingClientRect(), where, false);
    }
    if (where && Number.isFinite(where.x) && Number.isFinite(where.y)) return showTip(text, where, null, true);
    return false;
  }

  // -- a press, from the finger down to the long press or nothing ------------------------------------------------------
  let press = null;  // {id, type, x, y, target, hit, at, timer, lapse, up, fired, native}
  let firing = null;  // the long press being served now
  let after = 0;  // until when (ms) the click and a browser's menu after a long press served are swallowed
  let held = null;  // what a finger holds for its words
  let lastInput = '';  // what the user did last: 'mouse', 'touch', 'pen' or 'key' (a hardware keyboard's)
  const fingered = () => lastInput === 'touch' || lastInput === 'pen';

  function hold(el) { release(); held = el; el.setAttribute('data-touch-hold', ''); }
  function release() { if (held) { held.removeAttribute('data-touch-hold'); held = null; } }
  function drop() {  // no long press after all
    if (!press) return;
    clearTimeout(press.timer);
    clearTimeout(press.lapse);
    press = null;
    release();
  }
  function ofPress(p, target) {  // the browser's long press is on what this press holds (drawn again: the same kind of thing)
    if (!(target instanceof Element)) return false;
    if (p.at.isConnected) return p.at.contains(target);
    const again = p.hit ? servedAt(target) : null;
    return !!again && again.reg === p.hit.reg;
  }
  function serve(p) {  // the registration's callback: false when it declined
    const { reg } = p.hit;
    let { el } = p.hit;
    let target = p.target;
    if (!el.isConnected) {  // drawn again meanwhile: what is under the finger now
      const under = document.elementFromPoint(p.x, p.y);
      const again = under && servedAt(under);
      if (!again || again.reg !== reg) return false;
      el = again.el;
      target = under;
    } else if (!target.isConnected) target = el;
    firing = { x: p.x, y: p.y, target, el, pointerType: p.type, pointerId: p.id, down: !p.up };
    try {
      return reg.callback(el, { ...firing }) !== false;
    } catch (err) {
      setTimeout(() => { throw err; });
      return false;
    } finally {
      firing = null;
    }
  }
  function words(p) {  // the bubble with the pressed element's words
    const target = p.target.isConnected ? p.target : document.elementFromPoint(p.x, p.y);
    const found = target && tipOf(target);
    return !!found && showTip(found.text, { x: p.x, y: p.y }, found.el, true);
  }
  function fire(x, y) {
    const p = press;
    if (!p || p.fired) return;
    clearTimeout(p.timer);
    clearTimeout(p.lapse);
    p.fired = now();
    p.x = x;
    p.y = y;
    if (!((p.hit && serve(p)) || words(p))) { drop(); return; }  // nothing for it here: the browser's own ways stay
    if (!p.up) { after = Infinity; return; }  // until the finger lifts
    after = now() + GRACE;
    press = null;
    release();
  }

  document.addEventListener('pointerdown', (e) => {
    if (!e.isTrusted) return;  // a script's, not the user's
    lastInput = e.pointerType || 'mouse';
    hideTip();  // the next tap dismisses the bubble
    const t = e.target instanceof Element ? e.target : null;
    if (t) {  // a field's keyboard named in markup, filled in before the tap focuses the field
      const label = t.closest('label');
      const field = t.closest('[data-keyboard]') || (label && label.control);
      if (field && field.hasAttribute('data-keyboard')) fillKeyboard(field);
    }
    const finger = e.pointerType === 'touch' || e.pointerType === 'pen';
    // A long press served whose finger is still down: another finger, or a pen beside it, leaves it be (its tap goes
    // through: only a click at the held place is swallowed). A new primary pointer of its kind, or a mouse, says that
    // finger lifted unseen (what it pressed was drawn again under it, say): it is over.
    if (press && press.fired && !press.up && e.pointerId !== press.id
      && !(e.isPrimary && (e.pointerType === press.type || e.pointerType === 'mouse'))) return;
    after = 0;
    drop();  // a second finger (a pinch, a two-finger scroll): no long press
    if (!finger || e.button !== 0 || !e.isPrimary || !t || inField(t)) return;
    const hit = servedAt(t);
    const found = hit ? null : tipOf(t);
    if (!hit && !found) return;
    const p = { id: e.pointerId, type: e.pointerType, x: e.clientX, y: e.clientY, target: t, hit, at: hit ? hit.el : found.el,
      timer: 0, lapse: 0, up: false, fired: 0, native: false };  // fired: when (ms), 0 until then
    p.timer = setTimeout(() => { if (press === p) fire(p.x, p.y); }, HOLD);
    press = p;
    if (found) hold(found.el);
  }, { capture: true, passive: true });

  document.addEventListener('pointermove', (e) => {
    if (!press || press.fired || press.up || e.pointerId !== press.id) return;
    const dx = e.clientX - press.x, dy = e.clientY - press.y;
    if (dx * dx + dy * dy > SLOP * SLOP) drop();
  }, { capture: true, passive: true });

  function lifted(e) {
    const p = press;
    if (!p || e.pointerId !== p.id) return;
    if (p.fired) {  // served: its click and a browser's late menu swallowed a moment more
      after = now() + GRACE;
      press = null;
      release();
      return;
    }
    clearTimeout(p.timer);
    p.up = true;
    release();
    p.lapse = setTimeout(() => { if (press === p) press = null; }, LAPSE);
  }
  document.addEventListener('pointerup', lifted, true);
  document.addEventListener('pointercancel', lifted, true);

  document.addEventListener('scroll', (e) => {  // what was pressed, or the words shown, moved: no long press, no bubble
    const t = e.target;
    const moves = (el) => t === document || (t instanceof Element && !!el && t.contains(el));
    if (bubble && (!bubbleFor || moves(bubbleFor))) hideTip();
    if (press && !press.fired && !press.up && moves(press.target)) drop();
  }, { capture: true, passive: true });

  // The browser's own long-press menu (Chrome and Edge make a contextmenu of a long press; Safari never does): on what
  // a long press serves it is the long press, at once, its own menu not shown; one after a long press served is
  // swallowed, so no second menu opens. A script's contextmenu (menu.js passing a long press on) and a mouse's right
  // click go through as they are.
  window.addEventListener('contextmenu', (e) => {
    if (!e.isTrusted || e.pointerType === 'mouse') return;
    const p = press;
    if (p && !p.fired && ofPress(p, e.target)) {
      if (p.hit) {
        e.preventDefault();
        e.stopImmediatePropagation();
        fire(e.clientX, e.clientY);
      } else p.native = true;  // words to show, unless the page's own handler takes it (below, after them)
      return;
    }
    if (now() < after) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);
  window.addEventListener('contextmenu', (e) => {  // after the page's handlers: words nobody's menu took are shown
    const p = press;
    if (!e.isTrusted || !p || !p.native || p.fired) return;
    if (e.defaultPrevented) { drop(); return; }  // the page opened a menu of its own
    e.preventDefault();
    fire(e.clientX, e.clientY);
  });
  window.addEventListener('click', (e) => {  // the click a finger lifting from a long press served leaves: not a tap
    if (!e.isTrusted || !(now() < after)) return;
    // the finger still down: only a click at its place is its own (another finger's tap, on the menu it opened, is not)
    if (after === Infinity && press && Math.hypot(e.clientX - press.x, e.clientY - press.y) > NEAR) return;
    after = 0;
    e.preventDefault();
    e.stopImmediatePropagation();
  }, true);
  // What a hardware keyboard has and an on-screen one has not (an on-screen keyboard sends letters, Backspace and Enter
  // as keys too: Gboard's Go or Send is an Enter).
  const HARD_KEY = /^(Tab|Escape|Esc|Arrow(Up|Down|Left|Right)|Up|Down|Left|Right|Home|End|PageUp|PageDown|Insert|Delete|F\d{1,2}|Control|Alt|AltGraph|Meta|OS|ContextMenu)$/;
  document.addEventListener('keydown', (e) => {
    if (!e.isTrusted) return;  // a script's (a terminal's key row, say): not the user's keyboard
    after = 0;
    if (bubble) hideTip();
    if (e.isComposing || e.keyCode === 229 || e.key === 'Unidentified' || e.key === 'Process') return;  // a word composed
    // typing into the field a finger tapped stays the finger's; a key elsewhere, or one no on-screen keyboard has, is a
    // hardware keyboard's
    if (!fingered() || !textField(e.target) || HARD_KEY.test(e.key) || e.ctrlKey || e.altKey || e.metaKey) lastInput = 'key';
  }, true);
  window.addEventListener('resize', () => { if (bubble) hideTip(); });
  function away() {  // the window left meanwhile: no press goes on (one served keeps its click swallowed a moment)
    if (press && press.fired) after = now() + GRACE;
    drop();
  }
  window.addEventListener('blur', away);
  document.addEventListener('visibilitychange', () => { if (document.hidden) { away(); hideTip(); } });

  // -- the keyboard each field calls up --------------------------------------------------------------------------------
  // One name per kind of field, so every app asks for keyboards alike. EXACT is text typed as it is: no capitals, no
  // corrections, no suggestions, no form history. A secret (an API key) is kept out of password managers too.
  const EXACT = { autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', autocomplete: 'off' };
  const KEYBOARDS = {
    ticker: { ...EXACT, autocapitalize: 'characters', enterkeyhint: 'go' },  // AAPL, NQ1!, 7203.T
    search: { ...EXACT, enterkeyhint: 'search' },  // a search box or a filter
    number: { ...EXACT, inputmode: 'numeric', enterkeyhint: 'done' },  // a whole number, 0 or more: the digits pad
    decimal: { ...EXACT, inputmode: 'decimal', enterkeyhint: 'done' },  // a price, a quantity, 0 or more: digits and a point
    signed: { ...EXACT, enterkeyhint: 'done' },  // a number that may be negative: type=number's own keyboard has the minus
    secret: { ...EXACT, enterkeyhint: 'done', 'data-1p-ignore': 'true', 'data-lpignore': 'true', 'data-bwignore': 'true',
      'data-form-type': 'other' },  // an API key or a token (alias: key)
    plain: { ...EXACT, enterkeyhint: 'done' },  // literal text: a colour's hex, a DNS record, a pair's name
    name: { ...EXACT, autocapitalize: 'words', enterkeyhint: 'done' },  // a name someone gives: a profile, a list, a layout
    username: { ...EXACT, autocomplete: 'username', enterkeyhint: 'next' },  // an account's name, to sign in or up
    email: { ...EXACT, inputmode: 'email', autocomplete: 'email', enterkeyhint: 'next' },
    url: { ...EXACT, inputmode: 'url', enterkeyhint: 'done' },
    password: { ...EXACT, autocomplete: 'current-password', enterkeyhint: 'go' },  // {autocomplete: 'new-password'}: a new one
    code: { ...EXACT, inputmode: 'numeric', autocomplete: 'one-time-code', enterkeyhint: 'go' },  // a code sent by mail
    text: { enterkeyhint: 'done' },  // free text, capitals and corrections as usual (a textarea's Enter: 'enter')
    terminal: { ...EXACT },  // a terminal's input: every key its own, Enter unlabelled
  };
  KEYBOARDS.key = KEYBOARDS.secret;
  Object.values(KEYBOARDS).forEach((k) => Object.freeze(k));
  Object.freeze(KEYBOARDS);
  // every attribute a kind sets: what setKeyboard takes away when the kind it sets now has it not
  const KEYBOARD_ATTRS = [...new Set([].concat(...Object.values(KEYBOARDS).map((k) => Object.keys(k))))];

  const NAME = /^[a-z][a-z0-9-]*$/i;
  const own = (o, n) => Object.prototype.hasOwnProperty.call(o, n);
  // the kind's attributes; `more`: the Enter key's label ('go', 'next', 'done', 'search', 'send', 'enter'), or attributes
  // over the kind's ({enterkeyhint: 'next', autocomplete: 'new-password'}; null leaves one out)
  function attrsOf(kind, more, el) {
    const k = own(KEYBOARDS, kind) ? kind : 'text';
    const out = { 'data-keyboard': k, ...KEYBOARDS[k] };
    if (k === 'text' && el && el.localName === 'textarea') out.enterkeyhint = 'enter';
    if (typeof more === 'string') out.enterkeyhint = more;
    else if (more && typeof more === 'object') Object.keys(more).forEach((n) => { if (NAME.test(n)) out[n.toLowerCase()] = more[n]; });
    Object.keys(out).forEach((n) => { if (out[n] == null || out[n] === false) delete out[n]; });
    return out;
  }
  const escAttr = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  function keyboard(kind, more) {  // for markup: `<input ${LiminalTouch.keyboard('ticker', 'next')}>`
    const a = attrsOf(kind, more);
    return Object.keys(a).map((n) => `${n}="${escAttr(a[n])}"`).join(' ');
  }
  const setBefore = new WeakMap();  // a field -> the attributes setKeyboard gave it last (its kind's and `more`'s)
  function setKeyboard(el, kind, more) {  // for a field made in code: this kind's keyboard, in place of the one before
    if (!el || el.nodeType !== 1) return el;
    const a = attrsOf(kind, more, el);
    KEYBOARD_ATTRS.concat(setBefore.get(el) || []).forEach((n) => { if (!own(a, n)) el.removeAttribute(n); });
    Object.keys(a).forEach((n) => el.setAttribute(n, String(a[n])));
    setBefore.set(el, Object.keys(a));
    return el;
  }
  function fillKeyboard(el) {  // data-keyboard="kind" in markup: only what the field does not say itself, from its kind
    const a = attrsOf(el.getAttribute('data-keyboard'), null, el);
    Object.keys(a).forEach((n) => { if (!el.hasAttribute(n)) el.setAttribute(n, String(a[n])); });
  }
  document.addEventListener('focusin', (e) => {
    if (e.target instanceof Element && e.target.hasAttribute('data-keyboard')) fillKeyboard(e.target);
  }, true);
  const fillAll = () => document.querySelectorAll('[data-keyboard]').forEach(fillKeyboard);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fillAll);
  else fillAll();

  // -- the field typed in, here or in a frame of this page's origin (whose keyboard lies over this page) -----------------
  const followed = new WeakSet();  // the documents whose focus this page follows: its own, its frames'
  function focused() {  // {field, holder}: the field typed in, and what holds it on this page (the field, or its frame)
    const holder = document.activeElement;
    let el = holder;
    for (let depth = 0; el && el.localName === 'iframe' && depth < 4; depth++) {
      let doc = null;
      try { doc = el.contentDocument; } catch (e) { doc = null; }  // another origin's frame: its own page's business
      if (!doc) return null;
      follow(doc);
      el = doc.activeElement;
    }
    return textField(el) ? { field: el, holder } : null;
  }

  // -- typing: a redraw never replaces the field typed in ----------------------------------------------------------------
  let composing = null;  // the field a keyboard composes a word in (Gboard and others hold each word so until it is done)
  const waiting = new Map();  // root -> fn: a redraw held while a field in root is typed in
  function typing(root) {
    const r = root || document;
    const inside = (el) => !!el && el.isConnected && (r === document || r.contains(el));
    const f = focused();
    return (!!f && inside(f.holder)) || inside(composing);
  }
  function whenIdle(root, fn) {  // fn now, or once no field in root is typed in (the latest fn for a root wins)
    const r = root || document;
    if (!typing(r)) {
      waiting.delete(r);
      fn();
      return true;
    }
    waiting.set(r, fn);
    return false;
  }
  function settle() {  // the focus moved, or a word was composed: the redraws held for fields now left
    setTimeout(() => {
      waiting.forEach((fn, r) => {
        if (r !== document && !r.isConnected) { waiting.delete(r); return; }
        if (typing(r)) return;
        waiting.delete(r);
        try { fn(); } catch (err) { setTimeout(() => { throw err; }); }
      });
    }, 0);
  }
  document.addEventListener('compositionstart', (e) => { composing = e.target instanceof Element ? e.target : null; }, true);
  document.addEventListener('compositionend', () => { composing = null; }, true);

  // Focus by code calls up no keyboard unasked: not after a finger's (or a pen's) move, typing on the keyboard it
  // called up included, nor on a phone or a tablet before any move at all. A mouse's and a hardware keyboard's keep it.
  function mayFocus() {
    if (fingered()) return false;
    return lastInput !== '' || !(coarsePrimary && coarsePrimary.matches);
  }
  function autofocus(el, options) {
    if (!el || typeof el.focus !== 'function' || !mayFocus()) return false;
    el.focus(options);
    return true;
  }
  // From a tap: the field's keyboard comes up, even when the field kept the focus after the keyboard was put away
  // (Android's back gesture leaves it focused, and a focus() on it then does nothing).
  function raiseKeyboard(el, options) {
    if (!el || typeof el.focus !== 'function') return false;
    if (document.activeElement === el) el.blur();
    el.focus(options);
    return document.activeElement === el;
  }

  // -- room for the on-screen keyboard -----------------------------------------------------------------------------------
  // Chrome on Android shrinks the page above its keyboard when the viewport says interactive-widget=resizes-content
  // (every app's page does). Safari, and a browser that does not know it, lay the keyboard over the page: then <html>
  // has the class "keyboard", :root --vvh (the height left above the keyboard, which liminal.css fits the frame into)
  // and --vv-top (how far down the part seen is). Either way the field typed in is brought into view.
  const vv = window.visualViewport;
  let kbOpen = false, covered = 0, frame = 0;
  let tall = innerHeight, wide = innerWidth;  // the window's size while no field is focused: before a keyboard came up
  let short = false, keptAt = 0;  // the window that much shorter since, after a finger's tap; its height when last kept
  function keepInView(field) {
    const f = focused();
    if (!field || !f || f.field !== field || !field.isConnected) return;
    // a page fitted to the window (only its panes scroll) that Safari pushed up for its keyboard: back to its top first
    const body = document.body;
    if (kbOpen && body && body.scrollHeight <= innerHeight - covered + 1 && window.scrollY > 0) window.scrollTo(0, 0);
    try { field.scrollIntoView({ block: 'nearest', inline: 'nearest' }); } catch (e) { /* the browser's own scroll */ }
  }
  function measure() {
    frame = 0;
    const f = focused();
    const field = f ? f.field : null;
    if (!field || innerWidth !== wide) { tall = innerHeight; wide = innerWidth; }
    const gap = vv ? Math.max(0, Math.round(innerHeight - vv.height * vv.scale)) : 0;  // the height the keyboard covers
    const open = !!field && gap > 120;
    const opened = open && (!kbOpen || gap > covered + 40);
    // the page itself shrank above the keyboard (Chrome): brought into view once it is that much shorter, and again
    // each time it shrinks more (a keyboard sliding up in steps, its suggestions coming)
    const nowShort = !!field && fingered() && innerHeight < tall - 120;
    const shrank = nowShort && (!short || innerHeight < keptAt - 40);
    if (shrank) keptAt = innerHeight;
    short = nowShort;
    covered = open ? gap : 0;
    if (open) {
      html.style.setProperty('--vvh', `${innerHeight - gap}px`);
      html.style.setProperty('--vv-top', `${Math.round(vv.offsetTop)}px`);
    } else if (kbOpen) {
      html.style.removeProperty('--vvh');
      html.style.removeProperty('--vv-top');
    }
    if (open !== kbOpen) {
      kbOpen = open;
      html.classList.toggle('keyboard', open);
      window.dispatchEvent(new CustomEvent('liminal:keyboard', { detail: { open, height: gap } }));
    }
    if (opened || shrank) requestAnimationFrame(() => keepInView(field));
  }
  const schedule = () => { if (!frame) frame = requestAnimationFrame(measure); };
  if (vv) {
    vv.addEventListener('resize', schedule);
    vv.addEventListener('scroll', schedule);
  }
  window.addEventListener('resize', schedule);
  function focusMoved(e) {  // a field focused here or in a frame: the redraws held run, the next field kept in view
    settle();
    schedule();
    const t = e.target;
    if ((kbOpen || short) && textField(t)) requestAnimationFrame(() => keepInView(t));  // the keyboard up already
  }
  function focusLeft() { settle(); schedule(); }
  function follow(doc) {
    if (followed.has(doc)) return;
    followed.add(doc);
    doc.addEventListener('focusin', focusMoved, true);
    doc.addEventListener('focusout', focusLeft, true);
    doc.addEventListener('compositionend', settle, true);
  }
  follow(document);

  window.LiminalTouch = {
    get touch() { return touch; },
    get lastInput() { return lastInput; },
    get longPressing() { return firing ? { ...firing } : null; },
    get holding() { return !!(press && press.fired && !press.up); },
    get keyboardOpen() { return kbOpen; },
    get composing() { return !!(composing && composing.isConnected); },
    HOLD,
    onLongPress, tip, hideTip, keyboard, setKeyboard, KEYBOARDS, isTextField: textField, typing, whenIdle, mayFocus,
    autofocus, raiseKeyboard,
  };
})();
