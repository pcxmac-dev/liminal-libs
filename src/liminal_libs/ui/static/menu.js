// A small context menu for the apps' pages (liminal-libs ui/static, 1.23.0): LiminalMenu.open({x, y, title, items,
// from}) shows the items ({label, run, danger}) at the pointer, kept inside the window. Escape or Tab closes it and
// gives the focus back to `from`; a click elsewhere, the window losing focus, a resize or a scroll close it. The
// arrow keys move between the items. Texts are set with textContent (they are plugins' names).
//
// On a touch screen too (1.42.0; the user, 2026-11-10: "I want to support touch as well as mouse clicking on the
// interface"): a long press (touch.js, loaded before this file) on a rail icon fires the icon's contextmenu handlers as a
// right click does, on every device (Safari never makes a contextmenu of a long press), so every app's tray menu opens by
// a finger with no wiring of its own; LiminalMenu.longPress(root, selector) does the same for other elements. A menu a
// long press opens stands beside the finger rather than under it, its head gives the pressed element's own words (its
// data-tip, else its title: what no finger can hover), a scroll closes it once the finger is lifted, and a resize only
// when the width changes (a phone's bars come and go). A mouse's right click is as it was. A page with touch.js after
// this file still gets the long press (found once the page is read), and one without it a word in the console.
(() => {
  'use strict';

  let box = null, back = null;
  let fingered = null;  // a menu a long press opened: {width} (the window's width then)
  // the finger that opened it still down (touch.js knows: its lift, or a new tap showing the lift was missed)
  const holding = () => !!(window.LiminalTouch && window.LiminalTouch.holding);

  function close(restore = false) {
    if (!box) return;
    box.remove();
    box = null;
    fingered = null;
    const b = back;
    back = null;
    if (restore && b && b.isConnected) b.focus({ preventScroll: true });
  }

  function open({ x = 0, y = 0, title = '', items = [], from = null } = {}) {
    close();
    const finger = window.LiminalTouch ? window.LiminalTouch.longPressing : null;  // opened by a long press (touch.js)
    back = from || (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    box = document.createElement('div');
    box.className = 'menu';
    box.setAttribute('role', 'menu');
    if (title) {
      const h = document.createElement('div');
      h.className = 'menu-title';
      h.textContent = title;
      // by a finger: the pressed element's own words (a rail icon's name and its state), which a mouse reads on hover
      const words = finger && from ? String(from.getAttribute('data-tip') || from.getAttribute('title') || '').trim() : '';
      if (words && words !== title) {
        h.textContent = words;
        h.style.whiteSpace = 'normal';
        h.style.overflowWrap = 'anywhere';
      }
      box.appendChild(h);
      box.setAttribute('aria-label', title);
    }
    items.forEach((it) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.setAttribute('role', 'menuitem');
      b.textContent = it.label;
      if (it.danger) b.classList.add('danger');
      b.addEventListener('click', () => { close(true); it.run(); });
      box.appendChild(b);
    });
    document.body.appendChild(box);
    const r = box.getBoundingClientRect();
    let left = x, top = y;
    if (finger) {  // beside the finger, not under it: on its left where there is room (the rail is on the right), else its right
      left = x - r.width - 16 >= 8 ? x - r.width - 16 : x + 16;
      top = y - 16;
      fingered = { width: innerWidth };
    }
    box.style.left = `${Math.max(8, Math.min(left, innerWidth - r.width - 8))}px`;
    box.style.top = `${Math.max(8, Math.min(top, innerHeight - r.height - 8))}px`;
    const first = box.querySelector('button');
    if (first) first.focus({ preventScroll: true });
  }

  document.addEventListener('pointerdown', (e) => { if (box && !box.contains(e.target)) close(); }, true);
  document.addEventListener('keydown', (e) => {
    if (!box) return;
    if (e.key === 'Escape' || e.key === 'Tab') { e.preventDefault(); close(true); return; }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const all = [...box.querySelectorAll('button')];
      const i = all.indexOf(document.activeElement);
      const next = all[(i + (e.key === 'ArrowDown' ? 1 : -1) + all.length) % all.length];
      if (next) next.focus();
    }
  }, true);
  window.addEventListener('blur', () => close());
  window.addEventListener('resize', () => { if (!(fingered && innerWidth === fingered.width)) close(); });
  document.addEventListener('scroll', () => { if (!(fingered && holding())) close(); }, true);

  // touch.js later on the page than this file (it belongs right after theme.js): looked for again once the page is
  // read, and once it has loaded; still none, a word in the console (a mouse's right click works without it)
  function later(hold) {
    const last = () => {
      if (!hold()) console.warn('menu.js: no touch.js on this page (it loads right after theme.js), so a long press opens no menu');
    };
    if (document.readyState === 'complete') { setTimeout(last, 0); return; }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => { hold(); }, { once: true });
    window.addEventListener('load', last, { once: true });
  }

  // A long press (touch.js) on what matches `selector` in `root` fires its contextmenu handlers, as a right click does:
  // a contextmenu event at the finger (pointerType 'touch' or 'pen', isTrusted false). Taken when a handler prevents the
  // browser's own menu (it opened its menu); else the long press shows the element's words, as anywhere else. Returns
  // the function that removes it.
  function longPress(root, selector) {
    let off = null, removed = false;
    const hold = () => {
      if (off || removed) return true;
      const touch = window.LiminalTouch;
      if (!touch || !touch.onLongPress) return false;
      off = touch.onLongPress(root || document, selector, (el, at) => {
        const init = { bubbles: true, cancelable: true, composed: true, view: window, clientX: at.x, clientY: at.y, button: 2, buttons: 0 };
        let ev;
        try { ev = new PointerEvent('contextmenu', { ...init, pointerType: at.pointerType, isPrimary: true }); }
        catch (err) { ev = new MouseEvent('contextmenu', init); }
        return !at.target.dispatchEvent(ev);
      });
      return true;
    };
    if (!hold()) later(hold);
    return () => { removed = true; if (off) { off(); off = null; } };
  }
  longPress(document, '#rail button');  // every app's tray: the menus its icons' right click opens (panels.js, platform.js)

  window.LiminalMenu = { open, close: () => close(true), longPress, get shown() { return box !== null; } };
})();
