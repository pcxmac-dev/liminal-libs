// A small context menu for the apps' pages (liminal-libs ui/static, 1.23.0): LiminalMenu.open({x, y, title, items,
// from}) shows the items ({label, run, danger}) at the pointer, kept inside the window. Escape or Tab closes it and
// gives the focus back to `from`; a click elsewhere, the window losing focus, a resize or a scroll close it. The
// arrow keys move between the items. Texts are set with textContent (they are plugins' names).
(() => {
  'use strict';

  let box = null, back = null;

  function close(restore = false) {
    if (!box) return;
    box.remove();
    box = null;
    const b = back;
    back = null;
    if (restore && b && b.isConnected) b.focus({ preventScroll: true });
  }

  function open({ x = 0, y = 0, title = '', items = [], from = null } = {}) {
    close();
    back = from || (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    box = document.createElement('div');
    box.className = 'menu';
    box.setAttribute('role', 'menu');
    if (title) {
      const h = document.createElement('div');
      h.className = 'menu-title';
      h.textContent = title;
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
    box.style.left = `${Math.max(8, Math.min(x, innerWidth - r.width - 8))}px`;
    box.style.top = `${Math.max(8, Math.min(y, innerHeight - r.height - 8))}px`;
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
  window.addEventListener('resize', () => close());
  document.addEventListener('scroll', () => close(), true);

  window.LiminalMenu = { open, close: () => close(true), get shown() { return box !== null; } };
})();
