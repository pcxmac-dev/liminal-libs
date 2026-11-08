// The UI's theme on every app's page (liminal-libs ui/static, 1.23.0): the one the platform's Preferences plugin keeps
// (GET api/ui: the data folder's ui.json), remembered by the page's origin too so the next visit is painted in it at
// once. Load it as the first thing in <body>: <script src="theme.js"></script>. A `theme` in the page's address wins
// (a super app showing this page in its own theme). The themes are liminal.css's: Midnight and Graphite are
// dark-based, Paper light-based (it also gets body.light).
(() => {
  'use strict';

  const KEY = 'liminal-theme';
  const BASE = { dark: 'dark', midnight: 'dark', graphite: 'dark', light: 'light', paper: 'light' };
  const asked = new URLSearchParams(location.search).get('theme');

  function apply(name) {
    const theme = BASE[name] ? name : 'dark';
    const b = document.body;
    if (b) {
      b.dataset.theme = theme;
      b.classList.toggle('light', BASE[theme] === 'light');
    }
    try { localStorage.setItem(KEY, theme); } catch (e) { /* no storage here: the server's word each visit */ }
    return theme;
  }

  let remembered = null;
  try { remembered = localStorage.getItem(KEY); } catch (e) { remembered = null; }
  if (asked && BASE[asked]) apply(asked);
  else if (remembered) apply(remembered);

  async function load() {  // the saved preference, applied (null: none to read here)
    if (asked && BASE[asked]) return { theme: asked, base: BASE[asked] };
    try {
      const r = await fetch('api/ui', { credentials: 'same-origin' });
      if (!r.ok) return null;
      const ui = await r.json();
      apply(ui.theme);
      return ui;
    } catch (e) {
      return null;
    }
  }

  window.LiminalTheme = { apply, load, ready: load(), bases: BASE };
})();
