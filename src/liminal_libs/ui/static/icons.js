// Icons shared by the Liminal apps (liminal-libs ui/static, served beside every app's page): a symbol's
// logo (or a lettered badge, like TradingView), the data-state icon (fetching / backfilling / queued /
// new data / up to date) and the rails' icons. Plain functions returning HTML strings; all text is escaped.
(() => {
  'use strict';

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  // A link from a feed (a headline's URL) only if it is a web address: never javascript: or data:.
  const safeUrl = (u) => (/^https?:\/\//i.test(String(u ?? '').trim()) ? String(u).trim() : '');

  // Stable colour per ticker for lettered badges.
  const BADGE = ['#2962ff', '#00897b', '#7b1fa2', '#ef6c00', '#c2185b', '#455a64', '#5d4037', '#1565c0', '#2e7d32', '#ad1457'];
  function badgeColor(ticker) {
    let h = 0;
    for (const ch of ticker) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    return BADGE[h % BADGE.length];
  }
  const KIND_GLYPH = { future: '⧗', fx: '¤', crypto: '₿', index: 'Σ' };

  // `sym`: { ticker, icon (bool), asset }. Size in px.
  function symbolIcon(sym, size = 20) {
    const t = sym?.ticker || '?';
    const style = `width:${size}px;height:${size}px;font-size:${Math.round(size * 0.45)}px`;
    if (sym?.icon) {
      return `<span class="sym-icon" style="${style}" data-letter="${esc(t[0])}" data-color="${badgeColor(t)}"><img
        class="sym-img" src="/api/icon?ticker=${encodeURIComponent(t)}" alt="" loading="lazy"></span>`;
    }
    const glyph = KIND_GLYPH[sym?.asset] || t.replace(/[^A-Z0-9]/gi, '').slice(0, t.length > 3 ? 1 : 2) || '?';
    return `<span class="sym-icon letter" style="${style};background:${badgeColor(t)}" aria-hidden="true">${esc(glyph)}</span>`;
  }

  const SVG = (body, cls = '', size = 16) =>
    `<svg class="ico ${cls}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;

  const PATHS = {
    // The login app's master icon (the user), and its pairs' tools (liminal-libs 1.7.0)
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
    // Liminal's sign, the login app's master icon (the user, 2026-11-10: "the liminal icon is the italic lambda";
    // "replace all user icons (login app) with the lambda sign"; "M looks good"; "in japanese calligraphy"; "with a
    // thick brush, should see hair lines at end of stroke"; "now have horse hair brush strokes"): the mathematical
    // italic lambda written with a horse-hair brush, simulated (bristles in a teardrop held at 45 degrees, each
    // running dry at its own rate: the streaks of a dry brush and the hairs where the strokes end), then traced
    lambda: '<path fill="currentColor" stroke="none" fill-rule="evenodd" d="M11.79 2.93 L12.03 2.91 L12.05 2.94 L12.28 2.94 L12.3 2.96 L12.48 2.99 L12.68 3.09 L13.08 3.19 L13.33 3.31 L13.58 3.49 L13.84 3.75 L14.28 4.36 L14.34 4.35 L14.26 4.28 L14.24 4.18 L14.28 4.14 L14.35 4.16 L14.59 4.53 L14.69 4.9 L14.74 5.43 L14.79 5.58 L14.79 5.73 L14.84 5.85 L14.86 6.1 L14.95 6.09 L14.99 6.13 L15.06 6.5 L15.15 6.44 L15.2 6.44 L15.26 6.5 L15.44 7.18 L15.44 7.28 L15.49 7.4 L15.54 7.83 L15.56 7.85 L15.56 8.03 L15.59 8.05 L15.59 8.75 L15.61 8.78 L15.61 9 L15.64 9.03 L15.64 10.23 L15.66 10.25 L15.69 11.38 L15.71 11.4 L15.74 12.45 L15.76 12.48 L15.76 13.43 L15.79 13.45 L15.76 16.43 L15.79 16.45 L15.81 17.75 L15.84 17.77 L15.84 18.08 L15.86 18.1 L15.86 18.33 L15.89 18.35 L15.89 18.55 L15.91 18.6 L15.98 18.59 L16.15 18.46 L16.24 18.5 L16.24 18.6 L16.02 18.76 L15.95 18.79 L15.94 18.85 L16 18.86 L16.13 18.79 L16.48 18.51 L17.19 17.73 L17.23 17.69 L17.27 17.69 L17.31 17.75 L17.16 17.95 L17.24 18 L17.26 18.1 L16.94 18.63 L16.55 19.04 L16.3 19.24 L16.13 19.34 L16.09 19.38 L16.09 19.43 L16.29 19.8 L16.26 19.88 L16.33 19.89 L16.77 19.59 L17.24 19.13 L17.34 18.9 L17.4 18.84 L17.46 18.88 L17.46 18.95 L17.39 19.13 L17.02 19.54 L17.44 19.15 L17.58 18.94 L17.66 18.95 L17.66 19.05 L17.56 19.23 L17.49 19.3 L17.46 19.4 L16.95 19.94 L16.63 20.19 L16.59 20.25 L16.6 20.29 L16.77 20.29 L16.95 20.21 L17.1 20.09 L17.18 20.09 L17.24 20.15 L17.24 20.2 L17.13 20.31 L16.84 20.45 L16.8 20.56 L16.93 20.51 L16.98 20.51 L17.01 20.55 L17.01 20.63 L16.91 20.7 L16.88 20.81 L16.83 20.84 L16.75 20.81 L16.74 20.88 L16.63 20.99 L16.52 20.99 L16.43 20.94 L16.2 20.94 L15.93 20.81 L15.75 20.69 L15.56 20.5 L15.41 20.23 L15.26 20.02 L15.14 19.77 L15.06 19.52 L14.73 19.29 L14.41 18.93 L14.06 18.23 L13.99 17.95 L13.94 17.88 L13.91 17.68 L13.84 17.45 L13.79 17.05 L13.76 17.02 L13.76 16.88 L13.74 16.85 L13.74 16.7 L13.71 16.68 L13.71 16.48 L13.69 16.45 L13.69 16.23 L13.66 16.2 L13.66 15.95 L13.55 15.99 L13.49 15.93 L13.46 15.85 L13.44 15.15 L13.41 15.13 L13.41 14.63 L13.38 14.56 L13.3 14.59 L13.24 14.48 L13.21 11.93 L13.16 11.95 L12.79 12.48 L12.59 12.7 L12.41 12.98 L12.19 13.25 L11.66 14.03 L11.59 14.08 L11.39 14.35 L11.1 14.64 L11.03 14.64 L10.9 14.79 L10.83 14.81 L10.78 14.74 L10.41 15.15 L10.33 15.29 L10.23 15.31 L10.03 15.54 L9.95 15.56 L9.63 15.89 L9.54 15.9 L9.39 16.13 L9.2 16.34 L9.15 16.34 L9.1 16.29 L8.51 17.08 L8.45 17.14 L8.4 17.14 L8.23 17.34 L8.15 17.34 L8.11 17.3 L8.11 17.25 L8.64 16.6 L8.76 16.43 L8.79 16.27 L9.34 15.55 L9.25 15.56 L9.23 15.54 L9.19 15.58 L8.64 16.38 L7.61 17.75 L7.51 17.93 L7.43 18.01 L7.38 17.99 L7.34 18.02 L6.94 18.63 L6.9 18.66 L6.8 18.66 L6.66 18.9 L6.53 19.04 L6.44 19.02 L6.71 18.5 L7.34 17.6 L7.69 17 L8.11 16.38 L8.16 16.27 L8.16 16.18 L8.74 15.38 L9.04 14.9 L9.11 14.83 L9.14 14.75 L9.26 14.6 L9.29 14.53 L9.36 14.45 L9.64 14 L10.36 12.98 L10.39 12.9 L10.59 12.65 L11.56 11.2 L11.64 11.13 L12.84 9.3 L13.26 8.75 L13.26 6.6 L13.29 6.58 L13.29 5.88 L13.31 5.85 L13.31 4.93 L13.29 4.9 L13.26 4.5 L13.14 4.33 L13.11 4.22 L12.91 4 L12.91 3.95 L12.96 3.9 L12.73 3.69 L12.48 3.56 L12.18 3.54 L12.15 3.51 L12.13 3.54 L11.75 3.56 L11.64 3.65 L11.64 3.73 L11.58 3.79 L11.53 3.79 L11.09 4.22 L10.76 4.68 L10.58 4.86 L10.53 4.86 L10.49 4.9 L10.36 5.1 L10.26 5.15 L10.23 5.24 L10.1 5.24 L10.05 5.29 L10 5.29 L9.95 5.39 L9.82 5.39 L9.79 5.35 L9.79 5.25 L9.75 5.26 L9.71 5.23 L9.71 5.13 L9.66 5.08 L9.71 4.65 L9.74 4.63 L9.74 4.5 L9.79 4.33 L9.99 3.9 L10.24 3.6 L10.55 3.34 L10.95 3.11 L11.43 2.96Z M15.25 12.64 L15.24 12.88 L15.21 12.9 L15.24 16.18 L15.26 16.18Z M14.43 15.29 L14.41 15.83 L14.44 15.85 L14.46 16.45 L14.41 16.52 L14.44 16.75 L14.36 16.83 L14.36 17 L14.39 17.02 L14.39 17.23 L14.41 17.25 L14.41 17.43 L14.44 17.45 L14.44 17.6 L14.46 17.63 L14.46 17.77 L14.49 17.8 L14.51 18.02 L14.54 18.05 L14.61 18.43 L14.75 18.76 L14.83 18.81 L14.84 18.73 L14.81 18.7 L14.76 18.27 L14.74 18.25 L14.66 17.43 L14.59 17.3 L14.56 16.65 L14.54 16.63 L14.51 16.02 L14.49 16 L14.49 15.58 L14.46 15.55 L14.46 15.3Z M16.68 18.54 L16.38 18.86 L16.69 18.58Z M15.63 20.11 L15.61 20.15 L15.73 20.24 L15.74 20.2Z M16.3 20.11 L16.33 20.16 L16.4 20.14 L16.43 20.11Z M16.4 20.41 L16.52 20.54 L16.65 20.51 L16.68 20.46 L16.52 20.46Z M15.83 20.49 L15.81 20.53 L15.95 20.66 L16.05 20.69 L16.06 20.65 L15.9 20.49Z"/>',
    key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M16 5l3 3M13 8l2 2"/>',
    eye: '<path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    eyeoff: '<path d="M3 3l18 18"/><path d="M10.6 10.6a2 2 0 0 0 2.8 2.8"/><path d="M9.9 5.1A10.5 10.5 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.1"/><path d="M6.2 6.2C3.4 8.1 2 12 2 12s3.5 7 10 7a10 10 0 0 0 4.4-1"/>',
    trash: '<path d="M4 7h16M10 11v6M14 11v6"/><path d="M6 7l1 13h10l1-13"/><path d="M9 7V4h6v3"/>',
    logout: '<path d="M10 4H5v16h5"/><path d="M14 8l5 4-5 4"/><path d="M19 12H9"/>',
    sync: '<path d="M21 12a9 9 0 0 1-15.5 6.2L3 16"/><path d="M3 12a9 9 0 0 1 15.5-6.2L21 8"/><path d="M21 3v5h-5"/><path d="M3 21v-5h5"/>',
    check: '<circle cx="12" cy="12" r="9"/><path d="m8 12.5 2.8 2.8L16.5 9.5"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    download: '<path d="M12 4v11"/><path d="m7 10 5 5 5-5"/><path d="M5 20h14"/>',
    next: '<circle cx="12" cy="12" r="9"/><path d="m10.5 8 4 4-4 4"/>',
    pause: '<circle cx="12" cy="12" r="9"/><path d="M10 9v6M14 9v6"/>',
    database: '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.8"/><path d="M4.5 5.5v13c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8v-13"/><path d="M4.5 12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8"/>',
    analysis: '<path d="M3 3v18h18"/><path d="m7 15 4-5 3 3 5-7"/><path d="M15 6h4v4"/>',
    // the Analysis view: the definite integral, typeset: a calligraphic sign with ball terminals (an outline
    // drawn thick through the middle, thin at the ends), its limits and dx in an italic math serif
    integral: '<g fill="currentColor" stroke="none"><path d="M12.99 4.32 L12.97 4.27 L12.95 4.19 L12.92 4.1 L12.88 4 L12.85 3.88 L12.8 3.76 L12.76 3.63 L12.71 3.5 L12.66 3.37 L12.6 3.24 L12.53 3.12 L12.46 3 L12.38 2.89 L12.3 2.8 L12.2 2.72 L12.1 2.65 L12 2.58 L11.89 2.52 L11.77 2.46 L11.66 2.41 L11.54 2.36 L11.42 2.31 L11.3 2.28 L11.17 2.25 L11.05 2.23 L10.93 2.22 L10.8 2.22 L10.68 2.23 L10.57 2.26 L10.45 2.3 L10.35 2.36 L10.25 2.42 L10.15 2.49 L10.06 2.57 L9.97 2.65 L9.88 2.74 L9.8 2.84 L9.72 2.94 L9.64 3.04 L9.57 3.15 L9.49 3.25 L9.42 3.37 L9.35 3.49 L9.29 3.61 L9.22 3.73 L9.16 3.86 L9.11 3.99 L9.05 4.13 L9 4.27 L8.95 4.42 L8.89 4.57 L8.84 4.73 L8.78 4.9 L8.72 5.08 L8.66 5.27 L8.6 5.47 L8.53 5.69 L8.45 5.93 L8.38 6.18 L8.3 6.45 L8.22 6.73 L8.15 7.01 L8.07 7.3 L7.99 7.6 L7.92 7.89 L7.85 8.19 L7.78 8.49 L7.71 8.78 L7.65 9.06 L7.59 9.34 L7.53 9.62 L7.48 9.89 L7.42 10.17 L7.38 10.44 L7.33 10.71 L7.29 10.98 L7.25 11.25 L7.21 11.52 L7.17 11.8 L7.13 12.07 L7.1 12.34 L7.07 12.61 L7.04 12.88 L7.01 13.15 L6.99 13.43 L6.96 13.72 L6.94 14.01 L6.92 14.3 L6.9 14.59 L6.88 14.88 L6.87 15.17 L6.86 15.46 L6.84 15.73 L6.83 16 L6.82 16.27 L6.81 16.51 L6.79 16.75 L6.78 16.97 L6.77 17.18 L6.75 17.38 L6.74 17.57 L6.73 17.75 L6.71 17.92 L6.7 18.08 L6.69 18.23 L6.67 18.38 L6.65 18.52 L6.63 18.65 L6.61 18.78 L6.58 18.91 L6.55 19.05 L6.52 19.18 L6.48 19.31 L6.44 19.45 L6.4 19.58 L6.35 19.72 L6.31 19.85 L6.26 19.97 L6.2 20.09 L6.15 20.21 L6.09 20.32 L6.03 20.42 L5.97 20.51 L5.91 20.6 L5.85 20.67 L5.78 20.74 L5.72 20.8 L5.64 20.86 L5.56 20.91 L5.47 20.96 L5.38 21 L5.29 21.04 L5.19 21.07 L5.1 21.09 L5.01 21.1 L4.92 21.11 L4.83 21.11 L4.76 21.1 L4.69 21.08 L4.64 21.06 L4.6 21.03 L4.55 20.99 L4.49 20.92 L4.43 20.84 L4.37 20.74 L4.31 20.64 L4.25 20.53 L4.2 20.41 L4.14 20.3 L4.09 20.19 L4.05 20.09 L4.01 19.99 L3.97 19.91 L3.93 19.85 L3.57 20.05 L3.59 20.1 L3.63 20.17 L3.67 20.26 L3.71 20.36 L3.76 20.47 L3.82 20.59 L3.87 20.71 L3.94 20.84 L4.01 20.96 L4.08 21.07 L4.16 21.18 L4.25 21.28 L4.35 21.37 L4.46 21.44 L4.57 21.48 L4.68 21.51 L4.8 21.52 L4.92 21.53 L5.04 21.52 L5.16 21.51 L5.28 21.49 L5.41 21.47 L5.53 21.43 L5.65 21.39 L5.77 21.35 L5.89 21.29 L6.01 21.23 L6.12 21.16 L6.22 21.08 L6.33 20.99 L6.43 20.9 L6.52 20.8 L6.62 20.69 L6.71 20.57 L6.8 20.45 L6.89 20.33 L6.98 20.2 L7.06 20.07 L7.15 19.93 L7.23 19.8 L7.3 19.66 L7.38 19.52 L7.45 19.38 L7.52 19.24 L7.59 19.09 L7.65 18.95 L7.71 18.8 L7.76 18.65 L7.82 18.49 L7.88 18.33 L7.93 18.17 L7.98 18 L8.04 17.82 L8.1 17.63 L8.16 17.44 L8.22 17.23 L8.28 17 L8.35 16.76 L8.42 16.51 L8.48 16.25 L8.55 15.98 L8.62 15.7 L8.68 15.42 L8.74 15.14 L8.81 14.85 L8.87 14.56 L8.93 14.28 L8.98 14 L9.04 13.72 L9.09 13.45 L9.14 13.18 L9.18 12.91 L9.23 12.64 L9.27 12.37 L9.32 12.1 L9.35 11.83 L9.39 11.56 L9.43 11.29 L9.46 11.02 L9.5 10.75 L9.53 10.48 L9.56 10.2 L9.59 9.93 L9.61 9.66 L9.64 9.38 L9.67 9.08 L9.69 8.79 L9.72 8.49 L9.74 8.18 L9.76 7.88 L9.78 7.58 L9.8 7.28 L9.82 7 L9.84 6.72 L9.85 6.45 L9.87 6.19 L9.89 5.95 L9.9 5.73 L9.92 5.52 L9.94 5.32 L9.95 5.14 L9.97 4.97 L9.98 4.81 L10 4.66 L10.01 4.52 L10.03 4.39 L10.05 4.27 L10.07 4.16 L10.09 4.05 L10.12 3.94 L10.15 3.84 L10.18 3.73 L10.22 3.63 L10.26 3.52 L10.3 3.43 L10.34 3.33 L10.38 3.24 L10.43 3.16 L10.48 3.09 L10.53 3.02 L10.57 2.96 L10.62 2.9 L10.67 2.86 L10.72 2.82 L10.77 2.79 L10.82 2.77 L10.87 2.75 L10.94 2.74 L11.02 2.73 L11.11 2.73 L11.2 2.74 L11.3 2.76 L11.4 2.78 L11.5 2.81 L11.6 2.85 L11.69 2.89 L11.78 2.94 L11.87 2.99 L11.94 3.05 L12 3.1 L12.06 3.16 L12.11 3.23 L12.17 3.32 L12.22 3.43 L12.27 3.54 L12.32 3.65 L12.37 3.78 L12.41 3.9 L12.45 4.01 L12.48 4.13 L12.52 4.23 L12.55 4.33 L12.58 4.41 L12.61 4.48Z"/><circle cx="12.85" cy="4.5" r="1.2"/><circle cx="3.7" cy="19.85" r="1.2"/><text x="14.6" y="6.6" font-size="6.6" font-family=\"Cambria Math, STIX Two Math, Latin Modern Math, Times New Roman, serif\" font-style=\"italic\">b</text><text x="8.7" y="23.2" font-size="6.6" font-family=\"Cambria Math, STIX Two Math, Latin Modern Math, Times New Roman, serif\" font-style=\"italic\">a</text><text x="13.6" y="15.2" font-size="8.6" font-family=\"Cambria Math, STIX Two Math, Latin Modern Math, Times New Roman, serif\" font-style=\"italic\">dx</text></g>',
    // the Fetcher: a disk and its read/write arm (the platter turns while a run fetches: style.css)
    disk: '<g stroke-width="1.5"><g class="disk-platter"><circle cx="11" cy="11" r="8.5"/><path stroke-width="1.1" d="M5.36 8.95A6 6 0 0 1 12.55 5.20M16.64 13.05A6 6 0 0 1 9.45 16.80M9.15 14.20A3.7 3.7 0 0 1 7.97 8.88M12.85 7.80A3.7 3.7 0 0 1 14.03 13.12"/><circle cx="11" cy="11" r="1.3"/></g><g class="disk-arm"><circle cx="20.3" cy="20.3" r="1.6"/><path d="M19.2 19.1 14.2 15.2"/><path stroke-width="2" d="m13.2 16.3 2-2.2"/></g></g>',
    // the login page: Leonardo's Vitruvian Man, the figure in its circle and square (arms out to the
    // square's sides and raised to the circle, feet together on the square's base and spread to the circle)
    vitruvian: '<g stroke-width="1"><circle cx="12" cy="12.3" r="10.6"/><path d="M3.9 6.7h16.2v16.2H3.9z"/></g>'
      + '<g stroke-width="1.2"><circle cx="12" cy="8.3" r="1.5"/><path d="M12 9.8v5.8M3.9 11h16.2M12 11 2.4 7.8M12 11l9.6-3.2'
      + 'M12 15.6l-1 7.3M12 15.6l1 7.3M12 15.6l-5.3 5.9M12 15.6l5.3 5.9"/></g>',
    // the Gov view: a state house (its dome and lantern, the columns of its portico, its steps)
    statehouse: '<g stroke-width="1.5"><path d="M12 1.8v1.6"/><path d="M11 3.4h2v2.1h-2z"/><path d="M7.6 10a4.4 4.6 0 0 1 8.8 0"/><path d="M6.8 10h10.4v1.8H6.8z"/><path d="M3.5 13.2 12 11.8l8.5 1.4"/><path d="M4.2 13.2v6.1M19.8 13.2v6.1"/><path stroke-width="1.3" d="M7.4 14.6v4.7M10.5 14.6v4.7M13.5 14.6v4.7M16.6 14.6v4.7"/><path d="M3 19.3h18M2.2 21.4h19.6"/></g>',
    // the Exchanges view: a pair of scales (the balance of a trade, and of justice)
    scales: '<g stroke-width="1.5"><circle cx="12" cy="3.3" r="1.1"/><path d="M12 4.4v15.4M8 20.6h8M3.6 6.6h16.8"/><path stroke-width="1.2" d="M3.6 6.6 1.5 12.8M3.6 6.6l2.1 6.2M20.4 6.6l-2.1 6.2M20.4 6.6l2.1 6.2"/><path d="M1 12.8h5.2a2.6 2.3 0 0 1-5.2 0zM17.8 12.8H23a2.6 2.3 0 0 1-5.2 0z"/></g>',
    // the Plugins view: a plug (its two prongs, its body, its cord)
    plug: '<g stroke-width="1.5"><path d="M9 2.2v4.6M15 2.2v4.6"/><path d="M6.2 6.8h11.6v3.4a5.8 5.4 0 0 1-11.6 0z"/><path d="M12 15.6v2.2a3.2 3.2 0 0 0 3.2 3.2H19"/></g>',
    // the Resources view: a chip with its leads (three on each side) and its die
    chip: '<g stroke-width="1.5"><rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.3" y="9.3" width="5.4" height="5.4" rx=".6"/><path stroke-width="1.3" d="M9 2.4V6M12 2.4V6M15 2.4V6M9 18v3.6M12 18v3.6M15 18v3.6M2.4 9H6M2.4 12H6M2.4 15H6M18 9h3.6M18 12h3.6M18 15h3.6"/></g>',
    shield: '<path d="M12 2.8 4.6 5.6v5.6c0 4.7 3.1 8.4 7.4 9.9 4.3-1.5 7.4-5.2 7.4-9.9V5.6z"/><path d="m8.8 12.1 2.2 2.2 4.3-4.4"/>',
    wrench: '<path d="M14.6 6.4a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.6-3.6a6 6 0 0 1-7.9 7.9l-6.8 6.8a2.1 2.1 0 0 1-3-3l6.8-6.8a6 6 0 0 1 7.9-7.9z"/>',
    terminal: '<rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="m7 9.5 3 2.5-3 2.5M12.5 15h4.5"/>',
    gauge: '<path d="M4.2 17.5a9 9 0 1 1 15.6 0"/><path d="M12 13.6 15.8 8.6"/><circle cx="12" cy="14" r="1.6"/><path d="M6.6 11.2h1.2M12 5.6v1.2M16.2 11.2h1.2"/>',
    // the News view: a thermometer (the markets' temperature)
    thermometer: '<g stroke-width="1.5"><path d="M14 14.6V4.75a2 2 0 0 0-4 0v9.85a4 4 0 1 0 4 0z"/><path stroke-width="2" d="M12 8v8.3"/><circle cx="12" cy="17.75" r="1.7" fill="currentColor" stroke="none"/><path stroke-width="1.1" d="M16 5.5h2.2M16 8.25h1.4M16 11h2.2M16 13.75h1.4"/></g>',
    // the Datasets view (research series): a scroll
    scroll: '<g stroke-width="1.5"><path d="M5 3h12.5a2 2 0 0 1 0 4H5a2 2 0 0 1 0-4z"/><path d="M5 4.1a.9.9 0 1 0 0 1.8"/><path d="M6.5 7v10.5M17.5 7v10.5"/><path d="M6.5 17h12.5a2 2 0 0 1 0 4H6.5a2 2 0 0 1 0-4z"/><path d="M19 18.1a.9.9 0 1 1 0 1.8"/><path d="M9.25 10h5.5M9.25 12.5h5.5M9.25 15h3.5"/></g>',
    // the Trading view: two hands shaking
    trading: '<g stroke-width="1.5"><path d="M2 7.5h2.6v9H2z"/><path d="M22 7.5h-2.6v9H22z"/><path d="M19.4 9.2c-1.6-.9-3.4-1.4-5.2-1-1.3.3-2.6 1-3.6 1.9"/><path d="M4.6 9.6c1.6-.4 3.2-.6 4.6-.2l3.3 1.1"/><path d="M10.6 10.1 8.4 12.2c-.5.5-.4 1.3.2 1.6.5.3 1.1.2 1.5-.2l2.3-2.1"/><path d="M12.4 11.5l3 2.9c.5.5.5 1.2 0 1.6-.5.4-1.1.3-1.5-.1"/><path d="M14.6 13.6c.5.5.5 1.2 0 1.6-.5.4-1.1.3-1.5-.1l-1.1-1"/><path d="M12.9 15.2c.4.5.4 1.1 0 1.5-.4.4-1 .3-1.4-.1l-1-.9"/><path d="M10.9 16.6c.3.4.2 1-.2 1.3-.4.3-.9.2-1.2-.1L4.6 15.4"/><path d="M19.4 15.2c-1.3.8-2.8 1.3-4.3 1.5"/></g>',
    watchlist: '<path d="M9 6h12M9 12h12M9 18h7"/><path d="M4 6h.01M4 12h.01M4 18h.01"/><path d="m19 15 .9 1.8 2 .3-1.45 1.4.35 2-1.8-.95-1.8.95.35-2-1.45-1.4 2-.3z"/>',
    // Preferences: three sliders, their knobs right, left, right (the user's drawing, 2026-10-28)
    sliders: '<path d="M3 6.5h9.6M17.4 6.5H21M3 12h3.6M11.4 12H21M3 17.5h9.6M17.4 17.5H21"/><circle cx="15" cy="6.5" r="2.4"/><circle cx="9" cy="12" r="2.4"/><circle cx="15" cy="17.5" r="2.4"/>',
    scan: '<path d="M4 8V5a1 1 0 0 1 1-1h3"/><path d="M16 4h3a1 1 0 0 1 1 1v3"/><path d="M20 16v3a1 1 0 0 1-1 1h-3"/><path d="M8 20H5a1 1 0 0 1-1-1v-3"/><path d="M7 12h10"/>',
    expand: '<path d="M15 3h6v6"/><path d="M9 21H3v-6"/><path d="M21 3l-7 7"/><path d="M3 21l7-7"/>',
    news: '<rect x="3" y="4" width="15" height="16" rx="2"/><path d="M18 8h3v10a2 2 0 0 1-2 2"/><path d="M7 8h7"/><path d="M7 12h7"/><path d="M7 16h4"/>',
        globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18"/><path d="M12 3a14 14 0 0 0 0 18"/>',
    record: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4" fill="currentColor"/>',
        sort: '<path d="M7 4v16"/><path d="m3 16 4 4 4-4"/><path d="M17 20V4"/><path d="m13 8 4-4 4 4"/>',
    // The platform's plugins by their makers' marks, each drawn in this set's own line (the user, 2026-11-08: "for the
    // icons, WSL, use the distribution's mascot or icon"; "for the firewalls, lets use an icon of TUX penguin or Windows
    // and then convert it to a patchwork of bricks"; "for name cheap, use it's icon"; "for the AI icons, lets use the
    // respective mascot/icon from the business, logo, etc.."; "for the docker and kubernetes plugins, use their
    // respective logos"; "same with LXD and hyperv for windows")
    // Ubuntu's circle of friends: three heads about a ring broken beside each
    ubuntu: '<path stroke-width="1.6" d="M17.86 8.55a6.8 6.8 0 0 1 0 6.9M12.06 18.8a6.8 6.8 0 0 1-5.98-3.45M6.08 8.65a6.8 6.8 0 0 1 5.98-3.45"/>'
      + '<g fill="currentColor" stroke="none"><circle cx="5.2" cy="12" r="2.2"/><circle cx="15.4" cy="6.11" r="2.2"/><circle cx="15.4" cy="17.89" r="2.2"/></g>',
    // Fedora's bubble, its corner square, and its f closing on an infinity's loop
    fedora: '<g stroke-width="1.5"><path d="M20.5 12A8.5 8.5 0 1 0 12 20.5h8.5z"/><path d="M14.8 7.2H14a3.6 3.6 0 0 0-3.6 3.6v4.4a2.6 2.6 0 1 1-2.6-2.6H14"/></g>',
    // Gentoo's g: the round swirl with its hole, its tail hooked below
    gentoo: '<g stroke-width="1.5"><path d="M6.2 20.8c2.4-1.2 3.4-3.2 2.2-5.2-1.8-3.2-.8-7.8 2.4-10.2 3.2-2.4 7.8-2 9.4 1.2 1.6 3.2 0 7.2-3.8 9.8-3 2-6.6 3.8-10.2 4.4z"/>'
      + '<ellipse cx="15.2" cy="9.8" rx="2.6" ry="1.8" transform="rotate(-35 15.2 9.8)"/></g>',
    // the Linux firewall: a brick wall with a flame before it (the user's picture, 2026-11-08: "use this icon for linux
    // firewall")
    wallfire: '<g stroke-width="1.5"><path d="M7.4 21.6C4.4 21.6 2.3 19.4 2.3 16.5 2.3 12.6 5.6 10.4 5.9 4.2c2.5 2.1 3.5 4.4 3.4 7 .9-.7 1.5-1.6 1.8-2.8 1.1 2 1.5 4.3 1.5 6.9 0 3.7-2 6.3-5.2 6.3z"/>'
      + '<path d="M8.6 6.8V4.5A1.5 1.5 0 0 1 10.1 3h10.2a1.5 1.5 0 0 1 1.5 1.5v15.6a1.5 1.5 0 0 1-1.5 1.5h-8.7"/></g>'
      + '<g stroke-width="1.2"><path d="M7.5 19.9c-1.5 0-2.5-1.1-2.5-2.6 0-1.9 1.3-2.9 2.2-5 1.4 1.7 2.8 3 2.8 5 0 1.5-1 2.6-2.5 2.6z"/>'
      + '<path d="M9.7 7.65h12.1M13.5 12.3h8.3M13.6 16.95h8.2M15.2 3v4.65M18.5 7.65v4.65M15.2 12.3v4.65M18.5 16.95v4.65"/></g>',
    // the Windows firewall: a brick wall in three dimensions, the globe behind it (the user's picture: "this one for
    // windows firewall")
    wallglobe: '<g stroke-width="1.5"><path d="M9.81 7.6A6 6 0 1 1 18.7 13.25"/><path d="M2.5 11h12.5v10.5H2.5zM2.5 11l2.6-2.2h12.5L15 11M17.6 8.8v10.5L15 21.5"/></g>'
      + '<g stroke-width="1.1"><path d="M13.2 7.6a2.6 6 0 0 1 5.2 0M10.6 5q5.2 1.6 10.4 0"/>'
      + '<path d="M2.5 14.5H15M2.5 18H15M6.7 11v3.5M10.9 11v3.5M4.6 14.5V18M8.8 14.5V18M13 14.5V18M6.7 18v3.5M10.9 18v3.5M6.7 11l2.6-2.2M10.9 11l2.6-2.2M15 14.5l2.6-2.2M15 18l2.6-2.2"/></g>',
    // Namecheap's N, its strokes rounded
    namecheap: '<path stroke-width="2.6" d="M6 18.5V6.8c0-.9 1.1-1.3 1.7-.6l8.6 11.6c.6.7 1.7.3 1.7-.6V5.5"/>',
    // Claude's spark: rays of uneven length about an open heart
    claude: '<path stroke-width="2.1" d="M12 10V2.8M13.18 10.38 16.11 6.34M13.9 11.38l6.28-2.04M13.9 12.62l5.33 1.73M13.18 13.62l4.11 5.66M12 14v4.9'
      + 'M10.82 13.62l-3.99 5.5M10.1 12.62l-5.14 1.67M10.1 11.38 3.34 9.19M10.82 10.38 7.77 6.18"/>',
    // OpenAI's knot (the Codex plugin's): three links turned a sixth of a turn apart
    openai: '<g stroke-width="1.5"><rect x="8.9" y="3.2" width="6.2" height="17.6" rx="3.1"/>'
      + '<rect x="8.9" y="3.2" width="6.2" height="17.6" rx="3.1" transform="rotate(60 12 12)"/>'
      + '<rect x="8.9" y="3.2" width="6.2" height="17.6" rx="3.1" transform="rotate(120 12 12)"/></g>',
    // Grok's mark: a ring open at its upper right, a stroke through it and out
    grok: '<g stroke-width="1.8"><path d="M19.09 10.75A7.2 7.2 0 1 1 13.25 4.91"/><path d="M4.2 19.8 20.6 3.4"/></g>',
    // GitHub Copilot's pilot: the head, its goggles, its eyes
    copilot: '<g stroke-width="1.5"><path d="M4 13.5c0-1.1.4-2.2 1.1-3V9.2C5.1 6 8.2 4 12 4s6.9 2 6.9 5.2v1.3c.7.8 1.1 1.9 1.1 3v2.2c0 2.6-3.6 4.8-8 4.8s-8-2.2-8-4.8z"/>'
      + '<rect x="6.4" y="7" width="4.8" height="4" rx="1.8"/><rect x="12.8" y="7" width="4.8" height="4" rx="1.8"/><path stroke-width="1.8" d="M10 14.6v1.6M14 14.6v1.6"/></g>',
    // Cursor's cube (the user, 2026-11-09: "lets add an AI plugin for cursor"): the hexagon of its 2D mark, and the arrow
    // cut out of it, its top edge level, its tip at the cube's foot, its notch at the cube's centre
    cursor: '<g stroke-width="1.5"><path d="M12 2.2 20.49 7.1v9.8L12 21.8 3.51 16.9V7.1z"/><path d="M4.4 7.45H19.6L12 20.6V12.05z"/></g>',
    // Docker's whale, its containers on its back
    docker: '<path stroke-width="1.5" d="M2.4 12.2h16.2c.6-1.4 1.9-2.2 3.2-2 .2 1.2-.3 2.4-1.4 3C19 17.6 15.6 20 11 20c-4.6 0-7.8-2.6-8.6-7.8z"/>'
      + '<g stroke-width="1"><rect x="4" y="9.6" width="2.2" height="2.2"/><rect x="6.6" y="9.6" width="2.2" height="2.2"/><rect x="9.2" y="9.6" width="2.2" height="2.2"/>'
      + '<rect x="11.8" y="9.6" width="2.2" height="2.2"/><rect x="14.4" y="9.6" width="2.2" height="2.2"/><rect x="9.2" y="7" width="2.2" height="2.2"/>'
      + '<rect x="11.8" y="7" width="2.2" height="2.2"/><rect x="14.4" y="7" width="2.2" height="2.2"/><rect x="11.8" y="4.4" width="2.2" height="2.2"/></g>'
      + '<circle cx="6.4" cy="15.2" r=".75" fill="currentColor" stroke="none"/>',
    // Kubernetes' helm: the heptagon, the wheel, its seven spokes
    kubernetes: '<g stroke-width="1.5"><path d="M12 2.4 19.51 6.01 21.36 14.14 16.17 20.65H7.83L2.64 14.14 4.49 6.01z"/><circle cx="12" cy="12" r="5.2"/><circle cx="12" cy="12" r="1.5"/></g>'
      + '<path stroke-width="1.3" d="M12 10.5V4.6M13.17 11.06l4.62-3.67M13.46 12.33l5.75 1.32M12.65 13.35l2.56 5.32M11.35 13.35l-2.56 5.32M10.54 12.33l-5.75 1.32M10.83 11.06 6.21 7.39"/>',
    // LXD's cube of cubes (a container of containers)
    lxd: '<g stroke-width="1.5"><path d="M12 3 19.8 7.5v9L12 21l-7.8-4.5v-9z"/><path d="M4.2 7.5 12 12l7.8-4.5M12 12v9"/></g>'
      + '<path stroke-width="1" d="M15.9 5.25 8.1 9.75M8.1 5.25l7.8 4.5M8.1 9.75v9M4.2 12 12 16.5M15.9 9.75v9M12 16.5l7.8-4.5"/>',
    // libvirt's tin, turned as its logo has it: penguins packed head to toe, the lid rolled back on its key (the user:
    // "the platform icon matches libvirt's ... libvirt has a can of tuna as an icon")
    libvirt: '<g transform="rotate(-20 12 12)"><g stroke-width="1.5"><rect x="2.6" y="6.2" width="18.8" height="11.6" rx="2.3"/>'
      + '<path d="M14.1 6.6a1.3 1.3 0 0 1 2.6 0v10.8a1.3 1.3 0 0 1-2.6 0z"/><path d="M15.4 18.7v.8"/><circle cx="15.4" cy="20.7" r="1.2"/></g>'
      + '<g stroke-width="1.1"><path d="M14.1 6.6a1.3 1.1 0 0 0 2.6 0"/>'
      + '<ellipse cx="6.1" cy="11.7" rx="1.8" ry="3.8"/><ellipse stroke-width=".9" cx="6.55" cy="12.3" rx=".95" ry="2.5"/><path d="M5.2 16.2h.9M6.5 16.2h.9"/>'
      + '<ellipse cx="11.2" cy="12.3" rx="1.8" ry="3.8"/><ellipse stroke-width=".9" cx="10.75" cy="11.7" rx=".95" ry="2.5"/><path d="M10.3 7.9h.9M11.6 7.9h.9"/>'
      + '<path stroke-width="1" d="M18.4 8.4h1.3a.8.8 0 0 1 .8.8v5.6a.8.8 0 0 1-.8.8h-1.3"/></g></g>',
    // Hyper-V's machine within a machine: a screen showing another
    hyperv: '<g stroke-width="1.5"><rect x="2.5" y="3.5" width="19" height="13" rx="1.6"/><path d="M12 16.5v3.4M8.6 20.5h6.8"/></g>'
      + '<g stroke-width="1.2"><rect x="7.4" y="6.6" width="9.2" height="5.6" rx=".8"/><path d="M12 12.2v1.5M10.2 13.9h3.6"/></g>',
  };
  const icon = (name, size = 16, cls = '') => SVG(PATHS[name] || PATHS.plug, cls, size);  // a name it lacks: the plug

  function progressRing(fraction, size) {
    const r = 9, c = 2 * Math.PI * r, f = Math.max(0.04, Math.min(1, fraction || 0));
    return `<svg class="ico" width="${size}" height="${size}" viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="${r}" fill="none" stroke="currentColor" stroke-opacity=".25" stroke-width="3"/>
      <circle cx="12" cy="12" r="${r}" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"
        stroke-dasharray="${(c * f).toFixed(2)} ${c.toFixed(2)}" transform="rotate(-90 12 12)"/></svg>`;
  }

  // Every state the server gives a row (gui/activity.py STATE_RANK) has its name here: one without
  // drew an empty chip and a check mark.
  const DATA_LABEL = {
    fetching: 'Fetching now', next: 'Next in line', backfilling: 'Backfilling history', queued: 'Queued for download',
    new: 'New data should be available', held: 'Held: updates paused', current: 'Up to date',
    blocked: 'Not collected by this feed', closed: 'Closed: archive complete',
    retired: 'Retired: no longer listed, history only',
  };

  // The words of a data-state icon, "Backfilling history (40%)": its title for a mouse and its name for a screen
  // reader; a finger hovers nothing (1.42.0: a long press shows them, touch.js), so a page may show them as text too.
  function dataLabel(d) {
    if (!d) return '';
    const pctText = d.state === 'backfilling' && d.progress != null ? ` (${Math.round(d.progress * 100)}%)` : '';
    return (DATA_LABEL[d.state] || d.state) + pctText;
  }

  // `d`: { state, progress } from /api/activity or /api/symbols. `{text: true}`: its words beside it as text (a page
  // asks for them on a touch screen: dataIcon(d, 14, {text: LiminalTouch.touch})).
  function dataIcon(d, size = 14, { text = false } = {}) {
    if (!d) return '';
    const words = dataLabel(d);
    const body = d.state === 'fetching' ? icon('sync', size, 'spin')
      : d.state === 'backfilling' ? progressRing(d.progress, size)
        : d.state === 'queued' ? icon('clock', size)
          : d.state === 'new' ? icon('download', size)
            : d.state === 'next' ? icon('next', size)
              : d.state === 'held' ? icon('pause', size)
                : icon('check', size);
    if (text) {
      return `<span class="data-icon ${esc(d.state)} with-text" style="display:inline-flex;align-items:center;gap:4px" title="${esc(words)}">`
        + `${body}<span class="data-text">${esc(words)}</span></span>`;
    }
    return `<span class="data-icon ${esc(d.state)}" title="${esc(words)}" role="img" aria-label="${esc(words)}">${body}</span>`;
  }

  // A logo that fails to load falls back to the lettered badge.
  document.addEventListener('error', (e) => {
    const img = e.target;
    if (!(img instanceof HTMLImageElement) || !img.classList.contains('sym-img')) return;
    const box = img.parentElement;
    box.classList.add('letter');
    box.style.background = box.dataset.color;
    img.replaceWith(document.createTextNode(box.dataset.letter || '?'));
  }, true);

  window.LiminalIcons = { symbolIcon, dataIcon, dataLabel, icon, DATA_LABEL, esc, safeUrl };
})();
