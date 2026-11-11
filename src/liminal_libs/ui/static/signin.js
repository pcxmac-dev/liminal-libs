// An app's sign-in while it inherits a login app (liminal-libs 1.46.0): the login app's page held in a frame, through this
// app at /login/ (in this page's theme); once that page says you are signed in, this app's own page opens (the address
// loaded again: the app serves its page now). The tab's title is the app's own (GET api/app); the login's card names it.
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  fetch('api/app').then((r) => r.json()).then((a) => {
    if (a && a.title) document.title = `${a.title}: sign in`;
  }).catch(() => null);
  const frame = $('signinFrame');
  Promise.resolve(window.LiminalTheme && window.LiminalTheme.ready).catch(() => null).then(() => {
    const theme = document.body.dataset.theme;
    frame.src = `login/?embedded=1${theme ? `&theme=${encodeURIComponent(theme)}` : ''}`;
  });
  window.addEventListener('message', (e) => {
    // the login page held here says who signed in (liminal-login's login.js, embedded)
    if (e.origin !== location.origin || !e.data || e.data.liminal !== 'login') return;
    if (e.data.signedIn) location.reload();
  });
})();
