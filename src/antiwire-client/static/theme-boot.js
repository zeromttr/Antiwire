// Paints the saved theme before any module loads, so the window never flashes
// the wrong palette. Plain script: it must run synchronously in <head>.
(function () {
  try {
    var pref = localStorage.getItem('antiwire-theme');
    if (pref && pref.charAt(0) === '{') {
      var boot = JSON.parse(pref);
      pref = boot.preference || boot.theme;
    }
    if (!pref || (pref !== 'light' && pref !== 'dark' && pref !== 'system')) {
      var raw = localStorage.getItem('antiwire-client-settings');
      if (raw) pref = JSON.parse(raw).theme;
    }
    if (pref !== 'light' && pref !== 'dark' && pref !== 'system') pref = 'system';
    var resolved =
      pref === 'system'
        ? window.matchMedia('(prefers-color-scheme: light)').matches
          ? 'light'
          : 'dark'
        : pref;
    document.documentElement.dataset.theme = resolved;
    document.documentElement.style.colorScheme = resolved;
    var css = localStorage.getItem('antiwire-theme-css');
    if (css) {
      var snapshot = JSON.parse(css);
      if (snapshot.theme === 'light' || snapshot.theme === 'dark') {
        document.documentElement.dataset.theme = snapshot.theme;
        document.documentElement.style.colorScheme = snapshot.theme;
      }
      var vars = snapshot.vars || {};
      // Keep in sync with THEME_SNAPSHOT_VARS in src/lib/models/theme-snapshot.ts
      var allowed = {
        '--acc-base': 1,
        '--acc-sub-base': 1,
        '--on-acc': 1
      };
      for (var name in vars) {
        if (
          Object.prototype.hasOwnProperty.call(vars, name) &&
          Object.prototype.hasOwnProperty.call(allowed, name)
        ) {
          document.documentElement.style.setProperty(name, vars[name]);
        }
      }
    }
  } catch {
    // Theme boot must never block the page.
  }
})();
