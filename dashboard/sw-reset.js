/*
 * One-time cache reset for UI upgrades.
 *
 * Older PWA service workers used cache-first for app.js/style.css. A browser
 * could therefore keep an old Flows button (new index.html) with an old app.js
 * (no click handler). This tiny script is a new URL, so the old worker cannot
 * serve it from its cache. It unregisters workers, clears CacheStorage and
 * reloads once. The marker makes it a no-op after the first successful load.
 */
(function () {
  var VERSION = "3.61";
  var MARK = "lassi.cache-reset." + VERSION;
  var RELOADED = "lassi.cache-reload." + VERSION;
  try {
    if (localStorage.getItem(MARK) === "1") return;
    localStorage.setItem(MARK, "1");
  } catch (e) {
    return;                         // storage disabled: do not loop
  }

  function reloadOnce() {
    try {
      if (sessionStorage.getItem(RELOADED) === "1") return;
      sessionStorage.setItem(RELOADED, "1");
      location.reload();
    } catch (e) { /* ignore */ }
  }

  var tasks = [];
  try {
    if ("serviceWorker" in navigator) {
      tasks.push(navigator.serviceWorker.getRegistrations().then(function (regs) {
        return Promise.all(regs.map(function (reg) { return reg.unregister(); }));
      }));
    }
  } catch (e) { /* ignore */ }
  try {
    if (window.caches) {
      tasks.push(caches.keys().then(function (keys) {
        return Promise.all(keys.map(function (key) { return caches.delete(key); }));
      }));
    }
  } catch (e) { /* ignore */ }
  Promise.all(tasks).then(reloadOnce, reloadOnce);
})();
