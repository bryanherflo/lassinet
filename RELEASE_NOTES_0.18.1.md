# LassiNet 0.18.1 — UI update and map stability fixes

> **Status: pre-release / beta.** No behavior change to capture or firewall.

This is a bug-fix release for the 0.18 flow-history UI.

## Fixed

- **Flows button could do nothing after an update**: the PWA service worker
  could serve an old `app.js` with a new `index.html`. Static assets are now
  network-first, and a one-time `sw-reset.js` clears old workers/caches and
  reloads automatically. Manual clearing is still documented as a fallback.
- **The map no longer re-fits itself on every topology refresh.** It fits once
  on first load and when you press `R`/Fit; new devices can still reflow the
  tree, but the viewport is not yanked around.
- **Traffic particles at the map edge** are skipped when their coordinates are
  outside the canvas.
- UI cache is **`v=3.58`**.

## Notes

- White/cyan dots are normal traffic; red dots are attack flows. If they are
  distracting, press `D` to hide them.
- If an old browser still shows a no-op Flows button, clear site data once:
  DevTools → Application → Service Workers → Unregister, then Storage →
  Clear site data, and reload.
- 260 tests; CI on Ubuntu and Windows.

## Install / update

```powershell
git pull
# Ctrl+C the running server, then:
python run.py --live --fw mock
```

For the first load after this update the page may reload once while the old
cache is cleared. That is expected.
