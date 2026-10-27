/* LassiNet PWA shell cache.
 * Only static assets are cached. API/state, logs, metrics and the WebSocket are
 * always network-only: stale security data must never look live/offline.
 */
const CACHE = "lassinet-shell-3.61";
const ASSETS = [
  "./",
  "./index.html",
  "./style.css",
  "./app.js",
  "./sw-reset.js",
  "./vendor/vis-network.min.js",
  "./manifest.webmanifest",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/maskable-512.png"
];
const STATIC_PATHS = new Set([
  "/",
  "/index.html",
  "/style.css",
  "/app.js",
  "/sw-reset.js",
  "/vendor/vis-network.min.js",
  "/manifest.webmanifest",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/maskable-512.png"
]);

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/") || url.pathname === "/metrics") return;
  if (url.pathname === "/ws") return;

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).catch(() => caches.match("./index.html", { ignoreSearch: true }))
    );
    return;
  }

  // Never cache health/readiness, auth, docs, OpenAPI or any future dynamic
  // endpoint: only the explicit static shell is safe to serve from disk.
  if (!STATIC_PATHS.has(url.pathname)) return;

  event.respondWith(
    fetch(request).then((response) => {
      // Network-first for the static shell: a cached app.js after an update is
      // exactly how a new button can exist without its click handler.
      if (response.ok) {
        const copy = response.clone();
        caches.open(CACHE).then((cache) => cache.put(request, copy));
      }
      return response;
    }).catch(() => caches.match(request, { ignoreSearch: true }))
  );
});
