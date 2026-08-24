// Service worker: offline app shell only. Network-first so updates land
// immediately; cache is the fallback when offline. API responses are never
// cached — the vault exists only encrypted on the server and decrypted in
// page memory, never in cache storage.
const CACHE = "gk-shell-v4";
const SHELL = [
  "/", "/style.css", "/app.js", "/crypto.js", "/import.js", "/totp.js", "/icon.svg", "/manifest.json",
  "/icon-192.png", "/icon-512.png", "/apple-touch-icon.png",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.pathname.startsWith("/api/")) return;
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy));
        return res;
      })
      .catch(() => caches.match(e.request, { ignoreSearch: url.pathname === "/" }))
  );
});
