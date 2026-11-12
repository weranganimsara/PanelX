/* ==========================================================================
   PanelX Progressive Web App (PWA) Service Worker
   Version: 2.1.0
   Scope: High-Performance Linux VPS SSH/VPN Control Panel Shell
   ========================================================================== */

const CACHE_NAME = 'panelx-shell-v2.1.0';
const STATIC_ASSETS = [
  './',
  'manifest.webmanifest',
  'assets/logo.svg',
  'assets/icon-192.png',
  'assets/icon-512.png',
  'assets/apple-touch-icon.png',
  'favicon.ico'
];

// Install: Cache Shell Assets & Skip Waiting
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('[PWA] Cache pre-fetch non-fatal issue:', err);
      });
    }).then(() => self.skipWaiting())
  );
});

// Activate: Clean up old cache versions and claim clients immediately
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('[PWA] Purging outdated cache:', key);
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch Interceptor:
// 1. Never cache /api/ endpoints (real-time telemetry & mutating requests)
// 2. Network-first for HTML pages (so server updates show immediately)
// 3. Stale-while-revalidate for static assets & icons
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Bypass any non-GET requests or API requests completely
  if (req.method !== 'GET' || url.pathname.includes('/api/')) {
    return;
  }

  // HTML Navigation: Network first, fallback to cached index
  if (req.mode === 'navigate' || req.headers.get('accept')?.includes('text/html')) {
    event.respondWith(
      fetch(req)
        .then((networkRes) => {
          if (networkRes && networkRes.status === 200) {
            const resClone = networkRes.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
          }
          return networkRes;
        })
        .catch(() => caches.match(req).then((cached) => cached || caches.match('./')))
    );
    return;
  }

  // Static Assets (Images, Icons, Fonts, Manifest): Stale-While-Revalidate
  event.respondWith(
    caches.match(req).then((cachedRes) => {
      const fetchPromise = fetch(req).then((networkRes) => {
        if (networkRes && networkRes.status === 200) {
          const resClone = networkRes.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
        }
        return networkRes;
      }).catch(() => null);

      return cachedRes || fetchPromise;
    })
  );
});
