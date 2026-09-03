const CACHE_VERSION = 'glp1-shell-v1';
const APP_SHELL = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './db.js',
  './crypto.js',
  './validation.js',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_VERSION).then((cache) => cache.addAll(APP_SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE_VERSION).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

const APP_SHELL_URLS = new Set(APP_SHELL.map((path) => new URL(path, self.location.href).href));

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  const canonicalUrl = new URL(url.href);
  canonicalUrl.search = '';
  canonicalUrl.hash = '';
  if (!APP_SHELL_URLS.has(canonicalUrl.href)) {
    // Never place unrecognized requests into CacheStorage.
    event.respondWith(fetch(request));
    return;
  }

  // Cache only the fixed app shell. Health data has no network endpoint and never enters CacheStorage.
  event.respondWith(
    caches.match(request, { ignoreSearch: true }).then((cached) => cached || fetch(request).then((response) => {
      if (!response || !response.ok || response.type !== 'basic') return response;
      const copy = response.clone();
      caches.open(CACHE_VERSION).then((cache) => cache.put(canonicalUrl.href, copy)).catch(() => {});
      return response;
    })).catch(() => caches.match('./index.html')),
  );
});
