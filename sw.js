'use strict';

const CACHE_PREFIX = 'zm-academy-';
const CACHE_NAME = 'zm-academy-v5';
const CORE_FILES = [
  './',
  './index.html',
  './parent.html',
  './manifest.webmanifest',
  './assets/icon-192.png',
  './assets/icon-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await cache.addAll(CORE_FILES);
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys
      .filter(key => key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME)
      .map(key => caches.delete(key)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET' || request.headers.has('range')) return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // لا نخزن صفحات الحسابات أو الطلبات أو أي استجابات ديناميكية.
  const isNavigation = request.mode === 'navigate';
  const isCoreAsset = CORE_FILES.some(path => {
    const assetUrl = new URL(path, self.registration.scope);
    return assetUrl.href === url.href;
  });

  if (!isNavigation && !isCoreAsset) return;

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);

    if (isNavigation) {
      try {
        const response = await fetch(request);
        if (response && response.ok && response.type === 'basic') {
          const path = url.pathname;
          const scopePath = new URL(self.registration.scope).pathname;
          const isHome = path === scopePath || path === `${scopePath}index.html`;
          if (isHome) await cache.put(new URL('./index.html', self.registration.scope).href, response.clone());
        }
        return response;
      } catch (_) {
        const path = url.pathname;
        const scopePath = new URL(self.registration.scope).pathname;
        const isHome = path === scopePath || path === `${scopePath}index.html`;
        if (isHome) {
          const cachedHome = await cache.match(new URL('./index.html', self.registration.scope).href);
          if (cachedHome) return cachedHome;
        }
        return new Response('أنت غير متصل بالإنترنت. اتصل بالشبكة ثم حاول مرة أخرى.', {
          status: 503,
          statusText: 'Offline',
          headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
        });
      }
    }

    const cached = await cache.match(request);
    if (cached) return cached;

    try {
      const response = await fetch(request);
      if (response && response.ok && response.type === 'basic') {
        await cache.put(request, response.clone());
      }
      return response;
    } catch (_) {
      return new Response('تعذر تحميل الملف أثناء عدم الاتصال بالإنترنت.', {
        status: 503,
        statusText: 'Offline',
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
      });
    }
  })());
});
