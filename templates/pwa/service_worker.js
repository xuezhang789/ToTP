const CACHE_VERSION = 'totp-cache-v1';
const STATIC_CACHE = `static-${CACHE_VERSION}`;
const APP_SHELL = [
  '/',
  '{{ dashboard_url }}',
  '{{ list_url }}',
  '{{ offline_url }}'
];

// 安装阶段预缓存核心页面，确保离线时可访问
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => cache.addAll(APP_SHELL)).then(() => self.skipWaiting())
  );
});

// 激活时清理旧缓存，避免无限增长
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.filter((key) => key !== STATIC_CACHE).map((key) => caches.delete(key))
    )).then(() => self.clients.claim())
  );
});

function isApiRequest(request) {
  return request.url.includes('/totp/api/');
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') {
    return;
  }

  if (isApiRequest(request)) {
    // 对 API 采用网络优先策略，失败则回退到缓存的数据
    event.respondWith(
      fetch(request)
        .then((response) => {
          const cloned = response.clone();
          caches.open(STATIC_CACHE).then((cache) => cache.put(request, cloned));
          return response;
        })
        .catch(() => caches.match(request))
    );
    return;
  }

  if (request.mode === 'navigate') {
    // 页面导航：网络优先，失败时落回离线占位页
    event.respondWith(
      fetch(request)
        .then((response) => {
          const cloned = response.clone();
          caches.open(STATIC_CACHE).then((cache) => cache.put(request, cloned));
          return response;
        })
        .catch(async () => {
          const cache = await caches.open(STATIC_CACHE);
          const cached = await cache.match(request);
          return cached || cache.match('{{ offline_url }}');
        })
    );
    return;
  }

  // 其他静态资源：缓存优先，必要时回源
  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) {
        return cached;
      }
      return fetch(request).then((response) => {
        const cloned = response.clone();
        caches.open(STATIC_CACHE).then((cache) => cache.put(request, cloned));
        return response;
      });
    })
  );
});
