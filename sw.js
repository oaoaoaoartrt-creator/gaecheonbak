/* 개천박컴퍼니 서비스 워커
 * - 앱 화면(HTML, 아이콘, 이미지)을 버전별 캐시에 저장
 * - HTML은 네트워크 우선: 새 버전이 바로 반영되고, 오프라인일 때만 캐시 사용
 * - 채팅 서버(workers.dev) API와 WebSocket은 절대 캐시하지 않음
 */
var VERSION = "v2-20261118-media";
var SHELL_CACHE = "gcb-shell-" + VERSION;
var FONT_CACHE = "gcb-fonts-" + VERSION;

var SHELL = [
  "./",
  "./index.html",
  "./messenger.html",
  "./manifest.webmanifest",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/maskable-512.png",
  "./icons/apple-touch-icon.png",
  "./icons/favicon.ico",
  "./icons/favicon-48.png",
  "./images/seolpyo.jpg",
  "./images/taste.jpg"
];

var FONT_HOSTS = ["fonts.googleapis.com", "fonts.gstatic.com", "cdn.jsdelivr.net"];

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      .then(function (cache) { return cache.addAll(SHELL.map(function (u) { return new Request(u, { cache: "reload" }); })); })
      .then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys()
      .then(function (keys) {
        return Promise.all(keys.map(function (k) {
          if (k.indexOf("gcb-") === 0 && k !== SHELL_CACHE && k !== FONT_CACHE) return caches.delete(k);
        }));
      })
      .then(function () { return self.clients.claim(); })
  );
});

function isHTML(req) {
  return req.mode === "navigate" || (req.headers.get("accept") || "").indexOf("text/html") !== -1;
}

self.addEventListener("fetch", function (event) {
  var req = event.request;
  if (req.method !== "GET") return;
  var url = new URL(req.url);
  if (url.protocol !== "https:" && url.protocol !== "http:") return;

  var sameOrigin = url.origin === self.location.origin;
  var scopePath = new URL(self.registration.scope).pathname;

  /* 다른 도메인: 글꼴만 캐시, 나머지(채팅 API 등)는 손대지 않음 */
  if (!sameOrigin) {
    if (FONT_HOSTS.indexOf(url.hostname) !== -1 && url.hostname.indexOf("workers.dev") === -1) {
      event.respondWith(cacheFirst(req, FONT_CACHE));
    }
    return;
  }
  if (url.pathname.indexOf(scopePath) !== 0) return;

  if (isHTML(req)) {
    event.respondWith(networkFirstHTML(req));
  } else {
    event.respondWith(staleWhileRevalidate(req));
  }
});

function networkFirstHTML(req) {
  return fetch(req).then(function (res) {
    if (res && res.ok) {
      var copy = res.clone();
      caches.open(SHELL_CACHE).then(function (c) { c.put(req, copy); });
    }
    return res;
  }).catch(function () {
    return caches.open(SHELL_CACHE).then(function (c) {
      return c.match(req, { ignoreSearch: true }).then(function (hit) {
        return hit || c.match("./messenger.html");
      });
    });
  });
}

function staleWhileRevalidate(req) {
  return caches.open(SHELL_CACHE).then(function (c) {
    return c.match(req).then(function (hit) {
      var net = fetch(req).then(function (res) {
        if (res && res.ok) c.put(req, res.clone());
        return res;
      });
      if (hit) { net.catch(function () {}); return hit; }
      return net;
    });
  });
}

function cacheFirst(req, name) {
  return caches.open(name).then(function (c) {
    return c.match(req).then(function (hit) {
      if (hit) return hit;
      return fetch(req).then(function (res) {
        if (res && (res.ok || res.type === "opaque")) c.put(req, res.clone());
        return res;
      });
    });
  });
}
