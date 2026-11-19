/* 개천박컴퍼니 서비스 워커
 * - 앱 화면(HTML, 아이콘, 이미지)을 버전별 캐시에 저장
 * - HTML은 네트워크 우선: 새 버전이 바로 반영되고, 오프라인일 때만 캐시 사용
 * - 채팅 서버(workers.dev) API와 WebSocket은 절대 캐시하지 않음
 */
var VERSION = "v42-20261119-callchat-intro";
var SHELL_CACHE = "gcb-shell-" + VERSION;
var FONT_CACHE = "gcb-fonts-v2"; // 버전과 무관하게 유지 (업데이트마다 글꼴을 다시 받지 않게)

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
  "./icons/badge-96.png",
  "./images/seolpyo.jpg",
  "./images/taste.jpg",
  "./images/staff1.jpg",
  "./images/staff2.jpg",
  "./images/staff3.jpg",
  "./images/staff4.jpg",
  "./images/staff5.jpg",
  "./images/staff6.jpg",
  "./images/notice-notifications.png",
  "./images/notice-install.png"
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

/* ---------- 알림 (웹 푸시) ---------- */
self.addEventListener("push", function (event) {
  var data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) { data = { title: "개천박컴퍼니", body: event.data ? event.data.text() : "" }; }
  var title = String(data.title || "개천박컴퍼니 사내 메신저").slice(0, 80);
  var url = typeof data.url === "string" && /^messenger\.html(#[\w\/?=&%-]*)?$/.test(data.url) ? data.url : "messenger.html";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (list) {
      // 앱을 보고 있는 중이면 화면 안에서 알림(소리·배지)만 처리
      var focused = list.filter(function (c) { return c.visibilityState === "visible" && c.focused; });
      list.forEach(function (c) { c.postMessage({ type: "push", data: data }); });
      if (focused.length) return;
      if (self.navigator && self.navigator.setAppBadge) { try { self.navigator.setAppBadge(); } catch (e) {} }
      return self.registration.showNotification(title, {
        body: String(data.body || "").slice(0, 200),
        icon: "./icons/icon-192.png",
        badge: "./icons/badge-96.png",
        tag: data.tag || "gcb",
        renotify: true,
        data: { url: url }
      });
    })
  );
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var target = new URL((event.notification.data && event.notification.data.url) || "messenger.html", self.registration.scope).href;
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (list) {
      for (var i = 0; i < list.length; i++) {
        var c = list[i];
        if (c.url.indexOf(self.registration.scope) === 0 && "focus" in c) {
          c.postMessage({ type: "open", url: target });
          return c.focus();
        }
      }
      return self.clients.openWindow(target);
    })
  );
});

