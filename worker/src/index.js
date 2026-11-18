// 개천박컴퍼니 사내메신저 API (Cloudflare Workers + D1 + Durable Objects)
import { DurableObject } from "cloudflare:workers";

const PBKDF2_ITER = 100000;          // Workers WebCrypto 상한(100,000회)
const SESSION_DAYS = 30;
const MAX_MSG = 500;
const MAX_NICK = 20;
const RECENT_LIMIT = 100;

/* 이미지 (D1 BLOB 저장 — 무료 요금제, R2 미사용) */
const IMG_RULES = {
  avatar:   { maxBytes: 512 * 1024,  maxDim: 1024 },
  emoticon: { maxBytes: 512 * 1024,  maxDim: 512 },
  photo:    { maxBytes: 1024 * 1024, maxDim: 4096 },
};
const MAX_EMOTICONS = 50;
const MAX_EMO_NAME = 20;
const STORAGE_CAP = 400 * 1024 * 1024;   // D1 무료 DB 한도(500MB) 전에 업로드를 막아 텍스트 채팅을 보호
const IMG_ID_RE = /^[0-9a-f]{32}$/;

const enc = new TextEncoder();
const now = () => Date.now();

/* ---------- 유틸 ---------- */
function b64(buf) {
  let s = "";
  const a = new Uint8Array(buf);
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s);
}
function fromB64(str) {
  const bin = atob(str);
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}
function randomToken(bytes = 32) {
  const a = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(a, (x) => x.toString(16).padStart(2, "0")).join("");
}
async function sha256Hex(str) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return Array.from(new Uint8Array(d), (x) => x.toString(16).padStart(2, "0")).join("");
}
async function pbkdf2(password, salt, iter) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256);
  return new Uint8Array(bits);
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}
const charLen = (s) => [...s].length;
// 줄바꿈·탭을 제외한 제어문자 제거
const stripCtl = (s, allowNewline) =>
  s.replace(allowNewline ? /[\u0000-\u0008\u000B-\u001F\u007F\u2028\u2029]/g : /[\u0000-\u001F\u007F\u2028\u2029]/g, "");

function normLogin(v) {
  if (typeof v !== "string") return null;
  const s = v.trim().toLowerCase();
  return /^[a-z0-9._@+-]{3,64}$/.test(s) ? s : null;
}
function normNick(v) {
  if (typeof v !== "string") return null;
  const s = stripCtl(v, false).trim();
  const n = charLen(s);
  return n >= 1 && n <= MAX_NICK ? s : null;
}
function normText(v) {
  if (typeof v !== "string") return null;
  const s = stripCtl(v.replace(/\r\n?/g, "\n"), true).replace(/^\s+|\s+$/g, "");
  const n = charLen(s);
  return n >= 1 && n <= MAX_MSG ? s : null;
}

/* ---------- 이미지 검사 (매직 바이트 + 크기) ---------- */
function sniffImage(a) {
  if (a.length < 16) return null;
  const ascii = (o, n) => String.fromCharCode(...a.subarray(o, o + n));
  if (a[0] === 0xff && a[1] === 0xd8 && a[2] === 0xff) return "image/jpeg";
  if (a[0] === 0x89 && ascii(1, 3) === "PNG" && a[4] === 0x0d && a[5] === 0x0a && a[6] === 0x1a && a[7] === 0x0a) return "image/png";
  if (ascii(0, 6) === "GIF87a" || ascii(0, 6) === "GIF89a") return "image/gif";
  if (ascii(0, 4) === "RIFF" && ascii(8, 4) === "WEBP") return "image/webp";
  return null;
}
function imageSize(a, mime) {
  const u16be = (o) => (a[o] << 8) | a[o + 1];
  const u16le = (o) => a[o] | (a[o + 1] << 8);
  const u24le = (o) => a[o] | (a[o + 1] << 8) | (a[o + 2] << 16);
  const u32be = (o) => ((a[o] << 24) >>> 0) + (a[o + 1] << 16) + (a[o + 2] << 8) + a[o + 3];
  try {
    if (mime === "image/png") {
      if (String.fromCharCode(...a.subarray(12, 16)) !== "IHDR") return null;
      return { w: u32be(16), h: u32be(20) };
    }
    if (mime === "image/gif") return { w: u16le(6), h: u16le(8) };
    if (mime === "image/webp") {
      const fourcc = String.fromCharCode(...a.subarray(12, 16));
      if (fourcc === "VP8 " && a.length >= 30) return { w: u16le(26) & 0x3fff, h: u16le(28) & 0x3fff };
      if (fourcc === "VP8L" && a.length >= 25 && a[20] === 0x2f) {
        const b = a[21] | (a[22] << 8) | (a[23] << 16) | (a[24] << 24);
        return { w: (b & 0x3fff) + 1, h: ((b >> 14) & 0x3fff) + 1 };
      }
      if (fourcc === "VP8X" && a.length >= 30) return { w: u24le(24) + 1, h: u24le(27) + 1 };
      return null;
    }
    if (mime === "image/jpeg") {
      let o = 2;
      while (o + 9 < a.length) {
        if (a[o] !== 0xff) { o++; continue; }
        const m = a[o + 1];
        if (m === 0xff) { o++; continue; }
        if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { o += 2; continue; }
        const len = u16be(o + 2);
        if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) return { w: u16be(o + 7), h: u16be(o + 5) };
        if (m === 0xda || len < 2) return null;
        o += 2 + len;
      }
    }
  } catch {}
  return null;
}
// 요청 본문을 크기 제한 안에서 읽고 검사. 실패 시 오류 코드 문자열 반환
async function readImage(req, purpose) {
  const rule = IMG_RULES[purpose];
  const declared = (req.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase();
  if (!["image/jpeg", "image/png", "image/webp", "image/gif"].includes(declared)) return { error: "unsupported_type", status: 415 };
  const lenHdr = req.headers.get("Content-Length");
  if (lenHdr === null) return { error: "length_required", status: 411 };
  const len = Number(lenHdr);
  if (!Number.isFinite(len) || len <= 0) return { error: "bad_request", status: 400 };
  if (len > rule.maxBytes) return { error: "too_large", status: 413 };
  const buf = new Uint8Array(await req.arrayBuffer());
  if (buf.length === 0 || buf.length > rule.maxBytes) return { error: "too_large", status: 413 };
  const mime = sniffImage(buf);
  if (!mime || mime !== declared) return { error: "unsupported_type", status: 415 };
  const dim = imageSize(buf, mime);
  if (!dim || !dim.w || !dim.h) return { error: "unsupported_type", status: 415 };
  if (dim.w > rule.maxDim || dim.h > rule.maxDim) return { error: "too_large", status: 413 };
  return { buf, mime, w: dim.w, h: dim.h };
}
async function storeImage(env, userId, purpose, img) {
  const used = await env.DB.prepare("SELECT COALESCE(SUM(size), 0) AS s FROM images").first();
  if (used.s + img.buf.length > STORAGE_CAP) return null;
  const id = randomToken(16);
  await env.DB.prepare("INSERT INTO images (id, user_id, purpose, mime, size, w, h, created_at, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id, userId, purpose, img.mime, img.buf.length, img.w, img.h, now(), img.buf).run();
  return id;
}
// 메시지·프로필·이모티콘 어디에서도 쓰지 않는 이미지만 삭제
async function dropImageIfUnused(env, id) {
  if (!id) return;
  await env.DB.prepare(
    `DELETE FROM images WHERE id = ?1
       AND NOT EXISTS (SELECT 1 FROM messages WHERE image_id = ?1)
       AND NOT EXISTS (SELECT 1 FROM users WHERE avatar_id = ?1)
       AND NOT EXISTS (SELECT 1 FROM emoticons WHERE image_id = ?1)`
  ).bind(id).run();
}
function normEmoName(v) {
  if (typeof v !== "string") return null;
  const s = stripCtl(v, false).trim();
  const n = charLen(s);
  return n >= 1 && n <= MAX_EMO_NAME ? s : null;
}

/* ---------- CORS / 응답 ---------- */
function allowedOrigins(env) {
  return (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
}
function corsHeaders(origin, env) {
  const h = { "Vary": "Origin" };
  if (origin && allowedOrigins(env).includes(origin)) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS";
    h["Access-Control-Allow-Headers"] = "Authorization, Content-Type";
    h["Access-Control-Max-Age"] = "86400";
  }
  return h;
}
function json(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...cors },
  });
}
const fail = (code, status, cors) => json({ error: code }, status, cors);

async function readJson(req) {
  const len = Number(req.headers.get("Content-Length") || 0);
  if (len > 8192) return null;
  const txt = await req.text();
  if (txt.length > 8192) return null;
  try { const v = JSON.parse(txt); return v && typeof v === "object" ? v : null; } catch { return null; }
}

/* ---------- 속도 제한 (고정 창) ---------- */
async function hit(env, key, limit, windowMs) {
  const t = now();
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (key, window_start, count) VALUES (?1, ?2, 1)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN window_start <= ?2 - ?3 THEN 1 ELSE count + 1 END,
       window_start = CASE WHEN window_start <= ?2 - ?3 THEN ?2 ELSE window_start END
     RETURNING count`
  ).bind(key, t, windowMs).first();
  return row.count <= limit;
}

/* ---------- 세션 ---------- */
async function createSession(env, userId) {
  const token = randomToken(32);
  const t = now();
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
    .bind(await sha256Hex(token), userId, t, t + SESSION_DAYS * 86400000).run();
  return token;
}
export async function userFromToken(env, token) {
  if (!token || typeof token !== "string" || !/^[0-9a-f]{64}$/.test(token)) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.login, u.nickname, u.avatar_id FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  ).bind(await sha256Hex(token), now()).first();
  return row || null;
}
function bearer(req) {
  const h = req.headers.get("Authorization") || "";
  const m = /^Bearer\s+([0-9a-f]{64})$/i.exec(h);
  return m ? m[1].toLowerCase() : null;
}
const publicUser = (u) => ({ id: u.id, login: u.login, nickname: u.nickname || "", avatarId: u.avatar_id || null });
const publicMsg = (m) => ({
  id: m.id, userId: m.user_id, nickname: m.nickname, kind: m.kind || "text", text: m.text,
  image: m.image_id ? { id: m.image_id, w: m.w || 0, h: m.h || 0 } : null,
  avatarId: m.avatar_id || null, createdAt: m.created_at,
});
const MSG_SELECT = `SELECT m.id, m.user_id, m.nickname, m.kind, m.text, m.image_id, m.created_at, i.w, i.h, u.avatar_id
  FROM messages m LEFT JOIN users u ON u.id = m.user_id LEFT JOIN images i ON i.id = m.image_id`;
async function insertMessage(env, user, kind, text, imageId) {
  const r = await env.DB.prepare(
    "INSERT INTO messages (user_id, nickname, text, created_at, kind, image_id) VALUES (?, ?, ?, ?, ?, ?) RETURNING id"
  ).bind(user.id, user.nickname, text, now(), kind, imageId).first();
  return publicMsg(await env.DB.prepare(MSG_SELECT + " WHERE m.id = ?").bind(r.id).first());
}
function broadcast(env, ctx, payload) {
  const stub = env.ROOM.get(env.ROOM.idFromName("main"));
  ctx.waitUntil(stub.fetch("https://room/broadcast", { method: "POST", body: JSON.stringify(payload) }).catch(() => {}));
}
const publicEmo = (e) => ({ id: e.id, userId: e.user_id, nickname: e.nickname || "", name: e.name, imageId: e.image_id, createdAt: e.created_at });

/* ---------- 라우터 ---------- */
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin");
    const cors = corsHeaders(origin, env);
    const originOk = !origin || allowedOrigins(env).includes(origin);

    if (req.method === "OPTIONS") {
      return new Response(null, { status: originOk ? 204 : 403, headers: cors });
    }
    if (!originOk) return fail("origin_not_allowed", 403, cors);

    const path = url.pathname;
    const ip = req.headers.get("CF-Connecting-IP") || "unknown";

    try {
      if (path === "/" || path === "/api/health") return json({ ok: true, service: "gaecheonbak-chat" }, 200, cors);

      // 이미지 제공: 추측 불가능한 128비트 ID로만 접근 (img 태그는 인증 헤더를 보낼 수 없음)
      if (path.startsWith("/img/") && (req.method === "GET" || req.method === "HEAD")) {
        const id = path.slice(5);
        const base = { "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox", "Cross-Origin-Resource-Policy": "cross-origin", ...cors };
        if (!IMG_ID_RE.test(id)) return new Response("not found", { status: 404, headers: { ...base, "Cache-Control": "no-store" } });
        const row = await env.DB.prepare("SELECT mime, size, data FROM images WHERE id = ?").bind(id).first();
        if (!row) return new Response("not found", { status: 404, headers: { ...base, "Cache-Control": "no-store" } });
        const body = new Uint8Array(row.data);
        return new Response(req.method === "HEAD" ? null : body, {
          headers: { ...base, "Content-Type": row.mime, "Content-Length": String(body.length), "Content-Disposition": "inline", "Cache-Control": "public, max-age=31536000, immutable" },
        });
      }

      // 실시간 연결 (WebSocket → Durable Object)
      if (path === "/api/ws") {
        if (req.headers.get("Upgrade") !== "websocket") return fail("upgrade_required", 426, cors);
        if (!origin) return fail("origin_required", 403, cors);
        if (!(await hit(env, "ws:" + ip, 60, 60000))) return fail("rate_limited", 429, cors);
        const stub = env.ROOM.get(env.ROOM.idFromName("main"));
        return stub.fetch("https://room/ws", req);
      }

      if (path === "/api/signup" && req.method === "POST") {
        const body = await readJson(req);
        if (!body) return fail("bad_request", 400, cors);
        const login = normLogin(body.login);
        const pw = typeof body.password === "string" ? body.password : "";
        if (!login) return fail("invalid_login", 400, cors);
        if (pw.length < 8 || pw.length > 128) return fail("weak_password", 400, cors);
        if (!(await hit(env, "signup:" + ip, 10, 3600000))) return fail("rate_limited", 429, cors);
        const exists = await env.DB.prepare("SELECT 1 FROM users WHERE login = ?").bind(login).first();
        if (exists) return fail("login_taken", 409, cors);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const hash = await pbkdf2(pw, salt, PBKDF2_ITER);
        let user;
        try {
          user = await env.DB.prepare(
            "INSERT INTO users (login, pw_hash, pw_salt, pw_iter, nickname, created_at) VALUES (?, ?, ?, ?, '', ?) RETURNING id, login, nickname"
          ).bind(login, b64(hash), b64(salt), PBKDF2_ITER, now()).first();
        } catch (e) {
          if (String(e).includes("UNIQUE")) return fail("login_taken", 409, cors);
          throw e;
        }
        const token = await createSession(env, user.id);
        return json({ token, user: publicUser(user) }, 201, cors);
      }

      if (path === "/api/login" && req.method === "POST") {
        const body = await readJson(req);
        if (!body) return fail("bad_request", 400, cors);
        const login = normLogin(body.login);
        const pw = typeof body.password === "string" ? body.password : "";
        if (!login || !pw || pw.length > 128) return fail("invalid_credentials", 401, cors);
        if (!(await hit(env, "login-ip:" + ip, 30, 600000)) || !(await hit(env, "login-id:" + login, 10, 600000))) {
          return fail("rate_limited", 429, cors);
        }
        const u = await env.DB.prepare("SELECT id, login, nickname, avatar_id, pw_hash, pw_salt, pw_iter FROM users WHERE login = ?").bind(login).first();
        if (!u) {
          await pbkdf2(pw, crypto.getRandomValues(new Uint8Array(16)), PBKDF2_ITER); // 시간 차 줄이기
          return fail("invalid_credentials", 401, cors);
        }
        const got = await pbkdf2(pw, fromB64(u.pw_salt), u.pw_iter);
        if (!timingSafeEqual(got, fromB64(u.pw_hash))) return fail("invalid_credentials", 401, cors);
        const token = await createSession(env, u.id);
        return json({ token, user: publicUser(u) }, 200, cors);
      }

      // 이하 로그인 필요
      const token = bearer(req);
      const user = await userFromToken(env, token);
      if (!user) return fail("unauthorized", 401, cors);

      if (path === "/api/logout" && req.method === "POST") {
        await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256Hex(token)).run();
        return json({ ok: true }, 200, cors);
      }

      if (path === "/api/me" && req.method === "GET") return json({ user: publicUser(user) }, 200, cors);

      if (path === "/api/nickname" && req.method === "POST") {
        const body = await readJson(req);
        const nick = body && normNick(body.nickname);
        if (!nick) return fail("invalid_nickname", 400, cors);
        if (!(await hit(env, "nick:" + user.id, 20, 600000))) return fail("rate_limited", 429, cors);
        await env.DB.prepare("UPDATE users SET nickname = ? WHERE id = ?").bind(nick, user.id).run();
        broadcast(env, ctx, { type: "profile", user: { id: user.id, nickname: nick, avatarId: user.avatar_id || null } });
        return json({ user: { ...publicUser(user), nickname: nick } }, 200, cors);
      }

      if (path === "/api/messages" && req.method === "GET") {
        const after = url.searchParams.get("after");
        let rows;
        if (after !== null) {
          const a = Number(after);
          if (!Number.isInteger(a) || a < 0) return fail("bad_request", 400, cors);
          rows = await env.DB.prepare(MSG_SELECT + " WHERE m.id > ? ORDER BY m.id ASC LIMIT 200").bind(a).all();
          return json({ messages: rows.results.map(publicMsg) }, 200, cors);
        }
        rows = await env.DB.prepare(MSG_SELECT + " ORDER BY m.id DESC LIMIT ?").bind(RECENT_LIMIT).all();
        return json({ messages: rows.results.reverse().map(publicMsg) }, 200, cors);
      }

      // 텍스트 또는 이모티콘 메시지
      if (path === "/api/messages" && req.method === "POST") {
        const body = await readJson(req);
        if (!body) return fail("bad_request", 400, cors);
        if (!user.nickname) return fail("nickname_required", 400, cors);
        if (body.emoticonId !== undefined) {
          const eid = Number(body.emoticonId);
          if (!Number.isInteger(eid) || eid <= 0) return fail("bad_request", 400, cors);
          const emo = await env.DB.prepare("SELECT id, name, image_id FROM emoticons WHERE id = ?").bind(eid).first();
          if (!emo) return fail("emoticon_not_found", 404, cors);
          if (!(await hit(env, "post:" + user.id, 30, 60000))) return fail("rate_limited", 429, cors);
          const msg = await insertMessage(env, user, "emoticon", emo.name, emo.image_id);
          broadcast(env, ctx, { type: "message", message: msg });
          return json({ message: msg }, 201, cors);
        }
        const text = normText(body.text);
        if (!text) return fail("invalid_message", 400, cors);
        if (!(await hit(env, "post:" + user.id, 30, 60000))) return fail("rate_limited", 429, cors);
        const msg = await insertMessage(env, user, "text", text, null);
        broadcast(env, ctx, { type: "message", message: msg });
        return json({ message: msg }, 201, cors);
      }

      // 사진 메시지 (본문 = 이미지 바이트)
      if (path === "/api/photos" && req.method === "POST") {
        if (!user.nickname) return fail("nickname_required", 400, cors);
        if (!(await hit(env, "upload:" + user.id, 30, 600000)) || !(await hit(env, "upload-day:" + user.id, 300, 86400000))) return fail("rate_limited", 429, cors);
        const img = await readImage(req, "photo");
        if (img.error) return fail(img.error, img.status, cors);
        const id = await storeImage(env, user.id, "photo", img);
        if (!id) return fail("storage_full", 507, cors);
        const msg = await insertMessage(env, user, "image", "", id);
        broadcast(env, ctx, { type: "message", message: msg });
        return json({ message: msg }, 201, cors);
      }

      // 프로필 사진 등록·변경 / 삭제
      if (path === "/api/avatar" && (req.method === "POST" || req.method === "DELETE")) {
        if (!(await hit(env, "avatar:" + user.id, 10, 600000))) return fail("rate_limited", 429, cors);
        let id = null;
        if (req.method === "POST") {
          const img = await readImage(req, "avatar");
          if (img.error) return fail(img.error, img.status, cors);
          id = await storeImage(env, user.id, "avatar", img);
          if (!id) return fail("storage_full", 507, cors);
        }
        await env.DB.prepare("UPDATE users SET avatar_id = ? WHERE id = ?").bind(id, user.id).run();
        await dropImageIfUnused(env, user.avatar_id);
        const pu = { ...publicUser(user), avatarId: id };
        broadcast(env, ctx, { type: "profile", user: { id: pu.id, nickname: pu.nickname, avatarId: id } });
        return json({ user: pu }, 200, cors);
      }

      // 이모티콘 목록 (mine | all)
      if (path === "/api/emoticons" && req.method === "GET") {
        const scope = url.searchParams.get("scope") === "all" ? "all" : "mine";
        const sql = `SELECT e.id, e.user_id, e.name, e.image_id, e.created_at, u.nickname FROM emoticons e LEFT JOIN users u ON u.id = e.user_id`;
        const rows = scope === "all"
          ? await env.DB.prepare(sql + " ORDER BY e.id DESC LIMIT 500").all()
          : await env.DB.prepare(sql + " WHERE e.user_id = ? ORDER BY e.id DESC").bind(user.id).all();
        return json({ emoticons: rows.results.map(publicEmo), max: MAX_EMOTICONS }, 200, cors);
      }

      // 이모티콘 만들기 (본문 = 이미지 바이트, 이름은 ?name=)
      if (path === "/api/emoticons" && req.method === "POST") {
        const name = normEmoName(url.searchParams.get("name"));
        if (!name) return fail("invalid_emoticon_name", 400, cors);
        if (!(await hit(env, "emo:" + user.id, 30, 3600000))) return fail("rate_limited", 429, cors);
        const cnt = await env.DB.prepare("SELECT COUNT(*) AS c FROM emoticons WHERE user_id = ?").bind(user.id).first();
        if (cnt.c >= MAX_EMOTICONS) return fail("emoticon_limit", 409, cors);
        const img = await readImage(req, "emoticon");
        if (img.error) return fail(img.error, img.status, cors);
        const imageId = await storeImage(env, user.id, "emoticon", img);
        if (!imageId) return fail("storage_full", 507, cors);
        const e = await env.DB.prepare(
          "INSERT INTO emoticons (user_id, name, image_id, created_at) VALUES (?, ?, ?, ?) RETURNING id, user_id, name, image_id, created_at"
        ).bind(user.id, name, imageId, now()).first();
        return json({ emoticon: publicEmo({ ...e, nickname: user.nickname }) }, 201, cors);
      }

      // 내 이모티콘 삭제 (이미 보낸 메시지의 이모티콘은 그대로 남음)
      const emoDel = /^\/api\/emoticons\/(\d{1,12})$/.exec(path);
      if (emoDel && req.method === "DELETE") {
        const e = await env.DB.prepare("DELETE FROM emoticons WHERE id = ? AND user_id = ? RETURNING image_id").bind(Number(emoDel[1]), user.id).first();
        if (!e) return fail("emoticon_not_found", 404, cors);
        await dropImageIfUnused(env, e.image_id);
        return json({ ok: true }, 200, cors);
      }

      return fail("not_found", 404, cors);
    } catch (e) {
      console.error(e && e.stack || e);
      return fail("server_error", 500, cors);
    }
  },

  // 만료된 세션과 오래된 속도 제한 기록 정리 (하루 한 번)
  async scheduled(event, env) {
    const t = now();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(t),
      env.DB.prepare("DELETE FROM rate_limits WHERE window_start <= ?").bind(t - 86400000),
    ]);
  },
};

/* ---------- 실시간 방 (WebSocket Hibernation) ---------- */
export class ChatRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('{"type":"ping"}', '{"type":"pong"}'));
  }

  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/ws") {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server);
      server.serializeAttachment({ uid: 0, at: Date.now() });
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/broadcast" && req.method === "POST") {
      const payload = await req.text();
      for (const ws of this.ctx.getWebSockets()) {
        const a = ws.deserializeAttachment() || {};
        if (a.uid) { try { ws.send(payload); } catch {} }
      }
      return new Response("ok");
    }
    return new Response("not found", { status: 404 });
  }

  async webSocketMessage(ws, data) {
    const a = ws.deserializeAttachment() || {};
    if (typeof data !== "string" || data.length > 512) { ws.close(1009, "too big"); return; }
    let msg;
    try { msg = JSON.parse(data); } catch { ws.close(1003, "bad"); return; }
    if (msg && msg.type === "auth") {
      const user = await userFromToken(this.env, msg.token);
      if (!user) { try { ws.send('{"type":"unauthorized"}'); } catch {} ws.close(4001, "unauthorized"); return; }
      ws.serializeAttachment({ uid: user.id, at: a.at || Date.now() });
      ws.send('{"type":"ready"}');
      return;
    }
    if (!a.uid) ws.close(4001, "unauthorized");
  }

  async webSocketClose(ws, code) { try { ws.close(1000, "bye"); } catch {} }
  async webSocketError(ws) { try { ws.close(1011, "error"); } catch {} }
}
