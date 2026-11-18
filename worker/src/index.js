// 개천박컴퍼니 사내메신저 API (Cloudflare Workers + D1 + Durable Objects)
import { DurableObject } from "cloudflare:workers";

const PBKDF2_ITER = 100000;          // Workers WebCrypto 상한(100,000회)
const SESSION_DAYS = 30;
const MAX_MSG = 500;
const MAX_NICK = 20;
const RECENT_LIMIT = 100;

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

/* ---------- CORS / 응답 ---------- */
function allowedOrigins(env) {
  return (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
}
function corsHeaders(origin, env) {
  const h = { "Vary": "Origin" };
  if (origin && allowedOrigins(env).includes(origin)) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
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
    `SELECT u.id, u.login, u.nickname FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  ).bind(await sha256Hex(token), now()).first();
  return row || null;
}
function bearer(req) {
  const h = req.headers.get("Authorization") || "";
  const m = /^Bearer\s+([0-9a-f]{64})$/i.exec(h);
  return m ? m[1].toLowerCase() : null;
}
const publicUser = (u) => ({ id: u.id, login: u.login, nickname: u.nickname || "" });
const publicMsg = (m) => ({ id: m.id, userId: m.user_id, nickname: m.nickname, text: m.text, createdAt: m.created_at });

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
        const u = await env.DB.prepare("SELECT id, login, nickname, pw_hash, pw_salt, pw_iter FROM users WHERE login = ?").bind(login).first();
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
        return json({ user: { ...publicUser(user), nickname: nick } }, 200, cors);
      }

      if (path === "/api/messages" && req.method === "GET") {
        const after = url.searchParams.get("after");
        let rows;
        if (after !== null) {
          const a = Number(after);
          if (!Number.isInteger(a) || a < 0) return fail("bad_request", 400, cors);
          rows = await env.DB.prepare(
            "SELECT id, user_id, nickname, text, created_at FROM messages WHERE id > ? ORDER BY id ASC LIMIT 200"
          ).bind(a).all();
          return json({ messages: rows.results.map(publicMsg) }, 200, cors);
        }
        rows = await env.DB.prepare(
          "SELECT id, user_id, nickname, text, created_at FROM messages ORDER BY id DESC LIMIT ?"
        ).bind(RECENT_LIMIT).all();
        return json({ messages: rows.results.reverse().map(publicMsg) }, 200, cors);
      }

      if (path === "/api/messages" && req.method === "POST") {
        const body = await readJson(req);
        const text = body && normText(body.text);
        if (!text) return fail("invalid_message", 400, cors);
        if (!user.nickname) return fail("nickname_required", 400, cors);
        if (!(await hit(env, "post:" + user.id, 30, 60000))) return fail("rate_limited", 429, cors);
        const m = await env.DB.prepare(
          "INSERT INTO messages (user_id, nickname, text, created_at) VALUES (?, ?, ?, ?) RETURNING id, user_id, nickname, text, created_at"
        ).bind(user.id, user.nickname, text, now()).first();
        const msg = publicMsg(m);
        const stub = env.ROOM.get(env.ROOM.idFromName("main"));
        ctx.waitUntil(stub.fetch("https://room/broadcast", { method: "POST", body: JSON.stringify({ type: "message", message: msg }) }).catch(() => {}));
        return json({ message: msg }, 201, cors);
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
