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
IMG_RULES.board = { maxBytes: 1024 * 1024, maxDim: 4096 };
IMG_RULES.con = { maxBytes: 512 * 1024, maxDim: 512 };
IMG_RULES.banner = { maxBytes: 1024 * 1024, maxDim: 3000 };

/* 프로필 포스트 미디어 (D1 값 하나는 2MB 제한 → 1.5MB씩 나눠 저장) */
const CHUNK = 1536 * 1024;
const MEDIA_RULES = {
  image: { types: ["image/jpeg", "image/png", "image/webp"], maxBytes: 1024 * 1024 },
  gif:   { types: ["image/gif"], maxBytes: 5 * 1024 * 1024 },
  video: { types: ["video/mp4", "video/webm", "video/quicktime"], maxBytes: 15 * 1024 * 1024 },
};
const MEDIA_DAY_BYTES = 150 * 1024 * 1024;  // 1인 하루 업로드 총량
const MAX_PPOST = 1000;
const MAX_PPOST_MEDIA = 4;
const MAX_STATUS = 60;
const PPOST_PAGE = 20;

/* 게시판 콘 (주제별 묶음) */
const MAX_CON_PACKS = 20;                // 1인당 주제 수
const MAX_CONS_PER_PACK = 50;            // 주제당 콘 수
const MAX_PACK_NAME = 20;
const CON_TOKEN_RE = /\[\[con:(\d{1,12})\]\]/g;

/* 게시판 */
const BOARD_CATS = ["일반", "질문", "정보", "잡담"];
const MAX_TITLE = 60;
const MAX_BODY = 5000;
const MAX_COMMENT = 400;
const MAX_POST_IMAGES = 5;
const PAGE_SIZE = 20;
const BEST_MIN = 3;                      // 추천 3개 이상 = 개념글
const FRAMES = ["basic", "platinum_crown", "gold_crown", "hoqueen", "bbunin", "red", "geommeomwoyo", "mobai", "seommyeol"];
const TEAM_ROLES = ["staff", "slave", "ration"]; // 사원·노예·비상식량: 표시용 직함 (권한 없음)
const MOD_ROLES = ["ceo", "vp"];         // 사장·부사장: 모든 글/댓글 삭제, 공지 지정


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
function normLine(v, max) {
  if (typeof v !== "string") return null;
  const s = stripCtl(v, false).replace(/\s+/g, " ").trim();
  const n = charLen(s);
  return n >= 1 && n <= max ? s : null;
}
function normLong(v, max) {
  if (typeof v !== "string") return null;
  const s = stripCtl(v.replace(/\r\n?/g, "\n"), true).replace(/^\s+|\s+$/g, "").replace(/\n{4,}/g, "\n\n\n");
  const n = charLen(s);
  return n >= 1 && n <= max ? s : null;
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
async function storageUsed(env) {
  const r = await env.DB.prepare("SELECT (SELECT COALESCE(SUM(size), 0) FROM images) + (SELECT COALESCE(SUM(size), 0) FROM media) AS s").first();
  return r.s;
}
async function storeImage(env, userId, purpose, img) {
  if ((await storageUsed(env)) + img.buf.length > STORAGE_CAP) return null;
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
       AND NOT EXISTS (SELECT 1 FROM users WHERE banner_id = ?1)
       AND NOT EXISTS (SELECT 1 FROM emoticons WHERE image_id = ?1)
       AND NOT EXISTS (SELECT 1 FROM post_images WHERE image_id = ?1)
       AND NOT EXISTS (SELECT 1 FROM cons WHERE image_id = ?1)`
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

async function readJson(req, max = 8192) {
  const len = Number(req.headers.get("Content-Length") || 0);
  if (len > max) return null;
  const txt = await req.text();
  if (txt.length > max) return null;
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
    `SELECT u.id, u.login, u.nickname, u.avatar_id, u.frame, u.role, u.status, u.banner_id, u.member FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  ).bind(await sha256Hex(token), now()).first();
  return row || null;
}
function bearer(req) {
  const h = req.headers.get("Authorization") || "";
  const m = /^Bearer\s+([0-9a-f]{64})$/i.exec(h);
  return m ? m[1].toLowerCase() : null;
}
const cleanFrame = (f) => (FRAMES.includes(f) ? f : "basic");
const cleanRole = (r) => (MOD_ROLES.includes(r) || TEAM_ROLES.includes(r) ? r : "");
const publicUser = (u) => ({ id: u.id, login: u.login, nickname: u.nickname || "", avatarId: u.avatar_id || null, frame: cleanFrame(u.frame), role: cleanRole(u.role), status: u.status || "", bannerId: u.banner_id || null, member: !!u.member });
// 다른 사람에게 보이는 작성자 정보 (로그인 아이디 제외)
const author = (r) => ({ id: r.uid, nickname: r.u_nick || "(탈퇴한 사용자)", avatarId: r.u_avatar || null, frame: cleanFrame(r.u_frame), role: cleanRole(r.u_role) });
const isMod = (u) => MOD_ROLES.includes(u.role);
const CHANNELS = ["company", "free"];
// 1:1 DM 채널: "dm:<작은id>-<큰id>"
const DM_RE = /^dm:(\d{1,12})-(\d{1,12})$/;
const dmPair = (ch) => { const m = DM_RE.exec(String(ch || "")); if (!m) return null; const a = Number(m[1]), b = Number(m[2]); return a > 0 && a < b ? [a, b] : null; };
const dmChan = (x, y) => "dm:" + Math.min(x, y) + "-" + Math.max(x, y);
const chanOf = (v) => (v === "free" ? "free" : v === "company" || v === undefined || v === null || v === "" ? "company" : dmPair(v) ? String(v) : null);
const canSee = (u, ch) => { const p = dmPair(ch); if (p) return p.includes(u.id); return ch === "free" || !!u.member; };
const dmPeer = (u, ch) => { const p = dmPair(ch); return p ? (p[0] === u.id ? p[1] : p[0]) : 0; };
const publicMsg = (m) => ({
  id: m.id, channel: m.channel || "company", userId: m.user_id, nickname: m.nickname, kind: m.kind || "text", text: m.text,
  image: m.image_id ? { id: m.image_id, w: m.w || 0, h: m.h || 0 } : null,
  avatarId: m.avatar_id || null, frame: cleanFrame(m.frame), role: cleanRole(m.role), createdAt: m.created_at,
  reply: m.reply_to ? (m.r_id
    ? { id: m.r_id, userId: m.r_uid, nickname: m.r_nick, kind: m.r_kind || "text", text: m.r_kind === "image" ? "" : String(m.r_text || "") }
    : { id: m.reply_to, missing: true }) : null,
});
// 이름은 항상 현재 닉네임(users)으로 표시. 탈퇴 등으로 사용자가 없으면 보낼 때 저장된 이름으로 대체
const MSG_SELECT = `SELECT m.id, m.channel, m.user_id, COALESCE(NULLIF(u.nickname, ''), m.nickname) AS nickname, m.kind, m.text, m.image_id, m.created_at, m.reply_to, i.w, i.h, u.avatar_id, u.frame, u.role,
    r.id AS r_id, r.user_id AS r_uid, COALESCE(NULLIF(ru.nickname, ''), r.nickname) AS r_nick, r.kind AS r_kind, substr(r.text, 1, 80) AS r_text
  FROM messages m LEFT JOIN users u ON u.id = m.user_id LEFT JOIN images i ON i.id = m.image_id LEFT JOIN messages r ON r.id = m.reply_to LEFT JOIN users ru ON ru.id = r.user_id`;
/* 멘션: 본문에 <@사용자ID> 토큰으로 저장 (닉네임이 바뀌어도 유지). @everyone 은 채널 전체 */
const MENTION_RE = /<@(\d{1,12})>/g;
const EVERYONE_RE = /(^|[^0-9A-Za-z_@])@everyone(?![0-9A-Za-z_])/i;
async function parseMentions(env, text, ch) {
  const ids = [...new Set([...text.matchAll(MENTION_RE)].map((m) => Number(m[1])))].slice(0, 20);
  const found = new Map();
  if (ids.length) {
    const rows = (await env.DB.prepare(`SELECT id, nickname, member FROM users WHERE id IN (${ids.map(() => "?").join(",")})`).bind(...ids).all()).results;
    for (const r of rows) found.set(r.id, r);
  }
  const ok = new Set();
  const out = text.replace(MENTION_RE, (m, id) => {
    const u = found.get(Number(id));
    if (u && u.nickname && canSee(u, ch)) { ok.add(u.id); return m; }
    return "@" + (u && u.nickname ? u.nickname : "알 수 없음");
  });
  return { text: out, ids: [...ok], all: EVERYONE_RE.test(out) };
}
async function plainMentions(env, text) {
  const ids = [...new Set([...String(text || "").matchAll(MENTION_RE)].map((m) => Number(m[1])))].slice(0, 20);
  if (!ids.length) return String(text || "");
  const rows = (await env.DB.prepare(`SELECT id, nickname FROM users WHERE id IN (${ids.map(() => "?").join(",")})`).bind(...ids).all()).results;
  const map = new Map(rows.map((r) => [r.id, r.nickname]));
  return String(text).replace(MENTION_RE, (m, id) => "@" + (map.get(Number(id)) || "알 수 없음"));
}
// 답장 대상 확인: undefined/null → 0(답장 아님), 잘못된 값 → -1, 없는 메시지 → -2
async function replyTarget(env, v, ch) {
  if (v === undefined || v === null || v === "") return 0;
  const n = Number(v);
  if (!Number.isInteger(n) || n <= 0) return -1;
  const r = await env.DB.prepare("SELECT id FROM messages WHERE id = ? AND channel = ?").bind(n, ch).first();
  return r ? n : -2;
}
const replyFail = (rt, cors) => rt === -1 ? fail("bad_request", 400, cors) : fail("reply_not_found", 404, cors);
async function insertMessage(env, user, kind, text, imageId, replyTo, ch) {
  const r = await env.DB.prepare(
    "INSERT INTO messages (user_id, nickname, text, created_at, kind, image_id, reply_to, channel) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id"
  ).bind(user.id, user.nickname, text, now(), kind, imageId, replyTo || null, ch).first();
  return publicMsg(await env.DB.prepare(MSG_SELECT + " WHERE m.id = ?").bind(r.id).first());
}
function msgBroadcast(env, ctx, msg) {
  const p = dmPair(msg.channel);
  broadcast(env, ctx, p ? { type: "message", message: msg, to: p } : { type: "message", message: msg, membersOnly: msg.channel === "company" });
}
// DM 상대가 실제로 있는 사용자인지 (DB 확인)
async function dmPeerOk(env, user, ch) {
  const peer = dmPeer(user, ch);
  if (!peer) return true;
  const r = await env.DB.prepare("SELECT id FROM users WHERE id = ? AND nickname != ''").bind(peer).first();
  return !!r;
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

      // 프로필 미디어 제공 (Range 지원: 동영상 탐색)
      if (path.startsWith("/media/") && (req.method === "GET" || req.method === "HEAD")) {
        return serveMedia(req, env, path.slice(7), cors);
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
        const u = await env.DB.prepare("SELECT id, login, nickname, avatar_id, frame, role, status, banner_id, member, pw_hash, pw_salt, pw_iter FROM users WHERE login = ?").bind(login).first();
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
        // 닉네임 중복 금지 (대소문자 무시, 자기 자신 제외). 동시 요청은 DB 고유 인덱스가 막음
        const taken = await env.DB.prepare("SELECT 1 FROM users WHERE id != ? AND nickname != '' AND lower(trim(nickname)) = lower(?)")
          .bind(user.id, nick).first();
        if (taken) return fail("nickname_taken", 409, cors);
        try {
          await env.DB.prepare("UPDATE users SET nickname = ? WHERE id = ?").bind(nick, user.id).run();
        } catch (e) {
          if (String(e).includes("UNIQUE")) return fail("nickname_taken", 409, cors);
          throw e;
        }
        broadcast(env, ctx, { type: "profile", user: { id: user.id, nickname: nick, avatarId: user.avatar_id || null, frame: cleanFrame(user.frame), role: cleanRole(user.role) } });
        return json({ user: { ...publicUser(user), nickname: nick } }, 200, cors);
      }

      if (path === "/api/channel-members" && req.method === "GET") {
        const ch = chanOf(url.searchParams.get("channel"));
        if (!ch) return fail("bad_request", 400, cors);
        if (!canSee(user, ch)) return fail("members_only", 403, cors);
        const pr = dmPair(ch);
        const rows = pr ? (await env.DB.prepare("SELECT id, nickname, avatar_id, frame, role FROM users WHERE nickname != '' AND id IN (?, ?)").bind(pr[0], pr[1]).all()).results
          : (await env.DB.prepare("SELECT id, nickname, avatar_id, frame, role FROM users WHERE nickname != ''" + (ch === "company" ? " AND member = 1" : "")).all()).results;
        let online = [];
        try { const r = await env.ROOM.get(env.ROOM.idFromName("main")).fetch("https://room/presence"); online = (await r.json()).online || []; } catch {}
        const on = new Set(online);
        return json({ members: rows.map((u) => ({ id: u.id, nickname: u.nickname, avatarId: u.avatar_id || null, frame: cleanFrame(u.frame), role: cleanRole(u.role), online: on.has(u.id) })) }, 200, cors);
      }
      // DM 목록: 대화 상대, 마지막 메시지, 안 읽은 수
      if (path === "/api/dms" && req.method === "GET") {
        const rows = (await env.DB.prepare(
          `WITH c AS (SELECT channel, MAX(id) AS last FROM messages WHERE channel LIKE 'dm:%' AND (channel LIKE ?1 OR channel LIKE ?2) GROUP BY channel)
           SELECT c.channel, c.last, m.user_id AS last_uid, m.kind, m.text, m.created_at,
             COALESCE(r.last_id, 0) AS read_id,
             (SELECT COUNT(*) FROM messages x WHERE x.channel = c.channel AND x.id > COALESCE(r.last_id, 0) AND x.user_id != ?3) AS unread
           FROM c JOIN messages m ON m.id = c.last LEFT JOIN dm_reads r ON r.user_id = ?3 AND r.channel = c.channel
           ORDER BY c.last DESC LIMIT 100`
        ).bind("dm:" + user.id + "-%", "dm:%-" + user.id, user.id).all()).results.filter((r) => dmPair(r.channel) && canSee(user, r.channel));
        const peers = [...new Set(rows.map((r) => dmPeer(user, r.channel)))];
        const pm = new Map();
        if (peers.length) for (const u of (await env.DB.prepare(`SELECT id, nickname, avatar_id, frame, role FROM users WHERE id IN (${peers.map(() => "?").join(",")})`).bind(...peers).all()).results) pm.set(u.id, u);
        const out = [];
        for (const r of rows) {
          const pid = dmPeer(user, r.channel), u = pm.get(pid);
          const text = r.kind === "image" ? "사진" : r.kind === "emoticon" ? "이모티콘" : snip(await plainMentions(env, r.text), 60);
          out.push({ channel: r.channel, peer: { id: pid, nickname: (u && u.nickname) || "(탈퇴한 사용자)", avatarId: (u && u.avatar_id) || null, frame: cleanFrame(u && u.frame), role: cleanRole(u && u.role) },
            last: { id: r.last, userId: r.last_uid, text, createdAt: r.created_at }, unread: r.unread });
        }
        return json({ dms: out }, 200, cors);
      }
      if (path === "/api/dms/read" && req.method === "POST") {
        const body = await readJson(req);
        const ch = body && chanOf(body.channel);
        const id = body && Number(body.lastId);
        if (!ch || !dmPair(ch) || !canSee(user, ch) || !Number.isInteger(id) || id < 0) return fail("bad_request", 400, cors);
        await env.DB.prepare("INSERT INTO dm_reads (user_id, channel, last_id) VALUES (?, ?, ?) ON CONFLICT(user_id, channel) DO UPDATE SET last_id = MAX(last_id, excluded.last_id)").bind(user.id, ch, id).run();
        return json({ ok: true }, 200, cors);
      }
      if (path === "/api/unfurl" && req.method === "GET") return unfurl(env, url.searchParams.get("url"), user, ip, cors);

      // 사내 메신저 참여코드 (코드는 서버 비밀값의 SHA-256 해시로만 비교)
      if (path === "/api/join" && req.method === "POST") {
        if (user.member) return json({ user: publicUser(user) }, 200, cors);
        const body = await readJson(req);
        const code = body && typeof body.code === "string" ? body.code.trim() : "";
        if (!(await hit(env, "join:" + user.id, 5, 600000)) || !(await hit(env, "join-ip:" + ip, 20, 3600000))) return fail("rate_limited", 429, cors);
        if (!env.JOIN_CODE_SHA256 || !code || code.length > 32) return fail("wrong_code", 403, cors);
        const got = await sha256Hex("gcb-join:" + code);
        if (!timingSafeEqual(enc.encode(got), enc.encode(String(env.JOIN_CODE_SHA256).toLowerCase()))) return fail("wrong_code", 403, cors);
        await env.DB.prepare("UPDATE users SET member = 1 WHERE id = ?").bind(user.id).run();
        return json({ user: { ...publicUser(user), member: true } }, 200, cors);
      }

      if (path === "/api/messages" && req.method === "GET") {
        const ch = chanOf(url.searchParams.get("channel"));
        if (!ch) return fail("bad_request", 400, cors);
        if (!canSee(user, ch)) return fail("members_only", 403, cors);
        const after = url.searchParams.get("after");
        let rows;
        if (after !== null) {
          const a = Number(after);
          if (!Number.isInteger(a) || a < 0) return fail("bad_request", 400, cors);
          rows = await env.DB.prepare(MSG_SELECT + " WHERE m.channel = ? AND m.id > ? ORDER BY m.id ASC LIMIT 200").bind(ch, a).all();
          return json({ messages: rows.results.map(publicMsg) }, 200, cors);
        }
        rows = await env.DB.prepare(MSG_SELECT + " WHERE m.channel = ? ORDER BY m.id DESC LIMIT ?").bind(ch, RECENT_LIMIT).all();
        return json({ messages: rows.results.reverse().map(publicMsg) }, 200, cors);
      }

      // 텍스트 또는 이모티콘 메시지
      if (path === "/api/messages" && req.method === "POST") {
        const body = await readJson(req);
        if (!body) return fail("bad_request", 400, cors);
        if (!user.nickname) return fail("nickname_required", 400, cors);
        const ch = chanOf(body.channel);
        if (!ch) return fail("bad_request", 400, cors);
        if (!canSee(user, ch)) return fail("members_only", 403, cors);
        if (!(await dmPeerOk(env, user, ch))) return fail("user_not_found", 404, cors);
        if (body.emoticonId !== undefined) {
          const eid = Number(body.emoticonId);
          if (!Number.isInteger(eid) || eid <= 0) return fail("bad_request", 400, cors);
          const emo = await env.DB.prepare("SELECT id, name, image_id FROM emoticons WHERE id = ?").bind(eid).first();
          if (!emo) return fail("emoticon_not_found", 404, cors);
          const rt = await replyTarget(env, body.replyTo, ch);
          if (rt < 0) return replyFail(rt, cors);
          if (!(await hit(env, "post:" + user.id, 30, 60000))) return fail("rate_limited", 429, cors);
          const msg = await insertMessage(env, user, "emoticon", emo.name, emo.image_id, rt, ch);
          msgBroadcast(env, ctx, msg);
          ctx.waitUntil(notifyChat(env, ctx, user, msg));
          return json({ message: msg }, 201, cors);
        }
        const text0 = normText(body.text);
        if (!text0) return fail("invalid_message", 400, cors);
        const rt = await replyTarget(env, body.replyTo, ch);
        if (rt < 0) return replyFail(rt, cors);
        const mt = await parseMentions(env, text0, ch);
        if (mt.all && !isMod(user) && !(await hit(env, "everyone:" + user.id, 3, 600000))) return fail("everyone_limited", 429, cors);
        if (!(await hit(env, "post:" + user.id, 30, 60000))) return fail("rate_limited", 429, cors);
        const msg = await insertMessage(env, user, "text", mt.text, null, rt, ch);
        msgBroadcast(env, ctx, msg);
        ctx.waitUntil(notifyChat(env, ctx, user, msg, mt));
        return json({ message: msg }, 201, cors);
      }

      // 사진 메시지 (본문 = 이미지 바이트)
      if (path === "/api/photos" && req.method === "POST") {
        if (!user.nickname) return fail("nickname_required", 400, cors);
        const ch = chanOf(url.searchParams.get("channel"));
        if (!ch) return fail("bad_request", 400, cors);
        if (!canSee(user, ch)) return fail("members_only", 403, cors);
        if (!(await dmPeerOk(env, user, ch))) return fail("user_not_found", 404, cors);
        const rt = await replyTarget(env, url.searchParams.get("replyTo"), ch);
        if (rt < 0) return replyFail(rt, cors);
        if (!(await hit(env, "upload:" + user.id, 30, 600000)) || !(await hit(env, "upload-day:" + user.id, 300, 86400000))) return fail("rate_limited", 429, cors);
        const img = await readImage(req, "photo");
        if (img.error) return fail(img.error, img.status, cors);
        const id = await storeImage(env, user.id, "photo", img);
        if (!id) return fail("storage_full", 507, cors);
        const msg = await insertMessage(env, user, "image", "", id, rt, ch);
        msgBroadcast(env, ctx, msg);
        ctx.waitUntil(notifyChat(env, ctx, user, msg));
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
        broadcast(env, ctx, { type: "profile", user: { id: pu.id, nickname: pu.nickname, avatarId: id, frame: pu.frame, role: pu.role } });
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

      const pr = await profiles(req, env, ctx, url, path, user, cors);
      if (pr) return pr;

      if (path.startsWith("/api/board/")) {
        const r = await board(req, env, url, path, user, cors, ctx);
        if (r) return r;
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
      env.DB.prepare("DELETE FROM link_cache WHERE fetched_at <= ?").bind(t - 2 * 86400000),
      // 글에 붙지 않은 채 하루가 지난 게시판 이미지 정리
      env.DB.prepare(`DELETE FROM images WHERE purpose = 'board' AND created_at <= ?
        AND NOT EXISTS (SELECT 1 FROM post_images p WHERE p.image_id = images.id)`).bind(t - 86400000),
    ]);
    // 포스트에 붙지 않은 채 하루가 지난 미디어 정리
    const stale = (await env.DB.prepare(
      "SELECT id FROM media WHERE created_at <= ? AND NOT EXISTS (SELECT 1 FROM profile_post_media p WHERE p.media_id = media.id) LIMIT 200"
    ).bind(t - 86400000).all()).results;
    for (const m of stale) await deleteMedia(env, m.id);
  },
};


/* ---------- 사내 게시판 ---------- */
const POST_COLS = `p.id, p.user_id, p.category, p.title, p.created_at, p.updated_at, p.views, p.up, p.down, p.comment_count, p.pinned,
  (SELECT COUNT(*) FROM post_images pi WHERE pi.post_id = p.id) AS img_count,
  u.id AS uid, u.nickname AS u_nick, u.avatar_id AS u_avatar, u.frame AS u_frame, u.role AS u_role`;
const listItem = (r) => ({
  id: r.id, category: r.category, title: r.title, createdAt: r.created_at, updatedAt: r.updated_at || null,
  views: r.views, up: r.up, down: r.down, comments: r.comment_count, pinned: !!r.pinned, images: r.img_count,
  author: author({ ...r, uid: r.user_id }),
});
const likeEsc = (q) => "%" + q.replace(/[\\%_]/g, (c) => "\\" + c) + "%";

async function loadPost(env, id) {
  return env.DB.prepare(`SELECT ${POST_COLS}, p.body FROM posts p LEFT JOIN users u ON u.id = p.user_id WHERE p.id = ?`).bind(id).first();
}
// 내가 올렸고 아직 다른 글에 붙지 않은 게시판 이미지만 허용
async function checkImageIds(env, user, ids, postId) {
  if (ids === undefined) return [];
  if (!Array.isArray(ids) || ids.length > MAX_POST_IMAGES) return null;
  const out = [];
  for (const id of ids) {
    if (typeof id !== "string" || !IMG_ID_RE.test(id) || out.includes(id)) return null;
    const ok = await env.DB.prepare(
      `SELECT 1 FROM images i WHERE i.id = ? AND i.user_id = ? AND i.purpose = 'board'
         AND NOT EXISTS (SELECT 1 FROM post_images p WHERE p.image_id = i.id AND p.post_id != ?)`
    ).bind(id, user.id, postId || 0).first();
    if (!ok) return null;
    out.push(id);
  }
  return out;
}
async function postDetail(env, id, user) {
  const r = await loadPost(env, id);
  if (!r) return null;
  const imgs = await env.DB.prepare(
    "SELECT i.id, i.w, i.h FROM post_images p JOIN images i ON i.id = p.image_id WHERE p.post_id = ? ORDER BY p.ord"
  ).bind(id).all();
  const cm = await env.DB.prepare(
    `SELECT c.id, c.parent_id, c.body, c.created_at, c.updated_at, c.deleted, c.user_id,
       u.nickname AS u_nick, u.avatar_id AS u_avatar, u.frame AS u_frame, u.role AS u_role
     FROM comments c LEFT JOIN users u ON u.id = c.user_id WHERE c.post_id = ? ORDER BY c.id LIMIT 1000`
  ).bind(id).all();
  const vote = await env.DB.prepare("SELECT v FROM post_votes WHERE post_id = ? AND user_id = ?").bind(id, user.id).first();
  const cons = await conMap(env, [r.body, ...cm.results.map((c) => c.deleted ? "" : c.body)]);
  return {
    ...listItem(r), body: r.body, myVote: vote ? vote.v : 0, cons,
    images: imgs.results.map((i) => ({ id: i.id, w: i.w, h: i.h })),
    comments: cm.results.map((c) => c.deleted
      ? { id: c.id, parentId: c.parent_id, deleted: true, body: "", createdAt: c.created_at, author: null }
      : { id: c.id, parentId: c.parent_id, deleted: false, body: c.body, createdAt: c.created_at, updatedAt: c.updated_at || null, author: author({ ...c, uid: c.user_id }) }),
  };
}

// 본문·댓글의 [[con:ID]] 토큰 → { id: { imageId, name } }. 삭제된 콘은 빠짐(화면에서 자리 표시)
async function conMap(env, texts) {
  const ids = new Set();
  for (const t of texts) for (const m of String(t || "").matchAll(CON_TOKEN_RE)) { if (ids.size < 300) ids.add(Number(m[1])); }
  const out = {};
  const list = [...ids];
  for (let i = 0; i < list.length; i += 90) {
    const part = list.slice(i, i + 90);
    const rows = await env.DB.prepare(`SELECT id, name, image_id FROM cons WHERE id IN (${part.map(() => "?").join(",")})`).bind(...part).all();
    for (const c of rows.results) out[c.id] = { imageId: c.image_id, name: c.name };
  }
  return out;
}
function normPackName(v) {
  if (typeof v !== "string") return null;
  const s = stripCtl(v, false).replace(/\s+/g, " ").trim();
  const n = charLen(s);
  return n >= 1 && n <= MAX_PACK_NAME ? s : null;
}
async function deleteConImages(env, imageIds) { for (const i of imageIds) await dropImageIfUnused(env, i); }

async function cons(req, env, url, path, user, cors) {
  const M = req.method;
  // 전체 콘 목록 (내 주제 먼저, 다른 사람 주제도 함께 사용)
  if (path === "/api/board/cons" && M === "GET") {
    const packs = (await env.DB.prepare(
      `SELECT p.id, p.user_id, p.name, p.created_at, u.nickname, u.frame, u.role FROM con_packs p LEFT JOIN users u ON u.id = p.user_id
       ORDER BY CASE WHEN p.user_id = ? THEN 0 ELSE 1 END, p.id`
    ).bind(user.id).all()).results;
    const items = (await env.DB.prepare("SELECT id, pack_id, name, image_id FROM cons ORDER BY id").all()).results;
    const byPack = {};
    for (const c of items) (byPack[c.pack_id] = byPack[c.pack_id] || []).push({ id: c.id, name: c.name, imageId: c.image_id });
    return json({
      packs: packs.map((p) => ({ id: p.id, name: p.name, createdAt: p.created_at, owner: { id: p.user_id, nickname: p.nickname || "(탈퇴한 사용자)", role: cleanRole(p.role) }, cons: byPack[p.id] || [] })),
      maxPacks: MAX_CON_PACKS, maxPerPack: MAX_CONS_PER_PACK,
    }, 200, cors);
  }
  // 주제 만들기
  if (path === "/api/board/conpacks" && M === "POST") {
    if (!user.nickname) return fail("nickname_required", 400, cors);
    const body = await readJson(req);
    const name = body && normPackName(body.name);
    if (!name) return fail("invalid_pack_name", 400, cors);
    const cnt = await env.DB.prepare("SELECT COUNT(*) AS c FROM con_packs WHERE user_id = ?").bind(user.id).first();
    if (cnt.c >= MAX_CON_PACKS) return fail("pack_limit", 409, cors);
    if (!(await hit(env, "conpack:" + user.id, 20, 3600000))) return fail("rate_limited", 429, cors);
    const p = await env.DB.prepare("INSERT INTO con_packs (user_id, name, created_at) VALUES (?, ?, ?) RETURNING id").bind(user.id, name, now()).first();
    return json({ pack: { id: p.id, name } }, 201, cors);
  }
  const pk = /^\/api\/board\/conpacks\/(\d{1,12})(\/cons)?$/.exec(path);
  if (pk) {
    const pack = await env.DB.prepare("SELECT id, user_id, name FROM con_packs WHERE id = ?").bind(Number(pk[1])).first();
    if (!pack) return fail("pack_not_found", 404, cors);
    const own = pack.user_id === user.id;
    // 콘 추가 (본문 = 이미지 바이트, 이름은 ?name=)
    if (pk[2] && M === "POST") {
      if (!own) return fail("forbidden", 403, cors);
      const name = normEmoName(url.searchParams.get("name"));
      if (!name) return fail("invalid_con_name", 400, cors);
      const cnt = await env.DB.prepare("SELECT COUNT(*) AS c FROM cons WHERE pack_id = ?").bind(pack.id).first();
      if (cnt.c >= MAX_CONS_PER_PACK) return fail("pack_full", 409, cors);
      if (!(await hit(env, "con:" + user.id, 120, 3600000)) || !(await hit(env, "upload-day:" + user.id, 300, 86400000))) return fail("rate_limited", 429, cors);
      const img = await readImage(req, "con");
      if (img.error) return fail(img.error, img.status, cors);
      const imageId = await storeImage(env, user.id, "con", img);
      if (!imageId) return fail("storage_full", 507, cors);
      const c = await env.DB.prepare("INSERT INTO cons (pack_id, user_id, name, image_id, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id")
        .bind(pack.id, user.id, name, imageId, now()).first();
      return json({ con: { id: c.id, name, imageId } }, 201, cors);
    }
    if (pk[2]) return fail("not_found", 404, cors);
    // 주제 이름 바꾸기 (만든 사람만)
    if (M === "POST") {
      if (!own) return fail("forbidden", 403, cors);
      const body = await readJson(req);
      const name = body && normPackName(body.name);
      if (!name) return fail("invalid_pack_name", 400, cors);
      await env.DB.prepare("UPDATE con_packs SET name = ? WHERE id = ?").bind(name, pack.id).run();
      return json({ pack: { id: pack.id, name } }, 200, cors);
    }
    // 주제 삭제 (만든 사람 또는 사장·부사장)
    if (M === "DELETE") {
      if (!own && !isMod(user)) return fail("forbidden", 403, cors);
      const imgs = (await env.DB.prepare("SELECT image_id FROM cons WHERE pack_id = ?").bind(pack.id).all()).results.map((x) => x.image_id);
      await env.DB.batch([
        env.DB.prepare("DELETE FROM cons WHERE pack_id = ?").bind(pack.id),
        env.DB.prepare("DELETE FROM con_packs WHERE id = ?").bind(pack.id),
      ]);
      await deleteConImages(env, imgs);
      return json({ ok: true }, 200, cors);
    }
    return fail("not_found", 404, cors);
  }
  const cm = /^\/api\/board\/cons\/(\d{1,12})$/.exec(path);
  if (cm && (M === "POST" || M === "DELETE")) {
    const c = await env.DB.prepare("SELECT c.id, c.image_id, p.user_id FROM cons c JOIN con_packs p ON p.id = c.pack_id WHERE c.id = ?").bind(Number(cm[1])).first();
    if (!c) return fail("con_not_found", 404, cors);
    if (M === "POST") {
      if (c.user_id !== user.id) return fail("forbidden", 403, cors);
      const body = await readJson(req);
      const name = body && normEmoName(body.name);
      if (!name) return fail("invalid_con_name", 400, cors);
      await env.DB.prepare("UPDATE cons SET name = ? WHERE id = ?").bind(name, c.id).run();
      return json({ con: { id: c.id, name } }, 200, cors);
    }
    if (c.user_id !== user.id && !isMod(user)) return fail("forbidden", 403, cors);
    await env.DB.prepare("DELETE FROM cons WHERE id = ?").bind(c.id).run();
    await deleteConImages(env, [c.image_id]);
    return json({ ok: true }, 200, cors);
  }
  return null;
}

async function board(req, env, url, path, user, cors, ctx) {
  const M = req.method;
  if (path.startsWith("/api/board/con")) {
    const r = await cons(req, env, url, path, user, cors);
    if (r) return r;
  }

  // 게시판 이미지 올리기 (글 작성 전에 미리 업로드, 본문 = 이미지 바이트)
  if (path === "/api/board/images" && M === "POST") {
    if (!(await hit(env, "upload:" + user.id, 30, 600000)) || !(await hit(env, "upload-day:" + user.id, 300, 86400000))) return fail("rate_limited", 429, cors);
    const img = await readImage(req, "board");
    if (img.error) return fail(img.error, img.status, cors);
    const id = await storeImage(env, user.id, "board", img);
    if (!id) return fail("storage_full", 507, cors);
    return json({ image: { id, w: img.w, h: img.h } }, 201, cors);
  }

  // 목록: tab=all|best, page, q, field=title|content|title_content|author, cat
  if (path === "/api/board/posts" && M === "GET") {
    const best = url.searchParams.get("tab") === "best";
    let page = Number(url.searchParams.get("page") || 1);
    if (!Number.isInteger(page) || page < 1 || page > 100000) page = 1;
    const where = [], args = [];
    if (best) { where.push("p.up >= ?"); args.push(BEST_MIN); }
    const cat = url.searchParams.get("cat");
    if (cat && BOARD_CATS.includes(cat)) { where.push("p.category = ?"); args.push(cat); }
    const qRaw = stripCtl(String(url.searchParams.get("q") || ""), false).trim().slice(0, 40);
    if (qRaw) {
      const like = likeEsc(qRaw);
      const field = url.searchParams.get("field") || "title_content";
      if (field === "title") { where.push("p.title LIKE ? ESCAPE '\\'"); args.push(like); }
      else if (field === "content") { where.push("p.body LIKE ? ESCAPE '\\'"); args.push(like); }
      else if (field === "author") { where.push("u.nickname LIKE ? ESCAPE '\\'"); args.push(like); }
      else { where.push("(p.title LIKE ? ESCAPE '\\' OR p.body LIKE ? ESCAPE '\\')"); args.push(like, like); }
    }
    const w = where.length ? " WHERE " + where.join(" AND ") : "";
    const from = " FROM posts p LEFT JOIN users u ON u.id = p.user_id";
    const total = (await env.DB.prepare("SELECT COUNT(*) AS c" + from + w).bind(...args).first()).c;
    const rows = await env.DB.prepare(`SELECT ${POST_COLS}${from}${w} ORDER BY p.id DESC LIMIT ? OFFSET ?`)
      .bind(...args, PAGE_SIZE, (page - 1) * PAGE_SIZE).all();
    let notices = [];
    if (!best && !qRaw && !cat && page === 1) {
      notices = (await env.DB.prepare(`SELECT ${POST_COLS}${from} WHERE p.pinned = 1 ORDER BY p.id DESC LIMIT 5`).all()).results.map(listItem);
    }
    return json({ posts: rows.results.map(listItem), notices, total, page, pageSize: PAGE_SIZE, bestMin: BEST_MIN, categories: BOARD_CATS }, 200, cors);
  }

  // 글쓰기
  if (path === "/api/board/posts" && M === "POST") {
    if (!user.nickname) return fail("nickname_required", 400, cors);
    const body = await readJson(req, 32768);
    if (!body) return fail("bad_request", 400, cors);
    const title = normLine(body.title, MAX_TITLE);
    if (!title) return fail("invalid_title", 400, cors);
    const text = normLong(body.body, MAX_BODY);
    if (!text) return fail("invalid_body", 400, cors);
    const cat = BOARD_CATS.includes(body.category) ? body.category : "일반";
    const ids = await checkImageIds(env, user, body.imageIds, 0);
    if (!ids) return fail("bad_images", 400, cors);
    if (!(await hit(env, "bpost:" + user.id, 10, 600000)) || !(await hit(env, "bpost-day:" + user.id, 60, 86400000))) return fail("rate_limited", 429, cors);
    const r = await env.DB.prepare("INSERT INTO posts (user_id, category, title, body, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id")
      .bind(user.id, cat, title, text, now()).first();
    if (ids.length) await env.DB.batch(ids.map((id, i) => env.DB.prepare("INSERT INTO post_images (post_id, image_id, ord) VALUES (?, ?, ?)").bind(r.id, id, i)));
    return json({ post: { id: r.id } }, 201, cors);
  }

  const pm = /^\/api\/board\/posts\/(\d{1,12})(\/(vote|pin|comments))?$/.exec(path);
  if (pm) {
    const id = Number(pm[1]), sub = pm[3];
    const post = await env.DB.prepare("SELECT id, user_id, pinned FROM posts WHERE id = ?").bind(id).first();
    if (!post) return fail("post_not_found", 404, cors);

    if (!sub && M === "GET") {
      const v = await env.DB.prepare("INSERT OR IGNORE INTO post_views (post_id, user_id) VALUES (?, ?)").bind(id, user.id).run();
      if (v.meta && v.meta.changes) await env.DB.prepare("UPDATE posts SET views = views + 1 WHERE id = ?").bind(id).run();
      return json({ post: await postDetail(env, id, user), bestMin: BEST_MIN, categories: BOARD_CATS }, 200, cors);
    }
    // 수정 (작성자만)
    if (!sub && M === "POST") {
      if (post.user_id !== user.id) return fail("forbidden", 403, cors);
      const body = await readJson(req, 32768);
      if (!body) return fail("bad_request", 400, cors);
      const title = normLine(body.title, MAX_TITLE);
      if (!title) return fail("invalid_title", 400, cors);
      const text = normLong(body.body, MAX_BODY);
      if (!text) return fail("invalid_body", 400, cors);
      const cat = BOARD_CATS.includes(body.category) ? body.category : "일반";
      const ids = await checkImageIds(env, user, body.imageIds, id);
      if (!ids) return fail("bad_images", 400, cors);
      if (!(await hit(env, "bedit:" + user.id, 30, 600000))) return fail("rate_limited", 429, cors);
      const old = (await env.DB.prepare("SELECT image_id FROM post_images WHERE post_id = ?").bind(id).all()).results.map((x) => x.image_id);
      await env.DB.batch([
        env.DB.prepare("UPDATE posts SET title = ?, body = ?, category = ?, updated_at = ? WHERE id = ?").bind(title, text, cat, now(), id),
        env.DB.prepare("DELETE FROM post_images WHERE post_id = ?").bind(id),
        ...ids.map((iid, i) => env.DB.prepare("INSERT INTO post_images (post_id, image_id, ord) VALUES (?, ?, ?)").bind(id, iid, i)),
      ]);
      for (const o of old) if (!ids.includes(o)) await dropImageIfUnused(env, o);
      return json({ post: { id } }, 200, cors);
    }
    // 삭제 (작성자 또는 사장·부사장)
    if (!sub && M === "DELETE") {
      if (post.user_id !== user.id && !isMod(user)) return fail("forbidden", 403, cors);
      const old = (await env.DB.prepare("SELECT image_id FROM post_images WHERE post_id = ?").bind(id).all()).results.map((x) => x.image_id);
      await env.DB.batch([
        env.DB.prepare("DELETE FROM posts WHERE id = ?").bind(id),
        env.DB.prepare("DELETE FROM post_images WHERE post_id = ?").bind(id),
        env.DB.prepare("DELETE FROM post_votes WHERE post_id = ?").bind(id),
        env.DB.prepare("DELETE FROM post_views WHERE post_id = ?").bind(id),
        env.DB.prepare("DELETE FROM comments WHERE post_id = ?").bind(id),
      ]);
      for (const o of old) await dropImageIfUnused(env, o);
      return json({ ok: true }, 200, cors);
    }
    // 추천/비추천 (글마다 1인 1회)
    if (sub === "vote" && M === "POST") {
      const body = await readJson(req);
      const v = body && body.v === 1 ? 1 : body && body.v === -1 ? -1 : 0;
      if (!v) return fail("bad_request", 400, cors);
      if (!(await hit(env, "vote:" + user.id, 60, 600000))) return fail("rate_limited", 429, cors);
      const ins = await env.DB.prepare("INSERT OR IGNORE INTO post_votes (post_id, user_id, v, created_at) VALUES (?, ?, ?, ?)").bind(id, user.id, v, now()).run();
      if (!(ins.meta && ins.meta.changes)) return fail("already_voted", 409, cors);
      const r = await env.DB.prepare(`UPDATE posts SET ${v === 1 ? "up = up + 1" : "down = down + 1"} WHERE id = ? RETURNING up, down`).bind(id).first();
      return json({ up: r.up, down: r.down, myVote: v }, 200, cors);
    }
    // 공지 지정/해제 (사장·부사장)
    if (sub === "pin" && M === "POST") {
      if (!isMod(user)) return fail("forbidden", 403, cors);
      const body = await readJson(req);
      const pinned = !!(body && body.pinned);
      await env.DB.prepare("UPDATE posts SET pinned = ? WHERE id = ?").bind(pinned ? 1 : 0, id).run();
      return json({ pinned }, 200, cors);
    }
    // 댓글 쓰기 (답글은 한 단계까지)
    if (sub === "comments" && M === "POST") {
      if (!user.nickname) return fail("nickname_required", 400, cors);
      const body = await readJson(req);
      if (!body) return fail("bad_request", 400, cors);
      const text = normLong(body.body, MAX_COMMENT);
      if (!text) return fail("invalid_comment", 400, cors);
      let parent = null;
      if (body.parentId !== undefined && body.parentId !== null) {
        const pid = Number(body.parentId);
        if (!Number.isInteger(pid) || pid <= 0) return fail("bad_request", 400, cors);
        const pc = await env.DB.prepare("SELECT id, parent_id FROM comments WHERE id = ? AND post_id = ?").bind(pid, id).first();
        if (!pc) return fail("comment_not_found", 404, cors);
        parent = pc.id; // 답글의 답글도 그 댓글 아래에 (여러 단계)
      }
      if (!(await hit(env, "cmt:" + user.id, 30, 600000)) || !(await hit(env, "cmt-day:" + user.id, 300, 86400000))) return fail("rate_limited", 429, cors);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO comments (post_id, user_id, parent_id, body, created_at) VALUES (?, ?, ?, ?, ?)").bind(id, user.id, parent, text, now()),
        env.DB.prepare("UPDATE posts SET comment_count = comment_count + 1 WHERE id = ?").bind(id),
      ]);
      if (ctx) ctx.waitUntil(notifyComment(env, ctx, user, id, body.parentId ? Number(body.parentId) : null, text));
      return json({ post: await postDetail(env, id, user) }, 201, cors);
    }
    return fail("not_found", 404, cors);
  }

  // 댓글 수정 / 삭제
  const cmm = /^\/api\/board\/comments\/(\d{1,12})$/.exec(path);
  if (cmm && (M === "POST" || M === "DELETE")) {
    const cid = Number(cmm[1]);
    const c = await env.DB.prepare("SELECT id, post_id, user_id, parent_id, deleted FROM comments WHERE id = ?").bind(cid).first();
    if (!c || c.deleted) return fail("comment_not_found", 404, cors);
    if (M === "POST") {
      if (c.user_id !== user.id) return fail("forbidden", 403, cors);
      const body = await readJson(req);
      const text = body && normLong(body.body, MAX_COMMENT);
      if (!text) return fail("invalid_comment", 400, cors);
      if (!(await hit(env, "cedit:" + user.id, 30, 600000))) return fail("rate_limited", 429, cors);
      await env.DB.prepare("UPDATE comments SET body = ?, updated_at = ? WHERE id = ?").bind(text, now(), cid).run();
    } else {
      if (c.user_id !== user.id && !isMod(user)) return fail("forbidden", 403, cors);
      const kids = await env.DB.prepare("SELECT COUNT(*) AS n FROM comments WHERE parent_id = ?").bind(cid).first();
      const ops = [];
      // 답글이 달린 댓글은 '삭제된 댓글입니다'로 자리만 남김
      if (kids.n > 0) ops.push(env.DB.prepare("UPDATE comments SET deleted = 1, body = '' WHERE id = ?").bind(cid));
      else ops.push(env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(cid));
      ops.push(env.DB.prepare("UPDATE posts SET comment_count = MAX(comment_count - 1, 0) WHERE id = ?").bind(c.post_id));
      await env.DB.batch(ops);
      // 지워진 윗댓글에 남은 답글이 없으면 그 자리도 위로 올라가며 정리
      if (kids.n === 0) {
        let anc = c.parent_id;
        for (let i = 0; anc && i < 50; i++) {
          const a = await env.DB.prepare("SELECT id, parent_id, deleted FROM comments WHERE id = ?").bind(anc).first();
          if (!a || !a.deleted) break;
          const r = await env.DB.prepare("DELETE FROM comments WHERE id = ? AND deleted = 1 AND NOT EXISTS (SELECT 1 FROM comments k WHERE k.parent_id = ?)").bind(a.id, a.id).run();
          if (!r.meta || !r.meta.changes) break;
          anc = a.parent_id;
        }
      }
    }
    return json({ post: await postDetail(env, c.post_id, user) }, 200, cors);
  }
  return null;
}

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
    if (url.pathname === "/presence") return new Response(JSON.stringify({ online: [...this.onlineIds(null)] }), { headers: { "Content-Type": "application/json" } });
    if (url.pathname === "/broadcast" && req.method === "POST") {
      const payload = await req.text();
      let to = null, membersOnly = false;
      try { const o = JSON.parse(payload); if (Array.isArray(o.to)) to = o.to; membersOnly = !!o.membersOnly; } catch { return new Response("bad", { status: 400 }); }
      // 멤버 여부는 매번 DB에서 확인 (멤버에서 빠진 사람이 접속 중이어도 사내 메시지를 받지 않도록)
      let memberIds = null;
      if (membersOnly) {
        try { const r = await this.env.DB.prepare("SELECT id FROM users WHERE member = 1").all(); memberIds = new Set(r.results.map((x) => x.id)); } catch { memberIds = new Set(); }
      }
      for (const ws of this.ctx.getWebSockets()) {
        const a = ws.deserializeAttachment() || {};
        if (a.uid && (!to || to.includes(a.uid)) && (!membersOnly || memberIds.has(a.uid))) { try { ws.send(payload); } catch {} }
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
      const wasOnline = this.onlineIds(null).has(user.id);
      ws.serializeAttachment({ uid: user.id, member: !!user.member, at: a.at || Date.now() });
      ws.send('{"type":"ready"}');
      if (!wasOnline) this.sendPresence(null);
      return;
    }
    if (!a.uid) ws.close(4001, "unauthorized");
  }

  async webSocketClose(ws, code) { try { ws.close(1000, "bye"); } catch {} this.leave(ws); }
  async webSocketError(ws) { try { ws.close(1011, "error"); } catch {} this.leave(ws); }
  // 접속 상태: 연결된 사용자 목록이 바뀌면 모두에게 알림
  onlineIds(except) {
    const s = new Set();
    for (const w of this.ctx.getWebSockets()) { if (w === except) continue; const a = w.deserializeAttachment() || {}; if (a.uid) s.add(a.uid); }
    return s;
  }
  sendPresence(except) {
    const p = JSON.stringify({ type: "presence", online: [...this.onlineIds(except)] });
    for (const w of this.ctx.getWebSockets()) { if (w === except) continue; const a = w.deserializeAttachment() || {}; if (a.uid) { try { w.send(p); } catch {} } }
  }
  leave(ws) {
    const a = (() => { try { return ws.deserializeAttachment() || {}; } catch { return {}; } })();
    if (a.uid && !this.onlineIds(ws).has(a.uid)) this.sendPresence(ws);
  }
}


/* ---------- 프로필 / 프로필 포스트 / 미디어 ---------- */
function sniffMedia(a) {
  const img = sniffImage(a);
  if (img) return img;
  if (a.length > 12 && String.fromCharCode(...a.subarray(4, 8)) === "ftyp") return "video/iso";
  if (a[0] === 0x1a && a[1] === 0x45 && a[2] === 0xdf && a[3] === 0xa3) return "video/webm";
  return null;
}
async function deleteMedia(env, id) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM media_chunks WHERE media_id = ?").bind(id),
    env.DB.prepare("DELETE FROM media WHERE id = ?").bind(id),
  ]);
}
async function serveMedia(req, env, id, cors) {
  const base = { "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox", "Cross-Origin-Resource-Policy": "cross-origin", ...cors };
  const nf = () => new Response("not found", { status: 404, headers: { ...base, "Cache-Control": "no-store" } });
  if (!IMG_ID_RE.test(id)) return nf();
  const m = await env.DB.prepare("SELECT mime, size, chunks FROM media WHERE id = ?").bind(id).first();
  if (!m) return nf();
  let start = 0, end = m.size - 1, partial = false;
  const range = req.headers.get("Range");
  if (range) {
    const r = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
    if (r && (r[1] || r[2])) {
      if (r[1]) { start = Number(r[1]); if (r[2]) end = Math.min(Number(r[2]), m.size - 1); }
      else { start = Math.max(0, m.size - Number(r[2])); }
      if (start > end || start >= m.size) {
        return new Response(null, { status: 416, headers: { ...base, "Content-Range": "bytes */" + m.size } });
      }
      partial = true;
    }
  }
  const headers = { ...base, "Content-Type": m.mime, "Accept-Ranges": "bytes", "Content-Length": String(end - start + 1), "Cache-Control": "public, max-age=31536000, immutable" };
  if (partial) headers["Content-Range"] = `bytes ${start}-${end}/${m.size}`;
  if (req.method === "HEAD") return new Response(null, { status: partial ? 206 : 200, headers });
  const first = Math.floor(start / CHUNK), last = Math.floor(end / CHUNK);
  let i = first;
  const stream = new ReadableStream({
    async pull(ctl) {
      if (i > last) { ctl.close(); return; }
      const row = await env.DB.prepare("SELECT data FROM media_chunks WHERE media_id = ? AND idx = ?").bind(id, i).first();
      if (!row) { ctl.error(new Error("missing chunk")); return; }
      let buf = new Uint8Array(row.data);
      const off = i * CHUNK;
      const s0 = Math.max(0, start - off), e0 = Math.min(buf.length, end - off + 1);
      ctl.enqueue(buf.subarray(s0, e0));
      i++;
    },
  });
  return new Response(stream, { status: partial ? 206 : 200, headers });
}
async function mediaInfo(env, postIds) {
  const out = {};
  if (!postIds.length) return out;
  const rows = (await env.DB.prepare(
    `SELECT p.post_id, m.id, m.kind, m.mime, m.w, m.h FROM profile_post_media p JOIN media m ON m.id = p.media_id
     WHERE p.post_id IN (${postIds.map(() => "?").join(",")}) ORDER BY p.post_id, p.ord`
  ).bind(...postIds).all()).results;
  for (const r of rows) (out[r.post_id] = out[r.post_id] || []).push({ id: r.id, kind: r.kind, mime: r.mime, w: r.w, h: r.h });
  return out;
}
const profileOf = (u, posts) => ({
  id: u.id, nickname: u.nickname || "", avatarId: u.avatar_id || null, bannerId: u.banner_id || null,
  status: u.status || "", frame: cleanFrame(u.frame), role: cleanRole(u.role), createdAt: u.created_at, posts,
});

async function profiles(req, env, ctx, url, path, user, cors) {
  const M = req.method;
  if (path === "/api/push/key" && M === "GET") return json({ key: env.VAPID_PUBLIC || null }, 200, cors);
  if (path === "/api/push/subscribe" && M === "POST") {
    const body = await readJson(req, 4096);
    const ep = body && body.endpoint, k = body && body.keys;
    if (!pushHostOk(env, ep) || !k || typeof k.p256dh !== "string" || typeof k.auth !== "string" || !/^[A-Za-z0-9_-]{80,100}={0,2}$/.test(k.p256dh) || !/^[A-Za-z0-9_-]{16,32}={0,2}$/.test(k.auth)) return fail("bad_subscription", 400, cors);
    if (!(await hit(env, "pushsub:" + user.id, 30, 3600000))) return fail("rate_limited", 429, cors);
    const n = await env.DB.prepare("SELECT COUNT(*) AS c FROM push_subs WHERE user_id = ?").bind(user.id).first();
    if (n.c >= 10) await env.DB.prepare("DELETE FROM push_subs WHERE id = (SELECT id FROM push_subs WHERE user_id = ? ORDER BY id LIMIT 1)").bind(user.id).run();
    await env.DB.prepare(
      `INSERT INTO push_subs (user_id, endpoint, p256dh, auth, chat, created_at) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth, chat = excluded.chat`
    ).bind(user.id, ep, k.p256dh.replace(/=+$/, ""), k.auth.replace(/=+$/, ""), body.chat === false ? 0 : 1, now()).run();
    return json({ ok: true }, 200, cors);
  }
  if (path === "/api/push/unsubscribe" && M === "POST") {
    const body = await readJson(req, 4096);
    if (!body || typeof body.endpoint !== "string") return fail("bad_request", 400, cors);
    await env.DB.prepare("DELETE FROM push_subs WHERE endpoint = ? AND user_id = ?").bind(body.endpoint, user.id).run();
    return json({ ok: true }, 200, cors);
  }
  // 프로필 보기
  let m = /^\/api\/users\/(\d{1,12})$/.exec(path);
  if (m && M === "GET") {
    const u = await env.DB.prepare("SELECT id, nickname, avatar_id, banner_id, status, frame, role, created_at FROM users WHERE id = ? AND nickname != ''").bind(Number(m[1])).first();
    if (!u) return fail("user_not_found", 404, cors);
    const c = await env.DB.prepare("SELECT COUNT(*) AS c FROM profile_posts WHERE user_id = ?").bind(u.id).first();
    return json({ profile: profileOf(u, c.c) }, 200, cors);
  }
  // 프로필 포스트 목록 (최신순, before=마지막 id)
  m = /^\/api\/users\/(\d{1,12})\/posts$/.exec(path);
  if (m && M === "GET") {
    const before = Number(url.searchParams.get("before") || 0);
    const args = [Number(m[1])];
    let sql = "SELECT id, user_id, body, created_at FROM profile_posts WHERE user_id = ?";
    if (Number.isInteger(before) && before > 0) { sql += " AND id < ?"; args.push(before); }
    const rows = (await env.DB.prepare(sql + " ORDER BY id DESC LIMIT ?").bind(...args, PPOST_PAGE).all()).results;
    const media = await mediaInfo(env, rows.map((r) => r.id));
    return json({ posts: rows.map((r) => ({ id: r.id, userId: r.user_id, body: r.body, createdAt: r.created_at, media: media[r.id] || [] })), more: rows.length === PPOST_PAGE }, 200, cors);
  }
  // 상태메시지
  if (path === "/api/profile" && M === "POST") {
    const body = await readJson(req);
    if (!body || typeof body.status !== "string") return fail("bad_request", 400, cors);
    const st = stripCtl(body.status, false).replace(/\s+/g, " ").trim();
    if (charLen(st) > MAX_STATUS) return fail("invalid_status", 400, cors);
    if (!(await hit(env, "status:" + user.id, 30, 600000))) return fail("rate_limited", 429, cors);
    await env.DB.prepare("UPDATE users SET status = ? WHERE id = ?").bind(st, user.id).run();
    return json({ user: { ...publicUser(user), status: st } }, 200, cors);
  }
  // 배너
  if (path === "/api/banner" && (M === "POST" || M === "DELETE")) {
    if (!(await hit(env, "banner:" + user.id, 10, 600000))) return fail("rate_limited", 429, cors);
    let id = null;
    if (M === "POST") {
      const img = await readImage(req, "banner");
      if (img.error) return fail(img.error, img.status, cors);
      id = await storeImage(env, user.id, "banner", img);
      if (!id) return fail("storage_full", 507, cors);
    }
    await env.DB.prepare("UPDATE users SET banner_id = ? WHERE id = ?").bind(id, user.id).run();
    await dropImageIfUnused(env, user.banner_id);
    return json({ user: { ...publicUser(user), bannerId: id } }, 200, cors);
  }
  // 미디어 올리기 (본문 = 파일 바이트)
  if (path === "/api/media" && M === "POST") {
    const declared = (req.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase();
    const kind = Object.keys(MEDIA_RULES).find((k) => MEDIA_RULES[k].types.includes(declared));
    if (!kind) return fail("unsupported_media", 415, cors);
    const rule = MEDIA_RULES[kind];
    const len = Number(req.headers.get("Content-Length"));
    if (!Number.isFinite(len) || len <= 0) return fail("length_required", 411, cors);
    if (len > rule.maxBytes) return fail("media_too_large", 413, cors);
    if (!(await hit(env, "media:" + user.id, 20, 600000)) || !(await hit(env, "media-day:" + user.id, 120, 86400000))) return fail("rate_limited", 429, cors);
    const today = await env.DB.prepare("SELECT COALESCE(SUM(size), 0) AS s FROM media WHERE user_id = ? AND created_at > ?").bind(user.id, now() - 86400000).first();
    if (today.s + len > MEDIA_DAY_BYTES) return fail("rate_limited", 429, cors);
    const buf = new Uint8Array(await req.arrayBuffer());
    if (!buf.length || buf.length > rule.maxBytes) return fail("media_too_large", 413, cors);
    const sniff = sniffMedia(buf);
    const okType = kind === "video" ? (sniff === "video/iso" && declared !== "video/webm") || (sniff === "video/webm" && declared === "video/webm") : sniff === declared;
    if (!okType) return fail("unsupported_media", 415, cors);
    let w = 0, h = 0;
    if (kind !== "video") {
      const d = imageSize(buf, declared);
      if (!d || !d.w || !d.h || d.w > 8000 || d.h > 8000) return fail("unsupported_media", 415, cors);
      w = d.w; h = d.h;
    } else {
      w = Math.max(0, Math.min(8000, parseInt(url.searchParams.get("w") || "0", 10) || 0));
      h = Math.max(0, Math.min(8000, parseInt(url.searchParams.get("h") || "0", 10) || 0));
    }
    if ((await storageUsed(env)) + buf.length > STORAGE_CAP) return fail("storage_full", 507, cors);
    const id = randomToken(16);
    const mime = declared === "video/quicktime" ? "video/mp4" : declared;
    const chunks = Math.ceil(buf.length / CHUNK);
    try {
      for (let i = 0; i < chunks; i++) {
        await env.DB.prepare("INSERT INTO media_chunks (media_id, idx, data) VALUES (?, ?, ?)").bind(id, i, buf.slice(i * CHUNK, (i + 1) * CHUNK)).run();
      }
      await env.DB.prepare("INSERT INTO media (id, user_id, kind, mime, size, w, h, chunks, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(id, user.id, kind, mime, buf.length, w, h, chunks, now()).run();
    } catch (e) {
      await env.DB.prepare("DELETE FROM media_chunks WHERE media_id = ?").bind(id).run();
      throw e;
    }
    return json({ media: { id, kind, mime, w, h } }, 201, cors);
  }
  // 프로필 포스트 쓰기
  if (path === "/api/pposts" && M === "POST") {
    if (!user.nickname) return fail("nickname_required", 400, cors);
    const body = await readJson(req);
    if (!body) return fail("bad_request", 400, cors);
    const ids = Array.isArray(body.mediaIds) ? body.mediaIds : [];
    if (ids.length > MAX_PPOST_MEDIA) return fail("bad_media", 400, cors);
    let text = "";
    if (typeof body.body === "string" && body.body.trim()) {
      text = normLong(body.body, MAX_PPOST);
      if (!text) return fail("invalid_ppost", 400, cors);
    }
    if (!text && !ids.length) return fail("invalid_ppost", 400, cors);
    const seen = new Set();
    for (const id of ids) {
      if (typeof id !== "string" || !IMG_ID_RE.test(id) || seen.has(id)) return fail("bad_media", 400, cors);
      seen.add(id);
      const ok = await env.DB.prepare("SELECT 1 FROM media m WHERE m.id = ? AND m.user_id = ? AND NOT EXISTS (SELECT 1 FROM profile_post_media p WHERE p.media_id = m.id)").bind(id, user.id).first();
      if (!ok) return fail("bad_media", 400, cors);
    }
    if (!(await hit(env, "ppost:" + user.id, 15, 600000)) || !(await hit(env, "ppost-day:" + user.id, 100, 86400000))) return fail("rate_limited", 429, cors);
    const r = await env.DB.prepare("INSERT INTO profile_posts (user_id, body, created_at) VALUES (?, ?, ?) RETURNING id, created_at").bind(user.id, text, now()).first();
    if (ids.length) await env.DB.batch(ids.map((id, i) => env.DB.prepare("INSERT INTO profile_post_media (post_id, media_id, ord) VALUES (?, ?, ?)").bind(r.id, id, i)));
    const media = await mediaInfo(env, [r.id]);
    return json({ post: { id: r.id, userId: user.id, body: text, createdAt: r.created_at, media: media[r.id] || [] } }, 201, cors);
  }
  // 프로필 포스트 삭제 (작성자 또는 사장·부사장)
  m = /^\/api\/pposts\/(\d{1,12})$/.exec(path);
  if (m && M === "DELETE") {
    const p = await env.DB.prepare("SELECT id, user_id FROM profile_posts WHERE id = ?").bind(Number(m[1])).first();
    if (!p) return fail("ppost_not_found", 404, cors);
    if (p.user_id !== user.id && !isMod(user)) return fail("forbidden", 403, cors);
    const mids = (await env.DB.prepare("SELECT media_id FROM profile_post_media WHERE post_id = ?").bind(p.id).all()).results.map((x) => x.media_id);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM profile_post_media WHERE post_id = ?").bind(p.id),
      env.DB.prepare("DELETE FROM profile_posts WHERE id = ?").bind(p.id),
    ]);
    for (const id of mids) await deleteMedia(env, id);
    return json({ ok: true }, 200, cors);
  }
  return null;
}


/* ---------- 웹 푸시 (VAPID + aes128gcm, RFC 8291/8292) ---------- */
const PUSH_HOSTS = [/^fcm\.googleapis\.com$/, /^updates\.push\.services\.mozilla\.com$/, /^([a-z0-9-]+\.)*push\.apple\.com$/, /^([a-z0-9-]+\.)*notify\.windows\.com$/, /^([a-z0-9-]+\.)*push\.services\.mozilla\.com$/];
function pushHostOk(env, ep) {
  if (typeof ep !== "string" || ep.length > 1024) return false;
  let u; try { u = new URL(ep); } catch { return false; }
  const extra = (env.PUSH_TEST_HOSTS || "").split(",").filter(Boolean);
  if (extra.includes(u.host)) return true;
  return u.protocol === "https:" && !u.port && PUSH_HOSTS.some((r) => r.test(u.hostname));
}
const b64u = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s) => fromB64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}
let vapidKeyCache = null;
async function vapidJwt(env, endpoint) {
  if (!vapidKeyCache) {
    const jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
    vapidKeyCache = await crypto.subtle.importKey("jwk", { ...jwk, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  }
  const aud = new URL(endpoint).origin;
  const h = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const p = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT || "https://example.com/" })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, vapidKeyCache, enc.encode(h + "." + p));
  return h + "." + p + "." + b64u(sig);
}
async function encryptPush(sub, payload) {
  const ua = fromB64u(sub.p256dh), auth = fromB64u(sub.auth);
  const uaKey = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(auth, secret, concat(enc.encode("WebPush: info\0"), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, concat(enc.encode(payload), new Uint8Array([2]))));
  const head = new Uint8Array(21); head.set(salt, 0); new DataView(head.buffer).setUint32(16, 4096); head[20] = 65;
  return concat(head, asPub, ct);
}
async function sendPush(env, sub, data) {
  if (!env.VAPID_PRIVATE_JWK || !env.VAPID_PUBLIC) return;
  try {
    const body = await encryptPush(sub, JSON.stringify(data));
    const res = await fetch(sub.endpoint, {
      method: "POST",
      headers: { "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", "TTL": "86400", "Urgency": "high",
        "Authorization": "vapid t=" + (await vapidJwt(env, sub.endpoint)) + ", k=" + env.VAPID_PUBLIC },
      body,
    });
    if (res.status === 404 || res.status === 410) await env.DB.prepare("DELETE FROM push_subs WHERE id = ?").bind(sub.id).run();
  } catch (e) { console.error("push", e && e.message); }
}
async function pushTo(env, rows, data) {
  await Promise.all(rows.slice(0, 40).map((r) => sendPush(env, r, data)));
}
const snip = (t, n = 80) => { const a = [...String(t || "").replace(/\s+/g, " ").trim()]; return a.length > n ? a.slice(0, n).join("") + "…" : a.join(""); };
const conText = (t) => String(t || "").replace(/\[\[con:\d+\]\]/g, "(콘)");
// 채팅: 답장 받은 사람에게는 '답장' 알림, 나머지는 '모든 채팅 알림'을 켠 기기에만
async function notifyChat(env, ctx, user, msg, mt) {
  if (dmPair(msg.channel)) {
    // DM: 받는 사람의 모든 기기에 ("모든 채팅 알림" 설정과 무관, 개인 메시지)
    const peer = dmPeer(user, msg.channel);
    const body = msg.kind === "image" ? "사진을 보냈습니다." : msg.kind === "emoticon" ? "이모티콘을 보냈습니다." : snip(await plainMentions(env, msg.text));
    const rs = (await env.DB.prepare("SELECT * FROM push_subs WHERE user_id = ?").bind(peer).all()).results;
    await pushTo(env, rs, { title: user.nickname + " · DM", body, url: "messenger.html#/dm/" + user.id, tag: "dm-" + user.id, kind: "dm", channel: msg.channel });
    return;
  }
  const company = msg.channel !== "free";
  const label = company ? "사내 메신저" : "자유 메신저";
  const url = company ? "messenger.html#/chat" : "messenger.html#/free";
  const tag = company ? "chat" : "free";
  const memberSql = company ? " AND user_id IN (SELECT id FROM users WHERE member = 1)" : "";
  const body = msg.kind === "image" ? "사진을 보냈습니다." : msg.kind === "emoticon" ? "이모티콘을 보냈습니다." : snip(await plainMentions(env, msg.text));
  // @everyone: 채널을 볼 수 있는 모든 사람에게 ("모든 채팅 알림"을 꺼 둔 사람 포함)
  if (mt && mt.all) {
    const rs = (await env.DB.prepare("SELECT * FROM push_subs WHERE user_id != ?" + memberSql).bind(user.id).all()).results;
    await pushTo(env, rs, { title: user.nickname + "님이 모두를 불렀습니다 · " + label, body, url, tag: tag + "-mention", kind: "mention", channel: msg.channel });
    return;
  }
  const mentioned = mt ? mt.ids.filter((id) => id !== user.id) : [];
  if (mentioned.length) {
    const rs = (await env.DB.prepare(`SELECT * FROM push_subs WHERE user_id IN (${mentioned.map(() => "?").join(",")})` + memberSql).bind(...mentioned).all()).results;
    await pushTo(env, rs, { title: user.nickname + "님이 회원님을 언급했습니다 · " + label, body, url, tag: tag + "-mention", kind: "mention", channel: msg.channel });
  }
  const replyUid = msg.reply && !msg.reply.missing && msg.reply.userId !== user.id ? msg.reply.userId : 0;
  if (replyUid && !mentioned.includes(replyUid)) {
    const rs = (await env.DB.prepare("SELECT * FROM push_subs WHERE user_id = ?" + memberSql).bind(replyUid).all()).results;
    await pushTo(env, rs, { title: user.nickname + "님이 답장했습니다 · " + label, body, url, tag, kind: "reply", channel: msg.channel });
  }
  const skip = [user.id, replyUid, ...mentioned];
  const rows = (await env.DB.prepare(`SELECT * FROM push_subs WHERE chat = 1 AND user_id NOT IN (${skip.map(() => "?").join(",")})` + memberSql).bind(...skip).all()).results;
  await pushTo(env, rows, { title: user.nickname + " · " + label, body, url, tag, kind: "chat", channel: msg.channel });
}
// 게시판: 내 글에 댓글, 내 댓글에 답글
async function notifyComment(env, ctx, user, postId, parentId, text) {
  const post = await env.DB.prepare("SELECT user_id, title FROM posts WHERE id = ?").bind(postId).first();
  if (!post) return;
  const targets = new Map();
  if (parentId) {
    const pc = await env.DB.prepare("SELECT user_id FROM comments WHERE id = ?").bind(parentId).first();
    if (pc && pc.user_id !== user.id) targets.set(pc.user_id, user.nickname + "님이 내 댓글에 답글을 남겼습니다");
  }
  if (post.user_id !== user.id && !targets.has(post.user_id)) targets.set(post.user_id, user.nickname + "님이 내 글에 댓글을 남겼습니다");
  if (!targets.size) return;
  const url = "messenger.html#/board/" + postId;
  const body = "「" + snip(post.title, 30) + "」 " + snip(conText(text), 60);
  const stub = env.ROOM.get(env.ROOM.idFromName("main"));
  for (const [uid, title] of targets) {
    ctx.waitUntil(stub.fetch("https://room/broadcast", { method: "POST", body: JSON.stringify({ type: "notify", to: [uid], kind: "board", title, body, url }) }).catch(() => {}));
    const rs = (await env.DB.prepare("SELECT * FROM push_subs WHERE user_id = ?").bind(uid).all()).results;
    await pushTo(env, rs, { title, body, url, tag: "board-" + postId, kind: "board" });
  }
}

/* ---------- 링크 미리보기 (OG) ---------- */
const UNFURL_TTL = 86400000, UNFURL_FAIL_TTL = 3600000, UNFURL_MAX = 524288;
function safeLinkUrl(raw) {
  let u;
  try { u = new URL(String(raw || "").trim()); } catch { return null; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  if (u.username || u.password) return null;
  if (u.port && u.port !== "80" && u.port !== "443") return null;
  const h = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!h || h.length > 253 || !h.includes(".")) return null;
  if (h.startsWith("[") || h.includes(":")) return null; // IPv6 literal
  if (/^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.lan|.*\.home|.*\.arpa|metadata\.google\.internal)$/.test(h)) return null;
  if (/^[0-9.]+$/.test(h) || /^0x/i.test(h)) {
    const p = h.split(".").map(Number);
    if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    const [a, b] = p;
    if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19))) return null;
  }
  u.hash = "";
  u.hostname = h;
  if (u.href.length > 1000) return null;
  return u;
}
function ytId(u) {
  const h = u.hostname.replace(/^(www|m|music)\./, "");
  let id = null;
  if (h === "youtu.be") id = u.pathname.slice(1).split("/")[0];
  else if (h === "youtube.com" || h === "youtube-nocookie.com") {
    if (u.pathname === "/watch") id = u.searchParams.get("v");
    else { const m = /^\/(shorts|embed|live|v)\/([^/?#]+)/.exec(u.pathname); if (m) id = m[2]; }
  }
  return id && /^[A-Za-z0-9_-]{11}$/.test(id) ? id : null;
}
const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", "#39": "'" };
function decodeEnt(s) {
  return String(s || "").replace(/&(#x[0-9a-f]+|#\d+|[a-z0-9]+);/gi, (m, e) => {
    if (e[0] === "#") { const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ""; } catch { return ""; } }
    return ENT[e.toLowerCase()] ?? m;
  });
}
const clip = (s, n) => { s = decodeEnt(s).replace(/\s+/g, " ").trim(); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
function parseOg(html, base) {
  const meta = {};
  const tagRe = /<meta\b[^>]*>/gi; let m;
  while ((m = tagRe.exec(html))) {
    const t = m[0];
    const k = /(?:property|name)\s*=\s*["']([^"']+)["']/i.exec(t), c = /content\s*=\s*["']([^"']*)["']/i.exec(t) || /content\s*=\s*([^\s>"']+)/i.exec(t);
    if (k && c) { const key = k[1].toLowerCase(); if (!(key in meta)) meta[key] = c[1]; }
  }
  const title = meta["og:title"] || meta["twitter:title"] || (/<title[^>]*>([\s\S]{0,400}?)<\/title>/i.exec(html) || [])[1] || "";
  const abs = (v) => { if (!v) return ""; try { const x = new URL(decodeEnt(v).trim(), base); return x.protocol === "https:" || x.protocol === "http:" ? x.href.slice(0, 1000) : ""; } catch { return ""; } };
  let icon = "";
  const lr = /<link\b[^>]*>/gi;
  while ((m = lr.exec(html))) { if (/rel\s*=\s*["'][^"']*icon[^"']*["']/i.test(m[0])) { const h = /href\s*=\s*["']([^"']+)["']/i.exec(m[0]); if (h) { icon = abs(h[1]); break; } } }
  return {
    title: clip(title, 200), description: clip(meta["og:description"] || meta["twitter:description"] || meta["description"] || "", 300),
    siteName: clip(meta["og:site_name"] || "", 80), image: abs(meta["og:image:secure_url"] || meta["og:image"] || meta["twitter:image"] || meta["twitter:image:src"]),
    icon,
  };
}
async function readCapped(res, max) {
  const reader = res.body && res.body.getReader(); if (!reader) return "";
  const chunks = []; let total = 0;
  while (total < max) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); total += value.length; if (/<\/head>/i.test(new TextDecoder().decode(value))) break; }
  try { reader.cancel(); } catch {}
  const buf = new Uint8Array(Math.min(total, max)); let o = 0;
  for (const c of chunks) { const n = Math.min(c.length, buf.length - o); buf.set(c.subarray(0, n), o); o += n; if (o >= buf.length) break; }
  const ct = res.headers.get("content-type") || ""; const cs = (/charset=([\w-]+)/i.exec(ct) || [])[1];
  let txt = new TextDecoder(cs || "utf-8", { fatal: false }).decode(buf);
  if (!cs) { const mc = /<meta[^>]+charset\s*=\s*["']?([\w-]+)/i.exec(txt); if (mc && !/utf-?8/i.test(mc[1])) { try { txt = new TextDecoder(mc[1]).decode(buf); } catch {} } }
  return txt;
}
async function fetchPreview(u) {
  const host = u.hostname.replace(/^www\./, "");
  const out = { url: u.href, host, title: "", description: "", siteName: "", image: "", icon: "" };
  const yid = ytId(u);
  const ctl = new AbortController(); const timer = setTimeout(() => ctl.abort(), 5000);
  try {
    if (yid) {
      out.youtube = yid; out.siteName = "YouTube"; out.image = "https://i.ytimg.com/vi/" + yid + "/hqdefault.jpg";
      const r = await fetch("https://www.youtube.com/oembed?format=json&url=" + encodeURIComponent("https://www.youtube.com/watch?v=" + yid), { signal: ctl.signal });
      if (r.ok) { const d = await r.json(); out.title = clip(d.title || "", 200); out.description = clip(d.author_name || "", 120); }
      return out;
    }
    let cur = u;
    for (let i = 0; i < 4; i++) {
      const r = await fetch(cur.href, { redirect: "manual", signal: ctl.signal, headers: { "User-Agent": "Mozilla/5.0 (compatible; GaecheonbakLinkPreview/1.0; +https://oaoaoaoartrt-creator.github.io/gaecheonbak/)", Accept: "text/html,application/xhtml+xml", "Accept-Language": "ko,en;q=0.8" } });
      if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
        const nx = safeLinkUrl(new URL(r.headers.get("location"), cur).href); try { r.body && r.body.cancel(); } catch {}
        if (!nx) return out; cur = nx; continue;
      }
      if (!r.ok || !/html/i.test(r.headers.get("content-type") || "")) { try { r.body && r.body.cancel(); } catch {} return out; }
      Object.assign(out, parseOg(await readCapped(r, UNFURL_MAX), cur.href));
      return out;
    }
    return out;
  } catch { return out; } finally { clearTimeout(timer); }
}
async function unfurl(env, url, user, ip, cors) {
  const u = safeLinkUrl(url);
  if (!u) return fail("invalid_url", 400, cors);
  const key = u.href, now = Date.now();
  const row = await env.DB.prepare("SELECT data, fetched_at FROM link_cache WHERE url = ?").bind(key).first();
  if (row) { const d = JSON.parse(row.data); if (now - row.fetched_at < (d.title ? UNFURL_TTL : UNFURL_FAIL_TTL)) return json({ preview: d }, 200, { ...cors, "Cache-Control": "private, max-age=3600" }); }
  if (!(await hit(env, "unfurl:" + user.id, 60, 600000)) || !(await hit(env, "unfurl-ip:" + ip, 200, 3600000))) return fail("rate_limited", 429, cors);
  const d = await fetchPreview(u);
  await env.DB.prepare("INSERT INTO link_cache (url, data, fetched_at) VALUES (?, ?, ?) ON CONFLICT(url) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at").bind(key, JSON.stringify(d), now).run();
  return json({ preview: d }, 200, { ...cors, "Cache-Control": "private, max-age=3600" });
}
