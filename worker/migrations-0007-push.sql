-- 0007: 웹 푸시 구독 (기기별). 기존 데이터 변경 없음
CREATE TABLE IF NOT EXISTS push_subs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  chat INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_push_subs_user ON push_subs(user_id);
