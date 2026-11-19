-- 사내 참여코드 입력 기록 + 사내 멤버 지급 기록 (추가만, 기존 데이터 변경 없음)
CREATE TABLE IF NOT EXISTS join_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  user_id INTEGER,
  nickname TEXT,
  ip_hash TEXT,
  country TEXT,
  ua TEXT,
  ok INTEGER NOT NULL DEFAULT 0,
  reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_join_attempts_ts ON join_attempts(ts);
CREATE TABLE IF NOT EXISTS member_grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  nickname TEXT,
  via TEXT
);
CREATE INDEX IF NOT EXISTS idx_member_grants_ts ON member_grants(ts);
