-- 0005: 채팅 답장(reply_to), 게시판 콘(주제별 묶음). 기존 데이터 변경 없음
ALTER TABLE messages ADD COLUMN reply_to INTEGER;
CREATE TABLE IF NOT EXISTS con_packs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_con_packs_user ON con_packs(user_id);
CREATE TABLE IF NOT EXISTS cons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pack_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  image_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cons_pack ON cons(pack_id);
CREATE INDEX IF NOT EXISTS idx_cons_image ON cons(image_id);
