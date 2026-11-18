-- 0006: 프로필(상태메시지·배너), 프로필 포스트, 큰 미디어(GIF·동영상) 분할 저장. 기존 데이터 변경 없음
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN banner_id TEXT;
CREATE TABLE IF NOT EXISTS media (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  w INTEGER NOT NULL DEFAULT 0,
  h INTEGER NOT NULL DEFAULT 0,
  chunks INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_media_user ON media(user_id);
CREATE TABLE IF NOT EXISTS media_chunks (
  media_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  data BLOB NOT NULL,
  PRIMARY KEY (media_id, idx)
);
CREATE TABLE IF NOT EXISTS profile_posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_profile_posts_user ON profile_posts(user_id);
CREATE TABLE IF NOT EXISTS profile_post_media (
  post_id INTEGER NOT NULL,
  media_id TEXT NOT NULL,
  ord INTEGER NOT NULL,
  PRIMARY KEY (post_id, media_id)
);
CREATE INDEX IF NOT EXISTS idx_ppm_media ON profile_post_media(media_id);
