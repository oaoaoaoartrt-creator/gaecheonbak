-- 0002: 프로필 사진, 이모티콘, 사진 메시지 (기존 users/messages 데이터 보존)
ALTER TABLE users ADD COLUMN avatar_id TEXT;
ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'text';
ALTER TABLE messages ADD COLUMN image_id TEXT;
CREATE TABLE IF NOT EXISTS images (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  purpose TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  w INTEGER NOT NULL,
  h INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  data BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_images_user ON images(user_id);
CREATE INDEX IF NOT EXISTS idx_images_size ON images(size);
CREATE INDEX IF NOT EXISTS idx_messages_image ON messages(image_id);
CREATE TABLE IF NOT EXISTS emoticons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  image_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_emoticons_user ON emoticons(user_id);
