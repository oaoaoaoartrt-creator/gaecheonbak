CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  login TEXT NOT NULL UNIQUE,
  pw_hash TEXT NOT NULL,
  pw_salt TEXT NOT NULL,
  pw_iter INTEGER NOT NULL,
  nickname TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  avatar_id TEXT,
  frame TEXT NOT NULL DEFAULT 'basic',
  role TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  banner_id TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  nickname TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  kind TEXT NOT NULL DEFAULT 'text',
  image_id TEXT,
  reply_to INTEGER
);
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL
);

-- 미디어 (0002)
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

-- 게시판 (0003)
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  category TEXT NOT NULL DEFAULT '일반',
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER,
  views INTEGER NOT NULL DEFAULT 0,
  up INTEGER NOT NULL DEFAULT 0,
  down INTEGER NOT NULL DEFAULT 0,
  comment_count INTEGER NOT NULL DEFAULT 0,
  pinned INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_posts_up ON posts(up);
CREATE INDEX IF NOT EXISTS idx_posts_pinned ON posts(pinned);
CREATE TABLE IF NOT EXISTS post_images (
  post_id INTEGER NOT NULL,
  image_id TEXT NOT NULL,
  ord INTEGER NOT NULL,
  PRIMARY KEY (post_id, image_id)
);
CREATE INDEX IF NOT EXISTS idx_post_images_image ON post_images(image_id);
CREATE TABLE IF NOT EXISTS post_votes (
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  v INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (post_id, user_id)
);
CREATE TABLE IF NOT EXISTS post_views (
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  PRIMARY KEY (post_id, user_id)
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  parent_id INTEGER,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER,
  deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nick_unique ON users(lower(trim(nickname))) WHERE nickname != '';

-- 콘 (0005)
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

-- 프로필 (0006)
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
