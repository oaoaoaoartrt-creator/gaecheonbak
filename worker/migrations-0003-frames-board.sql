-- 0003: 프로필 테두리(frame)·직책(role), 사내 게시판 (기존 users/messages 데이터 보존)
ALTER TABLE users ADD COLUMN frame TEXT NOT NULL DEFAULT 'basic';
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT '';
-- 관리자 지정: 사장(설표, id 1) = 플래티넘 왕관, 부사장(테이스트, id 3) = 황금 왕관
UPDATE users SET frame = 'platinum_crown', role = 'ceo' WHERE id = 1 AND nickname = '설표';
UPDATE users SET frame = 'gold_crown', role = 'vp' WHERE id = 3 AND nickname = '테이스트';

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
