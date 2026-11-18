-- 링크 미리보기 캐시 (0009)
CREATE TABLE IF NOT EXISTS link_cache (
  url TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  fetched_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_link_cache_at ON link_cache(fetched_at);
