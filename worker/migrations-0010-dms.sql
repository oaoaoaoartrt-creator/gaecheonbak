-- 0010: 1:1 DM 읽음 위치. DM 메시지는 기존 messages 테이블에 channel = 'dm:작은id-큰id' 로 저장. 기존 데이터 변경 없음
CREATE TABLE IF NOT EXISTS dm_reads (
  user_id INTEGER NOT NULL,
  channel TEXT NOT NULL,
  last_id INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, channel)
);
