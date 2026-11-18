-- 0008: 채팅 채널 분리(사내/자유)와 사내 멤버십. 기존 메시지는 모두 사내 채널에 그대로 남음
ALTER TABLE messages ADD COLUMN channel TEXT NOT NULL DEFAULT 'company';
ALTER TABLE users ADD COLUMN member INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel, id);
-- 기존 임직원(설표·테이스트·인간·호퀸)만 사내 멤버로 지정. 로얄44 등 그 외는 비멤버
UPDATE users SET member = 1 WHERE (id = 1 AND nickname = '설표') OR (id = 3 AND nickname = '테이스트') OR (id = 6 AND nickname = '인간') OR nickname = '호퀸';
