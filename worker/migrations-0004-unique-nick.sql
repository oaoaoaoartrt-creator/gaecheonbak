-- 0004: 닉네임 중복 금지 (대소문자·앞뒤 공백 무시). 빈 닉네임(가입 직후)은 제외. 데이터 변경 없음
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nick_unique ON users(lower(trim(nickname))) WHERE nickname != '';
