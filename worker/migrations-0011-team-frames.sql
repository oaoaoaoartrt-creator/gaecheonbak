-- 인원 소개 테두리·직함 지급 (id + login 둘 다 맞을 때만 적용, 다른 값은 건드리지 않음)
UPDATE users SET frame = 'hoqueen', role = 'staff' WHERE id = 18 AND login = 'ryoshu0622@gmail.com';
UPDATE users SET frame = 'bbunin', role = 'staff' WHERE id = 32 AND login = 'renoir0422';
UPDATE users SET frame = 'red', role = 'slave' WHERE id = 31 AND login = 'yan_vismok';
UPDATE users SET frame = 'geommeomwoyo', role = 'slave' WHERE id = 33 AND login = 'blackwhat';
UPDATE users SET frame = 'mobai', role = 'ration' WHERE id = 41 AND login = '1234@gmail.com';
UPDATE users SET frame = 'seommyeol', role = 'ration' WHERE id = 38 AND login = 'annihilation';
