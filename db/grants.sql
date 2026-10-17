-- 최소권한 계정. __DB__, __APP_PW__, __CONF_PW__ 는 init.sh 가 치환한다.
-- 앱 계정: 필요한 표에 필요한 동작만. DDL/FILE/SUPER/GRANT 없음. 기밀 표 접근 없음.
CREATE USER IF NOT EXISTS 'nexus_app'@'%' IDENTIFIED BY '__APP_PW__';
CREATE USER IF NOT EXISTS 'nexus_conf'@'%' IDENTIFIED BY '__CONF_PW__';

-- users: 로그인 처리(비밀번호 해시·실패 횟수·잠금)와 관리자 역할 변경에 필요한 열만 수정 가능.
-- 아이디·이름·부서를 앱 계정이 바꿀 수 없다.
GRANT SELECT, INSERT         ON `__DB__`.users         TO 'nexus_app'@'%';
GRANT UPDATE (password_hash, failed_count, locked_until, role, session_version) ON `__DB__`.users TO 'nexus_app'@'%';
GRANT SELECT                 ON `__DB__`.employees     TO 'nexus_app'@'%';
GRANT SELECT                 ON `__DB__`.documents     TO 'nexus_app'@'%';
GRANT SELECT, INSERT, DELETE ON `__DB__`.posts         TO 'nexus_app'@'%';
GRANT SELECT, INSERT, DELETE ON `__DB__`.attachments   TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.chat_messages TO 'nexus_app'@'%';
-- 경비·결재는 이력을 남기므로 DELETE 없음. UPDATE 는 상태 전이에 필요한 열만 허용한다
-- (소유자·금액·상신자·결재자를 앱 계정이 바꿀 수 없다).
GRANT SELECT, INSERT         ON `__DB__`.expenses       TO 'nexus_app'@'%';
GRANT UPDATE (status)        ON `__DB__`.expenses       TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.approvals      TO 'nexus_app'@'%';
GRANT UPDATE (status, current_step, decided_at) ON `__DB__`.approvals TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.approval_steps TO 'nexus_app'@'%';
GRANT UPDATE (status, reason, decided_at)       ON `__DB__`.approval_steps TO 'nexus_app'@'%';

-- 기밀 표 전용 계정: 읽기만, 그 표들만. 앱은 기밀 권한 확인을 통과한 뒤에만 이 계정을 쓴다.
GRANT SELECT ON `__DB__`.confidential_documents TO 'nexus_conf'@'%';
GRANT SELECT ON `__DB__`.payroll                TO 'nexus_conf'@'%';
GRANT SELECT ON `__DB__`.financial_reports      TO 'nexus_conf'@'%';
