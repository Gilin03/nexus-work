-- 최소권한 계정. __DB__, __APP_PW__, __CONF_PW__ 는 init.sh 가 치환한다.
-- 앱 계정: 필요한 표에 필요한 동작만. DDL/FILE/SUPER/GRANT 없음. 기밀 표 접근 없음.
CREATE USER IF NOT EXISTS 'nexus_app'@'%' IDENTIFIED BY '__APP_PW__';
CREATE USER IF NOT EXISTS 'nexus_conf'@'%' IDENTIFIED BY '__CONF_PW__';

-- users: 로그인 처리(비밀번호 해시·실패 횟수·잠금)와 관리자 역할 변경에 필요한 열만 수정 가능.
-- 아이디·이름·부서를 앱 계정이 바꿀 수 없다. 사용자 삭제는 행을 지우지 않고 deleted_at·deleted_by 로 표시한다(DELETE 권한 없음).
GRANT SELECT, INSERT, DELETE ON `__DB__`.security_auth_events TO 'nexus_app'@'%';
GRANT UPDATE (r6_emitted_at, r1_emitted_at) ON `__DB__`.security_auth_events TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.users         TO 'nexus_app'@'%';
GRANT UPDATE (password_hash, failed_count, locked_until, role, session_version, deleted_at, deleted_by, dept) ON `__DB__`.users TO 'nexus_app'@'%';
-- 직원: 조회와 등록(관리자 화면의 계정 등록이 인사카드를 함께 만든다)만. 수정·삭제는 불가(사번·입사일·연차 보호).
GRANT SELECT, INSERT         ON `__DB__`.employees     TO 'nexus_app'@'%';
-- 직급(승진·강등)은 관리자 화면에서 바꾼다. 다른 열(사번·입사일·연차·부서·이름)은 그대로 수정 불가.
GRANT UPDATE (title, dept)   ON `__DB__`.employees     TO 'nexus_app'@'%';
GRANT SELECT                 ON `__DB__`.documents     TO 'nexus_app'@'%';
GRANT SELECT, INSERT, DELETE ON `__DB__`.posts         TO 'nexus_app'@'%';
GRANT SELECT, INSERT, DELETE ON `__DB__`.attachments   TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.chat_messages TO 'nexus_app'@'%';
-- 근태: 출근은 INSERT, 퇴근은 check_out 열만 UPDATE. 삭제 없음(이력 유지).
GRANT SELECT, INSERT         ON `__DB__`.attendance TO 'nexus_app'@'%';
GRANT UPDATE (check_out)     ON `__DB__`.attendance TO 'nexus_app'@'%';
-- 휴가: 상태 전이에 필요한 열만 수정(신청자·기간·일수 변경 불가), 삭제 없음.
GRANT SELECT, INSERT         ON `__DB__`.leave_requests TO 'nexus_app'@'%';
GRANT UPDATE (status, decided_by, decided_at, decision_reason) ON `__DB__`.leave_requests TO 'nexus_app'@'%';
-- 프로필 사진은 바꿀 때 지우고 다시 넣는다(UPDATE 권한 없음).
GRANT SELECT, INSERT, DELETE ON `__DB__`.profile_photos TO 'nexus_app'@'%';
-- 경비·결재는 이력을 남기므로 DELETE 없음. UPDATE 는 상태 전이에 필요한 열만 허용한다
-- (소유자·금액·상신자·결재자를 앱 계정이 바꿀 수 없다).
GRANT SELECT, INSERT         ON `__DB__`.expenses       TO 'nexus_app'@'%';
GRANT UPDATE (status)        ON `__DB__`.expenses       TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.approvals      TO 'nexus_app'@'%';
GRANT UPDATE (status, current_step, decided_at) ON `__DB__`.approvals TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.approval_steps TO 'nexus_app'@'%';
-- 참조자·첨부는 상신 때 넣기만 한다(수정·삭제 불가).
GRANT SELECT, INSERT         ON `__DB__`.approval_cc    TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.approval_files TO 'nexus_app'@'%';
-- 지출결의서와 내역은 상신 때 넣기만 한다(수정·삭제 불가).
GRANT SELECT, INSERT         ON `__DB__`.expenditures      TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.expenditure_items TO 'nexus_app'@'%';
GRANT UPDATE (status, reason, decided_at)       ON `__DB__`.approval_steps TO 'nexus_app'@'%';

-- 업무·자료: 이력을 남기므로 DELETE 는 구성원 해제(project_members)에만 준다. 수정은 상태 전이에 필요한 열만.
GRANT SELECT, INSERT         ON `__DB__`.projects        TO 'nexus_app'@'%';
GRANT UPDATE (status)        ON `__DB__`.projects        TO 'nexus_app'@'%';
GRANT SELECT, INSERT, DELETE ON `__DB__`.project_members TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.tasks           TO 'nexus_app'@'%';
GRANT UPDATE (status, completed_at, assignee_id) ON `__DB__`.tasks TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.task_comments   TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.events          TO 'nexus_app'@'%';
GRANT UPDATE (status)        ON `__DB__`.events          TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.event_attendees TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.resources       TO 'nexus_app'@'%';
GRANT UPDATE (active)        ON `__DB__`.resources       TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.reservations    TO 'nexus_app'@'%';
GRANT UPDATE (status)        ON `__DB__`.reservations    TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.lib_folders     TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.lib_files       TO 'nexus_app'@'%';
GRANT UPDATE (deleted_at, deleted_by) ON `__DB__`.lib_files TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.lib_forms       TO 'nexus_app'@'%';
GRANT UPDATE (deleted_at)    ON `__DB__`.lib_forms       TO 'nexus_app'@'%';
GRANT SELECT, INSERT         ON `__DB__`.contacts        TO 'nexus_app'@'%';
GRANT UPDATE (deleted_at)    ON `__DB__`.contacts        TO 'nexus_app'@'%';

-- 메신저(nexus-messenger)용 표. 토큰은 발급·조회·폐기(revoked_at)만, 삭제는 없다(감사 흔적 유지).
GRANT SELECT, INSERT              ON `__DB__`.api_tokens           TO 'nexus_app'@'%';
GRANT UPDATE (revoked_at)         ON `__DB__`.api_tokens           TO 'nexus_app'@'%';
GRANT SELECT, INSERT              ON `__DB__`.conversations        TO 'nexus_app'@'%';
GRANT SELECT, INSERT              ON `__DB__`.conversation_members TO 'nexus_app'@'%';
GRANT UPDATE (last_read_message_id) ON `__DB__`.conversation_members TO 'nexus_app'@'%';
GRANT SELECT, INSERT              ON `__DB__`.messenger_messages   TO 'nexus_app'@'%';

-- 기밀 표 전용 계정: 읽기만, 그 표들만. 앱은 기밀 권한 확인을 통과한 뒤에만 이 계정을 쓴다.
GRANT SELECT ON `__DB__`.confidential_documents TO 'nexus_conf'@'%';
GRANT SELECT ON `__DB__`.payroll                TO 'nexus_conf'@'%';
GRANT SELECT ON `__DB__`.financial_reports      TO 'nexus_conf'@'%';


-- IP 차단 목록 (보안 관제 및 n8n 대응)
GRANT SELECT, INSERT, UPDATE, DELETE ON __DB__.blocked_ips TO 'nexus_app'@'%';
