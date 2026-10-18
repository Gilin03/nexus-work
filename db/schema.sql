-- 공통 스키마. init.sh 가 nexus, nexus_test 두 DB 에 각각 적용한다.
CREATE TABLE users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(32)  NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role          ENUM('employee','manager','admin') NOT NULL DEFAULT 'employee',
  display_name  VARCHAR(64)  NOT NULL,
  dept          VARCHAR(64)  NOT NULL,
  failed_count  INT UNSIGNED NOT NULL DEFAULT 0,
  locked_until  DATETIME     NULL,
  session_version INT UNSIGNED NOT NULL DEFAULT 0,   -- 로그아웃·비밀번호 변경 때 올려 이전 세션 쿠키를 모두 무효화한다
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 직원 주소록(일반 정보). 계정이 없는 직원도 있을 수 있다.
CREATE TABLE employees (
  id      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NULL UNIQUE,
  name    VARCHAR(64) NOT NULL,
  dept    VARCHAR(64) NOT NULL,
  title   VARCHAR(64) NOT NULL,
  ext     VARCHAR(16) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

-- 일반 문서
CREATE TABLE documents (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  title      VARCHAR(200) NOT NULL,
  body       TEXT         NOT NULL,
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 기밀 표 3개(confidential_documents, payroll, financial_reports)는 nexus_conf 계정만 읽는다.
CREATE TABLE confidential_documents (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  title      VARCHAR(200) NOT NULL,
  body       TEXT         NOT NULL,
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE payroll (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id     INT UNSIGNED NOT NULL,
  pay_month   CHAR(7)      NOT NULL,
  base_salary INT UNSIGNED NOT NULL,
  bonus       INT UNSIGNED NOT NULL DEFAULT 0,
  UNIQUE KEY uq_payroll (user_id, pay_month),
  FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE TABLE financial_reports (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  report_month CHAR(7)      NOT NULL,
  title        VARCHAR(200) NOT NULL,
  body         TEXT         NOT NULL,
  created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 게시판: board 로 공지/자유 구분
CREATE TABLE posts (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  board      ENUM('notice','free') NOT NULL DEFAULT 'free',
  author_id  INT UNSIGNED NOT NULL,
  title      VARCHAR(120) NOT NULL,
  body       TEXT         NOT NULL,
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_posts_board (board, created_at),
  FOREIGN KEY (author_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE TABLE attachments (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  post_id     INT UNSIGNED NOT NULL,
  stored_name CHAR(36)     NOT NULL UNIQUE,
  orig_name   VARCHAR(120) NOT NULL,
  mime        VARCHAR(64)  NOT NULL,
  size        INT UNSIGNED NOT NULL,
  sha256      CHAR(64)     NOT NULL,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 챗봇 대화 기록: 본인 것만 조회(앱에서 user_id 로 강제)
CREATE TABLE chat_messages (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NOT NULL,
  sender     ENUM('user','assistant') NOT NULL,
  content    TEXT         NOT NULL,
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_chat_user (user_id, id),
  FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE TABLE expenses (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NOT NULL,
  title      VARCHAR(120) NOT NULL,
  amount     INT UNSIGNED NOT NULL,
  status     ENUM('draft','submitted','approved','rejected') NOT NULL DEFAULT 'draft',
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_expenses_user (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

-- 전자결재: 상신자가 정한 순서(결재선)대로 순차 결재한다.
-- approvals 는 문서 전체의 상태, approval_steps 는 결재자별 단계다.
CREATE TABLE approvals (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  title        VARCHAR(200) NOT NULL,
  body         TEXT         NOT NULL,
  requester_id INT UNSIGNED NOT NULL,
  expense_id   INT UNSIGNED NULL,
  status       ENUM('pending','approved','rejected','withdrawn') NOT NULL DEFAULT 'pending',
  current_step TINYINT UNSIGNED NOT NULL DEFAULT 1,
  decided_at   DATETIME     NULL,
  created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_approvals_requester (requester_id),
  FOREIGN KEY (requester_id) REFERENCES users(id),
  FOREIGN KEY (expense_id)   REFERENCES expenses(id)
) ENGINE=InnoDB;

CREATE TABLE approval_steps (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  approval_id INT UNSIGNED NOT NULL,
  step_no     TINYINT UNSIGNED NOT NULL,
  approver_id INT UNSIGNED NOT NULL,
  status      ENUM('waiting','pending','approved','rejected','skipped') NOT NULL DEFAULT 'waiting',
  reason      VARCHAR(500) NULL,
  decided_at  DATETIME     NULL,
  UNIQUE KEY uq_step_no (approval_id, step_no),
  UNIQUE KEY uq_step_approver (approval_id, approver_id),
  KEY idx_steps_approver (approver_id, status),
  CONSTRAINT chk_step_no CHECK (step_no BETWEEN 1 AND 5),
  FOREIGN KEY (approval_id) REFERENCES approvals(id),
  FOREIGN KEY (approver_id) REFERENCES users(id)
) ENGINE=InnoDB;

-- 상신자 본인을 결재선에 넣을 수 없다(앱 검사의 이중 방어). 결재자 열은 앱 계정이 수정할 수 없다(grants.sql).
DELIMITER //
CREATE TRIGGER trg_steps_no_self_approval BEFORE INSERT ON approval_steps
FOR EACH ROW
BEGIN
  IF NEW.approver_id = (SELECT requester_id FROM approvals WHERE id = NEW.approval_id) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'requester cannot be an approver of own request';
  END IF;
END//
DELIMITER ;

-- ===== 메신저(별도 앱: nexus-messenger)용 표. 계정은 users 를 그대로 쓴다. =====

-- 모바일·데스크톱 클라이언트 인증용 토큰. 토큰 평문은 저장하지 않고 sha256 해시만 둔다
-- (로그인 쿠키·CSRF 와는 별개 체계 — 네이티브 앱은 쿠키를 못 쓰므로).
CREATE TABLE api_tokens (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NOT NULL,
  token_hash CHAR(64)     NOT NULL UNIQUE,
  device     VARCHAR(120) NOT NULL DEFAULT '',
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME     NOT NULL,
  revoked_at DATETIME     NULL,
  KEY idx_tokens_user (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

-- 대화방: 1:1(dm) 또는 그룹(group). dm 은 이름이 없다(참가자 이름으로 화면에 표시).
CREATE TABLE conversations (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  kind       ENUM('dm','group') NOT NULL,
  name       VARCHAR(120) NULL,
  created_by INT UNSIGNED NOT NULL,
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (created_by) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE TABLE conversation_members (
  conversation_id      INT UNSIGNED NOT NULL,
  user_id              INT UNSIGNED NOT NULL,
  joined_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_read_message_id INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (conversation_id, user_id),
  KEY idx_members_user (user_id),
  FOREIGN KEY (conversation_id) REFERENCES conversations(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE TABLE messenger_messages (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  conversation_id INT UNSIGNED  NOT NULL,
  sender_id       INT UNSIGNED  NOT NULL,
  body            VARCHAR(4000) NOT NULL,
  created_at      TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_msg_conv (conversation_id, id),
  FOREIGN KEY (conversation_id) REFERENCES conversations(id),
  FOREIGN KEY (sender_id) REFERENCES users(id)
) ENGINE=InnoDB;
