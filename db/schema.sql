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
  emp_no       VARCHAR(16)  NULL UNIQUE,                 -- 사번
  hire_date    DATE         NULL,                        -- 입사일
  annual_days  TINYINT UNSIGNED NOT NULL DEFAULT 15,     -- 연간 부여 연차(일)
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
  size        BIGINT UNSIGNED NOT NULL,   -- 용량 제한이 없으므로 4GB 를 넘는 파일도 담는다
  sha256      CHAR(64)     NOT NULL,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 근태: 하루에 한 행(출근 시각, 퇴근 시각). 시각은 서버가 한국 시간으로 정해 넣고 사용자가 보낸 값은 쓰지 않는다.
CREATE TABLE attendance (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NOT NULL,
  work_date  DATE         NOT NULL,
  check_in   DATETIME     NOT NULL,
  check_out  DATETIME     NULL,
  UNIQUE KEY uq_attendance (user_id, work_date),
  CONSTRAINT chk_attendance_order CHECK (check_out IS NULL OR check_out >= check_in),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 휴가 신청: 신청자·종류·기간·일수는 만든 뒤 바꿀 수 없고, 상태 전이(승인·반려·취소)에 필요한 열만 수정할 수 있다.
-- 본인 신청은 본인이 결재할 수 없다(CHECK). 결재자 삭제 시 이력을 지우지 않도록 decided_by 는 기본 제약(RESTRICT)이다.
CREATE TABLE leave_requests (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id         INT UNSIGNED NOT NULL,
  leave_type      ENUM('annual','half','sick') NOT NULL,
  start_date      DATE         NOT NULL,
  end_date        DATE         NOT NULL,
  days            DECIMAL(4,1) NOT NULL,
  reason          VARCHAR(200) NOT NULL,
  status          ENUM('pending','approved','rejected','cancelled') NOT NULL DEFAULT 'pending',
  decided_by      INT UNSIGNED NULL,
  decided_at      DATETIME     NULL,
  decision_reason VARCHAR(200) NULL,
  created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT chk_leave_dates CHECK (end_date >= start_date),
  CONSTRAINT chk_leave_days CHECK (days > 0 AND days <= 30),
  CONSTRAINT chk_leave_no_self_decision CHECK (decided_by IS NULL OR decided_by <> user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (decided_by) REFERENCES users(id)
) ENGINE=InnoDB;

-- 프로필 사진: 사용자당 한 장. 파일은 웹루트 밖 instance/uploads/avatars 에 무작위 이름으로 둔다.
CREATE TABLE profile_photos (
  user_id     INT UNSIGNED PRIMARY KEY,
  stored_name CHAR(36)     NOT NULL UNIQUE,
  mime        VARCHAR(64)  NOT NULL,
  size        INT UNSIGNED NOT NULL,
  sha256      CHAR(64)     NOT NULL,
  updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
  body         MEDIUMTEXT   NOT NULL,                  -- body_html=1 이면 app/richtext.py 로 살균한 HTML(공문 본문), 0 이면 일반 글자
  body_html    TINYINT(1)   NOT NULL DEFAULT 0,
  recipient    VARCHAR(100) NULL,                      -- 공문의 수신(받는 곳). 비어 있으면 내부 결재
  requester_id INT UNSIGNED NOT NULL,
  expense_id   INT UNSIGNED NULL,
  status       ENUM('pending','approved','rejected','withdrawn') NOT NULL DEFAULT 'pending',
  doc_type     ENUM('general','coop','trip','purchase','expense','expenditure') NOT NULL DEFAULT 'general',   -- 양식(문서번호 앞부분)
  urgency      ENUM('normal','urgent') NOT NULL DEFAULT 'normal',
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

-- 참조자: 결재하지는 않지만 문서를 볼 수 있는 사람(상신 시점에 정해지며 이후 바꿀 수 없다).
CREATE TABLE approval_cc (
  approval_id INT UNSIGNED NOT NULL,
  user_id     INT UNSIGNED NOT NULL,
  PRIMARY KEY (approval_id, user_id),
  KEY idx_cc_user (user_id),
  FOREIGN KEY (approval_id) REFERENCES approvals(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 결재 첨부파일: 파일은 웹루트 밖 instance/uploads/approvals 에 무작위 이름으로 둔다. 상신할 때와, 결재자가 승인·반려할 때 올릴 수 있다.
CREATE TABLE approval_files (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  approval_id INT UNSIGNED NOT NULL,
  stored_name CHAR(36)     NOT NULL UNIQUE,
  orig_name   VARCHAR(120) NOT NULL,
  mime        VARCHAR(64)  NOT NULL,
  size        BIGINT UNSIGNED NOT NULL,   -- 용량 제한이 없으므로 4GB 를 넘는 파일도 담는다
  sha256      CHAR(64)     NOT NULL,
  step_no     TINYINT UNSIGNED NULL,     -- NULL = 상신할 때 올린 첨부, 값이 있으면 그 결재 단계에서 결재자가 올린 첨부
  uploaded_by INT UNSIGNED NULL,         -- 결재 첨부를 올린 결재자(상신 첨부는 NULL = 상신자)
  KEY idx_files_approval (approval_id),
  FOREIGN KEY (approval_id) REFERENCES approvals(id) ON DELETE CASCADE,
  FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 지출결의서(양식 expenditure): 결재 문서 하나에 지출 정보 한 행과 내역 여러 행이 붙는다. 금액은 서버가 수량×단가로 계산해 넣고
-- 합계도 서버가 낸다(화면에서 보낸 금액은 쓰지 않는다). 상신한 뒤에는 수정·삭제할 수 없다(grants.sql).
CREATE TABLE expenditures (
  approval_id   INT UNSIGNED PRIMARY KEY,
  spend_date    DATE         NOT NULL,                  -- 지출 일자
  account_name  VARCHAR(40)  NOT NULL,                  -- 계정과목(앱의 허용 목록)
  pay_method    ENUM('card','transfer','cash') NOT NULL,
  payee         VARCHAR(100) NOT NULL,                  -- 지급처(거래처)
  payee_account VARCHAR(100) NULL,                      -- 지급 계좌(계좌이체일 때). 민감 정보라 로그에 남기지 않는다
  pay_due       DATE         NULL,                      -- 지급 예정일
  evidence      ENUM('receipt','tax_invoice','card_slip','contract','none') NOT NULL,
  total_amount  BIGINT UNSIGNED NOT NULL,
  CONSTRAINT chk_expenditure_total CHECK (total_amount > 0),
  FOREIGN KEY (approval_id) REFERENCES approvals(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE expenditure_items (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  approval_id INT UNSIGNED NOT NULL,
  line_no     TINYINT UNSIGNED NOT NULL,
  item        VARCHAR(100) NOT NULL,
  memo        VARCHAR(100) NULL,
  qty         INT UNSIGNED NOT NULL,
  unit_price  BIGINT UNSIGNED NOT NULL,
  amount      BIGINT UNSIGNED NOT NULL,                 -- qty × unit_price (서버가 계산)
  UNIQUE KEY uq_expenditure_line (approval_id, line_no),
  CONSTRAINT chk_expenditure_qty CHECK (qty > 0),
  CONSTRAINT chk_expenditure_amount CHECK (amount = qty * unit_price),
  FOREIGN KEY (approval_id) REFERENCES approvals(id) ON DELETE CASCADE
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
