-- Additive migration for already initialized nexus and nexus_test databases.
-- The application stores only short-lived, non-secret authentication evidence.
CREATE TABLE IF NOT EXISTS nexus.security_auth_events (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  request_id      CHAR(32)     NOT NULL,
  event_type      VARCHAR(32)  NOT NULL,
  username        VARCHAR(64)  NOT NULL,
  src_ip          VARCHAR(45)  NOT NULL,
  occurred_at     DATETIME(6)  NOT NULL,
  r6_emitted_at   DATETIME(6)  NULL,
  r1_emitted_at   DATETIME(6)  NULL,
  KEY idx_security_auth_user_type_time (username, event_type, occurred_at),
  KEY idx_security_auth_lock_ip_time (event_type, username, src_ip, occurred_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS nexus_test.security_auth_events (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  request_id      CHAR(32)     NOT NULL,
  event_type      VARCHAR(32)  NOT NULL,
  username        VARCHAR(64)  NOT NULL,
  src_ip          VARCHAR(45)  NOT NULL,
  occurred_at     DATETIME(6)  NOT NULL,
  r6_emitted_at   DATETIME(6)  NULL,
  r1_emitted_at   DATETIME(6)  NULL,
  KEY idx_security_auth_user_type_time (username, event_type, occurred_at),
  KEY idx_security_auth_lock_ip_time (event_type, username, src_ip, occurred_at)
) ENGINE=InnoDB;

SET @r1_column_sql = IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = 'nexus' AND TABLE_NAME = 'security_auth_events' AND COLUMN_NAME = 'r1_emitted_at') = 0,
  'ALTER TABLE nexus.security_auth_events ADD COLUMN r1_emitted_at DATETIME(6) NULL',
  'SELECT 1'
);
PREPARE r1_column_stmt FROM @r1_column_sql;
EXECUTE r1_column_stmt;
DEALLOCATE PREPARE r1_column_stmt;

SET @r1_test_column_sql = IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = 'nexus_test' AND TABLE_NAME = 'security_auth_events' AND COLUMN_NAME = 'r1_emitted_at') = 0,
  'ALTER TABLE nexus_test.security_auth_events ADD COLUMN r1_emitted_at DATETIME(6) NULL',
  'SELECT 1'
);
PREPARE r1_test_column_stmt FROM @r1_test_column_sql;
EXECUTE r1_test_column_stmt;
DEALLOCATE PREPARE r1_test_column_stmt;

GRANT SELECT, INSERT, DELETE ON nexus.security_auth_events TO 'nexus_app'@'%';
GRANT UPDATE (r6_emitted_at, r1_emitted_at) ON nexus.security_auth_events TO 'nexus_app'@'%';
GRANT SELECT, INSERT, DELETE ON nexus_test.security_auth_events TO 'nexus_app'@'%';
GRANT UPDATE (r6_emitted_at, r1_emitted_at) ON nexus_test.security_auth_events TO 'nexus_app'@'%';

FLUSH PRIVILEGES;
