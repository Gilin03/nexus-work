-- Additive, idempotent R11 correlation and NEXUS Ticket persistence.
-- The Ticket event_payload contains only the workflow's normalized allowlist fields.

CREATE TABLE IF NOT EXISTS nexus.security_ai_tool_denials (
  request_id  VARCHAR(64) NOT NULL PRIMARY KEY,
  user_id     INT UNSIGNED NOT NULL,
  session_id  VARCHAR(64) NOT NULL,
  tool_name   VARCHAR(64) NOT NULL,
  occurred_at DATETIME(6) NOT NULL,
  KEY idx_ai_deny_correlation (user_id, session_id, tool_name, occurred_at),
  KEY idx_ai_deny_cleanup (occurred_at),
  FOREIGN KEY (user_id) REFERENCES nexus.users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS nexus_test.security_ai_tool_denials (
  request_id  VARCHAR(64) NOT NULL PRIMARY KEY,
  user_id     INT UNSIGNED NOT NULL,
  session_id  VARCHAR(64) NOT NULL,
  tool_name   VARCHAR(64) NOT NULL,
  occurred_at DATETIME(6) NOT NULL,
  KEY idx_ai_deny_correlation (user_id, session_id, tool_name, occurred_at),
  KEY idx_ai_deny_cleanup (occurred_at),
  FOREIGN KEY (user_id) REFERENCES nexus_test.users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS nexus.security_incident_tickets (
  id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ticket_key        VARCHAR(255) NOT NULL,
  status            ENUM('open','closed') NOT NULL DEFAULT 'open',
  active_ticket_key VARCHAR(255) GENERATED ALWAYS AS (CASE WHEN status='open' THEN ticket_key ELSE NULL END) STORED,
  src_ip            VARCHAR(45) NOT NULL DEFAULT '',
  ticket_type       VARCHAR(80) NOT NULL,
  type_rank         SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  event_count       BIGINT UNSIGNED NOT NULL DEFAULT 0,
  rule_ids          JSON NOT NULL,
  user_names        JSON NOT NULL,
  first_seen        DATETIME(6) NOT NULL,
  last_seen         DATETIME(6) NOT NULL,
  latest_event      JSON NOT NULL,
  resolution        VARCHAR(40) NULL,
  closed_at         DATETIME(6) NULL,
  note              VARCHAR(500) NULL,
  responses         JSON NOT NULL,
  UNIQUE KEY uq_security_incident_active_key (active_ticket_key),
  KEY idx_security_incident_status_seen (status, last_seen)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS nexus.security_incident_alerts (
  alert_id      VARCHAR(160) NOT NULL PRIMARY KEY,
  receipt_id    VARCHAR(64) NOT NULL,
  ticket_id     BIGINT UNSIGNED NULL,
  rule_id       VARCHAR(8) NOT NULL,
  event_type    VARCHAR(80) NOT NULL,
  user_name     VARCHAR(64) NOT NULL DEFAULT '',
  src_ip        VARCHAR(45) NOT NULL DEFAULT '',
  event_count   INT UNSIGNED NOT NULL DEFAULT 1,
  occurred_at   DATETIME(6) NOT NULL,
  event_payload JSON NOT NULL,
  KEY idx_security_incident_alert_ticket (ticket_id, occurred_at),
  KEY idx_security_incident_alert_rule_time (rule_id, occurred_at),
  CONSTRAINT fk_security_incident_alert_ticket FOREIGN KEY (ticket_id)
    REFERENCES nexus.security_incident_tickets(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- The table may already exist from an earlier idempotent draft without receipt_id.
SET @nexus_alert_receipt_ddl = (
  SELECT IF(
    EXISTS(SELECT 1 FROM information_schema.columns
           WHERE table_schema='nexus' AND table_name='security_incident_alerts' AND column_name='receipt_id'),
    'SELECT 1',
    CONCAT('ALTER TABLE nexus.security_incident_alerts ADD COLUMN receipt_id VARCHAR(64) NOT NULL DEFAULT ', CHAR(39), CHAR(39))
  )
);
PREPARE nexus_alert_receipt_stmt FROM @nexus_alert_receipt_ddl;
EXECUTE nexus_alert_receipt_stmt;
DEALLOCATE PREPARE nexus_alert_receipt_stmt;

-- Responses may be introduced after the ticket table has already been created.
SET @nexus_ticket_responses_ddl = (
  SELECT IF(
    EXISTS(SELECT 1 FROM information_schema.columns
           WHERE table_schema='nexus' AND table_name='security_incident_tickets' AND column_name='responses'),
    'SELECT 1',
    'ALTER TABLE nexus.security_incident_tickets ADD COLUMN responses JSON NULL'
  )
);
PREPARE nexus_ticket_responses_stmt FROM @nexus_ticket_responses_ddl;
EXECUTE nexus_ticket_responses_stmt;
DEALLOCATE PREPARE nexus_ticket_responses_stmt;

CREATE TABLE IF NOT EXISTS nexus.security_discord_rate_limit (
  id              TINYINT UNSIGNED NOT NULL PRIMARY KEY,
  next_allowed_at DATETIME(6) NOT NULL,
  CONSTRAINT chk_security_discord_rate_limit_singleton CHECK (id = 1)
) ENGINE=InnoDB;

-- Existing app and n8n accounts receive access only to the new, purpose-built tables.
GRANT SELECT, INSERT, DELETE ON nexus.security_ai_tool_denials TO 'nexus_app'@'%';
GRANT SELECT, INSERT, DELETE ON nexus_test.security_ai_tool_denials TO 'nexus_app'@'%';
GRANT SELECT, INSERT ON nexus.security_incident_alerts TO 'nexus_n8n'@'%';
GRANT UPDATE (ticket_id) ON nexus.security_incident_alerts TO 'nexus_n8n'@'%';
GRANT SELECT, INSERT ON nexus.security_incident_tickets TO 'nexus_n8n'@'%';
GRANT UPDATE (status, ticket_type, type_rank, event_count, rule_ids, user_names, last_seen,
              latest_event, resolution, closed_at, note, responses)
  ON nexus.security_incident_tickets TO 'nexus_n8n'@'%';
GRANT SELECT, INSERT, UPDATE ON nexus.security_discord_rate_limit TO 'nexus_n8n'@'%';
