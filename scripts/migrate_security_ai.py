"""Prepare/apply the security AI/XDR tables to one explicitly selected database."""
import argparse
import os
from pathlib import Path
import pymysql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DDLS = [
    """
    CREATE TABLE IF NOT EXISTS security_ai_tool_denials (
      request_id  VARCHAR(64) NOT NULL PRIMARY KEY,
      user_id     INT UNSIGNED NOT NULL,
      session_id  VARCHAR(64) NOT NULL,
      tool_name   VARCHAR(64) NOT NULL,
      occurred_at DATETIME(6) NOT NULL,
      KEY idx_ai_deny_correlation (user_id, session_id, tool_name, occurred_at),
      KEY idx_ai_deny_cleanup (occurred_at),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB;
    """,
    """
    CREATE TABLE IF NOT EXISTS security_incident_tickets (
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
    """,
    """
    CREATE TABLE IF NOT EXISTS security_xdr_assessments (
      assessment_id       CHAR(36) NOT NULL PRIMARY KEY,
      window_key          CHAR(64) NOT NULL UNIQUE,
      group_key           VARCHAR(255) NOT NULL,
      incident_ticket_id  BIGINT UNSIGNED NULL,
      src_ip              VARCHAR(45) NOT NULL DEFAULT '',
      user_names          JSON NOT NULL,
      rule_ids            JSON NOT NULL,
      event_types         JSON NOT NULL,
      event_count         INT UNSIGNED NOT NULL,
      first_seen          DATETIME(6) NOT NULL,
      last_seen           DATETIME(6) NOT NULL,
      event_summary       JSON NOT NULL,
      threat_score        TINYINT UNSIGNED NULL,
      confidence          DECIMAL(4,3) NULL,
      verdict             ENUM('BENIGN','SUSPICIOUS','MALICIOUS','REVIEW_REQUIRED') NOT NULL DEFAULT 'REVIEW_REQUIRED',
      reasoning           VARCHAR(500) NOT NULL DEFAULT '',
      recommended_actions JSON NOT NULL,
      policy_mode         VARCHAR(24) NOT NULL DEFAULT 'dry-run',
      policy_reason       VARCHAR(120) NOT NULL DEFAULT '',
      status              ENUM('PROCESSING','PENDING','APPROVED','REJECTED','FALSE_POSITIVE','NO_ACTION','AUTO_EXECUTED') NOT NULL DEFAULT 'PROCESSING',
      response_result     JSON NULL,
      created_at          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
      decided_by          INT UNSIGNED NULL,
      decided_at          DATETIME(6) NULL,
      KEY idx_xdr_status_created (status, created_at),
      KEY idx_xdr_ticket (incident_ticket_id),
      CONSTRAINT fk_xdr_assessment_ticket FOREIGN KEY (incident_ticket_id)
        REFERENCES security_incident_tickets(id) ON DELETE SET NULL
    ) ENGINE=InnoDB;
    """,
    """
    CREATE TABLE IF NOT EXISTS security_xdr_events (
      alert_id            VARCHAR(160) NOT NULL PRIMARY KEY,
      window_key          CHAR(64) NOT NULL,
      group_key           VARCHAR(255) NOT NULL,
      window_start        DATETIME(6) NOT NULL,
      incident_ticket_id  BIGINT UNSIGNED NULL,
      src_ip              VARCHAR(45) NOT NULL DEFAULT '',
      user_name           VARCHAR(64) NOT NULL DEFAULT '',
      rule_id             VARCHAR(8) NOT NULL,
      event_type          VARCHAR(80) NOT NULL,
      severity            VARCHAR(16) NOT NULL DEFAULT '',
      event_count         INT UNSIGNED NOT NULL DEFAULT 1,
      occurred_at         DATETIME(6) NOT NULL,
      event_payload       JSON NOT NULL,
      assessment_id       CHAR(36) NULL,
      created_at          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
      KEY idx_xdr_pending_window (assessment_id, window_start),
      KEY idx_xdr_group_time (group_key, occurred_at),
      KEY idx_xdr_event_ticket (incident_ticket_id),
      CONSTRAINT fk_xdr_event_assessment FOREIGN KEY (assessment_id)
        REFERENCES security_xdr_assessments(assessment_id) ON DELETE SET NULL
    ) ENGINE=InnoDB;
    """
]

GRANTS = [
    "GRANT SELECT, INSERT, DELETE ON `{db}`.security_ai_tool_denials TO 'nexus_app'@'%'",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON `{db}`.security_incident_tickets TO 'nexus_app'@'%'",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON `{db}`.security_xdr_assessments TO 'nexus_app'@'%'",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON `{db}`.security_xdr_events TO 'nexus_app'@'%'"
]


REQUIRED_COLUMNS = {
    "security_ai_tool_denials": {"request_id", "user_id", "session_id", "tool_name", "occurred_at"},
    "security_incident_tickets": {"id", "ticket_key", "status", "src_ip", "event_count", "rule_ids",
                                  "user_names", "first_seen", "last_seen", "latest_event", "responses"},
    "security_xdr_assessments": {"assessment_id", "window_key", "group_key", "incident_ticket_id", "src_ip",
                                  "user_names", "rule_ids", "event_types", "event_count", "first_seen", "last_seen",
                                  "event_summary", "threat_score", "confidence", "verdict", "reasoning",
                                  "recommended_actions", "policy_mode", "policy_reason", "status", "response_result",
                                  "decided_by", "decided_at"},
    "security_xdr_events": {"alert_id", "window_key", "group_key", "window_start", "incident_ticket_id", "src_ip",
                            "user_name", "rule_id", "event_type", "severity", "event_count", "occurred_at",
                            "event_payload", "assessment_id"},
}


def _validate_schema(cur):
    for table, required in REQUIRED_COLUMNS.items():
        cur.execute(f"SHOW COLUMNS FROM `{table}`")
        columns = {row[0]: str(row[1]).lower() for row in cur.fetchall()}
        missing = required - columns.keys()
        if missing:
            raise RuntimeError(f"{table} missing columns: {', '.join(sorted(missing))}")
    if REQUIRED_COLUMNS["security_incident_tickets"]:
        cur.execute("SHOW COLUMNS FROM `security_incident_tickets` LIKE 'id'")
        ticket_id = cur.fetchone()
        cur.execute("SHOW COLUMNS FROM `security_xdr_assessments` LIKE 'incident_ticket_id'")
        assessment_ticket_id = cur.fetchone()
        if not ticket_id or not assessment_ticket_id or str(ticket_id[1]).lower() != "bigint unsigned" or \
                str(assessment_ticket_id[1]).lower() != "bigint unsigned":
            raise RuntimeError("ticket foreign key column types do not match")

    cur.execute(
        "SELECT TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME "
        "FROM information_schema.KEY_COLUMN_USAGE "
        "WHERE CONSTRAINT_SCHEMA = DATABASE() AND CONSTRAINT_NAME IN "
        "('fk_xdr_assessment_ticket', 'fk_xdr_event_assessment')"
    )
    foreign_keys = {tuple(row) for row in cur.fetchall()}
    expected_foreign_keys = {
        ("security_xdr_assessments", "incident_ticket_id", "security_incident_tickets", "id"),
        ("security_xdr_events", "assessment_id", "security_xdr_assessments", "assessment_id"),
    }
    if not expected_foreign_keys.issubset(foreign_keys):
        raise RuntimeError("XDR foreign key relationships do not match the expected schema")

    cur.execute(
        "SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() "
        "AND TABLE_NAME IN ('security_incident_tickets', 'security_xdr_assessments', 'security_xdr_events')"
    )
    engines = {row[0]: str(row[1]).lower() for row in cur.fetchall()}
    if any(engines.get(table) != "innodb" for table in (
        "security_incident_tickets", "security_xdr_assessments", "security_xdr_events"
    )):
        raise RuntimeError("Ticket/XDR tables must use InnoDB")


def migrate(db_name):
    if db_name not in {"nexus", "nexus_test"}:
        raise ValueError("unsupported database")
    con = pymysql.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("DB_PORT", "3307")),
        user="root",
        password=os.environ["MYSQL_ROOT_PASSWORD"],
        database=db_name,
        autocommit=True,
        charset="utf8mb4"
    )
    try:
        cur = con.cursor()
        for ddl in DDLS:
            cur.execute(ddl)
        _validate_schema(cur)
        for grant in GRANTS:
            cur.execute(grant.format(db=db_name))
    finally:
        con.close()
    print(f"Migrated {db_name} successfully.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", choices=("nexus_test", "nexus"), required=True)
    parser.add_argument("--apply", action="store_true", help="apply the migration; default is a no-connection dry run")
    parser.add_argument("--confirm-production", action="store_true", help="required with --apply --database nexus")
    args = parser.parse_args(argv)
    if args.apply and args.database == "nexus" and not args.confirm_production:
        parser.error("production requires --confirm-production")
    if not args.apply:
        print(f"DRY RUN: no database connection; {len(DDLS)} idempotent table statements and "
              f"{len(GRANTS)} scoped grants are prepared for {args.database}.")
        return 0
    migrate(args.database)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
