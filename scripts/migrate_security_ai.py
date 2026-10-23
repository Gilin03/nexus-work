"""Migrate missing security tables (security_ai_tool_denials, security_incident_tickets)."""
import os
import sys
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
    """
]

GRANTS = [
    "GRANT SELECT, INSERT, DELETE ON `{db}`.security_ai_tool_denials TO 'nexus_app'@'%'",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON `{db}`.security_incident_tickets TO 'nexus_app'@'%'"
]

def migrate(db_name):
    con = pymysql.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("DB_PORT", "3307")),
        user="root",
        password=os.environ["MYSQL_ROOT_PASSWORD"],
        database=db_name,
        autocommit=True,
        charset="utf8mb4"
    )
    cur = con.cursor()
    for ddl in DDLS:
        cur.execute(ddl)
    for grant in GRANTS:
        try:
            cur.execute(grant.format(db=db_name))
        except Exception as e:
            print("Grant error:", e)
    con.close()
    print(f"Migrated {db_name} successfully.")

if __name__ == "__main__":
    for db in ["nexus", "nexus_test"]:
        migrate(db)
