"""blocked_ips 테이블 및 권한 생성 마이그레이션 스크립트.
- nexus 및 nexus_test DB에 blocked_ips 테이블 생성
- nexus_app 및 nexus_n8n 계정에 SELECT, INSERT, UPDATE, DELETE 권한 부여
"""
import argparse
import os
from pathlib import Path
import pymysql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

TABLE_DDL = """
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(100) NOT NULL DEFAULT 'auto_block',
    blocked_until DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(50) NOT NULL DEFAULT 'system',
    INDEX idx_ip_lookup (ip_address, blocked_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""


def migrate(db):
    con = pymysql.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("DB_PORT", "3307")),
        user="root",
        password=os.environ["MYSQL_ROOT_PASSWORD"],
        database=db,
        autocommit=True,
        charset="utf8mb4",
    )
    cur = con.cursor()
    cur.execute(TABLE_DDL)
    print(f"[{db}] blocked_ips table ready.")

    # 권한 부여 (nexus_app 및 nexus_n8n)
    cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON `{db}`.blocked_ips TO 'nexus_app'@'%'")
    try:
        cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON `{db}`.blocked_ips TO 'nexus_n8n'@'%'")
    except Exception as e:
        print(f"[{db}] Warning: nexus_n8n grant skipped ({e})")

    cur.execute("FLUSH PRIVILEGES")
    print(f"[{db}] Grants updated for nexus_app and nexus_n8n.")
    con.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", action="append", help="Target database (default: nexus and nexus_test)")
    args = parser.parse_args()
    dbs = args.db or ["nexus", "nexus_test"]
    for db in dbs:
        migrate(db)


if __name__ == "__main__":
    main()
