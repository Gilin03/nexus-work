"""이미 만들어진 DB 에 인사(HR) 기능의 표·열·권한을 더한다. root 계정으로 접속한다. 여러 번 실행해도 안전하다.

사용: python scripts/migrate_hr.py [--db nexus] [--db nexus_test]   (기본: 둘 다)
- employees 에 사번(emp_no)·입사일(hire_date)·연간 연차(annual_days) 열을 더한다.
- attendance(근태)·leave_requests(휴가) 표를 만들고 nexus_app 에 최소 권한을 준다(db/grants.sql 과 같은 내용).
- 새로 DB 를 만들 때는 db/schema.sql·grants.sql 이 이미 이 내용을 포함하므로 이 스크립트가 필요 없다(init.sh 는 최초 기동 때만 돈다).
- 이미 있는 직원 중 사번·입사일이 비어 있는 행에는 기본값(사번 NX-<연도>-<번호>, 입사일 오늘)을 채운다."""
import argparse
import os
import re
import sys
from datetime import date
from pathlib import Path

import pymysql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

GRANTS = [
    "GRANT SELECT, INSERT ON `{db}`.attendance TO 'nexus_app'@'%'",
    "GRANT UPDATE (check_out) ON `{db}`.attendance TO 'nexus_app'@'%'",
    "GRANT SELECT, INSERT ON `{db}`.leave_requests TO 'nexus_app'@'%'",
    "GRANT UPDATE (status, decided_by, decided_at, decision_reason) ON `{db}`.leave_requests TO 'nexus_app'@'%'",
    "GRANT INSERT ON `{db}`.employees TO 'nexus_app'@'%'",     # 관리자 화면의 계정 등록이 인사카드를 함께 만든다(수정·삭제는 불가)
]
COLUMNS = {
    "emp_no": "ALTER TABLE employees ADD COLUMN emp_no VARCHAR(16) NULL UNIQUE AFTER ext",
    "hire_date": "ALTER TABLE employees ADD COLUMN hire_date DATE NULL AFTER emp_no",
    "annual_days": "ALTER TABLE employees ADD COLUMN annual_days TINYINT UNSIGNED NOT NULL DEFAULT 15 AFTER hire_date",
}


def create_table_sql(name):
    schema = (ROOT / "db" / "schema.sql").read_text(encoding="utf-8")
    return re.search(rf"CREATE TABLE {name} \(.*?\) ENGINE=InnoDB;", schema, re.S).group(0).rstrip(";")


def migrate(db):
    con = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")), user="root",
                          password=os.environ["MYSQL_ROOT_PASSWORD"], database=db, autocommit=True)
    cur = con.cursor()
    done = []
    for col, ddl in COLUMNS.items():
        cur.execute("SELECT 1 FROM information_schema.columns WHERE table_schema=%s AND table_name='employees' AND column_name=%s", (db, col))
        if not cur.fetchone():
            cur.execute(ddl)
            done.append(f"+column {col}")
    for table in ("attendance", "leave_requests"):
        cur.execute("SHOW TABLES LIKE %s", (table,))
        if not cur.fetchone():
            cur.execute(create_table_sql(table))
            done.append(f"+table {table}")
    for g in GRANTS:
        cur.execute(g.format(db=db))
    cur.execute("SELECT id FROM employees WHERE emp_no IS NULL ORDER BY id")
    for (eid,) in cur.fetchall():
        cur.execute("UPDATE employees SET emp_no=%s, hire_date=COALESCE(hire_date, %s) WHERE id=%s",
                    (f"NX-{date.today().year}-{eid:03d}", date.today(), eid))
        done.append(f"emp {eid} filled")
    con.close()
    print(db, "->", done or "already up to date")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", action="append", choices=("nexus", "nexus_test"))
    args = ap.parse_args()
    for db in args.db or ["nexus", "nexus_test"]:
        migrate(db)


if __name__ == "__main__":
    sys.exit(main())
