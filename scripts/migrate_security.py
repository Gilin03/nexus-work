"""이미 만들어진 DB 에 '최상위 권한 고정'과 직급 변경 권한을 더한다. root 계정으로 접속한다. 여러 번 실행해도 안전하다.

사용: python scripts/migrate_security.py [--db nexus] [--db nexus_test]   (기본: 둘 다)
- users 에 pinned 열을 더하고, 보안관제팀 소속과 시스템관리자(admin) 계정을 admin 역할 + pinned 로 정한다(역할이 낮았다면 올린다).
- 고정 트리거(trg_users_pin_insert/update)를 db/schema.sql 에서 그대로 읽어 만든다. 이 트리거가 있으면 고정 계정의 역할을 낮추거나 pinned 를 풀 수 없다.
  (고정을 풀어야 하는 특별한 사정이 있으면 DBA 가 트리거를 직접 지운 뒤 처리한다. 앱은 지울 수 없다.)
- nexus_app 에 employees.title(직급) 수정 권한을 준다(db/grants.sql 과 같은 내용).
- 새로 DB 를 만들 때는 db/schema.sql·grants.sql 이 이미 이 내용을 포함하므로 이 스크립트가 필요 없다."""
import argparse
import os
import re
import sys
from pathlib import Path

import pymysql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

SECURITY_TEAM = "보안관제팀"
SYSTEM_ADMIN = "admin"
GRANT = "GRANT UPDATE (title) ON `{db}`.employees TO 'nexus_app'@'%'"


def trigger_sql(name):
    schema = (ROOT / "db" / "schema.sql").read_text(encoding="utf-8")
    return re.search(rf"CREATE TRIGGER {name}\b.*?END//", schema, re.S).group(0).removesuffix("//").rstrip()


def migrate(db):
    con = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")), user="root",
                          password=os.environ["MYSQL_ROOT_PASSWORD"], database=db, autocommit=True, charset="utf8mb4")
    cur = con.cursor()
    done = []
    cur.execute("SELECT 1 FROM information_schema.columns WHERE table_schema=%s AND table_name='users' AND column_name='pinned'", (db,))
    if not cur.fetchone():
        cur.execute("ALTER TABLE users ADD COLUMN pinned TINYINT(1) NOT NULL DEFAULT 0 AFTER session_version")
        done.append("+column users.pinned")
    for name in ("trg_users_pin_insert", "trg_users_pin_update"):
        cur.execute("DROP TRIGGER IF EXISTS " + name)                  # 고정된 이름만 쓰는 상수 문장
    cur.execute("UPDATE users SET role='admin' WHERE (dept=%s OR username=%s) AND role<>'admin'", (SECURITY_TEAM, SYSTEM_ADMIN))
    if cur.rowcount:
        done.append(f"{cur.rowcount} user(s) raised to admin")
    cur.execute("UPDATE users SET pinned=1 WHERE (dept=%s OR username=%s) AND pinned=0", (SECURITY_TEAM, SYSTEM_ADMIN))
    if cur.rowcount:
        done.append(f"{cur.rowcount} user(s) pinned")
    for name in ("trg_users_pin_insert", "trg_users_pin_update"):
        cur.execute(trigger_sql(name))
    done.append("triggers (re)created")
    cur.execute(GRANT.format(db=db))
    con.close()
    print(db, "->", done)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", action="append", choices=("nexus", "nexus_test"))
    args = ap.parse_args()
    for db in args.db or ["nexus", "nexus_test"]:
        migrate(db)


if __name__ == "__main__":
    sys.exit(main())
