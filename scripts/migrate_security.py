"""이미 만들어진 DB 에 '최고관리자 고정'·사용자 삭제 표시·직급 변경 권한을 더한다. root 계정으로 접속한다. 여러 번 실행해도 안전하다.

사용: python scripts/migrate_security.py [--db nexus] [--db nexus_test]   (기본: 둘 다)
- 고정 대상은 admin(시스템관리자)·hongjh 두 계정뿐이다(사용자 결정 2026-10-20). 예전 규칙(보안관제팀 전원 고정)으로 고정됐던
  다른 계정은 고정을 푼다(역할은 그대로 두므로 지금 admin 이면 admin 으로 남고, 이후 관리자 화면에서 바꿀 수 있다).
- users 에 pinned·deleted_at·deleted_by 열이 없으면 더한다.
- 고정 트리거(trg_users_pin_insert/update)를 db/schema.sql 에서 그대로 읽어 다시 만든다. 고정 계정은 역할을 낮추거나 고정을 풀거나 삭제 처리할 수 없다.
  (고정을 푸는 작업은 트리거가 막으므로 이 스크립트는 트리거를 잠깐 지운 뒤 정리하고 다시 만든다.)
- nexus_app 에 employees.title(직급)과 users.deleted_at·deleted_by(삭제 표시) 수정 권한을 준다(db/grants.sql 과 같은 내용).
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

PINNED_USERS = ("admin", "hongjh")
COLUMNS = {
    "pinned": "ALTER TABLE users ADD COLUMN pinned TINYINT(1) NOT NULL DEFAULT 0 AFTER session_version",
    "deleted_at": "ALTER TABLE users ADD COLUMN deleted_at DATETIME NULL AFTER created_at",
    "deleted_by": "ALTER TABLE users ADD COLUMN deleted_by INT UNSIGNED NULL AFTER deleted_at",
    "ai_restricted": "ALTER TABLE users ADD COLUMN ai_restricted TINYINT(1) NOT NULL DEFAULT 0 AFTER pinned",   # R3 대응(AI 제한), ai-agent 브랜치와 같은 정의
}
GRANTS = [
    "GRANT UPDATE (title) ON `{db}`.employees TO 'nexus_app'@'%'",
    "GRANT UPDATE (deleted_at, deleted_by) ON `{db}`.users TO 'nexus_app'@'%'",
    "GRANT UPDATE (dept) ON `{db}`.users TO 'nexus_app'@'%'",                 # 부서 변경(관리 화면)
    "GRANT UPDATE (dept) ON `{db}`.employees TO 'nexus_app'@'%'",
]
TRIGGERS = ("trg_users_pin_insert", "trg_users_pin_update")


def trigger_sql(name):
    schema = (ROOT / "db" / "schema.sql").read_text(encoding="utf-8")
    return re.search(rf"CREATE TRIGGER {name}\b.*?END//", schema, re.S).group(0).removesuffix("//").rstrip()


def migrate(db):
    con = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")), user="root",
                          password=os.environ["MYSQL_ROOT_PASSWORD"], database=db, autocommit=True, charset="utf8mb4")
    cur = con.cursor()
    done = []
    for col, ddl in COLUMNS.items():
        cur.execute("SELECT 1 FROM information_schema.columns WHERE table_schema=%s AND table_name='users' AND column_name=%s", (db, col))
        if not cur.fetchone():
            cur.execute(ddl)
            done.append(f"+column users.{col}")
    for name in TRIGGERS:
        cur.execute("DROP TRIGGER IF EXISTS " + name)                  # 고정된 이름만 쓰는 상수 문장
    cur.execute("UPDATE users SET pinned=0 WHERE pinned=1 AND username NOT IN (%s, %s)", PINNED_USERS)
    if cur.rowcount:
        done.append(f"{cur.rowcount} user(s) unpinned")
    cur.execute("UPDATE users SET role='admin', pinned=1, deleted_at=NULL, deleted_by=NULL "
                "WHERE username IN (%s, %s) AND (pinned=0 OR role<>'admin' OR deleted_at IS NOT NULL)", PINNED_USERS)
    if cur.rowcount:
        done.append(f"{cur.rowcount} user(s) pinned")
    for name in TRIGGERS:
        cur.execute(trigger_sql(name))
    done.append("triggers (re)created")
    for g in GRANTS:
        cur.execute(g.format(db=db))
    cur.execute("SELECT username FROM users WHERE pinned=1 ORDER BY username")
    done.append("pinned now: " + ",".join(r[0] for r in cur.fetchall()))
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
