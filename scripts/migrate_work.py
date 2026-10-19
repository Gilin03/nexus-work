"""이미 만들어진 DB 에 업무(할 일·일정·예약·프로젝트)와 자료(자료실·주소록·양식 모음)의 표·권한을 더한다. root 계정으로 접속한다. 여러 번 실행해도 안전하다.

사용: python scripts/migrate_work.py [--db nexus] [--db nexus_test]   (기본: 둘 다)
- 표 정의는 db/schema.sql, 권한은 db/grants.sql 의 해당 부분을 그대로 읽어 쓴다(두 파일이 유일한 원본).
- 기본 예약 자원(회의실·비품)이 하나도 없으면 몇 개 넣는다. 새로 DB 를 만들 때는 scripts/seed.py 가 넣는다.
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

# 외래 키 순서대로
TABLES = ["projects", "project_members", "tasks", "task_comments", "events", "event_attendees", "resources", "reservations",
          "lib_folders", "lib_files", "lib_forms", "contacts"]
DEFAULT_RESOURCES = [
    ("회의실 A", "room", "본관 3층", 8, "소규모 회의실(화이트보드)"),
    ("회의실 B", "room", "본관 3층", 6, "소규모 회의실"),
    ("대회의실", "room", "본관 5층", 20, "프로젝터·화상회의 장비"),
    ("이동형 빔프로젝터", "equipment", "경영지원팀", None, "외부 미팅용"),
    ("노트북(대여용)", "equipment", "경영지원팀", None, "출장·교육용"),
]


def create_table_sql(name):
    schema = (ROOT / "db" / "schema.sql").read_text(encoding="utf-8")
    return re.search(rf"CREATE TABLE {name} \(.*?\n\) ENGINE=InnoDB;", schema, re.S).group(0).rstrip(";")


def grant_statements(db):
    grants = (ROOT / "db" / "grants.sql").read_text(encoding="utf-8")
    pattern = r"^GRANT [^;]*? ON `__DB__`\.(?:" + "|".join(TABLES) + r")\s+TO 'nexus_app'@'%';"
    found = [m.group(0).rstrip(";").replace("__DB__", db) for m in re.finditer(pattern, grants, re.M)]
    assert len(found) >= 20, "grants.sql 에서 업무·자료 권한을 찾지 못했다"
    return found


def migrate(db):
    con = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")), user="root",
                          password=os.environ["MYSQL_ROOT_PASSWORD"], database=db, autocommit=True)
    cur = con.cursor()
    done = []
    for table in TABLES:
        cur.execute("SHOW TABLES LIKE %s", (table,))
        if not cur.fetchone():
            cur.execute(create_table_sql(table))
            done.append(f"+table {table}")
    for stmt in grant_statements(db):
        cur.execute(stmt)
    cur.execute("SELECT COUNT(*) FROM resources")
    if cur.fetchone()[0] == 0:
        cur.executemany("INSERT INTO resources(name, kind, location, capacity, description) VALUES(%s, %s, %s, %s, %s)", DEFAULT_RESOURCES)
        done.append("+default resources")
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
