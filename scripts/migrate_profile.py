"""기존 DB에 프로필 사진 테이블과 권한을 추가한다.

사용: python scripts/migrate_profile.py --db nexus_test
테이블 정의와 권한은 각각 db/schema.sql, db/grants.sql에서 읽는다.
새 DB에는 두 파일이 init.sh를 통해 이미 적용되므로 이 migration은 필요 없다.
"""
import argparse
import os
import re
import sys
from pathlib import Path

import pymysql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def create_table_sql():
    schema = (ROOT / "db" / "schema.sql").read_text(encoding="utf-8")
    matches = re.findall(r"CREATE TABLE profile_photos \(.*?\n\) ENGINE=InnoDB;", schema, re.S)
    if len(matches) != 1:
        raise RuntimeError("db/schema.sql에 profile_photos 정의가 정확히 하나 있어야 합니다")
    return matches[0].rstrip(";")


def grant_sql(db):
    grants = (ROOT / "db" / "grants.sql").read_text(encoding="utf-8")
    matches = re.findall(
        r"^GRANT SELECT, INSERT, DELETE ON `__DB__`\.profile_photos TO 'nexus_app'@'%';$",
        grants,
        re.M,
    )
    if len(matches) != 1:
        raise RuntimeError("db/grants.sql에 profile_photos 권한 정의가 정확히 하나 있어야 합니다")
    return matches[0].replace("`__DB__`", f"`{db}`")


def migrate(db):
    connection = pymysql.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("DB_PORT", "3307")),
        user="root",
        password=os.environ["MYSQL_ROOT_PASSWORD"],
        database=db,
        autocommit=True,
        charset="utf8mb4",
    )
    try:
        with connection.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema=%s AND table_name='profile_photos'",
                (db,),
            )
            created = cur.fetchone() is None
            if created:
                cur.execute(create_table_sql())
            cur.execute(grant_sql(db))
    finally:
        connection.close()

    result = ["+table profile_photos"] if created else ["profile_photos already exists"]
    result.append("profile_photos grant applied")
    print(db, "->", result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", choices=("nexus", "nexus_test"), required=True)
    args = parser.parse_args()
    migrate(args.db)


if __name__ == "__main__":
    sys.exit(main())
