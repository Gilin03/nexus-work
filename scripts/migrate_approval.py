"""이미 만들어진 DB 에 전자결재 확장(양식·긴급도 열, 참조자·첨부 표)과 최소 권한을 더한다. root 계정으로 접속한다. 여러 번 실행해도 안전하다.

사용: python scripts/migrate_approval.py [--db nexus] [--db nexus_test]   (기본: 둘 다)
- approvals 에 doc_type(양식)·urgency(긴급도)·body_html(서식 있는 본문 여부)·recipient(수신) 열을 더하고 body 를 MEDIUMTEXT 로 넓힌다. 이미 있는 문서는 일반 기안·보통으로 채워진다.
- expenditures(지출결의서)·expenditure_items(내역) 표와 양식 값 expenditure 를 더한다.
- approval_cc(참조자)·approval_files(첨부, 결재자가 올린 첨부의 단계·올린 사람 열 포함) 표를 만들고 nexus_app 에 SELECT·INSERT 만 준다(db/grants.sql 과 같은 내용).
- 새로 DB 를 만들 때는 db/schema.sql·grants.sql 이 이미 포함하므로 필요 없다(init.sh 는 최초 기동 때만 돈다)."""
import argparse
import os
import re
import sys
from pathlib import Path

import pymysql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

GRANTS = [
    "GRANT SELECT, INSERT ON `{db}`.approval_cc TO 'nexus_app'@'%'",
    "GRANT SELECT, INSERT ON `{db}`.approval_files TO 'nexus_app'@'%'",
    "GRANT SELECT, INSERT ON `{db}`.expenditures TO 'nexus_app'@'%'",
    "GRANT SELECT, INSERT ON `{db}`.expenditure_items TO 'nexus_app'@'%'",
]
COLUMNS = {
    "doc_type": "ALTER TABLE approvals ADD COLUMN doc_type ENUM('general','coop','trip','purchase','expense') NOT NULL DEFAULT 'general' AFTER status",
    "urgency": "ALTER TABLE approvals ADD COLUMN urgency ENUM('normal','urgent') NOT NULL DEFAULT 'normal' AFTER doc_type",
}
# approvals: 공문 본문(서식 있는 글)과 수신. body 는 서식 있는 글을 담도록 MEDIUMTEXT 로 넓힌다.
BODY_COLUMNS = {
    "body_html": "ALTER TABLE approvals ADD COLUMN body_html TINYINT(1) NOT NULL DEFAULT 0 AFTER body",
    "recipient": "ALTER TABLE approvals ADD COLUMN recipient VARCHAR(100) NULL AFTER body_html",
}
# approval_files: 결재자가 승인·반려할 때 올린 첨부를 구분한다(이미 있는 첨부는 NULL = 상신 첨부).
FILE_COLUMNS = {
    "step_no": "ALTER TABLE approval_files ADD COLUMN step_no TINYINT UNSIGNED NULL AFTER sha256",
    "uploaded_by": "ALTER TABLE approval_files ADD COLUMN uploaded_by INT UNSIGNED NULL AFTER step_no, "
                   "ADD CONSTRAINT fk_approval_files_uploader FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE CASCADE",
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
        cur.execute("SELECT 1 FROM information_schema.columns WHERE table_schema=%s AND table_name='approvals' AND column_name=%s", (db, col))
        if not cur.fetchone():
            cur.execute(ddl)
            done.append(f"+column {col}")
    cur.execute("SELECT column_type FROM information_schema.columns WHERE table_schema=%s AND table_name='approvals' AND column_name='doc_type'", (db,))
    row = cur.fetchone()
    if row and "expenditure" not in row[0]:                  # 양식에 지출결의서를 더한다(기존 값은 그대로)
        cur.execute("ALTER TABLE approvals MODIFY doc_type ENUM('general','coop','trip','purchase','expense','expenditure') NOT NULL DEFAULT 'general'")
        done.append("approvals.doc_type += expenditure")
    for table in ("approval_cc", "approval_files", "expenditures", "expenditure_items"):
        cur.execute("SHOW TABLES LIKE %s", (table,))
        if not cur.fetchone():
            cur.execute(create_table_sql(table))
            done.append(f"+table {table}")
    for col, ddl in FILE_COLUMNS.items():
        cur.execute("SELECT 1 FROM information_schema.columns WHERE table_schema=%s AND table_name='approval_files' AND column_name=%s", (db, col))
        if not cur.fetchone():
            cur.execute(ddl)
            done.append(f"+column approval_files.{col}")
    for col, ddl in BODY_COLUMNS.items():
        cur.execute("SELECT 1 FROM information_schema.columns WHERE table_schema=%s AND table_name='approvals' AND column_name=%s", (db, col))
        if not cur.fetchone():
            cur.execute(ddl)
            done.append(f"+column approvals.{col}")
    cur.execute("SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name='approvals' AND column_name='body'", (db,))
    row = cur.fetchone()
    if row and row[0] != "mediumtext":
        cur.execute("ALTER TABLE approvals MODIFY body MEDIUMTEXT NOT NULL")
        done.append("approvals.body -> MEDIUMTEXT")
    for table in ("attachments", "approval_files"):  # 용량 제한이 없으므로 크기 열을 BIGINT 로 넓힌다(4GB 초과 파일)
        cur.execute("SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND column_name='size'", (db, table))
        row = cur.fetchone()
        if row and row[0] != "bigint":
            cur.execute(f"ALTER TABLE {table} MODIFY size BIGINT UNSIGNED NOT NULL")  # 표 이름은 위 고정 목록의 값만 쓴다
            done.append(f"{table}.size -> BIGINT")
    for g in GRANTS:
        cur.execute(g.format(db=db))
    cur.execute("UPDATE approvals SET doc_type='expense' WHERE expense_id IS NOT NULL AND doc_type='general'")
    if cur.rowcount:
        done.append(f"{cur.rowcount} expense approvals typed")
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
