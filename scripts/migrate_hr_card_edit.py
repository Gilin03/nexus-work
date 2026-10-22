import os
from pathlib import Path
import pymysql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

def grant_permissions(db_name):
    try:
        con = pymysql.connect(
            host=os.environ.get("DB_HOST", "127.0.0.1"),
            port=int(os.environ.get("DB_PORT", "3307")),
            user="root",
            password=os.environ["MYSQL_ROOT_PASSWORD"],
            database=db_name,
            autocommit=True,
            charset="utf8mb4",
        )
        with con.cursor() as cur:
            # employees 테이블의 모든 수정 가능 필드 UPDATE 권한 부여
            cur.execute(f"GRANT UPDATE (name, dept, title, ext, emp_no, hire_date, annual_days) ON `{db_name}`.employees TO 'nexus_app'@'%'")
            # users 테이블의 display_name UPDATE 권한 부여
            cur.execute(f"GRANT UPDATE (display_name) ON `{db_name}`.users TO 'nexus_app'@'%'")
        con.close()
        print(f"[{db_name}] HR Card edit grants applied successfully.")
    except Exception as e:
        print(f"[{db_name}] error: {e}")

if __name__ == "__main__":
    for name in ("nexus", "nexus_test"):
        grant_permissions(name)
