import os
from pathlib import Path
import pymysql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

def migrate_db(db_name):
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
            cur.execute("ALTER TABLE users MODIFY COLUMN role ENUM('employee','manager','admin','sec_admin','hr_admin','finance_admin') NOT NULL DEFAULT 'employee'")
        con.close()
        print(f"[{db_name}] role ENUM altered successfully.")
    except Exception as e:
        print(f"[{db_name}] migration error: {e}")

if __name__ == "__main__":
    for name in ("nexus", "nexus_test"):
        migrate_db(name)
