import pymysql
import os

def clear_dummy():
    con = pymysql.connect(
        host="127.0.0.1", port=3307, user="root",
        password=os.environ["MYSQL_ROOT_PASSWORD"],
        database="nexus", autocommit=True
    )
    with con.cursor() as cur:
        deleted = cur.execute("DELETE FROM security_xdr_assessments WHERE group_key LIKE 'dummy_%'")
        print(f"CLEARED: Deleted {deleted} dummy assessment rows.")

if __name__ == "__main__":
    clear_dummy()
