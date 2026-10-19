"""팀원별 관리자(admin) 계정 생성. root 계정으로 접속한다. 기존 데이터는 건드리지 않는다.

사용: python scripts/create_team_admins.py [--db nexus] [--reset-initial]
- 초기 비밀번호는 모두 INITIAL_PASSWORD(1234)다. 각자 로그인한 뒤 비밀번호 변경 화면(/account/password)에서 직접 바꾼다.
  1234 는 비밀번호 정책(12자 이상)에 걸려 변경 화면에서는 쓸 수 없는 값이라, 이 스크립트가 해시를 DB 에 직접 넣는다.
- 이미 있는 아이디는 건너뛴다. --reset-initial 을 주면 그 계정의 비밀번호를 다시 1234 로 돌리고 잠금·세션을 초기화한다.
- 공개된 약한 비밀번호이므로 포털을 외부에 열 때는 모두 바뀌었는지 확인할 것.
- seed.py --reset 은 모든 표를 비우므로, 리셋한 뒤에는 이 스크립트를 다시 실행한다.
"""
import argparse
import os
import sys
from pathlib import Path

import pymysql
from argon2 import PasswordHasher
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

# (아이디, 표시 이름, 역할 설명) — 아이디는 소문자 영문으로 시작하는 3~32자(app/validators.USERNAME_RE)
TEAM = [
    ("hongjh", "홍주형", "웹·DB 하드닝(A)"),
    ("leesh", "이시헌", "네트워크(B)"),
    ("kimtb", "김태빈", "탐지(C)"),
    ("jinhj", "진혜정", "자동화·상황판(D)"),
]
DEPT = "보안관제팀"
INITIAL_PASSWORD = "1234"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.environ.get("DB_NAME", "nexus"))
    ap.add_argument("--reset-initial", action="store_true", help="이미 있는 팀 계정의 비밀번호를 다시 초기값으로 돌린다")
    args = ap.parse_args()
    if args.db not in ("nexus", "nexus_test"):
        sys.exit("허용되지 않는 DB 이름: nexus 또는 nexus_test 만 가능")

    con = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")),
                          user="root", password=os.environ["MYSQL_ROOT_PASSWORD"], database=args.db, autocommit=False)
    cur = con.cursor()
    ph = PasswordHasher()
    created, reset, skipped = [], [], []
    for n, (uname, name, _duty) in enumerate(TEAM):
        cur.execute("SELECT id FROM users WHERE username = %s", (uname,))
        row = cur.fetchone()
        if row and args.reset_initial:
            cur.execute("UPDATE users SET password_hash=%s, failed_count=0, locked_until=NULL, session_version=session_version+1 "
                        "WHERE id=%s", (ph.hash(INITIAL_PASSWORD), row[0]))
            reset.append(uname)
        elif row:
            skipped.append(uname)
        else:
            cur.execute("INSERT INTO users(username,password_hash,role,display_name,dept) VALUES(%s,%s,'admin',%s,%s)",
                        (uname, ph.hash(INITIAL_PASSWORD), name, DEPT))
            cur.execute("INSERT INTO employees(user_id,name,dept,title,ext) VALUES(%s,%s,%s,%s,%s)",
                        (cur.lastrowid, name, DEPT, "관리자", str(2100 + n)))
            created.append(uname)
    con.commit()
    print(f"created: {created}  reset: {reset}  skipped(이미 있음): {skipped}  db={args.db}")
    print("초기 비밀번호는 모두 1234 (로그인 후 /account/password 에서 각자 바꾼다)")


if __name__ == "__main__":
    main()
