"""n8n 대응 워크플로 전용 DB 계정(nexus_n8n)을 만든다. root 계정으로 접속한다. 여러 번 실행해도 안전하다.

사용: python scripts/create_n8n_account.py [--db nexus] [--rotate]
- 권한은 users 표의 열 단위로만 준다: SELECT(username, pinned, locked_until, session_version), UPDATE(locked_until, session_version).
  역할(role)·비밀번호 해시·다른 표는 읽거나 바꿀 수 없고 INSERT·DELETE 도 없다.
- 비밀번호는 .env 의 N8N_DB_PASSWORD 에서 읽는다. 없으면 무작위로 만들어 .env 에 적는다(화면·로그에는 쓰지 않는다). --rotate 는 새 값으로 바꾼다.
- 계정 호스트는 '%' 다. Docker Desktop 의 포트 전달(NAT) 때문에 MySQL 은 모든 외부 접속을 Docker 게이트웨이(예: 172.21.0.1)에서 온 것으로 본다.
  그래서 접속 장비 제한(예: n8n 장비 192.168.7.77)은 MySQL 이 아니라 Windows 방화벽의 차단 규칙으로 건다(docs/03_팀_연동안내.md).
- 무차별 대입 대비: 로그인 5회 실패 시 1일 잠금, 동시 접속 5개 제한.
- 대응 규칙(사용자 결정 2026-10-20): 고정 계정(pinned=1)은 n8n 이 세션 종료만 자동으로 하고, 잠금은 알림 뒤 사람이 승인한다(n8n 쪽에서 구현)."""
import argparse
import os
import re
import secrets
import sys
from pathlib import Path

import pymysql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"
USER = "nexus_n8n"
HOST = "%"
SELECT_COLS = ("username", "pinned", "locked_until", "session_version")
UPDATE_COLS = ("locked_until", "session_version")


def grant_statements(db, user=USER, host=HOST):
    """이 계정에 줄 권한 전부(다른 권한은 먼저 모두 거둔다)."""
    who = f"'{user}'@'{host}'"
    return [
        f"GRANT SELECT ({', '.join(SELECT_COLS)}) ON `{db}`.users TO {who}",
        f"GRANT UPDATE ({', '.join(UPDATE_COLS)}) ON `{db}`.users TO {who}",
    ]


def ensure_password(rotate=False):
    """N8N_DB_PASSWORD 를 돌려준다. 없거나 --rotate 면 새로 만들어 .env 에 적는다(값은 출력하지 않는다)."""
    text = ENV.read_text(encoding="utf-8") if ENV.exists() else ""
    m = re.search(r"^N8N_DB_PASSWORD=(.+)$", text, re.M)
    if m and not rotate:
        return m.group(1).strip(), False
    pw = secrets.token_urlsafe(24)
    if m:
        text = text[:m.start()] + f"N8N_DB_PASSWORD={pw}" + text[m.end():]
    else:
        text = text.rstrip("\n") + "\n\n# n8n 대응 워크플로 전용 DB 계정(scripts/create_n8n_account.py). 팀 채팅에 쓰지 말고 .env 로만 전달한다.\n" \
            f"N8N_DB_USER={USER}\nN8N_DB_PASSWORD={pw}\n"
    ENV.write_text(text, encoding="utf-8")
    return pw, True


def apply(cur, db, password, user=USER, host=HOST):
    who = f"'{user}'@'{host}'"
    who_fmt = who.replace("%", "%%")                                          # 인자를 쓰는 문장에서는 호스트의 % 를 서식 문자로 보지 않게
    cur.execute(f"CREATE USER IF NOT EXISTS {who_fmt} IDENTIFIED BY %s", (password,))
    cur.execute(f"ALTER USER {who_fmt} IDENTIFIED BY %s WITH MAX_USER_CONNECTIONS 5 FAILED_LOGIN_ATTEMPTS 5 PASSWORD_LOCK_TIME 1", (password,))
    cur.execute(f"REVOKE ALL PRIVILEGES, GRANT OPTION FROM {who}")            # 예전에 더 준 권한이 있어도 정확히 이 목록만 남긴다
    for stmt in grant_statements(db, user, host):
        cur.execute(stmt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="nexus", choices=("nexus", "nexus_test"))
    ap.add_argument("--rotate", action="store_true", help="비밀번호를 새로 만든다(n8n 자격 증명도 바꿔야 한다)")
    args = ap.parse_args()
    password, created = ensure_password(args.rotate)
    load_dotenv(ENV)
    con = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")), user="root",
                          password=os.environ["MYSQL_ROOT_PASSWORD"], autocommit=True)
    with con.cursor() as cur:
        apply(cur, args.db, password)
        cur.execute(f"SHOW GRANTS FOR '{USER}'@'{HOST}'")
        grants = [r[0] for r in cur.fetchall()]
    con.close()
    print("password:", "새로 만들어 .env 에 적음" if created else ".env 의 값을 사용")
    for g in grants:
        print(" ", g)


if __name__ == "__main__":
    sys.exit(main())
