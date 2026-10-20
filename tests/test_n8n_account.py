"""n8n 대응 계정(scripts/create_n8n_account.py)의 권한: 잠금·세션 종료에 필요한 열만 읽고 쓴다. Docker MySQL(nexus_test) 필요, 접속 불가면 skip.
시험용 계정(zz_n8n_t)에 실제 스크립트와 같은 권한을 nexus_test 범위로 주고, 그 계정으로 접속해 확인한 뒤 지운다."""
import importlib.util
import os
from pathlib import Path

import pymysql
import pytest

from support import login, sql, uid

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("create_n8n_account", ROOT / "scripts" / "create_n8n_account.py")
n8n = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(n8n)

USER, PW = "zz_n8n_t", "Zz-n8n-Test-Pass-2026!"


@pytest.fixture()
def n8n_con(root):
    with root.cursor() as cur:
        n8n.apply(cur, "nexus_test", PW, user=USER, host="%")
    con = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")),
                          user=USER, password=PW, database="nexus_test", autocommit=True)
    yield con
    con.close()
    sql(root, f"DROP USER IF EXISTS '{USER}'@'%%'")


def run(con, query, args=None):
    with con.cursor() as cur:
        cur.execute(query, args)
        return cur.fetchall()


# n8n 이 실행하는 문장(대응 워크플로와 같은 모양). 잠금 시각은 반드시 DB 시계(UTC)로 계산한다.
LOOKUP = "SELECT username, pinned, locked_until, session_version FROM users WHERE username = %s"
LOCK = "UPDATE users SET locked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE) WHERE username = %s AND pinned = 0"
KILL_SESSIONS = "UPDATE users SET session_version = session_version + 1 WHERE username = %s"


def test_grants_are_exactly_the_requested_columns():
    stmts = n8n.grant_statements("nexus")
    assert stmts == ["GRANT SELECT (username, pinned, locked_until, session_version) ON `nexus`.users TO 'nexus_n8n'@'%'",
                     "GRANT UPDATE (locked_until, session_version) ON `nexus`.users TO 'nexus_n8n'@'%'"]


def test_n8n_can_look_up_lock_and_end_sessions(n8n_con, root):
    rows = run(n8n_con, LOOKUP, ("zz_emp",))
    assert rows and rows[0][0] == "zz_emp" and rows[0][1] == 0
    before = sql(root, "SELECT session_version FROM users WHERE username='zz_emp'")[0][0]
    run(n8n_con, LOCK, ("zz_emp",))
    run(n8n_con, KILL_SESSIONS, ("zz_emp",))
    locked, version = sql(root, "SELECT locked_until > NOW() AND locked_until < DATE_ADD(NOW(), INTERVAL 16 MINUTE), session_version "
                                "FROM users WHERE username='zz_emp'")[0]
    assert locked == 1 and version == before + 1                                  # 15분 잠금(9시간 어긋남 없음), 세션 버전 +1


def test_pinned_accounts_get_session_kill_but_the_lock_query_skips_them(n8n_con, root):
    sql(root, "INSERT INTO users(username,password_hash,role,display_name,dept) VALUES('zz_pin_t','x','admin','p','보안관제팀')")
    sql(root, "UPDATE users SET pinned = 1 WHERE username = 'zz_pin_t'")             # 고정 계정(실제로는 admin·hongjh)과 같은 상태로
    assert run(n8n_con, LOOKUP, ("zz_pin_t",))[0][1] == 1                          # n8n 이 고정 여부를 읽을 수 있다
    with n8n_con.cursor() as cur:
        assert cur.execute(LOCK, ("zz_pin_t",)) == 0                               # 자동 잠금 문장은 고정 계정을 건드리지 않는다(사람 승인)
        assert cur.execute(KILL_SESSIONS, ("zz_pin_t",)) == 1                       # 세션 종료는 자동으로 된다
    assert sql(root, "SELECT role, pinned, locked_until FROM users WHERE username='zz_pin_t'")[0] == ("admin", 1, None)


@pytest.mark.parametrize("query", [
    "SELECT password_hash FROM users",
    "SELECT * FROM users",
    "SELECT id FROM users",
    "SELECT role FROM users",
    "SELECT username FROM users WHERE role = 'admin'",                             # 허용 안 된 열은 조건에도 못 쓴다
    "UPDATE users SET role = 'admin' WHERE username = 'zz_emp'",
    "UPDATE users SET pinned = 0 WHERE username = 'zz_emp'",
    "UPDATE users SET failed_count = 0 WHERE username = 'zz_emp'",
    "UPDATE users SET password_hash = 'x' WHERE username = 'zz_emp'",
    "DELETE FROM users WHERE username = 'zz_emp'",
    "INSERT INTO users(username,password_hash,role,display_name,dept) VALUES('zz_x','x','admin','x','x')",
    "SELECT COUNT(*) FROM posts",
    "SELECT COUNT(*) FROM confidential_documents",
    "SELECT COUNT(*) FROM payroll",
    "SELECT COUNT(*) FROM nexus.users",
    "DROP TABLE users",
    "CREATE TABLE zz_t(a INT)",
    "SELECT 1 INTO OUTFILE '/tmp/x'",
])
def test_everything_else_is_denied(n8n_con, root, query):
    with pytest.raises((pymysql.err.OperationalError, pymysql.err.ProgrammingError)) as exc:
        run(n8n_con, query)
    assert exc.value.args[0] in (1142, 1143, 1044, 1045, 1227, 1370)
    assert sql(root, "SELECT role, pinned FROM users WHERE username='zz_emp'")[0] == ("employee", 0)


def test_lock_from_n8n_cuts_an_open_portal_session(aapp, root, n8n_con):
    c = aapp.test_client()
    assert login(c, "zz_emp").status_code == 303
    assert c.get("/hr/leave").status_code == 200
    run(n8n_con, KILL_SESSIONS, ("zz_emp",))
    r = c.get("/hr/leave")
    assert r.status_code == 303 and "/login" in r.headers["Location"]              # 세션 종료가 바로 반영된다
    assert login(c, "zz_emp").status_code == 303
    run(n8n_con, LOCK, ("zz_emp",))
    assert c.get("/hr/leave").status_code == 303                                    # 잠금도 열린 세션을 끊는다
    assert login(aapp.test_client(), "zz_emp").status_code == 401                   # 잠금 동안 로그인 불가
    sql(root, "UPDATE users SET locked_until = NULL WHERE id = %s", (uid(root, "zz_emp"),))
