"""DB 연동 테스트 공용 헬퍼. 시험 계정·시험 데이터는 zz_ 접두사로 만들고 끝나면 지운다."""
import os

import pymysql
from argon2 import PasswordHasher

PW = "Zz-Test-Pass-2026!"
PW_HASH = PasswordHasher().hash(PW)
# (아이디, 역할, 부서): A팀·B팀으로 나눠 팀 범위 검사를 시험할 수 있게 한다
USERS = (("zz_emp", "employee", "A팀"), ("zz_emp2", "employee", "A팀"), ("zz_emp3", "employee", "B팀"),
         ("zz_mgr", "manager", "A팀"), ("zz_mgrb", "manager", "B팀"), ("zz_adm", "admin", "관리팀"),
         ("zz_sec", "admin", "보안관제팀"))

_ZZ = "(SELECT id FROM users WHERE username LIKE 'zz\\_%')"


def connect_root():
    return pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")),
                           user="root", password=os.environ["MYSQL_ROOT_PASSWORD"], database="nexus_test",
                           autocommit=True)


def cleanup(con):
    with con.cursor() as cur:
        cur.execute("DELETE FROM security_auth_events WHERE username LIKE 'zz\\_%'")
        # 업무·자료: 외래 키 순서대로(하위 폴더가 나중에 만들어지므로 id 역순으로 지운다)
        cur.execute(f"DELETE FROM lib_files WHERE uploaded_by IN {_ZZ} OR deleted_by IN {_ZZ}")
        cur.execute(f"DELETE FROM lib_folders WHERE created_by IN {_ZZ} ORDER BY id DESC")
        cur.execute(f"DELETE FROM lib_forms WHERE uploaded_by IN {_ZZ}")
        cur.execute(f"DELETE FROM contacts WHERE owner_id IN {_ZZ}")
        cur.execute(f"DELETE FROM task_comments WHERE user_id IN {_ZZ}")
        cur.execute(f"DELETE FROM tasks WHERE creator_id IN {_ZZ} OR assignee_id IN {_ZZ}")
        cur.execute(f"DELETE FROM projects WHERE owner_id IN {_ZZ}")
        cur.execute(f"DELETE FROM events WHERE owner_id IN {_ZZ}")
        cur.execute(f"DELETE FROM reservations WHERE user_id IN {_ZZ}")
        cur.execute("DELETE FROM resources WHERE name LIKE 'zz%'")
        cur.execute(f"DELETE FROM leave_requests WHERE user_id IN {_ZZ} OR decided_by IN {_ZZ}")
        cur.execute(f"DELETE FROM attendance WHERE user_id IN {_ZZ}")
        cur.execute(f"DELETE FROM posts WHERE author_id IN {_ZZ}")
        cur.execute(f"DELETE FROM approval_steps WHERE approver_id IN {_ZZ} "
                    f"OR approval_id IN (SELECT id FROM approvals WHERE requester_id IN {_ZZ})")
        cur.execute(f"DELETE FROM approvals WHERE requester_id IN {_ZZ}")
        cur.execute(f"DELETE FROM expenses WHERE user_id IN {_ZZ}")
        cur.execute(f"DELETE FROM payroll WHERE user_id IN {_ZZ}")
        cur.execute(f"DELETE FROM chat_messages WHERE user_id IN {_ZZ}")
        cur.execute(f"DELETE FROM api_tokens WHERE user_id IN {_ZZ}")
        _CONV = f"(SELECT id FROM conversations WHERE created_by IN {_ZZ})"
        cur.execute(f"DELETE FROM messenger_messages WHERE sender_id IN {_ZZ} OR conversation_id IN {_CONV}")
        cur.execute(f"DELETE FROM conversation_members WHERE user_id IN {_ZZ} OR conversation_id IN {_CONV}")
        cur.execute(f"DELETE FROM conversations WHERE created_by IN {_ZZ}")
        cur.execute("DELETE FROM documents WHERE title LIKE 'zz\\_%'")
        cur.execute("DELETE FROM confidential_documents WHERE title LIKE 'zz\\_%'")
        cur.execute("DELETE FROM financial_reports WHERE title LIKE 'zz\\_%'")
        cur.execute(f"DELETE FROM employees WHERE name LIKE 'zz%' OR user_id IN {_ZZ}")   # 시험 계정의 인사카드는 이름과 상관없이
        cur.execute("DELETE FROM users WHERE username LIKE 'zz\\_%'")


def seed_users(con):
    with con.cursor() as cur:
        for name, role, dept in USERS:
            cur.execute("INSERT INTO users(username,password_hash,role,display_name,dept) VALUES(%s,%s,%s,%s,%s)",
                        (name, PW_HASH, role, name, dept))


def sql(root, query, args=()):
    with root.cursor() as cur:
        cur.execute(query, args or None)  # 인자가 없을 때 빈 튜플을 넘기면 쿼리의 % 가 서식으로 해석된다
        return cur.fetchall()


def uid(root, name):
    return sql(root, "SELECT id FROM users WHERE username=%s", (name,))[0][0]


def token(client):
    client.get("/login")
    with client.session_transaction() as s:
        return s["csrf"]


def login(client, username="zz_emp", password=PW):
    t = token(client)
    return client.post("/login", data={"username": username, "password": password, "csrf_token": t})


def csrf_of(client):
    with client.session_transaction() as s:
        return s["csrf"]


def post(client, path, **data):
    return client.post(path, data={**data, "csrf_token": csrf_of(client)})


def as_user(app, name):
    c = app.test_client()
    assert login(c, name).status_code == 303
    return c
