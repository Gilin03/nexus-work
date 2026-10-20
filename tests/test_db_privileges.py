"""DB 최소권한 점검. Docker MySQL(nexus-mysql)이 떠 있어야 하며 nexus_test DB 에서 실행한다.
접속 불가면 건너뛴다(통과로 오인하지 않도록 skip 으로 표시)."""
import os
from pathlib import Path

import pymysql
import pytest
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
DB = "nexus_test"


def connect(user, password, autocommit=True):
    try:
        return pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"),
                               port=int(os.environ.get("DB_PORT", "3307")),
                               user=user, password=password, database=DB, autocommit=autocommit)
    except pymysql.err.OperationalError as exc:
        pytest.skip(f"MySQL 접속 불가: {exc.args[0]}")


@pytest.fixture(scope="module")
def app():
    c = connect("nexus_app", os.environ["NEXUS_APP_PASSWORD"])
    yield c
    c.close()


@pytest.fixture(scope="module")
def conf():
    c = connect("nexus_conf", os.environ["NEXUS_CONF_PASSWORD"])
    yield c
    c.close()


def run(con, sql):
    with con.cursor() as cur:
        cur.execute(sql)


APP_ALLOWED = [f"SELECT COUNT(*) FROM {t}" for t in (
    "users", "employees", "documents", "posts", "attachments", "chat_messages", "expenses", "approvals",
    "approval_steps", "profile_photos", "attendance", "leave_requests", "approval_cc", "approval_files", "expenditures", "expenditure_items",
    "projects", "project_members", "tasks", "task_comments", "events", "event_attendees", "resources", "reservations",
    "lib_folders", "lib_files", "lib_forms", "contacts")]
APP_DENIED = [
    # 지출결의서: 상신한 뒤에는 금액·내역을 바꾸거나 지울 수 없다
    "UPDATE expenditures SET total_amount=1",
    "UPDATE expenditures SET payee='x'",
    "DELETE FROM expenditures",
    "UPDATE expenditure_items SET amount=1",
    "UPDATE expenditure_items SET qty=1",
    "DELETE FROM expenditure_items",
    # 전자결재 확장: 양식·긴급도는 만든 뒤 바꿀 수 없고, 참조자·첨부는 수정·삭제할 수 없다
    "UPDATE approvals SET doc_type='trip'",
    "UPDATE approvals SET urgency='urgent'",
    "UPDATE approval_cc SET user_id=1",
    "DELETE FROM approval_cc",
    "UPDATE approval_files SET orig_name='x'",
    "DELETE FROM approval_files",
    # 업무·자료: 이력은 지울 수 없고(구성원 해제만 예외), 수정은 상태·숨김 열만 허용한다
    "DELETE FROM projects",
    "UPDATE projects SET owner_id=1",
    "UPDATE projects SET name='x'",
    "DELETE FROM tasks",
    "UPDATE tasks SET title='x'",
    "UPDATE tasks SET creator_id=1",
    "UPDATE tasks SET due_date=NOW()",
    "DELETE FROM task_comments",
    "UPDATE task_comments SET body='x'",
    "DELETE FROM events",
    "UPDATE events SET title='x'",
    "UPDATE events SET owner_id=1",
    "UPDATE events SET start_at=NOW()",
    "DELETE FROM event_attendees",
    "UPDATE event_attendees SET user_id=1",
    "DELETE FROM resources",
    "UPDATE resources SET name='x'",
    "DELETE FROM reservations",
    "UPDATE reservations SET user_id=1",
    "UPDATE reservations SET start_at=NOW()",
    "UPDATE reservations SET end_at=NOW()",
    "UPDATE reservations SET resource_id=1",
    "DELETE FROM lib_folders",
    "UPDATE lib_folders SET name='x'",
    "UPDATE lib_folders SET scope='company'",
    "DELETE FROM lib_files",
    "UPDATE lib_files SET stored_name='x'",
    "UPDATE lib_files SET orig_name='x'",
    "UPDATE lib_files SET uploaded_by=1",
    "DELETE FROM lib_forms",
    "UPDATE lib_forms SET title='x'",
    "UPDATE lib_forms SET stored_name='x'",
    "DELETE FROM contacts",
    "UPDATE contacts SET name='x'",
    "UPDATE contacts SET owner_id=1",
    "UPDATE contacts SET shared=1",
    # 근태: 퇴근 시각 외에는 수정할 수 없고 지울 수 없다(이력 유지)
    "UPDATE attendance SET check_in=NOW()",
    "UPDATE attendance SET user_id=1",
    "DELETE FROM attendance",
    # 휴가: 신청자·종류·기간·일수는 수정할 수 없고 지울 수 없다
    "UPDATE leave_requests SET days=30",
    "UPDATE leave_requests SET user_id=1",
    "UPDATE leave_requests SET start_date=NOW()",
    "UPDATE leave_requests SET reason='x'",
    "DELETE FROM leave_requests",
    # 직원 마스터(사번·입사일·연차)는 앱 계정이 바꿀 수 없다
    "UPDATE employees SET annual_days=99",
    # 고정 계정 표시는 앱 계정이 바꿀 수 없다(인사카드는 직급 title·부서 dept 만 수정 가능)
    "UPDATE users SET pinned=0",
    "UPDATE users SET pinned=1",
    "UPDATE users SET ai_restricted=1",           # AI 제한은 n8n 전용 계정의 몫이다(앱 계정은 바꿀 수 없다)
    "UPDATE employees SET emp_no='x'",
    "UPDATE employees SET hire_date=NOW()",
    "UPDATE profile_photos SET mime='x'",
    "SELECT COUNT(*) FROM confidential_documents",
    "SELECT COUNT(*) FROM payroll",
    "SELECT COUNT(*) FROM financial_reports",
    "INSERT INTO documents(title,body) VALUES('x','y')",
    "UPDATE employees SET name='x'",
    "DELETE FROM users",
    "DELETE FROM expenses",
    "DELETE FROM approvals",
    "DELETE FROM approval_steps",
    "UPDATE chat_messages SET content='x'",
    # 상태 전이에 필요한 열 외에는 수정할 수 없다(소유자·금액·상신자·결재자 변경 불가)
    "UPDATE expenses SET amount=1",
    "UPDATE expenses SET user_id=1",
    "UPDATE approvals SET requester_id=1",
    "UPDATE approvals SET title='x'",
    "UPDATE approval_steps SET approver_id=1",
    "UPDATE approval_steps SET step_no=1",
    # users: 아이디·이름·생성 시각은 앱 계정이 바꿀 수 없다
    "UPDATE users SET username='x'",
    "UPDATE users SET display_name='x'",
    "UPDATE users SET created_at=NOW()",
    "DELETE FROM users",
    "DROP TABLE users",
    "CREATE TABLE zz(a INT)",
    "SELECT COUNT(*) FROM mysql.user",
    "SELECT 1 INTO OUTFILE '/tmp/x'",
]
CONF_ALLOWED = [f"SELECT COUNT(*) FROM {t}" for t in ("confidential_documents", "payroll", "financial_reports")]
CONF_DENIED = [
    "SELECT COUNT(*) FROM users",
    "SELECT COUNT(*) FROM documents",
    "INSERT INTO payroll(user_id,pay_month,base_salary) VALUES(1,'2026-01',1)",
    "DELETE FROM confidential_documents",
    "DROP TABLE payroll",
]


@pytest.mark.parametrize("sql", APP_ALLOWED)
def test_app_allowed(app, sql):
    run(app, sql)


APP_ALLOWED_WRITES = [  # 해당 열은 수정할 수 있어야 한다(WHERE id=0 이라 실제 행은 바뀌지 않는다)
    "UPDATE projects SET status='done' WHERE id=0",
    "DELETE FROM project_members WHERE project_id=0",
    "UPDATE tasks SET status='done', completed_at=NOW(), assignee_id=1 WHERE id=0",
    "UPDATE events SET status='cancelled' WHERE id=0",
    "UPDATE resources SET active=0 WHERE id=0",
    "UPDATE reservations SET status='cancelled' WHERE id=0",
    "UPDATE lib_files SET deleted_at=NOW(), deleted_by=1 WHERE id=0",
    "UPDATE lib_forms SET deleted_at=NOW() WHERE id=0",
    "UPDATE contacts SET deleted_at=NOW() WHERE id=0",
    "UPDATE employees SET title='사원' WHERE id=0",
    "UPDATE users SET deleted_at=NOW(), deleted_by=1 WHERE id=0",
    "UPDATE users SET dept='x' WHERE id=0",
    "UPDATE employees SET dept='x' WHERE id=0",
    "UPDATE attendance SET check_out=NOW() WHERE id=0",
    "UPDATE leave_requests SET status='approved', decided_by=1, decided_at=NOW(), decision_reason='x' WHERE id=0",
    "UPDATE users SET password_hash='x' WHERE id=0",
    "UPDATE users SET failed_count=0 WHERE id=0",
    "UPDATE users SET locked_until=NULL WHERE id=0",
    "UPDATE users SET role='employee' WHERE id=0",
    "UPDATE users SET session_version=session_version WHERE id=0",
    "UPDATE expenses SET status='draft' WHERE id=0",
    "UPDATE approvals SET status='pending', current_step=1, decided_at=NULL WHERE id=0",
    "UPDATE approval_steps SET status='pending', reason=NULL, decided_at=NULL WHERE id=0",
]


@pytest.mark.parametrize("sql", APP_ALLOWED_WRITES)
def test_app_allowed_writes_on_state_columns(app, sql):
    run(app, sql)


@pytest.mark.parametrize("sql", APP_DENIED)
def test_app_denied(app, sql):
    with pytest.raises(pymysql.err.OperationalError) as exc:
        run(app, sql)
    assert exc.value.args[0] in (1142, 1143, 1044, 1227)  # 1143: 열 단위 권한 없음


@pytest.mark.parametrize("sql", CONF_ALLOWED)
def test_conf_allowed(conf, sql):
    run(conf, sql)


@pytest.mark.parametrize("sql", CONF_DENIED)
def test_conf_denied(conf, sql):
    with pytest.raises(pymysql.err.OperationalError) as exc:
        run(conf, sql)
    assert exc.value.args[0] in (1142, 1044)


def test_self_approval_blocked_by_db_trigger():
    """상신자 본인을 결재선에 넣으면 DB 트리거가 거부한다(root 로 시험하고 롤백). 다른 결재자는 허용된다."""
    root = connect("root", os.environ["MYSQL_ROOT_PASSWORD"], autocommit=False)
    try:
        with root.cursor() as cur:
            ids = []
            for name in ("zz_probe_a", "zz_probe_b"):
                cur.execute("INSERT INTO users(username,password_hash,role,display_name,dept) "
                            "VALUES(%s,'x','manager','probe','t')", (name,))
                ids.append(cur.lastrowid)
            cur.execute("INSERT INTO approvals(title,body,requester_id) VALUES('t','b',%s)", (ids[0],))
            approval_id = cur.lastrowid
            with pytest.raises(pymysql.err.OperationalError) as exc:
                cur.execute("INSERT INTO approval_steps(approval_id,step_no,approver_id) VALUES(%s,1,%s)",
                            (approval_id, ids[0]))
            assert exc.value.args[0] == 1644  # 트리거가 SIGNAL 한 오류
            cur.execute("INSERT INTO approval_steps(approval_id,step_no,approver_id) VALUES(%s,1,%s)",
                        (approval_id, ids[1]))  # 다른 사람은 가능
    finally:
        root.rollback()
        root.close()


def test_step_constraints_unique_order_unique_approver_and_range():
    root = connect("root", os.environ["MYSQL_ROOT_PASSWORD"], autocommit=False)
    try:
        with root.cursor() as cur:
            ids = []
            for name in ("zz_probe_r", "zz_probe_x", "zz_probe_y"):
                cur.execute("INSERT INTO users(username,password_hash,role,display_name,dept) "
                            "VALUES(%s,'x','manager','probe','t')", (name,))
                ids.append(cur.lastrowid)
            cur.execute("INSERT INTO approvals(title,body,requester_id) VALUES('t','b',%s)", (ids[0],))
            aid = cur.lastrowid
            cur.execute("INSERT INTO approval_steps(approval_id,step_no,approver_id) VALUES(%s,1,%s)", (aid, ids[1]))
            for step, approver in ((1, ids[2]), (2, ids[1])):       # 같은 순서·같은 결재자 중복 거부
                with pytest.raises(pymysql.err.IntegrityError):
                    cur.execute("INSERT INTO approval_steps(approval_id,step_no,approver_id) VALUES(%s,%s,%s)",
                                (aid, step, approver))
            for step in (0, 6):                                      # 1~5 범위 밖 거부
                with pytest.raises(pymysql.err.OperationalError) as exc:
                    cur.execute("INSERT INTO approval_steps(approval_id,step_no,approver_id) VALUES(%s,%s,%s)",
                                (aid, step, ids[2]))
                assert exc.value.args[0] == 3819
    finally:
        root.rollback()
        root.close()
