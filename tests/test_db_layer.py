"""app/db.py 를 실제 MySQL(nexus_test)에 붙여 검사한다. 접속 불가면 skip."""
import os

import pymysql
import pytest

from app import db


@pytest.fixture()
def db_app(app):
    app.config["DB_NAME"] = "nexus_test"
    try:
        with app.app_context():
            db.app_db()
            db.close_dbs()
    except pymysql.err.OperationalError as exc:
        pytest.skip(f"MySQL 접속 불가: {exc.args[0]}")
    return app


@pytest.fixture()
def probe_user():
    """root 로 시험용 사용자를 만들고(커밋), 끝나면 관련 행을 지운다."""
    root = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")),
                           user="root", password=os.environ["MYSQL_ROOT_PASSWORD"], database="nexus_test", autocommit=True)
    with root.cursor() as cur:
        cur.execute("INSERT INTO users(username,password_hash,role,display_name,dept) "
                    "VALUES('zz_probe','x','employee','probe','t')")
        uid = cur.lastrowid
    yield uid
    with root.cursor() as cur:
        cur.execute("DELETE FROM posts WHERE author_id=%s", (uid,))
        cur.execute("DELETE FROM users WHERE id=%s", (uid,))
    root.close()


def test_query_helpers_use_least_privilege_accounts(db_app):
    with db_app.app_context():
        assert db.query_one("SELECT COUNT(*) AS n FROM users")["n"] >= 0
        assert db.query_one("SELECT COUNT(*) AS n FROM payroll", conf=True)["n"] >= 0
        with pytest.raises(pymysql.err.OperationalError):
            db.query_one("SELECT COUNT(*) AS n FROM payroll")  # 앱 계정은 기밀 표 불가
        with pytest.raises(pymysql.err.OperationalError):
            db.query_one("SELECT COUNT(*) AS n FROM users", conf=True)  # 기밀 계정은 일반 표 불가
        db.close_dbs()


def test_parameters_are_bound_not_interpolated(db_app):
    with db_app.app_context():
        assert len(db.query_all("SELECT id FROM users WHERE username = %s", ("x' OR '1'='1",))) == 0
        db.close_dbs()


def test_commit_on_success_and_rollback_on_error_response(db_app, probe_user):
    @db_app.post("/_ok")
    def ok():
        db.execute("INSERT INTO posts(board,author_id,title,body) VALUES('free',%s,'keep','b')", (probe_user,))
        return "ok", 200

    @db_app.post("/_fail")
    def fail():
        db.execute("INSERT INTO posts(board,author_id,title,body) VALUES('free',%s,'drop','b')", (probe_user,))
        return "no", 400

    client = db_app.test_client()
    with client.session_transaction() as s:
        s["csrf"] = "t"
    hdr = {"X-CSRF-Token": "t"}
    assert client.post("/_ok", headers=hdr).status_code == 200
    assert client.post("/_fail", headers=hdr).status_code == 400
    with db_app.app_context():
        titles = {r["title"] for r in db.query_all("SELECT title FROM posts WHERE author_id=%s", (probe_user,))}
        db.close_dbs()
    assert titles == {"keep"}  # 200 응답의 쓰기만 남고, 400 응답의 쓰기는 롤백된다
