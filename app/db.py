"""DB 연결. 계정별(nexus_app / nexus_conf)로 요청당 연결 하나씩.
SQL 은 항상 상수 문자열 + params 로만 호출한다(tests/test_sql_static.py 가 검사).
커밋은 응답 상태가 400 미만일 때만, 그 외에는 롤백한다."""
import pymysql
import pymysql.cursors
from flask import current_app, g


def _connect(user, password):
    c = current_app.config
    return pymysql.connect(host=c["DB_HOST"], port=c["DB_PORT"], user=user, password=password,
                           database=c["DB_NAME"], charset="utf8mb4", autocommit=False,
                           cursorclass=pymysql.cursors.DictCursor,
                           connect_timeout=5, read_timeout=10, write_timeout=10)


def app_db():
    if "app_db" not in g:
        g.app_db = _connect(current_app.config["DB_APP_USER"], current_app.config["DB_APP_PASSWORD"])
    return g.app_db


def conf_db():
    """기밀 표 전용. 기밀 권한 확인을 통과한 뒤에만 호출한다."""
    if "conf_db" not in g:
        g.conf_db = _connect(current_app.config["DB_CONF_USER"], current_app.config["DB_CONF_PASSWORD"])
    return g.conf_db


def query_all(sql, params=(), conf=False):
    with (conf_db() if conf else app_db()).cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def query_one(sql, params=(), conf=False):
    with (conf_db() if conf else app_db()).cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def execute(sql, params=()):
    """쓰기 쿼리(nexus_app 전용). 새로 생긴 행의 id 를 돌려준다."""
    with app_db().cursor() as cur:
        cur.execute(sql, params)
        return cur.lastrowid


def commit():
    """401 같은 오류 응답에서도 남겨야 하는 쓰기(로그인 실패 횟수 등)를 즉시 확정한다."""
    for key in ("app_db", "conf_db"):
        con = g.get(key)
        if con is not None:
            con.commit()


def execute_rowcount(sql, params=()):
    """UPDATE 가 실제로 바꾼 행 수를 돌려준다. 상태 전이처럼 '조건에 맞을 때만 바뀌어야' 하는 쓰기에 쓴다."""
    with app_db().cursor() as cur:
        return cur.execute(sql, params)


def finish_request(resp):
    ok = resp.status_code < 400
    for key in ("app_db", "conf_db"):
        con = g.get(key)
        if con is not None:
            con.commit() if ok else con.rollback()
    return resp


def close_dbs(_exc=None):
    for key in ("app_db", "conf_db"):
        con = g.pop(key, None)
        if con is not None:
            try:
                con.rollback()
            finally:
                con.close()
