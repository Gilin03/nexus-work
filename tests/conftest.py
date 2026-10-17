import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app, security  # noqa: E402


@pytest.fixture()
def app(tmp_path):
    security.reset_rate_limits()
    app = create_app({"TESTING": True, "LOG_DIR": tmp_path / "logs", "SESSION_COOKIE_SECURE": False})
    app.log_path = tmp_path / "logs" / "security.jsonl"
    return app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def root():
    """root 연결(시험 계정 생성·상태 조작용). MySQL 에 접속할 수 없으면 해당 테스트를 skip 한다."""
    import pymysql
    import support
    try:
        con = support.connect_root()
    except pymysql.err.OperationalError as exc:
        pytest.skip(f"MySQL 접속 불가: {exc.args[0]}")
    support.cleanup(con)
    support.seed_users(con)
    yield con
    support.cleanup(con)
    con.close()


@pytest.fixture()
def aapp(app, root, tmp_path):
    """nexus_test DB 에 연결되고 업로드 폴더가 임시 경로인 앱."""
    app.config["DB_NAME"] = "nexus_test"
    app.config["UPLOAD_DIR"] = tmp_path / "uploads"
    return app


@pytest.fixture()
def events(app):
    """지금까지 기록된 보안 이벤트(dict 목록)를 돌려주는 함수."""
    def read():
        if not app.log_path.exists():
            return []
        return [json.loads(line) for line in app.log_path.read_text(encoding="utf-8").splitlines() if line]
    return read
