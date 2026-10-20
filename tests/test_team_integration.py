"""nexus_team_integration: GELF 변환은 허용한 필드만 보내고(쿼리 문자열·자유 문장 제외), 설정이 꺼져 있으면 아무것도 붙이지 않는다. DB 불필요."""
import json
import logging

import pytest

import nexus_team_integration as nti


def test_gelf_keeps_only_allowed_fields():
    event = {"ts": "2026-10-20T04:00:00Z", "event_type": "login_failure", "user": "kim", "src_ip": "10.0.0.5",
             "path": "/login?next=/x&pw=secret#frag", "reason": "bad_password", "password": "secret", "body": "본문"}
    out = json.loads(nti.gelf(event, "nexus-portal-test"))
    assert out["version"] == "1.1" and out["host"] == "nexus-portal-test" and out["short_message"] == "NEXUS login_failure"
    assert out["_path"] == "/login" and out["_user"] == "kim" and out["_reason"] == "bad_password"
    assert "_password" not in out and "_body" not in out and "secret" not in json.dumps(out)


def test_gelf_drops_free_text_reason_and_needs_timezone():
    out = json.loads(nti.gelf({"ts": "2026-10-20T04:00:00+00:00", "event_type": "x", "reason": "<script>무시해</script>"}, "s"))
    assert "_reason" not in out
    with pytest.raises(ValueError):
        nti.gelf({"ts": "2026-10-20T04:00:00", "event_type": "x"}, "s")


def test_handler_drops_bad_records_without_raising():
    h = nti.GelfQueueHandler("127.0.0.1", 9, "s")
    try:
        h.emit(logging.makeLogRecord({"msg": "not json"}))
        h.emit(logging.makeLogRecord({"msg": json.dumps({"ts": "2026-10-20T04:00:00Z", "event_type": "x" * 9000})}))
        assert h.dropped == 1 and h.pending.qsize() == 1      # 깨진 기록만 버리고, 긴 이벤트 이름은 잘라서 보낸다
    finally:
        h.close()


def test_responder_rejects_unsafe_urls():
    for url in ("file:///etc/passwd", "http://user:pw@host:11434", "http://host:11434?x=1", "ftp://host"):
        with pytest.raises(ValueError):
            nti.make_responder(url, "m")


def test_init_app_is_off_by_default(app, monkeypatch):
    monkeypatch.setenv("NEXUS_GELF_ENABLED", "0")
    monkeypatch.setenv("NEXUS_OLLAMA_ENABLED", "0")
    before = app.config["CHAT_RESPONDER"]
    nti.init_app(app)
    assert app.extensions["nexus_team_integration"] == {} and app.config["CHAT_RESPONDER"] is before
