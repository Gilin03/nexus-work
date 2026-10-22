"""허니팟 / 디셉션 (Decoy Canary) 동작 검증 테스트."""
import pytest
from app.decoy import DECOY_PATHS
from app import security


def test_decoy_path_returns_404_and_logs_event(aapp, root, events):
    client = aapp.test_client()
    attacker_ip = "203.0.113.88"

    with aapp.app_context():
        security.unblock_ip(attacker_ip)

    # 1. 공격자 환경 모사 (pfSense 신뢰 프록시 경유 /.env 스캔)
    resp = client.get(
        "/.env",
        environ_base={"REMOTE_ADDR": "192.168.3.10"},
        headers={"X-Forwarded-For": attacker_ip, "User-Agent": "Nikto/2.1.6"}
    )
    assert resp.status_code == 404

    # 2. 보안 이벤트 발생 여부 확인
    decoy_events = [e for e in events() if e["event_type"] == "decoy_triggered"]
    assert len(decoy_events) >= 1
    last_event = decoy_events[-1]
    assert last_event["decision"] == "BLOCK"
    assert last_event["reason"] == "scanner_decoy_path"
    assert last_event["path"] == "/.env"
    assert last_event["src_ip"] == attacker_ip

    # 3. 공격자 IP 실시간 차단 테이블 등록 여부 확인
    with aapp.app_context():
        blocked, reason = security.is_ip_blocked(attacker_ip)
        assert blocked is True
        assert "decoy_probe" in reason

        # 정리
        security.unblock_ip(attacker_ip)


def test_all_decoy_routes_respond_404(aapp):
    client = aapp.test_client()
    for path in ["/.git/config", "/backup/backup.sql", "/phpmyadmin", "/wp-login.php"]:
        resp = client.get(path)
        assert resp.status_code == 404
