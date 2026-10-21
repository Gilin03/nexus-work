import pytest
from app import security


def test_ip_blocking_lifecycle(app, client):
    test_ip = "192.168.100.99"

    # 1. 초기 상태: 차단되지 않음
    with app.app_context():
        security.unblock_ip(test_ip)
        blocked, _ = security.is_ip_blocked(test_ip)
        assert blocked is False

    # 2. IP 차단 등록 (30분)
    with app.app_context():
        assert security.block_ip(test_ip, reason="test_attack", minutes=30, created_by="tester") is True
        blocked, reason = security.is_ip_blocked(test_ip)
        assert blocked is True
        assert reason == "test_attack"

    # 3. HTTP 요청 시 403 거부 확인 (X-Forwarded-For 사용)
    # 192.168.3.10(신뢰 프록시)를 통해 test_ip가 접근하는 시나리오
    res = client.get("/login", environ_base={"REMOTE_ADDR": "192.168.3.10"}, headers={"X-Forwarded-For": test_ip})
    assert res.status_code == 403
    assert "차단된 IP" in res.get_data(as_text=True)

    # 4. API 경로 호출 시 403 JSON 응답 확인
    res_api = client.get("/api/v1/auth/check", environ_base={"REMOTE_ADDR": "192.168.3.10"}, headers={"X-Forwarded-For": test_ip})
    assert res_api.status_code == 403
    data = res_api.get_json()
    assert data["error"] == "ip_blocked"

    # 5. 다른 IP는 정상 접근 가능
    res_ok = client.get("/login", environ_base={"REMOTE_ADDR": "192.168.3.10"}, headers={"X-Forwarded-For": "192.168.100.100"})
    assert res_ok.status_code == 200

    # 6. 정적 파일 및 healthz는 차단되지 않음
    res_healthz = client.get("/healthz", environ_base={"REMOTE_ADDR": "192.168.3.10"}, headers={"X-Forwarded-For": test_ip})
    assert res_healthz.status_code == 200

    # 7. 차단 해제 후 정상 접근 확인
    with app.app_context():
        assert security.unblock_ip(test_ip) is True
        blocked, _ = security.is_ip_blocked(test_ip)
        assert blocked is False

    res_after = client.get("/login", environ_base={"REMOTE_ADDR": "192.168.3.10"}, headers={"X-Forwarded-For": test_ip})
    assert res_after.status_code == 200
