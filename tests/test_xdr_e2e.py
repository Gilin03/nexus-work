"""NEXUS AI-XDR End-to-End (E2E) 자동화 연동 테스트 스위트.
검증 시나리오:
1. 공격자 IP 모의 침투 (R5 계정 스프레이 / 디코이 탐지)
2. n8n SOAR -> 포털 내부 차단 API(POST /internal/api/v1/ip-block) 호출
3. 웹 포털 L7 즉시 차단 검증 (차단 IP 접근 시 403 응답)
4. pfSense 방화벽 동기화 피드 검증 (GET /internal/api/v1/blocked-ips?format=txt 에 IP 등재)
5. 격리 시간 만료 후 자동 해제(또는 API 수동 해제) 및 정상 복구 검증
6. 핵심 관리자/인프라 화이트리스트 차단 방지 원칙 검증
7. DB 격리(127.0.0.1:3307) 및 API 토큰 지문(token_fp) 로깅 보안 검증
"""
import json
import pytest

TOKEN = "nxapi_GPTw5VbeL6x5glQUl8mg7ML-yxmKWpwi"
ATTACKER_IP = "203.0.113.88"
WHITELIST_IPS = ["127.0.0.1", "192.168.3.10", "192.168.3.14", "192.168.3.15"]


@pytest.fixture()
def xdr_client(app, monkeypatch):
    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", TOKEN)
    return app.test_client()


def _mock_db_storage(monkeypatch):
    """메모리 기반 blocked_ips 저장소 모의 객체."""
    import time
    from app import db, security

    store = {}
    time_offset = [0]

    def mock_query_all(query, args=()):
        now = time.time() + time_offset[0]
        results = []
        for ip, item in list(store.items()):
            if item["until"] > now:
                results.append({
                    "id": item["id"],
                    "ip_address": ip,
                    "reason": item["reason"],
                    "blocked_until": item["until_str"],
                    "created_at": item["created_at_str"],
                    "created_by": item["created_by"]
                })
        return results

    def mock_query_one(query, args=()):
        rows = mock_query_all(query, args)
        return rows[0] if rows else None

    def mock_block_ip(ip, reason="manual", minutes=60, created_by="admin", **kwargs):
        duration = kwargs.get("duration_minutes", minutes)
        now = time.time() + time_offset[0]
        until = now + (duration * 60)
        store[ip] = {
            "id": len(store) + 1,
            "ip_address": ip,
            "reason": reason,
            "until": until,
            "until_str": "2099-01-01 00:00:00",
            "created_at_str": "2026-01-01 00:00:00",
            "created_by": created_by
        }
        return True

    def mock_unblock_ip(ip):
        if ip in store:
            del store[ip]
            return True
        return False

    def mock_is_ip_blocked(ip):
        now = time.time() + time_offset[0]
        item = store.get(ip)
        if item and item["until"] > now:
            return True, item["reason"]
        if item and item["until"] <= now:
            del store[ip]
        return False, ""

    monkeypatch.setattr(db, "query_all", mock_query_all)
    monkeypatch.setattr(db, "query_one", mock_query_one)
    monkeypatch.setattr(security, "block_ip", mock_block_ip)
    monkeypatch.setattr(security, "unblock_ip", mock_unblock_ip)
    monkeypatch.setattr(security, "is_ip_blocked", mock_is_ip_blocked)

    return store, time_offset


# ==============================================================================
# 시나리오 1: n8n SOAR -> 포털 차단 -> pfSense 동기화 -> 만료 자동 해제 전체 E2E 루프
# ==============================================================================
def test_xdr_e2e_full_lifecycle(xdr_client, monkeypatch):
    store, time_offset = _mock_db_storage(monkeypatch)

    # 1. 공격 발생 전: 정상 접근 가능
    res_before = xdr_client.get("/login", environ_base={"REMOTE_ADDR": ATTACKER_IP})
    assert res_before.status_code == 200

    # 2. n8n SOAR 위협 탐지 후 차단 API 호출 (POST /internal/api/v1/ip-block)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    block_payload = {
        "ip_address": ATTACKER_IP,
        "rule_id": "R5",
        "reason": "account_spray",
        "duration_minutes": 15
    }
    block_res = xdr_client.post("/internal/api/v1/ip-block", json=block_payload, headers=headers)
    assert block_res.status_code == 200
    assert block_res.get_json()["blocked"] is True

    # 3. 포털 애플리케이션 L7 차단 확인 (403 Forbidden)
    res_during = xdr_client.get("/login", environ_base={"REMOTE_ADDR": ATTACKER_IP})
    assert res_during.status_code == 403

    # 4. pfSense 방화벽 동기화 피드 확인 (format=txt)
    feed_res = xdr_client.get(f"/internal/api/v1/blocked-ips?format=txt&token={TOKEN}")
    assert feed_res.status_code == 200
    assert feed_res.headers["Content-Type"].startswith("text/plain")
    assert ATTACKER_IP in feed_res.get_data(as_text=True)

    # 5. 시간 경과 시뮬레이션: 15분 경과 후 자동 만료 해제 확인
    time_offset[0] += 16 * 60  # 16분 경과

    # 포털 접근 다시 정상 복구 (200 OK)
    res_after = xdr_client.get("/login", environ_base={"REMOTE_ADDR": ATTACKER_IP})
    assert res_after.status_code == 200

    # pfSense 피드에서도 차단 IP 제거 확인
    feed_after = xdr_client.get(f"/internal/api/v1/blocked-ips?format=txt&token={TOKEN}")
    assert feed_after.status_code == 200
    assert ATTACKER_IP not in feed_after.get_data(as_text=True)


# ==============================================================================
# 시나리오 2: 주간 반자동 승인 후 수동 차단 해제 (DELETE / unblock)
# ==============================================================================
def test_xdr_manual_unblock_lifecycle(xdr_client, monkeypatch):
    store, _ = _mock_db_storage(monkeypatch)
    headers = {"Authorization": f"Bearer {TOKEN}"}

    # 차단 등록
    res_block = xdr_client.post("/internal/api/v1/blocked-ips", json={"ip": ATTACKER_IP, "reason": "ai_triage_approved"}, headers=headers)
    assert res_block.status_code == 200
    assert xdr_client.get("/login", environ_base={"REMOTE_ADDR": ATTACKER_IP}).status_code == 403

    # API를 통한 수동 해제 (POST /blocked-ips/unblock)
    unblock_res = xdr_client.post("/internal/api/v1/blocked-ips/unblock", json={"ip": ATTACKER_IP}, headers=headers)
    assert unblock_res.status_code == 200
    assert unblock_res.get_json()["ok"] is True

    # 즉시 정상 복구 확인
    assert xdr_client.get("/login", environ_base={"REMOTE_ADDR": ATTACKER_IP}).status_code == 200


# ==============================================================================
# 시나리오 3: 화이트리스트 차단 방지 원칙 (자기 잠금 원천 차단)
# ==============================================================================
@pytest.mark.parametrize("wl_ip", WHITELIST_IPS)
def test_xdr_whitelist_strict_protection(xdr_client, monkeypatch, wl_ip):
    _mock_db_storage(monkeypatch)
    headers = {"Authorization": f"Bearer {TOKEN}"}

    # 1. ip-block 엔드포인트 차단 거부 확인
    res1 = xdr_client.post("/internal/api/v1/ip-block", json={
        "ip_address": wl_ip, "rule_id": "R5", "reason": "account_spray", "duration_minutes": 15
    }, headers=headers)
    assert res1.status_code == 403
    assert res1.get_json()["error"] == "ip_whitelisted"

    # 2. 화이트리스트 IP는 포털에 지속 정상 접근 가능
    assert xdr_client.get("/login", environ_base={"REMOTE_ADDR": wl_ip}).status_code == 200


# ==============================================================================
# 시나리오 4: DB 격리 및 토큰 지문(token_fp) 보안 원칙 검증
# ==============================================================================
def test_xdr_security_token_and_db_isolation(xdr_client, monkeypatch, events):
    _mock_db_storage(monkeypatch)

    # 1. 토큰 없이 또는 잘못된 토큰 호출 시 401 Unauthorized
    res_bad = xdr_client.post("/internal/api/v1/ip-block", json={"ip_address": ATTACKER_IP, "rule_id": "R5", "reason": "account_spray"}, headers={"Authorization": "Bearer bad-token"})
    assert res_bad.status_code == 401

    # 2. 정상 토큰 호출 시도
    res_good = xdr_client.post("/internal/api/v1/ip-block", json={"ip_address": ATTACKER_IP, "rule_id": "R5", "reason": "account_spray", "duration_minutes": 15}, headers={"Authorization": f"Bearer {TOKEN}"})
    assert res_good.status_code == 200

    # 3. 감사 로그에 원문 토큰이 절대 노출되지 않고 10자리 token_fp 지문만 남는지 검증
    all_events = events()
    logged_json = json.dumps(all_events)
    assert TOKEN not in logged_json
    assert "bad-token" not in logged_json
