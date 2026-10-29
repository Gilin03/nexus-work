"""실습용 내부 API(/internal/api/v1/flag): 맞는 토큰이면 FLAG, 아니면 401. 모든 호출을 via=direct·출발지·토큰 지문으로 남기고 토큰 원문은 남기지 않는다. DB 불필요."""
import json

import pytest

from app import internal_api

TOKEN = "nxapi_zz-test-token-0123456789abcdef"
FLAG = "FLAG{zz-test-flag}"


@pytest.fixture()
def lab(test_db_app, monkeypatch):
    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", TOKEN)
    monkeypatch.setenv("LAB_INTERNAL_API_FLAG", FLAG)
    return test_db_app.test_client()


def call(c, token=None, header=None):
    headers = {"Authorization": header if header is not None else f"Bearer {token}"} if (token or header is not None) else {}
    return c.get("/internal/api/v1/flag", headers=headers)


def test_right_token_returns_the_flag_and_is_logged_as_direct(lab, events):
    r = call(lab, TOKEN)
    assert r.status_code == 200 and r.get_json() == {"ok": True, "flag": FLAG}
    e = [x for x in events() if x["event_type"] == "internal_api"][-1]
    assert e["decision"] == "ALLOW" and e["via"] == "direct" and e["api_path"] == "/flag" and e["src_ip"]
    assert e["token_fp"] == internal_api.token_fingerprint(TOKEN) and len(e["token_fp"]) == 10
    assert TOKEN not in json.dumps(events()) and FLAG not in json.dumps(events())        # 토큰·FLAG 원문은 로그에 없다


@pytest.mark.parametrize("header", ["Bearer wrong", "Bearer " + TOKEN + "x", "Bearer " + TOKEN[:-1], TOKEN, "Basic " + TOKEN, ""])
def test_wrong_or_missing_token_is_denied(lab, events, header):
    r = call(lab, header=header)
    assert r.status_code == 401 and FLAG not in r.get_data(as_text=True)
    e = [x for x in events() if x["event_type"] == "internal_api"][-1]
    assert e["decision"] == "DENY" and e["reason"] == "bad_token" and e["via"] == "direct"


def test_no_token_configured_means_nothing_opens(app, monkeypatch):
    monkeypatch.delenv("LAB_INTERNAL_API_TOKEN", raising=False)
    monkeypatch.setenv("LAB_INTERNAL_API_FLAG", FLAG)
    c = app.test_client()
    for header in ("Bearer ", "Bearer x", ""):
        assert call(c, header=header).status_code == 401


def test_flag_not_configured_is_explained_not_leaked(app, monkeypatch):
    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", TOKEN)
    monkeypatch.delenv("LAB_INTERNAL_API_FLAG", raising=False)
    r = call(app.test_client(), TOKEN)
    assert r.status_code == 200 and "설정되지 않았습니다" in r.get_json()["flag"]


def test_gateway_path_uses_the_same_check(app, lab, events):
    with app.test_request_context("/chat"):                                                # 게이트웨이는 채팅 요청 안에서 부른다
        assert internal_api.internal_api("/flag", TOKEN, "gateway", conversation_id=7) == (True, FLAG)
        assert internal_api.internal_api("/flag", "bad", "gateway")[0] is False
        assert internal_api.internal_api("/other", TOKEN, "gateway") == (True, "지원하지 않는 경로입니다.")
    vias = [(x["via"], x["decision"]) for x in events() if x["event_type"] == "internal_api"]
    assert vias == [("gateway", "ALLOW"), ("gateway", "DENY"), ("gateway", "ALLOW")]


def test_rate_limit_per_ip(lab, events):
    codes = [call(lab, header="Bearer guess").status_code for _ in range(internal_api.RATE_LIMIT + 3)]
    assert codes[:internal_api.RATE_LIMIT] == [401] * internal_api.RATE_LIMIT and codes[-1] == 429
    assert call(lab, TOKEN).status_code == 429                                              # 한도를 넘기면 맞는 토큰도 잠시 거부
    assert any(x.get("reason") == "internal_api_limit" for x in events())


def test_only_get_and_no_cookie_session_needed(lab):
    assert lab.post("/internal/api/v1/flag", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 403   # POST 는 CSRF 단계에서 막힌다
    assert lab.get("/internal/api/v1/other", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 404


def test_blocked_ips_unauthorized(lab):
    # 토큰 없이 조회/차단/해제 요청 시 401 거부
    assert lab.get("/internal/api/v1/blocked-ips").status_code == 401
    assert lab.post("/internal/api/v1/blocked-ips", json={"ip": "1.2.3.4"}).status_code == 401
    assert lab.post("/internal/api/v1/blocked-ips/unblock", json={"ip": "1.2.3.4"}).status_code == 401
    assert lab.delete("/internal/api/v1/blocked-ips/1.2.3.4").status_code == 401

    # 잘못된 토큰 시 401 거부
    bad_headers = {"Authorization": "Bearer wrong_token"}
    assert lab.get("/internal/api/v1/blocked-ips", headers=bad_headers).status_code == 401
    assert lab.post("/internal/api/v1/blocked-ips", json={"ip": "1.2.3.4"}, headers=bad_headers).status_code == 401


@pytest.mark.parametrize("policy_reason", [
    "DAYTIME_APPROVAL", "WEEKEND_APPROVAL",
    "daytime_requires_approval", "weekend_requires_approval",
])
def test_xdr_approval_endpoint_records_only_eligible_r1_dry_run(app, monkeypatch, policy_reason):
    from app import ai_xdr, db

    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", TOKEN)
    app.config.update({"XDR_ENABLED": True, "XDR_AUTO_ENABLED": False, "XDR_RESPONSE_MODE": "dry-run",
                       "XDR_AUTO_MIN_SCORE": 80, "XDR_AUTO_MIN_CONFIDENCE": 0.8})
    assessment_id = "632a3638-6845-4904-abba-62a9f9e0e33a"
    approval_ref = assessment_id + ":NX-DB-000046"
    row = {"assessment_id": assessment_id, "rule_ids": '["R1"]', "status": "PENDING",
           "approval_allowed": 1, "auto_allowed": 0, "policy_reason": policy_reason,
           "verdict": "MALICIOUS", "threat_score": 80, "confidence": 0.85}
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: row)
    calls = []

    def decide(*args, **kwargs):
        calls.append((args, kwargs))
        return {"assessment_id": assessment_id, "status": "APPROVED",
                "response": {"blocked": False, "reason": "dry_run"}, "approval_ref": approval_ref}

    monkeypatch.setattr(ai_xdr, "decide_assessment", decide)
    response = app.test_client().post("/internal/api/v1/ai-xdr/decision", json={
        "assessment_id": assessment_id, "status": "APPROVED", "approval_ref": approval_ref,
    }, headers={"Authorization": f"Bearer {TOKEN}"})

    assert response.status_code == 200
    assert response.get_json() == {"ok": True, "assessment_id": assessment_id, "status": "APPROVED",
                                   "approval_ref": approval_ref,
                                   "response": {"blocked": False, "reason": "dry_run"}}
    assert calls[0][0] == (assessment_id, "APPROVED", None, "n8n_approve_response")
    assert calls[0][1]["approval_ref"] == approval_ref


def test_xdr_approval_endpoint_fails_closed_outside_dry_run(app, monkeypatch):
    from app import ai_xdr, db

    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", TOKEN)
    app.config.update({"XDR_ENABLED": True, "XDR_AUTO_ENABLED": False, "XDR_RESPONSE_MODE": "live",
                       "XDR_AUTO_MIN_SCORE": 80, "XDR_AUTO_MIN_CONFIDENCE": 0.8})
    calls = []
    assessment_id = "632a3638-6845-4904-abba-62a9f9e0e33a"
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: {"assessment_id": assessment_id, "rule_ids": '["R3"]'})
    monkeypatch.setattr(ai_xdr, "decide_assessment", lambda *args, **kwargs: calls.append(args))

    response = app.test_client().post("/internal/api/v1/ai-xdr/decision", json={
        "assessment_id": assessment_id, "status": "APPROVED", "approval_ref": assessment_id + ":NX-DB-000046",
    }, headers={"Authorization": f"Bearer {TOKEN}"})

    assert response.status_code == 409
    assert response.get_json()["error"] == "dry_run_only"
    assert calls == []


def test_xdr_approval_endpoint_rejects_non_r1_and_auto_enabled(app, monkeypatch):
    from app import ai_xdr, db

    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", TOKEN)
    app.config.update({"XDR_ENABLED": True, "XDR_AUTO_ENABLED": False, "XDR_RESPONSE_MODE": "dry-run",
                       "XDR_AUTO_MIN_SCORE": 80, "XDR_AUTO_MIN_CONFIDENCE": 0.8})
    assessment_id = "632a3638-6845-4904-abba-62a9f9e0e33a"
    row = {"assessment_id": assessment_id, "rule_ids": '["R3"]', "status": "PENDING",
           "approval_allowed": 1, "auto_allowed": 0, "policy_reason": "DAYTIME_APPROVAL",
           "verdict": "MALICIOUS", "threat_score": 90, "confidence": 0.95}
    monkeypatch.setattr(db, "query_one", lambda *_args, **_kwargs: row)
    calls = []
    monkeypatch.setattr(ai_xdr, "decide_assessment", lambda *args, **kwargs: calls.append(args))
    client = app.test_client()
    body = {"assessment_id": assessment_id, "status": "APPROVED",
            "approval_ref": assessment_id + ":NX-DB-000046"}
    headers = {"Authorization": f"Bearer {TOKEN}"}

    denied_rule = client.post("/internal/api/v1/ai-xdr/decision", json=body, headers=headers)
    assert denied_rule.status_code == 409
    assert denied_rule.get_json()["error"] == "approval_not_allowed"
    row["rule_ids"] = '["R1"]'
    app.config["XDR_AUTO_ENABLED"] = True
    denied_auto = client.post("/internal/api/v1/ai-xdr/decision", json=body, headers=headers)
    assert denied_auto.status_code == 409
    assert denied_auto.get_json()["error"] == "dry_run_only"
    assert calls == []
def test_blocked_ips_crud_lifecycle(lab, test_db_app, events):
    from app import security
    headers = {"Authorization": f"Bearer {TOKEN}"}
    target_ip = "198.51.100.42"

    with test_db_app.app_context():
        security.unblock_ip(target_ip)

    # 1. IP 차단 등록 (POST /blocked-ips)
    res_block = lab.post(
        "/internal/api/v1/blocked-ips",
        json={"ip": target_ip, "reason": "soar_auto_containment", "minutes": 45},
        headers=headers
    )
    assert res_block.status_code == 200
    data = res_block.get_json()
    assert data["ok"] is True
    assert data["ip"] == target_ip
    assert data["minutes"] == 45
    assert data["reason"] == "soar_auto_containment"

    # security 모듈 및 DB 확인
    with test_db_app.app_context():
        blocked, reason = security.is_ip_blocked(target_ip)
        assert blocked is True
        assert reason == "soar_auto_containment"

    # 2. 차단 목록 조회 (GET /blocked-ips)
    res_list = lab.get("/internal/api/v1/blocked-ips", headers=headers)
    assert res_list.status_code == 200
    list_data = res_list.get_json()
    assert list_data["ok"] is True
    assert any(item["ip_address"] == target_ip for item in list_data["items"])

    # 3. 차단 해제 (POST /blocked-ips/unblock)
    res_unblock = lab.post(
        "/internal/api/v1/blocked-ips/unblock",
        json={"ip": target_ip},
        headers=headers
    )
    assert res_unblock.status_code == 200
    assert res_unblock.get_json()["ok"] is True

    with test_db_app.app_context():
        blocked, _ = security.is_ip_blocked(target_ip)
        assert blocked is False

    # 4. 재차단 후 DELETE 메소드로 해제 테스트
    lab.post("/internal/api/v1/blocked-ips", json={"ip": target_ip}, headers=headers)
    with test_db_app.app_context():
        assert security.is_ip_blocked(target_ip)[0] is True

    res_del = lab.delete(f"/internal/api/v1/blocked-ips/{target_ip}", headers=headers)
    assert res_del.status_code == 200
    assert res_del.get_json()["ok"] is True

    with test_db_app.app_context():
        assert security.is_ip_blocked(target_ip)[0] is False


def test_blocked_ips_validation(lab):
    headers = {"Authorization": f"Bearer {TOKEN}"}

    # 잘못된 IP 형식
    res_invalid = lab.post("/internal/api/v1/blocked-ips", json={"ip": "invalid-ip-format"}, headers=headers)
    assert res_invalid.status_code == 400
    assert res_invalid.get_json()["error"] == "invalid_ip"

    # 루프백 주소 차단 방지 (127.0.0.1, ::1)
    res_loopback = lab.post("/internal/api/v1/blocked-ips", json={"ip": "127.0.0.1"}, headers=headers)
    assert res_loopback.status_code == 400
    assert "루프백" in res_loopback.get_json()["message"]

    res_loopback6 = lab.post("/internal/api/v1/blocked-ips", json={"ip": "::1"}, headers=headers)
    assert res_loopback6.status_code == 400

    # 빈 값
    res_empty = lab.post("/internal/api/v1/blocked-ips", json={}, headers=headers)
    assert res_empty.status_code == 400


@pytest.mark.parametrize("ip", [
    "192.168.3.10", "192.168.3.14", "192.168.3.15",
    "::ffff:192.168.3.10",
])
def test_blocked_ips_api_protects_management_and_server_ips(lab, ip):
    response = lab.post(
        "/internal/api/v1/blocked-ips", json={"ip": ip},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )

    assert response.status_code == 403
    assert response.get_json()["error"] == "ip_whitelisted"


def test_blocked_ips_api_allows_192_168_3_11_as_explicit_test_target(lab, monkeypatch):
    from app import security

    calls = []
    monkeypatch.setattr(security, "block_ip", lambda *args, **kwargs: calls.append((args, kwargs)) or True)
    response = lab.post(
        "/internal/api/v1/blocked-ips",
        json={"ip": "192.168.3.11", "reason": "synthetic_test", "minutes": 15},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )

    assert response.status_code == 200
    assert calls[0][0] == ("192.168.3.11",)
    assert calls[0][1]["minutes"] == 15


def test_n8n_api_token_support(test_db_app, monkeypatch):
    n8n_token = "n8n_custom_secret_key_98765"
    monkeypatch.setenv("N8N_API_TOKEN", n8n_token)
    c = test_db_app.test_client()

    # Bearer 헤더로 인증 확인
    res1 = c.get("/internal/api/v1/blocked-ips", headers={"Authorization": f"Bearer {n8n_token}"})
    assert res1.status_code == 200

    # X-API-Token 헤더로 인증 확인
    res2 = c.get("/internal/api/v1/blocked-ips", headers={"X-API-Token": n8n_token})
    assert res2.status_code == 200


def test_blocked_ips_feed_excludes_protected_ips(lab, monkeypatch):
    from app import db

    rows = [
        {"id": 1, "ip_address": "192.168.3.14", "reason": "legacy", "blocked_until": "2099-01-01",
         "created_at": "2026-10-28", "created_by": "legacy"},
        {"id": 2, "ip_address": "198.51.100.99", "reason": "test", "blocked_until": "2099-01-01",
         "created_at": "2026-10-28", "created_by": "test"},
        {"id": 3, "ip_address": "192.168.3.11", "reason": "synthetic_test", "blocked_until": "2099-01-01",
         "created_at": "2026-10-28", "created_by": "test"},
    ]
    monkeypatch.setattr(db, "query_all", lambda *_args, **_kwargs: rows)
    headers = {"Authorization": f"Bearer {TOKEN}"}

    json_response = lab.get("/internal/api/v1/blocked-ips", headers=headers)
    text_response = lab.get("/internal/api/v1/blocked-ips?format=txt", headers=headers)

    assert json_response.status_code == 200
    assert [item["ip_address"] for item in json_response.get_json()["items"]] == ["198.51.100.99", "192.168.3.11"]
    assert text_response.status_code == 200
    assert text_response.get_data(as_text=True) == "198.51.100.99\n192.168.3.11\n"


def _ip_block_client(monkeypatch, security):
    import time

    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", TOKEN)
    now = [time.monotonic()]
    blocked = {}
    calls = []

    def block_ip(ip, reason, minutes, created_by):
        calls.append((ip, reason, minutes, created_by))
        blocked[ip] = (now[0] + minutes * 60, reason)
        return True

    def is_ip_blocked(ip):
        row = blocked.get(ip)
        if row and row[0] > now[0]:
            return True, row[1]
        return False, ""

    monkeypatch.setattr(security, "block_ip", block_ip)
    monkeypatch.setattr(security, "is_ip_blocked", is_ip_blocked)
    return now, calls, blocked


def _block_request(client, ip="198.51.100.25", rule_id="R5", reason="account_spray", duration=15, token=TOKEN):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/internal/api/v1/ip-block", json={
        "ip_address": ip, "rule_id": rule_id, "reason": reason, "duration_minutes": duration,
    }, headers=headers)


def test_automated_ip_block_api_reuses_block_ip_and_causes_403_then_expires(app, monkeypatch):
    from app import security

    now, calls, _ = _ip_block_client(monkeypatch, security)
    client = app.test_client()
    response = _block_request(client)

    assert response.status_code == 200
    assert response.get_json() == {"ok": True, "blocked": True, "ip_address": "198.51.100.25",
                                   "rule_id": "R5", "duration_minutes": 15}
    assert calls == [("198.51.100.25", "n8n_R5_account_spray", 15, "n8n")]
    assert client.get("/login", environ_base={"REMOTE_ADDR": "198.51.100.25"}).status_code == 403

    now[0] += 15 * 60
    assert client.get("/login", environ_base={"REMOTE_ADDR": "198.51.100.25"}).status_code == 200


@pytest.mark.parametrize("ip", ["127.0.0.1", "192.168.3.10", "192.168.3.14", "192.168.3.15"])
def test_automated_ip_block_api_never_blocks_whitelisted_ips(app, monkeypatch, ip):
    from app import security

    _, calls, _ = _ip_block_client(monkeypatch, security)
    response = _block_request(app.test_client(), ip=ip)

    assert response.status_code == 403
    assert response.get_json() == {"ok": False, "error": "ip_whitelisted"}
    assert calls == []


@pytest.mark.parametrize(("rule_id", "reason"), [
    ("R5", "account_spray"),
    ("R6", "post_lock_retry"),
    ("R8", "web_path_scan"),
])
def test_automated_ip_block_api_accepts_only_supported_rule_reasons(app, monkeypatch, rule_id, reason):
    from app import security

    _, calls, _ = _ip_block_client(monkeypatch, security)
    response = _block_request(app.test_client(), rule_id=rule_id, reason=reason)

    assert response.status_code == 200
    assert calls == [("198.51.100.25", f"n8n_{rule_id}_{reason}", 15, "n8n")]


def test_automated_ip_block_api_requires_existing_bearer_token(app, monkeypatch):
    from app import security

    _, calls, _ = _ip_block_client(monkeypatch, security)
    response = _block_request(app.test_client(), token="wrong")

    assert response.status_code == 401
    assert response.get_json() == {"ok": False, "error": "unauthorized"}
    assert calls == []


def test_automated_ip_block_api_rejects_mapped_whitelisted_ip(app, monkeypatch):
    from app import security

    _, calls, _ = _ip_block_client(monkeypatch, security)
    response = _block_request(app.test_client(), ip="::ffff:192.168.3.10")

    assert response.status_code == 403
    assert response.get_json() == {"ok": False, "error": "ip_whitelisted"}
    assert calls == []


@pytest.mark.parametrize("kwargs", [
    {"ip": "not-an-ip"},
    {"rule_id": "R2", "reason": "direct_prompt_injection"},
    {"rule_id": "R6", "reason": "account_spray"},
    {"duration": 16},
    {"duration": 0},
])
def test_automated_ip_block_api_rejects_invalid_or_unsupported_requests(app, monkeypatch, kwargs):
    from app import security

    _, calls, _ = _ip_block_client(monkeypatch, security)
    response = _block_request(app.test_client(), **kwargs)

    assert response.status_code == 400
    assert response.get_json()["ok"] is False
    assert calls == []


def test_blocked_ips_supports_format_txt_and_token_query_param(lab, monkeypatch):
    from app import db
    monkeypatch.setattr(db, 'query_all', lambda q, a=(): [{'id': 1, 'ip_address': '198.51.100.99', 'reason': 'test', 'blocked_until': '2099-01-01', 'created_at': '2026-01-01', 'created_by': 'admin'}])
    client = lab
    res = client.get('/internal/api/v1/blocked-ips?format=txt&token=' + TOKEN)
    assert res.status_code == 200
    assert res.headers['Content-Type'].startswith('text/plain')
    assert '198.51.100.99' in res.get_data(as_text=True)
