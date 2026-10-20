"""실습용 내부 API(/internal/api/v1/flag): 맞는 토큰이면 FLAG, 아니면 401. 모든 호출을 via=direct·출발지·토큰 지문으로 남기고 토큰 원문은 남기지 않는다. DB 불필요."""
import json

import pytest

from app import internal_api

TOKEN = "nxapi_zz-test-token-0123456789abcdef"
FLAG = "FLAG{zz-test-flag}"


@pytest.fixture()
def lab(app, monkeypatch):
    monkeypatch.setenv("LAB_INTERNAL_API_TOKEN", TOKEN)
    monkeypatch.setenv("LAB_INTERNAL_API_FLAG", FLAG)
    return app.test_client()


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
