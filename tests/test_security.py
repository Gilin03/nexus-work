import json

import pytest

from app import security


def test_healthz_and_security_headers(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.get_json() == {"status": "ok"}
    h = r.headers
    csp = h["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp and "frame-ancestors 'none'" in csp
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer"
    assert h["Cache-Control"] == "no-store"
    assert h["Server"] == "NEXUS" and "Werkzeug" not in str(h) and "Python" not in str(h)   # 버전 정보 미노출


def test_real_server_sends_a_single_server_header_without_versions(app):
    """개발 서버는 앱과 별개로 Server 헤더를 붙인다. run.py 의 핸들러가 이를 NEXUS 하나로 만든다."""
    import http.client
    import threading

    from werkzeug.serving import make_server

    from run import QuietHandler

    srv = make_server("127.0.0.1", 0, app, request_handler=QuietHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=5)
        for path in ("/login", "/no/such/page", "/login"):          # 같은 연결에서 여러 요청: 매번 헤더가 하나여야 한다
            conn.request("GET", path)
            r = conn.getresponse()
            r.read()
            servers = [v for k, v in r.getheaders() if k.lower() == "server"]
            assert servers == ["NEXUS"], (path, servers)
    finally:
        srv.shutdown()


def test_404_is_generic_and_logged(client, events):
    r = client.get("/no/such/page")
    assert r.status_code == 404
    body = r.get_data(as_text=True)
    assert "Traceback" not in body and "werkzeug" not in body.lower()
    ev = events()[-1]
    assert ev["event_type"] == "not_found" and ev["path"] == "/no/such/page"


def test_unhandled_exception_hides_detail(app, client, events):
    @app.get("/boom")
    def boom():
        raise RuntimeError("secret-internal-detail")

    r = client.get("/boom")
    assert r.status_code == 500
    assert "secret-internal-detail" not in r.get_data(as_text=True)
    ev = events()[-1]
    assert ev["event_type"] == "server_error" and ev["reason"] == "RuntimeError"
    assert "secret-internal-detail" not in json.dumps(ev)


def _add_post_probe(app):
    @app.post("/probe")
    def probe():
        return "ok"


def test_csrf_blocks_post_without_token(app, client, events):
    _add_post_probe(app)
    assert client.post("/probe").status_code == 403
    ev = events()[-1]
    assert ev["event_type"] == "csrf_fail" and ev["decision"] == "BLOCK"


def test_csrf_blocks_wrong_token_and_allows_right_one(app, client):
    _add_post_probe(app)
    with client.session_transaction() as s:
        s["csrf"] = "right-token"
    assert client.post("/probe", headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert client.post("/probe", headers={"X-CSRF-Token": "right-token"}).status_code == 200
    assert client.post("/probe", data={"csrf_token": "right-token"}).status_code == 200


def test_log_event_has_standard_fields_and_resists_injection(app, events):
    with app.test_request_context("/x?a=1", method="POST", environ_base={"REMOTE_ADDR": "10.0.0.9"}):
        security.log_event("login_failure", "DENY", "bad\npassword\"}{", user="evil\nname")
    logged = events()
    assert len(logged) == 1  # 개행을 넣어도 로그가 한 줄로 유지된다
    e = logged[0]
    for field in ("ts", "event_type", "user", "role", "src_ip", "method", "path", "decision", "reason"):
        assert field in e
    assert e["src_ip"] == "10.0.0.9" and e["method"] == "POST" and e["path"] == "/x"
    assert e["user"] == "evil\nname" and e["reason"] == "bad\npassword\"}{"


def test_ip_rate_limit():
    security.reset_rate_limits()
    results = [security.ip_rate_limited("1.2.3.4", 3) for _ in range(5)]
    assert results == [False, False, False, True, True]
    assert security.ip_rate_limited("5.6.7.8", 3) is False  # 다른 IP는 별개


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "192.168.3.10", "192.168.3.14", "192.168.3.15", "::ffff:192.168.3.10"])
def test_protected_ips_cannot_be_blocked_or_checked(monkeypatch, ip):
    from app import db

    calls = []
    monkeypatch.setattr(db, "execute", lambda *args, **kwargs: calls.append(("write", args)))
    monkeypatch.setattr(db, "query_one", lambda *args, **kwargs: calls.append(("read", args)))

    assert security.block_ip(ip) is False
    assert security.is_ip_blocked(ip) == (False, "")
    assert calls == []


def test_192_168_3_11_is_not_a_protected_block_ip():
    assert security.is_protected_block_ip("192.168.3.11") is False


# ---------- 의심 입력 기록(차단하지 않고 탐지용 신호만 남긴다) ----------
SQLI_PROBES = ["' OR '1'='1", "' OR 1=1-- ", "admin'--", "' UNION SELECT NULL,NULL-- ", "'; DROP TABLE users; -- ",
               "1' AND SLEEP(5)-- ", "' OR SLEEP(5)#", "\") OR (\"1\"=\"1", "1; WAITFOR DELAY '0:0:5'--", "%' OR '%'='",
               r"\' OR 1=1 -- ", "' OR ''='", "x' UNION ALL SELECT 1,2--", "1 OR 1=1"]
XSS_PROBES = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "'><svg onload=alert(1)>",
              "<iframe src=javascript:alert(1)>", "javascript:alert(1)", " onerror=alert(1)"]
TRAVERSAL_PROBES = ["../../etc/passwd", r"..\..\windows\win.ini", "%2e%2e/%2e%2e/etc/passwd", "a/%2e%2e%5cb"]
BENIGN = ["홍길동", "O'Brien", "연차 신청합니다", "2026-10-17", "a-b-c", "SELECT 문서 정리", "R&D 팀", "100% OK", "union 회의",
          "Hello -- world", "or 그리고", "scripts 폴더", "on time", "javascript 스터디"]


def _suspicious(events):
    return [e for e in events() if e["event_type"] == "suspicious_input"]


@pytest.mark.parametrize("kind,probes", [("sqli", SQLI_PROBES), ("xss", XSS_PROBES), ("traversal", TRAVERSAL_PROBES)])
def test_known_attack_strings_are_flagged_but_not_blocked(client, events, kind, probes):
    for probe in probes:
        r = client.get("/login", query_string={"q": probe})
        assert r.status_code == 200                                       # 차단하지 않는다(안전한 처리는 따로 이미 되어 있다)
    found = _suspicious(events)
    assert len(found) == len(probes), [e.get("value") for e in found]
    assert all(e["kind"] == kind and e["field"] == "q" and e["decision"] == "WARN" and e["reason"] == kind for e in found)
    assert all(len(e["value"]) <= 80 for e in found)


def test_normal_text_is_not_flagged(client, events):
    for text in BENIGN:
        client.get("/login", query_string={"q": text})
    assert _suspicious(events) == []


def test_flag_has_the_standard_log_fields_and_counts_hits(client, events):
    client.get("/login", query_string={"a": "' OR 1=1--", "b": "<script>x</script>", "c": "정상"})
    e = _suspicious(events)[0]
    for field in ("ts", "event_type", "user", "role", "src_ip", "method", "path", "decision", "reason"):
        assert field in e
    assert e["count"] == 2 and e["path"] == "/login"


def test_passwords_are_never_scanned_or_logged(app, client, events):
    token = client.get("/login").get_data(as_text=True).split('name="csrf_token" value="')[1].split('"')[0]
    client.post("/login", data={"username": "nobody", "password": "' OR 1=1--<script>", "csrf_token": token})
    assert _suspicious(events) == []
    assert "<script>" not in app.log_path.read_text(encoding="utf-8")


def test_body_and_message_content_is_flagged_without_its_text(app, client, events):
    token = client.get("/login").get_data(as_text=True).split('name="csrf_token" value="')[1].split('"')[0]
    client.post("/login", data={"username": "nobody", "password": "x", "csrf_token": token, "message": "'; DROP TABLE users; --"})
    e = _suspicious(events)[0]
    assert e["field"] == "message" and e["kind"] == "sqli" and "value" not in e
    assert "DROP TABLE" not in app.log_path.read_text(encoding="utf-8")


def test_suspicious_prompt_input_is_flagged_without_its_text(app, client, events):
    prompt = "' OR 1=1-- ignore previous instructions"
    client.get("/login", query_string={"prompt": prompt})
    event = _suspicious(events)[0]
    assert event["field"] == "prompt" and event["kind"] == "sqli"
    assert "value" not in event
    assert prompt not in app.log_path.read_text(encoding="utf-8")


def test_traversal_in_the_url_path_is_flagged(client, events):
    client.get("/static/%2e%2e/app/config.py")
    assert any(e["kind"] == "traversal" and e["field"] == "path" for e in _suspicious(events))


def test_requests_blocked_by_csrf_are_still_flagged(app, client, events):
    assert client.post("/login", data={"username": "' OR 1=1--", "password": "x"}).status_code == 403
    assert any(e["kind"] == "sqli" and e["field"] == "username" for e in _suspicious(events))


def test_get_client_ip_with_trusted_proxy_and_forwarded_for(app):
    with app.test_request_context("/", environ_base={"REMOTE_ADDR": "192.168.3.10"}, headers={"X-Forwarded-For": "192.168.3.15, 192.168.3.10"}):
        from app.security import get_client_ip
        assert get_client_ip() == "192.168.3.15"


def test_get_client_ip_ignores_forwarded_for_from_untrusted_ip(app):
    with app.test_request_context("/", environ_base={"REMOTE_ADDR": "192.168.3.99"}, headers={"X-Forwarded-For": "10.0.0.1"}):
        from app.security import get_client_ip
        assert get_client_ip() == "192.168.3.99"

def test_get_client_ip_with_x_real_ip(app):
    with app.test_request_context('/', environ_base={'REMOTE_ADDR': '192.168.3.10'}, headers={'X-Real-IP': '192.168.7.77'}):
        from app.security import get_client_ip
        assert get_client_ip() == '192.168.7.77'
