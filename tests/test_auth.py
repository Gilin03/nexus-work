"""인증 통합 테스트. Docker MySQL(nexus_test)이 필요하며, 접속 불가면 skip.
시험 계정(zz_ 접두사)은 conftest 의 root 픽스처가 만들고 끝나면 지운다."""
import os
import re

import pytest

from app import auth, create_app
from support import PW, PW_HASH, csrf_of, login, post, sql, token


# ---------- 로그인 화면·쿠키 ----------
def test_login_page_has_form_csrf_and_no_inline_script(aapp):
    r = aapp.test_client().get("/login")
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and 'name="csrf_token"' in html and 'type="password"' in html
    assert "<script" not in html and " onclick=" not in html and " style=" not in html


def test_session_cookie_flags(aapp):
    r = aapp.test_client().get("/login")
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and cookie.startswith("nexus_session=")


def test_session_cookie_secure_flag_when_enabled(root):
    secure_app = create_app({"TESTING": True, "SESSION_COOKIE_SECURE": True, "DB_NAME": "nexus_test",
                             "LOG_DIR": __import__("pathlib").Path(os.environ.get("TEMP", ".")) / "nexus_t_logs"})
    assert "Secure" in secure_app.test_client().get("/login").headers["Set-Cookie"]


# ---------- 로그인 성공/실패 ----------
def test_login_success_redirects_and_rotates_session(aapp, events):
    c = aapp.test_client()
    pre = token(c)
    with c.session_transaction() as s:
        s["planted"] = "attacker-value"
    r = c.post("/login", data={"username": "zz_emp", "password": PW, "csrf_token": pre})
    assert r.status_code == 303 and r.headers["Location"].endswith("/")
    with c.session_transaction() as s:
        assert "planted" not in s and s["csrf"] != pre and s["uid"]  # 세션 고정 방지: 내용·CSRF 토큰 재발급
    assert "안녕하세요" in c.get("/").get_data(as_text=True)
    ev = [e for e in events() if e["event_type"] == "login_success"]
    assert ev and ev[-1]["user"] == "zz_emp" and ev[-1]["decision"] == "ALLOW"


def test_username_is_case_insensitive_via_normalization(aapp):
    assert login(aapp.test_client(), "ZZ_EMP").status_code == 303


def test_failure_messages_are_identical_for_every_cause(aapp, root):
    sql(root, "UPDATE users SET locked_until = DATE_ADD(NOW(), INTERVAL 5 MINUTE) WHERE username='zz_mgr'")
    bodies = set()
    for user, pw in (("zz_emp", "wrong-Password-1!"), ("no_such_user", PW), ("zz_mgr", PW), ("Bad Name!", "x"), ("", "")):
        r = login(aapp.test_client(), user, pw)
        assert r.status_code == 401
        bodies.add(re.sub(r'value="[^"]*"', "", r.get_data(as_text=True)))
    assert len(bodies) == 1  # 틀린 비밀번호·없는 계정·잠긴 계정·형식 오류가 구분되지 않는다


def test_unknown_user_still_runs_a_password_hash_check(aapp, monkeypatch):
    calls = []
    real = auth.verify_password
    monkeypatch.setattr(auth, "verify_password", lambda h, p: calls.append(h) or real(h, p))
    login(aapp.test_client(), "no_such_user", PW)
    assert calls == [auth._DUMMY_HASH]  # 응답 시간 균등화용 더미 검증


def test_sql_injection_in_username_is_just_a_failed_login(aapp):
    r = login(aapp.test_client(), "' OR '1'='1' -- ", "x")
    assert r.status_code == 401


def test_logs_never_contain_passwords(aapp, app):
    login(aapp.test_client(), "zz_emp", "Super-Secret-Wrong-Pw-9!")
    login(aapp.test_client(), "zz_emp", PW)
    assert "Super-Secret-Wrong-Pw-9!" not in app.log_path.read_text(encoding="utf-8")
    assert PW not in app.log_path.read_text(encoding="utf-8")


# ---------- 잠금 ----------
def test_five_failures_lock_the_account_even_for_the_right_password(aapp, root, events):
    c = aapp.test_client()
    for _ in range(5):
        assert login(c, "zz_emp", "wrong-Password-1!").status_code == 401
    assert login(c, "zz_emp", PW).status_code == 401  # 잠긴 동안은 맞는 비밀번호도 거부
    types = [e["event_type"] for e in events() if e["user"] == "zz_emp"]
    assert types.count("login_failure") == 5 and types.count("account_locked") == 1 and types.count("login_locked") == 1
    locked, count = sql(root, "SELECT locked_until IS NOT NULL AND locked_until > NOW(), failed_count FROM users WHERE username='zz_emp'")[0]
    assert locked == 1 and count == 0


def test_lock_expiry_allows_login_and_resets_counters(aapp, root):
    c = aapp.test_client()
    for _ in range(5):
        login(c, "zz_emp", "wrong-Password-1!")
    sql(root, "UPDATE users SET locked_until = DATE_SUB(NOW(), INTERVAL 1 MINUTE) WHERE username='zz_emp'")
    assert login(c, "zz_emp", PW).status_code == 303
    assert sql(root, "SELECT failed_count, locked_until FROM users WHERE username='zz_emp'")[0] == (0, None)


def test_success_resets_failure_count_so_failures_must_be_consecutive(aapp, root):
    c = aapp.test_client()
    for _ in range(3):
        login(c, "zz_emp", "wrong-Password-1!")
    assert sql(root, "SELECT failed_count FROM users WHERE username='zz_emp'")[0][0] == 3
    assert login(aapp.test_client(), "zz_emp", PW).status_code == 303
    for _ in range(4):
        login(c, "zz_emp", "wrong-Password-1!")
    assert sql(root, "SELECT locked_until IS NOT NULL FROM users WHERE username='zz_emp'")[0][0] == 0


def test_lock_applies_to_other_accounts_independently(aapp):
    c = aapp.test_client()
    for _ in range(5):
        login(c, "zz_emp", "wrong-Password-1!")
    assert login(aapp.test_client(), "zz_mgr", PW).status_code == 303


def test_ip_rate_limit_blocks_login_attempts(aapp, events):
    aapp.config["LOGIN_IP_LIMIT"] = 3
    c = aapp.test_client()
    t = token(c)
    codes = [c.post("/login", data={"username": "zz_emp", "password": "x", "csrf_token": t}).status_code for _ in range(5)]
    assert codes == [401, 401, 401, 429, 429]
    assert any(e["event_type"] == "rate_limited" for e in events())


# ---------- 세션 수명·권한 즉시 반영 ----------
def test_anonymous_access_redirects_to_login_and_logs(aapp, events):
    r = aapp.test_client().get("/")
    assert r.status_code == 303 and "/login" in r.headers["Location"]
    assert events()[-1]["event_type"] == "authz_deny" and events()[-1]["reason"] == "not_logged_in"


def test_locking_a_logged_in_user_ends_the_session_immediately(aapp, root):
    c = aapp.test_client()
    login(c)
    assert c.get("/").status_code == 200
    sql(root, "UPDATE users SET locked_until = DATE_ADD(NOW(), INTERVAL 5 MINUTE) WHERE username='zz_emp'")
    assert c.get("/").status_code == 303  # n8n 등이 계정을 잠그면 다음 요청부터 로그아웃


def test_role_change_is_reflected_without_relogin(aapp, root):
    c = aapp.test_client()
    login(c)
    assert "employee" in c.get("/").get_data(as_text=True)
    sql(root, "UPDATE users SET role='manager' WHERE username='zz_emp'")
    assert "manager" in c.get("/").get_data(as_text=True)


def test_deleted_user_session_is_dropped(aapp, root):
    c = aapp.test_client()
    login(c)
    sql(root, "DELETE FROM users WHERE username='zz_emp'")
    assert c.get("/").status_code == 303


def test_absolute_session_lifetime(aapp):
    c = aapp.test_client()
    login(c)
    with c.session_transaction() as s:
        s["iat"] = 1  # 아주 오래전에 로그인한 세션
    assert c.get("/").status_code == 303


def test_forged_session_for_unknown_uid_is_rejected(aapp):
    c = aapp.test_client()
    with c.session_transaction() as s:
        s["uid"], s["iat"] = 99999999, 2**31
    assert c.get("/").status_code == 303


# ---------- 로그아웃 ----------
def test_logout_needs_csrf_and_clears_session(aapp):
    c = aapp.test_client()
    login(c)
    assert c.post("/logout").status_code == 403
    assert c.get("/").status_code == 200  # CSRF 실패로 로그아웃되지 않았다
    r = post(c, "/logout")
    assert r.status_code == 303 and "/login" in r.headers["Location"]
    assert c.get("/").status_code == 303


def test_csrf_failure_of_a_logged_in_user_is_logged_with_the_username(aapp, events):
    c = aapp.test_client()
    login(c)
    assert c.post("/logout", data={"csrf_token": "forged"}).status_code == 403
    ev = [e for e in events() if e["event_type"] == "csrf_fail"][-1]
    assert ev["user"] == "zz_emp" and ev["role"] == "employee"


def test_logout_via_get_is_not_allowed(aapp):
    c = aapp.test_client()
    login(c)
    assert c.get("/logout").status_code == 405


# ---------- 비밀번호 변경·정책 ----------
NEW = "Brand-New-Pass-77!"


def test_password_change_success(aapp, root):
    c = aapp.test_client()
    login(c)
    r = post(c, "/account/password", current_password=PW, new_password=NEW, confirm_password=NEW)
    assert r.status_code == 303
    stored = sql(root, "SELECT password_hash FROM users WHERE username='zz_emp'")[0][0]
    assert stored.startswith("$argon2id$") and NEW not in stored
    assert login(aapp.test_client(), "zz_emp", PW).status_code == 401  # 옛 비밀번호 불가
    assert login(aapp.test_client(), "zz_emp", NEW).status_code == 303


@pytest.mark.parametrize("new,confirm,fragment", [
    ("Short-1a", "Short-1a", "12자 이상"),
    ("alllowercasepassword", "alllowercasepassword", "3가지"),
    ("Zz_emp-Contains-Name1", "Zz_emp-Contains-Name1", "아이디를 포함"),
    (NEW, "Different-Confirm-77!", "확인이 일치"),
    (PW, PW, "다른 비밀번호"),
])
def test_password_policy_is_enforced_on_change(aapp, root, new, confirm, fragment):
    c = aapp.test_client()
    login(c)
    r = post(c, "/account/password", current_password=PW, new_password=new, confirm_password=confirm)
    assert r.status_code == 400 and fragment in r.get_data(as_text=True)
    assert sql(root, "SELECT password_hash FROM users WHERE username='zz_emp'")[0][0] == PW_HASH  # 변경되지 않음


def test_wrong_current_password_counts_toward_lockout(aapp, root):
    c = aapp.test_client()
    login(c)
    for i in range(4):
        r = post(c, "/account/password", current_password="wrong-Current-1!", new_password=NEW, confirm_password=NEW)
        assert r.status_code == 401
    r = post(c, "/account/password", current_password="wrong-Current-1!", new_password=NEW, confirm_password=NEW)
    assert r.status_code == 303  # 5번째 실패로 잠기며 세션 종료
    assert login(aapp.test_client(), "zz_emp", PW).status_code == 401


def test_password_change_requires_login_and_csrf(aapp):
    c = aapp.test_client()
    assert c.get("/account/password").status_code == 303
    login(c)
    assert c.post("/account/password", data={"current_password": PW, "new_password": NEW, "confirm_password": NEW}).status_code == 403


# ---------- 역할 검사 데코레이터 ----------
def test_role_required_denies_and_allows(aapp):
    @aapp.get("/_mgr-only")
    @auth.role_required("manager", "admin")
    def mgr_only():
        return "secret"

    emp, mgr = aapp.test_client(), aapp.test_client()
    login(emp, "zz_emp")
    login(mgr, "zz_mgr")
    assert emp.get("/_mgr-only").status_code == 403
    assert mgr.get("/_mgr-only").get_data(as_text=True) == "secret"
    assert aapp.test_client().get("/_mgr-only").status_code == 303


def test_verify_password_handles_garbage_hash():
    assert auth.verify_password("not-a-hash", "x") is False
    assert auth.verify_password(PW_HASH, PW) is True
    assert auth.verify_password(PW_HASH, "nope") is False


# ---------- 세션 버전: 로그아웃·비밀번호 변경으로 이전 쿠키 무효화 ----------
def cookie_of(client):
    return client.get_cookie("nexus_session").value


def replay(app, cookie):
    c = app.test_client()
    c.set_cookie("nexus_session", cookie)
    return c


def test_login_stores_the_users_session_version(aapp, root):
    sql(root, "UPDATE users SET session_version=7 WHERE username='zz_emp'")
    c = aapp.test_client()
    login(c)
    with c.session_transaction() as s:
        assert s["sv"] == 7
    assert c.get("/").status_code == 200


def test_old_cookie_is_rejected_after_logout(aapp, root):
    c = aapp.test_client()
    login(c)
    stolen = cookie_of(c)
    assert replay(aapp, stolen).get("/").status_code == 200           # 로그아웃 전에는 같은 쿠키가 통한다
    assert post(c, "/logout").status_code == 303
    r = replay(aapp, stolen).get("/")                                  # 훔친 쿠키를 다시 보내도 통하지 않는다
    assert r.status_code == 303 and "/login" in r.headers["Location"]
    assert sql(root, "SELECT session_version FROM users WHERE username='zz_emp'")[0][0] == 1


def test_logout_ends_the_users_other_sessions_too_but_not_other_users(aapp):
    a, b, other = aapp.test_client(), aapp.test_client(), aapp.test_client()
    login(a)
    login(b)
    login(other, "zz_mgr")
    assert post(a, "/logout").status_code == 303
    assert b.get("/").status_code == 303                                # 같은 사용자의 다른 기기도 끊긴다
    assert other.get("/").status_code == 200                            # 다른 사용자는 영향 없음
    assert login(a).status_code == 303 and a.get("/").status_code == 200   # 다시 로그인하면 새 버전으로 정상


def test_password_change_invalidates_other_devices_but_keeps_this_one(aapp, root):
    a, b = aapp.test_client(), aapp.test_client()
    login(a)
    login(b)
    stolen = cookie_of(b)
    assert post(a, "/account/password", current_password=PW, new_password="Another-New-Pass-88!",
                confirm_password="Another-New-Pass-88!").status_code == 303
    assert a.get("/").status_code == 200                                # 비밀번호를 바꾼 기기는 새 세션으로 계속 사용
    assert b.get("/").status_code == 303                                # 다른 기기는 끊긴다
    assert replay(aapp, stolen).get("/").status_code == 303             # 비밀번호 변경 전에 탈취된 쿠키는 쓸모없다


def test_failed_password_change_does_not_end_sessions(aapp):
    a, b = aapp.test_client(), aapp.test_client()
    login(a)
    login(b)
    assert post(a, "/account/password", current_password="wrong-Current-1!", new_password="Another-New-Pass-88!",
                confirm_password="Another-New-Pass-88!").status_code == 401
    assert a.get("/").status_code == 200 and b.get("/").status_code == 200


@pytest.mark.parametrize("sv", [None, -1, 999, "7", "abc"])
def test_cookie_with_wrong_or_missing_session_version_is_rejected(aapp, root, sv):
    c = aapp.test_client()
    login(c)
    with c.session_transaction() as s:
        if sv is None:
            s.pop("sv")
        else:
            s["sv"] = sv
    assert c.get("/").status_code == 303


def test_idle_cookie_issued_before_this_change_is_rejected(aapp, root):
    """세션 버전이 없던 시절(이 변경 이전)의 쿠키는 다시 로그인하게 한다."""
    c = aapp.test_client()
    login(c)
    with c.session_transaction() as s:
        del s["sv"]
    assert c.get("/").status_code == 303
