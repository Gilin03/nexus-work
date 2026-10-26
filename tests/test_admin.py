"""관리자 화면 통합 테스트(사용자 목록·역할 변경·잠금 해제). Docker MySQL(nexus_test) 필요, 접속 불가면 skip.
계정: zz_emp·zz_emp2·zz_emp3(직원) / zz_mgr·zz_mgrb(팀장) / zz_adm(관리자)"""
import re

import pytest

from support import PW_HASH, as_user, login, post, sql, uid


def role_of(root, name):
    return sql(root, "SELECT role FROM users WHERE username=%s", (name,))[0][0]


def snapshot(root):
    return sql(root, "SELECT username, role, dept, display_name FROM users WHERE username LIKE 'zz\\_%' ORDER BY username")


def set_role(client, root, target, new_role, current_role):
    return post(client, f"/admin/users/{uid(root, target)}/role", role=new_role, current_role=current_role)


def unlock(client, root, target):
    return post(client, f"/admin/users/{uid(root, target)}/unlock")


def lock(root, name, failures=5):
    sql(root, "UPDATE users SET locked_until=DATE_ADD(NOW(), INTERVAL 10 MINUTE), failed_count=%s WHERE username=%s",
        (failures, name))


def pending_approval(root, requester, approver):
    with root.cursor() as cur:
        cur.execute("INSERT INTO approvals(title,body,requester_id) VALUES('zz_결재','본문',%s)", (uid(root, requester),))
        aid = cur.lastrowid
        cur.execute("INSERT INTO approval_steps(approval_id,step_no,approver_id,status) VALUES(%s,1,%s,'pending')",
                    (aid, uid(root, approver)))
        return aid


# ---------- 모든 관리자 경로는 관리자만 ----------
def test_every_admin_route_requires_admin(aapp, root):
    rules = [r for r in aapp.url_map.iter_rules() if r.rule.startswith("/admin")]
    assert {r.rule for r in rules} == {
        "/admin/users", "/admin/users/new", "/admin/users/<int:user_id>/role", "/admin/users/<int:user_id>/unlock",
        "/admin/users/<int:user_id>/lock", "/admin/users/<int:user_id>/reset-password", "/admin/overview", "/admin/audit",
        "/admin/audit/export.csv", "/admin/users/<int:user_id>/title", "/admin/users/<int:user_id>/dept", "/admin/users/<int:user_id>/delete", "/admin/users/<int:user_id>/restore", "/admin/permissions",
        "/admin/blocked-ips", "/admin/blocked-ips/<path:ip>/unblock", "/admin/audit/stream"}
    before = snapshot(root)
    anon, emp, mgr = aapp.test_client(), as_user(aapp, "zz_emp"), as_user(aapp, "zz_mgr")
    for rule in rules:
        assert rule.endpoint.startswith("admin.")
        path = re.sub(r"<[^>]+>", str(uid(root, "zz_emp2")), rule.rule)
        for method in rule.methods - {"HEAD", "OPTIONS"}:
            if method == "GET":
                assert anon.get(path).status_code == 303, path               # 비로그인: 로그인 화면으로
                assert emp.get(path).status_code == 403 and mgr.get(path).status_code == 403, path
            else:
                assert anon.post(path).status_code == 403, path               # CSRF 단계에서 차단
                for c in (emp, mgr):                                          # 토큰이 맞아도 관리자가 아니면 403
                    assert post(c, path, role="admin", current_role="employee").status_code == 403, path
    assert snapshot(root) == before                                           # 어떤 요청도 사용자 정보를 바꾸지 못했다


def test_admin_index_paths_do_not_exist_for_anyone(aapp):
    adm, anon = as_user(aapp, "zz_adm"), aapp.test_client()
    for path in ("/admin", "/admin/"):                       # 308 이동으로 존재가 드러나지 않는다
        assert anon.get(path).status_code == 404 and adm.get(path).status_code == 404


def test_non_admin_attempts_are_logged(aapp, root, events):
    as_user(aapp, "zz_mgr").get("/admin/users")
    ev = [e for e in events() if e["event_type"] == "authz_deny"][-1]
    assert ev["reason"] == "insufficient_role" and ev["user"] == "zz_mgr" and ev["required"] == "admin"


def test_admin_link_is_visible_only_to_admins(aapp):
    assert "/admin/users" not in as_user(aapp, "zz_mgr").get("/").get_data(as_text=True)
    assert "/admin/users" in as_user(aapp, "zz_adm").get("/").get_data(as_text=True)


# ---------- 사용자 목록 ----------
def test_user_list_shows_users_state_and_hides_secrets(aapp, root):
    sql(root, "UPDATE users SET display_name='<script>alert(1)</script>' WHERE username='zz_emp3'")
    lock(root, "zz_emp2", 4)
    c = as_user(aapp, "zz_adm")
    html = c.get("/admin/users").get_data(as_text=True)
    assert all(n in html for n in ("zz_emp", "zz_emp2", "zz_mgr", "zz_adm"))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html and "<script>alert" not in html
    assert "잠김" in html and "실패 4회" in html and "잠금 해제" in html
    assert "argon2" not in html and "password_hash" not in html and PW_HASH[:20] not in html   # 비밀번호 해시는 화면에 없다
    own_row = re.search(r"<tr>\s*<td>zz_adm</td>.*?</tr>", html, re.S).group(0)
    assert "(본인)" in own_row and "<select" not in own_row                           # 본인 행에는 역할 변경이 없다

def test_user_list_search_and_filters(aapp, root):
    adm = as_user(aapp, "zz_adm")
    # 1. 아이디 검색
    h_q = adm.get("/admin/users?q=zz_emp2").get_data(as_text=True)
    assert "zz_emp2" in h_q and "zz_mgr" not in h_q
    # 2. 역할 필터
    h_role = adm.get("/admin/users?role=manager").get_data(as_text=True)
    assert "zz_mgr" in h_role and "zz_emp2" not in h_role



# ---------- 역할 변경 ----------
def test_promotion_takes_effect_immediately_without_relogin(aapp, root, events):
    emp, adm = as_user(aapp, "zz_emp2"), as_user(aapp, "zz_adm")
    assert emp.get("/finance").status_code == 403
    assert set_role(adm, root, "zz_emp2", "manager", "employee").status_code == 303
    assert role_of(root, "zz_emp2") == "manager"
    assert emp.get("/finance").status_code == 200                                     # 재로그인 없이 바로 반영
    ev = [e for e in events() if e["event_type"] == "admin_action" and e["reason"] == "role_change"][-1]
    assert (ev["user"], ev["target"], ev["old"], ev["new"], ev["decision"]) == ("zz_adm", "zz_emp2", "employee", "manager", "ALLOW")


def test_demotion_takes_effect_immediately(aapp, root):
    mgr, adm = as_user(aapp, "zz_mgr"), as_user(aapp, "zz_adm")
    assert mgr.get("/finance").status_code == 200
    assert set_role(adm, root, "zz_mgr", "employee", "manager").status_code == 303
    assert mgr.get("/finance").status_code == 403
    assert "zz_mgr의" not in mgr.get("/expenses").get_data(as_text=True)


def test_admin_cannot_change_own_role(aapp, root, events):
    adm = as_user(aapp, "zz_adm")
    for new_role in ("employee", "manager", "admin"):
        assert set_role(adm, root, "zz_adm", new_role, "admin").status_code == 403
    assert role_of(root, "zz_adm") == "admin"
    assert adm.get("/admin/users").status_code == 200                                 # 여전히 관리자
    ev = [e for e in events() if e["event_type"] == "admin_action" and e["reason"] == "self_change"]
    assert len(ev) == 3 and ev[0]["decision"] == "DENY" and ev[0]["user"] == "zz_adm"


def test_admin_can_demote_another_admin_and_a_demoted_admin_loses_access(aapp, root):
    sql(root, "INSERT INTO users(username,password_hash,role,display_name,dept) VALUES('zz_adm2',%s,'admin','a2','관리팀')", (PW_HASH,))
    adm, adm2 = as_user(aapp, "zz_adm"), as_user(aapp, "zz_adm2")
    assert adm2.get("/admin/users").status_code == 200
    assert set_role(adm, root, "zz_adm2", "employee", "admin").status_code == 303
    assert adm2.get("/admin/users").status_code == 403                                # 강등 즉시 관리자 경로 차단
    assert role_of(root, "zz_adm") == "admin"                                         # 실행한 관리자는 남는다


@pytest.mark.parametrize("value", ["superuser", "", "ADMIN", "admin ", "root", "1", "employee;DROP TABLE users"])
def test_invalid_role_values_are_rejected(aapp, root, events, value):
    before = snapshot(root)
    assert set_role(as_user(aapp, "zz_adm"), root, "zz_emp", value, "employee").status_code == 400
    assert snapshot(root) == before
    assert any(e["event_type"] == "input_rejected" and e["field"] == "role" for e in events())


def test_invalid_current_role_value_is_rejected(aapp, root):
    assert set_role(as_user(aapp, "zz_adm"), root, "zz_emp", "manager", "hacker").status_code == 400
    assert role_of(root, "zz_emp") == "employee"


def test_stale_form_does_not_overwrite_a_newer_change(aapp, root, events):
    adm = as_user(aapp, "zz_adm")
    sql(root, "UPDATE users SET role='manager' WHERE username='zz_emp'")             # 화면을 연 뒤 다른 관리자가 이미 바꿈
    assert set_role(adm, root, "zz_emp", "admin", "employee").status_code == 409
    assert role_of(root, "zz_emp") == "manager"
    assert any(e["event_type"] == "admin_action" and e["reason"] == "stale_form" for e in events())


def test_same_role_is_a_no_op(aapp, root, events):
    assert set_role(as_user(aapp, "zz_adm"), root, "zz_emp", "employee", "employee").status_code == 303
    assert role_of(root, "zz_emp") == "employee"
    assert not any(e["event_type"] == "admin_action" and e["decision"] == "ALLOW" for e in events())


def test_role_change_for_unknown_users_and_bad_ids(aapp, root):
    adm = as_user(aapp, "zz_adm")
    assert post(adm, "/admin/users/999999/role", role="manager", current_role="employee").status_code == 404
    for path in ("/admin/users/abc/role", "/admin/users/-1/role", "/admin/users/1%27%20OR%201=1/role"):
        assert post(adm, path, role="manager", current_role="employee").status_code == 404


def test_role_change_needs_csrf_and_post(aapp, root):
    adm = as_user(aapp, "zz_adm")
    target = uid(root, "zz_emp")
    assert adm.post(f"/admin/users/{target}/role", data={"role": "admin", "current_role": "employee"}).status_code == 403
    assert adm.get(f"/admin/users/{target}/role").status_code == 405
    assert role_of(root, "zz_emp") == "employee"


def test_extra_form_fields_cannot_change_other_columns(aapp, root):
    before = sql(root, "SELECT username, dept, display_name, password_hash FROM users WHERE username='zz_emp'")
    post(as_user(aapp, "zz_adm"), f"/admin/users/{uid(root, 'zz_emp')}/role", role="manager", current_role="employee",
         username="hacked", dept="해킹팀", display_name="x", password_hash="x", failed_count="9")
    after = sql(root, "SELECT username, dept, display_name, password_hash FROM users WHERE username='zz_emp'")
    assert after == before and role_of(root, "zz_emp") == "manager"


# ---------- 결재선 전체 사원 선택 및 결재 처리 ----------
def test_all_employees_can_be_approvers_and_decide(aapp, root, events):
    a = pending_approval(root, "zz_emp", "zz_mgr")
    mgr = as_user(aapp, "zz_mgr")
    assert 'name="decision"' in mgr.get(f"/approvals/{a}").get_data(as_text=True)
    r = post(mgr, f"/approvals/{a}/decide", decision="approve")
    assert r.status_code == 303
    assert sql(root, "SELECT status FROM approvals WHERE id=%s", (a,))[0][0] == "approved"


def test_all_employees_appear_in_approver_candidates(aapp, root):
    emp = as_user(aapp, "zz_emp")
    approvers = emp.get("/approvals/new").get_data(as_text=True).split('name="cc"')[0]   # 결재자 선택 칸만
    assert f'value="{uid(root, "zz_mgr")}"' in approvers
    assert f'value="{uid(root, "zz_emp2")}"' in approvers  # 일반 사원도 결재선에 포함


# ---------- 잠금 해제 ----------
def test_unlock_lets_the_user_log_in_again(aapp, root, events):
    lock(root, "zz_emp", 5)
    assert login(aapp.test_client(), "zz_emp").status_code == 401                    # 잠겨 있어 올바른 비밀번호도 거부
    assert unlock(as_user(aapp, "zz_adm"), root, "zz_emp").status_code == 303
    assert sql(root, "SELECT failed_count, locked_until FROM users WHERE username='zz_emp'")[0] == (0, None)
    assert login(aapp.test_client(), "zz_emp").status_code == 303
    ev = [e for e in events() if e["event_type"] == "admin_action" and e["reason"] == "unlock"][-1]
    assert (ev["user"], ev["target"], ev["was_locked"], ev["failed_count"]) == ("zz_adm", "zz_emp", True, 5)


def test_unlock_resets_partial_failures_and_is_idempotent(aapp, root):
    sql(root, "UPDATE users SET failed_count=3 WHERE username='zz_emp'")
    adm = as_user(aapp, "zz_adm")
    assert unlock(adm, root, "zz_emp").status_code == 303
    assert sql(root, "SELECT failed_count FROM users WHERE username='zz_emp'")[0][0] == 0
    assert unlock(adm, root, "zz_emp").status_code == 303                             # 이미 정상이어도 오류 없음


def test_unlock_for_unknown_users_csrf_and_method(aapp, root):
    adm = as_user(aapp, "zz_adm")
    assert post(adm, "/admin/users/999999/unlock").status_code == 404
    assert post(adm, "/admin/users/abc/unlock").status_code == 404
    lock(root, "zz_emp", 5)
    target = uid(root, "zz_emp")
    assert adm.post(f"/admin/users/{target}/unlock").status_code == 403
    assert adm.get(f"/admin/users/{target}/unlock").status_code == 405
    assert sql(root, "SELECT failed_count FROM users WHERE username='zz_emp'")[0][0] == 5
