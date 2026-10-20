"""시스템 관리(관리 현황·사용자 등록·비밀번호 초기화·잠금·감사 로그·권한 현황). Docker MySQL(nexus_test) 필요, 접속 불가면 skip.
계정: zz_emp·zz_emp2·zz_emp3(직원) / zz_mgr·zz_mgrb(팀장) / zz_adm(관리자)"""
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from app import audit
from support import PW, as_user, login, post, sql, uid

PW_POLICY = re.compile(r"<code class=\"secret\">([^<]+)</code>")


def create(client, username="zz_new", name="신규직원", dept="zz_부서", role="employee", **extra):
    return post(client, "/admin/users/new", username=username, display_name=name, dept=dept, role=role, **extra)


def table_body(html):
    """감사 로그 표의 본문만(필터 목록의 이벤트 이름과 섞이지 않게). 결과가 없으면 본문이 없다."""
    return html.split("<tbody>")[1] if "<tbody>" in html else ""


def temp_password(response):
    return PW_POLICY.search(response.get_data(as_text=True)).group(1)


# ---------- 사용자 등록 ----------
def test_create_user_shows_temp_password_once_and_makes_the_hr_card(aapp, root, events):
    adm = as_user(aapp, "zz_adm")
    r = create(adm, role="manager")
    assert r.status_code == 200 and "한 번만" in r.get_data(as_text=True)
    pw = temp_password(r)
    assert len(pw) >= 12
    row = sql(root, "SELECT id, role, display_name, dept, password_hash FROM users WHERE username='zz_new'")[0]
    assert row[1:4] == ("manager", "신규직원", "zz_부서") and pw not in row[4] and row[4].startswith("$argon2id$")
    card = sql(root, "SELECT name, dept, title, emp_no, hire_date FROM employees WHERE user_id=%s", (row[0],))[0]
    assert card[0:3] == ("신규직원", "zz_부서", "팀장") and card[3] == f"NX-{card[4].year}-U{row[0]:04d}"
    c = aapp.test_client()                                       # 임시 비밀번호로 실제 로그인된다
    assert login(c, "zz_new", pw).status_code == 303
    assert all(pw not in json.dumps(e) for e in events())         # 비밀번호는 로그에 남지 않는다
    assert any(e["event_type"] == "admin_action" and e["reason"] == "user_create" and e["target"] == "zz_new" for e in events())
    assert pw not in adm.get("/admin/users").get_data(as_text=True)   # 목록에도 다시 보이지 않는다
    sql(root, "DELETE FROM employees WHERE user_id=%s", (row[0],))


def test_admin_cannot_choose_the_password_through_the_form(aapp, root):
    r = create(as_user(aapp, "zz_adm"), password="1234", password_hash="x", failed_count="0")
    pw = temp_password(r)
    assert pw != "1234" and login(aapp.test_client(), "zz_new", "1234").status_code != 303
    assert login(aapp.test_client(), "zz_new", pw).status_code == 303
    sql(root, "DELETE FROM employees WHERE user_id=(SELECT id FROM users WHERE username='zz_new')")


@pytest.mark.parametrize("kw", [
    dict(username="Zz_Upper"), dict(username="zz"), dict(username="1zz_num"), dict(username="zz new"), dict(username="zz-new"),
    dict(username="zz_" + "a" * 40), dict(name=""), dict(name="가" * 65), dict(dept=""), dict(role="superuser"), dict(role=""),
    dict(name="줄\x00바꿈"),
])
def test_invalid_user_input_is_rejected_without_creating_anything(aapp, root, kw):
    before = sql(root, "SELECT COUNT(*) FROM users")[0][0]
    r = create(as_user(aapp, "zz_adm"), **kw)
    assert r.status_code == 400 and sql(root, "SELECT COUNT(*) FROM users")[0][0] == before


def test_new_user_form_lists_departments(aapp, root):
    html = as_user(aapp, "zz_adm").get("/admin/users/new").get_data(as_text=True)
    box = html.split('<select name="dept"')[1].split("</select>")[0]
    for dept in ("A팀", "B팀", "보안관제팀", "경영지원팀", "인사팀", "재무팀"):       # 시험 계정의 부서 + 권한 규칙이 보는 부서
        assert f'<option value="{dept}">{dept}</option>' in box
    assert 'value="__new__"' in box and 'name="new_dept"' in html and "dept-select.js" in html


def test_pick_department_from_list_or_type_a_new_one(aapp, root):
    adm = as_user(aapp, "zz_adm")
    assert create(adm, username="zz_d1", dept="A팀", new_dept="무시됨").status_code == 200
    assert create(adm, username="zz_d2", dept="__new__", new_dept=" zz_신설팀 ").status_code == 200
    rows = dict(sql(root, "SELECT username, dept FROM users WHERE username IN ('zz_d1','zz_d2')"))
    assert rows == {"zz_d1": "A팀", "zz_d2": "zz_신설팀"}
    assert sql(root, "SELECT dept FROM employees WHERE user_id=%s", (uid(root, "zz_d2"),))[0][0] == "zz_신설팀"
    html = adm.get("/admin/users/new").get_data(as_text=True)
    assert '<option value="zz_신설팀">zz_신설팀</option>' in html                       # 새 부서는 다음부터 목록에 나온다
    for bad in ("", "가" * 65, "줄\x00바꿈"):
        r = create(adm, username="zz_d3", dept="__new__", new_dept=bad)
        assert r.status_code == 400 and 'value="__new__" selected' in r.get_data(as_text=True)
    assert not sql(root, "SELECT id FROM users WHERE username='zz_d3'")


def test_duplicate_username_is_a_conflict_and_does_not_change_the_existing_user(aapp, root):
    before = sql(root, "SELECT role, display_name, password_hash FROM users WHERE username='zz_emp'")
    r = create(as_user(aapp, "zz_adm"), username="zz_emp", name="탈취", role="admin")
    assert r.status_code == 409 and "이미 있는 아이디" in r.get_data(as_text=True)
    assert sql(root, "SELECT role, display_name, password_hash FROM users WHERE username='zz_emp'") == before


# ---------- 비밀번호 초기화 ----------
def test_reset_password_replaces_the_password_cuts_sessions_and_unlocks(aapp, root, events):
    victim = as_user(aapp, "zz_emp")
    assert victim.get("/").status_code == 200
    sql(root, "UPDATE users SET failed_count=3 WHERE username='zz_emp'")
    r = post(as_user(aapp, "zz_adm"), f"/admin/users/{uid(root, 'zz_emp')}/reset-password")
    assert r.status_code == 200
    pw = temp_password(r)
    assert victim.get("/").status_code == 303                                   # 이전에 로그인해 있던 기기는 끊긴다
    assert login(aapp.test_client(), "zz_emp", PW).status_code != 303           # 옛 비밀번호는 더 쓸 수 없다
    assert login(aapp.test_client(), "zz_emp", pw).status_code == 303
    assert sql(root, "SELECT failed_count FROM users WHERE username='zz_emp'")[0][0] == 0
    assert all(pw not in json.dumps(e) for e in events())
    assert any(e.get("reason") == "password_reset" and e["target"] == "zz_emp" for e in events())


def test_reset_password_also_clears_a_lock(aapp, root):
    sql(root, "UPDATE users SET locked_until=DATE_ADD(NOW(), INTERVAL 1 DAY) WHERE username='zz_emp'")
    pw = temp_password(post(as_user(aapp, "zz_adm"), f"/admin/users/{uid(root, 'zz_emp')}/reset-password"))
    assert login(aapp.test_client(), "zz_emp", pw).status_code == 303


def test_admin_cannot_reset_or_lock_their_own_account(aapp, root, events):
    adm = as_user(aapp, "zz_adm")
    me = uid(root, "zz_adm")
    before = sql(root, "SELECT password_hash, locked_until, session_version FROM users WHERE id=%s", (me,))
    assert post(adm, f"/admin/users/{me}/reset-password").status_code == 403
    assert post(adm, f"/admin/users/{me}/lock").status_code == 403
    assert sql(root, "SELECT password_hash, locked_until, session_version FROM users WHERE id=%s", (me,)) == before
    assert {e["reason"] for e in events() if e["event_type"] == "authz_deny"} >= {"self_password_reset", "self_lock"}


# ---------- 잠금 ----------
def test_manual_lock_blocks_login_and_cuts_the_session_until_unlocked(aapp, root, events):
    victim = as_user(aapp, "zz_emp")
    assert post(as_user(aapp, "zz_adm"), f"/admin/users/{uid(root, 'zz_emp')}/lock").status_code == 303
    assert victim.get("/").status_code == 303                                   # 진행 중이던 세션도 바로 끊긴다
    assert login(aapp.test_client(), "zz_emp", PW).status_code != 303           # 맞는 비밀번호여도 잠겨 있다
    assert any(e.get("reason") == "lock" and e["target"] == "zz_emp" for e in events())
    assert post(as_user(aapp, "zz_adm"), f"/admin/users/{uid(root, 'zz_emp')}/unlock").status_code == 303
    assert login(aapp.test_client(), "zz_emp", PW).status_code == 303


def test_lock_and_reset_for_unknown_users_and_non_post(aapp, root):
    adm = as_user(aapp, "zz_adm")
    for action in ("lock", "reset-password"):
        assert post(adm, f"/admin/users/999999/{action}").status_code == 404
        assert adm.get(f"/admin/users/{uid(root, 'zz_emp')}/{action}").status_code == 405


def test_user_list_shows_actions_for_others_only(aapp, root):
    html = as_user(aapp, "zz_adm").get("/admin/users").get_data(as_text=True)
    assert "zz_emp 비밀번호 초기화" in html and "zz_emp 잠금" in html
    assert "zz_adm 비밀번호 초기화" not in html and "zz_adm 잠금" not in html          # 본인 행에는 버튼이 없다


# ---------- 관리 현황 ----------
def test_overview_counts_follow_the_database(aapp, root):
    sql(root, "UPDATE users SET locked_until=DATE_ADD(NOW(), INTERVAL 1 DAY) WHERE username='zz_emp2'")
    html = as_user(aapp, "zz_adm").get("/admin/overview").get_data(as_text=True)
    total = sql(root, "SELECT COUNT(*) FROM users")[0][0]
    locked = sql(root, "SELECT COUNT(*) FROM users WHERE locked_until > NOW()")[0][0]
    assert f'<span class="stat-n">{total}</span><span class="stat-l">전체 사용자</span>' in html
    assert f'<span class="stat-n">{locked}</span><span class="stat-l">잠긴 계정</span>' in html and locked >= 1
    assert "zz_A팀" not in html and "A팀" in html and "최근 24시간 보안 이벤트" in html


# ---------- 감사 로그 ----------
def test_audit_log_lists_events_and_filters(aapp, root, events):
    adm = as_user(aapp, "zz_sec")
    as_user(aapp, "zz_emp").get("/confidential")                           # authz_deny 한 건
    bad = aapp.test_client()
    login(bad, "zz_emp3", "틀린-비밀번호-1!")                                   # login_failure 한 건
    html = adm.get("/admin/audit").get_data(as_text=True)
    assert "authz_deny" in html and "login_failure" in html and "insufficient_role" in html
    only = table_body(adm.get("/admin/audit?type=authz_deny").get_data(as_text=True))
    assert "authz_deny" in only and "login_failure" not in only
    deny = table_body(adm.get("/admin/audit?decision=DENY&user=zz_emp").get_data(as_text=True))
    assert "insufficient_role" in deny and "zz_emp3" not in deny
    assert "authz_deny" in table_body(adm.get("/admin/audit?ip=127.0.0.1").get_data(as_text=True))
    assert table_body(adm.get("/admin/audit?ip=10.9.9.9").get_data(as_text=True)) == ""
    assert any(e.get("reason") == "audit_view" for e in events())


def test_audit_log_escapes_attacker_controlled_values(aapp):
    as_user(aapp, "zz_emp").get("/<script>alert(1)</script>")
    html = as_user(aapp, "zz_sec").get("/admin/audit?type=not_found").get_data(as_text=True)
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html


@pytest.mark.parametrize("query", ["type=Bad-Type", "type=" + "a" * 50, "decision=EVIL", "user=a b", "user=" + "u" * 40,
                                   "ip=1.2.3.4;drop", "ip=" + "1" * 60, "limit=7", "limit=abc", "period=1y", "page=0", "page=999", "page=x"])
def test_audit_filters_reject_bad_values(aapp, query):
    r = as_user(aapp, "zz_sec").get("/admin/audit?" + query)
    assert r.status_code == 400 and "검색 조건이 올바르지 않습니다" in r.get_data(as_text=True)


def test_audit_reader_orders_newest_first_skips_junk_and_spans_rotated_files(tmp_path):
    def line(ts, **kw):
        return json.dumps({"ts": ts.isoformat(timespec="seconds"), "event_type": "e", "user": "u", "decision": "INFO", **kw})
    now = datetime.now(timezone.utc)
    (tmp_path / "security.jsonl").write_text("\n".join([line(now - timedelta(minutes=2), reason="b"), "not json", "[1,2]",
                                                         line(now - timedelta(minutes=1), reason="c")]) + "\n", encoding="utf-8")
    (tmp_path / "security.jsonl.1").write_text(line(now - timedelta(days=2), reason="old") + "\n", encoding="utf-8")
    events, kinds, scanned = audit.read_events(tmp_path)
    assert [e["reason"] for e in events] == ["c", "b", "old"] and scanned == 3 and kinds["e"] == 3
    assert events[0]["time"] > events[1]["time"]
    assert [e["reason"] for e in audit.read_events(tmp_path, limit=1)[0]] == ["c"]
    assert audit.recent_counts(tmp_path) == [("e", 2)]                          # 24시간 안의 것만 센다
    missing, _k, none = audit.read_events(tmp_path / "missing")
    assert missing == [] and none == 0                                         # 로그 파일이 없어도 오류 없이 빈 결과


def test_audit_reader_caps_how_much_it_reads(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "MAX_BYTES", 400)
    rows = [json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "event_type": "e", "reason": f"r{i:03d}"}) for i in range(50)]
    (tmp_path / "security.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")
    events, _kinds, scanned = audit.read_events(tmp_path, limit=500)
    assert 0 < scanned < 50 and events[0]["reason"] == "r049"                  # 끝(최신)에서부터 읽고, 잘린 첫 줄은 버린다


# ---------- 권한 현황 ----------
def test_permission_table_matches_what_the_server_enforces(aapp, root):
    html = as_user(aapp, "zz_adm").get("/admin/permissions").get_data(as_text=True)
    for name in ("기밀 문서함", "재무 보고", "휴가 승인·반려", "관리(현황·사용자·권한)", "보안 대시보드·감사 로그"):
        assert name in html
    emp, mgr, adm = as_user(aapp, "zz_emp"), as_user(aapp, "zz_mgr"), as_user(aapp, "zz_adm")
    for path in ("/confidential", "/finance", "/admin/overview"):                  # 표가 '불가'라고 한 것은 실제로 403
        assert emp.get(path).status_code == 403, path
    assert mgr.get("/confidential").status_code == 200 and mgr.get("/finance").status_code == 200
    assert mgr.get("/admin/overview").status_code == 403 and adm.get("/admin/overview").status_code == 200
    assert emp.get("/boards/notice/new").status_code == 403 and mgr.get("/boards/notice/new").status_code == 200
    assert re.search(r"employee\)<br><span class=\"hint\">\d+명", html)                # 역할별 인원도 함께 보인다


# ---------- 메뉴 ----------
def test_admin_menu_group_has_four_items_for_admins_only(aapp):
    sec = as_user(aapp, "zz_sec").get("/admin/overview").get_data(as_text=True)
    for label in ("관리 현황", "사용자 관리", "보안 대시보드", "권한 현황"):                    # 보안관제팀은 네 항목 모두
        assert f">{label}</a>" in sec
    assert 'aria-current="page">관리 현황</a>' in sec
    adm = as_user(aapp, "zz_adm").get("/admin/overview").get_data(as_text=True)              # 일반 관리자는 보안 대시보드가 메뉴에 없다
    for label in ("관리 현황", "사용자 관리", "권한 현황"):
        assert f">{label}</a>" in adm
    assert ">보안 대시보드</a>" not in adm
    for who in ("zz_emp", "zz_mgr"):
        html = as_user(aapp, who).get("/").get_data(as_text=True)
        assert "<h2>관리</h2>" not in html and "보안 대시보드" not in html and "권한 현황" not in html


# ---------- 부서 변경 ----------
def change_dept(client, target, current, dept, new_dept=""):
    return post(client, f"/admin/users/{target}/dept", current_dept=current, dept=dept, new_dept=new_dept)


def test_admin_moves_a_user_to_another_department(aapp, root, events):
    emp = uid(root, "zz_emp")
    sql(root, "INSERT INTO employees(user_id,name,dept,title,ext) VALUES(%s,'zz_emp','A팀','사원','-')", (emp,))
    adm = as_user(aapp, "zz_adm")
    assert change_dept(adm, emp, "A팀", "B팀").status_code == 303
    assert sql(root, "SELECT dept FROM users WHERE id=%s", (emp,))[0][0] == "B팀"
    assert sql(root, "SELECT dept FROM employees WHERE user_id=%s", (emp,))[0][0] == "B팀"        # 인사카드도 같이
    assert any(e.get("reason") == "dept_change" and e.get("old") == "A팀" and e.get("new") == "B팀" for e in events())
    assert change_dept(adm, emp, "B팀", "__new__", "zz_신설팀").status_code == 303               # 목록에 없는 새 부서
    assert sql(root, "SELECT dept FROM users WHERE id=%s", (emp,))[0][0] == "zz_신설팀"
    html = adm.get("/admin/users").get_data(as_text=True)
    assert f'action="/admin/users/{emp}/dept"' in html and 'data-new-dept=' in html and "dept-select.js" in html


def test_department_change_applies_to_team_scope_at_once(aapp, root):
    emp, other = uid(root, "zz_emp"), uid(root, "zz_emp3")                                      # zz_emp3 는 B팀
    sql(root, "INSERT INTO events(owner_id,title,start_at,end_at,scope) VALUES(%s,'zz_B팀 회의',NOW(),DATE_ADD(NOW(), INTERVAL 1 HOUR),'team')", (other,))
    c = as_user(aapp, "zz_emp")                                                                 # 이미 로그인해 있던 세션
    assert "zz_B팀 회의" not in c.get("/").get_data(as_text=True)
    assert change_dept(as_user(aapp, "zz_adm"), emp, "A팀", "B팀").status_code == 303
    assert "zz_B팀 회의" in c.get("/").get_data(as_text=True)                                     # 다시 로그인하지 않아도 새 부서 기준


def test_department_change_guards(aapp, root, pinned_dept):
    adm, emp, me = as_user(aapp, "zz_adm"), uid(root, "zz_emp"), uid(root, "zz_adm")
    assert change_dept(adm, me, "관리팀", "보안관제팀").status_code == 403                          # 본인 부서는 못 바꾼다(권한 올리기 방지)
    assert change_dept(adm, pinned_dept, "보안관제팀", "A팀").status_code == 403                   # 고정 계정은 최고관리자만
    assert change_dept(adm, emp, "B팀", "C팀").status_code == 409                                 # 화면을 연 사이 바뀜
    for bad in ("", "가" * 65):
        assert change_dept(adm, emp, "A팀", "__new__", bad).status_code == 409
    assert change_dept(as_user(aapp, "zz_mgr"), emp, "A팀", "B팀").status_code == 403             # 관리자가 아니면 못 한다
    assert aapp.test_client().post(f"/admin/users/{emp}/dept", data={"dept": "B팀", "current_dept": "A팀"}).status_code in (302, 303, 403)
    assert sql(root, "SELECT dept FROM users WHERE username IN ('zz_emp','zz_adm','zz_sec') ORDER BY username") == (("관리팀",), ("A팀",), ("보안관제팀",))
    assert change_dept(as_user(aapp, "zz_sec"), uid(root, "zz_adm"), "관리팀", "보안관제팀").status_code == 303   # 최고관리자는 가능


@pytest.fixture()
def pinned_dept(root):
    sql(root, "UPDATE users SET pinned=1 WHERE username='zz_sec'")
    return uid(root, "zz_sec")
