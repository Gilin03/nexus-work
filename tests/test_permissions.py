"""최상위 권한 고정(보안관제팀·시스템관리자), 직급·팀별 권한, 보안 대시보드. Docker MySQL(nexus_test) 필요, 접속 불가면 skip."""
import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pymysql
import pytest

from app import audit, permissions
from app.permissions import RANKS, can, matrix, rank_of
from support import PW_HASH, csrf_of, login, sql, uid


def as_user(app, name):
    c = app.test_client()
    assert login(c, name).status_code == 303
    return c


def post(client, path, **form):
    return client.post(path, data={"csrf_token": csrf_of(client), **form})


def make_user(root, name, role, dept, title=None, card=True):
    sql(root, "INSERT INTO users(username,password_hash,role,display_name,dept) VALUES(%s,%s,%s,%s,%s)", (name, PW_HASH, role, name, dept))
    if card:
        sql(root, "INSERT INTO employees(user_id,name,dept,title,ext,emp_no,hire_date) VALUES(%s,%s,%s,%s,'1',%s,'2024-01-01')",
            (uid(root, name), name, dept, title or permissions.DEFAULT_TITLE[role], f"ZZ-{name}"))
    return uid(root, name)


def state(root, name):
    return sql(root, "SELECT role, pinned FROM users WHERE username=%s", (name,))[0]


# =====================================================================================
# 고정 계정
# =====================================================================================
def test_security_team_members_are_created_as_pinned_admins_whatever_role_is_asked(root):
    sql(root, "INSERT INTO users(username,password_hash,role,display_name,dept) VALUES('zz_s1',%s,'employee','zz_s1','보안관제팀')", (PW_HASH,))
    assert state(root, "zz_s1") == ("admin", 1)
    sql(root, "INSERT INTO users(username,password_hash,role,display_name,dept) VALUES('zz_s2',%s,'manager','zz_s2','보안관제팀')", (PW_HASH,))
    assert state(root, "zz_s2") == ("admin", 1)
    assert state(root, "zz_emp") == ("employee", 0) and state(root, "zz_adm") == ("admin", 0)          # 다른 팀은 영향 없음


def test_system_admin_account_is_pinned_by_name(root):
    try:
        sql(root, "INSERT INTO users(username,password_hash,role,display_name,dept) VALUES('admin',%s,'employee','시스템관리자','경영지원팀')", (PW_HASH,))
        assert state(root, "admin") == ("admin", 1)
    finally:
        sql(root, "DELETE FROM users WHERE username='admin'")


@pytest.mark.parametrize("statement", [
    "UPDATE users SET role='employee' WHERE username='zz_sec'",
    "UPDATE users SET role='manager' WHERE username='zz_sec'",
    "UPDATE users SET pinned=0 WHERE username='zz_sec'",
    "UPDATE users SET role='employee', pinned=0 WHERE username='zz_sec'",
])
def test_database_refuses_to_demote_or_unpin_a_pinned_account_even_for_root(root, statement):
    with pytest.raises(pymysql.err.OperationalError) as exc:
        sql(root, statement)
    assert exc.value.args[0] == 1644 and "pinned" in exc.value.args[1]
    assert state(root, "zz_sec") == ("admin", 1)


def test_database_allows_everything_else_about_a_pinned_account(root):
    sql(root, "UPDATE users SET failed_count=3, session_version=session_version+1 WHERE username='zz_sec'")
    sql(root, "UPDATE users SET role='admin' WHERE username='zz_sec'")
    sql(root, "UPDATE users SET pinned=1 WHERE username='zz_adm'", ())                                  # 고정으로 올리는 것은 admin 일 때만 가능
    assert state(root, "zz_adm") == ("admin", 1)
    with pytest.raises(pymysql.err.OperationalError):
        sql(root, "UPDATE users SET pinned=1 WHERE username='zz_emp'")                                  # 직원을 그대로 고정할 수는 없다


def test_admin_screens_cannot_change_lock_or_reset_a_pinned_account(aapp, root, events):
    adm = as_user(aapp, "zz_adm")
    target = uid(root, "zz_sec")
    before = sql(root, "SELECT password_hash, locked_until, session_version FROM users WHERE id=%s", (target,))
    assert post(adm, f"/admin/users/{target}/role", role="employee", current_role="admin").status_code == 403
    assert post(adm, f"/admin/users/{target}/lock").status_code == 403
    assert post(adm, f"/admin/users/{target}/reset-password").status_code == 403
    assert state(root, "zz_sec") == ("admin", 1)
    assert sql(root, "SELECT password_hash, locked_until, session_version FROM users WHERE id=%s", (target,)) == before
    denied = [e for e in events() if e["event_type"] == "admin_action" and e["reason"] == "pinned_account"]
    assert {e["action"] for e in denied} == {"role_change", "lock", "password_reset"}


def test_pinned_admin_can_still_manage_other_people_and_unlock(aapp, root):
    sec = as_user(aapp, "zz_sec")
    target = uid(root, "zz_emp2")
    assert post(sec, f"/admin/users/{target}/role", role="manager", current_role="employee").status_code == 303
    assert state(root, "zz_emp2")[0] == "manager"
    sql(root, "UPDATE users SET failed_count=4 WHERE username='zz_sec'")
    assert post(as_user(aapp, "zz_adm"), f"/admin/users/{uid(root, 'zz_sec')}/unlock").status_code == 303   # 잠금 해제는 막지 않는다
    assert sql(root, "SELECT failed_count FROM users WHERE username='zz_sec'")[0][0] == 0


def test_failed_login_lockout_still_protects_pinned_accounts(aapp, root):
    c = aapp.test_client()
    for _ in range(5):
        login(c, "zz_sec", "틀린-비밀번호-1!")
    assert login(aapp.test_client(), "zz_sec").status_code == 401                                        # 5회 실패 후에는 올바른 비밀번호도 거부


def test_user_list_marks_pinned_accounts_and_hides_their_controls(aapp, root):
    html = as_user(aapp, "zz_adm").get("/admin/users").get_data(as_text=True)
    rows = html.split("<tr>")
    pinned = next(r for r in rows if "<td>zz_sec" in r)
    assert "고정" in pinned and "<form" not in pinned and "비밀번호 초기화" not in pinned and ">잠금<" not in pinned
    other = next(r for r in rows if "<td>zz_emp2</td>" in r)
    assert "비밀번호 초기화" in other and 'name="role"' in other and "고정" not in other


def test_registering_a_security_team_user_forces_admin_and_pins(aapp, root, events):
    adm = as_user(aapp, "zz_adm")
    r = post(adm, "/admin/users/new", username="zz_newsec", display_name="신규 관제", dept="보안관제팀", role="employee")
    assert r.status_code == 200
    assert state(root, "zz_newsec") == ("admin", 1)
    assert sql(root, "SELECT title FROM employees WHERE user_id=%s", (uid(root, "zz_newsec"),))[0][0] == "관리자"
    ev = [e for e in events() if e.get("action") == "user_create"][-1]
    assert ev["role"] == "admin" and ev["pinned"] is True
    sql(root, "DELETE FROM employees WHERE user_id=%s", (uid(root, "zz_newsec"),))


# =====================================================================================
# 직급
# =====================================================================================
@pytest.mark.parametrize("role,title,expected", [
    ("employee", "사원", 1), ("employee", "대리", 2), ("employee", "과장", 3), ("employee", "팀장", 3), ("employee", "관리자", 3),     # 역할 범위로 자른다
    ("employee", None, 1), ("employee", "임원", 1), ("manager", "사원", 4), ("manager", "팀장", 4), ("manager", None, 4),
    ("admin", "사원", 5), ("admin", "관리자", 5), ("admin", None, 5), ("nobody", "과장", 1),
])
def test_rank_is_clipped_into_the_range_of_the_role(role, title, expected):
    assert rank_of(role, title) == expected


def test_rank_names_and_order():
    assert RANKS == ("사원", "대리", "과장", "팀장", "관리자")


def test_admin_changes_titles_only_within_the_role(aapp, root, events):
    make_user(root, "zz_up", "employee", "A팀", "사원")
    uid_up = uid(root, "zz_up")
    adm = as_user(aapp, "zz_adm")
    assert post(adm, f"/admin/users/{uid_up}/title", title="과장").status_code == 303
    assert sql(root, "SELECT title FROM employees WHERE user_id=%s", (uid_up,))[0][0] == "과장"
    for bad in ("팀장", "관리자", "임원", "", "x" * 40):
        assert post(adm, f"/admin/users/{uid_up}/title", title=bad).status_code == 409, bad
    assert sql(root, "SELECT title FROM employees WHERE user_id=%s", (uid_up,))[0][0] == "과장"
    assert any(e.get("action") == "title_change" and e["old"] == "사원" and e["new"] == "과장" for e in events())
    assert post(adm, f"/admin/users/{uid_up}/title", title="과장").status_code == 303                 # 같은 값은 조용히 통과(기록 없음)


def test_title_change_rules_for_self_missing_card_unknown_and_non_admin(aapp, root):
    make_user(root, "zz_nocard", "employee", "A팀", card=False)
    adm = as_user(aapp, "zz_adm")
    assert post(adm, f"/admin/users/{uid(root, 'zz_adm')}/title", title="관리자").status_code == 403    # 본인
    assert post(adm, f"/admin/users/{uid(root, 'zz_nocard')}/title", title="과장").status_code == 409   # 인사카드 없음
    assert post(adm, "/admin/users/999999/title", title="과장").status_code == 404
    for who in ("zz_emp", "zz_mgr"):
        assert post(as_user(aapp, who), f"/admin/users/{uid(root, 'zz_emp2')}/title", title="과장").status_code == 403
    assert post(adm, f"/admin/users/{uid(root, 'zz_sec')}/title", title="사원").status_code in (404, 409)   # 관리자 역할은 관리자 직급만


def test_role_change_keeps_the_title_consistent(aapp, root):
    make_user(root, "zz_r", "employee", "A팀", "과장")
    r = uid(root, "zz_r")
    adm = as_user(aapp, "zz_adm")
    title = lambda: sql(root, "SELECT title FROM employees WHERE user_id=%s", (r,))[0][0]            # noqa: E731
    assert post(adm, f"/admin/users/{r}/role", role="manager", current_role="employee").status_code == 303
    assert title() == "팀장"                                                                         # 팀장 역할은 팀장 직급만
    assert post(adm, f"/admin/users/{r}/role", role="employee", current_role="manager").status_code == 303
    assert title() == "사원"                                                                         # 직원으로 돌아오면 기본 직급
    sql(root, "UPDATE employees SET title='대리' WHERE user_id=%s", (r,))
    assert post(adm, f"/admin/users/{r}/role", role="admin", current_role="employee").status_code == 303
    assert title() == "관리자"


def test_new_user_title_validation_and_default(aapp, root):
    adm = as_user(aapp, "zz_adm")
    assert post(adm, "/admin/users/new", username="zz_n1", display_name="n", dept="A팀", role="employee", title="대리").status_code == 200
    assert sql(root, "SELECT title FROM employees WHERE user_id=%s", (uid(root, "zz_n1"),))[0][0] == "대리"
    assert post(adm, "/admin/users/new", username="zz_n2", display_name="n", dept="A팀", role="manager", title="").status_code == 200
    assert sql(root, "SELECT title FROM employees WHERE user_id=%s", (uid(root, "zz_n2"),))[0][0] == "팀장"
    for role, title in (("employee", "팀장"), ("manager", "과장"), ("admin", "사원"), ("employee", "임원")):
        r = post(adm, "/admin/users/new", username="zz_bad", display_name="n", dept="A팀", role=role, title=title)
        assert r.status_code == 400, (role, title)
    assert sql(root, "SELECT COUNT(*) FROM users WHERE username='zz_bad'")[0][0] == 0
    for n in ("zz_n1", "zz_n2"):
        sql(root, "DELETE FROM employees WHERE user_id=%s", (uid(root, n),))


# =====================================================================================
# 직급·팀 권한이 실제 서버 응답과 같은가
# =====================================================================================
CASES = [  # (아이디, 역할, 부서, 직급)
    ("zz_c01", "employee", "C팀", "사원"), ("zz_c02", "employee", "C팀", "대리"), ("zz_c03", "employee", "C팀", "과장"),
    ("zz_c04", "employee", "경영지원팀", "대리"), ("zz_c05", "employee", "경영지원팀", "과장"), ("zz_c06", "employee", "재무팀", "과장"),
    ("zz_c07", "employee", "인사팀", "대리"), ("zz_c08", "employee", "인사팀", "과장"), ("zz_c09", "manager", "C팀", "팀장"),
    ("zz_c10", "manager", "경영지원팀", "팀장"), ("zz_c11", "admin", "관리팀", "관리자"), ("zz_c12", "admin", "보안관제팀", "관리자"),
]


@pytest.fixture()
def world(aapp, root):
    """다른 부서(Z팀)의 대상자 한 명(급여·인사카드)과 CASES 의 사용자들을 만든다."""
    target = make_user(root, "zz_target", "employee", "Z팀", "사원")
    sql(root, "INSERT INTO payroll(user_id,pay_month,base_salary,bonus) VALUES(%s,'2026-09',1000000,0)", (target,))
    for name, role, dept, title in CASES:
        make_user(root, name, role, dept, title)
    return aapp


def probe_results(app, name):
    c = as_user(app, name)
    out = {
        "finance.view": c.get("/finance").status_code == 200,
        "project.create": c.get("/work/projects/new").status_code == 200,
        "notice.write": c.get("/boards/notice/new").status_code == 200,
        "security.dashboard": c.get("/admin/audit").status_code == 200,
        "doc.confidential": c.get("/confidential").status_code == 200,
        "users.manage": c.get("/admin/users").status_code == 200,
        "payroll.all": "zz_target" in c.get("/payroll").get_data(as_text=True),
        "hr.cards.all": "zz_target" in c.get("/hr/cards").get_data(as_text=True),
    }
    # 폴더 만들기는 쓰기 요청이라 마지막에 한 번만 한다(이름은 사용자마다 다르게)
    out["folder.create"] = post(c, "/library/folders/new", name=f"{name}-폴더", scope="dept").status_code == 303
    return out


def test_every_permission_matches_what_the_server_does_for_every_team_and_rank(world, root):
    assert {p[0] for p in permissions.PERMS} == set(probe_results(world, "zz_c01"))               # 새 권한을 더하면 이 시험에도 더해야 한다
    for name, role, dept, title in CASES:
        user = {"role": role, "dept": dept, "title": title, "pinned": bool(state(root, name)[1]), "username": name}
        results = probe_results(world, name)
        for key, actual in results.items():
            assert actual == can(user, key), (name, role, dept, title, key)


def test_key_team_and_rank_expectations_spelled_out(world, root):
    r = {name: probe_results(world, name) for name, *_ in CASES}
    # 일반 팀: 사원·대리는 아무 권한도 없고, 과장부터 공지·프로젝트·폴더를 만든다
    for n in ("zz_c01", "zz_c02"):
        assert not any(r[n].values()), n
    assert r["zz_c03"]["notice.write"] and r["zz_c03"]["project.create"] and r["zz_c03"]["folder.create"]
    assert not r["zz_c03"]["finance.view"] and not r["zz_c03"]["payroll.all"] and not r["zz_c03"]["doc.confidential"]
    # 경영지원·재무팀: 과장 이상만 재무 보고·전사 급여, 대리는 불가, 인사카드는 인사 쪽 팀만
    assert not r["zz_c04"]["finance.view"] and not r["zz_c04"]["payroll.all"]
    assert r["zz_c05"]["finance.view"] and r["zz_c05"]["payroll.all"] and r["zz_c05"]["hr.cards.all"]
    assert r["zz_c06"]["finance.view"] and r["zz_c06"]["payroll.all"] and not r["zz_c06"]["hr.cards.all"]
    assert not r["zz_c05"]["doc.confidential"] and not r["zz_c05"]["security.dashboard"] and not r["zz_c05"]["users.manage"]
    # 인사팀: 과장 이상만 전사 인사카드
    assert not r["zz_c07"]["hr.cards.all"] and r["zz_c08"]["hr.cards.all"] and not r["zz_c08"]["payroll.all"]
    # 팀장(다른 팀)은 자기 부서까지만, 경영지원팀 팀장은 전사 급여·인사카드까지
    assert r["zz_c09"]["finance.view"] and r["zz_c09"]["doc.confidential"] and not r["zz_c09"]["payroll.all"] and not r["zz_c09"]["hr.cards.all"]
    assert r["zz_c10"]["payroll.all"] and r["zz_c10"]["hr.cards.all"]
    # 관리자: 모든 것, 단 보안 대시보드는 보안관제팀(고정 계정)만
    assert r["zz_c11"]["users.manage"] and r["zz_c11"]["payroll.all"] and not r["zz_c11"]["security.dashboard"]
    assert r["zz_c12"]["security.dashboard"] and r["zz_c12"]["users.manage"]


def test_matrix_is_computed_from_the_same_rules():
    rows = {label: cells for label, _note, cells in matrix()}
    assert rows["보안 대시보드·감사 로그·내보내기"] == [False] * 5                               # 일반 팀에서는 관리자도 불가(팀 조건)
    assert rows["공지사항 글쓰기"] == [False, False, True, True, True]
    assert rows["재무 보고 열람"] == [False, False, False, True, True]
    assert rows["사용자 관리·역할·직급 변경"] == [False, False, False, False, True]
    assert len(rows) == len(permissions.PERMS)
    only_finance = matrix(dept="경영지원팀")
    assert {l: c for l, _n, c in only_finance}["재무 보고 열람"] == [False, False, True, True, True]


def test_permissions_page_shows_matrix_pinned_accounts_and_rank_counts(aapp, root):
    make_user(root, "zz_tit", "employee", "A팀", "과장")
    html = as_user(aapp, "zz_adm").get("/admin/permissions").get_data(as_text=True)
    for text in ("최상위 권한 고정 계정", "zz_sec", "직급별 권한", "팀별 전용 권한", "역할별 접근 범위", "전사 급여 조회", "보안 대시보드·감사 로그·내보내기",
                 "경영지원팀·재무팀 (과장 이상)"):
        assert text in html, text
    assert html.count("사원<br>") == 1 and "과장<br>" in html
    assert as_user(aapp, "zz_emp").get("/admin/permissions").status_code == 403


def test_security_dashboard_permission_is_for_pinned_or_security_team_admins_only():
    assert can({"role": "admin", "dept": "보안관제팀"}, "security.dashboard")
    assert can({"role": "admin", "dept": "경영지원팀", "pinned": True, "username": "admin"}, "security.dashboard")
    assert not can({"role": "admin", "dept": "경영지원팀"}, "security.dashboard")
    assert not can({"role": "manager", "dept": "보안관제팀"}, "security.dashboard")             # 역할이 admin 이 아니면(있을 수 없지만) 불가
    assert not can(None, "security.dashboard")


# =====================================================================================
# 보안 대시보드
# =====================================================================================
def write_log(app, events):
    """로그는 시간 순서대로 쌓이므로(읽는 쪽도 그 가정) 오래된 것부터 쓴다."""
    path = app.config["LOG_DIR"] / "security.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for e in sorted(events, key=lambda x: x["ts"]):
            f.write(json.dumps(e, ensure_ascii=False) + "\n")


def ev(ago_hours, event_type="authz_deny", decision="DENY", user="zz_x", ip="10.0.0.1", reason="r", **extra):
    ts = (datetime.now(timezone.utc) - timedelta(hours=ago_hours)).isoformat(timespec="seconds")
    return {"ts": ts, "event_type": event_type, "user": user, "role": "employee", "src_ip": ip, "method": "GET", "path": "/p",
            "decision": decision, "reason": reason, **extra}


def test_dashboard_is_only_for_security_team_and_pinned_admins(aapp, root, events):
    assert as_user(aapp, "zz_sec").get("/admin/audit").status_code == 200
    assert as_user(aapp, "zz_sec").get("/admin/audit/export.csv").status_code == 200
    for who in ("zz_adm", "zz_mgr", "zz_emp"):
        c = as_user(aapp, who)
        assert c.get("/admin/audit").status_code == 403 and c.get("/admin/audit/export.csv").status_code == 403, who
    anon = aapp.test_client()
    assert anon.get("/admin/audit").status_code == 303 and anon.get("/admin/audit/export.csv").status_code == 303
    denied = [e for e in events() if e["event_type"] == "authz_deny" and e.get("required") == "security.dashboard"]
    assert denied and denied[-1]["user"] == "zz_emp" or any(e["user"] == "zz_adm" for e in denied)


def test_dashboard_summary_threats_tops_and_chart(aapp, root):
    write_log(aapp, [
        ev(1, "login_failure", "DENY", "zz_victim", "9.9.9.9", "bad_password"),
        ev(1, "login_failure", "DENY", "zz_victim", "9.9.9.9", "bad_password"),
        ev(2, "login_failure", "DENY", "zz_other", "8.8.8.8", "bad_password"),
        ev(2, "account_locked", "BLOCK", "zz_victim", "9.9.9.9", "max_failures"),
        ev(3, "suspicious_input", "WARN", "zz_x", "7.7.7.7", "sqli"),
        ev(3, "suspicious_input", "WARN", "zz_x", "7.7.7.7", "xss"),
        ev(3, "suspicious_input", "WARN", "zz_x", "7.7.7.7", "sqli"),
        ev(4, "login_success", "ALLOW", "zz_ok", "1.1.1.1", "ok"),
        ev(5, "task_created", "INFO", "zz_ok", "1.1.1.1", "ok"),
        ev(30, "rate_limited", "BLOCK", "-", "6.6.6.6", "login_ip_limit"),                     # 24시간 밖
    ])
    html = as_user(aapp, "zz_sec").get("/admin/audit").get_data(as_text=True)
    assert "<h1>보안 대시보드</h1>" in html
    stat = {label: int(n) for n, label in __import__("re").findall(r'stat-n">(\d+)</span><span class="stat-l">([^<]+)<', html)}
    assert stat["정상 (INFO·ALLOW)"] >= 2 and stat["경고 (WARN·ERROR)"] == 3 and stat["차단 (BLOCK)"] == 1       # 정상에는 이 요청의 로그인 이벤트도 더해진다
    assert stat["거부 (DENY)"] >= 3                                                              # 로그인 실패 3건 + 이번 요청 자체의 이벤트(있다면)
    assert 'threat-n">3</span> 로그인 실패' in html and 'threat-n">1</span> 계정 잠금 발생' in html
    assert 'threat-n">3</span> 의심 입력' in html and 'threat-n">0</span> 속도 제한 차단' in html     # 24시간 밖의 것은 세지 않는다
    top_ips = html.split("의심 출발지 IP TOP 10")[1].split("</div>")[0]
    assert top_ips.index("9.9.9.9") < top_ips.index("7.7.7.7") < top_ips.index("8.8.8.8")        # 거부·차단·경고 많은 순(3, 3, 1 중 동률은 먼저 본 것)
    fails = html.split("로그인 실패 계정 TOP 10")[1].split("</div>")[0]
    assert fails.index("zz_victim") < fails.index("zz_other") and 'top-n">2</span>' in fails
    susp = html.split("의심 입력 유형")[1].split("</div>")[0]
    assert "sqli" in susp and 'top-n">2</span>' in susp and "xss" in susp
    assert "<svg" in html and "<rect" in html and html.count("<g>") == 25 or html.count("<g>") == 24


def test_dashboard_periods_change_what_is_counted(aapp, root):
    write_log(aapp, [ev(1, "csrf_fail", "BLOCK"), ev(30, "csrf_fail", "BLOCK"), ev(24 * 10, "csrf_fail", "BLOCK"), ev(24 * 40, "csrf_fail", "BLOCK")])
    c = as_user(aapp, "zz_sec")
    count = lambda q: __import__("re").search(r'threat-n">(\d+)</span> CSRF 차단', c.get("/admin/audit" + q).get_data(as_text=True)).group(1)   # noqa: E731
    assert (count(""), count("?period=24h"), count("?period=7d"), count("?period=30d")) == ("1", "1", "2", "3")
    assert "일별" in c.get("/admin/audit?period=7d").get_data(as_text=True) and "시간별" in c.get("/admin/audit").get_data(as_text=True)


def test_dashboard_filters_pagination_and_detail(aapp, root):
    write_log(aapp, [ev(0.01 * i, "task_created", "INFO", f"zz_u{i % 3}", "2.2.2.2", f"n{i}") for i in range(130)] +
              [ev(0.5, "authz_deny", "DENY", "zz_u1", "3.3.3.3", "special_reason", resource="x:1")])
    c = as_user(aapp, "zz_sec")
    page1 = c.get("/admin/audit?type=task_created&limit=50").get_data(as_text=True)
    assert page1.count("<tr>") == 51 and "다음" in page1 and "이전" not in page1
    page3 = c.get("/admin/audit?type=task_created&limit=50&page=3").get_data(as_text=True)
    assert page3.count("<tr>") == 31 and "이전" in page3 and "다음" not in page3                       # 130건 = 50 + 50 + 30
    assert "special_reason" not in page1
    one = c.get("/admin/audit?type=authz_deny&user=zz_u1&ip=3.3.3.3&decision=DENY").get_data(as_text=True)
    assert one.count("<tr>") == 2 and "special_reason" in one
    assert "<pre class=\"raw\">" in one and "&#34;resource&#34;: &#34;x:1&#34;" in one                  # 상세에 기록된 전체 내용
    assert "조건에 맞는 이벤트가 없습니다" in c.get("/admin/audit?ip=4.4.4.4").get_data(as_text=True)


def test_dashboard_escapes_attacker_controlled_values_everywhere(aapp, root):
    evil = "<script>alert(1)</script>"
    write_log(aapp, [ev(1, "suspicious_input", "WARN", "zz_" + "x", "5.5.5.5", evil, note=evil),
                     ev(1, "login_failure", "DENY", evil[:32], "5.5.5.5", "bad_password")])
    html = as_user(aapp, "zz_sec").get("/admin/audit").get_data(as_text=True)
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html


def test_dashboard_robustness_with_empty_junk_and_naive_log_lines(aapp, root):
    c = as_user(aapp, "zz_sec")
    assert c.get("/admin/audit?period=30d").status_code == 200                                  # 거의 빈 로그에서도 오류 없음
    path = aapp.config["LOG_DIR"] / "security.jsonl"
    with open(path, "a", encoding="utf-8") as f:
        f.write("not json\n[]\n{\"ts\": \"bad\"}\n{\"ts\": \"%s\", \"event_type\": \"naive_ts\", \"decision\": \"INFO\"}\n" % datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
    html = c.get("/admin/audit").get_data(as_text=True)
    assert html and "naive_ts" in html


def test_dashboard_notice_when_log_does_not_cover_the_period(aapp, root):
    c = as_user(aapp, "zz_sec")
    assert "로그가 선택한 기간 전체를 덮지 않습니다" in c.get("/admin/audit?period=30d").get_data(as_text=True)      # 로그가 방금 생긴 것뿐
    write_log(aapp, [ev(24 * 29.5, "old", "INFO"), ev(1, "new", "INFO")])
    assert "덮지 않습니다" not in c.get("/admin/audit?period=30d").get_data(as_text=True)


def test_dashboard_lists_currently_locked_accounts(aapp, root):
    sql(root, "UPDATE users SET locked_until = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE username='zz_emp3'")
    html = as_user(aapp, "zz_sec").get("/admin/audit").get_data(as_text=True)
    assert "현재 잠긴 계정" in html.split("현재 잠긴 계정")[0] + "현재 잠긴 계정" and "zz_emp3" in html.split("현재 잠긴 계정")[1].split("</div>")[0]


def test_audit_view_and_export_are_themselves_logged(aapp, root, events):
    c = as_user(aapp, "zz_sec")
    c.get("/admin/audit?period=7d")
    c.get("/admin/audit/export.csv?period=7d&type=authz_deny")
    kinds = {(e["reason"], e.get("period")) for e in events() if e["event_type"] == "admin_action" and e["user"] == "zz_sec"}
    assert ("audit_view", "7d") in kinds and ("security_export", "7d") in kinds


# ---------- CSV ----------
def parse_csv(response):
    text = response.get_data(as_text=True)
    assert text.startswith("﻿")
    return list(csv.reader(io.StringIO(text.lstrip("﻿"))))


def test_csv_export_content_headers_and_filters(aapp, root):
    write_log(aapp, [ev(1, "authz_deny", "DENY", "zz_a", "1.1.1.1", "r1"), ev(1, "task_created", "INFO", "zz_b", "2.2.2.2", "r2"),
                     ev(1, "authz_deny", "DENY", "zz_c", "3.3.3.3", "r3", note="k=v")])
    c = as_user(aapp, "zz_sec")
    r = c.get("/admin/audit/export.csv?type=authz_deny&period=24h")
    assert r.status_code == 200 and r.mimetype == "text/csv"
    assert r.headers["Content-Disposition"].startswith('attachment; filename="security-events-') and r.headers["Content-Disposition"].endswith('.csv"')
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    rows = parse_csv(r)
    assert rows[0] == list(__import__("app.admin", fromlist=["EXPORT_COLUMNS"]).EXPORT_COLUMNS)
    body = rows[1:]
    assert {row[2] for row in body if row[1] == "authz_deny"} >= {"zz_a", "zz_c"} and all(row[1] == "authz_deny" for row in body)
    assert any("note=k=v" in row[9] for row in body)
    only_ip = parse_csv(c.get("/admin/audit/export.csv?ip=2.2.2.2"))
    assert [row[2] for row in only_ip[1:]] == ["zz_b"]
    assert len(parse_csv(c.get("/admin/audit/export.csv?ip=4.4.4.4"))) == 1                          # 머리글만


def test_csv_export_neutralises_formula_injection(aapp, root):
    write_log(aapp, [ev(1, "evil", "DENY", "=cmd|' /C calc'!A0", "1.1.1.1", "@SUM(1+1)", note="+1+1"),
                     ev(1, "evil", "DENY", "-2+3", "1.1.1.1", "\tTAB")])
    rows = parse_csv(as_user(aapp, "zz_sec").get("/admin/audit/export.csv?type=evil"))
    cells = [cell for row in rows[1:] for cell in row]
    assert not any(cell[:1] in ("=", "+", "-", "@", "\t") for cell in cells)
    assert "'=cmd|' /C calc'!A0" in cells and "'@SUM(1+1)" in cells and "'-2+3" in cells


def test_csv_export_row_cap_and_invalid_filters(aapp, root, monkeypatch):
    monkeypatch.setattr(audit, "MAX_MATCH", 25)
    write_log(aapp, [ev(0.001 * i, "bulk", "INFO", "zz_b", "2.2.2.2", f"r{i}") for i in range(60)])
    c = as_user(aapp, "zz_sec")
    assert len(parse_csv(c.get("/admin/audit/export.csv?type=bulk"))) == 26                           # 머리글 + 최신 25건
    for q in ("type=Bad-Type", "decision=EVIL", "ip=1.2.3.4;x", "user=a b", "period=1y"):
        assert c.get("/admin/audit/export.csv?" + q).status_code == 400, q


# ---------- audit.scan 단위 ----------
def put(tmp_path, lines):
    (tmp_path / "security.jsonl").write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")


def test_scan_counts_slots_and_stops_at_the_period_start(tmp_path):
    now = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
    mk = lambda h, **k: {**ev(0), "ts": (now - timedelta(hours=h)).isoformat(), **k}                      # noqa: E731
    put(tmp_path, [mk(100), mk(30), mk(5, decision="BLOCK"), mk(2, decision="INFO"), mk(0.5, decision="ALLOW")])
    r = audit.scan(tmp_path, 24, now=now)
    assert r["scanned"] == 3 and r["reached_start"] and r["hourly"] and len(r["slots"]) in (24, 25)
    assert r["decisions"] == {"BLOCK": 1, "INFO": 1, "ALLOW": 1}
    wide = audit.scan(tmp_path, 720, now=now)
    assert wide["scanned"] == 5 and not wide["hourly"] and len(wide["slots"]) in (30, 31) and not wide["reached_start"]


def test_chart_geometry_is_consistent(tmp_path):
    now = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
    lines = [{**ev(0), "ts": (now - timedelta(hours=1)).isoformat(), "decision": d} for d in ("INFO", "INFO", "DENY", "BLOCK")]
    put(tmp_path, lines)
    ch = audit.chart(audit.scan(tmp_path, 24, now=now))
    assert ch["peak"] == 4 and len(ch["bars"]) in (24, 25)
    busy = [b for b in ch["bars"] if b["total"]][0]
    assert sum(r["h"] for r in busy["rects"]) == pytest.approx(ch["plot"], abs=0.5)
    assert [r["cls"] for r in busy["rects"]] == ["ok", "deny", "block"]
    assert all(0 <= r["y"] and r["y"] + r["h"] <= ch["plot"] + 0.1 for b in ch["bars"] for r in b["rects"])
    empty = audit.chart(audit.scan(tmp_path / "nothing", 24, now=now))
    assert empty["peak"] == 1 and all(not b["rects"] for b in empty["bars"])


@pytest.mark.parametrize("raw,expected", [("=1+1", "'=1+1"), ("+1", "'+1"), ("-1", "'-1"), ("@a", "'@a"), ("\tx", "'\tx"), ("\rx", "'\rx"),
                                          ("safe", "safe"), ("1=1", "1=1"), ("", ""), (5, "5")])
def test_csv_cell_escaping(raw, expected):
    assert audit.csv_cell(raw) == expected


# ---------- 화면 점검(메뉴) ----------
def test_security_dashboard_menu_entry_follows_the_permission(aapp, root):
    assert ">보안 대시보드</a>" in as_user(aapp, "zz_sec").get("/admin/overview").get_data(as_text=True)
    assert ">보안 대시보드</a>" not in as_user(aapp, "zz_adm").get("/admin/overview").get_data(as_text=True)
    assert "보안 대시보드 열기" in as_user(aapp, "zz_sec").get("/admin/overview").get_data(as_text=True)
    assert "보안 대시보드 열기" not in as_user(aapp, "zz_adm").get("/admin/overview").get_data(as_text=True)
    mgr_menu = as_user(aapp, "zz_mgr").get("/").get_data(as_text=True)
    assert ">재무 보고</a>" in mgr_menu and ">기밀 문서함</a>" in mgr_menu
    assert ">재무 보고</a>" not in as_user(aapp, "zz_emp").get("/").get_data(as_text=True)
