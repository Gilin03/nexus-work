"""ERP(급여·재무·경비)와 전자결재 통합 테스트. Docker MySQL(nexus_test) 필요, 접속 불가면 skip.
부서: A팀(zz_emp, zz_emp2, zz_mgr) / B팀(zz_emp3, zz_mgrb) / 관리팀(zz_adm)"""
import pytest

from support import PW_HASH, as_user, post, sql, uid


# ---------- 도우미 ----------
def add_payroll(root, user, month, base, bonus=0):
    with root.cursor() as cur:
        cur.execute("INSERT INTO payroll(user_id,pay_month,base_salary,bonus) VALUES(%s,%s,%s,%s)",
                    (uid(root, user), month, base, bonus))
        return cur.lastrowid


def add_expense(root, user, title="zz_경비", amount=10000, status="draft"):
    with root.cursor() as cur:
        cur.execute("INSERT INTO expenses(user_id,title,amount,status) VALUES(%s,%s,%s,%s)",
                    (uid(root, user), title, amount, status))
        return cur.lastrowid


def add_approval(root, requester, approvers, title="zz_결재", status="pending", expense_id=None, current_step=1):
    """결재 문서와 결재선을 직접 만든다. current_step 앞 단계는 승인 완료, 그 단계는 pending, 뒤는 waiting."""
    with root.cursor() as cur:
        cur.execute("INSERT INTO approvals(title,body,requester_id,expense_id,status,current_step) VALUES(%s,%s,%s,%s,%s,%s)",
                    (title, "본문", uid(root, requester), expense_id, status, current_step))
        aid = cur.lastrowid
        for n, name in enumerate(approvers, start=1):
            if status != "pending":
                st = "skipped"
            else:
                st = "approved" if n < current_step else "pending" if n == current_step else "waiting"
            cur.execute("INSERT INTO approval_steps(approval_id,step_no,approver_id,status) VALUES(%s,%s,%s,%s)",
                        (aid, n, uid(root, name), st))
        return aid


def add_report(root, title="zz_보고", body="REPORT-BODY"):
    with root.cursor() as cur:
        cur.execute("INSERT INTO financial_reports(report_month,title,body) VALUES('2026-09',%s,%s)", (title, body))
        return cur.lastrowid


def expense_status(root, expense_id):
    return sql(root, "SELECT status FROM expenses WHERE id=%s", (expense_id,))[0][0]


def approval_state(root, approval_id):
    """(문서 상태, 현재 단계, 종결 시각 유무)"""
    return sql(root, "SELECT status, current_step, decided_at IS NOT NULL FROM approvals WHERE id=%s", (approval_id,))[0]


def steps_of(root, approval_id):
    """[(단계, 결재자, 상태, 사유)]"""
    return list(sql(root, "SELECT s.step_no, u.username, s.status, s.reason FROM approval_steps s "
                          "JOIN users u ON u.id = s.approver_id WHERE s.approval_id=%s ORDER BY s.step_no", (approval_id,)))


def chain(root, *names):
    """결재선 폼 필드: 앞에서부터 1차, 2차 … 결재자"""
    return {f"approver_{n}": str(uid(root, name)) for n, name in enumerate(names, start=1)}


def new_expense(client, title="zz_회식비", amount="50000", **extra):
    return post(client, "/expenses/new", title=title, amount=amount, **extra)


def submit(client, root, expense_id, *approvers):
    return post(client, f"/expenses/{expense_id}/submit", **chain(root, *approvers))


def decide(client, approval_id, decision, **extra):
    return post(client, f"/approvals/{approval_id}/decide", decision=decision, **extra)


def withdraw(client, approval_id):
    return post(client, f"/approvals/{approval_id}/withdraw")


# ---------- 로그인 필수 ----------
@pytest.mark.parametrize("path", ["/payroll", "/payroll/1", "/finance", "/finance/1", "/expenses", "/expenses/new",
                                  "/expenses/1", "/approvals", "/approvals/new", "/approvals/1"])
def test_every_erp_page_requires_login(aapp, path):
    r = aapp.test_client().get(path)
    assert r.status_code == 303 and "/login" in r.headers["Location"]


@pytest.mark.parametrize("path", ["/expenses/new", "/expenses/1/submit", "/approvals/new", "/approvals/1/decide",
                                  "/approvals/1/withdraw"])
def test_anonymous_posts_are_blocked(aapp, path):
    assert aapp.test_client().post(path, data={"decision": "approve"}).status_code == 403


# ---------- 급여(기밀) ----------
def seed_payroll(root):
    return {
        "emp": add_payroll(root, "zz_emp", "2026-09", 3_111_111),
        "emp2": add_payroll(root, "zz_emp2", "2026-09", 3_222_222),
        "emp3": add_payroll(root, "zz_emp3", "2026-09", 3_333_333),
        "mgr": add_payroll(root, "zz_mgr", "2026-09", 4_444_444),
        "mgrb": add_payroll(root, "zz_mgrb", "2026-09", 4_555_555),
        "adm": add_payroll(root, "zz_adm", "2026-09", 5_666_666),
    }


def amounts_in(html):
    return {n for n in ("3,111,111", "3,222,222", "3,333,333", "4,444,444", "4,555,555", "5,666,666") if n in html}


def test_employee_sees_only_own_payroll(aapp, root):
    seed_payroll(root)
    html = as_user(aapp, "zz_emp").get("/payroll").get_data(as_text=True)
    assert amounts_in(html) == {"3,111,111"}


def test_manager_sees_only_own_team_payroll(aapp, root):
    seed_payroll(root)
    a = amounts_in(as_user(aapp, "zz_mgr").get("/payroll").get_data(as_text=True))
    b = amounts_in(as_user(aapp, "zz_mgrb").get("/payroll").get_data(as_text=True))
    assert a == {"3,111,111", "3,222,222", "4,444,444"}      # A팀 전원(팀장 본인 포함), B팀·관리팀은 제외
    assert b == {"3,333,333", "4,555,555"}


def test_admin_sees_all_payroll(aapp, root):
    seed_payroll(root)
    assert len(amounts_in(as_user(aapp, "zz_adm").get("/payroll").get_data(as_text=True))) == 6


def test_payroll_detail_idor_matrix(aapp, root, events):
    ids = seed_payroll(root)
    emp = as_user(aapp, "zz_emp")
    assert "3,111,111" in emp.get(f"/payroll/{ids['emp']}").get_data(as_text=True)
    for other in ("emp2", "emp3", "mgr", "adm"):                  # 같은 팀 동료·팀장·관리자 것도 직원은 볼 수 없다
        r = emp.get(f"/payroll/{ids[other]}")
        assert r.status_code == 403 and "3,222,222" not in r.get_data(as_text=True)
    mgr = as_user(aapp, "zz_mgr")
    assert mgr.get(f"/payroll/{ids['emp2']}").status_code == 200   # 같은 팀
    assert mgr.get(f"/payroll/{ids['emp3']}").status_code == 403   # 다른 팀
    assert mgr.get(f"/payroll/{ids['adm']}").status_code == 403
    adm = as_user(aapp, "zz_adm")
    assert all(adm.get(f"/payroll/{i}").status_code == 200 for i in ids.values())
    deny = [e for e in events() if e["event_type"] == "authz_deny" and e["reason"] == "out_of_scope"]
    assert deny and deny[0]["user"] == "zz_emp" and deny[0]["resource"].startswith("payroll:")
    assert any(e["event_type"] == "confidential_access" and e["user"] == "zz_adm" for e in events())


@pytest.mark.parametrize("path", ["/payroll/999999", "/payroll/abc", "/payroll/-1", "/payroll/1%27%20OR%201=1"])
def test_bad_payroll_ids_are_404(aapp, path):
    assert as_user(aapp, "zz_adm").get(path).status_code == 404


# ---------- 재무 보고(기밀) ----------
def test_finance_is_manager_and_admin_only(aapp, root, events):
    rid = add_report(root)
    emp = as_user(aapp, "zz_emp")
    for path in ("/finance", f"/finance/{rid}"):
        r = emp.get(path)
        assert r.status_code == 403 and "REPORT-BODY" not in r.get_data(as_text=True)
    assert any(e["event_type"] == "authz_deny" and e["reason"] == "insufficient_role" for e in events())
    for name in ("zz_mgr", "zz_mgrb", "zz_adm"):
        c = as_user(aapp, name)
        assert "zz_보고" in c.get("/finance").get_data(as_text=True)
        assert "REPORT-BODY" in c.get(f"/finance/{rid}").get_data(as_text=True)
    assert as_user(aapp, "zz_adm").get("/finance/999999").status_code == 404


def test_nav_shows_finance_only_to_privileged_roles(aapp):
    assert "재무" not in as_user(aapp, "zz_emp").get("/").get_data(as_text=True).replace("재무 보고", "")
    assert "재무" in as_user(aapp, "zz_mgr").get("/").get_data(as_text=True)


# ---------- 경비: 등록·검증 ----------
def test_create_expense_always_starts_as_draft_and_ignores_extra_fields(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = new_expense(c, status="approved", user_id=str(uid(root, "zz_emp2")), id="1")
    assert r.status_code == 303
    row = sql(root, "SELECT user_id, status, amount FROM expenses WHERE title='zz_회식비'")[0]
    assert row == (uid(root, "zz_emp"), "draft", 50000)     # 상태·소유자를 폼으로 바꿀 수 없다
    assert "임시저장" in c.get(r.headers["Location"]).get_data(as_text=True)


@pytest.mark.parametrize("amount", ["0", "-5", "abc", "1.5", "1e3", " 5", "5 ", "", "٣", "100000001", "99999999999999999999"])
def test_expense_amount_validation(aapp, root, events, amount):
    r = new_expense(as_user(aapp, "zz_emp"), amount=amount)
    assert r.status_code == 400
    assert sql(root, "SELECT COUNT(*) FROM expenses WHERE title='zz_회식비'")[0][0] == 0
    assert any(e["event_type"] == "input_rejected" and e["field"] == "expense" for e in events())


def test_expense_amount_boundaries_and_title_rules(aapp, root):
    c = as_user(aapp, "zz_emp")
    assert new_expense(c, "zz_최소", "1").status_code == 303
    assert new_expense(c, "zz_최대", "100000000").status_code == 303
    for bad in ("", "a" * 121, "제\n목", "제\x00목"):
        assert new_expense(c, bad, "100").status_code == 400


def test_expense_text_is_escaped_and_sql_is_literal(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = new_expense(c, "zz_<script>alert(1)</script>'); DROP TABLE expenses; --", "100")
    html = c.get(r.headers["Location"]).get_data(as_text=True)
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html and "DROP TABLE expenses" in html
    assert sql(root, "SELECT COUNT(*) FROM expenses")[0][0] >= 1


# ---------- 경비: 본인·팀 범위 ----------
def test_expense_list_scope(aapp, root):
    add_expense(root, "zz_emp", "zz_emp의경비")
    add_expense(root, "zz_emp2", "zz_emp2의경비")
    add_expense(root, "zz_emp3", "zz_emp3의경비")
    add_expense(root, "zz_mgr", "zz_mgr의경비")

    def titles(name):
        html = as_user(aapp, name).get("/expenses").get_data(as_text=True)
        return {n for n in ("zz_emp의경비", "zz_emp2의경비", "zz_emp3의경비", "zz_mgr의경비") if n in html}
    assert titles("zz_emp") == {"zz_emp의경비"}
    assert titles("zz_emp3") == {"zz_emp3의경비"}
    assert titles("zz_mgr") == {"zz_emp의경비", "zz_emp2의경비", "zz_mgr의경비"}       # A팀 전체
    assert titles("zz_mgrb") == {"zz_emp3의경비"}
    assert len(titles("zz_adm")) == 4


def test_expense_detail_idor_matrix(aapp, root, events):
    mine = add_expense(root, "zz_emp", "zz_내경비")
    r = as_user(aapp, "zz_emp2").get(f"/expenses/{mine}")               # 같은 팀 동료 직원은 불가
    assert r.status_code == 403 and "zz_내경비" not in r.get_data(as_text=True)
    assert as_user(aapp, "zz_emp3").get(f"/expenses/{mine}").status_code == 403
    assert as_user(aapp, "zz_mgrb").get(f"/expenses/{mine}").status_code == 403   # 다른 팀 팀장
    assert as_user(aapp, "zz_mgr").get(f"/expenses/{mine}").status_code == 200    # 같은 팀 팀장
    assert as_user(aapp, "zz_adm").get(f"/expenses/{mine}").status_code == 200
    assert as_user(aapp, "zz_emp").get(f"/expenses/{mine}").status_code == 200
    assert any(e["event_type"] == "authz_deny" and e["resource"] == f"expense:{mine}" for e in events())
    for path in ("/expenses/999999", "/expenses/abc", "/expenses/-1"):
        assert as_user(aapp, "zz_adm").get(path).status_code == 404


# ---------- 경비 제출: 상신자가 결재선(순서)을 정한다 ----------
def test_submit_uses_the_chain_chosen_by_the_requester(aapp, root, events):
    e = add_expense(root, "zz_emp", "zz_제출", 12345)
    c = as_user(aapp, "zz_emp")
    r = submit(c, root, e, "zz_mgr")
    assert r.status_code == 303 and "/approvals/" in r.headers["Location"]
    assert expense_status(root, e) == "submitted"
    aid = int(r.headers["Location"].rsplit("/", 1)[1])
    assert approval_state(root, aid) == ("pending", 1, 0)
    assert steps_of(root, aid) == [(1, "zz_mgr", "pending", None)]
    assert "결재 중" in c.get(f"/expenses/{e}").get_data(as_text=True)
    ev = [x for x in events() if x["event_type"] == "expense_submitted"][-1]
    assert ev["steps"] == 1 and ev["approval_id"] == aid


@pytest.mark.parametrize("names", [("zz_mgr", "zz_adm"), ("zz_adm", "zz_mgr"), ("zz_mgrb", "zz_mgr", "zz_adm")])
def test_chain_order_is_exactly_what_the_requester_chose(aapp, root, names):
    e = add_expense(root, "zz_emp", "zz_순서")
    r = submit(as_user(aapp, "zz_emp"), root, e, *names)
    assert r.status_code == 303
    aid = int(r.headers["Location"].rsplit("/", 1)[1])
    steps = steps_of(root, aid)
    assert [s[1] for s in steps] == list(names)                              # 고른 순서 그대로
    assert [s[2] for s in steps] == ["pending"] + ["waiting"] * (len(names) - 1)   # 첫 결재자만 차례


def test_blank_slots_are_skipped_but_order_is_kept(aapp, root):
    e = add_expense(root, "zz_emp", "zz_빈칸")
    form = {"approver_1": "", "approver_2": str(uid(root, "zz_adm")), "approver_3": "", "approver_4": str(uid(root, "zz_mgr"))}
    r = post(as_user(aapp, "zz_emp"), f"/expenses/{e}/submit", **form)
    assert r.status_code == 303
    assert [s[1] for s in steps_of(root, int(r.headers["Location"].rsplit("/", 1)[1]))] == ["zz_adm", "zz_mgr"]


def test_sixth_approver_slot_is_ignored(aapp, root):
    e = add_expense(root, "zz_emp", "zz_여섯째")
    form = chain(root, "zz_mgr", "zz_adm")
    form["approver_6"] = str(uid(root, "zz_mgrb"))
    r = post(as_user(aapp, "zz_emp"), f"/expenses/{e}/submit", **form)
    assert [s[1] for s in steps_of(root, int(r.headers["Location"].rsplit("/", 1)[1]))] == ["zz_mgr", "zz_adm"]


@pytest.mark.parametrize("fields,message", [
    ({}, "한 명 이상"),
    ({"approver_1": ""}, "한 명 이상"),
    ({"approver_1": "{emp2}"}, "팀장 또는 관리자"),                      # 일반 직원은 결재자가 될 수 없다
    ({"approver_1": "{emp}"}, "본인을 결재자로"),                        # 본인 지정 불가
    ({"approver_1": "{mgr}", "approver_2": "{mgr}"}, "두 번 선택"),     # 중복 불가
    ({"approver_1": "{mgr}", "approver_2": "{emp}"}, "본인을 결재자로"),
    ({"approver_1": "999999"}, "선택할 수 없는"),                        # 없는 사용자
    ({"approver_1": "abc"}, "선택할 수 없는"),
    ({"approver_1": "-1"}, "선택할 수 없는"),
    ({"approver_1": "{mgr} OR 1=1"}, "선택할 수 없는"),
    ({"approver_1": "{mgr}", "approver_2": "{emp3}"}, "팀장 또는 관리자"),   # 둘째 칸에 일반 직원
])
def test_invalid_chains_are_rejected_without_side_effects(aapp, root, events, fields, message):
    ids = {"emp": uid(root, "zz_emp"), "emp2": uid(root, "zz_emp2"), "emp3": uid(root, "zz_emp3"), "mgr": uid(root, "zz_mgr")}
    fields = {k: v.format(**ids) for k, v in fields.items()}
    e = add_expense(root, "zz_emp", "zz_잘못된결재선")
    r = post(as_user(aapp, "zz_emp"), f"/expenses/{e}/submit", **fields)
    assert r.status_code == 400 and message in r.get_data(as_text=True)
    assert expense_status(root, e) == "draft"
    assert sql(root, "SELECT COUNT(*) FROM approvals WHERE expense_id=%s", (e,))[0][0] == 0
    assert any(x["event_type"] == "input_rejected" and x["field"] == "approvers" for x in events())


def test_submit_form_lists_only_managers_and_admins_except_self(aapp, root):
    e = add_expense(root, "zz_mgr", "zz_후보")
    html = as_user(aapp, "zz_mgr").get(f"/expenses/{e}").get_data(as_text=True)
    assert f'value="{uid(root, "zz_mgrb")}"' in html and f'value="{uid(root, "zz_adm")}"' in html
    assert f'value="{uid(root, "zz_mgr")}"' not in html                      # 본인 제외
    assert f'value="{uid(root, "zz_emp")}"' not in html                      # 일반 직원 제외
    assert html.count("<select") == 5                                        # 최대 5단계


def test_admin_can_choose_another_admin_but_not_self(aapp, root):
    sql(root, "INSERT INTO users(username,password_hash,role,display_name,dept) VALUES('zz_adm2',%s,'admin','a2','관리팀')", (PW_HASH,))
    e = add_expense(root, "zz_adm", "zz_관리자경비")
    c = as_user(aapp, "zz_adm")
    assert submit(c, root, e, "zz_adm").status_code == 400
    assert submit(c, root, e, "zz_adm2").status_code == 303


def test_only_the_owner_can_submit(aapp, root, events):
    e = add_expense(root, "zz_emp", "zz_남의경비")
    for name in ("zz_emp2", "zz_mgr", "zz_adm"):             # 같은 팀 동료·팀장·관리자도 남의 경비는 제출 불가
        assert submit(as_user(aapp, name), root, e, "zz_adm" if name != "zz_adm" else "zz_mgr").status_code == 403
    assert expense_status(root, e) == "draft"
    assert sql(root, "SELECT COUNT(*) FROM approvals WHERE expense_id=%s", (e,))[0][0] == 0
    assert any(x["event_type"] == "authz_deny" and x["reason"] == "not_owner" for x in events())


def test_double_submit_is_a_conflict(aapp, root, events):
    e = add_expense(root, "zz_emp", "zz_중복제출")
    c = as_user(aapp, "zz_emp")
    assert submit(c, root, e, "zz_mgr").status_code == 303
    assert submit(c, root, e, "zz_mgr").status_code == 409
    assert sql(root, "SELECT COUNT(*) FROM approvals WHERE expense_id=%s", (e,))[0][0] == 1
    assert any(x["event_type"] == "expense_invalid_transition" for x in events())


@pytest.mark.parametrize("status", ["submitted", "approved", "rejected"])
def test_only_drafts_can_be_submitted(aapp, root, status):
    e = add_expense(root, "zz_emp", "zz_상태", status=status)
    assert submit(as_user(aapp, "zz_emp"), root, e, "zz_mgr").status_code == 409
    assert expense_status(root, e) == status


def test_submit_requires_csrf_and_post(aapp, root):
    e = add_expense(root, "zz_emp", "zz_csrf")
    c = as_user(aapp, "zz_emp")
    assert c.post(f"/expenses/{e}/submit", data=chain(root, "zz_mgr")).status_code == 403
    assert c.get(f"/expenses/{e}/submit").status_code == 405
    assert expense_status(root, e) == "draft"


# ---------- 전자결재: 상신·조회 ----------
def test_create_general_approval_with_a_chain(aapp, root, events):
    c = as_user(aapp, "zz_emp")
    r = post(c, "/approvals/new", title="zz_연차 신청", body="<b>10월 연차</b>", **chain(root, "zz_mgr", "zz_adm"))
    assert r.status_code == 303
    html = c.get(r.headers["Location"]).get_data(as_text=True)
    assert "zz_연차 신청" in html and "&lt;b&gt;10월 연차&lt;/b&gt;" in html and "<b>10월" not in html
    aid = int(r.headers["Location"].rsplit("/", 1)[1])
    assert steps_of(root, aid) == [(1, "zz_mgr", "pending", None), (2, "zz_adm", "waiting", None)]
    assert sql(root, "SELECT requester_id, expense_id FROM approvals WHERE id=%s", (aid,))[0] == (uid(root, "zz_emp"), None)
    assert any(e["event_type"] == "approval_created" and e["steps"] == 2 for e in events())


def test_new_approval_form_lists_candidates(aapp, root):
    html = as_user(aapp, "zz_emp").get("/approvals/new").get_data(as_text=True)
    assert f'value="{uid(root, "zz_mgr")}"' in html and f'value="{uid(root, "zz_emp2")}"' not in html


@pytest.mark.parametrize("title,body", [("", "내용"), ("a" * 201, "내용"), ("제목", ""), ("제목", "a" * 2001), ("제\n목", "내용"), ("제목", "널\x00")])
def test_approval_form_validation(aapp, root, title, body):
    r = post(as_user(aapp, "zz_emp"), "/approvals/new", title=title, body=body, **chain(root, "zz_mgr"))
    assert r.status_code == 400
    assert sql(root, "SELECT COUNT(*) FROM approvals")[0][0] == 0


def test_approval_without_a_chain_is_rejected(aapp, root):
    assert post(as_user(aapp, "zz_emp"), "/approvals/new", title="제목", body="내용").status_code == 400
    assert sql(root, "SELECT COUNT(*) FROM approvals")[0][0] == 0


def test_approval_visibility_includes_every_approver_in_the_chain(aapp, root, events):
    a = add_approval(root, "zz_emp", ["zz_mgr", "zz_mgrb"], "zz_비밀결재")
    for name, code in (("zz_emp", 200), ("zz_mgr", 200), ("zz_mgrb", 200), ("zz_adm", 200),
                       ("zz_emp2", 403), ("zz_emp3", 403)):
        r = as_user(aapp, name).get(f"/approvals/{a}")
        assert r.status_code == code, name
        if code == 403:
            assert "zz_비밀결재" not in r.get_data(as_text=True)
    assert any(e["event_type"] == "authz_deny" and e["reason"] == "not_party" for e in events())
    assert as_user(aapp, "zz_adm").get("/approvals/999999").status_code == 404
    assert as_user(aapp, "zz_adm").get("/approvals/abc").status_code == 404


def test_approval_list_scope_and_whose_turn_marker(aapp, root):
    add_approval(root, "zz_emp", ["zz_mgr", "zz_adm"], "zz_결재A")
    add_approval(root, "zz_emp3", ["zz_mgrb"], "zz_결재B")

    def view(name):
        html = as_user(aapp, name).get("/approvals").get_data(as_text=True)
        return {t for t in ("zz_결재A", "zz_결재B") if t in html}, html
    assert view("zz_emp")[0] == {"zz_결재A"} and "결재 필요" not in view("zz_emp")[1]
    assert view("zz_emp2")[0] == set()
    assert view("zz_mgr")[0] == {"zz_결재A"} and "결재 필요" in view("zz_mgr")[1]
    assert view("zz_adm")[0] == {"zz_결재A", "zz_결재B"} and "결재 필요" not in view("zz_adm")[1]   # 2차 결재자는 차례 전
    assert "1 / 2단계" in view("zz_emp")[1]


# ---------- 순차 결재 ----------
def test_sequential_approval_passes_the_turn_and_finishes_the_expense(aapp, root, events):
    e = add_expense(root, "zz_emp", "zz_순차", status="submitted")
    a = add_approval(root, "zz_emp", ["zz_mgr", "zz_adm"], expense_id=e)
    mgr, adm = as_user(aapp, "zz_mgr"), as_user(aapp, "zz_adm")

    assert decide(adm, a, "approve").status_code == 403                        # 2차 결재자는 1차가 끝나기 전에 처리할 수 없다
    assert steps_of(root, a)[1][2] == "waiting" and approval_state(root, a) == ("pending", 1, 0)
    assert any(x["event_type"] == "authz_deny" and x["reason"] == "not_your_turn" and x["user"] == "zz_adm" for x in events())

    assert decide(mgr, a, "approve").status_code == 303                        # 1차 승인 → 차례가 2차로
    assert [s[2] for s in steps_of(root, a)] == ["approved", "pending"]
    assert approval_state(root, a) == ("pending", 2, 0) and expense_status(root, e) == "submitted"
    assert 'name="decision"' not in mgr.get(f"/approvals/{a}").get_data(as_text=True)   # 1차는 더 처리할 수 없다
    assert 'name="decision"' in adm.get(f"/approvals/{a}").get_data(as_text=True)

    assert decide(adm, a, "approve").status_code == 303                        # 마지막 승인 → 문서·경비 승인
    assert approval_state(root, a) == ("approved", 2, 1) and expense_status(root, e) == "approved"
    assert [s[2] for s in steps_of(root, a)] == ["approved", "approved"]
    done = [x for x in events() if x["event_type"] == "approval_decided"]
    assert [(x["user"], x["step"]) for x in done] == [("zz_mgr", 1), ("zz_adm", 2)]


def test_reject_at_first_step_skips_the_rest_and_keeps_the_reason(aapp, root):
    e = add_expense(root, "zz_emp", "zz_반려1", status="submitted")
    a = add_approval(root, "zz_emp", ["zz_mgr", "zz_adm"], expense_id=e)
    assert decide(as_user(aapp, "zz_mgr"), a, "reject", reason="영수증이 없습니다.\n<b>다시</b> 제출하세요").status_code == 303
    assert steps_of(root, a) == [(1, "zz_mgr", "rejected", "영수증이 없습니다.\n<b>다시</b> 제출하세요"), (2, "zz_adm", "skipped", None)]
    assert approval_state(root, a) == ("rejected", 1, 1) and expense_status(root, e) == "rejected"
    html = as_user(aapp, "zz_emp").get(f"/approvals/{a}").get_data(as_text=True)    # 상신자가 사유를 본다(이스케이프됨)
    assert "영수증이 없습니다." in html and "&lt;b&gt;다시&lt;/b&gt;" in html and "<b>다시" not in html


def test_reject_at_second_step_keeps_first_approval(aapp, root):
    e = add_expense(root, "zz_emp", "zz_반려2", status="submitted")
    a = add_approval(root, "zz_emp", ["zz_mgr", "zz_adm"], expense_id=e, current_step=2)
    assert decide(as_user(aapp, "zz_adm"), a, "reject", reason="금액 초과").status_code == 303
    assert steps_of(root, a) == [(1, "zz_mgr", "approved", None), (2, "zz_adm", "rejected", "금액 초과")]
    assert approval_state(root, a)[0] == "rejected" and expense_status(root, e) == "rejected"


@pytest.mark.parametrize("reason", [None, "", "   ", "\n\t ", "a" * 501, "널\x00문자", "제어\x07문자"])
def test_rejection_needs_a_valid_reason(aapp, root, events, reason):
    a = add_approval(root, "zz_emp", ["zz_mgr"])
    extra = {} if reason is None else {"reason": reason}
    r = decide(as_user(aapp, "zz_mgr"), a, "reject", **extra)
    assert r.status_code == 400 and "반려 사유" in r.get_data(as_text=True)
    assert steps_of(root, a) == [(1, "zz_mgr", "pending", None)] and approval_state(root, a)[0] == "pending"
    assert any(x["event_type"] == "input_rejected" and x["field"] == "reason" for x in events())


def test_rejection_reason_boundaries_and_approve_ignores_reason(aapp, root):
    a1 = add_approval(root, "zz_emp", ["zz_mgr"])
    assert decide(as_user(aapp, "zz_mgr"), a1, "reject", reason="a" * 500).status_code == 303
    a2 = add_approval(root, "zz_emp", ["zz_mgr"])
    assert decide(as_user(aapp, "zz_mgr"), a2, "approve", reason="무시되는 말").status_code == 303
    assert steps_of(root, a2) == [(1, "zz_mgr", "approved", None)]            # 승인에는 사유를 저장하지 않는다


@pytest.mark.parametrize("who", ["zz_emp", "zz_adm", "zz_mgrb", "zz_emp2"])
def test_only_approvers_in_the_chain_can_decide(aapp, root, events, who):
    e = add_expense(root, "zz_emp", "zz_권한", status="submitted")
    a = add_approval(root, "zz_emp", ["zz_mgr"], expense_id=e)
    assert decide(as_user(aapp, who), a, "approve").status_code == 403    # 상신자·결재선에 없는 관리자·타팀 팀장·동료
    assert approval_state(root, a) == ("pending", 1, 0) and expense_status(root, e) == "submitted"
    assert any(x["event_type"] == "authz_deny" and x["reason"] == "not_approver" and x["user"] == who for x in events())


@pytest.mark.parametrize("second", ["approve", "reject"])
def test_the_same_approver_cannot_decide_twice(aapp, root, events, second):
    e = add_expense(root, "zz_emp", "zz_두번", status="submitted")
    a = add_approval(root, "zz_emp", ["zz_mgr", "zz_adm"], expense_id=e)
    mgr = as_user(aapp, "zz_mgr")
    assert decide(mgr, a, "approve").status_code == 303
    assert decide(mgr, a, second, reason="번복").status_code == 409          # 이미 처리한 단계는 되돌릴 수 없다
    assert [s[2] for s in steps_of(root, a)] == ["approved", "pending"]
    assert any(x["event_type"] == "approval_invalid_transition" and x["decision"] == "DENY" for x in events())


@pytest.mark.parametrize("terminal,decision", [("approved", "reject"), ("rejected", "approve"), ("withdrawn", "approve")])
def test_terminal_documents_cannot_change(aapp, root, terminal, decision):
    a = add_approval(root, "zz_emp", ["zz_mgr"], status=terminal)
    assert decide(as_user(aapp, "zz_mgr"), a, decision, reason="번복").status_code == 409
    assert approval_state(root, a)[0] == terminal


@pytest.mark.parametrize("value", ["hack", "", "APPROVE", "approved", "approve ", "1"])
def test_invalid_decision_values_are_rejected(aapp, root, events, value):
    a = add_approval(root, "zz_emp", ["zz_mgr"])
    assert decide(as_user(aapp, "zz_mgr"), a, value).status_code == 400
    assert approval_state(root, a)[0] == "pending"
    assert any(x["event_type"] == "input_rejected" and x["field"] == "decision" for x in events())


def test_decide_needs_csrf_post_and_existing_id(aapp, root):
    a = add_approval(root, "zz_emp", ["zz_mgr"])
    mgr = as_user(aapp, "zz_mgr")
    assert mgr.post(f"/approvals/{a}/decide", data={"decision": "approve"}).status_code == 403
    assert mgr.get(f"/approvals/{a}/decide").status_code == 405
    assert decide(mgr, 999999, "approve").status_code == 404
    assert approval_state(root, a)[0] == "pending"


def test_extra_form_fields_cannot_reassign_the_chain_or_force_status(aapp, root):
    a = add_approval(root, "zz_emp", ["zz_mgr", "zz_adm"])
    decide(as_user(aapp, "zz_mgr"), a, "approve", approver_id="1", requester_id="1", status="approved",
           approver_1=str(uid(root, "zz_emp")), step_no="2")
    assert steps_of(root, a) == [(1, "zz_mgr", "approved", None), (2, "zz_adm", "pending", None)]
    assert approval_state(root, a) == ("pending", 2, 0)


# ---------- 철회 ----------
def test_requester_can_withdraw_before_anyone_decided_and_expense_returns_to_draft(aapp, root, events):
    e = add_expense(root, "zz_emp", "zz_철회", status="draft")
    c = as_user(aapp, "zz_emp")
    aid = int(submit(c, root, e, "zz_mgr", "zz_adm").headers["Location"].rsplit("/", 1)[1])
    assert expense_status(root, e) == "submitted"
    assert "상신 철회" in c.get(f"/approvals/{aid}").get_data(as_text=True)
    assert withdraw(c, aid).status_code == 303
    assert approval_state(root, aid) == ("withdrawn", 1, 1)
    assert [s[2] for s in steps_of(root, aid)] == ["skipped", "skipped"]
    assert expense_status(root, e) == "draft"                                  # 고쳐서 다시 올릴 수 있다
    after = c.get(f"/approvals/{aid}").get_data(as_text=True)
    assert "철회" in after and "상신 철회" not in after                         # 상태는 '철회', 철회 버튼은 사라진다
    assert any(x["event_type"] == "approval_withdrawn" and x["user"] == "zz_emp" for x in events())
    assert decide(as_user(aapp, "zz_mgr"), aid, "approve").status_code == 409  # 철회된 문서는 처리할 수 없다
    assert submit(c, root, e, "zz_adm").status_code == 303                     # 재상신: 새 결재 문서
    assert sql(root, "SELECT COUNT(*) FROM approvals WHERE expense_id=%s", (e,))[0][0] == 2


def test_withdraw_is_not_possible_after_the_first_approver_decided(aapp, root, events):
    e = add_expense(root, "zz_emp", "zz_진행중", status="submitted")
    a = add_approval(root, "zz_emp", ["zz_mgr", "zz_adm"], expense_id=e)
    assert decide(as_user(aapp, "zz_mgr"), a, "approve").status_code == 303
    c = as_user(aapp, "zz_emp")
    assert "상신 철회" not in c.get(f"/approvals/{a}").get_data(as_text=True)
    assert withdraw(c, a).status_code == 409
    assert approval_state(root, a)[0] == "pending" and expense_status(root, e) == "submitted"
    assert any(x["event_type"] == "approval_invalid_transition" and "withdrawn" in x["reason"] for x in events())


@pytest.mark.parametrize("terminal", ["approved", "rejected", "withdrawn"])
def test_terminal_documents_cannot_be_withdrawn(aapp, root, terminal):
    a = add_approval(root, "zz_emp", ["zz_mgr"], status=terminal)
    assert withdraw(as_user(aapp, "zz_emp"), a).status_code == 409
    assert approval_state(root, a)[0] == terminal


@pytest.mark.parametrize("who", ["zz_mgr", "zz_adm", "zz_emp2", "zz_mgrb"])
def test_only_the_requester_can_withdraw(aapp, root, events, who):
    a = add_approval(root, "zz_emp", ["zz_mgr"])
    assert withdraw(as_user(aapp, who), a).status_code == 403
    assert approval_state(root, a)[0] == "pending"
    assert any(x["event_type"] == "authz_deny" and x["reason"] == "not_requester" and x["user"] == who for x in events())


def test_withdraw_needs_csrf_post_and_existing_id(aapp, root):
    a = add_approval(root, "zz_emp", ["zz_mgr"])
    c = as_user(aapp, "zz_emp")
    assert c.post(f"/approvals/{a}/withdraw").status_code == 403
    assert c.get(f"/approvals/{a}/withdraw").status_code == 405
    assert withdraw(c, 999999).status_code == 404
    assert approval_state(root, a)[0] == "pending"


def test_decision_and_withdraw_buttons_are_shown_only_to_the_right_people(aapp, root):
    a = add_approval(root, "zz_emp", ["zz_mgr", "zz_adm"])
    page = lambda name: as_user(aapp, name).get(f"/approvals/{a}").get_data(as_text=True)
    mgr, adm, emp = page("zz_mgr"), page("zz_adm"), page("zz_emp")
    assert 'name="decision"' in mgr and "상신 철회" not in mgr                  # 지금 차례인 결재자: 처리 버튼만
    assert 'name="decision"' not in adm and "상신 철회" not in adm              # 2차 결재자는 아직 차례 전
    assert "상신 철회" in emp and 'name="decision"' not in emp                  # 상신자: 철회 버튼만
