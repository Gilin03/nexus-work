"""인사(HR): 인사카드·조직도·근태·휴가의 범위 검사, 상태 전이, 입력 검증, 동시성. Docker MySQL(nexus_test) 필요, 접속 불가면 skip."""
from datetime import datetime, timedelta

import pytest

from app import hr
from support import csrf_of, login, sql

ZZ = "zz_emp"


def as_user(app, name):
    c = app.test_client()
    assert login(c, name).status_code == 303
    return c


def uid(root, name):
    return sql(root, "SELECT id FROM users WHERE username=%s", (name,))[0][0]


def post(client, path, **form):
    return client.post(path, data={"csrf_token": csrf_of(client), **form})


def monday(weeks_ahead=2):
    d = hr.today_kst() + timedelta(weeks=weeks_ahead)
    return d - timedelta(days=d.weekday())


def apply(client, ltype="annual", start=None, end=None, reason="개인 사유", **extra):
    start = start or monday()
    end = end if end is not None else start
    return post(client, "/hr/leave/new", leave_type=ltype, start_date=start.isoformat(), end_date=end.isoformat() if end else "",
                reason=reason, **extra)


def leave_rows(root, name):
    return sql(root, "SELECT id, leave_type, days, status, decided_by, decision_reason FROM leave_requests "
                     "WHERE user_id=%s ORDER BY id", (uid(root, name),))


def add_employee(root, name, dept, user=None, title="사원"):
    sql(root, "INSERT INTO employees(user_id,name,dept,title,ext,emp_no,hire_date) VALUES(%s,%s,%s,%s,'1000',%s,'2024-03-04')",
        (uid(root, user) if user else None, name, dept, title, f"ZZ-{name}"))
    return sql(root, "SELECT id FROM employees WHERE name=%s", (name,))[0][0]


# ---------- 로그인 필수 ----------
@pytest.mark.parametrize("path", ["/hr/cards", "/hr/cards/1", "/hr/org", "/hr/attendance", "/hr/leave", "/hr/leave/new"])
def test_pages_require_login(aapp, path):
    r = aapp.test_client().get(path)
    assert r.status_code == 303 and "/login" in r.headers["Location"]


@pytest.mark.parametrize("path", ["/hr/attendance/check-in", "/hr/attendance/check-out", "/hr/leave/new", "/hr/leave/1/decide", "/hr/leave/1/cancel"])
def test_post_routes_need_csrf_even_when_logged_in(aapp, root, path):
    c = as_user(aapp, ZZ)
    assert c.post(path).status_code == 403
    assert aapp.test_client().post(path).status_code == 403


# ---------- 조직도·인사카드 ----------
def test_org_chart_groups_by_department_for_everyone(aapp, root):
    add_employee(root, "zz_가나", "zz_A부", user="zz_emp")
    add_employee(root, "zz_다라", "zz_B부")
    html = as_user(aapp, ZZ).get("/hr/org").get_data(as_text=True)
    assert "zz_A부" in html and "zz_B부" in html and "zz_가나" in html and "zz_다라" in html


def test_card_list_and_detail_follow_the_scope_rules(aapp, root):
    mine = add_employee(root, "zz_본인", "A팀", user="zz_emp")
    mate = add_employee(root, "zz_동료", "A팀", user="zz_emp2")
    other = add_employee(root, "zz_타팀", "B팀", user="zz_emp3")
    nouser = add_employee(root, "zz_계정없음", "A팀")
    emp = as_user(aapp, "zz_emp")
    names = emp.get("/hr/cards").get_data(as_text=True)
    assert "zz_본인" in names and "zz_동료" not in names and "zz_타팀" not in names
    assert emp.get(f"/hr/cards/{mine}").status_code == 200
    for eid in (mate, other, nouser):
        assert emp.get(f"/hr/cards/{eid}").status_code == 403

    mgr = as_user(aapp, "zz_mgr").get("/hr/cards").get_data(as_text=True)           # 팀장: 같은 부서(계정 없는 직원 포함)
    assert "zz_본인" in mgr and "zz_동료" in mgr and "zz_계정없음" in mgr and "zz_타팀" not in mgr
    assert as_user(aapp, "zz_mgr").get(f"/hr/cards/{other}").status_code == 403
    adm = as_user(aapp, "zz_adm")
    assert all(n in adm.get("/hr/cards").get_data(as_text=True) for n in ("zz_본인", "zz_타팀", "zz_계정없음"))
    assert adm.get(f"/hr/cards/{other}").status_code == 200 and adm.get("/hr/cards/999999").status_code == 404


def test_card_denied_is_logged_and_shows_tenure_and_leave(aapp, root, events):
    other = add_employee(root, "zz_타팀", "B팀", user="zz_emp3")
    c = as_user(aapp, ZZ)
    c.get(f"/hr/cards/{other}")
    assert any(e["event_type"] == "authz_deny" and e["reason"] == "out_of_scope" for e in events())
    mine = add_employee(root, "zz_본인", "A팀", user=ZZ)
    html = c.get(f"/hr/cards/{mine}").get_data(as_text=True)
    assert "ZZ-zz_본인" in html and "2024-03-04" in html and "연차" in html and "잔여 15일" in html


# ---------- 근태 ----------
def attendance_rows(root, name):
    return sql(root, "SELECT work_date, check_in, check_out FROM attendance WHERE user_id=%s", (uid(root, name),))


def test_check_in_and_out_use_server_time_and_only_once_per_day(aapp, root):
    c = as_user(aapp, ZZ)
    assert c.post("/hr/attendance/check-out", data={"csrf_token": csrf_of(c)}).status_code == 409   # 출근 전 퇴근
    assert post(c, "/hr/attendance/check-in", check_in="2000-01-01 00:00:00", work_date="2000-01-01").status_code == 303
    (day, cin, cout), = attendance_rows(root, ZZ)
    assert day == hr.today_kst() and cout is None                                   # 사용자가 보낸 날짜·시각은 무시
    assert abs((cin - hr.now_kst()).total_seconds()) < 60
    assert post(c, "/hr/attendance/check-in").status_code == 409                    # 같은 날 두 번째 출근
    assert len(attendance_rows(root, ZZ)) == 1
    assert post(c, "/hr/attendance/check-out").status_code == 303
    assert attendance_rows(root, ZZ)[0][2] is not None
    assert post(c, "/hr/attendance/check-out").status_code == 409                    # 이미 퇴근


def test_attendance_scope_and_late_flag(aapp, root):
    today = hr.today_kst()
    for name, tm in (("zz_emp", "09:30:00"), ("zz_emp2", "08:50:00"), ("zz_emp3", "08:55:00")):
        sql(root, "INSERT INTO attendance(user_id,work_date,check_in,check_out) VALUES(%s,%s,%s,%s)",
            (uid(root, name), today - timedelta(days=1), f"{(today - timedelta(days=1)).isoformat()} {tm}",
             f"{(today - timedelta(days=1)).isoformat()} 18:00:00"))
    month = (today - timedelta(days=1)).strftime("%Y-%m")
    emp = as_user(aapp, "zz_emp").get(f"/hr/attendance?month={month}").get_data(as_text=True)
    assert "09:30" in emp and "지각" in emp and "08:50" not in emp and "08:55" not in emp       # 직원은 본인 것만
    mgr = as_user(aapp, "zz_mgr").get(f"/hr/attendance?month={month}").get_data(as_text=True)
    assert "09:30" in mgr and "08:50" in mgr and "08:55" not in mgr                             # 팀장은 같은 부서
    adm = as_user(aapp, "zz_adm").get(f"/hr/attendance?month={month}").get_data(as_text=True)
    assert all(t in adm for t in ("09:30", "08:50", "08:55"))


@pytest.mark.parametrize("month", ["2026-13", "2026-1", "abc", "2026-00", "'; DROP TABLE users;--"])
def test_bad_month_is_rejected(aapp, root, month):
    r = as_user(aapp, ZZ).get("/hr/attendance", query_string={"month": month})
    assert r.status_code == 400 and "YYYY-MM" in r.get_data(as_text=True)


# ---------- 휴가: 신청과 검증 ----------
def test_apply_creates_pending_request_and_ignores_forged_fields(aapp, root, events):
    c = as_user(aapp, ZZ)
    d = monday()
    r = apply(c, "annual", d, d + timedelta(days=4), status="approved", decided_by="1", user_id=str(uid(root, "zz_adm")), days="30")
    assert r.status_code == 303
    (_, ltype, days, status, decided_by, _), = leave_rows(root, ZZ)
    assert (ltype, float(days), status, decided_by) == ("annual", 5.0, "pending", None)           # 평일 5일, 항상 대기로 시작
    assert not leave_rows(root, "zz_adm")
    assert any(e["event_type"] == "hr_leave_requested" for e in events())
    assert "잔여 10일" in c.get("/hr/leave").get_data(as_text=True)                                # 대기 중인 것도 미리 차감


def test_weekends_are_excluded_and_half_day_counts_half(aapp, root):
    c = as_user(aapp, ZZ)
    d = monday()
    apply(c, "annual", d + timedelta(days=4), d + timedelta(days=7))                              # 금~월 = 평일 2일
    apply(c, "half", d + timedelta(days=14))
    assert [float(r[2]) for r in leave_rows(root, ZZ)] == [2.0, 0.5]


@pytest.mark.parametrize("kw,fragment", [
    (dict(ltype="vacation"), "종류"),
    (dict(start="2026-02-30"), "YYYY-MM-DD"),
    (dict(start="내일"), "YYYY-MM-DD"),
    (dict(reason=""), "사유"),
    (dict(reason="줄\x00바꿈"), "사유"),
    (dict(reason="가" * 201), "사유"),
])
def test_invalid_leave_input_is_rejected_without_a_row(aapp, root, kw, fragment):
    c = as_user(aapp, ZZ)
    d = kw.pop("start", monday())
    start = d if isinstance(d, str) else d.isoformat()
    r = post(c, "/hr/leave/new", leave_type=kw.get("ltype", "annual"), start_date=start, end_date="", reason=kw.get("reason", "사유"))
    assert r.status_code == 400 and fragment in r.get_data(as_text=True)
    assert not leave_rows(root, ZZ)


def test_range_half_weekend_and_too_long_rules(aapp, root):
    c = as_user(aapp, ZZ)
    d = monday()
    assert apply(c, "annual", d + timedelta(days=3), d).status_code == 400                         # 종료일이 시작일보다 앞
    assert apply(c, "annual", hr.today_kst() - timedelta(days=hr.MAX_PAST_DAYS + 5)).status_code == 400   # 너무 먼 과거
    assert apply(c, "annual", hr.today_kst() + timedelta(days=hr.MAX_FUTURE_DAYS + 5)).status_code == 400
    assert apply(c, "half", d, d + timedelta(days=1)).status_code == 400                           # 반차는 하루만
    assert apply(c, "annual", d + timedelta(days=5), d + timedelta(days=6)).status_code == 400    # 토·일만
    assert apply(c, "sick", d, d + timedelta(days=60)).status_code == 400                           # 31일 넘는 기간
    assert not leave_rows(root, ZZ)


def test_balance_blocks_over_request_but_sick_leave_is_not_counted(aapp, root, events):
    c = as_user(aapp, ZZ)
    d = monday()
    assert apply(c, "annual", d, d + timedelta(days=4 + 7 * 3)).status_code == 409                  # 평일 20일 > 잔여 15일
    assert not leave_rows(root, ZZ)
    assert any(e["event_type"] == "hr_leave_rejected" and e["reason"] == "balance" for e in events())
    assert apply(c, "sick", d, d + timedelta(days=4 + 7 * 3)).status_code == 303                    # 병가는 차감하지 않는다
    assert float(leave_rows(root, ZZ)[0][2]) == 20.0


def test_overlapping_request_is_rejected_but_cancelled_one_is_not_a_conflict(aapp, root):
    c = as_user(aapp, ZZ)
    d = monday()
    assert apply(c, "annual", d, d + timedelta(days=1)).status_code == 303
    assert apply(c, "annual", d + timedelta(days=1), d + timedelta(days=2)).status_code == 409    # 하루 겹침
    first = leave_rows(root, ZZ)[0][0]
    assert post(c, f"/hr/leave/{first}/cancel").status_code == 303
    assert apply(c, "annual", d + timedelta(days=1), d + timedelta(days=2)).status_code == 303    # 취소했으면 다시 신청 가능


# ---------- 휴가: 결재와 취소 ----------
def pending(client, root, name=ZZ, **kw):
    assert apply(client, **kw).status_code == 303
    return leave_rows(root, name)[-1][0]


def test_same_department_manager_can_approve_and_it_is_recorded(aapp, root, events):
    emp = as_user(aapp, ZZ)
    lid = pending(emp, root)
    mgr = as_user(aapp, "zz_mgr")
    assert "승인" in mgr.get("/hr/leave").get_data(as_text=True)
    assert post(mgr, f"/hr/leave/{lid}/decide", action="approve").status_code == 303
    row = leave_rows(root, ZZ)[0]
    assert row[3] == "approved" and row[4] == uid(root, "zz_mgr")
    assert any(e["event_type"] == "hr_leave_decided" and e["reason"] == "approved" for e in events())
    assert post(mgr, f"/hr/leave/{lid}/decide", action="reject", reason="늦음").status_code == 409   # 이미 처리됨
    assert leave_rows(root, ZZ)[0][3] == "approved"


def test_reject_requires_a_reason_and_stores_it(aapp, root):
    lid = pending(as_user(aapp, ZZ), root)
    mgr = as_user(aapp, "zz_mgr")
    assert post(mgr, f"/hr/leave/{lid}/decide", action="reject", reason="").status_code == 409
    assert leave_rows(root, ZZ)[0][3] == "pending"
    assert post(mgr, f"/hr/leave/{lid}/decide", action="reject", reason="일정이 겹칩니다").status_code == 303
    assert leave_rows(root, ZZ)[0][3:6:2] == ("rejected", "일정이 겹칩니다")
    assert "일정이 겹칩니다" in as_user(aapp, ZZ).get("/hr/leave").get_data(as_text=True)


@pytest.mark.parametrize("who", ["zz_emp2", "zz_emp3", "zz_mgrb"])
def test_only_same_department_manager_or_admin_can_decide(aapp, root, who):
    lid = pending(as_user(aapp, ZZ), root)
    c = as_user(aapp, who)
    assert post(c, f"/hr/leave/{lid}/decide", action="approve").status_code == 403               # 직원·다른 부서 팀장
    assert leave_rows(root, ZZ)[0][3] == "pending"
    assert "승인" not in c.get("/hr/leave").get_data(as_text=True).replace("승인 ", "")


def test_admin_can_decide_any_department(aapp, root):
    lid = pending(as_user(aapp, "zz_emp3"), root, "zz_emp3")
    assert post(as_user(aapp, "zz_adm"), f"/hr/leave/{lid}/decide", action="approve").status_code == 303
    assert leave_rows(root, "zz_emp3")[0][3] == "approved"


def test_nobody_can_decide_their_own_request(aapp, root, events):
    mgr = as_user(aapp, "zz_mgr")
    lid = pending(mgr, root, "zz_mgr")
    assert post(mgr, f"/hr/leave/{lid}/decide", action="approve").status_code == 403
    adm = as_user(aapp, "zz_adm")
    lid2 = pending(adm, root, "zz_adm")
    assert post(adm, f"/hr/leave/{lid2}/decide", action="approve").status_code == 403           # 관리자도 본인 신청은 불가
    assert [r[3] for r in list(leave_rows(root, "zz_mgr")) + list(leave_rows(root, "zz_adm"))] == ["pending", "pending"]
    assert any(e["reason"] == "self_decision" for e in events())
    other_mgr = as_user(aapp, "zz_adm")
    assert post(other_mgr, f"/hr/leave/{lid}/decide", action="approve").status_code == 303       # 다른 사람(관리자)이 결재


@pytest.mark.parametrize("form", [{"action": "delete"}, {"action": ""}, {}])
def test_unknown_decision_action_is_rejected(aapp, root, form):
    lid = pending(as_user(aapp, ZZ), root)
    assert post(as_user(aapp, "zz_mgr"), f"/hr/leave/{lid}/decide", **form).status_code == 409
    assert leave_rows(root, ZZ)[0][3] == "pending"
    assert post(as_user(aapp, "zz_mgr"), "/hr/leave/999999/decide", action="approve").status_code == 404


def test_only_the_owner_can_cancel_and_only_while_pending(aapp, root):
    emp = as_user(aapp, ZZ)
    lid = pending(emp, root)
    assert post(as_user(aapp, "zz_mgr"), f"/hr/leave/{lid}/cancel").status_code == 403           # 팀장도 남의 신청은 취소 불가
    assert post(as_user(aapp, "zz_emp2"), f"/hr/leave/{lid}/cancel").status_code == 403
    assert leave_rows(root, ZZ)[0][3] == "pending"
    assert post(emp, f"/hr/leave/{lid}/cancel").status_code == 303
    assert leave_rows(root, ZZ)[0][3] == "cancelled"
    assert post(emp, f"/hr/leave/{lid}/cancel").status_code == 409
    lid2 = pending(emp, root, start=monday(4))
    post(as_user(aapp, "zz_mgr"), f"/hr/leave/{lid2}/decide", action="approve")
    assert post(emp, f"/hr/leave/{lid2}/cancel").status_code == 409                               # 승인된 뒤에는 취소 불가


def test_leave_list_is_scoped(aapp, root):
    pending(as_user(aapp, ZZ), root, reason="zz사유A")
    pending(as_user(aapp, "zz_emp3"), root, "zz_emp3", reason="zz사유B")
    emp = as_user(aapp, "zz_emp2").get("/hr/leave").get_data(as_text=True)
    assert "zz사유A" not in emp and "zz사유B" not in emp                                          # 직원은 본인 것만
    mgr = as_user(aapp, "zz_mgr").get("/hr/leave").get_data(as_text=True)
    assert "zz사유A" in mgr and "zz사유B" not in mgr
    adm = as_user(aapp, "zz_adm").get("/hr/leave").get_data(as_text=True)
    assert "zz사유A" in adm and "zz사유B" in adm


def test_concurrent_approvals_only_one_wins(aapp, root):
    """같은 대기 신청을 두 결재자가 동시에 처리해도 한쪽만 성공한다(조건부 UPDATE)."""
    import threading
    lid = pending(as_user(aapp, ZZ), root)
    clients = [as_user(aapp, "zz_mgr"), as_user(aapp, "zz_adm")]
    results = []

    def go(c, action, reason):
        results.append(post(c, f"/hr/leave/{lid}/decide", action=action, reason=reason).status_code)

    ts = [threading.Thread(target=go, args=(clients[0], "approve", "")), threading.Thread(target=go, args=(clients[1], "reject", "동시"))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(results) == [303, 409]
    assert leave_rows(root, ZZ)[0][3] in ("approved", "rejected")


def test_simultaneous_overlapping_leave_requests_only_one_is_stored(aapp, root):
    """같은 사람이 같은 기간으로 동시에 두 번 신청해도 한 건만 들어간다(요청 앞부분의 읽기로 잡힌 스냅샷이 겹침 검사를 속이지 않아야 한다)."""
    import threading
    clients = [as_user(aapp, ZZ) for _ in range(4)]
    gate, codes = threading.Barrier(len(clients)), []

    def go(c):
        gate.wait()
        codes.append(apply(c, "annual", monday(3), None, reason="동시 신청").status_code)

    ts = [threading.Thread(target=go, args=(c,)) for c in clients]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(codes) == [303, 409, 409, 409]
    assert len(leave_rows(root, ZZ)) == 1


def test_menu_lists_all_hr_items_and_marks_current_page(aapp):
    html = as_user(aapp, ZZ).get("/hr/org").get_data(as_text=True)
    for label in ("인사카드", "조직도", "근태관리", "휴가관리", "급여"):
        assert f">{label}</a>" in html
    assert 'aria-current="page">조직도</a>' in html
    assert 'aria-current="page">근태관리</a>' in as_user(aapp, ZZ).get("/hr/attendance").get_data(as_text=True)


def test_now_kst_has_no_fractional_seconds_so_checkout_right_after_checkin_works(aapp, root, monkeypatch):
    """회귀: DATETIME 이 초를 반올림해도 퇴근 시각이 출근 시각보다 이르게 보이지 않아야 한다(0.9초에 출근해도 같은 초 안에 퇴근 가능)."""
    assert hr.now_kst().microsecond == 0
    base = datetime(2026, 10, 19, 9, 0, 9, 900000, tzinfo=hr.KST)

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return base if tz else base.replace(tzinfo=None)
    monkeypatch.setattr(hr, "datetime", FrozenDatetime)
    c = as_user(aapp, ZZ)
    assert post(c, "/hr/attendance/check-in").status_code == 303
    assert post(c, "/hr/attendance/check-out").status_code == 303
    (_, cin, cout), = attendance_rows(root, ZZ)
    assert cout >= cin


def test_card_edit_permissions_and_update(aapp, root):
    emp_user = "zz_emp"
    adm = as_user(aapp, "zz_adm")
    emp = as_user(aapp, emp_user)

    eid = add_employee(root, "zz_수정대상", "A팀", user=emp_user)

    # 1. 일반 사원은 수정 폼 및 수정 제출 불가 (403)
    assert emp.get(f"/hr/cards/{eid}/edit").status_code == 403
    assert post(emp, f"/hr/cards/{eid}/edit", name="해킹시도", dept="A팀").status_code == 403

    # 2. 관리자는 수정 폼 접근 가능 (200)
    res_form = adm.get(f"/hr/cards/{eid}/edit")
    assert res_form.status_code == 200
    assert "인사카드 수정" in res_form.get_data(as_text=True)

    # 3. 관리자가 인사카드 수정 (이름, 내선, 연차 변경)
    res_post = post(adm, f"/hr/cards/{eid}/edit", name="김사원수정", dept="A팀", title="대리", ext="9988", annual_days="18")
    assert res_post.status_code == 303
    assert res_post.headers["Location"].endswith(f"/hr/cards/{eid}")

    # 4. DB 반영 확인
    card = sql(root, "SELECT name, title, ext, annual_days FROM employees WHERE id=%s", (eid,))[0]
    assert card == ("김사원수정", "대리", "9988", 18)

    # 5. users 테이블의 display_name도 동기화 확인
    u_name = sql(root, "SELECT display_name FROM users WHERE id=%s", (uid(root, emp_user),))[0][0]
    assert u_name == "김사원수정"
