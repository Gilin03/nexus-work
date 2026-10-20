"""업무: 업무 관리(할 일)·일정·회의실/비품 예약·프로젝트의 접근 범위, 상태 전이, 입력 검증, 동시성. Docker MySQL(nexus_test) 필요, 접속 불가면 skip."""
import threading
from datetime import datetime, timedelta

import pytest

from app import hr, work
from support import csrf_of, login, sql, uid

TODAY = hr.today_kst()


def as_user(app, name):
    c = app.test_client()
    assert login(c, name).status_code == 303
    return c


def post(client, path, data=None, **form):
    return client.post(path, data={"csrf_token": csrf_of(client), **(data or {}), **form})


def ids(root, *names):
    return [uid(root, n) for n in names]


def make_task(root, creator, assignee, title="zz 업무", status="todo", project=None, due=None):
    sql(root, "INSERT INTO tasks(title,creator_id,assignee_id,project_id,status,due_date) VALUES(%s,%s,%s,%s,%s,%s)",
        (title, uid(root, creator), uid(root, assignee), project, status, due))
    return sql(root, "SELECT MAX(id) FROM tasks WHERE title=%s", (title,))[0][0]


def make_project(root, owner, members=(), name="zz 프로젝트"):
    sql(root, "INSERT INTO projects(name,owner_id) VALUES(%s,%s)", (name, uid(root, owner)))
    pid = sql(root, "SELECT id FROM projects WHERE name=%s", (name,))[0][0]
    for m in {owner, *members}:
        sql(root, "INSERT INTO project_members(project_id,user_id) VALUES(%s,%s)", (pid, uid(root, m)))
    return pid


def make_event(root, owner, scope="private", title="zz 일정", attendees=(), day=None):
    day = day or TODAY
    sql(root, "INSERT INTO events(owner_id,title,start_at,end_at,scope) VALUES(%s,%s,%s,%s,%s)",
        (uid(root, owner), title, datetime.combine(day, datetime.min.time().replace(hour=10)), datetime.combine(day, datetime.min.time().replace(hour=11)), scope))
    eid = sql(root, "SELECT MAX(id) FROM events WHERE title=%s", (title,))[0][0]
    for a in attendees:
        sql(root, "INSERT INTO event_attendees(event_id,user_id) VALUES(%s,%s)", (eid, uid(root, a)))
    return eid


def make_resource(root, name="zz 회의실", kind="room", active=1):
    sql(root, "INSERT INTO resources(name,kind,active) VALUES(%s,%s,%s)", (name, kind, active))
    return sql(root, "SELECT id FROM resources WHERE name=%s", (name,))[0][0]


def day_plus(n):
    return (TODAY + timedelta(days=n)).isoformat()


# ---------- 로그인·CSRF ----------
GET_PAGES = ["/work/tasks", "/work/tasks/new", "/work/tasks/1", "/work/calendar", "/work/events/new", "/work/events/1",
             "/work/reservations", "/work/reservations/new?resource_id=1", "/work/projects", "/work/projects/new", "/work/projects/1"]
POST_PAGES = ["/work/tasks/new", "/work/tasks/1/status", "/work/tasks/1/assign", "/work/tasks/1/comment", "/work/events/new",
              "/work/events/1/cancel", "/work/reservations/new", "/work/reservations/1/cancel", "/work/resources/new",
              "/work/resources/1/toggle", "/work/projects/new", "/work/projects/1/members", "/work/projects/1/members/1/remove",
              "/work/projects/1/status"]


@pytest.mark.parametrize("path", GET_PAGES)
def test_pages_require_login(aapp, path):
    r = aapp.test_client().get(path)
    assert r.status_code == 303 and "/login" in r.headers["Location"]


@pytest.mark.parametrize("path", POST_PAGES)
def test_posts_need_csrf(aapp, root, path):
    assert as_user(aapp, "zz_adm").post(path).status_code == 403
    assert aapp.test_client().post(path).status_code == 403


# =====================================================================================
# 업무 관리
# =====================================================================================
def test_task_create_defaults_to_self_and_shows_in_my_box(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = post(c, "/work/tasks/new", title="보고서 작성", description="내용", priority="high", due_date=day_plus(3))
    assert r.status_code == 303
    row = sql(root, "SELECT creator_id, assignee_id, priority, status, project_id FROM tasks WHERE title='보고서 작성'")[0]
    assert row[0] == row[1] == uid(root, "zz_emp") and row[2:] == ("high", "todo", None)
    page = c.get("/work/tasks").get_data(as_text=True)
    assert "보고서 작성" in page and "높음" in page


def test_task_request_to_colleague_shows_for_both_sides(aapp, root):
    c = as_user(aapp, "zz_emp")
    post(c, "/work/tasks/new", title="자료 요청", assignee_id=uid(root, "zz_emp2"))
    assert "자료 요청" in as_user(aapp, "zz_emp2").get("/work/tasks").get_data(as_text=True)                 # 담당자의 내 업무
    mine = c.get("/work/tasks").get_data(as_text=True)
    assert "자료 요청" not in mine                                                                            # 요청한 사람의 내 업무에는 없다
    assert "자료 요청" in c.get("/work/tasks?box=requested").get_data(as_text=True)


@pytest.mark.parametrize("bad", [
    {"title": ""}, {"title": "x" * 121}, {"title": "a\x07b"}, {"title": "  "},
    {"priority": "urgent"}, {"due_date": "2026-13-40"}, {"due_date": "내일"}, {"due_date": "1999-01-01"}, {"due_date": "2099-01-01"},
    {"assignee_id": "999999"}, {"assignee_id": "abc"}, {"assignee_id": "-1"}, {"assignee_id": "٣"}, {"description": "x" * 2001},
    {"project_id": "999999"}, {"project_id": "x"},
])
def test_task_invalid_input_is_rejected_and_nothing_is_stored(aapp, root, bad):
    c = as_user(aapp, "zz_emp")
    form = {"title": "zz 잘못", "priority": "normal", **bad}
    r = post(c, "/work/tasks/new", **form)
    assert r.status_code == 400 and 'role="alert"' in r.get_data(as_text=True)
    assert sql(root, "SELECT COUNT(*) FROM tasks WHERE creator_id=%s", (uid(root, "zz_emp"),))[0][0] == 0


def test_task_form_values_are_kept_on_error_and_html_is_escaped(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = post(c, "/work/tasks/new", title="<script>alert(1)</script>", priority="bogus")
    html = r.get_data(as_text=True)
    assert r.status_code == 400 and "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    post(c, "/work/tasks/new", title="<b>굵게</b>")
    detail = c.get(f"/work/tasks/{sql(root, 'SELECT MAX(id) FROM tasks')[0][0]}").get_data(as_text=True)
    assert "<b>굵게</b>" not in detail and "&lt;b&gt;" in detail


def test_task_visibility_rules(aapp, root):
    t = make_task(root, "zz_emp", "zz_emp2")                       # A팀 직원 → A팀 직원
    for who, code in (("zz_emp", 200), ("zz_emp2", 200), ("zz_mgr", 200), ("zz_adm", 200),          # 만든 사람·담당자·같은 부서 팀장·관리자
                      ("zz_emp3", 403), ("zz_mgrb", 403)):                                          # 다른 부서 직원·다른 부서 팀장
        assert as_user(aapp, who).get(f"/work/tasks/{t}").status_code == code, who
    assert as_user(aapp, "zz_emp").get("/work/tasks/999999").status_code == 404


def test_project_members_can_see_project_tasks(aapp, root):
    pid = make_project(root, "zz_mgr", ["zz_emp", "zz_emp3"])
    t = make_task(root, "zz_mgr", "zz_emp", project=pid)
    assert as_user(aapp, "zz_emp3").get(f"/work/tasks/{t}").status_code == 200       # 다른 부서여도 같은 프로젝트 구성원
    assert as_user(aapp, "zz_emp2").get(f"/work/tasks/{t}").status_code == 403       # 구성원이 아닌 같은 부서 직원


def test_status_transitions_by_assignee(aapp, root):
    t = make_task(root, "zz_emp", "zz_emp2")
    c = as_user(aapp, "zz_emp2")
    assert post(c, f"/work/tasks/{t}/status", status="doing").status_code == 303
    assert post(c, f"/work/tasks/{t}/status", status="done").status_code == 303
    row = sql(root, "SELECT status, completed_at FROM tasks WHERE id=%s", (t,))[0]
    assert row[0] == "done" and row[1] is not None
    assert post(c, f"/work/tasks/{t}/status", status="todo").status_code == 409        # 완료에서 곧바로 할 일로는 못 간다
    assert post(c, f"/work/tasks/{t}/status", status="done").status_code == 409        # 같은 상태로의 전이도 거부
    assert post(c, f"/work/tasks/{t}/status", status="doing").status_code == 303        # 다시 진행(재오픈)
    assert sql(root, "SELECT completed_at FROM tasks WHERE id=%s", (t,))[0][0] is None


@pytest.mark.parametrize("bad", ["", "DONE", "deleted", "done'; --", "x" * 50])
def test_status_rejects_unknown_values(aapp, root, bad):
    t = make_task(root, "zz_emp", "zz_emp")
    assert post(as_user(aapp, "zz_emp"), f"/work/tasks/{t}/status", status=bad).status_code == 409
    assert sql(root, "SELECT status FROM tasks WHERE id=%s", (t,))[0][0] == "todo"


def test_only_participants_change_status_manager_and_outsiders_cannot(aapp, root):
    t = make_task(root, "zz_emp", "zz_emp2")
    for who in ("zz_emp3", "zz_mgr", "zz_mgrb"):                                         # 볼 수 있어도(팀장) 바꿀 수는 없다
        assert post(as_user(aapp, who), f"/work/tasks/{t}/status", status="doing").status_code == 403, who
    assert sql(root, "SELECT status FROM tasks WHERE id=%s", (t,))[0][0] == "todo"
    assert post(as_user(aapp, "zz_adm"), f"/work/tasks/{t}/status", status="doing").status_code == 303


def test_cancel_and_uncancel_are_for_creator_or_admin_only(aapp, root):
    t = make_task(root, "zz_emp", "zz_emp2")
    assignee, creator = as_user(aapp, "zz_emp2"), as_user(aapp, "zz_emp")
    assert post(assignee, f"/work/tasks/{t}/status", status="cancelled").status_code == 403
    assert post(creator, f"/work/tasks/{t}/status", status="cancelled").status_code == 303
    assert "tk-cancelled" in assignee.get(f"/work/tasks/{t}").get_data(as_text=True)      # 담당자 화면에도 상태가 보인다
    assert post(assignee, f"/work/tasks/{t}/status", status="todo").status_code == 403    # 취소된 업무를 담당자가 되살릴 수 없다
    assert post(creator, f"/work/tasks/{t}/status", status="todo").status_code == 303


def test_assignee_does_not_see_cancel_button(aapp, root):
    t = make_task(root, "zz_emp", "zz_emp2")
    assert 'value="cancelled"' not in as_user(aapp, "zz_emp2").get(f"/work/tasks/{t}").get_data(as_text=True)
    assert 'value="cancelled"' in as_user(aapp, "zz_emp").get(f"/work/tasks/{t}").get_data(as_text=True)


def test_reassign_by_creator_only_and_only_while_open(aapp, root):
    t = make_task(root, "zz_emp", "zz_emp2")
    assert post(as_user(aapp, "zz_emp2"), f"/work/tasks/{t}/assign", assignee_id=uid(root, "zz_emp3")).status_code == 403
    c = as_user(aapp, "zz_emp")
    assert post(c, f"/work/tasks/{t}/assign", assignee_id=uid(root, "zz_emp3")).status_code == 303
    assert sql(root, "SELECT assignee_id FROM tasks WHERE id=%s", (t,))[0][0] == uid(root, "zz_emp3")
    for bad in ("999999", "abc", ""):
        assert post(c, f"/work/tasks/{t}/assign", assignee_id=bad).status_code == 409
    sql(root, "UPDATE tasks SET status='done' WHERE id=%s", (t,))
    assert post(c, f"/work/tasks/{t}/assign", assignee_id=uid(root, "zz_emp2")).status_code == 409


def test_project_task_can_only_go_to_members(aapp, root):
    pid = make_project(root, "zz_mgr", ["zz_emp"])
    t = make_task(root, "zz_mgr", "zz_emp", project=pid)
    c = as_user(aapp, "zz_mgr")
    assert post(c, f"/work/tasks/{t}/assign", assignee_id=uid(root, "zz_emp2")).status_code == 409     # 구성원이 아니다
    assert post(c, f"/work/tasks/{t}/assign", assignee_id=uid(root, "zz_mgr")).status_code == 303


def test_task_with_project_needs_membership_of_creator_and_assignee(aapp, root):
    pid = make_project(root, "zz_mgr", ["zz_emp"])
    outsider = as_user(aapp, "zz_emp2")
    assert post(outsider, "/work/tasks/new", title="zz 침입", project_id=pid).status_code == 400
    member = as_user(aapp, "zz_emp")
    assert post(member, "/work/tasks/new", title="zz 비구성원 담당", project_id=pid, assignee_id=uid(root, "zz_emp2")).status_code == 400
    assert post(member, "/work/tasks/new", title="zz 정상", project_id=pid).status_code == 303
    assert sql(root, "SELECT COUNT(*) FROM tasks WHERE project_id=%s", (pid,))[0][0] == 1
    sql(root, "UPDATE projects SET status='done' WHERE id=%s", (pid,))
    assert post(member, "/work/tasks/new", title="zz 종료됨", project_id=pid).status_code == 400            # 종료된 프로젝트에는 추가 불가


def test_comments(aapp, root):
    t = make_task(root, "zz_emp", "zz_emp2")
    c = as_user(aapp, "zz_mgr")                                                           # 볼 수 있는 사람(같은 부서 팀장)은 댓글을 쓸 수 있다
    assert post(c, f"/work/tasks/{t}/comment", body="확인했습니다 <i>x</i>").status_code == 303
    page = c.get(f"/work/tasks/{t}").get_data(as_text=True)
    assert "확인했습니다" in page and "<i>x</i>" not in page
    assert post(as_user(aapp, "zz_emp3"), f"/work/tasks/{t}/comment", body="침입").status_code == 403
    for bad in ("", "  ", "x" * 1001, "a\x00b"):
        assert post(c, f"/work/tasks/{t}/comment", body=bad).status_code == 400
    assert sql(root, "SELECT COUNT(*) FROM task_comments WHERE task_id=%s", (t,))[0][0] == 1


def test_team_box_scope(aapp, root):
    make_task(root, "zz_emp", "zz_emp2", title="zz A팀 업무")
    make_task(root, "zz_emp3", "zz_emp3", title="zz B팀 업무")
    assert as_user(aapp, "zz_emp").get("/work/tasks?box=team").status_code == 403
    a = as_user(aapp, "zz_mgr").get("/work/tasks?box=team").get_data(as_text=True)
    assert "zz A팀 업무" in a and "zz B팀 업무" not in a
    both = as_user(aapp, "zz_adm").get("/work/tasks?box=team").get_data(as_text=True)
    assert "zz A팀 업무" in both and "zz B팀 업무" in both


@pytest.mark.parametrize("query", ["box=nope", "state=nope", "box=mine&state=", "box=TEAM"])
def test_task_list_rejects_unknown_filters(aapp, root, query):
    assert as_user(aapp, "zz_adm").get(f"/work/tasks?{query}").status_code == 400


def test_task_list_filters_and_overdue_flag(aapp, root):
    make_task(root, "zz_emp", "zz_emp", title="zz 진행", due=(TODAY - timedelta(days=2)).isoformat())
    make_task(root, "zz_emp", "zz_emp", title="zz 끝", status="done")
    c = as_user(aapp, "zz_emp")
    openp = c.get("/work/tasks").get_data(as_text=True)
    assert "zz 진행" in openp and "zz 끝" not in openp and "지연" in openp
    closed = c.get("/work/tasks?state=closed").get_data(as_text=True)
    assert "zz 끝" in closed and "zz 진행" not in closed
    both = c.get("/work/tasks?state=all").get_data(as_text=True)
    assert "zz 끝" in both and "zz 진행" in both


# =====================================================================================
# 일정
# =====================================================================================
def event_form(**over):
    base = {"title": "zz 새 일정", "start_date": day_plus(1), "start_time": "10:00", "end_time": "11:00", "scope": "team"}
    base.update(over)
    return base


def test_event_create_with_attendees(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = post(c, "/work/events/new", data={**event_form(location="회의실 A", scope="private"), "attendees": [str(uid(root, "zz_emp3")), str(uid(root, "zz_emp3"))]})
    assert r.status_code == 303
    eid = sql(root, "SELECT id FROM events WHERE title='zz 새 일정'")[0][0]
    assert [r[0] for r in sql(root, "SELECT user_id FROM event_attendees WHERE event_id=%s", (eid,))] == [uid(root, "zz_emp3")]      # 중복은 한 번만
    assert as_user(aapp, "zz_emp3").get(f"/work/events/{eid}").status_code == 200                                                   # 참석자는 비공개 일정도 본다


def test_event_visibility_by_scope(aapp, root):
    priv = make_event(root, "zz_emp", "private", "zz 비공개")
    team = make_event(root, "zz_emp", "team", "zz 팀")
    comp = make_event(root, "zz_emp", "company", "zz 전사")
    expect = {  # (비공개, 팀, 전사)
        "zz_emp": (200, 200, 200), "zz_emp2": (403, 200, 200), "zz_mgr": (403, 200, 200),            # 같은 부서
        "zz_emp3": (403, 403, 200), "zz_mgrb": (403, 403, 200),                                      # 다른 부서
        "zz_adm": (403, 403, 200),                                                                   # 관리자도 남의 비공개·다른 부서 팀 일정은 못 본다
    }
    for who, codes in expect.items():
        c = as_user(aapp, who)
        assert tuple(c.get(f"/work/events/{e}").status_code for e in (priv, team, comp)) == codes, who


def test_calendar_lists_only_visible_events(aapp, root):
    make_event(root, "zz_emp", "private", "zz 비공개일정")
    make_event(root, "zz_emp", "team", "zz 팀일정")
    make_event(root, "zz_emp", "company", "zz 전사일정")
    mine = as_user(aapp, "zz_emp").get("/work/calendar").get_data(as_text=True)
    assert all(t in mine for t in ("zz 비공개일정", "zz 팀일정", "zz 전사일정"))
    other = as_user(aapp, "zz_emp3").get("/work/calendar").get_data(as_text=True)
    assert "zz 전사일정" in other and "zz 팀일정" not in other and "zz 비공개일정" not in other
    admin = as_user(aapp, "zz_adm").get("/work/calendar").get_data(as_text=True)
    assert "zz 비공개일정" not in admin


def test_calendar_month_navigation_and_validation(aapp, root):
    c = as_user(aapp, "zz_emp")
    page = c.get("/work/calendar?month=2026-02").get_data(as_text=True)
    assert "2026년 2월" in page and "2026-01" in page and "2026-03" in page             # 이전·다음 달 링크
    assert "2025-12" in c.get("/work/calendar?month=2026-01").get_data(as_text=True)
    assert "2027-01" in c.get("/work/calendar?month=2026-12").get_data(as_text=True)
    for bad in ("2026-13", "2026-00", "abcd", "2026-1", "1999-01", "2101-01", "2026-02-01"):
        r = c.get(f"/work/calendar?month={bad}")
        assert r.status_code == 400 and 'role="alert"' in r.get_data(as_text=True), bad


def test_multi_day_event_appears_on_each_day(aapp, root):
    sql(root, "INSERT INTO events(owner_id,title,start_at,end_at,scope,all_day) VALUES(%s,'zz 연속',%s,%s,'company',1)",
        (uid(root, "zz_emp"), "2026-03-10 00:00:00", "2026-03-12 23:59:00"))
    page = as_user(aapp, "zz_emp2").get("/work/calendar?month=2026-03").get_data(as_text=True)
    assert page.count("zz 연속") == 3


def test_leave_markers_follow_hr_scope(aapp, root):
    sql(root, "INSERT INTO leave_requests(user_id,leave_type,start_date,end_date,days,reason,status,decided_by) VALUES(%s,'annual','2026-03-10','2026-03-10',1,'x','approved',%s)",
        (uid(root, "zz_emp2"), uid(root, "zz_mgr")))
    seen = lambda who: "zz_emp2 연차" in as_user(aapp, who).get("/work/calendar?month=2026-03").get_data(as_text=True)    # noqa: E731
    assert seen("zz_emp2") and seen("zz_mgr") and seen("zz_adm")
    assert not seen("zz_emp") and not seen("zz_mgrb") and not seen("zz_emp3")           # 같은 팀 직원·다른 부서 팀장에게는 보이지 않는다


def test_task_deadline_marker_only_for_assignee(aapp, root):
    make_task(root, "zz_emp", "zz_emp2", title="zz 마감표시", due=TODAY.isoformat())
    assert "마감 zz 마감표시" in as_user(aapp, "zz_emp2").get("/work/calendar").get_data(as_text=True)
    assert "마감 zz 마감표시" not in as_user(aapp, "zz_emp").get("/work/calendar").get_data(as_text=True)


@pytest.mark.parametrize("bad", [
    {"title": ""}, {"title": "x" * 101}, {"title": "a\x01"}, {"scope": "public"}, {"scope": ""},
    {"start_date": ""}, {"start_date": "2026-02-30"}, {"start_date": "1999-01-01"}, {"start_date": "2100-01-01"}, {"end_date": "xx"},
    {"start_time": "25:00"}, {"start_time": "10:60"}, {"start_time": ""}, {"start_time": "9:00"}, {"end_time": "09:00"},
    {"end_date": day_plus(40)}, {"location": "x" * 101}, {"description": "x" * 1001}, {"attendees": ["999999"]}, {"attendees": ["abc"]},
])
def test_event_invalid_input_is_rejected(aapp, root, bad):
    c = as_user(aapp, "zz_emp")
    r = post(c, "/work/events/new", data=event_form(**bad))
    assert r.status_code == 400 and 'role="alert"' in r.get_data(as_text=True)
    assert sql(root, "SELECT COUNT(*) FROM events WHERE owner_id=%s", (uid(root, "zz_emp"),))[0][0] == 0


def test_event_too_many_attendees_and_all_day(aapp, root):
    c = as_user(aapp, "zz_emp")
    many = [str(uid(root, "zz_emp2"))] * 70
    assert post(c, "/work/events/new", data={**event_form(), "attendees": many}).status_code == 400
    r = post(c, "/work/events/new", data={**event_form(title="zz 종일", start_time="", end_time=""), "all_day": "1", "end_date": day_plus(2)})
    assert r.status_code == 303
    start, end, all_day = sql(root, "SELECT start_at, end_at, all_day FROM events WHERE title='zz 종일'")[0]
    assert all_day == 1 and start.hour == 0 and end.hour == 23 and (end - start).days == 1


def test_event_html_is_escaped_everywhere(aapp, root):
    c = as_user(aapp, "zz_emp")
    post(c, "/work/events/new", data=event_form(title="<img src=x onerror=alert(1)>", location="<b>장소</b>", description="<script>x</script>", scope="company"))
    eid = sql(root, "SELECT MAX(id) FROM events")[0][0]
    for page in (c.get(f"/work/events/{eid}").get_data(as_text=True), c.get("/work/calendar").get_data(as_text=True)):
        assert "<img src=x" not in page and "<script>x" not in page and "<b>장소</b>" not in page


def test_event_cancel_rules(aapp, root):
    team = make_event(root, "zz_emp", "team", "zz 팀 일정")
    priv = make_event(root, "zz_emp", "private", "zz 내 일정")
    assert post(as_user(aapp, "zz_emp2"), f"/work/events/{team}/cancel").status_code == 403
    assert post(as_user(aapp, "zz_adm"), f"/work/events/{priv}/cancel").status_code == 403        # 관리자도 남의 비공개 일정은 건드릴 수 없다
    assert post(as_user(aapp, "zz_adm"), f"/work/events/{team}/cancel").status_code == 303        # 팀·전사 일정은 관리자가 취소할 수 있다
    assert post(as_user(aapp, "zz_adm"), f"/work/events/{team}/cancel").status_code == 409
    assert post(as_user(aapp, "zz_emp"), f"/work/events/{priv}/cancel").status_code == 303
    assert "zz 팀 일정" not in as_user(aapp, "zz_emp").get("/work/calendar").get_data(as_text=True)     # 취소된 일정은 달력에서 빠진다
    assert as_user(aapp, "zz_emp2").get(f"/work/events/{team}").status_code == 200                      # 상세는 '취소됨'으로 남는다
    assert as_user(aapp, "zz_emp").get("/work/events/999999").status_code == 404


# =====================================================================================
# 예약
# =====================================================================================
def reserve(c, rid, day=None, start="10:00", end="11:00", purpose="회의", **over):
    return post(c, "/work/reservations/new", resource_id=rid, date=day_plus(2) if day is None else day, start_time=start, end_time=end, purpose=purpose, **over)


def test_reserve_and_see_on_the_day(aapp, root):
    rid = make_resource(root)
    c = as_user(aapp, "zz_emp")
    assert reserve(c, rid, purpose="주간 회의").status_code == 303
    row = sql(root, "SELECT user_id, start_at, end_at, status FROM reservations WHERE resource_id=%s", (rid,))[0]
    assert row[0] == uid(root, "zz_emp") and row[1].hour == 10 and row[2].hour == 11 and row[3] == "active"
    page = as_user(aapp, "zz_emp2").get(f"/work/reservations?date={day_plus(2)}").get_data(as_text=True)
    assert "zz 회의실" in page and "10:00~11:00" in page and "주간 회의" in page
    assert "주간 회의" in c.get("/work/reservations").get_data(as_text=True)                          # 내 예약 목록


def test_overlapping_reservation_is_rejected_but_adjacent_is_fine(aapp, root):
    rid = make_resource(root)
    a, b = as_user(aapp, "zz_emp"), as_user(aapp, "zz_emp2")
    assert reserve(a, rid, start="10:00", end="12:00").status_code == 303
    for s, e in (("10:00", "11:00"), ("11:00", "13:00"), ("09:00", "10:30"), ("09:00", "13:00"), ("10:30", "11:30")):
        assert reserve(b, rid, start=s, end=e).status_code == 409, (s, e)
    assert reserve(b, rid, start="12:00", end="13:00").status_code == 303                            # 끝과 시작이 맞닿는 것은 허용
    assert reserve(b, rid, start="09:00", end="10:00").status_code == 303
    assert reserve(b, rid, day=day_plus(3), start="10:00", end="12:00").status_code == 303            # 다른 날은 문제없다
    other = make_resource(root, "zz 회의실2")
    assert reserve(b, other, start="10:00", end="12:00").status_code == 303                          # 다른 자원도
    assert sql(root, "SELECT COUNT(*) FROM reservations WHERE resource_id=%s", (rid,))[0][0] == 4


def test_cancelled_reservation_frees_the_slot(aapp, root):
    rid = make_resource(root)
    a, b = as_user(aapp, "zz_emp"), as_user(aapp, "zz_emp2")
    reserve(a, rid)
    res_id = sql(root, "SELECT id FROM reservations WHERE resource_id=%s", (rid,))[0][0]
    assert reserve(b, rid).status_code == 409
    assert post(a, f"/work/reservations/{res_id}/cancel").status_code == 303
    assert reserve(b, rid).status_code == 303


def test_simultaneous_reservations_for_one_slot_only_one_wins(aapp, root):
    rid = make_resource(root)
    clients = [as_user(aapp, n) for n in ("zz_emp", "zz_emp2", "zz_emp3", "zz_mgr")]
    codes, gate = [], threading.Barrier(len(clients))

    def go(c):
        gate.wait()
        codes.append(reserve(c, rid).status_code)

    threads = [threading.Thread(target=go, args=(c,)) for c in clients]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(codes) == [303, 409, 409, 409]
    assert sql(root, "SELECT COUNT(*) FROM reservations WHERE resource_id=%s AND status='active'", (rid,))[0][0] == 1


@pytest.mark.parametrize("bad", [
    {"start": "11:00", "end": "11:00"}, {"start": "12:00", "end": "11:00"}, {"start": "10:00", "end": "15:00"},     # 순서·4시간 초과
    {"start": "07:30", "end": "09:00"}, {"start": "19:30", "end": "20:30"}, {"start": "10:15", "end": "11:00"},      # 영업 시간·30분 단위
    {"start": "10:00", "end": "11:00:00"}, {"start": "", "end": "11:00"}, {"start": "abc", "end": "11:00"},
    {"day": "2026-02-30"}, {"day": "내일"}, {"day": ""}, {"day": (TODAY - timedelta(days=1)).isoformat()},            # 날짜 형식·과거
    {"day": (TODAY + timedelta(days=61)).isoformat()}, {"purpose": ""}, {"purpose": "x" * 101}, {"purpose": "a\x00"},
])
def test_reservation_invalid_input_rejected(aapp, root, bad):
    rid = make_resource(root)
    r = reserve(as_user(aapp, "zz_emp"), rid, day=bad.get("day"), start=bad.get("start", "10:00"), end=bad.get("end", "11:00"),
                purpose=bad.get("purpose", "회의"))
    assert r.status_code == 400
    assert sql(root, "SELECT COUNT(*) FROM reservations WHERE resource_id=%s", (rid,))[0][0] == 0


def test_reserve_today_in_the_past_is_rejected(aapp, root):
    rid = make_resource(root)
    now = hr.now_kst()
    c = as_user(aapp, "zz_emp")
    if now.hour >= 10:                                                                    # 오늘 10:00~10:30 은 이미 지난 시간
        assert reserve(c, rid, day=TODAY.isoformat(), start="08:00", end="08:30").status_code == 400
    # 오늘의 앞으로 올 시간은 허용 — 20:00 이 안 지났을 때만 시험한다
    if now.hour < 19:
        assert reserve(c, rid, day=TODAY.isoformat(), start="19:00", end="19:30").status_code == 303


def test_unknown_or_inactive_resource_is_404_and_bad_ids_rejected(aapp, root):
    off = make_resource(root, "zz 중지", active=0)
    c = as_user(aapp, "zz_emp")
    assert reserve(c, off).status_code == 404
    assert reserve(c, 999999).status_code == 404
    assert c.get(f"/work/reservations/new?resource_id={off}").status_code == 404
    assert reserve(c, "abc").status_code == 404 and reserve(c, "").status_code == 404
    assert "zz 중지" not in c.get("/work/reservations").get_data(as_text=True)                  # 사용 중지된 자원은 직원에게 보이지 않는다
    assert "zz 중지" in as_user(aapp, "zz_adm").get("/work/reservations").get_data(as_text=True)


def test_reservation_cancel_rules(aapp, root):
    rid = make_resource(root)
    reserve(as_user(aapp, "zz_emp"), rid)
    res_id = sql(root, "SELECT id FROM reservations WHERE resource_id=%s", (rid,))[0][0]
    assert post(as_user(aapp, "zz_emp2"), f"/work/reservations/{res_id}/cancel").status_code == 403
    assert post(as_user(aapp, "zz_mgr"), f"/work/reservations/{res_id}/cancel").status_code == 403      # 팀장도 남의 예약은 못 지운다
    assert post(as_user(aapp, "zz_adm"), f"/work/reservations/{res_id}/cancel").status_code == 303
    assert post(as_user(aapp, "zz_emp"), f"/work/reservations/{res_id}/cancel").status_code == 409
    assert post(as_user(aapp, "zz_emp"), "/work/reservations/999999/cancel").status_code == 404
    past = (datetime.now() - timedelta(days=1)).replace(microsecond=0)
    sql(root, "INSERT INTO reservations(resource_id,user_id,start_at,end_at,purpose) VALUES(%s,%s,%s,%s,'지난')", (rid, uid(root, "zz_emp"), past, past + timedelta(hours=1)))
    old = sql(root, "SELECT MAX(id) FROM reservations")[0][0]
    assert post(as_user(aapp, "zz_emp"), f"/work/reservations/{old}/cancel").status_code == 409        # 끝난 예약은 취소할 수 없다


def test_active_reservation_limit_per_user(aapp, root):
    rid = make_resource(root)
    base = datetime.now().replace(minute=0, second=0, microsecond=0) + timedelta(days=5)
    for i in range(work.MAX_ACTIVE_RESERVATIONS):
        s = base + timedelta(days=i)
        sql(root, "INSERT INTO reservations(resource_id,user_id,start_at,end_at,purpose) VALUES(%s,%s,%s,%s,'x')", (rid, uid(root, "zz_emp"), s, s + timedelta(hours=1)))
    assert reserve(as_user(aapp, "zz_emp"), rid, day=day_plus(2)).status_code == 409
    assert reserve(as_user(aapp, "zz_emp2"), rid, day=day_plus(2)).status_code == 303


def test_reservation_list_validation(aapp, root):
    c = as_user(aapp, "zz_emp")
    assert c.get("/work/reservations?date=abc").status_code == 400
    assert c.get("/work/reservations?kind=ship").status_code == 400
    assert c.get("/work/reservations?kind=room").status_code == 200
    r = make_resource(root, "zz 장비", "equipment")
    assert "zz 장비" in c.get("/work/reservations?kind=equipment").get_data(as_text=True)
    assert "zz 장비" not in c.get("/work/reservations?kind=room").get_data(as_text=True)
    assert r


def test_resource_admin_actions(aapp, root):
    emp, adm = as_user(aapp, "zz_emp"), as_user(aapp, "zz_adm")
    assert post(emp, "/work/resources/new", name="zz 무단", kind="room").status_code == 403
    assert post(adm, "/work/resources/new", name="zz 새 방", kind="room", location="3층", capacity="12", description="설명").status_code == 303
    assert sql(root, "SELECT capacity, location FROM resources WHERE name='zz 새 방'")[0] == (12, "3층")
    assert post(adm, "/work/resources/new", name="zz 새 방", kind="room").status_code == 409                     # 같은 이름
    for bad in ({"name": ""}, {"name": "x" * 61}, {"kind": "ship"}, {"capacity": "0"}, {"capacity": "501"}, {"capacity": "x"}, {"location": "x" * 61}):
        assert post(adm, "/work/resources/new", **{"name": "zz 잘못", "kind": "room", **bad}).status_code == 409, bad
    rid = sql(root, "SELECT id FROM resources WHERE name='zz 새 방'")[0][0]
    assert post(emp, f"/work/resources/{rid}/toggle").status_code == 403
    assert post(adm, f"/work/resources/{rid}/toggle").status_code == 303
    assert sql(root, "SELECT active FROM resources WHERE id=%s", (rid,))[0][0] == 0
    assert post(adm, f"/work/resources/{rid}/toggle").status_code == 303
    assert sql(root, "SELECT active FROM resources WHERE id=%s", (rid,))[0][0] == 1
    assert post(adm, "/work/resources/999999/toggle").status_code == 404
    assert 'action="/work/resources/new"' not in emp.get("/work/reservations").get_data(as_text=True)         # 직원 화면에는 추가 폼이 없다


# =====================================================================================
# 프로젝트
# =====================================================================================
def project_form(**over):
    return {"name": "zz 새 프로젝트", "description": "설명", "start_date": day_plus(0), "end_date": day_plus(30), **over}


def test_only_manager_or_admin_creates_projects(aapp, root):
    assert as_user(aapp, "zz_emp").get("/work/projects/new").status_code == 403
    assert post(as_user(aapp, "zz_emp"), "/work/projects/new", **project_form()).status_code == 403
    m = as_user(aapp, "zz_mgr")
    assert m.get("/work/projects/new").status_code == 200
    assert post(m, "/work/projects/new", **project_form()).status_code == 303
    pid, owner = sql(root, "SELECT id, owner_id FROM projects WHERE name='zz 새 프로젝트'")[0]
    assert owner == uid(root, "zz_mgr")
    assert sql(root, "SELECT user_id FROM project_members WHERE project_id=%s", (pid,)) == ((uid(root, "zz_mgr"),),)        # 소유자는 첫 구성원
    assert post(m, "/work/projects/new", **project_form()).status_code == 409                                              # 같은 이름


@pytest.mark.parametrize("bad", [{"name": ""}, {"name": "x" * 81}, {"name": "a\x00"}, {"description": "x" * 501},
                                 {"start_date": "2026-02-30"}, {"end_date": "x"}, {"start_date": "2026-05-01", "end_date": "2026-04-01"}])
def test_project_invalid_input(aapp, root, bad):
    r = post(as_user(aapp, "zz_mgr"), "/work/projects/new", **project_form(**bad))
    assert r.status_code == 400 and sql(root, "SELECT COUNT(*) FROM projects WHERE owner_id=%s", (uid(root, "zz_mgr"),))[0][0] == 0


def test_project_visibility(aapp, root):
    pid = make_project(root, "zz_mgr", ["zz_emp"])
    assert as_user(aapp, "zz_emp").get(f"/work/projects/{pid}").status_code == 200
    assert as_user(aapp, "zz_adm").get(f"/work/projects/{pid}").status_code == 200
    assert as_user(aapp, "zz_emp2").get(f"/work/projects/{pid}").status_code == 403                # 같은 부서여도 구성원이 아니면 못 본다
    assert as_user(aapp, "zz_mgrb").get(f"/work/projects/{pid}").status_code == 403
    assert as_user(aapp, "zz_emp").get("/work/projects/999999").status_code == 404
    assert "zz 프로젝트" in as_user(aapp, "zz_emp").get("/work/projects").get_data(as_text=True)
    assert "zz 프로젝트" not in as_user(aapp, "zz_emp2").get("/work/projects").get_data(as_text=True)
    assert "zz 프로젝트" in as_user(aapp, "zz_adm").get("/work/projects").get_data(as_text=True)


def test_project_member_management(aapp, root):
    pid = make_project(root, "zz_mgr", ["zz_emp"])
    owner, member, outsider = as_user(aapp, "zz_mgr"), as_user(aapp, "zz_emp"), as_user(aapp, "zz_emp2")
    assert post(member, f"/work/projects/{pid}/members", user_id=uid(root, "zz_emp2")).status_code == 403      # 구성원도 사람을 추가할 수 없다
    assert post(outsider, f"/work/projects/{pid}/members", user_id=uid(root, "zz_emp2")).status_code == 403
    assert post(owner, f"/work/projects/{pid}/members", user_id=uid(root, "zz_emp2")).status_code == 303
    assert post(owner, f"/work/projects/{pid}/members", user_id=uid(root, "zz_emp2")).status_code == 303      # 중복 추가는 조용히 무시
    assert sql(root, "SELECT COUNT(*) FROM project_members WHERE project_id=%s", (pid,))[0][0] == 3
    for bad in ("999999", "abc", ""):
        assert post(owner, f"/work/projects/{pid}/members", user_id=bad).status_code == 409
    assert as_user(aapp, "zz_emp2").get(f"/work/projects/{pid}").status_code == 200
    assert post(owner, f"/work/projects/{pid}/members/{uid(root, 'zz_mgr')}/remove").status_code == 409        # 소유자는 뺄 수 없다
    assert post(member, f"/work/projects/{pid}/members/{uid(root, 'zz_emp2')}/remove").status_code == 403
    assert post(owner, f"/work/projects/{pid}/members/{uid(root, 'zz_emp2')}/remove").status_code == 303
    assert as_user(aapp, "zz_emp2").get(f"/work/projects/{pid}").status_code == 403
    assert post(owner, "/work/projects/999999/members", user_id=1).status_code == 404


def test_cannot_remove_member_with_open_tasks(aapp, root):
    pid = make_project(root, "zz_mgr", ["zz_emp"])
    t = make_task(root, "zz_mgr", "zz_emp", project=pid)
    owner = as_user(aapp, "zz_mgr")
    assert post(owner, f"/work/projects/{pid}/members/{uid(root, 'zz_emp')}/remove").status_code == 409
    sql(root, "UPDATE tasks SET status='done' WHERE id=%s", (t,))
    assert post(owner, f"/work/projects/{pid}/members/{uid(root, 'zz_emp')}/remove").status_code == 303


def test_project_status_and_progress(aapp, root):
    pid = make_project(root, "zz_mgr", ["zz_emp"])
    make_task(root, "zz_mgr", "zz_emp", "zz 완료 업무", "done", pid)
    make_task(root, "zz_mgr", "zz_emp", "zz 진행 업무", "doing", pid)
    make_task(root, "zz_mgr", "zz_emp", "zz 취소 업무", "cancelled", pid)                      # 취소된 업무는 진척 계산에서 뺀다
    page = as_user(aapp, "zz_emp").get(f"/work/projects/{pid}").get_data(as_text=True)
    assert 'value="50"' in page and "zz 완료 업무" in page and "zz 취소 업무" in page
    assert '1/2' in as_user(aapp, "zz_mgr").get("/work/projects").get_data(as_text=True)
    assert post(as_user(aapp, "zz_emp"), f"/work/projects/{pid}/status", status="done").status_code == 403
    assert post(as_user(aapp, "zz_mgr"), f"/work/projects/{pid}/status", status="done").status_code == 303
    assert sql(root, "SELECT status FROM projects WHERE id=%s", (pid,))[0][0] == "done"
    assert post(as_user(aapp, "zz_mgr"), f"/work/projects/{pid}/status", status="done").status_code == 409
    assert post(as_user(aapp, "zz_adm"), f"/work/projects/{pid}/status", status="active").status_code == 303
    assert post(as_user(aapp, "zz_adm"), f"/work/projects/{pid}/status", status="bogus").status_code == 409


def test_project_text_is_escaped(aapp, root):
    pid = make_project(root, "zz_mgr", [], name="zz <i>이름</i>")
    sql(root, "UPDATE projects SET description='<script>alert(1)</script>' WHERE id=%s", (pid,))
    page = as_user(aapp, "zz_mgr").get(f"/work/projects/{pid}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page and "<i>이름</i>" not in page


# ---------- 기록 ----------
def test_audit_events_are_logged_without_content(aapp, root, events):
    c = as_user(aapp, "zz_emp")
    post(c, "/work/tasks/new", title="비밀스러운 제목")
    names = {e["event_type"] for e in events()}
    assert "task_created" in names
    assert "비밀스러운 제목" not in str(events())
