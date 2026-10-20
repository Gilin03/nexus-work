"""홈 대시보드: 본인 범위의 결재·업무·일정·근태·연차·공지·예약 요약, 홈에서 출퇴근, 관리자 전용 칸. Docker MySQL(nexus_test) 필요, 접속 불가면 skip."""
from datetime import datetime, timedelta

from app import hr
from support import as_user, post, sql, uid


def home(client):
    return client.get("/").get_data(as_text=True)


def section(html, title):
    """위젯 하나의 HTML(제목부터 그 위젯 끝까지)."""
    return html.split(f"<h2>{title}</h2>")[1].split("</section>")[0]


def test_home_shows_date_and_greeting(aapp, root):
    html = home(as_user(aapp, "zz_emp"))
    today = hr.today_kst()
    assert "안녕하세요" in html and f"{today.year}년 {today.month}월 {today.day}일 {'월화수목금토일'[today.weekday()]}요일" in html


def test_my_tasks_only_and_overdue_flag(aapp, root):
    me, other = uid(root, "zz_emp"), uid(root, "zz_emp3")
    yesterday = (hr.today_kst() - timedelta(days=1)).isoformat()
    sql(root, "INSERT INTO tasks(title,creator_id,assignee_id,due_date) VALUES('zz_내 업무',%s,%s,%s)", (me, me, yesterday))
    sql(root, "INSERT INTO tasks(title,creator_id,assignee_id) VALUES('zz_남의 업무',%s,%s)", (other, other))
    sql(root, "INSERT INTO tasks(title,creator_id,assignee_id,status) VALUES('zz_끝난 업무',%s,%s,'done')", (me, me))
    box = section(home(as_user(aapp, "zz_emp")), "내 업무")
    assert "zz_내 업무" in box and "지연" in box and "zz_남의 업무" not in box and "zz_끝난 업무" not in box


def test_waiting_and_my_submitted_approvals(aapp, root):
    emp, mgr = uid(root, "zz_emp"), uid(root, "zz_mgr")
    sql(root, "INSERT INTO approvals(title,body,requester_id,urgency) VALUES('zz_급한 결재','본문',%s,'urgent')", (emp,))
    aid = sql(root, "SELECT MAX(id) FROM approvals")[0][0]
    sql(root, "INSERT INTO approval_steps(approval_id,step_no,approver_id,status) VALUES(%s,1,%s,'pending')", (aid, mgr))
    mgr_html = home(as_user(aapp, "zz_mgr"))
    box = section(mgr_html, "내가 결재할 문서")
    assert "zz_급한 결재" in box and "긴급" in box and "zz_emp" in box
    assert 'stat-n">1</span><span class="stat-l">내가 결재할 문서' in mgr_html
    emp_html = home(as_user(aapp, "zz_emp"))
    assert "zz_급한 결재" in section(emp_html, "내가 올린 결재") and "1/1단계" in section(emp_html, "내가 올린 결재")
    assert "zz_급한 결재" not in section(emp_html, "내가 결재할 문서")
    assert "zz_급한 결재" not in home(as_user(aapp, "zz_emp3"))                                      # 관계없는 사람에게는 안 보인다


def test_week_events_follow_the_calendar_scope(aapp, root):
    me = uid(root, "zz_emp")
    tomorrow = datetime.combine(hr.today_kst() + timedelta(days=1), datetime.min.time()).replace(hour=10)
    for title, scope in (("zz_내 비공개", "private"), ("zz_팀 회의", "team"), ("zz_전사 행사", "company")):
        sql(root, "INSERT INTO events(owner_id,title,start_at,end_at,scope) VALUES(%s,%s,%s,%s,%s)",
            (me, title, tomorrow, tomorrow + timedelta(hours=1), scope))
    mine = section(home(as_user(aapp, "zz_emp")), "이번 주 일정")
    assert all(t in mine for t in ("zz_내 비공개", "zz_팀 회의", "zz_전사 행사")) and "내일 10:00" in mine
    other = section(home(as_user(aapp, "zz_emp3")), "이번 주 일정")                                   # 다른 부서
    assert "zz_전사 행사" in other and "zz_팀 회의" not in other and "zz_내 비공개" not in other


def test_check_in_and_out_from_home_returns_home(aapp, root):
    c = as_user(aapp, "zz_emp")
    assert "출근하기" in home(c) and "출근 전" in home(c)
    r = post(c, "/hr/attendance/check-in", next="home")
    assert r.status_code == 303 and r.headers["Location"].endswith("/")
    html = home(c)
    assert "근무 중" in html and "퇴근하기" in html
    r = post(c, "/hr/attendance/check-out", next="https://evil.example/")                          # 허용 밖 값은 무시하고 근태 화면으로
    assert r.status_code == 303 and r.headers["Location"].endswith("/hr/attendance")
    assert "출근하기" not in home(c) and "퇴근하기" not in home(c)


def test_admin_panel_only_for_admins(aapp, root):
    adm = home(as_user(aapp, "zz_adm"))
    panel = section(adm, "관리")
    assert "/admin/users" in panel and "사용자" in panel
    for who in ("zz_emp", "zz_mgr"):
        assert "<h2>관리</h2>" not in home(as_user(aapp, who))


def test_home_escapes_titles(aapp, root):
    me = uid(root, "zz_emp")
    sql(root, "INSERT INTO tasks(title,creator_id,assignee_id) VALUES('<script>alert(1)</script>',%s,%s)", (me, me))
    html = home(as_user(aapp, "zz_emp"))
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
