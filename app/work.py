"""업무: 업무 관리(할 일), 일정(캘린더), 회의실·비품 예약, 프로젝트.
접근 범위는 모두 서버에서 정한다(화면의 숨김은 편의일 뿐).
- 업무: 만든 사람·담당자·관리자·담당자 부서의 팀장·같은 프로젝트 구성원이 볼 수 있다. 상태는 만든 사람·담당자·관리자만 바꾸고(허용된 전이만, 조건부 UPDATE),
  취소와 취소 되살리기, 담당자 변경은 만든 사람·관리자만 한다. 댓글은 볼 수 있는 사람 누구나.
- 일정: 공개 범위는 나만(참석자 포함)·우리 팀·전사. 비공개 일정은 관리자도 볼 수 없다. 취소는 만든 사람(전사·팀 일정은 관리자도).
- 예약: 30분 단위, 08:00~20:00, 하루 안에서 최대 4시간, 오늘부터 60일 이내. 겹침 검사는 자원 행을 잠근 채로 해서 동시 요청에도 한 건만 들어간다.
- 프로젝트: 구성원과 관리자만 본다. 팀장·관리자가 만들고, 구성원 관리와 종료는 소유자·관리자.
- 모든 SQL 은 상수 문자열 + params 이고, 사용자 입력은 허용목록·길이·범위로 검증한다."""
import calendar as pycal
import re
from datetime import date, datetime, time, timedelta

import pymysql
from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from . import db, validators
from .approvals import conflict, forbidden
from .auth import login_required, role_required
from .permissions import can, permission_required
from .hr import _parse_day, now_kst, today_kst
from .security import log_event

bp = Blueprint("work", __name__, url_prefix="/work")

PRIORITY = {"low": "낮음", "normal": "보통", "high": "높음"}
TASK_STATUS = {"todo": "할 일", "doing": "진행 중", "done": "완료", "cancelled": "취소"}
TRANSITIONS = {"todo": {"doing", "done", "cancelled"}, "doing": {"todo", "done", "cancelled"}, "done": {"doing"}, "cancelled": {"todo"}}
TASK_BOXES = (("mine", "내 업무"), ("requested", "요청한 업무"), ("team", "팀 업무"))
TASK_STATES = (("open", "진행 중"), ("closed", "완료·취소"), ("all", "전체"))
SCOPES = {"private": "나만 보기(참석자 포함)", "team": "우리 팀", "company": "전사"}
RESOURCE_KINDS = {"room": "회의실", "equipment": "비품"}
PROJECT_STATUS = {"active": "진행 중", "done": "종료"}

TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
MONTH_RE = re.compile(r"^(\d{4})-(0[1-9]|1[0-2])$")
MAX_DUE_PAST, MAX_DUE_FUTURE = 30, 730
MAX_EVENT_PAST, MAX_EVENT_FUTURE, MAX_EVENT_DAYS = 365, 730, 14
MAX_ATTENDEES = 30
OPEN_HOUR, CLOSE_HOUR, MAX_RESERVE_HOURS, RESERVE_AHEAD_DAYS, MAX_ACTIVE_RESERVATIONS = 8, 20, 4, 60, 10
SLOTS = [f"{h:02d}:{m:02d}" for h in range(OPEN_HOUR, CLOSE_HOUR + 1) for m in (0, 30) if not (h == CLOSE_HOUR and m)]

MESSAGES = {
    "title": "제목은 1~120자로 입력하세요(제어문자 사용 불가).",
    "description": "내용은 2000자 이하로 입력하세요.",
    "assignee": "담당자를 선택하세요.",
    "priority": "우선순위를 선택하세요.",
    "due": f"마감일은 YYYY-MM-DD 형식이며 오늘 기준 {MAX_DUE_PAST}일 전부터 {MAX_DUE_FUTURE}일 후까지 입력할 수 있습니다.",
    "project": "프로젝트를 선택할 수 없습니다(구성원인 프로젝트만 고를 수 있고, 담당자도 구성원이어야 합니다).",
    "comment": "댓글은 1~1000자로 입력하세요(제어문자 사용 불가).",
    "ev_title": "일정 제목은 1~100자로 입력하세요(제어문자 사용 불가).",
    "ev_text": "장소는 100자, 내용은 1000자 이하로 입력하세요.",
    "ev_scope": "공개 범위를 선택하세요.",
    "ev_date": f"날짜는 YYYY-MM-DD 형식이며 오늘 기준 {MAX_EVENT_PAST}일 전부터 {MAX_EVENT_FUTURE}일 후까지입니다.",
    "ev_time": "시각은 HH:MM 형식으로 입력하세요(종일이 아니면 필수).",
    "ev_range": f"종료가 시작보다 빠르거나 기간이 {MAX_EVENT_DAYS}일을 넘습니다.",
    "ev_attendee": f"참석자는 {MAX_ATTENDEES}명까지, 존재하는 직원만 고를 수 있습니다.",
    "r_slot": "시간은 30분 단위로 08:00~20:00 사이에서 고르세요.",
    "r_range": f"종료가 시작보다 늦어야 하고, 하루 안에서 최대 {MAX_RESERVE_HOURS}시간까지 예약할 수 있습니다.",
    "r_date": f"예약은 오늘부터 {RESERVE_AHEAD_DAYS}일 이내 날짜만 가능하며 이미 지난 시간은 예약할 수 없습니다.",
    "r_purpose": "사용 목적은 1~100자로 입력하세요(제어문자 사용 불가).",
    "r_overlap": "그 시간에는 이미 다른 예약이 있습니다.",
    "r_limit": f"진행 중인 예약은 {MAX_ACTIVE_RESERVATIONS}건까지 가능합니다. 지난 예약이나 취소 후 다시 시도하세요.",
    "res_name": "이름은 1~60자로 입력하세요(제어문자 사용 불가).",
    "res_field": "구분·위치(60자)·수용 인원(1~500)·설명(200자)을 확인하세요.",
    "res_dup": "같은 이름의 자원이 이미 있습니다.",
    "p_name": "프로젝트 이름은 1~80자로 입력하세요(제어문자 사용 불가).",
    "p_desc": "설명은 500자 이하로 입력하세요.",
    "p_dates": "기간은 YYYY-MM-DD 형식이어야 하고 종료일이 시작일보다 빠를 수 없습니다.",
    "p_dup": "같은 이름의 프로젝트가 이미 있습니다.",
}


def _users():
    return db.query_all("SELECT id, display_name, dept FROM users WHERE deleted_at IS NULL ORDER BY dept, display_name LIMIT 300")


def _fail(field, key):
    log_event("input_rejected", "DENY", key, field=field)
    return MESSAGES[key]


def _optional_date(raw, past, future):
    """빈 값이면 None, 아니면 날짜. 범위를 벗어나면 ValueError."""
    if not raw:
        return None
    d = _parse_day(raw)
    today = today_kst()
    if not (today - timedelta(days=past) <= d <= today + timedelta(days=future)):
        raise ValueError("range")
    return d


def _positive(raw):
    try:
        return validators.positive_int(raw, "id")
    except ValueError:
        return None


# =====================================================================================
# 업무 관리(할 일)
# =====================================================================================
def _task_row(task_id):
    return db.query_one(
        "SELECT t.id, t.title, t.description, t.creator_id, t.assignee_id, t.project_id, t.priority, t.due_date, t.status, "
        "t.completed_at, t.created_at, a.display_name AS assignee, a.dept AS assignee_dept, c.display_name AS creator, "
        "p.name AS project FROM tasks t JOIN users a ON a.id = t.assignee_id JOIN users c ON c.id = t.creator_id "
        "LEFT JOIN projects p ON p.id = t.project_id WHERE t.id = %s", (task_id,))


def _is_member(project_id, user_id):
    return bool(db.query_one("SELECT 1 AS x FROM project_members WHERE project_id = %s AND user_id = %s", (project_id, user_id)))


def _task_visible(t):
    u = g.user
    if u["id"] in (t["creator_id"], t["assignee_id"]) or u["role"] == "admin":
        return True
    if u["role"] == "manager" and u["dept"] == t["assignee_dept"]:
        return True
    return bool(t["project_id"] and _is_member(t["project_id"], u["id"]))


def _can_change_task(t):
    return g.user["id"] in (t["creator_id"], t["assignee_id"]) or g.user["role"] == "admin"


def _my_projects():
    return db.query_all("SELECT p.id, p.name FROM projects p WHERE p.status = 'active' AND (%s = 'admin' OR EXISTS("
                        "SELECT 1 FROM project_members m WHERE m.project_id = p.id AND m.user_id = %s)) ORDER BY p.name LIMIT 100",
                        (g.user["role"], g.user["id"]))


@bp.get("/tasks")
@login_required
def task_list():
    box = request.args.get("box", "mine")
    state = request.args.get("state", "open")
    if box not in dict(TASK_BOXES) or state not in dict(TASK_STATES):
        abort(400)
    if box == "team" and g.user["role"] == "employee":
        return forbidden("insufficient_role", resource="work_tasks_team")
    u = g.user
    rows = db.query_all(
        "SELECT t.id, t.title, t.priority, t.due_date, t.status, t.project_id, a.display_name AS assignee, c.display_name AS creator, p.name AS project "
        "FROM tasks t JOIN users a ON a.id = t.assignee_id JOIN users c ON c.id = t.creator_id LEFT JOIN projects p ON p.id = t.project_id "
        "WHERE ((%s = 'mine' AND t.assignee_id = %s) OR (%s = 'requested' AND t.creator_id = %s AND t.assignee_id <> %s) "
        "OR (%s = 'team' AND (%s = 'admin' OR (%s = 'manager' AND a.dept = %s)))) "
        "AND (%s = 'all' OR (%s = 'open' AND t.status IN ('todo', 'doing')) OR (%s = 'closed' AND t.status IN ('done', 'cancelled'))) "
        "ORDER BY t.due_date IS NULL, t.due_date, FIELD(t.priority, 'high', 'normal', 'low'), t.id DESC LIMIT 200",
        (box, u["id"], box, u["id"], u["id"], box, u["role"], u["role"], u["dept"], state, state, state))
    today = today_kst()
    for r in rows:
        r["overdue"] = bool(r["due_date"] and r["due_date"] < today and r["status"] in ("todo", "doing"))
    counts = db.query_one(
        "SELECT SUM(assignee_id = %s AND status IN ('todo', 'doing')) AS mine_open, "
        "SUM(creator_id = %s AND assignee_id <> %s AND status IN ('todo', 'doing')) AS requested_open "
        "FROM tasks WHERE assignee_id = %s OR creator_id = %s", (u["id"],) * 5)
    boxes = [b for b in TASK_BOXES if b[0] != "team" or u["role"] != "employee"]
    return render_template("work_tasks.html", rows=rows, box=box, state=state, boxes=boxes, states=TASK_STATES,
                           counts={"mine": int(counts["mine_open"] or 0), "requested": int(counts["requested_open"] or 0)},
                           statuses=TASK_STATUS, priorities=PRIORITY)


def _task_form(values=None, error=None, status=200):
    return render_template("work_task_form.html", values=values or {}, error=error, users=_users(), projects=_my_projects(),
                           priorities=PRIORITY), status


@bp.route("/tasks/new", methods=["GET", "POST"])
@login_required
def task_new():
    if request.method == "GET":
        project = request.args.get("project", "")
        return _task_form({"assignee_id": str(g.user["id"]), "priority": "normal", "project_id": project if project.isdigit() else ""})
    f = request.form
    values = {k: f.get(k, "") for k in ("title", "description", "assignee_id", "priority", "due_date", "project_id")}
    values["priority"] = f.get("priority", "normal")        # 보내지 않으면 보통, 이상한 값이면 거부
    try:
        try:
            title = validators.text(values["title"], "title", 1, 120)
        except ValueError:
            raise ValueError("title")
        try:
            desc = validators.text(values["description"], "description", 0, 2000, multiline=True)
        except ValueError:
            raise ValueError("description")
        assignee_id = _positive(values["assignee_id"] or str(g.user["id"]))
        if assignee_id is None or not db.query_one("SELECT id FROM users WHERE id = %s AND deleted_at IS NULL", (assignee_id,)):
            raise ValueError("assignee")
        if values["priority"] not in PRIORITY:
            raise ValueError("priority")
        try:
            due = _optional_date(values["due_date"], MAX_DUE_PAST, MAX_DUE_FUTURE)
        except ValueError:
            raise ValueError("due")
        project_id = None
        if values["project_id"]:
            project_id = _positive(values["project_id"])
            ok = project_id and db.query_one("SELECT id FROM projects WHERE id = %s AND status = 'active'", (project_id,))
            if not ok or not (_is_member(project_id, g.user["id"]) or g.user["role"] == "admin") or not _is_member(project_id, assignee_id):
                raise ValueError("project")
    except ValueError as exc:
        key = str(exc) if str(exc) in MESSAGES else "title"
        return _task_form(values, _fail("task", key), 400)
    task_id = db.execute("INSERT INTO tasks(title, description, creator_id, assignee_id, project_id, priority, due_date) "
                         "VALUES(%s, %s, %s, %s, %s, %s, %s)",
                         (title, desc, g.user["id"], assignee_id, project_id, values["priority"], due))
    log_event("task_created", "INFO", "ok", task_id=task_id, assignee_id=assignee_id, project_id=project_id)
    return redirect(url_for("work.task_detail", task_id=task_id), 303)


def _render_task(task_id, error=None, status=200):
    t = _task_row(task_id)
    if not t:
        abort(404)
    if not _task_visible(t):
        return forbidden("not_visible", resource=f"task:{task_id}")
    comments = db.query_all("SELECT c.body, c.created_at, u.display_name FROM task_comments c JOIN users u ON u.id = c.user_id "
                            "WHERE c.task_id = %s ORDER BY c.id LIMIT 300", (task_id,))
    can_change = _can_change_task(t)
    manage = g.user["id"] == t["creator_id"] or g.user["role"] == "admin"
    allowed = sorted(TRANSITIONS[t["status"]]) if can_change else []
    if "cancelled" in allowed and not manage:
        allowed.remove("cancelled")
    if t["status"] == "cancelled" and not manage:
        allowed = []
    members = None
    if manage and t["status"] in ("todo", "doing"):
        members = (db.query_all("SELECT u.id, u.display_name, u.dept FROM project_members m JOIN users u ON u.id = m.user_id "
                                "WHERE m.project_id = %s ORDER BY u.display_name", (t["project_id"],))
                   if t["project_id"] else _users())
    return render_template("work_task.html", t=t, comments=comments, allowed=allowed, members=members, statuses=TASK_STATUS,
                           priorities=PRIORITY, error=error, overdue=bool(t["due_date"] and t["due_date"] < today_kst() and t["status"] in ("todo", "doing"))), status


@bp.get("/tasks/<int:task_id>")
@login_required
def task_detail(task_id):
    return _render_task(task_id)


@bp.post("/tasks/<int:task_id>/status")
@login_required
def task_status(task_id):
    t = db.query_one("SELECT id, creator_id, assignee_id, status FROM tasks WHERE id = %s FOR UPDATE", (task_id,))
    if not t:
        abort(404)
    if not _can_change_task(t):
        return forbidden("not_participant", resource=f"task:{task_id}")
    new = request.form.get("status", "")
    if new not in TASK_STATUS or new not in TRANSITIONS[t["status"]]:
        log_event("task_invalid_transition", "DENY", f"{t['status']}->{new[:20]}", task_id=task_id)
        return conflict("이 상태에서는 선택한 상태로 바꿀 수 없습니다.")
    if "cancelled" in (new, t["status"]) and g.user["id"] != t["creator_id"] and g.user["role"] != "admin":
        return forbidden("task_cancel_not_creator", resource=f"task:{task_id}")
    n = db.execute_rowcount("UPDATE tasks SET status = %s, completed_at = %s WHERE id = %s AND status = %s",
                            (new, now_kst() if new == "done" else None, task_id, t["status"]))
    if not n:
        return conflict("다른 곳에서 먼저 상태가 바뀌었습니다. 새로 고침 후 다시 시도하세요.")
    log_event("task_status", "INFO", f"{t['status']}->{new}", task_id=task_id)
    return redirect(url_for("work.task_detail", task_id=task_id), 303)


@bp.post("/tasks/<int:task_id>/assign")
@login_required
def task_assign(task_id):
    t = db.query_one("SELECT id, creator_id, assignee_id, project_id, status FROM tasks WHERE id = %s FOR UPDATE", (task_id,))
    if not t:
        abort(404)
    if g.user["id"] != t["creator_id"] and g.user["role"] != "admin":
        return forbidden("not_creator", resource=f"task:{task_id}")
    new = _positive(request.form.get("assignee_id", ""))
    ok = new and db.query_one("SELECT id FROM users WHERE id = %s AND deleted_at IS NULL", (new,)) and (not t["project_id"] or _is_member(t["project_id"], new))
    if not ok or t["status"] not in ("todo", "doing"):
        log_event("input_rejected", "DENY", "assignee", field="task_assign")
        return conflict("담당자를 바꿀 수 없습니다(진행 중인 업무에서, 프로젝트 업무는 구성원에게만 가능합니다).")
    n = db.execute_rowcount("UPDATE tasks SET assignee_id = %s WHERE id = %s AND status IN ('todo', 'doing')", (new, task_id))
    if not n:
        return conflict("다른 곳에서 먼저 상태가 바뀌었습니다.")
    log_event("task_assigned", "INFO", "ok", task_id=task_id, assignee_id=new)
    return redirect(url_for("work.task_detail", task_id=task_id), 303)


@bp.post("/tasks/<int:task_id>/comment")
@login_required
def task_comment(task_id):
    t = _task_row(task_id)
    if not t:
        abort(404)
    if not _task_visible(t):
        return forbidden("not_visible", resource=f"task:{task_id}")
    try:
        body = validators.text(request.form.get("body", ""), "body", 1, 1000, multiline=True)
    except ValueError:
        return _render_task(task_id, _fail("task_comment", "comment"), 400)
    db.execute("INSERT INTO task_comments(task_id, user_id, body) VALUES(%s, %s, %s)", (task_id, g.user["id"], body))
    log_event("task_comment", "INFO", "ok", task_id=task_id)
    return redirect(url_for("work.task_detail", task_id=task_id) + "#comments", 303)


# =====================================================================================
# 일정(캘린더)
# =====================================================================================
def _month_bounds(raw):
    m = MONTH_RE.match(raw or "")
    if raw and not m:
        raise ValueError("month")
    today = today_kst()
    y, mo = (int(m.group(1)), int(m.group(2))) if m else (today.year, today.month)
    if not 2000 <= y <= 2100:
        raise ValueError("month")
    return y, mo


def _shift(y, mo, delta):
    idx = y * 12 + mo - 1 + delta
    return idx // 12, idx % 12 + 1


def _event_visible(e, attendee_ids):
    u = g.user
    return (e["owner_id"] == u["id"] or e["scope"] == "company" or u["id"] in attendee_ids
            or (e["scope"] == "team" and e["owner_dept"] == u["dept"]))


@bp.get("/calendar")
@login_required
def calendar():
    error, status = None, 200
    try:
        y, mo = _month_bounds(request.args.get("month"))
    except ValueError:
        log_event("input_rejected", "DENY", "month", field="calendar")
        y, mo = _month_bounds(None)
        error, status = "월은 YYYY-MM 형식으로 입력하세요.", 400
    weeks = pycal.Calendar(firstweekday=6).monthdatescalendar(y, mo)
    first, last = weeks[0][0], weeks[-1][-1]
    lo, hi = datetime.combine(first, time.min), datetime.combine(last + timedelta(days=1), time.min)
    u = g.user
    cells = {d: [] for w in weeks for d in w}

    def put(d_from, d_to, item):
        d = max(d_from, first)
        while d <= min(d_to, last):
            cells[d].append(item)
            d += timedelta(days=1)

    events = db.query_all(
        "SELECT e.id, e.title, e.start_at, e.end_at, e.all_day FROM events e JOIN users o ON o.id = e.owner_id "
        "WHERE e.status = 'active' AND e.start_at < %s AND e.end_at >= %s AND (e.owner_id = %s OR e.scope = 'company' "
        "OR (e.scope = 'team' AND o.dept = %s) OR EXISTS(SELECT 1 FROM event_attendees x WHERE x.event_id = e.id AND x.user_id = %s)) "
        "ORDER BY e.start_at LIMIT 500", (hi, lo, u["id"], u["dept"], u["id"]))
    for e in events:
        label = e["title"] if e["all_day"] else f"{e['start_at'].strftime('%H:%M')} {e['title']}"
        put(e["start_at"].date(), e["end_at"].date(), {"kind": "event", "label": label, "href": url_for("work.event_detail", event_id=e["id"])})
    leaves = db.query_all(
        "SELECT r.start_date, r.end_date, r.leave_type, x.display_name FROM leave_requests r JOIN users x ON x.id = r.user_id "
        "WHERE r.status = 'approved' AND r.start_date <= %s AND r.end_date >= %s "
        "AND (%s = 'admin' OR x.id = %s OR (%s = 'manager' AND x.dept = %s)) ORDER BY r.start_date LIMIT 300",
        (last, first, u["role"], u["id"], u["role"], u["dept"]))
    leave_names = {"annual": "연차", "half": "반차", "sick": "병가"}
    for r in leaves:
        put(r["start_date"], r["end_date"], {"kind": "leave", "label": f"{r['display_name']} {leave_names[r['leave_type']]}", "href": url_for("hr.leave_list")})
    due = db.query_all("SELECT id, title, due_date FROM tasks WHERE assignee_id = %s AND status IN ('todo', 'doing') "
                       "AND due_date >= %s AND due_date <= %s ORDER BY due_date LIMIT 300", (u["id"], first, last))
    for t in due:
        put(t["due_date"], t["due_date"], {"kind": "task", "label": f"마감 {t['title']}", "href": url_for("work.task_detail", task_id=t["id"])})
    py, pm = _shift(y, mo, -1)
    ny, nm = _shift(y, mo, 1)
    return render_template("work_calendar.html", weeks=weeks, cells=cells, y=y, mo=mo, today=today_kst(), error=error,
                           prev=f"{py}-{pm:02d}", next=f"{ny}-{nm:02d}"), status


def _event_form(values=None, error=None, status=200):
    return render_template("work_event_form.html", values=values or {}, error=error, users=_users(), scopes=SCOPES), status


@bp.route("/events/new", methods=["GET", "POST"])
@login_required
def event_new():
    if request.method == "GET":
        d = request.args.get("date", "")
        try:
            d = _parse_day(d).isoformat()
        except ValueError:
            d = today_kst().isoformat()
        return _event_form({"start_date": d, "start_time": "10:00", "end_time": "11:00", "scope": "team"})
    f = request.form
    values = {k: f.get(k, "") for k in ("title", "start_date", "start_time", "end_date", "end_time", "location", "description", "scope")}
    values["all_day"] = "1" if f.get("all_day") else ""
    values["attendees"] = f.getlist("attendees")
    try:
        try:
            title = validators.text(values["title"], "title", 1, 100)
        except ValueError:
            raise ValueError("ev_title")
        try:
            location = validators.text(values["location"], "location", 0, 100)
            desc = validators.text(values["description"], "description", 0, 1000, multiline=True)
        except ValueError:
            raise ValueError("ev_text")
        if values["scope"] not in SCOPES:
            raise ValueError("ev_scope")
        try:
            start_day = _optional_date(values["start_date"], MAX_EVENT_PAST, MAX_EVENT_FUTURE)
            end_day = _optional_date(values["end_date"], MAX_EVENT_PAST + MAX_EVENT_DAYS, MAX_EVENT_FUTURE + MAX_EVENT_DAYS) or start_day
        except ValueError:
            raise ValueError("ev_date")
        if start_day is None:
            raise ValueError("ev_date")
        all_day = bool(values["all_day"])
        if all_day:
            start_at, end_at = datetime.combine(start_day, time(0, 0)), datetime.combine(end_day, time(23, 59))
        else:
            ms, me = TIME_RE.match(values["start_time"]), TIME_RE.match(values["end_time"] or values["start_time"])
            if not ms or not me:
                raise ValueError("ev_time")
            start_at = datetime.combine(start_day, time(int(ms.group(1)), int(ms.group(2))))
            end_at = datetime.combine(end_day, time(int(me.group(1)), int(me.group(2))))
        if end_at < start_at or end_at - start_at > timedelta(days=MAX_EVENT_DAYS):
            raise ValueError("ev_range")
        ids = []
        if len(values["attendees"]) > MAX_ATTENDEES * 2:
            raise ValueError("ev_attendee")
        known = {r["id"] for r in db.query_all("SELECT id FROM users WHERE deleted_at IS NULL LIMIT 1000")}
        for raw in values["attendees"]:
            n = _positive(raw)
            if n is None or n not in known:
                raise ValueError("ev_attendee")
            if n != g.user["id"] and n not in ids:
                ids.append(n)
        if len(ids) > MAX_ATTENDEES:
            raise ValueError("ev_attendee")
    except ValueError as exc:
        key = str(exc) if str(exc) in MESSAGES else "ev_title"
        return _event_form(values, _fail("event", key), 400)
    event_id = db.execute("INSERT INTO events(owner_id, title, location, description, start_at, end_at, all_day, scope) "
                          "VALUES(%s, %s, %s, %s, %s, %s, %s, %s)",
                          (g.user["id"], title, location, desc, start_at, end_at, int(all_day), values["scope"]))
    for n in ids:
        db.execute("INSERT INTO event_attendees(event_id, user_id) VALUES(%s, %s)", (event_id, n))
    log_event("event_created", "INFO", "ok", event_id=event_id, scope=values["scope"], attendees=len(ids))
    return redirect(url_for("work.event_detail", event_id=event_id), 303)


def _load_event(event_id):
    e = db.query_one("SELECT e.id, e.owner_id, e.title, e.location, e.description, e.start_at, e.end_at, e.all_day, e.scope, e.status, "
                     "o.display_name AS owner, o.dept AS owner_dept FROM events e JOIN users o ON o.id = e.owner_id WHERE e.id = %s", (event_id,))
    if not e:
        abort(404)
    people = db.query_all("SELECT u.id, u.display_name, u.dept FROM event_attendees a JOIN users u ON u.id = a.user_id "
                          "WHERE a.event_id = %s ORDER BY u.display_name", (event_id,))
    return e, people


@bp.get("/events/<int:event_id>")
@login_required
def event_detail(event_id):
    e, people = _load_event(event_id)
    if not _event_visible(e, {p["id"] for p in people}):
        return forbidden("not_visible", resource=f"event:{event_id}")
    can_cancel = e["status"] == "active" and (e["owner_id"] == g.user["id"] or (g.user["role"] == "admin" and e["scope"] != "private"))
    return render_template("work_event.html", e=e, people=people, scopes=SCOPES, can_cancel=can_cancel)


@bp.post("/events/<int:event_id>/cancel")
@login_required
def event_cancel(event_id):
    e = db.query_one("SELECT id, owner_id, scope, status FROM events WHERE id = %s FOR UPDATE", (event_id,))
    if not e:
        abort(404)
    if not (e["owner_id"] == g.user["id"] or (g.user["role"] == "admin" and e["scope"] != "private")):
        return forbidden("not_owner", resource=f"event:{event_id}")
    n = db.execute_rowcount("UPDATE events SET status = 'cancelled' WHERE id = %s AND status = 'active'", (event_id,))
    if not n:
        return conflict("이미 취소된 일정입니다.")
    log_event("event_cancelled", "INFO", "ok", event_id=event_id)
    return redirect(url_for("work.calendar"), 303)


# =====================================================================================
# 회의실·비품 예약
# =====================================================================================
def _floor_half_hour(dt):
    return dt.replace(minute=0 if dt.minute < 30 else 30, second=0, microsecond=0)


def _reservation_day(raw):
    """조회 날짜: 비어 있으면 오늘. 형식이 틀리면 ValueError."""
    return _parse_day(raw) if raw else today_kst()


@bp.get("/reservations")
@login_required
def reservation_list():
    kind = request.args.get("kind", "")
    error, status = None, 200
    if kind and kind not in RESOURCE_KINDS:
        abort(400)
    try:
        day = _reservation_day(request.args.get("date", ""))
    except ValueError:
        log_event("input_rejected", "DENY", "date", field="reservation_day")
        day, error, status = today_kst(), "날짜는 YYYY-MM-DD 형식으로 입력하세요.", 400
    resources = db.query_all("SELECT id, name, kind, location, capacity, description, active FROM resources "
                             "WHERE (active = 1 OR %s = 'admin') AND (%s = '' OR kind = %s) ORDER BY kind, name LIMIT 100",
                             (g.user["role"], kind, kind))
    day_start = datetime.combine(day, time.min)
    booked = db.query_all("SELECT r.id, r.resource_id, r.user_id, r.start_at, r.end_at, r.purpose, u.display_name FROM reservations r "
                          "JOIN users u ON u.id = r.user_id WHERE r.status = 'active' AND r.start_at < %s AND r.end_at > %s "
                          "ORDER BY r.start_at LIMIT 500", (day_start + timedelta(days=1), day_start))
    by_res = {}
    for b in booked:
        by_res.setdefault(b["resource_id"], []).append(b)
    mine = db.query_all("SELECT r.id, r.start_at, r.end_at, r.purpose, s.name AS resource FROM reservations r JOIN resources s ON s.id = r.resource_id "
                        "WHERE r.user_id = %s AND r.status = 'active' AND r.end_at > %s ORDER BY r.start_at LIMIT 50", (g.user["id"], now_kst()))
    return render_template("work_reservations.html", resources=resources, by_res=by_res, mine=mine, day=day, kind=kind, kinds=RESOURCE_KINDS,
                           prev=(day - timedelta(days=1)).isoformat(), next=(day + timedelta(days=1)).isoformat(), error=error,
                           me=g.user["id"], is_admin=g.user["role"] == "admin"), status


def _reserve_form(res, values, error=None, status=200):
    return render_template("work_reserve_form.html", res=res, values=values, error=error, slots=SLOTS,
                           max_hours=MAX_RESERVE_HOURS, ahead=RESERVE_AHEAD_DAYS), status


@bp.route("/reservations/new", methods=["GET", "POST"])
@login_required
def reservation_new():
    src = request.args if request.method == "GET" else request.form
    rid = _positive(src.get("resource_id", ""))
    res = rid and db.query_one("SELECT id, name, kind, location, capacity, description, active FROM resources WHERE id = %s", (rid,))
    if not res or not res["active"]:
        abort(404)
    if request.method == "GET":
        try:
            day = _reservation_day(request.args.get("date", "")).isoformat()
        except ValueError:
            day = today_kst().isoformat()
        return _reserve_form(res, {"date": day, "start_time": "10:00", "end_time": "11:00"})
    values = {k: request.form.get(k, "") for k in ("date", "start_time", "end_time", "purpose")}
    try:
        try:
            day = _parse_day(values["date"])
        except ValueError:
            raise ValueError("r_date")
        if values["start_time"] not in SLOTS or values["end_time"] not in SLOTS:
            raise ValueError("r_slot")
        start_at = datetime.combine(day, datetime.strptime(values["start_time"], "%H:%M").time())
        end_at = datetime.combine(day, datetime.strptime(values["end_time"], "%H:%M").time())
        if end_at <= start_at or end_at - start_at > timedelta(hours=MAX_RESERVE_HOURS):
            raise ValueError("r_range")
        now = now_kst()
        if day > now.date() + timedelta(days=RESERVE_AHEAD_DAYS) or start_at < _floor_half_hour(now):
            raise ValueError("r_date")
        try:
            purpose = validators.text(values["purpose"], "purpose", 1, 100)
        except ValueError:
            raise ValueError("r_purpose")
    except ValueError as exc:
        key = str(exc) if str(exc) in MESSAGES else "r_slot"
        return _reserve_form(res, values, _fail("reservation", key), 400)
    # 자원 행을 잠가 같은 자원에 대한 동시 예약을 한 줄로 세운 뒤 겹침·개수를 검사한다. 이 검사는 잠금 읽기(FOR UPDATE)여야 한다:
    # 요청 앞부분에서 이미 일반 읽기로 스냅샷이 잡혀 있어, 일반 읽기로는 먼저 끝난 다른 요청의 예약이 보이지 않는다.
    locked = db.query_one("SELECT id FROM resources WHERE id = %s AND active = 1 FOR UPDATE", (res["id"],))
    if not locked:
        abort(404)
    clash = db.query_one("SELECT id FROM reservations WHERE resource_id = %s AND status = 'active' AND start_at < %s AND end_at > %s LIMIT 1 FOR UPDATE",
                         (res["id"], end_at, start_at))
    if clash:
        log_event("reservation_rejected", "DENY", "overlap", resource_id=res["id"])
        return _reserve_form(res, values, MESSAGES["r_overlap"], 409)
    active = db.query_one("SELECT COUNT(*) AS n FROM reservations WHERE user_id = %s AND status = 'active' AND end_at > %s FOR UPDATE",
                          (g.user["id"], now_kst()))["n"]
    if active >= MAX_ACTIVE_RESERVATIONS:
        log_event("reservation_rejected", "DENY", "user_limit")
        return _reserve_form(res, values, MESSAGES["r_limit"], 409)
    rid = db.execute("INSERT INTO reservations(resource_id, user_id, start_at, end_at, purpose) VALUES(%s, %s, %s, %s, %s)",
                     (res["id"], g.user["id"], start_at, end_at, purpose))
    log_event("reservation_created", "INFO", "ok", reservation_id=rid, resource_id=res["id"])
    return redirect(url_for("work.reservation_list", date=day.isoformat()), 303)


@bp.post("/reservations/<int:reservation_id>/cancel")
@login_required
def reservation_cancel(reservation_id):
    r = db.query_one("SELECT id, user_id, status, end_at, start_at FROM reservations WHERE id = %s FOR UPDATE", (reservation_id,))
    if not r:
        abort(404)
    if r["user_id"] != g.user["id"] and g.user["role"] != "admin":
        return forbidden("not_owner", resource=f"reservation:{reservation_id}")
    n = db.execute_rowcount("UPDATE reservations SET status = 'cancelled' WHERE id = %s AND status = 'active' AND end_at > %s",
                            (reservation_id, now_kst()))
    if not n:
        return conflict("이미 취소되었거나 끝난 예약입니다.")
    log_event("reservation_cancelled", "INFO", "ok", reservation_id=reservation_id)
    return redirect(url_for("work.reservation_list", date=r["start_at"].date().isoformat()), 303)


@bp.post("/resources/new")
@role_required("admin")
def resource_new():
    f = request.form
    try:
        try:
            name = validators.text(f.get("name", ""), "name", 1, 60)
        except ValueError:
            raise ValueError("res_name")
        kind = f.get("kind", "")
        try:
            location = validators.text(f.get("location", ""), "location", 0, 60)
            desc = validators.text(f.get("description", ""), "description", 0, 200)
            capacity = validators.positive_int(f["capacity"], "capacity", 500) if f.get("capacity") else None
        except ValueError:
            raise ValueError("res_field")
        if kind not in RESOURCE_KINDS:
            raise ValueError("res_field")
        if db.query_one("SELECT id FROM resources WHERE name = %s", (name,)):
            raise ValueError("res_dup")
    except ValueError as exc:
        key = str(exc) if str(exc) in MESSAGES else "res_field"
        log_event("input_rejected", "DENY", key, field="resource")
        return conflict(MESSAGES[key])
    try:
        rid = db.execute("INSERT INTO resources(name, kind, location, capacity, description) VALUES(%s, %s, %s, %s, %s)",
                         (name, kind, location, capacity, desc))
    except pymysql.err.IntegrityError:
        return conflict(MESSAGES["res_dup"])
    log_event("resource_created", "INFO", "ok", resource_id=rid)
    return redirect(url_for("work.reservation_list"), 303)


@bp.post("/resources/<int:resource_id>/toggle")
@role_required("admin")
def resource_toggle(resource_id):
    r = db.query_one("SELECT id, active FROM resources WHERE id = %s FOR UPDATE", (resource_id,))
    if not r:
        abort(404)
    db.execute_rowcount("UPDATE resources SET active = %s WHERE id = %s", (0 if r["active"] else 1, resource_id))
    log_event("resource_toggled", "INFO", "off" if r["active"] else "on", resource_id=resource_id)
    return redirect(url_for("work.reservation_list"), 303)


# =====================================================================================
# 프로젝트
# =====================================================================================
def _project_row(project_id):
    return db.query_one("SELECT p.id, p.name, p.description, p.owner_id, p.status, p.start_date, p.end_date, p.created_at, "
                        "o.display_name AS owner FROM projects p JOIN users o ON o.id = p.owner_id WHERE p.id = %s", (project_id,))


def _project_access(project_id):
    """(프로젝트, 구성원 여부) 또는 오류 응답. 구성원과 관리자만 열 수 있다."""
    p = _project_row(project_id)
    if not p:
        abort(404)
    member = _is_member(project_id, g.user["id"])
    if not member and g.user["role"] != "admin":
        return forbidden("not_member", resource=f"project:{project_id}")
    return p, member


def _manage_project(p):
    return g.user["id"] == p["owner_id"] or g.user["role"] == "admin"


@bp.get("/projects")
@login_required
def project_list():
    rows = db.query_all(
        "SELECT p.id, p.name, p.status, p.start_date, p.end_date, o.display_name AS owner, "
        "(SELECT COUNT(*) FROM project_members m WHERE m.project_id = p.id) AS members, "
        "(SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id AND t.status <> 'cancelled') AS total, "
        "(SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id AND t.status = 'done') AS done "
        "FROM projects p JOIN users o ON o.id = p.owner_id "
        "WHERE %s = 'admin' OR EXISTS(SELECT 1 FROM project_members m WHERE m.project_id = p.id AND m.user_id = %s) "
        "ORDER BY p.status, p.id DESC LIMIT 200", (g.user["role"], g.user["id"]))
    for r in rows:
        r["percent"] = int(100 * r["done"] / r["total"]) if r["total"] else 0
    return render_template("work_projects.html", rows=rows, statuses=PROJECT_STATUS, can_create=can(g.user, "project.create"))


@bp.route("/projects/new", methods=["GET", "POST"])
@permission_required("project.create")
def project_new():
    if request.method == "GET":
        return render_template("work_project_form.html", values={}, error=None)
    f = request.form
    values = {k: f.get(k, "") for k in ("name", "description", "start_date", "end_date")}
    try:
        try:
            name = validators.text(values["name"], "name", 1, 80)
        except ValueError:
            raise ValueError("p_name")
        try:
            desc = validators.text(values["description"], "description", 0, 500, multiline=True)
        except ValueError:
            raise ValueError("p_desc")
        try:
            start = _optional_date(values["start_date"], 3650, 3650)
            end = _optional_date(values["end_date"], 3650, 3650)
        except ValueError:
            raise ValueError("p_dates")
        if start and end and end < start:
            raise ValueError("p_dates")
    except ValueError as exc:
        key = str(exc) if str(exc) in MESSAGES else "p_name"
        return render_template("work_project_form.html", values=values, error=_fail("project", key)), 400
    if db.query_one("SELECT id FROM projects WHERE name = %s", (name,)):
        return render_template("work_project_form.html", values=values, error=MESSAGES["p_dup"]), 409
    try:
        pid = db.execute("INSERT INTO projects(name, description, owner_id, start_date, end_date) VALUES(%s, %s, %s, %s, %s)",
                         (name, desc, g.user["id"], start, end))
    except pymysql.err.IntegrityError:
        return render_template("work_project_form.html", values=values, error=MESSAGES["p_dup"]), 409
    db.execute("INSERT INTO project_members(project_id, user_id) VALUES(%s, %s)", (pid, g.user["id"]))
    log_event("project_created", "INFO", "ok", project_id=pid)
    return redirect(url_for("work.project_detail", project_id=pid), 303)


@bp.get("/projects/<int:project_id>")
@login_required
def project_detail(project_id):
    loaded = _project_access(project_id)
    if not isinstance(loaded, tuple) or len(loaded) != 2 or not isinstance(loaded[0], dict):
        return loaded
    p, member = loaded
    members = db.query_all("SELECT u.id, u.display_name, u.dept FROM project_members m JOIN users u ON u.id = m.user_id "
                           "WHERE m.project_id = %s ORDER BY u.dept, u.display_name", (project_id,))
    tasks = db.query_all("SELECT t.id, t.title, t.status, t.priority, t.due_date, a.display_name AS assignee FROM tasks t "
                         "JOIN users a ON a.id = t.assignee_id WHERE t.project_id = %s "
                         "ORDER BY FIELD(t.status, 'doing', 'todo', 'done', 'cancelled'), t.due_date IS NULL, t.due_date, t.id LIMIT 300", (project_id,))
    counted = [t for t in tasks if t["status"] != "cancelled"]
    percent = int(100 * sum(t["status"] == "done" for t in counted) / len(counted)) if counted else 0
    ids = {m["id"] for m in members}
    candidates = [u for u in _users() if u["id"] not in ids] if _manage_project(p) else []
    return render_template("work_project.html", p=p, members=members, tasks=tasks, percent=percent, candidates=candidates,
                           manage=_manage_project(p), statuses=PROJECT_STATUS, task_statuses=TASK_STATUS, priorities=PRIORITY,
                           can_add_task=member or g.user["role"] == "admin")


@bp.post("/projects/<int:project_id>/members")
@login_required
def project_member_add(project_id):
    p = db.query_one("SELECT id, owner_id FROM projects WHERE id = %s FOR UPDATE", (project_id,))
    if not p:
        abort(404)
    if not _manage_project(p):
        return forbidden("not_owner", resource=f"project:{project_id}")
    uid = _positive(request.form.get("user_id", ""))
    if not uid or not db.query_one("SELECT id FROM users WHERE id = %s AND deleted_at IS NULL", (uid,)):
        log_event("input_rejected", "DENY", "user", field="project_member")
        return conflict("추가할 직원을 선택하세요.")
    n = db.execute_rowcount("INSERT IGNORE INTO project_members(project_id, user_id) VALUES(%s, %s)", (project_id, uid))
    if n:
        log_event("project_member_added", "INFO", "ok", project_id=project_id, user_id=uid)
    return redirect(url_for("work.project_detail", project_id=project_id), 303)


@bp.post("/projects/<int:project_id>/members/<int:user_id>/remove")
@login_required
def project_member_remove(project_id, user_id):
    p = db.query_one("SELECT id, owner_id FROM projects WHERE id = %s FOR UPDATE", (project_id,))
    if not p:
        abort(404)
    if not _manage_project(p):
        return forbidden("not_owner", resource=f"project:{project_id}")
    if user_id == p["owner_id"]:
        return conflict("프로젝트 소유자는 구성원에서 뺄 수 없습니다.")
    open_tasks = db.query_one("SELECT COUNT(*) AS n FROM tasks WHERE project_id = %s AND assignee_id = %s AND status IN ('todo', 'doing')",
                              (project_id, user_id))["n"]
    if open_tasks:
        return conflict(f"진행 중인 업무가 {open_tasks}건 남아 있습니다. 담당자를 바꾼 뒤 다시 시도하세요.")
    db.execute_rowcount("DELETE FROM project_members WHERE project_id = %s AND user_id = %s", (project_id, user_id))
    log_event("project_member_removed", "INFO", "ok", project_id=project_id, user_id=user_id)
    return redirect(url_for("work.project_detail", project_id=project_id), 303)


@bp.post("/projects/<int:project_id>/status")
@login_required
def project_status(project_id):
    p = db.query_one("SELECT id, owner_id, status FROM projects WHERE id = %s FOR UPDATE", (project_id,))
    if not p:
        abort(404)
    if not _manage_project(p):
        return forbidden("not_owner", resource=f"project:{project_id}")
    new = request.form.get("status", "")
    if new not in PROJECT_STATUS or new == p["status"]:
        return conflict("바꿀 수 없는 상태입니다.")
    db.execute_rowcount("UPDATE projects SET status = %s WHERE id = %s AND status = %s", (new, project_id, p["status"]))
    log_event("project_status", "INFO", new, project_id=project_id)
    return redirect(url_for("work.project_detail", project_id=project_id), 303)
