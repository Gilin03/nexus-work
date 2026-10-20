"""로그인 후 첫 화면(홈 대시보드)에 쓰는 자료. 모두 로그인한 사용자 본인의 범위만 읽는다(읽기 전용).
- 결재: 지금 내 차례인 문서(메뉴 배지와 같은 기준), 내가 올려 진행 중인 문서
- 업무: 내가 맡은 진행 중 업무(마감 순), 일정: 오늘부터 7일 안에 볼 수 있는 일정(일정 화면과 같은 공개 범위)
- 근태: 오늘 출퇴근, 올해 연차 잔여, 공지: 최근 공지사항, 예약: 앞으로의 내 예약
- 관리자에게만 계정 현황 수치(삭제된 계정 제외)
모든 SQL 은 상수 문자열 + params 이다."""
from datetime import datetime, time, timedelta

from . import approvals, db
from .hr import leave_balance, now_kst, today_kst
from .work import PRIORITY, TASK_STATUS

WEEKDAYS = "월화수목금토일"
LIMIT = 5


def build(user):
    uid, dept, today = user["id"], user["dept"], today_kst()
    now = now_kst()

    waiting = db.query_all(
        "SELECT a.id, a.title, a.doc_type, a.urgency, a.created_at, r.display_name AS requester FROM approval_steps s "
        "JOIN approvals a ON a.id = s.approval_id JOIN users r ON r.id = a.requester_id "
        "WHERE s.approver_id = %s AND s.status = 'pending' AND a.status = 'pending' "
        "ORDER BY a.urgency = 'urgent' DESC, a.id DESC LIMIT %s", (uid, LIMIT))
    for a in waiting:
        a["doc_no"] = approvals.doc_no(a)
        a["type_label"] = approvals.DOC_TYPES.get(a["doc_type"], approvals.DOC_TYPES["general"])[0]

    mine = db.query_all(
        "SELECT a.id, a.title, a.doc_type, a.status, a.current_step, a.created_at, "
        "(SELECT COUNT(*) FROM approval_steps s WHERE s.approval_id = a.id) AS total "
        "FROM approvals a WHERE a.requester_id = %s AND a.status = 'pending' ORDER BY a.id DESC LIMIT %s", (uid, LIMIT))
    for a in mine:
        a["doc_no"] = approvals.doc_no(a)

    tasks = db.query_all(
        "SELECT id, title, priority, status, due_date FROM tasks WHERE assignee_id = %s AND status IN ('todo', 'doing') "
        "ORDER BY due_date IS NULL, due_date, FIELD(priority, 'high', 'normal', 'low'), id DESC LIMIT %s", (uid, LIMIT))
    open_tasks = db.query_one("SELECT COUNT(*) AS n FROM tasks WHERE assignee_id = %s AND status IN ('todo', 'doing')", (uid,))["n"]
    for t in tasks:
        t["overdue"] = bool(t["due_date"] and t["due_date"] < today)
        t["due_today"] = t["due_date"] == today

    start = datetime.combine(today, time.min)
    events = db.query_all(
        "SELECT e.id, e.title, e.start_at, e.end_at, e.all_day, e.location FROM events e JOIN users o ON o.id = e.owner_id "
        "WHERE e.status = 'active' AND e.end_at >= %s AND e.start_at < %s AND (e.owner_id = %s OR e.scope = 'company' "
        "OR (e.scope = 'team' AND o.dept = %s) OR EXISTS(SELECT 1 FROM event_attendees x WHERE x.event_id = e.id AND x.user_id = %s)) "
        "ORDER BY e.start_at LIMIT 8", (start, start + timedelta(days=7), uid, dept, uid))
    for e in events:
        d = e["start_at"].date()
        e["day_label"] = "오늘" if d == today else ("내일" if d == today + timedelta(days=1) else f"{d.month}/{d.day}({WEEKDAYS[d.weekday()]})")
        e["time_label"] = "종일" if e["all_day"] else e["start_at"].strftime("%H:%M")

    notices = db.query_all(
        "SELECT p.id, p.title, p.created_at, u.display_name AS author FROM posts p JOIN users u ON u.id = p.author_id "
        "WHERE p.board = 'notice' ORDER BY p.id DESC LIMIT %s", (LIMIT,))

    reservations = db.query_all(
        "SELECT r.id, r.start_at, r.end_at, r.purpose, s.name AS resource FROM reservations r JOIN resources s ON s.id = r.resource_id "
        "WHERE r.user_id = %s AND r.status = 'active' AND r.end_at > %s ORDER BY r.start_at LIMIT 3", (uid, now))

    attendance = db.query_one("SELECT check_in, check_out FROM attendance WHERE user_id = %s AND work_date = %s", (uid, today))
    granted, used, remain = leave_balance(uid, today.year)

    admin = None
    if user["role"] == "admin":
        admin = {
            "users": db.query_one("SELECT COUNT(*) AS n FROM users WHERE deleted_at IS NULL")["n"],
            "locked": db.query_one("SELECT COUNT(*) AS n FROM users WHERE deleted_at IS NULL AND locked_until IS NOT NULL "
                                   "AND locked_until > NOW()")["n"],
            "leaves": db.query_one("SELECT COUNT(*) AS n FROM leave_requests WHERE status = 'pending'")["n"],
        }

    return {
        "today": today, "weekday": WEEKDAYS[today.weekday()], "now": now,
        "waiting": waiting, "mine": mine, "tasks": tasks, "open_tasks": open_tasks, "events": events,
        "notices": notices, "reservations": reservations, "attendance": attendance,
        "leave": {"granted": granted, "used": used, "remain": remain}, "admin": admin,
        "priorities": PRIORITY, "task_statuses": TASK_STATUS,
    }
