"""인사(HR): 인사카드, 조직도, 근태관리(출퇴근), 휴가관리(신청·승인·반려·취소). 급여는 erp.py 에 있다.
접근 범위(서버에서 강제, erp.py 와 같은 규칙): 직원=본인, 팀장=같은 부서(본인 포함), 관리자=전체. 조직도는 모두에게 열려 있다(직원 검색과 같은 공개 정보).
- 시각은 서버가 한국 시간(UTC+9)으로 정하고 사용자가 보낸 날짜·시각은 근태에 쓰지 않는다.
- 휴가: 신청자·종류·기간·일수는 만든 뒤 바꿀 수 없다(DB 권한). 승인·반려는 같은 부서 팀장 또는 관리자만, 본인 신청은 본인이 결재할 수 없고(앱+DB CHECK),
  대기 중인 것만 바꿀 수 있다(조건부 UPDATE 로 동시 처리 시 한쪽만 성공). 승인·반려·취소는 모두 hr_* 이벤트로 남는다.
- 모든 SQL 은 상수 문자열 + params 이고, 범위 조건은 한 쿼리 안의 파라미터로 처리한다(관리자/팀장/본인 쿼리를 따로 두지 않는다)."""
import re
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from . import db, validators
from .approvals import conflict, forbidden
from .auth import login_required
from .permissions import can
from .security import log_event

bp = Blueprint("hr", __name__, url_prefix="/hr")

KST = timezone(timedelta(hours=9))
WORK_START = time(9, 0)                      # 이 시각 이후(분 단위로 09:01부터)에 출근하면 지각으로 표시한다
LEAVE_TYPES = {"annual": "연차", "half": "반차", "sick": "병가"}
LEAVE_STATUS = {"pending": "대기", "approved": "승인", "rejected": "반려", "cancelled": "취소"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MONTH_RE = re.compile(r"^(\d{4})-(0[1-9]|1[0-2])$")
MAX_PAST_DAYS = 30
MAX_FUTURE_DAYS = 365
LEAVE_MESSAGES = {
    "type": "휴가 종류를 선택하세요.",
    "date": "날짜는 YYYY-MM-DD 형식으로 입력하세요.",
    "range": f"시작일은 오늘 기준 {MAX_PAST_DAYS}일 전부터 {MAX_FUTURE_DAYS}일 후까지, 종료일은 시작일 이후여야 합니다.",
    "half_single_day": "반차는 하루만 신청할 수 있습니다(시작일과 종료일이 같아야 합니다).",
    "no_workdays": "평일이 하루도 포함되지 않은 기간입니다.",
    "too_long": "한 번에 30일을 넘길 수 없습니다.",
    "reason": "사유는 1~200자로 입력하세요(제어문자 사용 불가).",
    "balance": "남은 연차가 부족합니다.",
    "overlap": "이미 신청했거나 승인된 휴가와 기간이 겹칩니다.",
}


def today_kst() -> date:
    return datetime.now(KST).date()


def now_kst() -> datetime:
    """한국 시간의 현재 시각(초 단위). 소수점 이하를 잘라 둔다: DATETIME 은 저장할 때 초를 반올림하므로, 그대로 넣으면 출근이 1초 뒤로 저장되어
    바로 이어진 퇴근이 '출근보다 이르다'고 거부될 수 있다."""
    return datetime.now(KST).replace(tzinfo=None, microsecond=0)


def _scope():
    """직원=본인, 팀장=같은 부서, 관리자=전체를 쿼리 파라미터로 표현한다: (역할, 내 id, 역할, 내 부서)."""
    u = g.user
    return (u["role"], u["id"], u["role"], u["dept"])


def _card_scope():
    """인사카드 범위: 전사 인사카드 권한(관리자, 경영지원·인사팀 과장 이상)이면 전체, 아니면 _scope() 와 같다."""
    u = g.user
    role = "admin" if can(u, "hr.cards.all") else u["role"]
    return (role, u["id"], role, u["dept"])


def _can_access(owner_id, owner_dept):
    u = g.user
    return u["role"] == "admin" or u["id"] == owner_id or (u["role"] == "manager" and u["dept"] == owner_dept)


def workdays(start: date, end: date) -> int:
    return sum(1 for i in range((end - start).days + 1) if (start + timedelta(days=i)).weekday() < 5)


def leave_balance(user_id, year):
    """(부여, 사용+대기, 잔여). 연차·반차만 차감하고 병가는 차감하지 않는다. 대기 중인 신청도 미리 잡아 둔다."""
    row = db.query_one("SELECT annual_days FROM employees WHERE user_id = %s", (user_id,))
    granted = Decimal(row["annual_days"] if row else 15)
    used = db.query_one("SELECT COALESCE(SUM(days), 0) AS used FROM leave_requests WHERE user_id = %s "
                        "AND leave_type IN ('annual', 'half') AND status IN ('approved', 'pending') "
                        "AND YEAR(start_date) = %s", (user_id, year))["used"]
    used = Decimal(used)
    return granted, used, granted - used


# ---------- 인사카드 ----------
@bp.get("/cards")
@login_required
def card_list():
    rows = db.query_all("SELECT id, emp_no, name, dept, title, ext, hire_date FROM employees "
                        "WHERE (%s = 'admin' OR user_id = %s OR (%s = 'manager' AND dept = %s)) "
                        "ORDER BY dept, name LIMIT 200", _card_scope())
    return render_template("hr_cards.html", rows=rows)


@bp.get("/cards/<int:emp_id>")
@login_required
def card_detail(emp_id):
    e = db.query_one("SELECT id, user_id, emp_no, name, dept, title, ext, hire_date, annual_days FROM employees WHERE id = %s",
                     (emp_id,))
    if not e:
        abort(404)
    if not (can(g.user, "hr.cards.all") or _can_access(e["user_id"], e["dept"])):
        return forbidden("out_of_scope", resource=f"hr_card:{emp_id}")
    tenure = None
    if e["hire_date"]:
        t = today_kst()
        months = (t.year - e["hire_date"].year) * 12 + t.month - e["hire_date"].month - (1 if t.day < e["hire_date"].day else 0)
        tenure = max(months, 0)
    balance = leave_balance(e["user_id"], today_kst().year) if e["user_id"] else None
    log_event("hr_card_view", "INFO", "ok", resource=f"hr_card:{emp_id}")
    return render_template("hr_card.html", e=e, tenure=tenure, balance=balance, year=today_kst().year)


# ---------- 조직도 ----------
@bp.get("/org")
@login_required
def org_chart():
    rows = db.query_all("SELECT e.name, e.dept, e.title, e.ext FROM employees e LEFT JOIN users u ON u.id = e.user_id "
                        "WHERE u.deleted_at IS NULL "                       # 삭제된 계정의 직원은 조직도에서 뺀다(인사카드 기록은 남는다)
                        "ORDER BY e.dept, FIELD(title, '관리자', '팀장', '과장', '대리', '사원'), name")
    depts = {}
    for r in rows:
        depts.setdefault(r["dept"], []).append(r)
    return render_template("hr_org.html", depts=depts, total=len(rows))


# ---------- 근태 ----------
def _month_range(raw):
    m = MONTH_RE.match(raw or "")
    if raw and not m:
        raise ValueError("month")
    today = today_kst()
    y, mo = (int(m.group(1)), int(m.group(2))) if m else (today.year, today.month)
    start = date(y, mo, 1)
    end = date(y + (mo == 12), mo % 12 + 1, 1)
    return start, end


@bp.get("/attendance")
@login_required
def attendance(error=None, status=200):
    try:
        start, end = _month_range(request.args.get("month"))
    except ValueError:
        log_event("input_rejected", "DENY", "month", field="attendance")
        start, end = _month_range(None)
        error, status = "월은 YYYY-MM 형식으로 입력하세요.", 400
    rows = db.query_all(
        "SELECT a.work_date, a.check_in, a.check_out, u.display_name, u.dept FROM attendance a JOIN users u ON u.id = a.user_id "
        "WHERE a.work_date >= %s AND a.work_date < %s "
        "AND (%s = 'admin' OR u.id = %s OR (%s = 'manager' AND u.dept = %s)) "
        "ORDER BY a.work_date DESC, u.display_name LIMIT 500", (start, end) + _scope())
    for r in rows:
        r["late"] = r["check_in"].time() > time(9, 0, 59)
    mine = db.query_one("SELECT check_in, check_out FROM attendance WHERE user_id = %s AND work_date = %s",
                        (g.user["id"], today_kst()))
    return render_template("hr_attendance.html", rows=rows, month=start.strftime("%Y-%m"), mine=mine, today=today_kst(),
                           show_names=g.user["role"] != "employee", error=error), status


@bp.post("/attendance/check-in")
@login_required
def check_in():
    now = now_kst()
    # INSERT IGNORE: 같은 날 두 번째 출근은 UNIQUE 때문에 0행이 되어 충돌로 처리한다(동시 요청에도 한 번만 들어간다).
    n = db.execute_rowcount("INSERT IGNORE INTO attendance(user_id, work_date, check_in) VALUES(%s, %s, %s)",
                            (g.user["id"], now.date(), now))
    if not n:
        log_event("hr_attendance_conflict", "DENY", "already_checked_in")
        return conflict("오늘은 이미 출근 처리되었습니다.")
    log_event("hr_check_in", "INFO", "ok", late=now.time() > time(9, 0, 59))
    return redirect(_after_attendance(), 303)


@bp.post("/attendance/check-out")
@login_required
def check_out():
    now = now_kst()
    n = db.execute_rowcount("UPDATE attendance SET check_out = %s WHERE user_id = %s AND work_date = %s "
                            "AND check_out IS NULL AND check_in <= %s", (now, g.user["id"], now.date(), now))
    if not n:
        log_event("hr_attendance_conflict", "DENY", "no_open_check_in")
        return conflict("오늘 출근 기록이 없거나 이미 퇴근 처리되었습니다.")
    log_event("hr_check_out", "INFO", "ok")
    return redirect(_after_attendance(), 303)


def _after_attendance():
    """출퇴근 뒤 돌아갈 곳: 홈에서 눌렀으면 홈, 아니면 근태 화면(다른 값은 무시해 열린 이동을 막는다)."""
    return url_for("auth.home") if request.form.get("next") == "home" else url_for("hr.attendance")


# ---------- 휴가 ----------
def _can_decide(req):
    """대기 중인 신청을 결재할 수 있는가: 본인 신청은 불가, 같은 부서 팀장 또는 관리자만."""
    u = g.user
    if req["status"] != "pending" or req["user_id"] == u["id"]:
        return False
    return u["role"] == "admin" or (u["role"] == "manager" and u["dept"] == req["dept"])


@bp.get("/leave")
@login_required
def leave_list():
    rows = db.query_all(
        "SELECT r.id, r.user_id, r.leave_type, r.start_date, r.end_date, r.days, r.reason, r.status, r.decision_reason, "
        "u.display_name, u.dept, d.display_name AS decider FROM leave_requests r JOIN users u ON u.id = r.user_id "
        "LEFT JOIN users d ON d.id = r.decided_by "
        "WHERE (%s = 'admin' OR u.id = %s OR (%s = 'manager' AND u.dept = %s)) "
        "ORDER BY r.status = 'pending' DESC, r.id DESC LIMIT 200", _scope())
    for r in rows:
        r["can_decide"] = _can_decide(r)
        r["can_cancel"] = r["status"] == "pending" and r["user_id"] == g.user["id"]
    year = today_kst().year
    return render_template("hr_leave.html", rows=rows, balance=leave_balance(g.user["id"], year), year=year,
                           types=LEAVE_TYPES, statuses=LEAVE_STATUS, show_names=g.user["role"] != "employee")


def _parse_day(raw):
    if not isinstance(raw, str) or not DATE_RE.match(raw):
        raise ValueError("date")
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date()
    except ValueError:
        raise ValueError("date")


def _leave_form(error=None, status=200, values=None):
    return render_template("hr_leave_form.html", error=error, types=LEAVE_TYPES, values=values or {},
                           balance=leave_balance(g.user["id"], today_kst().year), year=today_kst().year), status


@bp.route("/leave/new", methods=["GET", "POST"])
@login_required
def leave_new():
    if request.method == "GET":
        return _leave_form()
    values = {k: request.form.get(k, "") for k in ("leave_type", "start_date", "end_date", "reason")}
    try:
        ltype = values["leave_type"]
        if ltype not in LEAVE_TYPES:
            raise ValueError("type")
        start = _parse_day(values["start_date"])
        end = _parse_day(values["end_date"] or values["start_date"])
        today = today_kst()
        if end < start or start < today - timedelta(days=MAX_PAST_DAYS) or start > today + timedelta(days=MAX_FUTURE_DAYS) \
                or end > today + timedelta(days=MAX_FUTURE_DAYS + 30):
            raise ValueError("range")
        reason = validators.text(values["reason"], "reason", 1, 200)
        if ltype == "half":
            if start != end:
                raise ValueError("half_single_day")
            days = Decimal("0.5") if start.weekday() < 5 else Decimal(0)
        else:
            days = Decimal(workdays(start, end))
        if days <= 0:
            raise ValueError("no_workdays")
        if days > 30:
            raise ValueError("too_long")
    except ValueError as exc:
        key = str(exc) if str(exc) in LEAVE_MESSAGES else "reason"
        log_event("input_rejected", "DENY", str(exc), field="leave")
        return _leave_form(error=LEAVE_MESSAGES[key], status=400, values=values)

    # 같은 사용자의 신청을 한 줄로 세워 잔여·중복 검사와 입력 사이에 다른 신청이 끼어들지 못하게 한다.
    # 요청 앞부분(로그인 확인)의 일반 읽기로 이미 스냅샷이 잡혀 있으므로, 잠그기 전에 그 읽기 트랜잭션을 끝낸다
    # (여기까지 쓴 것이 없다). 그렇지 않으면 잠금을 얻은 뒤에도 먼저 끝난 다른 신청이 겹침·잔여 검사에 보이지 않는다.
    db.commit()
    db.query_one("SELECT id FROM users WHERE id = %s FOR UPDATE", (g.user["id"],))
    overlap = db.query_one("SELECT id FROM leave_requests WHERE user_id = %s AND status IN ('pending', 'approved') "
                           "AND start_date <= %s AND end_date >= %s LIMIT 1", (g.user["id"], end, start))
    if overlap:
        log_event("hr_leave_rejected", "DENY", "overlap")
        return _leave_form(error=LEAVE_MESSAGES["overlap"], status=409, values=values)
    if ltype in ("annual", "half") and days > leave_balance(g.user["id"], start.year)[2]:
        log_event("hr_leave_rejected", "DENY", "balance", days=float(days))
        return _leave_form(error=LEAVE_MESSAGES["balance"], status=409, values=values)
    # 상태는 항상 pending 으로 시작한다(폼으로 보낸 status·결재자 같은 다른 필드는 무시).
    req_id = db.execute("INSERT INTO leave_requests(user_id, leave_type, start_date, end_date, days, reason) "
                        "VALUES(%s, %s, %s, %s, %s, %s)", (g.user["id"], ltype, start, end, days, reason))
    log_event("hr_leave_requested", "INFO", "ok", leave_id=req_id, leave_type=ltype, days=float(days))
    return redirect(url_for("hr.leave_list"), 303)


@bp.post("/leave/<int:leave_id>/decide")
@login_required
def leave_decide(leave_id):
    req = db.query_one("SELECT r.id, r.user_id, r.status, u.dept FROM leave_requests r JOIN users u ON u.id = r.user_id "
                       "WHERE r.id = %s FOR UPDATE", (leave_id,))
    if not req:
        abort(404)
    if req["user_id"] == g.user["id"]:
        return forbidden("self_decision", resource=f"leave:{leave_id}")
    if g.user["role"] == "employee" or (g.user["role"] == "manager" and g.user["dept"] != req["dept"]):
        return forbidden("out_of_scope", resource=f"leave:{leave_id}")
    action = request.form.get("action", "")
    if action not in ("approve", "reject"):
        log_event("input_rejected", "DENY", "action", field="leave_decision")
        return conflict("처리 방법이 올바르지 않습니다.")
    reason = None
    if action == "reject":
        try:
            reason = validators.text(request.form.get("reason", ""), "reason", 1, 200)
        except ValueError:
            log_event("input_rejected", "DENY", "reason", field="leave_decision")
            return conflict("반려 사유는 1~200자로 입력하세요(제어문자 사용 불가).")
    new_status = "approved" if action == "approve" else "rejected"
    n = db.execute_rowcount("UPDATE leave_requests SET status = %s, decided_by = %s, decided_at = %s, decision_reason = %s "
                            "WHERE id = %s AND status = 'pending'", (new_status, g.user["id"], now_kst(), reason, leave_id))
    if not n:
        log_event("hr_leave_invalid_transition", "DENY", f"{req['status']}->{new_status}", leave_id=leave_id)
        return conflict("대기 중인 신청만 처리할 수 있습니다.")
    log_event("hr_leave_decided", "INFO", new_status, leave_id=leave_id)
    return redirect(url_for("hr.leave_list"), 303)


@bp.post("/leave/<int:leave_id>/cancel")
@login_required
def leave_cancel(leave_id):
    req = db.query_one("SELECT id, user_id, status FROM leave_requests WHERE id = %s FOR UPDATE", (leave_id,))
    if not req:
        abort(404)
    if req["user_id"] != g.user["id"]:  # 취소는 신청자 본인만(팀장·관리자도 남의 신청은 취소할 수 없다)
        return forbidden("not_owner", resource=f"leave:{leave_id}")
    n = db.execute_rowcount("UPDATE leave_requests SET status = 'cancelled', decided_at = %s "
                            "WHERE id = %s AND status = 'pending'", (now_kst(), leave_id))
    if not n:
        log_event("hr_leave_invalid_transition", "DENY", f"{req['status']}->cancelled", leave_id=leave_id)
        return conflict("대기 중인 신청만 취소할 수 있습니다.")
    log_event("hr_leave_cancelled", "INFO", "ok", leave_id=leave_id)
    return redirect(url_for("hr.leave_list"), 303)
