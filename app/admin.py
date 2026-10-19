"""관리자(시스템 관리): 관리 현황, 사용자 관리(등록·역할 변경·비밀번호 초기화·잠금·잠금 해제), 감사 로그, 권한 현황.
- 계정 등록·비밀번호 초기화는 임시 비밀번호를 무작위로 만들어 그 응답 화면에 한 번만 보여 준다(DB 에는 해시만, 로그에는 값 없음).
- 본인 계정은 역할 변경·비밀번호 초기화·잠금 대상이 될 수 없다(본인 비밀번호는 비밀번호 변경 화면에서).
- /admin/* 는 블루프린트 단위로 role=admin 을 서버에서 검사한다(새 경로를 추가해도 검사를 빼먹을 수 없다). 숨은 URL 에 의존하지 않는다.
- 변경은 POST + CSRF 만 허용하고, 모든 변경과 거부는 admin_action 이벤트로 남긴다.
- 자기 자신의 역할은 바꿀 수 없다(자기 강등·승격 금지). 이로써 관리자가 0명이 되는 일도 없다(실행하는 관리자 본인이 남는다).
- 역할은 즉시 반영된다(사용자·역할은 요청마다 DB 에서 다시 읽는다). 비밀번호 해시는 화면에 내보내지 않는다."""
import re
import secrets
import string

import pymysql
from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from . import audit, db, validators
from .approvals import conflict, forbidden
from .auth import hash_password
from .hr import today_kst
from .security import log_event

bp = Blueprint("admin", __name__, url_prefix="/admin")

ROLES = ("employee", "manager", "admin")


@bp.before_request
def require_admin():
    if not g.user:
        log_event("authz_deny", "DENY", "not_logged_in")
        return redirect(url_for("auth.login"), 303)
    if g.user["role"] != "admin":
        return forbidden("insufficient_role", required="admin")


# 색인 경로(/admin, /admin/)는 두지 않는다: 둘 다 404 라서 관리자 화면 존재 여부가 다른 없는 경로와 구분되지 않는다.
@bp.get("/users")
def users():
    rows = db.query_all(
        "SELECT id, username, display_name, dept, role, failed_count, created_at, "
        "(locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked "
        "FROM users ORDER BY dept, role, username LIMIT 500")
    return render_template("admin_users.html", rows=rows, roles=ROLES)


@bp.post("/users/<int:user_id>/role")
def change_role(user_id):
    new_role = request.form.get("role", "")
    expected = request.form.get("current_role", "")  # 화면을 연 시점의 역할: 그 사이 바뀌었으면 덮어쓰지 않는다
    if new_role not in ROLES or expected not in ROLES:
        log_event("input_rejected", "DENY", "role_value", field="role", value=new_role[:30])
        abort(400)
    if user_id == g.user["id"]:
        log_event("admin_action", "DENY", "self_change", action="role_change", target=g.user["username"])
        return forbidden("self_role_change", resource=f"user:{user_id}")
    target = db.query_one("SELECT id, username, role FROM users WHERE id = %s FOR UPDATE", (user_id,))
    if not target:
        abort(404)
    if target["role"] != expected:
        log_event("admin_action", "DENY", "stale_form", action="role_change", target=target["username"])
        return conflict("다른 곳에서 이미 변경된 사용자입니다. 목록을 새로 고친 뒤 다시 시도하세요.")
    if target["role"] == new_role:
        return redirect(url_for("admin.users"), 303)
    if db.execute_rowcount("UPDATE users SET role = %s WHERE id = %s AND role = %s", (new_role, user_id, expected)) != 1:
        return conflict("다른 곳에서 이미 변경된 사용자입니다. 목록을 새로 고친 뒤 다시 시도하세요.")
    log_event("admin_action", "ALLOW", "role_change", action="role_change", target=target["username"],
              old=expected, new=new_role)
    return redirect(url_for("admin.users"), 303)


@bp.post("/users/<int:user_id>/unlock")
def unlock(user_id):
    target = db.query_one("SELECT id, username, failed_count, (locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked "
                          "FROM users WHERE id = %s FOR UPDATE", (user_id,))
    if not target:
        abort(404)
    db.execute_rowcount("UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = %s", (user_id,))
    log_event("admin_action", "ALLOW", "unlock", action="unlock", target=target["username"],
              was_locked=bool(target["is_locked"]), failed_count=target["failed_count"])
    return redirect(url_for("admin.users"), 303)


# ---------- 계정 등록·비밀번호 초기화·잠금 ----------
TITLES = {"employee": "사원", "manager": "팀장", "admin": "관리자"}
_PW_CHARS = string.ascii_letters + string.digits


def make_temp_password(username: str) -> str:
    """비밀번호 정책(12자 이상, 문자 종류 3종 이상, 아이디 미포함)을 만족하는 무작위 임시 비밀번호."""
    while True:
        pw = "".join(secrets.choice(_PW_CHARS) for _ in range(14)) + secrets.choice("!@#$%^*-_=+") + secrets.choice(string.digits)
        try:
            return validators.password_policy(pw, username)
        except ValueError:
            continue


def _credentials(user, password, created):
    return render_template("admin_credentials.html", target=user, password=password, created=created)


def _new_form(error=None, status=200, values=None):
    return render_template("admin_user_new.html", roles=ROLES, titles=TITLES, error=error, values=values or {}), status


@bp.route("/users/new", methods=["GET", "POST"])
def user_new():
    if request.method == "GET":
        return _new_form()
    values = {k: request.form.get(k, "") for k in ("username", "display_name", "dept", "role")}
    try:
        username = validators.username(values["username"])
        display_name = validators.text(values["display_name"], "display_name", 1, 64)
        dept = validators.text(values["dept"], "dept", 1, 64)
        if values["role"] not in ROLES:
            raise ValueError("role")
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="user_create")
        return _new_form("아이디는 영문 소문자로 시작하는 3~32자(소문자·숫자·밑줄), 이름·부서는 1~64자, 역할은 목록에서 선택하세요.", 400, values)
    if db.query_one("SELECT id FROM users WHERE username = %s", (username,)):
        log_event("admin_action", "DENY", "duplicate_username", action="user_create", target=username)
        return _new_form("이미 있는 아이디입니다.", 409, values)
    password = make_temp_password(username)
    try:
        user_id = db.execute("INSERT INTO users(username, password_hash, role, display_name, dept) VALUES(%s, %s, %s, %s, %s)",
                             (username, hash_password(password), values["role"], display_name, dept))
        # 인사카드도 함께 만든다(사번은 사용자 id 로 정해 직원 번호와 겹치지 않는다).
        db.execute("INSERT INTO employees(user_id, name, dept, title, ext, emp_no, hire_date) VALUES(%s, %s, %s, %s, '-', %s, %s)",
                   (user_id, display_name, dept, TITLES[values["role"]], f"NX-{today_kst().year}-U{user_id:04d}", today_kst()))
    except pymysql.err.IntegrityError:
        log_event("admin_action", "DENY", "duplicate_username", action="user_create", target=username)
        return _new_form("이미 있는 아이디입니다.", 409, values)
    log_event("admin_action", "ALLOW", "user_create", action="user_create", target=username, role=values["role"])
    return _credentials({"username": username, "display_name": display_name}, password, created=True)


@bp.post("/users/<int:user_id>/reset-password")
def reset_password(user_id):
    if user_id == g.user["id"]:
        log_event("admin_action", "DENY", "self_change", action="password_reset", target=g.user["username"])
        return forbidden("self_password_reset", resource=f"user:{user_id}")
    target = db.query_one("SELECT id, username, display_name FROM users WHERE id = %s FOR UPDATE", (user_id,))
    if not target:
        abort(404)
    password = make_temp_password(target["username"])
    # 세션 버전을 올려 이전에 로그인해 있던 기기를 모두 끊고, 실패 횟수·잠금도 함께 풀어 바로 로그인할 수 있게 한다.
    db.execute("UPDATE users SET password_hash = %s, failed_count = 0, locked_until = NULL, session_version = session_version + 1 "
               "WHERE id = %s", (hash_password(password), user_id))
    log_event("admin_action", "ALLOW", "password_reset", action="password_reset", target=target["username"])
    return _credentials(target, password, created=False)


@bp.post("/users/<int:user_id>/lock")
def lock(user_id):
    if user_id == g.user["id"]:
        log_event("admin_action", "DENY", "self_change", action="lock", target=g.user["username"])
        return forbidden("self_lock", resource=f"user:{user_id}")
    target = db.query_one("SELECT id, username FROM users WHERE id = %s FOR UPDATE", (user_id,))
    if not target:
        abort(404)
    # 관리자가 풀 때까지 잠근다(10년). 잠긴 계정의 세션은 다음 요청에서 바로 끊긴다.
    db.execute("UPDATE users SET locked_until = DATE_ADD(NOW(), INTERVAL 3650 DAY), session_version = session_version + 1 WHERE id = %s",
               (user_id,))
    log_event("admin_action", "ALLOW", "lock", action="lock", target=target["username"])
    return redirect(url_for("admin.users"), 303)


# ---------- 관리 현황 ----------
@bp.get("/overview")
def overview():
    roles = {r["role"]: r["n"] for r in db.query_all("SELECT role, COUNT(*) AS n FROM users GROUP BY role")}
    depts = db.query_all("SELECT dept, COUNT(*) AS n FROM users GROUP BY dept ORDER BY dept")
    stats = {
        "users": sum(roles.values()),
        "locked": db.query_one("SELECT COUNT(*) AS n FROM users WHERE locked_until IS NOT NULL AND locked_until > NOW()")["n"],
        "approvals": db.query_one("SELECT COUNT(*) AS n FROM approvals WHERE status = 'pending'")["n"],
        "leaves": db.query_one("SELECT COUNT(*) AS n FROM leave_requests WHERE status = 'pending'")["n"],
        "attendance": db.query_one("SELECT COUNT(*) AS n FROM attendance WHERE work_date = %s", (today_kst(),))["n"],
    }
    recent = audit.recent_counts(current_app.config["LOG_DIR"])
    return render_template("admin_overview.html", roles=roles, depts=depts, stats=stats, recent=recent)


# ---------- 감사 로그 ----------
AUDIT_LIMITS = (100, 200, 500)
_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_USER_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")
_IP_RE = re.compile(r"^[0-9A-Fa-f:.]{1,45}$")


@bp.get("/audit")
def audit_log():
    f = {k: request.args.get(k, "").strip() for k in ("type", "decision", "user", "ip")}
    try:
        limit = int(request.args.get("limit", "200"))
        if limit not in AUDIT_LIMITS:
            raise ValueError("limit")
        if f["type"] and not _TYPE_RE.match(f["type"]):
            raise ValueError("type")
        if f["decision"] and f["decision"] not in audit.DECISIONS:
            raise ValueError("decision")
        if f["user"] and not _USER_RE.match(f["user"]):
            raise ValueError("user")
        if f["ip"] and not _IP_RE.match(f["ip"]):
            raise ValueError("ip")
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="audit_filter")
        _events, kinds, scanned = audit.read_events(current_app.config["LOG_DIR"], 0)
        return render_template("admin_audit.html", events=[], kinds=sorted(kinds), scanned=scanned, f=f, limit=200,
                               limits=AUDIT_LIMITS, decisions=audit.DECISIONS,
                               error="검색 조건이 올바르지 않습니다."), 400
    events, kinds, scanned = audit.read_events(current_app.config["LOG_DIR"], limit, f["type"], f["decision"], f["user"], f["ip"])
    log_event("admin_action", "INFO", "audit_view", action="audit_view", rows=len(events))
    return render_template("admin_audit.html", events=events, kinds=sorted(kinds), scanned=scanned, f=f, limit=limit,
                           limits=AUDIT_LIMITS, decisions=audit.DECISIONS, error=None)


# ---------- 권한 현황 ----------
# 실제 코드가 강제하는 규칙을 한 표로 보여 준다(읽기 전용). 값이 바뀌면 해당 모듈과 이 표를 함께 고친다.
PERMISSIONS = [
    ("문서함(일반 문서)", "열람", "열람", "열람"),
    ("기밀 문서함", "불가", "열람", "열람"),
    ("게시판·자유게시판 글쓰기", "허용", "허용", "허용"),
    ("공지사항 글쓰기", "불가", "허용", "허용"),
    ("게시글 삭제", "본인 글", "본인 글", "모든 글"),
    ("프로필 사진", "본인", "본인", "본인"),
    ("경비 등록·상신", "본인", "본인", "본인"),
    ("경비 조회 범위", "본인", "같은 부서", "전체"),
    ("전자결재 상신", "허용", "허용", "허용"),
    ("전자결재 결재자가 될 수 있음", "불가", "허용", "허용"),
    ("재무 보고", "불가", "열람", "열람"),
    ("급여 조회 범위", "본인", "같은 부서", "전체"),
    ("인사카드 조회 범위", "본인", "같은 부서", "전체"),
    ("조직도", "열람", "열람", "열람"),
    ("근태 조회 범위", "본인", "같은 부서", "전체"),
    ("휴가 신청", "허용", "허용", "허용"),
    ("휴가 승인·반려", "불가", "같은 부서(본인 제외)", "전체(본인 제외)"),
    ("AI 어시스턴트", "허용(요청자 권한 안에서)", "허용(요청자 권한 안에서)", "허용(요청자 권한 안에서)"),
    ("관리(현황·사용자·감사 로그·권한)", "불가", "불가", "허용"),
]


@bp.get("/permissions")
def permissions():
    counts = {r["role"]: r["n"] for r in db.query_all("SELECT role, COUNT(*) AS n FROM users GROUP BY role")}
    return render_template("admin_permissions.html", rows=PERMISSIONS, counts=counts)
