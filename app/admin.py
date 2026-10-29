"""관리자(시스템 관리): 관리 현황, 사용자 관리(등록·역할 변경·비밀번호 초기화·잠금·잠금 해제·삭제), 보안 대시보드, 권한 현황.
- 계정 등록·비밀번호 초기화는 임시 비밀번호를 무작위로 만들어 그 응답 화면에 한 번만 보여 준다(DB 에는 해시만, 로그에는 값 없음).
- 본인 계정은 역할 변경·비밀번호 초기화·잠금 대상이 될 수 없다(본인 비밀번호는 비밀번호 변경 화면에서).
- /admin/* 는 블루프린트 단위로 role=admin 을 서버에서 검사한다(새 경로를 추가해도 검사를 빼먹을 수 없다). 숨은 URL 에 의존하지 않는다.
- 변경은 POST + CSRF 만 허용하고, 모든 변경과 거부는 admin_action 이벤트로 남긴다.
- 자기 자신의 역할은 바꿀 수 없다(자기 강등·승격 금지). 이로써 관리자가 0명이 되는 일도 없다(실행하는 관리자 본인이 남는다).
- 역할은 즉시 반영된다(사용자·역할은 요청마다 DB 에서 다시 읽는다). 비밀번호 해시는 화면에 내보내지 않는다.
- 최고관리자 고정 계정(admin·hongjh, users.pinned): 역할 변경·수동 잠금·비밀번호 초기화·삭제를 이 화면에서 할 수 없다(앱 검사 + DB 트리거).
  다른 계정(보안관제팀 포함)은 일반 규칙대로 바꿀 수 있다(사용자 결정 2026-10-20).
- 사용자 삭제는 최고관리자만 한다(permissions 의 users.delete). 결재·업무·게시글·대화 같은 기록이 그 사용자를 가리키므로 행을 지우지 않고
  deleted_at 으로 표시한다: 로그인 불가(없는 계정과 같은 응답), 열린 세션·메신저 토큰 즉시 무효, 사용자 목록·결재선·담당자·참석자·조직도에서 빠짐.
  아이디는 새 계정에 다시 쓸 수 없다(기록과 혼동 방지). 본인·고정 계정·이미 삭제된 계정은 삭제할 수 없고, 아이디를 다시 입력해야 실행된다.
- 복구(재입사)도 최고관리자만 한다: 삭제 표시를 지우고 역할·직급을 다시 고르며, 새 임시 비밀번호를 한 번만 보여 준다.
  예전 비밀번호·세션·메신저 토큰은 계속 무효다. 인사카드와 지난 기록은 같은 계정이라 그대로 다시 연결된다.
- 직급(사원·대리·과장·팀장·관리자)은 역할 안의 세부 단계이고 사용자 관리에서 바꾼다(인사발령). 역할이 바뀌면 직급도 그 역할에 맞게 함께 바뀐다.
- 보안 대시보드(감사 로그)와 CSV 내보내기는 보안관제팀 소속과 시스템관리자만 쓴다(permissions.py 의 security.dashboard). 일반 관리자는 열 수 없다."""
import csv
import json
import queue
import io
import re
import secrets
import string
from datetime import datetime, timedelta

import pymysql
from flask import Blueprint, Response, abort, current_app, g, redirect, render_template, request, url_for

from . import audit, db, security, validators
from .approvals import conflict, forbidden
from .auth import hash_password
from .hr import today_kst
from .permissions import (ALLOWED_TITLES, DEFAULT_TITLE, FINANCE_TEAMS, HR_TEAMS, PINNED_USERS, RANKS, ROLES, ROLE_LABELS, SECURITY_TEAM, can, matrix,
                          permission_required)
from .security import log_event

bp = Blueprint("admin", __name__, url_prefix="/admin")

# ROLES is imported from permissions


@bp.before_request
def require_admin():
    if not g.user:
        log_event("authz_deny", "DENY", "not_logged_in")
        return redirect(url_for("auth.login"), 303)
    if g.user["role"] not in ("admin", "sec_admin", "hr_admin", "finance_admin"):
        return forbidden("insufficient_role", required="admin")


# 색인 경로(/admin, /admin/)는 두지 않는다: 둘 다 404 라서 관리자 화면 존재 여부가 다른 없는 경로와 구분되지 않는다.
@bp.get("/users")
def users():
    rows = db.query_all(
        "SELECT u.id, u.username, u.display_name, u.dept, u.role, u.pinned, u.ai_restricted, u.failed_count, u.created_at, e.title, "
        "(u.locked_until IS NOT NULL AND u.locked_until > NOW()) AS is_locked "
        "FROM users u LEFT JOIN employees e ON e.user_id = u.id WHERE u.deleted_at IS NULL "
        "ORDER BY u.pinned DESC, u.dept, u.role, u.username LIMIT 500")
    deleted = db.query_all(
        "SELECT u.id, u.username, u.display_name, u.dept, u.deleted_at, d.username AS deleted_by FROM users u "
        "LEFT JOIN users d ON d.id = u.deleted_by WHERE u.deleted_at IS NOT NULL ORDER BY u.deleted_at DESC LIMIT 200")

    stats = {
        "total": len(rows),
        "active": sum(1 for u in rows if not u["is_locked"]),
        "locked": sum(1 for u in rows if u["is_locked"]),
        "admin": sum(1 for u in rows if u["role"] == "admin"),
        "deleted": len(deleted),
    }

    q = request.args.get("q", "").strip()
    f_dept = request.args.get("dept", "").strip()
    f_role = request.args.get("role", "").strip()
    f_status = request.args.get("status", "").strip()

    filtered = rows
    if q:
        filtered = [u for u in filtered if q.lower() in u["username"].lower() or (u["display_name"] and q.lower() in u["display_name"].lower())]
    if f_dept:
        filtered = [u for u in filtered if u["dept"] == f_dept]
    if f_role and f_role in ROLES:
        filtered = [u for u in filtered if u["role"] == f_role]
    if f_status == "locked":
        filtered = [u for u in filtered if u["is_locked"]]
    elif f_status == "active":
        filtered = [u for u in filtered if not u["is_locked"]]
    elif f_status == "restricted":
        filtered = [u for u in filtered if u.get("ai_restricted")]

    return render_template("admin_users.html", rows=filtered, roles=ROLES, role_labels=ROLE_LABELS, titles=ALLOWED_TITLES, deleted=deleted,
                           can_delete=can(g.user, "users.delete"), depts=dept_options(), new_dept=NEW_DEPT,
                           me_pinned=bool(g.user.get("pinned")), stats=stats,
                           q=q, f_dept=f_dept, f_role=f_role, f_status=f_status)


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
    target = db.query_one("SELECT id, username, role, pinned FROM users WHERE id = %s AND deleted_at IS NULL FOR UPDATE", (user_id,))
    if not target:
        abort(404)
    if target["pinned"]:
        log_event("admin_action", "DENY", "pinned_account", action="role_change", target=target["username"])
        return forbidden("pinned_account", resource=f"user:{user_id}")
    if target["role"] != expected:
        log_event("admin_action", "DENY", "stale_form", action="role_change", target=target["username"])
        return conflict("다른 곳에서 이미 변경된 사용자입니다. 목록을 새로 고친 뒤 다시 시도하세요.")
    if target["role"] == new_role:
        return redirect(url_for("admin.users"), 303)
    if db.execute_rowcount("UPDATE users SET role = %s WHERE id = %s AND role = %s", (new_role, user_id, expected)) != 1:
        return conflict("다른 곳에서 이미 변경된 사용자입니다. 목록을 새로 고친 뒤 다시 시도하세요.")
    _sync_title(user_id, new_role)
    log_event("admin_action", "ALLOW", "role_change", action="role_change", target=target["username"],
              old=expected, new=new_role)
    return redirect(url_for("admin.users"), 303)


def _sync_title(user_id, role):
    """역할이 바뀌면 직급이 그 역할에 맞지 않을 수 있다(예: 팀장이 직원이 되면 팀장 직급을 쓸 수 없다): 맞지 않으면 그 역할의 기본 직급으로."""
    row = db.query_one("SELECT title FROM employees WHERE user_id = %s FOR UPDATE", (user_id,))
    if row and row["title"] not in ALLOWED_TITLES[role]:
        db.execute_rowcount("UPDATE employees SET title = %s WHERE user_id = %s", (DEFAULT_TITLE[role], user_id))


@bp.post("/users/<int:user_id>/dept")
def change_dept(user_id):
    """부서 변경(인사발령). 계정과 인사카드의 부서를 함께 바꾼다. 부서는 팀 권한·팀 일정·보안관제팀 권한을 정하므로
    본인 부서는 바꿀 수 없고, 고정 계정(admin·hongjh)의 부서는 최고관리자만 바꾼다. 화면을 연 사이 바뀌었으면 덮어쓰지 않는다."""
    raw = request.form.get("new_dept", "") if request.form.get("dept") == NEW_DEPT else request.form.get("dept", "")
    expected = request.form.get("current_dept", "")
    try:
        new_dept = validators.text(raw, "dept", 1, 64)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="dept_change")
        return conflict("부서는 1~64자로 고르거나 입력하세요(새 부서는 이름을 입력).")
    if user_id == g.user["id"]:
        log_event("admin_action", "DENY", "self_change", action="dept_change", target=g.user["username"])
        return forbidden("self_dept_change", resource=f"user:{user_id}")
    target = db.query_one("SELECT id, username, dept, pinned FROM users WHERE id = %s AND deleted_at IS NULL FOR UPDATE", (user_id,))
    if not target:
        abort(404)
    if target["pinned"] and not g.user.get("pinned"):
        log_event("admin_action", "DENY", "pinned_account", action="dept_change", target=target["username"])
        return forbidden("pinned_account", resource=f"user:{user_id}")
    if target["dept"] != expected:
        log_event("admin_action", "DENY", "stale_form", action="dept_change", target=target["username"])
        return conflict("다른 곳에서 이미 변경된 사용자입니다. 목록을 새로 고친 뒤 다시 시도하세요.")
    if target["dept"] == new_dept:
        return redirect(url_for("admin.users"), 303)
    if db.execute_rowcount("UPDATE users SET dept = %s WHERE id = %s AND dept = %s", (new_dept, user_id, expected)) != 1:
        return conflict("다른 곳에서 이미 변경된 사용자입니다. 목록을 새로 고친 뒤 다시 시도하세요.")
    db.execute_rowcount("UPDATE employees SET dept = %s WHERE user_id = %s", (new_dept, user_id))
    log_event("admin_action", "ALLOW", "dept_change", action="dept_change", target=target["username"], old=expected, new=new_dept)
    return redirect(url_for("admin.users"), 303)


@bp.post("/users/<int:user_id>/title")
def change_title(user_id):
    """직급(인사발령) 변경. 직급은 역할 안의 세부 단계라서 그 역할이 허용하는 직급만 고를 수 있다."""
    if user_id == g.user["id"]:
        log_event("admin_action", "DENY", "self_change", action="title_change", target=g.user["username"])
        return forbidden("self_title_change", resource=f"user:{user_id}")
    new_title = request.form.get("title", "")
    target = db.query_one("SELECT u.id, u.username, u.role, e.id AS emp_id, e.title FROM users u "
                          "LEFT JOIN employees e ON e.user_id = u.id WHERE u.id = %s AND u.deleted_at IS NULL FOR UPDATE", (user_id,))
    if not target:
        abort(404)
    if not target["emp_id"]:
        log_event("admin_action", "DENY", "no_hr_card", action="title_change", target=target["username"])
        return conflict("인사카드가 없는 계정은 직급을 바꿀 수 없습니다.")
    if new_title not in ALLOWED_TITLES[target["role"]]:
        log_event("input_rejected", "DENY", "title_value", field="title", value=new_title[:30])
        return conflict(f"이 역할({target['role']})에서 쓸 수 있는 직급이 아닙니다: " + ", ".join(ALLOWED_TITLES[target["role"]]))
    if new_title != target["title"]:
        n = db.execute_rowcount("UPDATE employees SET title = %s WHERE id = %s AND title = %s", (new_title, target["emp_id"], target["title"]))
        if n != 1:
            return conflict("다른 곳에서 이미 변경되었습니다. 목록을 새로 고친 뒤 다시 시도하세요.")
        log_event("admin_action", "ALLOW", "title_change", action="title_change", target=target["username"], old=target["title"], new=new_title)
    return redirect(url_for("admin.users"), 303)


@bp.post("/users/<int:user_id>/unlock")
def unlock(user_id):
    target = db.query_one("SELECT id, username, failed_count, (locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked "
                          "FROM users WHERE id = %s AND deleted_at IS NULL FOR UPDATE", (user_id,))
    if not target:
        abort(404)
    db.execute_rowcount("UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = %s", (user_id,))
    log_event("admin_action", "ALLOW", "unlock", action="unlock", target=target["username"],
              was_locked=bool(target["is_locked"]), failed_count=target["failed_count"])
    return redirect(url_for("admin.users"), 303)


# ---------- 계정 등록·비밀번호 초기화·잠금 ----------
TITLES = DEFAULT_TITLE
_PW_CHARS = string.ascii_letters + string.digits


def make_temp_password(username: str) -> str:
    """비밀번호 정책(12자 이상, 문자 종류 3종 이상, 아이디 미포함)을 만족하는 무작위 임시 비밀번호."""
    while True:
        pw = "".join(secrets.choice(_PW_CHARS) for _ in range(14)) + secrets.choice("!@#$%^*-_=+") + secrets.choice(string.digits)
        try:
            return validators.password_policy(pw, username)
        except ValueError:
            continue


def _credentials(user, password, created, restored=False):
    return render_template("admin_credentials.html", target=user, password=password, created=created, restored=restored)


NEW_DEPT = "__new__"   # 부서 목록의 "새 부서 직접 입력" 값


def dept_options():
    """사용자 등록 화면의 부서 목록: 권한 규칙이 이름으로 보는 부서 + 지금 계정(삭제된 계정 제외)·인사카드에 있는 부서."""
    rows = db.query_all("SELECT dept FROM users WHERE deleted_at IS NULL UNION SELECT dept FROM employees")
    return sorted({SECURITY_TEAM, *FINANCE_TEAMS, *HR_TEAMS} | {r["dept"] for r in rows if r["dept"]})


def _new_form(error=None, status=200, values=None):
    return render_template("admin_user_new.html", roles=ROLES, role_labels=ROLE_LABELS, titles=TITLES, ranks=RANKS, security_team=SECURITY_TEAM, error=error,
                           values=values or {}, depts=dept_options(), new_dept=NEW_DEPT), status


@bp.route("/users/new", methods=["GET", "POST"])
def user_new():
    if request.method == "GET":
        return _new_form()
    values = {k: request.form.get(k, "") for k in ("username", "display_name", "dept", "new_dept", "role", "title")}
    try:
        username = validators.username(values["username"])
        display_name = validators.text(values["display_name"], "display_name", 1, 64)
        # 목록에서 고르거나, "새 부서 직접 입력"을 고르면 새 부서 이름 칸의 값을 쓴다.
        dept = validators.text(values["new_dept"] if values["dept"] == NEW_DEPT else values["dept"], "dept", 1, 64)
        if values["role"] not in ROLES:
            raise ValueError("role")
        role = values["role"]
        title = values["title"] or DEFAULT_TITLE[role]
        if title not in ALLOWED_TITLES[role]:
            raise ValueError("title")
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="user_create")
        return _new_form("아이디는 영문 소문자로 시작하는 3~32자(소문자·숫자·밑줄), 이름·부서는 1~64자(새 부서는 이름을 입력), 역할·직급은 목록에서 선택하세요"
                         "(직급은 역할에 맞아야 합니다: 직원=사원·대리·과장, 팀장=팀장, 관리자=관리자).", 400, values)
    if db.query_one("SELECT id FROM users WHERE username = %s", (username,)):
        log_event("admin_action", "DENY", "duplicate_username", action="user_create", target=username)
        return _new_form("이미 있는 아이디입니다.", 409, values)
    password = make_temp_password(username)
    try:
        user_id = db.execute("INSERT INTO users(username, password_hash, role, display_name, dept) VALUES(%s, %s, %s, %s, %s)",
                             (username, hash_password(password), role, display_name, dept))
        # 인사카드도 함께 만든다(사번은 사용자 id 로 정해 직원 번호와 겹치지 않는다).
        db.execute("INSERT INTO employees(user_id, name, dept, title, ext, emp_no, hire_date) VALUES(%s, %s, %s, %s, '-', %s, %s)",
                   (user_id, display_name, dept, title, f"NX-{today_kst().year}-U{user_id:04d}", today_kst()))
    except pymysql.err.IntegrityError:
        log_event("admin_action", "DENY", "duplicate_username", action="user_create", target=username)
        return _new_form("이미 있는 아이디입니다.", 409, values)
    log_event("admin_action", "ALLOW", "user_create", action="user_create", target=username, role=role, title=title)
    return _credentials({"username": username, "display_name": display_name}, password, created=True)


@bp.post("/users/<int:user_id>/reset-password")
def reset_password(user_id):
    if user_id == g.user["id"]:
        log_event("admin_action", "DENY", "self_change", action="password_reset", target=g.user["username"])
        return forbidden("self_password_reset", resource=f"user:{user_id}")
    target = db.query_one("SELECT id, username, display_name, pinned FROM users WHERE id = %s AND deleted_at IS NULL FOR UPDATE", (user_id,))
    if not target:
        abort(404)
    if target["pinned"]:                         # 고정 계정의 비밀번호는 본인만 바꾼다(비밀번호 변경 화면)
        log_event("admin_action", "DENY", "pinned_account", action="password_reset", target=target["username"])
        return forbidden("pinned_account", resource=f"user:{user_id}")
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
    target = db.query_one("SELECT id, username, pinned FROM users WHERE id = %s AND deleted_at IS NULL FOR UPDATE", (user_id,))
    if not target:
        abort(404)
    if target["pinned"]:                         # 고정 계정은 다른 관리자가 잠글 수 없다(보안관제·시스템 관리 기능이 멈추는 것을 막는다)
        log_event("admin_action", "DENY", "pinned_account", action="lock", target=target["username"])
        return forbidden("pinned_account", resource=f"user:{user_id}")
    # 관리자가 풀 때까지 잠근다(10년). 잠긴 계정의 세션은 다음 요청에서 바로 끊긴다.
    db.execute("UPDATE users SET locked_until = DATE_ADD(NOW(), INTERVAL 3650 DAY), session_version = session_version + 1 WHERE id = %s",
               (user_id,))
    log_event("admin_action", "ALLOW", "lock", action="lock", target=target["username"])
    return redirect(url_for("admin.users"), 303)


# ---------- 사용자 삭제(최고관리자만) ----------
def _delete_target(user_id):
    """(대상, 오류 응답). 본인·없는 계정·이미 삭제·고정 계정은 삭제할 수 없다."""
    if user_id == g.user["id"]:
        log_event("admin_action", "DENY", "self_change", action="user_delete", target=g.user["username"])
        return None, forbidden("self_delete", resource=f"user:{user_id}")
    target = db.query_one("SELECT id, username, display_name, dept, role, pinned FROM users WHERE id = %s AND deleted_at IS NULL FOR UPDATE",
                          (user_id,))
    if not target:
        abort(404)
    if target["pinned"]:
        log_event("admin_action", "DENY", "pinned_account", action="user_delete", target=target["username"])
        return None, forbidden("pinned_account", resource=f"user:{user_id}")
    return target, None


@bp.get("/users/<int:user_id>/delete")
@permission_required("users.delete")
def delete_confirm(user_id):
    target, err = _delete_target(user_id)
    if err:
        return err
    return render_template("admin_user_delete.html", target=target, error=None)


@bp.post("/users/<int:user_id>/delete")
@permission_required("users.delete")
def delete_user(user_id):
    target, err = _delete_target(user_id)
    if err:
        return err
    if request.form.get("confirm_username", "").strip() != target["username"]:      # 실수로 지우지 않게 아이디를 다시 입력받는다
        log_event("admin_action", "DENY", "confirm_mismatch", action="user_delete", target=target["username"])
        return render_template("admin_user_delete.html", target=target, error="아이디가 일치하지 않습니다. 삭제할 계정의 아이디를 정확히 입력하세요."), 400
    n = db.execute_rowcount("UPDATE users SET deleted_at = NOW(), deleted_by = %s, session_version = session_version + 1 "
                            "WHERE id = %s AND deleted_at IS NULL AND pinned = 0", (g.user["id"], user_id))
    if n != 1:
        return conflict("이미 삭제되었거나 삭제할 수 없는 계정입니다.")
    revoked = db.execute_rowcount("UPDATE api_tokens SET revoked_at = NOW() WHERE user_id = %s AND revoked_at IS NULL", (user_id,))
    log_event("admin_action", "ALLOW", "user_delete", action="user_delete", target=target["username"], role=target["role"],
              tokens_revoked=revoked)
    return redirect(url_for("admin.users"), 303)


# ---------- 삭제한 계정 복구(재입사, 최고관리자만) ----------
def _restore_form(target, error=None, status=200, values=None):
    return render_template("admin_user_restore.html", target=target, roles=ROLES, ranks=RANKS, titles=TITLES, error=error,
                           values=values or {}), status


def _restore_target(user_id):
    target = db.query_one("SELECT u.id, u.username, u.display_name, u.dept, u.role, u.deleted_at, e.title FROM users u "
                          "LEFT JOIN employees e ON e.user_id = u.id WHERE u.id = %s AND u.deleted_at IS NOT NULL FOR UPDATE", (user_id,))
    if not target:
        abort(404)                               # 삭제되지 않은 계정·없는 계정
    return target


@bp.get("/users/<int:user_id>/restore")
@permission_required("users.delete")
def restore_confirm(user_id):
    return _restore_form(_restore_target(user_id))


@bp.post("/users/<int:user_id>/restore")
@permission_required("users.delete")
def restore_user(user_id):
    target = _restore_target(user_id)
    values = {k: request.form.get(k, "") for k in ("role", "title", "confirm_username")}
    if values["confirm_username"].strip() != target["username"]:
        log_event("admin_action", "DENY", "confirm_mismatch", action="user_restore", target=target["username"])
        return _restore_form(target, "아이디가 일치하지 않습니다. 복구할 계정의 아이디를 정확히 입력하세요.", 400, values)
    role = values["role"]
    title = values["title"] or DEFAULT_TITLE.get(role, "")
    if role not in ROLES or title not in ALLOWED_TITLES[role]:
        log_event("input_rejected", "DENY", "role_or_title", field="user_restore")
        return _restore_form(target, "역할과 직급을 목록에서 고르세요(직원=사원·대리·과장, 팀장=팀장, 관리자=관리자).", 400, values)
    password = make_temp_password(target["username"])
    # 예전 비밀번호·세션은 쓰지 못하게 새 임시 비밀번호로 바꾸고 세션 버전을 올린다. 메신저 토큰은 삭제 때 폐기된 그대로 둔다.
    n = db.execute_rowcount("UPDATE users SET deleted_at = NULL, deleted_by = NULL, role = %s, password_hash = %s, failed_count = 0, "
                            "locked_until = NULL, session_version = session_version + 1 WHERE id = %s AND deleted_at IS NOT NULL",
                            (role, hash_password(password), user_id))
    if n != 1:
        return conflict("이미 복구된 계정입니다.")
    if target["title"] is not None and target["title"] != title:
        db.execute_rowcount("UPDATE employees SET title = %s WHERE user_id = %s", (title, user_id))
    log_event("admin_action", "ALLOW", "user_restore", action="user_restore", target=target["username"], role=role, title=title)
    return _credentials(target, password, created=False, restored=True)


# ---------- 관리 현황 ----------
@bp.get("/overview")
def overview():
    roles = {r["role"]: r["n"] for r in db.query_all("SELECT role, COUNT(*) AS n FROM users WHERE deleted_at IS NULL GROUP BY role")}
    depts = db.query_all("SELECT dept, COUNT(*) AS n FROM users WHERE deleted_at IS NULL GROUP BY dept ORDER BY dept")
    stats = {
        "users": sum(roles.values()),
        "locked": db.query_one("SELECT COUNT(*) AS n FROM users WHERE deleted_at IS NULL AND locked_until IS NOT NULL AND locked_until > NOW()")["n"],
        "approvals": db.query_one("SELECT COUNT(*) AS n FROM approvals WHERE status = 'pending'")["n"],
        "leaves": db.query_one("SELECT COUNT(*) AS n FROM leave_requests WHERE status = 'pending'")["n"],
        "attendance": db.query_one("SELECT COUNT(*) AS n FROM attendance WHERE work_date = %s", (today_kst(),))["n"],
    }
    recent = audit.recent_counts(current_app.config["LOG_DIR"])
    return render_template("admin_overview.html", roles=roles, depts=depts, stats=stats, recent=recent)


# ---------- 보안 대시보드(감사 로그) ----------
_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_USER_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")
_IP_RE = re.compile(r"^[0-9A-Fa-f:.]{1,45}$")
PERIOD_HOURS = {key: hours for key, hours, _label in audit.PERIODS}
MAX_PAGE = audit.MAX_MATCH // min(audit.PAGE_SIZES)


def _dashboard_args(args):
    """조회 조건을 허용 형식으로만 받는다. 틀리면 ValueError(항목 이름)."""
    f = {k: args.get(k, "").strip() for k in ("type", "decision", "user", "ip")}
    period = args.get("period", "24h")
    if period not in PERIOD_HOURS:
        raise ValueError("period")
    try:
        limit = int(args.get("limit", str(audit.PAGE_SIZES[0])))
        page = int(args.get("page", "1"))
    except ValueError:
        raise ValueError("limit")
    if limit not in audit.PAGE_SIZES:
        raise ValueError("limit")
    if not 1 <= page <= MAX_PAGE:
        raise ValueError("page")
    if f["type"] and not _TYPE_RE.match(f["type"]):
        raise ValueError("type")
    if f["decision"] and f["decision"] not in audit.DECISIONS:
        raise ValueError("decision")
    if f["user"] and not _USER_RE.match(f["user"]):
        raise ValueError("user")
    if f["ip"] and not _IP_RE.match(f["ip"]):
        raise ValueError("ip")
    return f, period, limit, page


def _locked_accounts():
    return db.query_all("SELECT username, display_name, dept, locked_until FROM users "
                        "WHERE locked_until IS NOT NULL AND locked_until > NOW() ORDER BY locked_until DESC LIMIT 20")


def _dashboard_page(f, period, limit, page, error=None, status=200):
    res = audit.scan(current_app.config["LOG_DIR"], PERIOD_HOURS[period], f["type"], f["decision"], f["user"], f["ip"])
    d = res["decisions"]
    summary = {"total": res["scanned"], "ok": d["INFO"] + d["ALLOW"], "warn": d["WARN"] + d["ERROR"], "deny": d["DENY"], "block": d["BLOCK"],
               "ips": res["distinct_ips"]}
    threats = [(label, key, res["kinds"][key]) for key, label in audit.THREAT_TYPES]
    start = (page - 1) * limit
    shown = res["matched"][start:start + limit]
    covered = res["oldest"].astimezone(audit.KST).strftime("%Y-%m-%d %H:%M") if res["oldest"] else None
    grace = timedelta(hours=1) if res["hourly"] else timedelta(days=1)       # 가장 오래된 기록이 기간 시작에서 한 칸 안이면 덮는 것으로 본다
    truncated = bool(res["oldest"]) and not res["reached_start"] and res["oldest"] > res["since"] + grace
    if status == 200:
        log_event("admin_action", "INFO", "audit_view", action="audit_view", period=period, rows=len(shown))

    try:
        blocked_row = db.query_one("SELECT COUNT(*) AS n FROM blocked_ips WHERE blocked_until > NOW()")
        blocked_ips_count = blocked_row["n"] if blocked_row else 0
    except Exception:
        blocked_ips_count = 0

    bad_count = summary["deny"] + summary["block"] + summary["warn"]
    if summary["block"] > 10 or bad_count > 50:
        threat_level = {"code": "DEFCON 1", "title": "CRITICAL THREAT", "class": "defcon-critical", "desc": "능동 침해 공격 다수 감지 — 비상 방어 모드"}
    elif summary["block"] > 0 or summary["deny"] > 5 or bad_count > 10:
        threat_level = {"code": "DEFCON 2", "title": "ELEVATED THREAT", "class": "defcon-elevated", "desc": "비인가 접근 및 공격 시도 감지 — 적극 차단/추적 중"}
    elif bad_count > 0:
        threat_level = {"code": "DEFCON 3", "title": "GUARDED", "class": "defcon-guarded", "desc": "경미한 이상 징후 감지 — 상시 모니터링 모드"}
    else:
        threat_level = {"code": "DEFCON 4", "title": "NORMAL SECURE", "class": "defcon-normal", "desc": "모든 인프라 지표 정상 — 침해 시도 없음"}

    soc_pipeline = [
        {"name": "WAF / Gateway", "target": "pfSense (192.168.3.10)", "status": "ONLINE", "cls": "soc-green"},
        {"name": "SIEM Collector", "target": "Graylog (192.168.3.15)", "status": "STREAMING", "cls": "soc-green"},
        {"name": "EDR / FIM Agent", "target": "Wazuh (nexus-board-14)", "status": "ONLINE", "cls": "soc-green"},
        {"name": "SOAR Engine", "target": "n8n Auto-Ban", "status": "READY", "cls": "soc-cyan"},
    ]

    return render_template(
        "admin_audit.html", f=f, period=period, periods=audit.PERIODS, limit=limit, limits=audit.PAGE_SIZES, page=page, error=error,
        decisions=audit.DECISIONS, kinds=sorted(res["kinds"]), summary=summary, threats=threats, chart=audit.chart(res), series=audit.SERIES,
        top_kinds=res["kinds"].most_common(10), top_ips=res["bad_ips"].most_common(10), top_fail_users=res["fail_users"].most_common(10),
        top_suspicious=res["suspicious"].most_common(8), locked=_locked_accounts(), events=shown, matched_n=res["matched_n"],
        capped=res["matched_n"] > audit.MAX_MATCH, has_prev=page > 1, has_next=start + limit < len(res["matched"]), covered=covered,
        truncated=truncated, hourly=res["hourly"], blocked_ips_count=blocked_ips_count, threat_level=threat_level, soc_pipeline=soc_pipeline), status


@bp.get("/audit")
@permission_required("security.dashboard")
def audit_log():
    try:
        f, period, limit, page = _dashboard_args(request.args)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="audit_filter")
        blank = {"type": "", "decision": "", "user": "", "ip": ""}
        return _dashboard_page(blank, "24h", audit.PAGE_SIZES[0], 1, error="검색 조건이 올바르지 않습니다.", status=400)
    return _dashboard_page(f, period, limit, page)


EXPORT_COLUMNS = ("시각", "이벤트", "사용자", "역할", "출발지", "판정", "사유", "메서드", "경로", "상세")


@bp.get("/audit/export.csv")
@permission_required("security.dashboard")
def audit_export():
    """현재 조건에 맞는 이벤트를 CSV 로 내려받는다(최대 audit.MAX_MATCH 건). 수식 주입을 막기 위해 위험한 첫 글자는 이스케이프한다."""
    try:
        f, period, _limit, _page = _dashboard_args(request.args)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="audit_filter")
        abort(400)
    res = audit.scan(current_app.config["LOG_DIR"], PERIOD_HOURS[period], f["type"], f["decision"], f["user"], f["ip"])
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(EXPORT_COLUMNS)
    for e in res["matched"]:
        w.writerow([audit.csv_cell(v) for v in (e["time"], e["event_type"], e["user"], e["role"], e["src_ip"], e["decision"], e["reason"],
                                                  e["method"], e["path"], e["extra"])])
    log_event("admin_action", "INFO", "security_export", action="security_export", period=period, rows=len(res["matched"]),
              filter_type=f["type"], filter_decision=f["decision"])
    name = "security-events-" + datetime.now(audit.KST).strftime("%Y%m%d-%H%M") + ".csv"
    return Response("\ufeff" + out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})




@bp.get("/audit/stream")
@permission_required("security.dashboard")
def audit_stream():
    """실시간 보안 감사 이벤트 SSE 스트림."""
    q = audit.subscribe_audit_events()

    def generate():
        try:
            yield b": connected\n\n"
            while True:
                try:
                    event_data = q.get(timeout=15.0)
                    payload = json.dumps(event_data, ensure_ascii=False)
                    yield f"data: {payload}\n\n".encode("utf-8")
                except queue.Empty:
                    yield b": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            audit.unsubscribe_audit_events(q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------- 권한 현황 ----------
# 실제 코드가 강제하는 규칙을 한 표로 보여 준다(읽기 전용). 값이 바뀌면 해당 모듈과 이 표를 함께 고친다.
PERMISSIONS = [
    ("문서함(일반 문서)", "열람", "열람", "열람"),
    ("기밀 문서함", "불가", "열람", "열람"),
    ("게시판·자유게시판 글쓰기", "허용", "허용", "허용"),
    ("공지사항 글쓰기", "과장 이상만 허용", "허용", "허용"),
    ("게시글 삭제", "본인 글", "본인 글", "모든 글"),
    ("프로필 사진", "본인", "본인", "본인"),
    ("경비 등록·상신", "본인", "본인", "본인"),
    ("경비 조회 범위", "본인", "같은 부서", "전체"),
    ("전자결재 상신", "허용", "허용", "허용"),
    ("전자결재 결재자가 될 수 있음", "불가", "허용", "허용"),
    ("재무 보고", "경영지원·재무팀 과장 이상만 열람", "열람", "열람"),
    ("급여 조회 범위", "본인(경영지원·재무팀 과장 이상은 전체)", "같은 부서(경영지원·재무팀은 전체)", "전체"),
    ("인사카드 조회 범위", "본인(경영지원·인사팀 과장 이상은 전체)", "같은 부서(경영지원·인사팀은 전체)", "전체"),
    ("조직도", "열람", "열람", "열람"),
    ("근태 조회 범위", "본인", "같은 부서", "전체"),
    ("휴가 신청", "허용", "허용", "허용"),
    ("휴가 승인·반려", "불가", "같은 부서(본인 제외)", "전체(본인 제외)"),
    ("AI 어시스턴트", "허용(요청자 권한 안에서)", "허용(요청자 권한 안에서)", "허용(요청자 권한 안에서)"),
    ("관리(현황·사용자·권한)", "불가", "불가", "허용"),
    ("보안 대시보드·감사 로그", "불가", "불가", "보안관제팀·시스템관리자만"),
]


@bp.get("/permissions")
def permissions():
    counts = {r["role"]: r["n"] for r in db.query_all("SELECT role, COUNT(*) AS n FROM users WHERE deleted_at IS NULL GROUP BY role")}
    ranks = {r["title"]: r["n"] for r in db.query_all(
        "SELECT COALESCE(e.title, '(인사카드 없음)') AS title, COUNT(*) AS n FROM users u LEFT JOIN employees e ON e.user_id = u.id "
        "WHERE u.deleted_at IS NULL GROUP BY title")}
    pinned = db.query_all("SELECT username, display_name, dept FROM users WHERE pinned = 1 ORDER BY dept, username LIMIT 100")
    return render_template("admin_permissions.html", rows=PERMISSIONS, counts=counts, ranks=RANKS, rank_counts=ranks,
                           rank_matrix=matrix(), pinned=pinned, security_team=SECURITY_TEAM)


@bp.get("/blocked-ips")
@permission_required("security.dashboard")
def list_blocked_ips():
    rows = db.query_all(
        "SELECT id, ip_address, reason, blocked_until, created_at, created_by, "
        "CASE WHEN blocked_until > NOW() THEN 1 ELSE 0 END AS is_active "
        "FROM blocked_ips ORDER BY blocked_until DESC LIMIT 100"
    )
    rows = [r for r in rows if not security.is_protected_block_ip(r.get("ip_address"))]
    return render_template("admin_blocked_ips.html", rows=rows, prefill_ip=request.args.get("ip", "").strip(),
                           error=request.args.get("error", ""))


@bp.post("/blocked-ips")
@permission_required("security.dashboard")
def add_blocked_ip():
    ip = request.form.get("ip_address", "").strip()
    reason = request.form.get("reason", "manual_block").strip()[:100]
    try:
        minutes = int(request.form.get("minutes", "30"))
    except ValueError:
        minutes = 30
    if not ip or ip in ("127.0.0.1", "::1"):
        return redirect(url_for("admin.list_blocked_ips"), 303)
    if security.is_protected_block_ip(ip):
        log_event("admin_action", "DENY", "protected_ip", action="block_ip", target=ip)
        return redirect(url_for("admin.list_blocked_ips", error="protected_ip"), 303)
    if not security.block_ip(ip, reason=reason, minutes=minutes, created_by=g.user.get("username", "admin")):
        log_event("admin_action", "ERROR", "block_ip_failed", action="block_ip", target=ip)
        return redirect(url_for("admin.list_blocked_ips", error="block_failed"), 303)
    log_event("admin_action", "ALLOW", "block_ip", action="block_ip", target=ip, block_reason=reason, minutes=minutes)
    return redirect(url_for("admin.list_blocked_ips"), 303)


@bp.post("/blocked-ips/<path:ip>/unblock")
@permission_required("security.dashboard")
def remove_blocked_ip(ip):
    security.unblock_ip(ip)
    log_event("admin_action", "ALLOW", "unblock_ip", action="unblock_ip", target=ip)
    return redirect(url_for("admin.list_blocked_ips"), 303)


@bp.get("/xdr")
@permission_required("security.dashboard")
def xdr_assessments():
    rows = []
    unavailable = False
    if current_app.config.get("XDR_ENABLED"):
        from . import ai_xdr
        try:
            rows = ai_xdr.list_assessments(50)
        except pymysql.MySQLError:
            unavailable = True
    return render_template(
        "admin_xdr.html", assessments=rows, xdr_enabled=current_app.config.get("XDR_ENABLED", False),
        unavailable=unavailable, result=request.args.get("result", ""),
    )


@bp.post("/xdr/assessments/<assessment_id>/decision")
@permission_required("security.dashboard")
def decide_xdr_assessment(assessment_id):
    from . import ai_xdr
    decision = request.form.get("decision", "")
    approved_action = None
    if decision == "APPROVED_BLOCK_IP":
        decision = "APPROVED"
        approved_action = "block_ip"
    try:
        result = ai_xdr.decide_assessment(
            assessment_id, decision, int(g.user["id"]), g.user.get("username", "admin"),
            approved_action=approved_action,
        )
    except ValueError:
        abort(400)
    except LookupError:
        abort(404)
    except RuntimeError:
        abort(409)
    except pymysql.MySQLError as exc:
        log_event("xdr_assessment_decision", "ERROR", type(exc).__name__, assessment_id=assessment_id)
        abort(503)
    return redirect(url_for("admin.xdr_assessments", result=result["status"].lower()), 303)
