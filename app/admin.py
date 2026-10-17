"""관리자: 사용자 목록, 역할 변경, 잠금 해제.
- /admin/* 는 블루프린트 단위로 role=admin 을 서버에서 검사한다(새 경로를 추가해도 검사를 빼먹을 수 없다). 숨은 URL 에 의존하지 않는다.
- 변경은 POST + CSRF 만 허용하고, 모든 변경과 거부는 admin_action 이벤트로 남긴다.
- 자기 자신의 역할은 바꿀 수 없다(자기 강등·승격 금지). 이로써 관리자가 0명이 되는 일도 없다(실행하는 관리자 본인이 남는다).
- 역할은 즉시 반영된다(사용자·역할은 요청마다 DB 에서 다시 읽는다). 비밀번호 해시는 화면에 내보내지 않는다."""
from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from . import db
from .approvals import conflict, forbidden
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
