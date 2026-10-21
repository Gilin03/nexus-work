"""인증: 로그인·로그아웃, 세션, 실패 잠금, 비밀번호 변경.
- 로그인 실패 메시지는 항상 같다(계정 열거 방지). 존재하지 않는 계정도 더미 해시를 검증해 응답 시간을 맞춘다.
- 실패 횟수는 SELECT ... FOR UPDATE 로 행을 잠근 채 갱신해, 동시 요청으로 한도를 우회할 수 없다.
- 사용자·역할·잠금 상태는 요청마다 DB 에서 다시 읽는다. 세션 쿠키만으로 권한을 믿지 않는다.
- 세션은 서명된 쿠키지만 `users.session_version` 과 맞아야 유효하다. 로그아웃·비밀번호 변경은 이 값을 올려 이전 쿠키를 모두 무효로 만든다
  (그 사용자의 다른 기기 로그인도 함께 끊긴다).
# ponytail: 유휴 30분·절대 8시간 만료는 쿠키 안의 시각으로 판단한다. 기기별로 따로 폐기하려면 서버 측 세션 표가 필요하다."""
import time
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import Blueprint, current_app, g, redirect, render_template, request, session, url_for

from . import db, validators
from .security import csrf_token, get_client_ip, ip_rate_limited, log_event

bp = Blueprint("auth", __name__)

_ph = PasswordHasher()  # Argon2id
_DUMMY_HASH = _ph.hash("dummy-password-used-only-to-equalize-timing")

GENERIC_LOGIN_ERROR = "로그인할 수 없습니다. 아이디와 비밀번호를 확인하거나 잠시 후 다시 시도하세요."
POLICY_MESSAGES = {
    "password_length": "비밀번호는 12자 이상 128자 이하여야 합니다.",
    "password_complexity": "대문자·소문자·숫자·특수문자 중 3가지 이상을 포함해야 합니다.",
    "password_contains_username": "비밀번호에 아이디를 포함할 수 없습니다.",
    "password_mismatch": "새 비밀번호 확인이 일치하지 않습니다.",
    "password_reuse": "현재 비밀번호와 다른 비밀번호를 사용하세요.",
}

def hash_password(password: str) -> str:
    """관리자 화면(계정 등록·비밀번호 초기화)이 쓰는 Argon2id 해시. 해시 설정을 한 곳에 둔다."""
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


# ---- 요청마다 현재 사용자 로드 ----
def load_user():
    g.user = None
    if request.endpoint == "static":
        return
    uid = session.get("uid")
    if uid is None:
        return
    if time.time() - session.get("iat", 0) > current_app.config["SESSION_ABSOLUTE_SECONDS"]:
        session.clear()
        return
    row = db.query_one(
        "SELECT id, username, role, display_name, dept, session_version, pinned, "
        "(SELECT e.title FROM employees e WHERE e.user_id = users.id) AS title, "
        "(locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked, "
        "EXISTS(SELECT 1 FROM profile_photos p WHERE p.user_id = users.id) AS has_photo FROM users WHERE id = %s AND deleted_at IS NULL", (uid,))
    if not row or row["is_locked"] or session.get("sv") != row["session_version"]:
        # 삭제됐거나 잠긴 계정, 로그아웃·비밀번호 변경으로 무효가 된 쿠키는 즉시 세션 무효화
        session.clear()
        return
    g.user = {k: row[k] for k in ("id", "username", "role", "display_name", "dept", "title")}
    g.user["pinned"] = bool(row["pinned"])
    g.user["has_photo"] = bool(row["has_photo"])


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not g.user:
            log_event("authz_deny", "DENY", "not_logged_in")
            return redirect(url_for("auth.login"), 303)
        return view(*args, **kwargs)
    return wrapper


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if g.user["role"] not in roles:
                log_event("authz_deny", "DENY", "insufficient_role", required=",".join(roles))
                return render_template("error.html", code=403, message="접근 권한이 없습니다."), 403
            return view(*args, **kwargs)
        return wrapper
    return decorator


def _register_failure(user_id) -> bool:
    """실패 횟수를 올리고, 한도에 닿으면 잠근다(True). 호출 전에 FOR UPDATE 로 행이 잠겨 있어야 한다."""
    cfg = current_app.config
    db.execute("UPDATE users SET failed_count = failed_count + 1 WHERE id = %s", (user_id,))
    count = db.query_one("SELECT failed_count FROM users WHERE id = %s", (user_id,))["failed_count"]
    if count >= cfg["LOGIN_MAX_FAILURES"]:
        db.execute("UPDATE users SET locked_until = DATE_ADD(NOW(), INTERVAL %s MINUTE), failed_count = 0 WHERE id = %s",
                   (cfg["LOGIN_LOCK_MINUTES"], user_id))
        return True
    return False


def _start_session(user_id, session_version, keep_iat=None):
    """세션을 비우고 새로 만든다(세션 고정 방지). CSRF 토큰도 새로 발급된다.
    세션 버전을 함께 담아, 나중에 사용자의 버전이 올라가면(로그아웃·비밀번호 변경) 이 쿠키는 무효가 된다."""
    session.clear()
    session["uid"] = user_id
    session["sv"] = session_version
    session["iat"] = keep_iat if keep_iat is not None else int(time.time())
    session.permanent = True
    csrf_token()


def _log_login_failure(reason, event="login_failure", name="-"):
    log_event(event, "DENY", reason, user=name[:64])
    db.commit()  # 오류 응답이라도 실패 횟수는 남겨야 한다


def authenticate(raw_name: str, password: str):
    """아이디·비밀번호 확인(계정 열거 방지·잠금 모두 동일 적용). 쿠키 로그인(/login)과 메신저
    토큰 로그인(/api/v1/login)이 함께 쓴다 — 브루트포스 방어를 두 곳에 따로 두지 않는다.
    성공하면 (row, None), 실패하면 (None, 사유코드)를 돌려준다. 실패 쪽은 이벤트 기록·커밋까지 끝낸다."""
    try:
        name = validators.username(raw_name)
    except ValueError:
        name = None
    if len(password) > 256:  # 비정상적으로 긴 입력은 해시 계산 없이 실패 처리
        password = ""

    row = None
    if name:
        row = db.query_one(
            "SELECT id, username, password_hash, role, display_name, dept, session_version, "
            "(locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked "
            "FROM users WHERE username = %s AND deleted_at IS NULL FOR UPDATE", (name,))   # 삭제된 계정은 없는 계정과 똑같이 처리

    password_ok = verify_password(row["password_hash"] if row else _DUMMY_HASH, password)

    if not row:
        _log_login_failure("unknown_user" if name else "invalid_format", name=raw_name)
        return None, "invalid_credentials"
    if row["is_locked"]:  # 잠긴 동안은 맞는 비밀번호도 거부하고, 횟수는 올리지 않는다
        _log_login_failure("account_locked", "login_locked", row["username"])
        return None, "account_locked"
    if not password_ok:
        locked = _register_failure(row["id"])
        if locked:
            log_event("account_locked", "BLOCK", "max_failures", user=row["username"])
        _log_login_failure("bad_password", name=row["username"])
        return None, "invalid_credentials"

    # 성공
    new_hash = _ph.hash(password) if _ph.check_needs_rehash(row["password_hash"]) else None
    if new_hash:
        db.execute("UPDATE users SET password_hash = %s, failed_count = 0, locked_until = NULL WHERE id = %s",
                   (new_hash, row["id"]))
    else:
        db.execute("UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = %s", (row["id"],))
    return row, None


# ---- 화면 ----
@bp.get("/")
@login_required
def home():
    from . import dashboard                      # 홈 대시보드(본인 범위 요약). 순환 import 를 피하려고 여기서 불러온다
    return render_template("home.html", d=dashboard.build(g.user))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("auth.home"), 303)
    if request.method == "GET":
        return render_template("login.html", error=None)

    cfg = current_app.config
    if ip_rate_limited(f"login:{get_client_ip()}", cfg["LOGIN_IP_LIMIT"]):
        log_event("rate_limited", "BLOCK", "login_ip_limit")
        return render_template("error.html", code=429, message="요청이 너무 많습니다. 잠시 후 다시 시도하세요."), 429

    raw_name = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    row, _reason = authenticate(raw_name, password)
    if not row:
        return render_template("login.html", error=GENERIC_LOGIN_ERROR), 401

    _start_session(row["id"], row["session_version"])
    g.user = {k: row[k] for k in ("id", "username", "role", "display_name", "dept")}
    log_event("login_success", "ALLOW", "ok")
    return redirect(url_for("auth.home"), 303)


@bp.post("/logout")
def logout():
    if g.user:
        # 세션 버전을 올려 이 사용자의 이전 쿠키(다른 기기 포함)가 모두 쓸모없게 만든다. 훔친 쿠키를 다시 보내도 통하지 않는다.
        db.execute_rowcount("UPDATE users SET session_version = session_version + 1 WHERE id = %s", (g.user["id"],))
        log_event("logout", "INFO", "user_request")
    session.clear()
    return redirect(url_for("auth.login"), 303)


@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("password.html", error=None)

    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")
    row = db.query_one("SELECT id, password_hash FROM users WHERE id = %s FOR UPDATE", (g.user["id"],))

    if len(current) > 256 or not verify_password(row["password_hash"], current):
        # 현재 비밀번호 추측도 로그인과 같은 실패 한도를 적용한다
        locked = _register_failure(row["id"])
        log_event("password_change_failure", "DENY", "bad_current_password")
        if locked:
            log_event("account_locked", "BLOCK", "max_failures")
        db.commit()
        if locked:
            session.clear()
            return redirect(url_for("auth.login"), 303)
        return render_template("password.html", error="현재 비밀번호가 올바르지 않습니다."), 401

    try:
        validators.password_policy(new, g.user["username"])
        if new != confirm:
            raise ValueError("password_mismatch")
        if new == current:
            raise ValueError("password_reuse")
    except ValueError as exc:
        reason = str(exc)
        log_event("password_change_failure", "DENY", reason)
        return render_template("password.html", error=POLICY_MESSAGES.get(reason, "비밀번호를 확인하세요.")), 400

    # 비밀번호를 바꾸면 세션 버전도 올려, 이전에 발급된 다른 쿠키(탈취됐을 수 있는 것 포함)를 모두 무효로 만든다.
    db.execute("UPDATE users SET password_hash = %s, failed_count = 0, session_version = session_version + 1 WHERE id = %s",
               (_ph.hash(new), row["id"]))
    version = db.query_one("SELECT session_version FROM users WHERE id = %s", (row["id"],))["session_version"]
    log_event("password_changed", "ALLOW", "ok")
    _start_session(row["id"], version, keep_iat=session.get("iat"))  # 지금 기기만 새 세션(절대 만료 시각은 유지)
    return redirect(url_for("auth.home"), 303)
