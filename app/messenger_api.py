"""메신저(nexus-messenger, 별도 설치 앱)용 JSON API. `/api/v1/*`.

- 네이티브 앱은 쿠키를 못 쓰므로 세션 대신 토큰(`Authorization: Bearer <token>`)으로 인증한다.
  토큰은 로그인 때 한 번만 평문으로 내려주고, 서버는 sha256 해시만 저장한다.
- 자격증명 확인(아이디·비밀번호·잠금)은 app.auth 의 로직을 그대로 재사용한다(이중 구현 금지 —
  브루트포스 방어가 두 군데서 따로 놀면 한쪽만 고치고 잊어버리기 쉽다).
- 대화방 접근은 매 요청 conversation_members 로 재확인한다(세션 로그인과 같은 원칙:
  멤버 목록을 캐시하거나 토큰 안에 담지 않는다).
"""
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, g, jsonify, request

from . import auth, db, validators
from .realtime import broadcast_message, join_new_conversation
from .security import ip_rate_limited, log_event

bp = Blueprint("messenger_api", __name__, url_prefix="/api/v1")

TOKEN_TTL_DAYS = 30
MAX_MESSAGE = 4000
MAX_GROUP_MEMBERS = 50


def _err(code, message, status):
    return jsonify(error=code, message=message), status


# ---------- 토큰 인증 ----------
def _load_token_user():
    hdr = request.headers.get("Authorization", "")
    if not hdr.startswith("Bearer "):
        return None
    token = hdr[len("Bearer "):].strip()
    if not token:
        return None
    token_hash = __import__("hashlib").sha256(token.encode()).hexdigest()
    row = db.query_one(
        "SELECT t.id AS token_id, u.id, u.username, u.role, u.display_name, u.dept, "
        "(u.locked_until IS NOT NULL AND u.locked_until > NOW()) AS is_locked "
        "FROM api_tokens t JOIN users u ON u.id = t.user_id "
        "WHERE t.token_hash = %s AND t.revoked_at IS NULL AND t.expires_at > NOW()", (token_hash,))
    if not row or row["is_locked"]:
        return None
    g.token_id = row["token_id"]
    return {k: row[k] for k in ("id", "username", "role", "display_name", "dept")}


def token_required(view):
    from functools import wraps

    @wraps(view)
    def wrapper(*args, **kwargs):
        user = _load_token_user()
        if not user:
            log_event("messenger_authz_deny", "DENY", "bad_or_missing_token")
            return _err("unauthorized", "인증이 필요합니다.", 401)
        g.user = user
        return view(*args, **kwargs)
    return wrapper


def _is_member(conversation_id, user_id):
    return db.query_one("SELECT 1 FROM conversation_members WHERE conversation_id = %s AND user_id = %s",
                        (conversation_id, user_id)) is not None


# ---------- 로그인/로그아웃(토큰 발급) ----------
@bp.post("/login")
def api_login():
    cfg = current_app.config
    if ip_rate_limited(f"login:{request.remote_addr}", cfg["LOGIN_IP_LIMIT"]):
        log_event("rate_limited", "BLOCK", "login_ip_limit")
        return _err("rate_limited", "요청이 너무 많습니다. 잠시 후 다시 시도하세요.", 429)

    body = request.get_json(silent=True) or {}
    raw_name = str(body.get("username", ""))[:256].strip().lower()
    password = str(body.get("password", ""))[:256]
    device = str(body.get("device", ""))[:120]

    row, reason = auth.authenticate(raw_name, password)
    if not row:
        return _err("invalid_credentials", auth.GENERIC_LOGIN_ERROR, 401)

    token = secrets.token_urlsafe(32)
    token_hash = __import__("hashlib").sha256(token.encode()).hexdigest()
    expires = datetime.now(timezone.utc) + timedelta(days=TOKEN_TTL_DAYS)
    db.execute("INSERT INTO api_tokens(user_id, token_hash, device, expires_at) VALUES(%s, %s, %s, %s)",
              (row["id"], token_hash, device, expires.strftime("%Y-%m-%d %H:%M:%S")))
    log_event("messenger_login_success", "ALLOW", "ok", user=row["username"])
    return jsonify(token=token, expires_at=expires.isoformat(),
                  user={"id": row["id"], "username": row["username"], "display_name": row["display_name"],
                        "dept": row["dept"], "role": row["role"]})


@bp.post("/logout")
@token_required
def api_logout():
    db.execute("UPDATE api_tokens SET revoked_at = NOW() WHERE id = %s", (g.token_id,))
    log_event("messenger_logout", "INFO", "ok")
    return jsonify(ok=True)


# ---------- 대화 상대 찾기(계정이 있는 사용자만) ----------
@bp.get("/users")
@token_required
def list_users():
    q = request.args.get("q", "").strip()
    if not q:
        rows = db.query_all("SELECT id, username, display_name, dept FROM users WHERE id <> %s "
                            "ORDER BY display_name LIMIT 50", (g.user["id"],))
        return jsonify(users=rows)
    try:
        pattern = validators.like_pattern(q)
    except ValueError:
        return _err("invalid_query", "검색어는 1~50자로 입력하세요.", 400)
    rows = db.query_all("SELECT id, username, display_name, dept FROM users "
                        "WHERE id <> %s AND (display_name LIKE %s OR username LIKE %s OR dept LIKE %s) "
                        "ORDER BY display_name LIMIT 50", (g.user["id"], pattern, pattern, pattern))
    return jsonify(users=rows)


# ---------- 대화방 ----------
@bp.get("/conversations")
@token_required
def list_conversations():
    rows = db.query_all(
        "SELECT c.id, c.kind, c.name, "
        "(SELECT m.body FROM messenger_messages m WHERE m.conversation_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_body, "
        "(SELECT m.created_at FROM messenger_messages m WHERE m.conversation_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_at, "
        "(SELECT MAX(m.id) FROM messenger_messages m WHERE m.conversation_id = c.id) AS last_id, "
        "cm.last_read_message_id "
        "FROM conversations c JOIN conversation_members cm ON cm.conversation_id = c.id "
        "WHERE cm.user_id = %s ORDER BY last_at IS NULL, last_at DESC", (g.user["id"],))
    for r in rows:
        r["unread"] = bool(r["last_id"] and r["last_id"] > r["last_read_message_id"])
        if r["kind"] == "dm":
            other = db.query_one(
                "SELECT u.id, u.display_name, u.dept FROM conversation_members cm "
                "JOIN users u ON u.id = cm.user_id WHERE cm.conversation_id = %s AND cm.user_id <> %s",
                (r["id"], g.user["id"]))
            r["peer"] = other
    return jsonify(conversations=rows)


@bp.post("/conversations")
@token_required
def create_conversation():
    body = request.get_json(silent=True) or {}
    member_ids = body.get("member_ids")
    name = str(body.get("name", "") or "")[:120].strip()
    if not isinstance(member_ids, list) or not member_ids:
        return _err("invalid_members", "대화 상대를 한 명 이상 지정하세요.", 400)
    try:
        member_ids = sorted({validators.positive_int(m, "member") for m in member_ids})
    except ValueError:
        return _err("invalid_members", "대화 상대 지정이 올바르지 않습니다.", 400)
    if g.user["id"] in member_ids:
        return _err("invalid_members", "본인은 자동으로 포함되므로 따로 지정하지 마세요.", 400)
    if len(member_ids) > MAX_GROUP_MEMBERS:
        return _err("too_many_members", f"대화 상대는 최대 {MAX_GROUP_MEMBERS}명입니다.", 400)
    # 가변 개수 id 조회는 이 프로젝트의 기존 관례(erp.py 의 팀 범위 조회)와 같이 FIND_IN_SET 을 쓴다
    # (IN (...) 을 동적으로 만들면 tests/test_sql_static.py 의 "SQL은 항상 상수 문자열" 규칙에 걸린다).
    ids_csv = ",".join(str(m) for m in member_ids)
    existing = db.query_all("SELECT id FROM users WHERE FIND_IN_SET(id, %s)", (ids_csv,))
    if len(existing) != len(member_ids):
        return _err("invalid_members", "존재하지 않는 사용자가 포함되어 있습니다.", 400)

    kind = "dm" if len(member_ids) == 1 else "group"
    if kind == "dm":
        # 같은 두 사람의 1:1 대화방은 하나만 둔다(이미 있으면 그걸 돌려준다).
        dup = db.query_one(
            "SELECT c.id FROM conversations c "
            "JOIN conversation_members a ON a.conversation_id = c.id AND a.user_id = %s "
            "JOIN conversation_members b ON b.conversation_id = c.id AND b.user_id = %s "
            "WHERE c.kind = 'dm'", (g.user["id"], member_ids[0]))
        if dup:
            return jsonify(conversation_id=dup["id"], created=False)

    conv_id = db.execute("INSERT INTO conversations(kind, name, created_by) VALUES(%s, %s, %s)",
                         (kind, name or None, g.user["id"]))
    for uid in [g.user["id"]] + member_ids:
        db.execute("INSERT INTO conversation_members(conversation_id, user_id) VALUES(%s, %s)", (conv_id, uid))
    join_new_conversation(conv_id, [g.user["id"]] + member_ids)
    log_event("messenger_conversation_created", "INFO", "ok", conversation_id=conv_id, kind=kind, members=len(member_ids) + 1)
    return jsonify(conversation_id=conv_id, created=True), 201


@bp.get("/conversations/<int:conversation_id>/messages")
@token_required
def list_messages(conversation_id):
    if not _is_member(conversation_id, g.user["id"]):
        log_event("messenger_authz_deny", "DENY", "not_member", resource=f"conversation:{conversation_id}")
        return _err("forbidden", "접근 권한이 없습니다.", 403)
    try:
        after = validators.positive_int(request.args.get("after", "0"), "after", 2**31 - 1) if request.args.get("after", "0") != "0" else 0
        limit = min(validators.positive_int(request.args.get("limit", "50"), "limit", 200), 200)
    except ValueError:
        return _err("invalid_params", "after/limit 값이 올바르지 않습니다.", 400)
    rows = db.query_all(
        "SELECT m.id, m.sender_id, u.display_name AS sender_name, m.body, m.created_at "
        "FROM messenger_messages m JOIN users u ON u.id = m.sender_id "
        "WHERE m.conversation_id = %s AND m.id > %s ORDER BY m.id ASC LIMIT %s",
        (conversation_id, after, limit))
    db.execute("UPDATE conversation_members SET last_read_message_id = GREATEST(last_read_message_id, %s) "
              "WHERE conversation_id = %s AND user_id = %s",
              (rows[-1]["id"] if rows else after, conversation_id, g.user["id"]))
    return jsonify(messages=rows)


@bp.post("/conversations/<int:conversation_id>/messages")
@token_required
def send_message(conversation_id):
    if not _is_member(conversation_id, g.user["id"]):
        log_event("messenger_authz_deny", "DENY", "not_member", resource=f"conversation:{conversation_id}")
        return _err("forbidden", "접근 권한이 없습니다.", 403)
    if ip_rate_limited(f"msg:{g.user['id']}", current_app.config.get("CHAT_USER_LIMIT", 20)):
        log_event("rate_limited", "BLOCK", "messenger_user_limit")
        return _err("rate_limited", "메시지를 너무 빠르게 보내고 있습니다.", 429)
    body = request.get_json(silent=True) or {}
    try:
        text = validators.text(str(body.get("body", "")), "message", 1, MAX_MESSAGE, multiline=True)
    except ValueError:
        return _err("invalid_body", f"메시지는 1~{MAX_MESSAGE}자로 입력하세요(제어문자 사용 불가).", 400)

    msg_id = db.execute("INSERT INTO messenger_messages(conversation_id, sender_id, body) VALUES(%s, %s, %s)",
                        (conversation_id, g.user["id"], text))
    db.execute("UPDATE conversation_members SET last_read_message_id = %s WHERE conversation_id = %s AND user_id = %s",
              (msg_id, conversation_id, g.user["id"]))
    row = db.query_one("SELECT created_at FROM messenger_messages WHERE id = %s", (msg_id,))
    payload = {"id": msg_id, "conversation_id": conversation_id, "sender_id": g.user["id"],
              "sender_name": g.user["display_name"], "body": text, "created_at": row["created_at"].isoformat()}
    log_event("messenger_message_sent", "INFO", "ok", conversation_id=conversation_id, chars=len(text))
    broadcast_message(conversation_id, payload)
    return jsonify(message=payload), 201
