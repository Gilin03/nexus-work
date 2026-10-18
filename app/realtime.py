"""메신저 실시간 전송(Socket.IO). 네이티브 앱(nexus-messenger)이 메시지를 즉시 받도록
새 메시지가 생기면 그 대화방에 들어가 있는 연결로만 밀어준다.

접속: 클라이언트가 연결할 때 `auth={"token": "<api 토큰>"}` 으로 보낸다(쿠키 세션과는 별개 인증).
토큰이 유효하면 그 사용자가 속한 모든 대화방을 Socket.IO "room"으로 자동 구독시킨다.
토큰이 없거나 틀리면 연결을 거부한다(핸드셰이크 단계에서 끊음 — 익명 연결 없음).

접속해 있는 동안 새 대화방에 초대되면(REST `POST /api/v1/conversations`), 다음 재접속을
기다리지 않고 바로 그 방 알림을 받을 수 있어야 한다. 그래서 user_id -> 접속(sid) 목록을
메모리에 따로 들고 있다가, 대화방이 막 생겼을 때 `join_new_conversation()` 으로 즉시 합류시킨다.
# ponytail: 이 매핑도 프로세스 메모리라 단일 프로세스 가정(속도 제한과 같은 한계)."""
import hashlib
from collections import defaultdict

from flask import request
from flask_socketio import SocketIO, disconnect, join_room

from . import db
from .security import log_event

socketio = SocketIO(async_mode="threading")
_sids_by_user = defaultdict(set)  # user_id -> {sid, ...}


def _user_from_token(token: str):
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = db.query_one(
        "SELECT t.user_id, u.id, u.username, u.role, u.display_name, u.dept, "
        "(u.locked_until IS NOT NULL AND u.locked_until > NOW()) AS is_locked "
        "FROM api_tokens t JOIN users u ON u.id = t.user_id "
        "WHERE t.token_hash = %s AND t.revoked_at IS NULL AND t.expires_at > NOW()", (token_hash,))
    if not row or row["is_locked"]:
        return None
    return {k: row[k] for k in ("id", "username", "role", "display_name", "dept")}


def init_app(app):
    socketio.init_app(app)


@socketio.on("connect")
def on_connect(auth):
    user = _user_from_token((auth or {}).get("token", ""))
    if not user:
        log_event("messenger_ws_deny", "DENY", "bad_token")
        disconnect()
        return False
    rows = db.query_all("SELECT conversation_id FROM conversation_members WHERE user_id = %s", (user["id"],))
    for r in rows:
        join_room(f"conv:{r['conversation_id']}")
    _sids_by_user[user["id"]].add(request.sid)
    request.environ["_nexus_user_id"] = user["id"]  # disconnect 때 매핑 정리용
    log_event("messenger_ws_connect", "INFO", "ok", user=user["username"])


@socketio.on("disconnect")
def on_disconnect():
    uid = request.environ.get("_nexus_user_id")
    if uid is not None:
        _sids_by_user[uid].discard(request.sid)


def join_new_conversation(conversation_id: int, member_ids: list):
    """막 만든 대화방에, 그 순간 접속해 있는 멤버가 있으면 재접속 없이 바로 합류시킨다."""
    room = f"conv:{conversation_id}"
    for uid in member_ids:
        for sid in _sids_by_user.get(uid, ()):
            socketio.server.enter_room(sid, room)


def broadcast_message(conversation_id: int, message: dict):
    socketio.emit("message", message, room=f"conv:{conversation_id}")
