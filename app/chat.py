"""챗봇 화면·엔드포인트. 응답을 만드는 AI·Tool 호출은 다른 담당의 몫이라 `app.config["CHAT_RESPONDER"]` 로 갈아 끼운다.

접점(Responder): `responder(user: dict, message: str, history: list[dict]) -> str`
- `user` 는 지금 로그인한 사용자(id, username, role, dept, display_name)다. 챗봇이 하는 모든 조회는 이 사용자의 권한을 넘을 수 없다.
  (권한 검사는 Security Gateway 담당. 앱은 항상 현재 로그인 사용자만 넘기고, 폼으로 사용자를 바꿀 수 없다.)
- `history` 는 **본인의** 최근 대화(오래된 것부터, 이번 메시지는 제외)다: [{"sender": "user"|"assistant", "content": str}, ...]
- 반환값은 일반 글자로만 취급한다(HTML 로 해석하지 않고, 제어문자 제거·길이 제한). 예외가 나도 앱은 안전한 안내 문구를 남긴다.
- 응답이 오래 걸리면 호출 쪽 요청이 그동안 묶인다. 실제 구현은 자체 시간 제한을 둔다.

앱이 지키는 것: 로그인 필요, CSRF, 입력 길이·문자 검증, 사용자당 속도 제한, 대화 기록은 본인 것만 조회·표시, 응답도 이스케이프.
대화 내용은 DB(chat_messages)에만 저장하고 보안 로그에는 글자 수만 남긴다.
n8n 이 users.ai_restricted=1 로 바꾼 사용자(R3 대응)는 다음 요청부터 응답기를 부르지 않고 제한 안내만 받는다.
첨부 파일(chat_attach)은 저장하지 않고 뽑은 글자를 g.chat_attachment 로 응답기에 넘긴다(그 질문에만 쓰인다)."""
from flask import Blueprint, current_app, g, redirect, render_template, request, url_for

from . import chat_attach, db, validators
from .auth import login_required
from .security import ip_rate_limited, log_event

bp = Blueprint("chat", __name__)

MAX_MESSAGE = 2000
MAX_REPLY = 8000
HISTORY_SHOWN = 50
HISTORY_FOR_RESPONDER = 10
FALLBACK_REPLY = "답변을 만들지 못했습니다. 잠시 후 다시 시도하세요."
RESTRICTED_REPLY = "보안 조치로 AI 어시스턴트 사용이 제한된 계정입니다. 관리자에게 해제를 요청하세요."
MESSAGE_ERROR = f"메시지는 1~{MAX_MESSAGE:,}자로 입력하세요(제어문자 사용 불가)."


def placeholder_responder(user, message, history):
    """실제 AI 연결 전의 시험 응답. 받은 내용을 그대로 돌려준다(화면에서는 이스케이프되어 표시된다)."""
    return f"[시험 응답] {user['display_name']}님의 메시지를 받았습니다.\n{message}"


def _clean_reply(value):
    text = validators.CONTROL_RE.sub("", str(value)).strip()
    return text[:MAX_REPLY] or "(빈 응답)"


def is_ai_restricted(user_id):
    """n8n 이 users.ai_restricted 를 바꾸면 다음 요청부터 바로 적용되도록 매번 DB 에서 읽는다(ai-agent 브랜치의 ai_gateway.is_restricted 와 같은 규칙)."""
    row = db.query_one("SELECT ai_restricted FROM users WHERE id = %s", (user_id,))
    return bool(row and row["ai_restricted"])


def _history(user_id, limit):
    rows = db.query_all("SELECT id, sender, content, created_at FROM chat_messages WHERE user_id = %s "
                        "ORDER BY id DESC LIMIT %s", (user_id, limit))
    return list(reversed(rows))


def _render(error=None, status=200):
    from . import ai
    is_placeholder = current_app.config["CHAT_RESPONDER"] is placeholder_responder
    return render_template("chat.html", messages=_history(g.user["id"], HISTORY_SHOWN), error=error,
                           placeholder=is_placeholder,
                           ai_badge=None if is_placeholder else ai.provider_badge(current_app.config),
                           ai_options=[] if is_placeholder else ai.provider_options(current_app.config),
                           ai_selected=ai.selected_choice(current_app.config),
                           max_message=MAX_MESSAGE, limit=current_app.config["CHAT_USER_LIMIT"],
                           attach_accept=chat_attach.ACCEPT, attach_exts=sorted(chat_attach.ALLOWED_EXTS),
                           attach_mb=chat_attach.MAX_BYTES // (1024 * 1024), attach_chars=chat_attach.MAX_CHARS), status


@bp.get("/chat")
@login_required
def chat_view():
    return _render()


@bp.post("/chat/messages")
@login_required
def chat_send():
    user = g.user
    if ip_rate_limited(f"chat:{user['id']}", current_app.config["CHAT_USER_LIMIT"]):
        log_event("rate_limited", "BLOCK", "chat_user_limit")
        return _render("메시지를 너무 빠르게 보내고 있습니다. 잠시 후 다시 시도하세요.", 429)
    try:
        message = validators.text(request.form.get("message", ""), "message", 1, MAX_MESSAGE, multiline=True)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="chat")
        return _render(MESSAGE_ERROR, 400)
    attachment, note = None, ""
    storage = request.files.get("attachment")
    if storage and storage.filename:
        data = storage.read(chat_attach.MAX_BYTES + 1)
        try:
            attachment = chat_attach.extract(storage.filename, data)
        except ValueError as exc:
            log_event("upload_reject", "BLOCK", str(exc), target="chat_attachment", size=len(data))
            return _render(chat_attach.MESSAGES.get(str(exc), "첨부 파일을 읽지 못했습니다."), 400)
        g.chat_attachment = attachment
        note = f"\n\n[첨부 파일: {attachment['name']}, {attachment['chars']:,}자{' (길어서 앞부분만)' if attachment['truncated'] else ''}]"
        log_event("chat_attachment", "INFO", "ok", ext=attachment["ext"], size=len(data), chars=attachment["chars"])

    history = [{"sender": r["sender"], "content": r["content"]} for r in _history(user["id"], HISTORY_FOR_RESPONDER)]
    # 사용자 메시지는 응답을 기다리기 전에 먼저 확정한다(응답 생성이 실패·지연되어도 기록은 남는다).
    db.execute("INSERT INTO chat_messages(user_id, sender, content) VALUES(%s, 'user', %s)", (user["id"], message + note))
    db.commit()
    log_event("chat_message", "INFO", "ok", chars=len(message))

    if is_ai_restricted(user["id"]):            # n8n 의 R3 대응(AI 제한): 응답기·외부 모델을 아예 부르지 않는다
        log_event("ai_restricted_block", "DENY", "ai_restricted")
        db.execute("INSERT INTO chat_messages(user_id, sender, content) VALUES(%s, 'assistant', %s)", (user["id"], RESTRICTED_REPLY))
        return redirect(url_for("chat.chat_view"), 303)
    try:
        reply = _clean_reply(current_app.config["CHAT_RESPONDER"](dict(user), message, history))
    except Exception as exc:  # 응답기가 무엇을 던져도 사용자에게 내부 정보를 보이지 않는다
        log_event("chat_responder_error", "ERROR", type(exc).__name__)
        reply = FALLBACK_REPLY
    db.execute("INSERT INTO chat_messages(user_id, sender, content) VALUES(%s, 'assistant', %s)", (user["id"], reply))
    log_event("chat_reply", "INFO", "ok", chars=len(reply))
    return redirect(url_for("chat.chat_view"), 303)
