"""Allowlisted AI tool dispatcher and request-scoped security correlation.

The model never receives a database connection or SQL. Protected tools are selected by
the application planner and each handler re-reads the authenticated principal before access.
"""
from __future__ import annotations

import re
import secrets
import hashlib

from flask import g, has_request_context, session

from . import db
from .permissions import can
from .prompt_injection import detect_direct_prompt_injection
from .security import log_event

TOOL_RESTRICTED_DOCUMENT_READ = "restricted_document_read"
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{24,64}$")
_PROTECTED_TARGET_RE = re.compile(
    r"(?:기밀|비밀|관리자|제한(?:된)?|confidential|restricted|secret)"
    r"[^.!?。！？\n]{0,40}(?:문서|자료|데이터|정보|파일|기록|documents?|data|records?|files?)?"
    r"|(?:문서|자료|데이터|정보|파일|기록|documents?|data|records?|files?)"
    r"[^.!?。！？\n]{0,40}(?:기밀|비밀|관리자|제한(?:된)?|confidential|restricted|secret)",
    re.IGNORECASE,
)
_READ_ACTION_RE = re.compile(
    r"(?:보여\s*줘|보여주세요|읽어(?:와|줘|주세요)?|열람해(?:줘|주세요)?|"
    r"조회해(?:줘|주세요)?|가져와(?:줘|주세요)?|출력해(?:줘|주세요)?|"
    r"공개해(?:줘|주세요)?|알려(?:줘|주세요)?|요약해(?:줘|주세요)?|열어(?:줘|주세요)?|"
    r"\b(?:read|retrieve|access|fetch|export|reveal|show|download|list)\b)",
    re.IGNORECASE,
)
_CORRELATION_WINDOW_SECONDS = 300


def ensure_session_id() -> str:
    """Return a server-generated opaque conversation identifier, never the cookie value."""
    if not has_request_context():
        return secrets.token_urlsafe(24)
    value = session.get("nexus_session_id")
    if not isinstance(value, str) or not _SESSION_ID_RE.fullmatch(value):
        value = secrets.token_urlsafe(24)
        session["nexus_session_id"] = value
    return value


def _targeted_read_intent(text: str) -> bool:
    return bool(text and _PROTECTED_TARGET_RE.search(text) and _READ_ACTION_RE.search(text))


def observe_attachment(attachment: dict) -> None:
    """Attach a random correlation ID and record metadata only; never log extracted text."""
    resource_id = secrets.token_urlsafe(24)
    attachment["resource_id"] = resource_id
    session_id = ensure_session_id()
    log_event(
        "content_ingested", "ALLOW", "attachment_received",
        source_component="ai_content_gateway", source_type="attachment",
        resource_id=resource_id, session_id=session_id,
    )
    pattern_id = detect_direct_prompt_injection(attachment.get("text") or "")
    if pattern_id:
        g.indirect_prompt_injection_resource_id = resource_id
        g.indirect_prompt_injection_pattern_id = pattern_id
        log_event(
            "prompt_injection_observed", "ALLOW", "indirect_content_observed",
            source_component="ai_content_gateway", injection_type="indirect",
            source_type="attachment", resource_id=resource_id,
            pattern_id=pattern_id, session_id=session_id, severity="info",
        )


def mark_attachment_read(attachment: dict | None) -> None:
    """Record that extracted attachment content is being supplied to the responder."""
    if not attachment:
        return
    resource_id = attachment.get("resource_id")
    if not isinstance(resource_id, str) or not resource_id:
        return
    session_id = ensure_session_id()
    g.ai_read_resource_ids = set(g.get("ai_read_resource_ids", set())) | {resource_id}
    log_event(
        "ai_content_read", "ALLOW", "attachment_added_to_ai_context",
        source_component="ai_content_gateway", source_type="attachment",
        resource_id=resource_id, session_id=session_id,
    )


def plan_restricted_document_tool(message: str, attachment: dict | None = None) -> dict | None:
    """Return trusted correlation metadata for a selected tool, never arbitrary model arguments."""
    if _targeted_read_intent(message):
        return {"tool_name": TOOL_RESTRICTED_DOCUMENT_READ, "trigger_source": "user_request"}

    if not attachment or not _targeted_read_intent(attachment.get("text") or ""):
        return None
    resource_id = attachment.get("resource_id")
    observed_id = g.get("indirect_prompt_injection_resource_id") if has_request_context() else None
    read_ids = g.get("ai_read_resource_ids", set()) if has_request_context() else set()
    if (not resource_id or resource_id != observed_id or resource_id not in read_ids):
        return None
    return {
        "tool_name": TOOL_RESTRICTED_DOCUMENT_READ,
        "trigger_source": "indirect_prompt_injection",
        "trigger_resource_id": resource_id,
    }


def should_offer_tool_selection(message: str, attachment: dict | None = None) -> bool:
    """Ask the model for an allowlisted action only for protected-resource requests or attachments."""
    return bool(attachment or _targeted_read_intent(message))


def _authoritative_principal(user: dict) -> dict | None:
    """Refresh role/title/dept from the database; request or model fields cannot grant access."""
    if not isinstance(user, dict) or not user.get("id"):
        return None
    return db.query_one(
        "SELECT u.id, u.username, u.display_name, u.role, u.dept, u.pinned, e.title "
        "FROM users u LEFT JOIN employees e ON e.user_id = u.id "
        "WHERE u.id = %s AND u.deleted_at IS NULL",
        (user["id"],),
    )


def _record_deny(principal: dict | None, session_id: str, tool_name: str) -> int | None:
    """Persist and serialize R11 evidence across Flask workers and restarts.

    The MySQL advisory lock remains held on the request's app_db connection until
    db.finish_request commits and teardown closes it. This prevents two transactions
    for the same user/session/tool from observing the same pre-insert count.
    """
    subject = str((principal or {}).get("id") or "unknown")
    request_id = getattr(g, "nexus_request_id", None) if has_request_context() else None
    request_id = str(request_id or secrets.token_hex(16))[:64]
    lock_digest = hashlib.sha256(f"{subject}|{session_id}|{tool_name}".encode("utf-8")).hexdigest()[:60]
    lock_name = "r11:" + lock_digest  # MySQL 8 lock names are limited to 64 characters.
    lock_row = db.query_one("SELECT GET_LOCK(%s, 5) AS acquired", (lock_name,))
    if not lock_row or int(lock_row.get("acquired") or 0) != 1:
        return None

    # Keep only a bounded amount of stale evidence; no prompt, document, or token is stored.
    db.execute_rowcount(
        "DELETE FROM security_ai_tool_denials "
        "WHERE occurred_at < UTC_TIMESTAMP(6) - INTERVAL 1 DAY LIMIT 1000"
    )
    inserted = db.execute_rowcount(
        "INSERT IGNORE INTO security_ai_tool_denials "
        "(request_id, user_id, session_id, tool_name, occurred_at) "
        "VALUES (%s, %s, %s, %s, UTC_TIMESTAMP(6))",
        (request_id, int(subject) if subject.isdigit() else 0, session_id, tool_name),
    )
    if inserted != 1:
        return None  # request_id replay: it is not another denial and must not emit R11.
    count_row = db.query_one(
        "SELECT COUNT(*) AS denial_count FROM security_ai_tool_denials "
        "WHERE user_id = %s AND session_id = %s AND tool_name = %s "
        "AND occurred_at >= UTC_TIMESTAMP(6) - INTERVAL 300 SECOND",
        (int(subject) if subject.isdigit() else 0, session_id, tool_name),
    )
    return int((count_row or {}).get("denial_count") or 0)


def reset_deny_correlation() -> None:
    """Compatibility no-op: R11 evidence is persisted in MySQL, not process memory."""
    return None


TOOL_DOCUMENT_SEARCH = "document_search"
TOOL_DOCUMENT_READ = "document_read"
TOOL_RESTRICTED_DOCUMENT_READ = "restricted_document_read"
TOOL_INTERNAL_API_CALL = "internal_api_call"


def is_defense_on() -> bool:
    """DEFENSE_MODE(기본값: on). off 설정 시 기밀 문서 열람과 출력을 허용해 공격 성공을 시연한다.
    운영 중 .env 파일을 수정하면 서버 재시작 없이도 실시간으로 방어 켜짐/꺼짐이 전환된다."""
    import os
    import sys
    from pathlib import Path
    from dotenv import dotenv_values

    # 단위 테스트 환경에서는 monkeypatch 지원을 위해 os.environ 우선 적용
    if "pytest" in sys.modules or os.environ.get("TESTING"):
        return os.environ.get("DEFENSE_MODE", "on").strip().lower() != "off"

    # 운영 환경에서는 .env 파일 변경값을 실시간 우선 반영
    try:
        base_dir = Path(__file__).resolve().parent.parent
        env_file = base_dir / ".env"
        if env_file.exists():
            cfg = dotenv_values(env_file)
            mode = cfg.get("DEFENSE_MODE")
            if mode is not None and str(mode).strip():
                return str(mode).strip().lower() != "off"
    except Exception:
        pass

    return os.environ.get("DEFENSE_MODE", "on").strip().lower() != "off"


def dispatch_tool(
    tool_name: str,
    user: dict,
    *,
    session_id: str,
    trigger_source: str = "user_request",
    trigger_resource_id: str | None = None,
    args: dict | None = None,
) -> dict:
    """Authorize and run one allowlisted tool; denied calls never execute its database query."""
    if tool_name not in (TOOL_RESTRICTED_DOCUMENT_READ, TOOL_DOCUMENT_SEARCH, TOOL_DOCUMENT_READ, TOOL_INTERNAL_API_CALL):
        log_event(
            "agent_tool_call", "DENY", "tool_not_allowlisted",
            source_component="security_gateway", severity="high",
            session_id=session_id, tool_name="unsupported",
            resource_class="confidential", trigger_source="user_request",
        )
        return {"decision": "DENY", "documents": []}

    principal = _authoritative_principal(user)
    defense_active = is_defense_on()

    # n8n 이 설정한 AI 제한(users.ai_restricted=1)은 DEFENSE_MODE 와 무관하게 항상 적용된다.
    user_id = (principal or {}).get("id")
    if user_id:
        res_row = db.query_one("SELECT ai_restricted FROM users WHERE id = %s", (user_id,))
        if res_row and res_row.get("ai_restricted"):
            log_event(
                "agent_tool_call", "DENY", "user_ai_restricted",
                source_component="security_gateway", severity="high",
                session_id=session_id, tool_name=tool_name,
                resource_class="confidential", trigger_source="user_request",
            )
            return {"decision": "DENY", "documents": []}

    if tool_name == TOOL_DOCUMENT_SEARCH:
        query = str((args or {}).get("query", ""))[:50]
        q_param = f"%{query}%"
        docs = db.query_all("SELECT id, title FROM documents WHERE title LIKE %s OR body LIKE %s ORDER BY id DESC LIMIT 5", (q_param, q_param))
        posts = db.query_all("SELECT id, title FROM posts WHERE title LIKE %s OR body LIKE %s ORDER BY id DESC LIMIT 5", (q_param, q_param))
        return {"decision": "ALLOW", "documents": docs + posts}

    if tool_name == TOOL_DOCUMENT_READ:
        doc_id = (args or {}).get("id")
        doc = db.query_one("SELECT id, title, body FROM documents WHERE id = %s", (doc_id,)) if doc_id else None
        return {"decision": "ALLOW" if doc else "DENY", "document": doc}

    if tool_name == TOOL_INTERNAL_API_CALL:
        allowed = (not defense_active) or bool(principal and principal.get("role") == "service_account")
        if not allowed:
            log_event(
                "agent_tool_call", "DENY", "service_account_required",
                source_component="security_gateway", severity="high",
                session_id=session_id, tool_name=tool_name,
            )
            return {"decision": "DENY", "result": "서비스 계정 전용 도구입니다."}
        api_path = str((args or {}).get("path", "/flag"))
        token = str((args or {}).get("token", ""))
        from . import internal_api
        ok, res_text = internal_api.internal_api(api_path, token, via="gateway")
        return {"decision": "ALLOW" if ok else "DENY", "result": res_text}

    # 기밀 문서 열람 (restricted_document_read)
    allowed = (not defense_active) or bool(principal and can(principal, "doc.confidential"))
    safe_trigger = "indirect_prompt_injection" if trigger_source == "indirect_prompt_injection" else "user_request"
    resource_id = None
    if safe_trigger == "indirect_prompt_injection":
        read_ids = g.get("ai_read_resource_ids", set()) if has_request_context() else set()
        observed_id = g.get("indirect_prompt_injection_resource_id") if has_request_context() else None
        if trigger_resource_id and trigger_resource_id == observed_id and trigger_resource_id in read_ids:
            resource_id = trigger_resource_id
        else:
            safe_trigger = "user_request"

    base_fields = {
        "source_component": "security_gateway",
        "severity": "high" if not allowed else "info",
        "session_id": session_id,
        "tool_name": tool_name,
        "resource_class": "confidential",
        "resource": "confidential_documents",
        "role": (principal or {}).get("role", "unknown"),
        "trigger_source": safe_trigger,
    }
    if resource_id:
        base_fields["trigger_resource_id"] = resource_id

    if not allowed:
        try:
            count = _record_deny(principal, session_id, tool_name)
        except Exception:  # R3 must still deny safely even if the R11 store is unavailable.
            count = None
        if count == 3:
            base_fields["count"] = 3
            base_fields["window_seconds"] = _CORRELATION_WINDOW_SECONDS
        log_event("agent_tool_call", "DENY", "insufficient_permission", **base_fields)
        log_event("authz_deny", "DENY", "insufficient_role", resource="confidential_documents", source="ai")
        return {"decision": "DENY", "documents": []}

    # Never accept a query or document identifier from the caller/model; this SQL is fixed.
    documents = db.query_all(
        "SELECT id, title, body, created_at FROM confidential_documents ORDER BY id DESC LIMIT 5",
        conf=True,
    )
    reason = "permission_granted" if (principal and can(principal, "doc.confidential")) else "defense_off_allow"
    log_event("agent_tool_call", "ALLOW", reason, **base_fields)
    log_event("confidential_access", "ALLOW", "ai_context", resource="confidential_documents", rows=len(documents))
    return {"decision": "ALLOW", "documents": documents}
