"""보안 공통: JSON 이벤트 로그, CSRF, 응답 헤더, IP 단위 요청 제한."""
import gzip
import hmac
import ipaddress
import json
import os
import logging
import re
import secrets
import socket
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from flask import abort, current_app, g, jsonify, render_template, request, session

_logger = logging.getLogger("nexus.security")
_logger.propagate = False

PROTECTED_BLOCK_IPS = frozenset({"127.0.0.1", "192.168.3.10", "192.168.3.14", "192.168.3.15", "::1"})


def is_protected_block_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped:
        address = mapped
    return address.is_loopback or address.compressed in PROTECTED_BLOCK_IPS

GRAYLOG_FIELDS = {
    "event_type", "source_component", "severity", "user", "role", "src_ip", "method", "path",
    "decision", "reason", "request_id", "session_id", "injection_type", "source_type", "trigger_source",
    "tool_name", "resource_class", "resource_id", "trigger_resource_id", "pattern_id", "caller_service",
    "required", "resource", "field", "kind", "count", "chars", "rows", "size", "target", "action",
    "selected_window_key", "selected_window_start", "event_rows_count", "assessment_insert_affected_rows",
    "approval_id", "requester_id", "expense_id", "steps", "board", "post_id", "attachment_id", "failed_attempts",
    "conversation_id", "members", "action_level", "lock_request_id", "trigger_event_type", "window_seconds",
    "has_token", "token_fp", "user_agent",
}
SENSITIVE_LOG_FIELDS = {
    "password", "current_password", "new_password", "confirm_password", "token", "api_token", "access_token",
    "refresh_token", "authorization", "cookie", "prompt", "prompt_text", "prompt_raw", "message", "body",
    "content", "secret",
}
SEVERITY_LEVELS = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}


def get_client_ip() -> str:
    """클라이언트 실제 IP 확인.
    
    신뢰할 수 있는 프록시(기본: 127.0.0.1, 192.168.3.10 pfSense)를 거쳐 온 경우에만
    X-Forwarded-For 또는 X-Real-IP 헤더의 최초 클라이언트 IP를 채택하고, 그 외에는 소켓 연결 IP(remote_addr)를 반환한다.
    """
    remote = request.remote_addr or "-"
    trusted = {"127.0.0.1", "192.168.3.10", "::1"}
    if current_app:
        trusted = current_app.config.get("TRUSTED_PROXIES", trusted)

    if remote in trusted:
        forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
        if forwarded_for:
            first_ip = forwarded_for.split(",")[0].strip()
            if first_ip:
                return first_ip
        real_ip = request.headers.get("X-Real-IP", "").strip()
        if real_ip:
            return real_ip
    return remote



_blocked_ip_cache = {}  # {ip: (blocked: bool, reason: str, expire_at: float)}
_CACHE_TTL = 3.0  # 초 단위 캐시


def is_ip_blocked(ip: str) -> tuple[bool, str]:
    """해당 IP가 차단되어 있는지 확인 (만료 시간 검사 및 3초 캐시 적용)."""
    if not ip or ip == "-" or is_protected_block_ip(ip):
        return False, ""

    now_ts = time.time()
    cached = _blocked_ip_cache.get(ip)
    if cached and cached[2] > now_ts:
        return cached[0], cached[1]

    try:
        from . import db
        row = db.query_one(
            "SELECT reason, blocked_until FROM blocked_ips WHERE ip_address = %s AND blocked_until > NOW()",
            (ip,)
        )
        if row:
            _blocked_ip_cache[ip] = (True, row["reason"], now_ts + _CACHE_TTL)
            return True, row["reason"]
        else:
            _blocked_ip_cache[ip] = (False, "", now_ts + _CACHE_TTL)
            return False, ""
    except Exception:
        return False, ""


def block_ip(ip: str, reason: str = "manual_block", minutes: int = 30, created_by: str = "system") -> bool:
    """IP 차단 등록 (이미 있으면 차단 시간 연장)."""
    if not ip or is_protected_block_ip(ip):
        return False
    try:
        from . import db
        db.execute(
            """
            INSERT INTO blocked_ips (ip_address, reason, blocked_until, created_by)
            VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL %s MINUTE), %s)
            ON DUPLICATE KEY UPDATE
                reason = VALUES(reason),
                blocked_until = VALUES(blocked_until),
                created_by = VALUES(created_by)
            """,
            (ip, reason, minutes, created_by)
        )
        db.commit()
        _blocked_ip_cache.pop(ip, None)
        return True
    except Exception:
        return False


def unblock_ip(ip: str) -> bool:
    """IP 차단 해제."""
    try:
        from . import db
        db.execute("DELETE FROM blocked_ips WHERE ip_address = %s", (ip,))
        db.commit()
        _blocked_ip_cache.pop(ip, None)
        return True
    except Exception:
        return False


def check_ip_block():
    """모든 HTTP 요청 전 IP 차단 여부 검사 (before_request 훅)."""
    if request.path.startswith("/static/") or request.path == "/healthz":
        return None
    client_ip = get_client_ip()
    blocked, reason = is_ip_blocked(client_ip)
    if blocked:
        log_event("ip_blocked", "BLOCK", reason, src_ip=client_ip, target="ip_block")
        if request.path.startswith(("/api/", "/internal/api/")):
            return jsonify(ok=False, error="ip_blocked", message="보안 정책에 의해 접근이 차단된 IP입니다."), 403
        return render_template("error.html", code=403, message="보안 정책에 의해 접근이 차단된 IP입니다."), 403
    return None

def _is_sensitive_log_field(name, value=None):
    normalized = str(name).lower()
    if normalized == "has_token":
        return not isinstance(value, bool)
    if normalized == "token_fp":
        return not (isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{10}|-)", value))
    return normalized in SENSITIVE_LOG_FIELDS or any(
        part in normalized for part in ("password", "_token", "token_", "prompt", "authorization", "cookie", "secret")
    )


class GelfUdpHandler(logging.Handler):
    """Send a small, redacted GELF 1.1 event without coupling request success to UDP delivery."""

    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = int(port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    @staticmethod
    def _severity(event):
        severity = event.get("severity")
        if not isinstance(severity, str) or severity not in SEVERITY_LEVELS:
            severity = {"ERROR": "high", "DENY": "medium", "BLOCK": "medium", "WARN": "low"}.get(
                event.get("decision"), "info"
            )
        return severity

    @staticmethod
    def _timestamp(value):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (AttributeError, TypeError, ValueError):
            return time.time()

    def emit(self, record):
        try:
            event = json.loads(record.getMessage())
            event_type = event.get("event_type", "security_event")
            if not isinstance(event_type, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", event_type):
                event_type = "security_event"
            severity = self._severity(event)
            src_ip = event.get("src_ip") or "-"

            # 관제(Graylog SIEM)에서 14번 서버 IP 대신 실제 클라이언트 IP가 Source 컬럼에 노출되도록 지원
            use_client_as_source = os.environ.get("GRAYLOG_SOURCE_CLIENT_IP") == "1"
            if current_app and current_app.config.get("TESTING") and not current_app.config.get("GRAYLOG_SOURCE_CLIENT_IP"):
                use_client_as_source = False

            display_host = src_ip if (use_client_as_source and src_ip and src_ip != "-") else "nexus-portal"
            short_msg = f"[{src_ip}] {event_type} {event.get('path', '')}".strip() if use_client_as_source else event_type

            payload = {
                "version": "1.1",
                "host": display_host,
                "short_message": short_msg,
                "timestamp": self._timestamp(event.get("ts")),
                "level": SEVERITY_LEVELS[severity],
            }
            if use_client_as_source and src_ip and src_ip != "-":
                payload["_client_ip"] = src_ip
                payload["_real_ip"] = src_ip
                payload["_srcip"] = src_ip
                payload["_server_host"] = "nexus-portal-14"
            for name in GRAYLOG_FIELDS:
                if name == "ts" or name not in event or _is_sensitive_log_field(name, event[name]):
                    continue
                value = severity if name == "severity" else event[name]
                if isinstance(value, bool):
                    value = "true" if value else "false"
                elif isinstance(value, (int, float)):
                    pass
                elif isinstance(value, str):
                    if len(value) > 200 or any(ord(char) < 32 or ord(char) == 127 for char in value):
                        continue
                    if name == "reason" and not re.fullmatch(r"[A-Za-z0-9_.:/>\-]{1,120}", value):
                        continue
                else:
                    continue
                payload[f"_{name}"] = value

            encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            packet = gzip.compress(encoded)
            if len(packet) <= 8192:
                self.socket.sendto(packet, (self.host, self.port))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            # UDP is best-effort: a Graylog outage must not break portal requests or recurse into this logger.
            return

    def close(self):
        try:
            self.socket.close()
        finally:
            super().close()


def init_logging(log_dir, graylog_host=None, graylog_port=12201):
    """호출할 때마다 핸들러를 교체해 현재 설정의 로그 경로만 쓰게 한다."""
    log_dir.mkdir(parents=True, exist_ok=True)
    for h in list(_logger.handlers):
        _logger.removeHandler(h)
        h.close()
    handler = RotatingFileHandler(log_dir / "security.jsonl", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)
    if graylog_host:
        _logger.addHandler(GelfUdpHandler(graylog_host, graylog_port))
    _logger.setLevel(logging.INFO)


def log_xdr_process_debug(*, selected_window_key, selected_window_start, event_rows_count,
                          assessment_insert_affected_rows, reason=None):
    """Write metadata-only XDR processing diagnostics through the security log handlers."""
    if hasattr(selected_window_start, "isoformat"):
        selected_window_start = selected_window_start.isoformat(sep=" ")
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "event_type": "xdr_process_debug",
        "source_component": "ai_xdr",
        "severity": "info",
        "selected_window_key": str(selected_window_key)[:200],
        "selected_window_start": str(selected_window_start)[:80],
        "event_rows_count": int(event_rows_count),
        "assessment_insert_affected_rows": assessment_insert_affected_rows,
    }
    if reason is not None:
        record["reason"] = str(reason)[:80]
    _logger.info(json.dumps(record, ensure_ascii=False, separators=(",", ":")))


def log_event(event_type: str, decision: str = "INFO", reason: str = "", **extra):
    """모든 이벤트가 같은 필드 구조를 가진다. 비밀번호·토큰은 기록하지 않는다.
    값은 json.dumps 로 직렬화되므로 개행·따옴표를 넣어 로그 줄을 위조할 수 없다."""
    user = getattr(g, "user", None) or {}
    request_id = getattr(g, "nexus_request_id", None)
    if request_id is None:
        request_id = secrets.token_hex(16)
        g.nexus_request_id = request_id
    source_component = extra.pop("source_component", "portal")
    severity = extra.pop("severity", None)
    if not isinstance(severity, str) or severity not in SEVERITY_LEVELS:
        severity = {"ERROR": "high", "DENY": "medium", "BLOCK": "medium", "WARN": "low"}.get(decision, "info")
    client_ip_val = get_client_ip()
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "event_type": event_type,
        "request_id": request_id,
        "source_component": source_component,
        "severity": severity,
        "user": user.get("username") or extra.pop("user", "-"),
        "role": user.get("role", "-"),
        "src_ip": client_ip_val,
        "srcip": client_ip_val,
        "client_ip": client_ip_val,
        "method": request.method,
        "path": request.path[:200],
        "decision": decision,
        "reason": reason,
    }
    extra.pop("user", None)
    extra.pop("request_id", None)
    for k, v in extra.items():
        if _is_sensitive_log_field(k, v):
            continue
        record[k] = v if isinstance(v, (int, float, bool)) else str(v)[:200]
    _logger.info(json.dumps(record, ensure_ascii=False))
    try:
        from .audit import broadcast_audit_event
        broadcast_audit_event(record)
    except Exception:
        pass
    try:
        from .auth_events import collect_auth_events

        for derived in collect_auth_events(record):
            derived_type = derived.pop("event_type", "post_lock_retry_detected")
            log_event(
                derived_type,
                derived.pop("decision"),
                derived.pop("reason"),
                **derived,
            )
    except Exception as exc:  # Aggregation must not change authentication behavior.
        current_app.logger.error(
            "auth_event_aggregation_failed event_type=%s error_type=%s",
            event_type,
            type(exc).__name__,
        )


# ---- 의심 입력 기록(차단하지 않는다) ----
# 파라미터 바인딩·이스케이프로 이미 안전하게 처리되지만, 그 시도 자체는 탐지(C)가 쓸 신호다.
SUSPICIOUS = [
    ("sqli", re.compile(r"(?i)(\bunion\b\s+(all\s+)?select\b|\bor\b\s*\(?\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\bsleep\s*\(|\bbenchmark\s*\("
                        r"|\bwaitfor\s+delay\b|;\s*(drop|delete|insert|update|alter)\b|--\s*$|'\s*(or|and)\s+')")),
    ("xss", re.compile(r"(?i)(<\s*script|<\s*img[^>]*\bon\w+\s*=|<\s*svg[^>]*\bon\w+|<\s*iframe|javascript\s*:|\bon(error|load|click)\s*=)")),
    ("traversal", re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e(%2f|/|%5c)|%252e)")),
]
SKIP_FIELDS = {"password", "current_password", "new_password", "confirm_password", "csrf_token"}  # 비밀번호는 보지도 기록하지도 않는다
NO_VALUE_FIELDS = {"message", "body", "reason", "prompt", "prompt_text", "prompt_raw", "content", "document", "attachment"}  # 내용은 로그에 남기지 않고 종류만 남긴다


def scan_inputs():
    hits = []
    sources = [(k, v) for src in (request.args, request.form) for k, v in src.items(multi=True)]
    for key, value in sources:
        if key in SKIP_FIELDS or not isinstance(value, str):
            continue
        for kind, rx in SUSPICIOUS:
            if rx.search(value[:5000]):
                hits.append((key, kind, value))
                break
    if SUSPICIOUS[2][1].search(request.path):
        hits.append(("path", "traversal", request.path))
    if hits:
        key, kind, value = hits[0]
        extra = {"field": key, "kind": kind, "count": len(hits)}
        if key not in NO_VALUE_FIELDS:
            extra["value"] = value[:80]
        log_event("suspicious_input", "WARN", kind, **extra)


# ---- CSRF ----
def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if (request.path.startswith("/api/v1/")
            or request.path.startswith("/internal/api/v1/blocked-ips")
            or request.path.startswith("/internal/api/v1/ai-xdr/")
            or request.path == "/internal/api/v1/ip-block"):
        # Bearer 인증 API는 브라우저 세션 쿠키를 신뢰하지 않아 CSRF 검사가 필요 없다.
        return
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
        log_event("csrf_fail", "BLOCK", "csrf_token_invalid")
        abort(403)


# ---- 첨부 업로드의 본문 상한 ----
# 첨부를 받는 요청만 상한을 푼다(설정 UPLOAD_MAX_BYTES, 비어 있으면 제한 없음). 나머지 요청은 MAX_CONTENT_LENGTH(2MB)가 그대로 적용된다.
# 폼의 글자 칸 크기(500KB)와 한 요청의 폼 항목 수(1000)는 프레임워크 기본 보호를 유지한다.
UPLOAD_ENDPOINTS = ("portal.post_new", "approvals.approval_new", "approvals.approval_decide", "library.file_upload", "library.form_upload", "messenger_api.send_file")
# 첨부와 달리 상한이 따로 있는 요청: 본문을 메모리로 다 읽기 전에 413 으로 끊는다.
ENDPOINT_LIMITS = {"messenger_api.upload_profile_photo": 10 * 1024 * 1024 + 64 * 1024,   # 사진 10MB + multipart 머리
                   "profile.photo_upload": 10 * 1024 * 1024 + 64 * 1024,                 # 웹 프로필 사진도 같은 10MB
                   "chat.chat_send": 10 * 1024 * 1024 + 64 * 1024}                       # AI 어시스턴트 첨부 10MB(chat_attach.MAX_BYTES)


NO_LIMIT = 1 << 62  # Flask 는 max_content_length=None 을 "설정 파일의 값을 쓴다"로 해석하므로, 제한 없음은 사실상 무한대 값으로 표현한다


def apply_upload_limit():
    if request.endpoint in UPLOAD_ENDPOINTS:
        request.max_content_length = current_app.config["UPLOAD_MAX_BYTES"] or NO_LIMIT
    elif request.endpoint in ENDPOINT_LIMITS:
        request.max_content_length = ENDPOINT_LIMITS[request.endpoint]


# ---- 응답 헤더 ----
def add_headers(resp):
    # 첨부 미리보기 경로(portal.attachment_view)처럼 더 엄격한 CSP 를 직접 정한 응답은 그대로 둔다.
    resp.headers.setdefault("Content-Security-Policy", (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ))
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Server"] = "NEXUS"  # 개발 서버의 Werkzeug·Python 버전 노출을 막는다
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


# ---- IP 단위 분당 제한 (단일 프로세스 메모리) ----
# ponytail: 프로세스 로컬. 다중 워커·재시작 간 공유가 필요하면 Redis/DB 로 교체.
_hits = defaultdict(deque)


def ip_rate_limited(key: str, limit: int, window: int = 60) -> bool:
    now = time.monotonic()
    q = _hits[key]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def reset_rate_limits():
    _hits.clear()
