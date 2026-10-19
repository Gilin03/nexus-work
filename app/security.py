"""보안 공통: JSON 이벤트 로그, CSRF, 응답 헤더, IP 단위 요청 제한."""
import hmac
import json
import logging
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from flask import abort, current_app, g, request, session

_logger = logging.getLogger("nexus.security")
_logger.propagate = False


def init_logging(log_dir):
    """호출할 때마다 핸들러를 교체해 현재 설정의 로그 경로만 쓰게 한다."""
    log_dir.mkdir(parents=True, exist_ok=True)
    for h in list(_logger.handlers):
        _logger.removeHandler(h)
        h.close()
    handler = RotatingFileHandler(log_dir / "security.jsonl", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)


def log_event(event_type: str, decision: str = "INFO", reason: str = "", **extra):
    """모든 이벤트가 같은 필드 구조를 가진다. 비밀번호·토큰은 기록하지 않는다.
    값은 json.dumps 로 직렬화되므로 개행·따옴표를 넣어 로그 줄을 위조할 수 없다."""
    user = getattr(g, "user", None) or {}
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event_type": event_type,
        "user": user.get("username") or extra.pop("user", "-"),
        "role": user.get("role", "-"),
        "src_ip": request.remote_addr or "-",
        "method": request.method,
        "path": request.path[:200],
        "decision": decision,
        "reason": reason,
    }
    extra.pop("user", None)
    for k, v in extra.items():
        record[k] = v if isinstance(v, (int, float, bool)) else str(v)[:200]
    _logger.info(json.dumps(record, ensure_ascii=False))


# ---- 의심 입력 기록(차단하지 않는다) ----
# 파라미터 바인딩·이스케이프로 이미 안전하게 처리되지만, 그 시도 자체는 탐지(C)가 쓸 신호다.
SUSPICIOUS = [
    ("sqli", re.compile(r"(?i)(\bunion\b\s+(all\s+)?select\b|\bor\b\s*\(?\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\bsleep\s*\(|\bbenchmark\s*\("
                        r"|\bwaitfor\s+delay\b|;\s*(drop|delete|insert|update|alter)\b|--\s*$|'\s*(or|and)\s+')")),
    ("xss", re.compile(r"(?i)(<\s*script|<\s*img[^>]*\bon\w+\s*=|<\s*svg[^>]*\bon\w+|<\s*iframe|javascript\s*:|\bon(error|load|click)\s*=)")),
    ("traversal", re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e(%2f|/|%5c)|%252e)")),
]
SKIP_FIELDS = {"password", "current_password", "new_password", "confirm_password", "csrf_token"}  # 비밀번호는 보지도 기록하지도 않는다
NO_VALUE_FIELDS = {"message", "body", "reason"}  # 대화·본문 내용은 로그에 남기지 않고 종류만 남긴다


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
    if request.path.startswith("/api/v1/"):
        # 메신저(nexus-messenger)용 토큰 인증 API. 쿠키를 전혀 쓰지 않으므로(Authorization 헤더만
        # 신뢰) 브라우저가 자동으로 실어 보내는 쿠키를 노리는 CSRF가 애초에 성립하지 않는다.
        return
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
        log_event("csrf_fail", "BLOCK", "csrf_token_invalid")
        abort(403)


# ---- 첨부 업로드의 본문 상한 ----
# 첨부를 받는 요청만 상한을 푼다(설정 UPLOAD_MAX_BYTES, 비어 있으면 제한 없음). 나머지 요청은 MAX_CONTENT_LENGTH(2MB)가 그대로 적용된다.
# 폼의 글자 칸 크기(500KB)와 한 요청의 폼 항목 수(1000)는 프레임워크 기본 보호를 유지한다.
UPLOAD_ENDPOINTS = ("portal.post_new", "approvals.approval_new", "approvals.approval_decide")


NO_LIMIT = 1 << 62  # Flask 는 max_content_length=None 을 "설정 파일의 값을 쓴다"로 해석하므로, 제한 없음은 사실상 무한대 값으로 표현한다


def apply_upload_limit():
    if request.endpoint in UPLOAD_ENDPOINTS:
        request.max_content_length = current_app.config["UPLOAD_MAX_BYTES"] or NO_LIMIT


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
