"""실습용 내부 API(기획서 4.1 4~5단계) 및 SOAR/n8n 자동화 연동 API.
1. 플래그 확인: 기밀 문서(M&A_PLAN)에서 얻은 토큰으로 호출하면 FLAG 를 돌려준다.
2. IP 차단 관리: n8n/SOAR 등 외부 보안 자동화 워크플로우가 DB 포트(3307)를 직접 열지 않고도
   HTTP API(Bearer 토큰 인증)를 통해 악성 IP 차단/해제/목록 조회를 수행할 수 있도록 지원한다.

- 토큰 비교는 상수 시간(hmac.compare_digest)을 사용하며, 원문 대신 10자리 지문(token_fp)만 로그에 남긴다.
- 토큰은 LAB_INTERNAL_API_TOKEN, N8N_API_TOKEN, SOAR_API_TOKEN 환경변수를 검증한다.
- 동일 IP의 과도한 호출 방지를 위해 분당 RATE_LIMIT(30회) 제한을 둔다."""
import hashlib
import hmac
import ipaddress
import json
import os
import re

from flask import Blueprint, current_app, jsonify, request

from . import security
from .security import get_client_ip, ip_rate_limited, log_event

bp = Blueprint("internal_api", __name__, url_prefix="/internal/api/v1")

RATE_LIMIT = 30
AUTO_BLOCK_REASONS = {
    "R5": "account_spray",
    "R6": "post_lock_retry",
    "R8": "web_path_scan",
}
AUTO_BLOCK_WHITELIST = security.PROTECTED_BLOCK_IPS


def token_fingerprint(token: str) -> str:
    """토큰을 로그에 그대로 남기지 않고, 같은 토큰인지 알아볼 수 있는 짧은 지문만 남긴다."""
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()[:10] if token else "-"


def _extract_token(req) -> str:
    """Authorization 헤더(Bearer), X-API-Token 헤더, 또는 쿼리 파라미터(?token=)에서 토큰을 추출한다."""
    header = req.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    x_token = req.headers.get("X-API-Token", "").strip()
    if x_token:
        return x_token
    query_token = req.args.get("token", "").strip()
    if query_token:
        return query_token
    return ""


def _verify_token(token: str) -> bool:
    """LAB_INTERNAL_API_TOKEN, N8N_API_TOKEN, SOAR_API_TOKEN 중 하나와 일치하는지 검증한다."""
    if not token:
        return False
    candidates = [
        t for t in [
            os.environ.get("LAB_INTERNAL_API_TOKEN", ""),
            os.environ.get("N8N_API_TOKEN", ""),
            os.environ.get("SOAR_API_TOKEN", ""),
        ] if t
    ]
    if not candidates:
        return False
    token_bytes = str(token).encode("utf-8")
    return any(hmac.compare_digest(token_bytes, c.encode("utf-8")) for c in candidates)


def _is_valid_target_ip(ip_str: str) -> tuple[bool, str]:
    """차단 대상 IP 주소 유효성 검사 (루프백, 브로드캐스트 등 보호)."""
    if not ip_str or not isinstance(ip_str, str):
        return False, "IP 주소가 누락되었습니다."
    clean_ip = ip_str.strip()
    try:
        addr = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False, f"유효하지 않은 IP 주소 형식입니다: '{clean_ip}'"

    if addr.is_loopback or clean_ip in ("127.0.0.1", "::1"):
        return False, "루프백 주소(127.0.0.1, ::1 등)는 차단할 수 없습니다."
    if addr.is_multicast or addr.is_unspecified:
        return False, "유효하지 않은 대상 IP 주소입니다."

    return True, clean_ip


def internal_api(path, token, via, conversation_id=0):
    """내부 API 의 본체. (허용 여부, 응답 글자)를 돌려준다. 포털의 HTTP 경로(via=direct)와 AI 게이트웨이(via=gateway)가 같은 검사를 쓴다."""
    valid = _verify_token(token)
    clean_path = str(path or "")[:100]
    log_event("internal_api", "ALLOW" if valid else "DENY", "ok" if valid else "bad_token", via=via,
              token_fp=token_fingerprint(token), api_path=clean_path, conversation_id=conversation_id)
    if not valid:
        return False, "토큰이 올바르지 않습니다."
    if clean_path != "/flag":
        return True, "지원하지 않는 경로입니다."
    flag = os.environ.get("LAB_INTERNAL_API_FLAG", "")
    return True, flag if flag else "FLAG 가 설정되지 않았습니다(.env 의 LAB_INTERNAL_API_FLAG)."


@bp.get("/flag")
def flag():
    if ip_rate_limited(f"internal_api:{get_client_ip()}", RATE_LIMIT):
        log_event("rate_limited", "BLOCK", "internal_api_limit", via="direct")
        return jsonify(ok=False, error="rate_limited"), 429
    token = _extract_token(request)
    ok, text = internal_api("/flag", token, "direct")
    if not ok:
        return jsonify(ok=False, error="unauthorized"), 401
    return jsonify(ok=True, flag=text)


@bp.get("/blocked-ips")
def list_blocked_ips():
    """현재 활성화된 차단 IP 목록 조회 (n8n/SOAR 및 보안 관제용)."""
    if ip_rate_limited(f"internal_api:{get_client_ip()}", RATE_LIMIT):
        log_event("rate_limited", "BLOCK", "internal_api_limit", via="direct")
        return jsonify(ok=False, error="rate_limited", message="요청 한도를 초과했습니다."), 429

    token = _extract_token(request)
    if not _verify_token(token):
        log_event("internal_api", "DENY", "bad_token", via="direct",
                  token_fp=token_fingerprint(token), api_path="/blocked-ips")
        return jsonify(ok=False, error="unauthorized", message="유효하지 않은 인증 토큰입니다."), 401

    try:
        from . import db
        rows = db.query_all(
            "SELECT id, ip_address, reason, blocked_until, created_at, created_by "
            "FROM blocked_ips WHERE blocked_until > NOW() ORDER BY blocked_until DESC LIMIT 200"
        )
        rows = [r for r in rows if not security.is_protected_block_ip(r.get("ip_address"))]
        formatted = []
        for r in rows:
            b_until = r.get("blocked_until")
            c_at = r.get("created_at")
            formatted.append({
                "id": r.get("id"),
                "ip_address": r.get("ip_address"),
                "reason": r.get("reason"),
                "blocked_until": b_until.isoformat() if hasattr(b_until, "isoformat") else str(b_until),
                "created_at": c_at.isoformat() if hasattr(c_at, "isoformat") else str(c_at),
                "created_by": r.get("created_by")
            })
        if request.args.get("format") == "txt" or request.headers.get("Accept") == "text/plain":
            from flask import Response
            plain_text = "\n".join(str(r.get("ip_address")) for r in rows if r.get("ip_address"))
            return Response(plain_text + ("\n" if plain_text else ""), mimetype="text/plain; charset=utf-8")

        return jsonify(ok=True, count=len(formatted), items=formatted)
    except Exception as exc:
        return jsonify(ok=False, error="db_error", message=str(exc)), 500


@bp.post("/blocked-ips")
def create_blocked_ip():
    """악성 IP 차단 등록 API (n8n/SOAR 자동화 연동)."""
    if ip_rate_limited(f"internal_api:{get_client_ip()}", RATE_LIMIT):
        log_event("rate_limited", "BLOCK", "internal_api_limit", via="direct")
        return jsonify(ok=False, error="rate_limited", message="요청 한도를 초과했습니다."), 429

    token = _extract_token(request)
    if not _verify_token(token):
        log_event("internal_api", "DENY", "bad_token", via="direct",
                  token_fp=token_fingerprint(token), api_path="/blocked-ips")
        return jsonify(ok=False, error="unauthorized", message="유효하지 않은 인증 토큰입니다."), 401

    payload = request.get_json(silent=True) or {}
    raw_ip = payload.get("ip") or payload.get("ip_address") or request.form.get("ip") or request.form.get("ip_address", "")

    valid, result_or_err = _is_valid_target_ip(raw_ip)
    if not valid:
        return jsonify(ok=False, error="invalid_ip", message=result_or_err), 400

    ip = result_or_err
    if security.is_protected_block_ip(ip):
        return jsonify(ok=False, error="ip_whitelisted", message="관리·서버 주소는 차단할 수 없습니다."), 403

    reason = str(payload.get("reason") or request.form.get("reason", "n8n_soar_block")).strip()[:100]
    raw_minutes = payload.get("minutes") if "minutes" in payload else request.form.get("minutes", 30)
    try:
        minutes = int(raw_minutes)
        if minutes <= 0 or minutes > 525600:
            minutes = 30
    except (ValueError, TypeError):
        minutes = 30

    created_by = str(payload.get("created_by") or request.form.get("created_by", "n8n_soar")).strip()[:50]

    success = security.block_ip(ip, reason=reason, minutes=minutes, created_by=created_by)
    if not success:
        return jsonify(ok=False, error="block_failed", message="IP 차단 처리에 실패했습니다."), 500

    log_event("ip_block_api", "BLOCK", reason, via="direct",
              blocked_ip=ip, minutes=minutes, created_by=created_by,
              token_fp=token_fingerprint(token))

    return jsonify(
        ok=True,
        message=f"IP {ip} 차단이 등록되었습니다 ({minutes}분간 유효).",
        ip=ip,
        reason=reason,
        minutes=minutes,
        created_by=created_by
    ), 200


def _handle_unblock(raw_ip: str, token: str):
    valid, result_or_err = _is_valid_target_ip(raw_ip)
    if not valid:
        return jsonify(ok=False, error="invalid_ip", message=result_or_err), 400

    ip = result_or_err
    from . import security
    success = security.unblock_ip(ip)
    if not success:
        return jsonify(ok=False, error="unblock_failed", message="IP 차단 해제 처리에 실패했습니다."), 500

    log_event("ip_unblock_api", "ALLOW", "unblocked", via="direct",
              unblocked_ip=ip, token_fp=token_fingerprint(token))

    return jsonify(ok=True, message=f"IP {ip} 차단이 해제되었습니다.", ip=ip), 200


@bp.post("/blocked-ips/unblock")
def unblock_blocked_ip_post():
    """차단 IP 해제 API (POST 요청 바디의 ip 지정)."""
    if ip_rate_limited(f"internal_api:{get_client_ip()}", RATE_LIMIT):
        log_event("rate_limited", "BLOCK", "internal_api_limit", via="direct")
        return jsonify(ok=False, error="rate_limited", message="요청 한도를 초과했습니다."), 429

    token = _extract_token(request)
    if not _verify_token(token):
        log_event("internal_api", "DENY", "bad_token", via="direct",
                  token_fp=token_fingerprint(token), api_path="/blocked-ips/unblock")
        return jsonify(ok=False, error="unauthorized", message="유효하지 않은 인증 토큰입니다."), 401

    payload = request.get_json(silent=True) or {}
    raw_ip = payload.get("ip") or payload.get("ip_address") or request.form.get("ip") or request.form.get("ip_address", "")
    return _handle_unblock(raw_ip, token)


@bp.delete("/blocked-ips/<path:ip>")
def unblock_blocked_ip_delete(ip):
    """차단 IP 해제 API (DELETE RESTful 경로)."""
    if ip_rate_limited(f"internal_api:{get_client_ip()}", RATE_LIMIT):
        log_event("rate_limited", "BLOCK", "internal_api_limit", via="direct")
        return jsonify(ok=False, error="rate_limited"), 429

    token = _extract_token(request)
    if not _verify_token(token):
        log_event("internal_api", "DENY", "bad_token", via="direct",
                  token_fp=token_fingerprint(token), api_path=f"/blocked-ips/{ip}")
        return jsonify(ok=False, error="unauthorized", message="유효하지 않은 인증 토큰입니다."), 401

    return _handle_unblock(ip, token)


@bp.post("/ip-block")
def automated_ip_block():
    """NEXUS R5/R6/R8용 내부 차단 경로. 검증 후 기존 block_ip만 호출한다."""
    client_ip = get_client_ip()
    if ip_rate_limited(f"internal_api:{client_ip}", RATE_LIMIT):
        log_event("rate_limited", "BLOCK", "internal_api_limit", via="direct")
        return jsonify(ok=False, error="rate_limited"), 429

    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    authorized, _ = internal_api("/ip-block", token, "direct")
    if not authorized:
        return jsonify(ok=False, error="unauthorized"), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"ip_address", "rule_id", "reason", "duration_minutes"}:
        return jsonify(ok=False, error="invalid_request"), 400

    rule_id = data.get("rule_id")
    reason = data.get("reason")
    duration = data.get("duration_minutes")
    if rule_id not in AUTO_BLOCK_REASONS or reason != AUTO_BLOCK_REASONS.get(rule_id):
        return jsonify(ok=False, error="unsupported_rule_or_reason"), 400
    if isinstance(duration, bool) or not isinstance(duration, int) or not 1 <= duration <= 15:
        return jsonify(ok=False, error="invalid_duration"), 400

    raw_ip = data.get("ip_address")
    try:
        parsed_ip = ipaddress.ip_address(raw_ip)
        mapped_ip = getattr(parsed_ip, "ipv4_mapped", None)
        if mapped_ip:
            parsed_ip = mapped_ip
        ip = parsed_ip.compressed
    except (ValueError, TypeError):
        return jsonify(ok=False, error="invalid_ip"), 400
    if parsed_ip.is_unspecified or parsed_ip.is_multicast:
        return jsonify(ok=False, error="invalid_ip"), 400
    if security.is_protected_block_ip(ip):
        security.log_event("ip_block_automation", "DENY", "ip_whitelisted", action=rule_id, resource=ip)
        return jsonify(ok=False, error="ip_whitelisted"), 403

    block_reason = f"n8n_{rule_id}_{reason}"
    if not security.block_ip(ip, reason=block_reason, minutes=duration, created_by="n8n"):
        security.log_event("ip_block_automation", "ERROR", "block_ip_failed", action=rule_id, resource=ip)
        return jsonify(ok=False, error="block_failed"), 503

    security.log_event("ip_block_automation", "BLOCK", block_reason, action=rule_id, resource=ip)
    return jsonify(ok=True, blocked=True, ip_address=ip, rule_id=rule_id, duration_minutes=duration)


def _authorize_xdr(path):
    if ip_rate_limited(f"internal_api:{get_client_ip()}", RATE_LIMIT):
        log_event("rate_limited", "BLOCK", "internal_api_limit", via="direct")
        return jsonify(ok=False, error="rate_limited"), 429
    token = _extract_token(request)
    authorized, _ = internal_api(path, token, "direct")
    if not authorized:
        return jsonify(ok=False, error="unauthorized"), 401
    if not current_app.config.get("XDR_ENABLED", False):
        return jsonify(ok=False, error="xdr_disabled"), 503
    return None


@bp.post("/ai-xdr/events")
def ingest_ai_xdr_event():
    denied = _authorize_xdr("/ai-xdr/events")
    if denied:
        return denied
    from . import ai_xdr
    try:
        result = ai_xdr.ingest_event(request.get_json(silent=True))
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 422
    except Exception as exc:  # do not return database/provider details to the caller.
        log_event("xdr_event_intake", "ERROR", type(exc).__name__)
        return jsonify(ok=False, error="intake_failed"), 503
    return jsonify(ok=True, **result), 202


@bp.post("/ai-xdr/process")
def process_ai_xdr_windows():
    denied = _authorize_xdr("/ai-xdr/process")
    if denied:
        return denied
    from . import ai_xdr
    try:
        result = ai_xdr.process_ready_windows()
    except Exception as exc:  # keeps service diagnostics private; no raw event data is returned.
        log_event("xdr_processing", "ERROR", type(exc).__name__)
        return jsonify(ok=False, error="processing_failed"), 503
    return jsonify(ok=True, **result)


@bp.post("/ai-xdr/decision")
def decide_ai_xdr_approval():
    denied = _authorize_xdr("/ai-xdr/decision")
    if denied:
        return denied
    if current_app.config.get("XDR_AUTO_ENABLED", False) or \
            str(current_app.config.get("XDR_RESPONSE_MODE", "dry-run")).lower() != "dry-run":
        return jsonify(ok=False, error="dry_run_only"), 409

    data = request.get_json(silent=True)
    assessment_id = str((data or {}).get("assessment_id", "")).strip()
    approval_ref = str((data or {}).get("approval_ref", "")).strip()
    if not isinstance(data, dict) or data.get("status") != "APPROVED" or \
            not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", assessment_id, re.I) or \
            not re.fullmatch(re.escape(assessment_id) + r":NX-DB-\d{6,18}", approval_ref, re.I):
        return jsonify(ok=False, error="invalid_request"), 400

    from . import ai_xdr, db
    row = db.query_one(
        "SELECT assessment_id, rule_ids, status, approval_allowed, auto_allowed, policy_reason, verdict, "
        "threat_score, confidence, response_result FROM security_xdr_assessments WHERE assessment_id = %s",
        (assessment_id,),
    )
    if not row:
        return jsonify(ok=False, error="assessment_not_found"), 404
    try:
        rule_ids = row.get("rule_ids") if isinstance(row.get("rule_ids"), list) else json.loads(row.get("rule_ids") or "[]")
    except (TypeError, ValueError):
        rule_ids = []
    if rule_ids != ["R1"] or row.get("approval_allowed") not in (True, 1, "1") or \
            row.get("auto_allowed") not in (False, 0, "0") or \
            row.get("policy_reason") not in {
                "DAYTIME_APPROVAL", "WEEKEND_APPROVAL",
                "daytime_requires_approval", "weekend_requires_approval",
            } or \
            row.get("verdict") != "MALICIOUS" or ai_xdr._policy_threshold_error(row, current_app.config):
        return jsonify(ok=False, error="approval_not_allowed"), 409
    if row.get("status") == "APPROVED":
        previous = row.get("response_result")
        if isinstance(previous, str):
            try:
                previous = json.loads(previous)
            except ValueError:
                previous = {}
        if isinstance(previous, dict) and previous.get("approval_ref") == approval_ref:
            return jsonify(ok=True, assessment_id=assessment_id, status="APPROVED",
                           approval_ref=approval_ref, response=previous, idempotent=True)
        return jsonify(ok=False, error="assessment_not_pending"), 409
    if row.get("status") != "PENDING":
        return jsonify(ok=False, error="assessment_not_pending"), 409
    try:
        result = ai_xdr.decide_assessment(assessment_id, "APPROVED", None, "n8n_approve_response",
                                          approval_ref=approval_ref)
    except LookupError:
        return jsonify(ok=False, error="assessment_not_found"), 404
    except RuntimeError:
        return jsonify(ok=False, error="assessment_not_pending"), 409
    except Exception as exc:  # do not return database/provider details to the caller.
        log_event("xdr_assessment_decision", "ERROR", type(exc).__name__, assessment_id=assessment_id)
        return jsonify(ok=False, error="decision_failed"), 503
    return jsonify(ok=True, **result)
