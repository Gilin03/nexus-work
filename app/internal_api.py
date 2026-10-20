"""실습용 내부 API(기획서 4.1 4~5단계). 기밀 문서(M&A_PLAN)에서 얻은 토큰으로 호출하면 FLAG 를 돌려준다.
이시헌의 ai-agent 브랜치(9db742a)의 internal_api.py·ai_gateway.internal_api 를 main 으로 옮긴 것이다(AI 에이전트 부분은 아직 옮기지 않음).

- 이 HTTP 경로로 직접 오는 호출은 via=direct 로 남는다. 탐지 규칙 R4(출발지가 포털 서버(게이트웨이)가 아닌 호출)가 이것을 본다.
  나중에 AI 게이트웨이가 대신 부르는 호출은 같은 internal_api() 를 via=gateway 로 쓴다.
- 직접 호출을 막지는 않는다(토큰이 맞으면 FLAG 를 준다). 공방전 시나리오의 목표 지점이고, 막는 대신 탐지·대응(n8n)으로 다룬다.
- 로그에는 토큰 원문 대신 지문(token_fp)과 출발지 IP, 경로만 남긴다. 토큰 비교는 상수 시간.
- 토큰(LAB_INTERNAL_API_TOKEN)과 FLAG(LAB_INTERNAL_API_FLAG)는 .env 에서만 읽고 코드·문서에 쓰지 않는다.
- 같은 IP 의 호출은 분당 30번으로 제한한다(토큰 추측·로그 폭주 방지)."""
import hashlib
import hmac
import os

from flask import Blueprint, jsonify, request

from .security import ip_rate_limited, log_event

bp = Blueprint("internal_api", __name__, url_prefix="/internal/api/v1")

RATE_LIMIT = 30


def token_fingerprint(token):
    """토큰을 로그에 그대로 남기지 않고, 같은 토큰인지 알아볼 수 있는 짧은 지문만 남긴다."""
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()[:10] if token else "-"


def internal_api(path, token, via, conversation_id=0):
    """내부 API 의 본체. (허용 여부, 응답 글자)를 돌려준다. 포털의 HTTP 경로(via=direct)와 AI 게이트웨이(via=gateway)가 같은 검사를 쓴다."""
    expected = os.environ.get("LAB_INTERNAL_API_TOKEN", "")
    valid = bool(expected) and hmac.compare_digest(str(token or "").encode(), expected.encode())
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
    if ip_rate_limited(f"internal_api:{request.remote_addr}", RATE_LIMIT):
        log_event("rate_limited", "BLOCK", "internal_api_limit", via="direct")
        return jsonify(ok=False, error="rate_limited"), 429
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    ok, text = internal_api("/flag", token, "direct")
    if not ok:
        return jsonify(ok=False, error="unauthorized"), 401
    return jsonify(ok=True, flag=text)
