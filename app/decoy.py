"""허니팟 / 디셉션 (Decoy Canary) 모듈.

공격자 및 자동화된 보안 스캐너(Nikto, DirBuster, sqlmap 등)가 침투 시도 시 흔히 찌르는
비인가 경로(예: /.env, /.git/config, /admin/backup.sql, /phpmyadmin 등)를 미끼로 배치합니다.
해당 경로로의 접근이 감지되면 즉시 침해 시도로 판단하여 Graylog SIEM 및 Wazuh로 보안 이벤트를 기록하고,
해당 출발지 IP를 blocked_ips 테이블에 등록하여 실시간으로 접근을 전면 차단합니다.
공격자가 허니팟임을 눈치채지 못하도록 응답은 일반 404 Not Found 로 반환합니다.
"""
from flask import Blueprint, abort, request

from .security import block_ip, get_client_ip, log_event

bp = Blueprint("decoy", __name__)

DECOY_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/backup/backup.sql",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/phpmyadmin",
    "/phpmyadmin/index.php",
    "/pma",
    "/wp-login.php",
    "/xmlrpc.php",
    "/actuator/env",
    "/actuator/health",
    "/api/v1/debug",
]


def _handle_decoy():
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")[:120]
    log_event(
        "decoy_triggered",
        "BLOCK",
        "scanner_decoy_path",
        path=request.path,
        src_ip=ip,
        method=request.method,
        user_agent=ua,
    )
    # 루프백이 아닌 실제 외부 의심 IP는 60분간 즉시 차단
    if ip and ip not in ("127.0.0.1", "::1", "localhost", "-"):
        block_ip(ip, reason=f"decoy_probe:{request.path[:40]}", minutes=60, created_by="honeypot")
    abort(404)


# 각 허니팟 경로를 동적으로 라우트에 등록
for p in DECOY_PATHS:
    bp.add_url_rule(p, endpoint=f"decoy_{p.replace('/', '_').replace('.', '_')}", view_func=_handle_decoy, methods=["GET", "POST", "HEAD"])
