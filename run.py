"""NEXUS WORK 서버 구동 스크립트.

기본적으로 Windows 프로덕션 멀티스레드 WSGI 서버인 Waitress로 구동되어
Slowloris 및 DoS 공격 저항성을 확보하고 안정적인 다중 요청 병렬 처리를 제공합니다.
개발 및 디버깅 시에는 `--dev` 플래그를 주어 기존 Werkzeug 개발 서버로 실행할 수 있습니다.

실행:
  python run.py                     # 프로덕션 WSGI 모드 (기본값, Waitress)
  python run.py --dev               # 개발 서버 모드 (Werkzeug)
  python run.py --host 0.0.0.0      # 외부 접속 허용 (pfSense 경유 5070)
  python run.py --port 5070         # 포트 지정
"""
import argparse
import os
import sys
from pathlib import Path

from dotenv import dotenv_values
from werkzeug.serving import WSGIRequestHandler

from app import create_app
from app.realtime import socketio

BASE_DIR = Path(__file__).resolve().parent
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
SEED_PASSWORD_KEYS = ("SEED_KIM_PW", "SEED_LEE_PW", "SEED_ADMIN_PW")


class QuietHandler(WSGIRequestHandler):
    """서버 이름·버전 대신 NEXUS 만 알린다(개발 모드 전용)."""
    server_version = "NEXUS"
    sys_version = ""

    def version_string(self):
        return "NEXUS"

    def send_response(self, code, message=None):
        self._server_header_sent = False
        super().send_response(code, message)

    def send_header(self, keyword, value):
        if keyword.lower() == "server":
            if getattr(self, "_server_header_sent", False):
                return
            self._server_header_sent = True
        super().send_header(keyword, value)


class SafeSocketIOMiddleware:
    """Waitress 등 순수 WSGI 서버 환경에서 raw socket이 없을 때
    500 에러 대신 400 Bad Request를 반환하여 Socket.IO 클라이언트가
    표준 HTTP Long-Polling 실시간 모드로 매끄럽게 전환(Fallback)되도록 보호하는 미들웨어.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        qs = environ.get("QUERY_STRING", "")
        if path.startswith("/socket.io/") and "transport=websocket" in qs:
            if "werkzeug.socket" not in environ:
                start_response("400 Bad Request", [("Content-Type", "text/plain"), ("Content-Length", "11")])
                return [b"Bad Request"]
        return self.wsgi_app(environ, start_response)


def parse_args(argv=None, environ=os.environ):
    ap = argparse.ArgumentParser(description="NEXUS WORK 서버 구동기")
    ap.add_argument("--host", default=environ.get("APP_HOST", "127.0.0.1"), help="바인딩 호스트 (기본: .env APP_HOST 또는 127.0.0.1)")
    ap.add_argument("--port", type=int, default=int(environ.get("APP_PORT", "5070")), help="바인딩 포트 (기본: 5070)")
    ap.add_argument("--threads", type=int, default=8, help="프로덕션 WSGI 작업 스레드 수 (기본: 8)")
    ap.add_argument("--dev", action="store_true", help="Werkzeug 개발 서버로 구동 (미지정 시 Waitress 프로덕션 구동)")
    ap.add_argument("--prod", action="store_true", help="명시적 프로덕션 모드 강제")
    return ap.parse_args(argv)


def exposure_warnings(host, environ=os.environ, example=None):
    """루프백이 아닌 주소로 열 때, 시드 비밀번호가 저장소에 공개된 예시 값과 같으면 알려 준다."""
    if host in LOOPBACK:
        return []
    example = dotenv_values(BASE_DIR / ".env.example") if example is None else example
    return [
        f"{k} 가 .env.example 의 예시 값 그대로다. 외부에 열기 전에 .env 에서 바꾸고 seed.py --reset 으로 다시 넣을 것"
        for k in SEED_PASSWORD_KEYS
        if environ.get(k) and environ.get(k) == example.get(k)
    ]


def main():
    args = parse_args()
    for warning in exposure_warnings(args.host):
        print(f"[경고] {warning}")

    app = create_app()

    if args.dev:
        print(f"[*] NEXUS WORK 개발 서버 구동 (Werkzeug, http://{args.host}:{args.port})")
        print("[!] 주의: 개발 서버는 디버깅용이며 실제 운영/평가 시에는 --dev 없이 프로덕션 모드로 구동하세요.")
        socketio.run(
            app,
            host=args.host,
            port=args.port,
            use_reloader=False,
            debug=False,
            request_handler=QuietHandler,
            allow_unsafe_werkzeug=True,
        )
    else:
        try:
            import waitress
        except ImportError:
            print("[오류] waitress 패키지가 설치되지 않았습니다. 'pip install waitress'를 실행하세요.")
            sys.exit(1)

        print(f"==========================================================")
        print(f" [NEXUS WORK] 프로덕션 WSGI 서버 가동")
        print(f" - 엔진: Waitress (Multi-Threaded Production WSGI)")
        print(f" - 주소: http://{args.host}:{args.port}")
        print(f" - 작업자 스레드 풀: {args.threads}개 병렬 처리")
        print(f" - 실시간 관제: Graylog(UDP 12201), Wazuh Agent(security.jsonl)")
        print(f" - 방화벽 연계: pfSense WAF (192.168.3.10) 경유 보호")
        print(f"==========================================================")

        # 소켓 통신 보호 미들웨어 적용 후 서빙
        served_app = SafeSocketIOMiddleware(app.wsgi_app)

        waitress.serve(
            served_app,
            host=args.host,
            port=args.port,
            threads=args.threads,
            channel_timeout=120,
            cleanup_interval=30,
            _quiet=False,
        )


if __name__ == "__main__":
    main()
