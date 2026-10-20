"""개발·시연용 실행: python run.py [--host 주소] [--port 번호]

`flask run` 의 개발 서버는 앱과 별개로 `Server: Werkzeug/x Python/y` 헤더를 붙여 버전이 노출된다.
이 실행 파일은 헤더를 `Server: NEXUS` 하나로 내보낸다.
주소·포트의 기본값은 .env 의 APP_HOST(없으면 127.0.0.1 — 내 PC만)·APP_PORT(없으면 5070)이고, 명령줄 값이 우선한다.
다른 장비(네트워크 담당 장비·Kali)에서 접속하게 하려면 APP_HOST=0.0.0.0 으로 둔다. 이때 시드 비밀번호가
공개된 예시 값(.env.example) 그대로면 기동할 때 경고한다.
메신저(nexus-messenger) 실시간 전송(Socket.IO)도 같은 포트에서 돌므로 run_simple 대신
socketio.run() 으로 띄운다(내부적으로 같은 werkzeug 개발 서버 + 이 QuietHandler 를 그대로 쓴다).
운영에는 gunicorn·waitress 같은 WSGI 서버를 쓰고, 앱이 설정한 `Server` 헤더가 그대로 나가는지 확인한다."""
import argparse
import os
from pathlib import Path

from dotenv import dotenv_values
from werkzeug.serving import WSGIRequestHandler

from app import create_app  # app.config 가 import 될 때 .env 를 os.environ 으로 읽어 들인다
from app.realtime import socketio

BASE_DIR = Path(__file__).resolve().parent
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
SEED_PASSWORD_KEYS = ("SEED_KIM_PW", "SEED_LEE_PW", "SEED_ADMIN_PW")


class QuietHandler(WSGIRequestHandler):
    """서버 이름·버전 대신 NEXUS 만 알린다(앱이 넣은 Server 헤더와 겹치지 않게 한 번만)."""
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


def parse_args(argv=None, environ=os.environ):
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=environ.get("APP_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(environ.get("APP_PORT", "5070")))
    return ap.parse_args(argv)


def exposure_warnings(host, environ=os.environ, example=None):
    """루프백이 아닌 주소로 열 때, 시드 비밀번호가 저장소에 공개된 예시 값과 같으면 알려 준다(기동은 막지 않는다)."""
    if host in LOOPBACK:
        return []
    example = dotenv_values(BASE_DIR / ".env.example") if example is None else example
    return [f"{k} 가 .env.example 의 예시 값 그대로다. 외부에 열기 전에 .env 에서 바꾸고 seed.py --reset 으로 다시 넣을 것"
            for k in SEED_PASSWORD_KEYS if environ.get(k) and environ.get(k) == example.get(k)]


def main():
    args = parse_args()
    for warning in exposure_warnings(args.host):
        print(f"[주의] {warning}")
    app = create_app()
    # allow_unsafe_werkzeug: 이미 개발 서버임을 README/문서에 명시했고(운영에는 WSGI 서버 사용),
    # 대화형 터미널이 아닌 곳(nohup 등)에서 띄울 때 라이브러리가 거부하지 않도록 한다.
    socketio.run(app, host=args.host, port=args.port, use_reloader=False, debug=False,
                request_handler=QuietHandler, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
