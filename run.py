"""개발·시연용 실행: python run.py [--host 127.0.0.1] [--port 5070]

`flask run` 의 개발 서버는 앱과 별개로 `Server: Werkzeug/x Python/y` 헤더를 붙여 버전이 노출된다.
이 실행 파일은 헤더를 `Server: NEXUS` 하나로 내보낸다. 기본 주소는 내 PC(루프백)뿐이다.
운영에는 gunicorn·waitress 같은 WSGI 서버를 쓰고, 앱이 설정한 `Server` 헤더가 그대로 나가는지 확인한다."""
import argparse

from werkzeug.serving import WSGIRequestHandler, run_simple

from app import create_app


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5070)
    args = ap.parse_args()
    run_simple(args.host, args.port, create_app(), threaded=True, request_handler=QuietHandler,
               use_reloader=False, use_debugger=False)


if __name__ == "__main__":
    main()
