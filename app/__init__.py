from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from . import admin, approvals, auth, chat, db, erp, formats, hr, messenger_api, portal, profile, realtime, security
from .config import Config

ERROR_TEXT = {
    400: "요청을 처리할 수 없습니다.",
    403: "접근 권한이 없습니다.",
    404: "페이지를 찾을 수 없습니다.",
    405: "허용되지 않는 요청입니다.",
    409: "요청을 처리할 수 없는 상태입니다.",
    413: "업로드 용량이 너무 큽니다.",
    429: "요청이 너무 많습니다. 잠시 후 다시 시도하세요.",
}


STATUS_LABEL = {"draft": "임시저장", "submitted": "결재 중", "pending": "결재 대기",
                "approved": "승인", "rejected": "반려", "withdrawn": "철회", "waiting": "순서 대기",
                "skipped": "건너뜀"}


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.from_mapping(Config().as_flask())
    app.config.update(overrides or {})
    app.config["DEBUG"] = False  # 디버거·상세 오류 화면 노출 금지

    security.init_logging(app.config["LOG_DIR"])

    app.register_blueprint(auth.bp)
    app.register_blueprint(portal.bp)
    app.register_blueprint(erp.bp)
    app.register_blueprint(approvals.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(chat.bp)
    app.register_blueprint(profile.bp)
    app.register_blueprint(hr.bp)
    app.register_blueprint(messenger_api.bp)  # 메신저(nexus-messenger) 토큰 인증 JSON API, /api/v1/*
    realtime.init_app(app)  # 메신저 실시간 전송(Socket.IO)
    app.config.setdefault("CHAT_RESPONDER", chat.placeholder_responder)  # 실제 AI 연결은 다른 담당이 이 값을 교체한다
    app.jinja_env.filters["won"] = lambda n: f"{int(n):,}원"
    app.jinja_env.filters["hangul_won"] = formats.won_hangul
    app.jinja_env.filters["status_label"] = lambda s: STATUS_LABEL.get(s, s)
    app.before_request(security.apply_upload_limit)  # 본문을 읽기 전에(CSRF 검사가 폼을 읽는다) 첨부 요청의 상한을 푼다
    app.before_request(auth.load_user)  # CSRF 실패 로그에도 사용자명이 남도록 먼저 실행(세션 쿠키가 있을 때만 DB 조회)
    app.before_request(security.scan_inputs)  # CSRF 로 막히는 요청의 의심 입력도 기록되도록 먼저 실행
    app.before_request(security.check_csrf)
    app.after_request(db.finish_request)
    app.after_request(security.add_headers)
    app.teardown_request(db.close_dbs)
    app.jinja_env.globals["csrf_token"] = security.csrf_token

    @app.context_processor
    def inject_pending_approvals():
        """메뉴·홈의 결재 대기 배지. 로그인하지 않았거나 조회에 실패해도 화면이 깨지지 않게 0으로 둔다."""
        user = getattr(g, "user", None)
        if not user:
            return {}
        try:
            return {"pending_approvals": approvals.pending_count(user["id"])}
        except Exception:  # noqa: BLE001
            return {"pending_approvals": 0}

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.errorhandler(HTTPException)
    def http_error(exc):
        code = exc.code or 500
        if code == 404:
            security.log_event("not_found", "INFO", "no_such_path")
        elif code in (413, 429):
            security.log_event("request_rejected", "BLOCK", f"http_{code}")
        return render_template("error.html", code=code, message=ERROR_TEXT.get(code, "오류가 발생했습니다.")), code

    @app.errorhandler(Exception)
    def unexpected_error(exc):
        # 스택트레이스는 사용자에게 보여주지 않고, 예외 종류만 기록한다.
        app.logger.exception("unhandled error")
        security.log_event("server_error", "ERROR", type(exc).__name__)
        return render_template("error.html", code=500, message="일시적인 오류가 발생했습니다."), 500

    return app
