import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Config:
    """환경변수에서만 비밀을 읽는다. 약한 SECRET_KEY 면 기동하지 않는다."""

    def __init__(self):
        self.SECRET_KEY = os.environ.get("SECRET_KEY", "")
        if len(self.SECRET_KEY) < 32 or self.SECRET_KEY.startswith("change-me"):
            raise RuntimeError("SECRET_KEY 는 32자 이상의 임의 값이어야 한다 (.env 확인)")

        self.DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
        self.DB_PORT = int(os.environ.get("DB_PORT", "3307"))
        self.DB_NAME = os.environ.get("DB_NAME", "nexus")
        self.DB_APP_USER = "nexus_app"
        self.DB_APP_PASSWORD = os.environ.get("NEXUS_APP_PASSWORD", "")
        self.DB_CONF_USER = "nexus_conf"
        self.DB_CONF_PASSWORD = os.environ.get("NEXUS_CONF_PASSWORD", "")

        # 세션 쿠키
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Lax"
        self.SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"
        self.SESSION_COOKIE_NAME = "nexus_session"
        self.PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # 마지막 요청 후 30분 유휴 만료
        self.SESSION_ABSOLUTE_SECONDS = 8 * 3600  # 로그인 후 8시간이 지나면 활동 중이어도 만료

        # 업로드: 웹루트 밖 instance/uploads, 2MB 상한
        self.MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 첨부가 없는 모든 요청(프로필 사진 포함)의 본문 상한
        # 게시판·결재 첨부 요청은 용량 제한이 없다(security.apply_upload_limit). 필요하면 .env 의 MAX_UPLOAD_BYTES 로 다시 건다.
        self.UPLOAD_MAX_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", "0") or 0) or None
        self.UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", BASE_DIR / "instance" / "uploads"))
        self.LOG_DIR = Path(os.environ.get("LOG_DIR", BASE_DIR / "logs"))

        # 로그인 방어
        self.LOGIN_MAX_FAILURES = 5
        self.LOGIN_LOCK_MINUTES = 15
        self.LOGIN_IP_LIMIT = 20  # 분당 POST /login 상한(IP)

        # 챗봇: 사용자당 분당 메시지 상한
        self.CHAT_USER_LIMIT = 20

    def as_flask(self):
        return {k: v for k, v in vars(self).items() if k.isupper()}
