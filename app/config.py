import math
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
        self.GRAYLOG_GELF_ENABLED = os.environ.get("GRAYLOG_GELF_ENABLED", "0") == "1"
        self.GRAYLOG_GELF_HOST = os.environ.get("GRAYLOG_GELF_HOST", "127.0.0.1")
        self.GRAYLOG_GELF_PORT = int(os.environ.get("GRAYLOG_GELF_PORT", "12201"))
        # 메신저 자동 업데이트로 내줄 설치 파일(같은 폴더에 서명 파일 <이름>.sig 가 있어야 내준다). 기본은 저장소 옆(바탕화면)
        self.MESSENGER_SETUP_PATH = Path(os.environ.get("MESSENGER_SETUP_PATH", BASE_DIR.parent / "NEXUS_Messenger_Setup.exe"))

        # 신뢰할 수 있는 프록시 (pfSense, 루프백) - X-Forwarded-For 허용 대상
        trusted_raw = os.environ.get("TRUSTED_PROXIES", "127.0.0.1,192.168.3.10")
        self.TRUSTED_PROXIES = {ip.strip() for ip in trusted_raw.split(",") if ip.strip()}

        # 로그인 방어
        self.LOGIN_MAX_FAILURES = 5
        self.LOGIN_LOCK_MINUTES = 15
        self.LOGIN_IP_LIMIT = 20  # 분당 POST /login 상한(IP)

        # 챗봇: 사용자당 분당 메시지 상한 및 무료 AI 모델 연동 설정
        self.CHAT_USER_LIMIT = 20
        self.AI_PROVIDER = os.environ.get("AI_PROVIDER", "auto").strip().lower()
        self.AI_TIMEOUT = int(os.environ.get("AI_TIMEOUT", "60") or 60)
        self.OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip()
        self.OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b").strip()
        self.GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
        self.GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash").strip()
        self.GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
        self.GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b").strip()

        # AI-XDR is opt-in and starts in dry-run. An unset/invalid confidence keeps auto response closed.
        self.XDR_ENABLED = os.environ.get("XDR_ENABLED", "1") == "1"
        self.XDR_AUTO_ENABLED = os.environ.get("XDR_AUTO_ENABLED", "0") == "1"
        self.XDR_RESPONSE_MODE = os.environ.get("XDR_RESPONSE_MODE", "dry-run").strip().lower()
        self.XDR_IP_BLOCK_ENABLED = os.environ.get("XDR_IP_BLOCK_ENABLED", "0") == "1"
        self.XDR_AI_PROVIDER = os.environ.get("XDR_AI_PROVIDER", "auto").strip().lower()
        self.XDR_AI_TIMEOUT = self._int_setting("XDR_AI_TIMEOUT", 30)
        self.XDR_TRIAGE_WINDOW_SECONDS = self._int_setting("XDR_TRIAGE_WINDOW_SECONDS", 180)
        self.XDR_MAX_EVENT_AGE_SECONDS = self._int_setting("XDR_MAX_EVENT_AGE_SECONDS", 300)
        self.XDR_AUTO_MIN_SCORE = self._int_setting("XDR_AUTO_MIN_SCORE", 80)
        self.XDR_DAY_START_HOUR = self._int_setting("XDR_DAY_START_HOUR", 8)
        self.XDR_DAY_END_HOUR = self._int_setting("XDR_DAY_END_HOUR", 20)
        weekend_mode = os.environ.get("XDR_WEEKEND_MODE", "approval").strip().lower()
        self.XDR_WEEKEND_MODE = weekend_mode if weekend_mode in {"approval", "night_auto"} else "invalid"
        try:
            confidence = float(os.environ.get("XDR_AUTO_MIN_CONFIDENCE", "").strip())
            self.XDR_AUTO_MIN_CONFIDENCE = confidence if math.isfinite(confidence) and 0 <= confidence <= 1 else None
        except (TypeError, ValueError):
            self.XDR_AUTO_MIN_CONFIDENCE = None

    @staticmethod
    def _int_setting(name, default):
        try:
            return int(os.environ.get(name, str(default)).strip())
        except (TypeError, ValueError):
            return None

    def as_flask(self):
        return {k: v for k, v in vars(self).items() if k.isupper()}
