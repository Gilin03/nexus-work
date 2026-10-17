"""업로드 검증: 확장자 허용목록 + 실제 내용(매직바이트) 일치 확인."""
import hashlib
import re
import uuid
from pathlib import Path

ALLOWED = {
    "pdf": ("application/pdf", lambda d: d.startswith(b"%PDF-")),
    "png": ("image/png", lambda d: d.startswith(b"\x89PNG\r\n\x1a\n")),
    "jpg": ("image/jpeg", lambda d: d.startswith(b"\xff\xd8\xff")),
    "txt": ("text/plain", lambda d: _is_text(d)),
}
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._가-힣 -]")


def _is_text(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def inspect_upload(filename: str, data: bytes):
    """통과하면 (확장자, mime, 표시용 이름, sha256) 반환. 실패하면 ValueError(reason)."""
    if not filename or not data:
        raise ValueError("empty_upload")
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    # 이중 확장자(a.php.png)와 숨김/제어 문자 거부: 점은 확장자 앞에 한 번만 허용
    stem, dot, ext = base.rpartition(".")
    if not dot or not stem or "." in stem or ext.lower() not in ALLOWED:
        raise ValueError("extension_not_allowed")
    ext = ext.lower()
    mime, matches = ALLOWED[ext]
    if not matches(data):
        raise ValueError("content_mismatch")
    display = SAFE_NAME_RE.sub("_", base)[:120]
    return ext, mime, display, hashlib.sha256(data).hexdigest()


def store(upload_dir: Path, data: bytes) -> str:
    """예측 불가능한 이름으로 웹루트 밖에 저장하고 저장명(확장자 없음)을 반환."""
    upload_dir.mkdir(parents=True, exist_ok=True)
    name = str(uuid.uuid4())
    (upload_dir / name).write_bytes(data)
    return name
