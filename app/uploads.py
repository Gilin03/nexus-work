"""업로드 처리.
- 프로필 사진: inspect_upload — 확장자 허용목록(png·jpg) + 실제 내용(매직바이트) 일치를 확인하고 아니면 거부한다.
- 게시판·결재 첨부: save_attachment — **형식·개수·용량을 제한하지 않는다.** 대신 어떤 파일이든 무해하게 다룬다:
  서버가 만든 무작위 이름으로 웹루트 밖에 저장(원본 이름은 DB 의 표시용 문자열일 뿐 경로에 쓰이지 않음), 조각 단위로 디스크에 직접 써서
  큰 파일이 메모리를 차지하지 않게 하고, 형식은 거부하지 않고 분류만 한다(그림·PDF 는 내용이 맞을 때만 그 형식, 나머지는 일반 바이너리).
  내려줄 때는 항상 첨부(다운로드)로, nosniff 와 함께 내려서 브라우저가 열어 실행하지 않는다(미리보기는 분류된 그림·PDF 만)."""
import hashlib
import re
import uuid
from pathlib import Path

from flask import abort, send_from_directory

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


# ---------------- 첨부: 제한 없이 받기 ----------------
CHUNK = 1024 * 1024
GENERIC_MIME = "application/octet-stream"
# 그림·PDF 는 내용(매직바이트)이 확장자와 맞을 때만 그 형식으로 분류한다. 미리보기(인라인 표시)는 이렇게 분류된 형식만 한다.
SNIFF = {
    "pdf": ("application/pdf", lambda h: h.startswith(b"%PDF-")),
    "png": ("image/png", lambda h: h.startswith(b"\x89PNG\r\n\x1a\n")),
    "jpg": ("image/jpeg", lambda h: h.startswith(b"\xff\xd8\xff")),
    "jpeg": ("image/jpeg", lambda h: h.startswith(b"\xff\xd8\xff")),
}


def clean_name(filename: str) -> str:
    """표시용 파일 이름: 경로 부분을 버리고 안전한 문자만 남긴다(제어문자·따옴표·꺾쇠 등은 밑줄). 점으로 시작하는 숨김 이름은 막는다.
    이 값은 DB 에 표시용으로만 저장되고 저장 경로에는 쓰이지 않는다."""
    base = (filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    base = SAFE_NAME_RE.sub("_", base).strip().lstrip(".")
    if not base:
        return "첨부파일"
    if len(base) > 120:
        stem, dot, ext = base.rpartition(".")
        ext = ext[:20] if dot else ""
        base = (stem[:119 - len(ext)] + "." + ext) if ext else base[:120]
    return base


def classify(name: str, head: bytes) -> str:
    """형식을 거부하지 않고 분류만 한다. 그림·PDF 는 내용이 맞을 때만 해당 형식, txt 는 text/plain, 나머지는 일반 바이너리."""
    ext = name.rpartition(".")[2].lower() if "." in name else ""
    if ext in SNIFF and SNIFF[ext][1](head):
        return SNIFF[ext][0]
    if ext == "txt":
        return "text/plain"
    return GENERIC_MIME


def save_attachment(upload_dir: Path, storage) -> dict:
    """업로드된 파일(FileStorage)을 조각 단위로 무작위 이름 파일에 쓰고 DB 에 넣을 정보를 돌려준다. 실패하면 쓰다 만 파일을 지우고 예외를 다시 던진다."""
    upload_dir.mkdir(parents=True, exist_ok=True)
    stored = str(uuid.uuid4())
    path = upload_dir / stored
    digest, size, head = hashlib.sha256(), 0, b""
    try:
        with open(path, "wb") as out:
            while True:
                chunk = storage.stream.read(CHUNK)
                if not chunk:
                    break
                if not head:
                    head = chunk[:16]
                digest.update(chunk)
                size += len(chunk)
                out.write(chunk)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    name = clean_name(storage.filename)
    return {"stored_name": stored, "orig_name": name, "mime": classify(name, head), "size": size, "sha256": digest.hexdigest()}


def remove_saved(upload_dir: Path, saved) -> None:
    """요청이 도중에 실패했을 때 이미 저장한 파일을 지운다."""
    for meta in saved:
        (Path(upload_dir) / meta["stored_name"]).unlink(missing_ok=True)


def send_stored(directory, stored_name, **kwargs):
    """저장된 파일을 내려준다. 파일이 사라졌거나 운영체제가 열지 못하게 하면(백신 격리·권한 오류 등) 서버 오류(500)가 아니라 404 로 답하고 기록한다.
    형식을 제한하지 않으므로 서버의 백신이 올라온 파일을 격리하는 일이 실제로 생길 수 있다."""
    from .security import log_event
    try:
        return send_from_directory(directory, stored_name, **kwargs)
    except OSError as exc:  # 없는 파일(NotFound)은 werkzeug 가 별도로 처리한다. 여기는 열 수 없는 경우뿐이다.
        log_event("attachment_unreadable", "WARN", type(exc).__name__, errno=exc.errno)
        abort(404)
