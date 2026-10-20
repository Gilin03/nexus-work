"""AI 어시스턴트 첨부 파일: 올린 파일에서 글자만 뽑아 그 질문에만 참고 자료로 붙인다(김태빈 요청, 2026-10-20).

- 파일은 저장하지 않는다(메모리에서 글자만 뽑고 버린다). 대화 기록에는 "[첨부 파일: 이름, N자]" 표시만 남는다.
- 형식: txt·md·csv·json·log(UTF-8 또는 CP949), PDF(pypdf, 앞 MAX_PDF_PAGES 쪽, 암호 걸린 파일 거부), DOCX(압축 안 word/document.xml 의 글자).
- 크기: 파일 MAX_BYTES(본문 상한은 security.ENDPOINT_LIMITS), 뽑은 글자 MAX_CHARS 까지. 압축 폭탄 대비로 DOCX 의 풀린 크기도 제한한다.
- 뽑은 글자는 ai._build_messages 의 <사내자료> 경계 안에 들어가 '지시가 아닌 자료'로 다뤄진다(파일에 심은 프롬프트 인젝션 대비).
  클라우드 모델로 보낼 때는 내부 토큰을 지운다(ai.ai_responder).
- 실패하면 ValueError(사유 코드)를 던지고, 화면 문구는 MESSAGES 에 있다."""
import io
import zipfile
from xml.etree import ElementTree

from . import uploads, validators

MAX_BYTES = 10 * 1024 * 1024
MAX_CHARS = 12000
MAX_PDF_PAGES = 40
MAX_DOCX_XML = 30 * 1024 * 1024
TEXT_EXTS = {"txt", "md", "csv", "json", "log"}
ALLOWED_EXTS = TEXT_EXTS | {"pdf", "docx"}
ACCEPT = ",".join("." + e for e in sorted(ALLOWED_EXTS))
W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

MESSAGES = {
    "extension_not_allowed": "첨부는 " + "·".join(sorted(ALLOWED_EXTS)) + " 파일만 읽을 수 있습니다.",
    "too_large": f"첨부 파일은 {MAX_BYTES // (1024 * 1024)}MB 이하만 읽을 수 있습니다.",
    "encoding": "글자 인코딩을 알 수 없는 텍스트 파일입니다(UTF-8 또는 CP949 로 저장해 주세요).",
    "binary": "텍스트 파일이 아닌 것 같습니다.",
    "content_mismatch": "파일 내용이 확장자와 맞지 않습니다.",
    "encrypted": "암호가 걸린 PDF 는 읽을 수 없습니다.",
    "unreadable": "파일을 읽지 못했습니다(손상되었거나 지원하지 않는 형식).",
    "no_text": "파일에서 글자를 찾지 못했습니다(스캔한 그림 PDF 는 읽을 수 없습니다).",
}


def extract(filename: str, data: bytes) -> dict:
    """{"name", "ext", "text", "truncated"} 를 돌려준다. 실패하면 ValueError(사유 코드)."""
    name = uploads.clean_name(filename)
    ext = name.rpartition(".")[2].lower() if "." in name else ""
    if ext not in ALLOWED_EXTS:
        raise ValueError("extension_not_allowed")
    if len(data) > MAX_BYTES:
        raise ValueError("too_large")
    if ext in TEXT_EXTS:
        text = _text(data)
    elif ext == "pdf":
        text = _pdf(data)
    else:
        text = _docx(data)
    text = validators.CONTROL_RE.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    text = text.strip()
    if not text:
        raise ValueError("no_text")
    truncated = len(text) > MAX_CHARS
    return {"name": name, "ext": ext, "text": text[:MAX_CHARS], "truncated": truncated, "chars": min(len(text), MAX_CHARS)}


def _text(data: bytes) -> str:
    if b"\x00" in data[:8192]:
        raise ValueError("binary")
    for enc in ("utf-8-sig", "cp949"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    raise ValueError("encoding")


def _pdf(data: bytes) -> str:
    if not data.startswith(b"%PDF-"):
        raise ValueError("content_mismatch")
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            raise ValueError("encrypted")
        parts = []
        for page in reader.pages[:MAX_PDF_PAGES]:
            parts.append(page.extract_text() or "")
            if sum(len(p) for p in parts) > MAX_CHARS:
                break
        return "\n\n".join(parts)
    except ValueError:
        raise
    except (PdfReadError, OSError, KeyError, TypeError, AttributeError, RecursionError):
        raise ValueError("unreadable")


def _docx(data: bytes) -> str:
    if not data.startswith(b"PK"):
        raise ValueError("content_mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            info = zf.getinfo("word/document.xml")
            if info.file_size > MAX_DOCX_XML:                       # 압축 폭탄: 풀린 크기를 먼저 본다
                raise ValueError("too_large")
            with zf.open(info) as f:
                xml = f.read(MAX_DOCX_XML + 1)
        if len(xml) > MAX_DOCX_XML or b"<!DOCTYPE" in xml[:2048] or b"<!ENTITY" in xml:
            raise ValueError("unreadable")                          # 정상 DOCX 에는 DTD·엔티티가 없다
        paragraphs, current = [], []
        for event, el in ElementTree.iterparse(io.BytesIO(xml), events=("end",)):
            if el.tag == W_NS + "t" and el.text:
                current.append(el.text)
            elif el.tag == W_NS + "tab":
                current.append("\t")
            elif el.tag in (W_NS + "br", W_NS + "cr"):
                current.append("\n")
            elif el.tag == W_NS + "p":
                paragraphs.append("".join(current))
                current = []
                el.clear()
        return "\n".join(paragraphs)
    except ValueError:
        raise
    except (KeyError, zipfile.BadZipFile, ElementTree.ParseError, OSError, RuntimeError, NotImplementedError):
        raise ValueError("unreadable")
