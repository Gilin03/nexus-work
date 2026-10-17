"""입력 검증 허용목록. 검증 실패는 ValueError 로 알린다."""
import re

USERNAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,31}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def username(value: str) -> str:
    if not isinstance(value, str) or not USERNAME_RE.fullmatch(value):
        raise ValueError("invalid_username")
    return value


def password_policy(pw: str, uname: str = "") -> str:
    if not isinstance(pw, str) or not (12 <= len(pw) <= 128):
        raise ValueError("password_length")
    if uname and uname.lower() in pw.lower():
        raise ValueError("password_contains_username")
    if sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]")) < 3:
        raise ValueError("password_complexity")
    return pw


def text(value: str, field: str, min_len: int = 1, max_len: int = 200, multiline: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field}_type")
    value = value.strip()
    if not (min_len <= len(value) <= max_len):
        raise ValueError(f"{field}_length")
    if CONTROL_RE.search(value) or (not multiline and any(ch in value for ch in "\n\r\t")):
        raise ValueError(f"{field}_chars")
    return value


def positive_int(value, field: str = "id", max_value: int = 2**31 - 1) -> int:
    if isinstance(value, bool) or (isinstance(value, str) and not (value.isascii() and value.isdigit())):
        raise ValueError(f"{field}_int")  # True, "٣"(비ASCII 숫자), "-1", " 1" 등 거부
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field}_int")
    if not (0 < n <= max_value):
        raise ValueError(f"{field}_range")
    return n


def like_pattern(term: str) -> str:
    """LIKE 와일드카드를 이스케이프해 리터럴 검색으로만 쓰이게 한다."""
    term = text(term, "query", 1, 50)
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
