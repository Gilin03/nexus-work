"""Conservative direct prompt-injection patterns for the chat input boundary."""
import re
import unicodedata


_OVERRIDE_KO = re.compile(
    r"^\s*(?:이전|앞선|기존|위|모든)\s*(?:(?:시스템|개발자)\s*)?(?:지시|명령)(?:\s*사항)?"
    r"(?:을|를)?\s*(?:(?:모두|전부)\s*)?(?:무시(?:하고|해(?:요|줘|라)?|해도)|"
    r"잊어(?:버리고|버려|버리세요)|따르지\s*마(?:세요|라|고)?)(?![가-힣])"
)
_OVERRIDE_EN = re.compile(
    r"^\s*(?:(?:please|you must|from now on)\s+)?(?:ignore|disregard|forget|override)\s+"
    r"(?:(?:all|the)\s+)*(?:previous|prior|above|system|developer)\s+instructions?\b",
    re.IGNORECASE,
)

_REVEAL_KO = re.compile(
    r"^\s*(?:(?:(?:숨겨진|비공개)\s*(?:(?:시스템|개발자)\s*)?|(?:시스템|개발자)\s*)프롬프트|"
    r"(?:숨겨진|비공개)\s*(?:시스템|개발자)\s*지시문)"
    r"(?:을|를)?\s*(?:그대로\s*)?(?:공개해(?:줘|요|라|주세요)?|노출해(?:줘|요|라|주세요)?|"
    r"출력해(?:줘|요|라|주세요)?|보여\s*줘|보여주세요|알려\s*줘|알려주세요|"
    r"말해\s*줘|말해주세요|인쇄해(?:줘|요|라|주세요)?)(?![가-힣])"
)
_REVEAL_EN = re.compile(
    r"^\s*(?:(?:please|can you|could you)\s+)?(?:reveal|show|print|output|disclose|quote|dump|expose)\s+"
    r"(?:me\s+)?(?:the\s+)?(?:(?:hidden|secret|system|developer)\s+)*(?:system\s+|developer\s+)?prompt\b",
    re.IGNORECASE,
)

_POLICY_BYPASS_KO = re.compile(
    r"^\s*(?:보안\s*정책|접근\s*통제|권한\s*검사|보호\s*규칙|안전\s*정책)(?:을|를)?\s*"
    r"(?:우회해서|우회하고|우회한\s*뒤|우회해(?:줘|라|주세요)?|"
    r"무시하고|무시해(?:줘|라|주세요)?|해제하고|해제해(?:줘|라|주세요)?)(?![가-힣])"
)
_PROTECTED_REQUEST_KO = re.compile(
    r"(?:기밀|비밀|관리자)\s*(?:문서|데이터|자료|정보|파일|기록|계정|DB)?[^.!?。！？\n]{0,24}?"
    r"(?:읽어와|가져와|열람해(?:줘|라|주세요)?|출력해(?:줘|라|주세요)?|공개해(?:줘|라|주세요)?|"
    r"보여\s*줘|알려\s*줘|다운로드해(?:줘|라|주세요)?|조회해(?:줘|라|주세요)?)(?![가-힣])"
)
_POLICY_BYPASS_EN = re.compile(
    r"^\s*(?:(?:please|you must)\s+)?(?:bypass|circumvent|disable|override|ignore)\s+(?:the\s+)?"
    r"(?:security|access|authorization|safety)\s+(?:policy|controls?|checks?|rules?)\b",
    re.IGNORECASE,
)
_PROTECTED_REQUEST_EN = re.compile(
    r"\b(?:read|retrieve|access|fetch|export|reveal|show|dump|download|list)\s+(?:all\s+)?(?:the\s+)?"
    r"(?:confidential|restricted|secret|admin|administrator)\s+"
    r"(?:documents?|data|records?|files?|accounts?|database)\b",
    re.IGNORECASE,
)


def detect_direct_prompt_injection(message: str) -> str | None:
    """Return a stable pattern ID only for direct imperative override/disclosure requests."""
    normalized = unicodedata.normalize("NFKC", message).casefold()
    sentences = re.split(r"[.!?。！？\n]+", normalized)

    for sentence in sentences:
        if _OVERRIDE_KO.search(sentence) or _OVERRIDE_EN.search(sentence):
            return "ignore_previous_instructions"
        if _REVEAL_KO.search(sentence) or _REVEAL_EN.search(sentence):
            return "reveal_hidden_prompt"
        if ((_POLICY_BYPASS_KO.search(sentence) and _PROTECTED_REQUEST_KO.search(sentence))
                or (_POLICY_BYPASS_EN.search(sentence) and _PROTECTED_REQUEST_EN.search(sentence))):
            return "policy_bypass_protected_data"
    return None
