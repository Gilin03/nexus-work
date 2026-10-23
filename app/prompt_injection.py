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

# 완화된 우회 표현 탐지 (기획서 4.2 / 6.3 10/23 이슈 반영: 완곡한 질문형·유도형 시스템 프롬프트/지침 탈취 시도 탐지)
_MITIGATED_REVEAL_KO = re.compile(
    r"(?:네가|너의|현재|너가|자신이)?\s*(?:따르(?:는|고\s*있는)|준수하(?:는|고\s*있는)|받은|부여된|설정된|기본|내부)?\s*"
    r"(?:시스템\s*프롬프트|프롬프트|지침|가이드라인|규칙|지시(?:문|사항)?)\s*(?:을|를|이|은|는)?\s*"
    r"(?:그대로\s*)?(?:말해\s*(?:줘|봐|줄래|주세요|주시겠습니까)?|"
    r"보여\s*(?:줘|봐|줄래|주세요|줄\s*수\s*있어(?:요)?|주시겠습니까)?|"
    r"알려\s*(?:줘|봐|줄래|주세요|줄\s*수\s*있어(?:요)?|주시겠습니까)?|"
    r"출력해\s*(?:줘|봐|줄래|주세요)?|공개해\s*(?:줘|봐|줄래|주세요)?|"
    r"설명해\s*(?:줘|봐|줄래|주세요)?)(?![가-힣])"
)
_MITIGATED_REVEAL_EN = re.compile(
    r"(?:(?:can|could|would)\s+you\s+)?(?:tell|show|explain|share|print|reveal)\s+(?:me\s+)?"
    r"(?:the\s+|your\s+)?(?:system\s+|hidden\s+|operating\s+|core\s+)?(?:prompt|instructions?|guidelines?|rules?)\b",
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
        if (_REVEAL_KO.search(sentence) or _REVEAL_EN.search(sentence)
                or _MITIGATED_REVEAL_KO.search(sentence) or _MITIGATED_REVEAL_EN.search(sentence)):
            return "reveal_hidden_prompt"
        if ((_POLICY_BYPASS_KO.search(sentence) and _PROTECTED_REQUEST_KO.search(sentence))
                or (_POLICY_BYPASS_EN.search(sentence) and _PROTECTED_REQUEST_EN.search(sentence))):
            return "policy_bypass_protected_data"
    return None


# ---- 간접 프롬프트 주입 (Indirect Prompt Injection) 방어 ----
_INDIRECT_INJECTION_PATTERN = re.compile(
    r"(?i)(?:\[(?:AI|시스템|관리자|System|Developer)\s*(?:어시스턴트\s*)?(?:전용\s*)?(?:지시|명령|Prompt|Instruction)?[^\]]*\]|"
    r"(?:이전|앞선|기존|위|모든)\s*(?:(?:시스템|개발자)\s*)?(?:지시|명령|프롬프트)(?:\s*사항)?(?:을|를)?\s*(?:모두|전부)?\s*(?:무시|잊어|따르지\s*마)|"
    r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|"
    r"(?:내부\s*API|internal\s*api).*?(?:호출|token|nxapi_)|"
    r"(?:기밀|비밀|admin)\s*(?:문서|비밀번호|토큰|내용).*?(?:출력|알려|보여|공개))"
)


def sanitize_untrusted_context(text: str, source: str = "context") -> tuple[str, bool, str | None]:
    """사내 자료(게시글, 문서 등) 내 간접 프롬프트 주입(Indirect Prompt Injection) 시도를 탐지하고 무해화."""
    if not text:
        return text, False, None

    normalized = unicodedata.normalize("NFKC", text)
    if _INDIRECT_INJECTION_PATTERN.search(normalized):
        sanitized = _INDIRECT_INJECTION_PATTERN.sub("[보안 필터: 비인가 시스템 지시문 마스킹됨]", normalized)
        return sanitized, True, "indirect_prompt_injection"
    return text, False, None
