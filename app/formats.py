"""표시용 변환 도우미."""

_DIGITS = "영일이삼사오육칠팔구"
_SMALL = ("", "십", "백", "천")
_BIG = ("", "만", "억", "조", "경")


def won_hangul(n: int) -> str:
    """금액을 한글 숫자로 쓴다(공문서·지출결의서의 "일금 ○○원정" 표기). 위·변조를 막으려고 1도 "일십"·"일백"처럼 숫자를 모두 적는다.
    예: 3,800,000 → 삼백팔십만 / 10 → 일십 / 100,000,000 → 일억 / 0 → 영."""
    n = int(n)
    if n < 0:
        raise ValueError("negative")
    if n == 0:
        return "영"
    groups = []
    while n:
        groups.append(n % 10000)
        n //= 10000
    if len(groups) > len(_BIG):
        raise ValueError("too_large")
    out = []
    for i in range(len(groups) - 1, -1, -1):
        g = groups[i]
        if not g:
            continue
        s = "".join(_DIGITS[(g // 10 ** pos) % 10] + _SMALL[pos] for pos in (3, 2, 1, 0) if (g // 10 ** pos) % 10)
        out.append(s + _BIG[i])
    return "".join(out)
