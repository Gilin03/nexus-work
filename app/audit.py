"""감사 로그 읽기: logs/security.jsonl(과 회전된 .1~.3)에서 보안 이벤트를 최신순으로 읽어 필터링한다. 읽기 전용이다.
- 오래된 로그까지 전부 올리지 않도록 읽는 양에 상한을 둔다(파일 끝에서부터 MAX_BYTES). 깨진 줄은 건너뛴다.
- 값은 화면에서 Jinja 가 이스케이프한다. 비밀번호·토큰·대화 원문은 애초에 기록되지 않는다(security.log_event 설계).
- 필터 값은 허용 형식만 받는다(호출하는 쪽에서 검증하고, 여기서는 일치 비교만 한다)."""
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

KST = timezone(timedelta(hours=9))
MAX_BYTES = 4_000_000
STANDARD = ("ts", "event_type", "user", "role", "src_ip", "method", "path", "decision", "reason")
DECISIONS = ("INFO", "ALLOW", "WARN", "DENY", "BLOCK")


def _lines_newest_first(log_dir: Path):
    budget = MAX_BYTES
    for name in ("security.jsonl", "security.jsonl.1", "security.jsonl.2", "security.jsonl.3"):
        path = Path(log_dir) / name
        if budget <= 0 or not path.is_file():
            continue
        with open(path, "rb") as f:
            size = path.stat().st_size
            start = max(0, size - budget)
            f.seek(start)
            data = f.read()
        budget -= len(data)
        lines = data.decode("utf-8", errors="replace").splitlines()
        if start > 0 and lines:
            lines = lines[1:]                       # 잘린 첫 줄은 버린다
        yield from reversed(lines)


def read_events(log_dir, limit=200, event_type="", decision="", user="", ip=""):
    """(이벤트 목록(최신순, 최대 limit), 훑어본 전체 이벤트의 유형별 개수, 훑어본 이벤트 수)."""
    out, kinds, scanned = [], Counter(), 0
    for line in _lines_newest_first(log_dir):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict):
            continue
        scanned += 1
        kinds[str(e.get("event_type", "-"))] += 1
        if event_type and e.get("event_type") != event_type:
            continue
        if decision and e.get("decision") != decision:
            continue
        if user and e.get("user") != user:
            continue
        if ip and e.get("src_ip") != ip:
            continue
        if len(out) < limit:
            out.append(_shape(e))
    return out, kinds, scanned


def _shape(e):
    """화면용으로 정리한다: 시각은 한국 시간, 표준 필드 밖의 값은 '키=값'으로 합친다."""
    ts = str(e.get("ts", ""))
    try:
        shown = datetime.fromisoformat(ts).astimezone(KST).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        shown = ts[:19]
    extra = " ".join(f"{k}={str(v)[:80]}" for k, v in e.items() if k not in STANDARD)
    row = {k: str(e.get(k, "-"))[:200] for k in STANDARD if k != "ts"}
    row["time"], row["extra"], row["raw_ts"] = shown, extra[:300], ts
    return row


def recent_counts(log_dir, hours=24, top=8):
    """최근 hours 시간의 이벤트 유형별 개수 상위 top 개(관리 현황용)."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    counts = Counter()
    for line in _lines_newest_first(log_dir):
        try:
            e = json.loads(line)
            when = datetime.fromisoformat(str(e.get("ts", "")))
        except (ValueError, AttributeError):
            continue
        if when < since:
            break                                    # 최신순이라 이 시각 이전은 더 볼 필요 없다
        counts[str(e.get("event_type", "-"))] += 1
    return counts.most_common(top)
