"""감사 로그 읽기: logs/security.jsonl(과 회전된 .1~.3)에서 보안 이벤트를 최신순으로 읽어 필터링한다. 읽기 전용이다.
- 오래된 로그까지 전부 올리지 않도록 읽는 양에 상한을 둔다(파일 끝에서부터 MAX_BYTES). 깨진 줄은 건너뛴다.
- 값은 화면에서 Jinja 가 이스케이프한다. 비밀번호·토큰·대화 원문은 애초에 기록되지 않는다(security.log_event 설계).
- 필터 값은 허용 형식만 받는다(호출하는 쪽에서 검증하고, 여기서는 일치 비교만 한다)."""
import json
import queue
import threading
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
    t_score = e.get("threat_score") if "threat_score" in e else e.get("ai_score")
    verdict = e.get("verdict") if "verdict" in e else e.get("ai_verdict")
    if t_score is not None:
        try:
            row["threat_score"] = int(t_score)
        except (ValueError, TypeError):
            row["threat_score"] = str(t_score)
    if verdict:
        row["verdict"] = str(verdict)
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


# =====================================================================================
# 보안 대시보드: 기간별 요약·추이·상위 목록·필터링된 이벤트(표·CSV 내보내기)를 한 번 훑어서 만든다.
# =====================================================================================
PERIODS = (("24h", 24, "최근 24시간"), ("7d", 168, "최근 7일"), ("30d", 720, "최근 30일"))
PAGE_SIZES = (50, 100, 200)
MAX_MATCH = 2000                         # 필터에 맞는 이벤트는 최신순으로 이만큼까지만 모은다(표·내보내기 공통 상한)
# 위협 지표: 이벤트 유형 → 화면 이름. 값이 클수록 공격·오용 가능성이 높은 신호다.
THREAT_TYPES = (("login_failure", "로그인 실패"), ("login_locked", "잠긴 계정으로 로그인 시도"), ("account_locked", "계정 잠금 발생"),
                ("rate_limited", "속도 제한 차단"), ("csrf_fail", "CSRF 차단"), ("suspicious_input", "의심 입력(SQLi·XSS 등)"),
                ("upload_reject", "업로드 거부"), ("authz_deny", "권한 거부"))
LOGIN_FAIL_TYPES = ("login_failure", "login_locked")
BAD_DECISIONS = ("DENY", "BLOCK", "WARN", "ERROR")
CLASS_OF = {"INFO": "ok", "ALLOW": "ok", "WARN": "warn", "ERROR": "warn", "DENY": "deny", "BLOCK": "block"}
SERIES = (("ok", "정상(INFO·ALLOW)"), ("warn", "경고(WARN·ERROR)"), ("deny", "거부(DENY)"), ("block", "차단(BLOCK)"))
CHART_W, CHART_H, CHART_PAD = 720, 170, 22


def _parse_ts(value):
    try:
        t = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _slots(since, now, hourly):
    """since~now 를 덮는 시간(또는 날짜) 칸의 키 목록(한국 시간 기준, 오래된 것부터)."""
    step = timedelta(hours=1) if hourly else timedelta(days=1)
    t = since.astimezone(KST).replace(minute=0, second=0, microsecond=0)
    if not hourly:
        t = t.replace(hour=0)
    out, end = [], now.astimezone(KST)
    while t <= end:
        out.append(t)
        t += step
    return out


def _slot_key(t, hourly):
    t = t.astimezone(KST)
    return t.strftime("%Y-%m-%d %H") if hourly else t.strftime("%Y-%m-%d")


def scan(log_dir, hours=24, event_type="", decision="", user="", ip="", now=None):
    """로그를 한 번 훑는다. 기간 안의 모든 이벤트로 요약·추이·상위 목록을 만들고, 필터에 맞는 이벤트는 최신순으로 MAX_MATCH 건까지 모은다."""
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    hourly = hours <= 48
    slots = _slots(since, now, hourly)
    buckets = {_slot_key(t, hourly): Counter() for t in slots}
    decisions, kinds, bad_ips, fail_users, suspicious = Counter(), Counter(), Counter(), Counter(), Counter()
    ips, matched, matched_n, scanned, oldest, reached_start = set(), [], 0, 0, None, False
    for line in _lines_newest_first(log_dir):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict):
            continue
        when = _parse_ts(e.get("ts", ""))
        if when is None:
            continue
        if when < since:
            reached_start = True
            break                                         # 최신순이라 이 시각 이전은 더 볼 필요 없다
        scanned += 1
        oldest = when if oldest is None else min(oldest, when)
        et, dec, src = str(e.get("event_type", "-")), str(e.get("decision", "-")), str(e.get("src_ip", "-"))
        decisions[dec] += 1
        kinds[et] += 1
        ips.add(src)
        cls = CLASS_OF.get(dec)
        key = _slot_key(when, hourly)
        if cls and key in buckets:
            buckets[key][cls] += 1
        if dec in BAD_DECISIONS:
            bad_ips[src] += 1
        if et in LOGIN_FAIL_TYPES:
            fail_users[str(e.get("user", "-"))] += 1
        if et == "suspicious_input":
            suspicious[str(e.get("reason", "-"))] += 1
        if event_type and et != event_type or decision and dec != decision or user and e.get("user") != user or ip and src != ip:
            continue
        matched_n += 1
        if len(matched) < MAX_MATCH:
            row = _shape(e)
            row["raw"] = json.dumps(e, ensure_ascii=False, indent=1)[:1500]
            matched.append(row)
    return {"since": since, "now": now, "hourly": hourly, "slots": slots, "buckets": buckets, "decisions": decisions, "kinds": kinds,
            "bad_ips": bad_ips, "fail_users": fail_users, "suspicious": suspicious, "distinct_ips": len(ips), "matched": matched,
            "matched_n": matched_n, "scanned": scanned, "oldest": oldest, "reached_start": reached_start}


def chart(result):
    """추이 그래프용 SVG 좌표를 미리 계산한다(화면 템플릿은 숫자만 찍는다: 인라인 스타일·스크립트 없이 CSP 를 지킨다)."""
    slots, buckets, hourly = result["slots"], result["buckets"], result["hourly"]
    n = max(len(slots), 1)
    peak = max((sum(buckets[_slot_key(t, hourly)].values()) for t in slots), default=0) or 1
    plot_h = CHART_H - CHART_PAD
    slot_w = CHART_W / n
    bar_w = max(slot_w * 0.7, 1)
    label_every = max(1, n // 12)
    bars, labels = [], []
    for i, t in enumerate(slots):
        counts = buckets[_slot_key(t, hourly)]
        x = round(i * slot_w + (slot_w - bar_w) / 2, 1)
        y_bottom, rects = float(plot_h), []
        for cls, _label in SERIES:
            h = round(plot_h * counts[cls] / peak, 1)
            if h > 0:
                y_bottom -= h
                rects.append({"cls": cls, "y": round(y_bottom, 1), "h": h})
        local = t.astimezone(KST)
        title = f"{local.strftime('%m-%d %H시' if hourly else '%Y-%m-%d')}: " + ", ".join(f"{lab.split('(')[0]} {counts[c]}" for c, lab in SERIES)
        bars.append({"x": x, "w": round(bar_w, 1), "rects": rects, "title": title, "total": sum(counts.values())})
        if i % label_every == 0:
            labels.append({"x": round(x + bar_w / 2, 1), "text": local.strftime("%H시" if hourly else "%m-%d")})
    return {"width": CHART_W, "height": CHART_H, "plot": plot_h, "bars": bars, "labels": labels, "peak": peak}


def csv_cell(value):
    """CSV 수식 주입(= + - @ 로 시작하는 칸이 엑셀에서 수식으로 실행되는 것)을 막는다: 앞에 작은따옴표를 붙인다."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


# =====================================================================================
# 실시간 감사 로그 SSE (Server-Sent Events) 스트리밍 브로드캐스터
# =====================================================================================
_audit_subscribers = set()
_audit_subscribers_lock = threading.Lock()


def subscribe_audit_events():
    """새 SSE 클라이언트 큐 생성 및 등록."""
    q = queue.Queue(maxsize=100)
    with _audit_subscribers_lock:
        _audit_subscribers.add(q)
    return q


def unsubscribe_audit_events(q):
    """SSE 클라이언트 큐 해제."""
    with _audit_subscribers_lock:
        _audit_subscribers.discard(q)


def broadcast_audit_event(record: dict):
    """새로 발생한 보안 이벤트를 접속 중인 모든 SSE 클라이언트 큐로 전달."""
    with _audit_subscribers_lock:
        if not _audit_subscribers:
            return
        # 화면 테이블 및 상세 패널에 필요한 표준 포맷으로 정리
        row = _shape(record)
        row["raw"] = json.dumps(record, ensure_ascii=False, indent=2)[:2000]

        dead = []
        for q in _audit_subscribers:
            try:
                q.put_nowait(row)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _audit_subscribers.discard(q)

