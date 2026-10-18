"""방어 점검 확장판(블랙박스): defense_check.py(D01~D18)가 다루지 않는 공격 패턴을 더 보낸다.

defense_check.py 와 같은 하네스(Client/Db/Pacer)를 그대로 재사용한다. 반드시 **내 PC(루프백)의
실습 환경**에만 쓴다. 점검용 계정·데이터(zz_probe2_ 접두사)를 root 로 만들었다가 끝나면 모두 지운다.

추가로 보내는 공격 패턴(요약, 전부 defense_check.py D01~D18 과 겹치지 않는 것만):
  E01 SSTI(서버 템플릿 인젝션)        E06 열린 리다이렉트 추정
  E02 대량 할당(숨은 필드 위조)       E07 Host/X-Forwarded-* 위조
  E03 파라미터 오염(같은 이름 중복)   E08 동시 요청 경쟁(진짜 동시 스레드)
  E04 체계적 IDOR 전수조사            E09 제어문자·과장 길이·유니코드 스트레스
  E05 업로드 우회 추가 변형            E10 메서드 변조 추가 조합
  E12 Content-Type 혼동               E15 세션 고정
  E13 숫자 경계값·위조 결재단계        E16 통계적 계정 열거
  E14 업로드 폴리글랏
  E17 비밀번호 정책 경계값             E19 철회-결정 동시 경쟁
  E18 강등된 결재자의 처리 시도        E20 관리자 역할변경 동시 경쟁

사용: python scripts/red_team_extra.py [--base http://127.0.0.1:5070] [--report 파일.md] [--login-limit 20]
"""
import argparse
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import defense_check as dc  # noqa: E402  (같은 폴더의 하네스를 그대로 재사용)

PROBE2 = "zz_probe2_"
dc.PROBE = PROBE2  # Db.cleanup 등이 이 접두사로 점검용 데이터만 지우게 한다

SSTI = ["{{7*7}}", "{{config}}", "{{self}}", "{%for x in ().__class__.__base__.__subclasses__()%}{{x}}{%endfor%}",
        "${7*7}", "#{7*7}", "{{''.__class__.__mro__}}"]
UPLOAD_REJECT = [
    ("evil.svg", b"<svg onload=alert(1)>", "svg"),
    ("shell.phtml", b"<?php system($_GET['c']);?>", "phtml"),
    ("shell.jsp", b"<% Runtime.getRuntime().exec(\"id\"); %>", "jsp"),
    ("shell.asp", b"<% eval request(\"c\") %>", "asp"),
    ("x.exe", b"MZ" + b"\x00" * 30, "exe"),
    ("..%2f..%2fevil.txt", b"hello", "traversal-in-filename"),
    ("fake.PNG", b"not a real png", "uppercase-ext-fake-content"),  # 확장자는 맞지만 내용 불일치
]
UPLOAD_ACCEPT = [
    ("real.PNG", dc.PNG, "uppercase-ext-real-content"),         # 확장자 대소문자 무관
    ("a" * 300 + ".txt", b"hello", "overlong-filename-valid"),  # 정상 텍스트, 파일명만 과장
]
NEXT_PARAM_NAMES = ["next", "redirect", "return_to", "returnUrl", "url", "continue", "dest", "target"]
EVIL = "https://evil.example.com/"


def _scope_label(status, expected_ok):
    return "ok" if status in expected_ok else f"이상({status})"


def raw_post(client, path, body_bytes, content_type):
    """Client.request()는 data를 항상 urlencode 하므로, 미리 만든 원본 바이트(JSON 등)를
    그대로 보내려면 urllib 요청을 직접 만든다. 같은 쿠키·쿠키저장소를 그대로 쓴다."""
    hdr = {"Content-Type": content_type}
    if client.cookie_header:
        hdr["Cookie"] = client.cookie_header
    req = urllib.request.Request(client.base + path, body_bytes, hdr, method="POST")
    start = time.monotonic()
    try:
        r = client.op.open(req, timeout=15)
    except urllib.error.HTTPError as e:
        r = e
    cookies = r.headers.get_all("Set-Cookie") or []
    return dc.Resp(r.status, dict(r.headers), r.read(), time.monotonic() - start, cookies)


@dc.scenario("E01", "SSTI(서버 템플릿 인젝션)")
def e01(c):
    # 여러 페이로드를 한 화면에 모아 긁으면 다른 글자(개수·가격·id)와 "49" 가 우연히 섞여
    # 오탐이 난다. 그래서 페이로드마다 자신이 만든 글 하나만 떼어서, 그 본문에 원문 조각
    # "{{7*7}}" 이 그대로 있고(이스케이프 없이도 중괄호는 안 바뀐다) "49" 로 바뀌지 않았는지만 본다.
    p = []
    mgr = c.db.uid(PROBE2 + "mgr")
    CANARY = "{{7*7}}"
    r1 = c.emp.post("/boards/free/new", {"title": "SSTI1", "body": CANARY}, token_from="/boards/free/new")
    r2 = c.emp.post("/approvals/new", {"title": "SSTI2", "body": CANARY, "approver_1": str(mgr)}, token_from="/approvals/new")
    c.emp.post("/chat/messages", {"message": CANARY}, token_from="/chat")
    if r1.status == 303:
        body = re.search(r'<div class="body">(.*?)</div>', c.emp.get(r1.location).text, re.S)
        if not body or CANARY not in body.group(1):
            p.append("게시글 본문: {{7*7}} 원문이 그대로 보이지 않음(평가됐을 가능성)")
    if r2.status == 303:
        body = re.search(r'<div class="body">(.*?)</div>', c.emp.get(r2.location).text, re.S)
        if not body or CANARY not in body.group(1):
            p.append("결재 본문: {{7*7}} 원문이 그대로 보이지 않음(평가됐을 가능성)")
    chat_html = c.emp.get("/chat").text
    if CANARY not in chat_html:
        p.append("챗봇 화면: {{7*7}} 원문이 그대로 보이지 않음(평가됐을 가능성)")
    # 나머지 SSTI 변형(클래스 체인 등)은 한 번씩 더 보내 서버가 500 이나 비밀값 노출 없이 받아내는지만 확인
    for s in SSTI:
        r = c.emp.post("/chat/messages", {"message": s}, token_from="/chat")
        if r.status not in (303, 400, 429):
            p.append(f"'{s[:20]}' → {r.status}")
    html = c.emp.get("/chat").text
    if re.search(r"SECRET_KEY|nexus_app|nexus_conf", html):
        p.append("설정·비밀 값이 응답에 노출됨")
    return dc.verdict(p, f"SSTI 탐침 {len(SSTI)}종을 게시글·챗봇·결재에 넣었으나 글자 그대로만 표시, 서버 값 노출 없음")


@dc.scenario("E02", "대량 할당(숨은 필드 위조)")
def e02(c):
    p = []
    before_role = c.db.q("SELECT role FROM users WHERE username=%s", (PROBE2 + "emp",))[0][0]
    r = c.emp.post("/boards/free/new", {"title": "대량할당", "body": "x", "role": "admin", "author_id": "1",
                                        "id": "999999"}, token_from="/boards/free/new")
    pid = re.search(r"/posts/(\d+)", r.location).group(1) if r.status == 303 else None
    if pid:
        row = c.db.q("SELECT author_id FROM posts WHERE id=%s", (pid,))[0][0]
        if row != c.db.uid(PROBE2 + "emp"):
            p.append("author_id 가 위조한 값으로 들어감")
    r2 = c.emp.post("/expenses/new", {"title": "대량할당2", "amount": "1000", "status": "approved",
                                      "user_id": str(c.db.uid(PROBE2 + "mgr"))}, token_from="/expenses/new")
    eid = r2.location.rstrip("/").rsplit("/", 1)[1] if r2.status == 303 else None
    if eid:
        row = c.db.q("SELECT status, user_id FROM expenses WHERE id=%s", (eid,))[0]
        if row[0] != "draft":
            p.append(f"경비 status 가 위조한 값({row[0]})으로 들어감(항상 draft 여야 함)")
        if row[1] != c.db.uid(PROBE2 + "emp"):
            p.append("경비 user_id 가 위조한 값으로 들어감")
    r3 = c.emp.post("/admin/users/1/role", {"role": "admin", "current_role": "employee", "id": "1", "is_admin": "1"})
    if r3.status != 403:
        p.append(f"직원이 보낸 role 변경 위조 요청 → {r3.status}")
    after_role = c.db.q("SELECT role FROM users WHERE username=%s", (PROBE2 + "emp",))[0][0]
    if after_role != before_role:
        p.append("점검 계정 자신의 역할이 바뀜")
    return dc.verdict(p, "게시글/경비 작성 시 끼워 넣은 role·author_id·user_id·status 위조 필드가 모두 무시됨, 관리자 아닌 계정의 role 변경 403")


@dc.scenario("E03", "파라미터 오염(같은 이름 중복)")
def e03(c):
    # Client.post()는 data 를 dict()로 바꿔 중복 키를 지워버리므로, request()를 직접 불러
    # urlencode가 중복 키를 그대로 보내게 한다(튜플 목록).
    p = []
    mgr, emp2 = c.db.uid(PROBE2 + "mgr"), c.db.uid(PROBE2 + "emp2")

    token1 = c.emp.csrf("/boards/free/new")
    r = c.emp.request("POST", "/boards/free/new",
                      data=[("title", "오염1"), ("title", "오염2"), ("body", "x"), ("csrf_token", token1)])
    if r.status not in (303, 400):
        p.append(f"title 중복 파라미터 → {r.status}")

    anon2 = c.anon_fresh()
    token2 = anon2.csrf("/login")
    r2 = anon2.request("POST", "/login",
                       data=[("username", PROBE2 + "emp"), ("username", "admin"), ("password", "wrong"),
                             ("csrf_token", token2)])
    if r2.status == 303:
        p.append("username 중복 파라미터로 로그인 성공(둘 중 하나로 우회 가능)")

    token3 = c.emp.csrf("/approvals/new")
    r3 = c.emp.request("POST", "/approvals/new",
                       data=[("title", "오염결재"), ("body", "x"), ("approver_1", str(mgr)),
                             ("approver_1", str(emp2)), ("csrf_token", token3)])
    if r3.status == 303:
        aid = r3.location.rsplit("/", 1)[1]
        steps = c.db.q("SELECT approver_id FROM approval_steps WHERE approval_id=%s AND step_no=1", (aid,))
        if steps and steps[0][0] == emp2:
            p.append("중복 approver_1 중 뒤 값(일반 직원)이 채택됨(검증 우회 의심)")
    return dc.verdict(p, "같은 이름 파라미터 중복(제목·로그인 계정·결재자)을 보냈으나 비정상 동작(권한 우회·검증 우회) 없음")


@dc.scenario("E04", "체계적 IDOR 전수조사")
def e04(c):
    p = []
    checks = [
        ("/documents/{}", range(1, 4), (200, 404), c.emp),
        ("/posts/{}", range(1, 4), (200, 404), c.emp),
        ("/attachments/{}", range(1, 6), (200, 404), c.emp),
        ("/confidential/{}", range(1, 4), (403,), c.emp),
        ("/finance/{}", range(1, 4), (403,), c.emp),
        ("/payroll/{}", range(1, 10), (200, 403, 404), c.emp),   # 200 은 본인 급여일 때만 맞음(아래서 교차 확인)
        ("/expenses/{}", range(1, 10), (200, 403, 404), c.emp),
        ("/approvals/{}", range(1, 10), (200, 403, 404), c.emp),
    ]
    for tmpl, ids, ok_codes, client in checks:
        for i in ids:
            r = client.get(tmpl.format(i))
            if r.status not in ok_codes and r.status != 0:
                p.append(f"{tmpl.format(i)} → {r.status}(예상 밖)")
    # payroll/expenses/approvals 의 200 응답이 실제로 '내 것'인지 교차 확인
    my_id = c.db.uid(PROBE2 + "emp")
    for i in range(1, 10):
        r = c.emp.get(f"/payroll/{i}")
        if r.status == 200:  # 화면이 200 이면 본인 급여여야 한다
            row = c.db.q("SELECT user_id FROM payroll WHERE id=%s", (i,))
            if row and row[0][0] != my_id:
                p.append(f"/payroll/{i} 가 200 인데 본인 급여가 아님(user_id={row[0][0]})")
    anon_leaks = []
    for path in ("/documents/1", "/posts/1", "/payroll/1", "/expenses/1", "/approvals/1", "/confidential/1", "/admin/users"):
        r = c.anon.get(path)
        if r.status == 200:
            anon_leaks.append(path)
    if anon_leaks:
        p.append("비로그인으로 200: " + ", ".join(anon_leaks))
    return dc.verdict(p, "문서·게시글·첨부·기밀문서·재무·급여·경비·결재 ID를 1~9 전수로 직원·비로그인 계정으로 조회: 범위 밖은 403/404, 비로그인은 전부 차단")


@dc.scenario("E05", "업로드 우회 추가 변형")
def e05(c):
    def count():
        return len(list(c.upload_dir.glob("*"))) if c.upload_dir.exists() else 0
    before, p, accepted = count(), [], 0
    for name, data, label in UPLOAD_REJECT:
        r = c.emp.post("/boards/free/new", {"title": f"업로드추가-{label}", "body": "x"},
                       token_from="/boards/free/new", files={"attachment": (name, data)})
        if r.status not in (400, 413, 0):
            p.append(f"{label}({name[:30]}) → {r.status}(거부됐어야 함)")
    for name, data, label in UPLOAD_ACCEPT:
        r = c.emp.post("/boards/free/new", {"title": f"업로드추가-{label}", "body": "x"},
                       token_from="/boards/free/new", files={"attachment": (name, data)})
        if r.status != 303:
            p.append(f"{label}: 정상 파일이 거부됨 → {r.status}")
        else:
            accepted += 1
    if count() != before + accepted:
        p.append(f"업로드 폴더 파일 수 변화 {count() - before}건(정상 통과 {accepted}건과 불일치)")
    return dc.verdict(p, f"SVG·phtml·jsp·asp·exe·경로조작파일명·내용불일치 {len(UPLOAD_REJECT)}종 전부 거부, "
                         f"대문자 확장자·과장 파일명(정상 내용) {len(UPLOAD_ACCEPT)}종은 정상 통과")


@dc.scenario("E06", "열린 리다이렉트 추정")
def e06(c):
    p = []
    pages = ["/login", "/"]
    for page in pages:
        for name in NEXT_PARAM_NAMES:
            r = c.anon.get(page + "?" + urllib.parse.urlencode({name: EVIL}))
            if r.status in (301, 302, 303, 307, 308) and EVIL.rstrip("/") in r.location:
                p.append(f"{page}?{name}=... → {r.status} Location={r.location}")
    # /logout 은 실제로 세션을 끊으므로, 이후 점검에 쓰는 c.emp 가 아니라 따로 로그인한
    # 일회용 클라이언트(emp2)로만 시험한다.
    throwaway = c.fresh_client()
    throwaway.login(PROBE2 + "emp2", c.pw["emp2"])
    r2 = throwaway.post("/logout", {name: EVIL for name in NEXT_PARAM_NAMES[:2]})
    if r2.status in (301, 302, 303, 307, 308) and EVIL.rstrip("/") in r2.location:
        p.append(f"/logout 후 외부 주소로 리다이렉트: {r2.location}")
    return dc.verdict(p, f"흔한 리다이렉트 파라미터 이름 {len(NEXT_PARAM_NAMES)}종을 로그인·홈·로그아웃에 시도: 외부 주소로 보내는 응답 없음")


@dc.scenario("E07", "Host/X-Forwarded-* 위조")
def e07(c):
    p = []
    hdrs = {"Host": "evil.example.com", "X-Forwarded-Host": "evil.example.com", "X-Forwarded-Proto": "https",
            "X-Forwarded-For": "1.2.3.4, 5.6.7.8"}
    r = c.anon.request("GET", "/login", headers=hdrs)
    if r.status == 200 and "evil.example.com" in r.text:
        p.append("위조한 Host 가 응답 본문에 그대로 반영됨")
    return dc.verdict(p, "위조한 Host/X-Forwarded-Host 가 응답에 반영되지 않음(오픈 리다이렉트·캐시 오염 연계 없음)")


@dc.scenario("E08", "동시 요청 경쟁(진짜 동시 스레드)")
def e08(c):
    p = []
    mgr = c.db.uid(PROBE2 + "mgr")
    r = c.emp.post("/expenses/new", {"title": "경쟁시험", "amount": "5000"}, token_from="/expenses/new")
    eid = r.location.rstrip("/").rsplit("/", 1)[1] if r.status == 303 else None
    if not eid:
        return "FAIL", "경쟁 시험용 경비 생성 실패"
    results = []

    def submit():
        cl = dc.Client(c.base, c.pacer, cookie="; ".join(c.login_cookies_emp))
        results.append(cl.post(f"/expenses/{eid}/submit", {"approver_1": str(mgr)}, token_from=f"/expenses/{eid}").status)
    threads = [threading.Thread(target=submit) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok_count = sum(1 for s in results if s == 303)
    approvals = c.db.q("SELECT COUNT(*) FROM approvals WHERE expense_id=%s", (eid,))[0][0]
    if ok_count > 1 or approvals > 1:
        p.append(f"동시 상신 8회 중 성공 {ok_count}회, 생성된 결재 {approvals}건(1이어야 함)")
    # 결재 id는 스레드를 띄우기 전에 메인 스레드에서 한 번만 조회한다(공용 PyMySQL 커넥션을
    # 여러 스레드에서 동시에 쓰면 프로토콜이 깨진다 — HTTP 요청만 스레드마다 따로 보낸다).
    row = c.db.q("SELECT id FROM approvals WHERE expense_id=%s", (eid,))
    aid = row[0][0] if row else None
    decides = []

    def decide():
        if aid is None:
            return
        cl = dc.Client(c.base, c.pacer, cookie="; ".join(c.login_cookies_mgr))
        decides.append(cl.post(f"/approvals/{aid}/decide", {"decision": "approve"}, token_from=f"/approvals/{aid}").status)
    threads2 = [threading.Thread(target=decide) for _ in range(6)]
    for t in threads2:
        t.start()
    for t in threads2:
        t.join()
    decide_ok = sum(1 for s in decides if s == 303)
    if decide_ok > 1:
        p.append(f"동시 승인 6회 중 성공 {decide_ok}회(1이어야 함)")
    return dc.verdict(p, f"경비 상신 8동시·결재 승인 6동시 요청: 각 1회만 성공, 중복 결재 문서 생성 없음")


@dc.scenario("E09", "제어문자·과장 길이·유니코드 스트레스")
def e09(c):
    p = []
    weird = ["\x00\x01\x02", "A" * 100000, "​‌‍" * 50,  # 제로폭 문자
             "﻿제목", "ＡＢＣ０１２", "𝕏𝕊𝕊", "a\r\nX-Injected: 1"]
    for s in weird:
        for path, field in (("/boards/free/new", "title"), ("/chat/messages", "message"), ("/expenses/new", "title")):
            data = {"title": s[:50], "body": "x"} if field != "message" else {"message": s}
            if path == "/expenses/new":
                data = {"title": s[:50], "amount": "100"}
            r = c.emp.post(path, data, token_from=path if path != "/chat/messages" else "/chat")
            if r.status == 500 or dc.ERROR_LEAK.search(r.text):
                p.append(f"{path} ({field}, {s[:10]!r}) → {r.status}, 내부 정보 노출 가능성")
    return dc.verdict(p, f"제어문자·10만자 과장 입력·제로폭/전각/서로게이트페어 유니코드·개행삽입 {len(weird)}종: 500 또는 오류 정보 노출 없음")


@dc.scenario("E10", "메서드 변조 추가 조합")
def e10(c):
    p = []
    combos = [("HEAD", "/admin/users"), ("TRACE", "/"), ("OPTIONS", "/admin/users/1/role"),
             ("GET", "/admin/users/1/role"), ("GET", "/account/password"),
             ("POST", "/healthz"), ("PUT", "/attachments/1")]
    for method, path in combos:
        r = c.emp.request(method, path)
        if r.status not in (403, 404, 405, 200):
            p.append(f"{method} {path} → {r.status}(예상 밖)")
    return dc.verdict(p, f"메서드·경로 조합 {len(combos)}종: 모두 403/404/405/200 범위 안")


@dc.scenario("E12", "Content-Type 혼동(JSON 본문)")
def e12(c):
    p = []
    token = c.emp.csrf("/boards/free/new")
    body = ('{"title": "json\\u0027주입", "body": "x", "csrf_token": "%s"}' % token).encode()
    r = raw_post(c.emp, "/boards/free/new", body, "application/json")
    if r.status not in (400, 403, 415, 0):
        p.append(f"JSON 본문으로 글쓰기 → {r.status}(파싱되어 통과했다면 문제)")
    # multipart 내부에 두 번째 title 파트를 더 넣어 파서 혼동을 시도
    boundary = "zzbound"
    parts = (f'--{boundary}\r\nContent-Disposition: form-data; name="title"\r\n\r\n멀티파트1\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="title"\r\n\r\n멀티파트2\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="body"\r\n\r\nx\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="csrf_token"\r\n\r\n{c.emp.csrf("/boards/free/new")}\r\n'
            f'--{boundary}--\r\n').encode()
    r2 = raw_post(c.emp, "/boards/free/new", parts, f"multipart/form-data; boundary={boundary}")
    if r2.status not in (303, 400):
        p.append(f"중복 title 멀티파트 → {r2.status}")
    return dc.verdict(p, "JSON 본문·중복 필드 멀티파트로 글쓰기 시도: 정상 처리되지 않거나(400) 안전하게 하나만 반영")


@dc.scenario("E13", "숫자 경계값·위조 결재 단계")
def e13(c):
    p = []
    mgr = c.db.uid(PROBE2 + "mgr")
    for amount, label in (("0", "0원"), ("-1", "음수"), ("100000001", "상한+1"), ("1e3", "지수표기"),
                          ("+100", "부호"), (" 100", "앞공백"), ("100.0", "소수점"), ("٣٣٣", "아랍숫자")):
        r = c.emp.post("/expenses/new", {"title": f"경계값-{label}", "amount": amount}, token_from="/expenses/new")
        if r.status not in (400, 0):
            p.append(f"금액 '{amount}'({label}) → {r.status}(거부됐어야 함)")
    # MAX_STEPS(5) 를 넘는 6차 결재자를 끼워 넣어도 무시되는지
    r2 = c.emp.post("/approvals/new", {"title": "6단계결재", "body": "x", "approver_1": str(mgr),
                                       "approver_6": str(mgr)}, token_from="/approvals/new")
    if r2.status == 303:
        aid = r2.location.rsplit("/", 1)[1]
        steps = c.db.q("SELECT COUNT(*) FROM approval_steps WHERE approval_id=%s", (aid,))[0][0]
        if steps != 1:
            p.append(f"approver_6 이 반영되어 결재 단계가 {steps}개 생성됨(1이어야 함)")
    return dc.verdict(p, "0·음수·상한초과·지수표기·부호·공백·소수점·아랍숫자 금액 8종 전부 거부, 정의되지 않은 approver_6 은 무시됨")


@dc.scenario("E14", "업로드 폴리글랏(매직바이트 뒤에 스크립트 은닉)")
def e14(c):
    def count():
        return len(list(c.upload_dir.glob("*"))) if c.upload_dir.exists() else 0
    before, p = count(), []
    polyglot = dc.PNG + b"<?php system($_GET['c']); ?><script>alert(1)</script>"
    r = c.emp.post("/boards/free/new", {"title": "폴리글랏", "body": "x"}, token_from="/boards/free/new",
                   files={"attachment": ("evil.png", polyglot)})
    if r.status != 303:
        p.append(f"매직바이트가 맞는 폴리글랏 파일이 거부됨({r.status}) — PNG로서는 정상이어야 함")
    else:
        att = re.search(r"/attachments/(\d+)", c.emp.get(r.location).text)
        if att:
            d = c.emp.get(f"/attachments/{att.group(1)}")
            h = {k.lower(): v for k, v in d.headers.items()}
            if not h.get("content-disposition", "").startswith("attachment") or h.get("x-content-type-options") != "nosniff":
                p.append("폴리글랏 PNG가 첨부·nosniff 가 아닌 방식으로 내려감(브라우저가 스크립트로 해석할 위험)")
            if h.get("content-type", "").startswith("text/html"):
                p.append("Content-Type 이 text/html 로 내려감(스크립트 실행 위험)")
    if count() != before + 1:
        p.append("업로드 폴더 파일 수가 예상과 다름")
    return dc.verdict(p, "PNG 매직바이트 뒤에 PHP·script 태그를 숨긴 폴리글랏 파일: 매직바이트는 맞으므로 저장은 되지만 항상 첨부(nosniff)로만 내려감")


@dc.scenario("E15", "세션 고정(로그인 전에 쿠키를 먼저 쥐여줌)")
def e15(c):
    p = []
    fixed = "attacker-chosen-session-value-" + __import__("secrets").token_urlsafe(8)
    cl = dc.Client(c.base, c.pacer)
    # 로그인 전에 공격자가 정한 값으로 세션 쿠키를 먼저 심는다(공격자가 같은 값으로 나중에 들어오는 시나리오)
    cl.cookie_header = f"nexus_session={fixed}"
    r1 = cl.login(PROBE2 + "emp2", c.pw["emp2"])
    post_login_cookie = next((v for v in r1.set_cookies if v.startswith("nexus_session=")), "")
    if fixed in post_login_cookie:
        p.append("로그인 후에도 공격자가 지정한 세션 값이 그대로 쓰임(세션 고정 가능)")
    # 공격자가 심어둔 원래 값으로 다시 접근해도 로그인된 상태가 되면 안 된다
    r2 = dc.Client(c.base, c.pacer, cookie=f"nexus_session={fixed}").get("/")
    if r2.status == 200:
        p.append("공격자가 미리 심은 세션 값으로 로그인 상태에 접근됨")
    return dc.verdict(p, "로그인 전에 공격자가 지정한 세션 쿠키 값을 심어도, 로그인 후 쿠키가 새로 발급되고 그 값으로는 접근되지 않음")


@dc.scenario("E16", "통계적 계정 열거(표본 확대)")
def e16(c):
    p, real_times, fake_times = [], [], []
    real_users = ["admin", PROBE2 + "mgr", PROBE2 + "emp"]
    fake_users = ["zz_no_such_1", "zz_no_such_2", "zz_no_such_3"]
    for u in real_users * 3:
        r = c.fresh_client().login(u, "definitely-wrong-password-123!")
        real_times.append(r.elapsed)
        if r.status != 401:
            p.append(f"실제 계정 '{u}' 오답 로그인 → {r.status}")
    for u in fake_users * 3:
        r = c.fresh_client().login(u, "definitely-wrong-password-123!")
        fake_times.append(r.elapsed)
        if r.status != 401:
            p.append(f"없는 계정 '{u}' 로그인 → {r.status}")
    avg_real, avg_fake = sum(real_times) / len(real_times), sum(fake_times) / len(fake_times)
    gap = abs(avg_real - avg_fake)
    if gap > 0.15:  # 150ms 이상 체계적 차이면 계정 존재 여부를 시간으로 구분할 수 있다는 뜻
        p.append(f"실제/가짜 계정 평균 응답시간 차이 {gap*1000:.0f}ms(표본 {len(real_times)}+{len(fake_times)}개)")
    return dc.verdict(p, f"실제 계정 {len(set(real_users))}개·가짜 계정 {len(set(fake_users))}개를 각 3회씩(총 {len(real_times)+len(fake_times)}회) 오답 로그인: "
                         f"평균 응답시간 차이 {gap*1000:.0f}ms, 모두 동일 401")


@dc.scenario("E17", "비밀번호 정책 경계값")
def e17(c):
    p = []
    cl = c.fresh_client()
    cl.login(PROBE2 + "emp2", c.pw["emp2"])
    cur = c.pw["emp2"]

    def try_change(new, confirm=None, label=""):
        return cl.post("/account/password", {"current_password": cur, "new_password": new,
                                              "confirm_password": confirm if confirm is not None else new},
                       token_from="/account/password")

    r1 = try_change("Aa1!aaaaaaa", label="11자(짧음, 복잡도는 충족)")  # 11자
    if r1.status != 400:
        p.append(f"11자 미만 비밀번호(복잡도 충족)가 거부되지 않음 → {r1.status}")
    r2 = try_change("abcdefghijklmnop12", label="2종만(소문자+숫자)")
    if r2.status != 400:
        p.append(f"2종류 문자만 쓴 비밀번호가 거부되지 않음 → {r2.status}")
    r3 = try_change("Aa1!" + PROBE2 + "emp2", label="아이디포함")
    if r3.status != 400:
        p.append(f"아이디를 포함한 비밀번호가 거부되지 않음 → {r3.status}")
    r4 = try_change("Aa1!goodpass12", confirm="Aa1!different12", label="확인불일치")
    if r4.status != 400:
        p.append(f"새 비밀번호 확인이 다른데 거부되지 않음 → {r4.status}")
    r5 = try_change(cur, label="재사용")
    if r5.status != 400:
        p.append(f"현재와 같은 비밀번호로 변경이 거부되지 않음 → {r5.status}")
    good = "Aa1!" + __import__("secrets").token_urlsafe(10)
    r6 = try_change(good, label="정상 12자+4종")
    if r6.status != 303:
        p.append(f"정책을 만족하는 정상 비밀번호 변경이 실패함 → {r6.status}")
    else:
        c.pw["emp2"] = good
    return dc.verdict(p, "길이부족·복잡도부족·아이디포함·확인불일치·재사용 5종 모두 거부(400), 정책을 만족하는 변경은 성공(303)")


@dc.scenario("E18", "강등된 결재자의 처리 시도")
def e18(c):
    p = []
    mgr_id = c.db.uid(PROBE2 + "mgr")
    r = c.emp.post("/approvals/new", {"title": "강등시험", "body": "x", "approver_1": str(mgr_id)},
                   token_from="/approvals/new")
    if r.status != 303:
        return "FAIL", f"점검용 결재 생성 실패({r.status})"
    aid = r.location.rsplit("/", 1)[1]
    # 실제 관리자 화면으로 결재자(mgr)를 강등한다
    down = c.adm.post(f"/admin/users/{mgr_id}/role", {"role": "employee", "current_role": "manager"})
    if down.status != 303:
        p.append(f"관리자의 강등 처리 자체가 실패함({down.status}) — 이후 검사를 건너뜀")
    else:
        decide = c.mgr.post(f"/approvals/{aid}/decide", {"decision": "approve"}, token_from=f"/approvals/{aid}")
        if decide.status != 403:
            p.append(f"강등된 결재자가 여전히 승인할 수 있음 → {decide.status}")
        status = c.db.q("SELECT status FROM approvals WHERE id=%s", (aid,))[0][0]
        if status != "pending":
            p.append(f"강등만으로 결재 상태가 바뀜({status}, pending 이어야 함)")
    up = c.adm.post(f"/admin/users/{mgr_id}/role", {"role": "manager", "current_role": "employee"})
    if up.status != 303:
        p.append(f"테스트 후 역할 복구 실패({up.status}) — 다른 점검에 영향 가능")
    return dc.verdict(p, "결재 대기 중 결재자가 강등되면, 강등된 사람은 더는 승인할 수 없고(403) 결재는 대기 상태 그대로 유지됨")


@dc.scenario("E19", "철회-결정 동시 경쟁")
def e19(c):
    p = []
    mgr_id = c.db.uid(PROBE2 + "mgr")
    r = c.emp.post("/approvals/new", {"title": "철회결정경쟁", "body": "x", "approver_1": str(mgr_id)},
                   token_from="/approvals/new")
    if r.status != 303:
        return "FAIL", f"점검용 결재 생성 실패({r.status})"
    aid = r.location.rsplit("/", 1)[1]
    outcomes = []

    def withdraw():
        cl = dc.Client(c.base, c.pacer, cookie="; ".join(c.login_cookies_emp))
        outcomes.append(("withdraw", cl.post(f"/approvals/{aid}/withdraw", {}, token_from=f"/approvals/{aid}").status))

    def decide():
        cl = dc.Client(c.base, c.pacer, cookie="; ".join(c.login_cookies_mgr))
        outcomes.append(("decide", cl.post(f"/approvals/{aid}/decide", {"decision": "approve"}, token_from=f"/approvals/{aid}").status))

    threads = [threading.Thread(target=withdraw) for _ in range(4)] + [threading.Thread(target=decide) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok = [o for o in outcomes if o[1] == 303]
    if len(ok) > 1:
        p.append(f"철회·승인 동시 요청 8건 중 {len(ok)}건이 동시에 성공({ok})")
    final_status = c.db.q("SELECT status FROM approvals WHERE id=%s", (aid,))[0][0]
    if final_status not in ("withdrawn", "approved"):
        p.append(f"최종 상태가 이상함: {final_status}")
    return dc.verdict(p, f"철회 4동시·승인 4동시 요청 중 정확히 1건만 성공(최종 상태: {final_status}), 둘 다 성공하는 경우 없음")


@dc.scenario("E20", "관리자 역할변경 동시 경쟁")
def e20(c):
    p = []
    target_id = c.db.uid(PROBE2 + "emp2")
    outcomes = []

    def change(new_role):
        cl = dc.Client(c.base, c.pacer, cookie="; ".join(c.login_cookies_adm))
        outcomes.append(cl.post(f"/admin/users/{target_id}/role",
                                {"role": new_role, "current_role": "employee"},
                                token_from="/admin/users").status)

    threads = [threading.Thread(target=change, args=("manager",)) for _ in range(3)] + \
              [threading.Thread(target=change, args=("admin",)) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok = sum(1 for s in outcomes if s == 303)
    if ok > 1:
        p.append(f"같은 current_role 조건으로 보낸 역할변경 동시요청 6건 중 {ok}건이 성공(1이어야 함)")
    final_role = c.db.q("SELECT role FROM users WHERE id=%s", (target_id,))[0][0]
    # 테스트 후 원래 역할로 복구
    c.db.q("UPDATE users SET role='employee' WHERE id=%s", (target_id,))
    return dc.verdict(p, f"같은 current_role(employee)을 전제로 한 역할변경 요청(manager 3·admin 3) 동시 6건 중 정확히 1건만 성공(결과: {final_role})")


SCENARIOS = [e01, e02, e03, e04, e05, e06, e07, e08, e09, e10, e12, e13, e14, e15, e16, e17, e18, e19, e20]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:5070")
    ap.add_argument("--report")
    ap.add_argument("--login-limit", type=int, default=20)
    a = ap.parse_args()
    host = urllib.parse.urlparse(a.base).hostname
    if host not in dc.LOOPBACK:
        sys.exit(f"거부: {host} 는 루프백이 아니다.")

    pacer = dc.Pacer(a.login_limit)  # 로그인 요청만 서버의 분당 한도에 맞춰 스스로 속도를 늦춘다(Client.login 내부에서 호출)
    db = dc.Db()
    c = dc.Ctx()
    c.base, c.pacer, c.db = a.base.rstrip("/"), pacer, db
    c.upload_dir = Path(__import__("os").environ.get("UPLOAD_DIR", dc.ROOT / "instance" / "uploads"))
    c.fresh_client = lambda: dc.Client(c.base, pacer)
    c.anon_fresh = c.fresh_client
    c.anon = c.fresh_client()
    log_path = dc.ROOT / "logs" / "security.jsonl"
    offset = log_path.stat().st_size if log_path.exists() else 0
    c.read_log = dc.read_log_from(log_path, offset)

    try:
        c.anon.get("/healthz")
    except Exception as exc:
        sys.exit(f"서버에 접속할 수 없다({a.base}): {exc}")

    db.cleanup(c.upload_dir)
    baseline = db.counts()
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    c.pw = {k: __import__("secrets").token_urlsafe(14) + "aA1!" for k in ("mgr", "emp", "emp2", "adm")}
    for key, role in (("mgr", "manager"), ("emp", "employee"), ("emp2", "employee"), ("adm", "admin")):
        db.q("INSERT INTO users(username,password_hash,role,display_name,dept) VALUES(%s,%s,%s,%s,'프로브팀2')",
             (PROBE2 + key, ph.hash(c.pw[key]), role, PROBE2 + key))

    started = datetime.now()
    print(f"방어 점검 확장판 시작 {started:%Y-%m-%d %H:%M:%S} · 대상 {c.base} · DB {db.name}\n")
    try:
        c.mgr, c.emp, c.adm = c.fresh_client(), c.fresh_client(), c.fresh_client()
        for client, key in ((c.mgr, "mgr"), (c.emp, "emp"), (c.adm, "adm")):
            r = client.login(PROBE2 + key, c.pw[key])
            if r.status != 303:
                sys.exit(f"점검용 계정 로그인 실패({key}: {r.status})")
        c.login_cookies_emp = [f"{ck.name}={ck.value}" for ck in c.emp.jar]
        c.login_cookies_mgr = [f"{ck.name}={ck.value}" for ck in c.mgr.jar]
        c.login_cookies_adm = [f"{ck.name}={ck.value}" for ck in c.adm.jar]
        for fn in SCENARIOS:
            fn(c)
    finally:
        db.cleanup(c.upload_dir)
        after = db.counts()
    clean = after == baseline
    dc.RESULTS.append(("E11", "점검 데이터 정리", "PASS" if clean else "FAIL",
                       "점검용 계정·데이터를 모두 삭제했고 표별 건수가 점검 전과 같다" if clean else f"건수 불일치 {baseline} → {after}"))
    print(f"[{dc.RESULTS[-1][2]:5}] E11 {dc.RESULTS[-1][1]} — {dc.RESULTS[-1][3]}")

    results = [r for r in dc.RESULTS if r[0].startswith("E")]
    tally = {s: sum(1 for r in results if r[2] == s) for s in ("PASS", "FAIL", "LIMIT", "SKIP")}
    print(f"\n요약: PASS {tally['PASS']} · FAIL {tally['FAIL']} · 알려진 한계 {tally['LIMIT']} · 건너뜀 {tally['SKIP']}")
    if a.report:
        dc.write_report(Path(a.report), a, started, db.name, results, tally, {})
        print(f"보고서: {a.report}")
    sys.exit(1 if tally["FAIL"] else 0)


if __name__ == "__main__":
    main()
