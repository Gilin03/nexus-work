"""방어 점검(블랙박스): 내 PC에서 돌리는 NEXUS WORK 에 대해 흔한 공격 시도를 보내고 방어가 동작하는지 확인한다.

반드시 **내 PC(루프백)의 실습 환경**에만 사용한다. 루프백이 아닌 주소는 실행을 거부한다.
점검용 계정·데이터(zz_probe_ 접두사)를 root 로 만들었다가 끝나면 모두 지운다. 서버와 이 스크립트는 같은 .env(같은 DB)를 써야 한다.
공격 문자열은 입력 검증·이스케이프·권한 검사를 시험하는 일반적인 탐침이며, 방어가 뚫렸을 때 실제로 이득을 얻는 코드는 담겨 있지 않다.
점검 중 발생하는 보안 이벤트(login_failure, account_locked, authz_deny, csrf_fail, upload_reject, not_found …)는 logs/security.jsonl 에
그대로 남아 탐지 담당(C)의 탐지 룰 시험에도 쓸 수 있다.

사용: python scripts/defense_check.py [--base http://127.0.0.1:5070] [--report 파일.md] [--skip-rate-limit] [--login-limit 20]
"""
import argparse
import http.cookiejar
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

import pymysql
from argon2 import PasswordHasher
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
PROBE = "zz_probe_"
TABLES = ["users", "posts", "attachments", "expenses", "approvals", "approval_steps", "payroll", "chat_messages"]
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
ERROR_LEAK = re.compile(r"(?i)sql syntax|mysql|pymysql|sqlalchemy|traceback|werkzeug|python/3|flask")

SQLI = ["' OR '1'='1", "' OR 1=1-- ", "admin'-- ", "' UNION SELECT NULL,NULL-- ", "'; DROP TABLE users; -- ",
        "1' AND SLEEP(5)-- ", "' OR SLEEP(5)#", "\") OR (\"1\"=\"1", "1; WAITFOR DELAY '0:0:5'--", "%' OR '%'='",
        "\\' OR 1=1 -- ", "' OR ''='"]
XSS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "'><svg onload=alert(1)>",
       "<iframe src=javascript:alert(1)>", "javascript:alert(1)"]
RAW_XSS = ["<script>alert(1)", "<img src=x onerror", "<svg onload", "<iframe src=javascript"]  # 이스케이프되지 않고 나오면 안 되는 조각
SCAN_PATHS = ["admin", "administrator", "login.php", "wp-login.php", "wp-admin/", "phpmyadmin/", "pma/", ".git/HEAD", ".git/config",
              ".env", ".env.bak", "backup.zip", "backup.sql", "db.sql", "dump.sql", "config.php", "config.yml", "robots.txt",
              "sitemap.xml", "server-status", "console", "debug", "api/users", "api/v1/users", "swagger.json", "actuator/health",
              "manager/html", "cgi-bin/test.cgi", "upload", "uploads/", "files/", "test", "old/", "temp/", "tmp/", "logs/", "admin.php",
              "shell.php", "info.php", "setup.php"]


# ---------- HTTP 도우미 ----------
class Resp:
    def __init__(self, status, headers, body, elapsed, cookies):
        self.status, self.headers, self.body, self.elapsed, self.set_cookies = status, headers, body, elapsed, cookies
        self.text = body.decode("utf-8", "replace")

    @property
    def location(self):
        return self.headers.get("Location", "")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Pacer:
    """서버의 로그인 IP 제한(분당 N회)에 걸리지 않도록 로그인 요청 간격을 조절한다."""
    def __init__(self, limit):
        self.limit, self.times = limit, []

    def wait(self):
        now = time.monotonic()
        self.times = [t for t in self.times if now - t < 61]
        if len(self.times) >= self.limit - 3:
            time.sleep(max(0, 61 - (now - self.times[0])))
            self.times = [t for t in self.times if time.monotonic() - t < 61]
        self.times.append(time.monotonic())


class Client:
    def __init__(self, base, pacer, cookie=None):
        self.base, self.pacer, self.cookie_header = base, pacer, cookie
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def request(self, method, path, data=None, files=None, headers=None):
        body, hdr = None, dict(headers or {})
        if files:
            b = uuid.uuid4().hex
            parts = [f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode() for k, v in (data or {}).items()]
            for k, (fn, content) in files.items():
                parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"; filename="{fn}"\r\n'
                             f'Content-Type: application/octet-stream\r\n\r\n'.encode() + content + b"\r\n")
            parts.append(f"--{b}--\r\n".encode())
            body, hdr["Content-Type"] = b"".join(parts), f"multipart/form-data; boundary={b}"
        elif data is not None:
            body = urllib.parse.urlencode(data).encode()
        if self.cookie_header:
            hdr["Cookie"] = self.cookie_header
        req = urllib.request.Request(self.base + path, body, hdr, method=method)
        start = time.monotonic()
        try:
            r = self.op.open(req, timeout=15)
        except urllib.error.HTTPError as e:
            r = e
        except (ConnectionError, urllib.error.URLError, TimeoutError) as e:  # 서버가 큰 요청 등을 거부하며 연결을 끊은 경우
            return Resp(0, {}, str(e).encode(), time.monotonic() - start, [])
        cookies = r.headers.get_all("Set-Cookie") or []
        return Resp(r.status, dict(r.headers), r.read(), time.monotonic() - start, cookies)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def csrf(self, page="/"):
        m = re.search(r'name="csrf_token" value="([^"]+)"', self.get(page).text)
        return m.group(1) if m else ""

    def post(self, path, data=None, token_from="/", with_token=True, files=None, **kw):
        fields = dict(data or {})
        if with_token:
            fields["csrf_token"] = self.csrf(token_from)
        return self.request("POST", path, data=fields, files=files, **kw)

    def login(self, user, password):
        self.pacer.wait()
        return self.post("/login", {"username": user, "password": password}, token_from="/login")


# ---------- DB 도우미(점검용 데이터만 만들고 지운다) ----------
class Db:
    def __init__(self):
        name = os.environ.get("DB_NAME", "nexus")
        if name not in ("nexus", "nexus_test"):
            sys.exit(f"허용되지 않는 DB 이름: {name}")
        self.con = pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")), user="root",
                                   password=os.environ["MYSQL_ROOT_PASSWORD"], database=name, autocommit=True)
        self.name = name

    def q(self, sql, args=None):
        with self.con.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchall()

    def uid(self, username):
        return self.q("SELECT id FROM users WHERE username=%s", (username,))[0][0]

    def counts(self):
        return {t: self.q(f"SELECT COUNT(*) FROM `{t}`")[0][0] for t in TABLES}  # TABLES 는 고정 목록

    def cleanup(self, upload_dir):
        like = PROBE.replace("_", "\\_") + "%"
        users = "(SELECT id FROM users WHERE username LIKE %s)"
        for (stored,) in self.q(f"SELECT a.stored_name FROM attachments a JOIN posts p ON p.id=a.post_id WHERE p.author_id IN {users}", (like,)):
            (upload_dir / stored).unlink(missing_ok=True)
        self.q(f"DELETE FROM approval_steps WHERE approver_id IN {users} OR approval_id IN (SELECT id FROM approvals WHERE requester_id IN {users})", (like, like))
        for sql in (f"DELETE FROM approvals WHERE requester_id IN {users}", f"DELETE FROM expenses WHERE user_id IN {users}",
                    f"DELETE FROM payroll WHERE user_id IN {users}", f"DELETE FROM chat_messages WHERE user_id IN {users}",
                    f"DELETE FROM posts WHERE author_id IN {users}"):
            self.q(sql, (like,))
        self.q("DELETE FROM users WHERE username LIKE %s", (like,))


class Ctx:
    pass


RESULTS = []


def scenario(code, title):
    def deco(fn):
        def run(ctx):
            try:
                status, detail = fn(ctx)
            except Exception as exc:  # 점검 스크립트 자체의 오류도 결과에 남긴다
                status, detail = "FAIL", f"점검 중 예외: {type(exc).__name__}: {exc}"
            RESULTS.append((code, title, status, detail))
            print(f"[{status:5}] {code} {title} — {detail}")
        run.code = code
        return run
    return deco


def verdict(problems, ok_text):
    return ("PASS", ok_text) if not problems else ("FAIL", "; ".join(problems))


# ---------- 점검 시나리오 ----------
@scenario("D01", "보안 응답 헤더·버전 노출")
def d01(c):
    h = c.anon.get("/login").headers
    p = []
    csp = h.get("Content-Security-Policy", "")
    if "script-src 'self'" not in csp or "unsafe-inline" in csp or "frame-ancestors 'none'" not in csp:
        p.append("CSP 미흡")
    for k, v in (("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("Cache-Control", "no-store")):
        if h.get(k) != v:
            p.append(f"{k}={h.get(k)}")
    if h.get("Server") != "NEXUS" or re.search(r"(?i)werkzeug|python", str(h)):
        p.append(f"서버 버전 노출: {h.get('Server')}")
    return verdict(p, "CSP·X-Frame-Options·nosniff·Referrer-Policy·no-store 적용, 서버 버전 비노출")


@scenario("D02", "세션 쿠키 속성")
def d02(c):
    cookie = " ".join(c.login_cookies)
    p = [flag for flag in ("HttpOnly", "SameSite=Lax") if flag not in cookie]
    if os.environ.get("COOKIE_SECURE", "1") == "1" and "Secure" not in cookie:
        p.append("Secure")
    return verdict(p, f"HttpOnly·SameSite=Lax 적용(Secure 설정={os.environ.get('COOKIE_SECURE', '1')})")


@scenario("D03", "비로그인 접근 차단·CSRF")
def d03(c):
    p = []
    for path in ["/", "/chat", "/documents", "/documents/1", "/confidential", "/employees", "/boards/free", "/expenses", "/approvals",
                 "/payroll", "/finance", "/admin/users", "/account/password", "/attachments/1"]:
        r = c.anon.get(path)
        if not (r.status == 303 and "/login" in r.location):
            p.append(f"GET {path} → {r.status}")
    for path in ["/logout", "/boards/free/new", "/expenses/new", "/approvals/new", "/chat/messages", "/admin/users/1/role"]:
        r = c.anon.post(path, with_token=False)
        if r.status != 403:
            p.append(f"POST {path} → {r.status}")
    return verdict(p, "보호 화면 14종은 로그인으로 이동, 토큰 없는 POST 6종은 403")


@scenario("D04", "계정 열거 방지")
def d04(c):
    a = c.anon.login(PROBE + "emp", "wrong-Password-1!")
    b = c.anon.login("no_such_user_zz", "wrong-Password-1!")
    norm = lambda r: re.sub(r'value="[^"]*"', "", r.text)
    p = []
    if (a.status, b.status) != (401, 401):
        p.append(f"상태 {a.status}/{b.status}")
    if norm(a) != norm(b):
        p.append("존재하는 계정과 없는 계정의 실패 화면이 다르다")
    return verdict(p, f"둘 다 401, 응답 동일(응답 시간 {a.elapsed * 1000:.0f}ms / {b.elapsed * 1000:.0f}ms)")


@scenario("D05", "브루트포스 잠금과 관리자 해제")
def d05(c):
    lock = c.anon_fresh()
    codes = [lock.login(PROBE + "lock", f"wrong-Password-{i}!").status for i in range(5)]
    after = lock.login(PROBE + "lock", c.pw["lock"]).status                       # 잠긴 뒤에는 맞는 비밀번호도 거부
    unlocked = c.adm.post(f"/admin/users/{c.db.uid(PROBE + 'lock')}/unlock", token_from="/admin/users")
    back = lock.login(PROBE + "lock", c.pw["lock"]).status
    state = c.db.q("SELECT failed_count, locked_until FROM users WHERE username=%s", (PROBE + "lock",))[0]
    p = []
    if codes != [401] * 5 or after != 401:
        p.append(f"실패 {codes}, 잠금 후 {after}")
    if unlocked.status != 303 or back != 303 or state != (0, None):
        p.append(f"해제 {unlocked.status}, 해제 후 로그인 {back}, 상태 {state}")
    return verdict(p, "5회 실패→401×5, 잠금 중 올바른 비밀번호도 401, 관리자 해제 303 후 로그인 303·횟수 초기화")


@scenario("D06", "SQL 인젝션 탐침")
def d06(c):
    p, slow, base = [], [], c.db.counts()["users"]

    def inspect(label, r, ok_status):
        if r.status not in ok_status:
            p.append(f"{label} → {r.status}")
        if ERROR_LEAK.search(r.text):
            p.append(f"{label}: 오류 정보 노출")
        if r.elapsed > 3:
            slow.append(f"{label} {r.elapsed:.1f}s")

    for s in SQLI:
        inspect(f"로그인 '{s[:14]}'", c.anon.login(s, s), (401,))
        r = c.emp.get("/employees?" + urllib.parse.urlencode({"q": s}))
        inspect(f"직원검색 '{s[:14]}'", r, (200,))
        if "검색 결과가 없습니다" not in r.text:
            p.append(f"직원검색 '{s[:14]}': 결과가 비어 있지 않다(조건 우회 의심)")
        inspect(f"게시글 '{s[:14]}'", c.emp.post("/boards/free/new", {"title": s, "body": s}, token_from="/boards/free/new"), (303,))
        inspect(f"챗봇 '{s[:14]}'", c.emp.post("/chat/messages", {"message": s}, token_from="/chat"), (303,))
    enc = urllib.parse.quote("1' OR '1'='1", safe="")
    for path in (f"/documents/{enc}", f"/posts/{enc}", f"/expenses/{enc}", f"/payroll/{enc}"):
        inspect(path[:20], c.emp.get(path), (404,))
    inspect("page 값", c.emp.get(f"/boards/free?page={enc}"), (400,))
    if slow:
        p.append("지연 발생(시간 기반 인젝션 의심): " + ", ".join(slow))
    after = c.db.counts()["users"]
    if after != base:
        p.append(f"users 건수 변화 {base}→{after}")
    return verdict(p, f"로그인·직원검색·게시글·챗봇·ID·page에 {len(SQLI)}종 탐침: 오류 정보·지연·결과 확장·표 변경 없음")


@scenario("D07", "XSS 탐침(저장형·반사형)")
def d07(c):
    p = []
    for s in XSS:
        c.emp.post("/boards/free/new", {"title": s[:100], "body": s}, token_from="/boards/free/new")
        c.emp.post("/chat/messages", {"message": s}, token_from="/chat")
        c.emp.post("/expenses/new", {"title": s[:100], "amount": "1000"}, token_from="/expenses/new")
        c.emp.post("/approvals/new", {"title": s[:100], "body": s, "approver_1": str(c.db.uid(PROBE + "mgr"))}, token_from="/approvals/new")
    pages = ["/chat", "/boards/free", "/expenses", "/approvals"]
    html = "".join(c.emp.get(path).text for path in pages)
    html += "".join(c.emp.get("/employees?" + urllib.parse.urlencode({"q": s})).text for s in XSS)
    post_id = re.search(r"/posts/(\d+)", c.emp.get("/boards/free").text)
    if post_id:
        html += c.emp.get(f"/posts/{post_id.group(1)}").text
    for frag in RAW_XSS:
        if frag in html:
            p.append(f"이스케이프되지 않은 조각 발견: {frag}")
    if "&lt;script&gt;alert(1)&lt;/script&gt;" not in html:
        p.append("이스케이프된 형태가 보이지 않음(저장 실패 의심)")
    return verdict(p, f"{len(XSS)}종 입력을 게시글·챗봇·경비·결재·검색에 넣어 4개 화면과 상세를 조회: 모두 글자로만 표시")


@scenario("D08", "파일 업로드 우회(제한 없이 받되 무해하게 처리)")
def d08(c):
    """첨부는 형식·개수·용량을 제한하지 않는다(사용자 결정 2026-10-19). 그래서 '거부하는가'가 아니라 '받은 뒤에도 무해한가'를 점검한다:
    모두 무작위 이름으로 저장되고, 내려갈 때 항상 첨부+nosniff 이며, HTML·SVG 로 해석될 Content-Type 이 아니고, 그림·PDF 가 아닌 것은 인라인으로 열리지 않는다."""
    def count():
        return len(list(c.upload_dir.glob("*"))) if c.upload_dir.exists() else 0
    before, p, accepted = count(), [], 0
    files = [("shell.php", b"<?php echo 1; ?>"), ("shell.php.png", PNG), ("shell.png.php", PNG), ("page.html", b"<script>alert(1)</script>"),
             ("evil.svg", b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>"), (".htaccess", b"AddType application/x-httpd-php .png"),
             ("fake.png", b"<?php echo 1; ?>"), ("noext", b"hello"), ("big.txt", b"a" * (2 * 1024 * 1024 + 100))]
    for name, data in files:
        r = c.emp.post("/boards/free/new", {"title": "업로드 시험", "body": "x"}, token_from="/boards/free/new", files={"attachment": (name, data)})
        if r.status != 303:
            p.append(f"{name} → {r.status}(제한이 없으므로 받아야 함)")
            continue
        accepted += 1
        att = re.search(r"/attachments/(\d+)", c.emp.get(r.location).text)
        if not att:
            p.append(f"{name}: 첨부 링크가 글 화면에 없음")
            continue
        d = c.emp.get(f"/attachments/{att.group(1)}")
        h = {k.lower(): v for k, v in d.headers.items()}
        ctype = h.get("content-type", "")
        if d.status != 200 or not h.get("content-disposition", "").startswith("attachment") or h.get("x-content-type-options") != "nosniff":
            p.append(f"{name}: 다운로드가 첨부·nosniff 로 내려가지 않음")
        if ctype.startswith(("text/html", "image/svg", "application/xhtml", "text/xml", "application/xml")):
            p.append(f"{name}: Content-Type 이 {ctype} (브라우저가 문서로 해석할 위험)")
        v = c.emp.get(f"/attachments/{att.group(1)}/view")
        if v.status == 200 and not {k.lower(): x for k, x in v.headers.items()}.get("content-type", "").startswith(("image/png", "image/jpeg", "application/pdf")):
            p.append(f"{name}: 그림·PDF 가 아닌데 인라인으로 열림")
    # 프로필 사진은 첨부와 달리 그림만 받는다: 위험 파일은 400 으로 거부되고 upload_reject 이벤트가 남는다.
    for name, data in (("shell.php", b"<?php echo 1; ?>"), ("fake.png", b"<html>not a png</html>"), ("page.html", b"<script>alert(1)</script>")):
        r = c.emp.post("/account/photo", {}, token_from="/account/photo", files={"photo": (name, data)})
        if r.status != 400:
            p.append(f"프로필 사진 {name} → {r.status}(400 으로 거부돼야 함)")
    if count() != before + accepted:
        p.append(f"업로드 폴더 파일 수 변화 {count() - before}건(받은 {accepted}건과 불일치)")
    return verdict(p, f"위험 파일 {len(files)}종(2MB 초과 포함)을 모두 받아 무작위 이름으로 저장, 전부 첨부·nosniff 로만 내려가고 HTML·SVG 로 해석되지 않으며 인라인 표시 없음. 프로필 사진은 그림만 받아 위험 파일 3종 거부")


@scenario("D09", "경로 탐색·내부 파일 노출")
def d09(c):
    paths = ["/attachments/../../etc/passwd", "/static/../app/config.py", "/static/%2e%2e/app/config.py", "/documents/../../.env",
             "/..%2f..%2f.env", "/.env", "/.git/config", "/app/config.py", "/logs/security.jsonl", "/instance/uploads/",
             "/db/schema.sql", "/docker-compose.yml", "/static/..%5c..%5cconfig.py"]
    p = []
    for path in paths:
        for who, cl in (("비로그인", c.anon), ("직원", c.emp)):
            r = cl.get(path)
            if r.status not in (404, 303, 400) or re.search(r"SECRET_KEY|nexus_app|root:|MYSQL_ROOT", r.text):
                p.append(f"{who} {path} → {r.status}")
    return verdict(p, f"경로 {len(paths)}종을 비로그인·직원으로 요청: 모두 404/이동, 설정·비밀 내용 없음")


@scenario("D10", "권한 상승·타인 자료 접근(IDOR)")
def d10(c):
    d, p = c.data, []
    role_before = c.db.q("SELECT role FROM users WHERE username=%s", (PROBE + "emp",))[0][0]
    for path in (f"/payroll/{d['pay_mgr']}", f"/payroll/{d['pay_emp2']}", "/confidential", "/finance", "/admin/users",
                 f"/expenses/{d['exp']}", f"/approvals/{d['ap']}"):
        r = c.emp.get(path)
        if r.status != 403:
            p.append(f"직원 GET {path} → {r.status}")
    emp_id = c.db.uid(PROBE + "emp")
    tries = [(f"/admin/users/{emp_id}/role", {"role": "admin", "current_role": "employee"}), (f"/approvals/{d['ap']}/decide", {"decision": "approve"}),
             (f"/posts/{d['post']}/delete", {}), (f"/expenses/{d['exp']}/submit", {"approver_1": str(c.db.uid(PROBE + 'mgr'))})]
    for path, data in tries:
        r = c.emp.post(path, data)
        if r.status != 403:
            p.append(f"직원 POST {path} → {r.status}")
    if c.db.q("SELECT role FROM users WHERE username=%s", (PROBE + "emp",))[0][0] != role_before:
        p.append("역할이 바뀜")
    if c.mgr.get("/admin/users").status != 403 or c.mgr.get(f"/payroll/{d['pay_emp2']}").status != 200:
        p.append("팀장 범위 검사 이상(관리자 화면 403·같은 부서 급여 200 이어야 함)")
    if c.adm.get("/admin/users").status != 200:
        p.append("관리자 접근 불가")
    return verdict(p, "직원의 타인 급여·기밀·재무·관리자·타인 경비/결재 접근 403, 변경 시도 4종 403, 역할 불변, 팀장/관리자 범위 정상")


@scenario("D11", "CSRF 위조 요청")
def d11(c):
    p = []
    for path, data in (("/logout", {}), ("/boards/free/new", {"title": "csrf", "body": "x"}), ("/expenses/new", {"title": "csrf", "amount": "1"}),
                       ("/chat/messages", {"message": "csrf"}), ("/account/password", {"current_password": "x", "new_password": "y", "confirm_password": "y"})):
        for label, kw in (("토큰 없음", {"with_token": False}), ("틀린 토큰", {"with_token": False, "headers": {"X-CSRF-Token": "forged"}})):
            r = c.emp.post(path, data, **kw)
            if r.status != 403:
                p.append(f"{path} {label} → {r.status}")
    if c.emp.get("/").status != 200:
        p.append("위조 요청으로 세션이 끊김")
    return verdict(p, "5개 경로에 토큰 없음·틀린 토큰 위조 요청 10건 모두 403, 세션 유지")


@scenario("D12", "결재선 조작·자기 승인")
def d12(c):
    p, mgr, emp, emp2 = [], c.db.uid(PROBE + "mgr"), c.db.uid(PROBE + "emp"), c.db.uid(PROBE + "emp2")
    for label, fields in (("본인 지정", {"approver_1": str(emp)}), ("일반 직원 지정", {"approver_1": str(emp2)}),
                          ("중복 지정", {"approver_1": str(mgr), "approver_2": str(mgr)}), ("없는 사용자", {"approver_1": "999999"}),
                          ("결재자 없음", {})):
        r = c.emp.post("/approvals/new", {"title": "조작 시험", "body": "x", **fields}, token_from="/approvals/new")
        if r.status != 400:
            p.append(f"{label} → {r.status}")
    ok = c.emp.post("/approvals/new", {"title": "자기 승인 시험", "body": "x", "approver_1": str(mgr)}, token_from="/approvals/new")
    if ok.status != 303:
        p.append(f"정상 상신 {ok.status}")
    else:
        aid = ok.location.rsplit("/", 1)[1]
        if c.emp.post(f"/approvals/{aid}/decide", {"decision": "approve"}).status != 403:
            p.append("상신자가 자기 결재를 승인할 수 있음")
        if c.mgr.post(f"/approvals/{aid}/decide", {"decision": "reject", "reason": ""}).status != 400:
            p.append("반려 사유 없이 반려됨")
    return verdict(p, "본인·직원·중복·없는 결재자·결재자 없음 모두 400, 상신자 자기 승인 403, 사유 없는 반려 400")


@scenario("D13", "세션 위조·재사용")
def d13(c):
    p, name = [], "nexus_session"
    cookie = next((ck.value for ck in c.emp.jar if ck.name == name), "")
    tampered = cookie[:-3] + ("AAA" if not cookie.endswith("AAA") else "BBB")
    for label, value in (("변조", tampered), ("무작위", secrets.token_urlsafe(60))):
        r = Client(c.base, c.pacer, cookie=f"{name}={value}").get("/")
        if not (r.status == 303 and "/login" in r.location):
            p.append(f"{label} 쿠키 → {r.status}")
    # 로그아웃은 같은 사용자의 모든 세션을 끊으므로, 다른 점검이 쓰는 emp 가 아니라 emp2 로 시험한다
    def cookie_of(client):
        return next((ck.value for ck in client.jar if ck.name == name), "")

    def replay(value):
        return Client(c.base, c.pacer, cookie=f"{name}={value}").get("/")
    a, b = c.fresh_client(), c.fresh_client()
    a.login(PROBE + "emp2", c.pw["emp2"])
    b.login(PROBE + "emp2", c.pw["emp2"])
    saved_a, saved_b = cookie_of(a), cookie_of(b)
    if replay(saved_a).status != 200:
        p.append("로그아웃 전 정상 쿠키가 거부됨")
    a.post("/logout")
    r = replay(saved_a)
    if not (r.status == 303 and "/login" in r.location):
        return ("LIMIT" if r.status == 200 else "FAIL"), f"로그아웃 후 이전 쿠키 → {r.status}"
    if replay(saved_b).status != 303:
        p.append("로그아웃했는데 같은 사용자의 다른 기기 세션이 살아 있음")
    # 비밀번호 변경 후에는 변경 전에 발급된 쿠키가 모두 무효여야 한다
    a.login(PROBE + "emp2", c.pw["emp2"])
    b.login(PROBE + "emp2", c.pw["emp2"])
    saved_b = cookie_of(b)
    new_pw = secrets.token_urlsafe(14) + "aA1!"
    changed = a.post("/account/password", {"current_password": c.pw["emp2"], "new_password": new_pw, "confirm_password": new_pw})
    c.pw["emp2"] = new_pw
    if changed.status != 303 or replay(saved_b).status != 303:
        p.append(f"비밀번호 변경({changed.status}) 후 이전 쿠키가 살아 있음")
    if a.get("/").status != 200:
        p.append("비밀번호를 바꾼 기기의 새 세션이 거부됨")
    return verdict(p, "변조·무작위 쿠키 차단, 로그아웃·비밀번호 변경 후에는 이전 쿠키(다른 기기 포함)도 거부, 변경한 기기만 새 세션 유지")


@scenario("D14", "메서드 변조·오류 화면 정보 노출")
def d14(c):
    p = []
    for method, path in (("PUT", "/login"), ("DELETE", "/documents/1"), ("PATCH", "/"), ("PUT", "/admin/users/1/role"), ("DELETE", "/posts/1")):
        r = c.emp.request(method, path)
        if r.status not in (403, 405):
            p.append(f"{method} {path} → {r.status}")
    pages = {"404": c.emp.get("/no/such/page"), "405": c.emp.request("PUT", "/login"), "400": c.emp.get("/boards/free?page=abc")}
    for label, r in pages.items():
        if ERROR_LEAK.search(r.text) or re.search(r"(?i)werkzeug|python", str(r.headers)):
            p.append(f"{label} 화면에 내부 정보")
    return verdict(p, "허용되지 않은 메서드는 403/405, 404·405·400 화면에 스택트레이스·서버 버전 없음")


@scenario("D15", "웹 스캔(경로 탐색 도구 흉내)")
def d15(c):
    codes = [c.anon.get("/" + path).status for path in SCAN_PATHS]
    # /api/v1/* 는 메신저(nexus-messenger)용 토큰 인증 API 라서 실제로 있는 경로다. 토큰 없이 부르면 401 이 정상이고 내용은 새지 않는다.
    odd = [(path, code) for path, code in zip(SCAN_PATHS, codes) if code != (401 if path.startswith("api/v1/") else 404)]
    return verdict([f"{p} → {code}" for p, code in odd], f"흔한 관리·백업·설정 경로 {len(SCAN_PATHS)}개 모두 404(not_found 이벤트 생성), 메신저 API 경로는 토큰 없이 401")


@scenario("D16", "속도 제한(로그인 IP·챗봇)")
def d16(c):
    if c.skip_rate:
        return "SKIP", "--skip-rate-limit 로 건너뜀"
    p, limit = [], c.login_limit
    c.pacer.times.clear()
    hit = None
    for i in range(limit + 6):                      # 이 요청들은 일부러 속도 제한 한도를 넘긴다
        r = c.fresh_client().post("/login", {"username": "no_such_user_zz", "password": "x"}, token_from="/login")
        if r.status == 429:
            hit = i + 1
            break
    if not hit:
        p.append(f"로그인 {limit + 6}회에도 429 없음")
    chat_hit = None
    for i in range(40):
        r = c.emp.post("/chat/messages", {"message": f"속도 시험 {i}"}, token_from="/chat")
        if r.status == 429:
            chat_hit = i + 1
            break
    if not chat_hit:
        p.append("챗봇 40회에도 429 없음")
    return verdict(p, f"로그인은 {hit}번째 요청에서, 챗봇은 {chat_hit}번째 메시지에서 429")


@scenario("D17", "보안 로그 기록과 민감정보 비노출")
def d17(c):
    new = c.read_log()
    if new is None:
        return "FAIL", "로그 파일을 읽지 못함"
    events, bad_lines = {}, 0
    for line in new:
        try:
            e = json.loads(line)
        except ValueError:
            bad_lines += 1
            continue
        if not all(k in e for k in ("ts", "event_type", "user", "role", "src_ip", "method", "path", "decision", "reason")):
            bad_lines += 1
        events[e["event_type"]] = events.get(e["event_type"], 0) + 1
    c.event_counts = events
    p = []
    need = ["login_success", "login_failure", "account_locked", "login_locked", "authz_deny", "csrf_fail", "upload_reject", "input_rejected",
            "not_found", "approval_created", "post_created", "chat_message", "admin_action", "suspicious_input"]
    if not c.skip_rate:
        need.append("rate_limited")
    p += [f"{n} 없음" for n in need if n not in events]
    if bad_lines:
        p.append(f"형식 오류 {bad_lines}줄")
    blob = "\n".join(new)
    if any(pw in blob for pw in c.pw.values()) or "wrong-Password" in blob or "속도 시험" in blob:
        p.append("로그에 비밀번호 또는 대화 내용이 남음")
    return verdict(p, f"새 로그 {len(new)}줄 모두 표준 필드의 JSON, 필요한 이벤트 {len(need)}종 확인, 비밀번호·대화 내용 없음")


# ---------- 실행 ----------
def read_log_from(path, offset):
    def reader():
        try:
            with open(path, "rb") as f:
                f.seek(offset)
                return [l for l in f.read().decode("utf-8", "replace").splitlines() if l]
        except OSError:
            return None
    return reader


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:5070")
    ap.add_argument("--report")
    ap.add_argument("--skip-rate-limit", action="store_true")
    ap.add_argument("--login-limit", type=int, default=20)
    a = ap.parse_args()
    host = urllib.parse.urlparse(a.base).hostname
    if host not in LOOPBACK:
        sys.exit(f"거부: {host} 는 루프백이 아니다. 이 스크립트는 내 PC 의 실습 환경에만 사용한다.")

    pacer = Pacer(a.login_limit)
    ph, db = PasswordHasher(), Db()
    c = Ctx()
    c.base, c.pacer, c.db, c.skip_rate, c.login_limit = a.base.rstrip("/"), pacer, db, a.skip_rate_limit, a.login_limit
    c.upload_dir = Path(os.environ.get("UPLOAD_DIR", ROOT / "instance" / "uploads"))
    c.fresh_client = lambda: Client(c.base, pacer)
    c.anon_fresh = c.fresh_client
    c.anon = c.fresh_client()
    log_path = ROOT / "logs" / "security.jsonl"
    offset = log_path.stat().st_size if log_path.exists() else 0
    c.read_log = read_log_from(log_path, offset)

    try:
        c.anon.get("/healthz")
    except Exception as exc:
        sys.exit(f"서버에 접속할 수 없다({a.base}): {exc}")

    db.cleanup(c.upload_dir)                         # 이전 실행의 잔여물 제거
    baseline = db.counts()
    c.pw = {k: secrets.token_urlsafe(14) + "aA1!" for k in ("adm", "mgr", "emp", "emp2", "lock")}
    for key, role in (("adm", "admin"), ("mgr", "manager"), ("emp", "employee"), ("emp2", "employee"), ("lock", "employee")):
        db.q("INSERT INTO users(username,password_hash,role,display_name,dept) VALUES(%s,%s,%s,%s,'프로브팀')",
             (PROBE + key, ph.hash(c.pw[key]), role, PROBE + key))
    u = {k: db.uid(PROBE + k) for k in c.pw}
    db.q("INSERT INTO payroll(user_id,pay_month,base_salary,bonus) VALUES(%s,'2026-09',4000000,0)", (u["mgr"],))
    pay_mgr = db.q("SELECT id FROM payroll WHERE user_id=%s", (u["mgr"],))[0][0]
    db.q("INSERT INTO payroll(user_id,pay_month,base_salary,bonus) VALUES(%s,'2026-09',3000000,0)", (u["emp2"],))
    pay_emp2 = db.q("SELECT id FROM payroll WHERE user_id=%s", (u["emp2"],))[0][0]
    db.q("INSERT INTO expenses(user_id,title,amount,status) VALUES(%s,'zz 프로브 경비',1000,'draft')", (u["emp2"],))
    exp = db.q("SELECT id FROM expenses WHERE user_id=%s", (u["emp2"],))[0][0]
    db.q("INSERT INTO approvals(title,body,requester_id,status) VALUES('zz 프로브 결재','x',%s,'pending')", (u["emp2"],))
    ap_id = db.q("SELECT id FROM approvals WHERE requester_id=%s", (u["emp2"],))[0][0]
    db.q("INSERT INTO approval_steps(approval_id,step_no,approver_id,status) VALUES(%s,1,%s,'pending')", (ap_id, u["mgr"]))
    db.q("INSERT INTO posts(board,author_id,title,body) VALUES('free',%s,'zz 프로브 글','x')", (u["emp2"],))
    post_id = db.q("SELECT id FROM posts WHERE author_id=%s", (u["emp2"],))[0][0]
    c.data = {"pay_mgr": pay_mgr, "pay_emp2": pay_emp2, "exp": exp, "ap": ap_id, "post": post_id}

    started = datetime.now()
    print(f"방어 점검 시작 {started:%Y-%m-%d %H:%M:%S} · 대상 {c.base} · DB {db.name}\n")
    try:
        c.adm, c.mgr, c.emp = c.fresh_client(), c.fresh_client(), c.fresh_client()
        logins = [(c.adm, "adm"), (c.mgr, "mgr"), (c.emp, "emp")]
        c.login_cookies = []
        for client, key in logins:
            r = client.login(PROBE + key, c.pw[key])
            if r.status != 303:
                sys.exit(f"점검용 계정 로그인 실패({key}: {r.status}) — 서버가 같은 DB 를 쓰는지, 로그인 속도 제한에 걸리지 않았는지 확인")
            if key == "emp":
                c.login_cookies = r.set_cookies
        for fn in (d01, d02, d03, d04, d05, d06, d07, d08, d09, d10, d11, d12, d13, d14, d15, d16):
            fn(c)
        d17(c)
    finally:
        db.cleanup(c.upload_dir)
        after = db.counts()
    clean = after == baseline
    RESULTS.append(("D18", "점검 데이터 정리", "PASS" if clean else "FAIL",
                    "점검용 계정·글·경비·결재·급여·대화·업로드 파일을 모두 삭제했고 표별 건수가 점검 전과 같다" if clean else f"건수 불일치 {baseline} → {after}"))
    print(f"[{RESULTS[-1][2]:5}] D18 {RESULTS[-1][1]} — {RESULTS[-1][3]}")

    tally = {s: sum(1 for r in RESULTS if r[2] == s) for s in ("PASS", "FAIL", "LIMIT", "SKIP")}
    print(f"\n요약: PASS {tally['PASS']} · FAIL {tally['FAIL']} · 알려진 한계 {tally['LIMIT']} · 건너뜀 {tally['SKIP']}")
    if a.report:
        write_report(Path(a.report), a, started, db.name, RESULTS, tally, getattr(c, "event_counts", {}))
        print(f"보고서: {a.report}")
    sys.exit(1 if tally["FAIL"] else 0)


def write_report(path, a, started, dbname, results, tally, events):
    label = {"PASS": "통과", "FAIL": "실패", "LIMIT": "알려진 한계", "SKIP": "건너뜀"}
    lines = [f"# 방어 점검 결과 (역할 A: 앱·DB 하드닝)", "",
             f"- 실행: {started:%Y-%m-%d %H:%M:%S} · 대상 `{a.base}`(루프백) · DB `{dbname}`",
             f"- 도구: `scripts/defense_check.py` (직접 작성한 블랙박스 점검. sqlmap 등 외부 도구는 설치하지 않았다)",
             f"- 요약: 통과 {tally['PASS']} · 실패 {tally['FAIL']} · 알려진 한계 {tally['LIMIT']} · 건너뜀 {tally['SKIP']}", "",
             "| 번호 | 점검 | 결과 | 근거 |", "|---|---|---|---|"]
    for code, title, status, detail in results:
        lines.append(f"| {code} | {title} | {label[status]} | {detail.replace('|', '/')} |")
    if events:
        lines += ["", "## 점검 중 새로 쌓인 보안 이벤트", "", "| event_type | 건수 |", "|---|---|"]
        lines += [f"| `{k}` | {v} |" for k, v in sorted(events.items(), key=lambda kv: -kv[1])]
    lines += ["", "점검용 데이터는 모두 삭제했다(D18). 비밀번호 등 비밀값은 이 문서에 기록하지 않는다.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
