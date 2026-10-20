"""화면 전반 점검: CSP 호환 마크업, 접근성 기본, 결재란·기밀 도장 표시, 색 대비. Docker MySQL(nexus_test) 필요, 접속 불가면 skip."""
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from support import as_user, sql, uid

CSS = (Path(__file__).resolve().parents[1] / "app" / "static" / "style.css").read_text(encoding="utf-8")


# ---------- 도우미 ----------
class Page(HTMLParser):
    """입력 칸의 라벨 연결, POST 폼의 CSRF 토큰, 제목 수를 모은다."""
    def __init__(self):
        super().__init__()
        self.h1 = self.label_depth = 0
        self.unlabeled, self.post_forms, self.forms_with_csrf = [], 0, 0
        self._form_stack = []
        self.aria_current = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "h1":
            self.h1 += 1
        if tag == "label":
            self.label_depth += 1
        if a.get("aria-current") == "page":
            self.aria_current += 1
        if tag == "form":
            self._form_stack.append({"post": (a.get("method") or "get").lower() == "post", "csrf": False})
        if tag == "input" and a.get("name") == "csrf_token" and self._form_stack:
            self._form_stack[-1]["csrf"] = True
        control = tag in ("select", "textarea") or (tag == "input" and a.get("type") not in ("hidden", "submit"))
        if control and not self.label_depth and not a.get("aria-label"):
            self.unlabeled.append(f"{tag} name={a.get('name')}")

    def handle_endtag(self, tag):
        if tag == "label":
            self.label_depth -= 1
        if tag == "form" and self._form_stack:
            f = self._form_stack.pop()
            if f["post"]:
                self.post_forms += 1
                self.forms_with_csrf += f["csrf"]


def parse(html):
    p = Page()
    p.feed(html)
    return p


def ins(root, query, args=()):
    with root.cursor() as cur:
        cur.execute(query, args)
        return cur.lastrowid


@pytest.fixture()
def data(root):
    u = lambda n: uid(root, n)
    d = {}
    d["doc"] = ins(root, "INSERT INTO documents(title,body) VALUES('zz_문서','본문')")
    d["conf"] = ins(root, "INSERT INTO confidential_documents(title,body) VALUES('zz_기밀','본문')")
    d["report"] = ins(root, "INSERT INTO financial_reports(report_month,title,body) VALUES('2026-09','zz_보고','본문')")
    d["pay"] = ins(root, "INSERT INTO payroll(user_id,pay_month,base_salary,bonus) VALUES(%s,'2026-09',3000000,100000)", (u("zz_emp"),))
    d["post"] = ins(root, "INSERT INTO posts(board,author_id,title,body) VALUES('free',%s,'zz_글','본문')", (u("zz_emp"),))
    d["exp"] = ins(root, "INSERT INTO expenses(user_id,title,amount,status) VALUES(%s,'zz_경비',45000,'submitted')", (u("zz_emp"),))
    # 결재: 1차 승인 완료, 2차 차례, 3차 대기
    d["ap"] = ins(root, "INSERT INTO approvals(title,body,requester_id,expense_id,current_step) VALUES('zz_결재','본문',%s,%s,2)", (u("zz_emp"), d["exp"]))
    for n, (name, st) in enumerate((("zz_mgr", "approved"), ("zz_mgrb", "pending"), ("zz_adm", "waiting")), start=1):
        ins(root, "INSERT INTO approval_steps(approval_id,step_no,approver_id,status) VALUES(%s,%s,%s,%s)", (d["ap"], n, u(name), st))
    # 결재: 1차 반려(사유 포함), 2차 건너뜀
    d["rej"] = ins(root, "INSERT INTO approvals(title,body,requester_id,status,decided_at) VALUES('zz_반려문서','본문',%s,'rejected',NOW())", (u("zz_emp"),))
    ins(root, "INSERT INTO approval_steps(approval_id,step_no,approver_id,status,reason,decided_at) VALUES(%s,1,%s,'rejected','증빙 부족',NOW())", (d["rej"], u("zz_mgr")))
    ins(root, "INSERT INTO approval_steps(approval_id,step_no,approver_id,status) VALUES(%s,2,%s,'skipped')", (d["rej"], u("zz_adm")))
    # 업무·자료
    d["task"] = ins(root, "INSERT INTO tasks(title,creator_id,assignee_id) VALUES('zz_업무',%s,%s)", (u("zz_emp"), u("zz_emp")))
    d["project"] = ins(root, "INSERT INTO projects(name,owner_id) VALUES('zz_프로젝트',%s)", (u("zz_mgr"),))
    d["event"] = ins(root, "INSERT INTO events(owner_id,title,start_at,end_at,scope) VALUES(%s,'zz_일정',NOW(),NOW(),'company')", (u("zz_emp"),))
    d["resource"] = ins(root, "INSERT INTO resources(name,kind) VALUES('zz_회의실','room')")
    d["folder"] = ins(root, "INSERT INTO lib_folders(name,scope,created_by) VALUES('zz_폴더','company',%s)", (u("zz_adm"),))
    return d


def pages(d):
    return ["/", "/chat", "/documents", f"/documents/{d['doc']}", "/confidential", f"/confidential/{d['conf']}",
            "/boards/free", "/boards/notice", "/boards/free/new", f"/posts/{d['post']}", "/expenses", "/expenses/new",
            f"/expenses/{d['exp']}", "/approvals", "/approvals/new", f"/approvals/{d['ap']}", f"/approvals/{d['rej']}",
            "/payroll", f"/payroll/{d['pay']}", "/finance", f"/finance/{d['report']}", "/admin/users", "/account/password",
            "/account/photo", "/hr/cards", "/hr/org", "/hr/attendance", "/hr/leave", "/hr/leave/new",
            "/admin/overview", "/admin/audit", "/admin/audit?period=7d", "/admin/audit?period=30d", "/admin/permissions", "/admin/users/new", "/approvals/new?type=expenditure",
            "/work/tasks", "/work/tasks?box=team", "/work/tasks/new", f"/work/tasks/{d['task']}", "/work/calendar", "/work/events/new",
            f"/work/events/{d['event']}", "/work/reservations", f"/work/reservations/new?resource_id={d['resource']}", "/work/projects",
            "/work/projects/new", f"/work/projects/{d['project']}", "/library", f"/library/folders/{d['folder']}", "/library/contacts",
            "/library/contacts?tab=shared", "/library/contacts/new", "/library/search", "/library/search?q=zz", "/library/forms"]


# ---------- 모든 화면 공통 ----------
def test_every_page_is_csp_safe_and_accessible(aapp, data):
    c = as_user(aapp, "zz_sec")                     # 보안관제팀(고정 관리자): 보안 대시보드까지 모든 화면을 연다
    for path in pages(data):
        r = c.get(path)
        assert r.status_code == 200, path
        html = r.get_data(as_text=True)
        assert '<html lang="ko">' in html, path
        assert not re.search(r"\sstyle=|\son[a-z]+=|javascript:", html), path                       # CSP: 인라인 스타일·핸들러 없음
        # 스크립트는 같은 출처 /static/ 파일(src)만 허용하고 인라인 스크립트는 없다
        assert all(re.fullmatch(r'<script src="/static/[\w.-]+\.js"(?: defer)?></script>', t)
                   for t in re.findall(r"<script\b.*?</script>", html, re.S)), path
        assert not re.search(r"""(?:src|href|action)=["']https?://""", html), path                    # 외부 리소스 없음
        assert 'class="skip" href="#main"' in html and 'id="main"' in html, path
        assert '<nav aria-label="주 메뉴">' in html, path
        p = parse(html)
        assert p.h1 == 1, f"{path}: h1 {p.h1}개"
        assert not p.unlabeled, f"{path}: 라벨 없는 입력 {p.unlabeled}"
        assert p.forms_with_csrf == p.post_forms, f"{path}: CSRF 토큰 없는 POST 폼"
        assert p.aria_current <= 1, path


def test_login_and_error_pages_use_the_plain_layout(aapp):
    html = aapp.test_client().get("/login").get_data(as_text=True)
    assert 'class="plain"' in html and "주 메뉴" not in html and 'type="password"' in html
    err = aapp.test_client().get("/no/such/page")
    assert err.status_code == 404 and "404" in err.get_data(as_text=True)
    assert not re.search(r"\sstyle=|<script", err.get_data(as_text=True))


def test_navigation_marks_the_current_section(aapp, data):
    c = as_user(aapp, "zz_adm")
    for path, label in (("/chat", "AI 어시스턴트"), ("/approvals", "전자결재"), ("/expenses", "경비"), ("/documents", "문서함"), ("/payroll", "급여"),
                        ("/admin/users", "사용자 관리"), ("/boards/free", "자유게시판"), ("/boards/notice", "공지사항"),
                        ("/finance", "재무 보고"), ("/confidential", "기밀 문서함"),
                        ("/work/tasks", "업무 관리"), ("/work/calendar", "일정"), ("/work/reservations", "예약"), ("/work/projects", "프로젝트"),
                        ("/library", "자료실"), ("/library/search", "문서 검색"), ("/library/forms", "양식 모음"), ("/library/contacts", "주소록")):
        html = c.get(path).get_data(as_text=True)
        assert re.search(rf'<a href="[^"]+" aria-current="page">{label}</a>', html), path


def test_navigation_groups_are_role_aware(aapp):
    emp = as_user(aapp, "zz_emp").get("/").get_data(as_text=True)
    assert "<h2>관리</h2>" not in emp and "재무" not in emp.replace("재무 보고", "") and "기밀 문서함" not in emp
    mgr = as_user(aapp, "zz_mgr").get("/").get_data(as_text=True)
    assert "재무 보고" in mgr and "기밀 문서함" in mgr and "<h2>관리</h2>" not in mgr
    assert "<h2>관리</h2>" in as_user(aapp, "zz_adm").get("/").get_data(as_text=True)


# ---------- 결재란과 도장 ----------
def test_approval_seals_show_each_step_state(aapp, data):
    html = as_user(aapp, "zz_adm").get(f"/approvals/{data['ap']}").get_data(as_text=True)
    assert 'class="seals"' in html and html.count('class="seal-cell') == 4          # 상신 + 3단계
    assert "1차 결재" in html and "2차 결재" in html and "3차 결재" in html
    assert html.count('class="stamp ok"') == 1 and "stamp no" not in html          # 1차만 승인 도장
    assert html.count("seal-cell turn") == 1                                         # 지금 차례인 칸은 하나
    turn = re.search(r'<li class="seal-cell turn">.*?</li>', html, re.S).group(0)
    assert "zz_mgrb" in turn and "결재 대기" in turn
    assert "순서 대기" in html                                                         # 3차는 아직 순서 전


def test_rejected_approval_shows_red_stamp_skipped_cell_and_reason(aapp, data):
    html = as_user(aapp, "zz_emp").get(f"/approvals/{data['rej']}").get_data(as_text=True)
    assert html.count('class="stamp no"') == 1 and "stamp ok" not in html and "seal-cell turn" not in html
    assert "건너뜀" in html and "증빙 부족" in html and "1차 zz_mgr 반려 사유" in html


def test_approval_state_is_never_conveyed_by_color_alone(aapp, data):
    html = as_user(aapp, "zz_adm").get("/approvals").get_data(as_text=True)
    assert re.search(r'<span class="st st-pending">결재 대기</span>', html)           # 색 + 글자 + 점선 테두리
    assert re.search(r'<span class="st st-rejected">반려</span>', html)
    css_status = re.search(r"\.st-pending\s*\{[^}]*dashed", CSS)
    assert css_status, "대기 상태는 점선 테두리로도 구분되어야 한다"


# ---------- 기밀 도장 ----------
@pytest.mark.parametrize("path_key,expected", [
    ("/confidential", True), ("/confidential/{conf}", True), ("/payroll", True), ("/payroll/{pay}", True),
    ("/finance", True), ("/finance/{report}", True),
    ("/documents", False), ("/documents/{doc}", False), ("/library/contacts", False), ("/boards/free", False),
    ("/expenses", False), ("/approvals", False),
])
def test_confidential_stamp_only_on_confidential_pages(aapp, data, path_key, expected):
    html = as_user(aapp, "zz_adm").get(path_key.format(**data)).get_data(as_text=True)
    assert ('class="stamp-conf"' in html) is expected


# ---------- CSS: 색 대비와 외부 의존성 ----------
def lum(hex_color):
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def contrast(a, b):
    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def token(name):
    return re.search(rf"--{name}:\s*(#[0-9a-fA-F]{{6}})", CSS).group(1)


@pytest.mark.parametrize("fg,bg", [
    ("ink", "paper"), ("ink", "sheet"), ("ink-2", "paper"), ("ink-2", "sheet"), ("pen", "sheet"), ("pen", "paper"),
    ("seal", "sheet"), ("seal", "seal-bg"), ("side-text", "side"), ("side-muted", "side"),
    ("ok", "sheet"), ("warn", "sheet"), ("pen", "sheet"),
])
def test_text_color_pairs_meet_wcag_aa(fg, bg):
    assert contrast(token(fg), token(bg)) >= 4.5, (fg, bg, contrast(token(fg), token(bg)))


def test_filled_buttons_and_alerts_meet_contrast():
    assert contrast("#ffffff", token("pen")) >= 4.5
    assert contrast("#ffffff", token("gray-btn")) >= 4.5          # 로그아웃 버튼(흰 글자)
    assert contrast("#ffffff", "#46557c") >= 4.5                  # 그 버튼에 마우스를 올렸을 때
    assert contrast("#ffffff", "#0a3fb8") >= 4.5                  # 파란 버튼에 마우스를 올렸을 때
    assert contrast("#ffffff", "#173d7c") >= 4.5                  # 마우스를 올렸을 때의 파란 버튼
    assert contrast("#8f0c21", token("seal-bg")) >= 4.5           # 경고 상자 글자


def test_css_has_no_external_dependencies_and_keeps_focus_and_reduced_motion():
    assert not re.search(r"@import|url\(\s*['\"]?https?:", CSS)
    assert ":focus-visible" in CSS and "prefers-reduced-motion" in CSS and "@media (max-width: 860px)" in CSS
