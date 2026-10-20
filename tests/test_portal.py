"""포털 통합 테스트(문서함·기밀·직원 검색·게시판·첨부). Docker MySQL(nexus_test) 필요, 접속 불가면 skip."""
import io
import re

import pytest

from support import PW, csrf_of, login, post, sql

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


# ---------- 도우미 ----------
def uid(root, name):
    return sql(root, "SELECT id FROM users WHERE username=%s", (name,))[0][0]


def add_doc(root, title, body, table="documents"):
    assert table in ("documents", "confidential_documents")
    with root.cursor() as cur:
        cur.execute(f"INSERT INTO {table}(title,body) VALUES(%s,%s)", (title, body))
        return cur.lastrowid


def add_post(root, author, board, title, body="본문"):
    with root.cursor() as cur:
        cur.execute("INSERT INTO posts(board,author_id,title,body) VALUES(%s,%s,%s,%s)",
                    (board, uid(root, author), title, body))
        return cur.lastrowid


def add_employee(root, name, dept="영업팀", title="사원", ext="1000"):
    sql(root, "INSERT INTO employees(name,dept,title,ext) VALUES(%s,%s,%s,%s)", (name, dept, title, ext))


def as_user(app, name):
    c = app.test_client()
    assert login(c, name).status_code == 303
    return c


def new_post(client, board, title="zz_제목", body="내용", file=None):
    data = {"title": title, "body": body, "csrf_token": csrf_of(client)}
    if file:
        data["attachment"] = (io.BytesIO(file[1]), file[0])
    return client.post(f"/boards/{board}/new", data=data, content_type="multipart/form-data")


def stored_files(app):
    d = app.config["UPLOAD_DIR"]
    return sorted(p.name for p in d.glob("*")) if d.exists() else []


def count_posts(root, title):
    return sql(root, "SELECT COUNT(*) FROM posts WHERE title=%s", (title,))[0][0]


# ---------- 로그인 필수 ----------
@pytest.mark.parametrize("path", ["/documents", "/documents/1", "/confidential", "/confidential/1", "/library/contacts",
                                  "/boards/free", "/boards/notice", "/boards/free/new", "/posts/1", "/attachments/1",
                                  "/account/password"])
def test_every_page_requires_login(aapp, path):
    r = aapp.test_client().get(path)
    assert r.status_code == 303 and "/login" in r.headers["Location"]


def test_anonymous_post_requests_are_blocked(aapp):
    c = aapp.test_client()
    assert c.post("/boards/free/new", data={"title": "x", "body": "y"}).status_code == 403  # CSRF 단계에서 차단
    assert c.post("/posts/1/delete").status_code == 403


# ---------- 일반 문서함 ----------
def test_general_documents_list_and_detail_are_escaped(aapp, root):
    did = add_doc(root, "zz_공지문서", "<script>alert(1)</script> & <b>굵게</b>")
    c = as_user(aapp, "zz_emp")
    html = c.get("/documents").get_data(as_text=True)
    assert "zz_공지문서" in html
    detail = c.get(f"/documents/{did}").get_data(as_text=True)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in detail and "<script" not in detail and "<b>굵게" not in detail


@pytest.mark.parametrize("path", ["/documents/999999", "/documents/abc", "/documents/-1", "/documents/99999999999999999999",
                                  "/documents/1%27%20OR%201=1"])
def test_bad_document_ids_are_404_not_500(aapp, path):
    assert as_user(aapp, "zz_emp").get(path).status_code == 404


# ---------- 기밀 문서함 ----------
def test_employee_cannot_open_confidential_documents(aapp, root, events):
    cid = add_doc(root, "zz_M&A", "TOP-SECRET-BODY", "confidential_documents")
    c = as_user(aapp, "zz_emp")
    for path in ("/confidential", f"/confidential/{cid}"):
        r = c.get(path)
        assert r.status_code == 403 and "TOP-SECRET-BODY" not in r.get_data(as_text=True)
    denied = [e for e in events() if e["event_type"] == "authz_deny" and e["reason"] == "insufficient_role"]
    assert len(denied) == 2 and denied[-1]["path"] == f"/confidential/{cid}" and denied[-1]["user"] == "zz_emp"


def test_manager_and_admin_can_read_confidential_and_it_is_logged(aapp, root, events):
    cid = add_doc(root, "zz_M&A", "TOP-SECRET-BODY", "confidential_documents")
    for name in ("zz_mgr", "zz_adm"):
        c = as_user(aapp, name)
        assert "zz_M&amp;A" in c.get("/confidential").get_data(as_text=True)
        assert "TOP-SECRET-BODY" in c.get(f"/confidential/{cid}").get_data(as_text=True)
    reads = [e for e in events() if e["event_type"] == "confidential_access" and e["reason"] == "read"]
    assert {e["user"] for e in reads} == {"zz_mgr", "zz_adm"} and all(e["resource_id"] == cid for e in reads)


def test_confidential_content_never_leaks_through_general_paths(aapp, root):
    cid = add_doc(root, "zz_conf", "TOP-SECRET-BODY", "confidential_documents")
    add_doc(root, "zz_general", "공개 내용")
    c = as_user(aapp, "zz_mgr")  # 기밀 권한이 있는 계정으로도 일반 경로에는 나오지 않아야 한다
    assert "zz_conf" not in c.get("/documents").get_data(as_text=True)
    assert "TOP-SECRET-BODY" not in c.get(f"/documents/{cid}").get_data(as_text=True)
    assert "TOP-SECRET-BODY" not in c.get("/library/contacts?tab=company&q=zz_").get_data(as_text=True)


def test_nav_shows_confidential_link_only_to_privileged_roles(aapp):
    emp = as_user(aapp, "zz_emp").get("/").get_data(as_text=True)
    mgr = as_user(aapp, "zz_mgr").get("/").get_data(as_text=True)
    assert "기밀 문서함" not in emp and "기밀 문서함" in mgr


# ---------- 직원 검색(주소록의 사내 직원 탭) ----------
def test_employee_search_by_name_dept_and_title(aapp, root):
    add_employee(root, "zz_alpha", "영업팀", "사원")
    add_employee(root, "zzXalpha", "개발팀", "대리")
    add_employee(root, "zz_beta", "영업팀", "과장")
    c = as_user(aapp, "zz_emp")
    html = c.get("/library/contacts?tab=company&q=zz_alpha").get_data(as_text=True)
    assert "zz_alpha" in html and "zzXalpha" not in html            # '_' 는 와일드카드가 아니라 문자 그대로
    html = c.get("/library/contacts?tab=company&q=영업").get_data(as_text=True)
    assert "zz_alpha" in html and "zz_beta" in html and "zzXalpha" not in html
    assert "zz_beta" in c.get("/library/contacts?tab=company&q=과장").get_data(as_text=True)


def test_like_wildcards_are_literal(aapp, root):
    add_employee(root, "zz_one")
    add_employee(root, "zz_two")
    c = as_user(aapp, "zz_emp")
    assert "검색 결과가 없습니다" in c.get("/library/contacts?tab=company&q=%25").get_data(as_text=True)      # q=%  → 전체 일치 아님
    assert "검색 결과가 없습니다" in c.get("/library/contacts?tab=company&q=zz%25one").get_data(as_text=True)


def test_employee_search_sql_injection_returns_nothing(aapp, root):
    add_employee(root, "zz_alpha")
    c = as_user(aapp, "zz_emp")
    short = ("' OR 1=1 -- ", "x' UNION SELECT username,2,3,4 FROM users-- ", "\\", "%' OR '%'='", "x') OR ('1'='1")
    for payload in short:  # 길이 한도(50자) 안의 페이로드는 검색어로만 취급되어 결과가 없다
        r = c.get("/library/contacts", query_string={"tab": "company", "q": payload})
        html = r.get_data(as_text=True)
        assert r.status_code == 200 and "zz_alpha" not in html and "argon2" not in html, payload
    long_payload = "zz' UNION SELECT username,password_hash,role,dept FROM users -- "
    r = c.get("/library/contacts", query_string={"tab": "company", "q": long_payload})  # 50자를 넘으면 검증 단계에서 거부
    assert r.status_code == 400 and "argon2" not in r.get_data(as_text=True)


@pytest.mark.parametrize("q", ["a" * 51, "bad\x00char", "tab\tchar"])
def test_employee_search_rejects_bad_queries_and_logs(aapp, events, q):
    r = as_user(aapp, "zz_emp").get("/library/contacts", query_string={"tab": "company", "q": q})
    assert r.status_code == 400
    ev = [e for e in events() if e["event_type"] == "input_rejected"][-1]
    assert ev["field"] == "q" and ev["decision"] == "DENY"


def test_employee_search_echo_is_escaped(aapp):
    html = as_user(aapp, "zz_emp").get("/library/contacts", query_string={"tab": "company", "q": '"><script>alert(1)</script>'}).get_data(as_text=True)
    assert "<script" not in html


# ---------- 게시판 ----------
def test_free_board_create_view_and_list(aapp, root, events):
    c = as_user(aapp, "zz_emp")
    r = new_post(c, "free", "zz_첫 글", "<img src=x onerror=alert(1)>\n둘째 줄")
    assert r.status_code == 303
    detail = c.get(r.headers["Location"]).get_data(as_text=True)
    assert "zz_첫 글" in detail and "&lt;img src=x onerror=alert(1)&gt;" in detail and "<img" not in detail
    assert "zz_첫 글" in c.get("/boards/free").get_data(as_text=True)
    assert "zz_첫 글" not in c.get("/boards/notice").get_data(as_text=True)      # 게시판이 서로 구분된다
    assert any(e["event_type"] == "post_created" and e["board"] == "free" for e in events())


def test_post_requires_csrf(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = c.post("/boards/free/new", data={"title": "zz_csrf", "body": "x"})
    assert r.status_code == 403 and count_posts(root, "zz_csrf") == 0


def test_notice_board_is_read_for_all_but_write_for_manager_and_admin_only(aapp, root, events):
    emp = as_user(aapp, "zz_emp")
    assert emp.get("/boards/notice").status_code == 200
    assert "글쓰기" not in emp.get("/boards/notice").get_data(as_text=True)
    assert emp.get("/boards/notice/new").status_code == 403
    assert new_post(emp, "notice", "zz_공지시도").status_code == 403
    assert count_posts(root, "zz_공지시도") == 0
    assert any(e["event_type"] == "authz_deny" and e["resource"] == "board:notice" for e in events())
    mgr = as_user(aapp, "zz_mgr")
    assert "글쓰기" in mgr.get("/boards/notice").get_data(as_text=True)
    assert new_post(mgr, "notice", "zz_공지").status_code == 303


def test_unknown_board_is_404(aapp):
    c = as_user(aapp, "zz_emp")
    for path in ("/boards/secret", "/boards/secret/new", "/boards/..%2f", "/boards/free%27--"):
        assert c.get(path).status_code == 404


@pytest.mark.parametrize("title,body", [
    ("", "내용"), ("a" * 121, "내용"), ("제목", ""), ("제목", "   "), ("제\n목", "내용"),
    ("제목", "널\x00문자"), ("제목", "a" * 5001), ("제목\x07", "내용"),
])
def test_post_validation_rejects_and_logs(aapp, root, events, title, body):
    r = new_post(as_user(aapp, "zz_emp"), "free", title, body)
    assert r.status_code == 400
    assert sql(root, "SELECT COUNT(*) FROM posts WHERE author_id=%s", (uid(root, "zz_emp"),))[0][0] == 0
    assert any(e["event_type"] == "input_rejected" and e["field"] == "post" for e in events())


def test_sql_injection_text_is_stored_literally(aapp, root):
    c = as_user(aapp, "zz_emp")
    evil = "zz_'); DROP TABLE posts; -- "
    r = new_post(c, "free", evil, "x' OR '1'='1")
    assert r.status_code == 303
    assert "DROP TABLE posts" in c.get(r.headers["Location"]).get_data(as_text=True)
    assert sql(root, "SELECT COUNT(*) FROM posts")[0][0] >= 1  # 표가 그대로 있다


def test_pagination(aapp, root):
    for i in range(25):
        add_post(root, "zz_emp", "free", f"zz_page_{i:02d}")
    c = as_user(aapp, "zz_emp")
    p1 = c.get("/boards/free").get_data(as_text=True)
    assert p1.count("/posts/") == 20 and "다음" in p1 and "이전" not in p1
    p2 = c.get("/boards/free?page=2").get_data(as_text=True)
    assert p2.count("/posts/") == 5 and "이전" in p2 and "다음" not in p2
    for bad in ("0", "-1", "abc", "1.5", "10001", "1%20OR%201=1", ""):
        assert c.get(f"/boards/free?page={bad}").status_code == 400


def test_post_not_found(aapp):
    c = as_user(aapp, "zz_emp")
    assert c.get("/posts/999999").status_code == 404
    assert c.get("/posts/abc").status_code == 404


# ---------- 삭제 권한 ----------
def test_only_author_or_admin_can_delete(aapp, root, events):
    pid = add_post(root, "zz_emp", "free", "zz_삭제대상")
    for name in ("zz_emp2", "zz_mgr"):                      # 다른 직원·매니저는 불가
        c = as_user(aapp, name)
        assert post(c, f"/posts/{pid}/delete").status_code == 403
        assert count_posts(root, "zz_삭제대상") == 1
    assert any(e["event_type"] == "authz_deny" and e["reason"] == "not_owner" for e in events())
    assert as_user(aapp, "zz_adm").get(f"/posts/{pid}").get_data(as_text=True).count("삭제") >= 1  # 관리자에게는 버튼이 보인다
    assert "삭제</button>" not in as_user(aapp, "zz_mgr").get(f"/posts/{pid}").get_data(as_text=True)
    assert post(as_user(aapp, "zz_adm"), f"/posts/{pid}/delete").status_code == 303
    assert count_posts(root, "zz_삭제대상") == 0


def test_author_can_delete_own_post_and_get_is_not_allowed(aapp, root):
    pid = add_post(root, "zz_emp", "free", "zz_내글")
    c = as_user(aapp, "zz_emp")
    assert c.get(f"/posts/{pid}/delete").status_code == 405
    assert post(c, f"/posts/{pid}/delete").status_code == 303
    assert count_posts(root, "zz_내글") == 0
    assert post(c, f"/posts/{pid}/delete").status_code == 404


def test_delete_requires_csrf(aapp, root):
    pid = add_post(root, "zz_emp", "free", "zz_csrf삭제")
    c = as_user(aapp, "zz_emp")
    assert c.post(f"/posts/{pid}/delete").status_code == 403
    assert count_posts(root, "zz_csrf삭제") == 1


# ---------- 첨부 업로드·다운로드 ----------
def test_upload_store_and_download(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = new_post(c, "free", "zz_첨부", "본문", file=("메모.txt", "<script>alert(1)</script>안녕".encode("utf-8")))
    assert r.status_code == 303
    row = sql(root, "SELECT id, stored_name, orig_name, mime, size FROM attachments")[0]
    att_id, stored, orig, mime, size = row
    assert orig == "메모.txt" and mime == "text/plain" and len(stored) == 36 and "." not in stored
    assert stored_files(aapp) == [stored]                                  # 서버가 만든 이름으로 업로드 폴더에만 저장
    assert (aapp.config["UPLOAD_DIR"] / stored).read_bytes() == "<script>alert(1)</script>안녕".encode("utf-8")
    assert "메모.txt" in c.get(r.headers["Location"]).get_data(as_text=True)

    other = as_user(aapp, "zz_emp2")                                        # 게시판은 로그인한 모두에게 공개
    d = other.get(f"/attachments/{att_id}")
    assert d.status_code == 200 and d.data == "<script>alert(1)</script>안녕".encode("utf-8")
    assert d.headers["Content-Disposition"].startswith("attachment")
    assert d.headers["Content-Type"].startswith("text/plain") and d.headers["X-Content-Type-Options"] == "nosniff"


def test_upload_png_keeps_image_mime(aapp, root):
    c = as_user(aapp, "zz_emp")
    new_post(c, "free", "zz_이미지", file=("사진.png", PNG))
    att_id = sql(root, "SELECT id FROM attachments")[0][0]
    d = c.get(f"/attachments/{att_id}")
    assert d.headers["Content-Type"] == "image/png" and d.headers["Content-Disposition"].startswith("attachment")


# ---------- 첨부 미리보기(그림·PDF가 글 화면에서 보인다) ----------
PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


def test_image_attachment_is_shown_inline_on_the_post_page(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = new_post(c, "free", "zz_그림글", file=("사진.png", PNG))
    att_id = sql(root, "SELECT id FROM attachments")[0][0]
    page = as_user(aapp, "zz_emp2").get(r.headers["Location"]).get_data(as_text=True)
    assert f'<img class="attach-img" src="/attachments/{att_id}/view"' in page          # 다른 직원도 바로 본다
    assert f'href="/attachments/{att_id}"' in page                                       # 다운로드 링크는 그대로


def test_image_view_is_inline_with_strict_headers(aapp, root):
    c = as_user(aapp, "zz_emp")
    new_post(c, "free", "zz_그림뷰", file=("사진.png", PNG))
    att_id = sql(root, "SELECT id FROM attachments")[0][0]
    d = as_user(aapp, "zz_emp2").get(f"/attachments/{att_id}/view")
    assert d.status_code == 200 and d.data == PNG and d.headers["Content-Type"] == "image/png"
    assert not d.headers.get("Content-Disposition", "").startswith("attachment")
    assert d.headers["Content-Security-Policy"] == "default-src 'none'; sandbox"
    assert d.headers["X-Content-Type-Options"] == "nosniff" and d.headers["X-Frame-Options"] == "DENY"
    assert d.headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_pdf_has_view_link_and_opens_inline_while_download_stays_attachment(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = new_post(c, "free", "zz_pdf글", file=("문서.pdf", PDF))
    att_id = sql(root, "SELECT id FROM attachments")[0][0]
    page = c.get(r.headers["Location"]).get_data(as_text=True)
    assert f'href="/attachments/{att_id}/view" target="_blank" rel="noopener"' in page
    assert "<img" not in page.split("<h2>첨부</h2>")[1]                                   # PDF 는 그림으로 끼워 넣지 않는다
    v = c.get(f"/attachments/{att_id}/view")
    assert v.status_code == 200 and v.headers["Content-Type"] == "application/pdf"
    assert not v.headers.get("Content-Disposition", "").startswith("attachment")
    assert v.headers["Content-Security-Policy"] == "default-src 'none'" and v.headers["X-Frame-Options"] == "DENY"
    assert c.get(f"/attachments/{att_id}").headers["Content-Disposition"].startswith("attachment")


def test_text_attachment_has_no_inline_view_and_view_needs_login(aapp, root):
    c = as_user(aapp, "zz_emp")
    new_post(c, "free", "zz_텍스트글", file=("메모.txt", b"<html><script>alert(1)</script></html>"))
    att_id = sql(root, "SELECT id FROM attachments")[0][0]
    assert c.get(f"/attachments/{att_id}/view").status_code == 404                       # txt 는 다운로드만
    assert c.get("/attachments/999999/view").status_code == 404
    assert aapp.test_client().get(f"/attachments/{att_id}/view").status_code == 303      # 비로그인은 로그인 화면으로


def test_post_form_loads_paste_script_from_own_origin_and_script_is_served(aapp):
    c = as_user(aapp, "zz_emp")
    page = c.get("/boards/free/new")
    html = page.get_data(as_text=True)
    assert 'src="/static/paste-attach.js"' in html and 'id="attachment"' in html and 'id="attach-preview"' in html
    assert "script-src 'self'" in page.headers["Content-Security-Policy"]
    js = c.get("/static/paste-attach.js")
    assert js.status_code == 200 and b"clipboardData" in js.data


# 첨부는 형식·개수·용량을 제한하지 않는다. 대신 어떤 파일이든 무해하게 다룬다: 무작위 이름으로 웹루트 밖에 저장하고, 항상 다운로드로만 내려주며,
# 그림·PDF 는 내용이 맞을 때만 그 형식으로 인정한다(미리보기는 그 형식만).
HARMLESS = [  # (파일 이름, 내용, 기대하는 분류)
    ("shell.php", b"<?php echo 1; ?>", "application/octet-stream"),
    ("shell.php.png", PNG, "image/png"),                                   # 이름은 이중 확장자지만 내용이 진짜 PNG 라서 그림으로 인정
    ("shell.png.php", PNG, "application/octet-stream"),
    ("page.html", b"<script>alert(1)</script>", "application/octet-stream"),
    ("evil.svg", b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>", "application/octet-stream"),
    ("run.exe", b"MZ\x90\x00", "application/octet-stream"),
    ("noext", b"hello", "application/octet-stream"),
    (".htaccess", b"AddType application/x-httpd-php .png", "application/octet-stream"),
    ("fake.png", b"<?php echo 1; ?>", "application/octet-stream"),   # 내용이 그림이 아니면 그림으로 인정하지 않는다
    ("fake.pdf", PNG, "application/octet-stream"),
    ("bin.txt", b"a\x00b", "text/plain"),
    ("empty.txt", b"", "text/plain"),
    ("<img src=x onerror=alert(1)>.zip", b"PK\x03\x04", "application/octet-stream"),
]


@pytest.mark.parametrize("filename,data,mime", HARMLESS)
def test_any_file_is_accepted_but_handled_harmlessly(aapp, root, events, filename, data, mime):
    c = as_user(aapp, "zz_emp")
    r = new_post(c, "free", "zz_무해첨부", file=(filename, data))
    assert r.status_code == 303
    att_id, stored, orig, got_mime, size = sql(root, "SELECT id, stored_name, orig_name, mime, size FROM attachments")[0]
    assert len(stored) == 36 and "." not in stored and stored_files(aapp) == [stored]            # 서버가 만든 이름으로 업로드 폴더에만
    assert (aapp.config["UPLOAD_DIR"] / stored).read_bytes() == data and size == len(data)       # 내용은 그대로
    assert got_mime == mime
    assert re.fullmatch(r"[A-Za-z0-9._가-힣 -]+", orig) and not orig.startswith(".")           # 표시 이름은 안전한 문자만
    other = as_user(aapp, "zz_emp2")
    d = other.get(f"/attachments/{att_id}")                                                     # 내려받기: 항상 첨부 + nosniff
    assert d.status_code == 200 and d.data == data and d.headers["Content-Disposition"].startswith("attachment")
    assert d.headers["X-Content-Type-Options"] == "nosniff" and d.headers["Content-Type"].startswith(mime)
    view = other.get(f"/attachments/{att_id}/view")                                             # 미리보기는 분류된 그림·PDF 만
    assert view.status_code == (200 if mime in ("image/png",) else 404)
    page = other.get(r.headers["Location"]).get_data(as_text=True)
    assert "<script>alert(1)" not in page and "onerror=alert(1)>" not in page                  # 글 화면에서도 실행되는 조각이 없다


def test_no_limit_on_size_or_count_for_attachments(aapp, root):
    c = as_user(aapp, "zz_emp")
    big = b"0123456789abcdef" * (512 * 1024)                                                    # 8MB: 예전 상한(2MB)의 네 배
    assert new_post(c, "free", "zz_큰파일", file=("big.bin", big)).status_code == 303
    sha, size = sql(root, "SELECT sha256, size FROM attachments")[0]
    import hashlib
    assert size == len(big) and sha == hashlib.sha256(big).hexdigest()
    att = sql(root, "SELECT id FROM attachments")[0][0]
    assert c.get(f"/attachments/{att}").data == big
    files = [("attachment", (io.BytesIO(f"file{i}".encode()), f"f{i}.dat")) for i in range(15)]     # 한 글에 15개
    data = {"title": "zz_많은첨부", "body": "x", "csrf_token": csrf_of(c)}
    r = c.post("/boards/free/new", data={**data, "attachment": [f[1] for f in files]}, content_type="multipart/form-data")
    assert r.status_code == 303
    assert sql(root, "SELECT COUNT(*) FROM attachments WHERE post_id=(SELECT id FROM posts WHERE title='zz_많은첨부')")[0][0] == 15


def test_requests_without_attachments_keep_the_body_size_limit(aapp, root, events):
    """용량 제한을 푸는 것은 첨부를 받는 요청뿐이다. 로그인 같은 나머지 요청은 예전 상한(2MB)이 그대로다."""
    c = aapp.test_client()
    r = c.post("/login", data={"username": "zz_emp", "password": "x" * (3 * 1024 * 1024)})
    assert r.status_code == 413


def test_attachments_written_before_a_failure_are_removed(aapp, root, monkeypatch):
    from app import uploads
    real, calls = uploads.save_attachment, []

    def flaky(directory, storage):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("disk full")
        return real(directory, storage)
    monkeypatch.setattr(uploads, "save_attachment", flaky)
    c = as_user(aapp, "zz_emp")
    data = {"title": "zz_실패", "body": "x", "csrf_token": csrf_of(c), "attachment": [(io.BytesIO(b"a"), "a.dat"), (io.BytesIO(b"b"), "b.dat")]}
    assert c.post("/boards/free/new", data=data, content_type="multipart/form-data").status_code == 500                      # 앱이 예외를 오류 화면(500)으로 처리하고 DB 는 롤백된다
    assert stored_files(aapp) == []                                                                # 첫 파일도 지워진다
    assert count_posts(root, "zz_실패") == 0 and sql(root, "SELECT COUNT(*) FROM attachments")[0][0] == 0


def test_path_in_uploaded_filename_cannot_escape(aapp, root):
    c = as_user(aapp, "zz_emp")
    assert new_post(c, "free", "zz_경로", file=("../../evil.txt", b"hello")).status_code == 303
    orig, stored = sql(root, "SELECT orig_name, stored_name FROM attachments")[0]
    assert orig == "evil.txt" and stored_files(aapp) == [stored]
    assert not (aapp.config["UPLOAD_DIR"].parent.parent / "evil.txt").exists()


def test_attachment_download_edge_cases(aapp, root):
    c = as_user(aapp, "zz_emp")
    assert c.get("/attachments/999999").status_code == 404
    assert c.get("/attachments/abc").status_code == 404
    assert c.get("/attachments/..%2f..%2fetc%2fpasswd").status_code == 404
    new_post(c, "free", "zz_사라진파일", file=("a.txt", b"hello"))
    att_id, stored = sql(root, "SELECT id, stored_name FROM attachments")[0]
    (aapp.config["UPLOAD_DIR"] / stored).unlink()                           # 디스크에서 파일이 사라진 경우
    assert c.get(f"/attachments/{att_id}").status_code == 404


def test_deleting_a_post_removes_its_attachment_row_and_file(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = new_post(c, "free", "zz_첨부삭제", file=("a.txt", b"hello"))
    pid = int(r.headers["Location"].rsplit("/", 1)[1])
    assert len(stored_files(aapp)) == 1
    assert post(c, f"/posts/{pid}/delete").status_code == 303
    assert sql(root, "SELECT COUNT(*) FROM attachments")[0][0] == 0 and stored_files(aapp) == []


def test_post_with_wrong_board_slug_in_form_cannot_bypass_notice_rule(aapp, root):
    # 공지 권한은 URL 의 board 로만 판단하며 폼 필드로 board 를 바꿀 수 없다
    c = as_user(aapp, "zz_emp")
    r = c.post("/boards/free/new", data={"title": "zz_우회", "body": "x", "board": "notice", "csrf_token": csrf_of(c)})
    assert r.status_code == 303
    assert sql(root, "SELECT board FROM posts WHERE title='zz_우회'")[0][0] == "free"


def test_unreadable_stored_file_is_a_clean_404_not_a_server_error(aapp, root, events, monkeypatch):
    """업로드가 자유로우니 서버의 백신이 파일을 격리하는 일이 생길 수 있다(운영체제가 열지 못하게 함). 그때 500 이 아니라 404 로 답하고 기록한다."""
    from app import uploads
    c = as_user(aapp, "zz_emp")
    new_post(c, "free", "zz_격리", file=("a.dat", b"payload"))
    att_id = sql(root, "SELECT id FROM attachments")[0][0]

    def deny(*args, **kwargs):
        raise OSError(22, "Invalid argument")                     # Windows 에서 백신이 격리한 파일을 열 때의 오류
    monkeypatch.setattr(uploads, "send_from_directory", deny)
    r = c.get(f"/attachments/{att_id}")
    assert r.status_code == 404 and b"Traceback" not in r.data
    assert any(e["event_type"] == "attachment_unreadable" and e["reason"] == "OSError" and e["errno"] == 22 for e in events())


def test_old_employee_search_address_moves_to_the_address_book(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = c.get("/employees?q=영업")
    assert r.status_code == 301 and r.headers["Location"].endswith("/library/contacts?tab=company&q=%EC%98%81%EC%97%85")
    assert c.get("/employees").headers["Location"].endswith("/library/contacts?tab=company")
    anon = aapp.test_client().get("/employees")
    assert anon.status_code == 303 and "/login" in anon.headers["Location"]
    for entry in ("직원 검색",):
        assert entry not in c.get("/").get_data(as_text=True)                                  # 메뉴에 따로 남아 있지 않다
