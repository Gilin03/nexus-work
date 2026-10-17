"""포털 통합 테스트(문서함·기밀·직원 검색·게시판·첨부). Docker MySQL(nexus_test) 필요, 접속 불가면 skip."""
import io

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
@pytest.mark.parametrize("path", ["/documents", "/documents/1", "/confidential", "/confidential/1", "/employees",
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
    assert "TOP-SECRET-BODY" not in c.get("/employees?q=zz_").get_data(as_text=True)


def test_nav_shows_confidential_link_only_to_privileged_roles(aapp):
    emp = as_user(aapp, "zz_emp").get("/").get_data(as_text=True)
    mgr = as_user(aapp, "zz_mgr").get("/").get_data(as_text=True)
    assert "기밀 문서함" not in emp and "기밀 문서함" in mgr


# ---------- 직원 검색 ----------
def test_employee_search_by_name_dept_and_title(aapp, root):
    add_employee(root, "zz_alpha", "영업팀", "사원")
    add_employee(root, "zzXalpha", "개발팀", "대리")
    add_employee(root, "zz_beta", "영업팀", "과장")
    c = as_user(aapp, "zz_emp")
    html = c.get("/employees?q=zz_alpha").get_data(as_text=True)
    assert "zz_alpha" in html and "zzXalpha" not in html            # '_' 는 와일드카드가 아니라 문자 그대로
    html = c.get("/employees?q=영업").get_data(as_text=True)
    assert "zz_alpha" in html and "zz_beta" in html and "zzXalpha" not in html
    assert "zz_beta" in c.get("/employees?q=과장").get_data(as_text=True)


def test_like_wildcards_are_literal(aapp, root):
    add_employee(root, "zz_one")
    add_employee(root, "zz_two")
    c = as_user(aapp, "zz_emp")
    assert "검색 결과가 없습니다" in c.get("/employees?q=%25").get_data(as_text=True)      # q=%  → 전체 일치 아님
    assert "검색 결과가 없습니다" in c.get("/employees?q=zz%25one").get_data(as_text=True)


def test_employee_search_sql_injection_returns_nothing(aapp, root):
    add_employee(root, "zz_alpha")
    c = as_user(aapp, "zz_emp")
    short = ("' OR 1=1 -- ", "x' UNION SELECT username,2,3,4 FROM users-- ", "\\", "%' OR '%'='", "x') OR ('1'='1")
    for payload in short:  # 길이 한도(50자) 안의 페이로드는 검색어로만 취급되어 결과가 없다
        r = c.get("/employees", query_string={"q": payload})
        html = r.get_data(as_text=True)
        assert r.status_code == 200 and "zz_alpha" not in html and "argon2" not in html, payload
    long_payload = "zz' UNION SELECT username,password_hash,role,dept FROM users -- "
    r = c.get("/employees", query_string={"q": long_payload})  # 50자를 넘으면 검증 단계에서 거부
    assert r.status_code == 400 and "argon2" not in r.get_data(as_text=True)


@pytest.mark.parametrize("q", ["a" * 51, "bad\x00char", "tab\tchar"])
def test_employee_search_rejects_bad_queries_and_logs(aapp, events, q):
    r = as_user(aapp, "zz_emp").get("/employees", query_string={"q": q})
    assert r.status_code == 400
    ev = [e for e in events() if e["event_type"] == "input_rejected"][-1]
    assert ev["field"] == "q" and ev["decision"] == "DENY"


def test_employee_search_echo_is_escaped(aapp):
    html = as_user(aapp, "zz_emp").get("/employees", query_string={"q": '"><script>alert(1)</script>'}).get_data(as_text=True)
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


@pytest.mark.parametrize("filename,data,reason", [
    ("shell.php", b"<?php system($_GET[0]); ?>", "extension_not_allowed"),
    ("shell.php.png", PNG, "extension_not_allowed"),
    ("shell.png.php", PNG, "extension_not_allowed"),
    ("page.html", b"<script>alert(1)</script>", "extension_not_allowed"),
    ("run.exe", b"MZ\x90\x00", "extension_not_allowed"),
    ("noext", b"hello", "extension_not_allowed"),
    (".htaccess", b"AddType x", "extension_not_allowed"),
    ("fake.png", b"<?php system($_GET[0]); ?>", "content_mismatch"),
    ("fake.pdf", PNG, "content_mismatch"),
    ("bin.txt", b"a\x00b", "content_mismatch"),
    ("empty.txt", b"", "empty_upload"),
])
def test_dangerous_uploads_are_rejected_without_side_effects(aapp, root, events, filename, data, reason):
    c = as_user(aapp, "zz_emp")
    r = new_post(c, "free", "zz_위험첨부", file=(filename, data))
    assert r.status_code == 400
    assert count_posts(root, "zz_위험첨부") == 0 and stored_files(aapp) == []   # 글도 파일도 남지 않는다
    assert sql(root, "SELECT COUNT(*) FROM attachments")[0][0] == 0
    ev = [e for e in events() if e["event_type"] == "upload_reject"][-1]
    assert ev["reason"] == reason and ev["decision"] == "BLOCK" and ev["user"] == "zz_emp"


def test_oversized_upload_is_rejected(aapp, root, events):
    c = as_user(aapp, "zz_emp")
    r = new_post(c, "free", "zz_큰파일", file=("big.txt", b"a" * (2 * 1024 * 1024 + 10)))
    assert r.status_code == 413
    assert count_posts(root, "zz_큰파일") == 0 and stored_files(aapp) == []
    assert any(e["event_type"] == "request_rejected" and e["reason"] == "http_413" for e in events())


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
