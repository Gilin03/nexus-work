"""자료: 자료실(폴더·버전·권한)·주소록·문서 검색·양식 모음. Docker MySQL(nexus_test) 필요, 접속 불가면 skip."""
import io
import threading

import pytest

from support import csrf_of, login, sql, uid


def as_user(app, name):
    c = app.test_client()
    assert login(c, name).status_code == 303
    return c


def post(client, path, data=None, **form):
    return client.post(path, data={"csrf_token": csrf_of(client), **(data or {}), **form})


def upload(client, folder_id, files, note="", **extra):
    """files: [(이름, 내용 bytes)]"""
    data = {"csrf_token": csrf_of(client), "note": note, "file": [(io.BytesIO(body), name) for name, body in files], **extra}
    return client.post(f"/library/folders/{folder_id}/upload", data=data, content_type="multipart/form-data")


def make_folder(root, owner, name="zz 폴더", parent=None, scope="company", dept=None):
    sql(root, "INSERT INTO lib_folders(parent_id,name,scope,dept,created_by) VALUES(%s,%s,%s,%s,%s)", (parent, name, scope, dept, uid(root, owner)))
    return sql(root, "SELECT id FROM lib_folders WHERE name=%s AND created_by=%s ORDER BY id DESC", (name, uid(root, owner)))[0][0]


def files_of(root, folder_id):
    return sql(root, "SELECT orig_name, version, mime, deleted_at FROM lib_files WHERE folder_id=%s ORDER BY orig_name, version", (folder_id,))


GET_PAGES = ["/library", "/library/folders/1", "/library/contacts", "/library/contacts/new", "/library/search", "/library/forms",
             "/library/files/1", "/library/forms/1/download"]
POST_PAGES = ["/library/folders/new", "/library/folders/1/upload", "/library/files/1/delete", "/library/contacts/new",
              "/library/contacts/1/delete", "/library/forms/upload", "/library/forms/1/delete"]


@pytest.mark.parametrize("path", GET_PAGES)
def test_pages_require_login(aapp, path):
    r = aapp.test_client().get(path)
    assert r.status_code == 303 and "/login" in r.headers["Location"]


@pytest.mark.parametrize("path", POST_PAGES)
def test_posts_need_csrf(aapp, root, path):
    assert as_user(aapp, "zz_adm").post(path).status_code == 403
    assert aapp.test_client().post(path).status_code == 403


# =====================================================================================
# 자료실: 폴더
# =====================================================================================
def test_folder_creation_rights(aapp, root):
    assert post(as_user(aapp, "zz_emp"), "/library/folders/new", name="zz 직원폴더", scope="dept").status_code == 403
    mgr = as_user(aapp, "zz_mgr")
    assert post(mgr, "/library/folders/new", name="zz 팀폴더", scope="dept", dept="B팀").status_code == 303      # 팀장은 보낸 부서값을 무시하고 자기 부서로
    scope, dept = sql(root, "SELECT scope, dept FROM lib_folders WHERE name='zz 팀폴더'")[0]
    assert (scope, dept) == ("dept", "A팀")
    assert post(mgr, "/library/folders/new", name="zz 전사폴더", scope="company").status_code == 403           # 전사 공개는 관리자만
    adm = as_user(aapp, "zz_adm")
    assert post(adm, "/library/folders/new", name="zz 전사폴더", scope="company", dept="A팀").status_code == 303
    assert sql(root, "SELECT scope, dept FROM lib_folders WHERE name='zz 전사폴더'")[0] == ("company", None)
    assert post(adm, "/library/folders/new", name="zz B팀폴더", scope="dept", dept="B팀").status_code == 303
    assert sql(root, "SELECT dept FROM lib_folders WHERE name='zz B팀폴더'")[0][0] == "B팀"
    assert post(adm, "/library/folders/new", name="zz 없는부서", scope="dept", dept="없는부서").status_code == 409
    assert post(adm, "/library/folders/new", name="zz 이상한범위", scope="all").status_code == 403


@pytest.mark.parametrize("name", ["", "   ", "x" * 51, "a\x00b", "a\nb"])
def test_folder_name_validation(aapp, root, name):
    r = post(as_user(aapp, "zz_adm"), "/library/folders/new", name=name, scope="company")
    assert r.status_code == 409 and sql(root, "SELECT COUNT(*) FROM lib_folders WHERE created_by=%s", (uid(root, "zz_adm"),))[0][0] == 0


def test_duplicate_folder_name_in_same_parent(aapp, root):
    adm = as_user(aapp, "zz_adm")
    assert post(adm, "/library/folders/new", name="zz 중복", scope="company").status_code == 303
    assert post(adm, "/library/folders/new", name="zz 중복", scope="company").status_code == 409             # 최상위끼리 중복 불가
    top = sql(root, "SELECT id FROM lib_folders WHERE name='zz 중복'")[0][0]
    assert post(adm, "/library/folders/new", name="zz 중복", parent_id=top).status_code == 303              # 다른 부모 아래에는 같은 이름 가능
    assert post(adm, "/library/folders/new", name="zz 중복", parent_id=top).status_code == 409


def test_subfolders_inherit_scope_and_depth_is_limited(aapp, root):
    top = make_folder(root, "zz_mgr", "zz 1단계", scope="dept", dept="A팀")
    mgr = as_user(aapp, "zz_mgr")
    parent = top
    for level in (2, 3, 4):
        assert post(mgr, "/library/folders/new", name=f"zz {level}단계", parent_id=parent, scope="company").status_code == 303   # 보낸 범위는 무시
        parent = sql(root, "SELECT id FROM lib_folders WHERE name=%s", (f"zz {level}단계",))[0][0]
        assert sql(root, "SELECT scope, dept FROM lib_folders WHERE id=%s", (parent,))[0] == ("dept", "A팀")
    assert post(mgr, "/library/folders/new", name="zz 5단계", parent_id=parent).status_code == 409           # 4단계까지만
    page = mgr.get(f"/library/folders/{parent}").get_data(as_text=True)
    assert 'name="parent_id"' not in page                                                                  # 더 못 만드는 폴더에는 입력 칸도 없다
    assert "zz 1단계" in page and "zz 4단계" in page                                                        # 경로 표시


@pytest.mark.parametrize("parent", ["abc", "-1", "0", "٣"])
def test_bad_parent_id_is_rejected(aapp, root, parent):
    assert post(as_user(aapp, "zz_adm"), "/library/folders/new", name="zz x", parent_id=parent).status_code == 400


def test_unknown_parent_is_404_and_foreign_dept_parent_is_403(aapp, root):
    assert post(as_user(aapp, "zz_adm"), "/library/folders/new", name="zz x", parent_id=999999).status_code == 404
    other = make_folder(root, "zz_mgrb", "zz B팀 전용", scope="dept", dept="B팀")
    assert post(as_user(aapp, "zz_mgr"), "/library/folders/new", name="zz 침입", parent_id=other).status_code == 403


def test_folder_visibility_by_scope(aapp, root):
    comp = make_folder(root, "zz_adm", "zz 전사", scope="company")
    a = make_folder(root, "zz_mgr", "zz A팀", scope="dept", dept="A팀")
    b = make_folder(root, "zz_mgrb", "zz B팀", scope="dept", dept="B팀")
    expect = {"zz_emp": (200, 200, 403), "zz_mgr": (200, 200, 403), "zz_emp3": (200, 403, 200), "zz_mgrb": (200, 403, 200),
              "zz_adm": (200, 200, 200)}
    for who, codes in expect.items():
        c = as_user(aapp, who)
        assert tuple(c.get(f"/library/folders/{f}").status_code for f in (comp, a, b)) == codes, who
    home = as_user(aapp, "zz_emp").get("/library").get_data(as_text=True)
    assert "zz 전사" in home and "zz A팀" in home and "zz B팀" not in home
    assert "zz B팀" in as_user(aapp, "zz_adm").get("/library").get_data(as_text=True)
    assert as_user(aapp, "zz_emp").get("/library/folders/999999").status_code == 404


def test_create_forms_only_for_managers(aapp, root):
    assert 'action="/library/folders/new"' not in as_user(aapp, "zz_emp").get("/library").get_data(as_text=True)
    assert 'action="/library/folders/new"' in as_user(aapp, "zz_mgr").get("/library").get_data(as_text=True)


# =====================================================================================
# 자료실: 파일
# =====================================================================================
def test_upload_multiple_files_any_type_and_download(aapp, root):
    f = make_folder(root, "zz_adm")
    c = as_user(aapp, "zz_emp")
    r = upload(c, f, [("보고서.txt", b"hello"), ("run.exe", b"MZ\x90\x00"), ("shell.php", b"<?php echo 1;"), ("noext", b"x"), ("a.PDF", b"not a pdf")], note="메모")
    assert r.status_code == 303
    rows = {row[0]: row for row in files_of(root, f)}
    assert set(rows) == {"보고서.txt", "run.exe", "shell.php", "noext", "a.PDF"}
    assert rows["보고서.txt"][2] == "text/plain"
    assert rows["a.PDF"][2] == "application/octet-stream"                                       # 확장자만 PDF 이고 내용이 아니면 일반 파일로
    assert rows["shell.php"][2] == "application/octet-stream"
    fid = sql(root, "SELECT id FROM lib_files WHERE orig_name='보고서.txt'")[0][0]
    d = as_user(aapp, "zz_emp3").get(f"/library/files/{fid}")                                    # 전사 폴더는 다른 부서도 받을 수 있다
    assert d.status_code == 200 and d.data == b"hello"
    assert d.headers["Content-Disposition"].startswith("attachment") and d.headers["X-Content-Type-Options"] == "nosniff"
    php = sql(root, "SELECT id FROM lib_files WHERE orig_name='shell.php'")[0][0]
    p = c.get(f"/library/files/{php}")
    assert p.headers["Content-Disposition"].startswith("attachment") and not p.headers["Content-Type"].startswith("text/html")


def test_upload_has_no_size_limit_beyond_the_global_form_cap(aapp, root):
    f = make_folder(root, "zz_adm")
    assert upload(as_user(aapp, "zz_emp"), f, [("큰파일.bin", b"\x01" * (3 * 1024 * 1024))]).status_code == 303      # 전역 상한(2MB)보다 크다
    size = sql(root, "SELECT size FROM lib_files WHERE orig_name='큰파일.bin'")[0][0]
    assert size == 3 * 1024 * 1024


def test_same_name_creates_new_version_and_old_versions_stay(aapp, root):
    f = make_folder(root, "zz_adm")
    c = as_user(aapp, "zz_emp")
    for body in (b"v1", b"v2", b"v3"):
        assert upload(c, f, [("규정.txt", body)]).status_code == 303
    assert [r[1] for r in files_of(root, f)] == [1, 2, 3]
    page = c.get(f"/library/folders/{f}").get_data(as_text=True)
    assert page.count("v1") >= 1 and page.count("v3") >= 1 and page.count("최신") == 1
    old = sql(root, "SELECT id FROM lib_files WHERE version=1 AND folder_id=%s", (f,))[0][0]
    assert c.get(f"/library/files/{old}").data == b"v1"                                          # 이전 버전도 받을 수 있다
    assert upload(c, f, [("규정.txt", b"a"), ("규정.txt", b"b")]).status_code == 303                # 한 요청에 같은 이름 두 개 → 순서대로 v4, v5
    assert [r[1] for r in files_of(root, f)] == [1, 2, 3, 4, 5]


def test_simultaneous_uploads_of_the_same_name_get_distinct_versions(aapp, root):
    f = make_folder(root, "zz_adm")
    clients = [as_user(aapp, n) for n in ("zz_emp", "zz_emp2", "zz_mgr", "zz_adm")]
    gate, codes = threading.Barrier(len(clients)), []

    def go(c, i):
        gate.wait()
        codes.append(upload(c, f, [("동시.txt", f"본문{i}".encode())]).status_code)

    ts = [threading.Thread(target=go, args=(c, i)) for i, c in enumerate(clients)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert codes == [303] * 4
    assert [r[1] for r in files_of(root, f)] == [1, 2, 3, 4]


def test_upload_validation(aapp, root):
    f = make_folder(root, "zz_adm")
    c = as_user(aapp, "zz_emp")
    assert upload(c, f, []).status_code == 400                                                   # 파일 없음
    assert upload(c, f, [("a.txt", b"x")], note="x" * 201).status_code == 400
    assert upload(c, f, [("a.txt", b"x")], note="a\x00b").status_code == 400
    assert files_of(root, f) == ()
    assert upload(c, 999999, [("a.txt", b"x")]).status_code == 404
    assert upload(c, f, [("빈파일.txt", b"")]).status_code == 303                                  # 빈 파일도 받는다(제한 없음)


def test_upload_name_is_sanitised_and_cannot_traverse(aapp, root, tmp_path):
    f = make_folder(root, "zz_adm")
    assert upload(as_user(aapp, "zz_emp"), f, [("../../evil<script>.txt", b"x"), ("..\\..\\win.txt", b"y")]).status_code == 303
    names = {r[0] for r in files_of(root, f)}
    assert all("/" not in n and "\\" not in n and "<" not in n for n in names)
    stored = sql(root, "SELECT stored_name FROM lib_files WHERE folder_id=%s", (f,))
    assert all(len(s[0]) == 36 for s in stored)                                                  # 저장 이름은 서버가 만든 uuid
    on_disk = {p.name for p in (tmp_path / "uploads").iterdir()}
    assert {s[0] for s in stored} <= on_disk


def test_other_dept_cannot_upload_or_download_dept_files(aapp, root):
    f = make_folder(root, "zz_mgr", "zz A팀 자료", scope="dept", dept="A팀")
    assert upload(as_user(aapp, "zz_emp"), f, [("a.txt", "비밀".encode())]).status_code == 303
    fid = sql(root, "SELECT id FROM lib_files WHERE folder_id=%s", (f,))[0][0]
    out = as_user(aapp, "zz_emp3")
    assert upload(out, f, [("b.txt", b"x")]).status_code == 403
    assert out.get(f"/library/files/{fid}").status_code == 403
    assert post(out, f"/library/files/{fid}/delete").status_code == 403
    assert as_user(aapp, "zz_adm").get(f"/library/files/{fid}").status_code == 200
    assert len(files_of(root, f)) == 1


def test_file_delete_rules_and_soft_delete(aapp, root):
    f = make_folder(root, "zz_adm")
    upload(as_user(aapp, "zz_emp"), f, [("지울거.txt", b"data")])
    fid = sql(root, "SELECT id FROM lib_files WHERE folder_id=%s", (f,))[0][0]
    assert post(as_user(aapp, "zz_emp2"), f"/library/files/{fid}/delete").status_code == 403         # 올린 사람이 아니다
    assert post(as_user(aapp, "zz_mgr"), f"/library/files/{fid}/delete").status_code == 403          # 팀장도 남의 파일은 못 지운다
    assert post(as_user(aapp, "zz_emp"), f"/library/files/{fid}/delete").status_code == 303
    assert post(as_user(aapp, "zz_emp"), f"/library/files/{fid}/delete").status_code == 409
    assert as_user(aapp, "zz_emp").get(f"/library/files/{fid}").status_code == 404
    assert "지울거.txt" not in as_user(aapp, "zz_emp").get(f"/library/folders/{f}").get_data(as_text=True)
    row = sql(root, "SELECT deleted_at, deleted_by FROM lib_files WHERE id=%s", (fid,))[0]
    assert row[0] is not None and row[1] == uid(root, "zz_emp")                                      # 기록은 남는다
    upload(as_user(aapp, "zz_emp"), f, [("지울거.txt", b"new")])                                      # 같은 이름을 다시 올리면 번호가 이어진다
    assert [r[1] for r in files_of(root, f)] == [1, 2]
    fid2 = sql(root, "SELECT id FROM lib_files WHERE version=2 AND folder_id=%s", (f,))[0][0]
    assert post(as_user(aapp, "zz_adm"), f"/library/files/{fid2}/delete").status_code == 303        # 관리자는 남의 파일도 지울 수 있다
    assert post(as_user(aapp, "zz_adm"), "/library/files/999999/delete").status_code == 404


def test_missing_file_on_disk_is_404_not_500(aapp, root, tmp_path):
    f = make_folder(root, "zz_adm")
    upload(as_user(aapp, "zz_emp"), f, [("a.txt", b"x")])
    stored = sql(root, "SELECT stored_name FROM lib_files WHERE folder_id=%s", (f,))[0][0]
    (tmp_path / "uploads" / stored).unlink()
    assert as_user(aapp, "zz_emp").get(f"/library/files/{sql(root, 'SELECT id FROM lib_files WHERE folder_id=%s', (f,))[0][0]}").status_code == 404


def test_folder_page_escapes_names_and_notes(aapp, root):
    f = make_folder(root, "zz_adm", "zz <b>폴더</b>")
    upload(as_user(aapp, "zz_emp"), f, [("<img src=x onerror=alert(1)>.txt", b"x")], note="<script>alert(1)</script>")
    page = as_user(aapp, "zz_emp").get(f"/library/folders/{f}").get_data(as_text=True)
    assert "<b>폴더</b>" not in page and "<script>alert(1)" not in page and "<img src=x" not in page


# =====================================================================================
# 주소록
# =====================================================================================
def contact_form(**over):
    return {"name": "홍길동", "company": "A사", "title": "과장", "phone": "02-123-4567", "email": "hong@example.com", "memo": "메모", **over}


def test_company_tab_lists_employees_and_filters(aapp, root):
    sql(root, "INSERT INTO employees(name,dept,title,ext,emp_no) VALUES('zz직원','A팀','대리','7777','ZZ-1')")
    c = as_user(aapp, "zz_emp")
    page = c.get("/library/contacts").get_data(as_text=True)
    assert "zz직원" in page and "7777" in page
    assert "zz직원" not in c.get("/library/contacts?q=%EA%B0%80%EB%82%98%EB%8B%A4").get_data(as_text=True)
    assert "zz직원" in c.get("/library/contacts?q=7777").get_data(as_text=True)


def test_personal_and_shared_contacts(aapp, root):
    c = as_user(aapp, "zz_emp")
    assert post(c, "/library/contacts/new", **contact_form(name="zz개인")).status_code == 303
    assert post(c, "/library/contacts/new", **contact_form(name="zz공유"), shared="1").status_code == 303
    mine = c.get("/library/contacts?tab=mine").get_data(as_text=True)
    assert "zz개인" in mine and "zz공유" in mine                                                  # 내 연락처에는 내가 만든 것이 모두(공유한 것 포함)
    assert "zz공유" in c.get("/library/contacts?tab=shared").get_data(as_text=True)
    other = as_user(aapp, "zz_emp3")
    assert "zz공유" in other.get("/library/contacts?tab=shared").get_data(as_text=True)
    assert "zz개인" not in other.get("/library/contacts?tab=shared").get_data(as_text=True)
    assert "zz개인" not in other.get("/library/contacts?tab=mine").get_data(as_text=True)
    assert "zz개인" not in as_user(aapp, "zz_adm").get("/library/contacts?tab=mine").get_data(as_text=True)   # 관리자도 남의 개인 연락처는 안 보인다


@pytest.mark.parametrize("bad", [
    {"name": ""}, {"name": "x" * 61}, {"name": "a\x00"}, {"company": "x" * 81}, {"title": "x" * 61}, {"memo": "x" * 201},
    {"phone": "abc"}, {"phone": "02-123-4567; DROP"}, {"phone": "1" * 31}, {"email": "no-at-sign"}, {"email": "a@b"},
    {"email": "a b@example.com"}, {"email": "<x>@example.com"}, {"email": "a@" + "b" * 130 + ".com"}, {"phone": "", "email": ""},
])
def test_contact_validation(aapp, root, bad):
    r = post(as_user(aapp, "zz_emp"), "/library/contacts/new", **contact_form(**bad))
    assert r.status_code == 400 and 'role="alert"' in r.get_data(as_text=True)
    assert sql(root, "SELECT COUNT(*) FROM contacts WHERE owner_id=%s", (uid(root, "zz_emp"),))[0][0] == 0


def test_contact_requires_only_one_of_phone_or_email(aapp, root):
    c = as_user(aapp, "zz_emp")
    assert post(c, "/library/contacts/new", **contact_form(name="zz전화만", email="")).status_code == 303
    assert post(c, "/library/contacts/new", **contact_form(name="zz메일만", phone="")).status_code == 303


def test_contact_values_are_escaped_and_kept_on_error(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = post(c, "/library/contacts/new", **contact_form(name="<script>alert(1)</script>", phone="bad"))
    html = r.get_data(as_text=True)
    assert r.status_code == 400 and "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    post(c, "/library/contacts/new", **contact_form(name="<b>굵게</b>", memo="<i>x</i>"))
    page = c.get("/library/contacts?tab=mine").get_data(as_text=True)
    assert "<b>굵게</b>" not in page and "<i>x</i>" not in page and "&lt;b&gt;" in page


def test_contact_delete_rules(aapp, root):
    post(as_user(aapp, "zz_emp"), "/library/contacts/new", **contact_form(name="zz지울것"), shared="1")
    cid = sql(root, "SELECT id FROM contacts WHERE name='zz지울것'")[0][0]
    assert post(as_user(aapp, "zz_emp3"), f"/library/contacts/{cid}/delete").status_code == 403
    assert post(as_user(aapp, "zz_mgr"), f"/library/contacts/{cid}/delete").status_code == 403
    assert post(as_user(aapp, "zz_adm"), f"/library/contacts/{cid}/delete").status_code == 303
    assert post(as_user(aapp, "zz_emp"), f"/library/contacts/{cid}/delete").status_code == 404
    assert "zz지울것" not in as_user(aapp, "zz_emp3").get("/library/contacts?tab=shared").get_data(as_text=True)
    assert sql(root, "SELECT deleted_at FROM contacts WHERE id=%s", (cid,))[0][0] is not None


@pytest.mark.parametrize("query", ["tab=nope", "tab=", "tab=MINE"])
def test_contact_tab_validation(aapp, root, query):
    assert as_user(aapp, "zz_emp").get(f"/library/contacts?{query}").status_code == 400


def test_contact_search_escapes_wildcards_and_limits_length(aapp, root):
    c = as_user(aapp, "zz_emp")
    post(c, "/library/contacts/new", **contact_form(name="zz퍼센트100%"))
    post(c, "/library/contacts/new", **contact_form(name="zz다른사람"))
    page = c.get("/library/contacts?tab=mine&q=%25").get_data(as_text=True)                          # q='%' 는 글자 그대로만 일치
    assert "zz퍼센트100%" in page and "zz다른사람" not in page
    assert c.get("/library/contacts?tab=mine&q=_").get_data(as_text=True).count("zz다른사람") == 0
    assert c.get("/library/contacts?tab=mine&q=" + "a" * 51).status_code == 400


# =====================================================================================
# 문서 검색
# =====================================================================================
def test_search_empty_and_invalid(aapp, root, events):
    c = as_user(aapp, "zz_emp")
    r = c.get("/library/search")
    assert r.status_code == 200 and "검색되었습니다" not in r.get_data(as_text=True)
    assert c.get("/library/search?q=" + "a" * 51).status_code == 400
    assert c.get("/library/search?q=a%00b").status_code == 400
    assert "검색 결과가 없습니다" in c.get("/library/search?q=zz%EC%97%86%EB%8A%94%EB%A7%90").get_data(as_text=True)


def test_search_finds_documents_posts_and_forms(aapp, root):
    sql(root, "INSERT INTO documents(title,body) VALUES('zz_문서 제목','본문 zz키워드')")
    sql(root, "INSERT INTO posts(board,author_id,title,body) VALUES('free',%s,'zz글 제목','zz키워드 내용')", (uid(root, "zz_emp2"),))
    sql(root, "INSERT INTO lib_forms(title,category,description,stored_name,orig_name,mime,size,sha256,uploaded_by) "
              "VALUES('zz키워드 서식','인사','',%s,'a.txt','text/plain',1,%s,%s)", ("0" * 36, "0" * 64, uid(root, "zz_adm")))
    page = as_user(aapp, "zz_emp").get("/library/search?q=zz%ED%82%A4%EC%9B%8C%EB%93%9C").get_data(as_text=True)
    for label in ("문서함", "게시판", "양식 모음"):
        assert f"<h2>{label} (1)</h2>" in page
    assert "3건" in page


def test_search_only_returns_approvals_the_user_may_see(aapp, root):
    sql(root, "INSERT INTO approvals(title,body,requester_id) VALUES('zz결재 비밀사항','내용',%s)", (uid(root, "zz_emp2"),))
    aid = sql(root, "SELECT MAX(id) FROM approvals")[0][0]
    sql(root, "INSERT INTO approval_steps(approval_id,step_no,approver_id) VALUES(%s,1,%s)", (aid, uid(root, "zz_mgr")))
    q = "/library/search?q=zz%EA%B2%B0%EC%9E%AC"
    seen = lambda who: "zz결재 비밀사항" in as_user(aapp, who).get(q).get_data(as_text=True)   # noqa: E731
    assert seen("zz_emp2") and seen("zz_mgr") and seen("zz_adm")                              # 상신자·결재자·관리자
    assert not seen("zz_emp") and not seen("zz_emp3") and not seen("zz_mgrb")                 # 관계없는 사람은 같은 부서여도 못 찾는다
    sql(root, "INSERT INTO approval_cc(approval_id,user_id) VALUES(%s,%s)", (aid, uid(root, "zz_emp")))
    assert seen("zz_emp")                                                                      # 참조자는 볼 수 있다


def test_search_never_includes_confidential_documents(aapp, root):
    sql(root, "INSERT INTO confidential_documents(title,body) VALUES('zz_기밀 계획','zz기밀키워드')")
    for who in ("zz_emp", "zz_mgr", "zz_adm"):
        page = as_user(aapp, who).get("/library/search?q=zz%EA%B8%B0%EB%B0%80").get_data(as_text=True)
        assert "zz_기밀 계획" not in page and "zz기밀키워드" not in page, who


def test_search_respects_folder_scope(aapp, root):
    a = make_folder(root, "zz_mgr", "zz A팀 폴더", scope="dept", dept="A팀")
    b = make_folder(root, "zz_mgrb", "zz B팀 폴더", scope="dept", dept="B팀")
    upload(as_user(aapp, "zz_emp"), a, [("zz검색파일A.txt", b"x")])
    upload(as_user(aapp, "zz_emp3"), b, [("zz검색파일B.txt", b"x")])
    q = "/library/search?q=zz%EA%B2%80%EC%83%89%ED%8C%8C%EC%9D%BC"
    mine = as_user(aapp, "zz_emp").get(q).get_data(as_text=True)
    assert "zz검색파일A.txt" in mine and "zz검색파일B.txt" not in mine
    both = as_user(aapp, "zz_adm").get(q).get_data(as_text=True)
    assert "zz검색파일A.txt" in both and "zz검색파일B.txt" in both
    sql(root, "UPDATE lib_files SET deleted_at=NOW() WHERE orig_name='zz검색파일A.txt'")
    assert "zz검색파일A.txt" not in as_user(aapp, "zz_emp").get(q).get_data(as_text=True)          # 삭제된 파일은 안 나온다


def test_search_tasks_and_contacts_are_limited_to_owner_and_shared(aapp, root):
    sql(root, "INSERT INTO tasks(title,creator_id,assignee_id) VALUES('zz검사업무',%s,%s)", (uid(root, "zz_emp"), uid(root, "zz_emp")))
    sql(root, "INSERT INTO contacts(owner_id,name,phone,shared) VALUES(%s,'zz검사연락처','010',0)", (uid(root, "zz_emp"),))
    q = "/library/search?q=zz%EA%B2%80%EC%82%AC"
    mine = as_user(aapp, "zz_emp").get(q).get_data(as_text=True)
    assert "zz검사업무" in mine and "zz검사연락처" in mine
    other = as_user(aapp, "zz_emp2").get(q).get_data(as_text=True)
    assert "zz검사업무" not in other and "zz검사연락처" not in other


def test_search_escapes_wildcards_and_html(aapp, root):
    sql(root, "INSERT INTO documents(title,body) VALUES('zz_100% 달성','본문')")
    sql(root, "INSERT INTO documents(title,body) VALUES('zz_다른문서','본문')")
    c = as_user(aapp, "zz_emp")
    page = c.get("/library/search?q=%25").get_data(as_text=True)
    assert "zz_100% 달성" in page and "zz_다른문서" not in page
    sql(root, "INSERT INTO documents(title,body) VALUES('zz_<script>alert(1)</script>','본문')")
    html = c.get("/library/search?q=zz_%3Cscript").get_data(as_text=True)
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html


def test_search_log_does_not_contain_the_query(aapp, root, events):
    as_user(aapp, "zz_emp").get("/library/search?q=%EB%B9%84%EB%B0%80%EA%B2%80%EC%83%89%EC%96%B4")
    logged = [e for e in events() if e["event_type"] == "search"]
    assert logged and all("비밀검색어" not in str(e) for e in logged) and logged[0]["length"] == 5


# =====================================================================================
# 양식 모음
# =====================================================================================
def upload_form(client, title="zz 서식", category="인사", body=b"form", name="양식.txt", **extra):
    data = {"csrf_token": csrf_of(client), "title": title, "category": category, "description": "설명", "file": (io.BytesIO(body), name), **extra}
    return client.post("/library/forms/upload", data=data, content_type="multipart/form-data")


def test_form_upload_download_delete(aapp, root):
    adm, emp = as_user(aapp, "zz_adm"), as_user(aapp, "zz_emp")
    assert upload_form(emp).status_code == 403
    assert upload_form(adm, body=b"hello form").status_code == 303
    fid = sql(root, "SELECT id FROM lib_forms WHERE title='zz 서식'")[0][0]
    assert "zz 서식" in emp.get("/library/forms").get_data(as_text=True)
    d = emp.get(f"/library/forms/{fid}/download")
    assert d.status_code == 200 and d.data == b"hello form" and d.headers["Content-Disposition"].startswith("attachment")
    assert post(emp, f"/library/forms/{fid}/delete").status_code == 403
    assert post(adm, f"/library/forms/{fid}/delete").status_code == 303
    assert emp.get(f"/library/forms/{fid}/download").status_code == 404
    assert "zz 서식" not in emp.get("/library/forms").get_data(as_text=True)
    assert post(adm, f"/library/forms/{fid}/delete").status_code == 404


@pytest.mark.parametrize("bad", [{"title": ""}, {"title": "x" * 101}, {"category": "기타종류"}, {"category": ""}, {"description": "x" * 201}])
def test_form_upload_validation(aapp, root, bad):
    assert upload_form(as_user(aapp, "zz_adm"), **bad).status_code == 409
    assert sql(root, "SELECT COUNT(*) FROM lib_forms WHERE uploaded_by=%s", (uid(root, "zz_adm"),))[0][0] == 0


def test_form_upload_requires_a_file(aapp, root):
    adm = as_user(aapp, "zz_adm")
    r = adm.post("/library/forms/upload", data={"csrf_token": csrf_of(adm), "title": "zz 파일없음", "category": "인사"}, content_type="multipart/form-data")
    assert r.status_code == 409


def test_form_list_has_approval_shortcuts_and_admin_only_controls(aapp, root):
    emp = as_user(aapp, "zz_emp").get("/library/forms").get_data(as_text=True)
    for label in ("일반 기안", "업무 협조", "출장 신청", "구매 요청", "지출결의서"):
        assert label in emp
    assert "/approvals/new?type=expenditure" in emp
    assert 'action="/library/forms/upload"' not in emp
    assert 'action="/library/forms/upload"' in as_user(aapp, "zz_adm").get("/library/forms").get_data(as_text=True)


# ---------- 메뉴 ----------
def test_menu_lists_new_items_and_marks_current_page(aapp):
    html = as_user(aapp, "zz_emp").get("/library").get_data(as_text=True)
    for label in ("업무 관리", "일정", "예약", "프로젝트", "자료실", "문서 검색", "양식 모음", "주소록"):
        assert f">{label}</a>" in html, label
    assert 'aria-current="page">자료실</a>' in html
    assert 'aria-current="page">주소록</a>' in as_user(aapp, "zz_emp").get("/library/contacts").get_data(as_text=True)
    assert 'aria-current="page">일정</a>' in as_user(aapp, "zz_emp").get("/work/calendar").get_data(as_text=True)
    assert 'aria-current="page">예약</a>' in as_user(aapp, "zz_emp").get("/work/reservations").get_data(as_text=True)
