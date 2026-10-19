"""프로필 사진: 올리기·바꾸기·지우기, 형식·내용 검사, 본인 것만 바꿀 수 있음, 이미지로만 내려줌. Docker MySQL(nexus_test) 필요, 접속 불가면 skip."""
import io

import pytest

from support import csrf_of, login, sql

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 16


def as_user(app, name):
    c = app.test_client()
    assert login(c, name).status_code == 303
    return c


def upload(client, filename, data, **extra):
    form = {"csrf_token": csrf_of(client), "photo": (io.BytesIO(data), filename), **extra}
    return client.post("/account/photo", data=form, content_type="multipart/form-data")


def uid(root, name):
    return sql(root, "SELECT id FROM users WHERE username=%s", (name,))[0][0]


def avatar_files(app):
    d = app.config["UPLOAD_DIR"] / "avatars"
    return sorted(p.name for p in d.glob("*")) if d.exists() else []


def test_pages_require_login(aapp):
    c = aapp.test_client()
    assert c.get("/account/photo").status_code == 303
    assert c.get("/users/1/photo").status_code == 303
    assert c.post("/account/photo").status_code == 403           # 로그인 없이 CSRF 단계에서 막힌다
    assert c.post("/account/photo/delete").status_code == 403


def test_without_photo_header_shows_initial_and_view_is_404(aapp, root):
    c = as_user(aapp, "zz_emp")
    html = c.get("/").get_data(as_text=True)
    assert 'class="avatar"' in html and "<img" not in html.split('class="avatar"')[1].split("</a>")[0]
    assert c.get(f"/users/{uid(root, 'zz_emp')}/photo").status_code == 404
    assert "아직 사진이 없어" in c.get("/account/photo").get_data(as_text=True)


def test_upload_png_shows_in_header_and_is_served_as_a_locked_down_image(aapp, root, events):
    c = as_user(aapp, "zz_emp")
    r = upload(c, "내사진.png", PNG)
    assert r.status_code == 303 and r.headers["Location"].endswith("/account/photo?saved=1")
    me = uid(root, "zz_emp")
    stored, mime, size = sql(root, "SELECT stored_name, mime, size FROM profile_photos WHERE user_id=%s", (me,))[0]
    assert mime == "image/png" and size == len(PNG) and len(stored) == 36
    assert avatar_files(aapp) == [stored]                              # 웹루트 밖 avatars/ 에 무작위 이름으로만 저장
    assert f'<img src="/users/{me}/photo"' in c.get("/").get_data(as_text=True)

    other = as_user(aapp, "zz_emp2")                                   # 다른 로그인 사용자도 볼 수 있다
    d = other.get(f"/users/{me}/photo")
    assert d.status_code == 200 and d.data == PNG and d.headers["Content-Type"] == "image/png"
    assert not d.headers.get("Content-Disposition", "").startswith("attachment")
    assert d.headers["Content-Security-Policy"] == "default-src 'none'; sandbox"
    assert d.headers["X-Content-Type-Options"] == "nosniff" and d.headers["X-Frame-Options"] == "DENY"
    assert d.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert any(e["event_type"] == "profile_photo_changed" and e["decision"] == "INFO" for e in events())


def test_replacing_keeps_one_row_and_one_file(aapp, root):
    c = as_user(aapp, "zz_emp")
    upload(c, "a.png", PNG)
    first = avatar_files(aapp)
    assert upload(c, "b.jpg", JPG).status_code == 303
    me = uid(root, "zz_emp")
    rows = sql(root, "SELECT stored_name, mime FROM profile_photos WHERE user_id=%s", (me,))
    assert len(rows) == 1 and rows[0][1] == "image/jpeg"
    assert avatar_files(aapp) == [rows[0][0]] and avatar_files(aapp) != first   # 이전 파일은 지워진다
    assert c.get(f"/users/{me}/photo").data == JPG


@pytest.mark.parametrize("filename,data,reason", [
    ("메모.txt", b"hello", "extension_not_allowed"),
    ("문서.pdf", b"%PDF-1.4\n%%EOF\n", "extension_not_allowed"),           # 첨부와 달리 사진은 pdf 불가
    ("shell.php", b"<?php system($_GET[0]); ?>", "extension_not_allowed"),
    ("shell.php.png", PNG, "extension_not_allowed"),                        # 이중 확장자
    ("가짜.png", b"<html><script>alert(1)</script></html>", "content_mismatch"),
    ("가짜.jpg", PNG, "content_mismatch"),
])
def test_rejects_wrong_type_or_content(aapp, root, events, filename, data, reason):
    c = as_user(aapp, "zz_emp")
    r = upload(c, filename, data)
    assert r.status_code == 400 and "<script>alert" not in r.get_data(as_text=True)
    assert sql(root, "SELECT COUNT(*) FROM profile_photos")[0][0] == 0 and avatar_files(aapp) == []
    assert any(e["event_type"] == "upload_reject" and e["reason"] == reason and e.get("target") == "profile_photo" for e in events())


def test_empty_and_oversized_uploads_are_rejected(aapp, root):
    c = as_user(aapp, "zz_emp")
    assert c.post("/account/photo", data={"csrf_token": csrf_of(c)}, content_type="multipart/form-data").status_code == 400
    assert upload(c, "큰.png", PNG + b"\x00" * (2 * 1024 * 1024 + 10)).status_code == 413
    assert sql(root, "SELECT COUNT(*) FROM profile_photos")[0][0] == 0


def test_upload_requires_csrf(aapp, root):
    c = as_user(aapp, "zz_emp")
    r = c.post("/account/photo", data={"photo": (io.BytesIO(PNG), "a.png")}, content_type="multipart/form-data")
    assert r.status_code == 403 and sql(root, "SELECT COUNT(*) FROM profile_photos")[0][0] == 0


def test_a_user_can_only_change_their_own_photo(aapp, root):
    victim = uid(root, "zz_emp2")
    c = as_user(aapp, "zz_emp")
    upload(c, "a.png", PNG, user_id=str(victim))                          # 폼에 남의 user_id 를 실어 보내도 무시된다
    owners = [r[0] for r in sql(root, "SELECT user_id FROM profile_photos")]
    assert owners == [uid(root, "zz_emp")]


def test_delete_removes_row_and_file_and_is_idempotent(aapp, root):
    c = as_user(aapp, "zz_emp")
    upload(c, "a.png", PNG)
    other = as_user(aapp, "zz_emp2")
    upload(other, "o.png", PNG)
    r = c.post("/account/photo/delete", data={"csrf_token": csrf_of(c)})
    assert r.status_code == 303
    assert [x[0] for x in sql(root, "SELECT user_id FROM profile_photos")] == [uid(root, "zz_emp2")]   # 남의 사진은 그대로
    assert len(avatar_files(aapp)) == 1
    assert c.post("/account/photo/delete", data={"csrf_token": csrf_of(c)}).status_code == 303          # 없어도 오류 없음
    assert c.get(f"/users/{uid(root, 'zz_emp')}/photo").status_code == 404


def test_missing_file_on_disk_is_404_not_500(aapp, root):
    c = as_user(aapp, "zz_emp")
    upload(c, "a.png", PNG)
    (aapp.config["UPLOAD_DIR"] / "avatars" / avatar_files(aapp)[0]).unlink()
    assert c.get(f"/users/{uid(root, 'zz_emp')}/photo").status_code == 404
    assert c.get("/users/999999/photo").status_code == 404


def test_form_page_loads_own_script_and_csp_stays_strict(aapp):
    c = as_user(aapp, "zz_emp")
    page = c.get("/account/photo")
    html = page.get_data(as_text=True)
    assert 'src="/static/photo-preview.js"' in html and 'accept=".png,.jpg"' in html
    assert "script-src 'self'" in page.headers["Content-Security-Policy"]
    assert c.get("/static/photo-preview.js").status_code == 200
