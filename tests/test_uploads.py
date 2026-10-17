import hashlib

import pytest

from app import uploads

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
PDF = b"%PDF-1.7\n%test"
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 16


@pytest.mark.parametrize("name,data,mime", [
    ("report.pdf", PDF, "application/pdf"),
    ("photo.PNG", PNG, "image/png"),
    ("pic.jpg", JPG, "image/jpeg"),
    ("메모.txt", "안녕하세요".encode("utf-8"), "text/plain"),
])
def test_allowed(name, data, mime):
    ext, got_mime, display, digest = uploads.inspect_upload(name, data)
    assert got_mime == mime and digest == hashlib.sha256(data).hexdigest()
    assert "/" not in display and "\\" not in display


@pytest.mark.parametrize("name,data,reason", [
    ("shell.php", b"<?php ?>", "extension_not_allowed"),
    ("shell.php.png", PNG, "extension_not_allowed"),       # 이중 확장자
    ("shell.png.php", PNG, "extension_not_allowed"),
    (".png", PNG, "extension_not_allowed"),                 # 이름 없는 확장자
    ("noext", PNG, "extension_not_allowed"),
    ("run.exe", b"MZ", "extension_not_allowed"),
    ("page.html", b"<script>", "extension_not_allowed"),
    ("fake.png", b"<?php system($_GET[0]); ?>", "content_mismatch"),   # 확장자와 내용 불일치
    ("fake.pdf", PNG, "content_mismatch"),
    ("bin.txt", b"abc\x00def", "content_mismatch"),
    ("latin.txt", "é".encode("latin-1"), "content_mismatch"),
    ("empty.txt", b"", "empty_upload"),
    ("", b"abc", "empty_upload"),
])
def test_rejected(name, data, reason):
    with pytest.raises(ValueError, match=reason):
        uploads.inspect_upload(name, data)


def test_path_in_filename_is_stripped():
    _, _, display, _ = uploads.inspect_upload("../../etc/cron.d/x.txt", b"hello")
    assert display == "x.txt"


def test_store_uses_random_name_outside_webroot(tmp_path):
    a = uploads.store(tmp_path / "up", b"one")
    b = uploads.store(tmp_path / "up", b"one")
    assert a != b and len(a) == 36
    assert (tmp_path / "up" / a).read_bytes() == b"one"
