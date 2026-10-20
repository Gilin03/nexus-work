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


# ---------- 첨부(제한 없음)용 저장 함수 ----------
import hashlib
import io

from werkzeug.datastructures import FileStorage


def _fs(name, data):
    return FileStorage(stream=io.BytesIO(data), filename=name)


@pytest.mark.parametrize("raw,expected", [
    ("report.pdf", "report.pdf"),
    ("../../etc/passwd", "passwd"),
    ("C:\\Windows\\system32\\evil.exe", "evil.exe"),
    (".htaccess", "htaccess"),
    ("...", "첨부파일"),
    ("", "첨부파일"),
    (None, "첨부파일"),
    ("<img src=x onerror=alert(1)>.png", "_img src_x onerror_alert_1__.png"),
    ("한글 파일(1).txt", "한글 파일_1_.txt"),
    ("a\x00b\nc.txt", "a_b_c.txt"),
])
def test_clean_name_keeps_only_safe_characters(raw, expected):
    assert uploads.clean_name(raw) == expected


def test_clean_name_truncates_but_keeps_the_extension():
    name = uploads.clean_name("가" * 300 + ".pdf")
    assert len(name) <= 120 and name.endswith(".pdf")
    assert len(uploads.clean_name("a" * 300)) == 120


@pytest.mark.parametrize("name,head,mime", [
    ("a.png", PNG, "image/png"), ("a.PNG", PNG, "image/png"), ("a.jpg", b"\xff\xd8\xff\xe0", "image/jpeg"),
    ("a.jpeg", b"\xff\xd8\xff\xe0", "image/jpeg"), ("a.pdf", b"%PDF-1.4", "application/pdf"),
    ("a.png", b"<html>", "application/octet-stream"), ("a.pdf", PNG, "application/octet-stream"),
    ("a.txt", b"\x00\x01", "text/plain"), ("a.php", b"<?php", "application/octet-stream"),
    ("noext", PNG, "application/octet-stream"), ("png", PNG, "application/octet-stream"),
])
def test_classify_never_rejects_it_only_labels(name, head, mime):
    assert uploads.classify(name, head) == mime


def test_save_attachment_streams_to_a_random_name_and_reports_size_and_hash(tmp_path):
    data = bytes(range(256)) * 20_000                                  # 약 5MB: 조각(1MB) 여러 개
    meta = uploads.save_attachment(tmp_path / "up", _fs("../x.bin", data))
    assert meta["orig_name"] == "x.bin" and meta["size"] == len(data) and meta["sha256"] == hashlib.sha256(data).hexdigest()
    assert meta["mime"] == "application/octet-stream" and len(meta["stored_name"]) == 36
    assert (tmp_path / "up" / meta["stored_name"]).read_bytes() == data
    assert [p.name for p in (tmp_path / "up").iterdir()] == [meta["stored_name"]]
    empty = uploads.save_attachment(tmp_path / "up", _fs("e.txt", b""))
    assert empty["size"] == 0 and empty["mime"] == "text/plain"


def test_save_attachment_removes_a_partial_file_when_reading_fails(tmp_path):
    class Boom(io.BytesIO):
        def read(self, n=-1):
            if not getattr(self, "_once", False):
                self._once = True
                return b"x" * 10
            raise OSError("disk error")
    with pytest.raises(OSError):
        uploads.save_attachment(tmp_path / "up", FileStorage(stream=Boom(), filename="a.bin"))
    assert list((tmp_path / "up").iterdir()) == []


def test_remove_saved_deletes_only_the_listed_files(tmp_path):
    a = uploads.save_attachment(tmp_path, _fs("a", b"1"))
    b = uploads.save_attachment(tmp_path, _fs("b", b"2"))
    uploads.remove_saved(tmp_path, [a])
    assert [p.name for p in tmp_path.iterdir()] == [b["stored_name"]]
    uploads.remove_saved(tmp_path, [a])                                  # 이미 없어도 오류 없음
