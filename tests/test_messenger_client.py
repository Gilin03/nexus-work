"""메신저 API: 자동 업데이트(서명된 설치 파일만 알리고 내준다)와 프로필 사진(본인만 바꾸고, 형식·크기 제한).
Docker MySQL(nexus_test) 필요, 접속 불가면 skip."""
import base64
import hashlib
import io
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from support import sql, uid
from test_messenger_files import bearer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sign_messenger_setup  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))      # 시험 전용 키


def setup_file(aapp, tmp_path, data=b"MZ fake installer", signed=True):
    path = tmp_path / "NEXUS_Messenger_Setup.exe"
    path.write_bytes(data)
    aapp.config["MESSENGER_SETUP_PATH"] = path
    if signed:
        sign_messenger_setup.sign(path, KEY)
    return path


def test_unsigned_setup_is_not_offered(aapp, root, tmp_path):
    setup_file(aapp, tmp_path, signed=False)
    c, h = aapp.test_client(), bearer(root, "zz_emp")
    assert c.get("/api/v1/client/version", headers=h).get_json()["available"] is False
    assert c.get("/api/v1/client/setup", headers=h).status_code == 404


def test_signed_setup_is_offered_with_hash_and_signature(aapp, root, tmp_path):
    data = b"MZ signed installer"
    setup_file(aapp, tmp_path, data)
    c, h = aapp.test_client(), bearer(root, "zz_emp")
    v = c.get("/api/v1/client/version", headers=h).get_json()
    digest = hashlib.sha256(data).hexdigest()
    assert v["available"] is True and v["format"] == "nexus-messenger-update-v1" and v["sha256"] == digest and v["size"] == len(data)
    KEY.public_key().verify(base64.b64decode(v["signature"]), sign_messenger_setup.message(digest, len(data)))  # 클라이언트와 같은 검증
    d = c.get("/api/v1/client/setup", headers=h)
    assert d.status_code == 200 and d.data == data and "attachment" in d.headers["Content-Disposition"]
    assert c.get("/api/v1/client/version").status_code == 401                                       # 토큰 필요


def test_setup_replaced_after_signing_is_not_offered(aapp, root, tmp_path, events):
    path = setup_file(aapp, tmp_path)
    path.write_bytes(b"MZ swapped by attacker")                   # 서명 뒤에 파일만 바뀜
    c, h = aapp.test_client(), bearer(root, "zz_emp")
    assert c.get("/api/v1/client/version", headers=h).get_json()["available"] is False
    assert c.get("/api/v1/client/setup", headers=h).status_code == 404
    assert any(e["event_type"] == "messenger_client_update_unsigned" for e in events())
    sig = path.with_name(path.name + ".sig")
    sig.write_text(json.dumps({**json.loads(sig.read_text(encoding="utf-8")), "format": "other"}), encoding="utf-8")
    assert c.get("/api/v1/client/version", headers=h).get_json()["available"] is False


def upload_photo(c, h, name, data):
    return c.post("/api/v1/account/photo", data={"photo": (io.BytesIO(data), name)}, headers=h, content_type="multipart/form-data")


def test_profile_photo_upload_view_and_delete(aapp, root):
    me = uid(root, "zz_emp")
    c, h = aapp.test_client(), bearer(root, "zz_emp")
    assert c.get(f"/api/v1/users/{me}/photo", headers=h).status_code == 404
    r = upload_photo(c, h, "me.jpeg", b"\xff\xd8\xff" + b"\x00" * 16)
    assert r.status_code == 200 and r.get_json()["mime"] == "image/jpeg"
    assert upload_photo(c, h, "me.png", PNG).status_code == 200                                     # 바꾸면 한 장만 남는다
    assert sql(root, "SELECT COUNT(*) FROM profile_photos WHERE user_id=%s", (me,))[0][0] == 1
    other = bearer(root, "zz_emp3")
    d = c.get(f"/api/v1/users/{me}/photo", headers=other)
    assert d.status_code == 200 and d.data == PNG and d.headers["X-Content-Type-Options"] == "nosniff"
    d.close()                                                     # Windows 는 열린 파일을 지우지 못한다
    assert c.delete("/api/v1/account/photo", headers=h).status_code == 200
    assert c.get(f"/api/v1/users/{me}/photo", headers=other).status_code == 404


def test_profile_photo_rejects_bad_files(aapp, root):
    c, h = aapp.test_client(), bearer(root, "zz_emp")
    for name, data in (("a.gif", b"GIF89a" + b"\x00" * 10), ("a.png", b"<html><script>alert(1)</script>"),
                       ("shell.php.png", PNG), ("noext", PNG)):
        assert upload_photo(c, h, name, data).status_code == 400, name
    assert c.post("/api/v1/account/photo", data={}, headers=h, content_type="multipart/form-data").status_code == 400
    assert not sql(root, "SELECT 1 FROM profile_photos WHERE user_id=%s", (uid(root, "zz_emp"),))


def test_profile_photo_body_limit_stops_before_reading(aapp, root):
    c, h = aapp.test_client(), bearer(root, "zz_emp")
    big = PNG + b"\x00" * (11 * 1024 * 1024)
    assert upload_photo(c, h, "big.png", big).status_code == 413
    assert upload_photo(c, h, "ok.png", PNG + b"\x00" * (9 * 1024 * 1024)).status_code == 200      # 10MB 안쪽은 된다(웹의 2MB 보다 큼)
