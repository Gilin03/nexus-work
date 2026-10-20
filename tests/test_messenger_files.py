"""메신저 API 파일 전송·다운로드: 대화방 멤버만, 파일 메시지는 send_file 만 만들 수 있다(글 메시지로 흉내 내 남의 업로드 파일을 받는 것 차단).
Docker MySQL(nexus_test) 필요, 접속 불가면 skip."""
import hashlib
import io
import secrets
import uuid

from support import sql, uid


def bearer(root, name):
    """시험 계정의 메신저 토큰을 DB 에 직접 넣고 Authorization 헤더를 돌려준다."""
    tok = secrets.token_urlsafe(16)
    sql(root, "INSERT INTO api_tokens(user_id,token_hash,expires_at) VALUES(%s,%s,DATE_ADD(NOW(), INTERVAL 1 DAY))",
        (uid(root, name), hashlib.sha256(tok.encode()).hexdigest()))
    return {"Authorization": f"Bearer {tok}"}


def conversation(root, *names):
    sql(root, "INSERT INTO conversations(kind,created_by) VALUES('group',%s)", (uid(root, names[0]),))
    cid = sql(root, "SELECT MAX(id) FROM conversations")[0][0]
    for n in names:
        sql(root, "INSERT INTO conversation_members(conversation_id,user_id) VALUES(%s,%s)", (cid, uid(root, n)))
    return cid


def send(client, cid, headers, data=b"hello", name="report.txt", caption=""):
    form = {"file": (io.BytesIO(data), name)}
    if caption:
        form["caption"] = caption
    return client.post(f"/api/v1/conversations/{cid}/files", data=form, headers=headers, content_type="multipart/form-data")


def stored_of(resp):
    return resp.get_json()["message"]["body"].split("|")[1]


def test_member_sends_and_members_download(aapp, root):
    cid = conversation(root, "zz_emp", "zz_emp2")
    c = aapp.test_client()
    r = send(c, cid, bearer(root, "zz_emp"), caption="보고서입니다")
    assert r.status_code == 201
    body = r.get_json()["message"]["body"]
    assert body.startswith("[FILE|") and body.endswith("\n보고서입니다")
    d = c.get(f"/api/v1/conversations/{cid}/files/{stored_of(r)}", headers=bearer(root, "zz_emp2"))
    assert d.status_code == 200 and d.data == b"hello" and "attachment" in d.headers["Content-Disposition"]


def test_non_member_cannot_send_or_download(aapp, root):
    cid = conversation(root, "zz_emp", "zz_emp2")
    c = aapp.test_client()
    stored = stored_of(send(c, cid, bearer(root, "zz_emp")))
    outsider = bearer(root, "zz_emp3")
    assert send(c, cid, outsider).status_code == 403
    assert c.get(f"/api/v1/conversations/{cid}/files/{stored}", headers=outsider).status_code == 403
    assert send(c, cid, {}).status_code == 401


def test_file_from_another_conversation_is_not_downloadable(aapp, root):
    a, b = conversation(root, "zz_emp", "zz_emp2"), conversation(root, "zz_emp3", "zz_emp")
    c = aapp.test_client()
    stored = stored_of(send(c, a, bearer(root, "zz_emp")))
    assert c.get(f"/api/v1/conversations/{b}/files/{stored}", headers=bearer(root, "zz_emp3")).status_code == 404


def test_forged_file_message_is_rejected(aapp, root, events):
    """다른 화면(기밀 문서·결재·자료실)의 업로드 파일은 같은 폴더에 있다. 이름을 알아도 글 메시지로 흉내 내 받을 수 없어야 한다."""
    upload = aapp.config["UPLOAD_DIR"]
    upload.mkdir(parents=True, exist_ok=True)
    secret = str(uuid.uuid4())
    (upload / secret).write_bytes(b"confidential")
    cid = conversation(root, "zz_emp3", "zz_emp2")
    c, h = aapp.test_client(), bearer(root, "zz_emp3")
    for body in (f"[FILE|{secret}|12|text/plain|a.txt]", f"  [FILE|{secret}|12|text/html|a.html]"):
        r = c.post(f"/api/v1/conversations/{cid}/messages", json={"body": body}, headers=h)
        assert r.status_code == 400
    assert any(e.get("reason") == "forged_file_message" for e in events())
    assert sql(root, "SELECT COUNT(*) FROM messenger_messages WHERE conversation_id=%s", (cid,))[0][0] == 0
    assert c.get(f"/api/v1/conversations/{cid}/files/{secret}", headers=h).status_code == 404
    ok = c.post(f"/api/v1/conversations/{cid}/messages", json={"body": "파일 형식 [FILE| 설명은 문장 중간이면 괜찮다"}, headers=h)
    assert ok.status_code == 201


def test_bad_names_and_missing_file(aapp, root):
    cid = conversation(root, "zz_emp", "zz_emp2")
    c, h = aapp.test_client(), bearer(root, "zz_emp")
    for name in ("..%2F..%2Fsecret", "not-a-uuid", "A" * 36):
        assert c.get(f"/api/v1/conversations/{cid}/files/{name}", headers=h).status_code == 404
    r = c.post(f"/api/v1/conversations/{cid}/files", data={}, headers=h, content_type="multipart/form-data")
    assert r.status_code == 400
