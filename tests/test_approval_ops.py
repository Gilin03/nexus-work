"""전자결재 확장: 양식·문서번호·긴급, 참조자, 첨부, 결재 의견, 문서함, 결재 대기 배지, 재기안. Docker MySQL(nexus_test) 필요, 접속 불가면 skip.
부서: A팀(zz_emp, zz_emp2, zz_mgr) / B팀(zz_emp3, zz_mgrb) / 관리팀(zz_adm)"""
import io
import re

import pytest

from support import as_user, csrf_of, post, sql, uid

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
PDF = b"%PDF-1.4\n%%EOF\n"


def chain(root, *names):
    return {f"approver_{n}": uid(root, name) for n, name in enumerate(names, start=1)}


def submit(client, root, approvers=("zz_mgr",), cc=(), files=(), title="zz_결재", body="내용", **extra):
    form = {"csrf_token": csrf_of(client), "title": title, "body": body, **chain(root, *approvers), **extra}
    if cc:
        form["cc"] = [str(uid(root, n)) if isinstance(n, str) else str(n) for n in cc]
    if files:
        form["attachments"] = [(io.BytesIO(data), name) for name, data in files]
    return client.post("/approvals/new", data=form, content_type="multipart/form-data")


def last_id(root):
    return sql(root, "SELECT MAX(id) FROM approvals")[0][0]


def count(root):
    return sql(root, "SELECT COUNT(*) FROM approvals")[0][0]


def approval_dir(app):
    return app.config["UPLOAD_DIR"] / "approvals"


# ---------- 양식·문서번호·긴급 ----------
def test_form_type_is_stored_and_shown_with_a_document_number(aapp, root):
    r = submit(as_user(aapp, "zz_emp"), root, doc_type="trip", urgency="urgent", title="zz_출장")
    assert r.status_code == 303
    aid = last_id(root)
    year = sql(root, "SELECT YEAR(created_at) FROM approvals WHERE id=%s", (aid,))[0][0]
    assert sql(root, "SELECT doc_type, urgency FROM approvals WHERE id=%s", (aid,))[0] == ("trip", "urgent")
    html = as_user(aapp, "zz_emp").get(f"/approvals/{aid}").get_data(as_text=True)
    assert f"NX-TRP-{year}-{aid:05d}" in html and "출장 신청" in html and "긴급" in html


@pytest.mark.parametrize("field,value", [("doc_type", "expense"), ("doc_type", "hack"), ("doc_type", ""), ("urgency", "critical"), ("urgency", "")])
def test_invalid_form_choices_are_rejected(aapp, root, field, value):
    assert submit(as_user(aapp, "zz_emp"), root, **{field: value}).status_code == 400   # 경비 양식은 경비 화면에서만 만들어진다
    assert count(root) == 0


def test_missing_form_choice_defaults_to_a_plain_general_request(aapp, root):
    assert submit(as_user(aapp, "zz_emp"), root).status_code == 303
    assert sql(root, "SELECT doc_type, urgency FROM approvals")[0] == ("general", "normal")


def test_form_page_fills_a_template_per_type_and_ignores_unknown_types(aapp):
    c = as_user(aapp, "zz_emp")
    assert "출장지" in c.get("/approvals/new?type=trip").get_data(as_text=True)
    assert "구매 품목" in c.get("/approvals/new?type=purchase").get_data(as_text=True)
    html = c.get("/approvals/new?type=../../etc").get_data(as_text=True)
    assert "출장지" not in html and "일반 기안" in html


def test_expense_approval_gets_the_expense_form_type_and_number(aapp, root):
    with root.cursor() as cur:
        cur.execute("INSERT INTO expenses(user_id,title,amount,status) VALUES(%s,'zz_경비',1000,'draft')", (uid(root, "zz_emp"),))
        eid = cur.lastrowid
    c = as_user(aapp, "zz_emp")
    assert post(c, f"/expenses/{eid}/submit", **chain(root, "zz_mgr")).status_code == 303
    aid = last_id(root)
    assert sql(root, "SELECT doc_type FROM approvals WHERE id=%s", (aid,))[0][0] == "expense"
    assert f"NX-EXP-" in c.get(f"/approvals/{aid}").get_data(as_text=True)


# ---------- 참조자 ----------
def test_cc_can_read_but_not_decide_and_is_listed_in_the_cc_box(aapp, root, events):
    submit(as_user(aapp, "zz_emp"), root, cc=("zz_emp2", "zz_adm"))
    aid = last_id(root)
    assert sorted(r[0] for r in sql(root, "SELECT user_id FROM approval_cc WHERE approval_id=%s", (aid,))) == sorted([uid(root, "zz_emp2"), uid(root, "zz_adm")])
    cc = as_user(aapp, "zz_emp2")                                                         # 일반 직원도 참조자가 될 수 있다
    assert cc.get(f"/approvals/{aid}").status_code == 200
    assert "zz_결재" in cc.get("/approvals?box=cc").get_data(as_text=True) and "zz_결재" in cc.get("/approvals").get_data(as_text=True)
    assert post(cc, f"/approvals/{aid}/decide", decision="approve").status_code == 403    # 참조자는 결재할 수 없다
    assert any(e["reason"] == "not_approver" for e in events())
    assert sql(root, "SELECT status FROM approvals WHERE id=%s", (aid,))[0][0] == "pending"
    assert as_user(aapp, "zz_emp3").get(f"/approvals/{aid}").status_code == 403           # 참조자가 아닌 제3자는 볼 수 없다


@pytest.mark.parametrize("make,expected", [
    (lambda root: {"cc": [str(uid(root, "zz_emp"))]}, "본인"),                  # 본인
    (lambda root: {"cc": [str(uid(root, "zz_mgr"))]}, "결재자"),               # 결재자와 중복
    (lambda root: {"cc": ["999999"]}, "참조자"),                                # 없는 사용자
    (lambda root: {"cc": ["abc"]}, None),                                      # 숫자가 아닌 값은 무시된다
    (lambda root: {"cc": [str(uid(root, "zz_emp2"))] * 3}, None),              # 중복은 하나로
])
def test_invalid_cc_is_rejected_or_normalised(aapp, root, make, expected):
    form = {"csrf_token": None, "title": "zz_결재", "body": "내용", **chain(root, "zz_mgr"), **make(root)}
    c = as_user(aapp, "zz_emp")
    form["csrf_token"] = csrf_of(c)
    r = c.post("/approvals/new", data=form, content_type="multipart/form-data")
    if expected:
        assert r.status_code == 400 and expected in r.get_data(as_text=True) and count(root) == 0
    else:
        assert r.status_code in (303, 400)
        assert sql(root, "SELECT COUNT(*) FROM approval_cc")[0][0] <= 1


def test_too_many_cc_is_rejected(aapp, root):
    users = [uid(root, n) for n in ("zz_emp2", "zz_emp3", "zz_mgrb", "zz_adm")]
    with root.cursor() as cur:                                                          # 11명을 채우려고 시험용 사용자를 더 만든다
        from support import PW_HASH
        for i in range(8):
            cur.execute("INSERT INTO users(username,password_hash,role,display_name,dept) VALUES(%s,%s,'employee',%s,'A팀')",
                        (f"zz_extra{i}", PW_HASH, f"zz_extra{i}"))
            users.append(cur.lastrowid)
    assert submit(as_user(aapp, "zz_emp"), root, cc=users).status_code == 400            # 12명 > 10명
    assert count(root) == 0


def test_cc_cannot_be_changed_after_submitting(aapp, root):
    submit(as_user(aapp, "zz_emp"), root, cc=("zz_emp2",))
    aid = last_id(root)
    c = as_user(aapp, "zz_emp")
    before = sql(root, "SELECT user_id FROM approval_cc WHERE approval_id=%s", (aid,))
    for path in (f"/approvals/{aid}/cc", f"/approvals/{aid}/edit"):
        assert c.post(path, data={"csrf_token": csrf_of(c), "cc": str(uid(root, "zz_adm"))}).status_code in (404, 405)
    assert sql(root, "SELECT user_id FROM approval_cc WHERE approval_id=%s", (aid,)) == before


# ---------- 첨부 ----------
def test_files_are_stored_outside_the_web_root_and_only_parties_can_download(aapp, root, events):
    r = submit(as_user(aapp, "zz_emp"), root, cc=("zz_emp2",), files=[("견적서.pdf", PDF), ("현장.png", PNG), ("메모.txt", b"hello")])
    assert r.status_code == 303
    aid = last_id(root)
    rows = sql(root, "SELECT id, stored_name, orig_name, mime FROM approval_files WHERE approval_id=%s ORDER BY id", (aid,))
    assert [x[2] for x in rows] == ["견적서.pdf", "현장.png", "메모.txt"] and all(len(x[1]) == 36 for x in rows)
    assert sorted(p.name for p in approval_dir(aapp).glob("*")) == sorted(x[1] for x in rows)
    fid = rows[0][0]
    for who in ("zz_emp", "zz_mgr", "zz_emp2", "zz_adm"):                                # 상신자·결재자·참조자·관리자
        d = as_user(aapp, who).get(f"/approvals/{aid}/files/{fid}")
        assert d.status_code == 200 and d.data == PDF and d.headers["Content-Disposition"].startswith("attachment")
        assert d.headers["X-Content-Type-Options"] == "nosniff"
    assert as_user(aapp, "zz_emp3").get(f"/approvals/{aid}/files/{fid}").status_code == 403   # 제3자
    assert aapp.test_client().get(f"/approvals/{aid}/files/{fid}").status_code == 303        # 비로그인
    assert any(e["event_type"] == "approval_file_download" for e in events())
    html = as_user(aapp, "zz_mgr").get(f"/approvals/{aid}").get_data(as_text=True)
    assert "견적서.pdf" in html and f"/approvals/{aid}/files/{fid}" in html


def test_file_id_from_another_approval_is_not_reachable(aapp, root):
    submit(as_user(aapp, "zz_emp"), root, files=[("a.png", PNG)])
    mine = last_id(root)
    submit(as_user(aapp, "zz_emp3"), root, approvers=("zz_mgrb",), files=[("b.png", PNG)])
    other = last_id(root)
    fid_other = sql(root, "SELECT id FROM approval_files WHERE approval_id=%s", (other,))[0][0]
    c = as_user(aapp, "zz_emp")
    assert c.get(f"/approvals/{mine}/files/{fid_other}").status_code == 404                  # 내 문서 주소에 남의 파일 번호
    assert c.get(f"/approvals/{other}/files/{fid_other}").status_code == 403                 # 남의 문서는 열람 자체가 막힌다
    assert c.get(f"/approvals/{mine}/files/999999").status_code == 404


def test_any_number_type_and_size_of_files_is_accepted_on_submission(aapp, root):
    files = [("shell.php", b"<?php ?>"), ("run.exe", b"MZ"), ("page.html", b"<script>alert(1)</script>"), ("noext", b"x"),
             ("가짜.png", b"<html>"), ("진짜.png", PNG), ("큰파일.bin", b"0123456789abcdef" * (512 * 1024))] + [(f"f{i}.txt", b"x") for i in range(8)]
    r = submit(as_user(aapp, "zz_emp"), root, files=files)
    assert r.status_code == 303                                                                    # 15개, 형식 무관, 8MB 파일 포함
    aid = last_id(root)
    rows = sql(root, "SELECT orig_name, mime, size FROM approval_files WHERE approval_id=%s ORDER BY id", (aid,))
    assert len(rows) == 15 and stored_count(aapp) == 15 and rows[6][2] == 8 * 1024 * 1024
    assert {r[0]: r[1] for r in rows}["shell.php"] == "application/octet-stream" and {r[0]: r[1] for r in rows}["진짜.png"] == "image/png"
    fid = sql(root, "SELECT id FROM approval_files WHERE approval_id=%s AND orig_name='shell.php'", (aid,))[0][0]
    d = as_user(aapp, "zz_mgr").get(f"/approvals/{aid}/files/{fid}")                              # 위험한 파일도 항상 다운로드로만
    assert d.status_code == 200 and d.headers["Content-Disposition"].startswith("attachment") and d.headers["X-Content-Type-Options"] == "nosniff"
    assert d.headers["Content-Type"].startswith("application/octet-stream")


def test_attachments_written_before_a_failure_are_removed_on_submission(aapp, root, monkeypatch):
    from app import uploads
    real, calls = uploads.save_attachment, []

    def flaky(directory, storage):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("disk full")
        return real(directory, storage)
    monkeypatch.setattr(uploads, "save_attachment", flaky)
    assert submit(as_user(aapp, "zz_emp"), root, files=[("a.dat", b"a"), ("b.dat", b"b")]).status_code == 500                      # 앱이 예외를 오류 화면(500)으로 처리하고 DB 는 롤백된다
    assert count(root) == 0 and stored_count(aapp) == 0 and sql(root, "SELECT COUNT(*) FROM approval_files")[0][0] == 0


# ---------- 결재 의견 ----------
def test_approver_can_leave_a_comment_that_is_shown_and_kept(aapp, root):
    submit(as_user(aapp, "zz_emp"), root, approvers=("zz_mgr", "zz_adm"))
    aid = last_id(root)
    assert post(as_user(aapp, "zz_mgr"), f"/approvals/{aid}/decide", decision="approve", comment="금액 확인했습니다").status_code == 303
    assert sql(root, "SELECT status, reason FROM approval_steps WHERE approval_id=%s AND step_no=1", (aid,))[0] == ("approved", "금액 확인했습니다")
    html = as_user(aapp, "zz_emp").get(f"/approvals/{aid}").get_data(as_text=True)
    assert "결재 의견" in html and "금액 확인했습니다" in html and "반려 사유" not in html


def test_comment_is_optional_and_validated(aapp, root):
    submit(as_user(aapp, "zz_emp"), root)
    aid = last_id(root)
    mgr = as_user(aapp, "zz_mgr")
    assert post(mgr, f"/approvals/{aid}/decide", decision="approve", comment="가" * 501).status_code == 400
    assert post(mgr, f"/approvals/{aid}/decide", decision="approve", comment="줄\x00바꿈").status_code == 400
    assert sql(root, "SELECT status FROM approvals WHERE id=%s", (aid,))[0][0] == "pending"        # 거부되면 아무것도 바뀌지 않는다
    assert post(mgr, f"/approvals/{aid}/decide", decision="approve").status_code == 303            # 의견 없이도 승인된다
    assert sql(root, "SELECT reason FROM approval_steps WHERE approval_id=%s", (aid,))[0][0] is None


def test_rejection_still_needs_a_reason_even_with_a_comment(aapp, root):
    submit(as_user(aapp, "zz_emp"), root)
    aid = last_id(root)
    assert post(as_user(aapp, "zz_mgr"), f"/approvals/{aid}/decide", decision="reject", comment="의견만").status_code == 400
    assert sql(root, "SELECT status FROM approvals WHERE id=%s", (aid,))[0][0] == "pending"


# ---------- 문서함 ----------
def test_boxes_split_documents_by_my_role_and_counts_match(aapp, root):
    submit(as_user(aapp, "zz_emp"), root, approvers=("zz_mgr", "zz_adm"), title="zz_A", cc=("zz_emp2",))   # mgr 차례, adm 예정
    a = last_id(root)
    submit(as_user(aapp, "zz_mgr"), root, approvers=("zz_adm",), title="zz_B")                            # mgr 가 기안
    mgr, adm, emp2 = as_user(aapp, "zz_mgr"), as_user(aapp, "zz_adm"), as_user(aapp, "zz_emp2")
    page = lambda c, box: c.get(f"/approvals?box={box}").get_data(as_text=True)
    assert "zz_A" in page(mgr, "wait") and "zz_B" not in page(mgr, "wait")
    assert "zz_B" in page(mgr, "mine") and "zz_A" not in page(mgr, "mine")
    assert "zz_A" in page(adm, "soon") and "zz_A" not in page(adm, "wait") and "zz_B" in page(adm, "wait")
    assert "zz_A" in page(emp2, "cc") and "zz_A" not in page(emp2, "mine")
    assert post(mgr, f"/approvals/{a}/decide", decision="approve").status_code == 303
    assert "zz_A" in page(mgr, "done") and "zz_A" not in page(mgr, "wait")                              # 처리하면 대기에서 완료로
    assert "zz_A" in page(adm, "wait") and "zz_A" not in page(adm, "soon")                              # 다음 차례로 넘어옴
    html = adm.get("/approvals").get_data(as_text=True)
    assert re.search(r"결재 대기 <span class=\"count\">2</span>", html)                                   # 탭의 건수
    assert "지금 결재할 문서가 2건" in html


@pytest.mark.parametrize("box", ["everything", "ALL", "wait;drop", "", "1"])
def test_unknown_box_is_rejected(aapp, box):
    assert as_user(aapp, "zz_emp").get("/approvals", query_string={"box": box}).status_code == 400


def test_other_users_documents_never_appear_in_personal_boxes(aapp, root):
    submit(as_user(aapp, "zz_emp3"), root, approvers=("zz_mgrb",), title="zz_남의문서")
    for box in ("all", "mine", "wait", "soon", "done", "cc"):
        assert "zz_남의문서" not in as_user(aapp, "zz_emp").get(f"/approvals?box={box}").get_data(as_text=True)
    adm = as_user(aapp, "zz_adm")
    assert "zz_남의문서" in adm.get("/approvals").get_data(as_text=True)                                 # 관리자의 전체 보기에는 보인다
    assert "zz_남의문서" not in adm.get("/approvals?box=mine").get_data(as_text=True)                    # 나머지 문서함은 개인 기준


def test_urgent_pending_documents_come_first(aapp, root):
    c = as_user(aapp, "zz_emp")
    submit(c, root, title="zz_보통")
    submit(c, root, title="zz_긴급", urgency="urgent")
    html = c.get("/approvals?box=mine").get_data(as_text=True)
    assert html.index("zz_긴급") < html.index("zz_보통") and ">긴급<" in html


# ---------- 결재 대기 배지 ----------
def test_pending_badge_counts_only_my_turn_and_shows_on_home(aapp, root):
    submit(as_user(aapp, "zz_emp"), root, approvers=("zz_mgr", "zz_adm"))
    submit(as_user(aapp, "zz_emp2"), root, approvers=("zz_mgr",))
    mgr = as_user(aapp, "zz_mgr").get("/").get_data(as_text=True)
    assert 'aria-label="결재 대기 2건">2</span>' in mgr and "결재할 문서가 2건" in mgr
    adm = as_user(aapp, "zz_adm").get("/").get_data(as_text=True)                          # 2차 결재자는 아직 차례 전
    assert "결재 대기" not in adm and "결재할 문서가" not in adm
    assert "결재 대기" not in as_user(aapp, "zz_emp").get("/").get_data(as_text=True)


# ---------- 재기안 ----------
def test_requester_can_redraft_a_rejected_document_with_the_same_chain_and_cc(aapp, root):
    emp = as_user(aapp, "zz_emp")
    submit(emp, root, approvers=("zz_mgr", "zz_adm"), cc=("zz_emp2",), title="zz_원본", body="원본 내용", doc_type="purchase", urgency="urgent")
    old = last_id(root)
    post(as_user(aapp, "zz_mgr"), f"/approvals/{old}/decide", decision="reject", reason="금액 수정 필요")
    assert "다시 기안" in emp.get(f"/approvals/{old}").get_data(as_text=True)
    html = emp.get(f"/approvals/new?from={old}").get_data(as_text=True)
    assert 'value="[재기안] zz_원본"' in html and "원본 내용" in html and "구매 요청" in html
    assert re.search(rf'<option value="{uid(root, "zz_mgr")}" selected>', html) and re.search(rf'<option value="{uid(root, "zz_adm")}" selected>', html)
    assert re.search(rf'<option value="{uid(root, "zz_emp2")}" selected>', html)
    assert 'value="urgent" checked' in html
    assert submit(emp, root, approvers=("zz_mgr",), title="[재기안] zz_원본").status_code == 303
    assert last_id(root) != old and sql(root, "SELECT status FROM approvals WHERE id=%s", (old,))[0][0] == "rejected"   # 원본은 그대로


def test_withdrawn_documents_can_be_redrafted_but_open_ones_cannot(aapp, root):
    emp = as_user(aapp, "zz_emp")
    submit(emp, root, title="zz_철회")
    wd = last_id(root)
    assert emp.get(f"/approvals/new?from={wd}").status_code == 409                          # 진행 중
    assert "다시 기안" not in emp.get(f"/approvals/{wd}").get_data(as_text=True)
    post(emp, f"/approvals/{wd}/withdraw")
    assert emp.get(f"/approvals/new?from={wd}").status_code == 200


def test_only_the_requester_can_redraft_and_bad_ids_are_handled(aapp, root):
    submit(as_user(aapp, "zz_emp"), root)
    aid = last_id(root)
    post(as_user(aapp, "zz_mgr"), f"/approvals/{aid}/decide", decision="reject", reason="사유")
    assert as_user(aapp, "zz_mgr").get(f"/approvals/new?from={aid}").status_code == 403    # 결재자도 남의 문서는 복사 불가
    assert as_user(aapp, "zz_adm").get(f"/approvals/new?from={aid}").status_code == 403
    emp = as_user(aapp, "zz_emp")
    assert emp.get("/approvals/new?from=999999").status_code == 404
    assert emp.get("/approvals/new?from=abc").status_code == 404
    assert "다시 기안" not in as_user(aapp, "zz_mgr").get(f"/approvals/{aid}").get_data(as_text=True)


def test_rejected_expense_approvals_are_not_redraftable(aapp, root):
    with root.cursor() as cur:
        cur.execute("INSERT INTO expenses(user_id,title,amount,status) VALUES(%s,'zz_경비',1000,'draft')", (uid(root, "zz_emp"),))
        eid = cur.lastrowid
    emp = as_user(aapp, "zz_emp")
    post(emp, f"/expenses/{eid}/submit", **chain(root, "zz_mgr"))
    aid = last_id(root)
    post(as_user(aapp, "zz_mgr"), f"/approvals/{aid}/decide", decision="reject", reason="사유")
    assert emp.get(f"/approvals/new?from={aid}").status_code == 409
    assert "다시 기안" not in emp.get(f"/approvals/{aid}").get_data(as_text=True)


# ---------- 결재할 때 첨부 ----------
def decide(client, aid, decision="approve", files=(), **fields):
    form = {"csrf_token": csrf_of(client), "decision": decision, **fields}
    if files:
        form["attachments"] = [(io.BytesIO(data), name) for name, data in files]
    return client.post(f"/approvals/{aid}/decide", data=form, content_type="multipart/form-data")


def file_rows(root, aid):
    return sql(root, "SELECT orig_name, step_no, uploaded_by FROM approval_files WHERE approval_id=%s ORDER BY id", (aid,))


def stored_count(app):
    d = approval_dir(app)
    return len(list(d.glob("*"))) if d.exists() else 0


def test_approver_can_attach_files_when_approving_and_they_are_recorded_per_step(aapp, root, events):
    submit(as_user(aapp, "zz_emp"), root, approvers=("zz_mgr", "zz_adm"), cc=("zz_emp2",), files=[("견적서.pdf", PDF)])
    aid = last_id(root)
    r = decide(as_user(aapp, "zz_mgr"), aid, "approve", files=[("검토의견.txt", b"ok"), ("비교표.png", PNG)], comment="검토 자료 첨부합니다")
    assert r.status_code == 303
    assert file_rows(root, aid) == (("견적서.pdf", None, None), ("검토의견.txt", 1, uid(root, "zz_mgr")), ("비교표.png", 1, uid(root, "zz_mgr")))
    assert decide(as_user(aapp, "zz_adm"), aid, "approve", files=[("최종승인서.pdf", PDF)]).status_code == 303
    assert file_rows(root, aid)[-1] == ("최종승인서.pdf", 2, uid(root, "zz_adm"))
    assert stored_count(aapp) == 4
    html = as_user(aapp, "zz_emp").get(f"/approvals/{aid}").get_data(as_text=True)
    assert "상신 첨부" in html and "1차 결재 첨부" in html and "2차 결재 첨부" in html
    assert html.index("견적서.pdf") < html.index("검토의견.txt") < html.index("최종승인서.pdf")
    assert any(e["event_type"] == "approval_decided" and e.get("files") == 2 for e in events())
    for who in ("zz_emp", "zz_emp2", "zz_mgr", "zz_adm"):                                   # 상신자·참조자·결재자·관리자 모두 받을 수 있다
        fid = sql(root, "SELECT id FROM approval_files WHERE approval_id=%s AND orig_name='검토의견.txt'", (aid,))[0][0]
        d = as_user(aapp, who).get(f"/approvals/{aid}/files/{fid}")
        assert d.status_code == 200 and d.data == b"ok" and d.headers["Content-Disposition"].startswith("attachment")
    fid = sql(root, "SELECT id FROM approval_files WHERE approval_id=%s AND orig_name='검토의견.txt'", (aid,))[0][0]
    assert as_user(aapp, "zz_emp3").get(f"/approvals/{aid}/files/{fid}").status_code == 403    # 제3자는 받을 수 없다


def test_files_can_also_be_attached_when_rejecting(aapp, root):
    submit(as_user(aapp, "zz_emp"), root)
    aid = last_id(root)
    assert decide(as_user(aapp, "zz_mgr"), aid, "reject", files=[("수정요청.pdf", PDF)], reason="아래 양식으로 다시 작성하세요").status_code == 303
    assert sql(root, "SELECT status FROM approvals WHERE id=%s", (aid,))[0][0] == "rejected"
    assert file_rows(root, aid) == (("수정요청.pdf", 1, uid(root, "zz_mgr")),)
    html = as_user(aapp, "zz_emp").get(f"/approvals/{aid}").get_data(as_text=True)
    assert "1차 결재 첨부" in html and "수정요청.pdf" in html and "반려 사유" in html


def test_any_files_can_be_attached_when_deciding_too(aapp, root):
    submit(as_user(aapp, "zz_emp"), root)
    aid = last_id(root)
    files = [("shell.php", b"<?php ?>"), ("가짜.png", b"<html>"), ("큰파일.bin", b"0123456789abcdef" * (512 * 1024))] + [(f"x{i}.txt", b"x") for i in range(5)]
    assert decide(as_user(aapp, "zz_mgr"), aid, "approve", files=files).status_code == 303          # 8개, 형식 무관, 8MB 파일 포함
    assert sql(root, "SELECT status FROM approvals WHERE id=%s", (aid,))[0][0] == "approved"
    rows = file_rows(root, aid)
    assert len(rows) == 8 and all(r[1] == 1 and r[2] == uid(root, "zz_mgr") for r in rows) and stored_count(aapp) == 8


def test_decision_is_rolled_back_and_files_removed_if_saving_fails(aapp, root, monkeypatch):
    from app import uploads
    real, calls = uploads.save_attachment, []

    def flaky(directory, storage):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("disk full")
        return real(directory, storage)
    monkeypatch.setattr(uploads, "save_attachment", flaky)
    submit(as_user(aapp, "zz_emp"), root)
    aid = last_id(root)
    assert decide(as_user(aapp, "zz_mgr"), aid, "approve", files=[("a.dat", b"a"), ("b.dat", b"b")]).status_code == 500                      # 앱이 예외를 오류 화면(500)으로 처리하고 DB 는 롤백된다
    assert sql(root, "SELECT status FROM approvals WHERE id=%s", (aid,))[0][0] == "pending"        # 결재 처리도 함께 취소된다
    assert sql(root, "SELECT status FROM approval_steps WHERE approval_id=%s", (aid,))[0][0] == "pending"
    assert not file_rows(root, aid) and stored_count(aapp) == 0


def test_invalid_comment_or_reason_stores_no_files(aapp, root):
    submit(as_user(aapp, "zz_emp"), root)
    aid = last_id(root)
    mgr = as_user(aapp, "zz_mgr")
    assert decide(mgr, aid, "approve", files=[("a.png", PNG)], comment="가" * 501).status_code == 400
    assert decide(mgr, aid, "reject", files=[("a.png", PNG)], reason="").status_code == 400
    assert not file_rows(root, aid) and stored_count(aapp) == 0
    assert sql(root, "SELECT status FROM approvals WHERE id=%s", (aid,))[0][0] == "pending"


@pytest.mark.parametrize("who", ["zz_emp", "zz_emp2", "zz_emp3", "zz_adm"])
def test_only_the_approver_whose_turn_it_is_can_attach(aapp, root, who):
    submit(as_user(aapp, "zz_emp"), root, approvers=("zz_mgr",), cc=("zz_emp2",))
    aid = last_id(root)
    assert decide(as_user(aapp, who), aid, "approve", files=[("몰래.png", PNG)]).status_code == 403          # 상신자·참조자·제3자·결재선 밖 관리자
    assert not file_rows(root, aid) and stored_count(aapp) == 0 and sql(root, "SELECT status FROM approvals WHERE id=%s", (aid,))[0][0] == "pending"


def test_an_approver_before_their_turn_or_after_deciding_cannot_attach(aapp, root):
    submit(as_user(aapp, "zz_emp"), root, approvers=("zz_mgr", "zz_adm"))
    aid = last_id(root)
    assert decide(as_user(aapp, "zz_adm"), aid, "approve", files=[("미리.png", PNG)]).status_code == 403   # 아직 차례 전
    assert decide(as_user(aapp, "zz_mgr"), aid, "approve", files=[("첫번째.png", PNG)]).status_code == 303
    assert decide(as_user(aapp, "zz_mgr"), aid, "approve", files=[("두번째.png", PNG)]).status_code == 409  # 이미 처리함
    assert [r[0] for r in file_rows(root, aid)] == ["첫번째.png"] and stored_count(aapp) == 1


def test_closed_documents_accept_no_more_files(aapp, root):
    submit(as_user(aapp, "zz_emp"), root)
    aid = last_id(root)
    decide(as_user(aapp, "zz_mgr"), aid, "approve")
    assert decide(as_user(aapp, "zz_mgr"), aid, "reject", files=[("뒤늦게.png", PNG)], reason="번복").status_code == 409
    assert not file_rows(root, aid) and stored_count(aapp) == 0


def test_decision_form_offers_a_file_input_only_to_the_current_approver(aapp, root):
    submit(as_user(aapp, "zz_emp"), root, approvers=("zz_mgr", "zz_adm"))
    aid = last_id(root)
    mgr = as_user(aapp, "zz_mgr").get(f"/approvals/{aid}").get_data(as_text=True)
    assert 'enctype="multipart/form-data"' in mgr.split("결재 처리")[1] and 'name="attachments"' in mgr.split("결재 처리")[1]
    for who in ("zz_emp", "zz_adm"):
        assert "결재 처리" not in as_user(aapp, who).get(f"/approvals/{aid}").get_data(as_text=True)


def test_unreadable_approval_file_is_a_clean_404(aapp, root, events, monkeypatch):
    from app import uploads
    submit(as_user(aapp, "zz_emp"), root, files=[("a.dat", b"payload")])
    aid = last_id(root)
    fid = sql(root, "SELECT id FROM approval_files WHERE approval_id=%s", (aid,))[0][0]
    monkeypatch.setattr(uploads, "send_from_directory", lambda *a, **k: (_ for _ in ()).throw(OSError(22, "Invalid argument")))
    r = as_user(aapp, "zz_mgr").get(f"/approvals/{aid}/files/{fid}")
    assert r.status_code == 404 and any(e["event_type"] == "attachment_unreadable" for e in events())


# ---------- 서식 있는 본문(공문)·수신 ----------
RICH = ('<h2 class="al-center">출장 신청</h2><p class="al-right fs-5 c-red">굵은 <b>글</b></p>'
        '<table class="doc-table"><tbody><tr><th colspan="2">머리</th></tr><tr><td>출장지</td><td>광주</td></tr></tbody></table>')
EVIL = ('<p onclick="alert(1)" style="color:red">악성 <script>alert(1)</script><img src=x onerror=alert(1)>'
        '<a href="javascript:alert(1)">링크</a><iframe src="//evil"></iframe></p>')


def rich(client, root, body, **extra):
    return submit(client, root, body=body, body_format="html", **extra)


def stored(root, aid):
    return sql(root, "SELECT body, body_html, recipient FROM approvals WHERE id=%s", (aid,))[0]


def gm_body(page):
    return page.split('class="gm-body doc-body">')[1].split("</div>")[0]


def editor_source(page):
    import html as htmllib
    return htmllib.unescape(page.split('id="body-source"')[1].split(">", 1)[1].split("</textarea>")[0])


def test_rich_body_is_saved_sanitised_and_shown_as_a_document(aapp, root):
    emp = as_user(aapp, "zz_emp")
    assert rich(emp, root, RICH + EVIL, recipient="개발팀장").status_code == 303
    aid = last_id(root)
    body, is_html, recipient = stored(root, aid)
    assert is_html == 1 and recipient == "개발팀장"
    assert all(t not in body for t in ("<script", "<img", "<iframe", "onclick", "onerror", "style=", "javascript:", "<a "))   # 저장된 값에 위험한 조각이 없다
    assert 'class="al-right fs-5 c-red"' in body and '<table class="doc-table">' in body and 'colspan="2"' in body       # 서식과 표는 남는다
    doc = gm_body(as_user(aapp, "zz_mgr").get(f"/approvals/{aid}").get_data(as_text=True))
    assert '<p class="al-right fs-5 c-red">굵은 <b>글</b></p>' in doc and '<th colspan="2">머리</th>' in doc
    assert all(t not in doc for t in ("<script", "<img", "<iframe", "onclick", "onerror", "style=", "javascript:"))


def test_tampered_stored_html_is_sanitised_again_when_displayed_and_when_copied(aapp, root):
    emp = as_user(aapp, "zz_emp")
    rich(emp, root, "<p>정상 본문</p>")
    aid = last_id(root)
    sql(root, "UPDATE approvals SET body=%s WHERE id=%s", ('<p>변조</p><script>alert(1)</script><img src=x onerror=alert(1)><p onclick="x()">끝</p>', aid))
    doc = gm_body(as_user(aapp, "zz_mgr").get(f"/approvals/{aid}").get_data(as_text=True))
    assert "<p>변조</p>" in doc and "<p>끝</p>" in doc and all(t not in doc for t in ("<script", "<img", "onclick", "onerror"))
    post(as_user(aapp, "zz_mgr"), f"/approvals/{aid}/decide", decision="reject", reason="사유")
    form = emp.get(f"/approvals/new?from={aid}").get_data(as_text=True)                           # 재기안 편집기에도 날것이 들어가지 않는다
    source = editor_source(form)
    assert all(t not in source for t in ("<script", "<img", "onerror", "onclick")) and 'data-format="html"' in form


def test_plain_text_bodies_still_work_and_are_escaped(aapp, root):
    assert submit(as_user(aapp, "zz_emp"), root, body="첫 줄\n<script>alert(1)</script>\n셋째 줄").status_code == 303
    aid = last_id(root)
    assert stored(root, aid)[1] == 0
    page = as_user(aapp, "zz_mgr").get(f"/approvals/{aid}").get_data(as_text=True)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "<script>alert(1)" not in page
    assert 'class="body gm-body"' in page                                                          # 예전 방식(줄바꿈 유지) 본문 칸


@pytest.mark.parametrize("body", ["", "   ", "<p><br></p>", "<table><tr><td><br></td></tr></table>", "<script>alert(1)</script>", "<p> </p><hr>"])
def test_rich_body_without_visible_text_is_rejected(aapp, root, body):
    r = rich(as_user(aapp, "zz_emp"), root, body)
    assert r.status_code == 400 and count(root) == 0


def test_oversized_rich_body_is_rejected_and_large_ones_are_stored(aapp, root):
    """폼의 글자 칸은 프레임워크 기본 보호(500KB, 한글 약 16만 자)가 그대로 적용된다. 그보다 작은 큰 본문은 문제없이 저장된다."""
    emp = as_user(aapp, "zz_emp")
    assert rich(emp, root, "<p>" + "가" * 170_000 + "</p>").status_code == 413                   # 510KB: 보호 한도 초과
    assert count(root) == 0
    big = "<p>" + "나" * 100_000 + "</p>"                                                         # 300KB: TEXT 한도(64KB)의 다섯 배, 보호 한도 안
    assert rich(emp, root, big).status_code == 303
    assert stored(root, last_id(root))[0] == big


def test_library_level_input_cap_is_enforced_too(aapp, root, monkeypatch):
    """방어를 한 겹 더: 어떤 경로로든 상한(richtext.MAX_INPUT)을 넘는 본문은 살균기까지 가기 전에 거부한다."""
    from app import richtext
    monkeypatch.setattr(richtext, "MAX_INPUT", 1000)
    assert rich(as_user(aapp, "zz_emp"), root, "<p>" + "가" * 1500 + "</p>").status_code == 400
    assert count(root) == 0


def test_recipient_is_optional_validated_and_escaped(aapp, root):
    emp = as_user(aapp, "zz_emp")
    assert submit(emp, root).status_code == 303
    aid = last_id(root)
    assert stored(root, aid)[2] is None
    assert "내부 결재" in as_user(aapp, "zz_mgr").get(f"/approvals/{aid}").get_data(as_text=True)
    assert submit(emp, root, recipient="<b>영업팀</b> & 대표").status_code == 303
    page = as_user(aapp, "zz_mgr").get(f"/approvals/{last_id(root)}").get_data(as_text=True)
    assert "&lt;b&gt;영업팀&lt;/b&gt; &amp; 대표" in page and "<b>영업팀</b>" not in page
    before = count(root)
    for bad in ("가" * 101, "줄\x00바꿈", "줄\n바꿈"):
        assert submit(emp, root, recipient=bad).status_code == 400
    assert count(root) == before


def test_redraft_copies_the_rich_body_and_the_recipient(aapp, root):
    emp = as_user(aapp, "zz_emp")
    rich(emp, root, RICH, recipient="개발팀장")
    aid = last_id(root)
    post(as_user(aapp, "zz_mgr"), f"/approvals/{aid}/decide", decision="reject", reason="수정")
    form = emp.get(f"/approvals/new?from={aid}").get_data(as_text=True)
    assert 'data-format="html"' in form and "doc-table" in editor_source(form)
    assert 'name="recipient"' in form and 'value="개발팀장"' in form


def test_form_offers_the_editor_hooks_and_a_table_template_per_type(aapp):
    emp = as_user(aapp, "zz_emp")
    html = emp.get("/approvals/new?type=trip").get_data(as_text=True)
    assert 'id="body-source"' in html and 'id="body-format"' in html and 'data-format="html"' in html
    assert "required" not in html.split('id="body-source"')[0].split("<textarea")[-1]              # 숨겨질 칸에 required 가 있으면 브라우저가 제출을 막는다
    assert "doc-table" in editor_source(html) and "출장지" in html
    assert 'src="/static/rich-editor.js"' in html and "script-src 'self'" in emp.get("/approvals/new").headers["Content-Security-Policy"]
    assert emp.get("/static/rich-editor.js").status_code == 200
    blank = emp.get("/approvals/new").get_data(as_text=True)
    assert 'data-format="text"' in blank and editor_source(blank) == ""                            # 기본 상신 화면은 빈 일반 글 칸(편집기가 빈 문단으로 채운다)
    assert "<p><br></p>" in editor_source(emp.get("/approvals/new?type=general").get_data(as_text=True))


def test_document_layout_has_the_official_letter_parts(aapp, root):
    rich(as_user(aapp, "zz_emp"), root, RICH, recipient="영업팀장", cc=("zz_emp2",))
    aid = last_id(root)
    html = as_user(aapp, "zz_mgr").get(f"/approvals/{aid}").get_data(as_text=True)
    assert 'class="gongmun"' in html and html.count("<h1") == 1 and 'class="gm-org"' in html
    for part in ("시행일자", "기안", "수신", "참조", "끝.", "gm-sender"):
        assert part in html
    assert re.search(r"<th>기안</th><td>A팀 zz_emp</td>", html) and re.search(r"<th>수신</th><td>영업팀장</td>", html)
    assert re.search(r'<p class="gm-sender">A팀 zz_emp</p>', html)
    order = [html.index(k) for k in ('class="seals"', 'class="gm-title"', "gm-meta", 'class="gm-body', 'class="gm-end"', 'class="gm-sender"')]
    assert order == sorted(order)                                                                   # 결재란 → 제목 → 시행·기안·수신 → 본문 → 끝 → 발신 명의
    assert 'id="print-doc"' in html and 'src="/static/print.js"' in html and "noprint" in html


def test_formatting_survives_a_redraft_round_trip_unchanged(aapp, root):
    from app import richtext
    emp = as_user(aapp, "zz_emp")
    rich(emp, root, RICH)
    aid = last_id(root)
    first = stored(root, aid)[0]
    post(as_user(aapp, "zz_mgr"), f"/approvals/{aid}/decide", decision="reject", reason="수정")
    source = editor_source(emp.get(f"/approvals/new?from={aid}").get_data(as_text=True))
    assert richtext.sanitize(source)[0] == first                                                    # 편집기에 들어가는 값 = 저장된 값
