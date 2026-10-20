"""지출결의서: 서버가 금액을 계산하고, 입력은 허용 목록·범위로 검증하며, 상신한 뒤에는 바꿀 수 없다. Docker MySQL(nexus_test) 필요, 접속 불가면 skip.
부서: A팀(zz_emp, zz_emp2, zz_mgr) / B팀(zz_emp3, zz_mgrb) / 관리팀(zz_adm)"""
from datetime import timedelta

import pymysql
import pytest

from app import approvals
from app.formats import won_hangul
from support import as_user, csrf_of, post, sql, uid


def today():
    return approvals._today()


def fields(**over):
    base = dict(doc_type="expenditure", title="zz_지출결의서", body="<p>위와 같이 지출하고자 결의합니다.</p>", body_format="html",
                spend_date=today().isoformat(), account_name="복리후생비", pay_method="card", payee="○○식당", evidence="receipt",
                item_1="팀 회식", memo_1="9월 정기 회식", qty_1="4", price_1="30000", item_2="음료", qty_2="2", price_2="5000")
    base.update(over)
    return base


def submit(client, root, approvers=("zz_mgr",), **over):
    form = {"csrf_token": csrf_of(client), **{k: v for k, v in fields(**over).items() if v is not None}}
    form.update({f"approver_{n}": uid(root, name) for n, name in enumerate(approvers, start=1)})
    return client.post("/approvals/new", data=form, content_type="multipart/form-data")


def last_id(root):
    return sql(root, "SELECT MAX(id) FROM approvals")[0][0]


def count(root):
    return sql(root, "SELECT COUNT(*) FROM approvals")[0][0]


# ---------- 한글 금액 ----------
@pytest.mark.parametrize("n,expected", [
    (0, "영"), (1, "일"), (9, "구"), (10, "일십"), (11, "일십일"), (100, "일백"), (101, "일백일"), (1000, "일천"), (10000, "일만"),
    (12345, "일만이천삼백사십오"), (130000, "일십삼만"), (3_800_000, "삼백팔십만"), (100_000_000, "일억"), (100_020_003, "일억이만삼"),
    (1_0000_0000_0000, "일조"), (99_999_999, "구천구백구십구만구천구백구십구"),
])
def test_amount_in_korean_numerals(n, expected):
    assert won_hangul(n) == expected


def test_amount_in_korean_rejects_negative_and_too_large():
    with pytest.raises(ValueError):
        won_hangul(-1)
    with pytest.raises(ValueError):
        won_hangul(10 ** 20)


# ---------- 상신과 서버 계산 ----------
def test_server_computes_line_amounts_and_total_and_ignores_client_amounts(aapp, root, events):
    c = as_user(aapp, "zz_emp")
    r = submit(c, root, amount_1="1", amount_2="1", total_amount="1", total="1")      # 화면이 보낸 금액·합계는 읽지 않는다
    assert r.status_code == 303
    aid = last_id(root)
    assert sql(root, "SELECT doc_type, status FROM approvals WHERE id=%s", (aid,))[0] == ("expenditure", "pending")
    x = sql(root, "SELECT spend_date, account_name, pay_method, payee, payee_account, pay_due, evidence, total_amount FROM expenditures WHERE approval_id=%s", (aid,))[0]
    assert x == (today(), "복리후생비", "card", "○○식당", None, None, "receipt", 130000)                  # 4×30,000 + 2×5,000
    rows = sql(root, "SELECT line_no, item, memo, qty, unit_price, amount FROM expenditure_items WHERE approval_id=%s ORDER BY line_no", (aid,))
    assert rows == ((1, "팀 회식", "9월 정기 회식", 4, 30000, 120000), (2, "음료", None, 2, 5000, 10000))
    assert any(e["event_type"] == "approval_created" and e.get("amount") == 130000 for e in events())


def test_detail_shows_the_form_with_items_total_and_korean_amount(aapp, root):
    submit(as_user(aapp, "zz_emp"), root, pay_method="transfer", payee_account="국민 123-456-789012 홍길동", pay_due=(today() + timedelta(days=7)).isoformat())
    aid = last_id(root)
    html = as_user(aapp, "zz_mgr").get(f"/approvals/{aid}").get_data(as_text=True)
    year = today().year
    assert f"NX-EXD-{year}-{aid:05d}" in html and "지출결의서" in html
    for text in ("지출 내용", "복리후생비", "계좌이체", "○○식당", "국민 123-456-789012 홍길동", "영수증", "130,000원", "일금 일십삼만원정", "팀 회식", "120,000원", "합계"):
        assert text in html, text
    assert "지급 예정일" in html and "지출 일자" in html


def test_blank_rows_are_skipped_and_lines_are_numbered_from_one(aapp, root):
    submit(as_user(aapp, "zz_emp"), root, item_1="", memo_1="", qty_1="", price_1="", item_2="", qty_2="", price_2="",
           item_4="셋째", qty_4="1", price_4="100", item_7="넷째", qty_7="2", price_7="50")
    aid = last_id(root)
    assert [r[:2] for r in sql(root, "SELECT line_no, item FROM expenditure_items WHERE approval_id=%s ORDER BY line_no", (aid,))] == [(1, "셋째"), (2, "넷째")]
    assert sql(root, "SELECT total_amount FROM expenditures WHERE approval_id=%s", (aid,))[0][0] == 200


def test_rows_beyond_the_maximum_are_ignored_and_zero_price_lines_are_allowed(aapp, root):
    over = {f"item_{approvals.MAX_ITEM_ROWS + 1}": "범위 밖", f"qty_{approvals.MAX_ITEM_ROWS + 1}": "1", f"price_{approvals.MAX_ITEM_ROWS + 1}": "999999"}
    submit(as_user(aapp, "zz_emp"), root, item_3="무상 제공", qty_3="1", price_3="0", **over)
    aid = last_id(root)
    items = sql(root, "SELECT item, amount FROM expenditure_items WHERE approval_id=%s ORDER BY line_no", (aid,))
    assert [i[0] for i in items] == ["팀 회식", "음료", "무상 제공"] and items[2][1] == 0
    assert sql(root, "SELECT total_amount FROM expenditures WHERE approval_id=%s", (aid,))[0][0] == 130000


def test_payee_account_is_kept_only_for_bank_transfers(aapp, root):
    submit(as_user(aapp, "zz_emp"), root, pay_method="card", payee_account="111-222")
    assert sql(root, "SELECT payee_account FROM expenditures WHERE approval_id=%s", (last_id(root),))[0][0] is None
    submit(as_user(aapp, "zz_emp"), root, pay_method="transfer", payee_account="111-222")
    assert sql(root, "SELECT payee_account FROM expenditures WHERE approval_id=%s", (last_id(root),))[0][0] == "111-222"


# ---------- 입력 검증 ----------
BAD = [
    ("account", dict(account_name="비밀계정")), ("account-empty", dict(account_name="")),
    ("method", dict(pay_method="bitcoin")), ("method-empty", dict(pay_method="")),
    ("evidence", dict(evidence="rumor")), ("evidence-empty", dict(evidence="")),
    ("date-bad", dict(spend_date="내일")), ("date-impossible", dict(spend_date="2026-02-30")), ("date-empty", dict(spend_date="")),
    ("date-too-old", dict(spend_date=(today() - timedelta(days=366)).isoformat())),
    ("date-too-far", dict(spend_date=(today() + timedelta(days=31)).isoformat())),
    ("due-bad", dict(pay_due="곧")), ("due-past", dict(pay_due=(today() - timedelta(days=31)).isoformat())),
    ("due-far", dict(pay_due=(today() + timedelta(days=366)).isoformat())),
    ("payee-empty", dict(payee="")), ("payee-long", dict(payee="가" * 101)), ("payee-control", dict(payee="줄\x00바꿈")), ("payee-newline", dict(payee="줄\n바꿈")),
    ("transfer-no-account", dict(pay_method="transfer", payee_account="")), ("transfer-long-account", dict(pay_method="transfer", payee_account="9" * 101)),
    ("no-items", dict(item_1="", memo_1="", qty_1="", price_1="", item_2="", qty_2="", price_2="")),
    ("item-missing", dict(item_1="", qty_1="1", price_1="100")),
    ("item-long", dict(item_1="가" * 101)), ("memo-long", dict(memo_1="가" * 101)),
    ("qty-zero", dict(qty_1="0")), ("qty-negative", dict(qty_1="-1")), ("qty-float", dict(qty_1="1.5")), ("qty-text", dict(qty_1="많이")),
    ("qty-empty", dict(qty_1="")), ("qty-big", dict(qty_1="1000001")), ("qty-arabic-digit", dict(qty_1="٣")), ("qty-space", dict(qty_1="1 2")),
    ("price-negative", dict(price_1="-100")), ("price-float", dict(price_1="1.5")), ("price-exp", dict(price_1="1e3")), ("price-empty", dict(price_1="")),
    ("price-big", dict(price_1="10000000001")), ("price-arabic-digit", dict(price_1="٣")), ("price-sql", dict(price_1="1; DROP TABLE users")),
    ("total-over", dict(qty_1="1000000", price_1="10000000000")),
    ("total-zero", dict(item_2="", qty_2="", price_2="", price_1="0")),
]


@pytest.mark.parametrize("name,over", BAD, ids=[b[0] for b in BAD])
def test_invalid_expenditure_input_is_rejected_without_side_effects(aapp, root, name, over):
    r = submit(as_user(aapp, "zz_emp"), root, **over)
    assert r.status_code == 400, name
    assert count(root) == 0 and sql(root, "SELECT COUNT(*) FROM expenditures")[0][0] == 0 and sql(root, "SELECT COUNT(*) FROM expenditure_items")[0][0] == 0


def test_error_screen_keeps_what_the_user_typed_and_explains(aapp, root):
    r = submit(as_user(aapp, "zz_emp"), root, qty_1="0", payee="보존되어야 할 지급처", item_3="셋째 줄", qty_3="2", price_3="700")
    html = r.get_data(as_text=True)
    assert r.status_code == 400 and "수량은 1~1,000,000" in html and "보존되어야 할 지급처" in html and "셋째 줄" in html and 'value="700"' in html


def test_malicious_text_is_stored_literally_and_escaped_on_screen(aapp, root):
    evil = "<script>alert(1)</script>'; DROP TABLE users;--"
    submit(as_user(aapp, "zz_emp"), root, payee=evil, item_1=evil, memo_1=evil, pay_method="transfer", payee_account=evil)
    aid = last_id(root)
    assert sql(root, "SELECT payee FROM expenditures WHERE approval_id=%s", (aid,))[0][0] == evil
    html = as_user(aapp, "zz_mgr").get(f"/approvals/{aid}").get_data(as_text=True)
    assert "<script>alert(1)" not in html and html.count("&lt;script&gt;alert(1)&lt;/script&gt;") >= 4
    assert sql(root, "SELECT COUNT(*) FROM users")[0][0] > 0


def test_only_expenditure_forms_can_carry_expenditure_data_and_expense_type_is_still_closed(aapp, root):
    submit(as_user(aapp, "zz_emp"), root, doc_type="general")                                          # 일반 기안에 실어 보낸 지출 필드는 무시된다
    assert sql(root, "SELECT COUNT(*) FROM expenditures")[0][0] == 0
    assert submit(as_user(aapp, "zz_emp"), root, doc_type="expense").status_code == 400


# ---------- 화면 ----------
def test_form_page_shows_the_expenditure_fields_and_script_only_for_this_type(aapp):
    c = as_user(aapp, "zz_emp")
    html = c.get("/approvals/new?type=expenditure").get_data(as_text=True)
    for part in ('name="spend_date"', 'name="account_name"', 'name="pay_method"', 'name="payee"', 'name="payee_account"', 'name="pay_due"',
                 'name="evidence"', 'name="item_1"', 'name="qty_5"', 'name="price_5"', 'id="exd-add"', "지출결의서"):
        assert part in html, part
    assert html.count('class="exd-row"') == 5 and 'src="/static/expenditure.js"' in html and 'name="item_6"' not in html
    assert c.get("/static/expenditure.js").status_code == 200
    plain = c.get("/approvals/new?type=trip").get_data(as_text=True)
    assert 'name="payee"' not in plain and "expenditure.js" not in plain


def test_list_shows_the_amount_only_for_expenditures(aapp, root):
    emp = as_user(aapp, "zz_emp")
    submit(emp, root)
    emp.post("/approvals/new", data={"csrf_token": csrf_of(emp), "title": "zz_일반", "body": "내용", "approver_1": uid(root, "zz_mgr")})
    html = as_user(aapp, "zz_mgr").get("/approvals?box=wait").get_data(as_text=True)
    assert "130,000원" in html and "지출결의서" in html
    assert html.count("130,000원") == 1


def test_non_parties_cannot_see_the_expenditure(aapp, root):
    submit(as_user(aapp, "zz_emp"), root)
    aid = last_id(root)
    assert as_user(aapp, "zz_emp3").get(f"/approvals/{aid}").status_code == 403
    assert as_user(aapp, "zz_mgrb").get(f"/approvals/{aid}").status_code == 403
    assert as_user(aapp, "zz_adm").get(f"/approvals/{aid}").status_code == 200


def test_redraft_copies_the_expenditure_details_and_lines(aapp, root):
    emp = as_user(aapp, "zz_emp")
    submit(emp, root, pay_method="transfer", payee_account="111-222-333", account_name="교통비", evidence="tax_invoice")
    aid = last_id(root)
    post(as_user(aapp, "zz_mgr"), f"/approvals/{aid}/decide", decision="reject", reason="증빙 보완")
    html = emp.get(f"/approvals/new?from={aid}").get_data(as_text=True)
    assert 'value="○○식당"' in html and 'value="111-222-333"' in html and 'value="팀 회식"' in html and 'value="30000"' in html
    assert '<option value="교통비" selected>' in html and '<option value="tax_invoice" selected>' in html and 'value="transfer" checked' in html
    assert 'name="item_2"' in html and html.count('class="exd-row"') == 5


# ---------- DB 수준 방어 ----------
def test_database_rejects_inconsistent_amounts_and_empty_totals(aapp, root):
    submit(as_user(aapp, "zz_emp"), root)
    aid = last_id(root)
    with root.cursor() as cur:
        with pytest.raises(pymysql.err.Error):
            cur.execute("INSERT INTO expenditure_items(approval_id,line_no,item,qty,unit_price,amount) VALUES(%s,9,'x',2,100,999)", (aid,))   # 금액 ≠ 수량×단가
        with pytest.raises(pymysql.err.Error):
            cur.execute("INSERT INTO expenditure_items(approval_id,line_no,item,qty,unit_price,amount) VALUES(%s,9,'x',0,100,0)", (aid,))     # 수량 0
        with pytest.raises(pymysql.err.Error):
            cur.execute("UPDATE expenditures SET total_amount=0 WHERE approval_id=%s", (aid,))                                                  # 합계 0


def test_expenditure_rows_go_away_with_their_approval(aapp, root):
    submit(as_user(aapp, "zz_emp"), root)
    aid = last_id(root)
    sql(root, "DELETE FROM approval_steps WHERE approval_id=%s", (aid,))
    sql(root, "DELETE FROM approvals WHERE id=%s", (aid,))
    assert sql(root, "SELECT COUNT(*) FROM expenditures")[0][0] == 0 and sql(root, "SELECT COUNT(*) FROM expenditure_items")[0][0] == 0
