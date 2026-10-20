"""전자결재: 상신자가 정한 결재선(순서)대로 순차 결재한다. 반려는 사유가 필수이고, 상신자는 아직 아무도 결재하지 않았을 때만 철회할 수 있다.
- 양식: 일반 기안·업무 협조·출장 신청·구매 요청(경비 청구는 경비 화면에서 자동). 문서번호는 `NX-양식코드-연도-일련번호`로 화면에서 만든다. 긴급 표시를 달 수 있다.
- 결재선: 상신자가 최대 5명을 순서대로 고른다. 후보는 팀장·관리자이며, 본인·중복은 불가(앱 검사 + DB 트리거 + 결재자 열 수정 권한 없음).
- 참조: 결재하지는 않지만 문서를 볼 수 있는 사람(최대 10명, 결재자·본인 제외). 상신할 때만 정하고 이후 바꿀 수 없다.
- 첨부: 상신할 때, 그리고 결재자가 승인·반려할 때 올릴 수 있다. **개수·형식·용량 제한은 없다**(uploads.save_attachment: 무작위 이름으로 안전하게 저장하고
  항상 다운로드로만 내려줌). 문서를 볼 수 있는 사람만 내려받는다.
- 처리: 지금 차례인 결재자만 승인·반려할 수 있다. 승인할 때도 의견을 남길 수 있고(선택), 반려할 때는 사유가 필수다.
  차례가 아닌 결재자·상신자·제3자·(결재선에 없는) 관리자는 처리할 수 없다.
- 문서함: 전체·기안함·결재 대기·결재 예정·처리 완료·참조함. 반려·철회된 문서는 상신자가 복사해서 다시 기안할 수 있다(재기안).
- 상태: 문서는 pending → approved / rejected / withdrawn, 단계는 waiting → pending → approved / rejected / skipped 한 방향뿐이다.
  마지막 단계가 승인되면 문서가 승인, 어느 단계든 반려되면 문서가 반려(남은 단계는 skipped), 철회하면 연결 경비는 다시 임시저장이 된다.
- 볼 수 있는 사람: 상신자·결재선의 결재자·참조자·관리자. 그 외에는 403이다(관리자도 결재선에 없으면 처리는 못 한다)."""
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from . import db, richtext, uploads, validators
from .auth import login_required
from .security import log_event

bp = Blueprint("approvals", __name__)

DECISIONS = {"approve": "approved", "reject": "rejected"}
MAX_STEPS = 5
MAX_CC = 10
# 결재선에 넣을 수 있는 역할. 아래 approver_candidates 의 SQL 과 같은 값을 유지한다.
APPROVER_ROLES = ("manager", "admin")
APPROVER_MESSAGES = {
    "approver_required": "결재자를 한 명 이상 선택하세요.",
    "approver_invalid": "선택할 수 없는 결재자입니다. 팀장 또는 관리자만 지정할 수 있습니다.",
    "approver_duplicate": "같은 결재자를 두 번 선택할 수 없습니다.",
    "approver_self": "본인을 결재자로 지정할 수 없습니다.",
}
CC_MESSAGES = {
    "cc_invalid": "선택할 수 없는 참조자입니다.",
    "cc_too_many": f"참조자는 최대 {MAX_CC}명까지 지정할 수 있습니다.",
    "cc_self": "본인을 참조자로 지정할 수 없습니다.",
    "cc_approver": "결재자를 참조자로 중복 지정할 수 없습니다.",
}
REASON_ERROR = "반려 사유를 1~500자로 입력하세요(제어문자 사용 불가)."
COMMENT_ERROR = "결재 의견은 1~500자로 입력하세요(제어문자 사용 불가)."

# 양식: 키 -> (이름, 문서번호 코드). expense 는 경비 화면에서만 만들어진다.
DOC_TYPES = {"general": ("일반 기안", "GEN"), "coop": ("업무 협조", "COP"), "trip": ("출장 신청", "TRP"),
             "purchase": ("구매 요청", "PUR"), "expense": ("경비 청구", "EXP"), "expenditure": ("지출결의서", "EXD")}
FORM_TYPES = ("general", "coop", "trip", "purchase", "expenditure")
URGENCY = {"normal": "보통", "urgent": "긴급"}
def _form_table(*rows):
    """양식 작성 틀: 왼쪽 칸은 항목 이름(제목 칸), 오른쪽 칸은 작성할 칸인 2열 표."""
    body = "".join(f"<tr><th>{label}</th><td><br></td></tr>" for label in rows)
    return f'<p>아래 내용과 같이 요청합니다.</p><table class="doc-table"><tbody>{body}</tbody></table><p><br></p>'


# 서식 있는 편집기로 쓰는 양식별 작성 틀(HTML). 일반 기안은 빈 문단이다.
BODY_TEMPLATES = {
    "general": "<p><br></p>",
    "coop": _form_table("협조 요청 부서", "요청 내용", "희망 완료일", "비고"),
    "trip": _form_table("출장지", "출장 기간", "출장 목적", "예상 경비", "동행자"),
    "purchase": _form_table("구매 품목", "수량·단가", "예상 금액", "구매 사유", "희망 납기"),
    "expenditure": "<p>위와 같이 지출하고자 결의합니다.</p><p><br></p>",
}

# ---------- 지출결의서 ----------
# 계정과목·지급 방법·증빙은 허용 목록에서만 고른다. 금액은 서버가 수량×단가로 계산하고 합계도 서버가 낸다(화면에서 보낸 금액은 쓰지 않는다).
ACCOUNTS = ("복리후생비", "교통비", "접대비", "소모품비", "출장비", "교육훈련비", "통신비", "광고선전비", "도서인쇄비", "기타")
PAY_METHODS = {"card": "법인카드", "transfer": "계좌이체", "cash": "현금"}
EVIDENCE = {"receipt": "영수증", "tax_invoice": "세금계산서", "card_slip": "카드전표", "contract": "계약서·견적서", "none": "증빙 없음"}
MAX_ITEM_ROWS = 30
MAX_QTY = 1_000_000
MAX_PRICE = 10_000_000_000
MAX_TOTAL = 100_000_000_000
EXD_MESSAGES = {
    "exd_date": "지출 일자는 YYYY-MM-DD 형식의 실제 날짜로 입력하세요.",
    "exd_date_range": "지출 일자는 오늘 기준 1년 전부터 30일 후까지만 입력할 수 있습니다.",
    "exd_account": "계정과목을 목록에서 고르세요.",
    "exd_method": "지급 방법을 고르세요.",
    "exd_payee": "지급처는 1~100자로 입력하세요(제어문자 사용 불가).",
    "exd_account_no": "계좌이체는 지급 계좌를 1~100자로 입력하세요.",
    "exd_due": "지급 예정일은 YYYY-MM-DD 형식이며 오늘 기준 30일 전부터 1년 후까지만 입력할 수 있습니다.",
    "exd_evidence": "증빙 종류를 고르세요.",
    "exd_no_items": "지출 내역을 한 줄 이상 입력하세요.",
    "exd_item": "내역의 항목은 1~100자로 입력하세요(제어문자 사용 불가).",
    "exd_memo": "내역의 적요는 100자 이하로 입력하세요.",
    "exd_qty": f"수량은 1~{MAX_QTY:,} 사이의 정수로 입력하세요.",
    "exd_price": f"단가는 0~{MAX_PRICE:,} 사이의 정수로 입력하세요.",
    "exd_total": f"합계는 1원 이상 {MAX_TOTAL:,}원 이하여야 합니다.",
}
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_KST = timezone(timedelta(hours=9))


def _today() -> date:
    return datetime.now(_KST).date()


def _day(raw, code):
    raw = (raw or "").strip()
    if not _DATE_RE.match(raw):
        raise ValueError(code)
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date()
    except ValueError:
        raise ValueError(code)


def _blank_row():
    return {"item": "", "memo": "", "qty": "", "price": ""}


def _blank_exd():
    return {"spend_date": _today().isoformat(), "account_name": ACCOUNTS[0], "pay_method": "card", "payee": "", "payee_account": "",
            "pay_due": "", "evidence": "receipt", "rows": [_blank_row() for _ in range(5)]}


def exd_from_form(form):
    """오류 화면에 되돌려 줄 입력값(문자열 그대로). 비어 있지 않은 내역 줄만 남기고 최소 5줄로 채운다."""
    exd = {k: form.get(k, "") for k in ("spend_date", "account_name", "pay_method", "payee", "payee_account", "pay_due", "evidence")}
    rows = []
    for i in range(1, MAX_ITEM_ROWS + 1):
        row = {k: form.get(f"{k}_{i}", "") for k in ("item", "memo", "qty", "price")}
        if any(v.strip() for v in row.values()):
            rows.append(row)
    exd["rows"] = rows + [_blank_row() for _ in range(max(0, 5 - len(rows)))]
    return exd


def parse_expenditure(form):
    """지출결의서 입력을 검증하고 서버가 금액을 계산한다. 잘못되면 ValueError(EXD_MESSAGES 의 코드)."""
    today = _today()
    spend = _day(form.get("spend_date"), "exd_date")
    if not (today - timedelta(days=365) <= spend <= today + timedelta(days=30)):
        raise ValueError("exd_date_range")
    account = form.get("account_name", "")
    if account not in ACCOUNTS:
        raise ValueError("exd_account")
    method = form.get("pay_method", "")
    if method not in PAY_METHODS:
        raise ValueError("exd_method")
    try:
        payee = validators.text(form.get("payee", ""), "payee", 1, 100)
    except ValueError:
        raise ValueError("exd_payee")
    payee_account = None
    if method == "transfer":
        try:
            payee_account = validators.text(form.get("payee_account", ""), "payee_account", 1, 100)
        except ValueError:
            raise ValueError("exd_account_no")
    due = None
    if form.get("pay_due", "").strip():
        due = _day(form.get("pay_due"), "exd_due")
        if not (today - timedelta(days=30) <= due <= today + timedelta(days=365)):
            raise ValueError("exd_due")
    evidence = form.get("evidence", "")
    if evidence not in EVIDENCE:
        raise ValueError("exd_evidence")
    items, total = [], 0
    for i in range(1, MAX_ITEM_ROWS + 1):
        raw = {k: form.get(f"{k}_{i}", "").strip() for k in ("item", "memo", "qty", "price")}
        if not any(raw.values()):
            continue                                              # 빈 줄은 건너뛴다
        try:
            item = validators.text(raw["item"], "item", 1, 100)
        except ValueError:
            raise ValueError("exd_item")
        try:
            memo = validators.text(raw["memo"], "memo", 1, 100) if raw["memo"] else None
        except ValueError:
            raise ValueError("exd_memo")
        try:
            qty = validators.positive_int(raw["qty"], "qty", MAX_QTY)
        except ValueError:
            raise ValueError("exd_qty")
        if not (raw["price"].isascii() and raw["price"].isdigit() and int(raw["price"]) <= MAX_PRICE):
            raise ValueError("exd_price")
        price = int(raw["price"])
        amount = qty * price                                      # 서버가 계산한다(화면의 금액 칸 값은 읽지 않는다)
        items.append({"item": item, "memo": memo, "qty": qty, "price": price, "amount": amount})
        total += amount
    if not items:
        raise ValueError("exd_no_items")
    if not (1 <= total <= MAX_TOTAL):
        raise ValueError("exd_total")
    return {"spend_date": spend, "account_name": account, "pay_method": method, "payee": payee, "payee_account": payee_account,
            "pay_due": due, "evidence": evidence, "items": items, "total": total}
BOXES = (("all", "전체"), ("mine", "기안함"), ("wait", "결재 대기"), ("soon", "결재 예정"), ("done", "처리 완료"), ("cc", "참조함"))
BOX_KEYS = tuple(k for k, _ in BOXES)


def forbidden(reason, **extra):
    log_event("authz_deny", "DENY", reason, **extra)
    return render_template("error.html", code=403, message="접근 권한이 없습니다."), 403


def conflict(message):
    return render_template("error.html", code=409, message=message), 409


def doc_no(row) -> str:
    """문서번호: NX-양식코드-연도-일련번호(5자리). 저장하지 않고 id·양식·상신 연도로 만든다."""
    code = DOC_TYPES.get(row["doc_type"], DOC_TYPES["general"])[1]
    return f"NX-{code}-{row['created_at'].year}-{row['id']:05d}"


def pending_count(user_id) -> int:
    """내가 지금 결재할 차례인 문서 수(메뉴의 배지)."""
    return db.query_one("SELECT COUNT(*) AS n FROM approval_steps s JOIN approvals a ON a.id = s.approval_id "
                        "WHERE s.approver_id = %s AND s.status = 'pending' AND a.status = 'pending'", (user_id,))["n"]


# ---------- 결재선·참조 ----------
def approver_candidates(user):
    return db.query_all("SELECT id, display_name, dept, role FROM users "
                        "WHERE role IN ('manager', 'admin') AND id <> %s AND deleted_at IS NULL ORDER BY dept, display_name", (user["id"],))


def cc_candidates(user):
    return db.query_all("SELECT id, display_name, dept, role FROM users WHERE id <> %s AND deleted_at IS NULL ORDER BY dept, display_name", (user["id"],))


def parse_approvers(form, requester):
    """approver_1..approver_5 를 순서대로 읽어 검증한 결재자 id 목록을 돌려준다. 잘못되면 ValueError(코드)."""
    ids = []
    for n in range(1, MAX_STEPS + 1):
        raw = form.get(f"approver_{n}", "").strip()
        if not raw:
            continue
        try:
            ids.append(validators.positive_int(raw, "approver"))
        except ValueError:
            raise ValueError("approver_invalid")
    if not ids:
        raise ValueError("approver_required")
    if len(set(ids)) != len(ids):
        raise ValueError("approver_duplicate")
    if requester["id"] in ids:
        raise ValueError("approver_self")
    for approver_id in ids:
        row = db.query_one("SELECT role FROM users WHERE id = %s AND deleted_at IS NULL", (approver_id,))
        if not row or row["role"] not in APPROVER_ROLES:
            raise ValueError("approver_invalid")
    return ids


def parse_cc(form, requester, approver_ids):
    """cc(여러 값)를 검증한 참조자 id 목록으로. 빈 값은 건너뛰고 중복은 하나로 본다. 잘못되면 ValueError(코드)."""
    ids = []
    for raw in form.getlist("cc"):
        raw = raw.strip()
        if not raw:
            continue
        try:
            n = validators.positive_int(raw, "cc")
        except ValueError:
            raise ValueError("cc_invalid")
        if n not in ids:
            ids.append(n)
    if len(ids) > MAX_CC:
        raise ValueError("cc_too_many")
    if requester["id"] in ids:
        raise ValueError("cc_self")
    if any(i in approver_ids for i in ids):
        raise ValueError("cc_approver")
    for cc_id in ids:
        if not db.query_one("SELECT id FROM users WHERE id = %s AND deleted_at IS NULL", (cc_id,)):
            raise ValueError("cc_invalid")
    return ids


def uploaded_files(form_files):
    """요청에서 실제로 선택된 파일만 골라 낸다(빈 칸 제외). 개수·형식·용량 제한은 없다."""
    return [f for f in form_files.getlist("attachments") if f and f.filename]


def file_dir() -> Path:
    return Path(current_app.config["UPLOAD_DIR"]) / "approvals"


def save_files(approval_id, files, step_no=None, uploaded_by=None):
    """업로드된 첨부를 저장한다. 상신 첨부는 step_no·uploaded_by 가 NULL, 결재 첨부는 그 단계와 올린 결재자가 기록된다.
    도중에 실패하면(디스크 부족 등) 이미 쓴 파일을 지우고 예외를 다시 던진다(요청 전체가 롤백된다)."""
    saved = []
    try:
        for f in files:
            meta = uploads.save_attachment(file_dir(), f)
            saved.append(meta)
            db.execute("INSERT INTO approval_files(approval_id, stored_name, orig_name, mime, size, sha256, step_no, uploaded_by) "
                       "VALUES(%s, %s, %s, %s, %s, %s, %s, %s)",
                       (approval_id, meta["stored_name"], meta["orig_name"], meta["mime"], meta["size"], meta["sha256"], step_no, uploaded_by))
    except BaseException:
        uploads.remove_saved(file_dir(), saved)
        raise
    return saved


def create_approval(requester, title, body, approver_ids, expense_id=None, doc_type="general", urgency="normal",
                    cc_ids=(), files=(), body_html=False, recipient=None, expenditure=None):
    """결재 문서와 결재선·참조자·첨부를 만든다. 첫 결재자만 pending, 나머지는 차례를 기다린다(waiting). 경비 연동 문서는 양식이 경비 청구다."""
    if expense_id:
        doc_type = "expense"
    approval_id = db.execute("INSERT INTO approvals(title, body, body_html, recipient, requester_id, expense_id, doc_type, urgency) "
                             "VALUES(%s, %s, %s, %s, %s, %s, %s, %s)",
                             (title, body, 1 if body_html else 0, recipient, requester["id"], expense_id, doc_type, urgency))
    for n, approver_id in enumerate(approver_ids, start=1):
        db.execute("INSERT INTO approval_steps(approval_id, step_no, approver_id, status) VALUES(%s, %s, %s, %s)",
                   (approval_id, n, approver_id, "pending" if n == 1 else "waiting"))
    for cc_id in cc_ids:
        db.execute("INSERT INTO approval_cc(approval_id, user_id) VALUES(%s, %s)", (approval_id, cc_id))
    if expenditure:
        db.execute("INSERT INTO expenditures(approval_id, spend_date, account_name, pay_method, payee, payee_account, pay_due, evidence, total_amount) "
                   "VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                   (approval_id, expenditure["spend_date"], expenditure["account_name"], expenditure["pay_method"], expenditure["payee"],
                    expenditure["payee_account"], expenditure["pay_due"], expenditure["evidence"], expenditure["total"]))
        for n, it in enumerate(expenditure["items"], start=1):
            db.execute("INSERT INTO expenditure_items(approval_id, line_no, item, memo, qty, unit_price, amount) VALUES(%s, %s, %s, %s, %s, %s, %s)",
                       (approval_id, n, it["item"], it["memo"], it["qty"], it["price"], it["amount"]))
    save_files(approval_id, files)
    return approval_id


# ---------- 문서함 ----------
@bp.get("/approvals")
@login_required
def approval_list():
    u = g.user
    box = request.args.get("box", "all")
    if box not in BOX_KEYS:
        log_event("input_rejected", "DENY", "box", field="approval_box")
        abort(400)
    p = {"me": u["id"], "box": box, "admin": 1 if u["role"] == "admin" else 0}
    rows = db.query_all(
        "SELECT a.id, a.title, a.status, a.doc_type, a.urgency, a.current_step, a.created_at, r.display_name AS requester, x.total_amount, "
        "(SELECT COUNT(*) FROM approval_steps s WHERE s.approval_id = a.id) AS total, "
        "EXISTS(SELECT 1 FROM approval_steps s WHERE s.approval_id = a.id AND s.approver_id = %(me)s "
        "AND s.status = 'pending') AS needs_me "
        "FROM approvals a JOIN users r ON r.id = a.requester_id LEFT JOIN expenditures x ON x.approval_id = a.id WHERE "
        "(%(box)s = 'all' AND (%(admin)s = 1 OR a.requester_id = %(me)s "
        "OR EXISTS(SELECT 1 FROM approval_steps s WHERE s.approval_id = a.id AND s.approver_id = %(me)s) "
        "OR EXISTS(SELECT 1 FROM approval_cc c WHERE c.approval_id = a.id AND c.user_id = %(me)s))) "
        "OR (%(box)s = 'mine' AND a.requester_id = %(me)s) "
        "OR (%(box)s = 'wait' AND a.status = 'pending' AND EXISTS(SELECT 1 FROM approval_steps s "
        "WHERE s.approval_id = a.id AND s.approver_id = %(me)s AND s.status = 'pending')) "
        "OR (%(box)s = 'soon' AND a.status = 'pending' AND EXISTS(SELECT 1 FROM approval_steps s "
        "WHERE s.approval_id = a.id AND s.approver_id = %(me)s AND s.status = 'waiting')) "
        "OR (%(box)s = 'done' AND EXISTS(SELECT 1 FROM approval_steps s WHERE s.approval_id = a.id "
        "AND s.approver_id = %(me)s AND s.status IN ('approved', 'rejected'))) "
        "OR (%(box)s = 'cc' AND EXISTS(SELECT 1 FROM approval_cc c WHERE c.approval_id = a.id AND c.user_id = %(me)s)) "
        "ORDER BY (a.urgency = 'urgent' AND a.status = 'pending') DESC, a.id DESC LIMIT 200", p)
    for r in rows:
        r["doc_no"] = doc_no(r)
    counts = db.query_one(
        "SELECT (SELECT COUNT(*) FROM approvals WHERE requester_id = %(me)s) AS mine, "
        "(SELECT COUNT(*) FROM approval_steps s JOIN approvals a ON a.id = s.approval_id WHERE s.approver_id = %(me)s "
        "AND s.status = 'pending' AND a.status = 'pending') AS wait, "
        "(SELECT COUNT(*) FROM approval_steps s JOIN approvals a ON a.id = s.approval_id WHERE s.approver_id = %(me)s "
        "AND s.status = 'waiting' AND a.status = 'pending') AS soon, "
        "(SELECT COUNT(*) FROM approval_steps s WHERE s.approver_id = %(me)s AND s.status IN ('approved', 'rejected')) AS done, "
        "(SELECT COUNT(*) FROM approval_cc WHERE user_id = %(me)s) AS cc", p)
    return render_template("approvals.html", rows=rows, box=box, boxes=BOXES, counts=counts, types=DOC_TYPES, urgency=URGENCY)


# ---------- 상신 ----------
def _blank_values():
    return {"title": "", "body": "", "body_html": False, "recipient": "", "doc_type": "general", "urgency": "normal",
            "approvers": [], "cc": [], "exd": _blank_exd()}


def _form(values=None, error=None, status=200):
    return render_template("approval_form.html", error=error, candidates=approver_candidates(g.user), cc_candidates=cc_candidates(g.user),
                           max_steps=MAX_STEPS, max_cc=MAX_CC, values=values or _blank_values(),
                           form_types=FORM_TYPES, types=DOC_TYPES, urgency=URGENCY, selected=(values or {}).get("approvers", []),
                           accounts=ACCOUNTS, pay_methods=PAY_METHODS, evidence_types=EVIDENCE, max_rows=MAX_ITEM_ROWS), status


def _redraft_values(src_id):
    """반려·철회된 본인 문서를 복사해 새로 기안할 값. 문서가 없으면 404, 남의 문서면 403, 복사할 수 없는 상태면 None."""
    src = db.query_one("SELECT id, title, body, body_html, recipient, requester_id, status, doc_type, urgency, expense_id "
                       "FROM approvals WHERE id = %s", (src_id,))
    if not src:
        abort(404)
    if src["requester_id"] != g.user["id"]:
        return forbidden("not_requester", resource=f"approval:{src_id}")
    if src["status"] not in ("rejected", "withdrawn") or src["expense_id"]:
        return None
    steps = db.query_all("SELECT approver_id FROM approval_steps WHERE approval_id = %s ORDER BY step_no", (src_id,))
    ccs = db.query_all("SELECT user_id FROM approval_cc WHERE approval_id = %s ORDER BY user_id", (src_id,))
    title = src["title"] if src["title"].startswith("[재기안]") else f"[재기안] {src['title']}"
    # 서식 있는 본문은 편집기에 불러오기 전에 한 번 더 살균한다(저장된 값이 바뀌었더라도 편집기에 날것이 들어가지 않게).
    body = richtext.sanitize(src["body"])[0] if src["body_html"] else src["body"]
    copied = {"title": title[:200], "body": body, "body_html": bool(src["body_html"]), "recipient": src["recipient"] or "",
              "doc_type": src["doc_type"] if src["doc_type"] in FORM_TYPES else "general",
              "urgency": src["urgency"], "approvers": [s["approver_id"] for s in steps], "cc": [c["user_id"] for c in ccs],
              "exd": _blank_exd()}
    if copied["doc_type"] == "expenditure":
        x = db.query_one("SELECT spend_date, account_name, pay_method, payee, payee_account, pay_due, evidence FROM expenditures WHERE approval_id = %s", (src_id,))
        if x:
            rows = db.query_all("SELECT item, memo, qty, unit_price FROM expenditure_items WHERE approval_id = %s ORDER BY line_no", (src_id,))
            copied["exd"] = {"spend_date": x["spend_date"].isoformat(), "account_name": x["account_name"], "pay_method": x["pay_method"],
                             "payee": x["payee"], "payee_account": x["payee_account"] or "", "pay_due": x["pay_due"].isoformat() if x["pay_due"] else "",
                             "evidence": x["evidence"],
                             "rows": [{"item": r["item"], "memo": r["memo"] or "", "qty": str(r["qty"]), "price": str(r["unit_price"])} for r in rows]
                                     + [_blank_row() for _ in range(max(0, 5 - len(rows)))]}
    return copied


@bp.route("/approvals/new", methods=["GET", "POST"])
@login_required
def approval_new():
    if request.method == "GET":
        values = _blank_values()
        if request.args.get("from"):
            try:
                src_id = validators.positive_int(request.args["from"], "from")
            except ValueError:
                abort(404)
            copied = _redraft_values(src_id)
            if copied is None:
                return conflict("반려되거나 철회된 문서만 다시 기안할 수 있습니다.")
            if isinstance(copied, tuple):  # 남의 문서: forbidden() 응답
                return copied
            values = copied
        elif request.args.get("type") in FORM_TYPES:
            values["doc_type"] = request.args["type"]
            values["body"], values["body_html"] = BODY_TEMPLATES[values["doc_type"]], True
        return _form(values)

    values = _blank_values()
    values.update(title=request.form.get("title", ""), body=request.form.get("body", ""),
                  body_html=request.form.get("body_format", "text") == "html", recipient=request.form.get("recipient", ""),
                  doc_type=request.form.get("doc_type", "general"), urgency=request.form.get("urgency", "normal"),
                  approvers=[int(request.form[k]) for k in (f"approver_{n}" for n in range(1, MAX_STEPS + 1))
                             if request.form.get(k, "").isascii() and request.form.get(k, "").isdigit()],
                  cc=[int(v) for v in request.form.getlist("cc") if v.isascii() and v.isdigit()], exd=exd_from_form(request.form))
    # 허용 목록 밖의 양식·긴급도는 거부하되, 오류 화면은 안전한 기본값으로 다시 그린다(임의 값으로 템플릿을 조회하지 않는다).
    bad_choice = values["doc_type"] not in FORM_TYPES or values["urgency"] not in URGENCY
    if values["doc_type"] not in FORM_TYPES:
        values["doc_type"] = "general"
    if values["urgency"] not in URGENCY:
        values["urgency"] = "normal"
    visible = 0
    if values["body_html"]:
        # 서식 있는 본문: 서버가 허용 목록으로 다시 살균한다(편집기가 보낸 값을 믿지 않는다). 오류 화면에도 살균한 값을 돌려준다.
        if len(values["body"]) > richtext.MAX_INPUT:
            values["body"] = ""
        else:
            values["body"], visible = richtext.sanitize(values["body"])
    try:
        title = validators.text(values["title"], "title", 1, 200)
        if values["body_html"]:
            if visible < 1:
                raise ValueError("body_length")
            body = values["body"]
        else:
            body = validators.text(values["body"], "body", 1, 2000, multiline=True)
        recipient = validators.text(values["recipient"], "recipient", 1, 100) if values["recipient"].strip() else None
        if bad_choice:
            raise ValueError("form_choice")
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="approval")
        return _form(values, "제목은 1~200자, 내용은 글자가 있어야 하고(일반 글은 2000자까지), 수신은 100자 이하로 입력하고 "
                             "양식·긴급도는 목록에서 고르세요(제어문자 사용 불가).", 400)
    exd = None
    if values["doc_type"] == "expenditure":
        try:
            exd = parse_expenditure(request.form)
        except ValueError as exc:
            log_event("input_rejected", "DENY", str(exc), field="expenditure")
            return _form(values, EXD_MESSAGES.get(str(exc), "지출 내용을 확인하세요."), 400)
    try:
        approvers = parse_approvers(request.form, g.user)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="approvers")
        return _form(values, APPROVER_MESSAGES.get(str(exc), "결재선을 확인하세요."), 400)
    try:
        cc_ids = parse_cc(request.form, g.user, approvers)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="cc")
        return _form(values, CC_MESSAGES.get(str(exc), "참조자를 확인하세요."), 400)
    files = uploaded_files(request.files)
    approval_id = create_approval(g.user, title, body, approvers, doc_type=values["doc_type"], urgency=values["urgency"],
                                  body_html=values["body_html"], recipient=recipient, expenditure=exd,
                                  cc_ids=cc_ids, files=files)
    log_event("approval_created", "INFO", "ok", approval_id=approval_id, steps=len(approvers), cc=len(cc_ids),
              files=len(files), doc_type=values["doc_type"], urgency=values["urgency"], rich=values["body_html"],
              amount=exd["total"] if exd else None)
    return redirect(url_for("approvals.approval_view", approval_id=approval_id), 303)


# ---------- 상세 ----------
def _load_visible(approval_id):
    """문서·결재선·참조자를 읽고 볼 수 있는 사람인지 검사한다. (문서, 단계, 참조자) 또는 오류 응답(튜플 하나)."""
    a = db.query_one(
        "SELECT a.id, a.title, a.body, a.body_html, a.recipient, a.status, a.doc_type, a.urgency, a.current_step, a.decided_at, "
        "a.created_at, a.expense_id, a.requester_id, r.display_name AS requester, r.dept AS requester_dept FROM approvals a "
        "JOIN users r ON r.id = a.requester_id WHERE a.id = %s", (approval_id,))
    if not a:
        abort(404)
    steps = db.query_all(
        "SELECT s.step_no, s.status, s.reason, s.decided_at, s.approver_id, u.display_name AS approver "
        "FROM approval_steps s JOIN users u ON u.id = s.approver_id WHERE s.approval_id = %s ORDER BY s.step_no",
        (approval_id,))
    ccs = db.query_all("SELECT c.user_id, u.display_name, u.dept FROM approval_cc c JOIN users u ON u.id = c.user_id "
                       "WHERE c.approval_id = %s ORDER BY u.dept, u.display_name", (approval_id,))
    u = g.user
    is_party = (a["requester_id"] == u["id"] or any(s["approver_id"] == u["id"] for s in steps)
                or any(c["user_id"] == u["id"] for c in ccs))
    if not is_party and u["role"] != "admin":
        return forbidden("not_party", resource=f"approval:{approval_id}")
    return a, steps, ccs


def _render_approval(approval_id, error=None, status=200):
    loaded = _load_visible(approval_id)
    if len(loaded) == 2:  # forbidden() 의 (본문, 상태코드)
        return loaded
    a, steps, ccs = loaded
    u = g.user
    expense = None
    if a["expense_id"]:
        expense = db.query_one("SELECT id, title, amount, status FROM expenses WHERE id = %s", (a["expense_id"],))
    files = db.query_all("SELECT f.id, f.orig_name, f.size, f.step_no, u.display_name AS uploader FROM approval_files f "
                         "LEFT JOIN users u ON u.id = f.uploaded_by WHERE f.approval_id = %s ORDER BY f.id", (approval_id,))
    pending = next((s for s in steps if s["status"] == "pending"), None)
    can_decide = a["status"] == "pending" and pending is not None and pending["approver_id"] == u["id"]
    can_withdraw = a["status"] == "pending" and a["requester_id"] == u["id"] and a["current_step"] == 1
    can_redraft = a["requester_id"] == u["id"] and a["status"] in ("rejected", "withdrawn") and not a["expense_id"]
    # 서식 있는 본문은 저장된 문자열을 그대로 내보내지 않고, 표시할 때마다 다시 살균한 노드 트리로 그린다(템플릿 매크로가 이스케이프).
    body_tree = richtext.parse(a["body"])[0] if a["body_html"] else None
    exd = exd_items = None
    if a["doc_type"] == "expenditure":
        exd = db.query_one("SELECT spend_date, account_name, pay_method, payee, payee_account, pay_due, evidence, total_amount "
                           "FROM expenditures WHERE approval_id = %s", (approval_id,))
        exd_items = db.query_all("SELECT line_no, item, memo, qty, unit_price, amount FROM expenditure_items "
                                 "WHERE approval_id = %s ORDER BY line_no", (approval_id,))
    return render_template("approval.html", a=a, body_tree=body_tree, exd=exd, exd_items=exd_items,
                           pay_methods=PAY_METHODS, evidence_types=EVIDENCE, steps=steps, ccs=ccs, files=files, expense=expense, can_decide=can_decide,
                           can_withdraw=can_withdraw, can_redraft=can_redraft, doc_no=doc_no(a), types=DOC_TYPES,
                           urgency=URGENCY, error=error), status


@bp.get("/approvals/<int:approval_id>")
@login_required
def approval_view(approval_id):
    return _render_approval(approval_id)


@bp.get("/approvals/<int:approval_id>/files/<int:file_id>")
@login_required
def approval_file(approval_id, file_id):
    loaded = _load_visible(approval_id)
    if len(loaded) == 2:
        return loaded
    row = db.query_one("SELECT stored_name, orig_name, mime FROM approval_files WHERE id = %s AND approval_id = %s", (file_id, approval_id))
    if not row or not (file_dir() / row["stored_name"]).is_file():
        abort(404)
    log_event("approval_file_download", "INFO", "ok", approval_id=approval_id, file_id=file_id)
    # 저장명은 서버가 만든 uuid 이고 항상 첨부(다운로드)로만 내려 브라우저가 열어 실행하지 않는다.
    return uploads.send_stored(file_dir(), row["stored_name"], as_attachment=True, download_name=row["orig_name"], mimetype=row["mime"])


# ---------- 승인·반려 ----------
def _finish(approval_id, expense_id, target):
    """문서를 종결 상태로 바꾸고 연결 경비 상태를 함께 바꾼다(같은 트랜잭션)."""
    if db.execute_rowcount("UPDATE approvals SET status = %s, decided_at = NOW() WHERE id = %s AND status = 'pending'",
                           (target, approval_id)) != 1:
        return False
    if expense_id:
        db.execute_rowcount("UPDATE expenses SET status = %s WHERE id = %s AND status = 'submitted'", (target, expense_id))
    return True


@bp.post("/approvals/<int:approval_id>/decide")
@login_required
def approval_decide(approval_id):
    decision = request.form.get("decision", "")
    if decision not in DECISIONS:
        log_event("input_rejected", "DENY", "decision_value", field="decision", value=decision[:30])
        abort(400)
    target = DECISIONS[decision]
    a = db.query_one("SELECT id, requester_id, expense_id, status FROM approvals WHERE id = %s FOR UPDATE", (approval_id,))
    if not a:
        abort(404)
    steps = db.query_all("SELECT id, step_no, approver_id, status FROM approval_steps WHERE approval_id = %s "
                         "ORDER BY step_no", (approval_id,))
    u = g.user
    mine = next((s for s in steps if s["approver_id"] == u["id"]), None)
    if mine is None or a["requester_id"] == u["id"]:
        return forbidden("not_approver", resource=f"approval:{approval_id}")
    if u["role"] not in APPROVER_ROLES:  # 결재선에 지정된 뒤 팀장 권한을 잃은 사람(강등)은 처리할 수 없다
        return forbidden("approver_role_revoked", resource=f"approval:{approval_id}")
    if a["status"] != "pending":
        log_event("approval_invalid_transition", "DENY", f"{a['status']}->{target}", approval_id=approval_id)
        return conflict("이미 종결된 결재입니다.")
    if mine["status"] == "waiting":  # 아직 내 차례가 아니다
        return forbidden("not_your_turn", resource=f"approval:{approval_id}", step=mine["step_no"])
    if mine["status"] != "pending":
        log_event("approval_invalid_transition", "DENY", f"{mine['status']}->{target}", approval_id=approval_id)
        return conflict("이미 처리한 결재입니다.")

    reason = None
    if decision == "reject":
        try:
            reason = validators.text(request.form.get("reason", ""), "reason", 1, 500, multiline=True)
        except ValueError as exc:
            log_event("input_rejected", "DENY", str(exc), field="reason")
            return _render_approval(approval_id, error=REASON_ERROR, status=400)
    else:  # 승인할 때의 의견은 선택이다. 반려 사유 칸(reason)은 승인에는 쓰이지 않는다.
        comment = request.form.get("comment", "").strip()
        if comment:
            try:
                reason = validators.text(comment, "comment", 1, 500, multiline=True)
            except ValueError as exc:
                log_event("input_rejected", "DENY", str(exc), field="comment")
                return _render_approval(approval_id, error=COMMENT_ERROR, status=400)

    files = uploaded_files(request.files)  # 결재 첨부(선택): 개수·형식·용량 제한 없음

    if db.execute_rowcount("UPDATE approval_steps SET status = %s, reason = %s, decided_at = NOW() "
                           "WHERE id = %s AND status = 'pending'", (target, reason, mine["id"])) != 1:
        return conflict("이미 처리한 결재입니다.")
    saved = save_files(approval_id, files, step_no=mine["step_no"], uploaded_by=u["id"])

    if decision == "approve":
        nxt = next((s for s in steps if s["step_no"] == mine["step_no"] + 1), None)
        if nxt:  # 다음 결재자에게 차례를 넘긴다
            db.execute_rowcount("UPDATE approval_steps SET status = 'pending' WHERE id = %s AND status = 'waiting'", (nxt["id"],))
            db.execute_rowcount("UPDATE approvals SET current_step = %s WHERE id = %s AND status = 'pending'",
                                (nxt["step_no"], approval_id))
        elif not _finish(approval_id, a["expense_id"], "approved"):
            return conflict("이미 종결된 결재입니다.")
    else:
        db.execute_rowcount("UPDATE approval_steps SET status = 'skipped' WHERE approval_id = %s AND status = 'waiting'",
                            (approval_id,))
        if not _finish(approval_id, a["expense_id"], "rejected"):
            return conflict("이미 종결된 결재입니다.")
    log_event("approval_decided", "ALLOW", target, approval_id=approval_id, requester_id=a["requester_id"],
              step=mine["step_no"], commented=bool(reason) and decision == "approve", files=len(saved))
    return redirect(url_for("approvals.approval_view", approval_id=approval_id), 303)


# ---------- 철회 ----------
@bp.post("/approvals/<int:approval_id>/withdraw")
@login_required
def approval_withdraw(approval_id):
    a = db.query_one("SELECT id, requester_id, expense_id, status, current_step FROM approvals WHERE id = %s FOR UPDATE",
                     (approval_id,))
    if not a:
        abort(404)
    if a["requester_id"] != g.user["id"]:
        return forbidden("not_requester", resource=f"approval:{approval_id}")
    # 진행 중이고 아직 첫 결재자도 처리하지 않았을 때만 철회할 수 있다(동시에 승인과 철회가 오면 행 잠금으로 한쪽만 성공)
    if a["status"] != "pending" or a["current_step"] != 1:
        log_event("approval_invalid_transition", "DENY", f"{a['status']}/step{a['current_step']}->withdrawn",
                  approval_id=approval_id)
        return conflict("이미 결재가 진행되었거나 종결되어 철회할 수 없습니다.")
    if db.execute_rowcount("UPDATE approvals SET status = 'withdrawn', decided_at = NOW() "
                           "WHERE id = %s AND status = 'pending' AND current_step = 1", (approval_id,)) != 1:
        return conflict("이미 결재가 진행되었거나 종결되어 철회할 수 없습니다.")
    db.execute_rowcount("UPDATE approval_steps SET status = 'skipped' WHERE approval_id = %s "
                        "AND status IN ('waiting', 'pending')", (approval_id,))
    if a["expense_id"]:  # 연결된 경비는 다시 임시저장이 되어 고쳐서 재상신할 수 있다
        db.execute_rowcount("UPDATE expenses SET status = 'draft' WHERE id = %s AND status = 'submitted'", (a["expense_id"],))
    log_event("approval_withdrawn", "INFO", "ok", approval_id=approval_id)
    return redirect(url_for("approvals.approval_view", approval_id=approval_id), 303)
