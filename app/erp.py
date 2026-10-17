"""ERP(최소): 급여(기밀)·경비·재무 보고(기밀). 시드 데이터 + 목록·상세·경비 등록·제출까지만 제공한다.
접근 범위(서버에서 강제): 직원=본인, 팀장=같은 부서(본인 포함), 관리자=전체. 기밀 표(급여·재무)는 기밀 DB 계정으로만 읽는다."""
from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from . import db, validators
from .approvals import (APPROVER_MESSAGES, MAX_STEPS, approver_candidates, conflict, create_approval, forbidden,
                        parse_approvers)
from .auth import login_required, role_required
from .security import log_event

bp = Blueprint("erp", __name__)

MAX_AMOUNT = 100_000_000


def _can_access(owner_id, owner_dept):
    u = g.user
    return u["role"] == "admin" or u["id"] == owner_id or (u["role"] == "manager" and u["dept"] == owner_dept)


# ---------- 급여(기밀) ----------
@bp.get("/payroll")
@login_required
def payroll_list():
    u = g.user
    if u["role"] == "admin":
        rows = db.query_all("SELECT id, user_id, pay_month, base_salary, bonus FROM payroll "
                            "ORDER BY pay_month DESC, user_id LIMIT 200", conf=True)
    elif u["role"] == "manager":
        # ponytail: 팀 범위는 FIND_IN_SET 으로 조회한다(표가 작아 색인이 필요 없음). 대규모면 별도 팀 표·조인으로 교체.
        ids = ",".join(str(r["id"]) for r in db.query_all("SELECT id FROM users WHERE dept = %s", (u["dept"],)))
        rows = db.query_all("SELECT id, user_id, pay_month, base_salary, bonus FROM payroll "
                            "WHERE FIND_IN_SET(user_id, %s) ORDER BY pay_month DESC, user_id LIMIT 200", (ids,), conf=True)
    else:
        rows = db.query_all("SELECT id, user_id, pay_month, base_salary, bonus FROM payroll "
                            "WHERE user_id = %s ORDER BY pay_month DESC LIMIT 200", (u["id"],), conf=True)
    names = {r["id"]: r["display_name"] for r in db.query_all("SELECT id, display_name FROM users")}
    log_event("confidential_access", "ALLOW", "list", resource="payroll", rows=len(rows))
    return render_template("payroll.html", rows=rows, names=names)


@bp.get("/payroll/<int:pay_id>")
@login_required
def payroll_detail(pay_id):
    row = db.query_one("SELECT id, user_id, pay_month, base_salary, bonus FROM payroll WHERE id = %s", (pay_id,), conf=True)
    if not row:
        abort(404)
    owner = db.query_one("SELECT id, display_name, dept FROM users WHERE id = %s", (row["user_id"],))
    if not owner or not _can_access(owner["id"], owner["dept"]):
        return forbidden("out_of_scope", resource=f"payroll:{pay_id}")
    log_event("confidential_access", "ALLOW", "read", resource=f"payroll:{pay_id}")
    return render_template("payroll_detail.html", p=row, owner=owner)


# ---------- 재무 보고(기밀) ----------
@bp.get("/finance")
@role_required("manager", "admin")
def finance_list():
    rows = db.query_all("SELECT id, report_month, title, created_at FROM financial_reports "
                        "ORDER BY report_month DESC, id DESC", conf=True)
    log_event("confidential_access", "ALLOW", "list", resource="finance")
    return render_template("finance.html", rows=rows)


@bp.get("/finance/<int:report_id>")
@role_required("manager", "admin")
def finance_report(report_id):
    row = db.query_one("SELECT id, report_month, title, body, created_at FROM financial_reports WHERE id = %s",
                       (report_id,), conf=True)
    if not row:
        abort(404)
    log_event("confidential_access", "ALLOW", "read", resource=f"finance:{report_id}")
    return render_template("finance_report.html", r=row)


# ---------- 경비 ----------
@bp.get("/expenses")
@login_required
def expense_list():
    u = g.user
    if u["role"] == "admin":
        rows = db.query_all("SELECT e.id, e.title, e.amount, e.status, e.created_at, u.display_name AS owner "
                            "FROM expenses e JOIN users u ON u.id = e.user_id ORDER BY e.id DESC LIMIT 200")
    elif u["role"] == "manager":
        rows = db.query_all("SELECT e.id, e.title, e.amount, e.status, e.created_at, u.display_name AS owner "
                            "FROM expenses e JOIN users u ON u.id = e.user_id WHERE u.dept = %s "
                            "ORDER BY e.id DESC LIMIT 200", (u["dept"],))
    else:
        rows = db.query_all("SELECT e.id, e.title, e.amount, e.status, e.created_at, u.display_name AS owner "
                            "FROM expenses e JOIN users u ON u.id = e.user_id WHERE e.user_id = %s "
                            "ORDER BY e.id DESC LIMIT 200", (u["id"],))
    return render_template("expenses.html", rows=rows)


@bp.route("/expenses/new", methods=["GET", "POST"])
@login_required
def expense_new():
    if request.method == "GET":
        return render_template("expense_form.html", error=None, max_amount=MAX_AMOUNT)
    try:
        title = validators.text(request.form.get("title", ""), "title", 1, 120)
        amount = validators.positive_int(request.form.get("amount", ""), "amount", MAX_AMOUNT)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="expense")
        return render_template("expense_form.html", max_amount=MAX_AMOUNT,
                               error=f"제목은 1~120자, 금액은 1~{MAX_AMOUNT:,} 사이의 정수로 입력하세요."), 400
    # 상태는 항상 draft 로 시작한다(폼으로 보낸 status 등 다른 필드는 무시).
    expense_id = db.execute("INSERT INTO expenses(user_id, title, amount, status) VALUES(%s, %s, %s, 'draft')",
                            (g.user["id"], title, amount))
    log_event("expense_created", "INFO", "ok", expense_id=expense_id, amount=amount)
    return redirect(url_for("erp.expense_view", expense_id=expense_id), 303)


def _render_expense(expense_id, error=None, status=200):
    e = db.query_one("SELECT e.id, e.user_id, e.title, e.amount, e.status, e.created_at, "
                     "u.display_name AS owner, u.dept AS owner_dept "
                     "FROM expenses e JOIN users u ON u.id = e.user_id WHERE e.id = %s", (expense_id,))
    if not e:
        abort(404)
    if not _can_access(e["user_id"], e["owner_dept"]):
        return forbidden("out_of_scope", resource=f"expense:{expense_id}")
    approval = db.query_one("SELECT id, status FROM approvals WHERE expense_id = %s ORDER BY id DESC LIMIT 1", (expense_id,))
    can_submit = e["user_id"] == g.user["id"] and e["status"] == "draft"
    candidates = approver_candidates(g.user) if can_submit else []
    return render_template("expense.html", e=e, approval=approval, can_submit=can_submit, candidates=candidates,
                           max_steps=MAX_STEPS, error=error), status


@bp.get("/expenses/<int:expense_id>")
@login_required
def expense_view(expense_id):
    return _render_expense(expense_id)


@bp.post("/expenses/<int:expense_id>/submit")
@login_required
def expense_submit(expense_id):
    e = db.query_one("SELECT id, user_id, title, amount, status FROM expenses WHERE id = %s FOR UPDATE", (expense_id,))
    if not e:
        abort(404)
    if e["user_id"] != g.user["id"]:  # 본인 경비만 제출한다(팀장·관리자도 남의 경비는 제출 불가)
        return forbidden("not_owner", resource=f"expense:{expense_id}")
    if e["status"] != "draft":
        log_event("expense_invalid_transition", "DENY", f"{e['status']}->submitted", expense_id=expense_id)
        return conflict("임시저장 상태의 경비만 제출할 수 있습니다.")
    try:  # 결재선은 상신자가 순서대로 직접 고른다
        approvers = parse_approvers(request.form, g.user)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="approvers")
        return _render_expense(expense_id, error=APPROVER_MESSAGES.get(str(exc), "결재선을 확인하세요."), status=400)
    if db.execute_rowcount("UPDATE expenses SET status = 'submitted' WHERE id = %s AND status = 'draft'", (expense_id,)) != 1:
        return conflict("임시저장 상태의 경비만 제출할 수 있습니다.")
    approval_id = create_approval(g.user, f"경비 결재: {e['title']}", f"금액 {e['amount']:,}원", approvers, expense_id)
    log_event("expense_submitted", "INFO", "ok", expense_id=expense_id, approval_id=approval_id, steps=len(approvers))
    return redirect(url_for("approvals.approval_view", approval_id=approval_id), 303)
