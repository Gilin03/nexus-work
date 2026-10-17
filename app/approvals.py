"""전자결재: 상신자가 정한 결재선(순서)대로 순차 결재한다. 반려는 사유가 필수이고, 상신자는 아직 아무도 결재하지 않았을 때만 철회할 수 있다.
- 결재선: 상신자가 최대 5명을 순서대로 고른다. 후보는 팀장·관리자이며, 본인·중복은 불가(앱 검사 + DB 트리거 + 결재자 열 수정 권한 없음).
- 처리: 지금 차례인 결재자만 승인·반려할 수 있다. 차례가 아닌 결재자·상신자·제3자·(결재선에 없는) 관리자는 처리할 수 없다.
- 상태: 문서는 pending → approved / rejected / withdrawn, 단계는 waiting → pending → approved / rejected / skipped 한 방향뿐이다.
  마지막 단계가 승인되면 문서가 승인, 어느 단계든 반려되면 문서가 반려(남은 단계는 skipped), 철회하면 연결 경비는 다시 임시저장이 된다."""
from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from . import db, validators
from .auth import login_required
from .security import log_event

bp = Blueprint("approvals", __name__)

DECISIONS = {"approve": "approved", "reject": "rejected"}
MAX_STEPS = 5
# 결재선에 넣을 수 있는 역할. 아래 approver_candidates 의 SQL 과 같은 값을 유지한다.
APPROVER_ROLES = ("manager", "admin")
APPROVER_MESSAGES = {
    "approver_required": "결재자를 한 명 이상 선택하세요.",
    "approver_invalid": "선택할 수 없는 결재자입니다. 팀장 또는 관리자만 지정할 수 있습니다.",
    "approver_duplicate": "같은 결재자를 두 번 선택할 수 없습니다.",
    "approver_self": "본인을 결재자로 지정할 수 없습니다.",
}
REASON_ERROR = "반려 사유를 1~500자로 입력하세요(제어문자 사용 불가)."


def forbidden(reason, **extra):
    log_event("authz_deny", "DENY", reason, **extra)
    return render_template("error.html", code=403, message="접근 권한이 없습니다."), 403


def conflict(message):
    return render_template("error.html", code=409, message=message), 409


# ---------- 결재선 ----------
def approver_candidates(user):
    return db.query_all("SELECT id, display_name, dept, role FROM users "
                        "WHERE role IN ('manager', 'admin') AND id <> %s ORDER BY dept, display_name", (user["id"],))


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
        row = db.query_one("SELECT role FROM users WHERE id = %s", (approver_id,))
        if not row or row["role"] not in APPROVER_ROLES:
            raise ValueError("approver_invalid")
    return ids


def create_approval(requester, title, body, approver_ids, expense_id=None):
    """결재 문서와 결재선을 만든다. 첫 결재자만 pending, 나머지는 차례를 기다린다(waiting)."""
    approval_id = db.execute("INSERT INTO approvals(title, body, requester_id, expense_id) VALUES(%s, %s, %s, %s)",
                             (title, body, requester["id"], expense_id))
    for n, approver_id in enumerate(approver_ids, start=1):
        db.execute("INSERT INTO approval_steps(approval_id, step_no, approver_id, status) VALUES(%s, %s, %s, %s)",
                   (approval_id, n, approver_id, "pending" if n == 1 else "waiting"))
    return approval_id


# ---------- 목록·상신 ----------
@bp.get("/approvals")
@login_required
def approval_list():
    u = g.user
    if u["role"] == "admin":
        rows = db.query_all(
            "SELECT a.id, a.title, a.status, a.current_step, a.created_at, r.display_name AS requester, "
            "(SELECT COUNT(*) FROM approval_steps s WHERE s.approval_id = a.id) AS total, "
            "EXISTS(SELECT 1 FROM approval_steps s WHERE s.approval_id = a.id AND s.approver_id = %s "
            "AND s.status = 'pending') AS needs_me "
            "FROM approvals a JOIN users r ON r.id = a.requester_id ORDER BY a.id DESC LIMIT 200", (u["id"],))
    else:
        rows = db.query_all(
            "SELECT a.id, a.title, a.status, a.current_step, a.created_at, r.display_name AS requester, "
            "(SELECT COUNT(*) FROM approval_steps s WHERE s.approval_id = a.id) AS total, "
            "EXISTS(SELECT 1 FROM approval_steps s WHERE s.approval_id = a.id AND s.approver_id = %s "
            "AND s.status = 'pending') AS needs_me "
            "FROM approvals a JOIN users r ON r.id = a.requester_id "
            "WHERE a.requester_id = %s OR EXISTS(SELECT 1 FROM approval_steps s WHERE s.approval_id = a.id "
            "AND s.approver_id = %s) ORDER BY a.id DESC LIMIT 200", (u["id"], u["id"], u["id"]))
    return render_template("approvals.html", rows=rows)


def _form(error=None, status=200):
    return render_template("approval_form.html", error=error, candidates=approver_candidates(g.user),
                           max_steps=MAX_STEPS), status


@bp.route("/approvals/new", methods=["GET", "POST"])
@login_required
def approval_new():
    if request.method == "GET":
        return _form()
    try:
        title = validators.text(request.form.get("title", ""), "title", 1, 200)
        body = validators.text(request.form.get("body", ""), "body", 1, 2000, multiline=True)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="approval")
        return _form("제목은 1~200자, 내용은 1~2000자로 입력하세요(제어문자 사용 불가).", 400)
    try:
        approvers = parse_approvers(request.form, g.user)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="approvers")
        return _form(APPROVER_MESSAGES.get(str(exc), "결재선을 확인하세요."), 400)
    approval_id = create_approval(g.user, title, body, approvers)
    log_event("approval_created", "INFO", "ok", approval_id=approval_id, steps=len(approvers))
    return redirect(url_for("approvals.approval_view", approval_id=approval_id), 303)


# ---------- 상세 ----------
def _render_approval(approval_id, error=None, status=200):
    a = db.query_one(
        "SELECT a.id, a.title, a.body, a.status, a.current_step, a.decided_at, a.created_at, a.expense_id, "
        "a.requester_id, r.display_name AS requester FROM approvals a "
        "JOIN users r ON r.id = a.requester_id WHERE a.id = %s", (approval_id,))
    if not a:
        abort(404)
    steps = db.query_all(
        "SELECT s.step_no, s.status, s.reason, s.decided_at, s.approver_id, u.display_name AS approver "
        "FROM approval_steps s JOIN users u ON u.id = s.approver_id WHERE s.approval_id = %s ORDER BY s.step_no",
        (approval_id,))
    u = g.user
    is_party = a["requester_id"] == u["id"] or any(s["approver_id"] == u["id"] for s in steps)
    if not is_party and u["role"] != "admin":
        return forbidden("not_party", resource=f"approval:{approval_id}")
    expense = None
    if a["expense_id"]:
        expense = db.query_one("SELECT id, title, amount, status FROM expenses WHERE id = %s", (a["expense_id"],))
    pending = next((s for s in steps if s["status"] == "pending"), None)
    can_decide = a["status"] == "pending" and pending is not None and pending["approver_id"] == u["id"]
    can_withdraw = a["status"] == "pending" and a["requester_id"] == u["id"] and a["current_step"] == 1
    return render_template("approval.html", a=a, steps=steps, expense=expense, can_decide=can_decide,
                           can_withdraw=can_withdraw, error=error), status


@bp.get("/approvals/<int:approval_id>")
@login_required
def approval_view(approval_id):
    return _render_approval(approval_id)


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

    if db.execute_rowcount("UPDATE approval_steps SET status = %s, reason = %s, decided_at = NOW() "
                           "WHERE id = %s AND status = 'pending'", (target, reason, mine["id"])) != 1:
        return conflict("이미 처리한 결재입니다.")

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
              step=mine["step_no"])
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
