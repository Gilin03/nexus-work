"""포털: 문서함(일반/기밀), 직원 검색, 게시판·자유게시판, 첨부 업로드·다운로드.
- 기밀 문서는 manager 이상만, 별도 DB 계정(conf=True)으로만 읽는다.
- 모든 SQL 은 상수 문자열 + params. 화면 출력은 Jinja 자동 이스케이프를 그대로 쓰고 끄지 않는다.
- 첨부는 확장자 허용목록 + 내용 확인 후 웹루트 밖에 무작위 이름으로 저장하고, 항상 첨부(다운로드)로만 내려준다."""
from pathlib import Path

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, send_from_directory, url_for

from . import db, uploads, validators
from .auth import login_required, role_required
from .security import log_event

bp = Blueprint("portal", __name__)

BOARDS = {"notice": "공지사항", "free": "자유게시판"}
PAGE_SIZE = 20
MAX_PAGE = 10000
UPLOAD_MESSAGES = {
    "extension_not_allowed": "허용되지 않는 파일 형식입니다 (pdf, png, jpg, txt만 가능).",
    "content_mismatch": "파일 내용이 확장자와 일치하지 않습니다.",
    "empty_upload": "빈 파일입니다.",
}
POST_FORM_ERROR = "제목은 1~120자, 내용은 1~5000자로 입력하세요(제어문자 사용 불가)."


def _forbidden(reason, **extra):
    log_event("authz_deny", "DENY", reason, **extra)
    return render_template("error.html", code=403, message="접근 권한이 없습니다."), 403


def _board_or_404(board):
    if board not in BOARDS:
        abort(404)


def _page():
    try:
        page = validators.positive_int(request.args.get("page", "1"), "page")
    except ValueError:
        abort(400)
    if page > MAX_PAGE:
        abort(400)
    return page


# ---------- 문서함 ----------
@bp.get("/documents")
@login_required
def documents():
    docs = db.query_all("SELECT id, title, created_at FROM documents ORDER BY id DESC")
    return render_template("documents.html", docs=docs, title="문서함", confidential=False)


@bp.get("/documents/<int:doc_id>")
@login_required
def document(doc_id):
    row = db.query_one("SELECT id, title, body, created_at FROM documents WHERE id = %s", (doc_id,))
    if not row:
        abort(404)
    return render_template("document.html", doc=row, back=url_for("portal.documents"))


@bp.get("/confidential")
@role_required("manager", "admin")
def confidential_list():
    docs = db.query_all("SELECT id, title, created_at FROM confidential_documents ORDER BY id DESC", conf=True)
    log_event("confidential_access", "ALLOW", "list")
    return render_template("documents.html", docs=docs, title="기밀 문서함", confidential=True)


@bp.get("/confidential/<int:doc_id>")
@role_required("manager", "admin")
def confidential_document(doc_id):
    row = db.query_one("SELECT id, title, body, created_at FROM confidential_documents WHERE id = %s",
                       (doc_id,), conf=True)
    if not row:
        abort(404)
    log_event("confidential_access", "ALLOW", "read", resource_id=doc_id)
    return render_template("document.html", doc=row, back=url_for("portal.confidential_list"), confidential=True)


# ---------- 직원 검색 ----------
@bp.get("/employees")
@login_required
def employees():
    q = request.args.get("q", "").strip()
    if not q:
        rows = db.query_all("SELECT name, dept, title, ext FROM employees ORDER BY name LIMIT 50")
        return render_template("employees.html", rows=rows, q="", error=None)
    try:
        pattern = validators.like_pattern(q)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="q", value=q[:100])
        return render_template("employees.html", rows=[], q="", error="검색어는 1~50자로 입력하세요(제어문자 사용 불가)."), 400
    rows = db.query_all(
        "SELECT name, dept, title, ext FROM employees "
        "WHERE name LIKE %s OR dept LIKE %s OR title LIKE %s ORDER BY name LIMIT 50", (pattern, pattern, pattern))
    return render_template("employees.html", rows=rows, q=q, error=None)


# ---------- 게시판 ----------
@bp.get("/boards/<board>")
@login_required
def board_list(board):
    _board_or_404(board)
    page = _page()
    rows = db.query_all(
        "SELECT p.id, p.title, p.created_at, u.display_name AS author "
        "FROM posts p JOIN users u ON u.id = p.author_id WHERE p.board = %s "
        "ORDER BY p.id DESC LIMIT %s OFFSET %s", (board, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE))
    return render_template("board.html", board=board, name=BOARDS[board], rows=rows[:PAGE_SIZE],
                           page=page, has_next=len(rows) > PAGE_SIZE,
                           can_write=(board != "notice" or g.user["role"] in ("manager", "admin")))


@bp.route("/boards/<board>/new", methods=["GET", "POST"])
@login_required
def post_new(board):
    _board_or_404(board)
    if board == "notice" and g.user["role"] not in ("manager", "admin"):
        return _forbidden("insufficient_role", resource=f"board:{board}")
    if request.method == "GET":
        return render_template("post_form.html", board=board, name=BOARDS[board], error=None)

    try:
        title = validators.text(request.form.get("title", ""), "title", 1, 120)
        body = validators.text(request.form.get("body", ""), "body", 1, 5000, multiline=True)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="post")
        return render_template("post_form.html", board=board, name=BOARDS[board], error=POST_FORM_ERROR), 400

    upload = request.files.get("attachment")
    meta = data = None
    if upload and upload.filename:
        data = upload.read()
        try:
            _ext, mime, display, digest = uploads.inspect_upload(upload.filename, data)
        except ValueError as exc:
            log_event("upload_reject", "BLOCK", str(exc), filename=upload.filename[:100], size=len(data))
            return render_template("post_form.html", board=board, name=BOARDS[board],
                                   error=UPLOAD_MESSAGES.get(str(exc), "업로드할 수 없는 파일입니다.")), 400
        meta = (mime, display, digest)

    post_id = db.execute("INSERT INTO posts(board, author_id, title, body) VALUES(%s, %s, %s, %s)",
                         (board, g.user["id"], title, body))
    if meta:
        # ponytail: 파일을 먼저 쓰고 DB 행을 넣는다. 그 사이 실패하면 고아 파일이 남을 수 있다(정기 정리 스크립트로 해결 가능).
        stored = uploads.store(Path(current_app.config["UPLOAD_DIR"]), data)
        db.execute("INSERT INTO attachments(post_id, stored_name, orig_name, mime, size, sha256) "
                   "VALUES(%s, %s, %s, %s, %s, %s)", (post_id, stored, meta[1], meta[0], len(data), meta[2]))
    log_event("post_created", "INFO", "ok", post_id=post_id, board=board, attachment=bool(meta))
    return redirect(url_for("portal.post_view", post_id=post_id), 303)


@bp.get("/posts/<int:post_id>")
@login_required
def post_view(post_id):
    post = db.query_one(
        "SELECT p.id, p.board, p.title, p.body, p.created_at, p.author_id, u.display_name AS author "
        "FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = %s", (post_id,))
    if not post:
        abort(404)
    files = db.query_all("SELECT id, orig_name, size FROM attachments WHERE post_id = %s ORDER BY id", (post_id,))
    can_delete = post["author_id"] == g.user["id"] or g.user["role"] == "admin"
    return render_template("post.html", post=post, files=files, can_delete=can_delete,
                           board_name=BOARDS.get(post["board"], ""))


@bp.post("/posts/<int:post_id>/delete")
@login_required
def post_delete(post_id):
    post = db.query_one("SELECT id, board, author_id FROM posts WHERE id = %s FOR UPDATE", (post_id,))
    if not post:
        abort(404)
    if post["author_id"] != g.user["id"] and g.user["role"] != "admin":
        return _forbidden("not_owner", resource=f"post:{post_id}")
    stored = [r["stored_name"] for r in db.query_all(
        "SELECT stored_name FROM attachments WHERE post_id = %s", (post_id,))]
    db.execute("DELETE FROM posts WHERE id = %s", (post_id,))  # 첨부 행은 ON DELETE CASCADE
    db.commit()
    for name in stored:
        (Path(current_app.config["UPLOAD_DIR"]) / name).unlink(missing_ok=True)
    log_event("post_deleted", "INFO", "ok", post_id=post_id, board=post["board"])
    return redirect(url_for("portal.board_list", board=post["board"]), 303)


# ---------- 첨부 다운로드 ----------
@bp.get("/attachments/<int:att_id>")
@login_required
def attachment(att_id):
    row = db.query_one("SELECT stored_name, orig_name, mime FROM attachments WHERE id = %s", (att_id,))
    directory = Path(current_app.config["UPLOAD_DIR"])
    if not row or not (directory / row["stored_name"]).is_file():
        abort(404)
    log_event("attachment_download", "INFO", "ok", attachment_id=att_id)
    # 저장명은 서버가 만든 uuid 라서 경로 조작이 불가능하고, 항상 첨부(다운로드)로만 내려 브라우저가 실행·렌더링하지 않는다.
    return send_from_directory(directory, row["stored_name"], as_attachment=True,
                               download_name=row["orig_name"], mimetype=row["mime"])
