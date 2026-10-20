"""포털: 문서함(일반/기밀), 게시판·자유게시판, 첨부 업로드·다운로드.
- 기밀 문서는 manager 이상만, 별도 DB 계정(conf=True)으로만 읽는다.
- 모든 SQL 은 상수 문자열 + params. 화면 출력은 Jinja 자동 이스케이프를 그대로 쓰고 끄지 않는다.
- 첨부는 확장자 허용목록 + 내용 확인 후 웹루트 밖에 무작위 이름으로 저장하고, 항상 첨부(다운로드)로만 내려준다."""
from pathlib import Path

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from . import db, uploads, validators
from .auth import login_required, role_required
from .permissions import can
from .security import log_event

bp = Blueprint("portal", __name__)

BOARDS = {"notice": "공지사항", "free": "자유게시판"}
PAGE_SIZE = 20
MAX_PAGE = 10000
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


# ---------- 직원 검색 → 주소록 ----------
# 직원 검색은 주소록의 "사내 직원" 탭으로 합쳤다(같은 데이터·같은 공개 범위·같은 검색 규칙, app/library.py). 옛 주소와 북마크는 그대로 이동시킨다.
@bp.get("/employees")
@login_required
def employees():
    return redirect(url_for("library.contact_list", tab="company", q=request.args.get("q") or None), 301)


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
                           can_write=(board != "notice" or can(g.user, "notice.write")))


@bp.route("/boards/<board>/new", methods=["GET", "POST"])
@login_required
def post_new(board):
    _board_or_404(board)
    if board == "notice" and not can(g.user, "notice.write"):
        return _forbidden("insufficient_role", resource=f"board:{board}")
    if request.method == "GET":
        return render_template("post_form.html", board=board, name=BOARDS[board], error=None)

    try:
        title = validators.text(request.form.get("title", ""), "title", 1, 120)
        body = validators.text(request.form.get("body", ""), "body", 1, 5000, multiline=True)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="post")
        return render_template("post_form.html", board=board, name=BOARDS[board], error=POST_FORM_ERROR), 400

    uploaded = [f for f in request.files.getlist("attachment") if f and f.filename]   # 개수·형식·용량 제한 없음(무해하게 저장)
    post_id = db.execute("INSERT INTO posts(board, author_id, title, body) VALUES(%s, %s, %s, %s)",
                         (board, g.user["id"], title, body))
    saved = []
    try:
        for f in uploaded:
            meta = uploads.save_attachment(Path(current_app.config["UPLOAD_DIR"]), f)
            saved.append(meta)
            db.execute("INSERT INTO attachments(post_id, stored_name, orig_name, mime, size, sha256) VALUES(%s, %s, %s, %s, %s, %s)",
                       (post_id, meta["stored_name"], meta["orig_name"], meta["mime"], meta["size"], meta["sha256"]))
    except BaseException:  # 도중에 실패(디스크 부족 등)하면 글도 롤백되므로 이미 쓴 파일도 지운다
        uploads.remove_saved(Path(current_app.config["UPLOAD_DIR"]), saved)
        raise
    log_event("post_created", "INFO", "ok", post_id=post_id, board=board, attachment=bool(saved), attachments=len(saved),
              bytes=sum(m["size"] for m in saved))
    return redirect(url_for("portal.post_view", post_id=post_id), 303)


@bp.get("/posts/<int:post_id>")
@login_required
def post_view(post_id):
    post = db.query_one(
        "SELECT p.id, p.board, p.title, p.body, p.created_at, p.author_id, u.display_name AS author "
        "FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = %s", (post_id,))
    if not post:
        abort(404)
    files = db.query_all("SELECT id, orig_name, size, mime FROM attachments WHERE post_id = %s ORDER BY id", (post_id,))
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


# ---------- 첨부 미리보기(그림·PDF) ----------
# 앱이 올린 파일만 인라인으로 보여 준다: 이미지는 같은 출처의 <img> 로, PDF 는 새 탭(최상위 문서)으로 연다.
# 허용 형식은 업로드 때 확장자와 내용(매직바이트)이 모두 맞은 png·jpg·pdf 뿐이며 txt 등은 다운로드만 된다.
# nosniff 로 브라우저가 형식을 다시 추측하지 못하게 하고, 이 응답은 어떤 하위 자원도 불러올 수 없는 CSP 를 직접 붙인다.
# 이미지는 sandbox 까지 걸어 어떤 문서로 해석되더라도 스크립트가 실행되지 않는다(PDF 뷰어는 sandbox 와 맞지 않아 뺀다).
INLINE_CSP = {"image/png": "default-src 'none'; sandbox", "image/jpeg": "default-src 'none'; sandbox",
              "application/pdf": "default-src 'none'"}


@bp.get("/attachments/<int:att_id>/view")
@login_required
def attachment_view(att_id):
    row = db.query_one("SELECT stored_name, orig_name, mime FROM attachments WHERE id = %s", (att_id,))
    directory = Path(current_app.config["UPLOAD_DIR"])
    if not row or row["mime"] not in INLINE_CSP or not (directory / row["stored_name"]).is_file():
        abort(404)
    log_event("attachment_view", "INFO", "ok", attachment_id=att_id)
    resp = uploads.send_stored(directory, row["stored_name"], as_attachment=False,
                               download_name=row["orig_name"], mimetype=row["mime"])
    resp.headers["Content-Security-Policy"] = INLINE_CSP[row["mime"]]
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return resp


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
    return uploads.send_stored(directory, row["stored_name"], as_attachment=True,
                               download_name=row["orig_name"], mimetype=row["mime"])
