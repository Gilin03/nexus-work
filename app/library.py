"""자료: 자료실(폴더형), 주소록, 문서 검색, 양식 서식 모음.
- 자료실: 폴더는 전사 공개 또는 부서 공개(그 부서와 관리자만). 하위 폴더는 부모의 범위를 물려받고 깊이는 4단계까지.
  폴더는 팀장·관리자가 만들고(팀장은 자기 부서 폴더만 최상위로), 파일은 볼 수 있는 폴더에 누구나 올린다. **파일 형식·개수·용량은 제한하지 않는다**(게시판·결재 첨부와 같은 방식으로 무해하게 저장).
  같은 폴더에 같은 이름을 올리면 새 버전이 되고 이전 버전도 남는다. 삭제는 올린 사람·관리자만, 기록을 남기는 숨김 처리이며 파일 자체는 지우지 않는다.
- 주소록: 사내 직원(옛 '직원 검색'을 합친 탭: 이름·부서·직책·내선 검색, 로그인한 누구나)·공유 연락처(전 직원)·내 연락처(본인만). 연락처 삭제는 만든 사람·관리자(숨김 처리).
- 문서 검색: 문서함·게시판·내가 볼 수 있는 결재·볼 수 있는 자료실 파일 이름·양식·내 업무·볼 수 있는 연락처를 한 번에 찾는다. **기밀 문서함은 검색 대상이 아니다.**
- 양식 모음: 관리자가 올리는 서식 파일 + 전자결재 양식 바로가기.
- 모든 SQL 은 상수 문자열 + params 이고, 검색어는 LIKE 와일드카드를 이스케이프한다."""
import re
from pathlib import Path

import pymysql
from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from . import db, uploads, validators
from .approvals import DOC_TYPES, FORM_TYPES, conflict, forbidden
from .auth import login_required, role_required
from .permissions import can, permission_required
from .hr import now_kst
from .security import log_event

bp = Blueprint("library", __name__, url_prefix="/library")

MAX_DEPTH = 4
FORM_CATEGORIES = ("인사", "총무", "재무", "영업", "IT", "기타")
CONTACT_TABS = (("company", "사내 직원"), ("shared", "공유 연락처"), ("mine", "내 연락처"))
PHONE_RE = re.compile(r"^[0-9+()\- ]{0,30}$")
EMAIL_RE = re.compile(r"^[^@\s<>\"',;]{1,64}@[^@\s<>\"',;]{1,63}\.[^@\s<>\"',;]{2,40}$")
MESSAGES = {
    "name": "폴더 이름은 1~50자로 입력하세요(제어문자 사용 불가).",
    "note": "설명은 200자 이하로 입력하세요(제어문자 사용 불가).",
    "no_file": "올릴 파일을 선택하세요.",
    "depth": f"폴더는 {MAX_DEPTH}단계까지만 만들 수 있습니다.",
    "dup": "같은 이름의 폴더가 이미 있습니다.",
    "scope": "공개 범위가 올바르지 않습니다.",
    "c_name": "이름은 1~60자로 입력하세요(제어문자 사용 불가).",
    "c_field": "회사 80자·직책 60자·메모 200자 이하로 입력하세요(제어문자 사용 불가).",
    "c_phone": "전화번호는 숫자와 + ( ) - 공백만 30자 이하로 입력하세요.",
    "c_email": "이메일 형식이 올바르지 않습니다.",
    "c_contact": "전화번호나 이메일 중 하나는 입력하세요.",
    "f_title": "제목은 1~100자로 입력하세요(제어문자 사용 불가).",
    "f_category": "분류를 선택하세요.",
    "f_desc": "설명은 200자 이하로 입력하세요(제어문자 사용 불가).",
}


def _pattern(q):
    return validators.like_pattern(q)


# =====================================================================================
# 자료실
# =====================================================================================
def _folder(folder_id):
    return db.query_one("SELECT f.id, f.parent_id, f.name, f.scope, f.dept, f.created_by, f.created_at, u.display_name AS creator "
                        "FROM lib_folders f JOIN users u ON u.id = f.created_by WHERE f.id = %s", (folder_id,))


def _visible(f):
    u = g.user
    return u["role"] == "admin" or f["scope"] == "company" or f["dept"] == u["dept"]


def _path(f):
    """루트부터 f 까지의 폴더 목록(깊이 제한 때문에 반복 횟수도 제한된다)."""
    chain, cur, guard = [f], f, 0
    while cur["parent_id"] and guard < MAX_DEPTH + 2:
        cur = _folder(cur["parent_id"])
        if not cur:
            break
        chain.append(cur)
        guard += 1
    return list(reversed(chain))


def _load_folder(folder_id):
    f = _folder(folder_id)
    if not f:
        abort(404)
    if not _visible(f):
        return forbidden("folder_out_of_scope", resource=f"lib_folder:{folder_id}")
    return f


def _is_error(x):
    return isinstance(x, tuple)


@bp.get("")
@login_required
def library_home():
    u = g.user
    rows = db.query_all(
        "SELECT f.id, f.name, f.scope, f.dept, f.created_at, "
        "(SELECT COUNT(*) FROM lib_folders c WHERE c.parent_id = f.id) AS subs, "
        "(SELECT COUNT(DISTINCT x.orig_name) FROM lib_files x WHERE x.folder_id = f.id AND x.deleted_at IS NULL) AS files "
        "FROM lib_folders f WHERE f.parent_id IS NULL AND (%s = 'admin' OR f.scope = 'company' OR f.dept = %s) "
        "ORDER BY f.scope, f.dept, f.name LIMIT 200", (u["role"], u["dept"]))
    return render_template("lib_home.html", rows=rows, can_create=can(u, "folder.create"), depts=_depts(), is_admin=u["role"] == "admin")


def _depts():
    return [r["dept"] for r in db.query_all("SELECT DISTINCT dept FROM users ORDER BY dept LIMIT 100")]


@bp.get("/folders/<int:folder_id>")
@login_required
def folder_view(folder_id, error=None, status=200):
    f = _load_folder(folder_id)
    if _is_error(f):
        return f
    subs = db.query_all(
        "SELECT c.id, c.name, (SELECT COUNT(*) FROM lib_folders d WHERE d.parent_id = c.id) AS subs, "
        "(SELECT COUNT(DISTINCT x.orig_name) FROM lib_files x WHERE x.folder_id = c.id AND x.deleted_at IS NULL) AS files "
        "FROM lib_folders c WHERE c.parent_id = %s ORDER BY c.name LIMIT 200", (folder_id,))
    files = db.query_all(
        "SELECT x.id, x.orig_name, x.version, x.size, x.note, x.created_at, x.uploaded_by, u.display_name AS uploader, "
        "x.version = (SELECT MAX(y.version) FROM lib_files y WHERE y.folder_id = x.folder_id AND y.orig_name = x.orig_name "
        "AND y.deleted_at IS NULL) AS latest FROM lib_files x JOIN users u ON u.id = x.uploaded_by "
        "WHERE x.folder_id = %s AND x.deleted_at IS NULL ORDER BY x.orig_name, x.version DESC LIMIT 500", (folder_id,))
    path = _path(f)
    return render_template("lib_folder.html", f=f, path=path, subs=subs, files=files, error=error,
                           can_create=can(g.user, "folder.create") and len(path) < MAX_DEPTH, me=g.user["id"],
                           is_admin=g.user["role"] == "admin"), status


@bp.post("/folders/new")
@permission_required("folder.create")
def folder_new():
    u = g.user
    raw_parent = request.form.get("parent_id", "")
    parent = None
    if raw_parent:
        try:
            pid = validators.positive_int(raw_parent, "parent")
        except ValueError:
            abort(400)
        parent = _folder(pid)
        if not parent:
            abort(404)
        if not _visible(parent):
            return forbidden("folder_out_of_scope", resource=f"lib_folder:{pid}")
        if len(_path(parent)) >= MAX_DEPTH:
            log_event("input_rejected", "DENY", "depth", field="lib_folder")
            return conflict(MESSAGES["depth"])
        scope, dept = parent["scope"], parent["dept"]
    else:
        scope = request.form.get("scope", "dept")
        dept = request.form.get("dept", u["dept"]) if u["role"] == "admin" else u["dept"]
        if scope not in ("company", "dept") or (scope == "company" and u["role"] != "admin"):
            return forbidden("folder_scope", resource="lib_folder:new")
        if scope == "dept" and dept not in _depts():
            log_event("input_rejected", "DENY", "dept", field="lib_folder")
            return conflict(MESSAGES["scope"])
        if scope == "company":
            dept = None
    try:
        name = validators.text(request.form.get("name", ""), "name", 1, 50)
    except ValueError:
        log_event("input_rejected", "DENY", "name", field="lib_folder")
        return conflict(MESSAGES["name"])
    if db.query_one("SELECT id FROM lib_folders WHERE parent_key = %s AND name = %s", (parent["id"] if parent else 0, name)):
        return conflict(MESSAGES["dup"])
    try:
        new_id = db.execute("INSERT INTO lib_folders(parent_id, name, scope, dept, created_by) VALUES(%s, %s, %s, %s, %s)",
                            (parent["id"] if parent else None, name, scope, dept, u["id"]))
    except pymysql.err.IntegrityError:
        return conflict(MESSAGES["dup"])
    log_event("lib_folder_created", "INFO", "ok", folder_id=new_id, scope=scope)
    return redirect(url_for("library.folder_view", folder_id=new_id), 303)


@bp.post("/folders/<int:folder_id>/upload")
@login_required
def file_upload(folder_id):
    f = db.query_one("SELECT id, scope, dept FROM lib_folders WHERE id = %s", (folder_id,))
    if not f:
        abort(404)
    if not _visible(f):
        return forbidden("folder_out_of_scope", resource=f"lib_folder:{folder_id}")
    try:
        note = validators.text(request.form.get("note", ""), "note", 0, 200)
    except ValueError:
        log_event("input_rejected", "DENY", "note", field="lib_file")
        return folder_view(folder_id, error=MESSAGES["note"], status=400)
    uploaded = [x for x in request.files.getlist("file") if x and x.filename]
    if not uploaded:
        log_event("input_rejected", "DENY", "no_file", field="lib_file")
        return folder_view(folder_id, error=MESSAGES["no_file"], status=400)
    directory = Path(current_app.config["UPLOAD_DIR"])
    saved = []
    try:
        for storage in uploaded:                                  # 오래 걸리는 디스크 쓰기는 잠그기 전에 끝낸다
            saved.append(uploads.save_attachment(directory, storage))
        # 버전 번호가 겹치지 않게 폴더 단위 이름 잠금(GET_LOCK, 연결이 닫힐 때 풀린다)으로 한 줄로 세운다. 앱 계정에는 폴더 행을 잠글 권한(UPDATE)이 없다.
        # 잠그기 전에 읽기 트랜잭션을 끝내(쓴 것이 아직 없다) 잠금을 얻은 뒤의 읽기가 먼저 끝난 다른 업로드의 버전을 보게 한다.
        db.commit()
        if db.query_one("SELECT GET_LOCK(%s, 15) AS ok", (f"nexus_lib_folder_{folder_id}",))["ok"] != 1:
            uploads.remove_saved(directory, saved)
            log_event("lib_upload_busy", "WARN", "lock_timeout", folder_id=folder_id)
            return conflict("같은 폴더에 올리는 요청이 많아 처리하지 못했습니다. 잠시 후 다시 시도하세요.")
        for meta in saved:
            version = db.query_one("SELECT COALESCE(MAX(version), 0) + 1 AS v FROM lib_files WHERE folder_id = %s AND orig_name = %s",
                                   (folder_id, meta["orig_name"]))["v"]
            db.execute("INSERT INTO lib_files(folder_id, version, stored_name, orig_name, mime, size, sha256, note, uploaded_by) "
                       "VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                       (folder_id, version, meta["stored_name"], meta["orig_name"], meta["mime"], meta["size"], meta["sha256"], note, g.user["id"]))
            db.commit()                                           # 다음 파일의 버전 계산이 방금 넣은 행을 보게 한다(잠금은 연결이 닫힐 때까지 유지)
    except BaseException:
        uploads.remove_saved(directory, saved)
        raise
    log_event("lib_file_uploaded", "INFO", "ok", folder_id=folder_id, files=len(saved), bytes=sum(m["size"] for m in saved))
    return redirect(url_for("library.folder_view", folder_id=folder_id), 303)


def _file_with_folder(file_id):
    return db.query_one("SELECT x.id, x.folder_id, x.stored_name, x.orig_name, x.mime, x.uploaded_by, x.deleted_at, f.scope, f.dept "
                        "FROM lib_files x JOIN lib_folders f ON f.id = x.folder_id WHERE x.id = %s", (file_id,))


@bp.get("/files/<int:file_id>")
@login_required
def file_download(file_id):
    x = _file_with_folder(file_id)
    directory = Path(current_app.config["UPLOAD_DIR"])
    if not x or x["deleted_at"] or not (directory / x["stored_name"]).is_file():
        abort(404)
    if not _visible(x):
        return forbidden("folder_out_of_scope", resource=f"lib_file:{file_id}")
    log_event("lib_file_download", "INFO", "ok", file_id=file_id)
    return uploads.send_stored(directory, x["stored_name"], as_attachment=True, download_name=x["orig_name"], mimetype=x["mime"])


@bp.post("/files/<int:file_id>/delete")
@login_required
def file_delete(file_id):
    x = _file_with_folder(file_id)
    if not x:
        abort(404)
    if not _visible(x):
        return forbidden("folder_out_of_scope", resource=f"lib_file:{file_id}")
    if x["uploaded_by"] != g.user["id"] and g.user["role"] != "admin":
        return forbidden("not_owner", resource=f"lib_file:{file_id}")
    n = db.execute_rowcount("UPDATE lib_files SET deleted_at = %s, deleted_by = %s WHERE id = %s AND deleted_at IS NULL",
                            (now_kst(), g.user["id"], file_id))
    if not n:
        return conflict("이미 삭제된 파일입니다.")
    log_event("lib_file_deleted", "INFO", "ok", file_id=file_id)
    return redirect(url_for("library.folder_view", folder_id=x["folder_id"]), 303)


# =====================================================================================
# 주소록
# =====================================================================================
@bp.get("/contacts")
@login_required
def contact_list():
    tab = request.args.get("tab", "company")
    q = request.args.get("q", "").strip()
    if tab not in dict(CONTACT_TABS):
        abort(400)
    error, status, pattern = None, 200, "%"
    if q:
        try:
            pattern = _pattern(q)
        except ValueError:
            log_event("input_rejected", "DENY", "query", field="q")
            q, error, status = "", "검색어는 1~50자로 입력하세요(제어문자 사용 불가).", 400
    if tab == "company":
        rows = db.query_all("SELECT e.name, e.dept, e.title, e.ext, e.emp_no FROM employees e "
                            "WHERE e.name LIKE %s OR e.dept LIKE %s OR e.title LIKE %s OR e.ext LIKE %s ORDER BY e.dept, e.name LIMIT 300",
                            (pattern, pattern, pattern, pattern))
    else:
        rows = db.query_all(
            "SELECT c.id, c.owner_id, c.name, c.company, c.title, c.phone, c.email, c.memo, c.shared, u.display_name AS owner "
            "FROM contacts c JOIN users u ON u.id = c.owner_id WHERE c.deleted_at IS NULL "
            "AND ((%s = 'shared' AND c.shared = 1) OR (%s = 'mine' AND c.owner_id = %s)) "
            "AND (c.name LIKE %s OR c.company LIKE %s OR c.title LIKE %s OR c.phone LIKE %s OR c.email LIKE %s) "
            "ORDER BY c.name LIMIT 300", (tab, tab, g.user["id"], pattern, pattern, pattern, pattern, pattern))
    return render_template("lib_contacts.html", rows=rows, tab=tab, tabs=CONTACT_TABS, q=q, error=error, me=g.user["id"],
                           is_admin=g.user["role"] == "admin"), status


def _contact_form(values=None, error=None, status=200):
    return render_template("lib_contact_form.html", values=values or {}, error=error), status


@bp.route("/contacts/new", methods=["GET", "POST"])
@login_required
def contact_new():
    if request.method == "GET":
        return _contact_form({"shared": request.args.get("shared", "")})
    f = request.form
    values = {k: f.get(k, "") for k in ("name", "company", "title", "phone", "email", "memo")}
    values["shared"] = "1" if f.get("shared") else ""
    try:
        try:
            name = validators.text(values["name"], "name", 1, 60)
        except ValueError:
            raise ValueError("c_name")
        try:
            company = validators.text(values["company"], "company", 0, 80)
            title = validators.text(values["title"], "title", 0, 60)
            memo = validators.text(values["memo"], "memo", 0, 200)
        except ValueError:
            raise ValueError("c_field")
        phone, email = values["phone"].strip(), values["email"].strip()
        if not PHONE_RE.match(phone):
            raise ValueError("c_phone")
        if email and (len(email) > 120 or not EMAIL_RE.match(email)):
            raise ValueError("c_email")
        if not phone and not email:
            raise ValueError("c_contact")
    except ValueError as exc:
        key = str(exc) if str(exc) in MESSAGES else "c_name"
        log_event("input_rejected", "DENY", key, field="contact")
        return _contact_form(values, MESSAGES[key], 400)
    cid = db.execute("INSERT INTO contacts(owner_id, name, company, title, phone, email, memo, shared) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)",
                     (g.user["id"], name, company, title, phone, email, memo, 1 if values["shared"] else 0))
    log_event("contact_created", "INFO", "ok", contact_id=cid, shared=bool(values["shared"]))
    return redirect(url_for("library.contact_list", tab="shared" if values["shared"] else "mine"), 303)


@bp.post("/contacts/<int:contact_id>/delete")
@login_required
def contact_delete(contact_id):
    c = db.query_one("SELECT id, owner_id, shared, deleted_at FROM contacts WHERE id = %s FOR UPDATE", (contact_id,))
    if not c or c["deleted_at"]:
        abort(404)
    if c["owner_id"] != g.user["id"] and g.user["role"] != "admin":
        return forbidden("not_owner", resource=f"contact:{contact_id}")
    db.execute_rowcount("UPDATE contacts SET deleted_at = %s WHERE id = %s AND deleted_at IS NULL", (now_kst(), contact_id))
    log_event("contact_deleted", "INFO", "ok", contact_id=contact_id)
    return redirect(url_for("library.contact_list", tab="shared" if c["shared"] else "mine"), 303)


# =====================================================================================
# 문서 검색
# =====================================================================================
SEARCH_LIMIT = 15


@bp.get("/search")
@login_required
def search():
    q = request.args.get("q", "").strip()
    if not q:
        return render_template("lib_search.html", q="", groups=None, error=None, total=0)
    try:
        p = _pattern(q)
    except ValueError:
        log_event("input_rejected", "DENY", "query", field="search")
        return render_template("lib_search.html", q="", groups=None, error="검색어는 1~50자로 입력하세요(제어문자 사용 불가).", total=0), 400
    u = g.user
    groups = []

    def add(label, rows, build):
        if rows:
            groups.append({"label": label, "items": [build(r) for r in rows]})

    add("문서함", db.query_all("SELECT id, title FROM documents WHERE title LIKE %s OR body LIKE %s ORDER BY id DESC LIMIT %s",
                              (p, p, SEARCH_LIMIT)),
        lambda r: {"title": r["title"], "href": url_for("portal.document", doc_id=r["id"]), "meta": ""})
    add("게시판", db.query_all("SELECT id, board, title FROM posts WHERE title LIKE %s OR body LIKE %s ORDER BY id DESC LIMIT %s",
                              (p, p, SEARCH_LIMIT)),
        lambda r: {"title": r["title"], "href": url_for("portal.post_view", post_id=r["id"]),
                   "meta": "공지사항" if r["board"] == "notice" else "자유게시판"})
    add("전자결재", db.query_all(
        "SELECT a.id, a.title, a.doc_type, a.created_at FROM approvals a WHERE (a.requester_id = %s OR %s = 'admin' "
        "OR EXISTS(SELECT 1 FROM approval_steps s WHERE s.approval_id = a.id AND s.approver_id = %s) "
        "OR EXISTS(SELECT 1 FROM approval_cc c WHERE c.approval_id = a.id AND c.user_id = %s)) "
        "AND (a.title LIKE %s OR a.body LIKE %s) ORDER BY a.id DESC LIMIT %s", (u["id"], u["role"], u["id"], u["id"], p, p, SEARCH_LIMIT)),
        lambda r: {"title": r["title"], "href": url_for("approvals.approval_view", approval_id=r["id"]),
                   "meta": DOC_TYPES.get(r["doc_type"], DOC_TYPES["general"])[0]})
    add("자료실", db.query_all(
        "SELECT x.id, x.orig_name, x.version, f.name AS folder FROM lib_files x JOIN lib_folders f ON f.id = x.folder_id "
        "WHERE x.deleted_at IS NULL AND (%s = 'admin' OR f.scope = 'company' OR f.dept = %s) "
        "AND (x.orig_name LIKE %s OR x.note LIKE %s) ORDER BY x.id DESC LIMIT %s", (u["role"], u["dept"], p, p, SEARCH_LIMIT)),
        lambda r: {"title": r["orig_name"], "href": url_for("library.file_download", file_id=r["id"]), "meta": f"{r['folder']} · v{r['version']}"})
    add("양식 모음", db.query_all("SELECT id, title, category FROM lib_forms WHERE deleted_at IS NULL AND (title LIKE %s OR description LIKE %s) "
                               "ORDER BY id DESC LIMIT %s", (p, p, SEARCH_LIMIT)),
        lambda r: {"title": r["title"], "href": url_for("library.form_download", form_id=r["id"]), "meta": r["category"]})
    add("내 업무", db.query_all("SELECT id, title FROM tasks WHERE (assignee_id = %s OR creator_id = %s) AND (title LIKE %s OR description LIKE %s) "
                              "ORDER BY id DESC LIMIT %s", (u["id"], u["id"], p, p, SEARCH_LIMIT)),
        lambda r: {"title": r["title"], "href": url_for("work.task_detail", task_id=r["id"]), "meta": ""})
    add("주소록", db.query_all(
        "SELECT name, company, phone, email, shared FROM contacts WHERE deleted_at IS NULL AND (shared = 1 OR owner_id = %s) "
        "AND (name LIKE %s OR company LIKE %s OR phone LIKE %s OR email LIKE %s) ORDER BY name LIMIT %s",
        (u["id"], p, p, p, p, SEARCH_LIMIT)),
        lambda r: {"title": r["name"], "href": url_for("library.contact_list", tab="shared" if r["shared"] else "mine", q=q),
                   "meta": " · ".join(x for x in (r["company"], r["phone"], r["email"]) if x)})
    total = sum(len(g_["items"]) for g_ in groups)
    log_event("search", "INFO", "ok", length=len(q), hits=total)
    return render_template("lib_search.html", q=q, groups=groups, error=None, total=total)


# =====================================================================================
# 양식 서식 모음
# =====================================================================================
@bp.get("/forms")
@login_required
def form_list():
    rows = db.query_all("SELECT f.id, f.title, f.category, f.description, f.orig_name, f.size, f.created_at, u.display_name AS uploader "
                        "FROM lib_forms f JOIN users u ON u.id = f.uploaded_by WHERE f.deleted_at IS NULL ORDER BY f.category, f.title LIMIT 300")
    shortcuts = [(DOC_TYPES[k][0], url_for("approvals.approval_new", type=k)) for k in FORM_TYPES]
    return render_template("lib_forms.html", rows=rows, shortcuts=shortcuts, categories=FORM_CATEGORIES, is_admin=g.user["role"] == "admin")


@bp.post("/forms/upload")
@role_required("admin")
def form_upload():
    f = request.form
    try:
        try:
            title = validators.text(f.get("title", ""), "title", 1, 100)
        except ValueError:
            raise ValueError("f_title")
        category = f.get("category", "")
        if category not in FORM_CATEGORIES:
            raise ValueError("f_category")
        try:
            desc = validators.text(f.get("description", ""), "description", 0, 200)
        except ValueError:
            raise ValueError("f_desc")
        storage = request.files.get("file")
        if not storage or not storage.filename:
            raise ValueError("no_file")
    except ValueError as exc:
        key = str(exc) if str(exc) in MESSAGES else "f_title"
        log_event("input_rejected", "DENY", key, field="lib_form")
        return conflict(MESSAGES[key])
    directory = Path(current_app.config["UPLOAD_DIR"])
    meta = uploads.save_attachment(directory, storage)
    try:
        form_id = db.execute("INSERT INTO lib_forms(title, category, description, stored_name, orig_name, mime, size, sha256, uploaded_by) "
                             "VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                             (title, category, desc, meta["stored_name"], meta["orig_name"], meta["mime"], meta["size"], meta["sha256"], g.user["id"]))
    except BaseException:
        uploads.remove_saved(directory, [meta])
        raise
    log_event("lib_form_uploaded", "INFO", "ok", form_id=form_id, bytes=meta["size"])
    return redirect(url_for("library.form_list"), 303)


@bp.get("/forms/<int:form_id>/download")
@login_required
def form_download(form_id):
    x = db.query_one("SELECT stored_name, orig_name, mime FROM lib_forms WHERE id = %s AND deleted_at IS NULL", (form_id,))
    directory = Path(current_app.config["UPLOAD_DIR"])
    if not x or not (directory / x["stored_name"]).is_file():
        abort(404)
    log_event("lib_form_download", "INFO", "ok", form_id=form_id)
    return uploads.send_stored(directory, x["stored_name"], as_attachment=True, download_name=x["orig_name"], mimetype=x["mime"])


@bp.post("/forms/<int:form_id>/delete")
@role_required("admin")
def form_delete(form_id):
    n = db.execute_rowcount("UPDATE lib_forms SET deleted_at = %s WHERE id = %s AND deleted_at IS NULL", (now_kst(), form_id))
    if not n:
        abort(404)
    log_event("lib_form_deleted", "INFO", "ok", form_id=form_id)
    return redirect(url_for("library.form_list"), 303)
