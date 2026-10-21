"""프로필 사진: 사용자가 자기 사진을 올리고 바꾸고 지운다.
- 허용 형식은 png·jpg 뿐이고 확장자와 내용(매직바이트)이 모두 맞아야 한다(uploads.inspect_upload). 크기 상한은 10MB 이다(security.ENDPOINT_LIMITS, 메신저와 같다).
- 파일은 웹루트 밖 업로드 폴더의 avatars/ 에 무작위 이름으로 둔다. 사용자당 한 장이며 바꾸면 이전 파일을 지운다.
- 사진은 요청자가 자기 것만 올리고 지울 수 있다(대상은 항상 g.user). 보는 것은 로그인한 모두에게 열려 있다(상단바·목록용).
- 내려줄 때는 이미지로만 열리게 한다: 형식은 DB 에 저장한 값, nosniff, 아무것도 불러오지 못하는 CSP(+sandbox), 같은 출처만 허용."""
from pathlib import Path

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from . import db, uploads
from .auth import login_required
from .security import log_event

bp = Blueprint("profile", __name__)

PHOTO_EXTS = {"png", "jpg"}
PHOTO_MESSAGES = {
    "extension_not_allowed": "png 또는 jpg 그림만 올릴 수 있습니다.",
    "content_mismatch": "파일 내용이 확장자와 일치하지 않습니다.",
    "empty_upload": "파일을 선택하세요.",
}


def photo_dir() -> Path:
    return Path(current_app.config["UPLOAD_DIR"]) / "avatars"


def _form(error=None, notice=None, status=200):
    has_photo = bool(db.query_one("SELECT user_id FROM profile_photos WHERE user_id = %s", (g.user["id"],)))
    return render_template("profile.html", has_photo=has_photo, error=error, notice=notice), status


@bp.get("/account/photo")
@login_required
def photo_form():
    return _form(notice="저장했습니다." if request.args.get("saved") else "삭제했습니다." if request.args.get("removed") else None)


@bp.post("/account/photo")
@login_required
def photo_upload():
    upload = request.files.get("photo")
    if not upload or not upload.filename:
        return _form(error=PHOTO_MESSAGES["empty_upload"], status=400)
    data = upload.read()                                  # 본문 상한(security.ENDPOINT_LIMITS)을 넘으면 그 전에 413 이 난다
    try:
        ext, mime, _display, digest = uploads.inspect_upload(upload.filename, data)
        if ext not in PHOTO_EXTS:
            raise ValueError("extension_not_allowed")
    except ValueError as exc:
        log_event("upload_reject", "BLOCK", str(exc), filename=upload.filename[:100], size=len(data), target="profile_photo")
        return _form(error=PHOTO_MESSAGES.get(str(exc), "올릴 수 없는 파일입니다."), status=400)

    old = db.query_one("SELECT stored_name FROM profile_photos WHERE user_id = %s FOR UPDATE", (g.user["id"],))
    stored = uploads.store(photo_dir(), data)
    db.execute("DELETE FROM profile_photos WHERE user_id = %s", (g.user["id"],))
    db.execute("INSERT INTO profile_photos(user_id, stored_name, mime, size, sha256) VALUES(%s, %s, %s, %s, %s)",
               (g.user["id"], stored, mime, len(data), digest))
    db.commit()
    if old:
        (photo_dir() / old["stored_name"]).unlink(missing_ok=True)
    log_event("profile_photo_changed", "INFO", "ok", size=len(data), replaced=bool(old))
    return redirect(url_for("profile.photo_form", saved=1), 303)


@bp.post("/account/photo/delete")
@login_required
def photo_delete():
    old = db.query_one("SELECT stored_name FROM profile_photos WHERE user_id = %s FOR UPDATE", (g.user["id"],))
    if old:
        db.execute("DELETE FROM profile_photos WHERE user_id = %s", (g.user["id"],))
        db.commit()
        (photo_dir() / old["stored_name"]).unlink(missing_ok=True)
        log_event("profile_photo_removed", "INFO", "ok")
    return redirect(url_for("profile.photo_form", removed=1), 303)


@bp.get("/users/<int:user_id>/photo")
@login_required
def photo_view(user_id):
    row = db.query_one("SELECT stored_name, mime FROM profile_photos WHERE user_id = %s", (user_id,))
    if not row or not (photo_dir() / row["stored_name"]).is_file():
        abort(404)
    resp = uploads.send_stored(photo_dir(), row["stored_name"], as_attachment=False, mimetype=row["mime"])
    resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return resp
