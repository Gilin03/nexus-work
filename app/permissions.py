"""직급·팀·고정 계정에 따른 권한 판정(한 곳에서 정의하고, 서버 검사와 '권한 현황' 화면이 같은 규칙을 쓴다).

- 역할(role: employee/manager/admin)은 접근 범위의 큰 틀이고, 직급(사원<대리<과장<팀장<관리자)은 그 안에서의 세부 단계다.
  직급은 인사카드(employees.title)에서 읽되 역할의 범위로 잘라 쓴다: employee 는 사원~과장, manager 는 팀장, admin 은 관리자.
  (인사카드가 없는 계정은 역할의 가장 낮은 직급으로 본다.) 직급을 올려도 역할이 바뀌지 않으므로 결재자 자격 같은 역할 규칙은 그대로다.
- 팀(부서) 권한은 그 팀 소속 + 직급 조건이 함께 맞아야 한다: 보안관제팀=보안 대시보드, 경영지원·재무팀 과장 이상=재무 보고·전사 급여, 경영지원·인사팀 과장 이상=전사 인사카드.
- 최고관리자 고정 계정(users.pinned): admin(시스템관리자)·hongjh 두 계정만 항상 admin 이다(DB 트리거가 보장, 앱도 변경·잠금·초기화·삭제를 막는다).
  사용자 삭제는 이 두 계정만 할 수 있다(users.delete). 보안관제팀의 다른 계정은 일반 관리자처럼 역할을 바꿀 수 있다(사용자 결정 2026-10-20).
- 새 권한을 더할 때는 PERMS 에 한 줄을 추가하고, 서버의 해당 경로에 permission_required/can 을 건 뒤, tests/test_permissions.py 에서 실제 응답과 맞는지 확인한다."""
from functools import wraps

from flask import g, redirect, render_template, url_for

from .security import log_event

RANKS = ("사원", "대리", "과장", "팀장", "관리자")
SENIOR = 3                                   # 과장 이상(직급 번호 3)
ROLE_RANKS = {"employee": (1, 3), "manager": (4, 4), "admin": (5, 5)}
DEFAULT_TITLE = {"employee": "사원", "manager": "팀장", "admin": "관리자"}
ALLOWED_TITLES = {"employee": ("사원", "대리", "과장"), "manager": ("팀장",), "admin": ("관리자",)}
SECURITY_TEAM = "보안관제팀"
FINANCE_TEAMS = ("경영지원팀", "재무팀")
HR_TEAMS = ("경영지원팀", "인사팀")
SYSTEM_ADMIN = "admin"                       # 시스템관리자 계정 아이디
PINNED_USERS = ("admin", "hongjh")           # 최고관리자 고정 계정(DB 트리거의 값과 같다)


def rank_of(role, title):
    """직급 번호(1=사원 … 5=관리자). 인사카드 직급이 없거나 역할 범위 밖이면 역할이 허용하는 범위로 자른다."""
    lo, hi = ROLE_RANKS.get(role, (1, 1))
    n = RANKS.index(title) + 1 if title in RANKS else lo
    return max(lo, min(hi, n))


def subject(user):
    """권한 판정에 쓰는 값만 뽑는다. 로그인한 사용자(g.user)나 화면용 가상 사용자 모두 같은 모양이다."""
    role = user.get("role", "employee")
    return {"role": role, "dept": user.get("dept", ""), "rank": rank_of(role, user.get("title")),
            "pinned": bool(user.get("pinned")), "username": user.get("username", "")}


def _manager_up(s):
    return s["role"] in ("manager", "admin")


# (키, 이름, 규칙, 팀·직급 조건 설명). 규칙은 subject() 결과를 받아 True/False 를 돌려준다.
PERMS = [
    ("doc.confidential", "기밀 문서함 열람", lambda s: _manager_up(s), "팀장 이상(역할 manager·admin)"),
    ("finance.view", "재무 보고 열람", lambda s: _manager_up(s) or (s["dept"] in FINANCE_TEAMS and s["rank"] >= SENIOR),
     "팀장 이상, 또는 경영지원·재무팀 과장 이상"),
    ("payroll.all", "전사 급여 조회", lambda s: s["role"] == "admin" or (s["dept"] in FINANCE_TEAMS and s["rank"] >= SENIOR),
     "관리자, 또는 경영지원·재무팀 과장 이상"),
    ("hr.cards.all", "전사 인사카드 조회", lambda s: s["role"] == "admin" or (s["dept"] in HR_TEAMS and s["rank"] >= SENIOR),
     "관리자, 또는 경영지원·인사팀 과장 이상"),
    ("notice.write", "공지사항 글쓰기", lambda s: _manager_up(s) or s["rank"] >= SENIOR, "과장 이상"),
    ("project.create", "프로젝트 만들기", lambda s: _manager_up(s) or s["rank"] >= SENIOR, "과장 이상"),
    ("folder.create", "자료실 폴더 만들기", lambda s: _manager_up(s) or s["rank"] >= SENIOR, "과장 이상(최상위 폴더는 자기 부서 공개로 고정)"),
    ("users.manage", "사용자 관리·역할·직급 변경", lambda s: s["role"] == "admin", "관리자(역할 admin)"),
    ("users.delete", "사용자 삭제·복구(재입사)", lambda s: s["role"] == "admin" and s["pinned"], "최고관리자(admin·hongjh)만"),
    ("security.dashboard", "보안 대시보드·감사 로그·내보내기",
     lambda s: s["role"] == "admin" and (s["pinned"] or s["dept"] == SECURITY_TEAM), "보안관제팀 소속 관리자 또는 최고관리자(admin·hongjh)만"),
]
PERMS_BY_KEY = {p[0]: p for p in PERMS}


def can(user, key):
    return bool(user) and PERMS_BY_KEY[key][2](subject(user))


def can_context():
    """템플릿에서 `can('finance.view')` 로 쓴다(현재 로그인한 사용자 기준)."""
    return {"can": lambda key: can(g.get("user"), key)}


def permission_required(key):
    """로그인과 권한을 함께 검사하는 데코레이터. 권한이 없으면 403 과 authz_deny 이벤트."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not g.user:
                log_event("authz_deny", "DENY", "not_logged_in")
                return redirect(url_for("auth.login"), 303)
            if not can(g.user, key):
                log_event("authz_deny", "DENY", "insufficient_role", required=key)   # 사유 값은 기존 탐지 규칙과 같게 둔다
                return render_template("error.html", code=403, message="접근 권한이 없습니다."), 403
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ---- '권한 현황' 화면용 ----
def matrix(dept="일반팀"):
    """직급(사원~관리자)별로 각 권한이 허용되는지: [(이름, 조건 설명, [허용 여부 5개])]. 가상 사용자를 만들어 실제 규칙으로 판정한다."""
    out = []
    for key, label, rule, note in PERMS:
        cells = []
        for n, title in enumerate(RANKS, start=1):
            role = "employee" if n <= 3 else ("manager" if n == 4 else "admin")
            cells.append(bool(rule(subject({"role": role, "title": title, "dept": dept}))))
        out.append((label, note, cells))
    return out
