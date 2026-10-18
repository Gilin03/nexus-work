"""정적 점검: 위험한 코드 패턴, 실수로 공개된 경로, GitHub 에 올라갈 파일에 남은 비밀값. DB 없이 실행된다."""
import re
import subprocess
from pathlib import Path

import pytest
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"

BANNED = [
    (r"\beval\(", "eval"),
    (r"\bexec\(", "exec"),
    (r"os\.system|os\.popen|\bsubprocess\b", "외부 명령 실행"),
    (r"\bpickle\b|marshal\.loads|yaml\.load\(", "안전하지 않은 역직렬화"),
    (r"render_template_string", "템플릿 문자열 렌더링(SSTI)"),
    (r"verify\s*=\s*False", "TLS 검증 끄기"),
    (r"debug\s*=\s*True|\bapp\.run\(", "디버그·개발 서버 직접 실행"),
    (r"\|\s*safe\b|\bMarkup\(|autoescape\s+false|escape\s*=\s*False", "이스케이프 우회"),
    (r"redirect\(\s*request\.", "요청 값으로 리다이렉트(오픈 리다이렉트)"),
    (r"\b(md5|sha1)\(", "약한 해시"),
    (r"\brandom\.(random|randint|choice)\(", "보안용 난수에 random 사용"),
]


def test_app_code_has_no_banned_patterns():
    found = []
    for path in list(APP.rglob("*.py")) + list(APP.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        for pattern, label in BANNED:
            for m in re.finditer(pattern, text):
                line = text.count("\n", 0, m.start()) + 1
                found.append(f"{path.relative_to(ROOT)}:{line} {label}")
    assert found == []


def test_banned_pattern_checker_detects_each_kind():
    samples = ["eval(x)", "exec(x)", "os.system('x')", "subprocess.run", "pickle.loads", "render_template_string(x)",
               "requests.get(u, verify=False)", "debug=True", "{{ x|safe }}", "Markup(x)", "redirect(request.args['n'])",
               "hashlib.md5(x)", "random.randint(1, 2)"]
    for sample in samples:
        assert any(re.search(p, sample) for p, _ in BANNED), sample


# ---------- 실수로 공개된 경로가 없는가 ----------
def test_no_route_is_accidentally_public(app, client):
    # /api/v1/* 는 쿠키 세션이 아니라 Authorization 토큰으로 인증하는 별도 체계라
    # (메신저 앱용) CSRF 단계가 아예 적용되지 않는다(security.check_csrf 의 경로 예외).
    # 그래서 로그인 없이 보내면 403(CSRF)이 아니라 401(토큰 없음/자격증명 틀림)이 맞다.
    public = set()
    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        path = re.sub(r"<[^>]+>", "1", rule.rule)
        is_token_api = path.startswith("/api/v1/")
        for method in rule.methods - {"HEAD", "OPTIONS"}:
            r = client.open(path, method=method)
            if is_token_api:
                assert r.status_code == 401, (method, path, r.status_code)
                continue
            if method == "GET":
                if r.status_code == 200:
                    public.add(path)
                else:
                    assert r.status_code == 303 and "/login" in r.headers["Location"], (method, path, r.status_code)
            else:
                assert r.status_code == 403, (method, path, r.status_code)   # 로그인 없이 CSRF 단계에서 막힌다
    assert public == {"/login", "/healthz"}                                    # 비로그인으로 열리는 화면은 이 둘뿐이다


# ---------- GitHub 에 올라갈 파일 ----------
def _git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True)


@pytest.fixture(scope="module")
def publishable():
    r = _git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if r.returncode != 0:
        pytest.skip("git 저장소가 아니다")
    return [ROOT / p for p in r.stdout.decode("utf-8").split("\0") if p]


@pytest.mark.parametrize("path", [".env", "logs/security.jsonl", "instance/uploads/x", "_private/note.md",
                                  ".venv/Lib/x.py", "app/__pycache__/x.pyc", ".claude/launch.json"])
def test_sensitive_paths_are_git_ignored(path):
    if _git("rev-parse", "--is-inside-work-tree").returncode != 0:
        pytest.skip("git 저장소가 아니다")
    assert _git("check-ignore", "-q", path).returncode == 0, f"{path} 가 .gitignore 에 없다"


def _text(path):
    try:
        if path.stat().st_size > 2_000_000:
            return ""
        return path.read_bytes().decode("utf-8", errors="ignore")
    except OSError:
        return ""


def test_real_secret_values_never_appear_in_publishable_files(publishable):
    env, example = dotenv_values(ROOT / ".env"), dotenv_values(ROOT / ".env.example")
    secrets = {v for k, v in env.items() if v and len(v) >= 8 and re.search(r"PASSWORD|SECRET|KEY|TOKEN", k, re.I)
               and v != example.get(k)}                       # .env.example 과 같은 값(공개된 시험용 값)은 제외
    if not env:
        pytest.skip(".env 없음")
    leaks = [str(p.relative_to(ROOT)) for p in publishable if p.name != ".env" and any(s in _text(p) for s in secrets)]
    assert leaks == []


KEY_PATTERNS = [r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{30,}", r"xox[baprs]-[A-Za-z0-9-]{10,}",
                r"""(?i)\b(password|passwd|secret_key|api[_-]?key|token)\b\s*=\s*["'][^"'\s]{8,}["']"""]


def test_no_hardcoded_credentials_in_code_and_config(publishable):
    hits = []
    for p in publishable:
        rel = p.relative_to(ROOT).as_posix()
        if rel.startswith("tests/") or rel == ".env.example" or p.suffix in (".png", ".jpg", ".ico"):
            continue                                           # 시험용 값은 tests/ 와 예시 파일에만 둔다
        text = _text(p)
        for pat in KEY_PATTERNS:
            if re.search(pat, text):
                hits.append(f"{rel}: {pat[:30]}")
    assert hits == []


def test_no_key_or_dump_files_would_be_published(publishable):
    bad = [p.name for p in publishable if p.suffix.lower() in (".pem", ".key", ".p12", ".pfx", ".sqlite", ".db", ".dump")
           or (p.name.startswith(".env") and p.name != ".env.example")]
    assert bad == []
