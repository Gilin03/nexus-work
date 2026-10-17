"""모든 SQL 호출의 첫 인자가 상수 문자열인지 AST 로 검사한다(문자열 결합·f-string·format 금지)."""
import ast
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1] / "app"
SQL_CALLS = {"execute", "executemany", "execute_rowcount", "query_all", "query_one"}


def violations(app_dir=APP_DIR):
    bad = []
    for path in app_dir.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name))):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            if name not in SQL_CALLS or not node.args:
                continue
            first = node.args[0]
            # app/db.py 의 래퍼 안에서 매개변수 sql 을 그대로 넘기는 호출만 예외(호출자 쪽에서 검사됨)
            if path.name == "db.py" and isinstance(first, ast.Name) and first.id == "sql":
                continue
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                bad.append(f"{path.name}:{node.lineno} {name}() 첫 인자가 상수 문자열이 아님")
    return bad


def test_sql_is_always_constant_string():
    assert violations() == []


def test_checker_detects_bad_patterns(tmp_path):
    (tmp_path / "bad.py").write_text(
        'def f(cur, x):\n'
        '    cur.execute(f"SELECT {x}")\n'
        '    cur.execute("A" + x)\n'
        '    cur.execute("A %s" % x)\n'
        '    cur.execute("A {}".format(x))\n'
        '    query_all(x)\n', encoding="utf-8")
    assert len(violations(tmp_path)) == 5
