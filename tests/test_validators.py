import pytest

from app import validators as v


@pytest.mark.parametrize("name", ["kim", "park_01", "a" * 32])
def test_username_ok(name):
    assert v.username(name) == name


@pytest.mark.parametrize("name", ["", "Kim", "1kim", "k", "a" * 33, "kim-x", "kim x", "kim\n", "김민수", "kim'--"])
def test_username_rejected(name):
    with pytest.raises(ValueError):
        v.username(name)


@pytest.mark.parametrize("pw", ["Abcdef-123456", "correct-Horse-9-battery"])
def test_password_ok(pw):
    assert v.password_policy(pw, "kim") == pw


@pytest.mark.parametrize("pw,reason", [
    ("Short-1a", "password_length"),
    ("A" * 129, "password_length"),
    ("alllowercaseonly", "password_complexity"),
    ("Kim-Secret-2026!", "password_contains_username"),
])
def test_password_rejected(pw, reason):
    with pytest.raises(ValueError, match=reason):
        v.password_policy(pw, "kim")


def test_text_trims_and_limits():
    assert v.text("  안녕  ", "title") == "안녕"
    with pytest.raises(ValueError):
        v.text("   ", "title")
    with pytest.raises(ValueError):
        v.text("a" * 201, "title")
    with pytest.raises(ValueError):
        v.text("line1\nline2", "title")
    with pytest.raises(ValueError):
        v.text("tab\there", "title")  # 한 줄 필드는 탭도 거부
    assert v.text("tab\there", "body", multiline=True) == "tab\there"  # 여러 줄 필드(본문)는 허용
    assert v.text("line1\nline2", "body", multiline=True, max_len=50) == "line1\nline2"
    with pytest.raises(ValueError):
        v.text("null\x00byte", "body", multiline=True)


@pytest.mark.parametrize("value", ["1", 7, "2147483647"])
def test_positive_int_ok(value):
    assert v.positive_int(value) == int(value)


@pytest.mark.parametrize("value", ["0", "-1", " 1", "1 ", "1.5", "abc", "", None, True, "٣", "2147483648", "1; DROP TABLE users"])
def test_positive_int_rejected(value):
    with pytest.raises(ValueError):
        v.positive_int(value)


def test_like_pattern_escapes_wildcards():
    assert v.like_pattern("100%_x") == "%100\\%\\_x%"
    assert v.like_pattern("a\\b") == "%a\\\\b%"
    with pytest.raises(ValueError):
        v.like_pattern("")
