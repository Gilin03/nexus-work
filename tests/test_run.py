"""run.py: 실행 주소는 .env(APP_HOST·APP_PORT)를 따르되 기본은 루프백이고, 외부에 열 때 공개된 예시 비밀번호를 경고한다."""
from dotenv import dotenv_values

from run import BASE_DIR, SEED_PASSWORD_KEYS, exposure_warnings, parse_args

EXAMPLE = dotenv_values(BASE_DIR / ".env.example")


def test_default_bind_is_loopback_5070():
    args = parse_args([], environ={})
    assert (args.host, args.port) == ("127.0.0.1", 5070)


def test_bind_follows_env_and_command_line_wins():
    env = {"APP_HOST": "0.0.0.0", "APP_PORT": "5071"}
    args = parse_args([], environ=env)
    assert (args.host, args.port) == ("0.0.0.0", 5071)
    args = parse_args(["--host", "127.0.0.1", "--port", "5070"], environ=env)
    assert (args.host, args.port) == ("127.0.0.1", 5070)


def test_example_env_keeps_loopback_default():
    assert EXAMPLE["APP_HOST"] == "127.0.0.1" and EXAMPLE["APP_PORT"] == "5070"   # 저장소 기본값으로는 외부에 열리지 않는다


def test_exposure_warns_only_for_public_example_passwords_on_non_loopback():
    example_pw = {k: EXAMPLE[k] for k in SEED_PASSWORD_KEYS}
    assert exposure_warnings("127.0.0.1", environ=example_pw, example=EXAMPLE) == []      # 내 PC만이면 경고 없음
    warnings = exposure_warnings("0.0.0.0", environ=example_pw, example=EXAMPLE)
    assert len(warnings) == len(SEED_PASSWORD_KEYS) and all(k in " ".join(warnings) for k in SEED_PASSWORD_KEYS)
    changed = {k: v + "-changed" for k, v in example_pw.items()}
    assert exposure_warnings("0.0.0.0", environ=changed, example=EXAMPLE) == []           # 바꿨으면 경고 없음
