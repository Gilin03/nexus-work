"""create_team_admins.py: 아이디가 규칙에 맞고 기존 시드 아이디와 겹치지 않는다. 초기 비밀번호 1234 는 변경 화면 정책에는 걸린다(그래서 직접 바꾸게 된다)."""
import importlib.util
from pathlib import Path

import pytest

from app import validators

ROOT = Path(__file__).resolve().parents[1]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


team = _load("create_team_admins", "scripts/create_team_admins.py")
seed = _load("seed", "scripts/seed.py")


def test_usernames_are_valid_unique_and_do_not_collide_with_seed():
    names = [u for u, _, _ in team.TEAM]
    assert len(names) == len(set(names)) == 4
    assert all(validators.USERNAME_RE.fullmatch(n) for n in names)
    assert not set(names) & {u[0] for u in seed.USERS}


def test_initial_password_cannot_be_chosen_through_the_change_form():
    assert team.INITIAL_PASSWORD == "1234"
    with pytest.raises(ValueError):
        validators.password_policy(team.INITIAL_PASSWORD, "hongjh")   # 변경 화면은 약한 값을 받지 않는다
