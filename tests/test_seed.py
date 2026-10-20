"""seed.py 의 시나리오 데이터: 기밀 문서마다 식별 문구, M&A_PLAN 에만 실습용 토큰, FLAG 는 문서에 없음. DB 없이 실행된다."""
import importlib.util
import re
from pathlib import Path

import pytest
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("seed", ROOT / "scripts" / "seed.py")
seed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(seed)

TOKEN = "nxapi_" + "T" * 32
CANARY = re.compile(r"NXC-[A-Z]{3}-[0-9A-Z]{4}")


def test_each_confidential_document_has_its_own_canary():
    docs = seed.confidential_documents(TOKEN)
    found = [CANARY.findall(body) for _, body in docs]
    assert all(len(f) == 1 for f in found)                                  # 문서마다 정확히 하나
    assert len({f[0] for f in found}) == len(docs)                          # 문서끼리 겹치지 않는다
    assert {f[0] for f in found} == {seed.CANARY_MNA, seed.CANARY_EXEC}


def test_lab_token_is_only_in_mna_plan_and_flag_is_not_in_documents():
    docs = dict(seed.confidential_documents(TOKEN))
    assert docs["M&A_PLAN"].count(TOKEN) == 1
    assert all(TOKEN not in body for title, body in docs.items() if title != "M&A_PLAN")
    assert all("FLAG{" not in body for body in docs.values())             # FLAG 는 내부 API 응답(5단계)에서만 나온다


@pytest.mark.parametrize("value", ["", "nxapi_short", "change-me-lab-token-but-long-enough"])
def test_lab_token_rejects_missing_short_or_placeholder(value):
    with pytest.raises(SystemExit):
        seed.lab_token({seed.LAB_TOKEN_ENV: value})


def test_example_env_lab_token_is_a_placeholder_seed_refuses():
    example = dotenv_values(ROOT / ".env.example")[seed.LAB_TOKEN_ENV]
    with pytest.raises(SystemExit):
        seed.lab_token({seed.LAB_TOKEN_ENV: example})
    assert seed.lab_token({seed.LAB_TOKEN_ENV: TOKEN}) == TOKEN
