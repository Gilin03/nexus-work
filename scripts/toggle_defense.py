"""DEFENSE_MODE 전환 스크립트. .env 파일을 안전하게 수정하고 현재 상태를 표시한다."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"


def set_mode(mode: str):
    mode = mode.lower()
    if mode not in ("on", "off"):
        print("사용법: python scripts/toggle_defense.py [on|off|status]")
        return

    if not ENV_FILE.exists():
        ENV_FILE.write_text(f"DEFENSE_MODE={mode}\n", encoding="utf-8")
        print(f"[NEXUS] .env 파일 생성 및 DEFENSE_MODE={mode} 설정 완료.")
        return

    text = ENV_FILE.read_text(encoding="utf-8")
    if re.search(r"^DEFENSE_MODE=.*$", text, re.M):
        new_text = re.sub(r"^DEFENSE_MODE=.*$", f"DEFENSE_MODE={mode}", text, flags=re.M)
    else:
        new_text = text.rstrip() + f"\nDEFENSE_MODE={mode}\n"

    ENV_FILE.write_text(new_text, encoding="utf-8")
    status_str = "방어 활성화 (정상 방어 모드 - 비인가 도구 호출 거부, R3 경보 발동, 출력 마스킹)" if mode == "on" else "방어 비활성화 (공격 시연 모드 - 기밀 문서 유출 허용, 마스킹 해제)"
    print("==================================================")
    print(f" [NEXUS AI 보안 게이트웨이 상태 변경]")
    print(f" DEFENSE_MODE = {mode.upper()}")
    print(f" 상태: {status_str}")
    print(" (포털 서버를 재시작하지 않아도 실행 중인 환경에 즉시 반영됩니다)")
    print("==================================================")


def show_status():
    if not ENV_FILE.exists():
        print("DEFENSE_MODE = ON (기본값, 방어 활성화)")
        return
    text = ENV_FILE.read_text(encoding="utf-8")
    m = re.search(r"^DEFENSE_MODE=(.*)$", text, re.M)
    val = m.group(1).strip().lower() if m else "on (기본값)"
    print(f"현재 DEFENSE_MODE: {val.upper()}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ("on", "off"):
            set_mode(arg)
        elif arg == "status":
            show_status()
        else:
            print("사용법: python scripts/toggle_defense.py [on|off|status]")
    else:
        show_status()
