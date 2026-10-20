"""메신저 설치 파일 서명(자동 업데이트용).

포털은 HTTP 라서 같은 망의 공격자가 업데이트 파일을 바꿔치기할 수 있다. 그래서 설치 파일마다 Ed25519 로 서명하고,
메신저는 내장한 공개키로 서명을 확인한 뒤에만 실행한다. 포털은 서명 파일(<설치 파일>.sig)이 있고 해시가 맞을 때만 업데이트를 알린다.

  python scripts/sign_messenger_setup.py --init-key        # 처음 한 번: 키 만들기(개인키는 저장소 밖), 공개키 출력
  python scripts/sign_messenger_setup.py --public          # 공개키 다시 보기(메신저 lib/update_verifier.dart 에 넣는 값)
  python scripts/sign_messenger_setup.py [설치 파일 경로]   # 서명(기본: .env MESSENGER_SETUP_PATH 또는 바탕화면의 설치 파일)

개인키는 %USERPROFILE%\\.nexus\\messenger_update_ed25519.pem 에 두고 화면·문서·저장소에 옮기지 않는다(--key 로 바꿀 수 있다).
서명 대상 문장: "nexus-messenger-update-v1:<sha256>:<크기>" (메신저 update_verifier.dart 와 같아야 한다)."""
import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE_DIR = Path(__file__).resolve().parents[1]
FORMAT = "nexus-messenger-update-v1"
DEFAULT_KEY = Path(os.environ.get("USERPROFILE", Path.home())) / ".nexus" / "messenger_update_ed25519.pem"


def message(sha256_hex: str, size: int) -> bytes:
    return f"{FORMAT}:{sha256_hex}:{size}".encode()


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def load_key(path: Path) -> Ed25519PrivateKey:
    if not path.is_file():
        sys.exit(f"개인키가 없습니다: {path} (먼저 --init-key)")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("Ed25519 키가 아닙니다.")
    return key


def init_key(path: Path) -> None:
    if path.exists():
        sys.exit(f"이미 키가 있습니다: {path} (덮어쓰지 않는다. 바꾸려면 직접 옮긴 뒤 다시 실행하고 메신저의 공개키도 바꾼다)")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    print(f"개인키를 만들었습니다: {path}")
    print(f"공개키(메신저에 넣을 값): {public_b64(key)}")


def setup_path(arg: str | None) -> Path:
    if arg:
        return Path(arg)
    try:
        from dotenv import dotenv_values
        env = dotenv_values(BASE_DIR / ".env")
    except ImportError:
        env = {}
    return Path(env.get("MESSENGER_SETUP_PATH") or BASE_DIR.parent / "NEXUS_Messenger_Setup.exe")


def sign(path: Path, key: Ed25519PrivateKey) -> Path:
    if not path.is_file():
        sys.exit(f"설치 파일이 없습니다: {path}")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    sig = key.sign(message(digest, len(data)))
    out = path.with_name(path.name + ".sig")
    out.write_text(json.dumps({"format": FORMAT, "sha256": digest, "size": len(data),
                               "signature": base64.b64encode(sig).decode()}, indent=2), encoding="utf-8")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("setup", nargs="?", help="서명할 설치 파일")
    ap.add_argument("--key", type=Path, default=DEFAULT_KEY)
    ap.add_argument("--init-key", action="store_true")
    ap.add_argument("--public", action="store_true")
    a = ap.parse_args()
    if a.init_key:
        return init_key(a.key)
    key = load_key(a.key)
    if a.public:
        print(public_b64(key))
        return
    out = sign(setup_path(a.setup), key)
    info = json.loads(out.read_text(encoding="utf-8"))
    print(f"서명했습니다: {out.name} (sha256 {info['sha256'][:16]}…, {info['size']:,} bytes)")


if __name__ == "__main__":
    main()
