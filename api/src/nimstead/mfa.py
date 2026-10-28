"""TOTP (RFC 6238, SHA-1, 6 digits, 30 s) and one-time recovery codes for password sign-ins. Stdlib only."""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP, DIGITS, WINDOW = 30, 6, 1  # accept the previous and next step too: phone clocks drift


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def code(secret_b32: str, step: int, digits: int = DIGITS, digest=hashlib.sha1) -> str:
    mac = hmac.new(base64.b32decode(secret_b32), struct.pack(">Q", step), digest).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def verify(secret_b32: str, given: str, last_step: int, at: float | None = None) -> int | None:
    """The step the code matched if it's valid and newer than last_step (so a code works once), else None."""
    given = (given or "").strip().replace(" ", "")
    if len(given) != DIGITS or not given.isdigit():
        return None
    now = int((time.time() if at is None else at) // STEP)
    for step in range(now - WINDOW, now + WINDOW + 1):
        if step > last_step and hmac.compare_digest(code(secret_b32, step), given):
            return step
    return None


def uri(secret_b32: str, email: str) -> str:
    return f"otpauth://totp/Nimstead:{quote(email)}?secret={secret_b32}&issuer=Nimstead"


def recovery_codes(n: int = 10) -> list[str]:
    return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(n)]  # 64 bits each: sha256 is enough at rest


def code_hash(c: str) -> str:
    return hashlib.sha256(c.strip().lower().encode()).hexdigest()
