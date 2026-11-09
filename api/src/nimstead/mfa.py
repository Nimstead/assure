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
    """Return a random 160-bit secret encoded as a base32 string for a TOTP authenticator."""
    return base64.b32encode(secrets.token_bytes(20)).decode()


def code(secret_b32: str, step: int, digits: int = DIGITS, digest=hashlib.sha1) -> str:
    """Return the zero-padded OTP for base32 secret_b32 and integer counter step.

    digits controls the output width; digest is the HMAC hash constructor (SHA-1 by default).
    Invalid base32 raises binascii.Error; an out-of-range counter raises struct.error.
    Parameters are trusted internal values; digits is not range-validated.

    The example uses a fixed public test secret.

    >>> code('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1)
    '287082'"""
    mac = hmac.new(base64.b32decode(secret_b32), struct.pack(">Q", step), digest).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def verify(secret_b32: str, given: str, last_step: int, at: float | None = None) -> int | None:
    """Return the matching 30-second counter, or None for an invalid or replayed code.

    secret_b32 is the enrolled base32 secret; given is a six-digit code. last_step is the
    last accepted counter. at is Unix time in seconds, or None for the current clock.
    Check the current counter and one on either side; persist the returned counter to prevent replay.
    Malformed stored secrets propagate decoding errors."""
    given = (given or "").strip().replace(" ", "")
    if len(given) != DIGITS or not given.isdigit():
        return None
    now = int((time.time() if at is None else at) // STEP)
    for step in range(now - WINDOW, now + WINDOW + 1):
        if step > last_step and hmac.compare_digest(code(secret_b32, step), given):
            return step
    return None


def uri(secret_b32: str, email: str) -> str:
    """Return the otpauth enrolment URI for base32 secret_b32 and the account email string."""
    return f"otpauth://totp/Nimstead:{quote(email)}?secret={secret_b32}&issuer=Nimstead"


def recovery_codes(n: int = 10) -> list[str]:
    """Return n random recovery-code strings, or [] when n is nonpositive.

    Each code has 64 random bits. The caller stores hashes and consumes codes after use;
    this function does not persist or invalidate them."""
    return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(n)]  # 64 bits each: sha256 is enough at rest


def code_hash(c: str) -> str:
    """Return the SHA-256 hex digest of recovery-code string c after trimming and lowercasing."""
    return hashlib.sha256(c.strip().lower().encode()).hexdigest()
