"""TOTP second factor (RFC 6238, HMAC-SHA1, 30-second steps, 6 digits). Standard library only.

- A code is accepted for the current step or one step either side (clock drift).
- Replay protection: each accepted step number is remembered, and a code from that
  step or any earlier step is refused afterwards. So every code works once.
- Secrets are bytes held in memory. Nothing here logs, prints or puts them in errors.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import threading

STEP_SECONDS = 30
DIGITS = 6
DRIFT_STEPS = 1
SECRET_BYTES = 20

# MOCK MODE ONLY. A fixed, publicly known, FAKE secret so tests and demos are repeatable.
# Never valid in sandbox mode (the registry refuses it there).
MOCK_TOTP_SECRET_B32 = "FAKEMOCKSECRET23"


def new_secret_b32() -> str:
    """A fresh random secret, base32 encoded (what an authenticator app scans)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii")


def decode_secret(secret_b32: str) -> bytes:
    """Decode a base32 secret. Raises ValueError on bad input (message has no value)."""
    if not isinstance(secret_b32, str) or not secret_b32:
        raise ValueError("secret must be base32 text")
    text = secret_b32.strip().replace(" ", "").upper()
    try:
        raw = base64.b32decode(text + "=" * (-len(text) % 8))
    except Exception:
        raise ValueError("secret is not valid base32") from None
    if len(raw) < 10:
        raise ValueError("secret is too short")
    return raw


def hotp(secret: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 HOTP value for one counter."""
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def step_of(now: float) -> int:
    return int(now // STEP_SECONDS)


def code_at(secret: bytes, now: float, digits: int = DIGITS) -> str:
    """The code an authenticator shows at wall-clock time `now`."""
    return hotp(secret, step_of(now), digits)


def _is_code_text(code: object) -> bool:
    return isinstance(code, str) and len(code) == DIGITS and code.isascii() and code.isdigit()


class TotpChecker:
    """Checks codes for one secret and refuses any step already used (or older)."""

    def __init__(self, secret: bytes) -> None:
        self.__secret = secret
        self._last_used_step = -1
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "TotpChecker(secret=<hidden>)"

    def check(self, code: object, now: float) -> bool:
        """True once per step for a correct code. Fails closed on any odd input."""
        if not _is_code_text(code):
            return False
        current = step_of(now)
        with self._lock:
            matched = None
            for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
                if step >= 0 and hmac.compare_digest(hotp(self.__secret, step), code):
                    matched = step
            if matched is None or matched <= self._last_used_step:
                return False
            self._last_used_step = matched
            return True
