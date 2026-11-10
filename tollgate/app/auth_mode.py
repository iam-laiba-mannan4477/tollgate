"""TOLLGATE_AUTH_MODE = demo (default) | real, and the session signing key.

- demo: DEMO banner on every page, a documented demo account, the one-time code shown on
  screen, and only the fixed FAKE mock TOTP secret. Nothing to scan.
- real: no default account, setup by QR code, code never shown, fake secret refused, and
  TOLLGATE_SESSION_KEY is required.

Anything else is an error and the app does not start (fail closed). Error messages name
variables, never their values.
"""
from __future__ import annotations

import os
import secrets
from enum import Enum
from typing import Mapping

from tollgate.config import ConfigError

MIN_SESSION_KEY_CHARS = 32


class AuthMode(str, Enum):
    DEMO = "demo"
    REAL = "real"


def read_auth_mode(env: Mapping[str, str] | None = None) -> AuthMode:
    source = os.environ if env is None else env
    raw = source.get("TOLLGATE_AUTH_MODE", AuthMode.DEMO.value).strip().lower()
    try:
        return AuthMode(raw)
    except ValueError:
        raise ConfigError("TOLLGATE_AUTH_MODE must be 'demo' or 'real'") from None


def read_session_key(mode: AuthMode, env: Mapping[str, str] | None = None) -> bytes:
    """Real mode: TOLLGATE_SESSION_KEY (at least 32 characters) or refuse to start.
    Demo mode: a fresh random key each start, so demo sessions end on restart."""
    if mode is AuthMode.DEMO:
        return secrets.token_bytes(32)
    source = os.environ if env is None else env
    value = source.get("TOLLGATE_SESSION_KEY", "").strip()
    if len(value) < MIN_SESSION_KEY_CHARS:
        raise ConfigError(f"real mode needs TOLLGATE_SESSION_KEY with at least "
                          f"{MIN_SESSION_KEY_CHARS} characters")
    return value.encode("utf-8")
