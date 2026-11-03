"""Mode switch: TOLLGATE_MODE=mock (no keys) or sandbox (Braintree sandbox).

Fail closed: an unknown mode is an error, never a silent fallback to sandbox.
Production is not a valid mode at all.
"""
from __future__ import annotations

import os
from enum import Enum

REQUIRED_SANDBOX_VARS = (
    "BRAINTREE_MERCHANT_ID",
    "BRAINTREE_PUBLIC_KEY",
    "BRAINTREE_PRIVATE_KEY",
)


class Mode(str, Enum):
    MOCK = "mock"
    SANDBOX = "sandbox"


class ConfigError(Exception):
    """Configuration is missing or invalid. Messages never contain key values."""


def get_mode() -> Mode:
    """Read TOLLGATE_MODE. Unset means mock (the safe default)."""
    raw = os.environ.get("TOLLGATE_MODE", Mode.MOCK.value).strip().lower()
    try:
        return Mode(raw)
    except ValueError:
        raise ConfigError(
            f"TOLLGATE_MODE must be 'mock' or 'sandbox' (got {raw!r})"
        ) from None


def missing_sandbox_vars() -> list[str]:
    """Names (never values) of required sandbox variables that are empty or unset."""
    return [name for name in REQUIRED_SANDBOX_VARS if not os.environ.get(name)]
