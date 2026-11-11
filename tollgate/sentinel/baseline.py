"""The safe baseline: today's approved defaults. Nothing here changes any default.

For each setting, `STRICTER` says which direction is stricter: "lower" or "higher".
A value on the looser side of the baseline is "weak".
"""
from __future__ import annotations

from tollgate.approval.accounts import SESSION_IDLE_SECONDS, SESSION_LIFETIME_SECONDS
from tollgate.approval.policy import ApprovalPolicy
from tollgate.gate.rules import GateConfig

GATE = GateConfig()
POLICY = ApprovalPolicy()
SESSION = {"lifetime_seconds": SESSION_LIFETIME_SECONDS, "idle_seconds": SESSION_IDLE_SECONDS}

STRICTER: dict[str, dict[str, str]] = {
    "gate": {
        "auto_limit_cents": "lower",
        "velocity_max_payments": "lower",
        "velocity_window_seconds": "higher",
        "stamp_lifetime_seconds": "lower",
    },
    "policy": {
        "delay_over_cents": "lower",
        "new_recipient_delay_over_cents": "lower",
        "cooling_off_seconds": "higher",
        "daily_cap_cents": "lower",
        "cap_window_seconds": "higher",
        "max_failed_codes": "lower",
        "approvals_per_hour": "lower",
        "settings_cooling_off_seconds": "higher",
        "grant_lifetime_seconds": "lower",
    },
    "session": {"lifetime_seconds": "lower", "idle_seconds": "lower"},
}


def baseline_value(area: str, field: str) -> int:
    if area == "gate":
        return int(getattr(GATE, field))
    if area == "policy":
        return int(getattr(POLICY, field))
    return int(SESSION[field])


def is_weak(area: str, field: str, value: object) -> bool:
    """True if `value` is looser than the baseline. Unknown or odd input -> weak."""
    direction = STRICTER.get(area, {}).get(field)
    if direction is None or not isinstance(value, (int, float)) or isinstance(value, bool):
        return True
    base = baseline_value(area, field)
    return value > base if direction == "lower" else value < base
