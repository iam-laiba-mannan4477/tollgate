"""Approval tiers and abuse limits. All values are config; the defaults await owner sign-off.

Amounts are integer cents. Times are seconds on the injected (monotonic) clock.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, replace

# Fields where a LOWER number is stricter. Raising any of them is loosening.
LOOSEN_IF_RAISED = ("delay_over_cents", "new_recipient_delay_over_cents", "daily_cap_cents",
                    "max_failed_codes", "approvals_per_hour")
# Fields where a HIGHER number is stricter. Lowering any of them is loosening.
LOOSEN_IF_LOWERED = ("cooling_off_seconds", "settings_cooling_off_seconds")


@dataclass(frozen=True)
class ApprovalPolicy:
    """Every approval of a HELD request needs the approver session AND a fresh code.
    These values add delays and limits on top of that."""

    delay_over_cents: int = 1_000_000             # over $10,000: cooling-off delay too
    new_recipient_delay_over_cents: int = 100_000  # new recipient AND over $1,000: delay
    cooling_off_seconds: int = 900                # 15 minutes
    daily_cap_cents: int = 2_500_000              # $25,000 approved per rolling 24 h
    cap_window_seconds: int = 86_400
    max_failed_codes: int = 3                     # then lock approvals + trip breaker
    approvals_per_hour: int = 10
    settings_cooling_off_seconds: int = 900       # wait before a settings change applies
    grant_lifetime_seconds: int = 60              # a released grant must be used quickly

    def __post_init__(self) -> None:
        for f in fields(self):
            value = getattr(self, f.name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{f.name} must be a positive int")

    def is_loosening(self, field_name: str, new_value: int) -> bool:
        """True if setting `field_name` to `new_value` weakens protection. Unknown -> True."""
        old = getattr(self, field_name, None)
        if not isinstance(old, int) or not isinstance(new_value, int):
            return True
        if field_name in LOOSEN_IF_RAISED:
            return new_value > old
        if field_name in LOOSEN_IF_LOWERED:
            return new_value < old
        return new_value != old       # any other field: treat every change as loosening

    def with_value(self, field_name: str, new_value: int) -> "ApprovalPolicy":
        if field_name not in {f.name for f in fields(self)}:
            raise ValueError("unknown policy field")
        return replace(self, **{field_name: new_value})
