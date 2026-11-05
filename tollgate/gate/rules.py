"""The Gate's decision rules: plain code, no AI model, no I/O.

`evaluate` follows the gate-rules order exactly and fails closed: any
exception or malformed input yields BLOCK, never ALLOW.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tollgate.gate.models import Decision, Request, RequestType, Verdict, validate_request

STAMP_LIFETIME_MAX_SECONDS = 300  # hard ceiling from CLAUDE.md rule 4


@dataclass(frozen=True)
class GateConfig:
    auto_limit_cents: int = 100_000          # $1,000
    velocity_max_payments: int = 2           # more than this in the window -> BLOCK
    velocity_window_seconds: int = 600       # 10 minutes
    stamp_lifetime_seconds: int = 300        # 5 minutes

    def __post_init__(self) -> None:
        for name in ("auto_limit_cents", "velocity_max_payments",
                     "velocity_window_seconds", "stamp_lifetime_seconds"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive int")
        if self.stamp_lifetime_seconds > STAMP_LIFETIME_MAX_SECONDS:
            raise ValueError("stamp_lifetime_seconds may not exceed 300")


@dataclass
class GateState:
    """What the rules need to know about the world. Read-only to `evaluate`."""

    now: float
    breaker_open: bool = False
    known_recipients: frozenset[str] = field(default_factory=frozenset)
    recent_payments: tuple[tuple[str, float], ...] = ()  # (recipient, time)


def evaluate(request: Any, state: Any, config: Any) -> Decision:
    """Return ALLOW, HOLD or BLOCK for a proposed request. Never raises."""
    try:
        return _evaluate(request, state, config)
    except Exception:  # fail closed on anything unexpected
        return Decision(Verdict.BLOCK, "internal error: failing closed")


def _evaluate(req: Request, state: GateState, config: GateConfig) -> Decision:
    if not isinstance(config, GateConfig) or not isinstance(state, GateState):
        return Decision(Verdict.BLOCK, "invalid gate state or config")
    problems = validate_request(req)
    if problems:
        return Decision(Verdict.BLOCK, "invalid request: " + ", ".join(problems))
    if state.breaker_open is not False:
        return Decision(Verdict.BLOCK, "circuit breaker open")
    if req.via_agent is not True:
        return Decision(Verdict.BLOCK, "no approval path: direct call")
    if _is_refund(req) and req.amount_cents > req.order_total_cents:
        return Decision(Verdict.BLOCK, "refund exceeds order total")
    if _recent_count(req.recipient, state, config) >= config.velocity_max_payments:
        return Decision(Verdict.BLOCK, "velocity: too many payments to recipient",
                        trip_breaker=True)
    if req.amount_cents > config.auto_limit_cents:
        return Decision(Verdict.HOLD, "over auto limit: needs a person")
    if req.recipient not in state.known_recipients:
        return Decision(Verdict.HOLD, "new recipient: needs a person")
    return Decision(Verdict.ALLOW, "within limits, known recipient")


def _is_refund(req: Request) -> bool:
    return req.type in (RequestType.REFUND, "refund")


def _recent_count(recipient: str, state: GateState, config: GateConfig) -> int:
    """Payments to `recipient` within the window (future-dated ones count too)."""
    cutoff = state.now - config.velocity_window_seconds
    return sum(1 for who, at in state.recent_payments if who == recipient and at >= cutoff)
