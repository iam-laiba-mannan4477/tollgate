"""Data shapes for the Gate: a proposed Request and the Gate's Decision.

Requests are built from untrusted input, so the dataclass does NOT validate on
construction (that could crash a caller). Instead `validate_request` returns a
list of problems, and the rules turn any problem into BLOCK.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

MAX_AMOUNT_CENTS = 10_000_000  # $100,000: anything above is treated as bad input
MAX_ID_LEN = 64
MAX_RECIPIENT_LEN = 128
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9_.:@\-]+$")


class RequestType(str, Enum):
    PAY = "pay"
    REFUND = "refund"


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class Request:
    """A payment or refund an agent PROPOSES. It moves no money by itself."""

    id: Any
    type: Any
    amount_cents: Any
    recipient: Any
    via_agent: Any
    created_at: Any
    order_total_cents: Any = None


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    trip_breaker: bool = False  # set by the velocity rule; acted on in Day 3


def _is_cents(value: Any) -> bool:
    """A positive int (bools excluded) no larger than MAX_AMOUNT_CENTS."""
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= MAX_AMOUNT_CENTS
    )


def _is_safe_text(value: Any, max_len: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= max_len and bool(_SAFE_TEXT.match(value))


def validate_request(req: Any) -> list[str]:
    """Return a list of problems. Empty list means the request is well formed."""
    if not isinstance(req, Request):
        return ["not a Request"]
    problems: list[str] = []
    if not _is_safe_text(req.id, MAX_ID_LEN):
        problems.append("bad id")
    if req.type not in (RequestType.PAY, RequestType.REFUND, "pay", "refund"):
        problems.append("bad type")
    if not _is_cents(req.amount_cents):
        problems.append("bad amount_cents")
    if not _is_safe_text(req.recipient, MAX_RECIPIENT_LEN):
        problems.append("bad recipient")
    if not isinstance(req.via_agent, bool):
        problems.append("bad via_agent")
    if not isinstance(req.created_at, (int, float)) or isinstance(req.created_at, bool):
        problems.append("bad created_at")
    if req.type in (RequestType.REFUND, "refund") and not _is_cents(req.order_total_cents):
        problems.append("bad order_total_cents")
    return problems
