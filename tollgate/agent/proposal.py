"""Proposals: what the agent may ASK for. A proposal moves no money by itself.

Model output is untrusted, so `build_proposal` never raises on bad input. It
returns either a valid `Proposal` or a list of problems (the caller turns any
problem into BLOCK). Each kind accepts an exact set of argument names: a
missing or extra argument (for example a smuggled "stamp") is a problem.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from tollgate.gate.models import MAX_AMOUNT_CENTS

MAX_REASON_LEN = 200
MAX_SOURCE_TEXT_LEN = 2000
MAX_ID_LEN = 64
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:@\-]+$")


class ProposalKind(str, Enum):
    PAYMENT = "payment"
    REFUND = "refund"
    DISPUTE_RESPONSE = "dispute_response"        # SIMULATED
    SUBSCRIPTION_CHANGE = "subscription_change"  # SIMULATED


DISPUTE_ACTIONS = frozenset({"accept", "contest"})
SUBSCRIPTION_ACTIONS = frozenset({"change_plan", "cancel"})

# Exact argument names per kind: target field, reference field, extra fields.
_ARGS: dict[ProposalKind, frozenset[str]] = {
    ProposalKind.PAYMENT: frozenset({"amount_cents", "recipient", "reason"}),
    ProposalKind.REFUND: frozenset({"amount_cents", "customer", "refund_of",
                                    "order_total_cents", "reason"}),
    ProposalKind.DISPUTE_RESPONSE: frozenset({"amount_cents", "customer", "dispute_id",
                                              "action", "reason"}),
    ProposalKind.SUBSCRIPTION_CHANGE: frozenset({"amount_cents", "customer",
                                                 "subscription_id", "action", "reason"}),
}
_REF_FIELD = {ProposalKind.REFUND: "refund_of", ProposalKind.DISPUTE_RESPONSE: "dispute_id",
              ProposalKind.SUBSCRIPTION_CHANGE: "subscription_id"}
_ACTIONS = {ProposalKind.DISPUTE_RESPONSE: DISPUTE_ACTIONS,
            ProposalKind.SUBSCRIPTION_CHANGE: SUBSCRIPTION_ACTIONS}


@dataclass(frozen=True)
class Proposal:
    id: str
    kind: ProposalKind
    amount_cents: int
    target: str                       # recipient (payment) or customer (others)
    reason: str
    source_message_id: str
    source_text: str                  # untrusted customer text, kept as data only
    ref: str | None = None            # refund_of / dispute_id / subscription_id
    action: str | None = None         # dispute or subscription action
    order_total_cents: int | None = None


def is_cents(value: Any) -> bool:
    """A positive whole number of cents no larger than the Gate's maximum."""
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return 0 < value <= MAX_AMOUNT_CENTS


def is_safe_id(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_ID_LEN and bool(_SAFE_ID.match(value))


def _is_reason(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value.strip()) and len(value) <= MAX_REASON_LEN



def _arg_problems(kind: ProposalKind, args: Any) -> list[str]:
    if not isinstance(args, dict) or not all(isinstance(k, str) for k in args):
        return ["arguments must be a dict with text keys"]
    expected = _ARGS[kind]
    problems = [f"unexpected argument: {k}" for k in sorted(set(args) - expected)]
    problems += [f"missing argument: {k}" for k in sorted(expected - set(args))]
    if problems:
        return problems
    if not is_cents(args["amount_cents"]):
        problems.append("bad amount_cents")
    target_field = "recipient" if kind is ProposalKind.PAYMENT else "customer"
    if not is_safe_id(args[target_field]):
        problems.append(f"bad {target_field}")
    if not _is_reason(args["reason"]):
        problems.append("bad reason")
    if kind in _REF_FIELD and not is_safe_id(args[_REF_FIELD[kind]]):
        problems.append(f"bad {_REF_FIELD[kind]}")
    if kind in _ACTIONS and args["action"] not in _ACTIONS[kind]:
        problems.append("bad action")
    if kind is ProposalKind.REFUND and not is_cents(args["order_total_cents"]):
        problems.append("bad order_total_cents")
    return problems


def build_proposal(kind: Any, args: Any, *, proposal_id: Any, source_message_id: Any,
                   source_text: Any) -> Proposal | list[str]:
    """Return a Proposal, or a list of problems. Never raises."""
    try:
        if not isinstance(kind, ProposalKind):
            return ["bad kind"]
        problems = _arg_problems(kind, args)
        if not is_safe_id(proposal_id):
            problems.append("bad proposal id")
        if not is_safe_id(source_message_id):
            problems.append("bad source message id")
        if not isinstance(source_text, str):
            problems.append("bad source text")
        if problems:
            return problems
        target_field = "recipient" if kind is ProposalKind.PAYMENT else "customer"
        return Proposal(
            id=proposal_id, kind=kind, amount_cents=args["amount_cents"],
            target=args[target_field], reason=args["reason"].strip(),
            source_message_id=source_message_id,
            source_text=source_text[:MAX_SOURCE_TEXT_LEN],
            ref=args.get(_REF_FIELD.get(kind, ""), None),
            action=args.get("action"),
            order_total_cents=args.get("order_total_cents"),
        )
    except Exception:  # fail closed
        return ["internal error while building proposal"]
