"""SIMULATED dispute and subscription desk. No Braintree calls, no real data.

The Braintree sandbox may not give us real dispute data, so disputes and
subscriptions live in this in-memory store. They are clearly SIMULATED, but they
still go through the same Gate rules as money:

- every action is turned into a Gate request (amount = money at stake,
  recipient = customer) and checked with `evaluate` against the desk's own state,
- ALLOW applies the change; HOLD needs a one-time stamp from a person; BLOCK refuses,
- the amount must match the record (no inflated dispute payouts or fake prices
  for a cancel), the customer must own the record, and a resolved dispute or a
  cancelled subscription cannot be changed again,
- a velocity violation trips the desk's breaker; only a named person resets it,
- every attempt writes one audit event.
"""
from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from tollgate.gate.audit import AuditLog
from tollgate.gate.breaker import CircuitBreaker
from tollgate.gate.models import Decision, Request, Verdict, validate_request
from tollgate.gate.rules import GateConfig, GateState, evaluate
from tollgate.gate.stamps import SpendResult, StampError, StampStore

SIMULATED = True


@dataclass
class SimDispute:
    customer: str
    amount_cents: int
    status: str = "open"            # open -> accepted | contested


@dataclass
class SimSubscription:
    customer: str
    price_cents: int
    status: str = "active"          # active -> cancelled


@dataclass(frozen=True)
class SimAction:
    kind: str                       # "dispute_response" | "subscription_change"
    action: str
    ref: str


@dataclass(frozen=True)
class DeskResult:
    applied: bool
    verdict: Verdict
    reason: str


class SimulatedDesk:
    def __init__(self, audit_path: str | Path, clock: Callable[[], float] = time.monotonic,
                 config: GateConfig | None = None,
                 disputes: dict[str, SimDispute] | None = None,
                 subscriptions: dict[str, SimSubscription] | None = None,
                 known_customers: Iterable[str] = (),
                 grants: Callable[[object, Request], "str | None"] | None = None) -> None:
        self._grants = grants
        self._config = config or GateConfig()
        self._clock = clock
        self._audit = AuditLog(audit_path)
        self._breaker = CircuitBreaker()
        self.stamps = StampStore(self._config, clock)
        self._lock = threading.Lock()
        self._disputes = dict(disputes or {})
        self._subs = dict(subscriptions or {})
        self._known = set(known_customers)
        self._history: list[tuple[str, float]] = []
        self._done_ids: set[str] = set()
        self._reset_seq = itertools.count(1)

    # ---- read-only views -----------------------------------------------------
    def dispute_status(self, ref: str) -> str | None:
        d = self._disputes.get(ref)
        return d.status if d else None

    def subscription(self, ref: str) -> tuple[int, str] | None:
        s = self._subs.get(ref)
        return (s.price_cents, s.status) if s else None

    @property
    def breaker_open(self) -> bool:
        return self._breaker.is_open

    def preview(self, request: Request, op: SimAction) -> Decision:
        with self._lock:
            return self._decide(request, op)

    def knows_customer(self, customer: object) -> bool:
        with self._lock:
            return customer in self._known

    def trip_breaker(self) -> None:
        """Tightening: open the desk breaker (used on approval lockout)."""
        self._breaker.trip()

    def approve(self, request: Request, op: SimAction, grant: object) -> str:
        """Turn a valid step-up grant into a one-time stamp (same rule as the executor)."""
        if self._grants is None:
            raise StampError("no approval service: failing closed")
        approver = self._grants(grant, request)
        if not approver:
            raise StampError("approval grant rejected")
        return self.stamps.issue(request, self.preview(request, op), approver)

    # ---- the one path that changes simulated records -------------------------
    def apply(self, request: Request, op: SimAction, stamp: str | None = None) -> DeskResult:
        with self._lock:
            try:
                result = self._apply(request, op, stamp)
            except Exception:
                result = DeskResult(False, Verdict.BLOCK, "internal error: failing closed")
            self._audit.append(getattr(request, "id", "unknown"), result.verdict.value,
                               f"SIMULATED {getattr(op, 'kind', '?')}: {result.reason}",
                               getattr(request, "amount_cents", None),
                               getattr(request, "recipient", None))
            return result

    def reset_breaker(self, person: str, reason: str) -> None:
        if not isinstance(person, str) or not person.strip():
            raise ValueError("a person must be named to reset the breaker")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("a reason is required to reset the breaker")
        with self._lock:
            self._breaker.reset_by_person()
            self._audit.append(f"sim-reset-{next(self._reset_seq)}", "RESET",
                               f"SIMULATED desk breaker reset by {person.strip()}: "
                               f"{reason.strip()}", None, None)

    # ---- internals -------------------------------------------------------------
    def _apply(self, request: Request, op: SimAction, stamp: str | None) -> DeskResult:
        decision = self._decide(request, op)
        if decision.trip_breaker:
            self._breaker.trip()
            return DeskResult(False, Verdict.BLOCK, decision.reason + "; breaker tripped")
        if decision.verdict is Verdict.HOLD:
            if stamp is None:
                return DeskResult(False, Verdict.HOLD, decision.reason)
            spent = self.stamps.spend(stamp, request.amount_cents, request.recipient,
                                      request_id=request.id)
            if spent is not SpendResult.OK:
                return DeskResult(False, Verdict.BLOCK, f"stamp rejected: {spent.value}")
        elif decision.verdict is not Verdict.ALLOW:
            return DeskResult(False, Verdict.BLOCK, decision.reason)
        self._done_ids.add(request.id)
        self._change_record(op, request.amount_cents)
        self._known.add(request.recipient)
        self._history.append((request.recipient, self._clock()))
        return DeskResult(True, Verdict.ALLOW, f"applied {op.action} to {op.ref}")

    def _decide(self, request: Request, op: SimAction) -> Decision:
        try:
            problem = self._record_problem(request, op)
            if problem:
                return Decision(Verdict.BLOCK, problem)
            state = GateState(now=self._clock(), breaker_open=self._breaker.is_open,
                              known_recipients=frozenset(self._known),
                              recent_payments=tuple(self._history))
            return evaluate(request, state, self._config)
        except Exception:
            return Decision(Verdict.BLOCK, "internal error: failing closed")

    def _record_problem(self, request: Request, op: SimAction) -> str | None:
        problems = validate_request(request)
        if problems:
            return "invalid request: " + ", ".join(problems)
        if not isinstance(op, SimAction):
            return "invalid action"
        if request.id in self._done_ids:
            return "duplicate request id: already applied"
        if op.kind == "dispute_response":
            return _dispute_problem(self._disputes.get(op.ref), request, op.action)
        if op.kind == "subscription_change":
            return _subscription_problem(self._subs.get(op.ref), request, op.action)
        return "unknown simulated kind"

    def _change_record(self, op: SimAction, amount_cents: int) -> None:
        if op.kind == "dispute_response":
            self._disputes[op.ref].status = "accepted" if op.action == "accept" else "contested"
        elif op.action == "cancel":
            self._subs[op.ref].status = "cancelled"
        else:
            self._subs[op.ref].price_cents = amount_cents


def _dispute_problem(d: SimDispute | None, req: Request, action: str) -> str | None:
    if d is None:
        return "unknown dispute"
    if d.customer != req.recipient:
        return "dispute belongs to another customer"
    if d.status != "open":
        return "dispute already resolved"
    if action not in ("accept", "contest"):
        return "bad dispute action"
    if req.amount_cents != d.amount_cents:
        return "amount does not match disputed amount"
    return None


def _subscription_problem(s: SimSubscription | None, req: Request, action: str) -> str | None:
    if s is None:
        return "unknown subscription"
    if s.customer != req.recipient:
        return "subscription belongs to another customer"
    if s.status != "active":
        return "subscription not active"
    if action == "cancel" and req.amount_cents != s.price_cents:
        return "amount does not match current price"
    if action not in ("change_plan", "cancel"):
        return "bad subscription action"
    return None
