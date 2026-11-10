"""The executor: the only path from a proposed request to moving (sandbox) money.

It trusts nobody. For every call it:
  1. validates the request and refuses a request id that already executed,
  2. re-runs the Gate itself with its OWN state (never state from the caller),
  3. trips the breaker on a velocity violation,
  4. proceeds only on ALLOW, or on HOLD plus a stamp valid for this exact
     request id, amount and recipient,
  5. checks the breaker again right before sending,
  6. writes one audit event for every attempt, success or failure.
Any unexpected error returns BLOCK (fail closed).

Refunds: the caller names the original request (`refund_of`). The order total
and remaining refundable amount come from the executor's own ledger, not from
the caller. A refund that claims a different order total is blocked.

Approvals (Phase 3c): `approve` issues a stamp only for a single-use GRANT from the
step-up approval service (approver session + fresh second-factor code, plus any
cooling-off delay). With no service wired in, `approve` always refuses (fail closed).
A person's name alone is no longer enough.

One lock serialises execute() so id checks, breaker checks and state updates
cannot interleave. That limits throughput; correctness first.
"""
from __future__ import annotations

import dataclasses
import itertools
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from tollgate.executor.backend import Backend, BackendResult
from tollgate.gate.audit import AuditLog
from tollgate.gate.breaker import CircuitBreaker
from tollgate.gate.models import Decision, Request, RequestType, Verdict, validate_request
from tollgate.gate.rules import GateConfig, GateState, evaluate
from tollgate.gate.stamps import SpendResult, StampError, StampStore

# redeem(grant, request) -> approver name if the grant is valid for exactly this request
GrantRedeemer = Callable[[object, Request], "str | None"]


@dataclass(frozen=True)
class ExecutionResult:
    executed: bool
    verdict: Verdict
    reason: str
    transaction_id: str | None = None


@dataclass
class _LedgerEntry:
    transaction_id: str
    recipient: str
    amount_cents: int
    refunded_cents: int = 0


class Executor:
    def __init__(self, backend: Backend, audit_path: str | Path,
                 config: GateConfig | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 grants: GrantRedeemer | None = None) -> None:
        self._backend = backend
        self._grants = grants
        self._config = config or GateConfig()
        self._clock = clock
        self._audit = AuditLog(audit_path)
        self._breaker = CircuitBreaker()
        self.stamps = StampStore(self._config, clock)
        self._lock = threading.Lock()
        self._known_recipients: set[str] = set()
        self._history: list[tuple[str, float]] = []
        self._executed_ids: set[str] = set()
        self._ledger: dict[str, _LedgerEntry] = {}
        self._reset_seq = itertools.count(1)

    # ---- read-only views ---------------------------------------------------
    @property
    def breaker_open(self) -> bool:
        return self._breaker.is_open

    def preview(self, request: Request, refund_of: str | None = None) -> Decision:
        """What the Gate says right now (used before asking a person to approve)."""
        with self._lock:
            try:
                prepared = self._prepare(request, refund_of)
                if isinstance(prepared, Decision):
                    return prepared
                return evaluate(prepared, self._state(), self._config)
            except Exception:
                return Decision(Verdict.BLOCK, "internal error: failing closed")

    def knows_recipient(self, recipient: object) -> bool:
        with self._lock:
            return recipient in self._known_recipients

    def trip_breaker(self) -> None:
        """Tightening: open the breaker (used on approval lockout). Never closes it."""
        self._breaker.trip()

    def approve(self, request: Request, grant: object, refund_of: str | None = None) -> str:
        """Turn a valid step-up grant into a one-time stamp for this exact HELD request.

        The grant is used up even if it does not match. No grant service -> refuse.
        """
        if self._grants is None:
            raise StampError("no approval service: failing closed")
        approver = self._grants(grant, request)
        if not approver:
            raise StampError("approval grant rejected")
        return self.stamps.issue(request, self.preview(request, refund_of), approver)

    # ---- the one path that moves money ------------------------------------
    def execute(self, request: Request, stamp: str | None = None,
                refund_of: str | None = None) -> ExecutionResult:
        with self._lock:
            try:
                result = self._execute(request, stamp, refund_of)
            except Exception:
                result = ExecutionResult(False, Verdict.BLOCK, "internal error: failing closed")
            self._log(request, result)
            return result

    def reset_breaker(self, person: str, reason: str) -> None:
        """Loosening: a person closes the breaker with an explicit reason (audited)."""
        if not isinstance(person, str) or not person.strip():
            raise ValueError("a person must be named to reset the breaker")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("a reason is required to reset the breaker")
        with self._lock:
            self._breaker.reset_by_person()
            self._audit.append(f"reset-{next(self._reset_seq)}", "RESET",
                               f"breaker reset by {person.strip()}: {reason.strip()}",
                               None, None)

    # ---- internals ---------------------------------------------------------
    def _execute(self, request: Request, stamp: str | None,
                 refund_of: str | None) -> ExecutionResult:
        prepared = self._prepare(request, refund_of)
        if isinstance(prepared, Decision):
            return ExecutionResult(False, prepared.verdict, prepared.reason)
        decision = evaluate(prepared, self._state(), self._config)
        if decision.trip_breaker:
            self._breaker.trip()
            return ExecutionResult(False, Verdict.BLOCK, decision.reason + "; breaker tripped")
        if decision.verdict is Verdict.BLOCK:
            return ExecutionResult(False, Verdict.BLOCK, decision.reason)
        if decision.verdict is Verdict.HOLD:
            if stamp is None:
                return ExecutionResult(False, Verdict.HOLD, decision.reason)
            spent = self.stamps.spend(stamp, prepared.amount_cents, prepared.recipient,
                                      request_id=prepared.id)
            if spent is not SpendResult.OK:
                return ExecutionResult(False, Verdict.BLOCK, f"stamp rejected: {spent.value}")
        elif decision.verdict is not Verdict.ALLOW:
            return ExecutionResult(False, Verdict.BLOCK, "unknown verdict")
        if self._breaker.is_open:  # last check right before sending
            return ExecutionResult(False, Verdict.BLOCK, "circuit breaker open")
        return self._send(prepared, refund_of)

    def _prepare(self, request: Any, refund_of: str | None) -> Request | Decision:
        """Validate, enforce idempotency, and fill refund totals from our ledger."""
        problems = validate_request(request)
        if problems:
            return Decision(Verdict.BLOCK, "invalid request: " + ", ".join(problems))
        if request.id in self._executed_ids:
            return Decision(Verdict.BLOCK, "duplicate request id: already executed")
        is_refund = request.type in (RequestType.REFUND, "refund")
        if not is_refund:
            if refund_of is not None:
                return Decision(Verdict.BLOCK, "refund_of given for a payment")
            return request
        entry = self._ledger.get(refund_of) if isinstance(refund_of, str) else None
        if entry is None:
            return Decision(Verdict.BLOCK, "refund of unknown charge")
        if request.recipient != entry.recipient:
            return Decision(Verdict.BLOCK, "refund recipient differs from charge")
        if request.order_total_cents != entry.amount_cents:
            return Decision(Verdict.BLOCK, "claimed order total does not match ledger")
        remaining = entry.amount_cents - entry.refunded_cents
        if remaining <= 0:
            return Decision(Verdict.BLOCK, "charge already fully refunded")
        return dataclasses.replace(request, order_total_cents=remaining)

    def _state(self) -> GateState:
        return GateState(now=self._clock(), breaker_open=self._breaker.is_open,
                         known_recipients=frozenset(self._known_recipients),
                         recent_payments=tuple(self._history))

    def _send(self, req: Request, refund_of: str | None) -> ExecutionResult:
        # Consume the id BEFORE calling out: even an ambiguous failure must not
        # be retried under the same id (avoids double charges).
        self._executed_ids.add(req.id)
        if refund_of is not None:
            entry = self._ledger[refund_of]
            outcome: BackendResult = self._backend.refund(entry.transaction_id, req.amount_cents)
        else:
            outcome = self._backend.charge(req.amount_cents, req.id)
        if not outcome.ok or not outcome.transaction_id:
            return ExecutionResult(False, Verdict.BLOCK, f"backend failed: {outcome.reason}")
        self._record_success(req, refund_of, outcome.transaction_id)
        return ExecutionResult(True, Verdict.ALLOW, outcome.reason, outcome.transaction_id)

    def _record_success(self, req: Request, refund_of: str | None, txn_id: str) -> None:
        """State changes only after a successful execution."""
        self._known_recipients.add(req.recipient)
        self._history.append((req.recipient, self._clock()))
        if refund_of is not None:
            self._ledger[refund_of].refunded_cents += req.amount_cents
        else:
            self._ledger[req.id] = _LedgerEntry(txn_id, req.recipient, req.amount_cents)

    def _log(self, request: Any, result: ExecutionResult) -> None:
        reason = result.reason
        if result.transaction_id:
            reason += f" txn={result.transaction_id}"
        self._audit.append(getattr(request, "id", "unknown"), result.verdict.value, reason,
                           getattr(request, "amount_cents", None),
                           getattr(request, "recipient", None))
