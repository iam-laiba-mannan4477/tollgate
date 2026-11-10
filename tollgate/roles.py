"""Roles, least privilege, enforced by what each role is handed.

- DRAFTER (the agent) gets a `DrafterHandle`. It has ONE method, `submit`. It
  sends proposals with no stamp, so the executor's own Gate check decides:
  ALLOW runs, HOLD waits in the pending queue, BLOCK stops. It cannot approve,
  read stamps, reset breakers or reach the executor object.
- REVIEWER (the enrolled approver) gets a `ReviewerHandle`: list, approve, reject
  or cancel HELD proposals. Approving needs the approver's logged-in session AND a
  fresh second-factor code (tollgate/approval). Small approvals send at once; big
  ones wait out a cooling-off window first. Grants and stamps never leave this module.
- EXECUTOR (`tollgate/executor`) is the only code that moves money.

The agent package is not allowed to import this module, the executor, or the
stamp store (a test checks that). Honest limit: Python cannot truly sandbox code
in the same process, so the real guarantee is that the executor re-checks every
request and HOLD needs a stamp the agent never sees.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from tollgate.agent.loop import SubmitResult
from tollgate.agent.proposal import Proposal, ProposalKind
from tollgate.approval.service import ApprovalItem, ApprovalService, Grant, Status
from tollgate.executor.executor import Executor
from tollgate.gate.models import Decision, Request, Verdict
from tollgate.gate.stamps import StampError
from tollgate.simulated.desk import SimAction, SimulatedDesk

DRAFTER_NAMES = frozenset({"agent", "drafter", "bot", "ai", "assistant", "model"})


class Role(str, Enum):
    DRAFTER = "drafter"
    REVIEWER = "reviewer"
    EXECUTOR = "executor"


class RoleError(PermissionError):
    pass


@dataclass(frozen=True)
class Pending:
    proposal: Proposal
    request: Request


@dataclass
class _Queue:
    items: dict[str, Pending] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


def to_request(p: Proposal, now: float) -> Request:
    """Build the Gate request. via_agent is set HERE, never by the agent."""
    is_refund = p.kind is ProposalKind.REFUND
    return Request(id=p.id, type="refund" if is_refund else "pay",
                   amount_cents=p.amount_cents, recipient=p.target, via_agent=True,
                   created_at=now, order_total_cents=p.order_total_cents if is_refund else None)


def _sim_action(p: Proposal) -> SimAction:
    return SimAction(kind=p.kind.value, action=str(p.action), ref=str(p.ref))


class DrafterHandle:
    """What the agent holds. Only `submit`; no approve, no stamp, no executor."""

    __slots__ = ("_submit",)

    def __init__(self, submit: Callable[[Proposal], SubmitResult]) -> None:
        object.__setattr__(self, "_submit", submit)

    def __setattr__(self, name: str, value: Any) -> None:
        raise RoleError("drafter handle is read-only")

    @property
    def role(self) -> Role:
        return Role.DRAFTER

    def submit(self, proposal: Proposal) -> SubmitResult:
        if not isinstance(proposal, Proposal):
            return SubmitResult(Verdict.BLOCK, False, "not a proposal")
        return self._submit(proposal)


class ReviewerHandle:
    """What a person holds. Approving needs the approver's session AND a fresh code.

    Phase 3c: approval goes through the step-up service. Small approvals still send at
    once after the factor passes; big ones (and big ones to new recipients) wait out a
    cooling-off window, then `release_due` re-runs the Gate and re-checks the breaker.
    """

    def __init__(self, executor: Executor, desk: SimulatedDesk, queue: _Queue,
                 approvals: ApprovalService) -> None:
        self._executor = executor
        self._desk = desk
        self._queue = queue
        self._approvals = approvals

    @property
    def role(self) -> Role:
        return Role.REVIEWER

    def pending(self) -> list[Proposal]:
        with self._queue.lock:
            return [item.proposal for item in self._queue.items.values()]

    def approve(self, proposal_id: str, session: object, code: object) -> SubmitResult:
        with self._queue.lock:
            item = self._queue.items.get(proposal_id)
        if item is None:
            return SubmitResult(Verdict.BLOCK, False, "no such pending proposal")
        decision = self._preview(item)
        if decision.verdict is not Verdict.HOLD:
            self._take(proposal_id)
            return SubmitResult(Verdict.BLOCK, False, f"no longer held: {decision.reason}")
        target = ApprovalItem(item.proposal.id, item.request, not self._knows(item))
        result = self._approvals.authorize(
            session, code, target, lambda grant: self._release(item, grant, decision.reason))
        if result.status is Status.GRANTED and result.grant is not None:
            self._take(proposal_id)
            return self._send(item, result.grant)
        if result.status is Status.DELAYED:
            self._take(proposal_id)
            return SubmitResult(Verdict.HOLD, False, "approved, waiting: " + result.reason)
        if result.status is Status.BLOCKED:
            self._take(proposal_id)
        return SubmitResult(Verdict.BLOCK, False, result.reason)

    def release_due(self) -> list[tuple[str, SubmitResult]]:
        """Send approvals whose cooling-off is over (each re-checked first)."""
        out = []
        for item_id, res in self._approvals.release_due():
            out.append((item_id, res if isinstance(res, SubmitResult) else
                        SubmitResult(Verdict.BLOCK, False, "release blocked")))
        return out

    def cancel(self, proposal_id: str, person: str) -> bool:
        """The owner cancels an approval during its cooling-off window."""
        return self._approvals.cancel(proposal_id, person)

    def reject(self, proposal_id: str, person: str) -> bool:
        _require_person(person)
        return self._take(proposal_id) is not None

    # ---- internals -----------------------------------------------------------------------
    def _release(self, item: Pending, grant: Grant, approved_reason: str) -> SubmitResult:
        """At release: breaker closed and the Gate must still say exactly what it said."""
        p = item.proposal
        if self._breaker_open(item):
            return self._blocked_at_release(p, "circuit breaker open at release")
        now = self._preview(item)
        if now.verdict is not Verdict.HOLD or now.reason != approved_reason:
            return self._blocked_at_release(p, f"changed since approval: {now.reason}")
        return self._send(item, grant)

    def _blocked_at_release(self, p: Proposal, reason: str) -> SubmitResult:
        self._approvals.record(p.id, "BLOCK", "release: " + reason, p.amount_cents, p.target)
        return SubmitResult(Verdict.BLOCK, False, reason)

    def _send(self, item: Pending, grant: Grant) -> SubmitResult:
        p, req = item.proposal, item.request
        try:
            if p.kind in (ProposalKind.PAYMENT, ProposalKind.REFUND):
                refund_of = p.ref if p.kind is ProposalKind.REFUND else None
                stamp = self._executor.approve(req, grant, refund_of)
                res = self._executor.execute(req, stamp, refund_of)
                return SubmitResult(res.verdict, res.executed, res.reason)
            op = _sim_action(p)
            out = self._desk.apply(req, op, self._desk.approve(req, op, grant))
            return SubmitResult(out.verdict, out.applied, out.reason)
        except StampError as exc:
            return SubmitResult(Verdict.BLOCK, False, f"stamp refused: {exc}")

    def _preview(self, item: Pending) -> Decision:
        p, req = item.proposal, item.request
        if p.kind in (ProposalKind.PAYMENT, ProposalKind.REFUND):
            refund_of = p.ref if p.kind is ProposalKind.REFUND else None
            return self._executor.preview(req, refund_of)
        return self._desk.preview(req, _sim_action(p))

    def _knows(self, item: Pending) -> bool:
        if item.proposal.kind in (ProposalKind.PAYMENT, ProposalKind.REFUND):
            return self._executor.knows_recipient(item.request.recipient)
        return self._desk.knows_customer(item.request.recipient)

    def _breaker_open(self, item: Pending) -> bool:
        if item.proposal.kind in (ProposalKind.PAYMENT, ProposalKind.REFUND):
            return self._executor.breaker_open
        return self._desk.breaker_open

    def _take(self, proposal_id: str) -> Pending | None:
        with self._queue.lock:
            return self._queue.items.pop(proposal_id, None)


def _require_person(person: Any) -> str:
    if not isinstance(person, str) or not person.strip():
        raise RoleError("a named person must review")
    if person.strip().lower() in DRAFTER_NAMES:
        raise RoleError("the drafter role cannot approve")
    return person.strip()


def build_roles(executor: Executor, desk: SimulatedDesk, clock: Callable[[], float],
                approvals: ApprovalService) -> tuple[DrafterHandle, ReviewerHandle]:
    """Wire the roles. The drafter gets a closure, not the executor."""
    queue = _Queue()

    def submit(p: Proposal) -> SubmitResult:
        req = to_request(p, clock())
        if p.kind in (ProposalKind.PAYMENT, ProposalKind.REFUND):
            refund_of = p.ref if p.kind is ProposalKind.REFUND else None
            res = executor.execute(req, None, refund_of)     # never a stamp
            result = SubmitResult(res.verdict, res.executed, res.reason)
        else:
            out = desk.apply(req, _sim_action(p), None)      # never a stamp
            result = SubmitResult(out.verdict, out.applied, "SIMULATED: " + out.reason)
        if result.verdict is Verdict.HOLD:
            with queue.lock:
                queue.items[p.id] = Pending(p, req)
        return result

    return DrafterHandle(submit), ReviewerHandle(executor, desk, queue, approvals)
