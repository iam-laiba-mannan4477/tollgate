"""Roles, least privilege, enforced by what each role is handed.

- DRAFTER (the agent) gets a `DrafterHandle`. It has ONE method, `submit`. It
  sends proposals with no stamp, so the executor's own Gate check decides:
  ALLOW runs, HOLD waits in the pending queue, BLOCK stops. It cannot approve,
  read stamps, reset breakers or reach the executor object.
- REVIEWER (a named person) gets a `ReviewerHandle`: list, approve or reject
  HELD proposals. Approving issues a one-time stamp and spends it at once; the
  stamp never leaves this module.
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
from tollgate.executor.executor import Executor
from tollgate.gate.models import Request, Verdict
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
    """What a person holds. Every action needs a named human reviewer."""

    def __init__(self, executor: Executor, desk: SimulatedDesk, queue: _Queue) -> None:
        self._executor = executor
        self._desk = desk
        self._queue = queue

    @property
    def role(self) -> Role:
        return Role.REVIEWER

    def pending(self) -> list[Proposal]:
        with self._queue.lock:
            return [item.proposal for item in self._queue.items.values()]

    def approve(self, proposal_id: str, person: str) -> SubmitResult:
        name = _require_person(person)
        item = self._take(proposal_id)
        if item is None:
            return SubmitResult(Verdict.BLOCK, False, "no such pending proposal")
        p, req = item.proposal, item.request
        if p.kind in (ProposalKind.PAYMENT, ProposalKind.REFUND):
            refund_of = p.ref if p.kind is ProposalKind.REFUND else None
            stamp = self._executor.approve(req, name, refund_of)
            res = self._executor.execute(req, stamp, refund_of)
            return SubmitResult(res.verdict, res.executed, res.reason)
        op = _sim_action(p)
        out = self._desk.apply(req, op, self._desk.approve(req, op, name))
        return SubmitResult(out.verdict, out.applied, out.reason)

    def reject(self, proposal_id: str, person: str) -> bool:
        _require_person(person)
        return self._take(proposal_id) is not None

    def _take(self, proposal_id: str) -> Pending | None:
        with self._queue.lock:
            return self._queue.items.pop(proposal_id, None)


def _require_person(person: Any) -> str:
    if not isinstance(person, str) or not person.strip():
        raise RoleError("a named person must review")
    if person.strip().lower() in DRAFTER_NAMES:
        raise RoleError("the drafter role cannot approve")
    return person.strip()


def build_roles(executor: Executor, desk: SimulatedDesk,
                clock: Callable[[], float]) -> tuple[DrafterHandle, ReviewerHandle]:
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

    return DrafterHandle(submit), ReviewerHandle(executor, desk, queue)
