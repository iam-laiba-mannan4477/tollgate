"""The agent loop: read message -> model proposes -> every proposal goes to the Gate.

The agent holds only a `ProposalSink` (in practice a DrafterHandle from
tollgate/roles.py). The sink can submit a proposal; it cannot approve, and it
never receives or passes a stamp. So a HELD proposal waits for a person, and
only an ALLOW decision from the executor's own Gate check can move money.

Customer text is passed to the model as data and copied into the proposal for
the audit trail. The loop itself never reads instructions from it.
Every tool call writes one audit event. Any error fails closed (BLOCK).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from tollgate.agent.model import CustomerMessage, ModelAdapter, ToolCall
from tollgate.agent.proposal import Proposal, build_proposal, is_safe_id
from tollgate.agent.tools import ALL_TOOLS, PROPOSE_TOOLS, Directory
from tollgate.gate.audit import AuditLog
from tollgate.gate.models import Verdict

MAX_TOOL_CALLS_PER_MESSAGE = 6
MAX_PROPOSALS_PER_MESSAGE = 3


@dataclass(frozen=True)
class SubmitResult:
    verdict: Verdict
    executed: bool
    reason: str


class ProposalSink(Protocol):
    def submit(self, proposal: Proposal) -> SubmitResult: ...


@dataclass(frozen=True)
class Outcome:
    tool: str
    proposal_id: str | None
    verdict: Verdict | None          # None for a successful read-only lookup
    executed: bool
    reason: str


class Agent:
    def __init__(self, model: ModelAdapter, sink: ProposalSink, directory: Directory,
                 audit_path: str | Path, clock: Callable[[], float] = time.time) -> None:
        self._model = model
        self._sink = sink
        self._directory = directory
        self._audit = AuditLog(audit_path, clock)

    def handle(self, message: CustomerMessage) -> list[Outcome]:
        """Process one message. Never raises; never moves money itself."""
        if not isinstance(message, CustomerMessage) or not is_safe_id(message.id):
            return [self._record("message", None, Verdict.BLOCK, False, "bad message")]
        try:
            calls = self._model.generate(message, sorted(ALL_TOOLS))
            if not isinstance(calls, list):
                raise TypeError("model output must be a list")
        except Exception:
            return [self._record("model", f"{message.id}-0", Verdict.BLOCK, False,
                                 "model error: failing closed")]
        return self._run_calls(message, calls)

    def _run_calls(self, message: CustomerMessage, calls: list[Any]) -> list[Outcome]:
        outcomes: list[Outcome] = []
        proposals = 0
        for n, call in enumerate(calls, start=1):
            pid = f"{message.id}-{n}"
            name = call.name if isinstance(call, ToolCall) and isinstance(call.name, str) else "?"
            if n > MAX_TOOL_CALLS_PER_MESSAGE:
                outcomes.append(self._record(name, pid, Verdict.BLOCK, False,
                                             "too many tool calls in one message"))
                continue
            if name in PROPOSE_TOOLS:
                proposals += 1
                if proposals > MAX_PROPOSALS_PER_MESSAGE:
                    outcomes.append(self._record(name, pid, Verdict.BLOCK, False,
                                                 "too many proposals in one message"))
                    continue
            outcomes.append(self._run_one(message, call, name, pid))
        return outcomes

    def _run_one(self, message: CustomerMessage, call: Any, name: str, pid: str) -> Outcome:
        if name not in ALL_TOOLS:
            return self._record(name, pid, Verdict.BLOCK, False, "unknown or forbidden tool")
        args = dict(call.args) if hasattr(call.args, "keys") else call.args
        if name not in PROPOSE_TOOLS:
            found = self._directory.lookup(name, args)
            return self._record(name, None, None if found is not None else Verdict.BLOCK,
                                False, "lookup ok" if found is not None else "lookup failed")
        built = build_proposal(PROPOSE_TOOLS[name], args, proposal_id=pid,
                               source_message_id=message.id, source_text=message.text)
        if isinstance(built, list):
            return self._record(name, pid, Verdict.BLOCK, False,
                                "invalid proposal: " + ", ".join(built))
        return self._submit(name, built)

    def _submit(self, name: str, proposal: Proposal) -> Outcome:
        try:
            result = self._sink.submit(proposal)
            verdict = result.verdict if isinstance(result.verdict, Verdict) else Verdict.BLOCK
            executed = result.executed is True and verdict is Verdict.ALLOW
            return self._record(name, proposal.id, verdict, executed, str(result.reason),
                                proposal.amount_cents, proposal.target)
        except Exception:
            return self._record(name, proposal.id, Verdict.BLOCK, False,
                                "submit error: failing closed")

    def _record(self, tool: str, pid: str | None, verdict: Verdict | None, executed: bool,
                reason: str, amount: int | None = None, target: str | None = None) -> Outcome:
        decision = verdict.value if verdict is not None else "LOOKUP"
        self._audit.append(pid or "lookup", decision, f"agent {tool}: {reason}", amount, target)
        return Outcome(tool, pid, verdict, executed, reason)
