"""Wire the step-up approval service to the executor and desk.

    approvals = build_service(account, audit_path, outbox_path, clock=clock)
    executor = Executor(backend, audit_path, clock=clock, grants=approvals.redeem)
    connect(approvals, executor, desk)        # lockout trips both breakers
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

from tollgate.approval.accounts import ApproverAccount
from tollgate.approval.outbox import Outbox
from tollgate.approval.policy import ApprovalPolicy
from tollgate.approval.service import ApprovalService
from tollgate.gate.rules import GateConfig


def build_service(account: ApproverAccount, audit_path: str | Path, outbox_path: str | Path, *,
                  clock: Callable[[], float] = time.monotonic,
                  wall_clock: Callable[[], float] = time.time,
                  policy: ApprovalPolicy | None = None,
                  gate_config: GateConfig | None = None) -> ApprovalService:
    return ApprovalService(account, audit_path, Outbox(outbox_path, wall_clock), clock=clock,
                           wall_clock=wall_clock, policy=policy, gate_config=gate_config)


def connect(service: ApprovalService, *targets: Any) -> None:
    """Every target with `trip_breaker` gets tripped when approvals lock out."""
    for target in targets:
        service.add_breaker(target.trip_breaker)
