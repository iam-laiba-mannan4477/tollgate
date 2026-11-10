"""Test helpers for step-up approvals. MOCK MODE ONLY: uses the fixed fake TOTP secret.

`TestApprover` plays the human approver: it is logged in and holds the authenticator,
so it can produce a fresh code (it moves its own wall clock 30 s forward each time,
because a code works once per 30-second step).
"""
from __future__ import annotations

from pathlib import Path

from tollgate.approval.accounts import ApproverAccount
from tollgate.approval.policy import ApprovalPolicy
from tollgate.approval.service import ApprovalItem, Status
from tollgate.approval.setup import build_service, connect
from tollgate.approval.totp import MOCK_TOTP_SECRET_B32, code_at, decode_secret
from tollgate.config import Mode

PASSWORD = "correct-horse-battery-staple"   # test-only, not a real credential
OWNER = "owner@example.test"
SECRET = decode_secret(MOCK_TOTP_SECRET_B32)


class WallClock:
    def __init__(self, t: float = 1_700_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


# Low-level executor tests approve many things quickly; only the hourly rate is raised.
LOOSE_RATE = ApprovalPolicy(approvals_per_hour=10_000)


class TestApprover:
    __test__ = False          # not a pytest test class

    def __init__(self, folder: Path, clock, policy: ApprovalPolicy | None = None,
                 name: str = "alice", audit_name: str = "approvals.jsonl",
                 mode: Mode = Mode.MOCK) -> None:
        self.wall = WallClock()
        self.account = ApproverAccount(mode, iterations=1_000)
        fixed = MOCK_TOTP_SECRET_B32 if mode is Mode.MOCK else None   # sandbox: random secret
        self._secret = decode_secret(self.account.enroll(name, PASSWORD, OWNER, fixed))
        self.outbox_path = Path(folder) / "outbox.jsonl"
        self.service = build_service(self.account, Path(folder) / audit_name,
                                     self.outbox_path, clock=clock, wall_clock=self.wall,
                                     policy=policy)
        self.session = self.account.login(name, PASSWORD)

    def connect(self, *targets) -> None:
        connect(self.service, *targets)

    def code(self) -> str:
        """A fresh, valid code (the next 30-second step)."""
        self.wall.t += 30
        return code_at(self._secret, self.wall.t)

    def grant(self, request, new_recipient: bool = False):
        """Full step-up for one request (session + fresh code). Must be GRANTED."""
        item = ApprovalItem(request.id, request, new_recipient)
        result = self.service.authorize(self.session, self.code(), item, lambda g: None)
        assert result.status is Status.GRANTED, result.reason
        return result.grant
