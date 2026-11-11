"""Self-attack canaries: replay the frozen attack scenarios (tollgate/agent/scenarios.py)
against the Gate, each in a FRESH, ISOLATED mock world: in-memory MockBackend, a temporary
audit file, its own breakers and its own throwaway approver. Nothing touches the live
executor, the live audit log or any real money.

A canary "got through" if any outcome was ALLOW or executed, or the world's money,
dispute or subscription records changed. For the stolen-approver-session scenario the
attacker also tries to approve the held payment from the real approver session with no
code and with a wrong code. Any canary through -> a CRITICAL finding.

This module (seeding the isolated world) is the only Sentinel code that approves anything,
and only inside its own throwaway world.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from tollgate.agent import scenarios
from tollgate.agent.loop import Agent
from tollgate.agent.model import CustomerMessage, ScriptedModel
from tollgate.agent.tools import Directory
from tollgate.approval.accounts import ApproverAccount
from tollgate.approval.service import ApprovalItem, Status
from tollgate.approval.setup import build_service, connect
from tollgate.approval.totp import code_at, decode_secret, new_secret_b32
from tollgate.config import Mode
from tollgate.executor.backend import MockBackend
from tollgate.executor.executor import Executor
from tollgate.gate.models import Request, Verdict
from tollgate.gate.rules import GateConfig
from tollgate.roles import build_roles
from tollgate.sentinel.findings import Finding, Severity
from tollgate.simulated.desk import SimDispute, SimSubscription, SimulatedDesk

CANARY_PBKDF2_ROUNDS = 1_000      # throwaway in-memory account inside the canary world only


class _Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@dataclass(frozen=True)
class CanaryResult:
    name: str
    through: bool
    why: str


class CanaryWorld:
    """Same wiring as the test world in tests/test_agent.py, built for one canary run."""

    def __init__(self, folder: Path, config: GateConfig | None = None,
                 known: Iterable[str] = ()) -> None:
        self.clock, self.wall = _Clock(1_000.0), _Clock(1_700_000_000.0)
        audit = folder / "canary-audit.jsonl"
        self.account = ApproverAccount(Mode.MOCK, CANARY_PBKDF2_ROUNDS, clock=self.clock)
        self._secret = decode_secret(self.account.enroll("canary-owner", "canary-password-1",
                                                         "canary@invalid", new_secret_b32()))
        self.service = build_service(self.account, audit, folder / "canary-outbox.jsonl",
                                     clock=self.clock, wall_clock=self.wall)
        self.session = self.account.login("canary-owner", "canary-password-1")
        self.backend = MockBackend()
        self.executor = Executor(self.backend, audit, config=config, clock=self.clock,
                                 grants=self.service.redeem)
        self.desk = SimulatedDesk(audit, clock=self.clock, config=config,
                                  disputes={"dp_1": SimDispute("cust_2", 3_000)},
                                  subscriptions={"sub_1": SimSubscription("cust_3", 2_999)},
                                  known_customers={"cust_2", "cust_3"}, grants=self.service.redeem)
        connect(self.service, self.executor, self.desk)
        seeds = [("order-1", 4_000, "cust_1"), ("seed-supplier", 100, "acct_supplier_1"),
                 *[(f"seed-{k}", 100, k) for k in known]]
        for rid, cents, to in seeds:
            self._seed(rid, cents, to)
        self.clock.t += 60
        self.drafter, self.reviewer = build_roles(self.executor, self.desk, self.clock,
                                                  self.service)
        directory = Directory(orders={"order-1": {"customer": "cust_1", "total_cents": 4_000}})
        self.agent = Agent(ScriptedModel(scenarios.SCRIPTS), self.drafter, directory, audit,
                           clock=self.clock)
        self.start_balance = self.backend.balance_cents

    def code(self) -> str:
        self.wall.t += 30
        return code_at(self._secret, self.wall.t)

    def _seed(self, rid: str, cents: int, to: str) -> None:
        req = Request(id=rid, type="pay", amount_cents=cents, recipient=to, via_agent=True,
                      created_at=0.0)
        res = self.service.authorize(self.session, self.code(), ApprovalItem(rid, req, False),
                                     lambda g: None)
        if res.status is not Status.GRANTED or res.grant is None:
            raise RuntimeError("canary world could not be seeded")
        self.executor.execute(req, self.executor.approve(req, res.grant))

    def records_unchanged(self) -> bool:
        return (self.backend.balance_cents == self.start_balance
                and self.desk.dispute_status("dp_1") == "open"
                and self.desk.subscription("sub_1") == (2_999, "active"))


WorldFactory = Callable[[Path], CanaryWorld]


def default_world(folder: Path) -> CanaryWorld:
    return CanaryWorld(folder)


def run_one(scenario: scenarios.Scenario, world: CanaryWorld) -> CanaryResult:
    msg = CustomerMessage(f"canary-{scenario.name}", scenario.customer_id, scenario.text,
                          scenario.name)
    outcomes = world.agent.handle(msg)
    if any(o.executed or o.verdict is Verdict.ALLOW for o in outcomes):
        return CanaryResult(scenario.name, True, "an attack request was allowed or executed")
    if scenario.name == "stolen_approver_session":
        for pending in world.reviewer.pending():
            for code in ("", "000000"):              # stolen session, no device
                if world.reviewer.approve(pending.id, world.session, code).executed:
                    return CanaryResult(scenario.name, True, "approved without the device")
    if not world.records_unchanged():
        return CanaryResult(scenario.name, True, "money or records changed")
    return CanaryResult(scenario.name, False, "stopped")


def run_all(factory: WorldFactory = default_world) -> list[CanaryResult]:
    results = []
    for scenario in scenarios.ATTACKS:
        with tempfile.TemporaryDirectory(prefix="tollgate-canary-") as folder:
            try:
                results.append(run_one(scenario, factory(Path(folder))))
            except Exception:
                # Fail closed: a canary that cannot run is reported as not proven safe.
                results.append(CanaryResult(scenario.name, True, "canary could not run"))
    return results


def findings(results: list[CanaryResult]) -> list[Finding]:
    return [Finding(f"canary:{r.name}", "canaries", Severity.CRITICAL,
                    f"Canary attack got through: {r.name}",
                    f"Sentinel replayed the '{r.name}' attack in an isolated mock world and "
                    f"it was not stopped ({r.why}). Check the Gate settings and code.",
                    f"scenario {r.name}") for r in results if r.through]
