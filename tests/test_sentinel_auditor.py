"""Config auditor: settings in force vs the safe baseline."""
from __future__ import annotations

import dataclasses

from tollgate.approval.policy import ApprovalPolicy
from tollgate.gate.rules import GateConfig
from tollgate.sentinel import auditor, baseline
from tollgate.sentinel.findings import Severity

SESSION = dict(baseline.SESSION)


def test_defaults_are_all_ok():
    checks = auditor.audit(GateConfig(), GateConfig(), ApprovalPolicy(), SESSION)
    assert len(checks) == 4 + 4 + 9 + 2
    assert all(c.ok for c in checks), [c for c in checks if not c.ok]
    assert auditor.findings(checks) == []


def test_looser_gate_setting_is_weak_with_reason():
    loose = GateConfig(auto_limit_cents=500_000)
    [weak] = [c for c in auditor.audit(loose, GateConfig(), ApprovalPolicy(), SESSION) if not c.ok]
    assert (weak.area, weak.field, weak.now, weak.baseline) == ("gate", "auto_limit_cents",
                                                                500_000, 100_000)
    assert weak.reason.startswith("weak:") and "lower is stricter" in weak.reason
    [finding] = auditor.findings([weak])
    assert finding.severity is Severity.HIGH and finding.location == "gate.auto_limit_cents"


def test_stricter_settings_are_ok():
    strict_gate = GateConfig(auto_limit_cents=50_000, velocity_window_seconds=1_200)
    strict_policy = dataclasses.replace(ApprovalPolicy(), cooling_off_seconds=1_800,
                                        max_failed_codes=2)
    checks = auditor.audit(strict_gate, strict_gate, strict_policy,
                           {"lifetime_seconds": 1_800, "idle_seconds": 300})
    assert all(c.ok for c in checks)


def test_looser_policy_desk_and_session_are_weak():
    policy = dataclasses.replace(ApprovalPolicy(), cooling_off_seconds=60, daily_cap_cents=9_000_000)
    desk = GateConfig(velocity_max_payments=10)
    checks = auditor.audit(GateConfig(), desk, policy, {"lifetime_seconds": 86_400,
                                                         "idle_seconds": 900})
    weak = {(c.area, c.field) for c in checks if not c.ok}
    assert weak == {("policy", "cooling_off_seconds"), ("policy", "daily_cap_cents"),
                    ("desk", "velocity_max_payments"), ("session", "lifetime_seconds")}


def test_missing_settings_fail_closed_as_weak():
    checks = auditor.audit(object(), None, object(), {})
    assert checks and not any(c.ok for c in checks)
