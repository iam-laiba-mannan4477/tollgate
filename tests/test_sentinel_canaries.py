"""Self-attack canaries: every frozen attack is stopped in an isolated mock world, a
deliberately weakened world lets one through and is caught, and the live app is untouched."""
from __future__ import annotations

from pathlib import Path

from tollgate.agent import scenarios
from tollgate.gate.rules import GateConfig
from tollgate.sentinel import canaries
from tollgate.sentinel.findings import Severity
from tests.sentinel_support import demo_web, git_repo, sentinel_for


def test_all_frozen_attacks_are_stopped():
    results = canaries.run_all()
    assert [r.name for r in results] == [s.name for s in scenarios.ATTACKS]
    assert len(results) == 8
    assert not any(r.through for r in results), [r for r in results if r.through]
    assert canaries.findings(results) == []


def weakened(folder: Path) -> canaries.CanaryWorld:
    """DELIBERATELY broken world: huge auto limit, loose velocity, attacker already known."""
    config = GateConfig(auto_limit_cents=10_000_000, velocity_max_payments=100)
    return canaries.CanaryWorld(folder, config=config, known=("acct_evil", "acct_split"))


def test_a_canary_let_through_is_a_critical_finding():
    results = canaries.run_all(weakened)
    through = {r.name for r in results if r.through}
    assert {"injection_payment", "split_payments"} <= through
    found = {f.key: f for f in canaries.findings(results)}
    assert found["canary:injection_payment"].severity is Severity.CRITICAL
    assert "isolated mock world" in found["canary:injection_payment"].detail


def test_a_canary_that_cannot_run_counts_as_through():
    def broken(_folder):
        raise RuntimeError("cannot build")
    results = canaries.run_all(broken)
    assert all(r.through and r.why == "canary could not run" for r in results)


def test_stolen_session_canary_tries_to_approve_without_the_device(tmp_path):
    world = canaries.CanaryWorld(tmp_path)
    [stolen] = [s for s in scenarios.ATTACKS if s.name == "stolen_approver_session"]
    result = canaries.run_one(stolen, world)
    assert not result.through
    assert world.service.locked is False                 # 2 bad codes, under the 3c limit of 3
    assert world.records_unchanged()


def test_canaries_never_touch_the_live_app(tmp_path):
    web = demo_web(tmp_path)
    before_audit = web.audit_text()
    before = (web.backend.balance_cents, len(web.ctx.reviewer.pending()))
    repo = git_repo(tmp_path / "repo", tracked={"a.py": "a = 1\n"})
    sentinel = sentinel_for(web, repo, canary_world=weakened)
    sentinel._run("canaries")
    assert (web.backend.balance_cents, len(web.ctx.reviewer.pending())) == before
    new_lines = web.audit_text()[len(before_audit):]
    assert "canary-" not in new_lines.replace("canary:", "")      # no canary world lines
    assert "FINDING" in new_lines and "TRIP" in new_lines          # only Sentinel's own lines
