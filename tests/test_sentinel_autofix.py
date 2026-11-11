"""Tighten-only: the executor's tighten_config refuses anything looser, Sentinel's Tightener
can only trip breakers and tighten, and Sentinel code never approves, sends or loosens."""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from tollgate.executor.backend import MockBackend
from tollgate.executor.executor import Executor
from tollgate.gate.audit import AuditLog
from tollgate.gate.rules import GateConfig
from tollgate.sentinel import baseline
from tollgate.sentinel.autofix import Tightener
from tests.sentinel_support import demo_web, git_repo, sentinel_for

SENTINEL_DIR = Path(__file__).resolve().parent.parent / "tollgate" / "sentinel"


@pytest.fixture
def executor(tmp_path):
    return Executor(MockBackend(), tmp_path / "audit.jsonl")


# ---- executor.tighten_config ------------------------------------------------------------
@pytest.mark.parametrize("field,value", [
    ("auto_limit_cents", 50_000), ("velocity_max_payments", 1),
    ("velocity_window_seconds", 1_200), ("stamp_lifetime_seconds", 120)])
def test_tighten_config_applies_a_stricter_value(executor, tmp_path, field, value):
    assert executor.tighten_config(field, value, "sentinel") is True
    assert getattr(executor.config, field) == value
    assert getattr(executor.stamps._config, field) == value          # stamps use it too
    line = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[-1])
    assert line["decision"] == "TIGHTEN" and field in line["reason"]


@pytest.mark.parametrize("field,value", [
    ("auto_limit_cents", 100_000), ("auto_limit_cents", 200_000),        # equal, looser
    ("velocity_max_payments", 2), ("velocity_max_payments", 5),
    ("velocity_window_seconds", 600), ("velocity_window_seconds", 60),
    ("stamp_lifetime_seconds", 300), ("stamp_lifetime_seconds", 600),
    ("auto_limit_cents", 0), ("auto_limit_cents", -5),                   # invalid
    ("auto_limit_cents", True), ("auto_limit_cents", 99.5), ("auto_limit_cents", "1"),
    ("unknown_field", 1), (None, 1)])
def test_tighten_config_refuses_anything_not_stricter(executor, tmp_path, field, value):
    before = executor.config
    assert executor.tighten_config(field, value, "sentinel") is False
    assert executor.config == before
    assert not (tmp_path / "audit.jsonl").exists()                       # nothing audited


def test_tighten_config_is_one_way(executor):
    assert executor.tighten_config("auto_limit_cents", 50_000, "sentinel")
    assert not executor.tighten_config("auto_limit_cents", 100_000, "sentinel")
    assert executor.config.auto_limit_cents == 50_000


# ---- Tightener ----------------------------------------------------------------------------
def test_tightener_has_only_tightening_methods():
    public = {n for n in dir(Tightener) if not n.startswith("_")}
    assert public == {"trip_breakers", "restore"}


def test_restore_sets_a_drifted_setting_back_but_never_loosens(tmp_path):
    web = demo_web(tmp_path, seed=False)
    ctx = web.ctx
    t = Tightener(ctx.executor, ctx.desk, ctx.service, AuditLog(tmp_path / "s.jsonl"))
    ctx.executor._config = GateConfig(auto_limit_cents=900_000)          # drift (looser)
    assert t.restore("gate", "auto_limit_cents") is True
    assert ctx.executor.config.auto_limit_cents == baseline.GATE.auto_limit_cents
    ctx.executor._config = GateConfig(auto_limit_cents=10_000)           # stricter than baseline
    assert t.restore("gate", "auto_limit_cents") is False                # would loosen
    assert ctx.executor.config.auto_limit_cents == 10_000
    assert t.restore("session", "idle_seconds") is False                 # no tighten path
    assert t.restore("gate", "nope") is False


def test_restore_policy_only_tightens(tmp_path):
    web = demo_web(tmp_path, seed=False)
    t = Tightener(web.ctx.executor, web.ctx.desk, web.ctx.service, AuditLog(tmp_path / "s.jsonl"))
    web.ctx.service.tighten("approvals_per_hour", 3, "a person")
    assert t.restore("policy", "approvals_per_hour") is False            # 10 would loosen
    assert web.ctx.service.policy.approvals_per_hour == 3


def test_trip_breakers_trips_both_and_is_audited(tmp_path):
    web = demo_web(tmp_path, seed=False)
    t = Tightener(web.ctx.executor, web.ctx.desk, web.ctx.service, AuditLog(web.ctx.audit_path))
    t.trip_breakers("test")
    assert web.ctx.executor.breaker_open and web.ctx.desk.breaker_open
    assert '"decision": "TRIP"' in web.audit_text()


# ---- Sentinel never approves, sends or loosens --------------------------------------------
FORBIDDEN = {"approve", "execute", "redeem", "reset_breaker", "unlock", "authorize",
             "release_due", "cancel", "reject", "submit", "request_change", "apply_due_changes",
             "charge", "refund", "issue", "spend", "reset_by_person"}


@pytest.mark.parametrize("path", sorted(p for p in SENTINEL_DIR.glob("*.py")
                                        if p.name != "canaries.py"), ids=lambda p: p.name)
def test_sentinel_code_never_calls_money_or_loosening_methods(path):
    """canaries.py is excluded on purpose: it approves only inside its own throwaway world
    (tested separately to never touch the live app)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    called = {n.func.attr for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not (called & FORBIDDEN), called & FORBIDDEN


def test_a_full_sentinel_round_moves_no_money_and_approves_nothing(tmp_path):
    web = demo_web(tmp_path)
    web.ctx.executor._config = GateConfig(auto_limit_cents=900_000)      # a weak setting
    pending = [p.id for p in web.ctx.reviewer.pending()]
    sentinel = sentinel_for(web, git_repo(tmp_path / "repo", tracked={"a.py": "a = 1\n"}))
    sentinel.run_all_now()
    assert web.backend.balance_cents == 0
    assert [p.id for p in web.ctx.reviewer.pending()] == pending          # nothing approved
    assert web.ctx.service.waiting() == []
    assert web.ctx.executor.breaker_open                                  # tightened instead
    assert web.ctx.executor.config.auto_limit_cents == 100_000
