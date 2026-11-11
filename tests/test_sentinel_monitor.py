"""Live monitor: thresholds for bursts, repeated blocks, split payments, new recipient then
payment, and second-factor events. Audit lines are written with a fake wall clock."""
from __future__ import annotations

import pytest

from tollgate.gate.audit import AuditLog
from tollgate.sentinel import monitor
from tollgate.sentinel.findings import Severity

LIMIT = 100_000
T0 = 1_700_000_000.0


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def log(tmp_path):
    clock = Clock()
    return AuditLog(tmp_path / "audit.jsonl", clock), clock, tmp_path / "audit.jsonl"


def write(log, at: float, decision: str, amount=None, to=None, reason="gate decision"):
    audit, clock, _ = log
    clock.t = at
    audit.append(f"r{at}", decision, reason, amount, to)


def found(log, now: float | None = None) -> dict[str, monitor.Finding]:
    _, clock, path = log
    events = monitor.AuditReader(path).read(clock.t if now is None else now)
    return {f.key: f for f in monitor.detect(events, LIMIT)}


def test_burst_needs_five_within_sixty_seconds(log):
    for i in range(4):
        write(log, T0 + i * 10, "ALLOW", 100, f"a{i}")
    assert "monitor:burst" not in found(log)
    write(log, T0 + 59, "HOLD", 100, "a9")
    f = found(log)["monitor:burst"]
    assert f.severity is Severity.MEDIUM


def test_five_spread_over_more_than_a_minute_is_not_a_burst(log):
    for i in range(5):
        write(log, T0 + i * 16, "ALLOW", 100, f"a{i}")
    assert "monitor:burst" not in found(log)


def test_three_blocks_to_one_recipient_in_ten_minutes_is_high(log):
    for i in range(3):
        write(log, T0 + i * 200, "BLOCK", 500, "acct_x")
    assert found(log)["monitor:blocks:acct_x"].severity is Severity.HIGH


def test_blocks_spread_over_more_than_ten_minutes_are_ok(log):
    for i in range(3):
        write(log, T0 + i * 301, "BLOCK", 500, "acct_x")
    assert "monitor:blocks:acct_x" not in found(log)


@pytest.mark.parametrize("amounts", [[90_000] * 3, [80_000, 85_000, 100_000], [50_000, 40_000, 30_000]])
def test_split_payments_under_the_limit_are_high(log, amounts):
    for i, cents in enumerate(amounts):
        write(log, T0 + i * 300, "ALLOW", cents, "acct_split")
    assert found(log)["monitor:split:acct_split"].severity is Severity.HIGH


def test_small_payments_that_stay_under_the_limit_are_ok(log):
    for i in range(3):
        write(log, T0 + i * 300, "ALLOW", 10_000, "acct_s")
    assert "monitor:split:acct_s" not in found(log)


def test_split_needs_thirty_minutes(log):
    for i in range(3):
        write(log, T0 + i * 1_000, "ALLOW", 90_000, "acct_split")   # spans 33 min
    assert "monitor:split:acct_split" not in found(log)


def test_new_recipient_then_big_payment_is_medium(log):
    write(log, T0, "HOLD", 5_000, "acct_n", "new recipient: needs a person")
    write(log, T0 + 600, "ALLOW", 150_000, "acct_n", "charged")
    assert found(log)["monitor:newpay:acct_n"].severity is Severity.MEDIUM


@pytest.mark.parametrize("gap,amount", [(901, 150_000), (600, 100_000)])
def test_new_recipient_pattern_needs_15_min_and_over_1000(log, gap, amount):
    write(log, T0, "HOLD", 5_000, "acct_n", "new recipient: needs a person")
    write(log, T0 + gap, "ALLOW", amount, "acct_n", "charged")
    assert "monitor:newpay:acct_n" not in found(log)


def test_single_factorfail_is_medium_and_lockout_is_high(log):
    write(log, T0, "FACTORFAIL", reason="approval: second factor failed (1/3)")
    f = found(log)
    assert f["monitor:factorfail"].severity is Severity.MEDIUM and "monitor:lockout" not in f
    write(log, T0 + 1, "LOCKOUT", reason="approvals locked")
    assert found(log)["monitor:lockout"].severity is Severity.HIGH


def test_agent_and_sentinel_lines_are_ignored(log):
    for i in range(6):
        write(log, T0 + i, "BLOCK", 500, "acct_x", "agent tool refused")
        write(log, T0 + i, "FINDING", reason="sentinel high: x")
    assert found(log) == {}


def test_patterns_age_out_of_the_thirty_minute_window(log):
    for i in range(3):
        write(log, T0 + i, "BLOCK", 500, "acct_x")
    _, _, path = log
    reader = monitor.AuditReader(path)
    assert monitor.detect(reader.read(T0 + 10), LIMIT)
    assert monitor.detect(reader.read(T0 + 1_801 + 10), LIMIT) == []


def test_reader_only_reads_new_lines(log):
    _, clock, path = log
    reader = monitor.AuditReader(path)
    write(log, T0, "ALLOW", 100, "a")
    assert len(reader.read(T0)) == 1
    write(log, T0 + 1, "ALLOW", 100, "b")
    assert len(reader.read(T0 + 1)) == 2
