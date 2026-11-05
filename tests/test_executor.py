import json

import pytest

from tollgate.executor.backend import BackendResult, MockBackend
from tollgate.executor.executor import Executor
from tollgate.gate.audit import verify
from tollgate.gate.models import Request, Verdict


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def pay(rid, amount=500, recipient="acct_a"):
    return Request(id=rid, type="pay", amount_cents=amount, recipient=recipient,
                   via_agent=True, created_at=0.0)


def refund(rid, amount, total, recipient="acct_a"):
    return Request(id=rid, type="refund", amount_cents=amount, recipient=recipient,
                   via_agent=True, created_at=0.0, order_total_cents=total)


@pytest.fixture
def env(tmp_path):
    clock = FakeClock()
    backend = MockBackend()
    path = tmp_path / "audit.jsonl"
    return Executor(backend, path, clock=clock), backend, clock, path


def known(ex, recipient="acct_a", rid="seed"):
    """Make a recipient known via one approved (HELD -> stamped) payment."""
    r = pay(rid, 100, recipient)
    assert ex.execute(r, ex.approve(r, "alice")).executed


def audit_lines(path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]


# ---- refusals ----------------------------------------------------------------
def test_held_without_stamp_refused(env):
    ex, backend, _, _ = env
    res = ex.execute(pay("r1"))
    assert not res.executed and res.verdict is Verdict.HOLD and backend.balance_cents == 0


def test_direct_call_blocked_even_with_stamp(env):
    ex, backend, _, _ = env
    r = pay("r1")
    stamp = ex.approve(r, "alice")
    direct = Request(id="r1", type="pay", amount_cents=500, recipient="acct_a",
                     via_agent=False, created_at=0.0)
    assert ex.execute(direct, stamp).verdict is Verdict.BLOCK
    assert backend.balance_cents == 0


def test_wrong_amount_refused(env):
    ex, backend, _, _ = env
    stamp = ex.approve(pay("r1", 500), "alice")
    res = ex.execute(pay("r1", 501), stamp)
    assert not res.executed and "MISMATCH" in res.reason and backend.balance_cents == 0


def test_wrong_recipient_refused(env):
    ex, _, _, _ = env
    stamp = ex.approve(pay("r1"), "alice")
    assert "MISMATCH" in ex.execute(pay("r1", recipient="acct_evil"), stamp).reason


def test_stamp_for_other_request_id_refused(env):
    ex, _, _, _ = env
    stamp = ex.approve(pay("r1"), "alice")
    assert "MISMATCH" in ex.execute(pay("r2"), stamp).reason


def test_used_stamp_refused(env):
    ex, _, _, _ = env
    r = pay("r1")
    stamp = ex.approve(r, "alice")
    assert ex.execute(r, stamp).executed
    second = pay("r1b", 150_000)                # HELD (over limit), so the stamp matters
    res = ex.execute(second, stamp)
    assert not res.executed and "USED" in res.reason


def test_expired_stamp_refused(env):
    ex, backend, clock, _ = env
    r = pay("r1")
    stamp = ex.approve(r, "alice")
    clock.t += 300
    res = ex.execute(r, stamp)
    assert not res.executed and "EXPIRED" in res.reason and backend.balance_cents == 0


def test_fake_stamp_refused(env):
    ex, _, _, _ = env
    assert "UNKNOWN" in ex.execute(pay("r1"), "not-a-real-stamp").reason


def test_repeated_request_id_refused(env):
    ex, backend, _, _ = env
    known(ex)
    assert ex.execute(pay("r1")).executed
    res = ex.execute(pay("r1"))
    assert not res.executed and "duplicate" in res.reason
    assert backend.balance_cents == 100 + 500


def test_backend_failure_fails_closed_and_consumes_id(env, tmp_path):
    class Failing(MockBackend):
        def charge(self, amount_cents, reference):
            return BackendResult(False, None, "timeout")

    ex = Executor(Failing(), tmp_path / "f.jsonl", clock=FakeClock())
    r = pay("r1")
    res = ex.execute(r, ex.approve(r, "alice"))
    assert not res.executed and res.verdict is Verdict.BLOCK
    assert "duplicate" in ex.execute(r).reason        # no retry under same id
    assert ex.preview(pay("r2")).verdict is Verdict.HOLD  # recipient still unknown


def test_backend_exception_fails_closed(tmp_path):
    class Boom(MockBackend):
        def charge(self, amount_cents, reference):
            raise RuntimeError("boom")

    ex = Executor(Boom(), tmp_path / "b.jsonl", clock=FakeClock())
    r = pay("r1")
    res = ex.execute(r, ex.approve(r, "alice"))
    assert not res.executed and res.verdict is Verdict.BLOCK


@pytest.mark.parametrize("bad", [None, "pay", pay("r1", amount=-5), pay("r1", amount=1.5)])
def test_bad_input_blocked(env, bad):
    ex, _, _, _ = env
    assert ex.execute(bad).verdict is Verdict.BLOCK


# ---- breaker -------------------------------------------------------------------
def test_velocity_trips_breaker_then_blocks_everything(env):
    ex, backend, clock, path = env
    known(ex, rid="p1")                         # payment 1 to acct_a (approved)
    clock.t += 60
    assert ex.execute(pay("p2")).executed       # payment 2
    clock.t += 60
    res = ex.execute(pay("p3"))                 # payment 3 within 10 min
    assert res.verdict is Verdict.BLOCK and "breaker tripped" in res.reason
    assert ex.breaker_open
    known_other = pay("q1", 100, "acct_b")
    assert "breaker" in ex.execute(known_other).reason
    clock.t += 3600                             # time passing does not close it
    assert ex.execute(pay("q2", 100, "acct_b")).verdict is Verdict.BLOCK
    assert backend.balance_cents == 600


def test_reset_breaker_requires_person_and_reason(env):
    ex, _, clock, path = env
    known(ex, rid="p1")
    ex.execute(pay("p2"))
    ex.execute(pay("p3"))
    assert ex.breaker_open
    for person, reason in [("", "ok"), ("alice", ""), ("alice", "   "), (None, "x")]:
        with pytest.raises(ValueError):
            ex.reset_breaker(person, reason)
        assert ex.breaker_open
    ex.reset_breaker("alice", "checked velocity alert, legitimate")
    assert not ex.breaker_open
    resets = [l for l in audit_lines(path) if l["decision"] == "RESET"]
    assert len(resets) == 1 and "alice" in resets[0]["reason"]
    clock.t += 601                              # window passed
    assert ex.execute(pay("p4")).executed


def test_executor_exposes_no_other_breaker_reset(env):
    ex, _, _, _ = env
    public = [n for n in dir(ex) if not n.startswith("_")]
    assert [n for n in public if "reset" in n] == ["reset_breaker"]


# ---- end to end (mock) ------------------------------------------------------------
def test_e2e_mock_allowed_held_and_refunds(env):
    ex, backend, clock, path = env
    # held then approved: new recipient
    first = pay("o1", 2_000)
    assert ex.execute(first).verdict is Verdict.HOLD
    res = ex.execute(first, ex.approve(first, "alice"))
    assert res.executed and res.transaction_id.startswith("mock_")
    # allowed: known recipient, under limit
    clock.t += 700
    assert ex.execute(pay("o2", 300)).executed
    # held then approved: over the $1,000 limit
    clock.t += 700
    big = pay("o3", 150_000)
    assert ex.execute(big).verdict is Verdict.HOLD
    assert ex.execute(big, ex.approve(big, "alice")).executed
    # refund over the order total is blocked
    clock.t += 700
    over = ex.execute(refund("f1", 2_001, 2_000), refund_of="o1")
    assert over.verdict is Verdict.BLOCK and "order total" in over.reason
    # lying about the order total is blocked
    lie = ex.execute(refund("f2", 2_500, 5_000), refund_of="o1")
    assert lie.verdict is Verdict.BLOCK and "ledger" in lie.reason
    # a valid partial refund works, then over-refunding the remainder is blocked
    assert ex.execute(refund("f3", 1_500, 2_000), refund_of="o1").executed
    clock.t += 700
    rest = ex.execute(refund("f4", 501, 2_000), refund_of="o1")
    assert rest.verdict is Verdict.BLOCK
    assert ex.execute(refund("f5", 1, 2_000), refund_of="unknown").verdict is Verdict.BLOCK
    assert backend.balance_cents == 2_000 + 300 + 150_000 - 1_500
    # every attempt was audited and the chain is intact
    lines = audit_lines(path)
    assert len(lines) == 10 and verify(path)
    assert any("txn=mock_" in l["reason"] for l in lines)


def test_no_stamp_ever_in_audit(env):
    ex, _, _, path = env
    r = pay("r1")
    stamp = ex.approve(r, "alice")
    ex.execute(pay("r1", 999), stamp)
    assert stamp not in path.read_text(encoding="utf-8")
