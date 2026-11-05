import threading

import pytest

from tollgate.gate.models import Decision, Request, Verdict
from tollgate.gate.stamps import SpendResult, StampError, StampStore


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


HELD = Decision(Verdict.HOLD, "over auto limit")
REQ = Request(id="r1", type="pay", amount_cents=250_000, recipient="acct_new",
              via_agent=True, created_at=1000.0)


@pytest.fixture
def setup():
    clock = FakeClock()
    store = StampStore(clock=clock)
    return clock, store, store.issue(REQ, HELD, approver="alice")


def test_valid_stamp_works_once(setup):
    _, store, stamp = setup
    assert store.spend(stamp, 250_000, "acct_new") is SpendResult.OK
    assert store.spend(stamp, 250_000, "acct_new") is SpendResult.USED


def test_expired_stamp(setup):
    clock, store, stamp = setup
    clock.t += 300
    assert store.spend(stamp, 250_000, "acct_new") is SpendResult.EXPIRED


def test_stamp_just_before_expiry_works(setup):
    clock, store, stamp = setup
    clock.t += 299.9
    assert store.spend(stamp, 250_000, "acct_new") is SpendResult.OK


def test_wrong_amount_fails_and_burns(setup):
    _, store, stamp = setup
    assert store.spend(stamp, 250_001, "acct_new") is SpendResult.MISMATCH
    assert store.spend(stamp, 250_000, "acct_new") is SpendResult.USED


def test_wrong_recipient(setup):
    _, store, stamp = setup
    assert store.spend(stamp, 250_000, "acct_evil") is SpendResult.MISMATCH


@pytest.mark.parametrize("bad", ["made-up-stamp", "", None, 123, "x" * 1000])
def test_unknown_stamp(setup, bad):
    _, store, _ = setup
    assert store.spend(bad, 250_000, "acct_new") is SpendResult.UNKNOWN


def test_raw_stamp_not_stored(setup):
    _, store, stamp = setup
    assert stamp not in repr(store.__dict__)
    assert stamp.encode() not in b"".join(store._records.keys())


def test_stamps_are_random():
    store = StampStore(clock=FakeClock())
    assert len({store.issue(REQ, HELD, "alice") for _ in range(50)}) == 50


@pytest.mark.parametrize("decision", [Decision(Verdict.ALLOW, "ok"), Decision(Verdict.BLOCK, "no"), None])
def test_only_held_requests_get_stamps(decision):
    with pytest.raises(StampError):
        StampStore(clock=FakeClock()).issue(REQ, decision, "alice")


def test_approver_required_and_request_validated():
    store = StampStore(clock=FakeClock())
    with pytest.raises(StampError):
        store.issue(REQ, HELD, "  ")
    bad = Request(id="r2", type="pay", amount_cents=-1, recipient="a", via_agent=True, created_at=0)
    with pytest.raises(StampError):
        store.issue(bad, HELD, "alice")


def test_race_exactly_one_spend_succeeds():
    store = StampStore(clock=FakeClock())
    stamp = store.issue(REQ, HELD, "alice")
    barrier = threading.Barrier(50)
    results: list[SpendResult] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        r = store.spend(stamp, 250_000, "acct_new")
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 50
    assert results.count(SpendResult.OK) == 1
    assert results.count(SpendResult.USED) == 49
