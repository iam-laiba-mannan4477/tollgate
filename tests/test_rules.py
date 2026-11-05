import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tollgate.gate.models import Request, Verdict
from tollgate.gate.rules import GateConfig, GateState, evaluate

CFG = GateConfig()
KNOWN = frozenset({"acct_known"})


def req(**kw):
    base = dict(id="r1", type="pay", amount_cents=500, recipient="acct_known",
                via_agent=True, created_at=1000.0)
    base.update(kw)
    return Request(**base)


def state(**kw):
    base = dict(now=1000.0, known_recipients=KNOWN)
    base.update(kw)
    return GateState(**base)


def test_allow_small_known():
    assert evaluate(req(), state(), CFG).verdict is Verdict.ALLOW


def test_breaker_open_blocks():
    d = evaluate(req(), state(breaker_open=True), CFG)
    assert d.verdict is Verdict.BLOCK and "breaker" in d.reason


def test_direct_call_blocks():
    d = evaluate(req(via_agent=False), state(), CFG)
    assert d.verdict is Verdict.BLOCK and "approval path" in d.reason


def test_refund_over_order_total_blocks():
    d = evaluate(req(type="refund", amount_cents=901, order_total_cents=900), state(), CFG)
    assert d.verdict is Verdict.BLOCK and "order total" in d.reason


def test_refund_within_total_allowed():
    d = evaluate(req(type="refund", amount_cents=900, order_total_cents=900), state(), CFG)
    assert d.verdict is Verdict.ALLOW


def test_third_payment_in_window_blocks_and_flags_breaker():
    recent = (("acct_known", 500.0), ("acct_known", 900.0))
    d = evaluate(req(), state(recent_payments=recent), CFG)
    assert d.verdict is Verdict.BLOCK and d.trip_breaker


def test_old_payments_outside_window_do_not_count():
    recent = (("acct_known", 300.0), ("acct_known", 399.0))  # older than 600s
    assert evaluate(req(), state(recent_payments=recent), CFG).verdict is Verdict.ALLOW


def test_other_recipients_do_not_count():
    recent = (("acct_other", 900.0), ("acct_other", 950.0))
    assert evaluate(req(), state(recent_payments=recent), CFG).verdict is Verdict.ALLOW


def test_over_limit_holds():
    d = evaluate(req(amount_cents=100_001), state(), CFG)
    assert d.verdict is Verdict.HOLD and "limit" in d.reason


def test_exactly_limit_allowed():
    assert evaluate(req(amount_cents=100_000), state(), CFG).verdict is Verdict.ALLOW


def test_new_recipient_holds():
    d = evaluate(req(recipient="acct_new"), state(), CFG)
    assert d.verdict is Verdict.HOLD and "new recipient" in d.reason


@pytest.mark.parametrize("amount", [0, -5, 2.5, "500", None, True, 10**20])
def test_bad_amount_blocks(amount):
    assert evaluate(req(amount_cents=amount), state(), CFG).verdict is Verdict.BLOCK


@pytest.mark.parametrize("bad", [None, "pay", 42, {"id": "x"}])
def test_non_request_blocks(bad):
    assert evaluate(bad, state(), CFG).verdict is Verdict.BLOCK


def test_bad_state_or_config_blocks():
    assert evaluate(req(), None, CFG).verdict is Verdict.BLOCK
    assert evaluate(req(), state(), {"auto_limit_cents": 10**9}).verdict is Verdict.BLOCK


def test_broken_state_fails_closed():
    broken = state(recent_payments="not-a-list-of-pairs")
    assert evaluate(req(), broken, CFG).verdict is Verdict.BLOCK


def test_truthy_non_bool_breaker_blocks():
    assert evaluate(req(), state(breaker_open="no"), CFG).verdict is Verdict.BLOCK


@pytest.mark.parametrize("kw", [dict(auto_limit_cents=0), dict(stamp_lifetime_seconds=301),
                                dict(velocity_window_seconds=-1), dict(auto_limit_cents=1.5)])
def test_config_rejects_unsafe_values(kw):
    with pytest.raises(ValueError):
        GateConfig(**kw)


# ---- property test -------------------------------------------------------
recipients = st.sampled_from(["acct_known", "acct_new", "acct_x", ""])
amounts = st.one_of(st.integers(min_value=-10**6, max_value=10**8),
                    st.floats(allow_nan=True), st.none(), st.text(max_size=5))


@settings(max_examples=500)
@given(amount=amounts, recipient=recipients, via_agent=st.one_of(st.booleans(), st.none()),
       rtype=st.sampled_from(["pay", "refund", "other"]),
       total=st.one_of(st.none(), st.integers(min_value=-10, max_value=10**8)),
       breaker=st.booleans())
def test_never_allow_over_limit_new_recipient_or_no_path(amount, recipient, via_agent,
                                                         rtype, total, breaker):
    r = req(amount_cents=amount, recipient=recipient, via_agent=via_agent,
            type=rtype, order_total_cents=total)
    d = evaluate(r, state(breaker_open=breaker), CFG)
    if d.verdict is Verdict.ALLOW:
        assert isinstance(amount, int) and 0 < amount <= CFG.auto_limit_cents
        assert recipient in KNOWN
        assert via_agent is True
        assert breaker is False
