import pytest

from tollgate.gate.breaker import CircuitBreaker
from tollgate.gate.models import MAX_AMOUNT_CENTS, Request, validate_request


def make(**kw):
    base = dict(id="r1", type="pay", amount_cents=500, recipient="acct_1",
                via_agent=True, created_at=0.0)
    base.update(kw)
    return Request(**base)


def test_good_request_has_no_problems():
    assert validate_request(make()) == []


@pytest.mark.parametrize("amount", [0, -1, 1.5, "100", True, None, MAX_AMOUNT_CENTS + 1, 10**30])
def test_bad_amounts_rejected(amount):
    assert "bad amount_cents" in validate_request(make(amount_cents=amount))


@pytest.mark.parametrize("recipient", ["", None, "a" * 129, "acct 1", "x;rm -rf", 5])
def test_bad_recipients_rejected(recipient):
    assert "bad recipient" in validate_request(make(recipient=recipient))


def test_refund_needs_order_total():
    assert "bad order_total_cents" in validate_request(make(type="refund"))
    assert validate_request(make(type="refund", order_total_cents=900)) == []


def test_unknown_type_and_non_request():
    assert "bad type" in validate_request(make(type="withdraw"))
    assert validate_request({"id": "r1"}) == ["not a Request"]


def test_breaker_flag():
    b = CircuitBreaker()
    assert not b.is_open
    b.trip()
    assert b.is_open
    b.reset_by_person()
    assert not b.is_open
