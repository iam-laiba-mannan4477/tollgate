from types import SimpleNamespace

import braintree
import pytest

from tollgate.executor.backend import (BackendError, BraintreeBackend, MockBackend,
                                       cents_to_decimal_str)


@pytest.mark.parametrize("cents,text", [(1, "0.01"), (5, "0.05"), (100, "1.00"),
                                        (123456, "1234.56"), (10_000_000, "100000.00")])
def test_cents_to_decimal_exact(cents, text):
    assert cents_to_decimal_str(cents) == text


@pytest.mark.parametrize("bad", [0, -1, 1.5, True, "100"])
def test_cents_to_decimal_rejects_bad(bad):
    with pytest.raises(ValueError):
        cents_to_decimal_str(bad)


def test_mock_charge_and_refund():
    m = MockBackend()
    c = m.charge(500, "r1")
    assert c.ok and c.transaction_id.startswith("mock_") and m.balance_cents == 500
    assert m.refund(c.transaction_id, 300).ok
    assert not m.refund(c.transaction_id, 201).ok      # only 200 left
    assert not m.refund("mock_unknown", 1).ok
    assert not m.charge(0, "r2").ok
    assert m.balance_cents == 200


def test_braintree_refuses_outside_sandbox(monkeypatch):
    monkeypatch.setenv("TOLLGATE_MODE", "mock")
    with pytest.raises(BackendError):
        BraintreeBackend(gateway=object())


def test_braintree_refuses_non_sandbox_gateway(monkeypatch):
    monkeypatch.setenv("TOLLGATE_MODE", "sandbox")
    prod = SimpleNamespace(config=SimpleNamespace(environment=braintree.Environment.Production))
    with pytest.raises(BackendError):
        BraintreeBackend(gateway=prod)


def test_braintree_missing_keys_refuses(monkeypatch):
    monkeypatch.setenv("TOLLGATE_MODE", "sandbox")
    for name in ("BRAINTREE_MERCHANT_ID", "BRAINTREE_PUBLIC_KEY", "BRAINTREE_PRIVATE_KEY"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(BackendError):
        BraintreeBackend()


class FakeGateway:
    """Records calls; no network. Can be told to raise or decline."""

    def __init__(self, mode="ok"):
        self.config = SimpleNamespace(environment=braintree.Environment.Sandbox)
        self.calls = []
        self.mode = mode
        self.transaction = SimpleNamespace(sale=self._sale, refund=self._refund)
        self.testing = SimpleNamespace(settle_transaction=self._settle)

    def _result(self, txn_id):
        if self.mode == "raise":
            raise RuntimeError("SECRET-BODY private_key=abc")
        return SimpleNamespace(is_success=self.mode == "ok",
                               transaction=SimpleNamespace(id=txn_id))

    def _sale(self, params):
        self.calls.append(("sale", params))
        return self._result("bt_sale1")

    def _settle(self, txn):
        self.calls.append(("settle", txn))
        return self._result(txn)

    def _refund(self, txn, amount):
        self.calls.append(("refund", txn, amount))
        return self._result("bt_ref1")


@pytest.fixture
def sandbox_env(monkeypatch):
    monkeypatch.setenv("TOLLGATE_MODE", "sandbox")


def test_braintree_charge_params(sandbox_env):
    gw = FakeGateway()
    r = BraintreeBackend(gateway=gw).charge(100, "req-1")
    assert r.ok and r.transaction_id == "bt_sale1"
    assert gw.calls == [("sale", {"amount": "1.00", "payment_method_nonce": "fake-valid-nonce",
                                  "order_id": "req-1",
                                  "options": {"submit_for_settlement": True}})]


def test_braintree_refund_settles_first(sandbox_env):
    gw = FakeGateway()
    r = BraintreeBackend(gateway=gw).refund("bt_sale1", 100)
    assert r.ok
    assert gw.calls == [("settle", "bt_sale1"), ("refund", "bt_sale1", "1.00")]


@pytest.mark.parametrize("mode", ["decline", "raise"])
def test_braintree_errors_fail_closed_without_details(sandbox_env, mode):
    b = BraintreeBackend(gateway=FakeGateway(mode))
    for r in (b.charge(100, "req-1"), b.refund("bt_sale1", 100)):
        assert not r.ok and r.transaction_id is None
        assert "SECRET" not in r.reason and "private_key" not in r.reason
