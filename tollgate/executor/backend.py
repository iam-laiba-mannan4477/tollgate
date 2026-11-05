"""Payment backends. This is the ONLY file in the project that imports braintree.

- MockBackend: in memory, fake ids, no keys. Always available.
- BraintreeBackend: sandbox only. Refuses to start in any other mode or if the
  gateway is not configured for the sandbox environment.

Errors fail closed: a failed or ambiguous call returns ok=False with a short
generic reason. Raw Braintree error bodies and keys are never returned or printed.
"""
from __future__ import annotations

import os
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Protocol

import braintree

from tollgate.config import Mode, get_mode, missing_sandbox_vars

SANDBOX_TEST_NONCE = "fake-valid-nonce"
MAX_REFERENCE_LEN = 64


class BackendError(Exception):
    """The backend cannot be used. Messages never contain key values."""


@dataclass(frozen=True)
class BackendResult:
    ok: bool
    transaction_id: str | None
    reason: str


class Backend(Protocol):
    def charge(self, amount_cents: int, reference: str) -> BackendResult: ...
    def refund(self, transaction_id: str, amount_cents: int) -> BackendResult: ...


def cents_to_decimal_str(amount_cents: int) -> str:
    """Exact conversion, no floats: 100 -> '1.00', 5 -> '0.05'."""
    if not isinstance(amount_cents, int) or isinstance(amount_cents, bool) or amount_cents <= 0:
        raise ValueError("amount_cents must be a positive int")
    return f"{amount_cents // 100}.{amount_cents % 100:02d}"


def _valid_amount(amount_cents: Any) -> bool:
    return isinstance(amount_cents, int) and not isinstance(amount_cents, bool) and amount_cents > 0


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_REFERENCE_LEN


# ---------------------------------------------------------------------------
class MockBackend:
    """Fake money in memory. Tracks charged and refunded amounts per transaction."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._charged: dict[str, int] = {}
        self._refunded: dict[str, int] = {}
        self.balance_cents = 0

    def charge(self, amount_cents: int, reference: str) -> BackendResult:
        if not _valid_amount(amount_cents) or not _valid_id(reference):
            return BackendResult(False, None, "invalid charge input")
        with self._lock:
            txn = "mock_" + secrets.token_hex(8)
            self._charged[txn] = amount_cents
            self._refunded[txn] = 0
            self.balance_cents += amount_cents
        return BackendResult(True, txn, "charged")

    def refund(self, transaction_id: str, amount_cents: int) -> BackendResult:
        if not _valid_amount(amount_cents) or not _valid_id(transaction_id):
            return BackendResult(False, None, "invalid refund input")
        with self._lock:
            if transaction_id not in self._charged:
                return BackendResult(False, None, "unknown transaction")
            remaining = self._charged[transaction_id] - self._refunded[transaction_id]
            if amount_cents > remaining:
                return BackendResult(False, None, "refund exceeds charge")
            self._refunded[transaction_id] += amount_cents
            self.balance_cents -= amount_cents
            refund_id = "mock_" + secrets.token_hex(8)
        return BackendResult(True, refund_id, "refunded")


# ---------------------------------------------------------------------------
def make_sandbox_gateway() -> braintree.BraintreeGateway:
    """Build a gateway hard-wired to the sandbox environment, from env variables."""
    if get_mode() is not Mode.SANDBOX:
        raise BackendError("Braintree backend requires TOLLGATE_MODE=sandbox")
    missing = missing_sandbox_vars()
    if missing:
        raise BackendError("missing sandbox variables: " + ", ".join(missing))
    return braintree.BraintreeGateway(
        braintree.Configuration(
            environment=braintree.Environment.Sandbox,
            merchant_id=os.environ["BRAINTREE_MERCHANT_ID"],
            public_key=os.environ["BRAINTREE_PUBLIC_KEY"],
            private_key=os.environ["BRAINTREE_PRIVATE_KEY"],
        )
    )


class BraintreeBackend:
    """Real Braintree calls, sandbox only."""

    def __init__(self, gateway: Any = None) -> None:
        if get_mode() is not Mode.SANDBOX:
            raise BackendError("Braintree backend requires TOLLGATE_MODE=sandbox")
        self._gateway = gateway if gateway is not None else make_sandbox_gateway()
        env = getattr(getattr(self._gateway, "config", None), "environment", None)
        if env is not braintree.Environment.Sandbox:
            raise BackendError("gateway is not configured for the sandbox environment")

    def charge(self, amount_cents: int, reference: str) -> BackendResult:
        if not _valid_amount(amount_cents) or not _valid_id(reference):
            return BackendResult(False, None, "invalid charge input")
        try:
            result = self._gateway.transaction.sale({
                "amount": cents_to_decimal_str(amount_cents),
                "payment_method_nonce": SANDBOX_TEST_NONCE,
                "order_id": reference,
                "options": {"submit_for_settlement": True},
            })
            if result.is_success:
                return BackendResult(True, str(result.transaction.id), "charged")
            return BackendResult(False, None, "charge declined by gateway")
        except Exception as exc:  # type name only: messages could echo config
            return BackendResult(False, None, f"charge error ({type(exc).__name__})")

    def refund(self, transaction_id: str, amount_cents: int) -> BackendResult:
        if not _valid_amount(amount_cents) or not _valid_id(transaction_id):
            return BackendResult(False, None, "invalid refund input")
        try:
            # Sandbox only: a transaction must be settled before it can be refunded.
            settled = self._gateway.testing.settle_transaction(transaction_id)
            if not settled.is_success:
                return BackendResult(False, None, "sandbox settle failed")
            result = self._gateway.transaction.refund(
                transaction_id, cents_to_decimal_str(amount_cents))
            if result.is_success:
                return BackendResult(True, str(result.transaction.id), "refunded")
            return BackendResult(False, None, "refund declined by gateway")
        except Exception as exc:
            return BackendResult(False, None, f"refund error ({type(exc).__name__})")
