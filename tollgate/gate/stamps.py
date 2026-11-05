"""Approval stamps: a person approves a HELD request and receives a one-time stamp.

- The raw stamp is returned once and never stored; only its SHA-256 hash is kept.
- A stamp is bound to one exact amount and recipient and expires after the
  configured lifetime (max 5 minutes).
- Spending is atomic under a lock, so two threads cannot spend one stamp.
- Any failed spend attempt with a known stamp (wrong amount/recipient) burns it.
  That is the stricter choice: a mismatched attempt is treated as suspicious.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from tollgate.gate.models import Decision, Request, Verdict, validate_request
from tollgate.gate.rules import STAMP_LIFETIME_MAX_SECONDS, GateConfig

Clock = Callable[[], float]


class SpendResult(str, Enum):
    OK = "OK"
    UNKNOWN = "UNKNOWN"
    EXPIRED = "EXPIRED"
    USED = "USED"
    MISMATCH = "MISMATCH"


class StampError(Exception):
    """Raised when a stamp cannot be issued. Never contains a stamp value."""


@dataclass
class _Record:
    request_id: str
    binding: bytes          # hash of (amount, recipient)
    expires_at: float
    used: bool = False


def _hash(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8")).digest()


def _binding(amount_cents: int, recipient: str) -> bytes:
    return _hash(f"{amount_cents}|{recipient}")


class StampStore:
    def __init__(self, config: GateConfig | None = None, clock: Clock = time.monotonic) -> None:
        self._config = config or GateConfig()
        self._clock = clock
        self._lock = threading.Lock()
        self._records: dict[bytes, _Record] = {}

    def issue(self, request: Request, decision: Decision, approver: str) -> str:
        """Approve a HELD request. Returns the raw stamp (shown once, never stored)."""
        if not isinstance(decision, Decision) or decision.verdict is not Verdict.HOLD:
            raise StampError("only HELD requests can be approved")
        if validate_request(request):
            raise StampError("request is invalid")
        if not isinstance(approver, str) or not approver.strip():
            raise StampError("an approver is required")
        lifetime = min(self._config.stamp_lifetime_seconds, STAMP_LIFETIME_MAX_SECONDS)
        stamp = secrets.token_urlsafe(32)
        record = _Record(request.id, _binding(request.amount_cents, request.recipient),
                         self._clock() + lifetime)
        with self._lock:
            self._records[_hash(stamp)] = record
        return stamp

    def spend(self, stamp: object, amount_cents: object, recipient: object,
              request_id: object = None) -> SpendResult:
        """Use a stamp once. Fails closed: anything odd returns a non-OK result.

        If `request_id` is given (the executor always gives it), it must match the
        request the stamp was issued for.
        """
        if not isinstance(stamp, str) or not stamp or len(stamp) > 256:
            return SpendResult.UNKNOWN
        key = _hash(stamp)
        attempt = _binding(amount_cents, recipient)  # type: ignore[arg-type]
        with self._lock:
            record = self._find(key)
            if record is None:
                return SpendResult.UNKNOWN
            if record.used:
                return SpendResult.USED
            record.used = True  # burn first: every outcome below consumes the stamp
            if self._clock() >= record.expires_at:
                return SpendResult.EXPIRED
            if not hmac.compare_digest(record.binding, attempt):
                return SpendResult.MISMATCH
            if request_id is not None and request_id != record.request_id:
                return SpendResult.MISMATCH
            return SpendResult.OK

    def _find(self, key: bytes) -> _Record | None:
        """Constant-time comparison of the stamp hash against each stored hash."""
        found = None
        for stored, record in self._records.items():
            if hmac.compare_digest(stored, key):
                found = record
        return found
