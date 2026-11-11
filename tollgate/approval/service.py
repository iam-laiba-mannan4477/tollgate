"""Step-up approval service. The ONLY source of the grants the executor and desk need
before they issue a stamp for a HELD request.

authorize(session, code, item):
  1. approvals locked -> REFUSED
  2. not a live session of the enrolled approver (e.g. the agent) -> REFUSED
  3. second-factor code wrong, missing, replayed or expired -> REFUSED and counted;
     `max_failed_codes` failures in a row lock approvals, trip the breakers, log out
     every session and notify the owner
  4. too many approvals this hour -> REFUSED (item stays pending)
  5. per-recipient velocity, counting approvals still waiting -> BLOCK
  6. rolling 24 h cap, counting approvals still waiting -> BLOCK
  7. over `delay_over_cents`, or new recipient over `new_recipient_delay_over_cents`
     -> DELAYED: no grant yet; the owner is notified and may cancel
  8. otherwise GRANTED: a single-use grant bound to the exact request

release_due() hands out grants for waiting approvals whose delay has ended, then the
caller's release callback re-runs the Gate and re-checks the breaker before sending.

All times come from the injected clock (monotonic by default), never from the request.
If that clock ever goes backwards, approvals lock (fail closed). TOTP uses a separate
injected wall clock, because authenticator apps use real time.

Audit events never contain codes, secrets, passwords or grant tokens.
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from tollgate.approval.accounts import AccountError, ApproverAccount, check_name
from tollgate.approval.outbox import Outbox
from tollgate.approval.policy import ApprovalPolicy
from tollgate.approval.totp import new_secret_b32
from tollgate.gate.audit import AuditLog
from tollgate.gate.models import Request, validate_request
from tollgate.gate.rules import GateConfig

Clock = Callable[[], float]


class Status(str, Enum):
    GRANTED = "GRANTED"      # factor passed, no delay: grant attached
    DELAYED = "DELAYED"      # factor passed, cooling-off: grant comes from release_due()
    REFUSED = "REFUSED"      # try again later (bad code, rate limit, locked); item stays
    BLOCKED = "BLOCKED"      # final (cap, velocity, bad item); item should be dropped


@dataclass(frozen=True)
class ApprovalItem:
    """What the approver is approving. Built by trusted code (roles.py), not the agent."""
    item_id: str
    request: Request
    new_recipient: bool


@dataclass(frozen=True)
class Grant:
    """Single-use permission for the executor or desk to issue one stamp."""
    token: str
    request_id: str
    amount_cents: int
    recipient: str
    approver: str

    def __repr__(self) -> str:
        return f"Grant(request_id={self.request_id!r}, approver={self.approver!r}, token=<hidden>)"


@dataclass(frozen=True)
class AuthorizeResult:
    status: Status
    reason: str
    grant: Grant | None = None
    release_at: float | None = None


@dataclass
class _Waiting:
    item: ApprovalItem
    approver: str
    release_at: float
    release: Callable[[Grant], Any]
    state: str = "waiting"           # waiting | cancelled | released | blocked


@dataclass
class _Change:
    change_id: str
    kind: str
    value: Any
    approver: str
    release_at: float
    state: str = "waiting"           # waiting | cancelled | applied


@dataclass(frozen=True)
class ChangeResult:
    change_id: str | None
    applied_now: bool
    reason: str
    release_at: float | None = None
    new_secret_b32: str | None = None    # only for an authenticator change, shown once


CHANGE_KINDS = ("password", "authenticator", "alert_destination", "policy")
# Neutral labels: the audit log redacts any text containing words like "password".
_LABELS = {"password": "login credential", "authenticator": "authenticator",
           "alert_destination": "alert destination", "policy": "policy limit"}


def _hash(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8")).digest()


class ApprovalService:
    def __init__(self, account: ApproverAccount, audit_path: str | Path, outbox: Outbox, *,
                 clock: Clock = time.monotonic, wall_clock: Clock = time.time,
                 policy: ApprovalPolicy | None = None,
                 gate_config: GateConfig | None = None) -> None:
        self._account = account
        self._audit = AuditLog(audit_path, clock)
        self._outbox = outbox
        self._clock = clock
        self._wall = wall_clock
        self._policy = policy or ApprovalPolicy()
        self._gate = gate_config or GateConfig()
        self._lock = threading.Lock()
        self._breakers: list[Callable[[], None]] = []
        self._locked = False
        self._fails = 0
        self._last_now = float("-inf")
        self._approvals: list[tuple[float, int, str]] = []   # (time, cents, recipient)
        self._waiting: dict[str, _Waiting] = {}
        self._grants: dict[bytes, tuple[Grant, float]] = {}
        self._changes: dict[str, _Change] = {}
        self._seq = itertools.count(1)

    # ---- wiring and read-only views --------------------------------------------------
    def add_breaker(self, trip: Callable[[], None]) -> None:
        """Register a breaker to trip on lockout (tightening only)."""
        self._breakers.append(trip)

    @property
    def policy(self) -> ApprovalPolicy:
        return self._policy

    @property
    def locked(self) -> bool:
        return self._locked

    def waiting(self) -> list[tuple[str, float]]:
        """(item id, release time) of approvals still in their cooling-off window."""
        with self._lock:
            return [(w.item.item_id, w.release_at) for w in self._waiting.values()
                    if w.state == "waiting"]

    def committed_cents(self) -> int:
        """Approved value inside the rolling cap window, waiting approvals included."""
        with self._lock:
            return self._committed(self._clock())

    # ---- approvals -------------------------------------------------------------------
    def authorize(self, session: object, code: object, item: ApprovalItem,
                  release: Callable[[Grant], Any]) -> AuthorizeResult:
        with self._lock:
            result = self._authorize(session, code, item, release)
        self._log_result(item, result)
        return result

    def _authorize(self, session: object, code: object, item: ApprovalItem,
                   release: Callable[[Grant], Any]) -> AuthorizeResult:
        now = self._now()
        if self._locked:
            return AuthorizeResult(Status.REFUSED, "approvals locked: a person must unlock")
        if not isinstance(item, ApprovalItem) or validate_request(item.request):
            return AuthorizeResult(Status.BLOCKED, "invalid approval item")
        if not self._account.is_approver_session(session):
            return AuthorizeResult(Status.REFUSED, "not an approver session: refused")
        if not self._account.check_code(code, self._wall()):
            return self._factor_failed(item.item_id)
        self._fails = 0
        approver = str(self._account.name)
        problem = self._limit_problem(item.request, now)
        if problem is not None:
            return problem
        req = item.request
        self._approvals.append((now, req.amount_cents, req.recipient))
        if self._needs_delay(item):
            release_at = now + self._policy.cooling_off_seconds
            self._waiting[item.item_id] = _Waiting(item, approver, release_at, release)
            self._notify("approval_waiting",
                         f"{approver} approved {item.item_id}: {req.amount_cents} cents to "
                         f"{req.recipient}. It sends after a cooling-off wait unless you cancel.")
            return AuthorizeResult(Status.DELAYED, f"factor ok ({approver}); cooling-off "
                                   f"{self._policy.cooling_off_seconds}s, owner notified",
                                   release_at=release_at)
        grant = self._new_grant(req, approver, now)
        return AuthorizeResult(Status.GRANTED, f"factor ok ({approver}); granted", grant)

    def _limit_problem(self, req: Request, now: float) -> AuthorizeResult | None:
        hour = [a for a in self._approvals if a[0] > now - 3600]
        if len(hour) >= self._policy.approvals_per_hour:
            return AuthorizeResult(Status.REFUSED, "approval rate limit reached for this hour")
        window = now - self._gate.velocity_window_seconds
        to_recipient = sum(1 for t, _, r in self._approvals if r == req.recipient and t > window)
        if to_recipient >= self._gate.velocity_max_payments:
            return AuthorizeResult(Status.BLOCKED, "velocity: too many approvals to recipient")
        if self._committed(now) + req.amount_cents > self._policy.daily_cap_cents:
            return AuthorizeResult(Status.BLOCKED, "daily approval cap would be exceeded")
        return None

    def _committed(self, now: float) -> int:
        """Counted at approval time; cancelled or blocked approvals still count (stricter)."""
        start = now - self._policy.cap_window_seconds
        return sum(cents for t, cents, _ in self._approvals if t > start)

    def _needs_delay(self, item: ApprovalItem) -> bool:
        cents = item.request.amount_cents
        if cents > self._policy.delay_over_cents:
            return True
        return item.new_recipient and cents > self._policy.new_recipient_delay_over_cents

    def release_due(self) -> list[tuple[str, Any]]:
        """Release waiting approvals whose delay is over. Returns (item id, callback result)."""
        ready: list[tuple[_Waiting, Grant | None]] = []
        with self._lock:
            now = self._now()
            for w in self._waiting.values():
                if w.state != "waiting" or now < w.release_at:
                    continue
                if self._locked:
                    w.state = "blocked"
                    ready.append((w, None))
                else:
                    w.state = "released"
                    ready.append((w, self._new_grant(w.item.request, w.approver, now)))
        results = []
        for w, grant in ready:
            if grant is None:
                self._event(w.item.item_id, "BLOCK", "release blocked: approvals locked", w.item)
                results.append((w.item.item_id, None))
                continue
            self._event(w.item.item_id, "RELEASE", f"cooling-off over; releasing "
                        f"(approved by {w.approver})", w.item)
            results.append((w.item.item_id, w.release(grant)))
        return results

    def cancel(self, item_id: str, person: str) -> bool:
        """Owner cancels a waiting approval. Cancelling only tightens, so no code is needed."""
        name = check_name(person)
        with self._lock:
            w = self._waiting.get(item_id)
            if w is None or w.state != "waiting":
                return False
            w.state = "cancelled"
        self._event(item_id, "CANCEL", f"cancelled during cooling-off by {name}", w.item)
        self._notify("approval_cancelled", f"{item_id} was cancelled by {name}.")
        return True

    def redeem(self, grant: object, request: Request) -> str | None:
        """Used by the executor/desk: the approver's name if the grant is valid for exactly
        this request (single use, not expired), else None."""
        if not isinstance(grant, Grant) or not isinstance(grant.token, str):
            return None
        key = _hash(grant.token)
        with self._lock:
            found = next((k for k in self._grants if hmac.compare_digest(k, key)), None)
            if found is None:
                return None
            stored, expires = self._grants.pop(found)       # single use, even on mismatch
            if self._clock() >= expires or self._locked:
                return None
            same = (stored.request_id == request.id and stored.amount_cents ==
                    request.amount_cents and stored.recipient == request.recipient)
            return stored.approver if same else None

    # ---- lockout ---------------------------------------------------------------------
    def _factor_failed(self, item_id: str) -> AuthorizeResult:
        self._fails += 1
        if self._fails >= self._policy.max_failed_codes:
            self._lock_out(f"{self._fails} failed second-factor attempts")
            return AuthorizeResult(Status.REFUSED, "second factor failed: approvals locked, "
                                   "breaker tripped")
        return AuthorizeResult(Status.REFUSED, f"second factor failed "
                               f"({self._fails}/{self._policy.max_failed_codes})")

    def _lock_out(self, why: str) -> None:
        """Tighten everything. Caller holds the lock."""
        self._locked = True
        self._account.logout_all()
        for trip in self._breakers:
            try:
                trip()
            except Exception:
                pass                     # one broken hook must not stop the others
        self._audit.append(f"lockout-{next(self._seq)}", "LOCKOUT",
                           f"approvals locked, breaker tripped, sessions ended: {why}",
                           None, None)
        self._notify("lockout", f"Approvals locked: {why}. A person must unlock.")

    def unlock(self, person: str, reason: str) -> None:
        """Loosening: a named person unlocks approvals, with a reason (audited)."""
        name = check_name(person)
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("a reason is required to unlock approvals")
        with self._lock:
            self._locked = False
            self._fails = 0
            self._last_now = self._clock()
            self._audit.append(f"unlock-{next(self._seq)}", "UNLOCK",
                               f"approvals unlocked by {name}: {reason.strip()[:120]}",
                               None, None)

    def _now(self) -> float:
        """Read the injected clock. Going backwards is tampering: lock (fail closed)."""
        now = self._clock()
        if now < self._last_now:
            if not self._locked:
                self._lock_out("clock went backwards")
            return self._last_now
        self._last_now = now
        return now

    # ---- guarded settings changes ----------------------------------------------------
    def request_change(self, session: object, code: object, kind: str, value: Any = None,
                       field: str | None = None) -> ChangeResult:
        """Change the approver's password, authenticator, alert destination or a policy limit.

        Needs a live approver session AND a fresh code. Loosening changes wait out
        `settings_cooling_off_seconds` and notify the owner; tightening a limit applies now.
        """
        with self._lock:
            now = self._now()
            if self._locked:
                return ChangeResult(None, False, "approvals locked: a person must unlock")
            if kind not in CHANGE_KINDS:
                return ChangeResult(None, False, "unknown change kind")
            if not self._account.is_approver_session(session):
                return ChangeResult(None, False, "not an approver session: refused")
            if not self._account.check_code(code, self._wall()):
                failed = self._factor_failed(f"change-{kind}")
                return ChangeResult(None, False, failed.reason)
            self._fails = 0
            return self._queue_change(kind, value, field, now)

    def _queue_change(self, kind: str, value: Any, field: str | None, now: float) -> ChangeResult:
        approver = str(self._account.name)
        cid = f"change-{next(self._seq)}"
        secret = None
        if kind == "policy":
            if not isinstance(field, str) or not isinstance(value, int) or isinstance(value, bool):
                return ChangeResult(None, False, "policy change needs a field and an int value")
            try:
                self._policy.with_value(field, value)
            except ValueError:
                return ChangeResult(None, False, "invalid policy value")
            if not self._policy.is_loosening(field, value):
                self._policy = self._policy.with_value(field, value)
                self._audit.append(cid, "TIGHTEN", f"policy {field} tightened by {approver}",
                                   value, None)
                return ChangeResult(cid, True, "tightened: applied now")
            value = (field, value)
        elif kind == "authenticator":
            secret = new_secret_b32()
            value = secret
        elif not isinstance(value, str) or not value.strip():
            return ChangeResult(None, False, "a new value is required")
        release_at = now + self._policy.settings_cooling_off_seconds
        self._changes[cid] = _Change(cid, kind, value, approver, release_at)
        label = f"policy {value[0]} -> {value[1]}" if kind == "policy" else _LABELS[kind]
        self._audit.append(cid, "CHANGE", f"settings change requested by {approver}: {label}; "
                           f"applies after cooling-off unless cancelled", None, None)
        text = (f"{approver} asked to change: {label}. It applies after "
                f"{self._policy.settings_cooling_off_seconds}s unless you cancel {cid}.")
        self._notify("settings_change", text)
        if kind == "alert_destination":
            self._outbox.notify(str(value), "settings_change", text)    # tell the new one too
        return ChangeResult(cid, False, "queued: cooling-off, owner notified", release_at, secret)

    def verify_step_up(self, session: object, code: object, purpose: str) -> tuple[bool, str]:
        """Check a live approver session AND a fresh code for a loosening action outside
        approvals (the Sentinel page's breaker reset). Same rules as request_change: refused
        while locked; a wrong code counts toward the same lockout."""
        label = str(purpose)[:40] or "step-up"
        with self._lock:
            self._now()
            if self._locked:
                return False, "approvals locked: a person must unlock"
            if not self._account.is_approver_session(session):
                return False, "not an approver session: refused"
            if not self._account.check_code(code, self._wall()):
                failed = self._factor_failed(label)
                self._audit.append(f"{label}-{next(self._seq)}", "FACTORFAIL",
                                   f"{label}: {failed.reason}", None, None)
                return False, failed.reason
            self._fails = 0
            return True, "factor ok"

    def notify_owner(self, kind: str, text: str) -> None:
        """Send one owner notice through the outbox (no secrets in `text`)."""
        self._notify(kind, text)

    def cancel_change(self, change_id: str, person: str) -> bool:
        name = check_name(person)
        with self._lock:
            c = self._changes.get(change_id)
            if c is None or c.state != "waiting":
                return False
            c.state = "cancelled"
            self._audit.append(change_id, "CANCEL", f"settings change cancelled by {name}",
                               None, None)
        self._notify("settings_cancelled", f"{change_id} was cancelled by {name}.")
        return True

    def apply_due_changes(self) -> list[str]:
        """Apply waiting changes whose cooling-off is over. Nothing applies while locked."""
        applied = []
        with self._lock:
            now = self._now()
            if self._locked:
                return []
            for c in self._changes.values():
                if c.state == "waiting" and now >= c.release_at:
                    self._apply(c)
                    c.state = "applied"
                    applied.append(c.change_id)
                    self._audit.append(c.change_id, "CHANGED",
                                       f"settings change applied: {_LABELS[c.kind]}", None, None)
        return applied

    def _apply(self, c: _Change) -> None:
        if c.kind == "password":
            self._account._apply_password(c.value)
        elif c.kind == "authenticator":
            self._account._apply_reenroll(c.value)
        elif c.kind == "alert_destination":
            self._account._apply_destination(c.value)
        elif c.kind == "policy":
            self._policy = self._policy.with_value(*c.value)
        c.value = None                    # drop the new password/secret from memory

    def tighten(self, field: str, value: int, by: str) -> bool:
        """Tighten one policy limit at once, no code needed (Sentinel may call this).
        Refuses anything that would loosen."""
        name = str(by)[:40] or "unknown"
        with self._lock:
            try:
                candidate = self._policy.with_value(field, value)
            except (ValueError, TypeError):
                return False
            if self._policy.is_loosening(field, value):
                return False
            self._policy = candidate
            self._audit.append(f"tighten-{next(self._seq)}", "TIGHTEN",
                               f"policy {field} tightened by {name}", value, None)
            return True

    def record(self, event_id: str, decision: str, reason: str, amount_cents: object,
               recipient: object) -> None:
        """Write one approval-related audit event (used for blocks at release time)."""
        self._audit.append(str(event_id), decision, reason, amount_cents, recipient)

    # ---- helpers ---------------------------------------------------------------------
    def _new_grant(self, req: Request, approver: str, now: float) -> Grant:
        grant = Grant(secrets.token_urlsafe(32), req.id, req.amount_cents, req.recipient,
                      approver)
        self._grants[_hash(grant.token)] = (grant, now + self._policy.grant_lifetime_seconds)
        return grant

    def _notify(self, kind: str, text: str) -> None:
        self._outbox.notify(self._account.alert_destination or "owner (not set)", kind, text)

    def _log_result(self, item: Any, result: AuthorizeResult) -> None:
        decision = {Status.GRANTED: "GRANT", Status.DELAYED: "DELAY",
                    Status.REFUSED: "REFUSED", Status.BLOCKED: "BLOCK"}[result.status]
        if "second factor failed" in result.reason:
            decision = "FACTORFAIL"
        self._event(getattr(item, "item_id", "unknown"), decision, "approval: " + result.reason,
                    item if isinstance(item, ApprovalItem) else None)

    def _event(self, event_id: str, decision: str, reason: str,
               item: ApprovalItem | None) -> None:
        req = item.request if item is not None else None
        self._audit.append(str(event_id), decision, reason,
                           getattr(req, "amount_cents", None), getattr(req, "recipient", None))


__all__ = ["AccountError", "ApprovalItem", "ApprovalService", "AuthorizeResult",
           "ChangeResult", "Grant", "Status"]
