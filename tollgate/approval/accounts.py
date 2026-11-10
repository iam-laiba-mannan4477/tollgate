"""The approver account: identity, password, sessions and the TOTP factor.

One approver account per deployment (Phase 3c). Enrolment runs once; after that the
password, authenticator and alert destination change only through a guarded settings
change (fresh code + cooling-off + owner notification, see service.py).

A Session is what a logged-in browser would hold. It proves "logged in" only. It is
NOT enough to approve: every approval also needs a fresh second-factor code.

Sessions expire (Phase 3d): 1 hour after login at most, and after 15 minutes without use.
Times come from an injected monotonic clock. An expired session is deleted, not renewed.

Enrolment can run in two steps (Phase 3d web setup): `begin_enroll` makes a secret for the
QR code, and `confirm_enroll` enrols only once the first code from the app matches.
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

from tollgate.approval.totp import MOCK_TOTP_SECRET_B32, TotpChecker, decode_secret, new_secret_b32
from tollgate.config import Mode

DRAFTER_NAMES = frozenset({"agent", "drafter", "bot", "ai", "assistant", "model"})
PBKDF2_ITERATIONS = 600_000
MAX_PBKDF2_ITERATIONS = 10_000_000
MIN_PASSWORD_LEN = 12
SESSION_LIFETIME_SECONDS = 3_600      # 1 hour after login, however active
SESSION_IDLE_SECONDS = 900            # 15 minutes without use
PENDING_ENROLL_SECONDS = 600          # a QR setup must be confirmed within 10 minutes


class Role(str, Enum):
    APPROVER = "approver"
    AGENT = "agent"


class AccountError(PermissionError):
    """Account problem. Messages never contain passwords, secrets or codes."""


@dataclass(frozen=True)
class Session:
    """A logged-in session. `token` is random; only its hash is stored server side."""
    token: str
    name: str
    role: Role

    def __repr__(self) -> str:
        return f"Session(name={self.name!r}, role={self.role.value}, token=<hidden>)"


@dataclass
class _SessionTimes:
    created: float
    last_seen: float


@dataclass
class _PendingEnroll:
    name: str
    pw_hash: "PasswordHash"
    secret_b32: str
    alert_destination: str
    binding: bytes                    # hash of the setup cookie that started it
    expires: float


def _hash_password(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


@dataclass(frozen=True)
class PasswordHash:
    """A stored password hash. Keeps its own round count so older hashes still verify."""
    iterations: int
    salt: bytes
    digest: bytes

    def __repr__(self) -> str:
        return f"PasswordHash(iterations={self.iterations}, digest=<hidden>)"


def make_password_hash(password: str, iterations: int = PBKDF2_ITERATIONS) -> PasswordHash:
    salt = secrets.token_bytes(16)
    return PasswordHash(iterations, salt, _hash_password(password, salt, iterations))


def verify_password(password: object, stored: object) -> bool:
    """True only for a matching password. Any malformed input fails closed (False)."""
    if not isinstance(password, str) or not isinstance(stored, PasswordHash):
        return False
    rounds = stored.iterations
    if not isinstance(rounds, int) or isinstance(rounds, bool):
        return False
    if not 1 <= rounds <= MAX_PBKDF2_ITERATIONS or not stored.salt:
        return False
    attempt = _hash_password(password, stored.salt, rounds)
    return hmac.compare_digest(attempt, stored.digest)


def _token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def check_name(name: object) -> str:
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 64:
        raise AccountError("a named person is required")
    if name.strip().lower() in DRAFTER_NAMES:
        raise AccountError("the agent role cannot be an approver")
    return name.strip()


def _check_password(password: object) -> str:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise AccountError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    return password


class ApproverAccount:
    def __init__(self, mode: Mode = Mode.MOCK, iterations: int = PBKDF2_ITERATIONS, *,
                 clock: Callable[[], float] = time.monotonic,
                 session_lifetime: float = SESSION_LIFETIME_SECONDS,
                 session_idle: float = SESSION_IDLE_SECONDS) -> None:
        self._mode = mode
        self._iterations = iterations
        self._clock = clock
        self._lifetime = session_lifetime
        self._idle = session_idle
        self._pending: _PendingEnroll | None = None
        self._lock = threading.Lock()
        self._name: str | None = None
        self._pw_hash: PasswordHash | None = None
        self._checker: TotpChecker | None = None
        self._sessions: dict[bytes, _SessionTimes] = {}
        self.alert_destination = ""

    def __repr__(self) -> str:
        return f"ApproverAccount(name={self._name!r}, enrolled={self.enrolled})"

    @property
    def enrolled(self) -> bool:
        return self._name is not None

    @property
    def name(self) -> str | None:
        return self._name

    # ---- setup (once) ------------------------------------------------------------------
    def enroll(self, name: str, password: str, alert_destination: str,
               secret_b32: str | None = None) -> str:
        """First-time setup. Returns the base32 secret ONCE (for the authenticator app).

        Refused once enrolled: re-enrolment goes through a guarded settings change.
        """
        with self._lock:
            if self.enrolled:
                raise AccountError("already enrolled: changes need the current code")
            clean = check_name(name)
            secret = self._pick_secret(secret_b32)
            self._set_password(_check_password(password))
            self._checker = TotpChecker(decode_secret(secret))
            self.alert_destination = _check_destination(alert_destination)
            self._name = clean
            return secret

    def begin_enroll(self, name: str, password: str, alert_destination: str, binding: str,
                     secret_b32: str | None = None) -> str:
        """Step 1 of web setup: check the inputs and return a new secret for the QR code.

        Nothing is enrolled yet. `binding` ties the setup to one browser (its setup cookie).
        """
        with self._lock:
            if self.enrolled:
                raise AccountError("already enrolled: changes need the current code")
            clean = check_name(name)
            pw_hash = make_password_hash(_check_password(password), self._iterations)
            secret = self._pick_secret(secret_b32)
            self._pending = _PendingEnroll(clean, pw_hash, secret,
                                           _check_destination(alert_destination),
                                           _token_hash(binding),
                                           self._clock() + PENDING_ENROLL_SECONDS)
            return secret

    def confirm_enroll(self, code: object, binding: object, now_wall: float) -> bool:
        """Step 2: enrol only if the first code from the app matches. Fails closed."""
        with self._lock:
            p = self._pending
            if self.enrolled or p is None or not isinstance(binding, str):
                return False
            if self._clock() >= p.expires:
                self._pending = None
                return False
            if not hmac.compare_digest(_token_hash(binding), p.binding):
                return False
            checker = TotpChecker(decode_secret(p.secret_b32))
            if not checker.check(code, now_wall):
                return False
            self._name, self._pw_hash, self._checker = p.name, p.pw_hash, checker
            self.alert_destination = p.alert_destination
            self._pending = None
            return True

    def _pick_secret(self, secret_b32: str | None) -> str:
        if secret_b32 is None:
            return new_secret_b32()
        if secret_b32 == MOCK_TOTP_SECRET_B32 and self._mode is not Mode.MOCK:
            raise AccountError("the fake mock secret is refused outside mock mode")
        decode_secret(secret_b32)
        return secret_b32

    # ---- sessions ----------------------------------------------------------------------
    def login(self, name: str, password: str) -> Session:
        with self._lock:
            if not self.enrolled or not isinstance(password, str) or name != self._name:
                raise AccountError("login failed")
            if not verify_password(password, self._pw_hash):
                raise AccountError("login failed")
            token = secrets.token_urlsafe(32)
            now = self._clock()
            self._sessions[_token_hash(token)] = _SessionTimes(now, now)
            return Session(token, self._name, Role.APPROVER)

    def is_approver_session(self, session: object) -> bool:
        """A live, unexpired session of the enrolled approver, APPROVER role. Fails closed.

        Each successful check counts as use and resets the idle timer.
        """
        if not isinstance(session, Session) or session.role is not Role.APPROVER:
            return False
        if not isinstance(session.token, str) or session.name != self._name:
            return False
        key = _token_hash(session.token)
        with self._lock:
            found = next((k for k in self._sessions if hmac.compare_digest(key, k)), None)
            if found is None:
                return False
            times, now = self._sessions[found], self._clock()
            if now - times.created >= self._lifetime or now - times.last_seen >= self._idle:
                del self._sessions[found]
                return False
            times.last_seen = now
            return True

    def logout(self, session: object) -> None:
        """End one session. Unknown sessions are ignored."""
        if isinstance(session, Session) and isinstance(session.token, str):
            key = _token_hash(session.token)
            with self._lock:
                for k in [k for k in self._sessions if hmac.compare_digest(key, k)]:
                    del self._sessions[k]

    def code_used_in_current_step(self, now_wall: float) -> bool:
        """True if this 30-second step's code was already used (demo page hint only)."""
        checker = self._checker
        return checker is not None and checker.step_used(now_wall)

    def logout_all(self) -> None:
        with self._lock:
            self._sessions.clear()

    # ---- second factor -----------------------------------------------------------------
    def check_code(self, code: object, now: float) -> bool:
        checker = self._checker
        return checker is not None and checker.check(code, now)

    # ---- applied ONLY by the service after a guarded change ------------------------------
    def _apply_password(self, password: str) -> None:
        with self._lock:
            self._set_password(_check_password(password))
            self._sessions.clear()              # old sessions die with the old password

    def _apply_reenroll(self, secret_b32: str) -> None:
        with self._lock:
            self._checker = TotpChecker(decode_secret(self._pick_secret(secret_b32)))
            self._sessions.clear()

    def _apply_destination(self, destination: str) -> None:
        self.alert_destination = _check_destination(destination)

    def _set_password(self, password: str) -> None:
        self._pw_hash = make_password_hash(password, self._iterations)


def _check_destination(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise AccountError("an alert destination is required")
    return value.strip()
