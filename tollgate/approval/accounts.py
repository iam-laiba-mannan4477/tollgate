"""The approver account: identity, password, sessions and the TOTP factor.

One approver account per deployment (Phase 3c). Enrolment runs once; after that the
password, authenticator and alert destination change only through a guarded settings
change (fresh code + cooling-off + owner notification, see service.py).

A Session is what a logged-in browser would hold. It proves "logged in" only. It is
NOT enough to approve: every approval also needs a fresh second-factor code.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from enum import Enum

from tollgate.approval.totp import MOCK_TOTP_SECRET_B32, TotpChecker, decode_secret, new_secret_b32
from tollgate.config import Mode

DRAFTER_NAMES = frozenset({"agent", "drafter", "bot", "ai", "assistant", "model"})
PBKDF2_ITERATIONS = 600_000
MAX_PBKDF2_ITERATIONS = 10_000_000
MIN_PASSWORD_LEN = 12


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
    def __init__(self, mode: Mode = Mode.MOCK, iterations: int = PBKDF2_ITERATIONS) -> None:
        self._mode = mode
        self._iterations = iterations
        self._lock = threading.Lock()
        self._name: str | None = None
        self._pw_hash: PasswordHash | None = None
        self._checker: TotpChecker | None = None
        self._sessions: set[bytes] = set()
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
            self._sessions.add(_token_hash(token))
            return Session(token, self._name, Role.APPROVER)

    def is_approver_session(self, session: object) -> bool:
        """A live session of the enrolled approver, with the APPROVER role. Fails closed."""
        if not isinstance(session, Session) or session.role is not Role.APPROVER:
            return False
        if not isinstance(session.token, str) or session.name != self._name:
            return False
        key = _token_hash(session.token)
        with self._lock:
            return any(hmac.compare_digest(key, s) for s in self._sessions)

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
