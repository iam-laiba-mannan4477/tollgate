"""Signed session cookies and CSRF tokens. Standard library only.

Cookie value = "<random token>.<HMAC-SHA256 signature>". The cookie holds nothing else:
name, role and expiry live on the server (tollgate/approval/accounts.py), so logout,
expiry and lockout end a session for real.

CSRF: every form carries HMAC(key, "csrf:" + cookie token). Before login, a random
"pre-session" cookie plays the same role, so the login and setup forms are covered too.
All comparisons are constant time. Anything odd -> None / False (fail closed).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading

from tollgate.approval.accounts import ApproverAccount, Role, Session

MAX_COOKIE_CHARS = 200


def _sign(key: bytes, purpose: str, token: str) -> str:
    mac = hmac.new(key, f"{purpose}:{token}".encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")


class CookieSigner:
    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("session key too short")
        self.__key = key

    def __repr__(self) -> str:
        return "CookieSigner(key=<hidden>)"

    def seal(self, token: str) -> str:
        return f"{token}.{_sign(self.__key, 'cookie', token)}"

    def open(self, value: object) -> str | None:
        """The token inside a correctly signed cookie, else None."""
        if not isinstance(value, str) or not 0 < len(value) <= MAX_COOKIE_CHARS:
            return None
        token, dot, sig = value.rpartition(".")
        if not dot or not token:
            return None
        good = _sign(self.__key, "cookie", token)
        return token if hmac.compare_digest(sig.encode(), good.encode()) else None

    def csrf_for(self, token: str) -> str:
        return _sign(self.__key, "csrf", token)

    def csrf_ok(self, token: str | None, submitted: object) -> bool:
        if not token or not isinstance(submitted, str) or len(submitted) > 100:
            return False
        return hmac.compare_digest(submitted.encode(), self.csrf_for(token).encode())


def new_pre_token() -> str:
    return secrets.token_urlsafe(32)


class WebSessions:
    """Maps cookie tokens to account Sessions. Validity is always re-checked with the
    account (expiry, lockout, logout), never trusted from this table alone."""

    def __init__(self, account: ApproverAccount) -> None:
        self._account = account
        self._lock = threading.Lock()
        self._by_token: dict[str, Session] = {}

    def add(self, session: Session) -> None:
        with self._lock:
            self._by_token[session.token] = session

    def resolve(self, token: str | None) -> Session | None:
        if not token:
            return None
        with self._lock:
            session = self._by_token.get(token)
        if session is None or session.role is not Role.APPROVER:
            return None
        if not self._account.is_approver_session(session):
            self.drop(token)
            return None
        return session

    def drop(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            session = self._by_token.pop(token, None)
        if session is not None:
            self._account.logout(session)
