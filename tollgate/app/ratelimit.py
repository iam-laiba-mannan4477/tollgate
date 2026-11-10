"""Login rate limit: 5 failures within 60 s for one name OR one client IP locks logins for
that name or IP for 15 minutes. While locked, even the right password is refused.

Times come from an injected monotonic clock. Thread-safe.
"""
from __future__ import annotations

import threading
import time
from typing import Callable

MAX_FAILURES = 5
WINDOW_SECONDS = 60
LOCKOUT_SECONDS = 900


class LoginLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic, *,
                 max_failures: int = MAX_FAILURES, window: float = WINDOW_SECONDS,
                 lockout: float = LOCKOUT_SECONDS) -> None:
        self._clock = clock
        self._max = max_failures
        self._window = window
        self._lockout = lockout
        self._lock = threading.Lock()
        self._fails: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    @staticmethod
    def _keys(name: str, ip: str) -> tuple[str, str]:
        return ("name:" + name.strip().lower()[:64], "ip:" + ip[:64])

    def is_locked(self, name: str, ip: str) -> bool:
        now = self._clock()
        with self._lock:
            return any(self._locked_until.get(k, float("-inf")) > now
                       for k in self._keys(name, ip))

    def record_failure(self, name: str, ip: str) -> bool:
        """Count one failure. True if this failure started a lockout."""
        now = self._clock()
        started = False
        with self._lock:
            for key in self._keys(name, ip):
                recent = [t for t in self._fails.get(key, []) if t > now - self._window]
                recent.append(now)
                self._fails[key] = recent
                if len(recent) >= self._max and self._locked_until.get(key, 0.0) <= now:
                    self._locked_until[key] = now + self._lockout
                    self._fails[key] = []
                    started = True
        return started

    def record_success(self, name: str, ip: str) -> None:
        with self._lock:
            for key in self._keys(name, ip):
                self._fails.pop(key, None)
