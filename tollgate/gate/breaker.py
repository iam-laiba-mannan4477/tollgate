"""Circuit breaker: a simple flag the rules read. Tripping logic arrives on Day 3.

Opening is always allowed (tightening). Closing is a deliberate, separate call
that only a person should make; Sentinel must never call `reset`.
"""
from __future__ import annotations

import threading


class CircuitBreaker:
    def __init__(self) -> None:
        self._open = False
        self._lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        return self._open

    def trip(self) -> None:
        with self._lock:
            self._open = True

    def reset_by_person(self) -> None:
        """Loosening: for a human operator only."""
        with self._lock:
            self._open = False
