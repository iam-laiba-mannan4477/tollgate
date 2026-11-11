"""Tighten-only actions. The ONLY Sentinel code that changes live state.

It can: trip the breakers, tighten one Gate setting, tighten one approval-policy limit.
It holds bound methods for exactly those three things and nothing else: no approve, no
execute, no release, no reset, no unlock, no loosening. Every action is written to the
audit log (the tighten calls audit themselves; breaker trips are audited here).
"""
from __future__ import annotations

import itertools
from typing import Any, Callable

from tollgate.gate.audit import AuditLog
from tollgate.sentinel import baseline

ACTOR = "sentinel"


class Tightener:
    __slots__ = ("_trips", "_tighten_gate", "_tighten_policy", "_audit", "_seq")

    def __init__(self, executor: Any, desk: Any, service: Any, audit: AuditLog) -> None:
        self._trips: tuple[Callable[[], None], ...] = (executor.trip_breaker, desk.trip_breaker)
        self._tighten_gate: Callable[[str, int, str], bool] = executor.tighten_config
        self._tighten_policy: Callable[[str, int, str], bool] = service.tighten
        self._audit = audit
        self._seq = itertools.count(1)

    def trip_breakers(self, why: str) -> None:
        for trip in self._trips:
            try:
                trip()
            except Exception:
                pass                      # one broken hook must not stop the other
        self._audit.append(f"sentinel-trip-{next(self._seq)}", "TRIP",
                           f"sentinel tripped the breakers: {why}"[:180], None, None)

    def restore(self, area: str, field: str) -> bool:
        """Set one weak setting back to its baseline, only if that is stricter."""
        if area not in ("gate", "policy") or field not in baseline.STRICTER.get(area, {}):
            return False
        target = baseline.baseline_value(area, field)
        apply = self._tighten_gate if area == "gate" else self._tighten_policy
        try:
            return bool(apply(field, target, ACTOR))   # each refuses anything looser
        except Exception:
            return False
