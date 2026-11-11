"""Reset breaker from the Sentinel page. This LOOSENS protection, so (approved rules):

- needs the logged-in approver session (checked by the route), CSRF (route) and a fresh
  code (ApprovalService.verify_step_up: a wrong code counts toward the 3c lockout);
- refused while approvals are locked (unlocking stays: a person in Python, or a restart);
- refused while any critical or high Sentinel finding is open (it would re-trip anyway);
- refused when Sentinel is off, or when no breaker is open (nothing to reset);
- one reset closes both breakers (executor and desk), audited as RESET by the executor
  and desk with the approver's name and "reset from Sentinel page";
- real mode: waits `settings_cooling_off_seconds` (15 min), owner notified, cancellable;
  when the wait ends it applies only if approvals are still unlocked and no critical or
  high finding is open, otherwise it is dropped (audited);
- demo mode: no cooling-off (code, audit line and owner notice still required).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

REASON = "reset from Sentinel page"


@dataclass
class PendingReset:
    reset_id: str
    approver: str
    release_at: float


class BreakerReset:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self._lock = threading.Lock()
        self._seq = 0
        self.pending: PendingReset | None = None

    # ---- checks ----------------------------------------------------------------------
    def blocker(self) -> str | None:
        """Why a reset is not possible right now, or None."""
        ctx = self._ctx
        if ctx.sentinel is None:
            return "Sentinel is off."
        if ctx.service.locked:
            return ("Approvals are locked. Unlocking needs a person in Python "
                    "(approval_service.unlock) or a restart of the app.")
        blocking = ctx.sentinel.blocking_findings()
        if blocking:
            f = blocking[0]
            return f"An open {f.severity.value} finding blocks the reset: {f.title}."
        if not (ctx.executor.breaker_open or ctx.desk.breaker_open):
            return "No breaker is open; there is nothing to reset."
        if self.pending is not None:
            return "A reset is already waiting out its cooling-off."
        return None

    # ---- actions ---------------------------------------------------------------------
    def request(self, session: Any, code: str) -> str:
        ctx = self._ctx
        with self._lock:
            why = self.blocker()
            if why:
                return f"Not reset. {why}"
            ok, reason = ctx.service.verify_step_up(session, code, "breaker-reset")
            if not ok:
                return f"Not reset: {reason}."
            name = session.name
            if not ctx.real:
                self._apply(name)
                ctx.service.notify_owner("breaker_reset", f"{name} reset the breakers from "
                                         "the Sentinel page (demo: no cooling-off).")
                return "Breakers reset (demo: no cooling-off). The owner was notified."
            self._seq += 1
            wait = ctx.service.policy.settings_cooling_off_seconds
            self.pending = PendingReset(f"breaker-reset-{self._seq}", name, ctx.clock() + wait)
            ctx.event("sentinel-page", "CHANGE", f"breaker reset requested by {name}; applies "
                      f"after {wait}s cooling-off unless cancelled")
            ctx.service.notify_owner("breaker_reset", f"{name} asked to reset the breakers. "
                                     f"It applies after {wait}s unless cancelled.")
            return f"Reset queued: it applies after {wait // 60} min unless cancelled. Owner notified."

    def cancel(self, person: str) -> bool:
        with self._lock:
            if self.pending is None:
                return False
            self.pending = None
            self._ctx.event("sentinel-page", "CANCEL", f"breaker reset cancelled by {person}")
            return True

    def apply_due(self) -> None:
        """Called from the release loop. Applies a waiting reset once its wait is over."""
        ctx = self._ctx
        with self._lock:
            p = self.pending
            if p is None or ctx.clock() < p.release_at:
                return
            self.pending = None
            locked = ctx.service.locked
            blocking = ctx.sentinel.blocking_findings() if ctx.sentinel is not None else []
            if locked or blocking or ctx.sentinel is None:
                ctx.event("sentinel-page", "CANCEL", "breaker reset dropped: approvals locked "
                          "or a critical or high finding is open")
                return
            self._apply(p.approver)

    def _apply(self, name: str) -> None:
        self._ctx.executor.reset_breaker(name, REASON)
        self._ctx.desk.reset_breaker(name, REASON)

    def seconds_left(self) -> int | None:
        p = self.pending
        return None if p is None else max(0, int(p.release_at - self._ctx.clock()))
