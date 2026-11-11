"""Findings, severities and the security score.

Score: start at 100, minus 40 per open critical, 25 per high, 10 per medium, 3 per low;
floor 0. Status: 80-100 "good", 50-79 "warning", below 50 "at risk", and ANY open critical
finding means "at risk" whatever the number. The score is display only: it never triggers
an action.

A finding holds no secret values: `detail` and `location` are built from masked labels,
file names and line numbers only.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


PENALTY = {Severity.CRITICAL: 40, Severity.HIGH: 25, Severity.MEDIUM: 10, Severity.LOW: 3}
ACTION_SEVERITIES = frozenset({Severity.CRITICAL, Severity.HIGH})   # these trip the breakers


@dataclass(frozen=True)
class Finding:
    key: str            # stable id, e.g. "config:gate.auto_limit_cents"; used to dedupe
    job: str            # auditor | secrets | monitor | canaries
    severity: Severity
    title: str
    detail: str
    location: str = ""
    opened_at: float = 0.0


def score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(PENALTY[f.severity] for f in findings))


def status(findings: list[Finding]) -> str:
    if any(f.severity is Severity.CRITICAL for f in findings):
        return "at risk"
    value = score(findings)
    return "good" if value >= 80 else "warning" if value >= 50 else "at risk"


class FindingStore:
    """Open findings by key. `sync` replaces one job's findings with what it sees now."""

    def __init__(self) -> None:
        self._open: dict[str, Finding] = {}
        self._lock = threading.Lock()

    def sync(self, job: str, current: list[Finding],
             now: float) -> tuple[list[Finding], list[Finding]]:
        """Return (newly opened, resolved) for `job`. Findings still present stay open."""
        seen = {f.key: f for f in current if f.job == job}
        with self._lock:
            opened = [replace(f, opened_at=now) for k, f in seen.items() if k not in self._open]
            resolved = [f for k, f in self._open.items() if f.job == job and k not in seen]
            for f in opened:
                self._open[f.key] = f
            for f in resolved:
                del self._open[f.key]
        return opened, resolved

    def open_findings(self) -> list[Finding]:
        with self._lock:
            return sorted(self._open.values(), key=lambda f: (list(Severity).index(f.severity),
                                                               f.key))

    def counts(self) -> dict[str, int]:
        found = self.open_findings()
        return {s.value: sum(1 for f in found if f.severity is s) for s in Severity}
