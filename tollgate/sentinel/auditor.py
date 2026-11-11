"""Config auditor: compare the settings actually in force with the safe baseline.

Each setting is reported "ok" or "weak" with a plain reason. Weak settings become
HIGH findings (which trip the breakers); the runner also sets them back to the baseline
when that is stricter and a tighten-only path exists.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tollgate.sentinel import baseline
from tollgate.sentinel.findings import Finding, Severity


@dataclass(frozen=True)
class Check:
    area: str            # gate | desk | policy | session
    field: str
    now: Any
    baseline: int
    ok: bool
    reason: str


def _check(area: str, base_area: str, field: str, value: Any) -> Check:
    base = baseline.baseline_value(base_area, field)
    weak = baseline.is_weak(base_area, field, value)
    side = baseline.STRICTER[base_area][field]
    if weak:
        reason = (f"weak: {value} is looser than the safe baseline {base} "
                  f"({side} is stricter)")
    else:
        reason = "ok: equal to or stricter than the safe baseline"
    return Check(area, field, value, base, not weak, reason)


def audit(gate: Any, desk_gate: Any, policy: Any, session: dict[str, Any]) -> list[Check]:
    """All checks. A missing or unreadable setting counts as weak (fail closed)."""
    checks = []
    for area, cfg, base_area in (("gate", gate, "gate"), ("desk", desk_gate, "gate"),
                                 ("policy", policy, "policy")):
        for field in baseline.STRICTER[base_area]:
            checks.append(_check(area, base_area, field, getattr(cfg, field, None)))
    for field in baseline.STRICTER["session"]:
        checks.append(_check("session", "session", field, session.get(field)))
    return checks


def findings(checks: list[Check]) -> list[Finding]:
    return [Finding(key=f"config:{c.area}.{c.field}", job="auditor", severity=Severity.HIGH,
                    title=f"Weak setting: {c.area} {c.field}", detail=c.reason,
                    location=f"{c.area}.{c.field}")
            for c in checks if not c.ok]
