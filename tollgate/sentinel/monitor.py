"""Live monitor: read the audit log and raise findings for suspicious patterns.

Clocks: executor and desk lines carry wall-clock time (time.time). Approval-service lines
carry a monotonic time, so for those the monitor uses the wall time at which it first saw
the line. Only the last 30 minutes count; a finding resolves once its pattern leaves the
window. Lines written by the agent loop ("agent ...") and by Sentinel itself are ignored.

Thresholds (approved):
  burst            >= 5 Gate decisions within 60 s                          medium
  repeated blocks  >= 3 BLOCKs to one recipient within 10 min               high
  split payments   >= 3 payments to one recipient within 30 min, each at or
                   under the auto limit, and either all at 80-100% of it or
                   together over it                                         high
  new recipient    a HOLD for a new recipient, then a payment to it sent
  then payment     within 15 min and over $1,000                            medium
  LOCKOUT          any approval lockout event                               high
  FACTORFAIL       any failed second-factor code                            medium (report only)
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tollgate.sentinel.findings import Finding, Severity

WINDOW_SECONDS = 1_800
BURST_COUNT, BURST_SECONDS = 5, 60
BLOCKS_COUNT, BLOCKS_SECONDS = 3, 600
SPLIT_COUNT, SPLIT_SECONDS, SPLIT_LOW = 3, 1_800, 0.80
NEW_RECIPIENT_SECONDS, NEW_RECIPIENT_OVER_CENTS = 900, 100_000
VERDICTS = frozenset({"ALLOW", "HOLD", "BLOCK"})
SERVICE_EVENTS = frozenset({"FACTORFAIL", "LOCKOUT"})


@dataclass(frozen=True)
class Event:
    time: float
    decision: str
    reason: str
    amount: int | None
    recipient: str | None
    line_id: str


class AuditReader:
    """Reads new audit lines each round; remembers when it first saw service events."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._seen_lines = 0
        self._events: list[Event] = []

    def read(self, now_wall: float) -> list[Event]:
        if self._path.exists():
            lines = self._path.read_text(encoding="utf-8").splitlines()
            for raw in lines[self._seen_lines:]:
                event = _to_event(raw, now_wall)
                if event is not None:
                    self._events.append(event)
            self._seen_lines = len(lines)
        start = now_wall - WINDOW_SECONDS
        self._events = [e for e in self._events if e.time >= start]
        return list(self._events)


def _to_event(raw: str, now_wall: float) -> Event | None:
    try:
        row: dict[str, Any] = json.loads(raw)
    except ValueError:
        return None
    decision, reason = str(row.get("decision", "")), str(row.get("reason", ""))
    if decision in SERVICE_EVENTS:
        when = now_wall                       # service lines use a monotonic clock
    elif decision in VERDICTS and not reason.startswith("agent "):
        when = row.get("time")
        if not isinstance(when, (int, float)):
            return None
    else:
        return None
    amount = row.get("amount_cents")
    recipient = row.get("recipient")
    return Event(float(when), decision, reason, amount if isinstance(amount, int) else None,
                 recipient if isinstance(recipient, str) and recipient != "None" else None,
                 str(row.get("id", "?")))


def _within(events: list[Event], seconds: float) -> bool:
    return bool(events) and events[-1].time - events[0].time <= seconds


def _sliding(events: list[Event], count: int, seconds: float) -> bool:
    return any(_within(events[i:i + count], seconds) for i in range(len(events) - count + 1))


def detect(events: list[Event], auto_limit_cents: int) -> list[Finding]:
    found: list[Finding] = []
    verdicts = sorted((e for e in events if e.decision in VERDICTS), key=lambda e: e.time)
    if _sliding(verdicts, BURST_COUNT, BURST_SECONDS):
        found.append(Finding("monitor:burst", "monitor", Severity.MEDIUM, "Burst of requests",
                             f"{BURST_COUNT} or more Gate decisions within {BURST_SECONDS} s.",
                             "audit log"))
    by_recipient: dict[str, list[Event]] = {}
    for e in verdicts:
        if e.recipient:
            by_recipient.setdefault(e.recipient, []).append(e)
    for recipient, items in sorted(by_recipient.items()):
        found += _per_recipient(recipient, items, auto_limit_cents)
    service = [e for e in events if e.decision in SERVICE_EVENTS]
    if any(e.decision == "LOCKOUT" for e in service):
        found.append(Finding("monitor:lockout", "monitor", Severity.HIGH,
                             "Approvals locked after failed codes",
                             "Someone with a logged-in session failed the second factor "
                             "3 times. This looks like a stolen session.", "audit log"))
    if any(e.decision == "FACTORFAIL" for e in service):
        found.append(Finding("monitor:factorfail", "monitor", Severity.MEDIUM,
                             "Failed second-factor code",
                             "An approval was tried with a wrong, missing or reused code.",
                             "audit log"))
    return found


def _per_recipient(recipient: str, items: list[Event], limit: int) -> list[Finding]:
    found = []
    blocks = [e for e in items if e.decision == "BLOCK"]
    if _sliding(blocks, BLOCKS_COUNT, BLOCKS_SECONDS):
        found.append(Finding(f"monitor:blocks:{recipient}", "monitor", Severity.HIGH,
                             f"Repeated blocks to {recipient}",
                             f"{BLOCKS_COUNT} or more blocked requests to one recipient "
                             f"within {BLOCKS_SECONDS // 60} min.", recipient))
    under = [e for e in items if e.amount is not None and 0 < e.amount <= limit]
    for i in range(len(under) - SPLIT_COUNT + 1):
        group = under[i:i + SPLIT_COUNT]
        if not _within(group, SPLIT_SECONDS):
            continue
        near = all(e.amount >= SPLIT_LOW * limit for e in group)
        if near or sum(e.amount for e in group) > limit:
            found.append(Finding(f"monitor:split:{recipient}", "monitor", Severity.HIGH,
                                 f"Split payments to {recipient}",
                                 f"{SPLIT_COUNT} or more payments under the auto limit to one "
                                 "recipient within 30 min: a way to slip under the limit.",
                                 recipient))
            break
    holds = [e for e in items if e.decision == "HOLD" and "new recipient" in e.reason]
    sent = [e for e in items if e.decision == "ALLOW" and (e.amount or 0) > NEW_RECIPIENT_OVER_CENTS]
    if any(0 <= s.time - h.time <= NEW_RECIPIENT_SECONDS for h in holds for s in sent):
        found.append(Finding(f"monitor:newpay:{recipient}", "monitor", Severity.MEDIUM,
                             f"New recipient then a large payment to {recipient}",
                             "A first payment to a new recipient was held, then a payment of "
                             "over $1,000 to it was sent within 15 min.", recipient))
    return found
