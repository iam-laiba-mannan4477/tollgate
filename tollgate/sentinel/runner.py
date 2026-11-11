"""Sentinel: runs the jobs on a schedule and acts (tighten only) on new findings.

Schedule (approved): config audit and live monitor every 60 s, secrets scan every 10 min,
canaries every 15 min; every job also runs on the first round. The web app calls
`run_due()` from its 5-second release loop, right after release_due() (see app/main.py).

Audit lines (approved): FINDING when a finding opens, RESOLVED when it closes, TRIP and
TIGHTEN for actions, SNTL-ERR for a job error, and at most one SNTL-SUM summary per
10 minutes. None of these are ALLOW, HOLD or BLOCK, so they are never counted as requests.

Actions: a newly opened CRITICAL or HIGH finding trips both breakers; a weak Gate or policy
setting is also set back to its baseline when that is stricter. Nothing is ever loosened,
approved, released or sent by Sentinel. Fail closed: a job error is logged (job name and
error type only) and changes nothing.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

from tollgate.gate.audit import AuditLog
from tollgate.sentinel import auditor, canaries, monitor, secrets_scan
from tollgate.sentinel.autofix import Tightener
from tollgate.sentinel.findings import ACTION_SEVERITIES, Finding, FindingStore, score, status
from tollgate.sentinel.reports import Report, ReportWriter

SCHEDULE = (("auditor", 60), ("monitor", 60), ("secrets", 600), ("canaries", 900))
SUMMARY_EVERY_SECONDS = 600
Clock = Callable[[], float]


class Sentinel:
    def __init__(self, *, executor: Any, desk: Any, service: Any, account: Any,
                 audit_path: Path, data_dir: Path, repo_root: Path,
                 clock: Clock = time.monotonic, wall_clock: Clock = time.time,
                 canary_world: canaries.WorldFactory = canaries.default_world,
                 report_model: Any = None, git: secrets_scan.GitRunner | None = None) -> None:
        self._executor, self._desk, self._service, self._account = executor, desk, service, account
        self._data_dir, self._repo_root = Path(data_dir), Path(repo_root)
        self._clock, self._wall = clock, wall_clock
        self._canary_world, self._git = canary_world, git
        self._audit = AuditLog(audit_path, wall_clock)
        self._tightener = Tightener(executor, desk, service, self._audit)
        self._store = FindingStore()
        self._reader = monitor.AuditReader(audit_path)
        self._reports = ReportWriter(self._data_dir / "incidents.jsonl", report_model)
        self._last_run: dict[str, float] = {}
        self._last_summary: float | None = None
        self.rounds = 0
        self.errors = 0
        self.last_checks: list[auditor.Check] = []
        self.reports: list[Report] = []

    # ---- read-only views -----------------------------------------------------------------
    def open_findings(self) -> list[Finding]:
        return self._store.open_findings()

    def score(self) -> int:
        return score(self._store.open_findings())

    def status(self) -> str:
        return status(self._store.open_findings())

    # ---- scheduling ----------------------------------------------------------------------
    def run_due(self) -> None:
        """Run every job whose interval has passed (all of them on the first call)."""
        self.rounds += 1
        now = self._clock()
        for job, every in SCHEDULE:
            last = self._last_run.get(job)
            if last is None or now - last >= every:
                self._last_run[job] = now
                self._run(job)
        self._maybe_summary(now)

    def run_all_now(self) -> None:
        for job, _ in SCHEDULE:
            self._last_run[job] = self._clock()
            self._run(job)

    # ---- jobs ----------------------------------------------------------------------------
    def _job_auditor(self) -> list[Finding]:
        session = {"lifetime_seconds": getattr(self._account, "_lifetime", None),
                   "idle_seconds": getattr(self._account, "_idle", None)}
        self.last_checks = auditor.audit(self._executor.config,
                                         getattr(self._desk, "_config", None),
                                         self._service.policy, session)
        return auditor.findings(self.last_checks)

    def _job_monitor(self) -> list[Finding]:
        events = self._reader.read(self._wall())
        return monitor.detect(events, self._executor.config.auto_limit_cents)

    def _job_secrets(self) -> list[Finding]:
        result = secrets_scan.scan(self._repo_root, [self._data_dir], self._git)
        for problem in result.problems:
            self._event("SNTL-ERR", f"sentinel secrets scan: {problem}")
        return secrets_scan.findings(result)

    def _job_canaries(self) -> list[Finding]:
        return canaries.findings(canaries.run_all(self._canary_world))

    def _run(self, job: str) -> None:
        try:
            current = getattr(self, f"_job_{job}")()
        except Exception as exc:                      # fail closed: change nothing
            self.errors += 1
            self._event("SNTL-ERR", f"sentinel {job} job failed ({type(exc).__name__}); "
                                    f"nothing was changed")
            return
        opened, resolved = self._store.sync(job, current, self._wall())
        for f in opened:
            self._event("FINDING", f"sentinel {f.severity.value}: {f.title} [{f.location}]")
            self._act(f)
            self._report(f)
        for f in resolved:
            self._event("RESOLVED", f"sentinel: no longer seen: {f.title} [{f.location}]")

    def _act(self, f: Finding) -> None:
        if f.severity not in ACTION_SEVERITIES:
            return
        if f.job == "auditor" and "." in f.location:
            area, field = f.location.split(".", 1)
            self._tightener.restore(area, field)
        self._tightener.trip_breakers(f"{f.severity.value} finding: {f.title}")

    def _report(self, f: Finding) -> None:
        try:
            self.reports.append(self._reports.write(f))
        except Exception as exc:
            self.errors += 1
            self._event("SNTL-ERR", f"sentinel report failed ({type(exc).__name__})")

    def _maybe_summary(self, now: float) -> None:
        if self._last_summary is not None and now - self._last_summary < SUMMARY_EVERY_SECONDS:
            return
        self._last_summary = now
        c = self._store.counts()
        self._event("SNTL-SUM", f"sentinel summary: score {self.score()} ({self.status()}); "
                                f"open {c['critical']} critical, {c['high']} high, "
                                f"{c['medium']} medium, {c['low']} low")

    def _event(self, decision: str, reason: str) -> None:
        try:
            self._audit.append(f"sentinel-{decision.lower()}", decision, reason, None, None)
        except Exception:
            self.errors += 1
