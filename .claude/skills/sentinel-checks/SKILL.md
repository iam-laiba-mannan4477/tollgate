---
name: sentinel-checks
description: Use when building or changing Sentinel: config auditor, secrets scanner, live monitor, self-attack canaries, auto-fix, incident reports.
---
# Sentinel

Sentinel runs on a schedule (and on demand) and produces findings: id, severity, what, why, fix status.
Checks:
- Config auditor: compare live settings with a safe baseline (limits, roles, stamp expiry, approvals on). Weakened setting = finding.
- Secrets scanner: repo, logs and config for keys. Never print the secret itself, only file and line.
- Live monitor: bursts, new recipients, unusual amounts, odd hours, refund-heavy patterns. Replayed attack traffic alerts; normal traffic stays quiet.
- Self-attack canaries: replay the attack suite against the Gate. If one gets through, raise a critical finding.
- Safe auto-fix: tighten only (lower a limit, trip the breaker, pause the agent). Log every fix. Never loosen.
- Incident report: plain language, what was found, why it matters, what was done, what a person must still do.

Rules: Sentinel is read-mostly. It must be idempotent, survive restarts, and never crash the Gate. Be honest: it finds known classes of weakness and drift, not every possible attack.
