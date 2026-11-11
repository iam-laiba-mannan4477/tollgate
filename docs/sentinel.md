# Sentinel (core, no web page yet)

Code: `tollgate/sentinel/`. Sentinel watches, finds weak spots and may only **tighten**:
trip the breakers, or set a loosened setting back to its safe baseline. It never loosens
anything, never approves, never releases and never moves money (tested, including an AST
check of its code). No new dependencies.

| File | Purpose |
|------|---------|
| `findings.py` | Findings, severities, the score and the status label. |
| `baseline.py` | The safe baseline = today's approved defaults, and which direction is stricter. |
| `auditor.py` | Config auditor: every Gate, desk, approval-policy and session setting, ok or weak, with a reason. |
| `secret_patterns.py` | The secret patterns, shared with `scripts/check_secrets.py` (same patterns as before). |
| `secrets_scan.py` | Secrets scanner. |
| `monitor.py` | Live monitor over the audit log. |
| `canaries.py` | Self-attack canaries in isolated mock worlds. |
| `autofix.py` | `Tightener`: the only code that acts. Trip breakers, tighten one setting. Nothing else. |
| `reports.py` | Incident reports. |
| `runner.py` | `Sentinel`: schedule, findings, actions, audit lines. |

## Turning it on and off
`TOLLGATE_SENTINEL=on` (default) or `off`; anything else stops the app from starting.
The web app's 5-second loop calls `release_due()` first, then `Sentinel.run_due()`. With
`off`, the loop is exactly the Phase 3d loop. A Sentinel error never stops a release.

## Schedule
| Job | Every | Notes |
|---|---|---|
| Config audit | 60 s | also on the first round |
| Live monitor | 60 s | reads only new audit lines; window 30 min |
| Secrets scan | 10 min | tracked files, `tests/`, `*.log`, the data folder (audit, outbox, incidents) |
| Canaries | 15 min | all 8 frozen attack scenarios |

## Severities and actions
| Severity | Score penalty | Examples | Automatic action |
|---|---|---|---|
| critical | 40 | a canary got through; a key-like value in a git-tracked file; `.env` not ignored by git | trip both breakers |
| high | 25 | a weak setting; split payments; 3+ blocks to one recipient in 10 min; an approval LOCKOUT | trip both breakers; a weak Gate or policy setting is also set back to its baseline when that is stricter |
| medium | 10 | a burst (5+ decisions in 60 s); new recipient then a payment over $1,000 within 15 min; a single failed second-factor code (FACTORFAIL) | report only |
| low | 3 | a key-like value in an untracked file (log, data, untracked test file) | report only |

Score = 100 minus the penalties of all open findings, floor 0. Status: 80-100 **good**,
50-79 **warning**, below 50 **at risk**, and **any open critical finding means "at risk"**
whatever the number. The score never triggers anything.

A finding opens once (deduplicated by key) and resolves when its job no longer sees it.
Resolving a finding does **not** reset a breaker.

## What each job does
- **Config auditor**: compares the settings in force with the baseline (Gate auto limit
  $1,000, 2 payments per recipient per 10 min, stamps 5 min; the Phase 3c approval policy;
  sessions 1 hour / 15 min idle). Anything missing or unreadable counts as weak. The desk's
  Gate settings are audited too, but there is no tighten path for them, so a weak desk
  setting only trips the breakers.
- **Secrets scanner**: reports file, line number and a label such as "Groq API key
  (masked)". It never keeps, prints or stores the value, not even part of it. It never
  opens `.env` or `.env.*` (except `.env.example`); it only runs `git check-ignore .env`.
  It skips `.venv`, `.git`, binary files and files over 1 MB. If git is missing it says so
  and carries on.
- **Live monitor**: see `monitor.py` for the exact thresholds. Executor and desk lines are
  timed by their own wall-clock time; approval-service lines use a monotonic clock in the
  same file, so for those the monitor uses the time it first saw the line. Lines from the
  agent loop and from Sentinel are ignored.
- **Canaries**: each attack runs in a fresh world: in-memory mock backend, temporary audit
  file, its own breakers and a throwaway approver. For the stolen-approver-session attack
  it also tries to approve with the real session and no code, then a wrong code (2 tries,
  under the 3c lockout of 3). "Through" means any ALLOW, anything executed, or money,
  dispute or subscription records changed. A canary that cannot run counts as through.
- **Incident reports**: one per new finding, in `data/incidents.jsonl`. Written through the
  model adapter with one tool, `write_incident_summary`; the default is the keyless
  scripted model with a fixed template. Text is masked with the secret patterns and capped
  at 1,000 characters, and it is never parsed for actions.

## Audit lines
Only: `FINDING` (opened), `RESOLVED`, `TRIP` and `TIGHTEN` (actions), `SNTL-ERR` (a job
error: job name and error type only), and at most one `SNTL-SUM` summary per 10 minutes.
No line per scan. None of these are ALLOW, HOLD or BLOCK, so the Overview counts never
include them, and the Activity page shows them under their own "Sentinel" filter.

## A fresh demo clone
Demo mode with no keys starts with **no findings at all**, score 100, status "good", and
Sentinel never trips a breaker on its own (tested on the real repository). The demo account
and the fake mock TOTP secret are by design and are not findings.

## How a tripped breaker is reset today
There is no button. A tripped breaker stays open until one of these:
1. **A person, in Python**: `executor.reset_breaker(person, reason)` and
   `desk.reset_breaker(person, reason)` (both need a named person and a reason, both audited
   as `RESET`). If approvals were locked by 3 bad codes, also
   `approval_service.unlock(person, reason)` (audited as `UNLOCK`).
2. **Restarting the app.** Everything is in memory, so a restart starts with closed breakers
   and unlocked approvals. The audit log keeps the history.

The reset rules for a future Sentinel page are still to be decided by the owner.

## Honest limits
- Tested in mock mode with fake clocks, fake keys and temporary git repos; the
  fresh-clone test uses this repository. Nothing here was run against the Braintree sandbox.
- A real model for reports is **not wired in**: the Groq and Claude providers only accept
  the agent's own tool names. Any model failure falls back to the template. Untested with a
  real model.
- The patterns find key-shaped text only; a secret in an unusual format will be missed.
- The monitor sees only what reaches the audit log, and only the last 30 minutes.
- Findings and the score are in memory and are lost on restart (the audit lines remain).
- Canaries prove the frozen attack set is stopped by today's code; they cannot prove that
  new, unknown attacks are stopped.
- No web page yet: findings, score and reports are visible only in the audit log,
  `data/incidents.jsonl` and in code.
