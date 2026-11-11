# Sentinel

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
2. **Restarting the app.** Breakers and the approvals lock are in memory, so a restart starts
   with closed breakers and unlocked approvals. The audit log keeps the history. Sentinel's
   live monitor starts reading at the end of the audit file as it is at start-up, so old
   LOCKOUT lines do not trip the breakers again (security review finding 1, fixed). A new
   lockout after the restart still trips them.

3. **The Sentinel page** (`/sentinel`, "Reset breaker"), under these approved rules:
   - needs the logged-in approver session, the CSRF token and a **fresh code**; a wrong code
     counts toward the same 3-code lockout as approvals;
   - refused while approvals are locked (unlocking is still option 1 or a restart), while any
     **critical or high** finding is open (Sentinel would trip it again), when no breaker is
     open, and when Sentinel is off;
   - one reset closes both breakers (executor and desk), audited as `RESET` with the
     approver's name and "reset from Sentinel page"; the owner gets an outbox notice;
   - **real mode**: waits 15 minutes (`settings_cooling_off_seconds`), can be cancelled, and
     when the wait ends it applies only if approvals are unlocked and no critical or high
     finding is open (otherwise it is dropped, audited as `CANCEL`);
   - **demo mode**: no cooling-off, so a demo is not blocked.

## Web pages
- **`/sentinel`**: the real score and status (no score before the first scan), open findings
  with their reports, findings resolved since the app started, the last 50 Sentinel audit
  lines, "Scan now" (any logged-in approver, one per 30 s, runs all 4 jobs once, tighten-only)
  and "Reset breaker" (above). With `TOLLGATE_SENTINEL=off` it shows "Sentinel is off".
- **`/drills`** ("Try to break it", code in `tollgate/app/drills.py`): four drills, each in a
  new throwaway mock world in a temporary folder that is deleted afterwards. They never
  receive the live app objects, and write nothing to the live audit log (tested: the audit
  file is byte-identical after every drill). Results live in memory only: the last 10, for at
  most 1 hour. One drill per 10 s.
  1. attack drill: the 8 frozen attacks, each in its own world (attack, expected, actual,
     money moved);
  2. stolen session: a throwaway demo app is started in-process (FastAPI test client, no
     network) and a logged-in session with no authenticator tries 3 times through the web
     forms: no code, then two wrong codes. Expected and tested: refused, no money moved,
     approvals locked, breaker tripped, in that throwaway app;
  3. weaken a setting: the auto limit is loosened in a throwaway world and Sentinel's config
     audit there finds it, sets it back and trips that world's breakers;
  4. plant a fake key: a random fake key is written to a throwaway folder and the scanner
     finds it; only "Groq API key (masked)", file and line are shown.

## Honest limits
- Tested in mock mode with fake clocks, fake keys and temporary git repos; the
  fresh-clone test uses this repository. Nothing here was run against the Braintree sandbox.
- A real model for reports is **not wired in**: the Groq and Claude providers only accept
  the agent's own tool names. Any model failure falls back to the template. Untested with a
  real model.
- The patterns find key-shaped text only; a secret in an unusual format will be missed.
- The monitor sees only what reaches the audit log, and only the last 30 minutes.
- After a restart the monitor counts only lines written since start-up, so a slow pattern
  that spans a restart (split payments, repeated blocks) is not linked up. The Gate's own
  memory of recent payments is also cleared by a restart.
- When a person resets a breaker (a `RESET` line), the monitor forgets the lockout and
  failed-code events before it; payment-pattern events (bursts, repeated blocks, split
  payments) keep counting. If the audit file is ever shorter than what was read, the monitor
  reads it again from the top (stricter).
- Findings and the score are in memory and are lost on restart (the audit lines remain).
- Canaries prove the frozen attack set is stopped by today's code; they cannot prove that
  new, unknown attacks are stopped.
- The pages were tested with FastAPI's test client only, **not in a real browser** (phone
  width included).
- Resolved findings and drill results are in memory and are lost on restart.
