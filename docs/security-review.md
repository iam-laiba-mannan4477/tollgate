# Security review: Phase 3c, 3d and Sentinel

Scope: `tollgate/approval/`, `tollgate/app/`, `tollgate/sentinel/`, and
`Executor.tighten_config` in `tollgate/executor/executor.py`. Reviewed by reading the code at
commit `15a0686`, plus one reproduction script (finding 1). Line numbers were re-checked
against the working tree before this file was written. **No code was changed for this
review.** `.env` was not read; `git ls-files .env` prints nothing (not tracked).

Questions asked: can anyone approve or move money without a valid session and code? Can
settings be loosened? Do secrets leak into logs, pages or reports? Are there CSRF or cookie
gaps? Are there race conditions?

**Short answer:** no way was found to approve or move money without a live approver session
and a fresh code, no secret leak, and no CSRF gap. There are 3 medium and 3 low findings, plus
2 informational notes. Only finding 1 was reproduced by running code; the others are from
reading the code and are marked "confirmed by reading".

**Status (2026-11-12):** finding 1 is **fixed** (see below). Findings 9 and 10 were added as
**documented limits, not fixed**. All other findings are still open.

| # | Severity | Summary |
|---|----------|---------|
| 1 | Medium | **Fixed.** A restart did not clear a lockout: Sentinel re-read old LOCKOUT lines and tripped the breakers again |
| 2 | Medium | Demo login (public password and public TOTP secret) can be combined with the real Braintree sandbox backend |
| 3 | Medium | A queued real-mode breaker reset also closes a breaker that tripped again, for a new reason, during the wait |
| 4 | Low | The login and setup-confirm rate limits are check-then-act and can be raced with parallel requests |
| 5 | Low | Two Sentinel rounds can run at the same time; the monitor's audit reader is not locked |
| 6 | Low | Approval-time velocity uses its own default Gate settings, so a Sentinel tightening does not reach it |
| 7 | Info | Real mode: whoever opens `/setup` first becomes the approver |
| 8 | Info | Demo cookies are not `Secure` and have no `__Host-` prefix |
| 9 | Low | Documented limit, not fixed: the real-mode approver account is lost on restart |
| 10 | Low | Documented limit, not fixed: the memory of used codes is lost on restart |

---

## 1. Medium: a restart does not clear a lockout; Sentinel re-trips the breakers (FIXED)

**Fixed on 2026-11-12.** `tollgate/sentinel/monitor.py` (`AuditReader`) and
`tollgate/sentinel/runner.py` (the live Sentinel builds its reader with `start_at_end=True`):
- The live monitor starts reading at the **end** of the audit file as it is at start-up, so
  lines from before a restart never become events. The file is never edited, rotated or
  shortened, and the hash chain is untouched.
- A `RESET` line (a person closed a breaker) drops the LOCKOUT and FACTORFAIL events seen
  before it. Payment-pattern events (bursts, repeated blocks, split payments) keep counting.
- If the file is ever shorter than what was already read (lines removed), the reader starts
  again from the top. That is stricter, never looser.
- No threshold, severity, action or audit code changed, and the tighten-only autofix is
  untouched. A new lockout after the restart still trips both breakers.
- Tests: `tests/test_sentinel_restart.py`:
  - a restart with an old LOCKOUT leaves the breakers closed, with no TRIP line, the earlier
    audit bytes unchanged and the chain valid;
  - a new lockout after the restart is a high finding and trips the breakers;
  - a new wrong code after the restart is still seen;
  - a RESET drops lockout and failed-code events but keeps a burst;
  - a lockout after a RESET still counts;
  - only old lines are skipped at start-up;
  - a shortened file is read again from the top;
  - the full demo story: lock out, restart, approvals unlocked, breakers closed, no re-trip.

  Re-running the original reproduction now prints `after first monitor round: breaker False []`.
- Limit: a slow pattern that spans a restart is not linked up. The Gate's own memory of recent
  payments is also cleared by a restart.

The original report follows.

**Where:** `tollgate/sentinel/monitor.py:52` (`self._seen_lines = 0`) and
`tollgate/sentinel/monitor.py:75` (`when = now_wall` for service events).

**What happens:** the audit file lives on disk (`data/audit.jsonl`) and survives a restart.
A new `AuditReader` starts at line 0 and reads the whole file. Approval-service lines
(LOCKOUT, FACTORFAIL) are timed with a monotonic clock, so the monitor stamps them with the
time it *first sees* them. After a restart, every old LOCKOUT is therefore "new": it opens a
HIGH finding and trips both breakers on the first monitor round. A reset from the Sentinel page
is then refused, because a high finding is open, until the finding ages out of the 30-minute
window.

**Reproduced:** a scratch script (not in the repo) built an app context in a temp folder,
called `service._lock_out(...)`, then built a second context on the same folder as a
"restart". Output:
```
run 1 locked: True
after restart: breaker False locked False
after first monitor round: breaker True ['Approvals locked after failed codes']
```

**Impact:** fail-closed, so nothing gets looser. But the documented recovery is wrong: the
README line "If approvals lock during the demo, stop the app and start it again" and the
"Restarting the app" option in `docs/sentinel.md` do not work as written. The breakers stay
open, and cannot be reset from the page, for up to 30 minutes.

**Suggested fix:** at Sentinel start-up, skip the lines already in the file (set
`_seen_lines` to the current line count on the first read, without turning them into events),
so only lines written after start are watched. Alternatively, time service events from a wall
clock written into those lines. Add a test: lock out, "restart" on the same folder, run every
job, and check the breakers stay closed.

## 2. Medium: demo login can drive the real Braintree sandbox

**Where:** `tollgate/app/main.py:117` (demo auth gives a `Mode.MOCK` account with the public
fake TOTP secret) and `tollgate/app/main.py:122` (the backend comes from `TOLLGATE_MODE`,
independently of the auth mode).

**What happens:** `TOLLGATE_AUTH_MODE=demo` (the default) together with
`TOLLGATE_MODE=sandbox` is accepted. The documented demo password and the public mock secret
can then approve real calls to the Braintree sandbox.

**Confirmed by reading:** `build_context` reads the two variables separately, and nothing
refuses the combination.

**Impact:** sandbox only (fake money), and the app listens on 127.0.0.1 only. But anyone on
the machine, or any local process, can approve sandbox charges with public credentials.

**Suggested fix:** fail closed at start-up. If the auth mode is demo and the backend mode is
not mock, raise `ConfigError` ("demo login only with the mock backend"). Add a test that this
combination refuses to start.

## 3. Medium: a queued reset can close a newer, unrelated trip

**Where:** `tollgate/app/breaker_reset.py:90-104` (`apply_due`; the reset itself is at line
104).

**What happens:** in real mode, Reset breaker waits 15 minutes. When the wait ends,
`apply_due` checks only two things: approvals are not locked, and no critical or high
finding is open at that moment. It does not check whether the breaker tripped again during the
wait. Examples: the Gate trips it on a velocity burst, or Sentinel trips it for a finding that
resolves before the 15 minutes end. The queued reset then closes that newer trip as well,
although the approver only asked to undo the earlier one.

**Confirmed by reading.** No test covers a second trip during the wait.

**Impact:** a loosening action can apply to a situation the approver never saw.

**Suggested fix:** record a trip counter (or the time of the last trip) when the reset is
queued, and drop the reset (audited `CANCEL`) if any breaker tripped again before it
applies. This needs a small read-only trip counter on the breaker. Add a test: queue a reset,
trip again during the wait, and check the breaker stays open.

## 4. Low: login and setup rate limits can be raced

**Where:** `tollgate/app/routes.py:185-193` (login: `is_locked` at 185, the password check
in a thread pool, `record_failure` at 193) and `tollgate/app/routes.py:368-372` (setup
confirm).

**What happens:** "is it locked?" and "record a failure" are two separate steps, with the slow
PBKDF2 check in between. Many requests sent at the same moment all pass the check before any
failure is recorded, so more than 5 guesses get through in one burst.

**Confirmed by reading.** No test sends parallel requests.

**Impact:** the 600,000-round PBKDF2 limits the rate, and the setup confirm also needs the
setup cookie and only accepts 3 valid codes out of a million. The lockout can still be
exceeded.

**Suggested fix:** reserve an attempt atomically before the check, for example a
`LoginLimiter.try_begin(name, ip)` that counts the attempt under the lock and refuses at the
limit, and clear it on success. Add a test that fires parallel wrong logins and checks that at
most 5 are evaluated.

## 5. Low: concurrent Sentinel rounds share an unlocked audit reader

**Where:** `tollgate/app/routes.py:293` ("Scan now" runs `run_all_now` in a thread pool),
`tollgate/app/main.py:171` (the 5-second loop runs `run_due` in another thread), and
`tollgate/sentinel/monitor.py:55-65` (`AuditReader.read`, no lock).

**What happens:** a "Scan now" press can run at the same time as a loop round. Two monitor
reads can then share the reader's line counter and event list, so lines are counted twice
(giving false burst or repeated-block findings, which only tighten) or skipped (a missed
detection). The finding store is locked, so findings themselves do not duplicate.

**Confirmed by reading.**

**Suggested fix:** one `threading.Lock` in `Sentinel` around `run_due` and `run_all_now`,
so only one round runs at a time. Add a test that runs both from two threads and checks the
events are counted once.

## 6. Low: approval-time velocity ignores a tightened Gate setting

**Where:** `tollgate/approval/service.py:135` (`self._gate = gate_config or GateConfig()`)
and `tollgate/approval/service.py:213` (the velocity window used at approval time).

**What happens:** the approval service checks per-recipient velocity against its own copy
of the default Gate settings. When Sentinel tightens the executor's velocity settings with
`tighten_config`, the approval-time check keeps the default.

**Confirmed by reading.**

**Impact:** nothing gets looser. The executor still applies the tighter value when it sends,
so the payment is blocked there, but the approver gets a later and less clear refusal.

**Suggested fix:** let the service read the executor's current `config` (a read-only
callable passed in at wiring), instead of its own copy.

## 7. Info: first visitor sets up real mode

**Where:** `tollgate/app/routes.py:349` (`setup_start`).

**What:** in real mode with no approver yet, whoever reaches `/setup` first becomes the
approver. This is by design (trust on first use), localhost only, and stated on the setup
page. **Suggested:** an optional one-time setup token printed by `run_app.py` at start-up.

## 8. Info: demo cookies are not Secure

**Where:** `tollgate/app/routes.py:61` and `:68`.

**What:** demo mode serves plain http, so its cookies are not `Secure` and have no `__Host-`
prefix. Real mode sets both. By design. **Suggested:** none beyond keeping demo mode
localhost-only.

---

## 9. Low (documented limit, not fixed): the real-mode approver account is lost on restart

**Where:** `tollgate/approval/accounts.py` (`ApproverAccount`: name, password hash and TOTP
checker are plain attributes in memory) and `tollgate/app/main.py:117` (a new, unenrolled
account at every start in real mode).

**What happens:** only the audit log, outbox and incident reports are written to disk. After
a restart in real mode the app has no approver, so setup must be done again, and whoever
reaches `/setup` first becomes the approver (finding 7).

**Confirmed by reading:** no code writes the account anywhere. A grep for file writes in
`tollgate/` finds only the audit log, the outbox and the incident reports.

**Impact:** an operations gap rather than a way in: the app listens on 127.0.0.1 only, and
held payments are also cleared by a restart. The window is between a restart and the owner
finishing setup.

**Suggested fix (not built):** store the account (name, password hash with its round count,
TOTP secret encrypted at rest, alert destination) in a file only the app user can read, or
require a one-time setup token printed at start-up (see finding 7).

## 10. Low (documented limit, not fixed): the memory of used codes is lost on restart

**Where:** `tollgate/approval/totp.py` (`TotpChecker._last_used_step`, in memory only).

**What happens:** replay protection remembers the last accepted 30-second step only in
memory. After a restart, a code used just before the restart can be accepted once more while
it is still inside the accepted window (current step plus one either side). That is at most
about 60 to 90 seconds after it was first shown.

**Confirmed by reading.** In real mode the account is also lost on restart (finding 9), so
this matters only once something keeps the account across restarts. In demo mode the secret
is public anyway.

**Impact:** low. It needs the old code, the approver session (sessions also end on restart)
and a restart, all inside about a minute.

**Suggested fix (not built):** keep the last used step with the stored account (finding 9),
or refuse codes for the first 90 seconds after a start.

## Checked and found sound
- **Approving or moving money:**
  - Every approval goes through `ApprovalService.authorize`, which needs a live approver
    session and a code.
  - TOTP codes work once per 30-second step and are compared in constant time.
  - Grants are single use, bound to the exact request id, amount and recipient, and expire.
  - The executor refuses a duplicate request id, so two approvals of the same item at once
    cannot pay twice.
  - Three bad codes lock approvals, trip both breakers and end every session.
  - `verify_step_up`, used by Reset breaker, shares the same counter towards that lockout.
- **Loosening:**
  - `Executor.tighten_config` (`executor.py:118-137`) refuses anything looser, equal,
    unknown, invalid or a bool; every value it accepts is stricter.
  - Sentinel's `Tightener` holds only trip and tighten methods.
  - A code check confirms Sentinel never calls approve, execute, release, reset or unlock.
  - Drills never receive the live app objects.
- **Secrets:**
  - The audit log and outbox redact text that looks like a secret.
  - Findings and incident reports are masked.
  - Account, grant and signer objects hide their tokens when printed.
  - The planted drill key never reaches a page or a log.
  - Real mode never shows a code (tested).
- **CSRF and cookies:**
  - Every POST checks a CSRF token, including login and setup (through the pre-login
    cookie), and compares in constant time.
  - Cookies are signed, HttpOnly and SameSite=Strict, and in real mode also Secure with
    `__Host-`.
  - Any `Authorization` header is refused.
  - Every response gets `no-store`, a strict CSP and frame denial, errors included.
- **Races:**
  - The executor, the approval service, the stamp store and each audit file are serialised
    with their own locks.
  - Approvals released after cooling-off are sent outside the service lock, so they cannot
    deadlock with the executor.

## Limits of this review
Findings 9 and 10 were added on 2026-11-12 while planning the fix for finding 1. They come
from reading the code, and neither was fixed.

One person reading the code, plus one reproduction. Nothing was run against the Braintree
sandbox, no parallel-request test was run, and no browser was used. Results apply to this
code and these tests only.
