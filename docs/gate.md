# The Gate (Day 2, offline; step-up approval added in Phase 3c)

All code lives in `tollgate/gate/`. No Braintree calls, no keys.

| File | Purpose |
|------|---------|
| `models.py` | `Request`, `Decision` (ALLOW/HOLD/BLOCK + reason), `validate_request`. Amounts are positive int cents, max $100,000. |
| `rules.py` | `evaluate(request, state, config)`: pure, fails closed (any error -> BLOCK). `GateConfig` holds limits; stamp lifetime can never exceed 300 s. |
| `stamps.py` | `StampStore`: one-time stamps for HELD requests, bound to amount + recipient, 5-minute expiry, only the SHA-256 hash stored, lock + constant-time compare. A failed spend with a real stamp burns it (stricter choice). |
| `audit.py` | Append-only JSON-lines log, each line hash-chained to the previous. `verify()` detects edits, deletions and reordering. Secret-looking text is redacted. |
| `breaker.py` | `CircuitBreaker` flag. Tripping on velocity is wired up on Day 3. |

Decision order: breaker open -> BLOCK; not via agent -> BLOCK; refund > order total -> BLOCK;
more than 2 payments to one recipient in 10 min -> BLOCK (flags `trip_breaker`);
over $1,000 or new recipient -> HOLD; otherwise ALLOW.

Known limits:
- Deleting lines from the end of the audit log is only caught if you pass the last known
  hash to `verify(path, expected_last_hash=...)`.
- The stamp store is in memory; stamps are lost on restart (fails closed: they stop working).
- Velocity counts both payments and refunds to a recipient (stricter).

## Step-up approval (Phase 3c)

Code: `tollgate/approval/` (standard library only). Goal: a stolen logged-in approver
session **alone** cannot approve a payment.

| File | Purpose |
|------|---------|
| `totp.py` | RFC 6238 TOTP (HMAC-SHA1, 30 s, 6 digits), checked against the RFC test vectors. Accepts one step of clock drift either side. **Each code works once**: a used step, or any older step, is refused. A fixed `MOCK_TOTP_SECRET_B32` exists for mock mode only and is refused in sandbox mode. |
| `accounts.py` | The one approver account: name, password (PBKDF2-SHA256, salted, 600,000 rounds; each hash stores its own round count so older hashes still verify), sessions (random token, only its hash kept; expire after 1 hour or 15 minutes idle) and the TOTP checker. Setup runs once; it cannot be re-run after enrolment. Web setup runs in two steps (`begin_enroll`, then `confirm_enroll` with the first code). Agent names (`agent`, `ai`, `bot`, ...) cannot enrol. |
| `policy.py` | `ApprovalPolicy`: every tier and limit below is config. |
| `service.py` | `ApprovalService`: authorize, delays, release, cancel, cap, lockout, guarded settings changes, and the single-use **grants** the executor and desk require. |
| `outbox.py` | Owner notifications, written to an outbox **file** (no real email). |

### Tiers (defaults, waiting for the owner's sign-off)
| Request | What happens |
|---------|--------------|
| Up to $1,000, known recipient | ALLOW, unchanged; no approval needed |
| Any HELD request | Needs the approver session **and** a fresh second-factor code |
| Over $10,000 | Also a **15-minute cooling-off** before a grant exists; the owner is notified and can cancel |
| New recipient **and** over $1,000 | Always gets the cooling-off |
| Approved value in a rolling 24 h over $25,000 | BLOCK |

### Order of checks when a person approves
1. Approvals locked → refused.
2. Not a live session of the enrolled approver (the agent role, a forged or ended session) → refused.
3. Code wrong, missing, replayed or expired → refused and counted. **3 failures in a row** lock
   approvals, trip the executor and desk breakers, end every session, write a `LOCKOUT`
   audit event and notify the owner. Only `unlock(person, reason)` reopens it (audited).
4. More than 10 approvals in the last hour → refused (the item stays pending).
5. Velocity: approvals to one recipient in 10 minutes, **waiting ones included**, at the Gate
   limit (2) → BLOCK.
6. Cap: the 24 h total, **waiting ones included**, would pass $25,000 → BLOCK. Cancelled or
   blocked approvals still count until they age out (stricter).
7. Delay tier → DELAYED (no grant yet). Otherwise GRANTED: a grant bound to the exact
   request id, amount and recipient, single use, valid 60 s.

At release (`release_due()`, after the delay on the injected monotonic clock): approvals
must not be locked, the breaker must be closed, and the Gate must give **exactly** the
same HOLD decision as at approval time. Anything else → BLOCK, audited. Below the delay
tier, an approval still sends at once (this replaces Phase 3a's "approval sends at once").

### Settings changes
Changing the approver's password, re-enrolling the authenticator, changing the alert
destination, or raising any limit needs a live session **and** a fresh code. It then waits
out its own 15-minute cooling-off, with an owner notification (an alert destination change
also notifies the new destination), and can be cancelled. Lowering a limit is tightening
and applies at once (`tighten()`, which refuses anything that would loosen).

### Clock
Delays, cap and rate use the injected clock (monotonic by default), never the request's
`created_at` or the wall clock. If that clock ever goes backwards, approvals lock and the
breakers trip (fail closed). TOTP uses a separate injected wall clock.

### Audit
Events: `GRANT`, `DELAY`, `RELEASE`, `CANCEL`, `REFUSED`, `FACTORFAIL`, `LOCKOUT`, `UNLOCK`,
`CHANGE`, `CHANGED`, `TIGHTEN`, `BLOCK`. Each names the approver and the reason. They never
contain codes, secrets, passwords, session tokens or grant tokens (a test checks this).
Every `AuditLog` writing to the same file now shares **one lock per file**, so several
writers and threads cannot break the hash chain (concurrency test: 8 threads, 4 writers).

### Honest limits
- This **reduces** the risk of a stolen session; it does not remove it. An attacker who holds
  both the session and the second-factor device (or its secret) can still approve.
- The cooling-off only protects if the owner **sees the alert**. In sandbox the alert is a
  line in a file; a real deployment needs email or push.
- One approver account only. Sessions now expire (Phase 3d): 1 hour after login, or after
  15 minutes idle; they also end on logout, lockout, password change and re-enrolment.
  Cancel and unlock need a named person but no code: cancelling only tightens, and unlock
  is an operator action with no web page (see [web.md](web.md)).
- Someone who controls the process clock or the code itself can skip any delay. Python cannot
  protect against code running in the same process.
- All of this is in memory and lost on restart (waiting approvals then never release: fail closed).
- Tested in mock mode with a fake secret and fake clocks; results apply to these tests only.
