# The Gate (Day 2, offline)

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
