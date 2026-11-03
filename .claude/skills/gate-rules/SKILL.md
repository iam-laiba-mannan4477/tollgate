---
name: gate-rules
description: Use when writing or changing Tollgate Gate code: rules, approval stamps, circuit breaker, executor, audit log.
---
# Gate rules

Decision order for every proposed request: ALLOW, HOLD (needs a person), or BLOCK.
1. Circuit breaker open -> BLOCK.
2. No approval path (direct call, no stamp) -> BLOCK.
3. Refund larger than the order total -> BLOCK.
4. More than 2 payments to one recipient in 10 minutes -> BLOCK and trip the breaker.
5. Amount over the auto limit (default $1,000) or a new recipient -> HOLD.
6. Otherwise ALLOW.

Invariants (write a test for each):
- Errors or unknown input fail closed (HOLD or BLOCK).
- A stamp works once, for one amount and one recipient, for at most 5 minutes.
- Only the executor imports Braintree. The agent package must never import it.
- Every decision writes one audit event: id, time, decision, reason, amount, recipient. No secrets.
- Rules are plain code. No AI model sits in the decision path.
- Amounts are integers in cents, not floats.
- Use constant-time comparison for stamp checks and a lock so one stamp cannot be spent twice at once.
