# The executor (Day 3)

`tollgate/executor/` is the only code that moves money (Braintree **sandbox** or the mock).

## Files
- `backend.py`: the `Backend` interface (`charge`, `refund`), `MockBackend` (in memory, no keys)
  and `BraintreeBackend`. **The only file in the project that imports `braintree`**, which a test
  enforces. It refuses to start unless `TOLLGATE_MODE=sandbox` and the gateway environment is
  Sandbox. Charges use the sandbox test nonce `fake-valid-nonce` with `submit_for_settlement`.
  Refunds first call `gateway.testing.settle_transaction` (sandbox only) and then
  `transaction.refund`. Cents become decimal strings exactly (`100 -> "1.00"`), with no floats.
  Gateway errors return a generic reason; raw error bodies and keys are never returned or printed.
- `executor.py`: `Executor.execute(request, stamp=None, refund_of=None)`.

## How execute works
1. Validates the request and refuses a request id that already executed (idempotency).
   The id is used up just before the backend call, so a failed or timed-out send cannot be
   retried under the same id.
2. Re-runs the Gate with the executor's **own** state. It never takes state from the caller.
3. A velocity violation (a third payment to one recipient within 10 minutes) **trips the breaker**.
   From then on everything is BLOCK until a person calls
   `reset_breaker(person, reason)`. Both arguments are required, and the reset is audit-logged.
4. ALLOW goes ahead. HOLD goes ahead only with a stamp issued for this exact request id, amount
   and recipient (single use, 5 minutes). Get one with `approve(request, grant)`.
   **Phase 3c:** `approve` needs a single-use **grant** from the step-up approval service
   (`tollgate/approval`, see [gate.md](gate.md)): the approver's session plus a fresh
   second-factor code, and for big amounts a cooling-off wait first. A person's name is no
   longer enough. The grant is used up even if it does not match. An executor built without
   a grant service (`grants=None`) refuses every approval (fail closed).
5. Checks the breaker again right before sending.
6. Writes one audit event for every attempt (success, HOLD, BLOCK, backend failure).
7. Updates state (known recipients, velocity history, ledger) **only after a successful send**.

Refunds name the original request id (`refund_of`). The order total and the remaining refundable
amount come from the executor's ledger. A refund that claims a different order total, names a
different recipient, or exceeds what remains is blocked.

## Approval wiring (Phase 3c)
```python
approvals = build_service(account, audit_path, outbox_path, clock=clock)
executor = Executor(backend, audit_path, clock=clock, grants=approvals.redeem)
connect(approvals, executor, desk)       # an approval lockout trips both breakers
```
New read-only/tightening methods: `knows_recipient(recipient)` and `trip_breaker()` (opens the
breaker, never closes it). The simulated desk got the same `approve(request, op, grant)`,
`knows_customer` and `trip_breaker`.

## Honest limits
- **Braintree has no supplier payout.** It can charge a customer and refund a charge; it cannot
  send money to a third party. So "recipient" is a label tracked in **Tollgate's own ledger**.
  Rules about recipients (new recipient, velocity) apply to that ledger. Only charges and
  refunds are real sandbox transactions.
- State (ledger, history, known recipients, stamps, breaker) is in memory and lost on restart.
  After a restart every recipient is new again (HOLD), and the breaker starts closed.
- One lock serialises `execute`, including the network call. That is safe, but slow under load.
- Sandbox only. Results apply to this sandbox and these tests.

## Try it
- Mock (no keys): `python -m pytest -q`
- Real sandbox: `$env:TOLLGATE_MODE="sandbox"; python scripts\sandbox_demo.py`
- Sandbox test: `$env:TOLLGATE_MODE="sandbox"; python -m pytest -q -m sandbox`
