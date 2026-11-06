# Tollgate

A payment firewall for AI agents.

> **Sandbox only. Fake money.** Tollgate runs against the Braintree **sandbox**
> (or a built-in mock). It never touches real cards, real money or real customer data.

- **Gate**: an AI agent can only *propose* payments. Money moves only through the
  executor, and only with a valid, single-use approval stamp.
- **Sentinel**: scheduled checks that find weak spots and may only *tighten* settings.

## Quick start (Windows PowerShell)

```powershell
.venv\Scripts\pip.exe install -r requirements.txt
.venv\Scripts\python.exe -m pytest -q
```

Mode is set by `TOLLGATE_MODE`:
- `mock` (default): no keys needed.
- `sandbox`: uses Braintree sandbox keys from `.env` (copy `.env.example`).

Smoke test (sandbox keys required): `.venv\Scripts\python.exe scripts\smoke_test.py`
prints `client token OK` on success.

## What works now (after Phase 3a)

Last full run, mock mode, no network: **194 passed, 1 skipped**. The skipped test makes a
real Braintree sandbox call and runs only when sandbox keys are set.

| Part | What it does | Tests |
|------|--------------|-------|
| Gate rules | Decide ALLOW, HOLD (needs a person) or BLOCK for each request. Any error means BLOCK. | 30 rules + 18 request checks |
| Approval stamps | A person's approval works once, for one amount and recipient, for 5 minutes. | 17 |
| Audit log | Records every decision; editing, deleting or reordering lines is detected. | 11 |
| Executor | The only code that moves money: re-checks the Gate, needs a stamp for HOLD, trips the breaker on too many payments. | 20 |
| Payment backends | Mock money in memory. Braintree code checked offline against a fake gateway: exact cents, refuses anything but sandbox, errors give no details. (The real sandbox call was skipped in this run.) | 18 |
| Mode switch | `mock` or `sandbox` only; anything else is an error. | 7 |
| Import guard | Only the backend file may use Braintree; the agent never touches the executor. | 3 |
| Agent (scripted) | Can only propose. 4 normal scenarios run; 7 scripted attacks all end BLOCK or HOLD with no money moved. | 70 |
| Disputes and subscriptions | **SIMULATED** in memory, no Braintree data, but they go through the same Gate rules. | included in the 70 |

Limits: the agent uses a scripted model, not a real AI. Results apply to this sandbox and
these tests only. Details: [docs/agent-policy.md](docs/agent-policy.md),
[docs/executor.md](docs/executor.md), [docs/gate.md](docs/gate.md).

License: MIT.
