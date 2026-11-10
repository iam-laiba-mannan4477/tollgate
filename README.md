# Tollgate

A payment firewall for AI agents.

> **Sandbox only. Fake money.** Tollgate runs against the Braintree **sandbox**
> (or a built-in mock). It never touches real cards, real money or real customer data.

**Problem:** AI agents are being given the power to move money, and nothing independent stands between a tricked agent and a real transaction. An agent reads text (refund requests, customer notes, order comments), and anything it reads can carry an attacker's instructions.

**Evidence:** Card networks and bank technology vendors are building ways for AI agents to pay. Several major US banks (JPMorgan, Schwab, Citi) have said they block or limit outside agents from acting inside customer accounts; reported concerns include that an agent using a customer's login has no separate limits, approvals or audit trail, and prompt injection. In 2026 Binance reported that attackers reached its internal wallet signing service through engineers' computers, an internal AI tool and a stolen deployment token, and started transactions outside the normal withdrawal process (about $6.34 billion affected, per Binance).

**Gap:** Those reported concerns are the missing controls: separate limits, approvals, an audit trail, and protection from a tricked agent.

**Solution:** Tollgate is that layer. The agent can only propose. A Gate decides ALLOW, HOLD or BLOCK. Big or unusual payments need a person with a one-time code, and the largest get a cooling-off period with an alert and a cancel option. Every decision goes in a tamper-evident log, and it fails closed. Built and tested on the Braintree sandbox with test money only.

**Limits:** Sandbox and mock only. Tollgate protects only the paths that go through it; an attacker holding raw payment API keys bypasses it. Disputes and subscriptions are SIMULATED.

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

## What works now (after Phase 3c)

Last full run, mock mode, no network: **364 passed, 3 skipped** (367 collected). The skipped
tests make a real call (one Braintree sandbox, one Groq, one Claude) and run only when those
keys are set; all three were skipped in this run.

| Part | What it does | Tests |
|------|--------------|-------|
| Gate rules | Decide ALLOW, HOLD (needs a person) or BLOCK for each request. Any error means BLOCK. | 30 rules + 18 request checks |
| Approval stamps | A stamp works once, for one amount and recipient, for 5 minutes. | 17 |
| Audit log | Records every decision; editing, deleting or reordering lines is detected. All writers to one file share one lock. | 11 (+1 thread test in step-up) |
| Executor | The only code that moves money: re-checks the Gate, needs a stamp for HOLD, trips the breaker on too many payments. A stamp now needs a step-up grant, not just a name. | 20 |
| Step-up approval | Approving needs the approver's session **and** a one-time TOTP code. A stolen session alone, the agent role, and wrong, replayed or expired codes are refused. Over $10,000 (or over $1,000 to a new recipient) waits 15 minutes; the owner is notified (outbox **file**, no real email) and can cancel. 24 h cap of $25,000 counts waiting approvals too. 3 bad codes lock approvals and trip the breaker. At release the Gate and breaker are checked again. Settings changes need a fresh code and wait too. | 68 |
| Payment backends | Mock money in memory. Braintree code checked offline against a fake gateway: exact cents, refuses anything but sandbox, errors give no details. (The real sandbox call was skipped in this run.) | 18 |
| Mode switch | `mock` or `sandbox` only; anything else is an error. | 7 |
| Import guard | Only the backend file may use Braintree; the agent never touches the executor. | 3 |
| Agent (scripted) | Can only propose. 4 normal scenarios run; 8 scripted attacks (new: stolen approver session) all end BLOCK or HOLD with no money moved. | 74 |
| Real model providers | Optional Groq (any OpenAI-compatible API) or Claude model behind the agent, offered only propose/lookup tools. Bad replies are retried at most 3 times, then the agent proposes nothing. Redirects are refused so the key is never forwarded. Tested with a fake HTTP client only; no real model was called in this run. | 98 (+2 skipped live) |
| Disputes and subscriptions | **SIMULATED** in memory, no Braintree data, but they go through the same Gate rules and the same step-up approval. | included in the 74 |

Limits: step-up approval **reduces** the risk of a stolen approver session; it does not
remove it. Someone holding both the session and the authenticator can still approve, and the
15-minute wait only helps if the owner sees the alert (here a file, not email). Tested with
the fake mock TOTP secret and fake clocks only. By default the agent uses a scripted model,
not a real AI; real-model behaviour is untested until `scripts\tool_calling_check.py` is run.
Results apply to this sandbox and these tests only. Details:
[docs/gate.md](docs/gate.md), [docs/executor.md](docs/executor.md),
[docs/agent-policy.md](docs/agent-policy.md).

License: MIT.
