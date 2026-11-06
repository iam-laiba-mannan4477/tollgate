# Agent policy (Phase 3a)

The agent is a **drafter**. It can ask for money actions. It can never make them happen.
There is no real AI model yet: the agent runs on `ScriptedModel`, which replays canned
tool calls.

## What the agent CAN do
| Tool | What it does |
|------|--------------|
| `propose_payment` | Ask to pay a recipient (amount, recipient, reason). |
| `propose_refund` | Ask to refund part or all of an earlier charge. |
| `propose_dispute_response` | Ask to accept or contest a dispute. **SIMULATED.** |
| `propose_subscription_change` | Ask to change a plan price or cancel. **SIMULATED.** |
| `lookup_order`, `lookup_customer` | Read-only reference data. Never used as truth for money. |

## What the agent CANNOT do
- Send money, approve, issue or see stamps, reset a breaker, or read keys, files or `.env`.
  No tool exists for any of these. A tool name the model makes up (for example
  `execute_payment`) is blocked and logged.
- Add extra fields. Each tool takes an exact list of arguments; anything else (like a
  smuggled `stamp` or `via_agent`) blocks the proposal.
- Make more than **3 proposals** or **6 tool calls** for one message. Extras are blocked.

## How a proposal flows
1. A message arrives. Its text is **data**. It goes to the model and is copied into the
   proposal for the record. Tollgate never follows instructions found in it.
2. The model returns tool calls. Each is checked (amount must be whole cents, more than 0,
   at most $100,000; ids must be plain text; reason 1 to 200 characters).
3. The proposal goes to the agent's `DrafterHandle`, which submits it **with no stamp**:
   - payments and refunds go to the executor, which re-runs the Gate with its own state;
   - disputes and subscriptions go to the simulated desk, which runs the same Gate rules.
4. **ALLOW** runs. **HOLD** waits in a queue for a person. **BLOCK** stops.
5. Every tool call writes one audit event (agent side), and every executor or desk attempt
   writes its own event, all in the same hash-chained log.

## Roles (least privilege)
| Role | Holds | Can |
|------|-------|-----|
| Drafter (agent) | `DrafterHandle` | `submit` a proposal. Nothing else. |
| Reviewer (person) | `ReviewerHandle` | List, approve or reject HELD proposals. Must give a name; names like `agent`, `ai`, `bot` are refused. |
| Executor | `tollgate/executor` | The only code that moves money. |

How this is enforced in code: the agent receives only the drafter handle (a closure with
one method, read-only). Tests check that the `tollgate/agent` package imports only its own
modules, `tollgate.gate.models` and `tollgate.gate.audit`, never the executor, stamps or
roles, and uses no `open`, `eval`, `exec`, `getattr` or environment access.

## Simulated disputes and subscriptions
The Braintree sandbox may not give real dispute data, so disputes and subscriptions are kept
in an in-memory store (`tollgate/simulated/desk.py`). They are **SIMULATED**: no Braintree
call is made and nothing real changes. They still go through the Gate: the amount at stake
becomes a Gate request, so the $1,000 limit, the new-customer HOLD, velocity and the breaker
all apply. The desk also blocks wrong amounts, the wrong customer, and changing a dispute
that is already resolved or a subscription that is cancelled.

## Honest limits
- **ScriptedModel is not an AI.** Attack scripts show what a fooled model might emit. The
  tests show the Gate stops these 7 scripted attacks in this sandbox; they do not show how a
  real model behaves.
- The Gate **allows** a small payment to a known recipient even if a prompt injection asked
  for it. Limits and velocity cap the damage; they do not detect intent.
- A HELD attack moves money if a person approves it. The reviewer must read the reason and
  source text.
- Python cannot sandbox code inside one process. The real guarantee is that the executor
  re-checks every request and HOLD needs a stamp the agent never sees.
- Pending queue, desk records and stamps are in memory and lost on restart.
- The audit log is shared by several writers; each has its own lock, so they must not write
  from different threads at once (the agent loop is single-threaded today).
