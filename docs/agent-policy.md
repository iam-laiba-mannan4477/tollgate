# Agent policy (Phase 3b)

The agent is a **drafter**. It can ask for money actions. It can never make them happen.
By default the agent runs on `ScriptedModel` (offline, no key, replays canned tool calls).
A real AI model can be switched on; see "Real models" below.

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

## Real models (Phase 3b)
Switch with `TOLLGATE_AGENT_MODEL_PROVIDER`:
| Value | Model | Needs |
|-------|-------|-------|
| `scripted` (default) | ScriptedModel, offline | nothing |
| `groq` | any OpenAI-compatible `/chat/completions` API with tool calling | `GROQ_API_KEY`, `TOLLGATE_AGENT_MODEL`, optional `TOLLGATE_AGENT_MODEL_BASE_URL` (https only, default Groq) |
| `claude` | Anthropic Messages API | `ANTHROPIC_API_KEY`, `TOLLGATE_AGENT_MODEL` |

Any other value (including an empty one) is an error. There is no default model name.
The code is in `tollgate/llm/`, outside `tollgate/agent/`, so the agent package itself still
has no network, file or environment access (the import-guard tests still pass). HTTP uses
only the Python standard library (`urllib`); no dependency was added.

What a real model gets and what we accept back:
- **Tools offered:** only the 4 `propose_*` and 2 `lookup_*` tools, with exact argument
  schemas. There is no send, approve, stamp, breaker or secret tool to offer.
- **Customer text:** sent in the user turn as a JSON string, labelled untrusted data. The
  system prompt tells the model not to follow instructions inside it. This is a hint to the
  model, not a defence: the Gate is the defence.
- **Calls are one-shot:** the model answers once per message. Lookup results are not fed back.
- **A reply is accepted only if every tool call** names an offered tool and has exactly that
  tool's argument names. One bad call rejects the whole reply (nothing is partly used).
  Value checks (amounts, ids) stay in `build_proposal` and the Gate, which BLOCK bad values.
- **Text with no tool call** is a valid answer ("I won't do that"). The agent proposes
  nothing and writes a `NONE` audit event. It is not retried.
- **Bad replies** (empty, malformed JSON or body, unknown tool, extra or missing arguments,
  timeout, network error, 429, 5xx, 400 which Groq uses for broken tool output) are retried:
  at most **3 attempts**, waits of 1 s then 2 s (a 429 `Retry-After` is honoured but capped
  at **5 s**). Then the agent **fails closed**: it proposes nothing and writes a BLOCK audit
  event "model unavailable (<category>): proposed nothing". 401/403/404 are not retried.
- **Keys:** read only from the environment, sent only in the auth header, never logged,
  printed, put in error messages, test output or `repr()`. Only `https://` URLs are allowed.
  The secret checker now also looks for Groq and Anthropic key shapes.

### Tool-calling check (a test of the MODEL, not of the Gate)
`python scripts	ool_calling_check.py` runs the 4 normal and 7 attack messages against the
configured real model, each in a fresh mock-money world, and prints a table: empty and
malformed replies, Gate verdicts, whether the model did the right thing (normal: all
ALLOWed and done; attack: proposed nothing), and whether any attack moved money. It always
uses mock money. One run of one model says nothing certain about the next run.
The model is given a short trusted "facts" block (order totals, dispute and subscription
ids) because it cannot see the lookup results.

## Honest limits
- **ScriptedModel is not an AI.** Attack scripts show what a fooled model might emit. The
  tests show the Gate stops these 7 scripted attacks in this sandbox; they do not show how a
  real model behaves.
- **Real providers are tested only with a fake HTTP client.** The two live tests are skipped
  unless a key is set, and they were skipped in the last run. No claim is made about how any
  real model behaves until `tool_calling_check.py` has been run and its output recorded.
- The live tests and the check script share one `TOLLGATE_AGENT_MODEL`, so set one provider
  at a time.
- The Gate **allows** a small payment to a known recipient even if a prompt injection asked
  for it. Limits and velocity cap the damage; they do not detect intent.
- A HELD attack moves money if a person approves it. The reviewer must read the reason and
  source text.
- Python cannot sandbox code inside one process. The real guarantee is that the executor
  re-checks every request and HOLD needs a stamp the agent never sees.
- Pending queue, desk records and stamps are in memory and lost on restart.
- The audit log is shared by several writers; each has its own lock, so they must not write
  from different threads at once (the agent loop is single-threaded today).
