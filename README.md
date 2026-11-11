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

## Run the web app

```powershell
.venv\Scripts\python.exe scripts\run_app.py
```

Open http://127.0.0.1:8000. Demo mode is the default: log in as `demo-owner` /
`demo-password-not-secret` (a fake, documented demo account); the approvals page shows the
current one-time code. For real mode (`TOLLGATE_AUTH_MODE=real`, QR setup, your own
authenticator app) see [docs/web.md](docs/web.md). The app listens on 127.0.0.1 only.

If approvals lock during the demo (3 wrong codes), stop the app and start it again: approvals
unlock, the breakers start closed, and the two demo payments come back. The audit log keeps
the history.

### What a restart clears
Only three files survive a restart, all in `data/`: the audit log (`audit.jsonl`), the owner
notices (`outbox.jsonl`) and Sentinel's reports (`incidents.jsonl`). Everything else is held
in memory, so stopping and starting the app clears it:
- the approvals lock (after 3 wrong codes) and the wrong-code count;
- both circuit breakers (they start closed, and Sentinel does **not** re-trip them from old
  audit lines: it only counts lines written after start-up);
- login sessions and the 15-minute login lock;
- held payments, and approved payments still in cooling-off (those are **never sent**: the
  restart drops them);
- stamps and the list of known recipients (every recipient is new again, so payments to
  them are held);
- Sentinel findings, resolved findings, drill results and a queued breaker reset;
- in **real mode**, the approver account itself: you must do the setup again, and whoever
  reaches `/setup` first becomes the approver (security review findings 7 and 9);
- the memory of which codes were already used (finding 10).

Demo mode creates its two example payments again on every start.


## What works now (after Phase 3d)

Last full run, mock mode, no network: **647 passed, 3 skipped** (650 collected). The skipped
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
| Web login and sessions | The owner logs in with name and password; the agent has no login. Signed HttpOnly, SameSite=Strict cookies; sessions end after 1 hour, or 15 minutes idle, and on logout. 5 failed logins in a minute (per name or IP) lock login for 15 minutes. | 18 |
| CSRF | Every form that changes something needs a matching token; missing or wrong is refused and audited. | 10 |
| Web attacks | A stolen session with no code cannot approve (3 tries lock approvals, trip the breaker, end the session). Any `Authorization` header, a forged or wrongly signed cookie, and the agent role are refused at approve. Untrusted text is shown escaped. No money moved in any of them. | 12 |
| Demo and real modes | `TOLLGATE_AUTH_MODE` = `demo` (default: DEMO banner on every page, documented fake account, code shown on screen, fake secret only) or `real` (no default account, 12+ character password, code never shown, fake secret refused, session key required). Anything else stops startup. Security headers (frame blocking, nosniff, strict CSP with no inline scripts, no-referrer) on every response, errors included. | 24 |
| QR setup | Real mode: QR code shown once, finished only by the first code from the app, in the same browser, within 10 minutes. Re-running it needs the current code and waits 15 minutes. The secret never appears in the audit log, outbox or Python logs. | 7 |
| Release loop | A background loop calls `release_due()` every 5 seconds: releases due approvals, never cancelled ones, logs errors and releases nothing on error, stops on shutdown. With Sentinel on, the same loop also runs Sentinel. | 4 |
| Web pages (look) | Overview, approvals, activity, security, login and setup pages in the approved design. DEMO banner at the top of every demo page, never in real mode. No inline scripts or styles, no external files (strict CSP kept). Each held payment has one "Approve with code" button that opens a small panel (native `<details>`, works without JavaScript) with the code field, Confirm and Cancel; no permanent code card. Demo only: the field is pre-filled with the demo code in high contrast, and a used code shows the next code and makes Confirm wait until it is fresh. The live page has no stolen-session button (a note links to the throwaway drill). No code appears when nothing is held, and never in real mode. Before Sentinel's first scan no score is shown (nothing faked). The JavaScript and the phone-width layout were not run in a browser. | 21 |
| Page guide | A "Guide" button (bottom right) on every page. It opens (natively, even without JavaScript) a short "What is this app?", the tips for this page (each says what a thing is, then why it matters), a last "what next" step with a link, a glossary of 12 words and a "Try it yourself" task list (7 demo tasks, 8 real-mode tasks starting with setup; each links to its page and says what you should see). With `guide.js` it also runs a page tour: one note card at a time, kept inside the window and never over the thing it describes, or a strip along the bottom when space is tight; it opens once by itself per page per browser tab, with the "What is this app?" card first on the first visit. Real-mode text never suggests an on-screen code. The tour was run under Node with a fake page (placement, Next to the end, first visit, storage blocked), **not in a real browser**. | 24 |
| DEMO banner fix | The banner now sits in the page flow (no longer sticky), so it cannot cover the logo or page title; a DEMO label next to the logo in the side nav shows demo mode on every page. Real mode shows neither. Checked in the HTML and CSS only, **not in a real browser**. | 3 |
| Sentinel page | Real score and status from open findings, open findings with their reports, findings resolved since start, the scan log from Sentinel's audit lines. "Scan now": any logged-in approver, one per 30 s, tighten-only. "Reset breaker": session, CSRF and a fresh code (a wrong code counts toward the 3-code lockout); refused while approvals are locked, while a critical or high finding is open, or with no breaker open; real mode waits 15 minutes (owner notified, cancellable, dropped if a critical or high finding opens); demo mode has no wait. Overview and the side nav show the same real score. `TOLLGATE_SENTINEL=off` shows "Sentinel is off". | 22 |
| Try to break it | Four drills, each in a new throwaway mock world in a temporary folder: all 8 frozen attacks (8 of 8 stopped, no money moved); a stolen session tries 3 times through the web forms of a throwaway app (refused, no money moved, approvals locked, breaker tripped); a weakened setting is found and set back by Sentinel; a random fake key is found and shown only masked. The live settings, breakers, audit file (byte-identical), outbox and money are unchanged after every drill, and nothing is written to the live audit log. Results: last 10, up to 1 hour, memory only. One drill per 10 s. | 14 |
| Intro animation | The golden padlock and key from the design play once per browser tab, before the first page, in both modes. "Skip intro" button or any key skips it; reduced-motion settings and `?nointro=1` skip it entirely; "Replay intro" (in the Guide and the sidebar) or `?intro=1` on any page plays it again; if the script fails the page simply shows. Its control code was run under Node with a fake page, not in a real browser. | 13 |
| Sentinel: config audit | Compares every Gate, desk, approval and session setting with the safe baseline (today's defaults): ok or weak, with a reason. | 5 |
| Sentinel: secrets scan | Finds key-shaped text in tracked files, tests, logs and the data folder. Reports file, line and a masked label only; never stores the value; never opens `.env` (only asks git if it is ignored). A fake key fixture is found and never appears in reports, the audit log or logs. | 10 |
| Sentinel: live monitor | Watches the audit log for bursts, repeated blocks, split payments under the limit, new recipient then a big payment, failed codes and lockouts. | 16 |
| Sentinel: restart | After a restart the monitor counts only audit lines written since start-up, so an old lockout no longer trips the breakers again (security review finding 1, fixed); a new lockout still does. A person's breaker reset makes it forget earlier lockout and failed-code events, while payment patterns keep counting. The audit log is never edited, and a shortened file is read again from the top. | 8 |
| Sentinel: canaries | Replays all 8 frozen attacks in isolated mock worlds; all were stopped. A deliberately weakened world lets attacks through and that is caught as critical. The live app is never touched. | 5 |
| Sentinel: tighten-only | Can only trip breakers or set a loosened setting back to the baseline. The executor's new `tighten_config` refuses anything looser, equal or invalid. Sentinel code never approves, sends or loosens (checked in code and in a full run). | 35 |
| Sentinel: score, reports, schedule | Score 100 minus 40/25/10/3 per open critical/high/medium/low finding (any critical = "at risk"). One plain report per finding from the keyless scripted model, masked and capped; advisory only. Runs every 60 s / 10 min / 15 min inside the app loop; `TOLLGATE_SENTINEL=off` keeps the old loop. A fresh demo clone starts with no findings and never trips a breaker. A real model for reports is **not wired in** (untested). | 32 |

Limits: step-up approval **reduces** the risk of a stolen approver session; it does not
remove it. Someone holding both the session and the authenticator can still approve, and the
15-minute wait only helps if the owner sees the alert (here a file, not email). Tested with
the fake mock TOTP secret and fake clocks only. By default the agent uses a scripted model,
not a real AI; real-model behaviour is untested until `scripts\tool_calling_check.py` is run.
The web app is tested with FastAPI's test client only: the live server was started and served
its pages, but it has **not** been clicked through in a real browser, and real mode's secure
cookie on plain `http://127.0.0.1` is **untested** in a browser. Real-mode QR setup was tested
with codes computed by the tests, not with Google Authenticator. Results apply to this
sandbox and these tests only. Details:
[docs/gate.md](docs/gate.md), [docs/executor.md](docs/executor.md),
[docs/agent-policy.md](docs/agent-policy.md), [docs/web.md](docs/web.md), [docs/sentinel.md](docs/sentinel.md).

License: MIT.
