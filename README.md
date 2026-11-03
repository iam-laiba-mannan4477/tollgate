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

Status: Day 1 skeleton. License: MIT.
