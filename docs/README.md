# Docs

Architecture and design notes. Judges: start with the main [README](../README.md)
("Try it in 60 seconds" and "Judge checklist").

## Modes
- `TOLLGATE_MODE=mock` (default when unset): no keys, no network.
- `TOLLGATE_MODE=sandbox`: Braintree sandbox via `.env`. Any other value is an error (fail closed).

## Pages
- [gate.md](gate.md): rules, stamps, audit log, breaker
- [executor.md](executor.md): the only code that moves money
- [agent-policy.md](agent-policy.md): what the agent can and cannot do, roles, simulated skills
- [web.md](web.md): approver login, QR setup, demo and real modes, release loop
- [sentinel.md](sentinel.md): config audit, secrets scan, live monitor, canaries, tighten-only fixes
- [security-review.md](security-review.md): security review findings, fixes and documented limits
