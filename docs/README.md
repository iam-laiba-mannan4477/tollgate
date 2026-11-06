# Docs

Architecture, threat model and judge instructions will live here.

## Modes
- `TOLLGATE_MODE=mock` (default when unset): no keys, no network.
- `TOLLGATE_MODE=sandbox`: Braintree sandbox via `.env`. Any other value is an error (fail closed).

## Pages
- [gate.md](gate.md): rules, stamps, audit log, breaker
- [executor.md](executor.md): the only code that moves money
- [agent-policy.md](agent-policy.md): what the agent can and cannot do, roles, simulated skills
