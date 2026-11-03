# Docs

Architecture, threat model and judge instructions will live here.

## Modes
- `TOLLGATE_MODE=mock` (default when unset): no keys, no network.
- `TOLLGATE_MODE=sandbox`: Braintree sandbox via `.env`. Any other value is an error (fail closed).
