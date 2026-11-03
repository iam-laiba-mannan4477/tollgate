---
name: test-standards
description: Use when writing tests or the benchmark for Tollgate: unit, property, race, attack-chain, canary and benchmark tests and how to report results honestly.
---
# Test standards

Layers:
1. Unit: every rule and stamp case (expired, reused, changed amount, wrong recipient).
2. Property (hypothesis): random requests never produce ALLOW above the limit or to an unknown recipient without a stamp.
3. Race: many threads try to spend one stamp at once; exactly one succeeds.
4. Attack chains: multi-step attacks (new recipient then payment, split payments, stolen service key, fake approval claims, hidden instructions).
5. Hygiene: no secrets in logs, `.env` ignored, mock mode runs with no keys.
6. Sentinel canaries: weaken a rule in a test copy and confirm Sentinel raises a finding.
7. Normal use: about 15 ordinary tasks; count honest requests wrongly blocked.
8. Benchmark: frozen attack set, 3 runs each, gate OFF then ON, scored by plain code, not an AI judge.

Honesty rules: freeze the test set before tuning and never edit it afterwards. Report failures and wrongly blocked tasks. State sample sizes. Say results apply to this sandbox only. Never round a bad number into a good one.
