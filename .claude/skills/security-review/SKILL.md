---
name: security-review
description: Use before every commit and before finishing a milestone: checks for secrets, unsafe code paths and missing tests.
---
# Security review checklist

Before committing:
- [ ] `python scripts\check_secrets.py` is clean and `.env` is not tracked (`git ls-files .env` prints nothing).
- [ ] No keys, tokens or real personal data in code, tests, logs, docs or screenshots.
- [ ] The agent package cannot reach the executor or Braintree.
- [ ] New code fails closed on errors and unknown input.
- [ ] No `eval`, no shell calls with user text, no unsafe deserialization.
- [ ] Inputs are validated (type, range, length). Amounts are integer cents and positive.
- [ ] Logs hold ids and reasons, never secrets or full card data.
- [ ] Dependencies are few, pinned in requirements.txt, and well known.
- [ ] A test exists for every new rule or invariant.
If any box fails, fix it first and say what was fixed.
