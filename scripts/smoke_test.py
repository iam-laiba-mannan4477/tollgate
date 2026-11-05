r"""Smoke test: connect to the Braintree SANDBOX and generate a client token.

Prints exactly "client token OK" on success. Never prints keys.
Usage: .venv\Scripts\python.exe scripts\smoke_test.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

from tollgate.config import Mode, get_mode, missing_sandbox_vars  # noqa: E402
from tollgate.executor.backend import make_sandbox_gateway  # noqa: E402


def main() -> int:
    load_dotenv()
    if get_mode() is not Mode.SANDBOX:
        print("error: set TOLLGATE_MODE=sandbox to run the smoke test")
        return 1
    missing = missing_sandbox_vars()
    if missing:
        print("error: missing in .env: " + ", ".join(missing))
        return 1
    try:
        token = make_sandbox_gateway().client_token.generate()
    except Exception as exc:  # report the type only; messages could echo config
        print(f"error: client token failed ({type(exc).__name__})")
        return 1
    if not token:
        print("error: empty client token")
        return 1
    print("client token OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
