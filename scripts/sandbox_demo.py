r"""Sandbox demo: one 100-cent charge and one 100-cent refund THROUGH THE EXECUTOR.

Prints transaction ids and the audit lines. Never prints keys.
Usage (PowerShell):  $env:TOLLGATE_MODE="sandbox"; .venv\Scripts\python.exe scripts\sandbox_demo.py
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

from tollgate.config import Mode, get_mode  # noqa: E402
from tollgate.executor.backend import BackendError, BraintreeBackend  # noqa: E402
from tollgate.executor.executor import Executor  # noqa: E402
from tollgate.gate.audit import verify  # noqa: E402
from tollgate.gate.models import Request  # noqa: E402


def main() -> int:
    load_dotenv()
    if get_mode() is not Mode.SANDBOX:
        print("error: set TOLLGATE_MODE=sandbox to run the demo")
        return 1
    try:
        backend = BraintreeBackend()
    except BackendError as exc:  # our own messages: names only, never values
        print(f"error: {exc}")
        return 1
    audit_path = Path(tempfile.mkdtemp()) / "demo_audit.jsonl"
    ex = Executor(backend, audit_path)
    tag = str(int(time.time()))
    charge = Request(id=f"demo-{tag}-c", type="pay", amount_cents=100,
                     recipient="sandbox_supplier", via_agent=True, created_at=time.time())
    print("Gate says:", ex.preview(charge).verdict.value, "(new recipient -> needs a person)")
    stamp = ex.approve(charge, approver="demo-operator")  # stamp itself is never printed
    res = ex.execute(charge, stamp)
    print("charge:", "OK" if res.executed else "FAILED", res.transaction_id or res.reason)
    if not res.executed:
        return 1
    refund = Request(id=f"demo-{tag}-r", type="refund", amount_cents=100,
                     recipient="sandbox_supplier", via_agent=True, created_at=time.time(),
                     order_total_cents=100)
    res2 = ex.execute(refund, refund_of=charge.id)
    print("refund:", "OK" if res2.executed else "FAILED", res2.transaction_id or res2.reason)
    print("\naudit log:", audit_path)
    print(audit_path.read_text(encoding="utf-8").rstrip())
    print("audit chain valid:", verify(audit_path))
    return 0 if res2.executed else 1


if __name__ == "__main__":
    sys.exit(main())
