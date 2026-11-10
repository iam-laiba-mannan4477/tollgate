"""Real Braintree SANDBOX test: one 100-cent charge and one 100-cent refund.

Skipped unless TOLLGATE_MODE=sandbox is set in the process environment (explicit
opt-in) and the three sandbox keys are available (from the environment or .env).
Keys are loaded by python-dotenv and are never printed.
"""
import os
import time

import pytest
from dotenv import dotenv_values

from tollgate.config import REQUIRED_SANDBOX_VARS

_DOTENV = {k: v for k, v in dotenv_values().items() if k in REQUIRED_SANDBOX_VARS and v}
_HAVE_KEYS = all(os.environ.get(k) or _DOTENV.get(k) for k in REQUIRED_SANDBOX_VARS)
_OPTED_IN = os.environ.get("TOLLGATE_MODE", "").strip().lower() == "sandbox"

pytestmark = [
    pytest.mark.sandbox,
    pytest.mark.skipif(not (_OPTED_IN and _HAVE_KEYS),
                       reason="set TOLLGATE_MODE=sandbox and provide sandbox keys"),
]


def test_real_sandbox_charge_and_refund(tmp_path, monkeypatch):
    for k, v in _DOTENV.items():
        monkeypatch.setenv(k, v)
    from tollgate.executor.backend import BraintreeBackend
    from tollgate.executor.executor import Executor
    from tollgate.gate.models import Request

    from tollgate.config import Mode
    from tests.stepup_support import TestApprover

    approver = TestApprover(tmp_path, time.monotonic, mode=Mode.SANDBOX)
    ex = Executor(BraintreeBackend(), tmp_path / "audit.jsonl", grants=approver.service.redeem)
    approver.connect(ex)

    def grant(_ex, request):
        return approver.grant(request)

    charge = Request(id=f"t{os.getpid()}c", type="pay", amount_cents=100,
                     recipient="sandbox_supplier", via_agent=True, created_at=0.0)
    res = ex.execute(charge, ex.approve(charge, grant(ex, charge)))
    assert res.executed, res.reason
    ref = Request(id=f"t{os.getpid()}r", type="refund", amount_cents=100,
                  recipient="sandbox_supplier", via_agent=True, created_at=0.0,
                  order_total_cents=100)
    res2 = ex.execute(ref, refund_of=charge.id)
    assert res2.executed, res2.reason
