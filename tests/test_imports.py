"""Only tollgate/executor may import braintree (gate-rules invariant)."""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent / "tollgate"


@pytest.mark.parametrize("package", ["gate", "agent", "sentinel", "app"])
def test_no_braintree_outside_executor(package):
    for f in (ROOT / package).rglob("*.py"):
        assert "braintree" not in f.read_text(encoding="utf-8").lower(), f
