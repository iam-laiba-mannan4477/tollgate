"""Only tollgate/executor/backend.py may import braintree (gate-rules invariant)."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOWED = {Path("tollgate/executor/backend.py")}


def _imports_braintree(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name.split(".")[0] == "braintree" for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "braintree":
                return True
        elif isinstance(node, ast.Call) and getattr(node.func, "id", "") == "__import__":
            if any(isinstance(a, ast.Constant) and str(a.value).startswith("braintree")
                   for a in node.args):
                return True
    return False


def _project_files():
    for folder in ("tollgate", "scripts"):
        yield from (ROOT / folder).rglob("*.py")
    yield from ROOT.glob("*.py")


def test_braintree_only_in_backend():
    offenders = [p.relative_to(ROOT) for p in _project_files()
                 if _imports_braintree(p) and p.relative_to(ROOT) not in ALLOWED]
    assert offenders == []


def test_backend_does_import_braintree():
    assert _imports_braintree(ROOT / "tollgate/executor/backend.py")


def test_agent_cannot_reach_executor():
    for p in (ROOT / "tollgate/agent").rglob("*.py"):
        assert "tollgate.executor" not in p.read_text(encoding="utf-8"), p
