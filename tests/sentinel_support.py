"""Helpers for Sentinel tests. The FAKE key is assembled at runtime so no source file
contains a key-shaped string (the repo's own secret check must stay clean)."""
from __future__ import annotations

import subprocess
from pathlib import Path

from tollgate.sentinel.runner import Sentinel
from tests.web_support import DEMO_ENV, Web


def fake_groq_key() -> str:
    """A FAKE Groq-shaped key for tests only. Not a real credential."""
    return "gsk" + "_" + "Q7fake" * 5


def git_repo(root: Path, tracked: dict[str, str], untracked: dict[str, str] | None = None,
             gitignore: str = ".env\n") -> Path:
    """A tiny git repo: `tracked` files are added to the index, `untracked` are not."""
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    (root / ".gitignore").write_text(gitignore, encoding="utf-8")
    for name, text in {**tracked, **(untracked or {})}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore", *tracked], cwd=root, check=True)
    return root


def sentinel_for(web: Web, repo_root: Path, **kw) -> Sentinel:
    """A Sentinel wired to one Web app's live objects, scanning `repo_root`."""
    ctx = web.ctx
    return Sentinel(executor=ctx.executor, desk=ctx.desk, service=ctx.service,
                    account=ctx.account, audit_path=ctx.audit_path,
                    data_dir=ctx.audit_path.parent, repo_root=repo_root,
                    clock=web.clock, wall_clock=web.wall, **kw)


def demo_web(tmp_path: Path, seed: bool = True) -> Web:
    return Web(tmp_path / "app", DEMO_ENV, demo_seed=seed)
