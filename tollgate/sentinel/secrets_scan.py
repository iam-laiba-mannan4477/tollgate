"""Secrets scanner: look for leaked keys in tracked files, logs, the outbox/audit data and
test files.

It NEVER keeps, prints or stores a matched value: a hit is (file, line number, label).
It never opens .env (or .env.*, except .env.example): it only asks git whether .env is
ignored. Severity: a hit in a git-tracked file is CRITICAL; anywhere else (data, logs,
untracked test files) it is LOW. .env not ignored by git is CRITICAL.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from tollgate.sentinel.findings import Finding, Severity
from tollgate.sentinel.secret_patterns import label_for

MAX_BYTES = 1_000_000
SKIP_DIRS = frozenset({".venv", ".git", "__pycache__", ".pytest_cache", ".hypothesis",
                       "node_modules"})
GitRunner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _git(root: Path) -> GitRunner:
    def run(args: list[str]) -> "subprocess.CompletedProcess[str]":
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True,
                              timeout=30)
    return run


@dataclass(frozen=True)
class Hit:
    path: str            # relative, forward slashes
    line: int
    label: str           # pattern label only, e.g. "Groq API key"
    tracked: bool


@dataclass
class ScanResult:
    hits: list[Hit] = field(default_factory=list)
    env_ignored: bool | None = None          # None = could not check (git missing)
    files_scanned: int = 0
    problems: list[str] = field(default_factory=list)   # plain words, no values


def is_env_file(name: str) -> bool:
    return name == ".env" or (name.startswith(".env.") and name != ".env.example")


def _walk(folder: Path, suffix: str = "") -> Iterable[Path]:
    """Files under `folder`, never descending into SKIP_DIRS (pruned, so .venv is cheap)."""
    if not folder.is_dir():
        return
    for here, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name.endswith(suffix):
                yield Path(here) / name


def _scan_file(path: Path) -> list[tuple[int, str]]:
    """(line number, label) for each suspicious line. The line text is discarded."""
    if is_env_file(path.name) or path.stat().st_size > MAX_BYTES:
        return []
    raw = path.read_bytes()
    if b"\x00" in raw[:4096]:
        return []                                       # binary
    found = []
    for number, line in enumerate(raw.decode("utf-8", errors="ignore").splitlines(), 1):
        label = label_for(line)
        if label:
            found.append((number, label))
    return found


def scan(root: Path, extra_dirs: Iterable[Path] = (), git: GitRunner | None = None) -> ScanResult:
    root = Path(root).resolve()
    run = git or _git(root)
    result = ScanResult()
    tracked: set[Path] = set()
    try:
        listed = run(["ls-files"])
        if listed.returncode == 0:
            tracked = {(root / n).resolve() for n in listed.stdout.splitlines() if n.strip()}
        else:
            result.problems.append("git ls-files failed: tracked files not scanned")
        ignored = run(["check-ignore", "-q", ".env"])
        result.env_ignored = {0: True, 1: False}.get(ignored.returncode)
        if result.env_ignored is None:
            result.problems.append("could not ask git whether .env is ignored")
    except (OSError, subprocess.SubprocessError):
        result.problems.append("git is not available: tracked files and .env rule not checked")
    candidates = set(tracked)
    for folder in [root / "tests", *[Path(d) for d in extra_dirs]]:
        candidates.update(p.resolve() for p in _walk(folder))
    candidates.update(p.resolve() for p in _walk(root, ".log"))
    for path in sorted(candidates):
        if not path.is_file() or is_env_file(path.name):
            continue
        try:
            hits = _scan_file(path)
        except OSError:
            result.problems.append("a file could not be read")
            continue
        result.files_scanned += 1
        rel = _relative(path, root)
        for number, label in hits:
            result.hits.append(Hit(rel, number, label, path in tracked))
    return result


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name                                   # outside the repo: name only


def findings(result: ScanResult) -> list[Finding]:
    out = []
    for h in result.hits:
        where = "tracked file" if h.tracked else "untracked file"
        out.append(Finding(
            key=f"leak:{h.path}:{h.line}", job="secrets",
            severity=Severity.CRITICAL if h.tracked else Severity.LOW,
            title=f"Possible leaked credential ({h.label}, masked)",
            detail=f"A line in a {where} looks like a {h.label}. The value is masked and "
                   f"was not stored. Remove it and rotate it if it is real.",
            location=f"{h.path}:{h.line}"))
    if result.env_ignored is False:
        out.append(Finding(key="leak:env-not-ignored", job="secrets", severity=Severity.CRITICAL,
                           title=".env is not ignored by git",
                           detail="git does not ignore .env, so it could be committed. "
                                  "Add .env to .gitignore. (Its contents were not read.)",
                           location=".gitignore"))
    return out
