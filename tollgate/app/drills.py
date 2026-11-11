"""Try to break it: four drills, each in a FRESH THROWAWAY mock world.

Nothing here receives or touches the live app: no live settings, breakers, audit log or
money. Each drill builds its own world in a temporary folder that is deleted afterwards,
and writes nothing to the live audit log (approved: results appear only on the page).

Results are kept in memory only: the last 10, each for at most 1 hour, lost on restart.
Fake values only. The planted key is generated at runtime and never leaves this module
unmasked.
"""
from __future__ import annotations

import re
import secrets
import string
import subprocess
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from tollgate.agent import scenarios
from tollgate.approval.totp import MOCK_TOTP_SECRET_B32, STEP_SECONDS, code_at, decode_secret
from tollgate.executor.backend import MockBackend
from tollgate.gate.rules import GateConfig
from tollgate.sentinel import canaries, secrets_scan
from tollgate.sentinel.runner import Sentinel

KEEP_RESULTS = 10
KEEP_SECONDS = 3600
DRILL_EVERY_SECONDS = 10
THROWAWAY_ROUNDS = 1_000          # PBKDF2 rounds for the throwaway demo account only
DRILLS = {"attacks": "Attack drill: all 8 frozen attacks",
          "stolen": "Stolen session tries to approve",
          "weaken": "Weaken a setting",
          "leak": "Plant a fake key"}


@dataclass
class DrillResult:
    kind: str
    title: str
    at: float                      # wall time
    passed: bool
    summary: str
    columns: tuple[str, ...]
    rows: list[tuple[str, ...]] = field(default_factory=list)


class DrillStore:
    """The last 10 results for at most 1 hour, in memory only."""

    def __init__(self, wall_clock: Callable[[], float] = time.time) -> None:
        self._wall = wall_clock
        self._items: deque[DrillResult] = deque(maxlen=KEEP_RESULTS)
        self._lock = threading.Lock()

    def add(self, result: DrillResult) -> None:
        with self._lock:
            self._items.append(result)

    def recent(self) -> list[DrillResult]:
        now = self._wall()
        with self._lock:
            while self._items and now - self._items[0].at > KEEP_SECONDS:
                self._items.popleft()
            return list(reversed(self._items))


def run_drill(kind: str, wall: float) -> DrillResult:
    """Run one drill by name. Any drill error is shown as a failed drill (fail closed)."""
    runner = {"attacks": attack_drill, "stolen": stolen_session_drill,
              "weaken": weaken_drill, "leak": fake_key_drill}.get(kind)
    if runner is None:
        raise ValueError("unknown drill")
    try:
        return runner(wall)
    except Exception as exc:
        return DrillResult(kind, DRILLS[kind], wall, False,
                           f"The drill could not run ({type(exc).__name__}); "
                           "treat this as not proven safe.", ("Result",), [("could not run",)])


# ---- (a) attack drill ------------------------------------------------------------------
def attack_drill(wall: float) -> DrillResult:
    rows, stopped = [], 0
    for scenario in scenarios.ATTACKS:
        with tempfile.TemporaryDirectory(prefix="tollgate-drill-") as folder:
            try:
                world = canaries.CanaryWorld(Path(folder))
                result = canaries.run_one(scenario, world)
                moved = world.backend.balance_cents != world.start_balance
                actual = "got through" if result.through else "stopped"
            except Exception:
                moved, actual = False, "could not run (not proven safe)"
        stopped += actual == "stopped"
        rows.append((scenario.name, "stopped", actual, "yes" if moved else "no"))
    total = len(scenarios.ATTACKS)
    return DrillResult("attacks", DRILLS["attacks"], wall, stopped == total,
                       f"{stopped} of {total} attacks stopped in throwaway worlds.",
                       ("Attack", "Expected", "Actual", "Money moved"), rows)


# ---- (b) stolen session through the web layer ------------------------------------------
_CSRF = re.compile(r'name="csrf" value="([^"]+)"')


def _wrong_codes(now: float, count: int) -> list[str]:
    """Codes that are not valid near `now` for the public demo secret."""
    secret = decode_secret(MOCK_TOTP_SECRET_B32)
    valid = {code_at(secret, now + k * STEP_SECONDS) for k in range(-3, 4)}
    out, n = [], 0
    while len(out) < count:
        candidate = f"{(123456 + n * 111111) % 1_000_000:06d}"
        n += 1
        if candidate not in valid and candidate not in out:
            out.append(candidate)
    return out


def stolen_session_drill(wall: float) -> DrillResult:
    from fastapi.testclient import TestClient            # in-process only, no network

    from tollgate.app.main import DEMO_NAME, DEMO_PASSWORD, create_app

    with tempfile.TemporaryDirectory(prefix="tollgate-drill-") as folder:
        backend = MockBackend()
        app = create_app({"TOLLGATE_AUTH_MODE": "demo", "TOLLGATE_SENTINEL": "off"},
                         data_dir=folder, backend=backend, iterations=THROWAWAY_ROUNDS)
        ctx = app.state.ctx
        start = backend.balance_cents
        client = TestClient(app, base_url="http://throwaway")
        token = _CSRF.search(client.get("/login").text).group(1)
        client.post("/login", data={"name": DEMO_NAME, "password": DEMO_PASSWORD,
                                    "csrf": token})
        rows = []
        tries = [""] + _wrong_codes(ctx.wall_clock(), 2)
        for n, code in enumerate(tries, 1):
            page = client.get("/approvals")
            match = _CSRF.search(page.text)
            if match is None or "demo-2" not in page.text:
                rows.append((str(n), "no code" if not code else "wrong code",
                             "refused: session ended, approvals locked"))
                continue
            client.post("/approvals/demo-2/approve", data={"code": code,
                                                           "csrf": match.group(1)})
            sent = backend.balance_cents != start
            rows.append((str(n), "no code" if not code else "wrong code",
                         "SENT" if sent else "refused"))
        moved = backend.balance_cents != start
        locked = ctx.service.locked
        tripped = ctx.executor.breaker_open and ctx.desk.breaker_open
        client.close()
    rows.append(("result", "money moved", "yes" if moved else "no"))
    rows.append(("result", "approvals locked", "yes" if locked else "no"))
    rows.append(("result", "breaker tripped", "yes" if tripped else "no"))
    passed = not moved and locked and tripped
    return DrillResult("stolen", DRILLS["stolen"], wall, passed,
                       "A logged-in session without the authenticator tried 3 times in a "
                       "throwaway app: " + ("refused, no money moved, approvals locked, "
                                            "breaker tripped." if passed else "NOT fully stopped."),
                       ("Try", "Code", "Result"), rows)


# ---- (c) weaken a setting --------------------------------------------------------------
def weaken_drill(wall: float) -> DrillResult:
    from tollgate.app.main import build_context

    with tempfile.TemporaryDirectory(prefix="tollgate-drill-") as folder:
        ctx = build_context({"TOLLGATE_AUTH_MODE": "demo", "TOLLGATE_SENTINEL": "off"},
                            data_dir=folder, backend=MockBackend(),
                            iterations=THROWAWAY_ROUNDS)
        sentinel = Sentinel(executor=ctx.executor, desk=ctx.desk, service=ctx.service,
                            account=ctx.account, audit_path=ctx.audit_path,
                            data_dir=Path(folder), repo_root=Path(folder))
        safe = ctx.executor.config.auto_limit_cents
        weak = safe * 9
        ctx.executor._config = GateConfig(auto_limit_cents=weak)     # "someone loosened it"
        sentinel.run_job("auditor")
        found = [f for f in sentinel.open_findings() if f.location == "gate.auto_limit_cents"]
        after = ctx.executor.config.auto_limit_cents
        tripped = ctx.executor.breaker_open and ctx.desk.breaker_open
    rows = [("Auto limit before", _money(safe)), ("Weakened to (throwaway only)", _money(weak)),
            ("Sentinel finding", f"{found[0].severity.value}: {found[0].title}" if found
             else "none"),
            ("Auto limit after Sentinel", _money(after)),
            ("Breakers", "tripped" if tripped else "closed")]
    passed = bool(found) and after == safe and tripped
    return DrillResult("weaken", DRILLS["weaken"], wall, passed,
                       "Sentinel found the weakened setting and set it back."
                       if passed else "Sentinel did NOT fully tighten the setting.",
                       ("Step", "Value"), rows)


def _money(cents: int) -> str:
    return f"${cents / 100:,.0f}"


# ---- (d) plant a fake key --------------------------------------------------------------
def _fake_key() -> str:
    """A FAKE Groq-shaped key, random at runtime. Not a real credential."""
    letters = string.ascii_letters + string.digits
    return "gsk" + "_" + "fake" + "".join(secrets.choice(letters) for _ in range(28))


def _no_git(_args: list[str]) -> subprocess.CompletedProcess:
    raise OSError("throwaway folder is not a git repository")


def fake_key_drill(wall: float) -> DrillResult:
    key = _fake_key()
    with tempfile.TemporaryDirectory(prefix="tollgate-drill-") as folder:
        planted = Path(folder) / "planted"
        planted.mkdir()
        (planted / "settings.txt").write_text(f"name = demo\napi = {key}\n", encoding="utf-8")
        result = secrets_scan.scan(Path(folder), [planted], git=_no_git)
    rows = [(h.path, str(h.line), f"{h.label} (masked)") for h in result.hits]
    shown = " ".join(" ".join(r) for r in rows)
    del key
    passed = bool(rows) and "gsk_" not in shown
    return DrillResult("leak", DRILLS["leak"], wall, passed,
                       "The scanner found the planted fake key and showed it masked."
                       if passed else "The scanner did NOT find the planted fake key.",
                       ("File", "Line", "Found"), rows or [("-", "-", "nothing found")])
