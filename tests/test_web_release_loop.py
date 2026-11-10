"""The background release loop: runs on a schedule, releases due approvals, survives
errors (releasing nothing on error), and stops cleanly on shutdown."""
from __future__ import annotations

import time

from tollgate.app.main import run_release_once
from tests.web_support import DEMO_ENV, Web

FAST = 0.02


def _wait_for(check, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.01)
    return False


def test_loop_runs_and_stops_cleanly(tmp_path):
    w = Web(tmp_path, DEMO_ENV, release_interval=FAST)
    with w.client:
        assert _wait_for(lambda: w.ctx.loop_runs >= 3)
        assert not w.ctx.loop_stopped
    assert w.ctx.loop_stopped
    runs = w.ctx.loop_runs
    time.sleep(FAST * 5)
    assert w.ctx.loop_runs == runs                       # nothing runs after shutdown


def test_loop_releases_a_waiting_approval_after_cooling_off(tmp_path):
    w = Web(tmp_path, DEMO_ENV, release_interval=FAST)
    with w.client:
        w.login()
        r = w.approve("demo-2", w.code())                # $1,500 to a new recipient: waits
        assert "approved, waiting" in r.text
        assert [i for i, _ in w.ctx.service.waiting()] == ["demo-2"]
        time.sleep(FAST * 5)
        assert w.backend.balance_cents == 0              # not before the wait is over
        w.clock.t += 900
        assert _wait_for(lambda: w.backend.balance_cents == 150_000)
        assert w.ctx.service.waiting() == []
    assert "RELEASE" in w.audit_text()


def test_cancelled_approval_is_never_released(tmp_path):
    w = Web(tmp_path, DEMO_ENV, release_interval=FAST)
    with w.client:
        w.login()
        w.approve("demo-2", w.code())
        r = w.client.post("/waiting/demo-2/cancel", data={"csrf": w.csrf("/approvals")})
        assert "cancelled" in r.text
        w.clock.t += 901
        runs = w.ctx.loop_runs
        assert _wait_for(lambda: w.ctx.loop_runs >= runs + 3)
    assert w.backend.balance_cents == 0


def test_loop_error_is_logged_and_releases_nothing(tmp_path):
    w = Web(tmp_path, DEMO_ENV)

    def boom():
        raise RuntimeError("broken")
    w.ctx.reviewer.release_due = boom
    run_release_once(w.ctx)
    run_release_once(w.ctx)
    assert w.ctx.loop_errors == 2 and w.ctx.loop_runs == 2
    assert "release loop error" in w.audit_text()
    assert w.backend.balance_cents == 0
