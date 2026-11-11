"""Try to break it: every drill runs in a throwaway world and leaves the live app exactly
as it was (settings, breakers, audit file, outbox, money, pending items). No DRILL line is
written to the live audit log. The planted fake key never appears on any page."""
from __future__ import annotations

import re

import pytest

from tollgate.app import drills
from tollgate.app.drills import DrillResult, DrillStore, run_drill
from tests.web_support import DEMO_ENV, Web

CSRF_OF = re.compile(r'name="csrf" value="([^"]+)"')
KINDS = ["attacks", "stolen", "weaken", "leak"]


@pytest.fixture
def web(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    return w


def run(w: Web, kind: str):
    token = CSRF_OF.search(w.client.get("/drills").text).group(1)
    r = w.client.post(f"/drills/{kind}", data={"csrf": token})
    w.clock.t += 10                                   # past the one-per-10-s limit
    return r


def live_state(w: Web) -> dict:
    ctx = w.ctx
    return {"audit": ctx.audit_path.read_bytes(), "outbox": w.outbox_text(),
            "config": ctx.executor.config, "desk": ctx.desk._config,
            "policy": ctx.service.policy, "breakers": (ctx.executor.breaker_open,
                                                        ctx.desk.breaker_open),
            "locked": ctx.service.locked, "balance": w.backend.balance_cents,
            "pending": [p.id for p in ctx.reviewer.pending()],
            "findings": ctx.sentinel.open_findings(), "sessions": len(ctx.sessions._live)
            if hasattr(ctx.sessions, "_live") else None}


def test_page_says_clearly_that_nothing_live_is_touched(web):
    page = web.client.get("/drills").text
    assert "Your live settings, breakers, audit log and money are not touched" in page
    assert "nothing is written to the live audit log" in page


@pytest.mark.parametrize("kind", KINDS)
def test_each_drill_leaves_the_live_app_unchanged(web, kind):
    before = live_state(web)
    r = run(web, kind)
    assert r.status_code == 200
    assert live_state(web) == before                  # the audit FILE is byte-identical
    assert "DRILL" not in web.audit_text()
    [result] = web.ctx.drills.recent()
    assert result.passed, (result.summary, result.rows)


def test_all_drills_in_a_row_leave_the_live_audit_file_unchanged(web):
    before = live_state(web)
    for kind in KINDS * 2:
        run(web, kind)
    assert live_state(web) == before
    assert len(web.ctx.drills.recent()) == 8


def test_attack_drill_table(web):
    page = run(web, "attacks").text
    assert "8 of 8 attacks stopped" in page
    for name in ("injection_refund", "split_payments", "stolen_approver_session"):
        assert f"<td>{name}</td><td>stopped</td><td>stopped</td><td>no</td>" in page


def test_stolen_session_drill_is_refused_locks_and_trips(web):
    page = run(web, "stolen").text
    [r] = web.ctx.drills.recent()
    assert [row[2] for row in r.rows[:3]] == ["refused", "refused", "refused"]
    assert ("result", "money moved", "no") in r.rows
    assert ("result", "approvals locked", "yes") in r.rows
    assert ("result", "breaker tripped", "yes") in r.rows
    assert "refused, no money moved, approvals locked, breaker tripped" in page
    assert not web.ctx.service.locked and not web.ctx.executor.breaker_open   # live untouched


def test_weaken_drill_finds_and_tightens(web):
    run(web, "weaken")
    [r] = web.ctx.drills.recent()
    assert dict(r.rows)["Auto limit after Sentinel"] == "$1,000"
    assert dict(r.rows)["Breakers"] == "tripped" and "high" in dict(r.rows)["Sentinel finding"]
    assert web.ctx.executor.config.auto_limit_cents == 100_000


def test_fake_key_is_found_but_never_shown(web, monkeypatch):
    planted = "gsk" + "_" + "fakeZZ" + "Q9" * 14
    monkeypatch.setattr(drills, "_fake_key", lambda: planted)
    run(web, "leak")
    [r] = web.ctx.drills.recent()
    assert r.passed and r.rows[0][2] == "Groq API key (masked)"
    for path in ("/drills", "/sentinel", "/overview", "/audit"):
        html = web.client.get(path).text
        assert planted not in html and planted[:12] not in html, path
    assert planted not in web.audit_text() and planted not in repr(r)


def test_one_drill_per_10_seconds(web):
    token = CSRF_OF.search(web.client.get("/drills").text).group(1)
    web.client.post("/drills/leak", data={"csrf": token})
    r = web.client.post("/drills/leak", data={"csrf": token})
    assert "Not run: one drill per 10 s" in r.text and len(web.ctx.drills.recent()) == 1
    web.clock.t += 10
    web.client.post("/drills/leak", data={"csrf": token})
    assert len(web.ctx.drills.recent()) == 2


def test_unknown_drill_is_refused(web):
    token = CSRF_OF.search(web.client.get("/drills").text).group(1)
    assert web.client.post("/drills/nope", data={"csrf": token}).status_code == 404


def test_a_drill_that_cannot_run_is_shown_as_not_stopped(monkeypatch):
    def boom(_wall):
        raise RuntimeError("detail")
    monkeypatch.setattr(drills, "attack_drill", boom)
    r = run_drill("attacks", 0.0)
    assert not r.passed and "not proven safe" in r.summary and "detail" not in r.summary


def test_results_kept_10_for_one_hour_in_memory():
    now = [10_000.0]
    store = DrillStore(lambda: now[0])
    for i in range(12):
        store.add(DrillResult("leak", "t", now[0], True, str(i), ("x",)))
    assert [r.summary for r in store.recent()] == [str(i) for i in range(11, 1, -1)]
    now[0] += 3601
    assert store.recent() == []
