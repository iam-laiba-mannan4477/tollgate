"""Sentinel runner: schedule, audit lines, actions, fail closed, app loop takeover, and a
fresh demo clone that starts clean."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from tollgate.app.main import create_app, run_release_once
from tollgate.config import ConfigError
from tollgate.gate.rules import GateConfig
from tollgate.sentinel.findings import Severity
from tests.sentinel_support import demo_web, git_repo, sentinel_for
from tests.web_support import DEMO_ENV, Web

ROOT = Path(__file__).resolve().parent.parent
SENTINEL_CODES = {"FINDING", "RESOLVED", "TRIP", "TIGHTEN", "SNTL-ERR", "SNTL-SUM"}


def lines(web) -> list[dict]:
    return [json.loads(l) for l in web.audit_text().splitlines()]


def decisions(web) -> list[str]:
    return [l["decision"] for l in lines(web)]


@pytest.fixture
def clean_repo(tmp_path):
    return git_repo(tmp_path / "repo", tracked={"a.py": "a = 1\n"})


# ---- item 4: a fresh demo clone starts clean ---------------------------------------------
def test_fresh_demo_clone_has_no_critical_findings_and_never_trips(tmp_path):
    """The real repo, demo mode, no keys: the demo account and the fake mock TOTP secret
    are by design and must not be findings. Every job runs once, then a normal round."""
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    web = demo_web(tmp_path)
    sentinel = web.ctx.sentinel
    assert sentinel is not None                                   # on by default
    sentinel.run_due()
    sentinel.run_all_now()
    open_ = sentinel.open_findings()
    assert not [f for f in open_ if f.severity is Severity.CRITICAL], open_
    assert sentinel.status() == "good" and sentinel.score() >= 80, open_
    assert open_ == [], open_                                     # in fact nothing at all
    assert not web.ctx.executor.breaker_open and not web.ctx.desk.breaker_open
    assert "TRIP" not in decisions(web) and sentinel.errors == 0


# ---- audit lines ----------------------------------------------------------------------------
def test_no_scan_line_each_round_and_one_summary_per_ten_minutes(tmp_path, clean_repo):
    web = demo_web(tmp_path)
    s = sentinel_for(web, clean_repo)
    for _ in range(10):
        s.run_due()
        web.clock.t += 30                                          # 10 rounds over 5 minutes
    assert decisions(web).count("SNTL-SUM") == 1
    assert not {"SCAN", "CANARY"} & set(decisions(web))
    web.clock.t += 600
    s.run_due()
    assert decisions(web).count("SNTL-SUM") == 2


def test_schedule_intervals(tmp_path, clean_repo):
    web = demo_web(tmp_path)
    s = sentinel_for(web, clean_repo)
    ran: list[str] = []
    for job in ("auditor", "monitor", "secrets", "canaries"):
        setattr(s, f"_job_{job}", lambda job=job: ran.append(job) or [])
    s.run_due()
    assert ran == ["auditor", "monitor", "secrets", "canaries"]       # all on the first round
    ran.clear(); web.clock.t += 59; s.run_due()
    assert ran == []
    ran.clear(); web.clock.t += 1; s.run_due()
    assert ran == ["auditor", "monitor"]                              # 60 s
    ran.clear(); web.clock.t += 540; s.run_due()
    assert ran == ["auditor", "monitor", "secrets"]                   # 600 s
    ran.clear(); web.clock.t += 300; s.run_due()
    assert ran == ["auditor", "monitor", "canaries"]                  # 900 s


def test_weak_setting_opens_acts_and_resolves(tmp_path, clean_repo):
    web = demo_web(tmp_path)
    s = sentinel_for(web, clean_repo)
    web.ctx.executor._config = GateConfig(auto_limit_cents=900_000)  # someone loosened it
    s._run("auditor")
    assert web.ctx.executor.config.auto_limit_cents == 100_000         # set back (stricter)
    assert web.ctx.executor.breaker_open and web.ctx.desk.breaker_open
    assert [d for d in decisions(web) if d in SENTINEL_CODES] == ["FINDING", "TIGHTEN", "TRIP"]
    s._run("auditor")
    assert decisions(web).count("FINDING") == 1                         # deduped
    assert decisions(web)[-1] == "RESOLVED" and s.open_findings() == []
    assert web.ctx.executor.breaker_open                                # a person must reset it


def test_medium_finding_reports_only(tmp_path, clean_repo):
    web = demo_web(tmp_path)
    s = sentinel_for(web, clean_repo)
    web.ctx.service.record("x-1", "FACTORFAIL", "approval: second factor failed (1/3)", None, None)
    s._run("monitor")
    [f] = s.open_findings()
    assert f.severity is Severity.MEDIUM and not web.ctx.executor.breaker_open
    assert "TRIP" not in decisions(web) and len(s.reports) == 1


def test_desk_weakness_trips_but_is_not_rewritten(tmp_path, clean_repo):
    web = demo_web(tmp_path)
    s = sentinel_for(web, clean_repo)
    web.ctx.desk._config = GateConfig(velocity_max_payments=9)
    s._run("auditor")
    assert web.ctx.desk.breaker_open and web.ctx.desk._config.velocity_max_payments == 9


def test_job_error_fails_closed_without_details(tmp_path, clean_repo):
    web = demo_web(tmp_path)
    s = sentinel_for(web, clean_repo)

    def boom():
        raise RuntimeError("detail-that-must-not-leak")
    s._job_auditor = boom
    s._run("auditor")
    assert s.errors == 1 and decisions(web)[-1] == "SNTL-ERR"
    assert "detail-that-must-not-leak" not in web.audit_text()
    assert "RuntimeError" in web.audit_text()
    assert not web.ctx.executor.breaker_open and web.ctx.executor.config == GateConfig()


# ---- Sentinel lines are never counted as requests -----------------------------------------
def test_sentinel_lines_not_counted_in_overview_or_activity_filters(tmp_path, clean_repo):
    web = demo_web(tmp_path)
    s = sentinel_for(web, clean_repo)
    web.ctx.executor._config = GateConfig(auto_limit_cents=900_000)
    s._run("auditor")
    s.run_due()
    web.login()
    page = web.client.get("/overview").text
    assert "Requests checked by the Gate</span><b>2</b>" in page        # only the 2 demo HOLDs
    for tab in ("Allowed", "Held", "Blocked"):
        html = web.client.get(f"/audit?f={tab}").text
        for code in SENTINEL_CODES:
            assert f'">{code}</span>' not in html, (tab, code)
    sentinel_tab = web.client.get("/audit?f=Sentinel").text
    assert '">FINDING</span>' in sentinel_tab and '">TRIP</span>' in sentinel_tab


# ---- app loop takeover -----------------------------------------------------------------------
def test_sentinel_flag(tmp_path):
    assert create_app({**DEMO_ENV, "TOLLGATE_SENTINEL": "off"}, data_dir=tmp_path,
                      iterations=1_000).state.ctx.sentinel is None
    with pytest.raises(ConfigError, match="TOLLGATE_SENTINEL"):
        create_app({**DEMO_ENV, "TOLLGATE_SENTINEL": "maybe"}, data_dir=tmp_path, iterations=1_000)


def test_release_loop_still_works_with_sentinel_off(tmp_path):
    web = Web(tmp_path, {**DEMO_ENV, "TOLLGATE_SENTINEL": "off"})
    web.login()
    web.approve("demo-2", web.code())
    web.clock.t += 900
    run_release_once(web.ctx)
    assert web.backend.balance_cents == 150_000 and web.ctx.loop_runs == 1


def test_sentinel_error_never_stops_the_release(tmp_path):
    web = Web(tmp_path, DEMO_ENV)
    web.login()
    web.approve("demo-2", web.code())
    web.clock.t += 900

    def boom():
        raise RuntimeError("x")
    web.ctx.sentinel.run_due = boom
    run_release_once(web.ctx)
    assert web.backend.balance_cents == 150_000
    assert "sentinel round failed" in web.audit_text()


def test_app_loop_runs_sentinel_and_stops_cleanly(tmp_path):
    web = Web(tmp_path, DEMO_ENV, release_interval=0.02)
    with web.client:
        end = time.monotonic() + 20
        while web.ctx.sentinel.rounds < 2 and time.monotonic() < end:
            time.sleep(0.02)
        assert web.ctx.sentinel.rounds >= 2
    assert web.ctx.loop_stopped
    rounds = web.ctx.sentinel.rounds
    time.sleep(0.1)
    assert web.ctx.sentinel.rounds == rounds
