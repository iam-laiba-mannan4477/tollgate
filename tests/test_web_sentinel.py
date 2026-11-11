"""Sentinel page: real score and findings, Scan now (one per 30 s), Reset breaker under the
approved rules (session + CSRF + fresh code; refused while locked or while a critical or
high finding is open; 15 min cooling-off in real mode, none in demo), and the honest
"Sentinel is off" state."""
from __future__ import annotations

import re

import pytest

from tollgate.gate.rules import GateConfig
from tests.web_support import DEMO_ENV, REAL_ENV, REAL_PASSWORD, Web

CSRF_OF = re.compile(r'name="csrf" value="([^"]+)"')


@pytest.fixture
def web(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    return w


def csrf(w: Web) -> str:
    return CSRF_OF.search(w.client.get("/sentinel").text).group(1)


def post(w: Web, path: str, **data):
    return w.client.post(path, data={"csrf": csrf(w), **data})


def trip(w: Web) -> None:
    w.ctx.executor.trip_breaker()
    w.ctx.desk.trip_breaker()


def breakers(w: Web) -> tuple[bool, bool]:
    return w.ctx.executor.breaker_open, w.ctx.desk.breaker_open


# ---- access ---------------------------------------------------------------------------------
@pytest.mark.parametrize("path", ["/sentinel", "/drills"])
def test_pages_need_a_logged_in_approver(tmp_path, path):
    w = Web(tmp_path, DEMO_ENV)
    r = w.client.get(path, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    w.login()
    assert w.client.get(path).status_code == 200
    r = w.client.get(path, headers={"Authorization": "Bearer x"})
    assert r.status_code == 403


@pytest.mark.parametrize("path", ["/sentinel/scan", "/sentinel/reset", "/sentinel/reset/cancel",
                                  "/drills/attacks", "/drills/stolen", "/drills/weaken",
                                  "/drills/leak"])
def test_every_button_checks_csrf_and_session(tmp_path, path):
    w = Web(tmp_path, DEMO_ENV)
    trip(w)
    r = w.client.post(path, data={"csrf": "x", "code": "123456"})
    assert r.status_code == 401                                   # no session
    w.login()
    before = w.audit_text()
    for token in ("", "wrong"):
        r = w.client.post(path, data={"csrf": token, "code": w.code()})
        assert r.status_code == 403
    after = w.audit_text()[len(before):]
    assert after.count('"CSRF check failed"') == 2 and "RESET" not in after
    assert breakers(w) == (True, True) and w.ctx.drills.recent() == []
    assert w.ctx.sentinel.last_scan_wall is None


# ---- real data -----------------------------------------------------------------------------
def test_fresh_demo_scan_shows_real_good_score(web):
    r = post(web, "/sentinel/scan")
    assert "Scan finished" in r.text
    assert re.search(r'<b class="big">100</b><span class="st ok">good</span>', r.text)
    assert "No open findings" in r.text
    overview = web.client.get("/overview").text
    assert '<b class="big">100</b>' in overview
    assert "Sentinel: good, score 100" in overview                     # side nav, real


def test_weak_setting_shows_finding_report_and_score(web):
    web.ctx.executor._config = GateConfig(auto_limit_cents=900_000)
    page = post(web, "/sentinel/scan").text
    s = web.ctx.sentinel
    assert s.score() == 75 and s.status() == "warning"
    assert re.search(r'<b class="big">75</b><span class="st hold">warning</span>', page)
    assert "gate.auto_limit_cents" in page and "What now:" in page      # the report text
    assert '">FINDING</span>' in page and '">TRIP</span>' in page      # scan log
    assert '<b class="big">75</b>' in web.client.get("/overview").text
    web.clock.t += 30
    page = post(web, "/sentinel/scan").text                            # setting was restored
    assert "Resolved since the app started" in page and '<span class="st ok">resolved</span>' in page
    assert '<b class="big">100</b>' in page


def test_scan_now_once_per_30_seconds(web):
    post(web, "/sentinel/scan")
    lines = web.audit_text()
    r = post(web, "/sentinel/scan")
    assert "Not run: a scan ran 0 s ago" in r.text and web.audit_text() == lines
    web.clock.t += 29
    assert "Not run" in post(web, "/sentinel/scan").text
    web.clock.t += 1
    assert "Scan finished" in post(web, "/sentinel/scan").text


def test_sentinel_off_is_shown_honestly(tmp_path):
    w = Web(tmp_path, {**DEMO_ENV, "TOLLGATE_SENTINEL": "off"})
    w.login()
    page = w.client.get("/sentinel").text
    assert "Sentinel is off" in page and 'action="/sentinel/scan"' not in page
    assert 'action="/sentinel/reset"' not in page
    overview = w.client.get("/overview").text
    assert "Sentinel is off" in overview and 'class="score"' not in overview
    r = w.client.post("/sentinel/scan", data={"csrf": CSRF_OF.search(page).group(1)})
    assert "Sentinel is off: nothing was scanned" in r.text
    trip(w)
    r = w.client.post("/sentinel/reset", data={"csrf": CSRF_OF.search(page).group(1),
                                               "code": w.code()})
    assert "Sentinel is off" in r.text and breakers(w) == (True, True)


# ---- reset breaker -------------------------------------------------------------------------
def test_reset_needs_an_open_breaker(web):
    page = web.client.get("/sentinel").text
    assert "nothing to reset" in page and 'action="/sentinel/reset"' not in page


def test_demo_reset_with_fresh_code_applies_now(web):
    trip(web)
    assert 'action="/sentinel/reset"' in web.client.get("/sentinel").text
    r = post(web, "/sentinel/reset", code=web.code())
    assert "Breakers reset (demo: no cooling-off)" in r.text
    assert breakers(web) == (False, False)
    audit = web.audit_text()
    assert audit.count("breaker reset by demo-owner: reset from Sentinel page") == 2
    assert "breaker_reset" in web.outbox_text()


def test_wrong_code_does_not_reset_and_counts_toward_lockout(web):
    trip(web)
    r = post(web, "/sentinel/reset", code="000000")
    assert "Not reset: second factor failed (1/3)" in r.text and breakers(web) == (True, True)
    post(web, "/sentinel/reset", code="")
    r = web.client.post("/sentinel/reset", data={"csrf": csrf(web), "code": "999999"},
                        follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"   # sessions ended
    assert web.ctx.service.locked and breakers(web) == (True, True)
    assert web.audit_text().count('"FACTORFAIL"') == 3 and '"LOCKOUT"' in web.audit_text()


def test_reset_refused_while_approvals_locked(web):
    trip(web)
    web.ctx.service._lock_out("test")                    # as after 3 wrong codes
    web.login()
    page = web.client.get("/sentinel").text
    assert "Approvals are locked" in page and "restart" in page
    r = post(web, "/sentinel/reset", code=web.code())
    assert "Not reset. Approvals are locked" in r.text and breakers(web) == (True, True)


def test_reset_refused_while_a_high_finding_is_open(web):
    web.ctx.executor._config = GateConfig(auto_limit_cents=900_000)
    post(web, "/sentinel/scan")                           # HIGH finding, breakers tripped
    assert breakers(web) == (True, True)
    page = web.client.get("/sentinel").text
    assert "An open high finding blocks the reset" in page
    r = post(web, "/sentinel/reset", code=web.code())
    assert "Not reset. An open high finding" in r.text and breakers(web) == (True, True)
    assert '"FACTORFAIL"' not in web.audit_text()         # refused before the code check


@pytest.fixture
def real(tmp_path):
    w = Web(tmp_path, REAL_ENV)
    w.enroll_real()
    w.login("Robin", REAL_PASSWORD)
    trip(w)
    return w


def test_real_reset_waits_15_minutes_then_applies(real):
    r = post(real, "/sentinel/reset", code=real.code())
    assert "Reset queued: it applies after 15 min" in r.text
    assert breakers(real) == (True, True) and "breaker_reset" in real.outbox_text()
    assert "Cancel reset" in real.client.get("/sentinel").text
    real.clock.t += 899
    real.ctx.resets.apply_due()
    assert breakers(real) == (True, True)
    real.clock.t += 1
    real.ctx.resets.apply_due()
    assert breakers(real) == (False, False)
    assert real.audit_text().count("breaker reset by Robin: reset from Sentinel page") == 2


def test_real_reset_can_be_cancelled(real):
    post(real, "/sentinel/reset", code=real.code())
    r = post(real, "/sentinel/reset/cancel")
    assert "Reset cancelled" in r.text
    real.clock.t += 901
    real.ctx.resets.apply_due()
    assert breakers(real) == (True, True)
    assert "breaker reset cancelled by Robin" in real.audit_text()


def test_real_reset_is_dropped_if_a_high_finding_opens_during_the_wait(real):
    post(real, "/sentinel/reset", code=real.code())
    real.ctx.executor._config = GateConfig(auto_limit_cents=900_000)
    real.ctx.sentinel.run_job("auditor")
    real.clock.t += 900
    real.ctx.resets.apply_due()
    assert breakers(real) == (True, True)
    assert "breaker reset dropped" in real.audit_text()


def test_release_loop_applies_a_due_reset(real):
    from tollgate.app.main import run_release_once
    post(real, "/sentinel/reset", code=real.code())
    real.clock.t += 900
    real.ctx.sentinel.run_due = lambda: None              # keep this test about the reset
    run_release_once(real.ctx)
    assert breakers(real) == (False, False)
