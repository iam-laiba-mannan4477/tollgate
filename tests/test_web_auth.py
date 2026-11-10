"""Web login: success, failure, rate limit, lockout, session expiry, logout, cookies."""
from __future__ import annotations

import pytest

from tollgate.app.main import DEMO_NAME, DEMO_PASSWORD
from tollgate.app.ratelimit import LoginLimiter
from tests.web_support import DEMO_ENV, REAL_ENV, REAL_PASSWORD, Web


@pytest.fixture
def web(tmp_path):
    return Web(tmp_path, DEMO_ENV)


def test_login_success_sets_session_and_opens_approvals(web):
    r = web.login()
    assert r.status_code == 303 and r.headers["location"] == "/approvals"
    page = web.client.get("/approvals")
    assert page.status_code == 200 and "Held payments" in page.text


def test_wrong_password_fails(web):
    r = web.login(password="wrong-password-123")
    assert r.status_code == 401 and "Login failed" in r.text
    assert web.client.get("/approvals", follow_redirects=False).headers["location"] == "/login"


def test_unknown_name_fails_and_is_not_logged_by_name(web):
    r = web.login(name="mallory-typed-a-secret-here")
    assert r.status_code == 401
    assert "mallory-typed-a-secret-here" not in web.audit_text()
    assert "an unknown name" in web.audit_text()


def test_password_never_in_audit(web):
    web.login(password="this-is-my-wrong-pass")
    web.login()
    text = web.audit_text()
    assert "this-is-my-wrong-pass" not in text and DEMO_PASSWORD not in text


@pytest.mark.parametrize("name", ["agent", "AI", "bot"])
def test_agent_names_cannot_log_in(web, name):
    assert web.login(name=name).status_code == 401


def test_rate_limit_locks_after_five_failures_even_with_right_password(web):
    for _ in range(5):
        assert web.login(password="wrong-password-123").status_code == 401
    r = web.login()
    assert r.status_code == 429 and "15 minutes" in r.text
    assert "LOCKOUT" in web.audit_text()


def test_lockout_ends_after_fifteen_minutes(web):
    for _ in range(5):
        web.login(password="wrong-password-123")
    web.clock.t += 899
    assert web.login().status_code == 429
    web.clock.t += 2
    assert web.login().status_code == 303


def test_failures_spread_over_more_than_a_minute_do_not_lock(web):
    for _ in range(4):
        web.login(password="wrong-password-123")
    web.clock.t += 61
    web.login(password="wrong-password-123")
    assert web.login().status_code == 303


def test_ip_limit_covers_many_names():
    clock = [0.0]
    limiter = LoginLimiter(lambda: clock[0])
    for i in range(5):
        limiter.record_failure(f"name{i}", "10.0.0.9")
    assert limiter.is_locked("someone-new", "10.0.0.9")
    assert not limiter.is_locked("someone-new", "10.0.0.10")


def test_idle_session_expires_after_15_minutes(web):
    web.login()
    web.clock.t += 899
    assert web.client.get("/approvals").status_code == 200       # use resets idle timer
    web.clock.t += 900
    r = web.client.get("/approvals", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_session_expires_after_one_hour_even_when_active(web):
    web.login()
    for _ in range(5):
        web.clock.t += 600
        assert web.client.get("/approvals").status_code == 200    # 50 minutes, active
    web.clock.t += 600                                            # 60 minutes
    assert web.client.get("/approvals", follow_redirects=False).status_code == 303


def test_expired_session_cannot_approve(web):
    web.login()
    csrf = web.csrf("/approvals")
    web.clock.t += 3600
    r = web.approve("demo-1", web.code(), csrf=csrf)
    assert r.status_code == 401
    assert web.backend.balance_cents == 0


def test_logout_ends_session_on_server(web):
    web.login()
    cookie = dict(web.client.cookies)
    csrf = web.csrf("/approvals")
    assert web.client.post("/logout", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    web.client.cookies.clear()
    for k, v in cookie.items():
        web.client.cookies.set(k, v)                  # replay the old cookie
    assert web.client.get("/approvals", follow_redirects=False).status_code == 303


def test_demo_cookie_flags(web):
    r = web.login()
    header = r.headers["set-cookie"].lower()
    assert "tollgate_session=" in header and "httponly" in header
    assert "samesite=strict" in header and "path=/" in header and "max-age=3600" in header


def test_real_cookie_is_secure_with_host_prefix(tmp_path):
    w = Web(tmp_path, REAL_ENV)
    w.enroll_real()
    r = w.login("Robin", REAL_PASSWORD)
    assert r.status_code == 303
    header = r.headers["set-cookie"].lower()
    assert "__host-tollgate=" in header and "secure" in header and "httponly" in header
    assert "samesite=strict" in header and "domain=" not in header


def test_tampered_cookie_is_rejected(web):
    web.login()
    name = "tollgate_session"
    value = web.client.cookies.get(name)
    web.client.cookies.set(name, value[:-2] + ("A" if value[-2] != "A" else "B") + value[-1])
    assert web.client.get("/approvals", follow_redirects=False).status_code == 303
