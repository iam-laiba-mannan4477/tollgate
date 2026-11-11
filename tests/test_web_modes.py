"""Demo vs real mode, startup checks, and security headers on every response."""
from __future__ import annotations

import pytest

from tollgate.app.auth_mode import AuthMode, read_auth_mode
from tollgate.app.main import DEMO_NAME, DEMO_PASSWORD, create_app
from tollgate.app.security_headers import HEADERS
from tollgate.approval.accounts import AccountError
from tollgate.approval.totp import MOCK_TOTP_SECRET_B32
from tollgate.config import ConfigError
from tests.web_support import DEMO_ENV, REAL_ENV, REAL_PASSWORD, TEST_SESSION_KEY, Web


# ---- startup ------------------------------------------------------------------------
def test_default_auth_mode_is_demo():
    assert read_auth_mode({}) is AuthMode.DEMO


@pytest.mark.parametrize("value", ["", "prod", "production", "real-ish", "demo1", "none"])
def test_unknown_auth_mode_stops_startup(tmp_path, value):
    with pytest.raises(ConfigError, match="TOLLGATE_AUTH_MODE"):
        create_app({"TOLLGATE_AUTH_MODE": value}, data_dir=tmp_path, iterations=1_000)


@pytest.mark.parametrize("key", [None, "", "short", "x" * 31])
def test_real_mode_needs_a_long_session_key(tmp_path, key):
    env = {"TOLLGATE_AUTH_MODE": "real"}
    if key is not None:
        env["TOLLGATE_SESSION_KEY"] = key
    with pytest.raises(ConfigError, match="TOLLGATE_SESSION_KEY") as info:
        create_app(env, data_dir=tmp_path, iterations=1_000)
    if key:
        assert key not in str(info.value)          # the value is never echoed


# ---- demo mode ----------------------------------------------------------------------
def test_demo_banner_on_every_page(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    for path in ["/login", "/setup"]:
        assert "DEMO MODE" in w.client.get(path).text
    w.login()
    for path in ["/approvals", "/audit", "/setup"]:
        assert "DEMO MODE" in w.client.get(path).text
    refused = w.client.post("/approvals/demo-1/approve", data={"csrf": "bad"})
    assert refused.status_code == 403 and "DEMO MODE" in refused.text


def test_demo_account_documented_on_login_page(tmp_path):
    page = Web(tmp_path, DEMO_ENV).client.get("/login").text
    assert DEMO_NAME in page and DEMO_PASSWORD in page


def test_demo_shows_the_current_code_and_it_works(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    w.wall.t += 30
    page = w.client.get("/approvals").text
    import re
    shown = re.search(r'name="code"[^>]*value="(\d{6})"[^>]*data-demo-code-field', page).group(1)
    assert "demo-1: sent" in w.approve("demo-1", shown).text


def test_demo_marks_a_used_code(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    w.approve("demo-1", w.code())
    assert "This demo code was just used. Press Confirm and it will wait a few seconds for the next one, then approve." in w.client.get("/approvals").text


def test_demo_cannot_reset_authenticator(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    r = w.client.post("/setup/reset", data={"code": w.code(), "csrf": w.csrf("/approvals")})
    assert r.status_code == 403 and "fake demo secret" in r.text


# ---- real mode ----------------------------------------------------------------------
def test_real_mode_has_no_banner_and_no_default_account(tmp_path):
    w = Web(tmp_path, REAL_ENV)
    assert not w.ctx.account.enrolled
    r = w.client.get("/login", follow_redirects=False)
    assert r.headers["location"] == "/setup"                  # must set up first
    page = w.client.get("/setup").text
    assert "DEMO MODE" not in page and DEMO_PASSWORD not in page
    assert w.client.post("/login", data={"name": DEMO_NAME, "password": DEMO_PASSWORD,
                                         "csrf": w.csrf("/setup")}).status_code == 401


def test_real_mode_never_shows_the_code(tmp_path):
    w = Web(tmp_path, REAL_ENV)
    w.enroll_real()
    w.login("Robin", REAL_PASSWORD)
    page = w.client.get("/approvals").text
    assert 'class="code"' not in page and "Demo one-time code" not in page
    assert "DEMO MODE" not in page


def test_real_mode_refuses_the_fake_demo_secret(tmp_path):
    w = Web(tmp_path, REAL_ENV)
    with pytest.raises(AccountError, match="fake mock secret"):
        w.ctx.account.enroll("Robin", REAL_PASSWORD, "o@example.test", MOCK_TOTP_SECRET_B32)
    with pytest.raises(AccountError, match="fake mock secret"):
        w.ctx.account.begin_enroll("Robin", REAL_PASSWORD, "o@example.test", "bind",
                                   MOCK_TOTP_SECRET_B32)
    assert not w.ctx.account.enrolled


def test_real_mode_password_minimum_12(tmp_path):
    w = Web(tmp_path, REAL_ENV)
    r = w.client.post("/setup/start", data={"name": "Robin", "password": "short-11ch",
                                            "alert": "o@example.test", "csrf": w.csrf("/setup")})
    assert r.status_code == 400 and "at least 12" in r.text and not w.ctx.account.enrolled


# ---- security headers -------------------------------------------------------------------
def _assert_headers(response):
    for name, value in HEADERS.items():
        assert response.headers.get(name) == value, name
    csp = response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "'unsafe-inline'" not in csp
    assert "script-src 'self'" in csp


@pytest.mark.parametrize("env", [DEMO_ENV, REAL_ENV], ids=["demo", "real"])
def test_security_headers_on_every_response(tmp_path, env):
    w = Web(tmp_path, env)
    for path in ["/", "/login", "/setup", "/approvals", "/audit", "/static/style.css",
                 "/static/app.js", "/no-such-page"]:
        _assert_headers(w.client.get(path, follow_redirects=False))
    _assert_headers(w.client.post("/login", data={}))
    _assert_headers(w.client.post("/approvals/x/approve", data={"csrf": "bad"}))


def test_no_inline_scripts_in_pages(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    import re
    for path in ["/approvals", "/audit", "/setup"]:
        tags = re.findall(r"<script[^>]*>", w.client.get(path).text)
        assert tags and all('src="/static/' in t for t in tags)
        assert "onclick=" not in w.client.get(path).text


def test_unexpected_error_fails_closed_with_headers(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()

    def boom(*_a, **_k):
        raise RuntimeError("internal detail that must not leak")
    w.ctx.reviewer.approve = boom
    r = w.approve("demo-1", w.code())
    assert r.status_code == 500 and "internal detail" not in r.text
    _assert_headers(r)
    assert w.backend.balance_cents == 0
