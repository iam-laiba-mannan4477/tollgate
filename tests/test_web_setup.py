"""Real-mode setup by QR code: shown once, confirmed by the first code, bound to one
browser, never logged. Re-running setup needs the current code."""
from __future__ import annotations

import logging
import re

import pytest

from tollgate.approval.totp import code_at, decode_secret
from tests.web_support import CSRF_RE, REAL_ENV, REAL_PASSWORD, Web

SECRET_RE = re.compile(r'class="secret">([A-Z2-7]+)<')


@pytest.fixture
def web(tmp_path):
    return Web(tmp_path, REAL_ENV)


def _start(w: Web, name: str = "Robin"):
    r = w.client.post("/setup/start", data={"name": name, "password": REAL_PASSWORD,
                                            "alert": "owner@example.test",
                                            "csrf": w.csrf("/setup")})
    assert r.status_code == 200, r.text
    return r, SECRET_RE.search(r.text).group(1), CSRF_RE.search(r.text).group(1)


def _confirm(w: Web, csrf: str, code: str):
    return w.client.post("/setup/confirm", data={"code": code, "csrf": csrf})


def test_setup_shows_qr_once_and_confirms_with_first_code(web):
    r, secret, csrf = _start(web)
    assert "<svg" in r.text and "<path" in r.text
    assert not web.ctx.account.enrolled                    # not until confirmed
    web.wall.t += 30
    ok = _confirm(web, csrf, code_at(decode_secret(secret), web.wall.t))
    assert ok.status_code == 200 and "Setup complete" in ok.text
    assert web.ctx.account.enrolled
    assert web.login("Robin", REAL_PASSWORD).status_code == 303


def test_wrong_first_code_does_not_enrol(web):
    _, _, csrf = _start(web)
    assert _confirm(web, csrf, "000000").status_code == 400
    assert not web.ctx.account.enrolled


def test_setup_is_bound_to_the_browser_that_started_it(tmp_path, web):
    _, secret, _ = _start(web)
    other = web.client.__class__(web.app, base_url="https://testserver")
    other_csrf = CSRF_RE.search(other.get("/setup").text).group(1)
    web.wall.t += 30
    r = other.post("/setup/confirm", data={"code": code_at(decode_secret(secret), web.wall.t),
                                           "csrf": other_csrf})
    assert r.status_code == 400 and not web.ctx.account.enrolled


def test_setup_expires_after_ten_minutes(web):
    _, secret, csrf = _start(web)
    web.clock.t += 600
    web.wall.t += 30
    assert _confirm(web, csrf, code_at(decode_secret(secret), web.wall.t)).status_code == 400
    assert not web.ctx.account.enrolled


def test_setup_cannot_be_rerun_without_the_current_code(web):
    web.enroll_real()
    r = web.client.post("/setup/start", data={"name": "Eve", "password": "eve-password-123",
                                              "alert": "eve@example.test",
                                              "csrf": web.csrf("/login")})
    assert r.status_code == 403 and web.ctx.account.name == "Robin"
    assert web.client.get("/setup", follow_redirects=False).headers["location"] == "/login"


def test_reset_needs_current_code_and_queues_a_change(web):
    web.enroll_real()
    web.login("Robin", REAL_PASSWORD)
    csrf = web.csrf("/setup")
    bad = web.client.post("/setup/reset", data={"code": "000000", "csrf": csrf})
    assert bad.status_code == 400 and "second factor failed" in bad.text
    good = web.client.post("/setup/reset", data={"code": web.code(), "csrf": csrf})
    assert good.status_code == 200 and "<svg" in good.text and "cooling-off" in good.text
    new_secret = SECRET_RE.search(good.text).group(1)
    assert new_secret not in web.audit_text() and new_secret not in web.outbox_text()


def test_qr_secret_never_in_logs_audit_or_outbox(web, caplog):
    caplog.set_level(logging.DEBUG)
    r, secret, csrf = _start(web)
    web.wall.t += 30
    code = code_at(decode_secret(secret), web.wall.t)
    _confirm(web, csrf, code)
    web.login("Robin", REAL_PASSWORD)
    everything = caplog.text + web.audit_text() + web.outbox_text()
    assert secret not in everything
    assert code not in caplog.text and REAL_PASSWORD not in everything
    assert "SETUP" in web.audit_text()
    assert secret not in repr(web.ctx.account)
