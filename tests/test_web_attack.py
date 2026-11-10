"""Attacks through the web layer: stolen session without a code, agent credentials,
forged cookies and untrusted text. No money may move in any of them."""
from __future__ import annotations

import pytest

from tollgate.app.sessions import CookieSigner
from tollgate.approval.accounts import Role, Session
from tests.web_support import DEMO_ENV, REAL_ENV, REAL_PASSWORD, Web


@pytest.fixture
def web(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    assert w.login().status_code == 303
    return w


def _held(web, pid):
    return any(p.id == pid for p in web.ctx.reviewer.pending())


# ---- stolen session, no code --------------------------------------------------------
def test_stolen_session_without_code_cannot_approve(web):
    """The attacker holds the cookie AND a valid CSRF token, but not the authenticator."""
    csrf = web.csrf("/approvals")
    for n, code in enumerate(["", "000000"], start=1):
        r = web.approve("demo-1", code, csrf=csrf)
        assert f"second factor failed ({n}/3)" in r.text
    r = web.approve("demo-1", "123456", csrf=csrf)
    assert r.url.path == "/login"                   # third failure ends every session
    assert web.backend.balance_cents == 0
    assert web.ctx.service.locked                   # 3 bad codes lock approvals
    assert web.ctx.executor.breaker_open and web.ctx.desk.breaker_open
    # The stolen session is dead too.
    r = web.client.get("/approvals", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert "LOCKOUT" in web.audit_text() and "FACTORFAIL" in web.audit_text()


def test_replayed_code_is_refused_through_web(web):
    code = web.code()
    csrf = web.csrf("/approvals")
    assert "demo-1: sent" in web.approve("demo-1", code, csrf=csrf).text
    assert _held(web, "demo-2")                    # second held item to try the replay on
    r = web.approve("demo-2", code, csrf=web.csrf("/approvals"))
    assert "second factor failed" in r.text
    assert _held(web, "demo-2")


def test_lockout_stays_after_fresh_login(web):
    csrf = web.csrf("/approvals")
    for _ in range(3):
        web.approve("demo-1", "000000", csrf=csrf)
    assert web.login().status_code == 303          # password still works...
    r = web.approve("demo-1", web.code())          # ...but approvals stay locked
    assert "Approvals are LOCKED" in r.text and "circuit breaker open" in r.text
    assert web.backend.balance_cents == 0


# ---- agent credentials --------------------------------------------------------------
@pytest.mark.parametrize("header", ["Bearer agent-token", "Basic YWdlbnQ6eA==", "anything"])
def test_agent_credential_header_rejected_at_approve(web, header):
    csrf = web.csrf("/approvals")
    r = web.client.post("/approvals/demo-1/approve", data={"code": web.code(), "csrf": csrf},
                        headers={"Authorization": header})
    assert r.status_code == 403 and "only the approver" in r.text
    assert web.backend.balance_cents == 0 and _held(web, "demo-1")


def test_agent_without_any_cookie_rejected_at_approve(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    r = w.client.post("/approvals/demo-1/approve", data={"code": w.code(), "csrf": "x"})
    assert r.status_code == 401 and w.backend.balance_cents == 0


def test_agent_session_forged_with_real_key_is_rejected(web):
    """Even a correctly signed cookie for a token the server never issued is refused."""
    signer = web.ctx.signer
    fake = Session("forged-agent-token", "agent", Role.AGENT)
    web.ctx.sessions.add(fake)                     # worst case: it got into the table
    web.client.cookies.set("tollgate_session", signer.seal(fake.token))
    r = web.approve("demo-1", web.code(), csrf=signer.csrf_for(fake.token))
    assert r.status_code == 401 and web.backend.balance_cents == 0


def test_cookie_signed_with_another_key_is_rejected(web):
    other = CookieSigner(b"k" * 32)
    web.client.cookies.set("tollgate_session", other.seal("whatever-token"))
    assert web.client.get("/approvals", follow_redirects=False).status_code == 303


def test_agent_service_call_with_agent_role_is_refused(web):
    """Below the web layer: an agent-role session is refused by the approval service."""
    res = web.ctx.reviewer.approve("demo-1", Session("t", "agent", Role.AGENT), web.code())
    assert not res.executed and "not an approver session" in res.reason


# ---- untrusted text ---------------------------------------------------------------------
def test_untrusted_text_is_escaped(tmp_path):
    from tollgate.app.main import propose_payment
    w = Web(tmp_path, DEMO_ENV, demo_seed=False)
    propose_payment(w.ctx, "xss-1", 1_000, "acct_new_x", "invoice",
                    '<script>alert(1)</script><img src=x onerror=alert(2)>')
    w.login()
    page = w.client.get("/approvals").text
    assert "<script>alert(1)" not in page and "<img src=x" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_real_mode_stolen_session_without_code(tmp_path):
    w = Web(tmp_path, REAL_ENV)
    w.enroll_real()
    from tollgate.app.main import propose_payment
    propose_payment(w.ctx, "p-1", 5_000, "acct_new_y", "invoice")
    assert w.login("Robin", REAL_PASSWORD).status_code == 303
    csrf = w.csrf("/approvals")
    for _ in range(3):
        w.approve("p-1", "999999", csrf=csrf)
    assert w.backend.balance_cents == 0 and w.ctx.service.locked
