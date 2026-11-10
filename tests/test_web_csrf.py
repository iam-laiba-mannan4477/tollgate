"""CSRF: every state-changing form is refused without the right token."""
from __future__ import annotations

import pytest

from tollgate.app.main import DEMO_NAME, DEMO_PASSWORD
from tests.web_support import DEMO_ENV, Web


@pytest.fixture
def web(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    assert w.login().status_code == 303
    return w


@pytest.mark.parametrize("token", [None, "", "wrong-token", "x" * 500])
def test_approve_without_valid_csrf_is_refused(web, token):
    data = {"code": web.code()}
    if token is not None:
        data["csrf"] = token
    r = web.client.post("/approvals/demo-1/approve", data=data)
    assert r.status_code == 403
    assert web.backend.balance_cents == 0
    assert "CSRF check failed" in web.audit_text()
    assert any(p.id == "demo-1" for p in web.ctx.reviewer.pending())    # still held


@pytest.mark.parametrize("path", ["/approvals/demo-1/reject", "/waiting/demo-2/cancel",
                                  "/logout"])
def test_other_forms_need_csrf(web, path):
    assert web.client.post(path, data={"csrf": "nope"}).status_code == 403
    assert web.client.get("/approvals").status_code == 200        # still logged in


def test_csrf_from_another_session_is_refused(tmp_path, web):
    other = Web(tmp_path / "other", DEMO_ENV)
    other.login()
    foreign = other.csrf("/approvals")
    assert web.approve("demo-1", web.code(), csrf=foreign).status_code == 403


def test_csrf_token_dies_with_session(web):
    old = web.csrf("/approvals")
    web.client.post("/logout", data={"csrf": old})
    web.login()
    assert web.approve("demo-1", web.code(), csrf=old).status_code == 403


def test_login_form_needs_csrf(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    r = w.client.post("/login", data={"name": DEMO_NAME, "password": DEMO_PASSWORD})
    assert r.status_code == 403
    r = w.client.post("/login", data={"name": DEMO_NAME, "password": DEMO_PASSWORD,
                                      "csrf": "forged"})
    assert r.status_code == 403
