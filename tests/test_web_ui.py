"""UI rules: DEMO banner on every demo page, never in real mode; no inline script or style
anywhere (strict CSP); no external files; honest empty states; demo-code wiring."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from tollgate.app.main import propose_payment
from tollgate.approval.totp import code_at
from tests.web_support import CSRF_RE, DEMO_ENV, REAL_ENV, REAL_PASSWORD, Web

STATIC = Path(__file__).resolve().parent.parent / "tollgate" / "app" / "static"
LOGGED_IN_PAGES = ["/overview", "/approvals", "/audit", "/audit?f=Held", "/security", "/setup",
                   "/sentinel", "/drills"]
BANNER = 'class="demo-banner"'


def _demo_pages(w: Web) -> dict[str, str]:
    """Every HTML page a demo visitor can reach, logged out and logged in."""
    pages = {"/login": w.client.get("/login").text, "/setup (out)": w.client.get("/setup").text}
    pages["login error"] = w.login(password="wrong-password-123").text
    w.login()
    for path in LOGGED_IN_PAGES:
        pages[path] = w.client.get(path).text
    csrf = w.csrf("/approvals")
    pages["refused"] = w.client.post("/approvals/demo-1/approve", data={"csrf": "bad"}).text
    pages["reset refused"] = w.client.post("/setup/reset", data={"code": "1", "csrf": csrf}).text
    pages["after approve"] = w.approve("demo-1", w.code(), csrf=csrf).text
    return pages


def _real_pages(w: Web) -> dict[str, str]:
    pages = {"/setup (start)": w.client.get("/setup").text}
    r = w.client.post("/setup/start", data={"name": "Robin", "password": REAL_PASSWORD,
                                            "alert": "owner@example.test",
                                            "csrf": w.csrf("/setup")})
    pages["QR page"] = r.text
    secret = re.search(r'class="secret">([A-Z2-7]+)<', r.text).group(1)
    from tollgate.approval.totp import decode_secret
    w.secret = decode_secret(secret)
    w.wall.t += 30
    pages["setup done"] = w.client.post("/setup/confirm", data={
        "code": code_at(w.secret, w.wall.t), "csrf": CSRF_RE.search(r.text).group(1)}).text
    pages["/login"] = w.client.get("/login").text
    propose_payment(w.ctx, "p-1", 5_000, "acct_new_y", "invoice", "please pay")
    w.login("Robin", REAL_PASSWORD)
    for path in LOGGED_IN_PAGES:
        pages[path] = w.client.get(path).text
    return pages


@pytest.fixture
def demo_pages(tmp_path):
    return _demo_pages(Web(tmp_path, DEMO_ENV))


@pytest.fixture
def real_pages(tmp_path):
    return _real_pages(Web(tmp_path, REAL_ENV))


# ---- DEMO banner ------------------------------------------------------------------------
def test_demo_banner_on_every_demo_page(demo_pages):
    assert len(demo_pages) >= 11
    for name, html in demo_pages.items():
        assert BANNER in html and "DEMO MODE" in html, name
        # The banner is the first thing in <body>, so it shows at the top.
        body = html.split("<body>", 1)[1].lstrip()
        assert body.startswith(f"<div {BANNER}"), name


def test_no_demo_banner_or_code_in_real_mode(real_pages):
    for name, html in real_pages.items():
        assert BANNER not in html and "DEMO MODE" not in html, name
        assert 'class="code"' not in html and "data-next" not in html, name
        assert "demo-password" not in html, name
    assert "REAL MODE" in real_pages["/approvals"]


# ---- strict CSP: nothing inline, nothing external ---------------------------------------
INLINE_HANDLER = re.compile(r"\son[a-z]+\s*=", re.I)
SCRIPT_TAG = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.I | re.S)
EXTERNAL = re.compile(r"""(?:src|href)\s*=\s*["']?\s*(?:https?:)?//""", re.I)


def _assert_no_inline(name: str, html: str) -> None:
    assert "<style" not in html.lower(), f"{name}: <style> element"
    assert not re.search(r"\sstyle\s*=", html, re.I), f"{name}: style attribute"
    assert not INLINE_HANDLER.search(html), f"{name}: inline event handler"
    assert "javascript:" not in html.lower(), f"{name}: javascript: URL"
    scripts = SCRIPT_TAG.findall(html)
    assert scripts, f"{name}: app.js missing"
    for attrs, body in scripts:
        assert 'src="/static/app.js"' in attrs and not body.strip(), f"{name}: inline script"
    assert not EXTERNAL.search(html), f"{name}: external file"


def test_no_inline_script_or_style_in_demo_pages(demo_pages):
    for name, html in demo_pages.items():
        _assert_no_inline(name, html)


def test_no_inline_script_or_style_in_real_pages(real_pages):
    for name, html in real_pages.items():
        _assert_no_inline(name, html)


def test_static_files_are_self_contained():
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "@import" not in css and "http" not in css and "url(" not in css
    assert "http" not in js and "fetch(" not in js and "XMLHttpRequest" not in js
    assert "eval(" not in js and "innerHTML" not in js
    assert sorted(p.name for p in STATIC.iterdir()) == ["app.js", "style.css"]


# ---- honest content -----------------------------------------------------------------------
def test_no_score_before_sentinel_has_scanned(demo_pages):
    """Before Sentinel's first round there is no score at all (no fake number)."""
    for page in ("/overview", "/security", "/sentinel"):
        assert "First scan pending" in demo_pages[page]
        assert 'class="score"' not in demo_pages[page]
    assert "Security score" in demo_pages["/overview"]
    assert not re.search(r'class="ring', demo_pages["/overview"])     # no fake score dial


def test_overview_counts_come_from_the_audit_log(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    page = w.client.get("/overview").text
    assert re.search(r'<i class="c-hold">2</i>held', page)            # the two demo seeds
    assert re.search(r"Requests checked by the Gate</span><b>2</b>", page)


def test_audit_filter_tabs(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    held = w.client.get("/audit?f=Held").text
    assert "demo-1" in held and 'aria-current="true">Held' in held
    odd = w.client.get("/audit?f=<script>").text                       # unknown -> All
    assert 'aria-current="true">All' in odd and "<script>" not in odd.split("<body>")[1]


# ---- demo code wiring: only inside each held payment's approve panel ---------------------
PANEL = re.compile(r'<details class="su panel" data-approve-panel>.*?</details>', re.S)
SIX = re.compile(r"(?<!\d)\d{6}(?!\d)")


def _outside_panels(page: str) -> str:
    return PANEL.sub("", page)


def test_permanent_demo_code_card_is_gone(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    page = w.client.get("/approvals").text
    assert 'id="democode"' not in page and "Demo one-time code" not in page
    assert "AUTHENTICATOR STAND-IN" not in page
    assert page.count(">Approve with code</summary>") == 2            # one per held payment


def test_demo_code_appears_only_inside_the_panels(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    page = w.client.get("/approvals").text
    now, nxt = code_at(w.secret, w.wall.t), code_at(w.secret, w.wall.t + 30)
    panels = PANEL.findall(page)
    assert len(panels) == 2
    for panel in panels:
        assert f'data-code="{now}"' in panel and f'data-next="{nxt}"' in panel
        assert 'data-used="false"' in panel and "Demo code, filled in for you" in panel
        field = re.search(r'name="code"[^>]*value="(\d*)"[^>]*data-demo-code-field', panel)
        assert field and field.group(1) == now
        assert ">Confirm</button>" in panel and "data-panel-cancel" in panel
    outside = _outside_panels(page)
    assert now not in outside and nxt not in outside and "data-code=" not in outside
    assert "demo code" not in outside.lower()


def test_no_code_anywhere_when_nothing_is_held(tmp_path):
    w = Web(tmp_path, DEMO_ENV, demo_seed=False)
    w.login()
    page = w.client.get("/approvals").text
    body = page.split("<body>")[1]
    assert "data-approve-panel" not in page and "data-code=" not in page
    assert code_at(w.secret, w.wall.t) not in body
    assert code_at(w.secret, w.wall.t + 30) not in body
    assert "Nothing is waiting for a decision" in page


def test_real_mode_never_shows_a_code(tmp_path):
    w = Web(tmp_path, REAL_ENV)
    w.enroll_real()
    propose_payment(w.ctx, "p-1", 5_000, "acct_new_y", "invoice", "please pay")
    w.login("Robin", REAL_PASSWORD)
    now, nxt = code_at(w.secret, w.wall.t), code_at(w.secret, w.wall.t + 30)
    for path in LOGGED_IN_PAGES:
        html = w.client.get(path).text.split("<body>")[1]
        assert now not in html and nxt not in html, path
        assert "data-code=" not in html and "data-next=" not in html, path
        assert "demo code" not in html.lower(), path
    page = w.client.get("/approvals").text
    [panel] = PANEL.findall(page)
    field = re.search(r'<input name="code"[^>]*>', panel).group(0)
    assert "value=" not in field and "required" in field              # empty, typed by hand


def test_used_code_is_not_prefilled_and_flagged(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    w.approve("demo-1", code_at(w.secret, w.wall.t))                 # uses this step's code
    [panel] = PANEL.findall(w.client.get("/approvals").text)
    assert 'data-used="true"' in panel and "data-demoused" in panel
    assert re.search(r'name="code"[^>]*value=""[^>]*data-demo-code-field', panel)
    field = re.search(r'<input name="code"[^>]*>', panel).group(0)
    assert "required" not in field          # an empty field must not stop the waiting click


def test_next_step_code_is_accepted_after_the_wait(tmp_path):
    """What app.js does after waiting: send the next step's code once that step starts."""
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    w.approve("demo-1", code_at(w.secret, w.wall.t))
    nxt = re.search(r'data-next="(\d{6})"', w.client.get("/approvals").text).group(1)
    w.wall.t += 30
    page = w.approve("demo-2", nxt).text
    assert "demo-2: HOLD. approved, waiting" in page               # $1,500, new recipient
    assert [i for i, _ in w.ctx.service.waiting()] == ["demo-2"]


def test_panels_render_closed_and_work_without_javascript(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    page = w.client.get("/approvals").text
    assert "<details class=\"su panel\" data-approve-panel>" in page   # native, not [open]
    assert "<details class=\"su panel\" data-approve-panel open" not in page
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "data-approve-panel" in js and 'getElementById("democode")' not in js
