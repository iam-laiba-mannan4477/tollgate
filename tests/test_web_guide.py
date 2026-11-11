"""The Guide: on every page in both modes; "What is this app?", the page tips (what + why),
a last "what next" card with a link, the glossary, the "Try it yourself" task list, and
"Replay intro". Demo vs real wording; real mode never suggests an on-screen code. No inline
script or style; everything readable with the guide script missing. The tour itself
(Next to the end, placement inside the window, never over its target) runs under Node."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from html import unescape
from pathlib import Path

import pytest

from tollgate.app.main import propose_payment
from tests.test_web_ui import _assert_no_inline
from tests.web_support import DEMO_ENV, REAL_ENV, REAL_PASSWORD, Web

STATIC = Path(__file__).resolve().parent.parent / "tollgate" / "app" / "static"
HARNESS = Path(__file__).resolve().parent / "guide_harness.js"
NODE = shutil.which("node")
PAGES = ["/overview", "/approvals", "/audit", "/security", "/sentinel", "/drills", "/setup"]
GUIDE = re.compile(r'<details class="guide" id="guide".*?(?=<div class="guide-card")', re.S)
TIP = re.compile(r'<li data-guide-target="([^"]*)"[^>]*>(.*?)</li>', re.S)
TASK = re.compile(r'<li data-task="(\d+)">(.*?)</li>', re.S)
TAG = re.compile(r"<[^>]+>")
GLOSSARY = ["Gate", "Held", "Simulated proposal", "Approve with code", "Stamp", "Cooling-off", "Circuit breaker",
            "Sentinel", "Audit log", "Untrusted text", "Throwaway world", "Demo mode", "Real mode"]
# Wording that would suggest an on-screen code. Real mode must never contain it.
ON_SCREEN = ("filled in", "pre-filled", "prefilled", "demo code", "shown on screen",
             "shown here", "code is shown", "on-screen code", "code below", "just press confirm")


def guide(html: str) -> str:
    m = GUIDE.search(html)
    assert m, "no guide"
    return m.group(0)


def tips(html: str) -> list[tuple[str, str]]:
    return [(unescape(t), unescape(TAG.sub("", x)).strip()) for t, x in TIP.findall(guide(html))]


def page_tips(html: str) -> list[tuple[str, str]]:
    return [(t, x) for t, x in tips(html) if t]          # without the "what next" card


@pytest.fixture
def demo(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    return w


@pytest.fixture
def real(tmp_path):
    w = Web(tmp_path, REAL_ENV)
    w.enroll_real()
    propose_payment(w.ctx, "p-1", 5_000, "acct_new_y", "invoice", "please pay")
    w.login("Robin", REAL_PASSWORD)
    return w


# ---- structure ---------------------------------------------------------------------------
@pytest.mark.parametrize("mode", ["demo", "real"])
def test_guide_on_every_logged_in_page(mode, request):
    w = request.getfixturevalue(mode)
    for path in PAGES:
        html = w.client.get(path).text
        g = guide(html)
        assert 'class="guide-btn"' in g and 'id="guide-card" hidden' in html, path
        assert "<h3>What is this app?</h3>" in g, path
        assert "<summary>Words used in this app</summary>" in g, path
        assert "Try it yourself" in g, path
        assert page_tips(html), path
        for word in ("Back", "Next", "Close", "Skip"):
            assert f">{word}</button>" in html, (path, word)
        assert "data-guide-tour hidden" in g, path               # tour button needs the script
        _assert_no_inline(f"{mode} {path}", html)


def test_what_is_this_app_card(demo):
    text = unescape(re.search(r"<p data-guide-what>(.*?)</p>", guide(
        demo.client.get("/overview").text)).group(1))
    assert text.startswith("Tollgate is a payment firewall for AI agents.")
    for part in ("can only propose a payment", "allows it, holds it for a person, or blocks it",
                 "one-time code", "fake money in a sandbox"):
        assert part in text
    assert 3 <= text.count(". ") + 1 <= 4                          # 3 or 4 short sentences


def test_glossary_has_every_word_once_with_one_sentence(demo):
    g = guide(demo.client.get("/overview").text)
    terms = re.findall(r"<dt>([^<]+)</dt><dd>([^<]+)</dd>", g)
    assert [t for t, _ in terms] == GLOSSARY
    for term, sentence in terms:
        assert sentence.endswith(".") and sentence.count(". ") == 0, term


def test_every_tip_is_two_sentences_what_then_why(demo, real):
    for w in (demo, real):
        for path in PAGES:
            for _, text in page_tips(w.client.get(path).text):
                sentences = [s for s in re.split(r"(?<=[.!?])\s+", text) if s]
                assert len(sentences) == 2, (path, text)


def test_last_card_says_what_next_with_a_real_link(demo):
    for path in PAGES:
        g = guide(demo.client.get(path).text)
        m = re.search(r'<li class="guide-nextstep" data-guide-target="" data-guide-link="([^"]+)"'
                      r' data-guide-link-text="([^"]+)">Next:', g)
        assert m, path
        assert demo.client.get(m.group(1), follow_redirects=False).status_code in (200, 303), path
        assert g.rfind("<li data-guide-target=") < g.find('class="guide-nextstep"'), path


def test_tips_point_at_real_parts_of_each_page(demo):
    for path in PAGES:
        html = demo.client.get(path).text
        for target, _ in page_tips(html):
            hook = re.search(r"data-guide=(\w+)|\.([\w-]+)|action[$]?='([^']+)'|data-approve-panel",
                             target)
            assert hook, target
            if hook.group(1):
                assert f'data-guide="{hook.group(1)}"' in html, (path, target)
            elif hook.group(2):
                assert re.search(rf'class="[^"]*\b{re.escape(hook.group(2))}\b', html), (path, target)
            elif hook.group(3):
                assert hook.group(3) in html, (path, target)
            else:
                assert "data-approve-panel" in html, (path, target)


def test_approvals_has_tips_4_and_5(demo):
    t = page_tips(demo.client.get("/approvals").text)
    assert [x for x, _ in t] == [".sub", "[data-guide=simulate]", "[data-approve-panel] > summary",
                                 ".apr form[action$='/reject']", "[data-guide=waiting]",
                                 ".demo-banner"]
    assert "the way an AI agent would, through the Gate" in t[1][1]


def test_login_and_setup_pages_have_one_tip_each(tmp_path):
    d = Web(tmp_path / "d", DEMO_ENV)
    assert len(page_tips(d.client.get("/login").text)) == 1
    assert len(page_tips(d.client.get("/setup").text)) == 1
    r = Web(tmp_path / "r", REAL_ENV)
    assert len(page_tips(r.client.get("/setup").text)) == 1
    r.enroll_real()
    login = r.client.get("/login").text
    assert len(page_tips(login)) == 1 and "for the owner only" in login


# ---- wording ------------------------------------------------------------------------------
def test_page_tips_say_what_each_page_really_does(demo):
    text = {p: " ".join(t for _, t in page_tips(demo.client.get(p).text)) for p in PAGES}
    assert "summary" in text["/overview"] and "Sentinel" in text["/overview"]
    assert "Approve with code" in text["/approvals"] and "fresh code" in text["/approvals"]
    assert "15-minute cooling-off" in text["/approvals"]
    assert "audit log" in text["/audit"] and "detected" in text["/audit"]
    assert "Scan now" in text["/sentinel"] and "never loosen" in text["/sentinel"]
    assert "throwaway world" in text["/drills"] and "never touched" in text["/drills"]
    assert "in force right now" in text["/security"]
    assert "fake secret" in text["/setup"]


def test_demo_wording(demo):
    text = " ".join(t for p in ("/overview", "/approvals") for _, t in page_tips(demo.client.get(p).text))
    assert "DEMO banner means this is a demo with fake money and a fake secret" in text
    assert "in demo mode the code is filled in for you" in text


def test_real_wording_never_suggests_an_on_screen_code(real):
    approvals = " ".join(t for _, t in page_tips(real.client.get("/approvals").text))
    assert "from your authenticator app" in approvals
    for path in PAGES:
        g = guide(real.client.get(path).text).lower()
        for word in ON_SCREEN:
            assert word not in g, (path, word)


def test_sentinel_off_tip_is_honest(tmp_path):
    w = Web(tmp_path, {**DEMO_ENV, "TOLLGATE_SENTINEL": "off"})
    w.login()
    [(_, tip)] = page_tips(w.client.get("/sentinel").text)
    assert "Sentinel is off" in tip and "Scan now" not in tip


# ---- Try it yourself ---------------------------------------------------------------------
def test_demo_tasks(demo):
    g = guide(demo.client.get("/approvals").text)
    tasks = TASK.findall(g)
    n = len(tasks)
    assert n == 8
    for i, (num, body) in enumerate(tasks, 1):
        assert num == str(i) and f"Task {i} of {n}" in body
        assert "You should see:" in body
        href = re.search(r'<a href="([^"]+)">', body).group(1)
        assert demo.client.get(href, follow_redirects=False).status_code == 200, href
    joined = unescape(" ".join(b for _, b in tasks))
    assert "$25.00" in joined and "$1,500.00" in joined and "untrusted text" in joined
    assert "Scan now" in joined and "stolen-session drill" in joined and "Reject" in joined
    assert "Simulate an agent proposal" in tasks[3][1] and "quick-fill" in tasks[3][1]
    assert "Task 4 of 8" in tasks[3][1]
    assert "of 7" not in g
    assert "If approvals lock during the demo, stop the app and start it again." in g


def test_real_tasks_start_with_setup_and_never_show_a_code(real):
    g = guide(real.client.get("/approvals").text)
    tasks = TASK.findall(g)
    assert len(tasks) == 8
    assert 'href="/setup"' in tasks[0][1] and "authenticator app" in tasks[0][1]
    assert 'href="/login"' in tasks[1][1]
    assert "6-digit code from your authenticator app" in tasks[2][1]
    assert "Simulate an agent proposal" in tasks[2][1]
    assert "makes no example payments" not in g
    for word in ON_SCREEN:
        assert word not in g.lower(), word


# ---- replay intro --------------------------------------------------------------------------
def test_replay_intro_link_in_guide_and_sidebar(demo):
    html = demo.client.get("/approvals").text
    assert 'href="/approvals?intro=1" data-replay-intro>Replay intro</a>' in guide(html)
    nav = html.split('<div class="navfoot">')[1].split("</nav>")[0]
    assert 'href="/approvals?intro=1" data-replay-intro>Replay intro</a>' in nav
    assert demo.client.get("/approvals?intro=1").status_code == 200


# ---- no script -----------------------------------------------------------------------------
def test_pages_render_without_the_guide_script(demo, tmp_path):
    """guide.js really missing (404): every page is complete and the whole guide is a plain
    native <details>, readable with no script."""
    from starlette.staticfiles import StaticFiles
    copy = tmp_path / "static"
    shutil.copytree(STATIC, copy)
    (copy / "guide.js").unlink()
    for route in demo.app.routes:
        if getattr(route, "name", "") == "static":
            route.app = StaticFiles(directory=copy)
    assert demo.client.get("/static/guide.js").status_code == 404
    for path in PAGES:
        html = demo.client.get(path).text
        assert ('class="views"' in html and "</main>" in html) or 'class="lg-card"' in html, path
        g = guide(html)
        assert "<summary" in g and "<ol" in g and "<dl" in g, path


def test_guide_script_is_safe_and_separate():
    js = (STATIC / "guide.js").read_text(encoding="utf-8")
    assert "sessionStorage" in js and "catch (e)" in js
    assert "Escape" in js and "prefers-reduced-motion" in js
    assert "innerHTML" not in js and "fetch(" not in js and "eval(" not in js
    app = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "guide" not in app.lower()


# ---- the tour, run under Node -------------------------------------------------------------
def harness(scenario: str) -> dict:
    out = subprocess.run([NODE, str(HARNESS), str(STATIC / "guide.js"), scenario],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_tour_first_visit_runs_to_the_end_inside_the_window():
    r = harness("first")
    assert r["autoOpened"] and r["tourButtonShown"]
    counts = [c["count"] for c in r["cards"]]
    assert counts == ["Welcome"] + [f"Step {i} of 6" for i in range(1, 7)]
    assert [c["text"] for c in r["cards"][4:6]] == ["tip 4", "tip 5"]   # tips 4 and 5 appear
    assert all(c["inside"] and not c["covers"] for c in r["cards"])
    assert r["cards"][-1]["link"] == "/audit" and r["cards"][-1]["next"] == "Done"
    assert r["closedAtEnd"] and r["remembered"]


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_tour_uses_a_bottom_strip_when_space_is_tight():
    r = harness("tight")
    assert all(c["strip"] and not c["floating"] for c in r["cards"])


@pytest.mark.skipif(NODE is None, reason="node is not installed")
@pytest.mark.parametrize("scenario", ["seen", "nostorage"])
def test_tour_does_not_open_by_itself(scenario):
    r = harness(scenario)
    assert not r["autoOpened"] and r["tourButtonShown"]


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_placement_rule():
    r = harness("place")
    spot = r["besideButton"]
    assert spot is not None and r["tooSmall"] is None
    assert spot["left"] + 340 <= 1280 - 12 and spot["top"] >= 340 + 12   # below, inside, no overlap


def test_restart_notes_match_what_a_restart_really_clears(demo, real):
    """Security review finding 1 is fixed, so the demo note is true; real mode also says a
    restart clears the approver account (finding 9)."""
    d = guide(demo.client.get("/approvals").text)
    assert ("stop the app and start it again. Approvals unlock, the breakers start closed and "
            "the two demo payments come back.") in d
    r = guide(real.client.get("/approvals").text)
    assert "clears the approver account, so setup must be done again" in r
