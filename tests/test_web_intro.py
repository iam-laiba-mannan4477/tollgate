"""Intro animation: markup present on every page, hidden by default (so pages work without
the script), no inline script or style, and the app.js control logic (run under Node)."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_web_ui import _assert_no_inline
from tests.web_support import DEMO_ENV, REAL_ENV, REAL_PASSWORD, Web

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "tollgate" / "app" / "static" / "app.js"
HARNESS = Path(__file__).resolve().parent / "intro_harness.js"
INTRO_RE = re.compile(r'<div id="intro"([^>]*)>(.*?)<div class="title">', re.S)


def _intro(html: str) -> tuple[str, str]:
    match = INTRO_RE.search(html)
    assert match, "intro markup missing"
    return match.group(1), match.group(2)


def _pages(w: Web, real: bool) -> dict[str, str]:
    pages = {"setup" if real else "login": w.client.get("/setup" if real else "/login").text}
    if real:
        w.enroll_real()
        pages["login"] = w.client.get("/login").text
        w.login("Robin", REAL_PASSWORD)
    else:
        w.login()
    for path in ["/overview", "/approvals", "/audit", "/security"]:
        pages[path] = w.client.get(path).text
    return pages


@pytest.mark.parametrize("env,real", [(DEMO_ENV, False), (REAL_ENV, True)], ids=["demo", "real"])
def test_intro_markup_on_every_page(tmp_path, env, real):
    for name, html in _pages(Web(tmp_path, env), real).items():
        attrs, body = _intro(html)
        assert re.search(r"\shidden(\s|$)", attrs), f"{name}: intro must start hidden"
        assert 'aria-label="Tollgate intro animation"' in attrs
        assert 'id="skip"' in body and "Skip intro" in body, name
        assert 'class="lockwrap"' in body and 'class="key"' in body and 'class="shackle"' in body
        assert 'class="glow"' in body
        assert "golden padlock opened by a golden key" in body
        _assert_no_inline(name, html)


def test_pages_render_fully_without_the_intro_script(tmp_path):
    """No JavaScript runs in the test client: the intro stays hidden and the page is all there."""
    w = Web(tmp_path, DEMO_ENV)
    login = w.client.get("/login").text
    attrs, _ = _intro(login)
    assert "hidden" in attrs
    assert 'action="/login"' in login and 'class="demo-banner"' in login
    w.login()
    page = w.client.get("/approvals").text
    assert "Held payments" in page and "demo-1" in page
    assert page.index('class="demo-banner"') < page.index('id="intro"')   # banner stays first


def test_intro_svg_has_no_external_font_or_file():
    html = (ROOT / "tollgate" / "app" / "templates" / "_intro.html").read_text(encoding="utf-8")
    assert "Sora" not in html and "googleapis" not in html and "style=" not in html
    assert "<script" not in html and "http" not in html.replace("http://www.w3.org", "")


# ---- app.js behaviour, run under Node with a tiny fake DOM --------------------------------
NODE = shutil.which("node")


def _run(scenario: str) -> dict:
    out = subprocess.run([NODE, str(HARNESS), str(APP_JS), scenario], capture_output=True,
                         text=True, timeout=30, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_intro_replays_with_intro_1_even_when_seen():
    r = _run("replay")
    assert r["shownAtStart"] and r["autoEndMs"] == 6300


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_intro_plays_once_on_first_visit():
    r = _run("first")
    assert r["shownAtStart"] and r["remembered"] and r["skipFocused"]
    assert r["autoEndMs"] == 6300 and not r["endedEarly"]


@pytest.mark.skipif(NODE is None, reason="node is not installed")
@pytest.mark.parametrize("scenario", ["seen", "nointro", "reduced", "nostorage", "broken"])
def test_intro_does_not_show(scenario):
    r = _run(scenario)
    assert not r["shownAtStart"] and r["hiddenAfter"], scenario


@pytest.mark.skipif(NODE is None, reason="node is not installed")
@pytest.mark.parametrize("scenario", ["key", "skip"])
def test_intro_can_be_skipped(scenario):
    r = _run(scenario)
    assert r["shownAtStart"] and r["endedEarly"] and r["hiddenAfter"]
