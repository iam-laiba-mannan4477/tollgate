"""DEMO banner overlap fix: the banner sits in the page flow (never sticky or fixed, so it
cannot cover the logo or page title), and a DEMO label in the side nav keeps demo mode
visible on every logged-in page. Real mode shows neither. (Not checked in a real browser.)"""
from __future__ import annotations

import re
from pathlib import Path

from tests.web_support import DEMO_ENV, REAL_ENV, REAL_PASSWORD, Web

CSS = (Path(__file__).resolve().parent.parent / "tollgate" / "app" / "static" /
       "style.css").read_text(encoding="utf-8")
PAGES = ["/overview", "/approvals", "/audit", "/security", "/sentinel", "/drills"]
LABEL = '<em class="navdemo">DEMO</em>'


def test_banner_is_in_flow_not_sticky_or_fixed():
    rules = re.findall(r"\.demo-banner\s*\{([^}]*)\}", CSS)
    assert rules
    for body in rules:
        assert "sticky" not in body and "fixed" not in body and "absolute" not in body


def test_demo_label_in_side_nav_on_every_demo_page(tmp_path):
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    for path in PAGES:
        assert LABEL in w.client.get(path).text, path


def test_no_demo_label_in_real_mode(tmp_path):
    w = Web(tmp_path, REAL_ENV)
    w.enroll_real()
    w.login("Robin", REAL_PASSWORD)
    for path in PAGES:
        html = w.client.get(path).text
        assert LABEL not in html and 'class="demo-banner"' not in html, path
