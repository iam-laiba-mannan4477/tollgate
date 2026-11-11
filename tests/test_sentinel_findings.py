"""Findings store, score formula and status bands."""
from __future__ import annotations

import pytest

from tollgate.sentinel.findings import Finding, FindingStore, Severity, score, status


def f(key: str, sev: Severity, job: str = "auditor") -> Finding:
    return Finding(key, job, sev, key, "detail")


@pytest.mark.parametrize("sevs,expected", [
    ([], 100), ([Severity.LOW], 97), ([Severity.MEDIUM], 90), ([Severity.HIGH], 75),
    ([Severity.CRITICAL], 60), ([Severity.CRITICAL] * 2, 20), ([Severity.CRITICAL] * 3, 0),
    ([Severity.HIGH, Severity.MEDIUM, Severity.LOW], 62)])
def test_score_formula_and_floor(sevs, expected):
    assert score([f(f"k{i}", s) for i, s in enumerate(sevs)]) == expected


@pytest.mark.parametrize("sevs,label", [
    ([], "good"), ([Severity.MEDIUM, Severity.MEDIUM], "good"), ([Severity.HIGH], "warning"),
    ([Severity.HIGH, Severity.HIGH], "warning"), ([Severity.HIGH, Severity.HIGH, Severity.HIGH],
                                                   "at risk")])
def test_status_bands(sevs, label):
    assert status([f(f"k{i}", s) for i, s in enumerate(sevs)]) == label


def test_any_critical_means_at_risk_whatever_the_score():
    one = [f("c", Severity.CRITICAL)]
    assert score(one) == 60 and status(one) == "at risk"


def test_sync_opens_once_and_resolves_when_gone():
    store = FindingStore()
    opened, resolved = store.sync("auditor", [f("a", Severity.HIGH)], 1.0)
    assert [x.key for x in opened] == ["a"] and not resolved
    opened, resolved = store.sync("auditor", [f("a", Severity.HIGH)], 2.0)
    assert not opened and not resolved                     # deduped while open
    opened, resolved = store.sync("auditor", [], 3.0)
    assert not opened and [x.key for x in resolved] == ["a"]
    assert store.open_findings() == []


def test_sync_only_touches_its_own_job():
    store = FindingStore()
    store.sync("auditor", [f("a", Severity.HIGH)], 1.0)
    store.sync("monitor", [], 2.0)
    assert [x.key for x in store.open_findings()] == ["a"]
