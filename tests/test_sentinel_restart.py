"""Security review finding 1: after a restart Sentinel must not re-trip the breakers from old
LOCKOUT lines. Only lines written after start-up count; a RESET line drops older lockout and
failed-code events (payment patterns keep counting); the audit log is never changed; and a
real new lockout after the restart still trips everything."""
from __future__ import annotations

import json

from tollgate.app.main import build_context
from tollgate.gate.audit import AuditLog, verify
from tollgate.sentinel import monitor
from tollgate.sentinel.findings import Severity
from tests.web_support import DEMO_ENV, Web

ENV = {"TOLLGATE_AUTH_MODE": "demo"}


def ctx_on(folder):
    return build_context(ENV, data_dir=folder, iterations=1_000)


def lock_out(ctx) -> None:
    ctx.service._lock_out("3 failed second-factor attempts")      # as after 3 wrong codes


def high(sentinel) -> list:
    return [f for f in sentinel.open_findings() if f.severity in (Severity.HIGH, Severity.CRITICAL)]


def test_restart_with_an_old_lockout_leaves_breakers_closed(tmp_path):
    first = ctx_on(tmp_path)
    lock_out(first)
    assert first.service.locked and first.executor.breaker_open
    before = first.audit_path.read_bytes()
    assert b'"LOCKOUT"' in before

    again = ctx_on(tmp_path)                                         # the restart
    assert not again.service.locked and not again.executor.breaker_open
    again.sentinel.run_all_now()
    again.sentinel.run_due()
    assert not again.executor.breaker_open and not again.desk.breaker_open
    assert high(again.sentinel) == [], again.sentinel.open_findings()
    after = again.audit_path.read_bytes()
    assert after.startswith(before)                                  # nothing edited or cut
    assert b'"TRIP"' not in after[len(before):]
    assert verify(again.audit_path)                                  # hash chain still valid


def test_a_new_lockout_after_the_restart_still_trips(tmp_path):
    lock_out(ctx_on(tmp_path))
    again = ctx_on(tmp_path)
    again.sentinel.run_job("monitor")
    assert not again.executor.breaker_open
    lock_out(again)                                                  # a real, new lockout
    assert again.executor.breaker_open and again.desk.breaker_open
    again.sentinel.run_job("monitor")
    [f] = [f for f in again.sentinel.open_findings() if f.title.startswith("Approvals locked")]
    assert f.severity is Severity.HIGH


def test_new_wrong_code_after_restart_is_still_seen(tmp_path):
    lock_out(ctx_on(tmp_path))
    again = ctx_on(tmp_path)
    again.service.record("x-1", "FACTORFAIL", "approval: second factor failed (1/3)", None, None)
    again.sentinel.run_job("monitor")
    assert [f.severity for f in again.sentinel.open_findings()] == [Severity.MEDIUM]


def _write(path, decision, reason="r", amount=None, recipient=None, wall=1_000.0):
    AuditLog(path, lambda: wall).append(f"t-{decision}-{wall}", decision, reason, amount, recipient)


def test_reset_drops_lockout_and_failed_code_events_but_keeps_payment_patterns(tmp_path):
    path = tmp_path / "audit.jsonl"
    reader = monitor.AuditReader(path)
    _write(path, "LOCKOUT")
    _write(path, "FACTORFAIL")
    for i in range(5):                                               # a burst of 5 in 60 s
        _write(path, "ALLOW", "ok", 100, "acct_x", wall=1_000.0 + i)
    _write(path, "RESET", "breaker reset by Robin: test")
    events = reader.read(1_010.0)
    kinds = [e.decision for e in events]
    assert "LOCKOUT" not in kinds and "FACTORFAIL" not in kinds
    assert kinds.count("ALLOW") == 5
    titles = [f.title for f in monitor.detect(events, 100_000)]
    assert any("burst" in t.lower() for t in titles), titles
    assert not any("locked" in t.lower() for t in titles)


def test_lockout_after_a_reset_still_counts(tmp_path):
    path = tmp_path / "audit.jsonl"
    reader = monitor.AuditReader(path)
    _write(path, "RESET", "breaker reset by Robin: test")
    _write(path, "LOCKOUT")
    assert [e.decision for e in reader.read(1_010.0)] == ["LOCKOUT"]


def test_reader_starting_at_end_skips_old_lines_only(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, "LOCKOUT")
    _write(path, "BLOCK", "x", 100, "acct_y")
    reader = monitor.AuditReader(path, start_at_end=True)
    assert reader.skipped_at_start == 2 and reader.read(1_010.0) == []
    _write(path, "LOCKOUT")
    assert [e.decision for e in reader.read(1_010.0)] == ["LOCKOUT"]


def test_a_shortened_audit_file_is_reread_from_the_top(tmp_path):
    """Lines removed: fail closed and read everything again (stricter, never looser)."""
    path = tmp_path / "audit.jsonl"
    for _ in range(3):
        _write(path, "BLOCK", "x", 100, "acct_y")
    reader = monitor.AuditReader(path, start_at_end=True)
    assert reader.read(1_010.0) == []
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:1]) + "\n", encoding="utf-8")   # someone cut lines
    assert [e.decision for e in reader.read(1_010.0)] == ["BLOCK"]


def test_demo_restart_really_clears_a_lockout(tmp_path):
    """The README promise: 3 wrong codes lock approvals; stop and start the app again (same
    data folder) and approvals are open, breakers closed, and Sentinel does not re-trip."""
    w = Web(tmp_path, DEMO_ENV)
    w.login()
    for code in ("000000", "111111", "222222"):
        w.approve("demo-1", code)
    assert w.ctx.service.locked and w.ctx.executor.breaker_open
    again = Web(tmp_path, DEMO_ENV)                                  # restart, same data/
    assert not again.ctx.service.locked and not again.ctx.executor.breaker_open
    again.ctx.sentinel.run_due()
    assert not again.ctx.executor.breaker_open and high(again.ctx.sentinel) == []
    again.login()
    assert "demo-1" in again.client.get("/approvals").text           # demo payments are back
    assert any(json.loads(l)["decision"] == "LOCKOUT"
               for l in again.audit_text().splitlines())             # history kept on disk
