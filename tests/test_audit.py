import json
import secrets

import pytest

from tollgate.gate.audit import AuditLog, verify


@pytest.fixture
def log(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path, clock=lambda: 1000.0)
    for i in range(4):
        audit.append(f"r{i}", "HOLD", "over auto limit", 150_000 + i, "acct_new")
    return path, audit


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def test_intact_log_verifies(log):
    path, _ = log
    assert verify(path)
    rec = json.loads(lines(path)[0])
    assert set(rec) == {"id", "time", "decision", "reason", "amount_cents",
                        "recipient", "prev_hash", "hash"}


def test_edit_breaks_chain(log):
    path, _ = log
    ls = lines(path)
    ls[1] = ls[1].replace("150001", "1")
    path.write_text("\n".join(ls) + "\n", encoding="utf-8")
    assert not verify(path)


def test_delete_middle_line_breaks_chain(log):
    path, _ = log
    ls = lines(path)
    del ls[1]
    path.write_text("\n".join(ls) + "\n", encoding="utf-8")
    assert not verify(path)


def test_delete_last_line_caught_with_anchor(log):
    path, audit = log
    anchor = audit.append("r9", "ALLOW", "ok", 100, "acct_known")
    path.write_text("\n".join(lines(path)[:-1]) + "\n", encoding="utf-8")
    assert verify(path)              # known limit: tail truncation alone is invisible
    assert not verify(path, expected_last_hash=anchor)


def test_reorder_and_garbage_fail(log):
    path, _ = log
    ls = lines(path)
    path.write_text("\n".join([ls[1], ls[0]] + ls[2:]) + "\n", encoding="utf-8")
    assert not verify(path)
    path.write_text("not json\n", encoding="utf-8")
    assert not verify(path)


def test_missing_file_fails_closed(tmp_path):
    assert not verify(tmp_path / "nope.jsonl")


@pytest.mark.parametrize("reason", [
    "stamp: " + secrets.token_urlsafe(32),
    "api_key=abc",
    "card 4111111111111111",
    "BRAINTREE_PRIVATE_KEY leaked",
])
def test_secret_looking_text_is_never_logged(tmp_path, reason):
    path = tmp_path / "a.jsonl"
    AuditLog(path).append("r1", "BLOCK", reason, 100, "acct_1")
    text = path.read_text(encoding="utf-8")
    assert "[redacted]" in text
    for fragment in ("4111111111111111", "api_key", "PRIVATE_KEY", reason[7:]):
        assert fragment not in text
    assert verify(path)


def test_bad_amount_logged_as_null(tmp_path):
    path = tmp_path / "a.jsonl"
    AuditLog(path).append("r1", "BLOCK", "invalid request", "100; DROP", "acct_1")
    assert json.loads(lines(path)[0])["amount_cents"] is None
