"""PBKDF2 password hashes: round count stored with each hash."""
from __future__ import annotations

import dataclasses

from tollgate.approval.accounts import (
    PBKDF2_ITERATIONS, ApproverAccount, PasswordHash, make_password_hash, verify_password,
)
from tollgate.config import Mode

PASSWORD = "correct horse battery"


def test_new_hash_uses_600000_rounds() -> None:
    assert PBKDF2_ITERATIONS == 600_000
    assert make_password_hash(PASSWORD).iterations == 600_000


def test_account_default_uses_600000_rounds() -> None:
    acct = ApproverAccount(Mode.MOCK)
    acct.enroll("Dana", PASSWORD, "owner@example.test")
    assert acct._pw_hash is not None and acct._pw_hash.iterations == 600_000


def test_old_200000_round_hash_still_verifies() -> None:
    old = make_password_hash(PASSWORD, iterations=200_000)
    assert old.iterations == 200_000
    assert verify_password(PASSWORD, old)
    assert not verify_password("wrong password!!", old)


def test_account_verifies_hash_made_with_other_round_count() -> None:
    acct = ApproverAccount(Mode.MOCK, iterations=1_000)
    acct.enroll("Dana", PASSWORD, "owner@example.test")
    acct._pw_hash = make_password_hash(PASSWORD, iterations=200_000)
    assert acct.login("Dana", PASSWORD).name == "Dana"


def test_tampered_round_count_fails() -> None:
    good = make_password_hash(PASSWORD, iterations=1_000)
    assert not verify_password(PASSWORD, dataclasses.replace(good, iterations=1_001))


def test_malformed_hash_fails_closed() -> None:
    good = make_password_hash(PASSWORD, iterations=1_000)
    for bad in (None, b"", dataclasses.replace(good, iterations=0),
                dataclasses.replace(good, iterations=True),
                dataclasses.replace(good, iterations=10**9),
                dataclasses.replace(good, salt=b"")):
        assert not verify_password(PASSWORD, bad)
    assert not verify_password(None, good)


def test_repr_hides_digest() -> None:
    assert "hidden" in repr(make_password_hash(PASSWORD, iterations=1_000))
    assert isinstance(make_password_hash(PASSWORD, iterations=1_000), PasswordHash)
