import pytest

from tollgate.config import ConfigError, Mode, get_mode, missing_sandbox_vars


def test_default_mode_is_mock(monkeypatch):
    monkeypatch.delenv("TOLLGATE_MODE", raising=False)
    assert get_mode() is Mode.MOCK


@pytest.mark.parametrize("value,expected", [("mock", Mode.MOCK), (" SANDBOX ", Mode.SANDBOX)])
def test_known_modes(monkeypatch, value, expected):
    monkeypatch.setenv("TOLLGATE_MODE", value)
    assert get_mode() is expected


@pytest.mark.parametrize("value", ["production", "live", ""])
def test_unknown_mode_fails_closed(monkeypatch, value):
    monkeypatch.setenv("TOLLGATE_MODE", value)
    with pytest.raises(ConfigError):
        get_mode()


def test_missing_vars_reports_names_only(monkeypatch):
    monkeypatch.setenv("BRAINTREE_MERCHANT_ID", "fake_value_123")
    monkeypatch.delenv("BRAINTREE_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("BRAINTREE_PRIVATE_KEY", raising=False)
    missing = missing_sandbox_vars()
    assert missing == ["BRAINTREE_PUBLIC_KEY", "BRAINTREE_PRIVATE_KEY"]
    assert "fake_value_123" not in " ".join(missing)
