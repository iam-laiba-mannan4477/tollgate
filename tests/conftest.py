def pytest_configure(config):
    config.addinivalue_line(
        "markers", "sandbox: real Braintree sandbox call; needs TOLLGATE_MODE=sandbox and keys")
