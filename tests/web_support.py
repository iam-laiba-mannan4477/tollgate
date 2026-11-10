"""Helpers for web tests. Fake clocks, mock backend, low PBKDF2 rounds for speed.

Real-mode tests use https://testserver so the browser-style client sends Secure cookies.
The session key below is a TEST-ONLY placeholder, not a real key.
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from tollgate.app.main import DEMO_NAME, DEMO_PASSWORD, create_app
from tollgate.approval.totp import MOCK_TOTP_SECRET_B32, code_at, decode_secret, new_secret_b32
from tollgate.executor.backend import MockBackend

TEST_SESSION_KEY = "example-test-only-session-key-0123456789abcdef"
REAL_ENV = {"TOLLGATE_AUTH_MODE": "real", "TOLLGATE_SESSION_KEY": TEST_SESSION_KEY}
DEMO_ENV = {"TOLLGATE_AUTH_MODE": "demo"}
REAL_PASSWORD = "a-long-real-password"
CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')


class Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class Web:
    """One app plus one browser-like client, with fake monotonic and wall clocks."""

    def __init__(self, tmp_path: Path, env: dict[str, str], *, release_interval: float = 3600,
                 demo_seed: bool = True) -> None:
        self.clock = Clock(10_000.0)
        self.wall = Clock(1_700_000_000.0)
        self.backend = MockBackend()
        self.app = create_app(env, data_dir=tmp_path, clock=self.clock, wall_clock=self.wall,
                              backend=self.backend, iterations=1_000,
                              release_interval=release_interval, demo_seed=demo_seed)
        self.ctx = self.app.state.ctx
        base = "https://testserver" if self.ctx.real else "http://testserver"
        self.client = TestClient(self.app, base_url=base)
        self.secret = decode_secret(MOCK_TOTP_SECRET_B32) if not self.ctx.real else None

    # ---- helpers ------------------------------------------------------------------
    def csrf(self, path: str = "/login") -> str:
        match = CSRF_RE.search(self.client.get(path).text)
        assert match, f"no csrf token on {path}"
        return match.group(1)

    def login(self, name: str = DEMO_NAME, password: str = DEMO_PASSWORD):
        return self.client.post("/login", data={"name": name, "password": password,
                                                "csrf": self.csrf("/login")},
                                follow_redirects=False)

    def code(self) -> str:
        """A fresh code: the next 30-second step of the wall clock."""
        assert self.secret is not None
        self.wall.t += 30
        return code_at(self.secret, self.wall.t)

    def approve(self, pid: str, code: str, csrf: str | None = None, **kw):
        token = csrf if csrf is not None else self.csrf("/approvals")
        return self.client.post(f"/approvals/{pid}/approve",
                                data={"code": code, "csrf": token}, **kw)

    def enroll_real(self, name: str = "Robin") -> None:
        """Real mode: enrol directly with a fresh random secret (the QR flow is tested
        separately), and keep the secret so the test can act as the authenticator."""
        secret = new_secret_b32()
        self.ctx.account.enroll(name, REAL_PASSWORD, "owner@example.test", secret)
        self.secret = decode_secret(secret)

    def audit_text(self) -> str:
        path = self.ctx.audit_path
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def outbox_text(self) -> str:
        path = self.ctx.outbox_path
        return path.read_text(encoding="utf-8") if path.exists() else ""
