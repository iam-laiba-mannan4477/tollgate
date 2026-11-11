"""Secrets scanner: finds a FAKE leaked key, masks it, never stores or prints it, and never
opens .env (only asks git whether it is ignored)."""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import pytest

from tollgate.sentinel import secrets_scan
from tollgate.sentinel.findings import Severity
from tollgate.sentinel.secret_patterns import label_for, mask
from tests.sentinel_support import demo_web, fake_groq_key, git_repo, sentinel_for

KEY = fake_groq_key()


@pytest.fixture
def repo(tmp_path):
    return git_repo(tmp_path / "repo",
                    tracked={"app/config.py": f"x = 1\nGROQ = '{KEY}'\n", "ok.py": "y = 2\n"},
                    untracked={"tests/fixtures/leak.txt": f"line one\n\ntoken: {KEY}\n",
                               "logs/run.log": f"start\n{KEY}\n"})


def test_tracked_leak_is_critical_and_masked(repo):
    result = secrets_scan.scan(repo)
    hits = {(h.path, h.line): h for h in result.hits}
    tracked = hits[("app/config.py", 2)]
    assert tracked.tracked and tracked.label == "Groq API key"
    found = {f.location: f for f in secrets_scan.findings(result)}
    crit = found["app/config.py:2"]
    assert crit.severity is Severity.CRITICAL and "masked" in crit.title
    assert KEY not in repr(result) and KEY not in repr(found)


def test_untracked_fixture_and_log_are_found_as_low(repo):
    result = secrets_scan.scan(repo)
    sev = {f.location: f.severity for f in secrets_scan.findings(result)}
    assert sev["tests/fixtures/leak.txt:3"] is Severity.LOW
    assert sev["logs/run.log:2"] is Severity.LOW


def test_extra_data_dir_is_scanned(tmp_path, repo):
    data = tmp_path / "data"
    data.mkdir()
    (data / "outbox.jsonl").write_text(f'{{"text": "{KEY}"}}\n', encoding="utf-8")
    result = secrets_scan.scan(repo, [data])
    assert any(h.path == "outbox.jsonl" and h.line == 1 for h in result.hits)


def test_env_file_is_never_opened(repo, monkeypatch):
    name = "GROQ" + "_API_KEY"                 # built at runtime: keeps this file scan-clean
    (repo / ".env").write_text(f"{name}={KEY}\n", encoding="utf-8")
    (repo / ".env.local").write_text(f"{name}={KEY}\n", encoding="utf-8")
    opened: list[str] = []
    real = Path.read_bytes

    def spy(self):
        opened.append(self.name)
        return real(self)
    monkeypatch.setattr(Path, "read_bytes", spy)
    result = secrets_scan.scan(repo)
    assert ".env" not in opened and ".env.local" not in opened
    assert result.env_ignored is True
    assert not any(h.path.startswith(".env") for h in result.hits)


def test_env_not_ignored_is_critical(tmp_path):
    repo = git_repo(tmp_path / "r", tracked={"a.py": "a = 1\n"}, gitignore="data/\n")
    result = secrets_scan.scan(repo)
    assert result.env_ignored is False
    [f] = [f for f in secrets_scan.findings(result) if f.key == "leak:env-not-ignored"]
    assert f.severity is Severity.CRITICAL


def test_git_missing_is_reported_not_crashed(repo):
    def broken(_args):
        raise OSError("no git")
    result = secrets_scan.scan(repo, git=broken)
    assert result.env_ignored is None and result.problems
    assert all(f.severity is Severity.LOW for f in secrets_scan.findings(result))


def test_placeholders_and_binary_files_are_skipped(tmp_path):
    repo = git_repo(tmp_path / "r", tracked={
        "a.py": "GROQ_API_KEY=your_groq_key_here\nBRAINTREE_PRIVATE_KEY=example0000000000000\n"})
    (repo / "tests").mkdir()
    (repo / "tests" / "blob.bin").write_bytes(b"\x00\x01" + KEY.encode())
    assert secrets_scan.scan(repo).hits == []


def test_mask_and_label():
    assert label_for(f"key = {KEY}") == "Groq API key"
    assert KEY not in mask(f"see {KEY} here") and "[masked]" in mask(f"see {KEY} here")


def test_report_audit_and_logs_never_contain_the_fake_key(tmp_path, repo, caplog):
    caplog.set_level(logging.DEBUG)
    web = demo_web(tmp_path)
    sentinel = sentinel_for(web, repo)
    sentinel.run_all_now()
    assert any(f.location == "app/config.py:2" for f in sentinel.open_findings())
    reports = (web.ctx.audit_path.parent / "incidents.jsonl").read_text(encoding="utf-8")
    assert "app/config.py:2" in reports
    for text in (reports, web.audit_text(), caplog.text, repr(sentinel.reports),
                 repr(sentinel.open_findings())):
        assert KEY not in text
        assert KEY[:12] not in text                 # not even a prefix of it


def test_real_repo_tracked_files_have_no_leaks():
    """The project itself (tracked files) must scan clean, like scripts/check_secrets.py."""
    root = Path(__file__).resolve().parent.parent
    if subprocess.run(["git", "rev-parse"], cwd=root, capture_output=True).returncode:
        pytest.skip("not a git checkout")
    result = secrets_scan.scan(root)
    assert result.env_ignored is True
    assert [h for h in result.hits if h.tracked] == []
