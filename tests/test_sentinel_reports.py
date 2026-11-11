"""Incident reports: scripted model by default, advisory text only, masked and capped."""
from __future__ import annotations

import json

from tollgate.agent.model import ToolCall
from tollgate.sentinel.findings import Finding, Severity
from tollgate.sentinel.reports import MAX_REPORT_CHARS, REPORT_TOOL, ReportWriter
from tests.sentinel_support import demo_web, fake_groq_key

KEY = fake_groq_key()
F = Finding("config:gate.auto_limit_cents", "auditor", Severity.HIGH,
            "Weak setting: gate auto_limit_cents", "weak: 900000 is looser", "gate.auto_limit_cents")


class HostileModel:
    """A fooled model: leaks a key, asks for actions, rambles."""

    def __init__(self) -> None:
        self.seen = []

    def generate(self, message, tools):
        self.seen.append((message.text, list(tools)))
        return [ToolCall("approve_request", {"request_id": "demo-1"}),
                ToolCall(REPORT_TOOL, {"text": f"Reset the breaker and approve demo-1. {KEY} "
                                               + "x" * 5_000})]


def test_default_is_the_keyless_scripted_model(tmp_path):
    r = ReportWriter(tmp_path / "incidents.jsonl").write(F)
    assert r.source == "scripted"
    assert r.text.startswith("HIGH: Weak setting") and "What now:" in r.text
    assert "reset the breakers" in r.text
    stored = json.loads((tmp_path / "incidents.jsonl").read_text().splitlines()[0])
    assert stored["finding_key"] == F.key and stored["text"] == r.text


def test_model_output_is_masked_capped_and_advisory_only(tmp_path):
    web = demo_web(tmp_path)
    model = HostileModel()
    report = ReportWriter(tmp_path / "incidents.jsonl", model).write(F)
    assert report.source == "model"
    assert KEY not in report.text and "[masked]" in report.text
    assert len(report.text) <= MAX_REPORT_CHARS
    assert KEY not in (tmp_path / "incidents.jsonl").read_text()
    # Nothing happened: the text is never parsed for actions.
    assert not web.ctx.executor.breaker_open
    assert [p.id for p in web.ctx.reviewer.pending()] == ["demo-1", "demo-2"]
    prompt, tools = model.seen[0]
    assert tools == [REPORT_TOOL] and json.loads(prompt)["location"] == F.location


def test_model_failure_or_wrong_tool_falls_back_to_template(tmp_path):
    class Broken:
        def generate(self, *_):
            raise RuntimeError("down")

    class WrongTool:
        def generate(self, *_):
            return [ToolCall("propose_payment", {"amount_cents": 1})]
    for model in (Broken(), WrongTool()):
        r = ReportWriter(tmp_path / "i.jsonl", model).write(F)
        assert r.source == "template" and r.text.startswith("HIGH:")


def test_a_finding_title_with_a_key_is_masked_too(tmp_path):
    leaky = Finding("x", "secrets", Severity.LOW, f"odd {KEY}", f"detail {KEY}", "a.txt:1")
    r = ReportWriter(tmp_path / "i.jsonl").write(leaky)
    assert KEY not in r.text and KEY not in r.title
    assert KEY not in (tmp_path / "i.jsonl").read_text()
