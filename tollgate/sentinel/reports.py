"""Incident reports: a short plain-language report for each finding.

Written through the model adapter interface with one offered tool,
`write_incident_summary(text)`. The default is the keyless ScriptedModel with a fixed
template. Any model output is ADVISORY TEXT ONLY: it is never parsed for actions, it is
masked with the secret patterns and capped at 1,000 characters before it is stored.
The model is only shown the finding's kind, severity, title and masked location.

Honest limit: the real Groq/Claude providers only accept the agent's own tool names, so a
real model is not wired in yet; if one fails for any reason the template is used.
"""
from __future__ import annotations

import itertools
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tollgate.agent.model import CustomerMessage, ScriptedModel, ToolCall
from tollgate.sentinel.findings import Finding, Severity
from tollgate.sentinel.secret_patterns import mask

REPORT_TOOL = "write_incident_summary"
MAX_REPORT_CHARS = 1_000
_NEXT = {Severity.CRITICAL: "Sentinel tripped the breakers. A person must review it, fix "
                            "the cause, then reset the breakers.",
         Severity.HIGH: "Sentinel tripped the breakers. A person must review it, then reset "
                        "the breakers.",
         Severity.MEDIUM: "No automatic action. Please review it.",
         Severity.LOW: "No automatic action. Please tidy it up."}


@dataclass(frozen=True)
class Report:
    report_id: str
    finding_key: str
    severity: str
    title: str
    text: str
    source: str          # "scripted" (default), "model", or "template" (fallback)


def template_text(f: Finding) -> str:
    where = f" Where: {f.location}." if f.location else ""
    return (f"{f.severity.value.upper()}: {f.title}. {f.detail}{where} "
            f"What now: {_NEXT[f.severity]}")


def _prompt(f: Finding) -> str:
    return json.dumps({"kind": f.job, "severity": f.severity.value, "title": f.title,
                       "location": f.location})


class ReportWriter:
    def __init__(self, path: Path, model: Any | None = None) -> None:
        self._path = Path(path)
        self._model = model          # None -> a ScriptedModel built per finding (keyless)
        self._lock = threading.Lock()
        self._seq = itertools.count(1)

    def write(self, f: Finding) -> Report:
        rid = f"incident-{next(self._seq)}"
        text, source = self._ask(f, rid)
        report = Report(rid, f.key, f.severity.value, mask(f.title)[:200],
                        mask(text)[:MAX_REPORT_CHARS], source)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as out:
                out.write(json.dumps(report.__dict__, sort_keys=True) + "\n")
        return report

    def _ask(self, f: Finding, rid: str) -> tuple[str, str]:
        template = template_text(f)
        model = self._model or ScriptedModel({rid: [ToolCall(REPORT_TOOL, {"text": template})]})
        try:
            calls = model.generate(CustomerMessage(rid, "sentinel", _prompt(f), rid),
                                   [REPORT_TOOL])
            for call in calls:
                text = call.args.get("text") if call.name == REPORT_TOOL else None
                if isinstance(text, str) and text.strip():
                    return text.strip(), "scripted" if self._model is None else "model"
        except Exception:
            pass
        return template, "template"
