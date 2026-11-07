"""Model adapter interface and an offline, deterministic ScriptedModel.

A real AI model would implement `ModelAdapter.generate`. ScriptedModel is NOT an
AI: it replays canned tool calls so the rest of the system can be tested offline
with no key. Its attack scripts deliberately include what a fooled model might emit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence


@dataclass(frozen=True)
class CustomerMessage:
    """An incoming message. `text` is untrusted data, never instructions.

    `id` and `scenario` are set by Tollgate, not by the customer. `scenario` only
    routes ScriptedModel to a canned script; a real model ignores it.
    """

    id: str
    customer_id: str
    text: str
    scenario: str = ""


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: Mapping[str, Any] = field(default_factory=dict)


class ModelUnavailable(Exception):
    """A model gave no usable reply after bounded retries. The agent proposes nothing.

    `category` is a fixed short label (for example "timeout" or "malformed").
    It never holds reply text, keys or headers.
    """

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


class ModelAdapter(Protocol):
    def generate(self, message: CustomerMessage, tools: Sequence[str]) -> list[ToolCall]: ...


class ScriptedModel:
    """Replays a fixed list of tool calls per scenario. Unknown scenario -> no calls."""

    def __init__(self, scripts: Mapping[str, Sequence[ToolCall]]) -> None:
        self._scripts = {k: tuple(v) for k, v in scripts.items()}

    def generate(self, message: CustomerMessage, tools: Sequence[str]) -> list[ToolCall]:
        return [ToolCall(c.name, dict(c.args)) for c in self._scripts.get(message.scenario, ())]
