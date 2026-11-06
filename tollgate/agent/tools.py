"""The ONLY tools the agent may call. Every one either proposes or reads.

There is deliberately no tool that sends money, approves, issues stamps, resets
the breaker, or reads secrets, files or environment variables. A tool name the
model invents (for example "execute_payment") is simply unknown and BLOCKED.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

from tollgate.agent.proposal import ProposalKind, is_safe_id

PROPOSE_TOOLS: Mapping[str, ProposalKind] = MappingProxyType({
    "propose_payment": ProposalKind.PAYMENT,
    "propose_refund": ProposalKind.REFUND,
    "propose_dispute_response": ProposalKind.DISPUTE_RESPONSE,
    "propose_subscription_change": ProposalKind.SUBSCRIPTION_CHANGE,
})
_LOOKUP_KEYS: Mapping[str, str] = MappingProxyType({
    "lookup_order": "order_id",
    "lookup_customer": "customer_id",
})
LOOKUP_TOOLS = frozenset(_LOOKUP_KEYS)
ALL_TOOLS = frozenset(PROPOSE_TOOLS) | LOOKUP_TOOLS


class Directory:
    """Read-only reference data (orders, customers) the agent may look up.

    Data is copied into read-only views; the agent cannot change it, and it holds
    no secrets. It is a hint for the model, never a source of truth for money:
    the executor checks totals against its own ledger.
    """

    def __init__(self, orders: Mapping[str, Mapping[str, Any]] | None = None,
                 customers: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        self._tables = {
            "lookup_order": _freeze(orders or {}),
            "lookup_customer": _freeze(customers or {}),
        }

    def lookup(self, tool: str, args: Any) -> Mapping[str, Any] | None:
        """Return a read-only record, or None if the call is bad or unknown."""
        key = _LOOKUP_KEYS.get(tool)
        if key is None or not isinstance(args, dict) or set(args) != {key}:
            return None
        if not is_safe_id(args[key]):
            return None
        return self._tables[tool].get(args[key])


def _freeze(table: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Mapping[str, Any]]:
    return MappingProxyType({str(k): MappingProxyType(dict(v)) for k, v in table.items()})
