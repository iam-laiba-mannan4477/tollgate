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


def _str(desc: str) -> dict[str, Any]:
    return {"type": "string", "description": desc}


_CENTS = {"type": "integer", "description": "Whole cents, more than 0. $15.00 is 1500."}
_REASON = _str("Short reason, 1 to 200 characters.")

# JSON-schema style argument specs a real model sees. Argument names match
# proposal._ARGS exactly (a test checks this). Pure data: no I/O here.
TOOL_SPECS: Mapping[str, Mapping[str, Any]] = MappingProxyType({
    "propose_payment": {
        "description": "PROPOSE a payment. A person or the Gate decides; this sends nothing.",
        "properties": {"amount_cents": _CENTS, "recipient": _str("Recipient account id."),
                       "reason": _REASON}},
    "propose_refund": {
        "description": "PROPOSE a refund of an earlier order. This refunds nothing by itself.",
        "properties": {"amount_cents": _CENTS, "customer": _str("Customer id."),
                       "refund_of": _str("Order id being refunded."),
                       "order_total_cents": {**_CENTS, "description": "Order total in cents."},
                       "reason": _REASON}},
    "propose_dispute_response": {
        "description": "PROPOSE accepting or contesting a dispute (SIMULATED).",
        "properties": {"amount_cents": _CENTS, "customer": _str("Customer id."),
                       "dispute_id": _str("Dispute id."),
                       "action": {"type": "string", "enum": ["accept", "contest"]},
                       "reason": _REASON}},
    "propose_subscription_change": {
        "description": "PROPOSE a plan price change or cancellation (SIMULATED).",
        "properties": {"amount_cents": {**_CENTS, "description": "New plan price in cents."},
                       "customer": _str("Customer id."),
                       "subscription_id": _str("Subscription id."),
                       "action": {"type": "string", "enum": ["change_plan", "cancel"]},
                       "reason": _REASON}},
    "lookup_order": {"description": "Read an order record (read-only).",
                     "properties": {"order_id": _str("Order id.")}},
    "lookup_customer": {"description": "Read a customer record (read-only).",
                        "properties": {"customer_id": _str("Customer id.")}},
})
