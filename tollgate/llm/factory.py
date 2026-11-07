"""Pick the agent's model from TOLLGATE_AGENT_MODEL_PROVIDER = scripted | groq | claude.

Default is scripted (offline, no key). Any other value is an error (fail closed).
Keys come only from GROQ_API_KEY / ANTHROPIC_API_KEY; error messages name the
variable, never its value. The model name comes from TOLLGATE_AGENT_MODEL.
"""
from __future__ import annotations

import os
from typing import Any, Mapping, Sequence

from tollgate.agent.model import ModelAdapter, ScriptedModel, ToolCall
from tollgate.config import ConfigError
from tollgate.llm.providers import ClaudeModel, OpenAICompatModel

PROVIDERS = ("scripted", "groq", "claude")
DEFAULT_GROQ_BASE_URL = "https://api.groq.com/openai/v1"
KEY_VARS = {"groq": "GROQ_API_KEY", "claude": "ANTHROPIC_API_KEY"}


def get_provider(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    raw = env.get("TOLLGATE_AGENT_MODEL_PROVIDER", "scripted").strip().lower()
    if raw not in PROVIDERS:
        raise ConfigError(f"TOLLGATE_AGENT_MODEL_PROVIDER must be one of {PROVIDERS} "
                          f"(got {raw[:20]!r})")
    return raw


def build_model(scripts: Mapping[str, Sequence[ToolCall]] | None = None, *,
                env: Mapping[str, str] | None = None, facts: str = "",
                **provider_kw: Any) -> ModelAdapter:
    """Return the configured model. `provider_kw` (client, sleep, retry) is for tests."""
    env = os.environ if env is None else env
    provider = get_provider(env)
    if provider == "scripted":
        return ScriptedModel(scripts or {})
    key = env.get(KEY_VARS[provider], "").strip()
    if not key:
        raise ConfigError(f"{KEY_VARS[provider]} is not set")
    model = env.get("TOLLGATE_AGENT_MODEL", "").strip()
    if not model:
        raise ConfigError("TOLLGATE_AGENT_MODEL is not set (no default model name)")
    if provider == "groq":
        base = env.get("TOLLGATE_AGENT_MODEL_BASE_URL", "").strip() or DEFAULT_GROQ_BASE_URL
        if not base.startswith("https://"):
            raise ConfigError("TOLLGATE_AGENT_MODEL_BASE_URL must start with https://")
        return OpenAICompatModel(base_url=base, api_key=key, model=model, facts=facts,
                                 **provider_kw)
    return ClaudeModel(api_key=key, model=model, facts=facts, **provider_kw)
