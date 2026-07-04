"""
LiteLLM-backed model construction for GHOST v2.

Replaces the hand-rolled ``AnthropicBackend`` / ``BedrockBackend`` in
``beatrix/ai/assistant.py`` (for the agent path) with a single
provider-agnostic model built on ``openai-agents[litellm]``. The
``provider/model`` prefix in ``cfg.model`` selects the backend, so OpenAI,
Anthropic, Gemini, Bedrock, OpenRouter and Ollama all work with no
per-provider code (closes issue #8).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .config import GhostV2Config


def make_model(cfg: GhostV2Config):
    """Build a ``LitellmModel`` from resolved config.

    Imported lazily so the base Beatrix install (without the ``[agent]``
    extra) never pays for openai-agents/litellm at import time.
    """
    try:
        from agents.extensions.models.litellm_model import LitellmModel
    except ImportError as e:  # pragma: no cover - install guard
        raise RuntimeError(
            "GHOST v2 requires the 'agent' extra. Install it with:\n"
            "    pip install 'beatrix-cli[agent]'\n"
            "(or: pip install 'openai-agents[litellm]')"
        ) from e

    # LiteLLM tolerates provider params that a given backend doesn't support
    # (e.g. reasoning_effort on a non-reasoning model) only if drop_params is
    # on; enable it so cross-provider runs degrade gracefully instead of 400ing.
    try:
        import litellm

        litellm.drop_params = True
    except Exception:
        pass

    return LitellmModel(model=cfg.model, base_url=cfg.api_base, api_key=cfg.api_key)


def make_model_settings(cfg: GhostV2Config):
    """Build ``ModelSettings`` carrying reasoning/temperature/token limits.

    Reasoning effort is passed through ``extra_args`` as LiteLLM's
    ``reasoning_effort`` kwarg, which maps to each provider's native
    reasoning control (and is dropped for providers that lack one, thanks to
    ``drop_params`` above).
    """
    from agents import ModelSettings

    extra_args: Dict[str, Any] = {}
    if cfg.reasoning_effort:
        extra_args["reasoning_effort"] = cfg.reasoning_effort

    kwargs: Dict[str, Any] = {}
    if cfg.temperature is not None:
        kwargs["temperature"] = cfg.temperature
    if cfg.max_tokens is not None:
        kwargs["max_tokens"] = cfg.max_tokens
    if extra_args:
        kwargs["extra_args"] = extra_args

    return ModelSettings(**kwargs)
