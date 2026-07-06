"""
GHOST v2 configuration.

Resolves the LLM backend and run settings from ``~/.beatrix/config.yaml``
(the ``ai:`` block) plus environment variables, and normalises the model
string into a LiteLLM ``provider/model`` identifier.

Because the agent runs through LiteLLM (via ``openai-agents[litellm]``), a
single ``ai.model`` string selects any provider::

    openai/gpt-4o
    anthropic/claude-3-7-sonnet-latest
    openrouter/anthropic/claude-3.7-sonnet     # issue #8
    gemini/gemini-2.0-pro
    bedrock/us.anthropic.claude-sonnet-4-20250514-v1:0
    ollama/llama3

API keys are read from the environment only (never persisted to
config.yaml), matching Beatrix's existing credential policy.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

CONFIG_PATH = Path.home() / ".beatrix" / "config.yaml"

# Env var that, when set, overrides ai.model outright (Strix uses STRIX_LLM).
_ENV_MODEL = "BEATRIX_LLM"
_ENV_API_KEY = "LLM_API_KEY"
_ENV_API_BASE = "LLM_API_BASE"
_ENV_REASONING = "BEATRIX_REASONING_EFFORT"
_ENV_SANDBOX = "BEATRIX_SANDBOX"
_ENV_SANDBOX_NETWORK = "BEATRIX_SANDBOX_NETWORK"
_ENV_MAX_TURNS = "BEATRIX_MAX_TURNS"
_ENV_MAX_BUDGET = "BEATRIX_MAX_BUDGET_USD"
_ENV_MAX_LLM_CALLS = "BEATRIX_MAX_LLM_CALLS"

# Fallback provider-native key env vars, tried in order when LLM_API_KEY is
# unset. LiteLLM also reads most of these itself, but resolving here lets us
# fail fast with a clear message and pass the key explicitly.
_PROVIDER_KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}

# Providers that authenticate out-of-band (IAM / local server) and therefore
# don't require an explicit API key.
_KEYLESS_PROVIDERS = {"bedrock", "ollama", "vertex_ai", "sagemaker"}

_VALID_REASONING = {"minimal", "low", "medium", "high"}
_VALID_SANDBOX = {"docker", "host", "auto"}
# Egress policy for the Docker sandbox container:
#   open — container has normal outbound network (needed to reach the target)
#   none — container is fully network-isolated (network_disabled); pure-Python
#          in-process scanners still reach the target, but in-container shells
#          and external binaries cannot phone anywhere.
# Host-scoped allowlisting (only the target hosts) needs a forced egress proxy
# and is tracked separately; "open"/"none" are the two policies enforceable
# with a cap-dropped, no-new-privileges container today.
_VALID_SANDBOX_NETWORK = {"open", "none"}


@dataclass
class GhostV2Config:
    """Resolved configuration for a GHOST v2 run."""

    # LiteLLM provider/model string. Defaults to the free OpenRouter model so a
    # fresh install runs with only an OPENROUTER_API_KEY; override via
    # ai.model in config.yaml, BEATRIX_LLM, or --model.
    model: str = "openrouter/nvidia/nemotron-3-ultra-550b-a55b:free"
    api_key: Optional[str] = None          # env-resolved; never from config.yaml
    api_base: Optional[str] = None
    reasoning_effort: Optional[str] = None  # minimal|low|medium|high or None
    sandbox: str = "auto"                   # docker|host|auto
    sandbox_image: Optional[str] = None     # docker image for the sandbox runtime
    sandbox_network: str = "open"           # open|none — Docker sandbox egress policy
    allow_host_exec: bool = False           # permit shell/python on the host runtime
    max_turns: int = 40
    # Spend guardrails (Strix parity): stop the whole run when the accumulated
    # LLM cost or call count crosses a limit, instead of only capping turns.
    # None => unlimited (turn budget still applies).
    max_budget_usd: Optional[float] = None
    max_llm_calls: Optional[int] = None
    temperature: Optional[float] = None     # None => provider default
    max_tokens: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    # ── Provider helpers ────────────────────────────────────────────────
    @property
    def provider(self) -> str:
        """The LiteLLM provider prefix (text before the first '/')."""
        return self.model.split("/", 1)[0] if "/" in self.model else ""

    def requires_api_key(self) -> bool:
        return self.provider not in _KEYLESS_PROVIDERS

    def missing_key_message(self) -> Optional[str]:
        """Return a human-readable hint if a needed API key is absent."""
        if self.api_key or not self.requires_api_key():
            return None
        provider = self.provider or "your provider"
        native = _PROVIDER_KEY_ENV.get(provider)
        hint = f"{_ENV_API_KEY}" + (f" (or {native})" if native else "")
        return (
            f"No API key found for provider '{provider}'. "
            f"Set {hint} in your environment."
        )

    # ── Construction ────────────────────────────────────────────────────
    @classmethod
    def load(
        cls,
        *,
        model: Optional[str] = None,
        api_base: Optional[str] = None,
        reasoning_effort: Optional[str] = None,
        sandbox: Optional[str] = None,
        allow_host_exec: Optional[bool] = None,
        max_turns: Optional[int] = None,
        config_path: Optional[Path] = None,
    ) -> "GhostV2Config":
        """Resolve config from CLI args > env vars > config.yaml > defaults."""
        ai = _read_ai_block(config_path or CONFIG_PATH)

        # Model: CLI > BEATRIX_LLM env > config.yaml (with legacy shim) > default
        resolved_model = (
            model
            or os.environ.get(_ENV_MODEL)
            or _normalise_model(ai)
            or cls.model
        )

        cfg = cls(
            model=resolved_model,
            api_base=(api_base or os.environ.get(_ENV_API_BASE) or ai.get("api_base")),
            reasoning_effort=_pick_reasoning(reasoning_effort, ai),
            sandbox=_pick_choice(
                sandbox or os.environ.get(_ENV_SANDBOX) or ai.get("sandbox"),
                _VALID_SANDBOX,
                cls.sandbox,
            ),
            sandbox_image=ai.get("sandbox_image"),
            sandbox_network=_pick_choice(
                os.environ.get(_ENV_SANDBOX_NETWORK) or ai.get("sandbox_network"),
                _VALID_SANDBOX_NETWORK,
                cls.sandbox_network,
            ),
            allow_host_exec=(
                allow_host_exec
                if allow_host_exec is not None
                else bool(ai.get("allow_host_exec", False))
            ),
            max_turns=_pick_int(
                max_turns, os.environ.get(_ENV_MAX_TURNS), ai.get("max_turns"), cls.max_turns
            ),
            max_budget_usd=_pick_float(
                os.environ.get(_ENV_MAX_BUDGET), ai.get("max_budget_usd")
            ),
            max_llm_calls=_pick_opt_int(
                os.environ.get(_ENV_MAX_LLM_CALLS), ai.get("max_llm_calls")
            ),
            temperature=ai.get("temperature"),
            max_tokens=ai.get("max_tokens"),
        )
        cfg.api_key = _resolve_api_key(cfg.provider)
        return cfg


# ── Internal helpers ────────────────────────────────────────────────────
def _read_ai_block(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception:
        return {}
    ai = data.get("ai", {})
    return ai if isinstance(ai, dict) else {}


def _normalise_model(ai: Dict[str, Any]) -> Optional[str]:
    """Turn a config.yaml ``ai:`` block into a LiteLLM model string.

    Handles the legacy Beatrix format (``ai.provider: bedrock`` +
    ``ai.model: claude-sonnet-4-...``) by prefixing the provider, so existing
    configs keep working after the LiteLLM migration.
    """
    model = ai.get("model")
    if not model:
        return None
    model = str(model)

    # Already a LiteLLM identifier (has a provider prefix) — use verbatim.
    if "/" in model:
        return model

    provider = str(ai.get("provider", "")).lower()
    if provider == "bedrock":
        # Bedrock ids may already be inference-profile form (us.anthropic...).
        if model.startswith(("us.", "eu.", "apac.", "anthropic.")):
            return f"bedrock/{model}"
        return f"bedrock/us.anthropic.{model}"
    if provider == "anthropic":
        return f"anthropic/{model}"
    if provider in ("openai", "gemini", "groq", "mistral", "openrouter", "ollama"):
        return f"{provider}/{model}"
    # Unknown/legacy provider with a bare model — hand to LiteLLM as-is and let
    # it error clearly rather than guessing.
    return model


def _resolve_api_key(provider: str) -> Optional[str]:
    if os.environ.get(_ENV_API_KEY):
        return os.environ[_ENV_API_KEY]
    env_name = _PROVIDER_KEY_ENV.get(provider)
    if env_name and os.environ.get(env_name):
        return os.environ[env_name]
    return None


def _pick_reasoning(cli: Optional[str], ai: Dict[str, Any]) -> Optional[str]:
    val = cli or os.environ.get(_ENV_REASONING) or ai.get("reasoning_effort")
    if not val:
        return None
    val = str(val).lower()
    return val if val in _VALID_REASONING else None


def _pick_choice(val: Optional[str], valid: set, default: str) -> str:
    if val and str(val).lower() in valid:
        return str(val).lower()
    return default


def _pick_int(*candidates: Any) -> int:
    for c in candidates[:-1]:
        if c is None:
            continue
        try:
            return int(c)
        except (TypeError, ValueError):
            continue
    return int(candidates[-1])


def _pick_opt_int(*candidates: Any) -> Optional[int]:
    """First candidate parseable as a positive int, else None (unlimited)."""
    for c in candidates:
        if c is None or c == "":
            continue
        try:
            val = int(c)
        except (TypeError, ValueError):
            continue
        if val > 0:
            return val
    return None


def _pick_float(*candidates: Any) -> Optional[float]:
    """First candidate parseable as a positive finite float, else None."""
    import math

    for c in candidates:
        if c is None or c == "":
            continue
        try:
            val = float(c)
        except (TypeError, ValueError):
            continue
        if math.isfinite(val) and val > 0:
            return val
    return None
