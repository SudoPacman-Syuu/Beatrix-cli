"""
GHOST v2 — Strix-style autonomous pentesting agent for Beatrix.

Built on ``openai-agents[litellm]`` (provider-agnostic via LiteLLM), with
tools that drive Beatrix's existing arsenal (32 scanners, external tools,
findings DB). Requires the ``[agent]`` extra:

    pip install 'beatrix-cli[agent]'

Public surface:
    from beatrix.ai.ghost2 import run_investigation, GhostV2Config
"""

from __future__ import annotations

from .config import GhostV2Config

__all__ = ["GhostV2Config", "run_investigation"]


def run_investigation(*args, **kwargs):
    """Lazy proxy to :func:`core.runner.run_investigation`.

    Kept lazy so importing this package never pulls openai-agents unless a run
    actually starts (keeps ``import beatrix.ai`` cheap and dependency-free).
    """
    from .core.runner import run_investigation as _run

    return _run(*args, **kwargs)
