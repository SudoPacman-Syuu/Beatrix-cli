"""
Agent construction for GHOST v2.

``build_root_agent`` assembles the root orchestrator; ``build_subagent`` builds
the role-scoped recon / exploitation / validation agents the root delegates to
(all over the same session). Each is a plain openai-agents ``Agent`` with a
LiteLLM model, role-scoped tools, reasoning settings, and a stop behavior.
"""

from __future__ import annotations

from ..config import GhostV2Config
from ..core.session import Scope
from ..core.stop import child_stop_behavior, root_stop_behavior
from ..provider import make_model, make_model_settings
from ..tools import collect_tools
from .prompts import exploitation as exploitation_prompt
from .prompts import recon as recon_prompt
from .prompts import root as root_prompt
from .prompts import validation as validation_prompt

_SUBAGENT_PROMPTS = {
    "recon": recon_prompt,
    "exploitation": exploitation_prompt,
    "validation": validation_prompt,
}


def build_root_agent(scope: Scope, cfg: GhostV2Config, runtime=None):
    """Build the root orchestrator agent.

    ``runtime`` is the run's execution backend; its ``allows_exec`` decides
    whether the sandbox exec tools (shell/python_exec) are offered.
    """
    from agents import Agent

    allow_exec = bool(getattr(runtime, "allows_exec", False))

    return Agent(
        name="GHOST",
        instructions=root_prompt.render(scope),
        model=make_model(cfg),
        model_settings=make_model_settings(cfg),
        tools=collect_tools("root", allow_exec=allow_exec),
        # End the loop when the agent calls finish_scan (its returned summary
        # becomes final_output), instead of always exhausting max_turns.
        tool_use_behavior=root_stop_behavior(),
    )


def build_subagent(role: str, scope: Scope, cfg: GhostV2Config, runtime=None):
    """Build a role-scoped subagent (recon / exploitation / validation).

    Raises ``ValueError`` for an unknown role. Shares the run's session at
    invocation time (passed as ``Runner.run(context=session)``); ends its
    sub-loop on ``agent_finish``.
    """
    from agents import Agent

    role = role.lower().strip()
    prompt = _SUBAGENT_PROMPTS.get(role)
    if prompt is None:
        raise ValueError(f"unknown subagent role: {role!r}")

    allow_exec = bool(getattr(runtime, "allows_exec", False))

    return Agent(
        name=f"GHOST.{role}",
        instructions=prompt.render(scope),
        model=make_model(cfg),
        model_settings=make_model_settings(cfg),
        tools=collect_tools(role, allow_exec=allow_exec),
        tool_use_behavior=child_stop_behavior(),
    )
