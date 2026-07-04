"""
Loop-termination behavior for GHOST v2 agents.

openai-agents runs an agent in a loop until the model produces a message with
no tool calls *or* ``tool_use_behavior`` says to stop. Strix stops when a
lifecycle tool reports success; we do the same by naming the lifecycle tools
in ``StopAtTools``. When one is called, the loop halts and that tool's return
value becomes the run's ``final_output``.

M1: only the root agent exists, so only ``finish_scan`` is a stop tool. M3
adds child agents whose ``agent_finish`` tool stops their own sub-loop.
"""

from __future__ import annotations

from ..tools.lifecycle_tools import AGENT_FINISH, FINISH_SCAN

# Lifecycle tools that end an agent's loop.
ROOT_STOP_TOOLS = [FINISH_SCAN]
CHILD_STOP_TOOLS = [AGENT_FINISH]


def root_stop_behavior():
    """Return the ``tool_use_behavior`` value for the root orchestrator agent."""
    from agents import StopAtTools

    return StopAtTools(stop_at_tool_names=list(ROOT_STOP_TOOLS))


def child_stop_behavior():
    """Return the ``tool_use_behavior`` for a spawned subagent's sub-loop."""
    from agents import StopAtTools

    return StopAtTools(stop_at_tool_names=list(CHILD_STOP_TOOLS))


__all__ = [
    "root_stop_behavior", "child_stop_behavior",
    "ROOT_STOP_TOOLS", "CHILD_STOP_TOOLS",
]
