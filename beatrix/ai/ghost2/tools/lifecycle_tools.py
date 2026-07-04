"""
Lifecycle tools: how an agent declares it is done.

In Strix the run loop ends when a lifecycle tool reports success rather than
when a turn budget runs out. We mirror that with ``finish_scan``: the root
agent calls it once, passing a final summary, and the openai-agents
``tool_use_behavior`` (see ``core/stop.py``) stops the loop and returns that
summary as the run's ``final_output`` — so the agent controls termination and
we do not burn the whole ``max_turns`` budget on a target that is already
understood.

The child-agent equivalent (``agent_finish``) arrives with the agent graph in
M3; only the root agent exists in M1.
"""

from __future__ import annotations

from agents import function_tool

# Tool names the stop behaviors watch for. Kept as constants so factories and
# tools stay in sync. finish_scan ends the whole run (root); agent_finish ends
# a single subagent's sub-loop and hands its report back to the orchestrator.
FINISH_SCAN = "finish_scan"
AGENT_FINISH = "agent_finish"


@function_tool(name_override=FINISH_SCAN)
async def finish_scan(summary: str) -> str:
    """End the investigation. Call this exactly once, when you are done testing.

    Provide a concise final report: what you tested, what you confirmed (or
    that the target appears secure), and your confidence in each finding.
    Findings you already passed to record_finding are saved regardless.

    Args:
        summary: Your final investigation summary.
    """
    return summary


@function_tool(name_override=AGENT_FINISH)
async def agent_finish(report: str) -> str:
    """Finish your delegated task and hand a report back to the orchestrator.

    Call this once, when you have completed the task you were spawned for.
    Summarize what you did and what you found; anything you recorded with
    record_finding, or discovered and left in the shared notes, is already
    visible to the other agents.

    Args:
        report: A concise report of your results for the orchestrator.
    """
    return report


__all__ = ["finish_scan", "agent_finish", "FINISH_SCAN", "AGENT_FINISH"]
