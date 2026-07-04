"""
Graph-of-agents tools.

The root orchestrator delegates focused tasks to role-scoped subagents with
``spawn_agent``. Each subagent runs its own openai-agents loop over the *same*
``GhostSession`` — so findings, notes, the HTTP response store, the OOB server
and scope are shared — and ends on its ``agent_finish`` tool, handing a report
back to the orchestrator. That shared session is how recon feeds exploitation
feeds validation.

(Concurrent message-passing between live subagents — Strix's
``message_agent`` / ``wait_for_message`` — is a later refinement; delegation
through the shared session is the coordination primitive here.)
"""

from __future__ import annotations

from agents import RunContextWrapper, function_tool

from ..core.session import GhostSession

VALID_ROLES = ("recon", "exploitation", "validation")

# A subagent gets its own turn budget, capped so one delegation can't consume
# an unbounded amount of the run.
_SUBAGENT_MAX_TURNS = 20


@function_tool
async def spawn_agent(ctx: RunContextWrapper[GhostSession], role: str, task: str) -> str:
    """Delegate a focused task to a specialized subagent and get its report back.

    The subagent shares your session (findings, notes, response store, OOB
    server, scope), so anything it discovers or records is visible to you and
    to later agents. Spawn them in order: recon → exploitation → validation.

    Args:
        role: One of "recon", "exploitation", "validation".
        task: A specific, self-contained task for the subagent to carry out.
    """
    session = ctx.context
    role = role.lower().strip()
    if role not in VALID_ROLES:
        return f"Unknown role '{role}'. Valid roles: {', '.join(VALID_ROLES)}."

    cfg = getattr(session, "cfg", None)
    if cfg is None:
        return "Cannot spawn subagents: run config is unavailable."

    from agents import Runner

    from ..agents.factory import build_subagent

    subagent = build_subagent(role, session.scope, cfg, runtime=session.runtime)
    session._emit("spawn_agent", role, task)

    budget = min(getattr(cfg, "max_turns", _SUBAGENT_MAX_TURNS), _SUBAGENT_MAX_TURNS)
    try:
        result = await Runner.run(
            subagent, task, context=session,
            max_turns=budget, hooks=getattr(session, "hooks", None),
        )
        report = getattr(result, "final_output", None)
    except Exception as e:  # noqa: BLE001 - surface subagent failures to the root
        return f"{role} subagent failed: {type(e).__name__}: {e}"

    return report or f"{role} subagent finished without an explicit report."


__all__ = ["spawn_agent", "VALID_ROLES"]
