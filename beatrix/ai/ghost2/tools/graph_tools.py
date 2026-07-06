"""
Graph-of-agents tools.

The root orchestrator delegates focused tasks to role-scoped subagents. Each
subagent runs its own openai-agents loop over the *same* ``GhostSession`` — so
findings, notes, the HTTP response store, the OOB server and scope are shared —
and ends on its ``agent_finish`` tool, handing a report back to the
orchestrator. That shared session is how recon feeds exploitation feeds
validation.

Two delegation primitives:

* ``spawn_agent(role, task)`` — run one subagent and get its report back. Use
  when the next step depends on the previous one (recon → exploitation →
  validation).
* ``spawn_agents([...])`` — run several subagents *concurrently* with
  ``asyncio.gather`` and get all their reports back. Use for independent work
  that has no ordering dependency (e.g. probing several hosts/surfaces at once).
  The shared ``GhostSession`` serialises its own mutations under a lock, so
  concurrent subagents stay consistent.

(Live message-passing between still-running subagents — Strix's
``message_agent`` / ``wait_for_message`` — remains a later refinement; these two
primitives cover ordered and fan-out delegation.)
"""

from __future__ import annotations

import asyncio
from typing import List

from agents import RunContextWrapper, function_tool

from ..core.session import GhostSession

VALID_ROLES = ("recon", "exploitation", "validation")

# A subagent gets its own turn budget, capped so one delegation can't consume
# an unbounded amount of the run.
_SUBAGENT_MAX_TURNS = 20

# Cap on how many subagents one spawn_agents call fans out, so a single tool
# call can't launch an unbounded number of concurrent model loops.
_MAX_PARALLEL_AGENTS = 5


async def _run_subagent(session: GhostSession, role: str, task: str) -> str:
    """Build and run one role-scoped subagent over the shared session.

    Returns the subagent's report (or a readable error string). Control-flow
    exceptions that must stop the *whole* run — the budget circuit-breaker and
    task cancellation — are re-raised rather than swallowed, so a limit hit
    inside a subagent still tears the run down.
    """
    role = role.lower().strip()
    if role not in VALID_ROLES:
        return f"Unknown role '{role}'. Valid roles: {', '.join(VALID_ROLES)}."

    cfg = getattr(session, "cfg", None)
    if cfg is None:
        return "Cannot spawn subagents: run config is unavailable."

    from agents import Runner

    from ..agents.factory import build_subagent
    from ..core.hooks import BudgetExceededError

    subagent = build_subagent(role, session.scope, cfg, runtime=session.runtime)
    session._emit("spawn_agent", role, task)

    budget = min(getattr(cfg, "max_turns", _SUBAGENT_MAX_TURNS), _SUBAGENT_MAX_TURNS)
    try:
        result = await Runner.run(
            subagent, task, context=session,
            max_turns=budget, hooks=getattr(session, "hooks", None),
        )
        report = getattr(result, "final_output", None)
    except (BudgetExceededError, asyncio.CancelledError):
        # Run-wide stop conditions must propagate, not be reported as a
        # per-subagent failure the orchestrator can shrug off.
        raise
    except Exception as e:  # noqa: BLE001 - surface subagent failures to the root
        return f"{role} subagent failed: {type(e).__name__}: {e}"

    return report or f"{role} subagent finished without an explicit report."


# failure_error_function=None: let exceptions propagate out of the tool boundary
# instead of being stringified back to the model. _run_subagent only ever
# re-raises run-wide stops (budget breaker / cancellation), so this is how a
# limit hit inside a subagent actually tears the whole run down.
@function_tool(failure_error_function=None)
async def spawn_agent(ctx: RunContextWrapper[GhostSession], role: str, task: str) -> str:
    """Delegate a focused task to a specialized subagent and get its report back.

    Runs one subagent to completion, then returns its report. Use this when the
    next step depends on what this one finds; for independent work you want to
    run at the same time, use ``spawn_agents``.

    The subagent shares your session (findings, notes, response store, OOB
    server, scope), so anything it discovers or records is visible to you and
    to later agents.

    Args:
        role: One of "recon", "exploitation", "validation".
        task: A specific, self-contained task for the subagent to carry out.
    """
    return await _run_subagent(ctx.context, role, task)


@function_tool(failure_error_function=None)  # propagate run-wide stops; see spawn_agent
async def spawn_agents(
    ctx: RunContextWrapper[GhostSession], roles: List[str], tasks: List[str]
) -> str:
    """Delegate several independent tasks to subagents that run **concurrently**.

    ``roles[i]`` is given ``tasks[i]``; the two lists must be the same length.
    All subagents run in parallel over the shared session and their reports are
    returned together, labeled by index. Use this to fan out independent work
    (e.g. recon on several hosts at once) instead of spawning one at a time.
    For ordered, dependent steps use ``spawn_agent``.

    Args:
        roles: Role per task — each one of "recon", "exploitation", "validation".
        tasks: Task per role; ``tasks[i]`` is handed to ``roles[i]``.
    """
    session = ctx.context
    if len(roles) != len(tasks):
        return (
            f"roles and tasks must be the same length "
            f"(got {len(roles)} roles, {len(tasks)} tasks)."
        )
    if not tasks:
        return "No tasks to delegate."
    if len(tasks) > _MAX_PARALLEL_AGENTS:
        return (
            f"Too many parallel subagents ({len(tasks)}); "
            f"cap is {_MAX_PARALLEL_AGENTS}. Split into batches or use spawn_agent."
        )

    results = await asyncio.gather(
        *(_run_subagent(session, role, task) for role, task in zip(roles, tasks)),
        return_exceptions=True,
    )

    # Re-raise a run-wide stop if any branch hit one (gather captured it because
    # of return_exceptions=True); it takes precedence over the other reports.
    from ..core.hooks import BudgetExceededError

    for r in results:
        if isinstance(r, (BudgetExceededError, asyncio.CancelledError)):
            raise r

    lines = []
    for i, (role, r) in enumerate(zip(roles, results), start=1):
        if isinstance(r, Exception):
            lines.append(f"[{i}] {role}: failed — {type(r).__name__}: {r}")
        else:
            lines.append(f"[{i}] {role}:\n{r}")
    return "\n\n".join(lines)


__all__ = ["spawn_agent", "spawn_agents", "VALID_ROLES"]
