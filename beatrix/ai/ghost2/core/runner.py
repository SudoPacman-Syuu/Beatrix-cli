"""
Run entry point for GHOST v2.

``run_investigation`` builds the session + root agent, drives the
openai-agents ``Runner`` loop, and persists whatever findings the agent
recorded into Beatrix's FindingsDB so they surface in ``beatrix findings``
and every existing reporter.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..config import GhostV2Config
from .session import GhostSession, Scope
from .hooks import GhostHooks


async def run_investigation(
    target: str,
    *,
    cfg: Optional[GhostV2Config] = None,
    objective: str = "Find and validate security vulnerabilities.",
    base_headers: Optional[Dict[str, str]] = None,
    base_cookies: Optional[Dict[str, str]] = None,
    console: Any = None,
    verbose: bool = False,
    persist: bool = True,
    on_event: Optional[Any] = None,
) -> Dict[str, Any]:
    """Run a full GHOST v2 investigation against ``target``.

    Returns a result dict with the recorded findings, the agent's final
    summary, and (if persisted) the FindingsDB hunt id.
    """
    cfg = cfg or GhostV2Config.load()

    # Fail fast with a clear message if the provider needs a key we don't have.
    key_hint = cfg.missing_key_message()
    if key_hint:
        raise RuntimeError(key_hint)

    from agents import Runner  # lazy: only when actually running an investigation

    # Disable openai-agents' OpenAI-bound trace export — it's irrelevant when
    # running through LiteLLM/OpenRouter and otherwise logs a warning per turn.
    try:
        from agents import set_tracing_disabled
        set_tracing_disabled(True)
    except Exception:
        pass

    from ..agents.factory import build_root_agent

    from ..runtime.dispatch import make_runtime

    scope = Scope(
        target=target,
        objective=objective,
        base_headers=base_headers or {},
        base_cookies=base_cookies or {},
    )
    runtime = make_runtime(cfg, console=console)
    hooks = GhostHooks(
        console=console,
        verbose=verbose,
        on_event=on_event,
        model=cfg.model,
        max_budget_usd=cfg.max_budget_usd,
        max_llm_calls=cfg.max_llm_calls,
    )
    session = GhostSession(scope, runtime=runtime)
    # Run-scoped services the graph tools and OOB tools read off the session.
    session.cfg = cfg
    session.hooks = hooks
    session.pocserver = await _start_pocserver()
    # A scan directory (matching `beatrix hunt`) so raw tool output and the
    # final findings land in the standard layout every reporter reads.
    session.output_manager = _start_output_manager(scope.target)
    agent = build_root_agent(scope, cfg, runtime=runtime)

    initial = (
        f"Begin your authorized security investigation of {target}.\n"
        f"Objective: {objective}\n"
        "Start by understanding the target, then test systematically. "
        "Delegate focused work to subagents with spawn_agent (recon → "
        "exploitation → validation) or probe directly. Record every confirmed "
        "finding with record_finding, and call finish_scan with a final "
        "summary when you are done."
    )

    from agents.exceptions import MaxTurnsExceeded

    from .hooks import BudgetExceededError

    final_output: Optional[str] = None
    hit_turn_limit = False
    hit_budget_limit = False
    budget_message: Optional[str] = None
    try:
        result = await Runner.run(
            agent, initial, context=session, max_turns=cfg.max_turns, hooks=hooks
        )
        final_output = getattr(result, "final_output", None)
    except MaxTurnsExceeded:
        # The agent ran out its turn budget without calling finish_scan.
        # Findings already live on the shared session, so still report/persist
        # them rather than losing the whole run.
        hit_turn_limit = True
    except BudgetExceededError as e:
        # Spend ceiling (cost or call count) hit. Same disposition as the turn
        # limit: stop now, but keep and report whatever was already found.
        hit_budget_limit = True
        budget_message = str(e)
    finally:
        # Tear down the sandbox container (no-op for the host runtime) and the
        # OOB server.
        aclose = getattr(runtime, "aclose", None)
        if aclose is not None:
            try:
                await aclose()
            except Exception:
                pass
        if session.pocserver is not None:
            try:
                await session.pocserver.stop()
            except Exception:
                pass

    findings = session.findings
    verdict = "VULNERABLE" if findings else "SECURE"

    # Enrich, write the scan dir, and persist to the FindingsDB — the same
    # finalize path a `beatrix hunt` uses, so all existing reporters work.
    from ..report.bridge import finalize_findings

    outcome = finalize_findings(session, persist=persist)

    return {
        "target": target,
        "objective": objective,
        "model": cfg.model,
        "verdict": verdict,
        "findings": findings,
        "num_findings": len(findings),
        "final_output": final_output,
        "hit_turn_limit": hit_turn_limit,
        "hit_budget_limit": hit_budget_limit,
        "budget_message": budget_message,
        "usage": hooks.usage_summary(),
        "modules_run": sorted(session.modules_run),
        "duration_secs": round(session.duration_secs, 1),
        "hunt_id": outcome["hunt_id"],
        "scan_dir": outcome["scan_dir"],
    }


async def _start_pocserver():
    """Start the OOB/PoC server for this run. Best-effort — returns None if the
    server can't start, and the OOB tools degrade gracefully."""
    try:
        from beatrix.core.poc_server import PoCServer

        server = PoCServer()
        await server.start()
        return server
    except Exception:
        return None


def _start_output_manager(target: str):
    """Create the run's scan-output directory. Best-effort — returns None if it
    can't be created, and the bridge falls back to a fresh one at finalize."""
    try:
        from beatrix.core.scan_output import ScanOutputManager

        return ScanOutputManager(target)
    except Exception:
        return None
