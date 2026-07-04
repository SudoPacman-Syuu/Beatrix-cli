"""
Execution tools: shell and python_exec.

These run through the session's ``Runtime`` (Docker sandbox when available,
host otherwise). On the host runtime they are refused unless the operator
passed ``--allow-host-exec`` — running attacker-influenced commands directly on
the host is the largest new attack surface, so it is opt-in (see
``runtime.base.HostExecDenied``).
"""

from __future__ import annotations

from agents import RunContextWrapper, function_tool

from ..core.session import GhostSession
from ..runtime.base import HostExecDenied


def _runtime(session: GhostSession):
    rt = getattr(session, "runtime", None)
    if rt is None:
        raise RuntimeError("no execution runtime is attached to this run")
    return rt


@function_tool
async def shell(ctx: RunContextWrapper[GhostSession], command: str, timeout: int = 60) -> str:
    """Run a shell command in the run's sandbox and return its output.

    Use for external tooling and quick checks (curl, dig, jq, nuclei, ...).
    Runs in the Docker sandbox when available; on the host runtime it is
    disabled unless the run was started with --allow-host-exec.

    Args:
        command: The shell command to run.
        timeout: Max seconds to allow before the command is killed.
    """
    try:
        result = await _runtime(ctx.context).exec(command, timeout=timeout)
    except HostExecDenied as e:
        return f"Refused: {e}"
    return result.summarize()


@function_tool
async def python_exec(ctx: RunContextWrapper[GhostSession], code: str, timeout: int = 60) -> str:
    """Run a Python snippet in the run's sandbox and return stdout/stderr.

    Use for building/validating PoCs and computations that HTTP tools can't do.
    Runs in the Docker sandbox when available; on the host runtime it is
    disabled unless the run was started with --allow-host-exec.

    Args:
        code: Python source to execute. print() what you want to see.
        timeout: Max seconds to allow before execution is killed.
    """
    try:
        result = await _runtime(ctx.context).python(code, timeout=timeout)
    except HostExecDenied as e:
        return f"Refused: {e}"
    return result.summarize()


__all__ = ["shell", "python_exec"]
