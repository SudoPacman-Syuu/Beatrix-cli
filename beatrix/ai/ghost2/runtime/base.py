"""
Runtime protocol for GHOST v2 tool execution.

Shell / Python / external-binary execution runs through a ``Runtime`` so the
same tools work whether the run is sandboxed (Docker, M2's container driver) or
on the host (fallback when Docker is absent). Pure-Python scanners keep running
in-process regardless — only shell/python/external-binary execution is routed.

The protocol is deliberately small: ``exec`` (a shell command), ``python``
(a code string), ``write_file`` / ``read_file`` (move artifacts in and out).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable


class HostExecDenied(RuntimeError):
    """Raised when shell/python exec is attempted on a host runtime that has
    not been explicitly authorized (``--allow-host-exec`` / ``ai.allow_host_exec``).

    Executing attacker-influenced commands directly on the host is the largest
    new attack surface in GHOST v2, so it is refused by default outside the
    Docker sandbox.
    """


@dataclass
class ExecResult:
    """Outcome of a command or code execution."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def summarize(self, limit: int = 4000) -> str:
        """Render for the model: status line + (clipped) stdout/stderr."""
        head = (
            f"exit={self.exit_code}"
            + (" (timed out)" if self.timed_out else "")
        )
        out = (self.stdout or "").strip()
        err = (self.stderr or "").strip()
        if len(out) > limit:
            out = out[:limit] + f"\n… [{len(self.stdout) - limit} more chars]"
        if len(err) > limit:
            err = err[:limit] + f"\n… [{len(self.stderr) - limit} more chars]"
        parts = [head]
        if out:
            parts.append(f"stdout:\n{out}")
        if err:
            parts.append(f"stderr:\n{err}")
        return "\n".join(parts)


@runtime_checkable
class Runtime(Protocol):
    """Execution backend for shell/python/external tools."""

    #: Human-readable backend name ("host", "docker") for logs/UI.
    name: str

    #: Whether shell/python exec is permitted on this runtime.
    allows_exec: bool

    async def exec(self, command: str, *, timeout: int = 60, cwd: Optional[str] = None) -> ExecResult:
        """Run a shell command."""
        ...

    async def python(self, code: str, *, timeout: int = 60) -> ExecResult:
        """Run a Python snippet."""
        ...

    async def write_file(self, path: str, content: str) -> None:
        """Write a file into the runtime's filesystem."""
        ...

    async def read_file(self, path: str) -> str:
        """Read a file out of the runtime's filesystem."""
        ...
