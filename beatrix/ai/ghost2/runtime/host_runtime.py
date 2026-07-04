"""
Host runtime — runs commands/code directly on the machine GHOST v2 runs on.

Used when Docker is unavailable or ``ai.sandbox: host`` is set. Because this is
the machine itself, shell/python execution is **refused by default**: the caller
must opt in with ``--allow-host-exec`` (``allow_exec=True``). File I/O and the
protocol surface still work so the Docker driver (M2) can share tool code.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional

from .base import ExecResult, HostExecDenied


class HostRuntime:
    """Execute on the host. Exec gated behind ``allow_exec``."""

    name = "host"

    def __init__(self, allow_exec: bool = False, workdir: Optional[str] = None):
        self.allows_exec = allow_exec
        self.workdir = workdir or tempfile.mkdtemp(prefix="ghost2-host-")

    def _guard(self, what: str) -> None:
        if not self.allows_exec:
            raise HostExecDenied(
                f"{what} is disabled on the host runtime. GHOST v2 refuses to run "
                "shell/Python on the host by default. Re-run with a Docker sandbox "
                "(default when Docker is available) or pass --allow-host-exec to "
                "accept the risk of executing on this machine."
            )

    async def exec(self, command: str, *, timeout: int = 60, cwd: Optional[str] = None) -> ExecResult:
        self._guard("shell execution")
        return await _run_subprocess(
            ["/bin/sh", "-c", command], timeout=timeout, cwd=cwd or self.workdir
        )

    async def python(self, code: str, *, timeout: int = 60) -> ExecResult:
        self._guard("python execution")
        # Run via a temp file so multi-line snippets and quoting behave.
        path = Path(self.workdir) / f"_snippet_{os.getpid()}_{id(code)}.py"
        path.write_text(code)
        try:
            return await _run_subprocess(
                [sys.executable, str(path)], timeout=timeout, cwd=self.workdir
            )
        finally:
            path.unlink(missing_ok=True)

    async def write_file(self, path: str, content: str) -> None:
        p = self._resolve(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    async def read_file(self, path: str) -> str:
        return self._resolve(path).read_text()

    def _resolve(self, path: str) -> Path:
        p = Path(path)
        return p if p.is_absolute() else Path(self.workdir) / p


async def _run_subprocess(argv, *, timeout: int, cwd: Optional[str]) -> ExecResult:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return ExecResult(exit_code=-1, stdout="", stderr=f"timed out after {timeout}s", timed_out=True)
    return ExecResult(
        exit_code=proc.returncode if proc.returncode is not None else -1,
        stdout=out.decode(errors="replace"),
        stderr=err.decode(errors="replace"),
    )
