"""
Runtime selection for a GHOST v2 run.

``make_runtime(cfg)`` maps ``ai.sandbox`` to a concrete ``Runtime``:

* ``docker`` — the Docker sandbox (container driver lands with the sandbox
  image; until then this falls back to host with a warning);
* ``host``   — run on this machine (exec gated behind ``--allow-host-exec``);
* ``auto``   — Docker if the daemon is reachable, else host + a warning.

Kept separate from the runtimes themselves so the tool layer just asks the
session for ``session.runtime`` and never branches on the backend.
"""

from __future__ import annotations

from typing import Any, Optional

from ..config import GhostV2Config
from .base import Runtime
from .host_runtime import HostRuntime


def _docker_available() -> bool:
    """True if a Docker daemon is reachable. Never raises."""
    try:
        import docker  # type: ignore
    except Exception:
        return False
    try:
        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        return False


def make_runtime(cfg: GhostV2Config, *, console: Any = None) -> Runtime:
    """Build the runtime for this run based on ``cfg.sandbox``."""
    mode = cfg.sandbox
    allow_host_exec = bool(getattr(cfg, "allow_host_exec", False))

    def _warn(msg: str) -> None:
        if console is not None:
            console.print(f"[yellow]{msg}[/yellow]")

    if mode in ("docker", "auto"):
        if _docker_available():
            try:
                from .sandbox import DockerRuntime  # optional, lands with the image

                return DockerRuntime(cfg)
            except Exception as e:  # container driver not present yet / build missing
                if mode == "docker":
                    _warn(
                        f"Docker requested but the sandbox driver is unavailable ({e}); "
                        "falling back to the host runtime."
                    )
                else:
                    _warn(f"Docker sandbox unavailable ({e}); using the host runtime.")
        elif mode == "docker":
            _warn(
                "Docker requested but no reachable daemon; falling back to the host "
                "runtime. Shell/Python exec stays disabled unless --allow-host-exec."
            )
        else:  # auto, no docker
            _warn("No Docker daemon; using the host runtime.")

    if not allow_host_exec:
        # Informational: exec tools will refuse until explicitly allowed.
        _warn(
            "Host runtime active — shell/python_exec are disabled. "
            "Pass --allow-host-exec to enable them on this machine."
        )
    return HostRuntime(allow_exec=allow_host_exec)
