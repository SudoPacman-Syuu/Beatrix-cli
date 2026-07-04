"""GHOST v2 runtime (Docker sandbox / host fallback) — M2.

``make_runtime(cfg)`` picks the execution backend; tools use it via
``session.runtime`` and never branch on the concrete backend.
"""

from __future__ import annotations

from .base import ExecResult, HostExecDenied, Runtime
from .dispatch import make_runtime
from .host_runtime import HostRuntime
from .sandbox import DockerRuntime  # safe: imports the docker SDK lazily in __init__

__all__ = [
    "ExecResult", "HostExecDenied", "Runtime",
    "HostRuntime", "DockerRuntime", "make_runtime",
]
