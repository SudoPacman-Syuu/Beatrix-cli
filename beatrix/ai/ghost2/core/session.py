"""
Shared run state for a GHOST v2 investigation.

One ``GhostSession`` is created per run and passed as the openai-agents
run *context* (``Runner.run(..., context=session)``), so every tool — and,
once the agent graph lands, every subagent — reads and mutates the same
findings buffer, HTTP response store, notes, and scope. All mutating
accessors take a lock so concurrent subagents (M3) stay consistent.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from beatrix.core.types import Finding


@dataclass
class StoredResponse:
    """A cached HTTP response the agent can refer back to by id."""

    id: int
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time_ms: int
    url: str
    method: str


@dataclass
class Scope:
    """Target and rules of engagement for a run."""

    target: str
    objective: str = "Find and validate security vulnerabilities."
    # Hosts the agent is permitted to touch. Empty => derived from target host.
    allowed_hosts: List[str] = field(default_factory=list)
    base_headers: Dict[str, str] = field(default_factory=dict)
    base_cookies: Dict[str, str] = field(default_factory=dict)

    def host(self) -> str:
        from urllib.parse import urlparse

        netloc = urlparse(self.target if "://" in self.target else f"//{self.target}").netloc
        return netloc.split("@")[-1].split(":")[0]

    def in_scope(self, target: str) -> bool:
        """True if ``target`` (a URL or host) is within the authorized scope.

        A host is in scope when it equals, or is a subdomain of, the target host
        or any entry in ``allowed_hosts``. Used to keep noisy external tools
        from spraying traffic outside the engagement.
        """
        from urllib.parse import urlparse

        raw = target.strip()
        netloc = urlparse(raw if "://" in raw else f"//{raw}").netloc
        host = netloc.split("@")[-1].split(":")[0].lower()
        if not host:
            return False
        allowed = [h.lower() for h in (self.allowed_hosts or [self.host()])]
        return any(host == a or host.endswith("." + a) for a in allowed)


class GhostSession:
    """Mutable state shared across an investigation and its subagents."""

    def __init__(self, scope: Scope, callback: Optional[Any] = None, runtime: Optional[Any] = None):
        self.scope = scope
        self.callback = callback  # optional GhostCallback-style UI bridge
        # Execution backend for shell/python/external tools (host or Docker).
        # Attached by the runner; may be None in unit tests that never exec.
        self.runtime = runtime
        # Run-scoped services attached by the runner (M3): the resolved config,
        # lifecycle hooks (so spawned subagents stream to the same UI), and the
        # PoCServer used as the out-of-band validation channel. All optional so
        # unit tests can construct a bare session.
        self.cfg: Optional[Any] = None
        self.hooks: Optional[Any] = None
        self.pocserver: Optional[Any] = None
        # ScanOutputManager for this run's scan directory (raw tool output +
        # final findings), attached by the runner. Optional in unit tests.
        self.output_manager: Optional[Any] = None
        self.started_at = datetime.now()

        # HTTP response store (referenced by integer id in tool output)
        self._responses: Dict[int, StoredResponse] = {}
        self._response_counter = 0

        # Findings buffer (persisted to FindingsDB at finalize)
        self.findings: List[Finding] = []

        # Agent scratch state
        self.notes: List[str] = []
        self.todos: List[Dict[str, Any]] = []  # {id, text, done}
        self._todo_counter = 0

        # Which arsenal modules/tools the run actually exercised (for the DB)
        self.modules_run: set[str] = set()

        self._lock = asyncio.Lock()

    # ── HTTP responses ──────────────────────────────────────────────────
    async def store_response(
        self,
        *,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        response_time_ms: int,
        url: str,
        method: str,
    ) -> StoredResponse:
        async with self._lock:
            self._response_counter += 1
            rid = self._response_counter
            resp = StoredResponse(
                id=rid,
                status_code=status_code,
                headers=headers,
                body=body,
                response_time_ms=response_time_ms,
                url=url,
                method=method,
            )
            self._responses[rid] = resp
        self._emit("stored_response", str(rid), status_code)
        return resp

    def get_response(self, rid: int) -> Optional[StoredResponse]:
        return self._responses.get(rid)

    def latest_response(self) -> Optional[StoredResponse]:
        if not self._responses:
            return None
        return self._responses[max(self._responses)]

    # ── Findings ────────────────────────────────────────────────────────
    async def add_finding(self, finding: Finding) -> None:
        async with self._lock:
            self.findings.append(finding)
        self._emit("finding", finding.title, finding.severity.value)

    # ── Scratch state ───────────────────────────────────────────────────
    async def add_note(self, text: str) -> None:
        async with self._lock:
            self.notes.append(text)

    async def add_todo(self, text: str) -> int:
        async with self._lock:
            self._todo_counter += 1
            tid = self._todo_counter
            self.todos.append({"id": tid, "text": text, "done": False})
        return tid

    async def complete_todo(self, tid: int) -> bool:
        async with self._lock:
            for t in self.todos:
                if t["id"] == tid:
                    t["done"] = True
                    return True
        return False

    def record_module(self, name: str) -> None:
        self.modules_run.add(name)

    # ── UI bridge ───────────────────────────────────────────────────────
    def _emit(self, event: str, *args: Any) -> None:
        cb = self.callback
        if cb is None:
            return
        handler = getattr(cb, f"on_{event}", None)
        if callable(handler):
            try:
                handler(*args)
            except Exception:
                pass

    @property
    def duration_secs(self) -> float:
        return (datetime.now() - self.started_at).total_seconds()
