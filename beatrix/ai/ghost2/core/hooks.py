"""
Lifecycle hooks that bridge openai-agents run events to a Rich console.

``Runner.run(..., hooks=GhostHooks(...))`` calls these on every tool
invocation, agent start/stop, and LLM round-trip. We surface the same kind
of live, emoji-tagged output the legacy ``PrintCallback`` produced so the
CLI experience is familiar.
"""

from __future__ import annotations

from typing import Any

from agents import RunContextWrapper, RunHooks


class GhostHooks(RunHooks):
    """Streams agent activity to a Rich console (or any console-like object)."""

    def __init__(self, console: Any = None, verbose: bool = False):
        self.console = console
        self.verbose = verbose

    def _log(self, markup: str) -> None:
        if self.console is not None:
            self.console.print(markup)
        else:  # pragma: no cover - fallback when no Rich console supplied
            print(markup)

    async def on_agent_start(self, context: RunContextWrapper, agent) -> None:
        self._log(f"[bold cyan]▶ {agent.name}[/bold cyan] engaged")

    async def on_agent_end(self, context: RunContextWrapper, agent, output) -> None:
        self._log(f"[dim]■ {agent.name} finished[/dim]")

    async def on_tool_start(self, context: RunContextWrapper, agent, tool) -> None:
        self._log(f"[yellow]🔧 {tool.name}[/yellow]")

    async def on_tool_end(self, context: RunContextWrapper, agent, tool, result) -> None:
        if self.verbose:
            preview = str(result).replace("\n", " ")
            if len(preview) > 200:
                preview = preview[:200] + "…"
            self._log(f"[dim]   ↳ {preview}[/dim]")

    async def on_llm_start(self, context: RunContextWrapper, agent, system_prompt, input_items) -> None:
        if self.verbose:
            self._log("[dim]🧠 thinking…[/dim]")

    async def on_llm_end(self, context: RunContextWrapper, agent, response) -> None:
        pass
