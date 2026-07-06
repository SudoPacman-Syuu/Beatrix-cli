"""
Lifecycle hooks that bridge openai-agents run events to a Rich console.

``Runner.run(..., hooks=GhostHooks(...))`` calls these on every tool
invocation, agent start/stop, and LLM round-trip. We surface the same kind
of live, emoji-tagged output the legacy ``PrintCallback`` produced so the
CLI experience is familiar.

An optional ``on_event`` sink receives the same activity as structured dicts
``{"type", "text", "detail"}`` — used by the live web dashboard
(``beatrix ghost2 --web``) so a browser tab can mirror everything the agent does.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from agents import RunContextWrapper, RunHooks


class BudgetExceededError(RuntimeError):
    """Raised when a run crosses its configured LLM spend/call ceiling.

    ``run_investigation`` catches this like ``MaxTurnsExceeded``: the run stops
    cleanly and whatever findings already live on the session are still
    reported and persisted, rather than the spend continuing unbounded.
    """


class GhostHooks(RunHooks):
    """Streams agent activity to a Rich console and/or a structured event sink.

    Also meters LLM usage across the whole run — the root agent *and* every
    subagent share one ``GhostHooks`` instance (see ``graph_tools.spawn_agent``),
    so token/cost accumulation and the budget circuit-breaker span the entire
    agent graph, not a single loop.
    """

    def __init__(
        self,
        console: Any = None,
        verbose: bool = False,
        on_event: Optional[Callable[[dict], None]] = None,
        *,
        model: Optional[str] = None,
        max_budget_usd: Optional[float] = None,
        max_llm_calls: Optional[int] = None,
    ):
        self.console = console
        self.verbose = verbose
        self.on_event = on_event
        self._last_system: Optional[str] = None  # emit a system prompt only when it changes

        # Usage metering / spend guardrails.
        self.model = model
        self.max_budget_usd = max_budget_usd
        self.max_llm_calls = max_llm_calls
        self.llm_calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.cost_usd = 0.0

    def _log(self, markup: str) -> None:
        if self.console is not None:
            self.console.print(markup)
        else:  # pragma: no cover - fallback when no Rich console supplied
            print(markup)

    def _emit(self, etype: str, text: str, detail: str = "") -> None:
        """Push a structured event to the sink (never lets a sink error break a run)."""
        if self.on_event is not None:
            try:
                self.on_event({"type": etype, "text": text, "detail": detail})
            except Exception:
                pass

    @staticmethod
    def _preview(value: Any, limit: int = 4000) -> str:
        s = str(value)
        return s if len(s) <= limit else s[:limit] + "…"

    @classmethod
    def _content_text(cls, content: Any) -> str:
        """Flatten a message's content (str | list of parts | object) to text."""
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for p in content:
                if isinstance(p, dict):
                    parts.append(p.get("text") or p.get("content") or p.get("output") or "")
                else:
                    parts.append(getattr(p, "text", None) or str(p))
            return " ".join(x for x in parts if x)
        return str(content)

    @classmethod
    def _fmt_item(cls, item: Any) -> str:
        """Render one input message as ``role: text``, best-effort."""
        if isinstance(item, dict):
            role = item.get("role") or item.get("type") or "item"
            if "content" in item:
                return f"{role}: {cls._content_text(item.get('content'))}"
            # tool call / output items carry other keys
            return f"{role}: {cls._content_text(item.get('output') or item)}"
        role = getattr(item, "role", None) or getattr(item, "type", None) or "item"
        content = getattr(item, "content", None)
        return f"{role}: {cls._content_text(content) if content is not None else str(item)}"

    @classmethod
    def _serialize_response(cls, response: Any) -> str:
        """Pull the model's own text (its reasoning) out of a ModelResponse."""
        out = getattr(response, "output", None)
        if out is None and isinstance(response, dict):
            out = response.get("output")
        if not out:
            return cls._content_text(getattr(response, "content", None)) or ""
        chunks = []
        for item in out:
            itype = (item.get("type") if isinstance(item, dict) else getattr(item, "type", None)) or ""
            if "function" in str(itype) or "tool" in str(itype):
                name = (item.get("name") if isinstance(item, dict) else getattr(item, "name", None)) or "tool"
                chunks.append(f"→ calls {name}")
            else:
                content = item.get("content") if isinstance(item, dict) else getattr(item, "content", None)
                text = cls._content_text(content)
                if text:
                    chunks.append(text)
        return "\n".join(chunks)

    async def on_agent_start(self, context: RunContextWrapper, agent) -> None:
        self._log(f"[bold cyan]▶ {agent.name}[/bold cyan] engaged")
        self._emit("agent_start", f"{agent.name} engaged")

    async def on_agent_end(self, context: RunContextWrapper, agent, output) -> None:
        self._log(f"[dim]■ {agent.name} finished[/dim]")
        self._emit("agent_end", f"{agent.name} finished", self._preview(output))

    async def on_tool_start(self, context: RunContextWrapper, agent, tool) -> None:
        self._log(f"[yellow]🔧 {tool.name}[/yellow]")
        self._emit("tool_start", tool.name)

    async def on_tool_end(self, context: RunContextWrapper, agent, tool, result) -> None:
        preview = self._preview(result)
        if self.verbose:
            one_line = preview.replace("\n", " ")
            if len(one_line) > 200:
                one_line = one_line[:200] + "…"
            self._log(f"[dim]   ↳ {one_line}[/dim]")
        # The web dashboard always gets the fuller result, regardless of --verbose.
        self._emit("tool_end", tool.name, preview)

    async def on_llm_start(self, context: RunContextWrapper, agent, system_prompt, input_items) -> None:
        if self.verbose:
            self._log("[dim]🧠 thinking…[/dim]")
        self._emit("thinking", "thinking…")

        # Surface the agent's system prompt once (and again only if it changes,
        # e.g. when a differently-scoped subagent takes over).
        if system_prompt and system_prompt != self._last_system:
            self._last_system = system_prompt
            self._emit("system_prompt", f"{getattr(agent, 'name', 'agent')} — system prompt",
                       self._preview(system_prompt, 8000))

        # Show what this turn is actually prompted with: the newest input plus
        # how much context is being carried, so the browser mirrors the LLM input.
        items = list(input_items or [])
        if items:
            newest = "\n".join(self._fmt_item(it) for it in items[-2:])
            self._emit("prompt", f"prompt · {len(items)} context item(s)",
                       self._preview(newest, 6000))

    async def on_llm_end(self, context: RunContextWrapper, agent, response) -> None:
        text = self._serialize_response(response)
        if text:
            self._emit("reasoning", "model reasoning", self._preview(text, 6000))
        self._meter_usage(response)

    # ── usage metering / budget ─────────────────────────────────────────
    def _meter_usage(self, response: Any) -> None:
        """Accumulate token/cost usage and enforce the run's spend ceiling.

        Raises ``BudgetExceededError`` once the accumulated cost or call count
        crosses a configured limit; the SDK propagates it out of ``Runner.run``,
        which ``run_investigation`` handles like a turn-limit stop.
        """
        usage = getattr(response, "usage", None)
        self.llm_calls += 1
        in_tok = int(getattr(usage, "input_tokens", 0) or 0) if usage else 0
        out_tok = int(getattr(usage, "output_tokens", 0) or 0) if usage else 0
        self.input_tokens += in_tok
        self.output_tokens += out_tok
        self.cost_usd += _estimate_cost(self.model, in_tok, out_tok)

        self._emit(
            "usage",
            f"llm calls: {self.llm_calls} · tokens: {self.input_tokens + self.output_tokens}",
            f"est. cost: ${self.cost_usd:.4f}",
        )

        if self.max_llm_calls is not None and self.llm_calls >= self.max_llm_calls:
            raise BudgetExceededError(
                f"LLM call budget of {self.max_llm_calls} reached "
                f"(spent ${self.cost_usd:.4f} over {self.llm_calls} calls)."
            )
        if self.max_budget_usd is not None and self.cost_usd >= self.max_budget_usd:
            raise BudgetExceededError(
                f"LLM budget of ${self.max_budget_usd:.2f} exceeded "
                f"(spent ${self.cost_usd:.4f} over {self.llm_calls} calls)."
            )

    def usage_summary(self) -> Dict[str, Any]:
        """Run-total usage, for the result dict and end-of-run reporting."""
        return {
            "llm_calls": self.llm_calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.input_tokens + self.output_tokens,
            "cost_usd": round(self.cost_usd, 4),
        }


def _estimate_cost(model: Optional[str], input_tokens: int, output_tokens: int) -> float:
    """Best-effort per-response USD cost via LiteLLM's pricing table.

    Returns 0.0 when the model is unknown to LiteLLM (e.g. many OpenRouter
    ``:free`` models) so a missing price never breaks a run — a call-count
    budget (``max_llm_calls``) is the model-agnostic fallback ceiling.
    """
    if not model or (input_tokens <= 0 and output_tokens <= 0):
        return 0.0
    try:
        import litellm
    except Exception:
        return 0.0

    # Try the full "provider/model" id first, then the bare model name — some
    # LiteLLM price-table keys carry a provider prefix and some don't.
    candidates = [model]
    if "/" in model:
        candidates.append(model.split("/", 1)[1])
    for name in candidates:
        try:
            prompt_cost, completion_cost = litellm.cost_per_token(
                model=name, prompt_tokens=input_tokens, completion_tokens=output_tokens
            )
            cost = float(prompt_cost) + float(completion_cost)
            if cost > 0:
                return cost
        except Exception:
            continue
    return 0.0
