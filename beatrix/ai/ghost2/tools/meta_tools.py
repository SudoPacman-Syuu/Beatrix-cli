"""
Meta tools: thinking, notes, and a todo list.

Lightweight scratch-state tools (no external calls) that give the agent a
place to reason explicitly and track its own plan — the Strix `thinking` /
`notes` / `todo` tools, backed by the shared session.
"""

from __future__ import annotations

from agents import RunContextWrapper, function_tool

from ..core.session import GhostSession


@function_tool
async def think(thought: str) -> str:
    """Record a private reasoning step. Use this to plan and reflect before acting.

    Args:
        thought: Your reasoning — a hypothesis, a plan, or an analysis of results.
    """
    return "noted"


@function_tool
async def add_note(ctx: RunContextWrapper[GhostSession], note: str) -> str:
    """Save a durable note about the target (tech stack, endpoints, observations).

    Args:
        note: The observation to remember for the rest of the investigation.
    """
    await ctx.context.add_note(note)
    return "saved"


@function_tool
async def add_todo(ctx: RunContextWrapper[GhostSession], task: str) -> str:
    """Add a task to your investigation plan.

    Args:
        task: The task to test or investigate.
    """
    tid = await ctx.context.add_todo(task)
    return f"todo #{tid} added"


@function_tool
async def complete_todo(ctx: RunContextWrapper[GhostSession], todo_id: int) -> str:
    """Mark a todo item done.

    Args:
        todo_id: The id returned when the todo was added.
    """
    ok = await ctx.context.complete_todo(todo_id)
    return "done" if ok else f"no todo #{todo_id}"


@function_tool
async def list_todos(ctx: RunContextWrapper[GhostSession]) -> str:
    """List your current investigation plan (todos and their status)."""
    todos = ctx.context.todos
    if not todos:
        return "No todos yet."
    return "\n".join(f"[{'x' if t['done'] else ' '}] #{t['id']} {t['text']}" for t in todos)
