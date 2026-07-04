"""
Tool registry for GHOST v2.

``collect_tools(role, allow_exec)`` returns the function-tool set for a given
agent role:

* ``root``         — orchestrates: plans, delegates to subagents (spawn_agent),
                     and can do broad probing itself; ends the run (finish_scan).
* ``recon``        — maps the attack surface (http + scanners + notes).
* ``exploitation`` — turns leads into evidenced bugs (inject/scanners/oob/exec).
* ``validation``   — confirms real impact and kills false positives (oob/diff).

Subagent roles end their sub-loop with ``agent_finish``; ``root`` with
``finish_scan``. ``allow_exec`` gates the sandbox exec tools so they only
appear when the runtime can actually run them.
"""

from __future__ import annotations

from typing import List

from .exec_tools import python_exec, shell
from .external_tool import run_external_tool
from .findings_tool import record_finding
from .graph_tools import spawn_agent
from .http_tools import compare_responses, encode_payload, http_request, inject
from .knowledge_tools import kb_search, load_skill
from .lifecycle_tools import agent_finish, finish_scan
from .meta_tools import add_note, add_todo, complete_todo, list_todos, think
from .oob_tools import oob_poll, oob_register
from .scanner_tool import run_scanner

# Shared planning/scratch tools every role gets.
_META = [think, add_note, add_todo, complete_todo, list_todos]

# Knowledge-base tools (issue #11). Read-only and cheap, so every role gets
# them — the prompts require load_skill before an agent claims impact.
_KNOWLEDGE = [load_skill, kb_search]

# Exec tools run through the run's Runtime (Docker sandbox, or host with
# --allow-host-exec). Only offered when exec is actually usable.
_EXEC_TOOLS = [shell, python_exec]

# Role → tool set (excluding meta/exec/lifecycle, which are added below).
_ROLE_TOOLS = {
    "root": [
        spawn_agent,              # delegate to subagents
        http_request, run_scanner, run_external_tool,
        inject, encode_payload, compare_responses,
        oob_register, oob_poll,
        record_finding,
    ],
    "recon": [
        http_request, run_scanner, run_external_tool,
    ],
    "exploitation": [
        run_scanner, run_external_tool, http_request, inject, encode_payload,
        compare_responses, oob_register, oob_poll, record_finding,
    ],
    "validation": [
        http_request, compare_responses, oob_register, oob_poll, record_finding,
    ],
}

# Which lifecycle tool ends each role's loop.
_ROLE_FINISH = {
    "root": finish_scan,
    "recon": agent_finish,
    "exploitation": agent_finish,
    "validation": agent_finish,
}

# Roles allowed to run sandbox exec (when the runtime permits it).
_EXEC_ROLES = {"root", "exploitation"}


def collect_tools(role: str = "root", *, allow_exec: bool = False) -> List:
    """Return the ordered tool list for an agent role.

    ``allow_exec`` adds the sandbox exec tools for roles that use them; pass the
    active runtime's ``allows_exec``.
    """
    role = role if role in _ROLE_TOOLS else "root"
    tools = list(_ROLE_TOOLS[role]) + list(_META) + list(_KNOWLEDGE)
    if allow_exec and role in _EXEC_ROLES:
        tools.extend(_EXEC_TOOLS)
    tools.append(_ROLE_FINISH[role])  # lifecycle tool last
    return tools


__all__ = ["collect_tools"]
