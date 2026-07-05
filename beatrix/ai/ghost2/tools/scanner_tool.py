"""
`run_scanner` — drive any of Beatrix's 32 BaseScanner modules from the agent.

Reuses ``BeatrixEngine``'s module registry (``_load_modules``) so the agent
has the exact same arsenal the deterministic ``beatrix hunt`` pipeline uses,
with zero duplication. Findings the scanner yields pass through the same
``impact_gate`` as ``record_finding`` before being buffered on the shared
session — a real scan showed scanner-native findings (github_recon, nuclei,
js_bundle, ...) go straight to the findings buffer with no validation
otherwise, which is how findings like a documentation placeholder mis-flagged
as a "MySQL Connection String" reached the final report unfiltered.
"""

from __future__ import annotations

import inspect
from typing import Any, List, Optional

from agents import RunContextWrapper, function_tool

from ..core.session import GhostSession
from . import impact_gate

# Lazily-built, process-wide scanner registry (name -> BaseScanner instance).
_REGISTRY: Optional[dict] = None

# Module keys, surfaced in the tool description so the model picks valid ones.
_MODULE_KEYS = (
    "crawl, endpoint_prober, js_analysis, headers, github_recon, param_miner, "
    "takeover, error_disclosure, cache_poisoning, prototype_pollution, sequencer, "
    "cors, redirect, oauth_redirect, http_smuggling, websocket, "
    "backslash, injection, ssrf, idor, bac, auth, ssti, xxe, deserialization, "
    "graphql, mass_assignment, business_logic, redos, payment, nuclei, file_upload"
)


def _registry() -> dict:
    global _REGISTRY
    if _REGISTRY is None:
        from beatrix.core.engine import BeatrixEngine

        _REGISTRY = BeatrixEngine().modules
    return _REGISTRY


async def _collect(scanner, ctx) -> List[Any]:
    """Run a scanner's scan() supporting both async-generator and coroutine styles."""
    result = scanner.scan(ctx)
    findings: List[Any] = []
    if inspect.isasyncgen(result):
        async for f in result:
            findings.append(f)
    elif inspect.isawaitable(result):
        got = await result
        if got:
            findings.extend(got)
    return findings


@function_tool
async def run_scanner(ctx: RunContextWrapper[GhostSession], module: str, url: str) -> str:
    """Run one of Beatrix's built-in scanner modules against a URL.

    This is your primary weapon — it runs the same battle-tested scanners the
    deterministic pipeline uses. Any findings are recorded automatically.

    Valid module keys: crawl, endpoint_prober, js_analysis, headers,
    github_recon, param_miner, takeover, error_disclosure, cache_poisoning,
    prototype_pollution, sequencer, cors, redirect, oauth_redirect,
    http_smuggling, websocket, backslash, injection, ssrf, idor, bac, auth,
    ssti, xxe, deserialization, graphql, mass_assignment, business_logic,
    redos, payment, nuclei, file_upload.

    Args:
        module: Scanner key (see list above).
        url: Target URL to scan.
    """
    session = ctx.context
    registry = _registry()
    scanner = registry.get(module)
    if scanner is None:
        return f"Unknown module '{module}'. Valid modules: {_MODULE_KEYS}"

    from beatrix.scanners.base import ScanContext

    scan_ctx = ScanContext.from_url(url)
    session.record_module(module)

    try:
        async with scanner:
            findings = await _collect(scanner, scan_ctx)
    except Exception as e:  # noqa: BLE001 - surface tool errors to the model
        return f"Scanner '{module}' errored on {url}: {type(e).__name__}: {e}"

    killed = 0
    flagged = 0
    duplicate = 0
    kept: List[Any] = []
    for f in findings:
        if not getattr(f, "scanner_module", ""):
            f.scanner_module = module
        gate = impact_gate.evaluate(f, session.scope)
        if gate.action == "reject":
            killed += 1
            continue
        if gate.action == "flag":
            flagged += 1
        added = await session.add_finding(gate.finding)
        if not added:
            duplicate += 1
            continue
        kept.append(gate.finding)

    if not kept:
        if killed or duplicate:
            return (
                f"{module} scan of {url}: {killed + duplicate} finding(s) found but "
                f"none new ({killed} rejected as noise, {duplicate} already recorded)."
            )
        return f"{module} scan of {url}: no findings."
    header = f"{module} scan of {url}: {len(kept)} finding(s)"
    extras = [f"{c} {n}" for n, c in (("rejected as noise", killed), ("duplicate", duplicate)) if c]
    if extras:
        header += " (" + ", ".join(extras) + ")"
    lines = [header + ":"]
    for f in kept[:15]:
        sev = getattr(getattr(f, "severity", None), "value", "info")
        lines.append(f"  [{sev}] {getattr(f, 'title', 'finding')} @ {getattr(f, 'url', url)}")
    if len(kept) > 15:
        lines.append(f"  … and {len(kept) - 15} more")
    if flagged:
        lines.append(
            f"  ({flagged} flagged as needing more evidence — check impact "
            "level before treating as confirmed)"
        )
    return "\n".join(lines)
