"""
`record_finding` — the agent logs a validated vulnerability.

Unlike the legacy GHOST (which kept findings in an in-memory dict that never
reached storage), this builds a real ``beatrix.core.types.Finding`` and
buffers it on the session; ``core/runner.py`` persists the whole batch to the
FindingsDB at finalize, so agent findings show up in ``beatrix findings`` and
every existing reporter/exporter with no extra wiring.

Every finding passes through ``impact_gate.evaluate`` before it's buffered —
see that module for why: AI pentesting agents (any model, any platform)
reliably over-report informational/non-exploitable noise as real findings,
and Beatrix already has a validator built from real false-positive lessons
that this wires in automatically instead of leaving it a manual step.
"""

from __future__ import annotations

from agents import RunContextWrapper, function_tool

from beatrix.core.types import Confidence, Finding, Severity
from ..core.session import GhostSession
from . import impact_gate

_SEVERITY = {s.value: s for s in Severity}
_CONFIDENCE = {c.value: c for c in Confidence}


@function_tool
async def record_finding(
    ctx: RunContextWrapper[GhostSession],
    title: str,
    severity: str,
    description: str,
    url: str = "",
    parameter: str = "",
    payload: str = "",
    evidence: str = "",
    impact: str = "",
    remediation: str = "",
    confidence: str = "firm",
    validated: bool = False,
    request: str = "",
    response: str = "",
    poc_curl: str = "",
    reproduction_steps: str = "",
) -> str:
    """Record a confirmed vulnerability. Call this once per real finding.

    Only record findings you have actual evidence for. Set ``validated=True``
    only when you have proven exploitability (e.g. an OOB callback, a reflected
    payload executing, extracted data) — not for a mere anomaly.

    Every finding is automatically checked against Beatrix's impact-validation
    rules before it's recorded. A finding with no real, demonstrable impact
    (a generic error message, WAF noise, an unproven subdomain takeover, a
    "not a secret" client-side key, ...) will be REJECTED — you'll get back
    exactly why, so go find real evidence instead of resubmitting the same
    claim.

    To actually clear the bar (not just get flagged "needs work"), supply
    request/response/poc_curl/reproduction_steps whenever you have them — a
    bare evidence description alone is not enough evidence to pass cleanly.
    If you already ran http_request for this, quote the exact request and
    response you observed.

    Args:
        title: Short finding title (e.g. "SQL injection in id parameter").
        severity: One of critical, high, medium, low, info.
        description: What the vulnerability is and how you found it.
        url: Affected URL.
        parameter: Affected parameter, if any.
        payload: The payload that triggered it, if any.
        evidence: Concrete evidence (response snippet, callback, extracted value).
        impact: Business/security impact.
        remediation: How to fix it.
        confidence: One of certain, firm, tentative, weak.
        validated: True only if exploitability is proven.
        request: The exact request that triggered the vulnerability (method,
            URL, relevant headers/body) — quote it, don't paraphrase.
        response: The exact response snippet demonstrating impact.
        poc_curl: A literal curl command a triager could paste and run.
        reproduction_steps: Numbered steps to reproduce, one per line.
    """
    session = ctx.context
    finding = Finding(
        title=title.strip() or "Untitled finding",
        severity=_SEVERITY.get(severity.lower().strip(), Severity.INFO),
        confidence=_CONFIDENCE.get(confidence.lower().strip(), Confidence.FIRM),
        url=url or session.scope.target,
        parameter=parameter or None,
        payload=payload or None,
        evidence=evidence or None,
        description=description,
        impact=impact,
        remediation=remediation,
        scanner_module="ghost2",
        validated=bool(validated),
        request=request or None,
        response=response or None,
        poc_curl=poc_curl or None,
        reproduction_steps=[s.strip() for s in reproduction_steps.splitlines() if s.strip()],
    )

    gate = impact_gate.evaluate(finding, session.scope)
    if gate.action == "reject":
        return gate.message

    added = await session.add_finding(gate.finding)
    if not added:
        return f"Already recorded: [{gate.finding.severity.value}] {gate.finding.title} — not adding a duplicate."
    prefix = f"Recorded [{gate.finding.severity.value}] {gate.finding.title} (validated={gate.finding.validated})."
    return f"{prefix}\n{gate.message}"
