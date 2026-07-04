"""
`record_finding` — the agent logs a validated vulnerability.

Unlike the legacy GHOST (which kept findings in an in-memory dict that never
reached storage), this builds a real ``beatrix.core.types.Finding`` and
buffers it on the session; ``core/runner.py`` persists the whole batch to the
FindingsDB at finalize, so agent findings show up in ``beatrix findings`` and
every existing reporter/exporter with no extra wiring.
"""

from __future__ import annotations

from agents import RunContextWrapper, function_tool

from beatrix.core.types import Confidence, Finding, Severity
from ..core.session import GhostSession

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
) -> str:
    """Record a confirmed vulnerability. Call this once per real finding.

    Only record findings you have actual evidence for. Set ``validated=True``
    only when you have proven exploitability (e.g. an OOB callback, a reflected
    payload executing, extracted data) — not for a mere anomaly.

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
    )
    await session.add_finding(finding)
    return f"Recorded [{finding.severity.value}] {finding.title} (validated={finding.validated})."
