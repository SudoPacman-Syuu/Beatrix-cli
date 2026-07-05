"""
Impact-validation gate for ``record_finding``.

Beatrix already has two validators built from real lessons about what makes a
finding real vs. informational noise — ``ImpactValidator`` (13 checks, each a
"lesson paid for in blood") and ``ReportReadinessGate`` (the pre-submission
quality gate). Both existed only as a manual, disconnected ``beatrix validate``
CLI step; nothing stopped an AI agent from recording a finding no human review
would ever accept. This module makes them run automatically on every finding
ghost2 records, closing that gap:

- A finding that trips one of ImpactValidator's ``kill`` checks (WAF noise,
  an unproven subdomain takeover, a "not a secret" client-side key, ...) is
  rejected outright — it never reaches the findings buffer.
- A finding that fails a non-kill check (THEORETICAL/LIKELY) is still
  recorded — nothing is silently dropped — but downgraded and annotated so
  both the agent and any human reviewer see exactly what's missing.
- A finding that passes cleanly (PROVEN) also gets a non-blocking
  ReportReadinessGate pass; its score rides along as bonus feedback.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from beatrix.core.types import Finding
from beatrix.validators import ImpactValidator, ReportReadinessGate
from beatrix.validators.impact_validator import TargetContext

from ..core.session import Scope

_IMPACT_VALIDATOR = ImpactValidator()
_READINESS_GATE = ReportReadinessGate()

Action = Literal["reject", "flag", "accept"]


@dataclass
class GateResult:
    action: Action
    finding: Finding  # possibly severity-adjusted / annotated in place
    message: str


def _infer_target_context(scope: Scope) -> TargetContext:
    """Best-effort ``TargetContext`` from what a ghost2 ``Scope`` actually tracks.

    Most ``TargetContext`` fields (``mobile_only``, ``waf_detected``,
    ``cdn_provider``, ...) have no source in ``GhostSession`` today — they're
    left at their dataclass defaults rather than guessed. Only what's directly
    observable from the run's base auth is inferred.
    """
    headers_lower = {k.lower(): str(v).lower() for k, v in (scope.base_headers or {}).items()}
    uses_token_auth = "authorization" in headers_lower or any(
        "token" in k for k in headers_lower
    )
    return TargetContext(
        domain=scope.host(),
        uses_cookie_auth=bool(scope.base_cookies),
        uses_token_auth=uses_token_auth,
    )


def evaluate(finding: Finding, scope: Scope) -> GateResult:
    """Run ``finding`` through ImpactValidator, then ReportReadinessGate on a pass."""
    ctx = _infer_target_context(scope)
    verdict = _IMPACT_VALIDATOR.validate(finding, ctx)

    if verdict.kill_checks:
        return GateResult(
            action="reject",
            finding=finding,
            message=(
                f"REJECTED — {verdict.reason}\n"
                f"{verdict.recommendation}\n"
                "This was not recorded. Find concrete evidence (actual data "
                "extracted, a triggered OOB callback, a reproducible state "
                "change) before recording this vuln class again — or move on."
            ),
        )

    if not verdict.passed:
        if verdict.adjusted_severity is not None:
            finding.severity = verdict.adjusted_severity
        finding.description = (
            f"[IMPACT CHECK: {verdict.impact_level.value.upper()} — {verdict.reason}]\n"
            f"{finding.description}"
        )
        return GateResult(
            action="flag",
            finding=finding,
            message=(
                f"Recorded, but flagged {verdict.impact_level.value.upper()} — "
                f"{verdict.reason}\n{verdict.recommendation}"
            ),
        )

    readiness = _READINESS_GATE.check(finding)
    extra = f"\n{readiness.summary()}" if not readiness.ready else ""
    return GateResult(
        action="accept",
        finding=finding,
        message=f"Impact validated (PROVEN): {verdict.reason}{extra}",
    )
