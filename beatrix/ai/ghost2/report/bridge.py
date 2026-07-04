"""
Findings bridge: GHOST v2 → Beatrix's normal reporting pipeline.

The agent records plain Beatrix ``Finding`` objects on the session. This module
runs them through the *same* finalize path a ``beatrix hunt`` uses — deterministic
enrichment, the scan-directory writer, and the findings database — so every
existing reporter, exporter and the ``beatrix findings`` / ``beatrix hunts`` CLI
work on a GHOST v2 run with zero special-casing.

``finalize_findings`` is best-effort: enrichment or output failures never sink a
run whose findings already live on the session.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

PRESET = "ghost2"


def finalize_findings(session, *, persist: bool = True) -> Dict[str, Any]:
    """Enrich, write, and (optionally) persist a run's findings.

    Returns ``{hunt_id, scan_dir, num_findings}``. Each stage is independent and
    guarded, so a failure in one still lets the others run.
    """
    findings: List[Any] = session.findings
    duration = session.duration_secs
    modules = sorted(session.modules_run)

    _enrich(findings)
    scan_dir = _write_scan_dir(session, findings, duration, modules)
    hunt_id = _persist(session, findings, duration, modules) if persist else None

    return {
        "hunt_id": hunt_id,
        "scan_dir": scan_dir,
        "num_findings": len(findings),
    }


def _enrich(findings: List[Any]) -> None:
    """Deterministic enrichment (poc_curl, impact, cwe_id, repro steps) — the
    same pass the engine runs before reporting. No AI, no network."""
    if not findings:
        return
    try:
        from beatrix.core.finding_enricher import FindingEnricher

        FindingEnricher().enrich_batch(findings)
    except Exception:
        pass


def _write_scan_dir(
    session, findings: List[Any], duration: float, modules: List[str]
) -> Optional[str]:
    """Write findings + summary into a scan directory matching ``beatrix hunt``,
    reusing the run's ScanOutputManager if the runner attached one."""
    try:
        from beatrix.core.scan_output import ScanOutputManager

        om = getattr(session, "output_manager", None)
        if om is None:
            om = ScanOutputManager(session.scope.target)
        om.write_findings(findings)
        om.write_findings_summary(findings, duration)
        om.finalize(duration=duration, preset=PRESET, modules_run=modules)
        return str(om.scan_dir)
    except Exception:
        return None


def _persist(
    session, findings: List[Any], duration: float, modules: List[str]
) -> Optional[int]:
    """Save the hunt to the FindingsDB so it shows up in ``beatrix findings``."""
    try:
        from beatrix.core.findings_db import FindingsDB

        db = FindingsDB()
        try:
            return db.save_hunt(
                target=session.scope.target,
                preset=PRESET,
                findings=findings,
                duration=duration,
                modules_run=modules,
                ai_enabled=True,
            )
        finally:
            db.conn.close()
    except Exception:
        return None


__all__ = ["finalize_findings", "PRESET"]
