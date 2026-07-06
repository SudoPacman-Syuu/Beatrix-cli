"""
SARIF 2.1.0 output for GHOST v2 findings.

Emits a GitHub code-scanning compatible SARIF document from Beatrix ``Finding``
objects so a GHOST v2 run can be uploaded via
``github/codeql-action/upload-sarif``, ingested by ASPM platforms, or normalised
alongside other scanners in CI. This is the DevSecOps-integration surface Strix
gets from ``strix/report/sarif.py``; GHOST v2 findings are dynamic (DAST), so
results anchor on the finding's URL rather than a source file + line.

``finalize_findings`` (report/bridge) writes ``findings.sarif`` into the scan
directory next to the existing JSON/summary artifacts. The call is guarded there
so a SARIF failure never blocks the rest of the finalize path.

Design notes:
  * Rules are keyed on CWE (``CWE-NNN``), falling back to a scanner/title slug,
    so the same class of finding dedups to one rule across a run.
  * SARIF has three result levels (error/warning/note); Beatrix's five
    severities collapse into them, with the original label preserved in
    ``result.properties``.
  * GitHub code-scanning reads ``rule.properties['security-severity']`` (a
    0.0–10.0 string) to rank alerts; it's populated from a severity→score map.
  * Every result carries a ``logicalLocations`` entry (the URL) plus a web-URI
    ``physicalLocation`` so the finding keeps a meaningful anchor without a
    source file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "GHOST"
TOOL_INFORMATION_URI = "https://github.com/usestrix/strix"

# SARIF only has three result levels; Beatrix's five severities collapse here.
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# GitHub code-scanning ranks alerts by rule.properties['security-severity']
# (a 0.0–10.0 string).
_SEVERITY_TO_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}


def _severity_str(finding: Any) -> str:
    """Lowercase severity label from a Finding (Severity enum or plain str)."""
    sev = getattr(finding, "severity", None)
    val = getattr(sev, "value", sev)
    return str(val or "info").lower()


def _normalize_cwe(cwe: Any) -> Optional[str]:
    """Normalise a CWE value (``CWE-306``, ``cwe: 306``, ``306``) to ``CWE-NNN``."""
    if cwe is None:
        return None
    m = re.search(r"(\d+)", str(cwe))
    return f"CWE-{m.group(1)}" if m else None


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")
    return s or "finding"


def _rule_id(finding: Any) -> str:
    """Stable rule id: CWE if present, else scanner/title slug."""
    cwe = _normalize_cwe(getattr(finding, "cwe_id", None))
    if cwe:
        return cwe
    scanner = getattr(finding, "scanner_module", "") or ""
    return _slug(scanner or getattr(finding, "title", "finding"))


def _rule_for(finding: Any) -> Dict[str, Any]:
    """Build the reporting-descriptor (rule) object for a finding."""
    sev = _severity_str(finding)
    rule: Dict[str, Any] = {
        "id": _rule_id(finding),
        "name": _slug(getattr(finding, "title", "") or _rule_id(finding)),
        "shortDescription": {"text": getattr(finding, "title", "") or _rule_id(finding)},
        "properties": {
            "security-severity": _SEVERITY_TO_SCORE.get(sev, "1.0"),
            "tags": ["security"],
        },
    }
    remediation = getattr(finding, "remediation", "") or ""
    if remediation:
        rule["help"] = {"text": remediation}
    owasp = getattr(finding, "owasp_category", None)
    if owasp:
        rule["properties"]["tags"].append(str(owasp))
    return rule


def _result_for(finding: Any, rule_index: int) -> Dict[str, Any]:
    """Build the SARIF result object for a finding."""
    sev = _severity_str(finding)
    url = getattr(finding, "url", "") or ""
    message = getattr(finding, "description", "") or getattr(finding, "title", "") or "Finding"

    result: Dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "ruleIndex": rule_index,
        "level": _SEVERITY_TO_LEVEL.get(sev, "note"),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {"artifactLocation": {"uri": url or "urn:target:unknown"}},
                "logicalLocations": [{"name": url or "target", "kind": "resource"}],
            }
        ],
        "properties": {
            "severity": sev,
            "confidence": str(getattr(getattr(finding, "confidence", None), "value", "") or ""),
            "scanner": getattr(finding, "scanner_module", "") or "",
        },
    }
    param = getattr(finding, "parameter", None)
    if param:
        result["properties"]["parameter"] = param
    poc = getattr(finding, "poc_curl", None)
    if poc:
        result["properties"]["poc_curl"] = poc
    return result


def build_sarif(findings: List[Any], *, target: str = "", tool_version: str = "2.0") -> Dict[str, Any]:
    """Return a SARIF 2.1.0 document for ``findings``."""
    rules: List[Dict[str, Any]] = []
    rule_index: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        rid = _rule_id(finding)
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append(_rule_for(finding))
        results.append(_result_for(finding, rule_index[rid]))

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "informationUri": TOOL_INFORMATION_URI,
                "version": tool_version,
                "rules": rules,
            }
        },
        "results": results,
    }
    if target:
        run["properties"] = {"target": target}

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def write_sarif(path: Path, findings: List[Any], *, target: str = "", tool_version: str = "2.0") -> Path:
    """Serialise a SARIF document for ``findings`` to ``path``. Returns the path."""
    doc = build_sarif(findings, target=target, tool_version=tool_version)
    path = Path(path)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return path


__all__ = ["build_sarif", "write_sarif", "SARIF_VERSION", "SARIF_SCHEMA"]
