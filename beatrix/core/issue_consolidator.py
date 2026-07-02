"""
BEATRIX Issue Consolidator

Ported from Sweet Scanner's ConsolidationAction pattern.

Deduplicates findings so the same bug isn't reported twice.
Uses multi-dimensional similarity: URL, parameter, vuln type,
payload, evidence hash.
"""

import hashlib
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional
from urllib.parse import urlparse

from beatrix.core.types import Finding, Severity


class ConsolidationAction(Enum):
    """What to do when a new finding overlaps an existing one."""
    KEEP_EXISTING = auto()  # Drop the new one
    KEEP_NEW = auto()       # Replace existing with new
    KEEP_BOTH = auto()      # Both are distinct, keep both


@dataclass
class ConsolidationResult:
    """Result of attempting to add a finding."""
    action: ConsolidationAction
    finding: Finding
    existing: Optional[Finding] = None
    reason: str = ""


class IssueConsolidator:
    """
    Deduplicates findings based on configurable similarity dimensions.

    Mirrors Sweet Scanner's consolidateIssues() pattern but with richer heuristics.

    Usage:
        consolidator = IssueConsolidator()
        for finding in raw_findings:
            result = consolidator.add(finding)
            if result.action != ConsolidationAction.KEEP_EXISTING:
                # This is a genuinely new finding
                report(result.finding)

        unique = consolidator.unique_findings()
    """

    def __init__(self, *, strict: bool = False):
        """
        Args:
            strict: If True, requires more dimensions to match for dedup.
        """
        self._findings: List[Finding] = []
        self._fingerprints: Dict[str, int] = {}  # hash -> index in _findings
        self._variant_groups: Dict[str, List[int]] = {}  # base fp -> all indices
        self._strict = strict

    # Injection-class vuln types: same host + param + vuln = same bug
    # regardless of URL path (the backend handler is shared)
    INJECTION_VULN_TYPES = frozenset([
        "sqli", "xss", "rce", "ssti", "path_traversal", "xxe",
        "header_injection",
    ])

    # Host-scoped vuln types: a fact about the host/environment (WAF
    # present, tech stack, etc), not a distinct per-path bug. Detection
    # templates (e.g. nuclei's waf-detect) match identically on every URL
    # they're pointed at — the per-request curl reproduce embedded in
    # evidence differs each time even though the underlying signal is the
    # same fact, so these need path AND evidence/description variance
    # excluded from dedup entirely (see _fingerprint, _decide).
    HOST_SCOPED_VULN_TYPES = frozenset([
        "waf_detected",
    ])

    def _fingerprint(self, f: Finding) -> str:
        """
        Generate a dedup fingerprint for a finding.

        Dimensions considered:
        1. Vulnerability type (scanner_module + title pattern)
        2. Host + path (not full URL with params)
           — For injection vulns, path is EXCLUDED (same param on
             different paths = same backend bug)
        3. Parameter name
        4. Injection point type (strict mode only)
        """
        parsed = urlparse(f.url)
        host = parsed.netloc.lower()
        path = parsed.path.rstrip("/").lower()

        # Normalize title to vuln-type (strip specifics)
        vuln_type = self._normalize_title(f.title)

        param = (f.parameter or "").lower()
        module = f.scanner_module.lower()

        # F-06 (revised): include the path for ALL findings.
        # Different URL paths nearly always mean different backend handlers,
        # and dropping the path caused massive over-dedup (e.g. every XSS on
        # param "q" across dozens of endpoints collapsed into one finding).
        # Cross-scanner dedup (injection vs smart_fuzzer, same URL) is still
        # handled by dropping the module from injection-class vulns.
        if vuln_type in self.HOST_SCOPED_VULN_TYPES:
            # Same fact regardless of which path/param triggered it.
            components = [host, vuln_type]
        elif vuln_type in self.INJECTION_VULN_TYPES and param:
            components = [host, path, vuln_type, param]
        else:
            components = [host, path, vuln_type, param, module]

        if not self._strict:
            raw = "|".join(components)
        else:
            ip_type = str(f.injection_point) if f.injection_point else ""
            components.append(ip_type)
            raw = "|".join(components)

        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _normalize_title(self, title: str) -> str:
        """
        Reduce a finding title to its vulnerability class.

        e.g. "SQL Injection in search parameter" -> "sql_injection"
             "Reflected XSS via q parameter" -> "reflected_xss"
        """
        title_lower = title.lower()

        PATTERNS = [
            (r"sql\s*inject", "sqli"),
            (r"cross.site\s*script|xss", "xss"),
            (r"ssrf|server.side\s*request", "ssrf"),
            (r"idor|insecure\s*direct", "idor"),
            (r"cors", "cors"),
            (r"csrf|cross.site\s*request\s*forg", "csrf"),
            (r"open\s*redirect", "open_redirect"),
            (r"path\s*traversal|directory\s*traversal|lfi", "path_traversal"),
            (r"command\s*inject|rce|remote\s*code", "rce"),
            (r"xxe|xml\s*external", "xxe"),
            (r"ssti|template\s*inject", "ssti"),
            (r"jwt", "jwt"),
            (r"oauth", "oauth"),
            (r"auth.*bypass|broken\s*auth", "auth_bypass"),
            (r"info.*disclos|information\s*leak|error.*disclos", "info_disclosure"),
            (r"header\s*inject", "header_injection"),
            (r"priv.*escal", "privilege_escalation"),
            (r"rate\s*limit", "rate_limit"),
            (r"brute\s*force", "brute_force"),
            # F-09: Previously missing vuln types
            (r"deseriali[sz]", "deserialization"),
            (r"file\s*upload|unrestricted\s*upload", "file_upload"),
            (r"cache\s*poison", "cache_poisoning"),
            (r"mass\s*assign", "mass_assignment"),
            (r"prototype\s*pollut", "prototype_pollution"),
            (r"http\s*smuggl|request\s*smuggl", "http_smuggling"),
            (r"websocket|web\s*socket", "websocket"),
            (r"takeover|subdomain\s*takeover", "takeover"),
            (r"graphql", "graphql"),
            (r"\bwaf\s*detect", "waf_detected"),
        ]

        import re
        for pattern, label in PATTERNS:
            if re.search(pattern, title_lower):
                return label

        # Fallback: slugify the title
        return re.sub(r"[^a-z0-9]+", "_", title_lower).strip("_")

    def add(self, finding: Finding) -> ConsolidationResult:
        """
        Attempt to add a finding. Returns what action was taken.
        """
        fp = self._fingerprint(finding)

        if fp in self._variant_groups:
            # Compare against ALL variants with this base fingerprint
            group = self._variant_groups[fp]
            replace_idx = None
            replace_existing = None

            for idx in group:
                existing = self._findings[idx]
                action = self._decide(existing, finding)

                if action == ConsolidationAction.KEEP_EXISTING:
                    # Duplicate of this variant — drop it
                    return ConsolidationResult(
                        action=action, finding=existing,
                        existing=existing,
                        reason="Duplicate of existing finding",
                    )
                elif action == ConsolidationAction.KEEP_NEW:
                    replace_idx = idx
                    replace_existing = existing
                    # Don't return yet — might be a dup of another variant

            if replace_idx is not None:
                self._findings[replace_idx] = finding
                return ConsolidationResult(
                    action=ConsolidationAction.KEEP_NEW, finding=finding,
                    existing=replace_existing,
                    reason="Replaced: new has higher severity/confidence",
                )

            # KEEP_BOTH for all variants — truly distinct
            new_idx = len(self._findings)
            self._findings.append(finding)
            group.append(new_idx)
            return ConsolidationResult(
                action=ConsolidationAction.KEEP_BOTH, finding=finding,
                existing=self._findings[group[0]],
                reason="Distinct variant, keeping both",
            )
        else:
            idx = len(self._findings)
            self._findings.append(finding)
            self._fingerprints[fp] = idx
            self._variant_groups[fp] = [idx]
            return ConsolidationResult(
                action=ConsolidationAction.KEEP_BOTH,
                finding=finding,
                reason="New unique finding",
            )

    def _decide(self, existing: Finding, new: Finding) -> ConsolidationAction:
        """
        Decide what to do when two findings have the same fingerprint.
        """
        SEVERITY_ORDER = {
            Severity.CRITICAL: 5, Severity.HIGH: 4,
            Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1,
        }

        existing_score = SEVERITY_ORDER.get(existing.severity, 0)
        new_score = SEVERITY_ORDER.get(new.severity, 0)

        # Higher severity wins
        if new_score > existing_score:
            return ConsolidationAction.KEEP_NEW

        # Same severity: check if evidence differs significantly
        if new_score == existing_score:
            host_scoped = self._normalize_title(new.title) in self.HOST_SCOPED_VULN_TYPES

            # F-07: Different payloads on the same vuln type + param are
            # redundant — the first confirmed payload is sufficient.
            # Only genuinely different evidence (e.g. different secrets,
            # different endpoints) warrants keeping both.
            #
            # Skipped for host-scoped types: their evidence embeds a
            # per-request curl reproduce command whose URL differs on every
            # match even though the underlying fact (e.g. "WAF present")
            # is identical — comparing it verbatim would defeat dedup for
            # exactly the findings this category exists to collapse.
            if not host_scoped and new.evidence and existing.evidence:
                new_ev = str(sorted(new.evidence.items())) if isinstance(new.evidence, dict) else str(new.evidence)
                old_ev = str(sorted(existing.evidence.items())) if isinstance(existing.evidence, dict) else str(existing.evidence)
                if new_ev != old_ev:
                    return ConsolidationAction.KEEP_BOTH

            # F-05: Compare descriptions after stripping dynamic content
            # (timestamps, response snippets, request IDs, IP addresses).
            # Without normalization, the same finding from two runs —
            # or two requests to the same endpoint — always differs and
            # defeats dedup.
            if (not host_scoped and new.description and existing.description and
                    len(new.description) > 20):
                norm_new = self._normalize_description(new.description)
                norm_old = self._normalize_description(existing.description)
                if norm_new != norm_old:
                    return ConsolidationAction.KEEP_BOTH

            # Validated > unvalidated
            if new.validated and not existing.validated:
                return ConsolidationAction.KEEP_NEW

        return ConsolidationAction.KEEP_EXISTING

    # Regex patterns for dynamic content that should be stripped before
    # comparing descriptions for dedup.
    _DYN_PATTERNS = [
        # Timestamps — ISO-8601, RFC-2822, epoch, common date formats
        re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\dZ+:-]*"),
        re.compile(r"\b\d{10,13}\b"),  # Unix epoch seconds/millis
        # UUIDs
        re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I),
        # HTTP status codes in context like "HTTP 200" or "(HTTP 403)"
        re.compile(r"HTTP\s*/?\s*\d\.\d\s+\d{3}|HTTP\s+\d{3}", re.I),
        # IP addresses (v4)
        re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        # Hex hashes (32+ chars)
        re.compile(r"\b[0-9a-f]{32,}\b", re.I),
        # Response body excerpts — anything between "Response:" and newline
        re.compile(r"Response:.*", re.I),
        # Uploaded-to / Location URLs — dynamic per request
        re.compile(r"Uploaded to:.*", re.I),
        # Nonce / token-like strings (16+ alphanumeric)
        re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b"),
    ]

    def _normalize_description(self, desc: str) -> str:
        """Strip dynamic content from a description for dedup comparison.

        Replaces timestamps, UUIDs, IPs, hashes, response excerpts, and
        other run-specific data with placeholders so that two descriptions
        describing the *same* finding but with different dynamic values
        compare as equal.
        """
        result = desc
        for pat in self._DYN_PATTERNS:
            result = pat.sub("", result)
        # Collapse whitespace
        result = re.sub(r"\s+", " ", result).strip()
        return result

    def unique_findings(self) -> List[Finding]:
        """Return all unique findings."""
        return list(self._findings)

    def stats(self) -> Dict[str, int]:
        """Return dedup stats."""
        by_type: Dict[str, int] = {}
        for f in self._findings:
            vtype = self._normalize_title(f.title)
            by_type[vtype] = by_type.get(vtype, 0) + 1
        return {
            "total_unique": len(self._findings),
            "by_type": by_type,
        }

    def clear(self):
        """Reset the consolidator."""
        self._findings.clear()
        self._fingerprints.clear()
        self._variant_groups.clear()
