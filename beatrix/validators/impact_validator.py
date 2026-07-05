"""
BEATRIX Impact Validator

Post-scan filter that answers ONE question:
"Does this finding demonstrate REAL, concrete impact?"

Born from real-world informative closures during bug bounty testing:
  1. WAF bypass + PostgreSQL error → "error messages without demonstrable impact are out of scope"
  2. CORS on Socket.IO → "websockets only used in mobile apps, CORS doesn't apply"
  3. Nominatim + CORS → "Nominatim is public data by design"

Each check encodes a lesson we paid for with reputation points.

Usage:
    validator = ImpactValidator()
    verdict = validator.validate(finding, target_context)
    if not verdict.passed:
        print(f"BLOCKED: {verdict.reason}")
        # DO NOT SUBMIT
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from beatrix.core.types import Finding, Severity

# ============================================================================
# VERDICTS
# ============================================================================

class ImpactLevel(Enum):
    """How real is the impact?"""
    PROVEN = "proven"          # Data extracted, action performed, undeniable
    LIKELY = "likely"          # Strong evidence, needs one more step
    THEORETICAL = "theoretical"  # "Could lead to..." — NOT submittable
    NONE = "none"              # No impact at all


@dataclass
class ImpactCheck:
    """Result of a single impact check"""
    name: str
    passed: bool
    reason: str
    severity_modifier: int = 0  # -2 to +2 adjustment suggestion
    kill: bool = False          # If True, finding should be dropped entirely


@dataclass
class ImpactVerdict:
    """Final verdict on a finding's impact"""
    finding: Finding
    passed: bool
    impact_level: ImpactLevel
    checks: List[ImpactCheck] = field(default_factory=list)
    adjusted_severity: Optional[Severity] = None
    reason: str = ""
    recommendation: str = ""
    validated_at: datetime = field(default_factory=datetime.now)

    @property
    def failed_checks(self) -> List[ImpactCheck]:
        return [c for c in self.checks if not c.passed]

    @property
    def kill_checks(self) -> List[ImpactCheck]:
        return [c for c in self.checks if c.kill]

    def __str__(self) -> str:
        status = "✅ PASS" if self.passed else "❌ BLOCKED"
        return f"{status} [{self.impact_level.value}] {self.reason}"


# ============================================================================
# TARGET CONTEXT — What we know about the target
# ============================================================================

@dataclass
class TargetContext:
    """
    Context about the target that affects impact assessment.
    Fill this in during recon before validating findings.
    """
    domain: str = ""

    # Client type — CRITICAL for CORS assessment
    has_web_app: bool = False          # Browser-based UI exists
    mobile_only: bool = False          # API serves mobile apps only
    uses_cookie_auth: bool = False     # Session cookies for auth
    uses_token_auth: bool = False      # Bearer/header-based auth

    # Data sensitivity
    handles_pii: bool = True           # Default assume PII
    handles_payments: bool = False
    public_data_endpoints: List[str] = field(default_factory=list)  # Known public data

    # Infrastructure
    api_gateway: Optional[str] = None  # "kong", "aws_apigw", etc.
    waf_detected: bool = False
    cdn_provider: Optional[str] = None

    # Auth requirements
    requires_auth_token: bool = False    # Needs non-guessable token
    requires_booking_id: bool = False    # Needs booking-specific ID
    auth_mechanism: str = ""             # "cookie", "bearer", "api_key", "custom_header"

    # Notes from recon
    notes: str = ""


# ============================================================================
# THE VALIDATOR
# ============================================================================

class ImpactValidator:
    """
    Validates that a finding has real, demonstrable impact.

    Runs a battery of checks, each encoding a lesson from the field.
    A finding must pass ALL checks to be submittable.

    Usage:
        validator = ImpactValidator()
        ctx = TargetContext(domain="api.target.com", mobile_only=True)
        verdict = validator.validate(finding, ctx)
    """

    def validate(self, finding: Finding, context: Optional[TargetContext] = None) -> ImpactVerdict:
        """
        Run all impact checks against a finding.

        Returns ImpactVerdict with pass/fail and detailed reasoning.
        """
        ctx = context or TargetContext()
        checks: List[ImpactCheck] = []

        # Run each check
        checks.append(self._check_placeholder_credential(finding))
        checks.append(self._check_error_only(finding))
        checks.append(self._check_cors_relevance(finding, ctx))
        checks.append(self._check_public_data(finding, ctx))
        checks.append(self._check_client_side_keys(finding))
        checks.append(self._check_subdomain_takeover(finding))
        checks.append(self._check_evidence_exists(finding))
        checks.append(self._check_reproducible(finding))
        checks.append(self._check_auth_required(finding, ctx))
        checks.append(self._check_not_info_noise(finding))
        checks.append(self._check_waf_detection_noise(finding))
        checks.append(self._check_behavioral_sqli_on_waf(finding))
        checks.append(self._check_unconfirmed_dom_xss(finding))
        checks.append(self._check_source_map_noise(finding))

        # Determine overall verdict
        kill_checks = [c for c in checks if c.kill]
        failed_checks = [c for c in checks if not c.passed]

        if kill_checks:
            return ImpactVerdict(
                finding=finding,
                passed=False,
                impact_level=ImpactLevel.NONE,
                checks=checks,
                reason=f"KILLED: {kill_checks[0].reason}",
                recommendation="Drop this finding. It will be closed informative.",
            )

        if failed_checks:
            # Determine if it's theoretical or just needs more work
            critical_fails = [c for c in failed_checks if c.severity_modifier <= -1]
            if critical_fails:
                impact_level = ImpactLevel.THEORETICAL
                reason = f"THEORETICAL: {critical_fails[0].reason}"
                recommendation = "Do NOT submit. Need concrete proof of impact first."
            else:
                impact_level = ImpactLevel.LIKELY
                reason = f"NEEDS WORK: {failed_checks[0].reason}"
                recommendation = "Almost there. Address the failed checks before submitting."

            return ImpactVerdict(
                finding=finding,
                passed=False,
                impact_level=impact_level,
                checks=checks,
                reason=reason,
                recommendation=recommendation,
            )

        # All checks passed
        return ImpactVerdict(
            finding=finding,
            passed=True,
            impact_level=ImpactLevel.PROVEN,
            checks=checks,
            reason="All impact checks passed. Finding is submittable.",
            recommendation="Ready for Three-Cycle validation (Rule #7).",
        )

    # ========================================================================
    # INDIVIDUAL CHECKS — Each one is a lesson paid for in blood
    # ========================================================================

    def _check_placeholder_credential(self, finding: Finding) -> ImpactCheck:
        """
        LESSON: A regex matching a `user:pass@host` shape against a
        documentation EXAMPLE line is not a finding.

        airbnb/knowledge-repo 2026-07 — a scanner flagged
        "SQLALCHEMY_DATABASE_URI = 'mysql://username:password@hostname/database'"
        as a critical "MySQL Connection String" leak. That line is a
        commented-out example in the file's own docs showing the config
        syntax — "username"/"password"/"hostname"/"database" are literal
        placeholder words, not a real credential. The active config two
        lines above was SQLite in-memory. Passed every existing check
        (evidence/reproducible/error_only all fire on different signals) —
        nothing validated that the "secret" wasn't a template token.
        """
        title_lower = finding.title.lower()
        is_credential_finding = any(term in title_lower for term in [
            "connection string", "hardcoded secret", "hardcoded credential",
            "api key", "credential", "secret", "password",
        ])
        if not is_credential_finding:
            return ImpactCheck(
                name="placeholder_credential",
                passed=True,
                reason="Not a credential/secret finding.",
            )

        combined = f"{finding.evidence or ''} {finding.payload or ''}".lower()

        placeholder_tokens = [
            "username", "hostname", "yourpassword", "your_password",
            "changeme", "change_me", "your_api_key", "your_key_here",
            "insert_key_here", "insert_your", "xxxxxxxx", "placeholder_key",
            "<password>", "<secret>", "<api_key>", "<username>",
            "${password}", "${secret}", "${api_key}",
        ]
        # "password" alone as the literal matched value (not part of a real
        # secret string) is the exact shape of the airbnb/knowledge-repo bug —
        # check it as a standalone token, not a substring, so a real secret
        # that happens to contain "password" elsewhere isn't penalized.
        tokens = re.findall(r"[a-z0-9_]+", combined)
        token_set = set(tokens)
        standalone_hits = {t for t in ("username", "password", "hostname", "database")
                            if t in token_set}

        matched = [t for t in placeholder_tokens if t in combined]
        if matched or len(standalone_hits) >= 2:
            signal = matched[0] if matched else ", ".join(sorted(standalone_hits))
            return ImpactCheck(
                name="placeholder_credential",
                passed=False,
                reason=f"Matched value looks like a documentation placeholder "
                       f"({signal!r}), not a real credential. Verify the "
                       "actual secret value before reporting — many scanners "
                       "regex-match 'user:pass@host' shapes in example config "
                       "lines and comments.",
                severity_modifier=-2,
                kill=True,
            )

        return ImpactCheck(
            name="placeholder_credential",
            passed=True,
            reason="Credential value does not match known placeholder patterns.",
        )

    def _check_error_only(self, finding: Finding) -> ImpactCheck:
        """
        LESSON: Error messages alone are NOT vulnerabilities.
        "Standalone error messages without demonstrable impact
        are out of scope."

        An error message is only interesting if it leaks ACTIONABLE data:
        - Database credentials
        - Internal IPs that enable further attack
        - Table/column names that enable SQLi
        - Stack traces revealing exploitable code paths

        A generic "500 error" or "PostgreSQL error" is NOISE.
        """
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        combined = f"{title_lower} {desc_lower}"

        is_error_finding = any(term in combined for term in [
            "error disclosure", "error message", "stack trace",
            "debug info", "verbose error", "error leak",
            "database error", "sql error", "exception",
        ])

        if not is_error_finding:
            return ImpactCheck(
                name="error_only",
                passed=True,
                reason="Not an error disclosure finding.",
            )

        # Check if evidence contains ACTIONABLE leaked data
        evidence = str(finding.evidence or "").lower()
        request = str(finding.request or "").lower()
        response = str(finding.response or "").lower()
        all_evidence = f"{evidence} {request} {response}"

        actionable_patterns = [
            r"password\s*[:=]",
            r"(jdbc|mysql|postgres|mongodb)://",  # Connection strings
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # Internal IPs
            r"(aws_access_key|api_key|secret|token)\s*[:=]",
            r"(select|insert|update|delete)\s+.+\s+from\s+",  # SQL queries
            r"table\s+['\"]?\w+['\"]?\s+doesn",  # Table names in errors
        ]

        has_actionable = any(re.search(p, all_evidence) for p in actionable_patterns)

        if has_actionable:
            return ImpactCheck(
                name="error_only",
                passed=True,
                reason="Error disclosure contains actionable leaked data.",
            )

        return ImpactCheck(
            name="error_only",
            passed=False,
            reason="Error disclosure without actionable data. "
                   "Generic error messages are not vulnerabilities. "
                   "Need leaked credentials, internal IPs, or exploitable info.",
            severity_modifier=-2,
            kill=True,
        )

    def _check_cors_relevance(self, finding: Finding, ctx: TargetContext) -> ImpactCheck:
        """
        LESSON: CORS is irrelevant on mobile-only APIs.
        "Websockets only used in mobile apps,
        CORS exploitation doesn't apply."

        CORS attacks require:
        1. A BROWSER visits attacker's page (mobile apps don't browse random sites)
        2. Cookie-based auth (so the browser auto-attaches credentials)
        3. Sensitive data in the response

        If auth is header-based (Bearer tokens, custom headers like
        x-app-user-token), CORS is irrelevant because the attacker's
        page can't set those headers cross-origin anyway.
        """
        title_lower = finding.title.lower()

        is_cors_finding = "cors" in title_lower or "cross-origin" in title_lower

        if not is_cors_finding:
            return ImpactCheck(
                name="cors_relevance",
                passed=True,
                reason="Not a CORS finding.",
            )

        # Check 1: Mobile-only API → CORS is meaningless
        if ctx.mobile_only:
            return ImpactCheck(
                name="cors_relevance",
                passed=False,
                reason="Target is mobile-only. CORS attacks require browser-based "
                       "sessions. Mobile apps don't visit attacker-controlled web pages.",
                severity_modifier=-2,
                kill=True,
            )

        # Check 2: Token-based auth → CORS can't steal tokens
        if ctx.uses_token_auth and not ctx.uses_cookie_auth:
            return ImpactCheck(
                name="cors_relevance",
                passed=False,
                reason="Target uses token-based auth (not cookies). CORS attacks "
                       "rely on the browser auto-attaching cookies. Bearer/header "
                       "tokens are not sent cross-origin automatically.",
                severity_modifier=-2,
                kill=True,
            )

        # Check 3: No web app exists to exploit
        if not ctx.has_web_app:
            return ImpactCheck(
                name="cors_relevance",
                passed=False,
                reason="No web application detected. CORS attacks need a victim "
                       "to be using the target in a browser.",
                severity_modifier=-1,
            )

        # Check 4: Even with web app, does the CORS endpoint return sensitive data?
        evidence = str(finding.evidence or "")
        response = str(finding.response or "")
        combined = f"{evidence} {response}"

        sensitive_patterns = [
            r"email|password|ssn|credit.?card|phone|address",
            r"token|session|auth",
            r"user_id|account|balance|payment",
            r"private|secret|confidential",
        ]

        has_sensitive = any(re.search(p, combined, re.I) for p in sensitive_patterns)

        if not has_sensitive:
            return ImpactCheck(
                name="cors_relevance",
                passed=False,
                reason="CORS misconfiguration found but no sensitive data proven "
                       "in the response. Need to show WHAT data an attacker "
                       "would steal via cross-origin request.",
                severity_modifier=-1,
            )

        return ImpactCheck(
            name="cors_relevance",
            passed=True,
            reason="CORS finding is relevant: web app exists, cookie auth, "
                   "and sensitive data in response.",
        )

    def _check_public_data(self, finding: Finding, ctx: TargetContext) -> ImpactCheck:
        """
        LESSON: "Exposing" data that is PUBLIC BY DESIGN is not a vulnerability.
        "Nominatim is a public OSS geocoding service.
        The data is publicly available by design."

        Known public-by-design services:
        - Nominatim/OSM geocoding
        - Public status pages
        - Public API documentation
        - Open source project metadata
        - DNS records (already public)
        - WHOIS data
        - Certificate transparency logs
        """
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        url_lower = finding.url.lower()
        combined = f"{title_lower} {desc_lower} {url_lower}"

        public_by_design = [
            ("nominatim", "Nominatim is a public OSS geocoding service"),
            ("openstreetmap", "OpenStreetMap data is public"),
            ("status.", "Status pages are intentionally public"),
            ("/docs", "API documentation is intentionally public"),
            ("/swagger", "Swagger/OpenAPI docs are intentionally public"),
            ("/health", "Health check endpoints are expected to be public"),
            ("/ping", "Ping endpoints are expected to be public"),
            ("/robots.txt", "robots.txt is public by definition"),
            ("/.well-known/", ".well-known paths are public by spec"),
            ("/sitemap", "Sitemaps are public by definition"),
        ]

        for pattern, reason in public_by_design:
            if pattern in combined:
                return ImpactCheck(
                    name="public_data",
                    passed=False,
                    reason=f"Data is PUBLIC BY DESIGN: {reason}. "
                           "Reporting access to intentionally public data "
                           "will be closed informative.",
                    severity_modifier=-2,
                    kill=True,
                )

        # Check explicit public endpoints from context
        for endpoint in ctx.public_data_endpoints:
            if endpoint.lower() in url_lower:
                return ImpactCheck(
                    name="public_data",
                    passed=False,
                    reason=f"Endpoint '{endpoint}' is marked as public data "
                           "in target context. Not a vulnerability.",
                    severity_modifier=-2,
                    kill=True,
                )

        return ImpactCheck(
            name="public_data",
            passed=True,
            reason="Data does not appear to be public by design.",
        )

    def _check_evidence_exists(self, finding: Finding) -> ImpactCheck:
        """
        RULE #6: Zero Theory — Reality Is the Only Report.

        A finding MUST have concrete evidence:
        - A request/response pair showing the vulnerability
        - Extracted data proving the impact
        - A PoC that a triager can reproduce

        "Could lead to..." is not a finding.
        "Here is the data I extracted" IS.
        """
        has_evidence = bool(finding.evidence)
        has_request = bool(finding.request)
        has_response = bool(finding.response)
        has_poc = bool(finding.poc_curl or finding.poc_python)
        has_steps = bool(finding.reproduction_steps)

        evidence_score = sum([
            has_evidence,
            has_request,
            has_response,
            has_poc,
            has_steps,
        ])

        if evidence_score == 0:
            return ImpactCheck(
                name="evidence_exists",
                passed=False,
                reason="No evidence at all. Need at minimum: request, response, "
                       "and evidence of impact.",
                severity_modifier=-2,
            )

        if evidence_score < 3:
            return ImpactCheck(
                name="evidence_exists",
                passed=False,
                reason=f"Insufficient evidence (score {evidence_score}/5). "
                       "Need request + response + evidence/PoC at minimum.",
                severity_modifier=-1,
            )

        return ImpactCheck(
            name="evidence_exists",
            passed=True,
            reason=f"Evidence present (score {evidence_score}/5).",
        )

    def _check_reproducible(self, finding: Finding) -> ImpactCheck:
        """
        RULE #6 continued: Could a triager paste the PoC into a terminal
        and see the vulnerability with their own eyes?
        """
        has_poc = bool(finding.poc_curl or finding.poc_python)
        has_steps = len(finding.reproduction_steps) >= 2

        if has_poc:
            return ImpactCheck(
                name="reproducible",
                passed=True,
                reason="PoC command available for reproduction.",
            )

        if has_steps:
            return ImpactCheck(
                name="reproducible",
                passed=True,
                reason="Reproduction steps documented.",
            )

        return ImpactCheck(
            name="reproducible",
            passed=False,
            reason="No PoC curl/python command and no reproduction steps. "
                   "Triager must be able to reproduce this independently.",
            severity_modifier=-1,
        )

    def _check_auth_required(self, finding: Finding, ctx: TargetContext) -> ImpactCheck:
        """
        If exploiting a finding requires auth credentials that an attacker
        can't reasonably obtain, the impact is severely limited.

        Example: A tracking CORS endpoint needs booking_id + hash — both are
        non-guessable and unique per booking. An attacker can't enumerate them.
        """
        # Check if context indicates hard-to-obtain auth requirements
        if ctx.requires_booking_id or ctx.requires_auth_token:
            desc_lower = finding.description.lower()
            evidence_lower = str(finding.evidence or "").lower()

            # Check if the finding acknowledges and addresses auth requirements
            auth_addressed = any(term in f"{desc_lower} {evidence_lower}" for term in [
                "without auth", "unauthenticated", "no auth required",
                "bypassed auth", "auth bypass", "enumerable",
                "predictable", "sequential",
            ])

            if not auth_addressed:
                return ImpactCheck(
                    name="auth_required",
                    passed=False,
                    reason="Target requires non-guessable auth tokens/IDs. "
                           "Finding doesn't demonstrate how an attacker "
                           "would obtain these. Address the auth prerequisite.",
                    severity_modifier=-1,
                )

        return ImpactCheck(
            name="auth_required",
            passed=True,
            reason="No hard auth prerequisites, or finding addresses them.",
        )

    def _check_not_info_noise(self, finding: Finding) -> ImpactCheck:
        """
        Final sanity check: Is this finding just noise?

        Common noise patterns that waste triage time:
        - Server version disclosure (nginx/1.14.0)
        - Missing optional headers (X-Frame-Options on API)
        - Default pages (Apache/nginx welcome page)
        - Known CVEs without proof of exploitability
        """
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        combined = f"{title_lower} {desc_lower}"

        noise_patterns = [
            ("server version", "Server version disclosure alone is informational"),
            ("missing header", "Missing optional headers are rarely accepted"),
            ("x-frame-options", "X-Frame-Options missing is noise for APIs"),
            ("x-content-type", "X-Content-Type-Options missing is noise"),
            ("default page", "Default server pages are not vulnerabilities"),
            ("directory listing", "Directory listing alone needs sensitive file proof"),
            ("cve-", "CVE references need proof of exploitability on this target"),
            ("information disclosure", "Must show WHAT was disclosed and WHY it matters"),
            ("api routes disclosed", "API route disclosure in JS bundles is standard for SPAs"),
        ]

        # Only flag as noise for INFO/LOW severity — medium+ gets a pass
        if finding.severity in (Severity.INFO, Severity.LOW):
            for pattern, reason in noise_patterns:
                if pattern in combined:
                    return ImpactCheck(
                        name="info_noise",
                        passed=False,
                        reason=f"Likely noise: {reason}. "
                               "Upgrade to real impact or drop it.",
                        severity_modifier=-1,
                    )

        return ImpactCheck(
            name="info_noise",
            passed=True,
            reason="Finding doesn't match common noise patterns.",
        )

    def _check_client_side_keys(self, finding: Finding) -> ImpactCheck:
        """
        LESSON: Client-side keys/tokens designed for browser embedding are NOT secrets.
        Con Edison 2026-02-09 — P5'd for submitting AppInsights keys, Sentry DSN,
        and Bing Maps key as "credential exposure." Correct classification by triage.

        Keys that are NOT findings (designed for client-side use):
        - Application Insights instrumentation keys
        - Sentry DSNs
        - Maps API keys (Bing, Google, Mapbox)
        - OAuth client IDs (public by RFC 6749)
        - Firebase config objects
        - Analytics IDs (GA, Segment, Mixpanel)
        - OpenID Connect discovery data

        Keys that ARE findings IF they access sensitive backend data:
        - APIM subscription keys → but must show what APIs they unlock
        - Service account keys, AWS secret keys, private API tokens
        - Database connection strings with credentials

        The rule: Finding the key is recon. Using the key to access unauthorized
        data is the finding. Stop at the key = stop before the finding.
        """
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        evidence_lower = str(finding.evidence or "").lower()
        combined = f"{title_lower} {desc_lower} {evidence_lower}"

        # Client-side keys that are NEVER findings on their own
        client_side_key_patterns = [
            (r"application.?insights?", r"instrumentation.?key",
             "Application Insights instrumentation keys are not secrets — "
             "Microsoft documents them as safe for client-side embedding"),
            (r"sentry", r"dsn",
             "Sentry DSNs are not secrets — Sentry documents them as safe "
             "for client-side embedding"),
            (r"(bing|google|mapbox|leaflet).*map", r"(api.?key|access.?token)",
             "Maps API keys are designed for client-side embedding — browser "
             "needs the key to render tiles"),
            (r"firebase", r"(config|api.?key|project.?id|messaging.?sender)",
             "Firebase config is public by design — check Firestore/RTDB "
             "security rules for actual unauthorized access instead"),
            (r"(google.?analytics|ga\-|gtm\-|segment|mixpanel|amplitude)", r"(id|key|token)",
             "Analytics tracking IDs are public by design"),
            (r"oauth|openid", r"client.?id",
             "OAuth client IDs are public by specification (RFC 6749) — "
             "check for redirect URI misconfiguration instead"),
            (r"launchdarkly|launch.?darkly", r"(client.?id|sdk.?key|client.?side)",
             "LaunchDarkly client-side SDK IDs are public by design — "
             "the browser needs them to evaluate feature flags. Flag names "
             "visible to the client are intentional, not a secret"),
        ]

        # SPA/Next.js config exposure patterns — public by framework design
        spa_config_patterns = [
            (r"__next_data__", r"(runtime.?config|public.?runtime|config)",
             "__NEXT_DATA__ publicRuntimeConfig is public by Next.js design — "
             "the browser needs this data to render the page. Only "
             "serverRuntimeConfig leaking client-side would be a finding"),
            (r"(__env__|__config__|window\.__)", r"(config|runtime|setting)",
             "SPA window config objects (__ENV__, __CONFIG__) are public by "
             "design — the client needs them to function"),
            (r"feature.?flag", r"(expos|leak|disclos|enumer)",
             "Client-side feature flag names are public by design — the "
             "browser evaluates them locally. Only flag TOGGLING that "
             "bypasses security controls (auth, payment, fraud) is a finding"),
        ]

        for service_pattern, key_pattern, reason in spa_config_patterns:
            if (re.search(service_pattern, combined) and
                re.search(key_pattern, combined)):
                data_access_proof = [
                    r"(pii|personal.?data|customer.?record|billing|payment)",
                    r"(bypass|toggle|disable).*(auth|fraud|payment|security|3ds)",
                    r"(server.?runtime.?config|secret.?key|private.?key)",
                    r"(database|connection.?string|aws.?secret)",
                ]
                has_real_impact = any(
                    re.search(p, combined) for p in data_access_proof
                )
                if has_real_impact:
                    return ImpactCheck(
                        name="client_side_keys",
                        passed=True,
                        reason="Config exposure BUT demonstrates actual security "
                               "bypass or unauthorized data access.",
                    )
                return ImpactCheck(
                    name="client_side_keys",
                    passed=False,
                    reason=f"CLIENT-SIDE CONFIG — NOT A FINDING. {reason}. "
                           f"This is recon, not exploitation. Chase what the "
                           f"config ENABLES, not the config itself.",
                    severity_modifier=-2,
                    kill=True,
                )

        for service_pattern, key_pattern, reason in client_side_key_patterns:
            if (re.search(service_pattern, combined) and
                re.search(key_pattern, combined)):
                # Check if the finding demonstrates ACTUAL unauthorized data access
                # beyond just "the key works" (HTTP 200, ValidCredentials, itemsAccepted)
                data_access_proof = [
                    r"(pii|personal.?data|customer.?record|billing|payment)",
                    r"(internal.?api|backend.?data|admin.?access)",
                    r"(database|table|column|row|record).*returned",
                    r"(unauthorized|shouldn.t have access|access.?control)",
                ]
                has_real_impact = any(
                    re.search(p, combined) for p in data_access_proof
                )

                if has_real_impact:
                    return ImpactCheck(
                        name="client_side_keys",
                        passed=True,
                        reason="Client-side key finding BUT demonstrates actual "
                               "unauthorized data access. Proceed with caution.",
                    )

                return ImpactCheck(
                    name="client_side_keys",
                    passed=False,
                    reason=f"CLIENT-SIDE KEY — NOT A FINDING. {reason}. "
                           f"HTTP 200 on a public API is not demonstrated impact. "
                           f"Chase what the key UNLOCKS, not the key itself.",
                    severity_modifier=-2,
                    kill=True,
                )

        # Check for generic "hardcoded credential" findings that are actually
        # just client-side config
        if ("hardcoded" in combined or "embedded" in combined or
            re.search(r"exposed.*credential", combined) or re.search(r"credential.*expos", combined)):
            benign_indicators = [
                r"instrumentation", r"dsn", r"client.?id", r"tracking",
                r"analytics", r"maps?\.api", r"public.?key",
            ]
            is_benign = any(re.search(p, combined) for p in benign_indicators)
            if is_benign:
                return ImpactCheck(
                    name="client_side_keys",
                    passed=False,
                    reason="Finding describes 'hardcoded credentials' but the "
                           "credentials are client-side keys designed for browser "
                           "embedding. Not secrets. Chase what they unlock instead.",
                    severity_modifier=-2,
                    kill=True,
                )

        return ImpactCheck(
            name="client_side_keys",
            passed=True,
            reason="Not a client-side key finding.",
        )

    def _check_subdomain_takeover(self, finding: Finding) -> ImpactCheck:
        """
        RULE #12: Subdomain takeover requires demonstrated control.

        Kill findings that report dangling DNS records (CNAME, A, etc.)
        without actually proving the attacker can serve content on the
        subdomain. CDN providers like Fastly, Cloudflare, Azure, AWS
        have domain ownership verification — dangling CNAME ≠ takeover.
        """
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        evidence_lower = str(finding.evidence or "").lower()
        impact_lower = str(getattr(finding, 'impact', '') or "").lower()
        combined = f"{title_lower} {desc_lower} {evidence_lower} {impact_lower}"

        # Only triggers on subdomain takeover findings
        takeover_indicators = [
            r"subdomain.?take.?over",
            r"dangling.?(cname|dns|record)",
            r"unclaimed.?(subdomain|domain|cname)",
            r"orphan.?(subdomain|dns|cname)",
            r"cname.?(point|resolv|dangle)",
        ]

        is_takeover_finding = any(
            re.search(p, combined) for p in takeover_indicators
        )
        if not is_takeover_finding:
            return ImpactCheck(
                name="subdomain_takeover",
                passed=True,
                reason="Not a subdomain takeover finding.",
            )

        # Check for proof of actual control
        control_proof = [
            r"(claimed|registered|served|hosted).*(subdomain|domain)",
            r"(poc|proof).*(content|page|served|hosted|controlled)",
            r"(content|page|html).*(served|controlled|injected)",
            r"(screenshot|evidence).*(controlled|served|claimed)",
            r"(took.?over|claimed|now.?control|own.?the.?subdomain)",
            r"(serving|hosted).*(our|my|attacker|controlled)",
        ]

        has_control = any(
            re.search(p, combined) for p in control_proof
        )

        if has_control:
            return ImpactCheck(
                name="subdomain_takeover",
                passed=True,
                reason="Subdomain takeover finding with demonstrated control.",
            )

        # CDN providers with domain verification (can't just claim CNAMEs)
        verified_cdns = [
            "fastly", "cloudflare", "azure", "akamai",
            "cloudfront", "incapsula", "sucuri",
        ]
        mentions_verified_cdn = any(
            cdn in combined for cdn in verified_cdns
        )

        extra_note = ""
        if mentions_verified_cdn:
            extra_note = (
                " This CDN has domain ownership verification — "
                "a dangling CNAME alone does NOT prove takeover is possible. "
            )

        return ImpactCheck(
            name="subdomain_takeover",
            passed=False,
            reason=f"SUBDOMAIN TAKEOVER WITHOUT PROOF OF CONTROL. "
                   f"Dangling DNS records are recon, not exploitation. "
                   f"You must ACTUALLY claim the subdomain and serve "
                   f"content to prove takeover.{extra_note}"
                   f"Submit the PoC page, not the nslookup output.",
            severity_modifier=-2,
            kill=True,
        )

    # ========================================================================
    # WAF / CDN / BEHAVIORAL FALSE POSITIVE CHECKS
    # ========================================================================

    def _check_source_map_noise(self, finding: Finding) -> ImpactCheck:
        """
        LESSON: Source maps for public/OSS libraries are not findings.

        Source maps are only impactful when they expose proprietary
        application code — internal business logic, auth flows, API keys
        baked into source. A source map for a known open-source library
        (oc-client, jQuery, React, etc.) or one with very few source
        files is noise.
        """
        title_lower = finding.title.lower()
        if "source map" not in title_lower:
            return ImpactCheck(
                name="source_map_noise",
                passed=True,
                reason="Not a source map finding.",
            )

        evidence = str(finding.evidence or "")
        desc_lower = finding.description.lower()
        url_lower = finding.url.lower()
        combined = f"{evidence} {desc_lower} {url_lower}"

        # Known open-source libraries — source maps for these are meaningless
        oss_patterns = [
            r"oc-client", r"jquery", r"react", r"angular",
            r"vue", r"bootstrap", r"lodash", r"moment",
            r"axios", r"polyfill", r"core-js", r"webpack-runtime",
            r"vendor\.", r"chunk-vendors",
        ]
        is_oss = any(re.search(p, combined, re.I) for p in oss_patterns)

        # Check source count — 1-3 files is trivial
        source_count_match = re.search(r"source_count['\"]?\s*[:=]\s*(\d+)", evidence)
        source_count = int(source_count_match.group(1)) if source_count_match else None
        title_count_match = re.search(r"\((\d+)\s+original", finding.title)
        if not source_count and title_count_match:
            source_count = int(title_count_match.group(1))

        is_trivial = source_count is not None and source_count <= 3

        if is_oss:
            return ImpactCheck(
                name="source_map_noise",
                passed=False,
                reason="Source map exposes open-source library code, not "
                       "proprietary application source. Not a finding.",
                severity_modifier=-2,
                kill=True,
            )

        if is_trivial:
            return ImpactCheck(
                name="source_map_noise",
                passed=False,
                reason=f"Source map exposes only {source_count} source file(s). "
                       "Trivial exposure — need significant proprietary code "
                       "leak to be reportable.",
                severity_modifier=-2,
                kill=True,
            )

        return ImpactCheck(
            name="source_map_noise",
            passed=True,
            reason="Source map exposes non-trivial amount of code.",
        )

    def _check_waf_detection_noise(self, finding: Finding) -> ImpactCheck:
        """
        LESSON: WAF/CDN detection is recon intel, not a vulnerability.

        Nuclei WAF detection templates confirm that a WAF is present.
        That's useful for the attacker's notes, not for a bug report.
        """
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        combined = f"{title_lower} {desc_lower}"

        waf_noise_patterns = [
            r"waf.?detect",
            r"firewall.?detect",
            r"cdn.?detect",
            r"(cloudflare|akamai|fastly|incapsula|sucuri|imperva|f5|barracuda|fortinet|perimeterx|datadome|shape|distil|reblaze|wallarm|signal.?sciences).*detect",
        ]

        is_waf_detection = any(re.search(p, combined) for p in waf_noise_patterns)

        if is_waf_detection:
            return ImpactCheck(
                name="waf_detection_noise",
                passed=False,
                reason="WAF/CDN detection is reconnaissance, not a vulnerability. "
                       "Knowing a WAF exists is useful for your notes but will "
                       "be closed informative on any bug bounty platform.",
                severity_modifier=-2,
                kill=True,
            )

        return ImpactCheck(
            name="waf_detection_noise",
            passed=True,
            reason="Not a WAF/CDN detection finding.",
        )

    def _check_behavioral_sqli_on_waf(self, finding: Finding) -> ImpactCheck:
        """
        LESSON: Behavioral SQLi on WAF/bot-protection endpoints is always false.

        WAFs and bot-protection systems (PerimeterX, Cloudflare Challenge,
        Akamai Bot Manager, DataDome) are DESIGNED to respond differently
        to malicious-looking input. That's their job. Behavioral detection
        (response fingerprint divergence) will always trigger on these
        endpoints because the WAF is doing exactly what it should do.

        Only error-based or data-extraction SQLi on these endpoints would
        be meaningful (and even then, extremely unlikely).
        """
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        evidence_lower = str(finding.evidence or "").lower()
        url_lower = finding.url.lower()
        combined = f"{title_lower} {desc_lower} {evidence_lower} {url_lower}"

        is_sqli = any(term in title_lower for term in [
            "sql injection", "sqli", "sql error",
        ])
        if not is_sqli:
            return ImpactCheck(
                name="behavioral_sqli_waf",
                passed=True,
                reason="Not a SQL injection finding.",
            )

        is_behavioral = "behavior" in combined and "fingerprint" in combined
        if not is_behavioral:
            return ImpactCheck(
                name="behavioral_sqli_waf",
                passed=True,
                reason="SQLi finding uses non-behavioral detection.",
            )

        # Check if endpoint is a known WAF/bot-protection path
        waf_endpoint_patterns = [
            r"captcha", r"challenge", r"bot.?detect", r"bot.?manage",
            r"perimeterx", r"px/", r"datadome", r"_bm/",
            r"/cdn-cgi/", r"__cf_chl", r"turnstile",
            r"/ff0j69t5/",  # PerimeterX path pattern
        ]

        on_waf_endpoint = any(re.search(p, url_lower) for p in waf_endpoint_patterns)

        if on_waf_endpoint:
            return ImpactCheck(
                name="behavioral_sqli_waf",
                passed=False,
                reason="BEHAVIORAL SQLi ON WAF/BOT-PROTECTION ENDPOINT. "
                       "WAFs are DESIGNED to respond differently to malicious input. "
                       "Response fingerprint divergence on captcha/challenge endpoints "
                       "is the WAF doing its job, not SQL execution. "
                       "Need error-based or data-extraction proof, not behavioral.",
                severity_modifier=-2,
                kill=True,
            )

        return ImpactCheck(
            name="behavioral_sqli_waf",
            passed=True,
            reason="SQLi finding is not on a known WAF endpoint.",
        )

    def _check_unconfirmed_dom_xss(self, finding: Finding) -> ImpactCheck:
        """
        LESSON: Source→sink pattern matches without confirmed execution are noise.

        Passive DOM XSS checks look for patterns like:
          location.hash → innerHTML
          document.URL → eval()

        These patterns exist in virtually every modern JS application because
        frameworks and libraries use them safely (with sanitization). A pattern
        match with tentative confidence and no confirmed alert() execution is
        not a finding — it's a code review suggestion.

        Only DOM XSS with CONFIRMED execution (dialog triggered, payload
        rendered in DOM) is submittable.
        """
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        evidence_lower = str(finding.evidence or "").lower()
        combined = f"{title_lower} {desc_lower} {evidence_lower}"

        is_dom_xss = "dom xss" in title_lower or "dom-based xss" in title_lower
        if not is_dom_xss:
            return ImpactCheck(
                name="unconfirmed_dom_xss",
                passed=True,
                reason="Not a DOM XSS finding.",
            )

        # Confirmed execution indicators
        confirmed_indicators = [
            r"alert\s*\(.*\)\s*(triggered|fired|executed|called)",
            r"dialog\s*(triggered|fired|detected|intercepted)",
            r"(confirmed|verified|proven).*xss",
            r"xss.*(confirmed|verified|proven)",
            r"javascript\s+execut",
            r"payload.*executed",
            r"certain",  # confidence: certain means confirmed
        ]

        from beatrix.core.types import Confidence
        is_confirmed = (
            finding.confidence == Confidence.CERTAIN
            or any(re.search(p, combined) for p in confirmed_indicators)
        )

        if is_confirmed:
            return ImpactCheck(
                name="unconfirmed_dom_xss",
                passed=True,
                reason="DOM XSS has confirmed execution evidence.",
            )

        # Check for pattern-only indicators
        pattern_only_indicators = [
            r"source.*sink.*pattern",
            r"pattern.*match",
            r"manual.?verification.?required",
            r"tentative",
            r"dangerous.?source.*sink",
            r"code.?pattern.?is.?risky",
        ]

        is_pattern_only = any(re.search(p, combined) for p in pattern_only_indicators)

        if is_pattern_only:
            return ImpactCheck(
                name="unconfirmed_dom_xss",
                passed=False,
                reason="DOM XSS is pattern-match only — no confirmed execution. "
                       "Source→sink patterns exist in virtually every modern JS app. "
                       "Need confirmed alert()/payload execution to be submittable. "
                       "This is a code review note, not a vulnerability report.",
                severity_modifier=-2,
                kill=True,
            )

        # If not clearly confirmed, still block
        return ImpactCheck(
            name="unconfirmed_dom_xss",
            passed=False,
            reason="DOM XSS finding lacks clear execution confirmation. "
                   "Need confirmed payload execution (alert triggered, DOM mutation) "
                   "to be submittable.",
            severity_modifier=-1,
        )

    # ========================================================================
    # BATCH VALIDATION
    # ========================================================================

    def validate_batch(
        self,
        findings: List[Finding],
        context: Optional[TargetContext] = None,
    ) -> Dict[str, List[ImpactVerdict]]:
        """
        Validate a batch of findings. Returns dict grouped by result.

        Returns:
            {
                "submittable": [...],   # Passed all checks
                "needs_work": [...],    # Failed non-fatal checks
                "killed": [...],        # Should be dropped
            }
        """
        results = {
            "submittable": [],
            "needs_work": [],
            "killed": [],
        }

        for finding in findings:
            verdict = self.validate(finding, context)

            if verdict.passed:
                results["submittable"].append(verdict)
            elif verdict.kill_checks:
                results["killed"].append(verdict)
            else:
                results["needs_work"].append(verdict)

        return results
