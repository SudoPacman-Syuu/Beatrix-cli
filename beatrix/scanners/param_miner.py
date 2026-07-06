"""
BEATRIX Param Miner

Inspired by James Kettle's Param Miner Burp extension.

Discovers hidden/undocumented parameters by brute-forcing candidate
parameter names and detecting response changes. Finds:
- Cache poisoning vectors (unkeyed parameters that change response)
- Hidden debug parameters (debug=1, admin=true, test=1)
- Mass assignment fields (role, is_admin, price)
- Undocumented API parameters

Architecture:
    ┌──────────────────────┐
    │ 1. BASELINE          │  Fingerprint the normal response (30 attributes)
    ├──────────────────────┤
    │ 2. BATCH PROBE       │  Add 10-15 candidate params per request
    │                      │  Compare response fingerprint vs baseline
    ├──────────────────────┤
    │ 3. BISECT            │  When batch triggers diff → split and retry
    │                      │  to identify the exact parameter
    ├──────────────────────┤
    │ 4. CLASSIFY          │  Determine parameter type: cache key, debug,
    │                      │  privilege escalation, etc.
    └──────────────────────┘

Reference: https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943
CWE:       CWE-912 (Hidden Functionality)
"""

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from beatrix.core.types import Confidence, Finding, Severity
from .base import BaseScanner, ScanContext

logger = logging.getLogger("beatrix.scanners.param_miner")


# =============================================================================
# PARAMETER CLASSIFICATIONS
# =============================================================================

class ParamType(Enum):
    """Classification of discovered hidden parameters."""
    CACHE_POISON = auto()      # Unkeyed param that changes cached response
    DEBUG_PARAM = auto()        # Enables debug/verbose mode
    PRIVILEGE_ESCALATION = auto() # Changes role/access level
    HIDDEN_FEATURE = auto()     # Unlocks undocumented functionality
    BEHAVIORAL_CHANGE = auto()  # Changes application behavior
    INFORMATION_DISCLOSURE = auto() # Leaks extra information
    UNKNOWN = auto()            # Detected change but can't classify


@dataclass
class DiscoveredParam:
    """A discovered hidden parameter."""
    name: str
    url: str
    param_type: ParamType
    detection_method: str          # What changed: status, length, headers, content
    baseline_fingerprint: Dict[str, Any] = field(default_factory=dict)
    triggered_fingerprint: Dict[str, Any] = field(default_factory=dict)
    diffs: Dict[str, Tuple] = field(default_factory=dict)
    tested_values: List[str] = field(default_factory=list)
    effective_value: str = ""      # Value that triggered the change
    response_code: int = 0
    confidence: float = 0.0


# =============================================================================
# BUILT-IN PARAMETER WORDLIST
# =============================================================================

# Curated high-value parameter names (from SecLists + experience)
# These target the most commonly-hidden parameters in web applications
BUILTIN_PARAMS: List[str] = [
    # Debug / Development
    "debug", "test", "testing", "verbose", "dev", "development",
    "staging", "stage", "preview", "draft", "internal", "beta",
    "trace", "log", "logging", "profiler", "profile", "profiling",
    "monitor", "monitoring", "diag", "diagnostic", "diagnostics",
    "dump", "info", "status", "health", "metrics", "stats",
    "version", "ver", "v", "env", "environment", "mode",
    # Admin / Privilege
    "admin", "administrator", "is_admin", "isAdmin", "isadmin",
    "role", "roles", "user_role", "userRole", "group", "groups",
    "permission", "permissions", "privilege", "privileges", "level",
    "access", "access_level", "accessLevel", "type", "user_type",
    "userType", "account_type", "accountType", "tier", "plan",
    "superuser", "super", "root", "staff", "moderator", "mod",
    # Features / Flags
    "feature", "features", "flag", "flags", "enable", "enabled",
    "disable", "disabled", "toggle", "switch", "on", "off",
    "show", "hide", "hidden", "visible", "display", "render",
    "include", "exclude", "filter", "fields", "expand", "embed",
    "with", "without", "extra", "extended", "full", "detailed",
    "raw", "format", "output", "view", "layout", "template",
    # Security / Auth
    "token", "api_key", "apiKey", "api-key", "key", "secret",
    "password", "passwd", "pass", "auth", "authorization",
    "session", "sid", "jwt", "csrf", "xsrf", "nonce",
    "otp", "2fa", "mfa", "verify", "verified", "validated",
    # Caching
    "cache", "cached", "no-cache", "nocache", "no_cache",
    "refresh", "reload", "force", "force_refresh", "bust",
    "cb", "cachebuster", "_", "t", "ts", "timestamp",
    # Redirect / URL
    "redirect", "redirect_uri", "redirect_url", "redirectUri",
    "return", "return_url", "returnUrl", "return_to", "returnTo",
    "next", "next_url", "nextUrl", "goto", "url", "uri", "link",
    "continue", "destination", "dest", "target", "ref", "referrer",
    # Data / API
    "page", "per_page", "perPage", "limit", "offset", "skip",
    "count", "total", "max", "min", "size", "pageSize", "page_size",
    "sort", "order", "orderBy", "order_by", "sortBy", "sort_by",
    "asc", "desc", "direction", "dir",
    "id", "ids", "user_id", "userId", "user", "username",
    "email", "name", "q", "query", "search", "keyword", "keywords",
    "lang", "language", "locale", "country", "region", "timezone",
    # Callbacks / JSONP
    "callback", "cb", "jsonp", "jsonpcallback", "fn",
    # Framework-specific
    "_method", "_token", "_format", "_encoding", "_charset",
    "_action", "_type", "_debug", "_profiler", "_trace",
    "X-Forwarded-For", "X-Real-IP", "X-Original-URL",
    "X-Rewrite-URL", "X-Custom-IP-Authorization",
]

# Values to test when a parameter is found to cause changes
PROBE_VALUES: List[str] = [
    "1", "true", "yes", "on", "enabled", "admin",
    "0", "false", "no", "off", "disabled",
    "../../etc/passwd", "<script>alert(1)</script>",
]


# =============================================================================
# SCANNER
# =============================================================================

class ParamMiner(BaseScanner):
    """
    Hidden parameter discovery scanner.

    Brute-forces candidate parameter names against endpoints, detecting
    response changes to find undocumented functionality, cache poisoning
    vectors, debug modes, and privilege escalation parameters.
    """

    name = "param_miner"
    description = "Hidden parameter discovery (Param Miner)"
    version = "1.0.0"
    checks = ["hidden_params", "cache_poisoning", "mass_assignment"]
    owasp_category = "A05:2021"  # Security Misconfiguration
    mitre_technique = "T1595.002"  # Active Scanning: Vulnerability Scanning

    def __init__(self, config=None):
        super().__init__(config)
        self.batch_size = self.config.get("param_batch_size", 12)
        self.max_params = self.config.get("max_params_to_test", 500)
        self.max_urls = self.config.get("max_urls", 15)
        self.diff_threshold = self.config.get("diff_threshold", 50)  # bytes
        self._seclists_params: List[str] = []
        self._init_wordlist()

    def _init_wordlist(self):
        """Load parameter wordlist, augmenting with SecLists if available."""
        self._params = list(BUILTIN_PARAMS)

        try:
            from beatrix.core.seclists_manager import get_manager
            mgr = get_manager(verbose=False)
            seclists_params = mgr.get_wordlist(
                "Discovery/Web-Content/burp-parameter-names.txt"
            )
            if seclists_params:
                # Merge, keeping our curated list first (higher priority)
                existing = set(self._params)
                for p in seclists_params:
                    p = p.strip()
                    if p and p not in existing:
                        self._params.append(p)
                        existing.add(p)
                logger.info(
                    f"Param Miner: {len(self._params)} params "
                    f"({len(BUILTIN_PARAMS)} built-in + "
                    f"{len(self._params) - len(BUILTIN_PARAMS)} from SecLists)"
                )
        except Exception as e:
            logger.debug(f"SecLists not available for param mining: {e}")

    # ─────────────────────────────────────────────────────────────────────
    # BASELINE FINGERPRINTING
    # ─────────────────────────────────────────────────────────────────────

    async def _get_baseline(self, url: str) -> Optional[Dict[str, Any]]:
        """Get a stable baseline fingerprint for the URL.

        Also auto-calibrates: any field that already differs between two
        *identical* requests is volatile (per-response nonces, timestamps in
        the body, rotating cache/session headers, ...) and is recorded so it
        won't later be mistaken for a parameter-induced change. This is what
        keeps a CDN's ever-incrementing ``Age`` header (and similar noise)
        from flagging every probed parameter as a cache-poisoning hit.
        """
        try:
            resp1 = await self.get(url)
            await asyncio.sleep(0.1)
            resp2 = await self.get(url)
        except Exception:
            return None

        fp1 = self._fingerprint(resp1)
        fp2 = self._fingerprint(resp2)

        # Check baseline stability — if two identical requests differ,
        # this endpoint has too much variance for param mining
        if fp1["status"] != fp2["status"]:
            logger.debug(f"Baseline unstable (status varies): {url}")
            return None

        length_diff = abs(fp1["length"] - fp2["length"])
        if length_diff > self.diff_threshold:
            logger.debug(f"Baseline unstable (length varies by {length_diff}): {url}")
            return None

        # Record volatile diff-keys (those that already vary between two
        # identical requests) so _responses_differ can ignore them.
        fp1["_volatile"] = frozenset(self._responses_differ(fp1, fp2).keys())
        return fp1

    def _fingerprint(self, resp) -> Dict[str, Any]:
        """Create a lightweight fingerprint of an HTTP response."""
        body = resp.text
        headers = dict(resp.headers)

        return {
            "status": resp.status_code,
            "length": len(body),
            "content_type": headers.get("content-type", ""),
            "headers_set": frozenset(k.lower() for k in headers.keys()),
            "body_hash": hashlib.md5(body.encode()).hexdigest(),
            # Cache-specific headers
            "cache_control": headers.get("cache-control", ""),
            "vary": headers.get("vary", ""),
            "x_cache": headers.get("x-cache", ""),
            "age": headers.get("age", ""),
            "etag": headers.get("etag", ""),
            # Detect new cookies
            "set_cookie_names": frozenset(
                c.split("=")[0].strip()
                for c in headers.get("set-cookie", "").split(",")
                if "=" in c
            ),
            # Body sample (first 500 chars for quick comparison)
            "body_prefix": body[:500],
        }

    def _responses_differ(
        self, baseline: Dict[str, Any], test: Dict[str, Any]
    ) -> Dict[str, Tuple]:
        """Compare baseline and test fingerprints, return meaningful diffs.

        Volatile fields recorded on the baseline during calibration (see
        ``_get_baseline``) are ignored so per-response noise isn't reported as
        a parameter-induced change.
        """
        diffs = {}

        # Status code change is always significant
        if baseline["status"] != test["status"]:
            diffs["status"] = (baseline["status"], test["status"])

        # Content length change beyond threshold
        length_diff = abs(baseline["length"] - test["length"])
        if length_diff > self.diff_threshold:
            diffs["length"] = (baseline["length"], test["length"])

        # Body hash change (content actually different)
        if baseline["body_hash"] != test["body_hash"]:
            diffs["body_hash"] = (baseline["body_hash"], test["body_hash"])

        # New headers appeared
        new_headers = test["headers_set"] - baseline["headers_set"]
        if new_headers:
            diffs["new_headers"] = (set(), new_headers)

        # New cookies
        new_cookies = test["set_cookie_names"] - baseline["set_cookie_names"]
        if new_cookies:
            diffs["new_cookies"] = (set(), new_cookies)

        # Cache header changes (important for cache poisoning). NOTE: `age` is
        # deliberately excluded — it's the seconds-in-cache counter, which
        # increments on essentially every request to a CDN-fronted origin, so
        # comparing it by equality flags every probed parameter. Real
        # cache-key influence shows up in vary/cache-control/x-cache (and the
        # body), not in a monotonic timer.
        for h in ("cache_control", "vary", "x_cache", "etag"):
            if baseline.get(h) != test.get(h):
                diffs[f"cache_{h}"] = (baseline.get(h), test.get(h))

        # Content type change
        if baseline["content_type"] != test["content_type"]:
            diffs["content_type"] = (baseline["content_type"], test["content_type"])

        # Drop any fields that were already volatile between two identical
        # baseline requests (nonces, timestamps, rotating headers, ...).
        volatile = baseline.get("_volatile")
        if volatile:
            for key in volatile:
                diffs.pop(key, None)

        return diffs

    # ─────────────────────────────────────────────────────────────────────
    # BATCH PROBING AND BISECTION
    # ─────────────────────────────────────────────────────────────────────

    async def _probe_batch(
        self,
        url: str,
        param_names: List[str],
        baseline: Dict[str, Any],
        value: str = "1",
    ) -> Optional[Dict[str, Tuple]]:
        """Test a batch of parameter names in a single request."""
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query, keep_blank_values=True)

        # Add candidate params
        test_params = dict(existing_params)
        for name in param_names:
            if name not in test_params:
                test_params[name] = [value]

        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            resp = await self.get(test_url)
        except Exception:
            return None

        test_fp = self._fingerprint(resp)
        diffs = self._responses_differ(baseline, test_fp)

        # Filter out body_hash-only changes that are just length changes
        # (avoid double-counting)
        if "body_hash" in diffs and "length" not in diffs:
            # Body changed but length is similar — might be nonce/timestamp
            # Only keep if the prefix also changed
            if baseline["body_prefix"] == test_fp["body_prefix"]:
                del diffs["body_hash"]

        return diffs if diffs else None

    async def _bisect_params(
        self,
        url: str,
        param_names: List[str],
        baseline: Dict[str, Any],
        value: str = "1",
    ) -> List[str]:
        """Bisect a batch of parameters to find which one(s) cause the change."""
        if len(param_names) <= 1:
            return param_names

        mid = len(param_names) // 2
        left = param_names[:mid]
        right = param_names[mid:]

        found = []

        # Test left half
        left_diffs = await self._probe_batch(url, left, baseline, value)
        if left_diffs:
            if len(left) == 1:
                found.extend(left)
            else:
                found.extend(await self._bisect_params(url, left, baseline, value))

        # Test right half
        right_diffs = await self._probe_batch(url, right, baseline, value)
        if right_diffs:
            if len(right) == 1:
                found.extend(right)
            else:
                found.extend(await self._bisect_params(url, right, baseline, value))

        await asyncio.sleep(0.05)
        return found

    # ─────────────────────────────────────────────────────────────────────
    # CLASSIFICATION
    # ─────────────────────────────────────────────────────────────────────

    def _classify_param(
        self, name: str, diffs: Dict[str, Tuple], url: str
    ) -> ParamType:
        """Classify a discovered parameter based on response changes."""
        name_lower = name.lower()

        # Check for cache-related changes (age excluded — see _responses_differ)
        cache_keys = {"cache_cache_control", "cache_vary", "cache_x_cache", "cache_etag"}
        if cache_keys & set(diffs.keys()):
            return ParamType.CACHE_POISON

        # Debug/dev parameter names
        debug_names = {
            "debug", "test", "testing", "verbose", "dev", "development",
            "trace", "log", "profiler", "profile", "diag", "diagnostic",
            "dump", "monitor", "info", "status", "metrics",
        }
        if name_lower in debug_names:
            return ParamType.DEBUG_PARAM

        # Privilege-related parameter names
        priv_names = {
            "admin", "is_admin", "isadmin", "role", "roles", "user_role",
            "permission", "privilege", "level", "access", "access_level",
            "superuser", "staff", "moderator", "type", "user_type",
            "account_type", "tier", "plan", "group",
        }
        if name_lower in priv_names:
            return ParamType.PRIVILEGE_ESCALATION

        # Status code change suggests significant behavioral change
        if "status" in diffs:
            return ParamType.BEHAVIORAL_CHANGE

        # New headers appeared — could be info disclosure
        if "new_headers" in diffs:
            return ParamType.INFORMATION_DISCLOSURE

        # Significant length change suggests hidden feature
        if "length" in diffs:
            baseline_len, test_len = diffs["length"]
            if test_len > baseline_len * 1.5:
                return ParamType.INFORMATION_DISCLOSURE
            return ParamType.HIDDEN_FEATURE

        return ParamType.UNKNOWN

    def _severity_for_type(self, param_type: ParamType) -> Severity:
        return {
            ParamType.CACHE_POISON: Severity.HIGH,
            ParamType.DEBUG_PARAM: Severity.MEDIUM,
            ParamType.PRIVILEGE_ESCALATION: Severity.HIGH,
            ParamType.HIDDEN_FEATURE: Severity.LOW,
            ParamType.BEHAVIORAL_CHANGE: Severity.MEDIUM,
            ParamType.INFORMATION_DISCLOSURE: Severity.MEDIUM,
            ParamType.UNKNOWN: Severity.LOW,
        }.get(param_type, Severity.LOW)

    # ─────────────────────────────────────────────────────────────────────
    # MAIN SCAN ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Main entry point — discover hidden parameters across target endpoints.
        """
        url = context.url
        urls_to_test = [url]

        # Test crawl-discovered endpoints
        if context.extra.get("discovered_urls"):
            extra = list(context.extra["discovered_urls"])[:self.max_urls]
            urls_to_test.extend(u for u in extra if u != url)
        if context.extra.get("urls_with_params"):
            extra = list(context.extra["urls_with_params"])[:self.max_urls]
            urls_to_test.extend(u for u in extra if u not in urls_to_test)

        # Dedup by (host, path)
        seen_paths = set()
        deduped_urls = []
        for u in urls_to_test:
            parsed = urlparse(u)
            key = (parsed.netloc, parsed.path)
            if key not in seen_paths:
                seen_paths.add(key)
                deduped_urls.append(u)

        for test_url in deduped_urls[:self.max_urls]:
            logger.info(f"Param mining: {test_url}")

            # Step 1: Get baseline
            baseline = await self._get_baseline(test_url)
            if not baseline:
                logger.info(f"  Baseline unstable, skipping: {test_url}")
                continue

            # Step 2: Filter out parameters already in the URL
            parsed = urlparse(test_url)
            existing = set(parse_qs(parsed.query, keep_blank_values=True).keys())
            candidates = [p for p in self._params if p not in existing]
            candidates = candidates[:self.max_params]

            # Step 3: Batch probe
            discovered: List[DiscoveredParam] = []

            for i in range(0, len(candidates), self.batch_size):
                batch = candidates[i:i + self.batch_size]
                diffs = await self._probe_batch(test_url, batch, baseline)

                if diffs:
                    # Bisect to find the exact parameter(s)
                    found_params = await self._bisect_params(
                        test_url, batch, baseline
                    )

                    for param_name in found_params:
                        # Get the specific diffs for this individual param
                        single_diff = await self._probe_batch(
                            test_url, [param_name], baseline
                        )
                        if not single_diff:
                            continue

                        param_type = self._classify_param(
                            param_name, single_diff, test_url
                        )

                        discovered.append(DiscoveredParam(
                            name=param_name,
                            url=test_url,
                            param_type=param_type,
                            detection_method=", ".join(single_diff.keys()),
                            baseline_fingerprint=baseline,
                            diffs=single_diff,
                            effective_value="1",
                            confidence=min(0.5 + 0.1 * len(single_diff), 0.95),
                        ))

                await asyncio.sleep(0.05)

            # Step 4: Yield findings for discovered parameters
            for dp in discovered:
                severity = self._severity_for_type(dp.param_type)
                type_label = dp.param_type.name.replace("_", " ").title()

                # Build diff description
                diff_lines = []
                for key, (old, new) in dp.diffs.items():
                    diff_lines.append(f"  - **{key}**: `{old}` → `{new}`")
                diff_text = "\n".join(diff_lines)

                # Build PoC URL
                parsed = urlparse(test_url)
                poc_params = parse_qs(parsed.query, keep_blank_values=True)
                poc_params[dp.name] = [dp.effective_value]
                poc_query = urlencode(poc_params, doseq=True)
                poc_url = urlunparse(parsed._replace(query=poc_query))

                yield self.create_finding(
                    title=f"Hidden Parameter Discovered: {dp.name} ({type_label})",
                    severity=severity,
                    confidence=Confidence.FIRM if dp.confidence > 0.7 else Confidence.TENTATIVE,
                    url=test_url,
                    description=(
                        f"The hidden parameter `{dp.name}` was discovered via "
                        f"response fingerprint analysis.\n\n"
                        f"**Parameter Type:** {type_label}\n"
                        f"**Detection Method:** {dp.detection_method}\n\n"
                        f"**Response Differences:**\n{diff_text}\n\n"
                        f"This parameter is not documented in the application's "
                        f"public API or visible forms, but the server processes "
                        f"it and changes its behavior when it's present."
                    ),
                    evidence=f"Response changed when '{dp.name}={dp.effective_value}' added: {dp.detection_method}",
                    parameter=dp.name,
                    payload=f"{dp.name}={dp.effective_value}",
                    cwe_id="CWE-912",
                    impact=self._impact_for_type(dp.param_type, dp.name),
                    remediation=(
                        "Review the hidden parameter and determine if it should be "
                        "publicly accessible. If it controls debug/development features, "
                        "ensure it is disabled in production. If it affects authorization, "
                        "ensure proper access controls are enforced server-side regardless "
                        "of client-supplied parameters."
                    ),
                    references=[
                        "https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943",
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables",
                    ],
                    poc_curl=f"curl -sk '{poc_url}'",
                    reproduction_steps=[
                        f"1. Send a normal request to {test_url}",
                        f"2. Add the parameter: {dp.name}={dp.effective_value}",
                        f"3. Compare the two responses — differences in: {dp.detection_method}",
                    ],
                )

    @staticmethod
    def _impact_for_type(param_type: ParamType, param_name: str) -> str:
        impacts = {
            ParamType.CACHE_POISON: (
                "This unkeyed parameter modifies the response content but is not "
                "included in the cache key. An attacker can poison the cache by "
                "sending a request with this parameter, causing all subsequent "
                "users to receive the modified (potentially malicious) response."
            ),
            ParamType.DEBUG_PARAM: (
                f"The hidden parameter '{param_name}' enables debug/development "
                f"functionality in production. This may expose stack traces, "
                f"database queries, internal paths, environment variables, or "
                f"other sensitive implementation details."
            ),
            ParamType.PRIVILEGE_ESCALATION: (
                f"The hidden parameter '{param_name}' appears to affect access "
                f"control or user privileges. An attacker may be able to escalate "
                f"their privileges by including this parameter in API requests, "
                f"potentially gaining admin/moderator access."
            ),
            ParamType.HIDDEN_FEATURE: (
                f"The server responds differently when '{param_name}' is included, "
                f"suggesting undocumented functionality. This may expose additional "
                f"data, bypass restrictions, or enable features not intended for "
                f"public use."
            ),
            ParamType.INFORMATION_DISCLOSURE: (
                f"Including '{param_name}' causes the server to return additional "
                f"information not present in the normal response. This may include "
                f"internal data, user information, or system details."
            ),
            ParamType.BEHAVIORAL_CHANGE: (
                f"The parameter '{param_name}' changes the application's behavior "
                f"(different status code or response structure). This indicates "
                f"server-side processing of an undocumented parameter."
            ),
        }
        return impacts.get(param_type,
            f"Hidden parameter '{param_name}' causes response changes when added to requests."
        )
