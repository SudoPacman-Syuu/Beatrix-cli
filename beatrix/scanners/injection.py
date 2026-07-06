"""
BEATRIX Injection Scanner

Tests for common injection vulnerabilities:
- SQL Injection (error-based, blind, time-based)
- XSS (reflected, stored indicators)
- Command Injection
- SSTI (Server-Side Template Injection)
- Path Traversal

Uses insertion points from InsertionPointDetector.
Inspired by Sweet Scanner's active scanner approach.
"""

import asyncio
import re
import secrets
import time
from dataclasses import dataclass
from typing import AsyncIterator, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, urlunparse

from beatrix.core.types import Confidence, Finding, InsertionPoint, InsertionPointType, Severity

from .base import BaseScanner, ScanContext
from .insertion import InsertionPointDetector, ParsedRequest

# Response fingerprint comparison for blind detection
try:
    from beatrix.core.response_analyzer import (
        responses_differ,
        is_blind_indicator,
        ResponseVariationsAnalyzer,
    )
    HAS_RESPONSE_ANALYZER = True
except ImportError:
    HAS_RESPONSE_ANALYZER = False

# Reflection context analysis for context-aware XSS
try:
    from beatrix.core.reflection_analyzer import (
        CANARY as REFLECTION_CANARY,
        ReflectionContext,
        find_reflection_contexts,
        payloads_for_context,
        evasion_payloads_for_context,
        detect_char_escaping,
        _classify_context,
    )
    HAS_REFLECTION_ANALYZER = True
except ImportError:
    HAS_REFLECTION_ANALYZER = False

# WAF bypass payload generation
try:
    from beatrix.utils.advanced_waf_bypass import (
        get_waf_bypass_payloads as _get_adv_bypass,
        PayloadObfuscator,
        AdvancedWAFBypass,
    )
    HAS_WAF_BYPASS = True
except ImportError:
    HAS_WAF_BYPASS = False


@dataclass
class Payload:
    """Injection test payload"""
    value: str
    name: str
    category: str  # sqli, xss, cmdi, ssti, path
    detection: str  # error, reflect, time, behavior
    patterns: List[str]  # Regex patterns to detect success
    severity: Severity
    time_threshold: float = 0  # For time-based detection


class InjectionScanner(BaseScanner):
    """
    Multi-vector injection scanner.

    Tests insertion points with payloads for:
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Command Injection
    - Server-Side Template Injection
    - Path Traversal
    """

    name = "injection"
    description = "Multi-vector injection scanner"
    version = "1.0.0"

    checks = ["sqli", "xss", "cmdi", "ssti", "path_traversal"]

    owasp_category = "A03:2021"  # Injection

    # G-03: Time-based injection payloads use 5s sleep; 10s barely covers
    # one round-trip.  20s gives comfortable margin for slow targets.
    DEFAULT_TIMEOUT = 20

    def __init__(self, config=None):
        super().__init__(config)
        self.insertion_detector = InsertionPointDetector(config)
        self._seclists = None
        self._payloads = None  # Lazy-loaded on first scan
        self._waf_profile = None  # Set by kill_chain via set_waf_profile()
        self._obfuscator = PayloadObfuscator() if HAS_WAF_BYPASS else None

    def set_waf_profile(self, waf_name: str) -> None:
        """Set the WAF profile for targeted payload encoding.

        Called by the kill chain when a CDN/WAF is detected during recon.
        """
        self._waf_profile = waf_name
        self.log(f"WAF profile set: {waf_name} — payloads will be obfuscated")

    @property
    def payloads(self) -> Dict[str, List[Payload]]:
        """Lazy-load payloads + SecLists on first access."""
        if self._payloads is None:
            self._init_seclists()
            self._payloads = self._load_payloads()
        return self._payloads

    def _init_seclists(self):
        """Initialize SecLists manager for dynamic wordlist fetching."""
        try:
            from beatrix.core.seclists_manager import get_manager
            self._seclists = get_manager(verbose=True)
            self.log("SecLists manager initialized — dynamic wordlists enabled")
        except Exception as e:
            self.log(f"SecLists manager unavailable, using built-in payloads: {e}")
            self._seclists = None

    # Detection method priority — fast/high-signal methods first so the
    # scan timeout covers the most effective payloads.  Error-based are
    # instant (pattern match on DB error strings), reflects are instant
    # (check if payload appears in response), behavioral needs baseline
    # comparison, and time-based payloads burn 5+ seconds each.
    _DETECTION_PRIORITY = {"error": 0, "reflect": 1, "behavior": 2, "time": 3}

    def _load_payloads(self) -> Dict[str, List[Payload]]:
        """Load injection payloads by category, augmented with dynamic wordlists.

        After loading, payloads within each category are sorted so that
        fast/high-signal detection methods run first (error → reflect →
        behavior → time).  Builtin payloads naturally stay near the top
        because they're loaded first and the sort is stable.
        """

        base_payloads = self._load_builtin_payloads()

        # Augment with dynamic wordlists from SecLists if available
        if self._seclists:
            self._augment_with_seclists(base_payloads)

        # Sort each category: fast detection methods first, time-based last.
        # Stable sort preserves builtin-before-seclists order within each
        # detection type, so hand-crafted payloads always lead.
        for cat in base_payloads:
            base_payloads[cat].sort(
                key=lambda p: self._DETECTION_PRIORITY.get(p.detection, 99)
            )

        return base_payloads

    def _augment_with_seclists(self, payloads: Dict[str, List[Payload]]) -> None:
        """Fetch and merge external wordlists into the payload dict."""
        # D-01: hard cap on SecLists payloads per category to keep total
        # request volume manageable.  Builtins are already priority-sorted
        # (D-03), so this caps only the dynamic tail.
        _MAX_SECLISTS_PER_CAT: int = self.config.get("seclists_cap", 100)

        category_map = {
            "sqli": ("sqli", "error", Severity.HIGH),
            "xss": ("xss", "reflect", Severity.MEDIUM),
            "cmdi": ("cmdi", "reflect", Severity.CRITICAL),
            "ssti": ("ssti", "reflect", Severity.HIGH),
            "path": ("lfi", "reflect", Severity.HIGH),
        }

        detection_patterns = {
            "sqli": [
                r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR",
                r"ORA-\d{5}", r"Microsoft.*ODBC.*SQL Server", r"SQLSTATE\[",
                r"Unclosed quotation mark",
            ],
            "xss": [],  # Reflection-based, payload itself is the pattern
            "cmdi": [r"uid=\d+.*gid=\d+"],
            "ssti": [r"8348842383"],  # Canary multiplication result
            "path": [r"root:.*:0:0:", r"/bin/bash", r"\[fonts\]"],
        }

        for payload_cat, (seclists_cat, detect_method, sev) in category_map.items():
            try:
                extra_payloads = self._seclists.get_by_category(seclists_cat)
                existing_values = {p.value for p in payloads.get(payload_cat, [])}
                added = 0

                for raw_payload in extra_payloads:
                    if added >= _MAX_SECLISTS_PER_CAT:
                        break
                    if raw_payload not in existing_values:
                        patterns = detection_patterns.get(payload_cat, [])
                        # For XSS reflection checks, use escaped payload as pattern
                        if payload_cat == "xss" and not patterns:
                            patterns = [re.escape(raw_payload)]

                        payloads.setdefault(payload_cat, []).append(Payload(
                            value=raw_payload,
                            name=f"seclists_{payload_cat}_{added}",
                            category=payload_cat,
                            detection=detect_method,
                            patterns=patterns,
                            severity=sev,
                        ))
                        existing_values.add(raw_payload)
                        added += 1

                if added:
                    self.log(f"Augmented {payload_cat} with {added} dynamic payloads from SecLists")
            except Exception as e:
                self.log(f"Failed to augment {payload_cat} from SecLists: {e}")

    def _load_builtin_payloads(self) -> Dict[str, List[Payload]]:
        """Load built-in injection payloads by category"""

        return {
            "sqli": [
                # Error-based SQLi
                Payload(
                    value="'",
                    name="single_quote",
                    category="sqli",
                    detection="error",
                    patterns=[
                        r"SQL syntax.*MySQL",
                        r"Warning.*mysql_",
                        r"PostgreSQL.*ERROR",
                        r"ORA-\d{5}",
                        r"Microsoft.*ODBC.*SQL Server",
                        r"SQLite3::SQLException",
                        r"SQLSTATE\[",
                        r"Unclosed quotation mark",
                        r"quoted string not properly terminated",
                    ],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="1' OR '1'='1",
                    name="or_true",
                    category="sqli",
                    detection="behavior",
                    patterns=[],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="1 AND 1=1--",
                    name="and_true",
                    category="sqli",
                    detection="behavior",
                    patterns=[],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="' OR ''='",
                    name="or_empty",
                    category="sqli",
                    detection="behavior",
                    patterns=[],
                    severity=Severity.HIGH,
                ),
                # Time-based blind SQLi
                Payload(
                    value="' OR SLEEP(5)--",
                    name="sleep_mysql",
                    category="sqli",
                    detection="time",
                    patterns=[],
                    severity=Severity.HIGH,
                    time_threshold=4.5,
                ),
                Payload(
                    value="'; WAITFOR DELAY '0:0:5'--",
                    name="waitfor_mssql",
                    category="sqli",
                    detection="time",
                    patterns=[],
                    severity=Severity.HIGH,
                    time_threshold=4.5,
                ),
                Payload(
                    value="' || pg_sleep(5)--",
                    name="sleep_postgres",
                    category="sqli",
                    detection="time",
                    patterns=[],
                    severity=Severity.HIGH,
                    time_threshold=4.5,
                ),
            ],

            "xss": [
                # Reflected XSS probes
                Payload(
                    value="<script>alert(1)</script>",
                    name="script_tag",
                    category="xss",
                    detection="reflect",
                    patterns=[r"<script>alert\(1\)</script>"],
                    severity=Severity.MEDIUM,
                ),
                Payload(
                    value='"><img src=x onerror=alert(1)>',
                    name="img_onerror",
                    category="xss",
                    detection="reflect",
                    patterns=[r'"><img src=x onerror=alert\(1\)>'],
                    severity=Severity.MEDIUM,
                ),
                Payload(
                    value="javascript:alert(1)",
                    name="javascript_uri",
                    category="xss",
                    detection="reflect",
                    patterns=[r"javascript:alert\(1\)"],
                    severity=Severity.MEDIUM,
                ),
                Payload(
                    value="'-alert(1)-'",
                    name="js_context",
                    category="xss",
                    detection="reflect",
                    patterns=[r"'-alert\(1\)-'"],
                    severity=Severity.MEDIUM,
                ),
                # Canary for detection
                Payload(
                    value="bx<>\"'`rx",
                    name="xss_canary",
                    category="xss",
                    detection="reflect",
                    patterns=[r"bx<>\"'`rx", r"bx&lt;&gt;", r"bx<>"],
                    severity=Severity.LOW,  # Just detection
                ),
            ],

            "cmdi": [
                # Command injection
                Payload(
                    value="; id",
                    name="semicolon_id",
                    category="cmdi",
                    detection="reflect",
                    patterns=[r"uid=\d+.*gid=\d+"],
                    severity=Severity.CRITICAL,
                ),
                Payload(
                    value="| id",
                    name="pipe_id",
                    category="cmdi",
                    detection="reflect",
                    patterns=[r"uid=\d+.*gid=\d+"],
                    severity=Severity.CRITICAL,
                ),
                Payload(
                    value="$(id)",
                    name="subshell_id",
                    category="cmdi",
                    detection="reflect",
                    patterns=[r"uid=\d+.*gid=\d+"],
                    severity=Severity.CRITICAL,
                ),
                Payload(
                    value="`id`",
                    name="backtick_id",
                    category="cmdi",
                    detection="reflect",
                    patterns=[r"uid=\d+.*gid=\d+"],
                    severity=Severity.CRITICAL,
                ),
                # Time-based
                Payload(
                    value="; sleep 5",
                    name="sleep_semicolon",
                    category="cmdi",
                    detection="time",
                    patterns=[],
                    severity=Severity.CRITICAL,
                    time_threshold=4.5,
                ),
                Payload(
                    value="| sleep 5",
                    name="sleep_pipe",
                    category="cmdi",
                    detection="time",
                    patterns=[],
                    severity=Severity.CRITICAL,
                    time_threshold=4.5,
                ),
            ],

            "ssti": [
                # Server-Side Template Injection
                # Use unique canary values to avoid false positives (NOT 7*7=49 which matches everywhere)
                Payload(
                    value="{{91371*91373}}",
                    name="jinja_multiply",
                    category="ssti",
                    detection="reflect",
                    patterns=[r"8348842383"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="${91371*91373}",
                    name="freemarker_multiply",
                    category="ssti",
                    detection="reflect",
                    patterns=[r"8348842383"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="<%= 91371*91373 %>",
                    name="erb_multiply",
                    category="ssti",
                    detection="reflect",
                    patterns=[r"8348842383"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="#{91371*91373}",
                    name="ruby_multiply",
                    category="ssti",
                    detection="reflect",
                    patterns=[r"8348842383"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="{{constructor.constructor('return this')()}}",
                    name="angular_escape",
                    category="ssti",
                    detection="error",
                    patterns=[r"\[object Window\]", r"\[object Object\]"],
                    severity=Severity.HIGH,
                ),
            ],

            "path": [
                # Path Traversal
                Payload(
                    value="../../../etc/passwd",
                    name="etc_passwd_unix",
                    category="path",
                    detection="reflect",
                    patterns=[r"root:.*:0:0:", r"/bin/bash", r"/bin/sh"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="..\\..\\..\\windows\\win.ini",
                    name="win_ini",
                    category="path",
                    detection="reflect",
                    patterns=[r"\[fonts\]", r"\[extensions\]"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="....//....//....//etc/passwd",
                    name="double_encoding",
                    category="path",
                    detection="reflect",
                    patterns=[r"root:.*:0:0:"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="..%252f..%252f..%252fetc/passwd",
                    name="double_url_encode",
                    category="path",
                    detection="reflect",
                    patterns=[r"root:.*:0:0:"],
                    severity=Severity.HIGH,
                ),
            ],
        }

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Main injection scan - test all insertion points.
        """
        self.log(f"Starting injection scan on {context.url}")

        # Parse request
        request = self.insertion_detector.parse_request(
            method=context.request.method,
            url=context.url,
            headers=dict(context.headers),
            body=context.request.body,
        )

        # Detect insertion points
        insertion_points = self.insertion_detector.detect(request)

        # ── Parameter discovery for paramless URLs ────────────────────
        # Many pages accept query parameters that aren't in the crawled URL
        # (e.g. /reflected/parameter/body accepts ?q=).  When no URL_PARAM
        # insertion points exist, probe with common param names + a canary
        # to discover hidden parameters.
        has_url_params = any(ip.type == InsertionPointType.URL_PARAM for ip in insertion_points)
        if not has_url_params:
            discovered = await self._discover_params(request)
            if discovered:
                insertion_points = discovered + insertion_points
                # Re-parse request with the first discovered param so
                # baseline captures reflect the parameterized page.
                first_param = discovered[0]
                new_url = self._build_param_url(request.url, first_param.name, first_param.value)
                request = self.insertion_detector.parse_request(
                    method=request.method,
                    url=new_url,
                    headers=dict(request.headers),
                    body=request.body,
                )

        self.log(f"Found {len(insertion_points)} insertion points")

        # D-04: Capture baseline ONCE per URL, not per insertion point.
        # The baseline is the same URL with the same method — it doesn't
        # depend on which parameter we're testing.
        self._baseline_body = ''
        self._baseline_status = 200
        self._baseline_headers: Dict[str, str] = {}
        self._baseline_time = 0.0
        # Track which response attributes naturally vary between
        # identical requests (timestamps, CSRF tokens, CDN cache
        # node headers, PerimeterX tokens, etc.).  These must be
        # excluded from behavioral injection comparisons.
        self._variant_attrs: set = set()

        if HAS_RESPONSE_ANALYZER:
            try:
                # Take 3 identical baseline samples to measure content
                # stability.  Attributes that differ across these neutral
                # requests are naturally noisy and must be ignored when
                # comparing against injected responses.
                variance_analyzer = ResponseVariationsAnalyzer()
                baseline_times: list = []
                for _i in range(3):
                    bstart = time.time()
                    resp = await self.request(
                        request.method,
                        request.url,
                        headers=dict(request.headers),
                        content=request.body if request.body else None,
                    )
                    baseline_times.append(time.time() - bstart)
                    variance_analyzer.update(
                        resp.status_code,
                        dict(resp.headers) if hasattr(resp, 'headers') else {},
                        resp.text,
                    )

                # Use last sample as the representative baseline
                self._baseline_body = resp.text
                self._baseline_status = resp.status_code
                self._baseline_headers = dict(resp.headers) if hasattr(resp, 'headers') else {}
                self._baseline_time = sum(baseline_times) / len(baseline_times)
                self._variant_attrs = variance_analyzer.variant_attributes()
            except Exception:
                self._baseline_body = ''
                self._baseline_status = 200
                self._baseline_headers = {}
                self._baseline_time = 0.5  # conservative default
                self._variant_attrs = set()

        # D-05: Track categories where we already found a vuln.
        # Finding SQLi on param `id` means we don't need to test SQLi on
        # params `page`, `sort`, etc. — it's the same backend handler.
        self._found_categories: set = set()

        # Test each insertion point
        for ip in insertion_points:
            async for finding in self._test_insertion_point(request, ip):
                yield finding

    # ── Parameter discovery ───────────────────────────────────────────
    # Common parameter names that frequently accept and reflect user input.
    _PROBE_PARAMS = [
        "q", "s", "search", "id", "query", "name", "url", "page",
        "input", "redirect", "file", "path", "callback", "data",
        "text", "value", "p", "key", "action", "cmd", "type",
        "user", "email", "lang", "next", "ref", "src", "target",
        "return", "view", "cat", "dir", "msg", "title", "content",
    ]

    async def _discover_params(self, request: ParsedRequest) -> List[InsertionPoint]:
        """Probe a paramless URL with common param names to discover hidden parameters."""
        canary = "bxD" + secrets.token_hex(4)
        # Build a single probe URL with ALL common params set to
        # unique canary values so we can identify which param(s) reflect.
        tagged = {p: f"{canary}_{p}" for p in self._PROBE_PARAMS}
        probe_url = self._build_param_url(request.url, None, None, tagged)

        try:
            resp = await self.request(
                request.method, probe_url,
                headers=dict(request.headers),
                content=request.body if request.body else None,
            )
        except Exception:
            return []

        body = resp.text
        discovered = []
        for pname in self._PROBE_PARAMS:
            if f"{canary}_{pname}" in body:
                discovered.append(InsertionPoint(
                    name=pname,
                    value="test",
                    type=InsertionPointType.URL_PARAM,
                    original_request=None,
                    position=(0, 0),
                ))
        if discovered:
            self.log(f"Parameter discovery found {len(discovered)} hidden params: "
                     f"{[ip.name for ip in discovered]}")
        return discovered

    @staticmethod
    def _build_param_url(base_url: str, name: Optional[str], value: Optional[str],
                         params: Optional[Dict[str, str]] = None) -> str:
        """Construct a URL by adding query parameters."""
        parsed = urlparse(base_url)
        if params:
            qs = urlencode(params)
        else:
            qs = urlencode({name: value})
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, qs, parsed.fragment,
        ))

    async def _test_insertion_point(
        self,
        request: ParsedRequest,
        insertion_point: InsertionPoint,
    ) -> AsyncIterator[Finding]:
        """Test a single insertion point with all relevant payloads"""

        # Determine which payload categories to test
        categories = self._select_categories(insertion_point)
        # D-04: Use the per-URL baseline captured in scan(), not per-insertion-point
        baseline_time = getattr(self, '_baseline_time', 0.0)

        for category in categories:
            # D-05: Skip categories already confirmed on another param
            if category in getattr(self, '_found_categories', set()):
                continue

            # ── Context-aware XSS: use reflection analyzer ───────────
            if category == "xss" and HAS_REFLECTION_ANALYZER:
                found_xss = False
                async for finding in self._test_xss_context_aware(request, insertion_point, baseline_time):
                    yield finding
                    found_xss = True
                    if hasattr(self, '_found_categories'):
                        self._found_categories.add(category)
                    break  # one XSS per insertion point is enough
                if found_xss:
                    continue  # skip generic XSS payloads

            payloads = self.payloads.get(category, [])
            found_in_category = False

            # ── WAF-aware payload enrichment ───────────────────────────
            # When a WAF profile is set, generate obfuscated variants of
            # each payload BEFORE batching — bypass-first, not bypass-last.
            if self._waf_profile and self._obfuscator and payloads:
                attack_type_map = {"sqli": "sqli", "xss": "xss", "cmdi": "cmdi",
                                   "ssti": "ssti", "path": "lfi"}
                attack_type = attack_type_map.get(category, "sqli")
                enriched = []
                seen = set()
                for p in payloads:
                    # Original payload first
                    if p.value not in seen:
                        enriched.append(p)
                        seen.add(p.value)
                    # Generate 3 WAF bypass variants per payload
                    try:
                        bypasses = _get_adv_bypass(p.value, attack_type, self._waf_profile)[:3]
                        for bp in bypasses:
                            if bp not in seen:
                                seen.add(bp)
                                enriched.append(Payload(
                                    value=bp,
                                    name=f"{p.name}_waf",
                                    category=p.category,
                                    detection=p.detection,
                                    patterns=p.patterns,
                                    severity=p.severity,
                                    time_threshold=p.time_threshold,
                                ))
                    except Exception:
                        pass
                payloads = enriched

            # D-02: parallel batching — split payloads into non-time (batchable)
            # and time-based (must be sequential for timing accuracy).
            _BATCH_SIZE = self.config.get("payload_batch_size", 5)

            non_time = [p for p in payloads if p.detection != "time"]
            time_based = [p for p in payloads if p.detection == "time"]

            # ── Batch non-time-based payloads ──────────────────────────
            for i in range(0, len(non_time), _BATCH_SIZE):
                batch = non_time[i:i + _BATCH_SIZE]
                results = await asyncio.gather(
                    *(self._test_payload(request, insertion_point, p, baseline_time)
                      for p in batch),
                    return_exceptions=True,
                )
                for result in results:
                    if isinstance(result, Exception) or result is None:
                        continue
                    yield result
                    found_in_category = True
                    if hasattr(self, '_found_categories'):
                        self._found_categories.add(category)
                    break  # first hit in batch → stop category
                if found_in_category:
                    break  # stop further batches

            # ── Sequential time-based payloads (only if nothing found yet) ──
            if not found_in_category:
                for payload in time_based:
                    finding = await self._test_payload(request, insertion_point, payload, baseline_time)
                    if finding:
                        yield finding
                        found_in_category = True
                        if hasattr(self, '_found_categories'):
                            self._found_categories.add(category)
                        break

            # WAF bypass fallback — only if no WAF profile was set upfront
            # (if profile was set, payloads were already enriched above)
            if not found_in_category and not self._waf_profile and HAS_WAF_BYPASS and payloads:
                attack_type_map = {"sqli": "sqli", "xss": "xss", "cmdi": "cmdi",
                                   "ssti": "ssti", "path": "lfi"}
                attack_type = attack_type_map.get(category, "sqli")
                # Use the first (most reliable) payload to generate bypass variants
                base_payload = payloads[0]
                bypass_payloads = _get_adv_bypass(base_payload.value, attack_type)[:5]
                for bp in bypass_payloads:
                    if bp == base_payload.value:
                        continue  # skip original, already tested
                    waf_payload = Payload(
                        value=bp,
                        name=f"{base_payload.name}_waf_bypass",
                        category=base_payload.category,
                        detection=base_payload.detection,
                        patterns=base_payload.patterns,
                        severity=base_payload.severity,
                        time_threshold=base_payload.time_threshold,
                    )
                    finding = await self._test_payload(request, insertion_point, waf_payload, baseline_time)
                    if finding:
                        yield finding
                        break
    def _select_categories(self, ip: InsertionPoint) -> List[str]:
        """Select payload categories based on insertion point type"""

        # URL and body params (incl. multipart form fields) get everything
        if ip.type in [
            InsertionPointType.URL_PARAM,
            InsertionPointType.BODY_PARAM,
            InsertionPointType.JSON_VALUE,
            InsertionPointType.MULTIPART,
        ]:
            return ["sqli", "xss", "ssti", "cmdi", "path"]

        # Headers get limited testing
        if ip.type == InsertionPointType.HEADER:
            if ip.name.lower() in ["user-agent", "referer"]:
                return ["sqli", "xss", "ssti"]
            if ip.name.lower() in ["x-forwarded-for", "x-real-ip"]:
                return ["sqli", "cmdi"]
            return ["sqli"]

        # Cookies
        if ip.type == InsertionPointType.COOKIE:
            return ["sqli", "xss"]

        # Path segments
        if ip.type == InsertionPointType.URL_PATH:
            return ["path", "sqli"]

        return ["sqli", "xss"]

    # ═════════════════════════════════════════════════════════════════════════
    # Context-Aware XSS Testing
    # ═════════════════════════════════════════════════════════════════════════

    async def _test_xss_context_aware(
        self,
        request: ParsedRequest,
        ip: InsertionPoint,
        baseline_time: float,
    ) -> AsyncIterator[Finding]:
        """
        Context-aware XSS testing flow:

        1. Send canary string as parameter value
        2. Analyze WHERE the canary is reflected in the response
        3. Send a char-escaping probe to detect which chars get encoded
        4. Generate context-appropriate breakout payloads
        5. If standard payloads fail, try evasion payloads
        """
        # Step 1: Send canary to discover reflection points
        try:
            canary_url, canary_headers, canary_body = \
                self.insertion_detector.build_request_with_payload(
                    request, ip, REFLECTION_CANARY
                )
            canary_resp = await self.request(
                request.method,
                canary_url,
                headers=canary_headers,
                content=canary_body if canary_body else None,
            )
        except Exception as e:
            self.log(f"Context-aware XSS canary request failed for {ip.name}: {e}")
            return

        # Step 2: Find reflection contexts
        reflections = find_reflection_contexts(canary_resp.text, REFLECTION_CANARY)
        if not reflections:
            self.log(f"No reflection found for param {ip.name} — skipping context-aware XSS")
            return

        self.log(
            f"Param {ip.name}: reflected in {len(reflections)} context(s): "
            + ", ".join(r.context.name for r in reflections)
        )

        # Step 3: Send char-escaping probe to detect encoding
        _PROBE_CHARS = REFLECTION_CANARY + '<>"\'`()/;'
        escaped_chars: List[str] = []
        try:
            probe_url, probe_headers, probe_body = \
                self.insertion_detector.build_request_with_payload(
                    request, ip, _PROBE_CHARS
                )
            probe_resp = await self.request(
                request.method,
                probe_url,
                headers=probe_headers,
                content=probe_body if probe_body else None,
            )
            escaped_chars = detect_char_escaping(
                canary_resp.text, REFLECTION_CANARY,
                probe_resp.text, _PROBE_CHARS,
            )
            if escaped_chars:
                self.log(f"Param {ip.name}: chars escaped by server: {escaped_chars}")
        except Exception:
            pass  # Proceed without escaping knowledge

        # Step 4: Generate context-specific payloads and test them
        # Deduplicate contexts — no need to test the same context type twice
        seen_contexts = set()
        for reflection in reflections:
            if reflection.context in seen_contexts:
                continue
            seen_contexts.add(reflection.context)

            ctx_payloads = payloads_for_context(reflection.context, escaped_chars)
            if not ctx_payloads:
                continue

            # Test context-specific payloads
            found = False
            for ctx_payload in ctx_payloads:
                payload_obj = Payload(
                    value=ctx_payload.value,
                    name=f"ctx_{ctx_payload.name}",
                    category="xss",
                    detection="reflect",
                    patterns=ctx_payload.confirm_patterns,
                    severity=Severity.MEDIUM,
                )
                finding = await self._test_payload(request, ip, payload_obj, baseline_time)
                if finding:
                    # Enrich the finding with context info
                    finding.description = (
                        f"{finding.description}\n\n"
                        f"Reflection context: {reflection.context.name}\n"
                        f"Context evidence: ...{reflection.surrounding}..."
                    )
                    yield finding
                    found = True
                    break

            # Step 5: If standard context payloads failed, try evasion payloads
            if not found:
                evasion = evasion_payloads_for_context(reflection.context)
                for ev_payload in evasion[:6]:  # Cap evasion attempts
                    payload_obj = Payload(
                        value=ev_payload.value,
                        name=f"evasion_{ev_payload.name}",
                        category="xss",
                        detection="reflect",
                        patterns=ev_payload.confirm_patterns,
                        severity=Severity.MEDIUM,
                    )
                    finding = await self._test_payload(request, ip, payload_obj, baseline_time)
                    if finding:
                        finding.description = (
                            f"{finding.description}\n\n"
                            f"Reflection context: {reflection.context.name} (evasion payload)\n"
                            f"Context evidence: ...{reflection.surrounding}..."
                        )
                        yield finding
                        break

    async def _test_payload(
        self,
        request: ParsedRequest,
        ip: InsertionPoint,
        payload: Payload,
        baseline_time: float = 0.0,
    ) -> Optional[Finding]:
        """Test a single payload against an insertion point"""

        try:
            # Build modified request
            url, headers, body = self.insertion_detector.build_request_with_payload(
                request, ip, payload.value
            )

            # Time the request
            start = time.time()
            response = await self.request(
                request.method,
                url,
                headers=headers,
                content=body if body else None,
            )
            elapsed = time.time() - start

            # Check for vulnerability
            is_vuln, evidence = self._check_response(
                payload, response.text, elapsed, baseline_time,
                response_status=response.status_code,
                response_headers=dict(response.headers) if hasattr(response, 'headers') else {},
                ip_type=ip.type,
            )

            if is_vuln:
                # ── Confirmation pass for time-based findings ─────────────
                # A single slow response can be network jitter. Re-test 2 more
                # times and require at least 2/3 total to show consistent delay.
                if payload.detection == "time":
                    confirm_count = 1  # First test already passed
                    for _ in range(2):
                        try:
                            cstart = time.time()
                            cresp = await self.request(
                                request.method,
                                url,
                                headers=headers,
                                content=body if body else None,
                            )
                            celapsed = time.time() - cstart
                            c_vuln, _ = self._check_response(
                                payload, cresp.text, celapsed, baseline_time,
                                response_status=cresp.status_code,
                                response_headers=dict(cresp.headers) if hasattr(cresp, 'headers') else {},
                                ip_type=ip.type,
                            )
                            if c_vuln:
                                confirm_count += 1
                        except Exception:
                            pass
                    if confirm_count < 2:
                        self.log(f"Time-based finding NOT confirmed ({confirm_count}/3 passed) — skipping {payload.name}")
                        return None
                    evidence += f"\nConfirmed: {confirm_count}/3 samples showed consistent delay"

                return self._create_injection_finding(
                    url, request, ip, payload, response, evidence
                )

        except Exception as e:
            self.log(f"Error testing {payload.name}: {e}")

        return None

    def _check_response(
        self,
        payload: Payload,
        response_text: str,
        elapsed: float,
        baseline_time: float = 0.0,
        response_status: int = 0,
        response_headers: Optional[Dict[str, str]] = None,
        ip_type: Optional[InsertionPointType] = None,
    ) -> Tuple[bool, str]:
        """
        Check if the response indicates a vulnerability.

        Returns (is_vulnerable, evidence)
        """

        # Time-based detection — MUST compare against baseline
        if payload.detection == "time":
            # Calculate the actual delay introduced by our payload
            injected_delay = elapsed - baseline_time

            # Only flag if the injected delay is close to the expected threshold
            # AND significantly above baseline. This prevents false positives from
            # naturally slow endpoints.
            if baseline_time > 0:
                # Require: response took at least (threshold) seconds longer than baseline
                if injected_delay >= payload.time_threshold * 0.8:
                    return True, (
                        f"Response time: {elapsed:.2f}s (baseline: {baseline_time:.2f}s, "
                        f"injected delay: {injected_delay:.2f}s, threshold: {payload.time_threshold}s)"
                    )
            else:
                # No baseline available — require very high threshold to compensate
                if elapsed >= payload.time_threshold + 3.0:
                    return True, (
                        f"Response time: {elapsed:.2f}s (no baseline, "
                        f"threshold: {payload.time_threshold}s + 3s safety buffer)"
                    )

        # Pattern-based detection
        if payload.detection in ["error", "reflect"]:
            for pattern in payload.patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    # For reflection checks, verify the pattern is NOT already
                    # present in the baseline response. If the same match exists
                    # without any payload, it's static server content (e.g. nginx
                    # error page HTML), not reflected user input.
                    if payload.detection == "reflect":
                        baseline_body = getattr(self, '_baseline_body', '')
                        if baseline_body and re.search(pattern, baseline_body, re.IGNORECASE):
                            continue  # Match exists in baseline — not reflection

                    # For XSS reflection, verify the match is in an executable
                    # HTML context. Skip matches inside comments, <head>,
                    # <textarea>, <title>, <style>, <noscript> where event
                    # handlers and scripts cannot execute.
                    if payload.detection == "reflect" and HAS_REFLECTION_ANALYZER:
                        matched_text = match.group(0)
                        ctx = _classify_context(response_text, match.start(), matched_text)
                        _NON_EXEC = {
                            ReflectionContext.HTML_COMMENT,
                            ReflectionContext.HEAD,
                            ReflectionContext.TEXTAREA,
                            ReflectionContext.TITLE,
                            ReflectionContext.NOSCRIPT,
                            ReflectionContext.CSS_VALUE,
                            ReflectionContext.CSS_URL,
                        }
                        if ctx in _NON_EXEC:
                            continue  # Payload in non-executable context

                    # Get context around match
                    start = max(0, match.start() - 50)
                    end = min(len(response_text), match.end() + 50)
                    context = response_text[start:end]
                    return True, f"Pattern matched: {pattern}\nContext: ...{context}..."

        # Behavioral detection — 30-dimension response fingerprint comparison
        # Detects blind injection through subtle response structure differences
        if payload.detection == "behavior" and HAS_RESPONSE_ANALYZER:
            # ── Skip behavioral SQLi for URL path segments ──────────────
            # Changing a URL path segment almost always returns a completely
            # different page (404, different route) regardless of injection.
            # Behavioral diffs from path changes are routing artifacts, not
            # evidence of SQL execution.  Time-based detection still works.
            if payload.category == "sqli" and ip_type in (
                InsertionPointType.URL_PATH, InsertionPointType.URL_PATH_FOLDER,
            ):
                return False, ""

            baseline_body = getattr(self, '_baseline_body', '')
            baseline_status = getattr(self, '_baseline_status', 200)
            baseline_headers = getattr(self, '_baseline_headers', {})
            variant_attrs = getattr(self, '_variant_attrs', set())
            if baseline_body:
                ignore = set(variant_attrs)

                # ── Check if payload is reflected (raw or encoded) ──────
                # On reflecting pages, ANY response diff (body, status code,
                # content type, tag structure) can be caused by input processing
                # rather than SQL execution.  Behavioral SQLi is unreliable
                # when the page echoes back the payload in any form.
                if payload.category == "sqli" and payload.value:
                    import html as _html
                    from urllib.parse import quote as _quote
                    reflected = (
                        payload.value in response_text
                        or _html.escape(payload.value) in response_text
                        or _quote(payload.value, safe='') in response_text
                    )
                    if reflected:
                        return False, ""

                diffs = responses_differ(
                    baseline_status, baseline_headers, baseline_body,
                    response_status, response_headers or {}, response_text,
                    ignore_attrs=ignore,
                )
                if diffs and is_blind_indicator(diffs, min_attrs=2):
                    diff_attrs = ', '.join(a.name for a in list(diffs.keys())[:5])
                    return True, (
                        f"Behavioral difference detected across {len(diffs)} stable response attributes "
                        f"({diff_attrs}). Indicates blind injection via response fingerprint divergence."
                    )

        return False, ""

    def _create_injection_finding(
        self,
        url: str,
        request: ParsedRequest,
        ip: InsertionPoint,
        payload: Payload,
        response,
        evidence: str,
    ) -> Finding:
        """Create an injection vulnerability finding"""

        category_names = {
            "sqli": "SQL Injection",
            "xss": "Cross-Site Scripting (XSS)",
            "cmdi": "Command Injection",
            "ssti": "Server-Side Template Injection",
            "path": "Path Traversal",
        }

        category_desc = {
            "sqli": "The application appears vulnerable to SQL injection. An attacker could extract, modify, or delete database contents.",
            "xss": "The application reflects user input without proper encoding. An attacker could execute JavaScript in victims' browsers.",
            "cmdi": "The application executes user-controlled input as system commands. An attacker could execute arbitrary commands on the server.",
            "ssti": "The application processes user input in a server-side template engine. An attacker could execute arbitrary code on the server.",
            "path": "The application allows traversing outside the intended directory. An attacker could read sensitive files from the server.",
        }

        remediation_map = {
            "sqli": "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
            "xss": "Encode output based on context (HTML, JavaScript, URL). Use Content-Security-Policy headers.",
            "cmdi": "Avoid passing user input to system commands. If necessary, use strict allowlisting.",
            "ssti": "Avoid passing user input to template engines. Use sandboxed template engines if needed.",
            "path": "Validate and sanitize file paths. Use allowlisting for permitted files/directories.",
        }

        cwe_map = {
            "sqli": "CWE-89",
            "xss": "CWE-79",
            "cmdi": "CWE-78",
            "ssti": "CWE-1336",
            "path": "CWE-22",
        }

        # Generate poc_curl command
        import shlex
        poc_curl = f"curl -sSk {shlex.quote(url)}"

        return self.create_finding(
            title=f"{category_names[payload.category]} in {ip.type.value}: {ip.name}",
            severity=payload.severity,
            confidence=(
                Confidence.FIRM if payload.detection == "time"
                else Confidence.TENTATIVE if payload.detection == "behavior"
                else Confidence.CERTAIN
            ),
            url=url,
            description=f"{category_desc[payload.category]}\n\nVulnerable parameter: {ip.name}\nPayload: {payload.value}\nDetection method: {payload.detection}",
            evidence=evidence,
            request=f"{request.method} {url}\n\nPayload: {payload.value}\nInjection point: {ip.name} ({ip.type.value})",
            response=f"HTTP {response.status_code}\n\n{response.text[:1000]}...",
            remediation=remediation_map.get(payload.category, "Implement proper input validation and output encoding."),
            references=[
                f"https://owasp.org/www-community/attacks/{payload.category.upper()}_Attacks" if payload.category != "path" else "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://portswigger.net/web-security",
            ],
            parameter=ip.name,
            payload=payload.value,
            cwe_id=cwe_map.get(payload.category),
            poc_curl=poc_curl,
        )

    async def quick_sqli_check(self, url: str) -> AsyncIterator[Finding]:
        """
        Quick SQLi check - just test URL params with basic payloads.
        Useful for rapid scanning.
        """
        ScanContext.from_url(url)
        request = self.insertion_detector.parse_request(
            method="GET",
            url=url,
            headers={"User-Agent": "Mozilla/5.0"},
            body=b"",
        )

        for name, value in request.url_params.items():
            ip = InsertionPoint(
                name=name,
                value=value,
                type=InsertionPointType.URL_PARAM,
                original_request=None,
                position=(0, 0),
            )

            # Just test single quote error
            payload = self.payloads["sqli"][0]  # single quote
            finding = await self._test_payload(request, ip, payload)
            if finding:
                yield finding
