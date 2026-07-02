"""
BEATRIX Business Logic Vulnerability Scanner

Born from: OWASP WSTG-BUSL (4.10 - Business Logic Testing)
Cross-referenced with: PCI DSS v4.0.1 Req 6.2.4, MITRE ATT&CK T1190

Business logic bugs are the #1 missed vulnerability class because:
- Automated scanners can't detect them (no signature/pattern)
- They require understanding of the application's PURPOSE
- Each one is unique to the application's workflow
- They often bypass all technical controls

TECHNIQUE:
1. Workflow circumvention — skip steps in multi-step processes
2. Rate limit testing — abuse lack of throttling on sensitive operations
3. Numeric boundary testing — INT overflow, negative values, MAX_INT
4. Race condition detection — TOCTOU on state-changing operations
5. Privilege boundary confusion — mix roles in multi-tenant systems
6. Feature abuse — use intended features for unintended purposes
7. Data validation bypass — inconsistent validation between client/server

OWASP Business Logic Tests (WSTG-BUSL-01 through BUSL-09):
- BUSL-01: Test business logic data validation
- BUSL-02: Test ability to forge requests
- BUSL-03: Test integrity checks
- BUSL-04: Test for process timing
- BUSL-05: Test number of times a function can be used / limits
- BUSL-06: Test circumvention of work flow
- BUSL-07: Test defenses against application misuse
- BUSL-08: Test upload of unexpected file types
- BUSL-09: Test upload of malicious files
- BUSL-10: Test payment functionality (see payment_scanner.py)

SEVERITY: HIGH-CRITICAL — logic bugs frequently = money
- Direct financial loss (price manipulation, free orders)
- Data breach via access control bypass
- Regulatory violations (PCI DSS, SOX, HIPAA)
- Reputation damage

CWE: CWE-840 (Business Logic Errors)
     CWE-841 (Improper Enforcement of Behavioral Workflow)
     CWE-799 (Improper Control of Interaction Frequency)
     CWE-770 (Allocation of Resources Without Limits)
     CWE-362 (Race Condition - TOCTOU)
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import AsyncIterator, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class LogicTestType(Enum):
    """Types of business logic tests"""
    WORKFLOW_BYPASS = auto()         # BUSL-06: Skip steps
    RATE_LIMIT_ABUSE = auto()        # BUSL-05: No throttling
    NUMERIC_BOUNDARY = auto()        # BUSL-01: INT overflow / negative
    RACE_CONDITION = auto()          # BUSL-04: TOCTOU
    PRIVILEGE_CONFUSION = auto()     # Mixed role actions
    DATA_CONSISTENCY = auto()        # BUSL-03: Integrity checks
    REQUEST_FORGERY = auto()         # BUSL-02: Forged requests
    FEATURE_ABUSE = auto()           # BUSL-07: Application misuse
    FILE_UPLOAD_LOGIC = auto()       # BUSL-08/09: Upload bypass


class RaceConditionStrategy(Enum):
    """Race condition exploitation strategies"""
    PARALLEL_REQUESTS = auto()       # Send N identical requests simultaneously
    LAST_BYTE_SYNC = auto()          # Send all-but-last-byte, release together
    PIPELINE = auto()                # HTTP pipelining for synchronized arrival
    CHUNK_TRANSFER = auto()          # Chunked encoding for timing control


@dataclass
class WorkflowStep:
    """A step in a multi-step workflow"""
    name: str
    url: str
    method: str = "GET"
    required_state: Optional[str] = None  # State from previous step
    produces_state: Optional[str] = None  # State for next step
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    expected_status: int = 200


@dataclass
class LogicTest:
    """A business logic test case"""
    name: str
    test_type: LogicTestType
    description: str
    severity: Severity
    owasp_ref: str = ""            # e.g., "BUSL-06"
    cwe_id: str = ""               # e.g., "CWE-841"


# =============================================================================
# SCANNER
# =============================================================================

class BusinessLogicScanner(BaseScanner):
    """
    Business Logic Vulnerability Scanner.

    Unlike technical vulnerability scanners, this module tests for
    LOGICAL FLAWS in how the application handles workflows, state
    transitions, and business rules.

    Key testing areas:
    1. Numeric boundary testing (negative quantities, INT overflow, zero prices)
    2. Rate limiting (can I call this 1000 times?)
    3. Workflow circumvention (can I skip step 2?)
    4. Race conditions (can I redeem this coupon twice simultaneously?)
    5. Data consistency (does the server actually re-validate prices?)
    6. Privilege confusion (can user A access user B's resources?)
    """

    name = "business_logic"
    description = "Business Logic Vulnerability Scanner (OWASP WSTG-BUSL)"
    version = "1.0.0"
    author = "BEATRIX"

    owasp_category = "WSTG-BUSL"
    mitre_technique = "T1190"

    checks = [
        "Numeric boundary testing (negative, zero, overflow)",
        "Rate limiting / function abuse",
        "Workflow circumvention",
        "Race condition detection",
        "Data consistency validation",
        "Parameter tampering (hidden fields, state params)",
        "HTTP method confusion",
    ]

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.race_concurrency = self.config.get("race_concurrency", 20)
        self.rate_test_count = self.config.get("rate_test_count", 50)
        self.numeric_test_values = self._build_numeric_test_values()

    def _build_numeric_test_values(self) -> List[Tuple[str, str, Severity]]:
        """
        Build numeric boundary test values.

        These values are designed to trigger:
        - Integer overflow on 32-bit and 64-bit signed integers
        - Negative value handling (negative quantities, prices)
        - Zero values (free items, zero-length allocations)
        - Floating point precision issues
        - String-to-number coercion bugs
        """
        return [
            # Negative values
            ("-1", "Negative value", Severity.HIGH),
            ("-100", "Large negative value", Severity.HIGH),
            ("-0.01", "Negative fractional", Severity.HIGH),
            ("-999999", "Very large negative", Severity.HIGH),

            # Zero
            ("0", "Zero value", Severity.MEDIUM),
            ("0.00", "Zero decimal", Severity.MEDIUM),
            ("0e0", "Scientific zero", Severity.MEDIUM),

            # Near-zero fractional
            ("0.001", "Near-zero fractional", Severity.MEDIUM),
            ("0.0000001", "Micro-fractional", Severity.MEDIUM),

            # Integer overflow (32-bit signed max = 2147483647)
            ("2147483647", "INT32_MAX", Severity.MEDIUM),
            ("2147483648", "INT32_MAX + 1 (overflow)", Severity.HIGH),
            ("-2147483648", "INT32_MIN", Severity.MEDIUM),
            ("-2147483649", "INT32_MIN - 1 (underflow)", Severity.HIGH),

            # 64-bit overflow
            ("9999999999999999", "Near INT64_MAX", Severity.HIGH),
            ("9223372036854775807", "INT64_MAX", Severity.MEDIUM),
            ("9223372036854775808", "INT64_MAX + 1", Severity.HIGH),

            # Floating point confusion
            ("1e308", "Float near MAX (may → Infinity)", Severity.HIGH),
            ("1e-308", "Float near MIN (may → 0)", Severity.MEDIUM),
            ("99999999999999999999999", "Exceeds all integer types", Severity.HIGH),
            ("NaN", "Not a Number literal", Severity.MEDIUM),
            ("Infinity", "Infinity literal", Severity.MEDIUM),
            ("-Infinity", "Negative Infinity", Severity.MEDIUM),

            # Type confusion
            ("true", "Boolean true (type juggling)", Severity.LOW),
            ("false", "Boolean false (type juggling)", Severity.LOW),
            ("null", "Null literal", Severity.MEDIUM),
            ("undefined", "Undefined literal", Severity.LOW),
            ("[]", "Empty array", Severity.LOW),
            ("{}", "Empty object", Severity.LOW),

            # Very long numeric strings
            ("9" * 100, "100-digit number (buffer/precision)", Severity.MEDIUM),

            # Special decimal precision
            ("0.1 + 0.2", "Floating point arithmetic string", Severity.LOW),
            ("1.0000000000000001", "Beyond float64 precision", Severity.MEDIUM),
        ]

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Run business logic tests against the target.

        Tests are organized by OWASP WSTG-BUSL category:
        1. Numeric boundaries (BUSL-01)
        2. Request forgery detection (BUSL-02)
        3. HTTP method confusion (BUSL-02)
        4. Rate limiting (BUSL-05)
        5. Data consistency (BUSL-03)
        """
        self.log(f"Starting Business Logic scan on {context.url}")
        self.log(f"Parameters: {list(context.parameters.keys())}")

        # Test 1: Numeric boundary testing on all parameters
        async for finding in self._test_numeric_boundaries(context):
            yield finding

        # Test 2: HTTP method confusion
        async for finding in self._test_method_confusion(context):
            yield finding

        # Test 3: Parameter pollution
        async for finding in self._test_parameter_pollution(context):
            yield finding

        # Test 4: Rate limiting
        async for finding in self._test_rate_limiting(context):
            yield finding

        # Test 5: Race conditions
        async for finding in self._test_race_conditions(context):
            yield finding

        self.log("Business logic scan complete")

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Passive detection of business logic indicators.

        Analyzes the response for:
        - Hidden form fields with state/price/quantity values
        - Client-side validation without server-side enforcement
        - Token/nonce patterns that may be predictable
        - Sequential identifiers vulnerable to enumeration
        """
        if context.response is None:
            return

        response_text = ""
        if hasattr(context.response, 'body'):
            response_text = context.response.body
        elif hasattr(context.response, 'text'):
            response_text = context.response.text

        # Detect hidden form fields with sensitive business data
        hidden_fields = re.findall(
            r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
            response_text, re.IGNORECASE
        )

        sensitive_field_patterns = {
            r'price|amount|total|cost|fee': "Price/amount field",
            r'discount|coupon|promo': "Discount/coupon field",
            r'quantity|qty|count': "Quantity field",
            r'role|admin|privilege|permission': "Role/privilege field",
            r'user_?id|account_?id|customer_?id': "User identifier field",
            r'status|state|step|phase': "Workflow state field",
        }

        for field_name, field_value in hidden_fields:
            for pattern, desc in sensitive_field_patterns.items():
                if re.search(pattern, field_name, re.IGNORECASE):
                    yield self.create_finding(
                        title=f"Hidden Form Field Contains Business Data: {field_name}",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        url=context.url,
                        description=(
                            f"A hidden form field '{field_name}' (value: '{field_value}') "
                            f"contains {desc} data. Hidden fields can be trivially "
                            f"modified by users.\n\n"
                            f"**Test:** Modify this value and submit the form. If the "
                            f"server accepts the modified value without re-validation, "
                            f"this is a business logic vulnerability.\n\n"
                            f"**Common attacks:**\n"
                            f"- Set price to 0 or negative\n"
                            f"- Change user ID to another user's\n"
                            f"- Skip workflow steps by manipulating state\n"
                            f"- Escalate privileges by changing role field"
                        ),
                        evidence=f"<input type='hidden' name='{field_name}' value='{field_value}'>",
                        references=[
                            "OWASP WSTG-BUSL-01",
                            "CWE-472: External Control of Assumed-Immutable Web Parameter",
                        ],
                    )
                    break

        # Detect sequential/predictable identifiers
        # Look for numeric IDs in URLs or parameters that could be enumerated
        for param_name, param_value in context.parameters.items():
            if re.match(r'^\d+$', param_value):
                id_val = int(param_value)
                if 1 <= id_val <= 999999:  # Reasonable ID range
                    for pattern in [r'id$', r'_id$', r'^id_', r'user', r'account', r'order']:
                        if re.search(pattern, param_name, re.IGNORECASE):
                            yield self.create_finding(
                                title=f"Sequential Identifier in Parameter: {param_name}={param_value}",
                                severity=Severity.LOW,
                                confidence=Confidence.TENTATIVE,
                                url=context.url,
                                description=(
                                    f"Parameter '{param_name}' contains a sequential numeric "
                                    f"identifier ({param_value}). Sequential IDs are vulnerable "
                                    f"to IDOR enumeration.\n\n"
                                    f"**Test:** Try {param_name}={id_val-1} and {param_name}={id_val+1} "
                                    f"to check if other users' data is accessible.\n\n"
                                    f"Consider using UUIDs instead of sequential integers."
                                ),
                                evidence=f"{param_name}={param_value}",
                                references=[
                                    "OWASP WSTG-BUSL-02",
                                    "CWE-639: Authorization Bypass Through User-Controlled Key",
                                ],
                            )
                            break

    # =========================================================================
    # NUMERIC BOUNDARY TESTING (BUSL-01)
    # =========================================================================

    async def _test_numeric_boundaries(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test all parameters with boundary values.

        The key insight: most applications validate on the client side but
        trust values that arrive at the server. We test if the server
        accepts values that should be logically impossible.
        """
        self.log("Testing numeric boundaries (BUSL-01)")

        # Identify parameters likely to accept numeric values
        numeric_param_patterns = [
            r'quantity|qty|count|num|number|amount',
            r'price|cost|total|subtotal|fee|rate',
            r'id|user_?id|item_?id|product_?id|order_?id',
            r'page|limit|offset|size|per_page|page_size',
            r'discount|coupon_value|credits',
            r'rating|score|rank|priority|weight',
        ]

        for param_name, original_value in context.parameters.items():
            # Check if this parameter looks numeric or matches patterns
            is_numeric_param = any(
                re.search(p, param_name, re.IGNORECASE)
                for p in numeric_param_patterns
            )
            is_numeric_value = bool(re.match(r'^-?\d+(\.\d+)?$', original_value))

            if not (is_numeric_param or is_numeric_value):
                continue

            self.log(f"  Numeric testing: {param_name}={original_value}")

            # Get baseline response
            baseline_response = await self.get(
                context.base_url + urlparse(context.url).path,
                params=context.parameters,
            )
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)

            # Test each boundary value
            for test_value, test_desc, test_severity in self.numeric_test_values:
                try:
                    params = dict(context.parameters)
                    params[param_name] = test_value

                    response = await self.get(
                        context.base_url + urlparse(context.url).path,
                        params=params,
                    )

                    # Analyze response — look for acceptance of invalid values
                    accepted = False
                    analysis = ""

                    if response.status_code == 200:
                        # Server accepted the value — check if it actually processed it
                        # vs just ignoring it / showing error in body

                        # Look for error indicators
                        error_patterns = [
                            r'invalid|error|fail|illegal|out.of.range|not.allowed',
                            r'must be|cannot|unable|exception',
                        ]
                        has_error = any(
                            re.search(p, response.text[:2000], re.IGNORECASE)
                            for p in error_patterns
                        )

                        if not has_error:
                            # Check content-length difference
                            resp_length = len(response.text)
                            length_diff = abs(resp_length - baseline_length)

                            if length_diff < baseline_length * 0.5:
                                # Response is similar size — may have been accepted
                                accepted = True
                                analysis = (
                                    f"Server returned HTTP 200 with similar response "
                                    f"(Δ{length_diff} bytes). The {test_desc} value "
                                    f"'{test_value}' appears to have been accepted."
                                )

                    elif response.status_code == baseline_status:
                        # Same status as baseline — might have been accepted
                        accepted = True
                        analysis = (
                            f"Server returned same status ({response.status_code}) "
                            f"as baseline. The {test_desc} value may be accepted."
                        )

                    if accepted and test_value in ["-1", "-100", "0", "-999999", "0.00"]:
                        yield self.create_finding(
                            title=f"Parameter '{param_name}' Accepts {test_desc}: {test_value}",
                            severity=test_severity,
                            confidence=Confidence.TENTATIVE,
                            url=context.url,
                            description=(
                                f"**Business Logic: {test_desc}**\n\n"
                                f"Parameter '{param_name}' (original: '{original_value}') "
                                f"accepted the value '{test_value}' without error.\n\n"
                                f"{analysis}\n\n"
                                f"**Potential Impact:**\n"
                                f"- Negative quantities → negative charges (refund)\n"
                                f"- Zero prices → free items\n"
                                f"- Integer overflow → unexpected behavior\n\n"
                                f"**Manual verification required** — check if the value actually "
                                f"affected business logic (e.g., check calculated total)."
                            ),
                            evidence=f"{param_name}={test_value} → HTTP {response.status_code}",
                            request=(
                                f"GET {context.url}?{param_name}={test_value}"
                            ),
                            references=[
                                "OWASP WSTG-BUSL-01",
                                "CWE-20: Improper Input Validation",
                            ],
                        )

                    await asyncio.sleep(0.3)

                except Exception as e:
                    self.log(f"    Error testing {test_desc}: {e}")

    # =========================================================================
    # HTTP METHOD CONFUSION (BUSL-02)
    # =========================================================================

    async def _test_method_confusion(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test if the endpoint responds differently to unexpected HTTP methods.

        Many frameworks route differently based on method. A GET endpoint
        that also responds to DELETE could be dangerous.
        """
        self.log("Testing HTTP method confusion (BUSL-02)")

        methods_to_test = ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        original_method = context.request.method.upper()

        # Baseline
        try:
            await self.request(original_method, context.url)
        except Exception:
            return

        for method in methods_to_test:
            if method == original_method:
                continue

            try:
                response = await self.request(method, context.url)

                # Interesting if: method accepted (200), or different behavior
                if response.status_code == 200 and method in ("DELETE", "PUT", "PATCH"):
                    yield self.create_finding(
                        title=f"Endpoint Accepts {method} Method (originally {original_method})",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        url=context.url,
                        description=(
                            f"The endpoint at {context.url} accepts {method} requests "
                            f"in addition to {original_method}.\n\n"
                            f"If this is unintended, it could allow:\n"
                            f"- DELETE: Unauthorized data deletion\n"
                            f"- PUT/PATCH: Unauthorized data modification\n"
                            f"- POST: Replay attacks / duplicate actions\n\n"
                            f"**Manual verification:** Confirm endpoint behavior differs per method."
                        ),
                        evidence=f"{method} {context.url} → HTTP {response.status_code}",
                        remediation=(
                            "1. Explicitly restrict HTTP methods per endpoint\n"
                            "2. Return 405 Method Not Allowed for unsupported methods\n"
                            "3. Include Allow header with supported methods"
                        ),
                        references=[
                            "OWASP WSTG-BUSL-02",
                            "CWE-749: Exposed Dangerous Method or Function",
                        ],
                    )

                await asyncio.sleep(0.3)

            except Exception:
                continue

    # =========================================================================
    # PARAMETER POLLUTION (BUSL-02)
    # =========================================================================

    async def _test_parameter_pollution(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test HTTP Parameter Pollution (HPP).

        Sending the same parameter multiple times can cause different behavior
        depending on the framework:
        - PHP/Apache: uses LAST value
        - ASP.NET/IIS: uses ALL values (comma-separated)
        - Python/Flask: uses FIRST value
        - Node.js/Express: uses FIRST value (or array)

        This inconsistency between front-end and back-end is exploitable.
        """
        self.log("Testing parameter pollution (BUSL-02)")

        for param_name, original_value in context.parameters.items():
            try:
                # Test with duplicate parameter
                # Build URL manually to include duplicate params
                base_path = context.base_url + urlparse(context.url).path
                other_params = {k: v for k, v in context.parameters.items() if k != param_name}

                # First value wins vs Last value wins
                test_url = base_path + "?"
                if other_params:
                    test_url += urlencode(other_params) + "&"
                test_url += f"{param_name}=FIRST&{param_name}=LAST"

                response = await self.get(test_url)

                if response.status_code == 200:
                    body = response.text.lower()

                    if "first" in body and "last" not in body:
                        priority = "FIRST"
                    elif "last" in body and "first" not in body:
                        priority = "LAST"
                    elif "first" in body and "last" in body:
                        priority = "BOTH (concatenated)"
                    else:
                        priority = "NEITHER (may be ignored)"

                    if priority in ("FIRST", "LAST", "BOTH (concatenated)"):
                        yield self.create_finding(
                            title=f"HTTP Parameter Pollution: {param_name} uses {priority} value",
                            severity=Severity.LOW,
                            confidence=Confidence.FIRM,
                            url=context.url,
                            description=(
                                f"When parameter '{param_name}' is sent twice, the server "
                                f"uses the {priority} value. This behavior can be exploited "
                                f"when a front-end proxy and back-end application handle "
                                f"duplicate parameters differently.\n\n"
                                f"**Attack scenario:** If a WAF validates the FIRST value "
                                f"but the application uses the LAST, the WAF check is bypassed."
                            ),
                            evidence=f"{param_name}=FIRST&{param_name}=LAST → uses {priority}",
                            references=[
                                "OWASP WSTG-BUSL-02",
                                "CWE-235: Improper Handling of Extra Parameters",
                            ],
                        )

                await asyncio.sleep(0.3)

            except Exception as e:
                self.log(f"  HPP error for {param_name}: {e}")

    # =========================================================================
    # RATE LIMITING (BUSL-05)
    # =========================================================================

    async def _test_rate_limiting(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test if the endpoint has rate limiting.

        Sends multiple rapid requests and checks if any are blocked.
        Lack of rate limiting on sensitive endpoints enables:
        - Brute force attacks (login, OTP, password reset)
        - Coupon/promo code brute force
        - Resource exhaustion
        - Enumeration attacks
        """
        self.log(f"Testing rate limiting (BUSL-05) — sending {self.rate_test_count} requests")

        # Detect what kind of endpoint this is
        url_lower = context.url.lower()
        is_sensitive = any(p in url_lower for p in [
            'login', 'auth', 'password', 'reset', 'otp', 'verify',
            'coupon', 'promo', 'discount', 'redeem', 'checkout',
            'transfer', 'payment', 'api/v',
        ])

        if not is_sensitive:
            self.log("  Skipping rate limit test — endpoint doesn't appear sensitive")
            return

        statuses: List[int] = []
        start_time = time.monotonic()
        blocked = False

        try:
            for i in range(self.rate_test_count):
                response = await self.get(context.url, params=context.parameters)
                statuses.append(response.status_code)

                # Check for rate limit response
                if response.status_code in (429, 503):
                    blocked = True
                    self.log(f"  Rate limited at request #{i+1}")
                    break

                # Check for CAPTCHA or block page indicators
                if any(indicator in response.text.lower() for indicator in [
                    'captcha', 'rate limit', 'too many requests',
                    'please try again later', 'blocked', 'security check',
                ]):
                    blocked = True
                    self.log(f"  Soft rate limit at request #{i+1}")
                    break

                # Don't sleep — we want to test rapid-fire

            elapsed = time.monotonic() - start_time
            rps = len(statuses) / elapsed if elapsed > 0 else 0

            if not blocked and len(statuses) >= self.rate_test_count:
                yield self.create_finding(
                    title="No Rate Limiting on Sensitive Endpoint",
                    severity=Severity.HIGH if is_sensitive else Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=context.url,
                    description=(
                        f"**No rate limiting detected** after {len(statuses)} consecutive "
                        f"requests at {rps:.0f} requests/second.\n\n"
                        f"All requests returned similar status codes "
                        f"({', '.join(str(s) for s in set(statuses))}). "
                        f"No HTTP 429, CAPTCHA, or blocking was observed.\n\n"
                        f"**Impact on this endpoint:**\n"
                        f"- Brute force attacks on authentication\n"
                        f"- Credential stuffing at scale\n"
                        f"- OTP/verification code brute force\n"
                        f"- Coupon/promo code enumeration\n"
                        f"- API abuse / resource exhaustion"
                    ),
                    evidence=(
                        f"{len(statuses)} requests in {elapsed:.1f}s ({rps:.0f} rps), "
                        f"0 blocked"
                    ),
                    remediation=(
                        "1. Implement rate limiting (e.g., 10 req/min for auth endpoints)\n"
                        "2. Use exponential backoff after failed attempts\n"
                        "3. Implement CAPTCHA after N failures\n"
                        "4. Consider account lockout after threshold\n"
                        "5. Use a WAF with rate limiting rules\n"
                        "6. Per PCI DSS Req 8.3.4: Lock account after ≤10 invalid attempts"
                    ),
                    references=[
                        "OWASP WSTG-BUSL-05",
                        "CWE-799: Improper Control of Interaction Frequency",
                        "CWE-307: Improper Restriction of Excessive Authentication Attempts",
                        "PCI DSS v4.0.1 Req 8.3.4",
                    ],
                )

            elif blocked:
                block_point = len(statuses)
                yield self.create_finding(
                    title=f"Rate Limiting Active (after {block_point} requests)",
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    url=context.url,
                    description=(
                        f"Rate limiting kicked in after {block_point} requests. "
                        f"This is GOOD security practice.\n\n"
                        f"Consider if {block_point} is sufficiently restrictive "
                        f"for the sensitivity of this endpoint."
                    ),
                )

        except Exception as e:
            self.log(f"  Rate limit test error: {e}")

    # =========================================================================
    # RACE CONDITIONS (BUSL-04)
    # =========================================================================

    async def _test_race_conditions(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test for race conditions using last-byte synchronization and HTTP/2
        single-packet attack.

        Last-byte sync: open N TCP connections, send all request bytes except
        the final byte, then release all final bytes simultaneously via a
        single asyncio event. This collapses the server-side processing window
        to near-zero and triggers TOCTOU bugs that asyncio.gather() misses.

        HTTP/2 single-packet: multiplex N requests into a single TCP frame with
        the END_STREAM flag set, forcing the server to process them at once.
        Falls back to last-byte sync over HTTP/1.1 when h2 is unavailable.
        """
        self.log(f"Testing race conditions (BUSL-04) — last-byte sync, {self.race_concurrency} concurrent requests")

        url_lower = context.url.lower()
        is_state_changing = any(p in url_lower for p in [
            'redeem', 'apply', 'coupon', 'discount', 'promo',
            'transfer', 'withdraw', 'deposit', 'checkout',
            'vote', 'like', 'follow', 'invite', 'claim',
            'purchase', 'buy', 'order', 'book', 'reserve',
        ])

        if not is_state_changing and context.request.method == "GET":
            self.log("  Skipping race condition test — endpoint doesn't appear state-changing")
            return

        # Try HTTP/2 single-packet first, fall back to last-byte sync over HTTP/1.1
        h2_available = False
        try:
            import h2  # noqa: F401  (python-h2 package)
            h2_available = True
        except ImportError:
            pass

        if h2_available:
            async for finding in self._race_http2_single_packet(context, is_state_changing):
                yield finding
        else:
            async for finding in self._race_last_byte_sync(context, is_state_changing):
                yield finding

    async def _race_last_byte_sync(
        self, context: ScanContext, is_state_changing: bool
    ) -> AsyncIterator[Finding]:
        """
        Last-byte synchronization race condition test over HTTP/1.1.

        1. Open N raw TCP connections (asyncio streams).
        2. Send everything except the final byte of each request.
        3. Release all final bytes simultaneously via asyncio.Event.
        4. Read all responses and detect concurrent success.
        """
        import asyncio
        import ssl
        from urllib.parse import urlparse, urlencode

        parsed = urlparse(context.url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        elif context.parameters and context.request.method == "GET":
            path = f"{path}?{urlencode(context.parameters)}"

        method = context.request.method or "POST"
        body = b""
        if context.request.method == "POST" and context.parameters:
            body = urlencode(context.parameters).encode()

        # Build the full raw HTTP/1.1 request bytes
        headers = [
            f"Host: {host}",
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
            "Connection: close",
        ]
        for k, v in (getattr(context.request, "headers", None) or {}).items():
            if k.lower() not in ("host", "content-type", "content-length", "connection"):
                headers.append(f"{k}: {v}")
        request_head = (
            f"{method} {path} HTTP/1.1\r\n"
            + "\r\n".join(headers)
            + "\r\n\r\n"
        ).encode()
        full_request = request_head + body

        # Split: send everything except the very last byte
        preamble = full_request[:-1]
        final_byte = full_request[-1:]

        n = self.race_concurrency
        release_event = asyncio.Event()
        responses_raw: List[Optional[bytes]] = [None] * n

        async def _connect_and_hold(idx: int) -> None:
            try:
                if use_tls:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=10
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=10
                    )
                writer.write(preamble)
                await writer.drain()
                # Hold until all connections are ready
                await asyncio.wait_for(release_event.wait(), timeout=10)
                writer.write(final_byte)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(8192), timeout=10)
                responses_raw[idx] = data
                writer.close()
            except Exception:
                responses_raw[idx] = None

        # Open all connections and prime them
        tasks = [asyncio.create_task(_connect_and_hold(i)) for i in range(n)]
        # Brief window for all connections to reach the hold point
        await asyncio.sleep(0.05)
        # Simultaneously release all final bytes
        release_event.set()
        await asyncio.gather(*tasks, return_exceptions=True)

        async for finding in self._analyze_race_responses(
            context, responses_raw, n, is_state_changing, strategy="last-byte-sync"
        ):
            yield finding

    async def _race_http2_single_packet(
        self, context: ScanContext, is_state_changing: bool
    ) -> AsyncIterator[Finding]:
        """
        HTTP/2 single-packet race condition attack.

        Multiplexes N HEADERS+DATA frames into a single TCP write with
        END_STREAM set on all of them. The server receives all request streams
        simultaneously in one TCP segment, minimising jitter.

        Falls back to last-byte sync on any h2 error.
        """
        import ssl
        from urllib.parse import urlparse, urlencode

        try:
            import h2.config
            import h2.connection
            import h2.events
        except ImportError:
            async for f in self._race_last_byte_sync(context, is_state_changing):
                yield f
            return

        parsed = urlparse(context.url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        elif context.parameters and context.request.method == "GET":
            path = f"{path}?{urlencode(context.parameters)}"

        method = context.request.method or "POST"
        body = b""
        if method == "POST" and context.parameters:
            body = urlencode(context.parameters).encode()

        n = self.race_concurrency
        responses_raw: List[Optional[bytes]] = []

        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            ssl_ctx.set_alpn_protocols(["h2"])

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=10
            )

            cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
            conn = h2.connection.H2Connection(config=cfg)
            conn.initiate_connection()
            writer.write(conn.data_to_send(65535))
            await writer.drain()

            # Build all HEADERS+DATA frames, accumulate in buffer, send as one write
            base_headers = [
                (":method", method),
                (":path", path),
                (":scheme", "https"),
                (":authority", host),
                ("content-type", "application/x-www-form-urlencoded"),
            ]
            stream_ids = []
            buf = b""
            for i in range(n):
                sid = conn.get_next_available_stream_id()
                stream_ids.append(sid)
                conn.send_headers(sid, base_headers, end_stream=(len(body) == 0))
                if body:
                    conn.send_data(sid, body, end_stream=True)
                buf += conn.data_to_send(65535)

            # Single TCP write — all streams arrive in one segment
            writer.write(buf)
            await writer.drain()

            # Read responses for all streams
            stream_responses: Dict[int, bytes] = {}
            deadline = asyncio.get_event_loop().time() + 15
            while len(stream_responses) < n and asyncio.get_event_loop().time() < deadline:
                try:
                    data = await asyncio.wait_for(reader.read(65535), timeout=5)
                    if not data:
                        break
                    events = conn.receive_data(data)
                    for ev in events:
                        if isinstance(ev, h2.events.DataReceived):
                            stream_responses.setdefault(ev.stream_id, b"")
                            stream_responses[ev.stream_id] += ev.data
                            conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                        elif isinstance(ev, h2.events.StreamEnded):
                            pass
                    out = conn.data_to_send(65535)
                    if out:
                        writer.write(out)
                        await writer.drain()
                except asyncio.TimeoutError:
                    break

            writer.close()
            for sid in stream_ids:
                responses_raw.append(stream_responses.get(sid))

        except Exception as e:
            self.log(f"  HTTP/2 single-packet failed ({e}), falling back to last-byte sync")
            async for f in self._race_last_byte_sync(context, is_state_changing):
                yield f
            return

        async for finding in self._analyze_race_responses(
            context, responses_raw, n, is_state_changing, strategy="h2-single-packet"
        ):
            yield finding

    async def _analyze_race_responses(
        self,
        context: ScanContext,
        responses_raw: List[Optional[bytes]],
        n: int,
        is_state_changing: bool,
        strategy: str,
    ) -> AsyncIterator[Finding]:
        """Parse raw HTTP response bytes and emit findings on concurrent success."""
        successful = []
        errors = 0
        status_counts: Dict[int, int] = {}

        for raw in responses_raw:
            if raw is None:
                errors += 1
                continue
            try:
                status_line = raw.split(b"\r\n", 1)[0].decode(errors="replace")
                parts = status_line.split(" ", 2)
                code = int(parts[1]) if len(parts) > 1 else 0
                status_counts[code] = status_counts.get(code, 0) + 1
                if 200 <= code < 300:
                    # Grab body (after double CRLF)
                    body = raw.split(b"\r\n\r\n", 1)[1][:500] if b"\r\n\r\n" in raw else b""
                    successful.append((code, body.decode(errors="replace")))
            except Exception:
                errors += 1

        self.log(
            f"  Race ({strategy}): {len(successful)}/{n} successful, "
            f"{errors} errors, statuses={status_counts}"
        )

        if len(successful) > 1 and is_state_changing:
            unique_bodies = len({body for _, body in successful})
            yield self.create_finding(
                title=f"Race Condition ({len(successful)}/{n} concurrent succeeded) [{strategy}]",
                severity=Severity.HIGH,
                confidence=Confidence.TENTATIVE,
                url=context.url,
                description=(
                    f"**Race Condition Test — {strategy}**\n\n"
                    f"- Strategy: {strategy}\n"
                    f"- Concurrent requests sent: {n}\n"
                    f"- Successful (2xx): {len(successful)}\n"
                    f"- Connection errors: {errors}\n"
                    f"- Status distribution: {status_counts}\n"
                    f"- Unique response bodies: {unique_bodies}\n\n"
                    f"Multiple concurrent requests to this state-changing endpoint "
                    f"all returned success. If this endpoint performs a one-time "
                    f"operation (coupon redemption, fund transfer, invite claim), "
                    f"this is a confirmed TOCTOU race condition.\n\n"
                    f"**Manual verification required:** confirm the operation executed "
                    f"more than once server-side (check balance, coupon status, order count)."
                ),
                evidence=(
                    f"{len(successful)}/{n} concurrent 2xx responses via {strategy}; "
                    f"{unique_bodies} unique body variants"
                ),
                remediation=(
                    "1. Use database-level locking (SELECT FOR UPDATE / advisory locks)\n"
                    "2. Issue idempotency keys and reject duplicate key reuse\n"
                    "3. Optimistic concurrency control (version columns)\n"
                    "4. Application-level mutex / Redis distributed lock\n"
                    "5. Atomic compare-and-swap operations at the DB layer"
                ),
                references=[
                    "OWASP WSTG-BUSL-04",
                    "PortSwigger Research: HTTP/2 Single-Packet Attack",
                    "CWE-362: Concurrent Execution using Shared Resource (TOCTOU)",
                    "CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition",
                ],
            )
