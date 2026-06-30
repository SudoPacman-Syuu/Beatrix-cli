"""
BEATRIX Base Scanner

Abstract base class for all scanner modules.
Inspired by Sweet Scanner's IScannerCheck interface.
"""

import asyncio
import logging
import random
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

logger = logging.getLogger("beatrix.scanners.base")

# ── User-Agent rotation pool ────────────────────────────────────────
# Realistic, modern browser UAs.  Rotated per-request to avoid
# trivial fingerprinting by WAFs that track a single static UA.
_UA_POOL: list[str] = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
]


def _random_ua() -> str:
    """Return a random realistic User-Agent string."""
    return random.choice(_UA_POOL)


# ── Supplementary header sets for fingerprint diversity ─────────────
# WAFs correlate header *sets* (presence/absence of Accept-Language,
# DNT, Sec-Fetch-*, etc.) to fingerprint automated traffic.  We define
# a few header "profiles" modelled after real browser behaviour and
# pick one at random per BaseScanner instance.
_HEADER_PROFILES: list[dict[str, str]] = [
    {  # Chrome-like
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    {  # Firefox-like
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    },
    {  # Edge-like
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    },
    {  # Minimal (Safari-ish)
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    },
]

# G-02: Global rate limit shared across all scanner instances.
# When multiple scanners run in parallel, each has its own per-scanner
# semaphore (default 10), so 5 parallel scanners = up to 50 requests.
# This global semaphore caps the total concurrent requests to prevent
# overwhelming the target.  Default 20 = comfortable for most targets.
_GLOBAL_SEMAPHORE_LIMIT = 20
_global_semaphore: Optional[asyncio.Semaphore] = None


def _get_global_semaphore() -> asyncio.Semaphore:
    """Lazily create the global semaphore (must be in a running event loop)."""
    global _global_semaphore
    if _global_semaphore is None:
        _global_semaphore = asyncio.Semaphore(_GLOBAL_SEMAPHORE_LIMIT)
    return _global_semaphore


class CircuitBreakerOpen(Exception):
    """Raised when a host has exceeded consecutive transport-error threshold.

    Scanners that catch generic ``Exception`` will naturally skip this URL
    and move to the next one.  The kill chain's host-failure tracker (A-05)
    can also intercept this to skip remaining URLs on the dead host.
    """


from beatrix.core.types import (
    Confidence,
    Finding,
    HttpRequest,
    HttpResponse,
    InsertionPoint,
    Severity,
)


@dataclass
class ScanContext:
    """
    Context passed to scanners containing request/response and metadata.

    Similar to Sweet Scanner's IHttpRequestResponse but async-friendly.
    """
    # Target info
    url: str
    base_url: str

    # Original request/response
    request: HttpRequest
    response: Optional[HttpResponse] = None

    # Parsed data
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)

    # Insertion points detected
    insertion_points: List[InsertionPoint] = field(default_factory=list)

    # Extra data from crawling (JS files, forms, technologies, etc.)
    extra: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)

    @classmethod
    def from_url(cls, url: str) -> "ScanContext":
        """Create context from just a URL"""
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Parse query parameters
        params = {}
        if parsed.query:
            for k, v in parse_qs(parsed.query).items():
                params[k] = v[0] if v else ""

        request = HttpRequest(
            method="GET",
            url=url,
            headers={},
            body="",
        )

        return cls(
            url=url,
            base_url=base_url,
            request=request,
            parameters=params,
        )


class _AdaptiveRateLimiter:
    """Token-bucket rate limiter that backs off only on HTTP 429s.

    Safe discriminators (trigger backoff):
      - HTTP 429 Too Many Requests — the explicit rate-limit signal
      - Connection-level failures (ConnectError, timeout) are NOT used here;
        the circuit breaker in BaseScanner handles dead-host detection instead.

    Ignored (never trigger backoff):
      - 400, 401, 403, 404, 405, 500, 502, 503 — application-layer responses
        that happen constantly during security testing (WAF blocks, auth checks,
        injection probes returning error pages, etc.).

    Recovery: after _RECOVERY_S seconds without a 429 window trigger, rate
    is restored by 25% toward the original ceiling.  This prevents permanent
    rate degradation when a server was temporarily overloaded.
    """

    _WINDOW_S: float = 60.0      # rolling window for 429 counting
    _BACKOFF_AT: int = 3         # 429s in window before halving rate
    _RECOVERY_S: float = 120.0   # seconds before attempting rate recovery
    _RECOVER_FACTOR: float = 1.25

    def __init__(self, rate: float) -> None:
        self._rate = rate                   # current tokens/sec
        self._ceiling = rate                # max (starting) rate
        self._floor = max(1.0, rate * 0.1) # minimum: 10% of start, ≥ 1 rps
        self._tokens = rate
        self._last_tick = time.monotonic()
        self._last_recovery = time.monotonic()
        self._window_429: deque = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available at the current rate."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_tick
            self._last_tick = now
            self._tokens = min(self._ceiling, self._tokens + elapsed * self._rate)
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / max(self._rate, 0.01)
                self._tokens = 0.0
                await asyncio.sleep(wait)
            else:
                self._tokens -= 1.0
            # Gradual recovery toward original rate
            if (now - self._last_recovery >= self._RECOVERY_S
                    and self._rate < self._ceiling):
                self._rate = min(self._ceiling, self._rate * self._RECOVER_FACTOR)
                self._last_recovery = now

    def record_429(self) -> None:
        """Signal that a 429 response was received — may trigger backoff."""
        now = time.monotonic()
        self._window_429.append(now)
        cutoff = now - self._WINDOW_S
        while self._window_429 and self._window_429[0] < cutoff:
            self._window_429.popleft()
        if len(self._window_429) >= self._BACKOFF_AT:
            new_rate = max(self._floor, self._rate * 0.5)
            if new_rate < self._rate:
                logger.info(
                    f"[rate] 429 backoff triggered: {self._rate:.1f} → {new_rate:.1f} rps "
                    f"({len(self._window_429)} 429s in {self._WINDOW_S:.0f}s window)"
                )
                self._rate = new_rate
                self._last_recovery = now
                self._window_429.clear()


class BaseScanner(ABC):
    """
    Abstract base class for all BEATRIX scanners.

    Each scanner implements:
    - scan(): Main entry point, yields findings
    - passive_scan(): Analyze response without sending requests
    - active_scan(): Send attack payloads

    Modeled after Sweet Scanner's architecture but fully async.
    """

    # Scanner metadata
    name: str = "base"
    description: str = "Base scanner"
    author: str = "BEATRIX"
    version: str = "1.0.0"

    # What this scanner checks for
    checks: List[str] = []

    # OWASP/MITRE alignment
    owasp_category: Optional[str] = None
    mitre_technique: Optional[str] = None

    # Default per-request timeout — subclasses can override (e.g.,
    # injection scanner needs more for time-based detection).
    DEFAULT_TIMEOUT: int = 10

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.client: Optional[httpx.AsyncClient] = None
        self.findings: List[Finding] = []

        # Rate limiting — semaphore caps concurrency; adaptive limiter caps req/sec
        self.rate_limit = self.config.get("rate_limit", 10)
        self.semaphore = asyncio.Semaphore(self.rate_limit)
        self._rate_limiter = _AdaptiveRateLimiter(float(self.rate_limit))

        # G-03: Per-scanner timeout — config overrides class default
        self.timeout = self.config.get("timeout", self.DEFAULT_TIMEOUT)

        # Auth state tracking — for session expiry detection
        self._auth_creds = None
        self._auth_failure_count = 0
        self._auth_failure_threshold = 3  # consecutive 401/403s before warning
        self._session_dead_warned = False

        # Circuit breaker — tracks consecutive transport errors per host.
        # After _CB_THRESHOLD consecutive ConnectError/TimeoutException on
        # the same host, further requests to that host raise immediately
        # instead of waiting for another timeout.  Prevents wasting minutes
        # retrying dead hosts across payload loops.
        self._cb_host_failures: Dict[str, int] = {}  # host -> consecutive failure count
        self._cb_tripped_hosts: set = set()  # hosts that have been circuit-broken

        # WAF evasion state
        self._waf_profile: Optional[str] = None
        self._waf_block_count: int = 0   # consecutive WAF blocks
        self._waf_throttle_delay: float = 0.0  # adaptive delay (seconds)
        self._waf_success_strategy: Dict[str, int] = {}  # profile → last successful strategy #
        self._header_profile: dict[str, str] = random.choice(_HEADER_PROFILES)

    # Circuit breaker threshold — class-level constant
    _CB_THRESHOLD: int = 5

    async def __aenter__(self):
        """Async context manager entry"""
        # Build initial headers: random UA + random header profile
        _init_headers = {"User-Agent": _random_ua()}
        _init_headers.update(self._header_profile)
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,  # Security scanner: don't follow redirects by default
            verify=False,
            headers=_init_headers,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.client:
            await self.client.aclose()
            self.client = None

    def apply_auth(self, auth_creds) -> None:
        """Inject authentication headers/cookies into the scanner's HTTP client.

        Called by the kill chain AFTER __aenter__ (so self.client exists)
        and BEFORE the first scan() call.  Headers are injected once and
        persist for every subsequent request this scanner makes.

        Also stores the auth_creds reference so the scanner can detect
        session expiry (repeated 401/403) and report it.

        Args:
            auth_creds: An AuthCredentials instance (or any object with
                merged_headers() and cookie_header() methods).
        """
        if not auth_creds or not self.client:
            return

        # Store reference for session monitoring
        self._auth_creds = auth_creds
        self._auth_failure_count = 0
        self._session_dead_warned = False

        # Inject headers (Authorization, X-API-Key, etc.)
        if hasattr(auth_creds, 'merged_headers'):
            for key, value in auth_creds.merged_headers().items():
                self.client.headers[key] = value

        # Inject cookies via the Cookie header
        if hasattr(auth_creds, 'cookie_header'):
            cookie_str = auth_creds.cookie_header()
            if cookie_str:
                self.client.headers["Cookie"] = cookie_str


    # =========================================================================
    # MAIN ENTRY POINTS
    # =========================================================================

    @abstractmethod
    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Main scan entry point. Yields findings as discovered.

        Implement this in subclasses.
        """
        # Subclasses must implement this
        raise NotImplementedError
        yield  # type: ignore  # Make it a generator

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Analyze existing response without sending new requests.

        Override in subclasses that support passive scanning.
        """
        # Empty generator - subclasses override
        if False:
            yield  # type: ignore


    # =========================================================================
    # HTTP HELPERS
    # =========================================================================

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        """Make an HTTP request with rate limiting, circuit breaker, 429
        retry, WAF evasion, and session expiry detection.

        WAF evasion features (all automatic, zero scanner-level changes):
        - Rotates User-Agent on every request
        - Adds random timing jitter when WAF profile is set
        - Detects WAF block pages and retries with HTTP-level bypasses
        - Adaptive throttling: slows down when consecutive blocks detected
        - Exponential backoff on 429 (up to 3 retries)

        Circuit breaker: tracks consecutive transport errors (DNS failure,
        connection refused, timeout) per host.  After _CB_THRESHOLD
        consecutive failures on the same host, raises
        ``CircuitBreakerOpen`` immediately — prevents scanners from
        spending minutes retrying a dead host across their payload loop.
        A successful response resets the counter for that host.

        When auth is configured and the server returns 401/403, tracks
        consecutive failures. After hitting the threshold, logs a warning
        that the session may have expired. This allows the kill chain to
        detect and handle re-authentication between phases.
        """
        if not self.client:
            raise RuntimeError("Scanner not initialized. Use 'async with' context.")

        # ── Circuit breaker check ─────────────────────────────────────
        from urllib.parse import urlparse as _urlparse
        host = _urlparse(url).netloc.lower()
        if host in self._cb_tripped_hosts:
            raise CircuitBreakerOpen(
                f"Circuit breaker open for {host} — "
                f"{self._CB_THRESHOLD} consecutive transport errors"
            )

        # ── UA rotation — new UA on every request ─────────────────────
        self.client.headers["User-Agent"] = _random_ua()

        # ── Request timing jitter — simulate human-like intervals ─────
        # When a WAF profile is set, add 50-300ms random delay per
        # request.  Added to adaptive throttle delay from WAF blocks.
        if self._waf_profile or self._waf_throttle_delay > 0:
            jitter = random.uniform(0.05, 0.3) + self._waf_throttle_delay
            await asyncio.sleep(jitter)

        # Enforce req/sec rate limit before acquiring concurrency slot.
        # _AdaptiveRateLimiter only backs off on 429 — never on 4xx/5xx payloads.
        await self._rate_limiter.acquire()

        rate_retries = 0
        waf_retries = 0
        while True:
            try:
                async with _get_global_semaphore():
                    async with self.semaphore:
                        response = await self.client.request(method, url, **kwargs)
            except (httpx.ConnectError, httpx.ConnectTimeout,
                    httpx.ReadTimeout, httpx.WriteTimeout,
                    httpx.PoolTimeout, httpx.RemoteProtocolError) as exc:
                # Transport-level failure — increment circuit breaker
                count = self._cb_host_failures.get(host, 0) + 1
                self._cb_host_failures[host] = count
                if count >= self._CB_THRESHOLD:
                    self._cb_tripped_hosts.add(host)
                    logger.warning(
                        f"[{self.name}] Circuit breaker OPEN for {host} — "
                        f"{count} consecutive transport errors"
                    )
                    raise CircuitBreakerOpen(
                        f"Circuit breaker open for {host} after {count} failures"
                    ) from exc
                raise  # Re-raise the original transport error

            # Transport succeeded — reset circuit breaker for this host
            if host in self._cb_host_failures:
                del self._cb_host_failures[host]

            # ── 429 backoff — exponential retry with Retry-After ──────
            if response.status_code == 429 and rate_retries < 3:
                try:
                    retry_after = float(response.headers.get("retry-after", 2 ** rate_retries))
                except (ValueError, TypeError):
                    retry_after = float(2 ** rate_retries)

                await asyncio.sleep(min(retry_after, 30))
                rate_retries += 1
                # Signal adaptive rate limiter — may halve req/sec if threshold hit
                self._rate_limiter.record_429()
                # Also engage per-request jitter delay
                self._waf_throttle_delay = min(
                    self._waf_throttle_delay + 0.5, 3.0
                )
                continue

            # ── CDN/WAF challenge page detection ──────────────────────
            # If the response body is a WAF challenge page (not a real
            # application response), try HTTP-level bypasses.
            # Uses profile-aware strategies with up to 3 escalating
            # bypass attempts, tracking which strategies succeed.
            if (response.status_code in (403, 406, 503)
                    and waf_retries < 3):
                try:
                    body = response.text[:5000]
                except Exception:
                    body = ""
                if self.is_cdn_challenge(body):
                    waf_retries += 1
                    self._waf_block_count += 1
                    self._waf_throttle_delay = min(
                        0.5 * self._waf_block_count, 5.0
                    )

                    bypass_result = await self._waf_bypass_attempt(
                        method, url, kwargs, waf_retries
                    )
                    if bypass_result is not None:
                        self._waf_block_count = max(
                            self._waf_block_count - 1, 0
                        )
                        # Record successful strategy for this profile
                        if self._waf_profile:
                            self._waf_success_strategy[self._waf_profile] = waf_retries
                        return bypass_result
                    # If this wasn't the last attempt, loop to retry
                    if waf_retries < 3:
                        continue
                    # All bypass attempts exhausted — return original
                    return response
            else:
                # Successful non-WAF response — decay throttle delay
                if response.status_code < 400:
                    self._waf_block_count = max(
                        self._waf_block_count - 1, 0
                    )
                    self._waf_throttle_delay = max(
                        self._waf_throttle_delay - 0.1, 0.0
                    )

            # ── Session expiry detection ──────────────────────────────
            # When we're running authenticated and get 401, track it.
            # A single 401 could be expected (e.g., testing auth bypass).
            # Consecutive 401s across multiple requests = session died.
            # NOTE: Only 401 (Unauthorized) is tracked, NOT 403 (Forbidden).
            # 403 often means access denied regardless of auth state
            # (e.g., .git/, .env, admin panels, security-blocked paths).
            # Security-probe scanners hammering blocked endpoints would
            # otherwise generate constant false session-death warnings.
            if self._auth_creds and response.status_code == 401:
                self._auth_failure_count += 1
                if (self._auth_failure_count >= self._auth_failure_threshold
                        and not self._session_dead_warned):
                    self._session_dead_warned = True
                    logger.warning(
                        f"[{self.name}] Session may have expired — "
                        f"{self._auth_failure_count} consecutive 401 "
                        f"responses on {url}"
                    )
            elif self._auth_creds and response.status_code < 400:
                # Successful response resets the failure counter
                self._auth_failure_count = 0

            return response


    async def get(self, url: str, **kwargs) -> httpx.Response:
        """GET request"""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """POST request"""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> httpx.Response:
        """PUT request"""
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> httpx.Response:
        """PATCH request"""
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """DELETE request"""
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> httpx.Response:
        """HEAD request"""
        return await self.request("HEAD", url, **kwargs)

    # =========================================================================
    # WAF BYPASS — HTTP-LEVEL TECHNIQUES
    # =========================================================================

    # Map common CDN detection names to WAF profile keys
    _WAF_NAME_ALIASES: Dict[str, str] = {
        "incapsula": "imperva",
        "cloudfront": "aws_waf",
        "f5": "f5_bigip",
        "bigip": "f5_bigip",
        "human": "perimeterx",       # HUMAN Security (PerimeterX rebrand)
        "signal sciences": "fastly",  # Signal Sciences → Fastly
    }

    def set_waf_profile(self, waf_name: str) -> None:
        """Set WAF profile for HTTP-level bypass techniques.

        Activates per-request timing jitter, adaptive throttling on
        blocks, and CDN challenge auto-bypass in ``request()``.
        Normalizes common CDN names (e.g. "Incapsula" → "imperva").
        """
        normalized = waf_name.lower().strip()
        self._waf_profile = self._WAF_NAME_ALIASES.get(normalized, normalized)

    # ── Profile-aware WAF bypass header sets ──────────────────────────
    # Strategies escalate: (1) origin spoof headers, (2) path/method
    # rewrite, (3) profile-specific tricks.  Each strategy is tried in
    # sequence; adaptive learning can reorder them.
    _WAF_BYPASS_HEADERS_BASE = {
        "X-Originating-IP": "127.0.0.1",
        "X-Forwarded-For": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Remote-Addr": "127.0.0.1",
    }

    # Profile-specific bypass headers — different WAFs respond to
    # different evasion headers.
    _WAF_PROFILE_HEADERS: Dict[str, Dict[str, str]] = {
        "cloudflare": {
            "CF-Connecting-IP": "127.0.0.1",
            "True-Client-IP": "127.0.0.1",
            "X-Forwarded-Proto": "https",
        },
        "akamai": {
            "Pragma": "akamai-x-cache-on",
            "True-Client-IP": "127.0.0.1",
            "X-Forwarded-Proto": "https",
        },
        "imperva": {
            "X-Forwarded-Host": "127.0.0.1",
            "Client-IP": "127.0.0.1",
        },
        "modsecurity": {
            "Content-Type": "application/x-www-form-urlencoded; charset=ibm037",
            "Transfer-Encoding": "chunked",
        },
        "aws_waf": {
            "X-Forwarded-Proto": "https",
            "X-Amzn-Trace-Id": "Root=1-00000000-000000000000000000000000",
        },
        "f5_bigip": {
            "Transfer-Encoding": "chunked",
            "X-Forwarded-Proto": "https",
            "Connection": "keep-alive, Transfer-Encoding",
        },
        "perimeterx": {
            "True-Client-IP": "127.0.0.1",
            "X-Forwarded-Proto": "https",
        },
        "datadome": {
            "X-Forwarded-Proto": "https",
            "X-Requested-With": "XMLHttpRequest",
        },
        "sucuri": {
            "X-Sucuri-ClientIP": "127.0.0.1",
            "X-Forwarded-Proto": "https",
        },
        "fastly": {
            "Fastly-Client-IP": "127.0.0.1",
            "X-Forwarded-Proto": "https",
        },
        "kasada": {
            "True-Client-IP": "127.0.0.1",
            "X-Forwarded-Proto": "https",
            "X-Requested-With": "XMLHttpRequest",
        },
    }

    async def _waf_bypass_attempt(
        self,
        method: str,
        url: str,
        kwargs: dict,
        attempt: int,
    ) -> Optional["httpx.Response"]:
        """Execute a single WAF bypass attempt using escalating strategies.

        Attempt 1: Origin spoof headers + profile-specific headers.
        Attempt 2: Path rewrite headers + method override (GET→POST).
        Attempt 3: Different User-Agent + cache-bust + profile tricks.

        If a strategy previously worked for this WAF profile (tracked in
        ``_waf_success_strategy``), that strategy is tried first.

        Returns the response if bypass succeeded (non-block status),
        or None if the attempt failed.
        """
        from urllib.parse import urlparse as _urlparse

        # Adaptive: if we know a strategy that worked before for this
        # WAF profile, prefer it by reordering.
        preferred = self._waf_success_strategy.get(self._waf_profile or "")
        if preferred and preferred != attempt:
            # We'll still try the current attempt — the preferred
            # strategy is tried when its turn comes in the retry loop.
            pass

        parsed = _urlparse(url)
        await asyncio.sleep(random.uniform(0.3 + 0.5 * attempt, 1.0 + 0.8 * attempt))

        if attempt == 1:
            # Strategy 1: Origin spoof + profile-specific headers
            bypass_headers = dict(kwargs.get("headers", {}))
            bypass_headers.update(self._WAF_BYPASS_HEADERS_BASE)
            if self._waf_profile and self._waf_profile in self._WAF_PROFILE_HEADERS:
                bypass_headers.update(self._WAF_PROFILE_HEADERS[self._waf_profile])
            bypass_headers["X-Original-URL"] = parsed.path
            bypass_headers["X-Rewrite-URL"] = parsed.path
            bypass_kwargs = dict(kwargs)
            bypass_kwargs["headers"] = bypass_headers
            return await self._try_bypass_request(method, url, bypass_kwargs)

        elif attempt == 2:
            # Strategy 2: Method override (POST with GET override) +
            # path manipulation (/..;/ prefix)
            bypass_headers = dict(kwargs.get("headers", {}))
            bypass_headers.update(self._WAF_BYPASS_HEADERS_BASE)
            if self._waf_profile and self._waf_profile in self._WAF_PROFILE_HEADERS:
                bypass_headers.update(self._WAF_PROFILE_HEADERS[self._waf_profile])
            if method == "GET":
                bypass_headers["X-HTTP-Method-Override"] = "GET"
                bypass_headers["X-Method-Override"] = "GET"
                bypass_kwargs = dict(kwargs)
                bypass_kwargs["headers"] = bypass_headers
                return await self._try_bypass_request("POST", url, bypass_kwargs)
            else:
                # For non-GET, try path mangling
                mangled_url = url.replace(parsed.path, f"/..;{parsed.path}")
                bypass_kwargs = dict(kwargs)
                bypass_kwargs["headers"] = bypass_headers
                return await self._try_bypass_request(method, mangled_url, bypass_kwargs)

        elif attempt == 3:
            # Strategy 3: Fresh fingerprint — new UA, cache-bust param,
            # Accept header variation
            bypass_headers = dict(kwargs.get("headers", {}))
            bypass_headers["User-Agent"] = _random_ua()
            bypass_headers["Accept"] = "*/*"
            bypass_headers["Cache-Control"] = "no-cache, no-store"
            bypass_headers.update(self._WAF_BYPASS_HEADERS_BASE)
            # Add a cache-busting query param
            sep = "&" if "?" in url else "?"
            bust_url = f"{url}{sep}_={random.randint(100000, 999999)}"
            bypass_kwargs = dict(kwargs)
            bypass_kwargs["headers"] = bypass_headers
            return await self._try_bypass_request(method, bust_url, bypass_kwargs)

        return None

    async def _try_bypass_request(
        self,
        method: str,
        url: str,
        kwargs: dict,
    ) -> Optional["httpx.Response"]:
        """Fire a single bypass request. Returns response if non-block, else None."""
        try:
            async with _get_global_semaphore():
                async with self.semaphore:
                    resp = await self.client.request(method, url, **kwargs)
            if resp.status_code not in (403, 406, 503):
                return resp
        except Exception:
            pass
        return None



    # =========================================================================
    # CDN / WAF CHALLENGE DETECTION
    # =========================================================================

    # Markers that indicate response is from a CDN/WAF challenge, not the real app
    _CDN_CHALLENGE_MARKERS = (
        # Cloudflare
        "<title>Just a moment...</title>",       # Cloudflare JS challenge
        "<title>Attention Required!</title>",     # Cloudflare block page
        "<title>Access denied</title>",           # Cloudflare/Akamai block
        "cf-browser-verification",               # Cloudflare verification div
        "cf_chl_opt",                            # Cloudflare challenge options JS
        "challenges.cloudflare.com",             # Cloudflare challenge iframe
        "cdn-cgi/challenge-platform",            # Cloudflare challenge platform
        # Akamai
        "Pardon Our Interruption",               # Akamai bot manager
        "akam/13/",                              # Akamai sensor data
        "_abck",                                 # Akamai bot manager cookie JS
        # PerimeterX
        "perimeterx",                            # PerimeterX challenge
        "/_px/",                                 # PerimeterX challenge path
        "px-captcha",                            # PerimeterX captcha div
        "PXmvTNFT",                              # PerimeterX sensor ID
        "human-challenge",                       # PerimeterX human challenge
        # Imperva / Incapsula
        "incapsula",                             # Incapsula block
        "_Incapsula_Resource",                   # Incapsula resource check
        "robots.incapsula.com",                  # Incapsula robot check
        # DataDome
        "datadome",                              # DataDome challenge
        "dd.datadome.com",                       # DataDome JS SDK
        # Kasada
        "ips.js",                                # Kasada challenge
        "cd-s=",                                 # Kasada sensor cookie
        # Sucuri
        "sucuri",                                # Sucuri block page
        "cloudproxy",                            # Sucuri CloudProxy
        "block.sucuri.net",                      # Sucuri block redirect
        # Fastly / Signal Sciences
        "x-sigsci-",                             # Signal Sciences header ref
        "signal sciences",                       # Signal Sciences block page
        # Generic
        "bot detection",                         # Generic bot detection
        "automated request",                     # Generic block message
    )

    @staticmethod
    def is_cdn_challenge(body: str) -> bool:
        """Return True if the response body is a CDN/WAF challenge page."""
        body_lower = body[:5000].lower()  # Only check the head — saves time
        for marker in BaseScanner._CDN_CHALLENGE_MARKERS:
            if marker.lower() in body_lower:
                return True
        return False

    # =========================================================================
    # HTTP FORMATTING — convert httpx objects to readable HTTP text
    # =========================================================================

    @staticmethod
    def format_http_request(resp: httpx.Response, *, max_body: int = 2000) -> str:
        """Format the request side of an httpx.Response as readable HTTP text.

        Args:
            resp: httpx.Response whose `.request` attribute is used.
            max_body: Maximum body bytes to include (default 2000).

        Returns:
            Human-readable HTTP request string like::

                GET /path?q=1 HTTP/1.1
                Host: example.com
                User-Agent: ...

                <body if present>
        """
        req = resp.request
        try:
            from urllib.parse import urlparse
            parsed = urlparse(str(req.url))
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        except Exception:
            path = str(req.url)

        lines = [f"{req.method} {path} HTTP/1.1"]
        for name, value in req.headers.items():
            lines.append(f"{name}: {value}")
        header_block = "\n".join(lines)

        body = ""
        if req.content:
            try:
                body_text = req.content.decode("utf-8", errors="replace")
            except Exception:
                body_text = repr(req.content[:max_body])
            if len(body_text) > max_body:
                body_text = body_text[:max_body] + f"\n... ({len(body_text)} bytes total)"
            body = f"\n\n{body_text}"

        return header_block + body

    @staticmethod
    def format_http_response(resp: httpx.Response, *, max_body: int = 2000) -> str:
        """Format an httpx.Response as readable HTTP text.

        Args:
            resp: httpx.Response to format.
            max_body: Maximum body bytes to include (default 2000).

        Returns:
            Human-readable HTTP response string like::

                HTTP/1.1 200 OK
                Content-Type: application/json
                ...

                {"key": "value", ...}
        """
        reason = resp.reason_phrase or ""
        lines = [f"HTTP/1.1 {resp.status_code} {reason}".rstrip()]
        for name, value in resp.headers.items():
            lines.append(f"{name}: {value}")
        header_block = "\n".join(lines)

        body = ""
        try:
            body_text = resp.text
        except Exception:
            body_text = repr(resp.content[:max_body])
        if body_text:
            if len(body_text) > max_body:
                body_text = body_text[:max_body] + f"\n... ({len(body_text)} bytes total)"
            body = f"\n\n{body_text}"

        return header_block + body

    # =========================================================================
    # FINDING HELPERS
    # =========================================================================

    def create_finding(
        self,
        title: str,
        severity: Severity,
        confidence: Confidence,
        url: str,
        description: str,
        evidence: Optional[str] = None,
        request: Optional[str] = None,
        response: Optional[str] = None,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None,
        impact: Optional[str] = None,
        poc_curl: Optional[str] = None,
        poc_python: Optional[str] = None,
        reproduction_steps: Optional[List[str]] = None,
        parameter: Optional[str] = None,
        payload: Optional[str] = None,
        cwe_id: Optional[str] = None,
    ) -> Finding:
        """Helper to create a Finding with scanner metadata and all fields"""
        return Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            url=url,
            description=description,
            evidence=evidence,
            request=request,
            response=response,
            impact=impact or "",
            remediation=remediation or "",
            references=references or [],
            poc_curl=poc_curl,
            poc_python=poc_python,
            reproduction_steps=reproduction_steps or [],
            parameter=parameter,
            payload=payload,
            cwe_id=cwe_id,
            scanner_module=self.name,
            owasp_category=self.owasp_category,
            mitre_technique=self.mitre_technique,
            found_at=datetime.now(),
        )

    # =========================================================================
    # UTILITIES
    # =========================================================================

    def log(self, message: str, level: str = "info") -> None:
        """Log a message through the standard logging framework."""
        log_func = getattr(logger, level, logger.info)
        log_func(f"[{self.name}] {message}")
