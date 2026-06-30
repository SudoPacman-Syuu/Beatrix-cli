"""
BEATRIX Auto-Login Engine

Performs automated credential-based authentication against targets.
Like Burp Suite's login functionality: give it username + password,
it DISCOVERS the login endpoint from the target itself, authenticates,
and captures the session cookies/tokens for use throughout the scan.

How Burp Suite actually works:
- It observes traffic — crawls the site, follows links
- Finds login forms and API routes from page content + JS bundles
- Doesn't hardcode endpoint lists — it DISCOVERS them from the target
- Then replays credentials against the discovered endpoint

Our approach (matching Burp):
1. Crawl the target — find <a> tags with login/signin text, forms
2. Analyse JS bundles — extract API routes containing auth/login/session
3. Extract login forms from HTML — detect fields + action URLs
4. Try all DISCOVERED endpoints (not a hardcoded list)
5. Judge success by response: cookies set, tokens returned, status codes

Supports:
- HTML form login (multipart, urlencoded)
- JSON API login (the dominant modern pattern)
- SPA applications (React, Vue, Angular, Next.js) via JS bundle mining
- CSRF token extraction and injection
- Auto-detection of login URL, field names, and method
- Session cookie + auth token capture from response
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, unquote

import httpx

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger("beatrix.auto_login")


# ── WAF detection signatures ──────────────────────────────────────────────

WAF_SIGNATURES = [
    "cloudflare", "cf-browser-verification", "challenge-platform",
    "jschl_vc", "cf_chl_opt", "just a moment", "checking your browser",
    "ddos-guard", "sucuri", "incapsula", "imperva", "akamai",
    "cf-ray",  # Cloudflare header value often in body too
    "blocked by security policy", "request blocked", "security challenge",
    "access denied", "bot detection",
]


# ── Patterns for DISCOVERING login endpoints from page content ─────────────

# Words in link text / button text / href that indicate a login page
LOGIN_LINK_WORDS = re.compile(
    r'\b(?:log\s*in|sign\s*in|signin|login|authenticate|member\s*area|my\s*account)\b',
    re.IGNORECASE,
)

# Patterns in URLs that indicate auth/login endpoints
AUTH_URL_PATTERN = re.compile(
    r'(?:login|signin|sign-in|sign_in|auth|authenticate|session|oauth|token|sso)',
    re.IGNORECASE,
)

# API route patterns in JS code that look like auth endpoints
JS_AUTH_ROUTE_PATTERNS = [
    # Explicit fetch/axios calls to auth endpoints
    re.compile(r'(?:fetch|axios\.post|\.post|\.request)\s*\(\s*["\']([^"\']*(?:login|signin|sign-in|auth(?:enticate)?|session|token|oauth)[^"\']*)["\']', re.IGNORECASE),
    # String assignments / route definitions containing auth paths
    re.compile(r'["\'](\/?(?:api\/)?(?:v\d+\/)?(?:auth|users?|account|sessions?)\/(?:login|signin|sign-in|authenticate|token|session|oauth)[^"\']*)["\']', re.IGNORECASE),
    # Standalone auth paths
    re.compile(r'["\'](\/(?:api\/)?(?:v\d+\/)?(?:login|signin|sign-in|authenticate|auth|token|oauth|session))\s*["\']', re.IGNORECASE),
    # Next.js / SPA route patterns
    re.compile(r'["\'](\/?(?:api\/)?auth\/(?:callback|signin|login|credentials|session)[^"\']*)["\']', re.IGNORECASE),
    # GraphQL auth mutations
    re.compile(r'mutation\s+\w*(?:login|signin|auth)\w*', re.IGNORECASE),
]

# CSRF token field/header names
CSRF_FIELD_NAMES = [
    "csrf_token", "_csrf", "csrfmiddlewaretoken", "csrf",
    "authenticity_token", "_token", "token", "__RequestVerificationToken",
    "X-CSRF-Token", "x-csrf-token", "XSRF-TOKEN",
]

CSRF_HEADER_NAMES = [
    "x-csrf-token", "x-xsrf-token", "x-csrftoken",
]

# Auth token patterns in JSON responses
AUTH_TOKEN_KEYS = [
    "token", "access_token", "accessToken", "auth_token",
    "authToken", "jwt", "session_token", "sessionToken",
    "id_token", "idToken", "bearer", "api_token",
    "authorization", "refresh_token", "refreshToken",
]

# ── OTP / 2FA detection ───────────────────────────────────────────────

# Keywords in JSON responses that indicate an OTP/2FA step is required
OTP_RESPONSE_KEYWORDS = [
    "verification code", "verify your", "otp", "one-time",
    "two-factor", "2fa", "mfa", "multi-factor",
    "check your email", "check your inbox", "sent a code",
    "enter the code", "enter code", "confirmation code",
    "verify_token", "verification_required", "requires_verification",
    "needs_verification", "second_factor", "challenge_required",
    "email_verification", "sms_verification", "authenticator",
]

# JSON keys that indicate OTP is required
OTP_RESPONSE_KEYS = [
    "requires_2fa", "requires_verification", "needs_otp",
    "two_factor_required", "mfa_required", "challenge",
    "verification_required", "requires_otp", "needs_verification",
    "2fa_required", "otp_required", "second_factor_required",
]

# Common OTP submission endpoints (relative to base URL)
OTP_SUBMIT_PATHS = [
    "/api/auth/verify", "/api/auth/2fa", "/api/auth/otp",
    "/api/verify", "/api/2fa", "/api/otp",
    "/api/auth/verify-otp", "/api/auth/confirm",
    "/api/auth/challenge", "/api/auth/mfa",
    "/auth/verify", "/auth/2fa", "/auth/otp",
    "/verify", "/2fa", "/otp", "/confirm",
    "/api/v1/auth/verify", "/api/v1/auth/2fa",
    "/api/v2/auth/verify", "/api/v2/auth/2fa",
]

# All JSON payload field-name combos to try
JSON_FIELD_COMBOS = [
    ("email", "password"),
    ("username", "password"),
    ("login", "password"),
    ("user", "password"),
    ("identifier", "password"),
    ("account", "password"),
    ("user_email", "password"),
    ("email_address", "password"),
    ("username", "pass"),
    ("email", "pass"),
]

# Username field names for HTML form detection
USERNAME_FIELD_NAMES = [
    "email", "username", "user", "login", "user_email",
    "user_login", "login_email", "identifier", "account",
    "userid", "user_id", "name", "uname", "emailOrUsername",
]

# Password field names for HTML form detection
PASSWORD_FIELD_NAMES = [
    "password", "pass", "passwd", "user_password",
    "login_password", "pwd", "secret", "passphrase",
]


@dataclass
class LoginResult:
    """Result of an auto-login attempt."""
    success: bool
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    method_used: str = ""       # "form" | "json" | "browser"
    login_url: str = ""
    message: str = ""
    token: Optional[str] = None
    otp_required: bool = False   # Server asked for OTP/2FA
    otp_context: Optional[Dict[str, Any]] = None  # Context for OTP submission


@dataclass
class DiscoveredEndpoint:
    """A login endpoint discovered from the target."""
    url: str
    source: str          # "html_link", "html_form", "js_bundle", "js_inline", "meta_redirect"
    method: str = "auto" # "json", "form", "auto"
    confidence: float = 0.5
    form_fields: Optional[Dict[str, str]] = None  # Pre-extracted form fields if from HTML form


class AutoLoginEngine:
    """
    Discovers login endpoints from the target, then authenticates.

    Unlike brute-force endpoint lists, this engine works like Burp Suite:
    it crawls the target, analyses HTML and JS bundles, discovers where
    the login endpoint actually is, then tries to authenticate there.
    """

    def __init__(
        self,
        target: str,
        username: str,
        password: str,
        login_url: Optional[str] = None,
        login_method: Optional[str] = None,       # "form" | "json" | "auto"
        username_field: Optional[str] = None,
        password_field: Optional[str] = None,
        timeout: float = 30.0,
        interactive: bool = True,                  # Allow stdin prompts (OTP)
    ):
        self.target = target
        self.username = username
        self.password = password
        self.login_url = login_url
        self.login_method = login_method or "auto"
        self.username_field = username_field
        self.password_field = password_field
        self.timeout = timeout
        self.interactive = interactive

        # Normalize target to base URL
        if "://" not in self.target:
            self.target = f"https://{self.target}"
        parsed = urlparse(self.target)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.domain = parsed.netloc

    async def login(self) -> LoginResult:
        """
        Discover login endpoints and authenticate.

        1. If login_url provided, try it directly
        2. Otherwise, crawl the target + JS bundles to discover endpoints
        3. Try all discovered endpoints (highest confidence first)
        4. If WAF blocks httpx, fall back to Playwright (real browser)
        """
        waf_detected = False
        endpoints_tried = False
        endpoint_found_but_creds_wrong = False

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        ) as client:
            # If user specified a login URL, try it directly first
            if self.login_url:
                target_url = self.login_url
                if "://" not in target_url:
                    target_url = urljoin(self.base_url, target_url)

                result = await self._try_endpoint(client, target_url, self.login_method)
                if result.success:
                    return result
                # If user-specified login_url returned OTP result, propagate it
                if result.otp_required:
                    return result
                if "waf" in result.message.lower() or "cloudflare" in result.message.lower():
                    waf_detected = True
                else:
                    logger.info(f"User-specified login URL {target_url} failed, discovering alternatives...")

            # ── Phase 1: Discover endpoints ──────────────────────────
            if not waf_detected:
                logger.info(f"Discovering login endpoints on {self.base_url}...")
                endpoints = await self._discover_endpoints(client)

                if endpoints:
                    # Sort by confidence (highest first)
                    endpoints.sort(key=lambda e: e.confidence, reverse=True)

                    discovered = [e for e in endpoints if e.source != "fallback"]
                    fallback = [e for e in endpoints if e.source == "fallback"]
                    if discovered:
                        logger.info(f"Discovered {len(discovered)} endpoints from page content" +
                                    (f" + {len(fallback)} fallback paths" if fallback else ""))
                    else:
                        logger.info(f"Using {len(fallback)} well-known API fallback paths (site may be WAF-protected)")

                    for ep in endpoints[:10]:
                        logger.info(f"  [{ep.confidence:.1f}] {ep.url} (via {ep.source})")

                    # ── Phase 2: Try each discovered endpoint ────────────
                    endpoints_tried = True
                    endpoint_found_but_creds_wrong = False
                    waf_blocked_count = 0
                    for ep in endpoints:
                        method = ep.method if ep.method != "auto" else self.login_method
                        result = await self._try_endpoint(client, ep.url, method, ep.form_fields)
                        if result.success:
                            return result

                        # OTP required — the creds were accepted, just need verification
                        if result.otp_required:
                            return result

                        if "waf" in result.message.lower() or "cloudflare" in result.message.lower():
                            waf_blocked_count += 1
                        elif any(kw in result.message.lower() for kw in (
                            "credentials rejected", "endpoint found",
                            "invalid credentials", "login failed",
                        )):
                            endpoint_found_but_creds_wrong = True

                    if endpoint_found_but_creds_wrong:
                        # Don't bail out — a 401 from httpx may be due to missing
                        # captcha/fingerprint/nonce that only the real browser
                        # provides. Fall through to browser login before giving up.
                        logger.info("httpx login rejected — trying browser login as fallback "
                                    "(endpoint may require captcha/JS tokens)")

                    if waf_blocked_count > 0:
                        waf_detected = True
                        logger.info(f"WAF blocked {waf_blocked_count} endpoint(s) — switching to browser login")

        # ── Phase 3: Browser-based login (Playwright) ────────────────
        # Used when WAF blocks httpx, discovery found nothing, or httpx got rejected
        if waf_detected or not endpoints_tried or endpoint_found_but_creds_wrong:
            logger.info("Attempting browser-based login...")
            browser_result = await self._try_browser_login()
            if browser_result.success or "rejected" in browser_result.message.lower():
                return browser_result

            # Browser also failed
            if waf_detected:
                return LoginResult(
                    success=False,
                    message=f"WAF/Cloudflare blocks automated requests to {self.base_url}. "
                            f"Browser login also failed: {browser_result.message}",
                )
            if endpoint_found_but_creds_wrong:
                return LoginResult(
                    success=False,
                    message=f"Login endpoint(s) found on {self.base_url} but credentials were rejected "
                            f"by both httpx and browser. Verify your username/email and password. "
                            f"Browser: {browser_result.message}",
                )

        return LoginResult(
            success=False,
            message=f"Could not authenticate against {self.base_url}. "
                    f"Use --login-url to specify the exact login endpoint.",
        )

    # =====================================================================
    # ENDPOINT DISCOVERY — the core difference from brute-force
    # =====================================================================

    async def _discover_endpoints(self, client: httpx.AsyncClient) -> List[DiscoveredEndpoint]:
        """
        Discover login endpoints by crawling the target.

        Sources:
        1. HTML <a> links with login/signin text or href
        2. HTML <form> elements with password fields
        3. JavaScript bundles — mine API routes containing auth/login
        4. <meta> refresh / JS redirects to login pages
        5. Inline <script> tags with auth routes
        """
        endpoints: List[DiscoveredEndpoint] = []
        seen_urls: Set[str] = set()

        # ── Fetch the home page ──────────────────────────────────────
        home_body = ""
        home_status = 0
        try:
            home_resp = await client.get(self.base_url)
            home_body = home_resp.text
            home_status = home_resp.status_code
            logger.info(f"Home page: HTTP {home_status}, {len(home_body)} bytes")

            # Detect Cloudflare / WAF challenge pages
            if any(sig in home_body.lower() for sig in [
                "cloudflare", "cf-browser-verification", "challenge-platform",
                "jschl_vc", "cf_chl_opt", "just a moment",
                "checking your browser", "ddos-guard", "sucuri",
            ]):
                logger.warning("WAF/Cloudflare challenge detected — page content unreliable for discovery")
        except Exception as e:
            logger.warning(f"Could not fetch home page: {e}")

        # ── Source 1: HTML links ─────────────────────────────────────
        self._discover_from_html_links(home_body, endpoints, seen_urls)

        # ── Source 2: HTML forms with password fields ────────────────
        self._discover_from_html_forms(home_body, self.base_url, endpoints, seen_urls)

        # ── Source 3: Meta redirects / JS redirects ──────────────────
        self._discover_from_redirects(home_body, endpoints, seen_urls)

        # ── Source 4: JS bundles ─────────────────────────────────────
        js_urls = self._extract_js_urls(home_body)
        if js_urls:
            await self._discover_from_js_bundles(client, js_urls, endpoints, seen_urls)

        # ── Source 5: Inline <script> tags ───────────────────────────
        self._discover_from_inline_scripts(home_body, endpoints, seen_urls)

        # ── Source 6: Follow discovered login pages and extract forms ──
        link_endpoints = [ep for ep in endpoints if ep.source == "html_link"]
        for ep in link_endpoints[:5]:
            try:
                page_resp = await client.get(ep.url)
                if page_resp.status_code == 200:
                    self._discover_from_html_forms(
                        page_resp.text, ep.url, endpoints, seen_urls,
                    )
                    self._discover_from_inline_scripts(
                        page_resp.text, endpoints, seen_urls,
                    )
                    login_js = self._extract_js_urls(page_resp.text)
                    new_js = [u for u in login_js if u not in js_urls]
                    if new_js:
                        await self._discover_from_js_bundles(
                            client, new_js, endpoints, seen_urls,
                        )
            except Exception:
                continue

        # ── Fallback: well-known API paths (WAF-protected or JS-heavy sites) ──
        if not endpoints:
            logger.info("Discovery found nothing — trying well-known API login paths as fallback")
            self._generate_fallback_endpoints(endpoints, seen_urls)

        return endpoints

    def _generate_fallback_endpoints(
        self, endpoints: List[DiscoveredEndpoint], seen: Set[str],
    ):
        """
        Generate fallback endpoints from well-known API conventions.

        Only called when crawl-based discovery returns zero results
        (typically because the site is behind a WAF like Cloudflare).
        These get LOW confidence so discovered endpoints always win.
        """
        fallback_paths = [
            # Versioned API patterns (v1/v2 — common on modern platforms)
            "/api/v1/auth/login",
            "/api/v2/auth/login",
            "/api/v1/login",
            "/api/v2/login",
            "/api/v1/session",
            "/api/v2/session",
            # Unversioned API
            "/api/auth/login",
            "/api/auth/signin",
            "/api/login",
            "/api/signin",
            "/api/session",
            "/api/auth/session",
            "/api/authenticate",
            # OAuth / token
            "/oauth/token",
            "/auth/token",
            "/token",
            # Non-API paths
            "/auth/login",
            "/auth/signin",
            "/login",
            "/signin",
            "/session",
            "/account/login",
            "/users/sign_in",
            "/user/login",
        ]
        for path in fallback_paths:
            url = urljoin(self.base_url, path)
            if url not in seen:
                seen.add(url)
                # JSON for /api/ paths, auto for others
                method = "json" if "/api/" in path else "auto"
                endpoints.append(DiscoveredEndpoint(
                    url=url, source="fallback",
                    method=method, confidence=0.4,
                ))

    def _discover_from_html_links(
        self, html: str, endpoints: List[DiscoveredEndpoint], seen: Set[str],
    ):
        """Find <a> tags whose text or href suggests a login page."""
        for match in re.finditer(
            r'<a\s[^>]*href=["\']([^"\'#]+)["\'][^>]*>(.*?)</a>',
            html, re.IGNORECASE | re.DOTALL,
        ):
            href, text = match.group(1), match.group(2)
            text_clean = re.sub(r'<[^>]+>', '', text).strip()

            text_match = LOGIN_LINK_WORDS.search(text_clean)
            href_match = AUTH_URL_PATTERN.search(href)

            if text_match or href_match:
                url = href if href.startswith("http") else urljoin(self.base_url, href)
                url = url.split("#")[0]
                if url not in seen:
                    seen.add(url)
                    conf = 0.9 if (text_match and href_match) else 0.7
                    endpoints.append(DiscoveredEndpoint(
                        url=url, source="html_link",
                        method="auto", confidence=conf,
                    ))

        # onclick / data-href / data-url attributes
        for match in re.finditer(
            r'(?:onclick|data-href|data-url)\s*=\s*["\']([^"\']+)["\']',
            html, re.IGNORECASE,
        ):
            url_val = match.group(1)
            if AUTH_URL_PATTERN.search(url_val):
                url = url_val if url_val.startswith("http") else urljoin(self.base_url, url_val)
                url = url.split("#")[0]
                if url not in seen:
                    seen.add(url)
                    endpoints.append(DiscoveredEndpoint(
                        url=url, source="html_link",
                        method="auto", confidence=0.6,
                    ))

    def _discover_from_html_forms(
        self, html: str, page_url: str,
        endpoints: List[DiscoveredEndpoint], seen: Set[str],
    ):
        """Find <form> elements that contain password fields."""
        for form_match in re.finditer(
            r'<form\s[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL,
        ):
            form_html = form_match.group(0)
            form_body = form_match.group(1)

            has_password = bool(re.search(
                r'<input[^>]*type=["\']password["\']', form_body, re.IGNORECASE,
            ))
            if not has_password:
                continue

            action_match = re.search(
                r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE,
            )
            action = action_match.group(1) if action_match else page_url
            if not action:
                action = page_url
            url = action if action.startswith("http") else urljoin(page_url, action)
            url = url.split("#")[0]

            form_fields = self._extract_form_fields(form_body)

            if url not in seen:
                seen.add(url)
                endpoints.append(DiscoveredEndpoint(
                    url=url, source="html_form",
                    method="form", confidence=0.95,
                    form_fields=form_fields,
                ))

    def _discover_from_redirects(
        self, html: str, endpoints: List[DiscoveredEndpoint], seen: Set[str],
    ):
        """Find meta refresh or JS window.location redirects to login pages."""
        for match in re.finditer(
            r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\';\s]+)',
            html, re.IGNORECASE,
        ):
            url = match.group(1)
            if AUTH_URL_PATTERN.search(url):
                full_url = url if url.startswith("http") else urljoin(self.base_url, url)
                full_url = full_url.split("#")[0]
                if full_url not in seen:
                    seen.add(full_url)
                    endpoints.append(DiscoveredEndpoint(
                        url=full_url, source="meta_redirect",
                        method="auto", confidence=0.8,
                    ))

        for match in re.finditer(
            r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
            html, re.IGNORECASE,
        ):
            url = match.group(1)
            if AUTH_URL_PATTERN.search(url):
                full_url = url if url.startswith("http") else urljoin(self.base_url, url)
                full_url = full_url.split("#")[0]
                if full_url not in seen:
                    seen.add(full_url)
                    endpoints.append(DiscoveredEndpoint(
                        url=full_url, source="meta_redirect",
                        method="auto", confidence=0.7,
                    ))

    def _extract_js_urls(self, html: str) -> List[str]:
        """Extract JavaScript file URLs from HTML."""
        js_urls: List[str] = []

        for match in re.finditer(
            r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']',
            html, re.IGNORECASE,
        ):
            src = match.group(1)
            url = src if src.startswith("http") else urljoin(self.base_url, src)
            js_urls.append(url)

        for match in re.finditer(
            r'["\']((?:/_next/static|/static/js|/assets|/js)/[^"\']+\.js)["\']',
            html, re.IGNORECASE,
        ):
            path = match.group(1)
            url = urljoin(self.base_url, path)
            if url not in js_urls:
                js_urls.append(url)

        return js_urls

    async def _discover_from_js_bundles(
        self, client: httpx.AsyncClient, js_urls: List[str],
        endpoints: List[DiscoveredEndpoint], seen: Set[str],
    ):
        """Download JS bundles and mine them for auth-related API routes."""
        for js_url in js_urls[:20]:
            try:
                resp = await client.get(js_url, headers={"Accept": "*/*"})
                if resp.status_code != 200:
                    continue
                code = resp.text
                if not code or len(code) < 50:
                    continue
            except Exception:
                continue

            for pattern in JS_AUTH_ROUTE_PATTERNS:
                for match in pattern.finditer(code):
                    path = match.group(1) if match.lastindex else match.group(0)
                    path = path.strip().rstrip(',').rstrip(')')
                    if not path or len(path) < 3:
                        continue
                    if not path.startswith("/") and "://" not in path:
                        path = "/" + path

                    url = path if path.startswith("http") else urljoin(self.base_url, path)
                    url = url.split("#")[0]
                    if url not in seen:
                        seen.add(url)
                        method = "json" if "/api/" in path.lower() else "auto"
                        endpoints.append(DiscoveredEndpoint(
                            url=url, source="js_bundle",
                            method=method, confidence=0.8,
                        ))
                        logger.info(f"  JS bundle → discovered auth endpoint: {url}")

            # base URL + route concatenation patterns
            base_url_match = re.search(
                r'baseURL\s*[:=]\s*["\']([^"\']+)["\']', code, re.IGNORECASE,
            )
            if base_url_match:
                api_base = base_url_match.group(1)
                for match in re.finditer(
                    r'\.(?:post|put)\s*\(\s*["\']([^"\']*(?:login|signin|auth|session|token)[^"\']*)["\']',
                    code, re.IGNORECASE,
                ):
                    rel_path = match.group(1)
                    full_url = urljoin(api_base + "/", rel_path.lstrip("/"))
                    full_url = full_url.split("#")[0]
                    if full_url not in seen:
                        seen.add(full_url)
                        endpoints.append(DiscoveredEndpoint(
                            url=full_url, source="js_bundle",
                            method="json", confidence=0.85,
                        ))
                        logger.info(f"  JS bundle (baseURL) → discovered: {full_url}")

    def _discover_from_inline_scripts(
        self, html: str, endpoints: List[DiscoveredEndpoint], seen: Set[str],
    ):
        """Mine inline <script> blocks for auth routes."""
        for match in re.finditer(
            r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL,
        ):
            code = match.group(1)
            if not code or len(code) < 20:
                continue

            for pattern in JS_AUTH_ROUTE_PATTERNS:
                for route_match in pattern.finditer(code):
                    path = route_match.group(1) if route_match.lastindex else route_match.group(0)
                    path = path.strip().rstrip(',').rstrip(')')
                    if not path or len(path) < 3:
                        continue
                    if not path.startswith("/") and "://" not in path:
                        path = "/" + path

                    url = path if path.startswith("http") else urljoin(self.base_url, path)
                    url = url.split("#")[0]
                    if url not in seen:
                        seen.add(url)
                        method = "json" if "/api/" in path.lower() else "auto"
                        endpoints.append(DiscoveredEndpoint(
                            url=url, source="js_inline",
                            method=method, confidence=0.75,
                        ))

    # =====================================================================
    # BROWSER-BASED LOGIN (Playwright) — bypasses WAF/Cloudflare
    # =====================================================================

    async def _try_browser_login(self) -> LoginResult:
        """
        Use a real headless browser to login.

        This bypasses Cloudflare/WAF challenges that block httpx.
        The browser navigates to the site, finds the login form/page,
        fills credentials, submits, and captures session cookies.
        """
        if not PLAYWRIGHT_AVAILABLE:
            return LoginResult(
                success=False,
                message="Playwright not available — cannot bypass WAF. "
                        "Install with: pip install playwright && playwright install chromium",
            )

        logger.info("Attempting browser-based login (Playwright)...")

        # Ensure Playwright can find browsers installed by another user (e.g., codespace vs root)
        import os
        if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
            for candidate in [
                os.path.expanduser("~/.cache/ms-playwright"),
                "/home/codespace/.cache/ms-playwright",
                "/root/.cache/ms-playwright",
            ]:
                if os.path.isdir(candidate):
                    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = candidate
                    logger.info(f"Using Playwright browsers from {candidate}")
                    break

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                )
                page = await context.new_page()

                try:
                    # Step 1: Navigate to the site — browser solves Cloudflare challenge
                    logger.info(f"Browser: navigating to {self.base_url}...")
                    await page.goto(self.base_url, wait_until="domcontentloaded", timeout=30000)
                    # Wait for Cloudflare challenge to resolve (Turnstile can take 5-15s)
                    await asyncio.sleep(8)

                    # Step 2: Find the login page
                    login_page_url = await self._browser_find_login_page(page)
                    if login_page_url and login_page_url != page.url:
                        logger.info(f"Browser: navigating to login page {login_page_url}...")
                        await page.goto(login_page_url, wait_until="domcontentloaded", timeout=30000)
                        await asyncio.sleep(5)

                    # Step 3: Find and fill the login form
                    filled = await self._browser_fill_credentials(page)
                    if not filled:
                        await page.close()
                        await browser.close()
                        return LoginResult(
                            success=False,
                            message="Browser could not find login form fields on the page.",
                        )

                    # Step 4: Submit the form
                    await self._browser_submit_form(page)
                    await asyncio.sleep(3)  # Wait for auth response

                    # Step 5: Capture cookies
                    cookies = await context.cookies()
                    cookie_dict = {c["name"]: c["value"] for c in cookies}

                    # Check if any session cookies were set
                    session_names = {
                        "session", "sessionid", "session_id", "sid", "token",
                        "auth", "jwt", "connect.sid", "PHPSESSID", "JSESSIONID",
                        "laravel_session", "_session_id",
                    }
                    has_session = any(
                        c["name"].lower() in session_names
                        for c in cookies
                    )

                    # Also check current URL — did we leave the login page?
                    current_url = page.url
                    left_login = not any(
                        kw in current_url.lower()
                        for kw in ["login", "signin", "sign-in", "auth"]
                    )

                    # Check page for success indicators
                    page_text = await page.text_content("body") or ""
                    page_lower = page_text.lower()
                    has_success_text = any(
                        w in page_lower
                        for w in ["dashboard", "welcome", "logged in", "sign out",
                                  "logout", "my account", "profile"]
                    )

                    # Check for error text scoped to the login form/modal area,
                    # not the entire page (full SPAs contain "invalid" etc. in
                    # unrelated contexts).
                    has_error_text = False
                    try:
                        dialog_el = await page.query_selector(
                            'dialog, [role="dialog"], [role="modal"], '
                            '.modal, .login-form, form:has(input[type="password"])'
                        )
                        if dialog_el:
                            form_text = (await dialog_el.text_content() or "").lower()
                        else:
                            form_text = ""
                        error_phrases = [
                            "invalid username", "invalid password",
                            "invalid credentials", "invalid email",
                            "incorrect password", "incorrect username",
                            "wrong password", "login failed",
                            "bad credentials", "authentication failed",
                        ]
                        has_error_text = any(p in form_text for p in error_phrases)
                    except Exception:
                        pass

                    # Session cookies / URL change take priority over error text
                    if has_session or left_login or has_success_text:
                        logger.info(f"Browser login succeeded! Captured {len(cookie_dict)} cookies")

                        # Also try to extract auth tokens from localStorage
                        headers: Dict[str, str] = {}
                        token = None
                        try:
                            for key in AUTH_TOKEN_KEYS:
                                val = await page.evaluate(
                                    f"localStorage.getItem('{key}') || sessionStorage.getItem('{key}')"
                                )
                                if val and len(val) > 10:
                                    token = val
                                    headers["Authorization"] = f"Bearer {val}"
                                    break
                        except Exception:
                            pass

                        await page.close()
                        await browser.close()

                        parts = []
                        if cookie_dict:
                            parts.append(f"{len(cookie_dict)} cookies")
                        if headers:
                            parts.append(f"{len(headers)} headers")
                        if token:
                            parts.append("auth token")

                        return LoginResult(
                            success=True,
                            cookies=cookie_dict,
                            headers=headers,
                            method_used="browser",
                            login_url=current_url,
                            token=token,
                            message=f"Browser login successful — captured {', '.join(parts) if parts else 'session'}",
                        )

                    await page.close()
                    await browser.close()

                    # No session cookies detected — check for clear error text
                    if has_error_text:
                        return LoginResult(
                            success=False,
                            cookies=cookie_dict,
                            message="Browser login: credentials were rejected by the application.",
                        )

                    if cookie_dict:
                        return LoginResult(
                            success=True,
                            cookies=cookie_dict,
                            method_used="browser",
                            login_url=current_url,
                            message=f"Browser login likely successful — captured {len(cookie_dict)} cookies (verify manually)",
                        )

                    return LoginResult(
                        success=False,
                        message="Browser login: no session cookies or tokens captured after form submission.",
                    )

                except Exception as e:
                    try:
                        await page.close()
                    except Exception:
                        pass
                    await browser.close()
                    return LoginResult(success=False, message=f"Browser login error: {e}")

        except Exception as e:
            return LoginResult(success=False, message=f"Playwright launch failed: {e}")

    async def _browser_find_login_page(self, page) -> Optional[str]:
        """Find the login page URL from the current page using Playwright."""
        # Check if we're already on a login page
        current_lower = page.url.lower()
        if any(kw in current_lower for kw in ["login", "signin", "sign-in", "auth/login"]):
            return page.url

        # Look for login links
        try:
            login_link = await page.evaluate("""
                () => {
                    const links = document.querySelectorAll('a, button');
                    for (const el of links) {
                        const text = (el.textContent || '').trim().toLowerCase();
                        const href = el.getAttribute('href') || '';
                        if (/\\b(log\\s*in|sign\\s*in|signin|login)\\b/i.test(text) ||
                            /\\b(log\\s*in|sign\\s*in|signin|login)\\b/i.test(href)) {
                            if (el.tagName === 'A' && href) return href;
                            // For buttons, try clicking and return null to indicate click happened
                            el.click();
                            return '__clicked__';
                        }
                    }
                    return null;
                }
            """)
        except Exception:
            login_link = None

        if login_link == "__clicked__":
            # Button was clicked — wait for modal/navigation to render a password field
            try:
                await page.wait_for_selector(
                    'input[type="password"], input[type="email"], input[name="email"], input[name="username"]',
                    timeout=10000,
                )
            except Exception:
                await asyncio.sleep(3)  # Fallback sleep if no field appears
            return page.url
        elif login_link:
            if login_link.startswith("http"):
                return login_link
            return urljoin(self.base_url, login_link)

        # Try common paths
        for path in ["/login", "/signin", "/auth/login"]:
            try:
                test_url = urljoin(self.base_url, path)
                resp = await page.goto(test_url, wait_until="domcontentloaded", timeout=30000)
                await asyncio.sleep(5)  # Let SPA render + Cloudflare resolve
                if resp and resp.status in (200, 302):
                    # Check if this page has a password field
                    has_password = await page.query_selector('input[type="password"]')
                    if has_password:
                        return page.url
            except Exception:
                continue

        return None

    async def _browser_fill_credentials(self, page) -> bool:
        """Find credential fields and fill them in the browser.

        Handles both single-step forms (email + password visible together)
        and multi-step forms (email first → continue → password appears).
        """
        # Wait a moment for any SPA rendering
        await asyncio.sleep(1)

        # Find the username/email field first — on multi-step forms the
        # password field won't exist yet.
        username_selectors = [
            f'input[name="{name}"]' for name in USERNAME_FIELD_NAMES
        ] + [
            'input[type="email"]',
            'input[type="text"]',
            'input:not([type])',  # HTML inputs default to text when type is omitted
        ]

        username_field = None
        for selector in username_selectors:
            try:
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    username_field = el
                    break
            except Exception:
                continue

        # If no username field, try waiting for one to render
        if not username_field:
            try:
                username_field = await page.wait_for_selector(
                    'input[type="email"], input[name="email"], input[name="username"], input[type="text"]',
                    timeout=10000,
                )
            except Exception:
                logger.warning("Browser: no username/email field found on page")
                return False

        # Fill email/username
        try:
            await username_field.fill(self.username)
            await asyncio.sleep(0.5)
        except Exception as e:
            logger.warning(f"Browser: could not fill username: {e}")
            return False

        # Check if password field is already visible (single-step form)
        password_field = await page.query_selector('input[type="password"]')
        if password_field:
            try:
                if await password_field.is_visible():
                    await password_field.fill(self.password)
                    await asyncio.sleep(0.3)
                    logger.info("Browser: credentials filled (single-step form)")
                    return True
            except Exception:
                pass

        # ── Multi-step form: submit email first, then wait for password ──
        logger.info("Browser: password field not visible — trying multi-step login")

        # Try clicking Continue/Next/Submit buttons after entering email
        continue_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Continue")',
            'button:has-text("Next")',
            'button:has-text("Submit")',
            'button:has-text("Sign in")',
            'button:has-text("Log in")',
            'button:has-text("Proceed")',
        ]
        clicked_continue = False
        for selector in continue_selectors:
            try:
                btn = await page.query_selector(selector)
                if btn and await btn.is_visible():
                    await btn.click()
                    clicked_continue = True
                    break
            except Exception:
                continue

        if not clicked_continue:
            # Try pressing Enter on the username field
            try:
                await username_field.press("Enter")
                clicked_continue = True
            except Exception:
                pass

        if not clicked_continue:
            logger.warning("Browser: could not advance past email step")
            return False

        # Wait for password field to appear
        try:
            password_field = await page.wait_for_selector(
                'input[type="password"]', timeout=15000,
            )
        except Exception:
            logger.warning("Browser: password field did not appear after email step")
            return False

        # Fill password
        try:
            await password_field.fill(self.password)
            await asyncio.sleep(0.3)
            logger.info("Browser: credentials filled (multi-step form)")
            return True
        except Exception as e:
            logger.warning(f"Browser: could not fill credentials: {e}")
            return False

    async def _browser_submit_form(self, page):
        """Submit the login form in the browser."""
        # Try multiple submit strategies

        # Strategy 1: Press Enter on the password field
        password_field = await page.query_selector('input[type="password"]')
        if password_field:
            try:
                await password_field.press("Enter")
                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass
                return
            except Exception:
                pass

        # Strategy 2: Click a submit button
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Log in")',
            'button:has-text("Sign in")',
            'button:has-text("Login")',
            'button:has-text("Submit")',
        ]
        for selector in submit_selectors:
            try:
                btn = await page.query_selector(selector)
                if btn and await btn.is_visible():
                    await btn.click()
                    try:
                        await page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass
                    return
            except Exception:
                continue

    def _is_waf_response(self, resp: httpx.Response) -> bool:
        """Detect if an HTTP response is from a WAF/CDN, not the actual application."""
        # Check server header
        server = resp.headers.get("server", "").lower()
        if any(w in server for w in ["cloudflare", "ddos-guard", "sucuri", "incapsula", "akamai"]):
            return True

        # Check for cf-ray header (Cloudflare)
        if "cf-ray" in resp.headers:
            # cf-ray alone doesn't mean blocked — check status AND body
            if resp.status_code in (403, 503):
                return True

        # Check body for WAF signatures
        body_lower = resp.text.lower() if resp.text else ""
        waf_count = sum(1 for sig in WAF_SIGNATURES if sig in body_lower)
        if waf_count >= 2:
            return True

        return False

    # =====================================================================
    # OTP / 2FA HANDLING
    # =====================================================================

    def _detect_otp_response(self, resp: httpx.Response) -> Optional[Dict[str, Any]]:
        """
        Detect if a login response is requesting OTP / 2FA verification.

        Returns a context dict if OTP is needed, None otherwise.
        The context contains any useful info for submitting the OTP
        (verify URL, token, method hints).
        """
        body_lower = resp.text.lower() if resp.text else ""
        ct = resp.headers.get("content-type", "").lower()

        otp_context: Dict[str, Any] = {}

        # ── JSON response analysis ──────────────────────────────────
        if "application/json" in ct:
            try:
                data = resp.json()
                if not isinstance(data, dict):
                    return None

                # Check for explicit OTP-required keys
                for key in OTP_RESPONSE_KEYS:
                    val = data.get(key)
                    if val is True or val == "required" or val == "pending":
                        otp_context["trigger"] = f"json_key:{key}={val}"
                        break

                # Check for verify URL in response
                for key in ("verify_url", "verification_url", "otp_url",
                            "2fa_url", "challenge_url", "next", "redirect"):
                    val = data.get(key)
                    if isinstance(val, str) and val:
                        otp_context["verify_url"] = val

                # Check for a verification token to pass back
                for key in ("verify_token", "verification_token", "challenge_token",
                            "session_token", "otp_token", "nonce", "state"):
                    val = data.get(key)
                    if isinstance(val, str) and val:
                        otp_context["verify_token"] = val
                        otp_context["verify_token_key"] = key

                # Check message/error text for OTP keywords
                for msg_key in ("message", "error", "msg", "detail", "description",
                                "status_message", "info"):
                    msg = data.get(msg_key)
                    if isinstance(msg, str):
                        msg_lower = msg.lower()
                        if any(kw in msg_lower for kw in OTP_RESPONSE_KEYWORDS):
                            otp_context["trigger"] = f"json_msg:{msg_key}={msg}"
                            otp_context["user_message"] = msg
                            break

            except (ValueError, KeyError):
                pass

        # ── Fallback: body text scan ─────────────────────────────────
        if not otp_context:
            keyword_hits = sum(1 for kw in OTP_RESPONSE_KEYWORDS if kw in body_lower)
            if keyword_hits >= 2:
                otp_context["trigger"] = f"body_keywords:{keyword_hits}"

        if not otp_context:
            return None

        # Don't confuse actual failures with OTP. If the response has
        # clear failure signals (wrong password), it's not an OTP step.
        fail_words = ["invalid password", "incorrect password", "wrong password",
                      "bad credentials", "account not found", "invalid email"]
        if any(w in body_lower for w in fail_words):
            return None

        # HTTP 200 or 202 with OTP signals = OTP required
        # HTTP 401/403 could be OTP OR rejection — context matters
        if resp.status_code in (401, 403) and not otp_context.get("trigger", "").startswith("json_key"):
            # Only trust explicit JSON keys for 401/403, not vague body matches
            return None

        otp_context["login_url"] = str(resp.url)
        otp_context["status_code"] = resp.status_code
        otp_context["cookies"] = dict(resp.cookies)
        return otp_context

    async def _prompt_otp(self, context: Dict[str, Any]) -> Optional[str]:
        """
        Prompt the user for an OTP code via stdin.

        Returns the code string, or None if non-interactive or user cancels.
        """
        if not self.interactive:
            return None

        import sys
        if not sys.stdin.isatty():
            logger.warning("OTP required but stdin is not a TTY — cannot prompt")
            return None

        user_msg = context.get("user_message", "")
        if user_msg:
            print(f"\n🔐 {user_msg}")
        else:
            print(f"\n🔐 OTP/2FA verification required for {self.domain}")
            print("   Check your email for the verification code.")

        try:
            code = input("   Enter OTP code: ").strip()
            if code:
                return code
        except (EOFError, KeyboardInterrupt):
            pass

        return None

    async def _submit_otp(
        self, client: httpx.AsyncClient, code: str,
        context: Dict[str, Any], pre_cookies: Dict[str, str],
    ) -> LoginResult:
        """
        Submit an OTP code to complete 2FA login.

        Tries the verify_url from the OTP context first, then falls back
        to common OTP submission endpoints.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Referer": self.base_url + "/",
            "Origin": self.base_url,
        }

        # Merge cookies from login step
        cookies = dict(pre_cookies)
        cookies.update(context.get("cookies", {}))

        # Build payload — common OTP field names
        otp_field_combos = [
            {"code": code},
            {"otp": code},
            {"verification_code": code},
            {"token": code},
            {"otp_code": code},
            {"2fa_code": code},
            {"totp": code},
        ]

        # If we got a verify token from the initial response, include it
        verify_token = context.get("verify_token")
        verify_token_key = context.get("verify_token_key", "verify_token")
        if verify_token:
            for combo in otp_field_combos:
                combo[verify_token_key] = verify_token

        # Build list of URLs to try
        urls_to_try: List[str] = []
        if context.get("verify_url"):
            vurl = context["verify_url"]
            if "://" not in vurl:
                vurl = urljoin(self.base_url, vurl)
            urls_to_try.append(vurl)

        # Also try the same login URL (some sites accept OTP on same endpoint)
        login_url = context.get("login_url", "")
        if login_url and login_url not in urls_to_try:
            urls_to_try.append(login_url)

        # Common OTP paths
        for path in OTP_SUBMIT_PATHS:
            url = urljoin(self.base_url, path)
            if url not in urls_to_try:
                urls_to_try.append(url)

        for url in urls_to_try[:8]:
            for payload in otp_field_combos[:3]:  # Don't try every combo on every URL
                try:
                    resp = await client.post(
                        url, json=payload, headers=headers, cookies=cookies,
                    )
                except Exception:
                    continue

                if resp.status_code in (404, 405):
                    break  # Skip to next URL

                if resp.status_code in (400, 422):
                    # Wrong field name, try next combo
                    continue

                # Analyze the response
                result = self._analyze_login_response(resp, cookies, dict(client.cookies))
                result.login_url = url
                result.method_used = "json+otp"

                if result.success:
                    logger.info(f"OTP verification succeeded at {url}")
                    return result

                # Check if we got a clear rejection (wrong code)
                body_lower = resp.text.lower() if resp.text else ""
                if any(w in body_lower for w in [
                    "invalid code", "incorrect code", "wrong code",
                    "expired", "invalid otp", "invalid token",
                ]):
                    return LoginResult(
                        success=False,
                        message=f"OTP code was rejected at {url}. Code may be expired or incorrect.",
                        login_url=url,
                        method_used="json+otp",
                    )

        return LoginResult(
            success=False,
            message="Could not find a working OTP submission endpoint. "
                    "Try: beatrix auth browser <target>",
        )

    # =====================================================================
    # AUTHENTICATION — try discovered endpoints
    # =====================================================================

    async def _try_endpoint(
        self, client: httpx.AsyncClient, url: str,
        method: str = "auto", form_fields: Optional[Dict[str, str]] = None,
    ) -> LoginResult:
        """Try authenticating against a single discovered URL."""
        if method == "json":
            return await self._try_json_endpoint(client, url)
        elif method == "form":
            return await self._try_form_endpoint(client, url, form_fields)
        else:
            # Auto mode: try JSON first, then form.
            # But if JSON got a definitive answer (success OR clear rejection),
            # don't waste time trying form — the endpoint is correct, just the
            # credentials or method are right/wrong.
            result = await self._try_json_endpoint(client, url)
            if result.success:
                return result
            if "credentials rejected" in result.message.lower() or \
               "endpoint found" in result.message.lower():
                return result
            return await self._try_form_endpoint(client, url, form_fields)

    async def _acquire_sanctum_csrf(self, client: httpx.AsyncClient) -> Optional[str]:
        """Try Laravel Sanctum CSRF preflight.

        Calls ``/sanctum/csrf-cookie`` which sets the ``XSRF-TOKEN``
        cookie.  Returns the URL-decoded token value or ``None`` if the
        endpoint doesn't exist.
        """
        try:
            sanctum_url = urljoin(self.base_url, "/sanctum/csrf-cookie")
            resp = await client.get(sanctum_url)
            if resp.status_code in (200, 204):
                xsrf = (client.cookies.get("XSRF-TOKEN", domain=f".{self.domain}")
                        or client.cookies.get("XSRF-TOKEN"))
                if xsrf:
                    decoded = unquote(xsrf)
                    logger.info(f"Sanctum CSRF acquired ({len(decoded)} chars)")
                    return decoded
        except Exception as e:
            logger.debug(f"Sanctum CSRF unavailable: {e}")
        return None

    async def _try_json_endpoint(
        self, client: httpx.AsyncClient, url: str,
    ) -> LoginResult:
        """Try JSON POST login against a discovered URL."""
        # Collect CSRF tokens from a GET request
        csrf_header_token = None
        pre_cookies: Dict[str, str] = {}
        try:
            pre_resp = await client.get(url)
            csrf_header_token = self._extract_csrf_from_headers(pre_resp)
            pre_cookies = dict(pre_resp.cookies)
            if not csrf_header_token:
                csrf_from_body, _ = self._extract_csrf_from_html(pre_resp.text)
                if csrf_from_body:
                    csrf_header_token = csrf_from_body
        except Exception:
            pass

        # Also grab XSRF-TOKEN from the client cookie jar (may have been
        # set by an earlier request, e.g. the home-page GET in discover)
        if not csrf_header_token:
            xsrf_jar = (client.cookies.get("XSRF-TOKEN", domain=f".{self.domain}")
                        or client.cookies.get("XSRF-TOKEN"))
            if xsrf_jar:
                csrf_header_token = unquote(xsrf_jar)

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Referer": self.base_url + "/",
            "Origin": self.base_url,
        }
        if csrf_header_token:
            # Send CSRF token via the standard header; don't blast all 3 variants
            # (WAFs flag requests with multiple redundant CSRF headers)
            headers["x-csrf-token"] = csrf_header_token
            # Laravel specifically looks for X-XSRF-TOKEN
            headers["X-XSRF-TOKEN"] = csrf_header_token

        # Build field name combos — user-specified first, then auto-detect
        if self.username_field and self.password_field:
            combos = [(self.username_field, self.password_field)] + \
                     [c for c in JSON_FIELD_COMBOS if c != (self.username_field, self.password_field)]
        else:
            combos = JSON_FIELD_COMBOS

        sanctum_attempted = False
        last_error = ""
        for user_field, pass_field in combos:
            payload = {user_field: self.username, pass_field: self.password}
            try:
                resp = await client.post(
                    url, json=payload, headers=headers, cookies=pre_cookies,
                )
            except httpx.ConnectError:
                return LoginResult(success=False, message=f"Connection refused: {url}")
            except httpx.TimeoutException:
                return LoginResult(success=False, message=f"Timeout connecting to {url}")
            except Exception as e:
                return LoginResult(success=False, message=f"Connection error on {url}: {e}")

            if resp.status_code in (404, 405):
                return LoginResult(success=False, message=f"{resp.status_code}: {url}")

            # ── HTTP 419: Laravel CSRF mismatch → try Sanctum flow ──
            if resp.status_code == 419 and not sanctum_attempted:
                sanctum_attempted = True
                logger.info(f"HTTP 419 CSRF mismatch at {url} — trying Sanctum CSRF preflight")
                sanctum_token = await self._acquire_sanctum_csrf(client)
                if sanctum_token:
                    headers["X-XSRF-TOKEN"] = sanctum_token
                    headers["x-csrf-token"] = sanctum_token
                    pre_cookies = {}  # Sanctum sets fresh session cookies
                    # Retry the same field combo with the Sanctum token
                    try:
                        resp = await client.post(url, json=payload, headers=headers)
                    except Exception:
                        pass
                    if resp.status_code == 419:
                        last_error = f"CSRF mismatch persists after Sanctum flow"
                        continue
                else:
                    last_error = "HTTP 419 CSRF mismatch and Sanctum unavailable"
                    continue
            elif resp.status_code == 419:
                last_error = "HTTP 419 CSRF mismatch (Sanctum already attempted)"
                continue

            # Detect WAF block masquerading as auth rejection
            is_waf = self._is_waf_response(resp)
            if is_waf and resp.status_code in (401, 403):
                logger.warning(f"WAF block detected on {url} (HTTP {resp.status_code}) — not a real auth rejection")
                return LoginResult(
                    success=False,
                    message=f"WAF/Cloudflare blocked request to {url} (HTTP {resp.status_code})",
                )

            result = self._analyze_login_response(resp, pre_cookies, dict(client.cookies))
            result.login_url = url
            result.method_used = "json"

            # Log the raw response for debugging login issues
            logger.debug(f"Login response from {url}: HTTP {resp.status_code}, "
                        f"body={resp.text[:500] if resp.text else '(empty)'}")

            if result.success:
                logger.info(f"JSON login succeeded at {url} ({user_field}, {pass_field})")
                return result

            # ── Check for OTP/2FA challenge ──────────────────────────
            otp_context = self._detect_otp_response(resp)
            if otp_context:
                logger.info(f"OTP/2FA required at {url} — prompting user...")
                otp_code = await self._prompt_otp(otp_context)
                if otp_code:
                    otp_result = await self._submit_otp(
                        client, otp_code, otp_context,
                        {**pre_cookies, **dict(resp.cookies)},
                    )
                    if otp_result.success:
                        return otp_result
                    # OTP failed — return the failure with context
                    return otp_result

                # Non-interactive or user cancelled
                return LoginResult(
                    success=False,
                    otp_required=True,
                    otp_context=otp_context,
                    login_url=url,
                    method_used="json",
                    cookies=dict(resp.cookies),
                    message=f"OTP/2FA required at {url}. "
                            f"Use --manual-login or beatrix auth browser {self.domain}",
                )

            # 401/403 = endpoint is correct but bad credentials
            if resp.status_code in (401, 403):
                result.message = f"Endpoint found ({url}) but credentials rejected (HTTP {resp.status_code})"
                return result

            # 400/422 = likely wrong field names, try next combo
            if resp.status_code in (400, 422):
                last_error = f"HTTP {resp.status_code} with fields ({user_field}, {pass_field})"
                continue

        return LoginResult(success=False, message=f"JSON login failed at {url}" + (f" — last: {last_error}" if last_error else ""))

    async def _try_form_endpoint(
        self, client: httpx.AsyncClient, url: str,
        pre_extracted_fields: Optional[Dict[str, str]] = None,
    ) -> LoginResult:
        """Try HTML form POST login against a discovered URL."""
        pre_cookies: Dict[str, str] = {}

        # GET the page first
        try:
            page_resp = await client.get(url)
            if page_resp.status_code == 404:
                return LoginResult(success=False, message=f"404: {url}")
            # If the GET itself is WAF-blocked, no point trying to POST
            if self._is_waf_response(page_resp) and page_resp.status_code in (401, 403):
                logger.warning(f"WAF block detected on GET {url} (HTTP {page_resp.status_code}) — skipping form POST")
                return LoginResult(
                    success=False,
                    message=f"WAF/Cloudflare blocked form page {url} (HTTP {page_resp.status_code})",
                )
            pre_cookies = dict(page_resp.cookies)
            page_body = page_resp.text
        except Exception:
            return LoginResult(success=False, message=f"Cannot reach {url}")

        # Extract CSRF token
        csrf_token, csrf_field = self._extract_csrf_from_html(page_body)
        csrf_header_token = self._extract_csrf_from_headers(page_resp)

        # Detect field names from HTML (or use user-specified, or defaults)
        user_field = self.username_field or self._detect_username_field(page_body)
        pass_field = self.password_field or self._detect_password_field(page_body)

        # Detect form action URL
        action_url = self._extract_form_action(page_body, url)

        # Build form data
        form_data: Dict[str, str] = {}

        # Use pre-extracted fields from discovery if available
        if pre_extracted_fields:
            form_data.update(pre_extracted_fields)

        form_data[user_field] = self.username
        form_data[pass_field] = self.password

        if csrf_token and csrf_field:
            form_data[csrf_field] = csrf_token

        # Add hidden fields from the page
        hidden_fields = self._extract_hidden_fields(page_body)
        for k, v in hidden_fields.items():
            if k not in form_data:
                form_data[k] = v

        submit_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": url,
            "Origin": self.base_url,
        }
        if csrf_header_token:
            submit_headers["x-csrf-token"] = csrf_header_token

        try:
            login_resp = await client.post(
                action_url, data=form_data,
                headers=submit_headers, cookies=pre_cookies,
                follow_redirects=True,
            )
        except Exception as e:
            return LoginResult(success=False, message=f"Form POST failed: {e}")

        if login_resp.status_code == 404:
            return LoginResult(success=False, message=f"Form action 404: {action_url}")

        # Detect WAF block masquerading as auth rejection
        if self._is_waf_response(login_resp) and login_resp.status_code in (401, 403):
            logger.warning(f"WAF block detected on {action_url} (form, HTTP {login_resp.status_code}) — not a real auth rejection")
            return LoginResult(
                success=False,
                message=f"WAF/Cloudflare blocked form request to {action_url} (HTTP {login_resp.status_code})",
            )

        # 401/403 = endpoint is correct but credentials were rejected
        if login_resp.status_code in (401, 403):
            # Check for OTP before declaring rejection
            otp_context = self._detect_otp_response(login_resp)
            if otp_context:
                logger.info(f"OTP/2FA required at {action_url} (form) — prompting user...")
                otp_code = await self._prompt_otp(otp_context)
                if otp_code:
                    otp_result = await self._submit_otp(
                        client, otp_code, otp_context,
                        {**pre_cookies, **dict(login_resp.cookies)},
                    )
                    return otp_result
                return LoginResult(
                    success=False,
                    otp_required=True,
                    otp_context=otp_context,
                    login_url=action_url,
                    method_used="form",
                    cookies=dict(login_resp.cookies),
                    message=f"OTP/2FA required at {action_url}. "
                            f"Use --manual-login or beatrix auth browser {self.domain}",
                )
            return LoginResult(
                success=False,
                login_url=action_url,
                method_used="form",
                message=f"Endpoint found ({action_url}) but credentials rejected (HTTP {login_resp.status_code})",
            )

        # Check for OTP on 200 responses too (many sites return 200 + OTP prompt)
        otp_context = self._detect_otp_response(login_resp)
        if otp_context:
            logger.info(f"OTP/2FA required at {action_url} (form, HTTP {login_resp.status_code}) — prompting user...")
            otp_code = await self._prompt_otp(otp_context)
            if otp_code:
                otp_result = await self._submit_otp(
                    client, otp_code, otp_context,
                    {**pre_cookies, **dict(login_resp.cookies)},
                )
                return otp_result
            return LoginResult(
                success=False,
                otp_required=True,
                otp_context=otp_context,
                login_url=action_url,
                method_used="form",
                cookies=dict(login_resp.cookies),
                message=f"OTP/2FA required at {action_url}. "
                        f"Use --manual-login or beatrix auth browser {self.domain}",
            )

        result = self._analyze_login_response(login_resp, pre_cookies, dict(client.cookies))
        result.login_url = action_url
        result.method_used = "form"
        return result

    # =====================================================================
    # HELPERS
    # =====================================================================

    def _extract_form_fields(self, form_body: str) -> Dict[str, str]:
        """Extract input field names from a form body."""
        fields: Dict[str, str] = {}
        for m in re.finditer(
            r'<input[^>]*name=["\']([^"\']+)["\']', form_body, re.IGNORECASE,
        ):
            name = m.group(1)
            # Get the value if present
            val_match = re.search(
                rf'name=["\']{ re.escape(name) }["\'][^>]*value=["\']([^"\']*)["\']',
                form_body, re.IGNORECASE,
            )
            fields[name] = val_match.group(1) if val_match else ""
        return fields

    def _extract_csrf_from_html(self, html: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract CSRF token from HTML form hidden fields."""
        for field_name in CSRF_FIELD_NAMES:
            patterns = [
                rf'name="{re.escape(field_name)}"[^>]*value="([^"]*)"',
                rf"name='{re.escape(field_name)}'[^>]*value='([^']*)'",
                rf'value="([^"]*)"[^>]*name="{re.escape(field_name)}"',
                rf"value='([^']*)'[^>]*name='{re.escape(field_name)}'",
            ]
            for pattern in patterns:
                m = re.search(pattern, html, re.IGNORECASE)
                if m:
                    return m.group(1), field_name

        # Also check <meta> tags for CSRF
        meta_patterns = [
            r'<meta\s+name="csrf-token"\s+content="([^"]*)"',
            r'<meta\s+content="([^"]*)"\s+name="csrf-token"',
            r'<meta\s+name="csrf-param"\s+content="([^"]*)"',
        ]
        for pattern in meta_patterns:
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                return m.group(1), "csrf_token"

        return None, None

    def _extract_csrf_from_headers(self, resp: httpx.Response) -> Optional[str]:
        """Extract CSRF token from response headers or cookies.

        URL-decodes cookie values (e.g. Laravel's XSRF-TOKEN contains
        URL-encoded base64 with trailing %3D → =).
        """
        for hname in CSRF_HEADER_NAMES:
            val = resp.headers.get(hname)
            if val:
                return val

        csrf_cookie_names = ["csrf_token", "csrftoken", "XSRF-TOKEN", "_csrf", "csrf"]
        for cname, cval in resp.cookies.items():
            if any(cname.lower() == n.lower() for n in csrf_cookie_names):
                # URL-decode: Laravel's XSRF-TOKEN cookie is URL-encoded
                return unquote(cval)

        return None

    def _detect_username_field(self, html: str) -> str:
        """Detect the username/email field name from HTML."""
        for name in USERNAME_FIELD_NAMES:
            if f'name="{name}"' in html or f"name='{name}'" in html:
                return name

        email_match = re.search(r'<input[^>]*type="email"[^>]*name="([^"]*)"', html, re.IGNORECASE)
        if email_match:
            return email_match.group(1)
        email_match = re.search(r'<input[^>]*name="([^"]*)"[^>]*type="email"', html, re.IGNORECASE)
        if email_match:
            return email_match.group(1)

        return "email"

    def _detect_password_field(self, html: str) -> str:
        """Detect the password field name from HTML."""
        for name in PASSWORD_FIELD_NAMES:
            if f'name="{name}"' in html or f"name='{name}'" in html:
                return name

        pass_match = re.search(r'<input[^>]*type="password"[^>]*name="([^"]*)"', html, re.IGNORECASE)
        if pass_match:
            return pass_match.group(1)
        pass_match = re.search(r'<input[^>]*name="([^"]*)"[^>]*type="password"', html, re.IGNORECASE)
        if pass_match:
            return pass_match.group(1)

        return "password"

    def _extract_form_action(self, html: str, current_url: str) -> str:
        """Extract the form action URL, defaulting to current URL."""
        form_match = re.search(
            r'<form[^>]*action="([^"]*)"[^>]*>.*?type="password"',
            html, re.IGNORECASE | re.DOTALL,
        )
        if form_match:
            action = form_match.group(1)
            if action:
                return urljoin(current_url, action)

        form_match = re.search(
            r'<form[^>]*action="([^"]*)"',
            html, re.IGNORECASE,
        )
        if form_match:
            action = form_match.group(1)
            if action:
                return urljoin(current_url, action)

        return current_url

    def _extract_hidden_fields(self, html: str) -> Dict[str, str]:
        """Extract all hidden input fields from HTML."""
        fields: Dict[str, str] = {}
        pattern = r'<input[^>]*type="hidden"[^>]*name="([^"]*)"[^>]*value="([^"]*)"'
        for m in re.finditer(pattern, html, re.IGNORECASE):
            name, value = m.group(1), m.group(2)
            if name.lower() not in {f.lower() for f in CSRF_FIELD_NAMES}:
                fields[name] = value

        pattern2 = r'<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"[^>]*type="hidden"'
        for m in re.finditer(pattern2, html, re.IGNORECASE):
            name, value = m.group(1), m.group(2)
            if name.lower() not in {f.lower() for f in CSRF_FIELD_NAMES}:
                fields[name] = value

        return fields

    def _analyze_login_response(
        self, resp: httpx.Response, pre_cookies: Dict[str, str],
        client_cookies: Optional[Dict[str, str]] = None,
    ) -> LoginResult:
        """Analyze login response to determine success and extract session data.

        Args:
            resp: The final HTTP response from the login attempt.
            pre_cookies: Cookies that existed before the login POST.
            client_cookies: All cookies accumulated by the httpx client,
                including cookies set during redirect chains (302 → 200).
                resp.cookies only contains the final response's Set-Cookie
                headers, missing cookies set on intermediate redirects.
        """
        result = LoginResult(success=False)

        # Capture all cookies — merge from pre-request, response, AND
        # client jar (which accumulates cookies across redirect chains)
        all_cookies = dict(pre_cookies)
        all_cookies.update(dict(resp.cookies))
        if client_cookies:
            all_cookies.update(client_cookies)

        new_cookies = {
            n: v for n, v in all_cookies.items()
            if v and v != "deleted" and v != '""'
        }
        result.cookies = new_cookies

        success_signals = 0
        failure_signals = 0

        # Signal 1: HTTP status
        if resp.status_code in (200, 201, 204, 302, 303):
            success_signals += 1
        elif resp.status_code == 419:
            # Laravel CSRF token mismatch — not a credential rejection
            failure_signals += 3
            result.message = "CSRF token mismatch (HTTP 419) — retry with Sanctum CSRF flow"
            return result
        elif resp.status_code in (401, 403, 422, 429):
            failure_signals += 3

        # Signal 2: New session cookies
        new_cookie_names = set(all_cookies.keys()) - set(pre_cookies.keys())
        session_cookie_names = {
            "session", "sessionid", "session_id", "sid",
            "token", "auth", "jwt", "connect.sid",
            "PHPSESSID", "JSESSIONID", "laravel_session",
            "asp.net_sessionid", "_session_id",
        }
        if any(n.lower() in session_cookie_names for n in new_cookie_names):
            success_signals += 2
        elif new_cookie_names:
            success_signals += 1

        # Signal 3: JSON auth token
        ct = resp.headers.get("content-type", "").lower()
        if "application/json" in ct:
            try:
                json_body = resp.json()
                if isinstance(json_body, dict):
                    token = self._extract_token_from_json(json_body)
                    if token:
                        result.token = token
                        result.headers["Authorization"] = f"Bearer {token}"
                        success_signals += 3

                    for key in ("success", "ok", "status"):
                        val = json_body.get(key)
                        if val is True or val == "ok" or val == "success":
                            success_signals += 2
                        elif val is False or val == "error" or val == "fail":
                            failure_signals += 2

                    error_msg = json_body.get("error") or json_body.get("message", "")
                    if isinstance(error_msg, str):
                        err_lower = error_msg.lower()
                        if any(w in err_lower for w in [
                            "invalid", "incorrect", "wrong", "failed", "unauthorized",
                        ]):
                            failure_signals += 2
            except Exception:
                pass

        # Signal 4: Body keywords
        body_lower = resp.text.lower() if resp.text else ""
        fail_words = [
            "invalid password", "incorrect password", "login failed",
            "authentication failed", "wrong password", "invalid credentials",
            "invalid email", "account not found", "bad credentials",
        ]
        ok_words = [
            "welcome", "dashboard", "logged in", "sign out", "logout",
            "my account", "profile",
        ]
        if any(w in body_lower for w in fail_words):
            failure_signals += 2
        if any(w in body_lower for w in ok_words):
            success_signals += 1

        # Signal 5: Redirect to dashboard
        if resp.status_code in (302, 303):
            location = resp.headers.get("location", "").lower()
            if any(p in location for p in ["/dashboard", "/home", "/account", "/profile"]):
                success_signals += 1

        # Final decision
        if failure_signals >= 3:
            result.success = False
            result.message = "Login failed (invalid credentials or error response)"
        elif success_signals >= 2:
            result.success = True
            parts = []
            if result.cookies:
                parts.append(f"{len(result.cookies)} cookies")
            if result.headers:
                parts.append(f"{len(result.headers)} headers")
            if result.token:
                parts.append("auth token")
            result.message = f"Login successful — captured {', '.join(parts) if parts else 'session'}"
        else:
            if new_cookies:
                result.success = True
                result.message = f"Login likely successful — captured {len(new_cookies)} cookies (verify manually)"
            else:
                result.success = False
                result.message = "Login result ambiguous — no session cookies or tokens captured"

        return result

    def _extract_token_from_json(self, data: Dict[str, Any], depth: int = 0) -> Optional[str]:
        """Recursively search JSON response for auth tokens."""
        if depth > 3:
            return None

        for key in AUTH_TOKEN_KEYS:
            if key in data:
                val = data[key]
                if isinstance(val, str) and len(val) > 10:
                    return val

        for key, val in data.items():
            if isinstance(val, dict):
                token = self._extract_token_from_json(val, depth + 1)
                if token:
                    return token

        return None


async def perform_auto_login(auth_creds: "AuthCredentials", target: str = "") -> LoginResult:
    """
    Convenience function: perform auto-login using AuthCredentials fields.
    Returns LoginResult with captured cookies/headers.

    Args:
        auth_creds: AuthCredentials with login_username and login_password set
        target: The scan target URL/domain (used as base_url for login discovery)

    Usage:
        if auth_creds.has_login_creds:
            result = await perform_auto_login(auth_creds, target="example.com")
            if result.success:
                auth_creds.cookies.update(result.cookies)
                auth_creds.headers.update(result.headers)
    """
    from beatrix.core.auth_config import AuthCredentials  # avoid circular

    if not auth_creds.has_login_creds:
        return LoginResult(success=False, message="No login credentials provided")

    # Always use the scan target as the base URL for endpoint discovery.
    # login_url is passed separately — using it as 'target' breaks base_url
    # resolution when login_url is relative (e.g. "/api/login" → base_url = "://").
    base_target = target or ""

    engine = AutoLoginEngine(
        target=base_target,
        username=auth_creds.login_username,
        password=auth_creds.login_password,
        login_url=auth_creds.login_url,
        login_method=auth_creds.login_method,
        username_field=auth_creds.login_username_field,
        password_field=auth_creds.login_password_field,
    )
    return await engine.login()


# =====================================================================
# SESSION PERSISTENCE — save/load sessions to avoid re-auth
# =====================================================================

import json as _json
from pathlib import Path as _Path

SESSIONS_DIR = _Path.home() / ".beatrix" / "sessions"


def _session_file(domain: str) -> _Path:
    """Get the session file path for a domain."""
    safe_name = domain.replace(":", "_").replace("/", "_")
    return SESSIONS_DIR / f"{safe_name}.json"


def save_session(
    domain: str,
    login_result: LoginResult,
    playwright_state: Optional[Dict] = None,
) -> _Path:
    """
    Save a successful login session to disk for reuse.

    Args:
        domain: Target domain
        login_result: Captured login result (cookies, headers, token)
        playwright_state: Optional Playwright storage_state() output for full restore.
                          Includes HttpOnly cookies + localStorage from all origins.

    Returns the path where the session was saved.
    """
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

    import time
    session_data = {
        "domain": domain,
        "cookies": login_result.cookies,
        "headers": login_result.headers,
        "token": login_result.token,
        "method_used": login_result.method_used,
        "login_url": login_result.login_url,
        "saved_at": time.time(),
        "saved_at_human": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    if playwright_state:
        session_data["playwright_state"] = playwright_state

    path = _session_file(domain)
    path.write_text(_json.dumps(session_data, indent=2))
    logger.info(f"Session saved to {path}")
    return path


def load_session(domain: str, max_age_hours: float = 24.0) -> Optional[LoginResult]:
    """
    Load a previously saved session for a domain.

    Returns LoginResult if a valid (non-expired) session exists, None otherwise.
    Skips the session if any JWT token is within 5 minutes of expiry.

    Args:
        domain: Target domain
        max_age_hours: Maximum session age in hours (default 24h)
    """
    path = _session_file(domain)
    if not path.exists():
        return None

    try:
        data = _json.loads(path.read_text())
    except Exception:
        return None

    import time
    saved_at = data.get("saved_at", 0)
    age_hours = (time.time() - saved_at) / 3600
    if age_hours > max_age_hours:
        logger.info(f"Saved session for {domain} expired ({age_hours:.1f}h > {max_age_hours}h)")
        path.unlink(missing_ok=True)
        return None

    # JWT expiry check — decode without signature verification to read exp claim.
    # Protects against loading a short-lived token (e.g. 15-min JWT) that the
    # 24h wall-clock check would pass but the server would reject.
    token = data.get("token")
    if token and isinstance(token, str) and token.count(".") == 2:
        try:
            import base64 as _b64
            payload_b64 = token.split(".")[1]
            # Base64url padding
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = _json.loads(_b64.urlsafe_b64decode(payload_b64))
            exp = payload.get("exp")
            if exp and isinstance(exp, (int, float)):
                remaining_s = exp - time.time()
                if remaining_s < 300:  # less than 5 minutes remaining
                    logger.info(
                        f"JWT for {domain} expires in {remaining_s:.0f}s — discarding stale session"
                    )
                    path.unlink(missing_ok=True)
                    return None
                logger.info(
                    f"JWT for {domain} valid for another {remaining_s/3600:.1f}h"
                )
        except Exception:
            pass  # Not a standard JWT or decode failed — trust wall-clock check

    logger.info(f"Loaded saved session for {domain} (age: {age_hours:.1f}h)")
    return LoginResult(
        success=True,
        cookies=data.get("cookies", {}),
        headers=data.get("headers", {}),
        token=token,
        method_used=data.get("method_used", "saved"),
        login_url=data.get("login_url", ""),
        message=f"Loaded saved session (age: {age_hours:.0f}h). Use --fresh-login to re-authenticate.",
    )


def clear_session(domain: str) -> bool:
    """Delete a saved session for a domain."""
    path = _session_file(domain)
    if path.exists():
        path.unlink()
        return True
    return False


def list_sessions() -> List[Dict[str, Any]]:
    """List all saved sessions with metadata."""
    if not SESSIONS_DIR.exists():
        return []

    import time
    sessions = []
    for f in SESSIONS_DIR.glob("*.json"):
        try:
            data = _json.loads(f.read_text())
            age_hours = (time.time() - data.get("saved_at", 0)) / 3600
            sessions.append({
                "domain": data.get("domain", f.stem),
                "saved_at": data.get("saved_at_human", "unknown"),
                "age_hours": round(age_hours, 1),
                "cookies": len(data.get("cookies", {})),
                "headers": len(data.get("headers", {})),
                "has_token": bool(data.get("token")),
                "method": data.get("method_used", ""),
                "file": str(f),
            })
        except Exception:
            continue
    return sessions


async def browser_interactive_login(target: str) -> LoginResult:
    """
    Open a real browser for the user to manually complete login
    (handles OTP, captcha, or any challenge).

    Captures all cookies and localStorage tokens after the user signals
    they're done by navigating to a success page or pressing Enter.

    For headless environments (like codespaces), falls back to a
    cookie-paste prompt.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return _fallback_cookie_import(target)

    import os
    if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        for candidate in [
            os.path.expanduser("~/.cache/ms-playwright"),
            "/home/codespace/.cache/ms-playwright",
            "/root/.cache/ms-playwright",
        ]:
            if os.path.isdir(candidate):
                os.environ["PLAYWRIGHT_BROWSERS_PATH"] = candidate
                break

    # Detect if we have a display (X11/Wayland) for headed mode
    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))

    if not has_display:
        # No display — can't open headed browser in codespace
        return _fallback_cookie_import(target)

    # Normalize target
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=False)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            )
            page = await context.new_page()
            await page.goto(target, wait_until="networkidle", timeout=30000)

            print(f"\n🌐 Browser opened to {target}")
            print("   Complete the login (including any OTP/2FA).")
            print("   Press Enter here when you're logged in...\n")

            # Wait for user to press Enter
            import sys
            try:
                input("   [Press Enter when login is complete] ")
            except (EOFError, KeyboardInterrupt):
                await browser.close()
                return LoginResult(success=False, message="Browser login cancelled.")

            # Capture complete session via storage_state() — this includes ALL
            # cookies (HttpOnly included, via CDP) + localStorage + sessionStorage.
            # Falls back to cookies() if storage_state is unavailable.
            headers: Dict[str, str] = {}
            token = None
            cookie_dict: Dict[str, str] = {}
            playwright_state: Optional[Dict] = None

            try:
                state = await context.storage_state()
                playwright_state = state
                cookie_dict = {c["name"]: c["value"] for c in state.get("cookies", [])}
                # Extract auth tokens from localStorage/sessionStorage origins
                for origin in state.get("origins", []):
                    for item in origin.get("localStorage", []) + origin.get("sessionStorage", []):
                        name = item.get("name", "")
                        val = item.get("value", "")
                        if name in AUTH_TOKEN_KEYS and val and len(val) > 10 and not token:
                            token = val
                            headers["Authorization"] = f"Bearer {val}"
            except Exception:
                # storage_state unavailable — fall back to cookies() + JS eval
                try:
                    raw_cookies = await context.cookies()
                    cookie_dict = {c["name"]: c["value"] for c in raw_cookies}
                    for key in AUTH_TOKEN_KEYS:
                        val = await page.evaluate(
                            f"localStorage.getItem('{key}') || sessionStorage.getItem('{key}')"
                        )
                        if val and len(val) > 10:
                            token = val
                            headers["Authorization"] = f"Bearer {val}"
                            break
                except Exception:
                    pass

            await browser.close()

            if cookie_dict:
                result = LoginResult(
                    success=True,
                    cookies=cookie_dict,
                    headers=headers,
                    token=token,
                    method_used="browser_interactive",
                    message=f"Browser login captured {len(cookie_dict)} cookies"
                            + (" + auth token" if token else ""),
                )
                # Auto-save the session (including Playwright storage state for full restore)
                save_session(domain, result, playwright_state=playwright_state)
                return result

            return LoginResult(
                success=False,
                message="No cookies captured from browser session.",
            )
    except Exception as e:
        logger.error(f"Browser interactive login error: {e}")
        return _fallback_cookie_import(target)


def _fallback_cookie_import(target: str) -> LoginResult:
    """
    Fallback for headless environments: prompt user to paste session data
    captured from their browser's DevTools Network tab.
    """
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    domain = parsed.netloc

    print(f"\n  Manual Session Import — {domain}")
    print()
    print("  ── Option A: Copy from Network request (recommended) ──────────────────")
    print("  This captures ALL cookies including HttpOnly session cookies,")
    print("  which are invisible to document.cookie and the Application tab.")
    print()
    print("  1. Log into the site in your browser (complete OTP/2FA etc.)")
    print("  2. Open DevTools (F12) → Network tab")
    print("  3. Click any authenticated request (e.g. /api/me, /dashboard, /profile)")
    print("  4. In the 'Headers' panel, scroll to 'Request Headers'")
    print("  5. Copy the entire value of the 'Cookie:' header")
    print()
    print("  ── Option B: Application tab (easier, misses HttpOnly cookies) ────────")
    print("  1. DevTools → Application → Storage → Cookies → select your domain")
    print("  2. Note each Name and Value, format as: name=value; name2=value2")
    print()
    print("  Paste cookie string below (name=value; name2=value2):")
    print("  (or 'skip' to scan without authentication)")
    print()

    import sys
    if not sys.stdin.isatty():
        return LoginResult(success=False, message="No TTY — cannot prompt for cookies")

    try:
        cookie_str = input("   Cookies: ").strip()
    except (EOFError, KeyboardInterrupt):
        return LoginResult(success=False, message="Cookie import cancelled")

    if not cookie_str or cookie_str.lower() == "skip":
        return LoginResult(success=False, message="Cookie import skipped")

    cookies: Dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()

    if not cookies:
        return LoginResult(success=False, message="No valid cookies parsed")

    # Optionally get a bearer token too
    print()
    try:
        token_str = input("   Bearer token (optional, Enter to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        token_str = ""

    headers: Dict[str, str] = {}
    token = None
    if token_str:
        token = token_str
        headers["Authorization"] = f"Bearer {token_str}"

    result = LoginResult(
        success=True,
        cookies=cookies,
        headers=headers,
        token=token,
        method_used="cookie_import",
        message=f"Imported {len(cookies)} cookies" + (f" + auth token" if token else ""),
    )
    save_session(domain, result)
    return result
