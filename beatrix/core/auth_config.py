"""
BEATRIX Authentication Configuration

Provides a unified way to manage authentication credentials for scanning.
Supports multiple credential sources:

1. YAML config file (~/.beatrix/auth.yaml or --auth-config)
2. CLI flags (--cookie, --header, --token, --user/--pass)
3. Environment variables (BEATRIX_AUTH_*)

Credentials flow through the entire kill chain:
- Nuclei gets -H flags for authenticated template scanning
- IDOR scanner gets user1/user2 sessions for access control testing
- All HTTP scanners get auth headers on their httpx clients
- Crawler gets cookies for authenticated crawling

Config file format (~/.beatrix/auth.yaml):
---
# Global auth applied to all targets
global:
  headers:
    Authorization: "Bearer eyJ..."
  cookies:
    session: "abc123"
    csrf_token: "xyz789"

# Per-target auth (overrides global)
targets:
  "example.com":
    headers:
      Authorization: "Bearer target-specific-token"
    cookies:
      session: "target-session"

  "api.example.com":
    headers:
      X-API-Key: "key-123"

# IDOR testing requires two different user sessions
idor:
  user1:
    login:
      username: "user1@example.com"
      password: "password1"
    # OR static cookies:
    # cookies:
    #   session: "user1-session-cookie"
  user2:
    login:
      username: "user2@example.com"
      password: "password2"
"""

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("beatrix.auth_config")


@dataclass
class AuthCredentials:
    """
    Resolved authentication credentials for a scan.

    This is the final, merged result of all credential sources
    (config file + CLI + env vars), ready to be consumed by scanners.
    """
    # HTTP headers to inject (e.g., Authorization, X-API-Key)
    headers: Dict[str, str] = field(default_factory=dict)

    # Cookies to inject
    cookies: Dict[str, str] = field(default_factory=dict)

    # Basic auth (username:password)
    basic_auth: Optional[Tuple[str, str]] = None

    # Bearer token (convenience — also added to headers)
    bearer_token: Optional[str] = None

    # Login credentials — Beatrix performs the login and captures the session
    login_url: Optional[str] = None        # e.g. https://example.com/login
    login_username: Optional[str] = None   # email or username
    login_password: Optional[str] = None   # password
    login_method: Optional[str] = None     # "form" | "json" | "auto" (default: auto)
    login_username_field: Optional[str] = None  # form field name (default: auto-detect)
    login_password_field: Optional[str] = None  # form field name (default: auto-detect)

    # IDOR: second user credentials for access control testing
    idor_user1: Optional["AuthCredentials"] = None
    idor_user2: Optional["AuthCredentials"] = None

    @property
    def has_auth(self) -> bool:
        """Whether any authentication is configured."""
        return bool(self.headers or self.cookies or self.basic_auth or self.bearer_token)

    @property
    def has_login_creds(self) -> bool:
        """Whether login credentials are provided (needs auto-login)."""
        return bool(self.login_username and self.login_password)

    @property
    def has_idor_accounts(self) -> bool:
        """Whether two accounts are configured for IDOR testing."""
        return self.idor_user1 is not None and self.idor_user2 is not None

    def merged_headers(self) -> Dict[str, str]:
        """Get all headers including bearer token."""
        h = dict(self.headers)
        if self.bearer_token and "Authorization" not in h:
            h["Authorization"] = f"Bearer {self.bearer_token}"
        if self.basic_auth:
            import base64
            creds = base64.b64encode(
                f"{self.basic_auth[0]}:{self.basic_auth[1]}".encode()
            ).decode()
            if "Authorization" not in h:
                h["Authorization"] = f"Basic {creds}"
        return h

    def cookie_header(self) -> Optional[str]:
        """Build a Cookie header string from cookies dict."""
        if not self.cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def all_headers(self) -> Dict[str, str]:
        """Get all headers including cookies as Cookie header."""
        h = self.merged_headers()
        cookie_str = self.cookie_header()
        if cookie_str:
            h["Cookie"] = cookie_str
        return h

    def nuclei_header_flags(self) -> List[str]:
        """Build nuclei -H flags for authenticated scanning."""
        flags = []
        for key, val in self.merged_headers().items():
            flags.extend(["-H", f"{key}: {val}"])
        cookie_str = self.cookie_header()
        if cookie_str:
            flags.extend(["-H", f"Cookie: {cookie_str}"])
        return flags


# ─────────────────────────────────────────────────────────────────────────────
# Session Validator
#
# Modeled on Burp Suite's session validation approach:
# 1. Establish a "session check" URL — a page that behaves differently
#    when authenticated vs unauthenticated (e.g., /account, /api/me).
# 2. Capture a "logged-in fingerprint" — response patterns that prove
#    the session is alive (status code, body keywords, absence of login
#    redirects).
# 3. Periodically re-check during the scan.
# 4. If the session is dead → re-authenticate automatically.
#
# The validator is non-blocking and designed to be called between
# kill chain phases or after a scanner detects repeated 401/403s.
# ─────────────────────────────────────────────────────────────────────────────

# Pages likely to differ between auth'd and unauth'd states
SESSION_CHECK_PATHS = [
    "/api/v1/me", "/api/v1/user", "/api/me", "/api/user",
    "/api/v2/me", "/api/v2/user", "/api/auth/me", "/api/auth/session",
    "/api/session", "/api/account", "/api/profile",
    "/me", "/account", "/profile", "/settings", "/dashboard",
    "/user/settings", "/account/settings", "/my-account",
]

# Patterns in response body that indicate "logged in"
LOGGED_IN_PATTERNS = [
    "logout", "sign out", "sign_out", "signout", "log out", "log_out",
    "my account", "my-account", "my_account", "dashboard",
    "welcome back", "settings", "profile", "preferences",
]

# Patterns that indicate "not logged in" / redirected to login
LOGGED_OUT_PATTERNS = [
    "log in", "login", "sign in", "signin", "sign_in",
    "forgot password", "create account", "register", "sign up",
    "unauthorized", "session expired", "please authenticate",
]


@dataclass
class SessionFingerprint:
    """Captured fingerprint of a valid authenticated session."""
    check_url: str
    expected_status: int
    logged_in_markers: List[str]  # substrings found in body when authenticated
    logged_out_markers: List[str]  # substrings found in body when NOT authenticated
    response_size_range: tuple  # (min, max) expected body size
    captured_at: float = 0.0
    # How to replay check_url for later is_session_alive() checks. Defaults
    # to a plain GET; set when calibration found its signal in a background
    # API call (e.g. a GraphQL POST) fired during SPA hydration rather than
    # a directly-fetchable page.
    check_method: str = "GET"
    check_body: Optional[str] = None

    def is_stale(self, max_age_seconds: float = 3600) -> bool:
        return (time.time() - self.captured_at) > max_age_seconds


class SessionValidator:
    """
    Validates whether an authenticated session is still alive.

    Usage:
        validator = SessionValidator(target_url, auth_creds)
        await validator.calibrate()  # probe once to build fingerprint
        ...
        if not await validator.is_session_alive():
            # re-authenticate
    """

    def __init__(self, target: str, auth_creds: "AuthCredentials"):
        self.target = target if "://" in target else f"https://{target}"
        self.auth_creds = auth_creds
        self.fingerprint: Optional[SessionFingerprint] = None
        self._calibrated = False
        self._consecutive_failures = 0
        self._last_check_time = 0.0
        self._check_interval = 120  # seconds between checks (2 min)

        # Set when httpx-based calibration finds nothing but a browser-backed
        # probe (real Chromium network stack) succeeds — i.e. the target
        # fingerprints scripted HTTP clients (e.g. Akamai bot management)
        # and blocks/redirects them regardless of valid cookies. Consumers
        # (kill_chain) read this to route authenticated scan requests
        # through browser_transport.BrowserRequestClient instead of httpx.
        self.needs_browser_transport = False
        self._browser_client = None  # lazily-created BrowserRequestClient, reused for is_session_alive()

    async def _probe_paths(self, get_fn, auth_headers: dict, base_headers: dict) -> bool:
        """Try SESSION_CHECK_PATHS with a generic async GET callable.

        `get_fn(url, headers)` must return an object with `.status_code`
        and `.text` — both httpx.Response and browser_transport.BrowserResponse
        satisfy this, so the same scoring logic works for either transport.
        """
        for path in SESSION_CHECK_PATHS:
            url = self.target.rstrip("/") + path
            try:
                # Request WITH auth
                auth_resp = await get_fn(url, auth_headers)
                # Request WITHOUT auth (plain)
                noauth_resp = await get_fn(url, base_headers)

                # Skip if both return the same thing (not auth-sensitive)
                if (auth_resp.status_code == noauth_resp.status_code
                        and abs(len(auth_resp.text) - len(noauth_resp.text)) < 50):
                    continue

                # Skip 404s — not a real endpoint
                if auth_resp.status_code == 404:
                    continue

                # Good candidate: auth'd response is 200 and unauth'd is
                # 401/403 or a redirect to login
                auth_ok = auth_resp.status_code in (200, 201)
                noauth_blocked = (
                    noauth_resp.status_code in (401, 403, 302, 303, 307)
                    or any(p in noauth_resp.text.lower() for p in LOGGED_OUT_PATTERNS[:5])
                )

                if auth_ok and noauth_blocked:
                    # Build fingerprint
                    body_lower = auth_resp.text.lower()
                    markers = [p for p in LOGGED_IN_PATTERNS if p in body_lower]
                    out_markers = [p for p in LOGGED_OUT_PATTERNS
                                   if p in noauth_resp.text.lower()]

                    body_len = len(auth_resp.text)
                    self.fingerprint = SessionFingerprint(
                        check_url=url,
                        expected_status=auth_resp.status_code,
                        logged_in_markers=markers,
                        logged_out_markers=out_markers,
                        response_size_range=(
                            max(0, body_len - 500),
                            body_len + 500,
                        ),
                        captured_at=time.time(),
                    )
                    self._calibrated = True
                    logger.info(
                        f"Session validator calibrated: {url} "
                        f"(auth={auth_resp.status_code}, "
                        f"noauth={noauth_resp.status_code}, "
                        f"markers={len(markers)})"
                    )
                    return True

            except Exception:
                continue

        return False

    @staticmethod
    def _path_key(url: str) -> str:
        """Normalize a URL for auth'd-vs-anon comparison: host + path, no
        query string. SPA API calls often vary a query/nonce per request,
        but GraphQL-style backends (including Airbnb's) put the meaningful
        distinguisher — the operation — in the path itself, so this still
        lines up the same logical call across both navigations."""
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        return f"{parts.netloc}{parts.path}"

    async def _probe_spa(
        self,
        browser_client: "Any",
        auth_cookie_header: str,
        domain: str,
    ) -> bool:
        """SPA-aware calibration: load the real page once authenticated and
        once anonymous, then diff the background API calls each run fires.

        Needed because client-rendered apps (Airbnb included) return the
        same initial HTML/status regardless of login state — the app
        decides what to render only after JS runs and calls its own
        `viewer`/`me`-style endpoint. Neither plain httpx nor the
        browser-backed `request()` transport above ever triggers that call
        since neither executes JavaScript; this does, by using a real page
        navigation instead of a bare fetch.
        """
        try:
            auth_calls = await browser_client.capture_page_responses(self.target, auth_cookie_header, domain)
            noauth_calls = await browser_client.capture_page_responses(self.target, "", domain)
        except Exception as e:
            logger.debug(f"Session calibration (SPA) failed: {e}")
            return False

        noauth_by_path: Dict[str, dict] = {}
        for c in noauth_calls:
            noauth_by_path.setdefault(self._path_key(c["url"]), c)

        for c in auth_calls:
            nc = noauth_by_path.get(self._path_key(c["url"]))

            if nc is None:
                # Only called when authenticated — a strong signal on its
                # own, as long as it looks like a real data response and
                # not e.g. an analytics beacon that happened to fire once.
                if c["status"] not in (200, 201) or len(c["body"]) < 20:
                    continue
            else:
                if (c["status"] == nc["status"]
                        and abs(len(c["body"]) - len(nc["body"])) < 50):
                    continue  # identical either way — not auth-sensitive
                if c["status"] == 404:
                    continue
                auth_ok = c["status"] in (200, 201)
                noauth_blocked = (
                    nc["status"] in (401, 403, 302, 303, 307)
                    or any(p in nc["body"].lower() for p in LOGGED_OUT_PATTERNS[:5])
                )
                if not (auth_ok and noauth_blocked):
                    continue

            body_lower = c["body"].lower()
            markers = [p for p in LOGGED_IN_PATTERNS if p in body_lower]
            out_markers = [p for p in LOGGED_OUT_PATTERNS if p in (nc["body"].lower() if nc else "")]
            body_len = len(c["body"])

            self.fingerprint = SessionFingerprint(
                check_url=c["url"],
                expected_status=c["status"],
                logged_in_markers=markers,
                logged_out_markers=out_markers,
                response_size_range=(max(0, body_len - 500), body_len + 500),
                captured_at=time.time(),
                check_method=c["method"],
                check_body=c["post_data"] or None,
            )
            self._calibrated = True
            logger.info(
                f"Session validator calibrated (SPA): {c['method']} {c['url']} "
                f"(auth={c['status']}, noauth={nc['status'] if nc else 'not-called-when-anonymous'})"
            )
            return True

        return False

    async def calibrate(self) -> bool:
        """
        Probe the target to discover a session-check URL and capture a
        fingerprint of what "authenticated" looks like.

        Tries httpx first (fast, no browser overhead). If that finds no
        auth-sensitive endpoint, retries the same probe through a real
        browser network stack before giving up — some targets (Akamai bot
        management and similar) fingerprint scripted HTTP clients and
        block/redirect them even with entirely valid session cookies, so a
        genuinely alive session can look dead to httpx alone.

        Returns True if calibration succeeded (found a URL that differs
        between auth'd and unauth'd responses).
        """
        import httpx

        base_headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
        }

        auth_headers = {**base_headers, **self.auth_creds.all_headers()}

        # ── Attempt 1: httpx ────────────────────────────────────────────
        try:
            async with httpx.AsyncClient(
                timeout=10, follow_redirects=True, verify=False
            ) as client:
                async def _httpx_get(url, headers):
                    return await client.get(url, headers=headers)

                if await self._probe_paths(_httpx_get, auth_headers, base_headers):
                    return True
        except Exception as e:
            logger.debug(f"Session calibration (httpx) failed: {e}")

        # ── Attempt 2: browser-backed (Akamai/bot-fingerprinted targets) ─
        if self.auth_creds.cookies:
            try:
                from beatrix.core.browser_transport import BrowserRequestClient, PLAYWRIGHT_AVAILABLE

                if PLAYWRIGHT_AVAILABLE:
                    browser_client = BrowserRequestClient()
                    await browser_client.start()
                    try:
                        # auth_headers already carries the Cookie header (via
                        # self.auth_creds.all_headers()) — BrowserRequestClient
                        # syncs its cookie jar from that per request.
                        async def _browser_get(url, headers):
                            return await browser_client.request("GET", url, headers=headers)

                        if await self._probe_paths(_browser_get, auth_headers, base_headers):
                            self.needs_browser_transport = True
                            self._browser_client = browser_client
                            logger.info(
                                "Session validator: httpx found no auth-sensitive endpoint "
                                "but browser-backed calibration succeeded — target "
                                "fingerprints scripted HTTP clients. Routing authenticated "
                                "scan requests through a real browser context."
                            )
                            return True
                    finally:
                        if not self.needs_browser_transport:
                            await browser_client.close()
            except Exception as e:
                logger.debug(f"Session calibration (browser) failed: {e}")

        # ── Attempt 3: SPA-aware (client-rendered apps) ──────────────────
        # Attempts 1-2 only ever send one bare request per path, auth'd and
        # anon — that reveals server-side auth checks but nothing a client-
        # rendered app decides after JS runs. Load the app for real instead
        # and diff whatever API calls it fires on its own.
        if self.auth_creds.cookies:
            spa_client = None
            try:
                from beatrix.core.browser_transport import BrowserRequestClient, PLAYWRIGHT_AVAILABLE

                if PLAYWRIGHT_AVAILABLE:
                    from urllib.parse import urlparse
                    domain = urlparse(self.target).netloc.split(":")[0]
                    spa_client = BrowserRequestClient()
                    await spa_client.start()
                    auth_cookie_header = self.auth_creds.cookie_header() or ""

                    if await self._probe_spa(spa_client, auth_cookie_header, domain):
                        self.needs_browser_transport = True
                        self._browser_client = spa_client
                        logger.info(
                            "Session validator: neither httpx nor a bare browser "
                            "request found an auth-sensitive endpoint, but SPA "
                            "network capture did — login state here is only "
                            "observable after client-side hydration."
                        )
                        return True
            except Exception as e:
                logger.debug(f"Session calibration (SPA) failed: {e}")
            finally:
                if spa_client is not None and not self.needs_browser_transport:
                    await spa_client.close()

        # Fallback — no perfect candidate found; use the target root with a
        # simple status-code check (less reliable but still useful)
        try:
            async with httpx.AsyncClient(
                timeout=10, follow_redirects=False, verify=False
            ) as client:
                auth_resp = await client.get(self.target, headers=auth_headers)
                self.fingerprint = SessionFingerprint(
                    check_url=self.target,
                    expected_status=auth_resp.status_code,
                    logged_in_markers=[],
                    logged_out_markers=[],
                    response_size_range=(0, len(auth_resp.text) + 2000),
                    captured_at=time.time(),
                )
                self._calibrated = True
                logger.info(f"Session validator calibrated (fallback): {self.target}")
                return True
        except Exception:
            pass

        logger.warning("Session validator: could not calibrate — no auth-sensitive endpoint found")
        return False

    async def close(self) -> None:
        """Release the browser client, if calibration created one."""
        if self._browser_client is not None:
            await self._browser_client.close()
            self._browser_client = None

    async def is_session_alive(self, force: bool = False) -> bool:
        """
        Check if the current session is still valid.

        Respects the check interval to avoid hammering the target.
        Returns True if session appears alive, False if it's dead.
        """
        if not self._calibrated or not self.fingerprint:
            return True  # Can't check → assume alive

        now = time.time()
        if not force and (now - self._last_check_time) < self._check_interval:
            return True  # Too soon since last check

        self._last_check_time = now

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
            **self.auth_creds.all_headers(),
        }

        # check_method/check_body are set when calibration's signal came
        # from a background API call (e.g. a GraphQL POST fired during SPA
        # hydration) rather than a directly re-fetchable page — replay it
        # the same way or the recheck won't hit the same endpoint at all.
        method = self.fingerprint.check_method
        body = self.fingerprint.check_body

        # Reuse the same transport calibration succeeded with — if httpx
        # gets fingerprinted and blocked, checking liveness with httpx would
        # report a genuinely alive session as dead.
        if self.needs_browser_transport and self._browser_client is not None:
            try:
                resp = await self._browser_client.request(
                    method, self.fingerprint.check_url, headers=headers, data=body
                )
                return self._evaluate_liveness(resp)
            except Exception as e:
                logger.debug(f"Session check error (browser): {e}")
                return True  # transient error → don't declare dead

        import httpx

        try:
            async with httpx.AsyncClient(
                timeout=10, follow_redirects=True, verify=False
            ) as client:
                resp = await client.request(
                    method, self.fingerprint.check_url, headers=headers,
                    content=body.encode() if body else None,
                )
                return self._evaluate_liveness(resp)
        except Exception as e:
            logger.debug(f"Session check error: {e}")
            return True  # Network error → don't declare dead, could be transient

    def _evaluate_liveness(self, resp) -> bool:
        """Shared status/marker checks against a fingerprinted session, for
        either an httpx.Response or a browser_transport.BrowserResponse."""
        # Check 1: Status code
        if resp.status_code in (401, 403):
            self._consecutive_failures += 1
            logger.warning(
                f"Session check: {resp.status_code} on "
                f"{self.fingerprint.check_url} "
                f"(failure #{self._consecutive_failures})"
            )
            return False

        # Check 2: Redirected to login page
        body_lower = resp.text.lower()
        if any(p in body_lower for p in self.fingerprint.logged_out_markers):
            # Also verify NO logged-in markers are present
            if not any(p in body_lower for p in self.fingerprint.logged_in_markers):
                self._consecutive_failures += 1
                logger.warning(
                    f"Session check: login page detected in response "
                    f"(failure #{self._consecutive_failures})"
                )
                return False

        # Check 3: Logged-in markers present (if we have any)
        if self.fingerprint.logged_in_markers:
            marker_hits = sum(1 for p in self.fingerprint.logged_in_markers
                              if p in body_lower)
            if marker_hits == 0:
                self._consecutive_failures += 1
                logger.warning(
                    f"Session check: no logged-in markers found "
                    f"(failure #{self._consecutive_failures})"
                )
                # Only declare dead if we had reliable markers
                if len(self.fingerprint.logged_in_markers) >= 2:
                    return False

        # Session looks alive
        self._consecutive_failures = 0
        return True

    @property
    def needs_reauth(self) -> bool:
        """Whether we should trigger re-authentication based on failure history."""
        return self._consecutive_failures >= 2

    def reset(self):
        """Reset failure counters after successful re-authentication."""
        self._consecutive_failures = 0
        self._last_check_time = 0.0


class AuthConfigLoader:
    """
    Loads and merges authentication from all sources.

    Priority (highest to lowest):
    1. CLI flags (--cookie, --header, --token)
    2. Environment variables (BEATRIX_AUTH_*)
    3. Per-target config from auth.yaml
    4. Global config from auth.yaml
    """

    @staticmethod
    def _user_home() -> Path:
        """Resolve the real user's home, even under sudo."""
        import os
        # If running under sudo, prefer the invoking user's home
        sudo_home = os.environ.get("SUDO_HOME")
        if sudo_home:
            return Path(sudo_home)
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            try:
                import pwd
                return Path(pwd.getpwnam(sudo_user).pw_dir)
            except (KeyError, ImportError):
                pass
        return Path.home()

    @classmethod
    def _default_config_path(cls) -> Path:
        return cls._user_home() / ".beatrix" / "auth.yaml"

    @classmethod
    def _resolve_config_path(cls) -> Path:
        """Resolve auth config path, handling sudo correctly.

        When running via 'sudo beatrix', Path.home() returns /root/ but the
        auth.yaml lives under the real user's home.  Check SUDO_USER first.
        """
        default = cls._default_config_path()
        if default.exists():
            return default

        # Under sudo, try the original user's home
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            import pwd
            try:
                real_home = Path(pwd.getpwnam(sudo_user).pw_dir)
                alt = real_home / ".beatrix" / "auth.yaml"
                if alt.exists():
                    return alt
            except KeyError:
                pass

        # Fallback: check relative to the venv (the wrapper hardcodes it)
        venv = os.environ.get("VIRTUAL_ENV")
        if venv:
            alt = Path(venv) / "auth.yaml"
            if alt.exists():
                return alt

        return default

    @classmethod
    def load(
        cls,
        target: str,
        config_path: Optional[str] = None,
        cli_cookies: Optional[List[str]] = None,
        cli_headers: Optional[List[str]] = None,
        cli_token: Optional[str] = None,
        cli_user: Optional[str] = None,
        cli_password: Optional[str] = None,
        login_user: Optional[str] = None,
        login_pass: Optional[str] = None,
        login_url: Optional[str] = None,
    ) -> AuthCredentials:
        """
        Load and merge credentials from all sources for a target.

        Args:
            target: Target domain/URL being scanned
            config_path: Path to auth config YAML (default: ~/.beatrix/auth.yaml)
            cli_cookies: Cookies from CLI (format: "name=value")
            cli_headers: Headers from CLI (format: "Name: Value")
            cli_token: Bearer token from CLI
            cli_user: Username for basic auth
            cli_password: Password for basic auth
            login_user: Username/email for auto-login
            login_pass: Password for auto-login
            login_url: Login page URL (optional, auto-detected if omitted)

        Returns:
            Merged AuthCredentials ready for use
        """
        creds = AuthCredentials()

        # 1. Load from config file (lowest priority)
        file_path = Path(config_path) if config_path else cls._resolve_config_path()
        if file_path.exists():
            file_creds = cls._load_config_file(file_path, target)
            creds = cls._merge(creds, file_creds)

        # 2. Environment variables
        env_creds = cls._load_env_vars()
        creds = cls._merge(creds, env_creds)

        # 3. CLI flags (highest priority)
        cli_creds = cls._parse_cli_args(
            cookies=cli_cookies,
            headers=cli_headers,
            token=cli_token,
            user=cli_user,
            password=cli_password,
            login_user=login_user,
            login_pass=login_pass,
            login_url=login_url,
        )
        creds = cls._merge(creds, cli_creds)

        return creds

    @classmethod
    def _load_config_file(cls, path: Path, target: str) -> AuthCredentials:
        """Load credentials from YAML config file."""
        try:
            import yaml
        except ImportError:
            # PyYAML not installed — try raw parsing
            return cls._load_config_file_raw(path, target)

        try:
            data = yaml.safe_load(path.read_text())
            if not isinstance(data, dict):
                return AuthCredentials()
        except Exception:
            return AuthCredentials()

        return cls._parse_config_data(data, target)

    @classmethod
    def _load_config_file_raw(cls, path: Path, target: str) -> AuthCredentials:
        """Fallback config parser when PyYAML is not installed.

        Supports a simplified key: value format for the most common cases.
        """
        creds = AuthCredentials()
        try:
            content = path.read_text()
            # Simple line-by-line parsing for flat config
            section = "global"
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                # Detect section headers (no leading spaces, ends with colon)
                if not line.startswith(" ") and stripped.endswith(":"):
                    section = stripped[:-1].strip().strip('"').strip("'")
                    continue

                # Parse key: value pairs  
                if ":" in stripped:
                    key, _, val = stripped.partition(":")
                    key = key.strip().strip('"').strip("'")
                    val = val.strip().strip('"').strip("'")

                    if section == "headers" or section.endswith("/headers"):
                        creds.headers[key] = val
                    elif section == "cookies" or section.endswith("/cookies"):
                        creds.cookies[key] = val
        except Exception:
            pass
        return creds

    @classmethod
    def _parse_config_data(cls, data: Dict[str, Any], target: str) -> AuthCredentials:
        """Parse the structured config data dict."""
        creds = AuthCredentials()

        # Extract target domain for matching
        target_domain = cls._extract_domain(target)

        # Global config
        global_cfg = data.get("global") or {}
        if isinstance(global_cfg, dict):
            creds.headers.update(global_cfg.get("headers") or {})
            creds.cookies.update(global_cfg.get("cookies") or {})

        # Per-target config (overrides global)
        target_matched = False
        targets = data.get("targets") or {}
        if isinstance(targets, dict):
            for pattern, tcfg in targets.items():
                if cls._target_matches(target_domain, pattern):
                    target_matched = True
                    if isinstance(tcfg, dict):
                        creds.headers.update(tcfg.get("headers") or {})
                        creds.cookies.update(tcfg.get("cookies") or {})

                        # Login credentials from per-target config
                        login_cfg = tcfg.get("login") or {}
                        if isinstance(login_cfg, dict) and login_cfg:
                            creds.login_username = login_cfg.get("username") or login_cfg.get("email")
                            creds.login_password = login_cfg.get("password")
                            creds.login_url = login_cfg.get("url")
                            creds.login_method = login_cfg.get("method", "auto")
                            creds.login_username_field = login_cfg.get("username_field")
                            creds.login_password_field = login_cfg.get("password_field")

                        # Per-target IDOR config (preferred over top-level)
                        idor_cfg = tcfg.get("idor") or {}
                        if isinstance(idor_cfg, dict) and idor_cfg:
                            cls._load_idor_config(creds, idor_cfg)

        # Global login credentials (if no per-target login was found)
        if not creds.has_login_creds:
            login_cfg = data.get("login") or (global_cfg.get("login") if isinstance(global_cfg, dict) else None) or {}
            if isinstance(login_cfg, dict) and login_cfg:
                creds.login_username = login_cfg.get("username") or login_cfg.get("email")
                creds.login_password = login_cfg.get("password")
                creds.login_url = login_cfg.get("url")
                creds.login_method = login_cfg.get("method", "auto")
                creds.login_username_field = login_cfg.get("username_field")
                creds.login_password_field = login_cfg.get("password_field")

        # Top-level IDOR accounts — only load if: (a) no per-target IDOR was
        # already loaded, AND (b) the target matched a configured target entry
        # OR no targets are configured at all (backward-compatible global use).
        # This prevents IDOR credentials for domain X from leaking into scans
        # of unrelated targets (e.g., IP addresses).
        if not creds.has_idor_accounts:
            idor_cfg = data.get("idor") or {}
            if isinstance(idor_cfg, dict) and idor_cfg:
                no_targets_configured = not targets or not isinstance(targets, dict)
                if target_matched or no_targets_configured:
                    cls._load_idor_config(creds, idor_cfg)

        return creds

    @classmethod
    def _load_idor_config(cls, creds: AuthCredentials, idor_cfg: Dict[str, Any]) -> None:
        """Load IDOR user1/user2 credentials from an idor config block."""
        u1 = idor_cfg.get("user1") or {}
        u2 = idor_cfg.get("user2") or {}
        if u1:
            u1_login = u1.get("login") or {}
            creds.idor_user1 = AuthCredentials(
                headers=u1.get("headers") or {},
                cookies=u1.get("cookies") or {},
                login_username=u1_login.get("username") or u1_login.get("email") if u1_login else None,
                login_password=u1_login.get("password") if u1_login else None,
                login_url=u1_login.get("url") if u1_login else None,
                login_method=u1_login.get("method", "auto") if u1_login else None,
                login_username_field=u1_login.get("username_field") if u1_login else None,
                login_password_field=u1_login.get("password_field") if u1_login else None,
            )
        if u2:
            u2_login = u2.get("login") or {}
            creds.idor_user2 = AuthCredentials(
                headers=u2.get("headers") or {},
                cookies=u2.get("cookies") or {},
                login_username=u2_login.get("username") or u2_login.get("email") if u2_login else None,
                login_password=u2_login.get("password") if u2_login else None,
                login_url=u2_login.get("url") if u2_login else None,
                login_method=u2_login.get("method", "auto") if u2_login else None,
                login_username_field=u2_login.get("username_field") if u2_login else None,
                login_password_field=u2_login.get("password_field") if u2_login else None,
            )

        return creds

    @classmethod
    def _load_env_vars(cls) -> AuthCredentials:
        """Load credentials from environment variables."""
        creds = AuthCredentials()

        # BEATRIX_AUTH_TOKEN → Bearer token
        token = os.environ.get("BEATRIX_AUTH_TOKEN")
        if token:
            creds.bearer_token = token

        # BEATRIX_AUTH_COOKIE → raw cookie string  ("name1=val1; name2=val2")
        cookie_str = os.environ.get("BEATRIX_AUTH_COOKIE")
        if cookie_str:
            for part in cookie_str.split(";"):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    creds.cookies[k.strip()] = v.strip()

        # BEATRIX_AUTH_HEADER → single header ("Authorization: Bearer xxx")
        header_str = os.environ.get("BEATRIX_AUTH_HEADER")
        if header_str and ":" in header_str:
            k, _, v = header_str.partition(":")
            creds.headers[k.strip()] = v.strip()

        # BEATRIX_AUTH_USER + BEATRIX_AUTH_PASS → basic auth
        user = os.environ.get("BEATRIX_AUTH_USER")
        passwd = os.environ.get("BEATRIX_AUTH_PASS")
        if user and passwd:
            creds.basic_auth = (user, passwd)

        # BEATRIX_LOGIN_USER + BEATRIX_LOGIN_PASS → auto-login credentials
        login_user = os.environ.get("BEATRIX_LOGIN_USER")
        login_pass = os.environ.get("BEATRIX_LOGIN_PASS")
        if login_user and login_pass:
            creds.login_username = login_user
            creds.login_password = login_pass
            creds.login_url = os.environ.get("BEATRIX_LOGIN_URL")

        return creds

    @classmethod
    def _parse_cli_args(
        cls,
        cookies: Optional[List[str]] = None,
        headers: Optional[List[str]] = None,
        token: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        login_user: Optional[str] = None,
        login_pass: Optional[str] = None,
        login_url: Optional[str] = None,
    ) -> AuthCredentials:
        """Parse CLI arguments into AuthCredentials."""
        creds = AuthCredentials()

        if token:
            creds.bearer_token = token

        if user and password:
            creds.basic_auth = (user, password)

        if login_user and login_pass:
            creds.login_username = login_user
            creds.login_password = login_pass
            creds.login_url = login_url

        if cookies:
            for cookie in cookies:
                if "=" in cookie:
                    k, _, v = cookie.partition("=")
                    creds.cookies[k.strip()] = v.strip()

        if headers:
            for header in headers:
                if ":" in header:
                    k, _, v = header.partition(":")
                    creds.headers[k.strip()] = v.strip()

        return creds

    @classmethod
    def _merge(cls, base: AuthCredentials, override: AuthCredentials) -> AuthCredentials:
        """Merge two AuthCredentials, with override taking precedence."""
        merged = AuthCredentials(
            headers={**base.headers, **override.headers},
            cookies={**base.cookies, **override.cookies},
            basic_auth=override.basic_auth or base.basic_auth,
            bearer_token=override.bearer_token or base.bearer_token,
            login_url=override.login_url or base.login_url,
            login_username=override.login_username or base.login_username,
            login_password=override.login_password or base.login_password,
            login_method=override.login_method or base.login_method,
            login_username_field=override.login_username_field or base.login_username_field,
            login_password_field=override.login_password_field or base.login_password_field,
            idor_user1=override.idor_user1 or base.idor_user1,
            idor_user2=override.idor_user2 or base.idor_user2,
        )
        return merged

    @staticmethod
    def _extract_domain(target: str) -> str:
        """Extract domain from target string."""
        from urllib.parse import urlparse
        if "://" in target:
            return urlparse(target).netloc.split(":")[0]
        return target.split("/")[0].split(":")[0]

    @staticmethod
    def _target_matches(target_domain: str, pattern: str) -> bool:
        """Check if target domain matches a config pattern."""
        pattern = pattern.strip().lower()
        target = target_domain.strip().lower()
        # Exact match
        if target == pattern:
            return True
        # Subdomain match (e.g., api.example.com matches example.com)
        if target.endswith("." + pattern):
            return True
        # Wildcard (e.g., *.example.com)
        if pattern.startswith("*."):
            base = pattern[2:]
            return target == base or target.endswith("." + base)
        return False

    @classmethod
    def generate_sample_config(cls) -> str:
        """Generate a sample auth.yaml config for the user."""
        return """# Beatrix Authentication Config
# Place at: ~/.beatrix/auth.yaml
# Or pass with: beatrix hunt target --auth-config /path/to/auth.yaml

# ─────────────────────────────────────────────
# Global auth — applied to ALL targets
# ─────────────────────────────────────────────
global:
  headers:
    # Authorization: "Bearer eyJhbGciOiJIUzI1NiIs..."
    # X-API-Key: "your-api-key"
  cookies:
    # session: "your-session-cookie"
    # csrf_token: "your-csrf-token"

# ─────────────────────────────────────────────
# Login credentials — Beatrix auto-logs in and captures the session
# Like Burp Suite: give username + password → Beatrix handles login
# ─────────────────────────────────────────────
login:
  # username: "your-email@example.com"   # or 'email:' — both work
  # password: "your-password"
  # url: "https://target.com/login"      # optional — auto-detected if omitted
  # method: "auto"                       # auto | form | json
  # username_field: "email"              # optional — auto-detected from form
  # password_field: "password"           # optional — auto-detected from form

# ─────────────────────────────────────────────
# Per-target auth — overrides global for specific targets
# ─────────────────────────────────────────────
targets:
  # "example.com":
  #   headers:
  #     Authorization: "Bearer target-specific-token"
  #   cookies:
  #     session: "target-session-id"
  #   login:
  #     username: "user@example.com"
  #     password: "password123"
  #     url: "https://example.com/api/auth/login"
  #     method: "json"
  #
  # "*.example.com":
  #   headers:
  #     X-API-Key: "wildcard-api-key"

# ─────────────────────────────────────────────
# IDOR testing — two different user sessions
# Required for proper access control testing
#
# Option A: Supply static cookies/tokens (manual capture)
# Option B: Supply login credentials → Beatrix auto-logs in both accounts
# ─────────────────────────────────────────────
idor:
  user1:
    # Option A: static cookies/headers
    # cookies:
    #   session: "user1-session-cookie"
    # headers:
    #   Authorization: "Bearer user1-token"
    # Option B: auto-login (recommended)
    login:
      # username: "user1@example.com"
      # password: "password1"
      # url: "https://target.com/api/auth/login"  # optional
      # method: "json"                             # optional: auto|form|json
  user2:
    login:
      # username: "user2@example.com"
      # password: "password2"

# ─────────────────────────────────────────────
# Environment variables (alternative to this file)
# ─────────────────────────────────────────────
# BEATRIX_AUTH_TOKEN=your-bearer-token
# BEATRIX_AUTH_COOKIE="session=abc; csrf=xyz"
# BEATRIX_AUTH_HEADER="Authorization: Bearer xxx"
# BEATRIX_AUTH_USER=admin
# BEATRIX_AUTH_PASS=password123
# BEATRIX_LOGIN_USER=user@example.com
# BEATRIX_LOGIN_PASS=mypassword
# BEATRIX_LOGIN_URL=https://target.com/login
"""
