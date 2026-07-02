"""
BEATRIX Browser Transport

Lightweight HTTP transport backed by a real Chromium network stack
(Playwright's APIRequestContext), for targets that fingerprint scripted
HTTP clients (httpx) and block/redirect otherwise-valid authenticated
sessions.

Uses `context.request` rather than full page navigation — this shares
Chromium's real TLS/network fingerprint (which is what defeats bot
fingerprinting like Akamai's) without the overhead of rendering a page
per request, making it fast enough to use as a scanner's request
transport rather than just for one-off checks.

Important: passing cookies as an explicit `Cookie:` header on
`context.request.fetch()` does NOT reliably authenticate — verified
empirically against a real Akamai-fronted target, a request with only a
header (no jar entry) got redirected to login while the same cookies
seeded into the context's cookie jar succeeded. So this client keeps
cookies in the browser context's jar, re-syncing it before each request
from whatever `Cookie` header the caller passed — this lets callers
(like the IDOR scanner, which swaps between two accounts per request)
keep using a plain header-based interface identical to httpx, while the
actual authentication happens through the jar underneath.
"""

import asyncio
import json as _json
from typing import Any, Dict, List, Optional

try:
    from playwright.async_api import APIResponse, BrowserContext, async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class BrowserResponse:
    """Minimal httpx.Response-compatible wrapper around a Playwright APIResponse."""

    def __init__(self, api_response: "APIResponse", body: bytes, url: str):
        self._resp = api_response
        self._body = body
        self.status_code = api_response.status
        self.headers = dict(api_response.headers)
        self.url = url

    @property
    def content(self) -> bytes:
        return self._body

    @property
    def text(self) -> str:
        return self._body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return _json.loads(self.text)


def _parse_cookie_header(cookie_str: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out


class BrowserRequestClient:
    """
    Persistent browser-backed request client for one scan.

    Launches Chromium once and reuses it across many calls, unlike a
    one-off Playwright launch per request which would be far too slow
    for scanner-scale traffic. The cookie jar is re-synced (cleared and
    re-added) before each request based on the caller's `Cookie` header,
    so a single client transparently supports callers that switch between
    multiple sessions per request (e.g. IDOR's user1/user2 comparison).
    """

    def __init__(self, user_agent: Optional[str] = None):
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright not available for browser transport. "
                "Install with: pip install playwright && playwright install chromium"
            )
        self._user_agent = user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )
        self._playwright = None
        self._browser = None
        self._context: Optional["BrowserContext"] = None
        self._current_cookie_key: Optional[str] = None  # dedupes repeated jar syncs

    async def start(self) -> None:
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(args=["--no-sandbox"])
        self._context = await self._browser.new_context(user_agent=self._user_agent)

    async def _sync_cookies(self, cookie_header: str, domain: str) -> None:
        # Skip the clear+re-add round trip if the jar already matches —
        # the common case when a scanner isn't actively switching accounts.
        if cookie_header == self._current_cookie_key:
            return
        await self._context.clear_cookies()
        cookies = _parse_cookie_header(cookie_header)
        if cookies:
            jar_domain = domain if domain.startswith(".") else f".{domain}"
            await self._context.add_cookies([
                {"name": k, "value": v, "domain": jar_domain, "path": "/"}
                for k, v in cookies.items()
            ])
        self._current_cookie_key = cookie_header

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        **_ignored: Any,
    ) -> BrowserResponse:
        """Send one request through the browser's network stack.

        Signature mirrors the subset of httpx.AsyncClient.request() that
        BaseScanner actually uses, so it's a drop-in swap at the call site.
        A `Cookie` header, if present, is moved into the context's cookie
        jar rather than sent as a literal header (see module docstring).
        """
        if self._context is None:
            raise RuntimeError("BrowserRequestClient not started — call start() first")

        headers = dict(headers or {})
        cookie_header = None
        for k in list(headers.keys()):
            if k.lower() == "cookie":
                cookie_header = headers.pop(k)

        from urllib.parse import urlparse as _urlparse
        domain = _urlparse(url).netloc.split(":")[0]
        if cookie_header is not None:
            await self._sync_cookies(cookie_header, domain)

        kwargs: Dict[str, Any] = {"headers": headers}
        if params:
            kwargs["params"] = params
        if timeout is not None:
            kwargs["timeout"] = timeout * 1000  # Playwright wants ms
        if json is not None:
            kwargs["data"] = _json.dumps(json)
            kwargs["headers"].setdefault("Content-Type", "application/json")
        elif content is not None:
            kwargs["data"] = content
        elif data is not None:
            kwargs["data"] = data

        api_resp = await self._context.request.fetch(url, method=method.upper(), **kwargs)
        body = await api_resp.body()
        return BrowserResponse(api_resp, body, api_resp.url)

    async def capture_page_responses(
        self,
        url: str,
        cookie_header: str,
        domain: str,
        settle_ms: int = 2500,
        timeout_ms: int = 20000,
    ) -> List[Dict[str, Any]]:
        """Navigate a real page and capture the background XHR/fetch
        responses fired while it loads.

        `request()` above deliberately avoids page navigation for speed,
        but that means it never executes the target's JavaScript — fine
        for server-rendered targets, but on a client-rendered SPA the
        initial HTML/status is identical whether authenticated or not;
        login state only shows up in the API calls the app itself fires
        after hydration (e.g. a `viewer`/`me` GraphQL call). This method
        trades speed for that visibility: it actually loads the page,
        waits for the network to settle, and returns what the app called
        so SessionValidator can diff an authenticated run against an
        anonymous one the same way it already diffs plain GETs.
        """
        if self._context is None:
            raise RuntimeError("BrowserRequestClient not started — call start() first")

        await self._sync_cookies(cookie_header, domain)

        captured: List[Dict[str, Any]] = []
        pending: List[asyncio.Task] = []

        async def _capture(response) -> None:
            try:
                ctype = response.headers.get("content-type", "")
                if "json" not in ctype and "html" not in ctype:
                    return
                req = response.request
                if req.resource_type not in ("xhr", "fetch", "document"):
                    return
                body = await response.body()
                captured.append({
                    "method": req.method,
                    "url": response.url,
                    "status": response.status,
                    "content_type": ctype,
                    "body": body.decode("utf-8", errors="replace")[:20000],
                    "post_data": req.post_data or "",
                })
            except Exception:
                pass  # response body can be discarded by the time we read it (redirects, aborts) — skip it

        def _on_response(response) -> None:
            pending.append(asyncio.ensure_future(_capture(response)))

        page = await self._context.new_page()
        page.on("response", _on_response)
        try:
            try:
                await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception:
                pass  # SPAs that poll/long-poll never go fully idle — use whatever loaded before timeout
            await page.wait_for_timeout(settle_ms)
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        finally:
            await page.close()

        return captured

    async def close(self) -> None:
        try:
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass
