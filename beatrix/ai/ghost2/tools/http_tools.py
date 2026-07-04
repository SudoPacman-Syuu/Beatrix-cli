"""
HTTP tools for GHOST v2.

Native openai-agents function tools that let the agent send requests, inject
payloads, encode strings for WAF evasion, and diff responses. The request /
indicator-detection logic is ported from the legacy ``beatrix/ai/ghost.py``
(``_send_http``, ``_tool_inject_payload``, ``_tool_encode_payload``), but the
response store now lives on the shared ``GhostSession`` instead of per-agent
instance state.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse
from typing import Dict, Optional

import httpx
from agents import RunContextWrapper, function_tool

from ..core.session import GhostSession, StoredResponse

# ── Indicator patterns (ported from ghost.py) ──────────────────────────────
_SQL_ERROR = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite/JDBCDriver|"
    r"Unclosed quotation mark|quoted string not properly terminated|"
    r"You have an error in your SQL syntax)",
    re.IGNORECASE,
)
_STACK_TRACE = re.compile(
    r"(Traceback \(most recent call last\)|Exception in thread|"
    r"at [\w.$]+\([\w.]+\.java:\d+\)|\.php on line \d+|Warning: |Fatal error:)",
    re.IGNORECASE,
)

_IMPORTANT_HEADERS = {
    "content-type", "server", "x-powered-by", "set-cookie",
    "x-frame-options", "content-security-policy", "location",
}


def _describe_http_error(url: str, exc: Exception) -> str:
    """Turn an httpx exception into a message the agent can act on.

    httpx network errors often stringify to an empty message (e.g.
    ``ConnectTimeout('')``), which openai-agents would surface to the model as a
    bare "an error occurred" — leaving the agent to retry blindly. We report the
    error class and a hint so it can change tactics (different host, note it as
    unreachable) instead.
    """
    kind = type(exc).__name__
    detail = str(exc).strip()
    hint = ""
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout)):
        hint = " — the host is unreachable or blocking connections from here; it is not a payload/tool problem."
    elif isinstance(exc, (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout)):
        hint = " — the request timed out; the server may be slow or the endpoint may hang."
    return f"Request to {url} failed: {kind}{f' ({detail})' if detail else ''}.{hint}"


def _parse_headers(raw: str) -> Dict[str, str]:
    """Parse headers from JSON, python-dict-literal, or ``Key: Value`` lines."""
    if not raw or raw.strip() in ("{}", ""):
        return {}
    raw = raw.strip()
    for candidate in (raw, raw.replace("'", '"') if raw.startswith("{") else None):
        if candidate is None:
            continue
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
        except (json.JSONDecodeError, ValueError):
            pass
    headers: Dict[str, str] = {}
    for line in raw.split("\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip().strip("'\"{")
            if key:
                headers[key] = v.strip().strip("'\"}")
    return headers


async def _send(
    session: GhostSession,
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
) -> StoredResponse:
    merged = {**session.scope.base_headers}
    if headers:
        merged.update(headers)
    merged.setdefault("User-Agent", "GHOST/2.0")

    async with httpx.AsyncClient(timeout=20, follow_redirects=True, verify=False) as client:
        start = time.monotonic()
        resp = await client.request(
            method=method.upper(), url=url, headers=merged,
            content=body, cookies=session.scope.base_cookies,
        )
        elapsed = int((time.monotonic() - start) * 1000)

    return await session.store_response(
        status_code=resp.status_code,
        headers=dict(resp.headers),
        body=resp.text,
        response_time_ms=elapsed,
        url=url,
        method=method.upper(),
    )


@function_tool
async def http_request(
    ctx: RunContextWrapper[GhostSession],
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
) -> str:
    """Send an HTTP request to a target URL and cache the response.

    Args:
        url: Absolute URL to request.
        method: HTTP method (GET, POST, PUT, DELETE, ...).
        headers: Extra headers as JSON (``{"X-Foo": "bar"}``) or ``Key: Value`` lines.
        body: Optional request body.
    """
    try:
        stored = await _send(ctx.context, method, url, _parse_headers(headers), body or None)
    except httpx.HTTPError as e:
        return _describe_http_error(url, e)
    header_summary = "; ".join(
        f"{k}: {v}" for k, v in stored.headers.items() if k.lower() in _IMPORTANT_HEADERS
    )
    return (
        f"Response #{stored.id}\n"
        f"Status: {stored.status_code}  Time: {stored.response_time_ms}ms  "
        f"Length: {len(stored.body)} bytes\n"
        f"Headers: {header_summary}\n"
        f"Body preview: {stored.body[:600]}"
    )


@function_tool
async def inject(
    ctx: RunContextWrapper[GhostSession],
    url: str,
    parameter: str,
    payload: str,
    location: str = "query",
) -> str:
    """Inject a payload into a parameter, send the request, and analyze the response.

    Sends a clean baseline first, then the payloaded request, and reports
    status/length/timing deltas plus SQL-error, reflection, and stack-trace
    indicators — the raw signal you need to decide whether a bug is real.

    Args:
        url: Target URL (may already contain query parameters).
        parameter: Name of the parameter to inject into.
        payload: The payload string to inject.
        location: Where to inject — "query" (URL query string) or "body" (form body).
    """
    session = ctx.context
    location = location.lower()

    method = "GET" if location == "query" else "POST"
    headers = {"Content-Type": "application/x-www-form-urlencoded"} if location == "body" else None
    try:
        # Baseline (parameter present with a benign value)
        base_url, base_body = _build_request(url, parameter, "1", location)
        baseline = await _send(session, method, base_url, None, base_body)

        # Payloaded request
        inj_url, inj_body = _build_request(url, parameter, payload, location)
        actual = await _send(session, method, inj_url, headers, inj_body)
    except httpx.HTTPError as e:
        return _describe_http_error(url, e)

    indicators = []
    if _SQL_ERROR.search(actual.body):
        indicators.append("SQL error string present")
    if payload and payload in actual.body:
        indicators.append("payload reflected in response")
    if _STACK_TRACE.search(actual.body) and not _STACK_TRACE.search(baseline.body):
        indicators.append("stack trace / server exception surfaced")
    if actual.status_code != baseline.status_code:
        indicators.append(f"status changed {baseline.status_code}→{actual.status_code}")
    len_delta = len(actual.body) - len(baseline.body)
    if abs(len_delta) > max(50, int(0.2 * max(1, len(baseline.body)))):
        indicators.append(f"length delta {len_delta:+d} bytes")
    if actual.response_time_ms > baseline.response_time_ms * 3 and actual.response_time_ms > 2000:
        indicators.append(f"response {actual.response_time_ms}ms vs baseline {baseline.response_time_ms}ms (possible time-based)")

    verdict = "; ".join(indicators) if indicators else "no obvious anomaly"
    return (
        f"Baseline #{baseline.id}: {baseline.status_code}, {len(baseline.body)} bytes, {baseline.response_time_ms}ms\n"
        f"Injected #{actual.id}: {actual.status_code}, {len(actual.body)} bytes, {actual.response_time_ms}ms\n"
        f"Indicators: {verdict}"
    )


def _build_request(url: str, parameter: str, value: str, location: str):
    """Return (url, body) with ``parameter=value`` placed per ``location``."""
    if location == "query":
        parsed = urllib.parse.urlparse(url)
        q = dict(urllib.parse.parse_qsl(parsed.query))
        q[parameter] = value
        new_query = urllib.parse.urlencode(q)
        return urllib.parse.urlunparse(parsed._replace(query=new_query)), None
    # body
    return url, urllib.parse.urlencode({parameter: value})


@function_tool
async def encode_payload(payload: str, encoding: str = "url") -> str:
    """Encode a payload for WAF evasion.

    Args:
        payload: The raw payload string.
        encoding: One of url, double_url, base64, html, hex, unicode.
    """
    enc = encoding.lower()
    if enc == "url":
        out = urllib.parse.quote(payload, safe="")
    elif enc == "double_url":
        out = urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
    elif enc == "base64":
        out = base64.b64encode(payload.encode()).decode()
    elif enc == "html":
        out = "".join(f"&#{ord(c)};" for c in payload)
    elif enc == "hex":
        out = "".join(f"\\x{ord(c):02x}" for c in payload)
    elif enc == "unicode":
        out = "".join(f"\\u{ord(c):04x}" for c in payload)
    else:
        return f"Unknown encoding '{encoding}'. Use url, double_url, base64, html, hex, or unicode."
    return f"{encoding}: {out}"


@function_tool
async def compare_responses(ctx: RunContextWrapper[GhostSession], id_a: int, id_b: int) -> str:
    """Diff two cached responses by their ids (from earlier tool output)."""
    session = ctx.context
    a, b = session.get_response(id_a), session.get_response(id_b)
    if a is None or b is None:
        return f"Response id not found (have ids: {sorted(session._responses)})."
    parts = [
        f"#{id_a}: {a.status_code}, {len(a.body)} bytes, {a.response_time_ms}ms",
        f"#{id_b}: {b.status_code}, {len(b.body)} bytes, {b.response_time_ms}ms",
    ]
    if a.status_code != b.status_code:
        parts.append(f"status differs: {a.status_code} vs {b.status_code}")
    len_delta = len(b.body) - len(a.body)
    if abs(len_delta) > 10:
        parts.append(f"length delta {len_delta:+d} bytes")
    if a.body == b.body:
        parts.append("bodies identical")
    return "\n".join(parts)
