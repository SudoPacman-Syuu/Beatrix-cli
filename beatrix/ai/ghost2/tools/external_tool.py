"""
``run_external_tool`` — drive Beatrix's external-binary arsenal from the agent.

Beatrix wraps ~20 external security tools (sqlmap, dalfox, commix, arjun,
katana, gau, dirsearch, whatweb, jwt_tool, …) behind ``ExternalToolkit``. This
bridge exposes the highest-value ones to the agent through a single tool, so
GHOST can escalate a lead with the same battle-tested runners the deterministic
``beatrix hunt`` pipeline uses — no reimplementation.

Like ``run_scanner`` (in-process httpx scanners) and unlike ``shell`` /
``python_exec`` (arbitrary agent-authored code), these are fixed binaries
invoked with a target argument — the same execution profile ``beatrix hunt``
already has on the host — so they don't require the sandbox's ``allow_exec``
gate. Routing the external binaries *through* the Docker sandbox (via the
``ExternalTool._run`` seam) is a later hardening pass; today they run on the
host runtime, matching the existing pipeline. A scope guard keeps these noisier
tools inside the authorized target.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from agents import RunContextWrapper, function_tool

from ..core.session import GhostSession

# Lazily-built, process-wide toolkit (locating binaries is mildly expensive).
_TOOLKIT = None


def _toolkit():
    global _TOOLKIT
    if _TOOLKIT is None:
        from beatrix.core.external_tools import ExternalToolkit

        _TOOLKIT = ExternalToolkit()
    return _TOOLKIT


def _opt_int(opts: Dict[str, str], key: str, default: int) -> int:
    try:
        return int(opts.get(key, default))
    except (TypeError, ValueError):
        return default


def _parse_options(raw: str) -> Dict[str, str]:
    """Parse the options argument (a JSON object string) into a flat str dict.

    Tolerant: accepts ``{}``/empty, JSON with single quotes, and coerces all
    values to strings so handlers can read them uniformly.
    """
    if not raw or not raw.strip() or raw.strip() == "{}":
        return {}
    text = raw.strip()
    for candidate in (text, text.replace("'", '"')):
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items() if v is not None}
        except (json.JSONDecodeError, ValueError):
            continue
    return {}


# Each handler maps (toolkit, target, options) → the runner's own coroutine.
# ``url_target`` marks tools whose target is a URL/host (scope-checked); the
# others (e.g. jwt_tool) take a non-network argument like a token.
async def _sqlmap(tk, target, o):
    return await tk.sqlmap.exploit(
        url=target, param=o.get("param"), method=o.get("method", "GET"),
        data=o.get("data"), level=_opt_int(o, "level", 2), risk=_opt_int(o, "risk", 1),
    )


async def _dalfox(tk, target, o):
    return await tk.dalfox.scan(url=target, param=o.get("param"))


async def _commix(tk, target, o):
    return await tk.commix.exploit(url=target, param=o.get("param"), data=o.get("data"))


async def _arjun(tk, target, o):
    return await tk.arjun.discover(url=target, method=o.get("method", "GET"))


async def _jwt_tool(tk, target, o):
    claim = o.get("claim")
    if claim is not None:
        return await tk.jwt_tool.tamper(token=target, claim=claim, value=o.get("value", ""))
    return await tk.jwt_tool.analyze(token=target)


async def _katana(tk, target, o):
    return await tk.katana.crawl(url=target, depth=_opt_int(o, "depth", 3))


async def _gau(tk, target, o):
    return await tk.gau.fetch_urls(domain=target)


async def _whatweb(tk, target, o):
    return await tk.whatweb.fingerprint(url=target)


async def _webanalyze(tk, target, o):
    return await tk.webanalyze.fingerprint(url=target)


async def _dirsearch(tk, target, o):
    return await tk.dirsearch.scan(
        url=target, extensions=o.get("extensions", "php,asp,aspx,jsp,html,js,json"),
    )


async def _nomore403(tk, target, o):
    return await tk.nomore403.bypass(url=target)


async def _crlfuzz(tk, target, o):
    return await tk.crlfuzz.scan(url=target)


# name → (toolkit attribute, handler, url_target?)
_SPEC = {
    "sqlmap": ("sqlmap", _sqlmap, True),
    "dalfox": ("dalfox", _dalfox, True),
    "commix": ("commix", _commix, True),
    "arjun": ("arjun", _arjun, True),
    "jwt_tool": ("jwt_tool", _jwt_tool, False),
    "katana": ("katana", _katana, True),
    "gau": ("gau", _gau, True),
    "whatweb": ("whatweb", _whatweb, True),
    "webanalyze": ("webanalyze", _webanalyze, True),
    "dirsearch": ("dirsearch", _dirsearch, True),
    "nomore403": ("nomore403", _nomore403, True),
    "crlfuzz": ("crlfuzz", _crlfuzz, True),
}

_TOOL_KEYS = ", ".join(_SPEC)


def _format(result: Any, limit: int = 4000) -> str:
    """Render a runner's structured result (dict / list / str) compactly."""
    if result is None:
        return "(no result)"
    if isinstance(result, str):
        text = result
    elif isinstance(result, dict):
        text = "\n".join(f"{k}: {_short(v)}" for k, v in result.items())
    elif isinstance(result, (list, tuple)):
        items = [str(_short(x)) for x in result]
        head = items[:40]
        text = "\n".join(head)
        if len(items) > 40:
            text += f"\n… and {len(items) - 40} more"
    else:
        text = str(result)
    return text if len(text) <= limit else text[:limit] + "\n… (truncated)"


def _short(v: Any, n: int = 500) -> Any:
    s = v if isinstance(v, str) else repr(v)
    return s if len(s) <= n else s[:n] + " …"


@function_tool
async def run_external_tool(
    ctx: RunContextWrapper[GhostSession],
    tool: str,
    target: str,
    options: str = "",
) -> str:
    """Run one of Beatrix's external security tools against a target.

    Use this to escalate a lead with a specialized binary once you have one —
    e.g. sqlmap to dump a confirmed SQLi, dalfox to prove XSS, commix for
    command injection, arjun to discover hidden params, jwt_tool on a token.

    Valid tools: sqlmap, dalfox, commix, arjun, jwt_tool, katana, gau, whatweb,
    webanalyze, dirsearch, nomore403, crlfuzz.

    Args:
        tool: Which external tool to run (see list above).
        target: URL or host to run against (for jwt_tool, pass the JWT).
        options: A JSON object string of extra settings, pass only what applies.
            Supported keys: param, method, data (POST body), level, risk
            (sqlmap); claim, value (jwt_tool tamper); depth (katana);
            extensions (dirsearch). Example: '{"param":"id","method":"POST"}'.
    """
    tool = tool.strip().lower()
    spec = _SPEC.get(tool)
    if spec is None:
        return f"Unknown tool '{tool}'. Valid tools: {_TOOL_KEYS}."
    attr, handler, url_target = spec

    session = ctx.context
    if url_target and not session.scope.in_scope(target):
        return (
            f"Refusing to run {tool}: '{target}' is outside the authorized scope "
            f"({', '.join(session.scope.allowed_hosts) or session.scope.host()})."
        )

    toolkit = _toolkit()
    # Route raw tool output into this run's scan directory, if one is attached.
    om = getattr(session, "output_manager", None)
    if om is not None:
        toolkit.set_output_manager(om)
    runner = getattr(toolkit, attr)
    if not getattr(runner, "available", False):
        return (
            f"'{tool}' is not installed on this host. "
            "Install it (see install.sh) or use a built-in scanner instead."
        )

    session.record_module(f"ext:{tool}")
    try:
        result = await handler(toolkit, target, _parse_options(options))
    except Exception as e:  # noqa: BLE001 - surface tool failures to the model
        return f"{tool} failed on {target}: {type(e).__name__}: {e}"

    return f"{tool} against {target}:\n{_format(result)}"


__all__ = ["run_external_tool"]
