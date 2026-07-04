"""
Out-of-band (OOB) tools — the ground-truth channel for blind vulnerabilities.

Backed by Beatrix's ``PoCServer`` (an aiohttp server on a free port). The agent
registers a unique callback URL, plants it inside a payload (blind SSRF, blind
RCE, XXE, etc.), then polls: if the target server ever hits the URL, that is
proof the payload executed — the difference between a guess and a validated
finding.

The PoCServer is started once per run by the runner and shared through the
session, so recon/exploitation/validation all see the same callbacks.
"""

from __future__ import annotations

from agents import RunContextWrapper, function_tool

from ..core.session import GhostSession


def _server(session: GhostSession):
    srv = getattr(session, "pocserver", None)
    if srv is None or not getattr(srv, "is_running", False):
        return None
    return srv


@function_tool
async def oob_register(ctx: RunContextWrapper[GhostSession], vuln_type: str = "ssrf") -> str:
    """Register an out-of-band callback URL to plant in a payload.

    Returns a unique id and a callback URL. Put the URL in your payload (e.g.
    an SSRF target, an XXE external entity, a shell ``curl`` to it), send it,
    then call oob_poll with the id to see whether the target called back.

    Args:
        vuln_type: The vulnerability class this callback is for (ssrf, rce, xxe, ...).
    """
    import secrets

    server = _server(ctx.context)
    if server is None:
        return "OOB server unavailable for this run; use a differential/reflection check instead."
    uid = secrets.token_hex(8)
    url = server.oob_url(vuln_type, uid=uid, target_url=ctx.context.scope.target)
    return f"id={uid}\ncallback_url={url}\nPlant callback_url in your payload, then oob_poll('{uid}')."


@function_tool
async def oob_poll(ctx: RunContextWrapper[GhostSession], id: str) -> str:
    """Check whether an OOB callback URL was hit (proof the payload executed).

    Args:
        id: The id returned by oob_register.
    """
    server = _server(ctx.context)
    if server is None:
        return "OOB server unavailable for this run."
    callbacks = server.get_callbacks(uid=id)
    if not callbacks:
        return f"No callback for id={id} yet. If you just sent the payload, wait and poll again."
    lines = [f"CALLBACK RECEIVED for id={id} ({len(callbacks)}): payload executed — this is real proof."]
    for cb in callbacks[:5]:
        src = getattr(cb, "source_ip", "") or getattr(cb, "remote", "")
        method = getattr(cb, "method", "")
        lines.append(f"  {method} from {src}".rstrip())
    return "\n".join(lines)


__all__ = ["oob_register", "oob_poll"]
