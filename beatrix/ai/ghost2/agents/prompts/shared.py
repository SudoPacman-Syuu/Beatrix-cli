"""Shared prompt fragments: rules of engagement and methodology."""

from __future__ import annotations

from ...core.session import Scope


def rules_of_engagement(scope: Scope) -> str:
    hosts = ", ".join(scope.allowed_hosts) if scope.allowed_hosts else scope.host()
    return (
        "RULES OF ENGAGEMENT\n"
        f"- Authorized target: {scope.target}\n"
        f"- In-scope host(s): {hosts}\n"
        "- Never send requests to any host outside the authorized scope.\n"
        "- This is authorized security testing. Be thorough, but stay in scope.\n"
    )


METHODOLOGY = """METHODOLOGY
1. UNDERSTAND — map the target: fetch it, run recon/crawl scanners, note the tech stack and endpoints.
2. HYPOTHESIZE — from what you see, form specific, testable vulnerability hypotheses.
3. STUDY — before you test a vulnerability class, load_skill(<class>) (e.g. "ssrf", "idor", "sqli"). The writeup tells you how to confirm real impact and which signals are false positives. Use kb_search(<symptom>) when unsure which class applies.
4. TEST — drive Beatrix's scanners (run_scanner) and your HTTP/inject tools to test each hypothesis.
5. CONFIRM — corroborate anomalies with a second signal before believing them; distinguish real bugs from noise, using the writeup's false-positive criteria.
6. DOCUMENT — call record_finding once per confirmed issue, with concrete evidence. Set validated=True only when you have proof.
"""
