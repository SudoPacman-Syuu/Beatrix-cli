"""
Knowledge-base tools: ``load_skill`` and ``kb_search`` (issue #11).

These give the agent progressive access to a curated corpus of vulnerability
writeups (``knowledge/store/``). The prompts require exploitation and
validation agents to ``load_skill`` the relevant class before claiming impact —
the writeups define what *real* impact looks like and which signals are false
positives, which is how the knowledge base reduces the FP rate.

Both tools are read-only and cheap, so every role gets them.
"""

from __future__ import annotations

from agents import function_tool

from ..knowledge.index import get_kb


@function_tool
async def load_skill(topic: str) -> str:
    """Load the security writeup for a vulnerability class before exploiting it.

    Consult this BEFORE claiming impact for a bug class: the writeup defines
    what genuine (non-false-positive) impact looks like, how to confirm it with
    Beatrix's tools, and which signals are noise to reject.

    ``topic`` accepts a scanner key (e.g. "idor", "ssrf", "injection", "bac"),
    a common name ("blind-ssrf", "jwt", "template-injection"), or a category
    name. If it doesn't resolve, you'll get the list of available topics — try
    kb_search instead.

    Args:
        topic: The vulnerability class to study (scanner key, alias, or category).
    """
    kb = get_kb()
    writeup = kb.load_skill(topic)
    if writeup is None:
        cats = ", ".join(kb.categories) or "(none installed)"
        return (
            f"No writeup for '{topic}'. Available topics: {cats}. "
            "Use kb_search(<query>) for a keyword search."
        )
    return writeup.text


@function_tool
async def kb_search(query: str, k: int = 3) -> str:
    """Search the security knowledge base for writeups relevant to a query.

    Use this when you're not sure which vulnerability class applies, or want
    guidance for a specific symptom (e.g. "response reflects filename in error"
    or "jwt none algorithm"). Returns the top matches with a snippet each; call
    load_skill(<category>) to read the full writeup.

    Args:
        query: What you're looking for (a symptom, technique, or vuln class).
        k: How many results to return (default 3).
    """
    kb = get_kb()
    results = kb.search(query, k=max(1, min(k, 8)))
    if not results:
        return f"No knowledge-base matches for '{query}'."
    lines = [f"Top {len(results)} match(es) for '{query}':"]
    for writeup, score in results:
        lines.append(
            f"  • [{writeup.category}] {writeup.title}  (score {score:.2f})\n"
            f"    {writeup.snippet()}"
        )
    lines.append("Call load_skill(<category>) to read a full writeup.")
    return "\n".join(lines)


__all__ = ["load_skill", "kb_search"]
