"""
Ingest curated, publicly-disclosed HackerOne report excerpts into ghost2's
knowledge base (issue #11).

The 18 rubric writeups under ``store/*.md`` say what real impact looks like
in the abstract; this adds concrete, genuine examples alongside them — real
disclosed reports, not synthesized ones.

Source: ``ajaysenr/HackerOne-Disclosed-Reports`` on GitHub, an actively
maintained mirror of public HackerOne disclosures that already includes full
report body text (``reports/<id>.md``) and a metadata index
(``index.json``). This script never talks to hackerone.com directly — every
report it reads is already public, mirrored there by the reporting
researcher's and program's own choice to disclose.

Run standalone to (re-)build the corpus:

    python -m beatrix.ai.ghost2.knowledge.ingest_hackerone

Idempotent — skips report ids already present in a category's ``.jsonl``, so
it's safe to re-run periodically as the source repo grows (it's updated
same-day as of this writing).
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Set

_INDEX_URL = "https://raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/index.json"
_REPORT_URL = "https://raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/reports/{id}.md"
_STORE_DIR = Path(__file__).parent / "store" / "examples"

_MAX_PER_CATEGORY = 6
_CANDIDATE_POOL_MULTIPLIER = 4  # over-fetch candidates since some mirrored
                                # reports have no captured body text — we skip
                                # those and fall through to the next-best one.
_MAX_EXCERPT_WORDS = 400  # keeps each on-disk excerpt small at ingestion time,
                          # so load_skill's per-category output stays bounded
                          # no matter how large the corpus grows over time.
_MIN_SEVERITY = {"critical", "high"}

# category -> keywords matched against the report's `weakness` field (primary
# signal — HackerOne's own CWE-style classification).
_WEAKNESS_KEYWORDS: Dict[str, List[str]] = {
    "sqli": ["sql injection"],
    "ssrf": ["server-side request forgery", "ssrf"],
    "xxe": ["xml external entit"],
    "xss": ["cross-site scripting", "cross site scripting"],
    "idor": ["insecure direct object reference", "idor"],
    "access-control": ["improper access control", "broken access control"],
    "deserialization": ["deserialization"],
    "command-injection": ["command injection", "os command injection"],
    "open-redirect": ["open redirect"],
    "race-conditions": ["race condition", "time-of-check", "toctou"],
    "path-traversal": ["path traversal", "directory traversal"],
    "auth-bypass": ["authentication bypass", "improper authentication"],
    "business-logic": ["business logic"],
    "file-upload": ["unrestricted upload", "file upload"],
    # No dedicated weakness bucket in the source taxonomy for these three —
    # fall through to the title-keyword match below.
    "cors": [],
    "graphql": [],
    "mass-assignment": [],
    "ssti": ["template injection", "server-side template"],
}

# Fallback: category -> keywords matched against the report title, used when
# the weakness-based match finds nothing (or the category has no CWE bucket).
_TITLE_KEYWORDS: Dict[str, List[str]] = {
    "cors": ["cors", "cross-origin"],
    "graphql": ["graphql"],
    "mass-assignment": ["mass assignment", "mass-assignment"],
    "ssti": ["template injection", "ssti"],
}


def _fetch(url: str) -> Optional[str]:
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"  ! fetch failed: {url}: {e}", file=sys.stderr)
        return None


def _select_reports(index: List[dict]) -> Dict[str, List[dict]]:
    """Bucket index records into ghost2 categories, top-N by bounty per category."""
    buckets: Dict[str, List[dict]] = {c: [] for c in _WEAKNESS_KEYWORDS}

    for rec in index:
        severity = (rec.get("severity") or "").lower()
        if severity not in _MIN_SEVERITY:
            continue
        weakness = (rec.get("weakness") or "").lower()
        title = (rec.get("title") or "").lower()

        matched = None
        for cat, keywords in _WEAKNESS_KEYWORDS.items():
            if keywords and any(k in weakness for k in keywords):
                matched = cat
                break
        if matched is None:
            for cat, keywords in _TITLE_KEYWORDS.items():
                if any(k in title for k in keywords):
                    matched = cat
                    break
        if matched is None:
            continue
        buckets[matched].append(rec)

    for cat, recs in buckets.items():
        recs.sort(key=lambda r: (r.get("bounty") or 0, r.get("votes") or 0), reverse=True)
        buckets[cat] = recs[: _MAX_PER_CATEGORY * _CANDIDATE_POOL_MULTIPLIER]
    return buckets


_PLACEHOLDER_PATTERNS = (
    "no vulnerability information available",
    "no official summary provided",
)


def _is_placeholder(text: str) -> bool:
    t = text.strip().strip("*").strip().lower()
    return not t or any(p in t for p in _PLACEHOLDER_PATTERNS)


def _section(report_md: str, heading: str, next_heading: Optional[str] = None) -> str:
    idx = report_md.find(heading)
    if idx == -1:
        return ""
    start = idx + len(heading)
    end = report_md.find(next_heading, start) if next_heading else -1
    body = report_md[start:end] if end != -1 else report_md[start:]
    body = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", body)  # strip embedded images
    return body.strip()


def _extract_excerpt(report_md: str) -> str:
    """Pull the real technical content out of a mirrored report file.

    The mirror's format is a metadata table, then "## Program Summary"
    (often just boilerplate — "No official summary provided"), then
    "## Vulnerability Details" with the researcher's actual write-up. Some
    older/incompletely-mirrored reports have no captured Details section
    either ("No vulnerability information available") — in that case fall
    back to the Program Summary if it has real content, else return "" so
    the caller skips this report and tries the next-best candidate.

    Whatever's kept is capped to a bounded word count at ingestion time, so
    reading this example later never returns something large.
    """
    details = _section(report_md, "## Vulnerability Details")
    summary = _section(report_md, "## Program Summary", "## Vulnerability Details")

    body = details if not _is_placeholder(details) else summary
    if _is_placeholder(body):
        return ""

    words = body.split()
    if len(words) > _MAX_EXCERPT_WORDS:
        body = " ".join(words[:_MAX_EXCERPT_WORDS]) + " […]"
    else:
        body = " ".join(words)
    return body.strip()


def _existing_ids(path: Path) -> Set[int]:
    if not path.exists():
        return set()
    ids: Set[int] = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ids.add(json.loads(line)["report_id"])
        except Exception:
            continue
    return ids


def ingest(categories: Optional[List[str]] = None) -> None:
    """Fetch the index, select top reports per category, pull + excerpt each.

    Pass ``categories`` to limit the run to specific ghost2 vuln classes
    (mainly useful for testing); omit it to refresh everything.
    """
    print("Fetching report index...")
    raw = _fetch(_INDEX_URL)
    if raw is None:
        print("Could not fetch the report index — aborting.", file=sys.stderr)
        return
    index = json.loads(raw)
    print(f"  {len(index)} reports in index")

    buckets = _select_reports(index)
    _STORE_DIR.mkdir(parents=True, exist_ok=True)

    for cat, recs in buckets.items():
        if categories and cat not in categories:
            continue
        out_path = _STORE_DIR / f"{cat}.jsonl"
        existing = _existing_ids(out_path)
        new_lines = []
        skipped_empty = 0
        target = max(0, _MAX_PER_CATEGORY - len(existing))
        for rec in recs:
            if len(new_lines) >= target:
                break
            rid = rec["id"]
            if rid in existing:
                continue
            report_md = _fetch(_REPORT_URL.format(id=rid))
            if report_md is None:
                continue
            excerpt = _extract_excerpt(report_md)
            if not excerpt:
                skipped_empty += 1
                continue
            new_lines.append(json.dumps({
                "report_id": rid,
                "title": rec.get("title", ""),
                "program": rec.get("program", ""),
                "url": rec.get("url", ""),
                "weakness": rec.get("weakness", ""),
                "severity": rec.get("severity", ""),
                "bounty": rec.get("bounty"),
                "cve_ids": rec.get("cve_ids") or [],
                "excerpt": excerpt,
            }))
            time.sleep(0.2)  # polite pacing against raw.githubusercontent.com

        skip_note = f", skipped {skipped_empty} empty" if skipped_empty else ""
        if new_lines:
            with out_path.open("a") as f:
                for line in new_lines:
                    f.write(line + "\n")
            print(f"  {cat}: +{len(new_lines)} new example(s) ({len(existing) + len(new_lines)} total{skip_note})")
        else:
            print(f"  {cat}: no new examples ({len(existing)} total{skip_note})")


if __name__ == "__main__":
    ingest()
