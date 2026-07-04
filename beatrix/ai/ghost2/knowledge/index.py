"""
Knowledge base for GHOST v2 (issue #11).

A small, curated corpus of security writeups — one markdown file per
vulnerability class under ``store/`` — that the agent consults *before*
claiming impact. Each writeup defines what real (non-false-positive) impact
looks like for that class, how to confirm it with Beatrix's tooling, and the
common false positives to reject. Grounding the agent in these writeups is the
core of the FP-reduction goal.

Two-tier progressive retrieval:

* ``load_skill(topic)`` — deterministic category lookup. Cheap, no embeddings:
  a topic (a scanner key like ``idor``, an alias like ``blind-ssrf``, or the
  category name) maps to exactly one writeup, returned in full.
* ``search(query, k)`` — ranked lookup across the whole corpus. Uses BM25
  (``rank-bm25``) when installed, and degrades to a pure-Python token-overlap
  score when it isn't, so the base install never breaks.

The corpus is tiny (a few dozen short docs), so it is loaded and indexed once
per process via :func:`get_kb` and kept in memory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_STORE = Path(__file__).parent / "store"

# Aliases → canonical category (the ``store/<category>.md`` stem). Includes the
# ``run_scanner`` module keys so ``load_skill("injection")`` or
# ``load_skill("bac")`` resolve, plus common informal names the model may use.
_ALIASES: Dict[str, str] = {
    # SQL injection
    "sqli": "sqli", "sql": "sqli", "sql-injection": "sqli",
    "blind-sqli": "sqli", "injection": "sqli",
    # Cross-site scripting
    "xss": "xss", "cross-site-scripting": "xss", "dom-xss": "xss",
    "stored-xss": "xss", "reflected-xss": "xss",
    # Command injection
    "rce": "command-injection", "command-injection": "command-injection",
    "cmdi": "command-injection", "os-command-injection": "command-injection",
    # SSRF
    "ssrf": "ssrf", "blind-ssrf": "ssrf", "server-side-request-forgery": "ssrf",
    # IDOR / access control
    "idor": "idor", "bola": "idor", "object-reference": "idor",
    "bac": "access-control", "access-control": "access-control",
    "broken-access-control": "access-control", "privilege-escalation": "access-control",
    "forced-browsing": "access-control",
    # Auth
    "auth": "auth-bypass", "auth-bypass": "auth-bypass",
    "authentication": "auth-bypass", "jwt": "auth-bypass",
    "session": "auth-bypass", "oauth": "auth-bypass", "oauth_redirect": "auth-bypass",
    # SSTI
    "ssti": "ssti", "template-injection": "ssti",
    "server-side-template-injection": "ssti",
    # XXE
    "xxe": "xxe", "xml": "xxe", "xml-external-entity": "xxe",
    # Deserialization
    "deserialization": "deserialization", "deser": "deserialization",
    "insecure-deserialization": "deserialization",
    # CORS
    "cors": "cors", "cross-origin": "cors",
    # Open redirect
    "redirect": "open-redirect", "open-redirect": "open-redirect",
    # GraphQL
    "graphql": "graphql", "gql": "graphql",
    # Mass assignment
    "mass_assignment": "mass-assignment", "mass-assignment": "mass-assignment",
    "autobinding": "mass-assignment",
    # Race conditions
    "race": "race-conditions", "race-condition": "race-conditions",
    "race-conditions": "race-conditions", "toctou": "race-conditions",
    # Business logic
    "business_logic": "business-logic", "business-logic": "business-logic",
    "logic": "business-logic",
    # File upload / path traversal
    "file_upload": "file-upload", "file-upload": "file-upload", "upload": "file-upload",
    "lfi": "path-traversal", "path-traversal": "path-traversal",
    "traversal": "path-traversal", "directory-traversal": "path-traversal",
}

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> List[str]:
    return _TOKEN_RE.findall(text.lower())


def _normalize(topic: str) -> str:
    return re.sub(r"[\s_]+", "-", topic.strip().lower()).strip("-")


@dataclass
class Writeup:
    """One knowledge-base document."""

    category: str
    title: str
    text: str

    def snippet(self, n: int = 240) -> str:
        body = self.text.strip()
        return body if len(body) <= n else body[:n].rsplit(" ", 1)[0] + " …"


class KnowledgeBase:
    """In-memory index over the ``store/`` writeups."""

    def __init__(self, store: Path = _STORE):
        self._store = store
        self._docs: Dict[str, Writeup] = {}
        self._bm25 = None
        self._corpus_tokens: List[List[str]] = []
        self._ordered: List[str] = []  # category order matching _corpus_tokens
        self._load()
        self._build_index()

    # ── loading / indexing ──────────────────────────────────────────────
    def _load(self) -> None:
        if not self._store.is_dir():
            return
        for path in sorted(self._store.glob("*.md")):
            text = path.read_text(encoding="utf-8", errors="replace")
            first = text.lstrip().splitlines()[0] if text.strip() else path.stem
            title = first.lstrip("# ").strip() or path.stem
            self._docs[path.stem] = Writeup(category=path.stem, title=title, text=text)

    def _build_index(self) -> None:
        self._ordered = list(self._docs)
        self._corpus_tokens = [
            _tokenize(f"{d.category} {d.title} {d.text}")
            for d in (self._docs[c] for c in self._ordered)
        ]
        try:
            from rank_bm25 import BM25Okapi  # optional dep

            if self._corpus_tokens:
                self._bm25 = BM25Okapi(self._corpus_tokens)
        except Exception:
            self._bm25 = None  # pure-Python fallback in search()

    # ── retrieval ───────────────────────────────────────────────────────
    @property
    def categories(self) -> List[str]:
        return list(self._docs)

    def resolve(self, topic: str) -> Optional[str]:
        """Map a topic/alias/scanner-key to a canonical category, or None."""
        norm = _normalize(topic)
        if norm in self._docs:
            return norm
        alias = _ALIASES.get(norm) or _ALIASES.get(topic.strip().lower())
        if alias in self._docs:
            return alias
        return None

    def load_skill(self, topic: str) -> Optional[Writeup]:
        """Return the full writeup for a topic via deterministic lookup."""
        category = self.resolve(topic)
        return self._docs.get(category) if category else None

    def search(self, query: str, k: int = 3) -> List[Tuple[Writeup, float]]:
        """Return up to ``k`` (writeup, score) pairs ranked by relevance."""
        if not self._docs:
            return []
        q_tokens = _tokenize(query)
        if not q_tokens:
            return []

        if self._bm25 is not None:
            scores = self._bm25.get_scores(q_tokens)
        else:
            scores = self._overlap_scores(q_tokens)

        ranked = sorted(
            zip(self._ordered, scores), key=lambda t: t[1], reverse=True
        )
        out: List[Tuple[Writeup, float]] = []
        for category, score in ranked[:k]:
            if score <= 0:
                continue
            out.append((self._docs[category], float(score)))
        return out

    def _overlap_scores(self, q_tokens: List[str]) -> List[float]:
        """Dependency-free ranking: normalized query-token overlap per doc."""
        q_set = set(q_tokens)
        scores: List[float] = []
        for tokens in self._corpus_tokens:
            if not tokens:
                scores.append(0.0)
                continue
            doc_set = set(tokens)
            hits = sum(1 for t in q_set if t in doc_set)
            # Reward matches, lightly penalize very long docs to spread scores.
            scores.append(hits / (1 + len(doc_set) / 400))
        return scores


@lru_cache(maxsize=1)
def get_kb() -> KnowledgeBase:
    """Process-wide singleton knowledge base (loaded + indexed once)."""
    return KnowledgeBase()


__all__ = ["KnowledgeBase", "Writeup", "get_kb"]
