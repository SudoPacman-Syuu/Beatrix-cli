"""
Beatrix Suite — the central dashboard (`beatrix-suite`).

One local server, one port, one browser tab. A Burp-Suite-style top tab bar
switches between tools *inside the page* (client-side show/hide) instead of the
old "one server + one port + one new tab per tool" pattern.

Layout:
  * Left rail  — Projects: numbered workspaces the user switches between (each
                 sections off its own scan data / scope). "+" creates a project;
                 right-click a project -> Delete.
  * Top tabs   — Tools within the active project:
      - Auth   — the existing auth GUI, rendered inline in a same-origin
                 ``<iframe>`` (its ``/api/*`` calls are mounted on this server).
      - Ghost  — a target/objective form that launches a GHOST v2 investigation
                 in a background thread and streams its events inline.

Everything is stdlib ``http.server`` — no web-framework dependency, same toolkit
as the two GUIs it unifies. Only one ``webbrowser.open`` ever fires, at launch.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

# Reuse the auth GUI wholesale: its self-contained page + the exact backend
# functions the standalone `beatrix auth gui` uses, so saved data is identical.
from beatrix.cli.auth_gui import (
    _PAGE as _AUTH_PAGE,
    _build_and_save,
    _clear_auth,
    _get_model_settings,
    _list_auth,
    _list_keys,
    _list_openrouter_models,
    _save_keys,
    _save_model_settings,
)
# Reuse the ghost dashboard's thread-safe event ring buffer.
from beatrix.cli.ghost_web import _Broker

DEFAULT_PORT = 8790
DEFAULT_STATE_DIR = Path.home() / ".beatrix" / "suite"

# Auth route -> backend fn, mirroring auth_gui._Handler exactly.
_AUTH_GET = {
    "/api/list": _list_auth,
    "/api/keys": _list_keys,
    "/api/model": _get_model_settings,
    "/api/models": _list_openrouter_models,
}
_AUTH_POST = {
    "/api/save": _build_and_save,
    "/api/clear": _clear_auth,
    "/api/keys": _save_keys,
    "/api/model": _save_model_settings,
}


# ── Hunt module/preset catalog ───────────────────────────────────────────────
# Plain-language descriptions for the control panel's hover tooltips. Reuses
# the CLI's own MODULE_REFERENCE (same table `beatrix arsenal` prints) so
# descriptions never drift; a few modules that exist on BeatrixEngine but
# predate/postdate that table get a short fallback description here instead.
_MODULE_FALLBACK_DESC = {
    "param_miner": {
        "name": "Param Miner", "category": "Reconnaissance",
        "description": "Finds hidden, unlinked request parameters by diffing responses "
                        "against a large wordlist — surfaces debug flags, cache keys, "
                        "and undocumented API parameters.",
    },
    "sequencer": {
        "name": "Token Sequencer", "category": "A07: Authentication Failures",
        "description": "Statistically analyzes session tokens, password-reset codes, and "
                        "CSRF tokens for low entropy or predictable patterns.",
    },
    "backslash": {
        "name": "Backslash-Powered Scanner", "category": "A03: Injection",
        "description": "Probes how each parameter's input is actually processed before "
                        "attacking it — cuts false positives versus blindly spraying payloads.",
    },
    "dom_xss": {
        "name": "DOM XSS Scanner", "category": "A03: Injection",
        "description": "Drives a real browser (Playwright) to find client-side / "
                        "DOM-based XSS that a payload sent straight to the server would never trigger.",
    },
}

_catalog_cache: Dict[str, Any] = {}


def _build_hunt_catalog() -> Dict[str, Any]:
    """Build the module + preset catalog once, from the real engine.

    Modules are restricted to whatever ``BeatrixEngine`` actually loaded, so
    the panel can never offer a module that doesn't exist or isn't installed
    (e.g. ``dom_xss`` when Playwright is missing), and each is enriched with
    the plain-language description used for the control panel's hover tooltips.
    """
    if _catalog_cache:
        return _catalog_cache

    from beatrix.cli.main import MODULE_REFERENCE
    from beatrix.core.engine import BeatrixEngine

    engine = BeatrixEngine()
    modules = []
    for key in sorted(engine.modules):
        info = MODULE_REFERENCE.get(key) or _MODULE_FALLBACK_DESC.get(key) or {
            "name": key.replace("_", " ").title(), "category": "Other",
            "description": "No description available yet.",
        }
        modules.append({"key": key, "name": info["name"],
                        "category": info["category"], "description": info["description"]})
    # Sort by category (then name) so same-category modules are adjacent —
    # the control panel groups consecutive same-category entries under one
    # header, so alphabetical-by-key order would print a near-duplicate
    # header per module instead of grouping them.
    modules.sort(key=lambda m: (m["category"], m["name"]))

    presets = []
    for key, cfg in BeatrixEngine.PRESETS.items():
        preset_modules = cfg["modules"] or sorted(engine.modules)  # [] means "all modules"
        presets.append({
            "key": key, "name": cfg["name"], "description": cfg["description"],
            "modules": [m for m in preset_modules if m in engine.modules],
        })

    _catalog_cache["modules"] = modules
    _catalog_cache["presets"] = presets
    return _catalog_cache


def _hunt_event_to_line(event: str, data: dict) -> Optional[Dict[str, str]]:
    """Convert one kill-chain progress event into a terminal line for the Hunt
    broker. Mirrors the CLI hunt command's own event renderer (``main.py``'s
    ``_on_event``) so the browser terminal reads like the real CLI output —
    just without Rich markup, since the frontend colors lines by ``type``
    instead (same pattern as the Ghost pane's event tags).
    """
    if event == "phase_start":
        return {"type": "phase",
                "text": f"{data.get('icon', '🔧')} {data.get('phase', '')} — {data.get('description', '')}"}
    if event == "phase_done":
        dur = data.get("duration", 0)
        n = data.get("findings", 0)
        return {"type": "phase_done",
                "text": f"✓ {data.get('phase', '')} complete — {n} finding{'s' if n != 1 else ''} ({dur:.1f}s)"}
    if event == "crawl_start":
        return {"type": "info", "text": "🕷 Crawling target..."}
    if event == "crawl_done":
        return {"type": "info", "text": (
            f"🕷 Crawl complete — {data.get('pages', 0)} pages, {data.get('urls', 0)} URLs, "
            f"{data.get('params_urls', 0)} with params, {data.get('js_files', 0)} JS files"
        )}
    if event == "crawl_error":
        return {"type": "scanner_error", "text": f"✗ Crawl error: {data.get('error', '')}"}
    if event == "scanner_start":
        return {"type": "scanner_start", "text": f"▸ {data.get('scanner', '')} → {data.get('target', '')}"}
    if event == "scanner_done":
        # Quiet on zero-finding completions (33 modules × "done, 0 findings"
        # would drown the transcript) — matches the CLI's own verbosity choice.
        n = data.get("findings", 0)
        if n > 0:
            return {"type": "scanner_done",
                    "text": f"⚡ {data.get('scanner', '')} found {n} issue{'s' if n != 1 else ''}"}
        return None
    if event == "scanner_error":
        return {"type": "scanner_error", "text": f"✗ {data.get('scanner', '')}: {data.get('error', '')}"}
    if event == "finding":
        f = data.get("finding")
        if not f:
            return None
        sev = getattr(getattr(f, "severity", None), "value", "info")
        title = getattr(f, "title", "Finding")
        parts = []
        if getattr(f, "url", None):
            parts.append(f"URL: {f.url}")
        if getattr(f, "parameter", None):
            parts.append(f"Param: {f.parameter}")
        evidence = getattr(f, "evidence", None)
        if evidence:
            parts.append(f"Evidence: {str(evidence)[:500]}")
        return {"type": "finding", "text": f"[{sev.upper()}] {title}", "detail": "\n".join(parts)}
    if event == "info":
        return {"type": "info", "text": f"ℹ {data.get('message', '')}"}
    return None


# ── Scope parsing/matching (Burp-style target scope) ─────────────────────────
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _parse_scope_entry(raw: str) -> Optional[str]:
    """Normalize one pasted scope line to a bare hostname/IP.

    Accepts a full URL (``https://example.com/path``), a bare domain
    (``example.com``), an already-wildcarded pattern (``*.example.com``), or a
    bare IP — with or without a trailing path/port. Returns ``None`` for
    blank/unparseable input.
    """
    raw = raw.strip()
    if not raw:
        return None
    if "://" in raw:
        host = urlparse(raw).hostname
        return host.lower() if host else None
    host = raw.split("/", 1)[0].split(":", 1)[0].strip()
    return host.lower() or None


def _is_ip_literal(host: str) -> bool:
    return bool(_IPV4_RE.match(host)) or ":" in host  # crude-but-sufficient IPv6 check


def _expand_for_crawler(hosts: List[str]) -> List[str]:
    """Turn plain hostnames into crawler-compatible scope patterns.

    ``TargetCrawler._hostname_in_scope`` only treats a pattern as covering
    subdomains when it's explicitly written ``*.host`` — a bare ``host`` is an
    exact match only there. ghost2's ``Scope.in_scope`` (used for the findings
    backstop and Ghost's tool gating below) already treats every allowed host
    as covering its own subdomains, so this expansion is crawler-specific.
    """
    patterns: List[str] = []
    for h in hosts:
        if h.startswith("*."):
            patterns.append(h)
            continue
        patterns.append(h)
        if not _is_ip_literal(h):
            patterns.append(f"*.{h}")
    return patterns


def _host_in_scope(url_or_host: str, hosts: List[str]) -> bool:
    """True if ``url_or_host`` matches one of ``hosts`` (or its subdomains).

    Delegates to ghost2's own ``Scope.in_scope`` so matching semantics are
    identical everywhere in the suite — the findings backstop filter here and
    the tool-level gating in ghost2's http_tools/scanner_tool/external_tool —
    instead of a second, possibly-drifting implementation.
    """
    from beatrix.ai.ghost2.core.session import Scope
    return Scope(target="", allowed_hosts=hosts).in_scope(url_or_host)


def _shutdown_loop(loop) -> None:
    """Cancel any tasks still pending on ``loop`` and close it.

    Mirrors what ``asyncio.run`` does on the way out. Needed because a
    stoppable run manages its own loop (instead of using ``asyncio.run``)
    so its task can be cancelled from another thread via
    ``loop.call_soon_threadsafe(task.cancel)`` when the user hits Stop.
    """
    import asyncio
    try:
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for t in pending:
            t.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
    except Exception:
        pass
    finally:
        asyncio.set_event_loop(None)
        loop.close()


def _parse_scope_text(raw: str) -> List[str]:
    """Split a pasted blob (newline/comma/whitespace-separated) into
    normalized, deduplicated hostnames, dropping anything unparseable."""
    parts = re.split(r"[\s,]+", raw or "")
    seen: List[str] = []
    for part in parts:
        host = _parse_scope_entry(part)
        if host and host not in seen:
            seen.append(host)
    return seen


# ── Projects ─────────────────────────────────────────────────────────────────
class _ProjectStore:
    """Persistent list of projects (workspaces) the dashboard switches between.

    v1: projects are numerically labeled in creation order, persisted to
    ``<state_dir>/projects.json``; each gets its own workspace dir under
    ``<state_dir>/projects/<id>/`` (the future home for that project's scan
    data / output / scope). IDs are monotonic (never reused), so a label always
    identifies the same project even after deletions. At least one project
    always exists — deleting the last one re-seeds a fresh one.
    """

    def __init__(self, state_dir: Path):
        self.root = Path(state_dir)
        self.file = self.root / "projects.json"
        self._lock = threading.Lock()
        self.root.mkdir(parents=True, exist_ok=True)
        self._data = self._read()
        if not self._data["projects"]:
            self._create_locked()
            self._write()

    # ── persistence ──────────────────────────────────────────────────────
    def _read(self) -> Dict[str, Any]:
        try:
            d = json.loads(self.file.read_text())
            d.setdefault("projects", [])
            d.setdefault("active", None)
            d.setdefault("next_id", 1)
            return d
        except Exception:
            return {"projects": [], "active": None, "next_id": 1}

    def _write(self) -> None:
        try:
            self.file.write_text(json.dumps(self._data, indent=2))
        except Exception:
            pass

    def _proj_dir(self, pid: int) -> Path:
        return self.root / "projects" / str(pid)

    def workspace_dir(self, pid: Any) -> Path:
        """Public accessor: the on-disk directory a project's scan output
        lives under, so tools (e.g. Hunt) can root their output there and
        keep projects' data separated."""
        d = self._proj_dir(pid)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _create_locked(self) -> Dict[str, Any]:
        """Append a new project + make it active. Caller holds the lock."""
        pid = self._data["next_id"]
        self._data["next_id"] = pid + 1
        proj = {"id": pid, "name": f"Project {pid}", "created_at": time.time()}
        self._data["projects"].append(proj)
        self._data["active"] = pid
        try:
            self._proj_dir(pid).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return proj

    # ── API ──────────────────────────────────────────────────────────────
    def state(self) -> Dict[str, Any]:
        with self._lock:
            return {"projects": list(self._data["projects"]), "active": self._data["active"]}

    def new(self) -> Dict[str, Any]:
        with self._lock:
            self._create_locked()
            self._write()
            return {"ok": True, "projects": list(self._data["projects"]),
                    "active": self._data["active"]}

    def select(self, pid: Any) -> Dict[str, Any]:
        with self._lock:
            if any(p["id"] == pid for p in self._data["projects"]):
                self._data["active"] = pid
                self._write()
                return {"ok": True, "active": pid}
            return {"ok": False, "error": "no such project"}

    def delete(self, pid: Any) -> Dict[str, Any]:
        with self._lock:
            before = len(self._data["projects"])
            self._data["projects"] = [p for p in self._data["projects"] if p["id"] != pid]
            if len(self._data["projects"]) == before:
                return {"ok": False, "error": "no such project"}
            shutil.rmtree(self._proj_dir(pid), ignore_errors=True)
            # Keep at least one project, and keep `active` valid.
            if not self._data["projects"]:
                self._create_locked()
            elif self._data["active"] == pid:
                self._data["active"] = self._data["projects"][0]["id"]
            self._write()
            return {"ok": True, "projects": list(self._data["projects"]),
                    "active": self._data["active"]}

    # ── Scope (per project — separate from every other project's, like the
    # scan data in workspace_dir()) ───────────────────────────────────────
    def _find(self, pid: Any) -> Optional[Dict[str, Any]]:
        # str() comparison: `pid` may arrive as an int (POST JSON body) or a
        # str (parsed from a GET query string) — project ids are stored as int.
        for p in self._data["projects"]:
            if str(p["id"]) == str(pid):
                return p
        return None

    def get_scope(self, pid: Any) -> List[str]:
        with self._lock:
            p = self._find(pid)
            return list(p.get("scope", [])) if p else []

    def add_scope(self, pid: Any, entries: List[str]) -> Dict[str, Any]:
        with self._lock:
            p = self._find(pid)
            if p is None:
                return {"ok": False, "error": "no such project"}
            merged = set(p.get("scope", [])) | set(entries)
            p["scope"] = sorted(merged)
            self._write()
            return {"ok": True, "scope": p["scope"]}

    def remove_scope(self, pid: Any, entry: str) -> Dict[str, Any]:
        with self._lock:
            p = self._find(pid)
            if p is None:
                return {"ok": False, "error": "no such project"}
            p["scope"] = [s for s in p.get("scope", []) if s != entry]
            self._write()
            return {"ok": True, "scope": p["scope"]}

    def clear_scope(self, pid: Any) -> Dict[str, Any]:
        with self._lock:
            p = self._find(pid)
            if p is None:
                return {"ok": False, "error": "no such project"}
            p["scope"] = []
            self._write()
            return {"ok": True, "scope": []}


# ── Issues (Burp-style) ──────────────────────────────────────────────────────
# Every scanner "result"/finding — from a deterministic Hunt scan or a GHOST
# agent run — becomes a persistent, per-project *issue* the user can inspect,
# re-triage (severity), highlight, and delete, exactly like Burp's Issue
# activity. Severity has a fixed rank so the list can sort by it meaningfully.
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_VALID_SEVERITIES = set(_SEVERITY_ORDER)
# The palette offered in the right-click "Highlight" menu (Burp-style).
_HIGHLIGHT_COLORS = {"red", "orange", "yellow", "green", "blue", "purple", "gray", "none"}


def _stringify_evidence(ev: Any) -> str:
    """A Finding's ``evidence`` may be a str, dict, list, or anything — render
    it to a stable string for display without exploding on odd types."""
    if ev is None:
        return ""
    if isinstance(ev, str):
        return ev
    try:
        return json.dumps(ev, indent=2, default=str)
    except Exception:
        return str(ev)


def _doc_links(finding: Any) -> List[str]:
    """Derive documentation links (Burp's "References"/classifications) from a
    finding's own references plus its CWE id, so every issue links out to real
    docs even when the scanner didn't supply a URL."""
    links: List[str] = []
    for r in (getattr(finding, "references", None) or []):
        if r and r not in links:
            links.append(str(r))
    cwe = getattr(finding, "cwe_id", None)
    if cwe is not None:
        m = re.search(r"\d+", str(cwe))
        if m:
            url = f"https://cwe.mitre.org/data/definitions/{m.group()}.html"
            if url not in links:
                links.append(url)
    return links


def _finding_to_issue(finding: Any, scanner: str, origin: str) -> Dict[str, Any]:
    """Serialize a ``beatrix.core.types.Finding`` into a plain-dict issue record
    (the on-disk + wire format). Tolerates partially-populated findings from any
    of the 33 scanners or the agent's ``record_finding``."""
    url = getattr(finding, "url", "") or ""
    parsed = urlparse(url)
    sev = getattr(getattr(finding, "severity", None), "value", None) or "info"
    conf = getattr(getattr(finding, "confidence", None), "value", None) or "tentative"
    module = (getattr(finding, "scanner_module", "") or scanner or "unknown")
    title = getattr(finding, "title", "") or "Untitled finding"
    return {
        "title": title,
        "severity": sev,
        "orig_severity": sev,
        "confidence": conf,
        "url": url,
        "host": parsed.netloc,
        "path": parsed.path or "/",
        "parameter": getattr(finding, "parameter", None) or "",
        "module": module,
        "origin": origin,
        "payload": getattr(finding, "payload", None) or "",
        "description": getattr(finding, "description", "") or "",
        "impact": getattr(finding, "impact", "") or "",
        "remediation": getattr(finding, "remediation", "") or "",
        "evidence": _stringify_evidence(getattr(finding, "evidence", None)),
        "request": getattr(finding, "request", None) or "",
        "response": getattr(finding, "response", None) or "",
        "references": _doc_links(finding),
        "cwe": ("" if getattr(finding, "cwe_id", None) is None else str(finding.cwe_id)),
        "owasp": getattr(finding, "owasp_category", None) or "",
        "poc_curl": getattr(finding, "poc_curl", None) or "",
        "poc_python": getattr(finding, "poc_python", None) or "",
        "reproduction_steps": list(getattr(finding, "reproduction_steps", None) or []),
        "validated": bool(getattr(finding, "validated", False)),
    }


# Fields the list view needs — keep the /issues payload light (request/response
# bodies can be large); the full record is fetched per-issue via /issues/detail.
_ISSUE_SUMMARY_FIELDS = ("id", "title", "severity", "confidence", "host", "path",
                         "url", "module", "origin", "highlight", "validated",
                         "discovered_at")


class _IssueStore:
    """Per-project issue list, persisted to ``<project>/issues.json``.

    Disk-backed with no long-lived cache (issue volume is modest and ops are
    low-frequency), so it can't drift from a project that was deleted out from
    under it — a removed project's workspace dir (and its issues.json) is gone,
    and this simply reads an empty list. All read-modify-write ops hold one
    lock, so the scan thread adding findings and the HTTP thread editing/listing
    never corrupt the file.
    """

    def __init__(self, projects: "_ProjectStore"):
        self._projects = projects
        self._lock = threading.Lock()

    def _file(self, pid: Any) -> Path:
        return self._projects.workspace_dir(pid) / "issues.json"

    def _read(self, pid: Any) -> Dict[str, Any]:
        try:
            d = json.loads(self._file(pid).read_text())
            d.setdefault("issues", [])
            d.setdefault("next_id", 1)
            return d
        except Exception:
            return {"issues": [], "next_id": 1}

    def _write(self, pid: Any, data: Dict[str, Any]) -> None:
        try:
            self._file(pid).write_text(json.dumps(data, indent=2, default=str))
        except Exception:
            pass

    @staticmethod
    def _key(issue: Dict[str, Any]) -> str:
        # Issue identity (for dedup): a scanner re-emitting the same finding, or
        # the post-run completion sweep re-seeing a live-captured one, must NOT
        # create a second issue — and must NOT clobber a user's re-triage.
        return "␟".join((issue.get("title", ""), issue.get("url", ""),
                              issue.get("parameter", ""), issue.get("module", "")))

    def add_finding(self, pid: Any, finding: Any, scanner: str, origin: str) -> Optional[Dict[str, Any]]:
        """Add a finding as a new issue; returns the issue summary, or None if a
        matching issue already exists (idempotent, so live capture + the
        completion sweep never double-count and edits are preserved)."""
        issue = _finding_to_issue(finding, scanner, origin)
        key = self._key(issue)
        with self._lock:
            data = self._read(pid)
            for existing in data["issues"]:
                if existing.get("key") == key:
                    return None
            issue["id"] = data["next_id"]
            issue["key"] = key
            issue["highlight"] = None
            issue["discovered_at"] = time.time()
            data["next_id"] += 1
            data["issues"].append(issue)
            self._write(pid, data)
            return {k: issue.get(k) for k in _ISSUE_SUMMARY_FIELDS}

    def list(self, pid: Any) -> List[Dict[str, Any]]:
        with self._lock:
            data = self._read(pid)
        return [{k: i.get(k) for k in _ISSUE_SUMMARY_FIELDS} for i in data["issues"]]

    def count(self, pid: Any) -> int:
        with self._lock:
            return len(self._read(pid)["issues"])

    def get(self, pid: Any, issue_id: Any) -> Optional[Dict[str, Any]]:
        with self._lock:
            data = self._read(pid)
        for i in data["issues"]:
            if str(i.get("id")) == str(issue_id):
                return i
        return None

    def update(self, pid: Any, issue_id: Any, severity: Optional[str] = None,
               highlight: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            data = self._read(pid)
            for i in data["issues"]:
                if str(i.get("id")) == str(issue_id):
                    if severity is not None:
                        sev = severity.lower().strip()
                        if sev not in _VALID_SEVERITIES:
                            return {"ok": False, "error": f"invalid severity '{severity}'"}
                        i["severity"] = sev
                    if highlight is not None:
                        color = highlight.lower().strip()
                        if color not in _HIGHLIGHT_COLORS:
                            return {"ok": False, "error": f"invalid highlight '{highlight}'"}
                        i["highlight"] = None if color == "none" else color
                    self._write(pid, data)
                    return {"ok": True, "issue": {k: i.get(k) for k in _ISSUE_SUMMARY_FIELDS}}
            return {"ok": False, "error": "no such issue"}

    def delete(self, pid: Any, issue_id: Any) -> Dict[str, Any]:
        with self._lock:
            data = self._read(pid)
            before = len(data["issues"])
            data["issues"] = [i for i in data["issues"] if str(i.get("id")) != str(issue_id)]
            if len(data["issues"]) == before:
                return {"ok": False, "error": "no such issue"}
            self._write(pid, data)
            return {"ok": True}

    def clear(self, pid: Any) -> Dict[str, Any]:
        with self._lock:
            data = self._read(pid)
            data["issues"] = []
            self._write(pid, data)
        return {"ok": True}


# ── Shell page ───────────────────────────────────────────────────────────────
# Left project rail + top tab bar (Dashboard | Auth | Ghost); panes swap
# client-side. Theme-aware, inline CSS/JS, no external requests.
_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Beatrix Suite</title>
<style>
  :root { --bg:#0b0e14; --panel:#11151f; --border:#222a38; --fg:#c9d4e5; --muted:#6b7787;
    --accent:#3fd0d6; --red:#ff6b6b; --green:#5fd479; --yellow:#e5c07b; --violet:#b98cff; --blue:#5aa9ff; }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f7f9fc; --panel:#fff; --border:#dce3ec; --fg:#1f2733; --muted:#6b7787;
      --accent:#0b8a90; --red:#c0392b; --green:#1a7f37; --yellow:#8a6d1a; --violet:#7a3ff2; --blue:#0969da; } }
  * { box-sizing:border-box; }
  html, body { height:100%; }
  body { margin:0; display:flex; flex-direction:column; background:var(--bg); color:var(--fg);
    font:14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  header { display:flex; align-items:center; gap:16px; padding:10px 18px;
    background:var(--panel); border-bottom:1px solid var(--border); }
  header .t { font-weight:700; font-size:15px; }
  header .t .g { color:var(--red); }
  header .proj-label { margin-left:auto; color:var(--muted); font-size:12px; }
  header .status { color:var(--muted); font-size:12px; }
  .dot { width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:6px;
    background:var(--green); vertical-align:middle; }

  .body { flex:1; min-height:0; display:flex; }

  /* Left project rail */
  .projects { width:54px; flex-shrink:0; background:var(--panel); border-right:1px solid var(--border);
    display:flex; flex-direction:column; align-items:center; gap:6px; padding:8px 0; overflow-y:auto; }
  .proj { width:38px; height:38px; border-radius:8px; border:1px solid var(--border); background:var(--bg);
    color:var(--muted); font:inherit; font-weight:700; cursor:pointer; flex-shrink:0;
    display:flex; align-items:center; justify-content:center; }
  .proj:hover { color:var(--fg); border-color:var(--accent); }
  .proj.active { color:var(--fg); border-color:var(--accent); background:rgba(63,208,214,.12);
    box-shadow:inset 3px 0 0 var(--accent); }
  .proj.add { color:var(--muted); font-weight:400; font-size:20px; border-style:dashed; }
  .proj.add:hover { color:var(--accent); }

  .workspace { flex:1; min-width:0; display:flex; flex-direction:column; }
  nav { display:flex; gap:2px; padding:0 12px; background:var(--panel); border-bottom:1px solid var(--border); }
  nav button { font:inherit; font-size:13px; color:var(--muted); background:transparent; border:none;
    border-bottom:2px solid transparent; padding:9px 16px; cursor:pointer; }
  nav button:hover { color:var(--fg); }
  nav button.active { color:var(--fg); border-bottom-color:var(--accent); }
  main { flex:1; min-height:0; position:relative; }
  .pane { position:absolute; inset:0; display:none; overflow:auto; }
  .pane.active { display:block; }
  .pane.frame { overflow:hidden; }
  iframe { width:100%; height:100%; border:0; display:block; }
  /* The Hunt workstation is a control panel + terminal side by side, so it
     overrides the generic block layout while active (ID beats .pane.active). */
  #pane-dashboard.active { display:flex; flex-direction:row; overflow:hidden; }

  /* Right-click context menu for project tabs */
  .ctx { position:fixed; z-index:50; display:none; background:var(--panel); border:1px solid var(--border);
    border-radius:6px; padding:4px; min-width:130px; box-shadow:0 8px 24px rgba(0,0,0,.35); }
  .ctx button { display:block; width:100%; text-align:left; font:inherit; font-size:13px; color:var(--red);
    background:transparent; border:0; padding:6px 10px; border-radius:4px; cursor:pointer; }
  .ctx button:hover { background:var(--bg); }

  .pad { padding:20px 24px; }
  h2 { font-size:16px; margin:0 0 8px; }
  p.sub { color:var(--muted); margin:0 0 18px; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end; margin-bottom:12px; }
  label { display:block; font-size:12px; color:var(--muted); margin-bottom:4px; }
  input[type=text] { font:inherit; color:var(--fg); background:var(--bg); border:1px solid var(--border);
    border-radius:6px; padding:7px 10px; min-width:280px; }
  button.run { font:inherit; color:#08131a; background:var(--accent); border:0; border-radius:6px;
    padding:8px 16px; cursor:pointer; font-weight:600; }
  button.run:disabled { opacity:.5; cursor:default; }
  button.stop { font:inherit; color:#fff; background:var(--red); border:0; border-radius:6px;
    padding:8px 16px; cursor:pointer; font-weight:600; }
  button.stop:disabled { opacity:.4; cursor:default; }
  .ghost-toolbar { display:flex; align-items:center; gap:16px; margin:10px 0 4px;
    color:var(--muted); font-size:12px; }
  .ghost-toolbar b { color:var(--fg); }
  .ghost-toolbar .autoscroll-toggle { cursor:pointer; }
  .ghost-toolbar .autoscroll-toggle:hover { color:var(--fg); }
  .ghost-toolbar .btn { margin-left:auto; font:inherit; font-size:12px; color:var(--fg); background:var(--bg);
    border:1px solid var(--border); border-radius:6px; padding:5px 11px; cursor:pointer; }
  .ghost-toolbar .btn:hover { border-color:var(--accent); color:var(--accent); }
  #ghost-log { margin-top:6px; border-top:1px solid var(--border); padding-top:12px; }
  .ev { padding:2px 0; white-space:pre-wrap; word-break:break-word; }
  .ev .ts { color:var(--muted); margin-right:8px; font-size:12px; }
  .ev .tag { font-weight:700; margin-right:8px; }
  .ev.tool_start .tag { color:var(--yellow); } .ev.tool_end .tag { color:var(--blue); }
  .ev.agent_start .tag { color:var(--accent); } .ev.agent_end .tag { color:var(--muted); }
  .ev.reasoning .tag, .ev.thinking .tag { color:var(--violet); }
  .ev.finding .tag { color:var(--red); } .ev.verdict .tag { color:var(--green); }
  .ev.phase .tag { color:var(--accent); } .ev.phase_done .tag { color:var(--green); }
  .ev.scanner_start .tag { color:var(--yellow); } .ev.scanner_done .tag { color:var(--blue); }
  .ev.scanner_error .tag { color:var(--red); } .ev.info .tag { color:var(--muted); }
  .ev .detail { display:block; color:var(--muted); margin:2px 0 2px 84px; padding:6px 9px;
    background:var(--panel); border:1px solid var(--border); border-radius:6px; max-height:220px; overflow:auto; }
  .card { border:1px solid var(--border); border-radius:8px; background:var(--panel); padding:16px 18px; max-width:640px; }

  /* ── Hunt workstation: control panel (left) + terminal (right) ── */
  .hunt-controls { width:340px; flex-shrink:0; overflow-y:auto; border-right:1px solid var(--border);
    padding:16px; display:flex; flex-direction:column; min-height:0; }
  .hunt-controls label { display:block; font-size:12px; color:var(--muted); margin:12px 0 4px; }
  .hunt-controls label:first-of-type { margin-top:0; }
  .hunt-controls input[type=text] { width:100%; }
  .presets { display:flex; flex-wrap:wrap; gap:6px; }
  .preset-chip { font:inherit; font-size:11px; color:var(--muted); background:var(--bg);
    border:1px solid var(--border); border-radius:12px; padding:4px 10px; cursor:pointer; }
  .preset-chip:hover { border-color:var(--accent); color:var(--fg); }
  .preset-chip.active { background:var(--accent); color:#08131a; border-color:var(--accent); font-weight:600; }
  .mod-actions { display:flex; align-items:center; gap:10px; font-size:11px; color:var(--muted); margin:12px 0 6px; }
  .mod-actions a { color:var(--accent); text-decoration:none; cursor:pointer; }
  .mod-actions a:hover { text-decoration:underline; }
  .mod-actions .spacer { flex:1; }
  .modules { flex:1; min-height:80px; overflow-y:auto; border:1px solid var(--border); border-radius:6px; padding:4px 6px; }
  .mod-cat { font-size:10px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted);
    font-weight:700; padding:8px 4px 3px; }
  .mod-cat:first-child { padding-top:4px; }
  .mod-row { display:flex; align-items:center; gap:8px; padding:4px 6px; border-radius:4px; cursor:pointer; font-size:12.5px; }
  .mod-row:hover { background:var(--bg); }
  .mod-row input { flex-shrink:0; margin:0; }
  .mod-tooltip { position:fixed; z-index:60; display:none; max-width:280px; background:var(--panel);
    border:1px solid var(--border); border-radius:6px; padding:8px 10px; font-size:12px; color:var(--fg);
    line-height:1.45; box-shadow:0 8px 24px rgba(0,0,0,.35); pointer-events:none; }

  .hunt-terminal-wrap { flex:1; min-width:0; display:flex; flex-direction:column; padding:16px; min-height:0; }
  .term-chrome { flex:1; min-height:0; display:flex; flex-direction:column; background:#050607;
    border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  .term-titlebar { display:flex; align-items:center; gap:6px; padding:8px 10px; background:#0d0f14;
    border-bottom:1px solid #1a1e28; flex-shrink:0; }
  .term-titlebar .dot { width:10px; height:10px; border-radius:50%; }
  .term-titlebar .dot.r { background:#ff5f57; }
  .term-titlebar .dot.y { background:#febc2e; }
  .term-titlebar .dot.g { background:#28c840; }
  .term-title { margin-left:8px; color:#6b7787; font-size:11.5px; }
  #hunt-log.terminal { flex:1; min-height:0; overflow-y:auto; padding:10px 14px; color:#c9d4e5; }

  /* ── Scope tab ── */
  .scope-list { border:1px solid var(--border); border-radius:6px; min-height:60px; max-height:340px; overflow-y:auto; }
  .scope-item { display:flex; align-items:center; gap:10px; padding:7px 12px; font-size:13px;
    border-bottom:1px solid var(--border); }
  .scope-item:last-child { border-bottom:none; }
  .scope-item .host { flex:1; }
  .scope-item button { font:inherit; font-size:12px; color:var(--muted); background:transparent;
    border:0; cursor:pointer; padding:2px 6px; border-radius:4px; }
  .scope-item button:hover { color:var(--red); background:var(--bg); }
  .scope-empty { padding:14px 12px; color:var(--muted); font-size:12.5px; }

  /* ── Issues tab (Burp-style) ── */
  nav button .badge { display:none; margin-left:6px; min-width:16px; padding:0 5px; border-radius:9px;
    background:var(--red); color:#fff; font-size:10.5px; font-weight:700; line-height:16px; text-align:center; }
  nav button .badge.show { display:inline-block; }
  #pane-issues.active { display:flex; flex-direction:column; overflow:hidden; }
  .iss-toolbar { display:flex; align-items:center; gap:14px; padding:8px 14px; border-bottom:1px solid var(--border);
    background:var(--panel); flex-shrink:0; font-size:12px; color:var(--muted); }
  .iss-toolbar b { color:var(--fg); }
  .iss-toolbar .spacer { flex:1; }
  .iss-toolbar select { font:inherit; font-size:12px; color:var(--fg); background:var(--bg);
    border:1px solid var(--border); border-radius:5px; padding:3px 6px; }
  .iss-toolbar a { color:var(--accent); cursor:pointer; }
  .iss-split { flex:1; min-height:0; display:flex; flex-direction:column; }
  .iss-list-wrap { flex:1 1 55%; min-height:80px; overflow:auto; }
  .iss-detail-wrap { flex:1 1 45%; min-height:120px; border-top:1px solid var(--border);
    display:flex; flex-direction:column; overflow:hidden; }
  table.iss { width:100%; border-collapse:collapse; font-size:12.5px; }
  table.iss thead th { position:sticky; top:0; background:var(--panel); text-align:left; padding:7px 10px;
    border-bottom:1px solid var(--border); cursor:pointer; user-select:none; white-space:nowrap; color:var(--muted); font-weight:600; }
  table.iss thead th:hover { color:var(--fg); }
  table.iss thead th .arrow { color:var(--accent); }
  table.iss tbody td { padding:6px 10px; border-bottom:1px solid var(--border); vertical-align:top; }
  table.iss tbody tr { cursor:pointer; }
  table.iss tbody tr:hover { background:var(--bg); }
  table.iss tbody tr.sel { background:rgba(63,208,214,.14); }
  table.iss tbody tr.hl-red { box-shadow:inset 3px 0 0 #ff5f57; }
  table.iss tbody tr.hl-orange { box-shadow:inset 3px 0 0 #ff9f43; }
  table.iss tbody tr.hl-yellow { box-shadow:inset 3px 0 0 #f7c948; }
  table.iss tbody tr.hl-green { box-shadow:inset 3px 0 0 #28c840; }
  table.iss tbody tr.hl-blue { box-shadow:inset 3px 0 0 #5aa9ff; }
  table.iss tbody tr.hl-purple { box-shadow:inset 3px 0 0 #b98cff; }
  table.iss tbody tr.hl-gray { box-shadow:inset 3px 0 0 #8a94a6; }
  .sev { display:inline-block; padding:1px 7px; border-radius:4px; font-size:10.5px; font-weight:700;
    text-transform:uppercase; letter-spacing:.03em; color:#08131a; }
  .sev.critical { background:#ff5f57; color:#fff; } .sev.high { background:#ff9f43; }
  .sev.medium { background:#f7c948; } .sev.low { background:#5aa9ff; } .sev.info { background:#8a94a6; color:#fff; }
  .conf { color:var(--muted); font-size:11.5px; }
  .iss-empty { padding:24px; color:var(--muted); font-size:13px; text-align:center; }
  .iss-dtabs { display:flex; gap:2px; padding:6px 12px 0; border-bottom:1px solid var(--border); flex-shrink:0; }
  .iss-dtabs button { font:inherit; font-size:12px; color:var(--muted); background:transparent; border:none;
    border-bottom:2px solid transparent; padding:6px 12px; cursor:pointer; }
  .iss-dtabs button:hover { color:var(--fg); }
  .iss-dtabs button.active { color:var(--fg); border-bottom-color:var(--accent); }
  .iss-detail { flex:1; min-height:0; overflow:auto; padding:14px 18px; font-size:12.5px; }
  .iss-detail h3 { font-size:14px; margin:0 0 4px; }
  .iss-detail .kv { color:var(--muted); margin-bottom:12px; }
  .iss-detail .kv b { color:var(--fg); }
  .iss-detail section { margin-bottom:14px; }
  .iss-detail section > .lbl { font-weight:700; color:var(--accent); font-size:11px; text-transform:uppercase;
    letter-spacing:.04em; margin-bottom:4px; }
  .iss-detail pre { margin:0; padding:10px 12px; background:var(--panel); border:1px solid var(--border);
    border-radius:6px; overflow:auto; max-height:340px; white-space:pre-wrap; word-break:break-word; font-size:12px; }
  .iss-detail ul { margin:4px 0; padding-left:20px; }
  .iss-detail a { color:var(--blue); word-break:break-all; }
  .iss-detail .none { color:var(--muted); font-style:italic; }
  /* Issue right-click menu (severity / highlight / delete) */
  .iss-ctx { position:fixed; z-index:70; display:none; background:var(--panel); border:1px solid var(--border);
    border-radius:8px; padding:6px; min-width:190px; box-shadow:0 10px 30px rgba(0,0,0,.4); font-size:12.5px; }
  .iss-ctx .lbl { color:var(--muted); font-size:10.5px; text-transform:uppercase; letter-spacing:.04em; padding:5px 8px 3px; }
  .iss-ctx .opts { display:flex; flex-wrap:wrap; gap:4px; padding:0 6px 6px; }
  .iss-ctx .opts button { font:inherit; font-size:11px; padding:3px 8px; border-radius:4px; border:1px solid var(--border);
    background:var(--bg); color:var(--fg); cursor:pointer; }
  .iss-ctx .opts button:hover { border-color:var(--accent); }
  .iss-ctx .sw { display:inline-block; width:16px; height:16px; border-radius:4px; border:1px solid rgba(0,0,0,.3);
    cursor:pointer; }
  .iss-ctx .sw:hover { outline:2px solid var(--accent); }
  .iss-ctx hr { border:0; border-top:1px solid var(--border); margin:5px 4px; }
  .iss-ctx .del { display:block; width:100%; text-align:left; font:inherit; font-size:12.5px; color:var(--red);
    background:transparent; border:0; padding:6px 8px; border-radius:4px; cursor:pointer; }
  .iss-ctx .del:hover { background:var(--bg); }
</style>
</head>
<body>
<header>
  <span class="t">👻 <span class="g">Beatrix Suite</span></span>
  <span class="proj-label" id="proj-label">—</span>
  <span class="status"><span class="dot"></span>connected</span>
</header>
<div class="body">
  <aside id="projects" class="projects"></aside>
  <div class="workspace">
    <nav>
      <button data-tab="dashboard" class="active">Dashboard</button>
      <button data-tab="issues">Issues<span id="issues-badge" class="badge"></span></button>
      <button data-tab="scope">Scope</button>
      <button data-tab="auth">Auth</button>
      <button data-tab="ghost">Ghost</button>
    </nav>
    <main>
      <section id="pane-dashboard" class="pane active">
        <aside class="hunt-controls">
          <h2 style="margin-top:0;">New Scan</h2>
          <p class="sub" style="margin:0 0 12px;">Project: <b id="dash-project">—</b></p>

          <label>Target</label>
          <input id="h-target" type="text" placeholder="https://example.com or example.com">

          <label>Presets <span style="font-weight:400; color:var(--muted);">(quick-select)</span></label>
          <div class="presets" id="h-presets"></div>

          <div class="mod-actions">
            <span id="h-selcount">0 selected</span>
            <span class="spacer"></span>
            <a id="h-selall">select all</a>
            <a id="h-selnone">clear</a>
          </div>
          <div class="modules" id="h-modules"></div>

          <button id="h-run" class="run" style="width:100%; margin-top:14px;">▶ Begin Scan</button>
          <button id="h-stop" class="stop" style="width:100%; margin-top:8px;" disabled>■ Stop Scan</button>
          <div id="h-msg" style="color:var(--muted); font-size:12px; margin-top:8px;"></div>
        </aside>

        <div class="hunt-terminal-wrap">
          <div class="ghost-toolbar" style="margin-top:0;">
            <span>events <b id="h-count">0</b></span>
            <span>findings <b id="h-findings">0</b></span>
            <span>elapsed <b id="h-elapsed">0s</b></span>
            <span id="h-autoscroll" class="autoscroll-toggle" title="click to toggle">⤓ autoscroll: on</span>
            <button id="h-save" class="btn" title="Save this run as a standalone HTML file">💾 Save HTML</button>
          </div>
          <div class="term-chrome">
            <div class="term-titlebar">
              <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
              <span class="term-title" id="h-term-title">beatrix@hunt</span>
            </div>
            <div id="hunt-log" class="terminal"></div>
          </div>
        </div>
      </section>

      <section id="pane-issues" class="pane">
        <div class="iss-toolbar">
          <span>Project <b id="iss-project">—</b></span>
          <span><b id="iss-count">0</b> issue(s)</span>
          <span class="spacer"></span>
          <label>Sort by
            <select id="iss-sort">
              <option value="severity">Severity</option>
              <option value="title">Issue type</option>
              <option value="host">Host</option>
              <option value="path">URL / path</option>
              <option value="module">Module</option>
              <option value="confidence">Confidence</option>
              <option value="discovered_at">Time found</option>
            </select>
          </label>
          <a id="iss-clear" title="Delete all issues in this project">clear all</a>
        </div>
        <div class="iss-split">
          <div class="iss-list-wrap">
            <table class="iss">
              <thead><tr id="iss-head"></tr></thead>
              <tbody id="iss-body"></tbody>
            </table>
            <div id="iss-empty" class="iss-empty">No issues yet — run a Hunt or Ghost scan and findings appear here.</div>
          </div>
          <div class="iss-detail-wrap">
            <div class="iss-dtabs" id="iss-dtabs">
              <button data-dt="advisory" class="active">Advisory</button>
              <button data-dt="request">Request</button>
              <button data-dt="response">Response</button>
              <button data-dt="poc">PoC</button>
            </div>
            <div id="iss-detail" class="iss-detail">
              <div class="none">Select an issue to view its details.</div>
            </div>
          </div>
        </div>
      </section>

      <section id="pane-scope" class="pane">
        <div class="pad">
          <h2>Scope</h2>
          <p class="sub">Paste URLs, domains, or IP addresses that are in scope for
            <b id="scope-project">—</b>. Testing (Ghost's tools) and reported findings (Hunt) are
            limited to these hosts and their subdomains. Leave empty to scan only the target itself.</p>
          <div class="card" style="max-width:720px;">
            <label style="display:block; font-size:12px; color:var(--muted); margin-bottom:6px;">Add to scope</label>
            <textarea id="scope-input" rows="4"
              placeholder="https://example.com&#10;api.example.com&#10;10.0.0.5"
              style="width:100%; font:inherit; font-size:13px; color:var(--fg); background:var(--bg);
                border:1px solid var(--border); border-radius:6px; padding:8px 10px; resize:vertical;"></textarea>
            <div style="display:flex; gap:10px; align-items:center; margin-top:8px;">
              <button id="scope-add" class="run">+ Add to scope</button>
              <span id="scope-msg" style="color:var(--muted); font-size:12px;"></span>
            </div>
          </div>
          <div style="max-width:720px; margin-top:18px;">
            <div style="display:flex; align-items:center; margin-bottom:8px;">
              <b style="font-size:13px;">In scope (<span id="scope-count">0</span>)</b>
              <span class="spacer" style="flex:1;"></span>
              <a id="scope-clear" style="color:var(--accent); font-size:12px; cursor:pointer;">clear all</a>
            </div>
            <div id="scope-list" class="scope-list"></div>
          </div>
        </div>
      </section>

      <section id="pane-auth" class="pane frame"></section>

      <section id="pane-ghost" class="pane">
        <div class="pad">
          <h2>Ghost — autonomous investigation</h2>
          <p class="sub">Enter a target and run. Events stream below in real time.</p>
          <div class="row">
            <div><label>Target</label><input id="g-target" type="text" placeholder="https://example.com"></div>
            <div><label>Objective (optional)</label><input id="g-obj" type="text" placeholder="Find and validate security vulnerabilities."></div>
            <button id="g-run" class="run">Run</button>
            <button id="g-stop" class="stop" disabled>■ Stop</button>
          </div>
          <div id="g-msg" style="color:var(--muted); font-size:12px;"></div>
          <div class="ghost-toolbar">
            <span>events <b id="g-count">0</b></span>
            <span>tools <b id="g-tools">0</b></span>
            <span>elapsed <b id="g-elapsed">0s</b></span>
            <span id="g-autoscroll" class="autoscroll-toggle" title="click to toggle">⤓ autoscroll: on</span>
            <button id="g-save" class="btn" title="Save this run as a standalone HTML file">💾 Save HTML</button>
          </div>
          <div id="ghost-log"></div>
        </div>
      </section>
    </main>
  </div>
</div>
<div id="ctxmenu" class="ctx"><button id="ctx-del">Delete project</button></div>
<div id="issue-ctx" class="iss-ctx"></div>
<div id="mod-tooltip" class="mod-tooltip"></div>
<script>
const TAGS = { thinking:"🧠 thinking", system_prompt:"📋 system", prompt:"📤 prompt",
  reasoning:"💭 reasoning", tool_start:"🔧 tool", tool_end:"↳ result", agent_start:"▶ agent",
  agent_end:"■ agent", finding:"⚑ finding", verdict:"✔ verdict", done:"● done" };
const esc = s => String(s).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const $ = id => document.getElementById(id);

// ── Tabs: swap panes in-place, never open a new tab/port ──
let authLoaded = false;
document.querySelectorAll("nav button").forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll("nav button").forEach(b => b.classList.toggle("active", b === btn));
    const tab = btn.dataset.tab;
    document.querySelectorAll(".pane").forEach(p => p.classList.toggle("active", p.id === "pane-" + tab));
    if (tab === "auth" && !authLoaded) {           // lazy-load the auth GUI iframe once
      $("pane-auth").innerHTML = '<iframe src="/auth" title="Beatrix Auth"></iframe>';
      authLoaded = true;
    }
    if (tab === "issues") loadIssuesFor(activeProject);   // freshen on view
  };
});

// ── Ghost: each project has its OWN run + event stream on the server.
// `pollProject` is the project id the in-flight poll loop belongs to; every
// poll checks it's still current before rendering or rescheduling, so a run
// left going in another project can never leak into (or get cut off by
// switching away from) the one currently on screen.
let since = 0, pollProject = null;
// `autoscroll` is a UI preference, not run data — it's intentionally NOT reset
// on project switch, matching the standalone GHOST v2 dashboard.
let ghostTools = 0, autoscroll = true, ghostStarted = null;

function renderEvent(ev) {
  const d = document.createElement("div");
  d.className = "ev " + ev.type;
  const tag = TAGS[ev.type] || ev.type;
  let html = `<span class="ts">${new Date(ev.ts*1000).toLocaleTimeString()}</span><span class="tag">${tag}</span>${esc(ev.text||"")}`;
  if (ev.detail) html += `<span class="detail">${esc(ev.detail)}</span>`;
  d.innerHTML = html;
  $("ghost-log").appendChild(d);
  if (ev.type === "tool_start") { ghostTools++; $("g-tools").textContent = ghostTools; }
}
async function poll(id) {
  if (id !== pollProject) return;               // a different project is on screen now
  let r;
  try {
    r = await (await fetch("/ghost/events?since=" + since + "&project=" + id)).json();
  } catch (e) { setTimeout(() => poll(id), 600); return; }
  if (id !== pollProject) return;                // switched away while this fetch was in flight
  for (const ev of r.events) { renderEvent(ev); since = ev.seq; }
  $("g-count").textContent = since;
  if (autoscroll) $("ghost-log").scrollTop = $("ghost-log").scrollHeight;
  if (ghostStarted) $("g-elapsed").textContent = Math.round(Date.now()/1000 - ghostStarted) + "s";
  if (r.done) { $("g-run").disabled = false; $("g-stop").disabled = true;
    $("g-msg").textContent = "Run finished."; return; }
  $("g-run").disabled = true; $("g-stop").disabled = false;
  setTimeout(() => poll(id), 600);
}
// Rebuild the Ghost pane for `id`: clear the shared log DOM, then replay that
// project's own event history from the server (not from memory — the whole
// point is this survives having been switched away from) and resume polling
// if it's still running.
async function loadGhostViewFor(id) {
  $("ghost-log").innerHTML = ""; since = 0; ghostTools = 0; ghostStarted = null;
  $("g-count").textContent = "0"; $("g-tools").textContent = "0"; $("g-elapsed").textContent = "0s";
  pollProject = id;
  $("g-run").disabled = false; $("g-stop").disabled = true; $("g-msg").textContent = "";
  let st = {};
  try { st = await (await fetch("/ghost/state?project=" + id)).json(); } catch (e) {}
  if (id !== pollProject) return;                 // switched again while loading
  if (st && st.target) {
    $("g-target").value = st.target;
    $("g-obj").value = st.objective || "";
    ghostStarted = st.started || null;
    $("g-run").disabled = !!st.running; $("g-stop").disabled = !st.running;
    $("g-msg").textContent = st.running ? "Running: " + st.target : "Run finished.";
    poll(id);                                     // replays history; keeps going if still running
  } else {
    $("g-target").value = ""; $("g-obj").value = "";
  }
}
$("g-run").onclick = async () => {
  const target = $("g-target").value.trim();
  if (!target) { $("g-msg").textContent = "Enter a target first."; return; }
  $("g-run").disabled = true; $("g-msg").textContent = "Starting…";
  $("ghost-log").innerHTML = ""; since = 0; ghostTools = 0; ghostStarted = Date.now() / 1000;
  $("g-count").textContent = "0"; $("g-tools").textContent = "0"; $("g-elapsed").textContent = "0s";
  pollProject = activeProject;
  try {
    const r = await (await fetch("/ghost/run", { method:"POST",
      body: JSON.stringify({ target, objective: $("g-obj").value.trim(), project: activeProject }) })).json();
    if (!r.ok) { $("g-msg").textContent = "Error: " + (r.error || "could not start"); $("g-run").disabled = false; return; }
    $("g-stop").disabled = false;
    $("g-msg").textContent = "Running: " + target;
    poll(activeProject);
  } catch (e) { $("g-msg").textContent = "Error: " + e; $("g-run").disabled = false; }
};
$("g-stop").onclick = async () => {
  $("g-stop").disabled = true; $("g-msg").textContent = "Stopping…";
  try {
    const r = await (await fetch("/ghost/stop", { method:"POST",
      body: JSON.stringify({ project: activeProject }) })).json();
    if (!r.ok) { $("g-msg").textContent = "Error: " + (r.error || "could not stop"); $("g-stop").disabled = false; }
  } catch (e) { $("g-msg").textContent = "Error: " + e; $("g-stop").disabled = false; }
};

$("g-autoscroll").onclick = () => {
  autoscroll = !autoscroll;
  $("g-autoscroll").textContent = "⤓ autoscroll: " + (autoscroll ? "on" : "off");
};

// Save the CURRENT project's ghost log as a standalone, self-contained HTML
// file for the record — same feature as the standalone GHOST v2 dashboard,
// scoped to just this run's content (not the whole Suite shell/other panes).
function saveGhostHtml() {
  const proj = projects.find(p => p.id === activeProject);
  const projName = proj ? proj.name : ("Project " + activeProject);
  const target = $("g-target").value || "—";
  const objective = $("g-obj").value || "—";
  const statusText = $("g-msg").textContent || "";
  const logHtml = $("ghost-log").innerHTML;
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>GHOST v2 — ${esc(projName)} — ${esc(target)}</title>
<style>
  :root { --bg:#0b0e14; --panel:#11151f; --border:#222a38; --fg:#c9d4e5; --muted:#6b7787;
    --accent:#3fd0d6; --red:#ff6b6b; --green:#5fd479; --yellow:#e5c07b; --violet:#b98cff; --blue:#5aa9ff; }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f7f9fc; --panel:#fff; --border:#dce3ec; --fg:#1f2733; --muted:#6b7787;
      --accent:#0b8a90; --red:#c0392b; --green:#1a7f37; --yellow:#8a6d1a; --violet:#7a3ff2; --blue:#0969da; } }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
    font:14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding:20px 24px 60px; }
  h1 { font-size:16px; margin:0 0 6px; }
  .meta { color:var(--muted); font-size:12px; margin-bottom:2px; }
  .ev { padding:2px 0; white-space:pre-wrap; word-break:break-word; }
  .ev .ts { color:var(--muted); margin-right:8px; font-size:12px; }
  .ev .tag { font-weight:700; margin-right:8px; }
  .ev.tool_start .tag { color:var(--yellow); } .ev.tool_end .tag { color:var(--blue); }
  .ev.agent_start .tag { color:var(--accent); } .ev.agent_end .tag { color:var(--muted); }
  .ev.reasoning .tag, .ev.thinking .tag { color:var(--violet); }
  .ev.finding .tag { color:var(--red); } .ev.verdict .tag { color:var(--green); }
  .ev .detail { display:block; color:var(--muted); margin:2px 0 2px 84px; padding:6px 9px;
    background:var(--panel); border:1px solid var(--border); border-radius:6px; max-height:220px; overflow:auto; }
</style></head><body>
<h1>👻 GHOST v2 — ${esc(projName)}</h1>
<div class="meta">target <b>${esc(target)}</b> · objective <b>${esc(objective)}</b></div>
<div class="meta">${esc(statusText)} · saved ${new Date().toLocaleString()}</div>
<div style="margin-top:14px; border-top:1px solid var(--border); padding-top:12px;">${logHtml}</div>
</body></html>`;
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const safeProj = projName.replace(/[^a-z0-9.\-]+/gi, "_");
  const safeTarget = target.replace(/[^a-z0-9.\-]+/gi, "_");
  const ts = new Date().toISOString().replace(/[:]/g, "-").replace("T", "_").slice(0, 19);
  a.href = url;
  a.download = "ghost2-" + safeProj + "-" + safeTarget + "-" + ts + ".html";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
$("g-save").onclick = saveGhostHtml;

// ── Hunt: the Dashboard workstation — module/preset control panel + terminal.
// Structurally mirrors the Ghost pane above (own per-project broker on the
// server, same rebuild-not-wipe project-switch pattern, same toolbar), kept
// as its own separate set of functions rather than sharing code with Ghost's,
// since Ghost's per-project streaming took real care to get right and this
// avoids risking a regression there for the sake of DRY-ing working code.
const HUNT_TAGS = { phase:"▶ phase", phase_done:"✓ phase", scanner_start:"▸ scanner",
  scanner_done:"⚡ result", scanner_error:"✗ error", finding:"⚑ finding",
  verdict:"✔ verdict", info:"ℹ info" };
let hSince = 0, hPollProject = null, hFindings = 0, hAutoscroll = true, hStarted = null;
let hCatalog = { modules: [], presets: [] };
let hSelected = new Set();

function renderHuntEvent(ev) {
  const d = document.createElement("div");
  d.className = "ev " + ev.type;
  const tag = HUNT_TAGS[ev.type] || ev.type;
  let html = `<span class="ts">${new Date(ev.ts*1000).toLocaleTimeString()}</span><span class="tag">${tag}</span>${esc(ev.text||"")}`;
  if (ev.detail) html += `<span class="detail">${esc(ev.detail)}</span>`;
  d.innerHTML = html;
  $("hunt-log").appendChild(d);
  if (ev.type === "finding") { hFindings++; $("h-findings").textContent = hFindings; }
}
async function hPoll(id) {
  if (id !== hPollProject) return;
  let r;
  try { r = await (await fetch("/hunt/events?since=" + hSince + "&project=" + id)).json(); }
  catch (e) { setTimeout(() => hPoll(id), 600); return; }
  if (id !== hPollProject) return;
  for (const ev of r.events) { renderHuntEvent(ev); hSince = ev.seq; }
  $("h-count").textContent = hSince;
  if (hAutoscroll) $("hunt-log").scrollTop = $("hunt-log").scrollHeight;
  if (hStarted) $("h-elapsed").textContent = Math.round(Date.now()/1000 - hStarted) + "s";
  if (r.done) { $("h-run").disabled = false; $("h-stop").disabled = true;
    $("h-msg").textContent = "Run finished."; return; }
  $("h-run").disabled = true; $("h-stop").disabled = false;
  setTimeout(() => hPoll(id), 600);
}
async function loadHuntViewFor(id) {
  $("hunt-log").innerHTML = ""; hSince = 0; hFindings = 0; hStarted = null;
  $("h-count").textContent = "0"; $("h-findings").textContent = "0"; $("h-elapsed").textContent = "0s";
  hPollProject = id;
  $("h-run").disabled = false; $("h-stop").disabled = true; $("h-msg").textContent = "";
  let st = {};
  try { st = await (await fetch("/hunt/state?project=" + id)).json(); } catch (e) {}
  if (id !== hPollProject) return;
  const ap = projects.find(p => p.id === id);
  $("h-term-title").textContent = "beatrix@hunt — " + (ap ? ap.name : "project " + id);
  if (st && st.target) {
    hStarted = st.started || null;
    $("h-run").disabled = !!st.running; $("h-stop").disabled = !st.running;
    $("h-msg").textContent = st.running ? "Running: " + st.target : "Run finished.";
    hPoll(id);
  }
}

// ── Module/preset control panel ──
function showModTooltip(x, y, text) {
  const t = $("mod-tooltip");
  t.textContent = text;
  t.style.left = (x + 14) + "px"; t.style.top = (y + 14) + "px";
  t.style.display = "block";
}
function hideModTooltip() { $("mod-tooltip").style.display = "none"; }

function renderModules() {
  const wrap = $("h-modules"); wrap.innerHTML = "";
  let lastCat = null;
  for (const m of hCatalog.modules) {
    if (m.category !== lastCat) {
      const h = document.createElement("div");
      h.className = "mod-cat"; h.textContent = m.category;
      wrap.appendChild(h); lastCat = m.category;
    }
    const row = document.createElement("label");
    row.className = "mod-row"; row.dataset.desc = m.description;
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.dataset.key = m.key; cb.checked = hSelected.has(m.key);
    cb.onchange = () => {
      if (cb.checked) hSelected.add(m.key); else hSelected.delete(m.key);
      updateSelCount(); syncPresetHighlight();
    };
    row.appendChild(cb);
    row.appendChild(document.createTextNode(" " + m.name));
    wrap.appendChild(row);
  }
  // Hover tooltip via delegation — one listener instead of one per row.
  wrap.onmouseover = (e) => {
    const row = e.target.closest(".mod-row");
    if (row) showModTooltip(e.clientX, e.clientY, row.dataset.desc);
  };
  wrap.onmousemove = (e) => {
    const row = e.target.closest(".mod-row");
    if (row) showModTooltip(e.clientX, e.clientY, row.dataset.desc);
  };
  wrap.onmouseout = (e) => { if (!e.relatedTarget || !e.relatedTarget.closest(".mod-row")) hideModTooltip(); };
}
function updateSelCount() {
  $("h-selcount").textContent = hSelected.size + " selected";
}
function syncPresetHighlight() {
  // A preset chip lights up only when the current selection exactly matches it.
  for (const chip of document.querySelectorAll(".preset-chip")) {
    const preset = hCatalog.presets.find(p => p.key === chip.dataset.key);
    const matches = preset && preset.modules.length === hSelected.size
      && preset.modules.every(k => hSelected.has(k));
    chip.classList.toggle("active", !!matches);
  }
}
function applySelection(keys) {
  hSelected = new Set(keys);
  for (const cb of document.querySelectorAll("#h-modules input[type=checkbox]")) {
    cb.checked = hSelected.has(cb.dataset.key);
  }
  updateSelCount(); syncPresetHighlight();
}
function renderPresets() {
  const wrap = $("h-presets"); wrap.innerHTML = "";
  for (const p of hCatalog.presets) {
    const chip = document.createElement("button");
    chip.type = "button"; chip.className = "preset-chip"; chip.dataset.key = p.key;
    chip.textContent = p.name; chip.title = p.description;
    chip.onclick = () => applySelection(p.modules);
    wrap.appendChild(chip);
  }
}
async function loadHuntCatalog() {
  hCatalog = await (await fetch("/hunt/catalog")).json();
  renderPresets(); renderModules();
  const standard = hCatalog.presets.find(p => p.key === "standard");
  applySelection(standard ? standard.modules : []);  // sensible one-click default
}
$("h-selall").onclick = (e) => { e.preventDefault(); applySelection(hCatalog.modules.map(m => m.key)); };
$("h-selnone").onclick = (e) => { e.preventDefault(); applySelection([]); };

$("h-autoscroll").onclick = () => {
  hAutoscroll = !hAutoscroll;
  $("h-autoscroll").textContent = "⤓ autoscroll: " + (hAutoscroll ? "on" : "off");
};

$("h-run").onclick = async () => {
  const target = $("h-target").value.trim();
  if (!target) { $("h-msg").textContent = "Enter a target first."; return; }
  if (hSelected.size === 0) { $("h-msg").textContent = "Select at least one module."; return; }
  $("h-run").disabled = true; $("h-msg").textContent = "Starting…";
  $("hunt-log").innerHTML = ""; hSince = 0; hFindings = 0; hStarted = Date.now() / 1000;
  $("h-count").textContent = "0"; $("h-findings").textContent = "0"; $("h-elapsed").textContent = "0s";
  hPollProject = activeProject;
  const matchedPreset = hCatalog.presets.find(p =>
    p.modules.length === hSelected.size && p.modules.every(k => hSelected.has(k)));
  try {
    const r = await (await fetch("/hunt/run", { method:"POST", body: JSON.stringify({
      target, modules: Array.from(hSelected), preset: matchedPreset ? matchedPreset.key : "custom",
      project: activeProject,
    }) })).json();
    if (!r.ok) { $("h-msg").textContent = "Error: " + (r.error || "could not start"); $("h-run").disabled = false; return; }
    $("h-stop").disabled = false;
    $("h-msg").textContent = "Running: " + target;
    hPoll(activeProject);
  } catch (e) { $("h-msg").textContent = "Error: " + e; $("h-run").disabled = false; }
};
$("h-stop").onclick = async () => {
  $("h-stop").disabled = true; $("h-msg").textContent = "Stopping…";
  try {
    const r = await (await fetch("/hunt/stop", { method:"POST",
      body: JSON.stringify({ project: activeProject }) })).json();
    if (!r.ok) { $("h-msg").textContent = "Error: " + (r.error || "could not stop"); $("h-stop").disabled = false; }
  } catch (e) { $("h-msg").textContent = "Error: " + e; $("h-stop").disabled = false; }
};

function saveHuntHtml() {
  const proj = projects.find(p => p.id === activeProject);
  const projName = proj ? proj.name : ("Project " + activeProject);
  const target = $("h-target").value || "—";
  const statusText = $("h-msg").textContent || "";
  const logHtml = $("hunt-log").innerHTML;
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Hunt — ${esc(projName)} — ${esc(target)}</title>
<style>
  :root { --bg:#0b0e14; --panel:#11151f; --border:#222a38; --fg:#c9d4e5; --muted:#6b7787;
    --accent:#3fd0d6; --red:#ff6b6b; --green:#5fd479; --yellow:#e5c07b; --violet:#b98cff; --blue:#5aa9ff; }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f7f9fc; --panel:#fff; --border:#dce3ec; --fg:#1f2733; --muted:#6b7787;
      --accent:#0b8a90; --red:#c0392b; --green:#1a7f37; --yellow:#8a6d1a; --violet:#7a3ff2; --blue:#0969da; } }
  * { box-sizing:border-box; }
  body { margin:0; background:#050607; color:var(--fg);
    font:14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding:20px 24px 60px; }
  h1 { font-size:16px; margin:0 0 6px; }
  .meta { color:var(--muted); font-size:12px; margin-bottom:2px; }
  .ev { padding:2px 0; white-space:pre-wrap; word-break:break-word; }
  .ev .ts { color:var(--muted); margin-right:8px; font-size:12px; }
  .ev .tag { font-weight:700; margin-right:8px; }
  .ev.phase .tag { color:var(--accent); } .ev.phase_done .tag { color:var(--green); }
  .ev.scanner_start .tag { color:var(--yellow); } .ev.scanner_done .tag { color:var(--blue); }
  .ev.scanner_error .tag { color:var(--red); } .ev.info .tag { color:var(--muted); }
  .ev.finding .tag { color:var(--red); } .ev.verdict .tag { color:var(--green); }
  .ev .detail { display:block; color:var(--muted); margin:2px 0 2px 84px; padding:6px 9px;
    background:var(--panel); border:1px solid var(--border); border-radius:6px; max-height:220px; overflow:auto; }
</style></head><body>
<h1>⚔️ BEATRIX HUNT — ${esc(projName)}</h1>
<div class="meta">target <b>${esc(target)}</b></div>
<div class="meta">${esc(statusText)} · saved ${new Date().toLocaleString()}</div>
<div style="margin-top:14px; border-top:1px solid var(--border); padding-top:12px;">${logHtml}</div>
</body></html>`;
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const safeProj = projName.replace(/[^a-z0-9.\-]+/gi, "_");
  const safeTarget = target.replace(/[^a-z0-9.\-]+/gi, "_");
  const ts = new Date().toISOString().replace(/[:]/g, "-").replace("T", "_").slice(0, 19);
  a.href = url;
  a.download = "hunt-" + safeProj + "-" + safeTarget + "-" + ts + ".html";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
$("h-save").onclick = saveHuntHtml;

// ── Scope: per-project list of in-scope hosts (Burp-style target scope) ──
async function loadScopeFor(id) {
  const ap = projects.find(p => p.id === id);
  $("scope-project").textContent = ap ? ap.name : "—";
  let entries = [];
  try { entries = (await (await fetch("/scope?project=" + id)).json()).scope || []; } catch (e) {}
  renderScopeList(entries);
}
function renderScopeList(entries) {
  const wrap = $("scope-list");
  $("scope-count").textContent = entries.length;
  if (!entries.length) {
    wrap.innerHTML = '<div class="scope-empty">No scope defined — Ghost and Hunt will scan only the target itself.</div>';
    return;
  }
  wrap.innerHTML = "";
  for (const host of entries) {
    const row = document.createElement("div");
    row.className = "scope-item";
    const span = document.createElement("span");
    span.className = "host"; span.textContent = host;
    const btn = document.createElement("button");
    btn.textContent = "✕ remove";
    btn.onclick = () => removeScopeEntry(host);
    row.appendChild(span); row.appendChild(btn);
    wrap.appendChild(row);
  }
}
async function addScopeEntries() {
  const text = $("scope-input").value;
  if (!text.trim()) { $("scope-msg").textContent = "Paste a URL, domain, or IP first."; return; }
  try {
    const r = await (await fetch("/scope/add", { method: "POST",
      body: JSON.stringify({ project: activeProject, text }) })).json();
    if (!r.ok) { $("scope-msg").textContent = "Error: " + (r.error || "could not add"); return; }
    $("scope-input").value = ""; $("scope-msg").textContent = "";
    renderScopeList(r.scope);
  } catch (e) { $("scope-msg").textContent = "Error: " + e; }
}
async function removeScopeEntry(host) {
  const r = await (await fetch("/scope/remove", { method: "POST",
    body: JSON.stringify({ project: activeProject, entry: host }) })).json();
  if (r.ok) renderScopeList(r.scope);
}
$("scope-add").onclick = addScopeEntries;
$("scope-clear").onclick = async () => {
  const r = await (await fetch("/scope/clear", { method: "POST",
    body: JSON.stringify({ project: activeProject }) })).json();
  if (r.ok) renderScopeList(r.scope);
};

// ── Issues: Burp-style master/detail. Every finding from a Hunt or Ghost run
// becomes a persistent, per-project issue you can inspect, re-triage, highlight
// or delete. The list is disk-backed on the server; the client mirrors it and
// re-fetches on tab/project switch and on a light poll so new findings appear
// live as a scan runs.
const SEV_RANK = { critical:0, high:1, medium:2, low:3, info:4 };
const HL_COLORS = { red:"#ff5f57", orange:"#ff9f43", yellow:"#f7c948", green:"#28c840",
  blue:"#5aa9ff", purple:"#b98cff", gray:"#8a94a6" };
const ISS_COLS = [
  { key:"severity", label:"Severity" }, { key:"title", label:"Issue" },
  { key:"host", label:"Host" }, { key:"path", label:"Path" },
  { key:"module", label:"Module" }, { key:"confidence", label:"Confidence" },
];
let issuesData = [], issueSort = { key:"severity", dir:1 }, selectedIssue = null;
let issueDetailTab = "advisory", issueDetail = null;

function cmpIssues(a, b) {
  const k = issueSort.key;
  let av, bv;
  if (k === "severity") { av = SEV_RANK[a.severity] ?? 9; bv = SEV_RANK[b.severity] ?? 9; }
  else if (k === "discovered_at") { av = a.discovered_at || 0; bv = b.discovered_at || 0; }
  else { av = String(a[k] || "").toLowerCase(); bv = String(b[k] || "").toLowerCase(); }
  if (av < bv) return -1 * issueSort.dir;
  if (av > bv) return 1 * issueSort.dir;
  return (a.id - b.id);   // stable tiebreak by discovery order
}
function renderIssueHead() {
  const tr = $("iss-head"); tr.innerHTML = "";
  for (const c of ISS_COLS) {
    const th = document.createElement("th");
    const arrow = issueSort.key === c.key ? ` <span class="arrow">${issueSort.dir > 0 ? "▲" : "▼"}</span>` : "";
    th.innerHTML = c.label + arrow;
    th.onclick = () => {
      if (issueSort.key === c.key) issueSort.dir *= -1; else { issueSort.key = c.key; issueSort.dir = 1; }
      $("iss-sort").value = issueSort.key;
      renderIssues();
    };
    tr.appendChild(th);
  }
}
function renderIssues() {
  renderIssueHead();
  const body = $("iss-body"); body.innerHTML = "";
  const rows = issuesData.slice().sort(cmpIssues);
  $("iss-count").textContent = issuesData.length;
  $("iss-empty").style.display = rows.length ? "none" : "block";
  for (const it of rows) {
    const tr = document.createElement("tr");
    if (it.highlight) tr.className = "hl-" + it.highlight;
    if (selectedIssue === it.id) tr.className += " sel";
    tr.innerHTML =
      `<td><span class="sev ${esc(it.severity)}">${esc(it.severity)}</span></td>` +
      `<td>${esc(it.title)}</td><td>${esc(it.host)}</td><td>${esc(it.path)}</td>` +
      `<td>${esc(it.module)}</td><td class="conf">${esc(it.confidence)}</td>`;
    tr.onclick = () => selectIssue(it.id);
    tr.oncontextmenu = (e) => { e.preventDefault(); showIssueCtx(e, it.id); };
    body.appendChild(tr);
  }
}
function updateIssueBadge(n) {
  const b = $("issues-badge");
  b.textContent = n; b.classList.toggle("show", n > 0);
}
async function loadIssuesFor(id) {
  $("iss-project").textContent = (projects.find(p => p.id === id) || {}).name || "—";
  let list = [];
  try { list = (await (await fetch("/issues?project=" + id)).json()).issues || []; } catch (e) {}
  if (id !== activeProject) return;      // switched away while fetching
  issuesData = list;
  updateIssueBadge(list.length);
  if (selectedIssue !== null && !list.some(i => i.id === selectedIssue)) {
    selectedIssue = null; issueDetail = null; renderIssueDetail();
  }
  renderIssues();
}
async function selectIssue(id) {
  selectedIssue = id;
  renderIssues();
  try { issueDetail = (await (await fetch("/issues/detail?project=" + activeProject + "&id=" + id)).json()).issue; }
  catch (e) { issueDetail = null; }
  renderIssueDetail();
}
function fld(label, val, opts) {
  opts = opts || {};
  if (!val || (Array.isArray(val) && !val.length)) {
    return opts.hideEmpty ? "" : `<section><div class="lbl">${esc(label)}</div><div class="none">—</div></section>`;
  }
  let inner;
  if (opts.pre) inner = `<pre>${esc(val)}</pre>`;
  else if (opts.links) inner = "<ul>" + val.map(u =>
    /^https?:\/\//.test(u) ? `<li><a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a></li>` : `<li>${esc(u)}</li>`).join("") + "</ul>";
  else if (opts.list) inner = "<ul>" + val.map(s => `<li>${esc(s)}</li>`).join("") + "</ul>";
  else inner = `<div>${esc(val)}</div>`;
  return `<section><div class="lbl">${esc(label)}</div>${inner}</section>`;
}
function renderIssueDetail() {
  const box = $("iss-detail");
  const d = issueDetail;
  if (!d) { box.innerHTML = '<div class="none">Select an issue to view its details.</div>'; return; }
  if (issueDetailTab === "advisory") {
    box.innerHTML =
      `<h3>${esc(d.title)}</h3>` +
      `<div class="kv"><span class="sev ${esc(d.severity)}">${esc(d.severity)}</span> · ` +
      `confidence <b>${esc(d.confidence)}</b> · module <b>${esc(d.module)}</b> · ` +
      `found by <b>${esc(d.origin === "ghost" ? "Ghost agent" : "Hunt")}</b>${d.validated ? " · <b>validated</b>" : ""}</div>` +
      `<div class="kv">URL: <b>${esc(d.url || "—")}</b>${d.parameter ? " · parameter <b>" + esc(d.parameter) + "</b>" : ""}</div>` +
      fld("Description", d.description) + fld("Impact", d.impact) + fld("Remediation", d.remediation) +
      fld("Classifications", [d.cwe, d.owasp].filter(Boolean), { list:true, hideEmpty:true }) +
      fld("References / documentation", d.references, { links:true });
  } else if (issueDetailTab === "request") {
    box.innerHTML = fld("HTTP request", d.request, { pre:true });
  } else if (issueDetailTab === "response") {
    box.innerHTML = fld("HTTP response", d.response, { pre:true });
  } else {   // poc
    box.innerHTML =
      fld("Evidence", d.evidence, { pre:true }) +
      fld("Payload", d.payload, { pre:true, hideEmpty:true }) +
      fld("curl PoC", d.poc_curl, { pre:true, hideEmpty:true }) +
      fld("Python PoC", d.poc_python, { pre:true, hideEmpty:true }) +
      fld("Reproduction steps", d.reproduction_steps, { list:true });
  }
}
document.querySelectorAll("#iss-dtabs button").forEach(b => {
  b.onclick = () => {
    document.querySelectorAll("#iss-dtabs button").forEach(x => x.classList.toggle("active", x === b));
    issueDetailTab = b.dataset.dt; renderIssueDetail();
  };
});
$("iss-sort").onchange = () => { issueSort.key = $("iss-sort").value; issueSort.dir = 1; renderIssues(); };
$("iss-clear").onclick = async () => {
  if (!issuesData.length) return;
  if (!confirm("Delete all " + issuesData.length + " issue(s) in this project?")) return;
  await fetch("/issues/clear", { method:"POST", body: JSON.stringify({ project: activeProject }) });
  selectedIssue = null; issueDetail = null; renderIssueDetail();
  loadIssuesFor(activeProject);
};

// Right-click menu: set severity / highlight / delete.
function showIssueCtx(e, id) {
  const m = $("issue-ctx");
  const sevBtns = Object.keys(SEV_RANK).map(s =>
    `<button data-act="sev" data-v="${s}">${s}</button>`).join("");
  const swatches = Object.entries(HL_COLORS).map(([name, col]) =>
    `<span class="sw" title="${name}" style="background:${col}" data-act="hl" data-v="${name}"></span>`).join("") +
    `<button data-act="hl" data-v="none" style="font-size:11px; padding:1px 6px;">none</button>`;
  m.innerHTML =
    `<div class="lbl">Set severity</div><div class="opts">${sevBtns}</div>` +
    `<div class="lbl">Highlight</div><div class="opts">${swatches}</div>` +
    `<hr><button class="del" data-act="del">Delete issue</button>`;
  m.dataset.iid = id;
  m.style.display = "block"; m.style.left = e.clientX + "px"; m.style.top = e.clientY + "px";
  // keep the menu on-screen
  const r = m.getBoundingClientRect();
  if (r.right > innerWidth) m.style.left = (innerWidth - r.width - 6) + "px";
  if (r.bottom > innerHeight) m.style.top = (innerHeight - r.height - 6) + "px";
  m.querySelectorAll("[data-act]").forEach(el => {
    el.onclick = async (ev) => {
      ev.stopPropagation();
      const act = el.dataset.act, v = el.dataset.v;
      $("issue-ctx").style.display = "none";
      if (act === "del") {
        await fetch("/issues/delete", { method:"POST", body: JSON.stringify({ project: activeProject, id }) });
        if (selectedIssue === id) { selectedIssue = null; issueDetail = null; renderIssueDetail(); }
      } else {
        const patch = { project: activeProject, id };
        if (act === "sev") patch.severity = v; else patch.highlight = v;
        await fetch("/issues/update", { method:"POST", body: JSON.stringify(patch) });
      }
      loadIssuesFor(activeProject);
    };
  });
}

// ── Projects: left rail (switch / create / delete) ──
let projects = [], activeProject = null;
function renderProjects() {
  const rail = $("projects"); rail.innerHTML = "";
  for (const p of projects) {
    const b = document.createElement("button");
    b.className = "proj" + (p.id === activeProject ? " active" : "");
    b.textContent = p.id; b.title = p.name;
    b.onclick = () => selectProject(p.id);
    b.oncontextmenu = (e) => { e.preventDefault(); showCtx(e, p.id); };
    rail.appendChild(b);
  }
  const add = document.createElement("button");
  add.className = "proj add"; add.textContent = "+"; add.title = "New project";
  add.onclick = newProject;
  rail.appendChild(add);
  const ap = projects.find(p => p.id === activeProject);
  $("proj-label").textContent = ap ? ap.name : "—";
  $("dash-project").textContent = ap ? ap.name : "—";
}
function applyState(d) { projects = d.projects || []; activeProject = d.active; renderProjects(); }
async function loadProjects() { applyState(await (await fetch("/projects")).json()); }
async function selectProject(id) {
  if (id === activeProject) return;
  await fetch("/projects/select", { method:"POST", body: JSON.stringify({ id }) });
  activeProject = id; renderProjects(); onProjectSwitch();
}
async function newProject() {
  applyState(await (await fetch("/projects/new", { method:"POST", body:"{}" })).json());
  onProjectSwitch();
}
async function deleteProject(id) {
  const d = await (await fetch("/projects/delete", { method:"POST", body: JSON.stringify({ id }) })).json();
  if (d.ok) { applyState(d); onProjectSwitch(); }
}
function onProjectSwitch() {
  // Rebuild (never just clear) the per-project tool views from server state,
  // so a run left going in another project stays visible when you switch back.
  loadGhostViewFor(activeProject);
  loadHuntViewFor(activeProject);
  loadScopeFor(activeProject);
  selectedIssue = null; issueDetail = null; renderIssueDetail();
  loadIssuesFor(activeProject);
}

// Context menu
function showCtx(e, id) {
  const m = $("ctxmenu");
  m.style.display = "block"; m.style.left = e.clientX + "px"; m.style.top = e.clientY + "px";
  m.dataset.pid = id;
}
document.addEventListener("click", () => {
  $("ctxmenu").style.display = "none"; $("issue-ctx").style.display = "none";
});
$("ctx-del").onclick = () => {
  const id = parseInt($("ctxmenu").dataset.pid, 10);
  $("ctxmenu").style.display = "none";
  deleteProject(id);
};

// Live refresh: keep the Issues badge current everywhere, and the list current
// while it's the visible tab, so findings appear as a scan discovers them.
setInterval(() => {
  if (activeProject === null) return;
  const onIssues = document.querySelector('nav button[data-tab="issues"]').classList.contains("active");
  if (onIssues) { loadIssuesFor(activeProject); return; }
  fetch("/issues/count?project=" + activeProject).then(r => r.json())
    .then(d => updateIssueBadge(d.count || 0)).catch(() => {});
}, 2000);

loadHuntCatalog();
loadProjects().then(() => {
  loadGhostViewFor(activeProject); loadHuntViewFor(activeProject);
  loadScopeFor(activeProject); loadIssuesFor(activeProject);
});  // restore any run in progress + the active project's scope/issues on load/refresh
</script>
</body>
</html>"""


class SuiteServer:
    """The single central-dashboard server. One port, all tools + projects."""

    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_PORT,
                 state_dir: Optional[Path] = None):
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None
        self.url: str = ""
        self.public_url: Optional[str] = None
        self.projects = _ProjectStore(Path(state_dir) if state_dir else DEFAULT_STATE_DIR)
        # Per-project issue log (Burp-style): every finding from Hunt or Ghost
        # lands here for inspection / re-triage / highlight / delete.
        self.issues = _IssueStore(self.projects)
        # One ghost run + event broker PER project (keyed by str(project id)), so
        # switching projects preserves each project's live run view.
        self.ghost_brokers: Dict[str, _Broker] = {}
        # Same per-project isolation for Hunt (the deterministic scanner pipeline).
        self.hunt_brokers: Dict[str, _Broker] = {}
        # (loop, task) for each in-flight run, keyed the same way, so the Stop
        # button can cancel a run from the HTTP handler thread.
        self.ghost_tasks: Dict[str, Any] = {}
        self.hunt_tasks: Dict[str, Any] = {}
        self._lock = threading.Lock()

    # ── Ghost run lifecycle ──────────────────────────────────────────────
    def start_ghost_run(self, target: str, objective: str, project_id: Any) -> Dict[str, Any]:
        """Launch a GHOST v2 investigation in a background thread, scoped to
        ``project_id``.

        Each project keeps its own event broker (keyed by ``str(project_id)``)
        so switching projects never loses or clobbers another project's live
        run view — that was the v1 bug: a single shared broker meant creating
        or switching to a different project blew away whatever the previous
        project's run had streamed, even though the run itself kept going.

        Returns an ack dict; run output is streamed via that project's broker.
        Guards the ``[agent]`` extra + missing-API-key the same way the CLI does.
        """
        target = (target or "").strip()
        if not target:
            return {"ok": False, "error": "target required"}

        key = str(project_id)
        with self._lock:
            existing = self.ghost_brokers.get(key)
            # since(<huge>) is a read-only way to ask "is this broker done?"
            # without reaching into _Broker's private _done attribute.
            if existing is not None and not existing.since(10**9)["done"]:
                return {"ok": False, "error": "A scan is already running for this project."}

        try:
            from beatrix.ai.ghost2.config import GhostV2Config
            from beatrix.ai.ghost2.core.runner import run_investigation
        except ImportError:
            return {"ok": False, "error": "GHOST v2 needs the 'agent' extra "
                    "(pip install 'beatrix-cli[agent]')."}

        cfg = GhostV2Config.load()
        key_hint = cfg.missing_key_message()
        if key_hint:
            return {"ok": False, "error": key_hint}

        objective = (objective or "").strip() or "Find and validate security vulnerabilities."
        allowed_hosts = self.projects.get_scope(project_id)
        broker = _Broker(meta={"target": target, "model": cfg.model,
                               "objective": objective, "auth": "none",
                               "scope": allowed_hosts})
        with self._lock:
            self.ghost_brokers[key] = broker

        # Live Issues-tab capture: every finding the agent records (root or any
        # subagent) streams into this project's issue log with full detail.
        def _capture(finding: Any) -> None:
            try:
                self.issues.add_finding(project_id, finding,
                                        getattr(finding, "scanner_module", "") or "ghost2", "ghost")
            except Exception:
                pass

        def _run() -> None:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            task = loop.create_task(run_investigation(
                target, cfg=cfg, objective=objective,
                allowed_hosts=allowed_hosts,
                on_event=broker.emit, on_finding=_capture, persist=True,
            ))
            with self._lock:
                self.ghost_tasks[key] = (loop, task)
            try:
                result = loop.run_until_complete(task)
                # Completion backstop: sweep the authoritative final findings
                # into the issue log (idempotent — the live sink already added
                # most; dedup keeps this from double-counting).
                for f in (result.get("findings") or []):
                    _capture(f)
                broker.emit({"type": "verdict", "text": result.get("verdict", "done"),
                             "detail": result.get("final_output") or ""})
            except asyncio.CancelledError:
                broker.emit({"type": "verdict", "text": "stopped",
                             "detail": "Scan stopped by user."})
            except Exception as e:  # noqa: BLE001 — surface any failure to the pane
                broker.emit({"type": "verdict", "text": "error",
                             "detail": f"{type(e).__name__}: {e}"})
            finally:
                _shutdown_loop(loop)
                with self._lock:
                    self.ghost_tasks.pop(key, None)
                broker.finish()

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True, "target": target}

    def stop_ghost_run(self, project_id: Any) -> Dict[str, Any]:
        """Cancel the in-flight GHOST run for ``project_id``, if any.

        Cancelling the task raises ``asyncio.CancelledError`` at its current
        await point — since that's a ``BaseException``, not ``Exception``, it
        passes straight through every broad ``except Exception`` in the run
        (session/agent teardown still happens via their own ``finally``
        blocks) and is caught here as a distinct "stopped" outcome.
        """
        with self._lock:
            entry = self.ghost_tasks.get(str(project_id))
        if entry is None:
            return {"ok": False, "error": "No scan running for this project."}
        loop, task = entry
        loop.call_soon_threadsafe(task.cancel)
        return {"ok": True}

    def ghost_events(self, since: int, project_id: Any) -> Dict[str, Any]:
        b = self.ghost_brokers.get(str(project_id))
        # No broker for this project => nothing has run there; report "done"
        # so a client never sits in a poll loop for a project with no run.
        return b.since(since) if b is not None else {"events": [], "done": True}

    def ghost_state(self, project_id: Any) -> Dict[str, Any]:
        b = self.ghost_brokers.get(str(project_id))
        if b is None:
            return {}
        state = dict(b.meta)
        state["running"] = not b.since(10**9)["done"]
        return state

    # ── Hunt run lifecycle ───────────────────────────────────────────────
    def start_hunt_run(self, target: str, modules: List[str], preset_label: str,
                        ai: bool, project_id: Any) -> Dict[str, Any]:
        """Launch a deterministic Hunt scan in a background thread, scoped to
        ``project_id`` exactly like Ghost — its own broker, its own
        concurrent-run guard, and its scan output rooted in the project's own
        workspace dir so projects' scan data stays separated.

        ``modules`` must be a non-empty explicit list: ``BeatrixEngine.hunt()``
        treats an *empty* list as "run every module" (see kill_chain's
        module-filter: ``if requested_modules and name not in requested_modules:
        skip`` — empty is falsy, so nothing gets filtered out). Silently running
        the entire arsenal on a selection the user meant to leave blank would
        be a nasty surprise, so this is rejected instead.
        """
        target = (target or "").strip()
        if not target:
            return {"ok": False, "error": "target required"}
        modules = [m for m in (modules or []) if m]
        if not modules:
            return {"ok": False, "error": "select at least one module"}

        key = str(project_id)
        with self._lock:
            existing = self.hunt_brokers.get(key)
            if existing is not None and not existing.since(10**9)["done"]:
                return {"ok": False, "error": "A scan is already running for this project."}

        # Empty scope == unrestricted (same convention as everywhere else in
        # the suite): scan/report on whatever the target and its crawl turn up.
        scope_hosts = self.projects.get_scope(project_id)

        broker = _Broker(meta={"target": target, "preset": preset_label,
                               "modules": modules, "ai": bool(ai), "scope": scope_hosts})
        with self._lock:
            self.hunt_brokers[key] = broker

        def _on_event(event: str, data: dict) -> None:
            # Scope backstop #1: never even show an out-of-scope finding in
            # the live terminal, regardless of whether the scanner that found
            # it consulted the crawler's scope patterns.
            if event == "finding" and scope_hosts:
                f = data.get("finding")
                url = (getattr(f, "url", "") if f else "") or target
                if not _host_in_scope(url, scope_hosts):
                    host = urlparse(url).hostname or url
                    broker.emit({"type": "info", "text": f"⚠ Skipped out-of-scope finding on {host}"})
                    return
            # Live Issues-tab capture: an in-scope finding becomes an issue the
            # moment the scanner reports it (Burp-style), with full detail.
            if event == "finding":
                f = data.get("finding")
                if f is not None:
                    try:
                        self.issues.add_finding(project_id, f, data.get("scanner", "") or "", "hunt")
                    except Exception:
                        pass
            line = _hunt_event_to_line(event, data)
            if line is not None:
                broker.emit(line)

        def _run() -> None:
            import asyncio
            from datetime import datetime

            from beatrix.core.engine import BeatrixEngine, EngineConfig
            from beatrix.core.scan_output import ScanOutputManager

            output_mgr = None
            try:
                output_mgr = ScanOutputManager(
                    target, base_dir=self.projects.workspace_dir(project_id))
            except Exception:
                pass

            engine = BeatrixEngine(config=EngineConfig(), on_event=_on_event,
                                   output_manager=output_mgr)
            crawler_scope = _expand_for_crawler(scope_hosts) if scope_hosts else None

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            # preset="full" always opens every phase (1-7), so an arbitrary,
            # cross-category module selection can never be silently blocked
            # by a narrower preset's phase gate — the explicit `modules` list
            # is what actually restricts which scanners run (see kill_chain's
            # per-scanner filter above).
            task = loop.create_task(engine.hunt(target=target, preset="full", ai=ai,
                                                modules=modules, scope=crawler_scope))
            with self._lock:
                self.hunt_tasks[key] = (loop, task)

            try:
                state = loop.run_until_complete(task)

                # Scope backstop #2: the same filter as _on_event above, but
                # against the final, deduplicated findings list — covers
                # anything a scanner recorded through a path that bypassed the
                # live per-event stream, before it's counted or persisted.
                if scope_hosts:
                    kept = [f for f in engine.findings
                            if _host_in_scope((getattr(f, "url", "") or target), scope_hosts)]
                    dropped = len(engine.findings) - len(kept)
                    engine.findings = kept
                    if dropped:
                        broker.emit({"type": "info",
                                     "text": f"⚠ {dropped} out-of-scope finding(s) excluded from the final report"})

                duration = (datetime.now() - state.started_at).total_seconds()
                modules_run = set()
                for pr in state.phase_results.values():
                    modules_run.update(pr.modules_run)

                hunt_id = None
                try:
                    from beatrix.core.findings_db import FindingsDB
                    with FindingsDB() as db:
                        hunt_id = db.save_hunt(
                            target=target, preset=preset_label, findings=engine.findings,
                            duration=duration, modules_run=sorted(modules_run),
                            ai_enabled=ai, started_at=state.started_at,
                        )
                except Exception:
                    pass

                n = len(engine.findings)
                detail = f"{duration:.1f}s · modules: {', '.join(sorted(modules_run)) or 'none'}"
                if hunt_id:
                    detail += f" · hunt #{hunt_id}"
                broker.emit({"type": "verdict",
                             "text": f"Hunt complete — {n} finding{'s' if n != 1 else ''}",
                             "detail": detail})
            except asyncio.CancelledError:
                n = len(engine.findings)
                broker.emit({"type": "verdict", "text": "stopped",
                             "detail": f"Scan stopped by user — {n} finding{'s' if n != 1 else ''} "
                                       "recorded before stop."})
            except Exception as e:  # noqa: BLE001 — surface any failure to the pane
                broker.emit({"type": "verdict", "text": "error",
                             "detail": f"{type(e).__name__}: {e}"})
            finally:
                _shutdown_loop(loop)
                with self._lock:
                    self.hunt_tasks.pop(key, None)
                broker.finish()

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True, "target": target}

    def stop_hunt_run(self, project_id: Any) -> Dict[str, Any]:
        """Cancel the in-flight Hunt scan for ``project_id``, if any (see
        ``stop_ghost_run`` for why ``asyncio.CancelledError`` cleanly
        distinguishes a user-requested stop from a real error)."""
        with self._lock:
            entry = self.hunt_tasks.get(str(project_id))
        if entry is None:
            return {"ok": False, "error": "No scan running for this project."}
        loop, task = entry
        loop.call_soon_threadsafe(task.cancel)
        return {"ok": True}

    def hunt_events(self, since: int, project_id: Any) -> Dict[str, Any]:
        b = self.hunt_brokers.get(str(project_id))
        return b.since(since) if b is not None else {"events": [], "done": True}

    def hunt_state(self, project_id: Any) -> Dict[str, Any]:
        b = self.hunt_brokers.get(str(project_id))
        if b is None:
            return {}
        state = dict(b.meta)
        state["running"] = not b.since(10**9)["done"]
        return state

    # ── HTTP ─────────────────────────────────────────────────────────────
    def start(self, open_browser: bool = True) -> str:
        suite = self

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, code: int, body: bytes, ctype: str):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _json(self, obj: Any):
                self._send(200, json.dumps(obj).encode("utf-8"), "application/json")

            def do_GET(self):
                path = urlparse(self.path).path
                if path in ("/", "/index.html"):
                    self._send(200, _PAGE.encode("utf-8"), "text/html; charset=utf-8")
                elif path == "/auth":
                    # Existing auth GUI, verbatim, same origin (its /api/* calls
                    # resolve to the handlers below).
                    self._send(200, _AUTH_PAGE.encode("utf-8"), "text/html; charset=utf-8")
                elif path == "/projects":
                    self._json(suite.projects.state())
                elif path in _AUTH_GET:
                    try:
                        result = _AUTH_GET[path]()
                    except Exception as e:  # noqa: BLE001
                        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                    self._json(result)
                elif path == "/ghost/events":
                    q = parse_qs(urlparse(self.path).query)
                    since = int((q.get("since") or ["0"])[0])
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.ghost_events(since, proj))
                elif path == "/ghost/state":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.ghost_state(proj))
                elif path == "/hunt/catalog":
                    self._json(_build_hunt_catalog())
                elif path == "/hunt/events":
                    q = parse_qs(urlparse(self.path).query)
                    since = int((q.get("since") or ["0"])[0])
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.hunt_events(since, proj))
                elif path == "/hunt/state":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.hunt_state(proj))
                elif path == "/scope":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json({"scope": suite.projects.get_scope(proj)})
                elif path == "/issues":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json({"issues": suite.issues.list(proj)})
                elif path == "/issues/count":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json({"count": suite.issues.count(proj)})
                elif path == "/issues/detail":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    iid = (q.get("id") or [None])[0]
                    self._json({"issue": suite.issues.get(proj, iid)})
                else:
                    self._send(404, b"not found", "text/plain")

            def do_POST(self):
                path = urlparse(self.path).path
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    payload = json.loads(raw or b"{}")
                except Exception:
                    payload = {}

                if path in _AUTH_POST:
                    try:
                        result = _AUTH_POST[path](payload)
                    except Exception as e:  # noqa: BLE001
                        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                    self._json(result)
                elif path == "/ghost/run":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.start_ghost_run(
                        payload.get("target", ""), payload.get("objective", ""), proj))
                elif path == "/ghost/stop":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.stop_ghost_run(proj))
                elif path == "/hunt/run":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.start_hunt_run(
                        payload.get("target", ""), payload.get("modules") or [],
                        payload.get("preset", "custom"), bool(payload.get("ai")), proj))
                elif path == "/hunt/stop":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.stop_hunt_run(proj))
                elif path == "/scope/add":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    entries = _parse_scope_text(payload.get("text", ""))
                    if not entries:
                        self._json({"ok": False, "error": "no valid hosts/URLs found"})
                    else:
                        self._json(suite.projects.add_scope(proj, entries))
                elif path == "/scope/remove":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.projects.remove_scope(proj, payload.get("entry", "")))
                elif path == "/scope/clear":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.projects.clear_scope(proj))
                elif path == "/issues/update":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.issues.update(
                        proj, payload.get("id"),
                        severity=payload.get("severity"),
                        highlight=payload.get("highlight")))
                elif path == "/issues/delete":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.issues.delete(proj, payload.get("id")))
                elif path == "/issues/clear":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.issues.clear(proj))
                elif path == "/projects/new":
                    self._json(suite.projects.new())
                elif path == "/projects/select":
                    self._json(suite.projects.select(payload.get("id")))
                elif path == "/projects/delete":
                    self._json(suite.projects.delete(payload.get("id")))
                else:
                    self._send(404, b"not found", "text/plain")

        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port), _H)
        except OSError:
            # Port busy — fall back to an ephemeral free port rather than fail.
            self._httpd = ThreadingHTTPServer((self.host, 0), _H)
        self.port = self._httpd.server_address[1]
        display_host = "127.0.0.1" if self.host in ("0.0.0.0", "::") else self.host
        self.url = f"http://{display_host}:{self.port}/"
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

        codespace = os.environ.get("CODESPACE_NAME")
        fwd = os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN")
        if codespace and fwd:
            self.public_url = f"https://{codespace}-{self.port}.{fwd}/"

        if open_browser:
            threading.Thread(target=lambda: webbrowser.open(self.url), daemon=True).start()
        return self.url

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


def main(host: str = "0.0.0.0", port: int = DEFAULT_PORT, open_browser: bool = True) -> None:
    """Launch the Beatrix Suite dashboard and block until Ctrl-C."""
    # Load ~/.beatrix/.env so AI keys are available to the Ghost tool, matching
    # the CLI startup path.
    try:
        from beatrix.cli.auth_gui import load_beatrix_env
        load_beatrix_env()
    except Exception:
        pass

    server = SuiteServer(host=host, port=port)
    server.start(open_browser=open_browser)
    print(f"Beatrix Suite → {server.url}", flush=True)
    if server.public_url:
        print(f"   Codespaces → {server.public_url}", flush=True)
    print("Press Ctrl-C to stop.", flush=True)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
