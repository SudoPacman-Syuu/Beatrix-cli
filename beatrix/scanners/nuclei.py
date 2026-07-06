"""
BEATRIX Nuclei Scanner — Intelligent Template Engine

Full-featured nuclei integration with:
1. Authenticated scanning — passes auth headers/cookies via -H flags
2. Workflow support — runs nuclei workflows for detected technologies
3. Custom templates — loads user templates from ~/.beatrix/nuclei-templates/
4. Headless browser — DOM XSS/prototype pollution via -headless mode
5. Intelligent tag selection — tech-aware inclusion + exclude-tags
6. Interactsh integration — passes Beatrix OOB domain via -iserver
7. Network port scanning — feeds non-HTTP services for protocol checks
8. Split-phase execution — fast recon (Phase 1) + full exploit (Phase 4)
9. Global rate limiting — WAF-adaptive request throttling
10. External template repos — auto-fetches bug-bounty focused templates

Template Sources (auto-updated):
- Official nuclei-templates (ProjectDiscovery community)
- projectdiscovery/fuzzing-templates (DAST-style active fuzzing)
- User custom templates (~/.beatrix/nuclei-templates/)

Architecture:
- scan_recon(): Phase 1 — fast tech/panel/WAF detection
- scan_exploit(): Phase 4 — full CVE/exploit run with workflows
- scan_network(): Phase 1 — network protocol templates on discovered ports
- scan_headless(): Phase 4 — DOM-based checks with headless chromium
- scan(): Default entry — runs exploit pass (backward compatible)
"""

import asyncio
import json
import os
import re
import shutil
import signal
import time
from pathlib import Path
from typing import AsyncIterator, Dict, List, Optional, Set

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext, get_host_rate_ceiling

# Map nuclei severity strings to Beatrix Severity
NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

# ── Per-host parallel scanning (issue #9) ────────────────────────────────
# nuclei's -rate-limit is a single global budget per process, so packing
# every subdomain into one invocation means the whole site shares one rate —
# slow for large scopes, and if raised it 429s individual hosts. Instead we
# partition targets by host and run several single-host nuclei processes at
# once: each host gets its own safe per-host rate (no 429s), and a semaphore
# caps how many run concurrently (so CPU/RAM stays bounded).

# Hard ceiling on concurrent nuclei processes, regardless of CPU count —
# each process loads the full template set into memory, so RAM, not CPU, is
# the binding constraint. Overridable via config ``nuclei_max_parallel_hosts``.
_DEFAULT_MAX_PARALLEL_HOSTS = 6

# Total in-flight request concurrency to spread across the running processes
# (each process gets ``budget // parallel``). Keeps the aggregate close to a
# single process's default (-concurrency 25) rather than parallel × 25.
_PARALLEL_CONCURRENCY_BUDGET = 50
# Floor so a highly-parallel run doesn't starve each process to a crawl.
_MIN_HOST_CONCURRENCY = 10
# nuclei's own default when running a single host (unchanged behaviour).
_DEFAULT_HOST_CONCURRENCY = 25


class NucleiScanner(BaseScanner):
    """
    Nuclei template scanner — intelligent, multi-phase, authenticated.

    Operates in multiple modes:
    - RECON: Fast tech/panel/WAF detection (~60s, info/low only)
    - EXPLOIT: Full CVE/exploit scan (~15min, all severities)
    - NETWORK: Protocol-specific checks on non-HTTP services
    - HEADLESS: DOM-based checks via headless chromium
    - WORKFLOW: Technology-specific multi-step attack chains
    """

    name = "nuclei"
    description = "Nuclei template scanner — CVEs, misconfigs, exposed panels, takeovers"
    version = "3.0.0"

    # ─────────────────────────────────────────────────────────────────────
    # Technology → nuclei tag mapping (used for BOTH inclusion and exclusion)
    # ─────────────────────────────────────────────────────────────────────
    TECH_TAG_MAP = {
        # Web servers
        "nginx": ["nginx"],
        "apache": ["apache", "httpd"],
        "iis": ["iis", "microsoft"],
        "caddy": ["caddy"],
        "tomcat": ["tomcat"],
        "lighttpd": ["lighttpd"],
        # CMS / Frameworks
        "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
        "joomla": ["joomla"],
        "drupal": ["drupal"],
        "magento": ["magento"],
        "shopify": ["shopify"],
        "ghost": ["ghost"],
        "hugo": ["hugo"],
        "woocommerce": ["woocommerce", "wordpress"],
        # Languages / Runtimes
        "php": ["php"],
        "asp.net": ["asp", "dotnet", "microsoft"],
        "java": ["java"],
        "spring": ["spring", "springboot"],
        "python": ["python"],
        "django": ["django"],
        "flask": ["flask"],
        "laravel": ["laravel", "php"],
        "rails": ["rails", "ruby"],
        "express": ["nodejs", "express"],
        "node": ["nodejs"],
        "next.js": ["nextjs"],
        "nuxt": ["nuxt"],
        "react": ["react"],
        "angular": ["angular"],
        "vue": ["vue"],
        # Infrastructure
        "cloudflare": ["cloudflare"],
        "aws": ["aws", "amazon"],
        "azure": ["azure", "microsoft"],
        "gcp": ["gcp", "google"],
        # Panels / Services
        "jenkins": ["jenkins"],
        "gitlab": ["gitlab"],
        "grafana": ["grafana"],
        "kibana": ["kibana"],
        "elasticsearch": ["elasticsearch"],
        "prometheus": ["prometheus"],
        "docker": ["docker"],
        "kubernetes": ["kubernetes", "k8s"],
        "traefik": ["traefik"],
        "consul": ["consul"],
        "vault": ["vault", "hashicorp"],
        "minio": ["minio"],
        "redis": ["redis"],
        "mongodb": ["mongodb"],
        "mysql": ["mysql"],
        "postgres": ["postgres"],
        "rabbitmq": ["rabbitmq"],
        "kafka": ["kafka"],
        "solr": ["solr"],
        "jira": ["jira", "atlassian"],
        "confluence": ["confluence", "atlassian"],
        "bitbucket": ["bitbucket", "atlassian"],
        "sonarqube": ["sonarqube"],
        "harbor": ["harbor"],
        "airflow": ["airflow"],
        "superset": ["superset"],
    }

    # Technologies that have nuclei workflow files
    WORKFLOW_TECH_MAP = {
        "wordpress": "wordpress-workflow.yaml",
        "joomla": "joomla-workflow.yaml",
        "drupal": "drupal-workflow.yaml",
        "jenkins": "jenkins-workflow.yaml",
        "gitlab": "gitlab-workflow.yaml",
        "jira": "jira-workflow.yaml",
        "springboot": "springboot-workflow.yaml",
        "spring": "springboot-workflow.yaml",
        "magento": "magento-workflow.yaml",
        "moodle": "moodle-workflow.yaml",
        "grafana": "grafana-workflow.yaml",
        "airflow": "airflow-workflow.yaml",
    }

    # External template repositories to auto-fetch.
    # Each is cloned once (--depth=1), then git-pulled if >7 days stale.
    # All clones run in parallel on first invocation.
    #
    # NOTE: Do NOT add projectdiscovery/nuclei-templates here — it's already
    # managed separately via `nuclei -update-templates` (~/nuclei-templates/).
    TEMPLATE_REPOS = [
        {
            "name": "fuzzing-templates",
            "url": "https://github.com/projectdiscovery/fuzzing-templates",
            "dir": "fuzzing-templates",
            "description": "DAST-style active fuzzing templates (ProjectDiscovery)",
        },
        {
            "name": "nuclei-templates-pikpikcu",
            "url": "https://github.com/pikpikcu/nuclei-templates",
            "dir": "nuclei-templates-pikpikcu",
            "description": "Bug bounty focused CVE and exploit templates",
        },
        {
            "name": "kenzer-templates",
            "url": "https://github.com/ARPSyndicate/kenzer-templates",
            "dir": "kenzer-templates",
            "description": "KENZER recon & exploit templates — subdomain takeover, misconfigs",
        },
    ]

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.nuclei_path = self._find_nuclei()

        # Timeouts — None means no wall-clock limit (run until nuclei finishes)
        self._base_timeout = self.config.get("nuclei_timeout", None)
        self.timeout_seconds = self._base_timeout

        # URL lists for different scan modes
        self._urls_to_scan: Set[str] = set()
        self._network_targets: List[str] = []  # host:port for network scans

        # Severity filter
        self._severity_filter = self.config.get(
            "nuclei_severity", "critical,high,medium,low,info"
        )

        # Detected technologies (name -> version, empty string if unknown)
        self._detected_technologies: Dict[str, str] = {}

        # Template directories
        self._template_dir = Path.home() / "nuclei-templates"
        self._custom_template_dir = Path.home() / ".beatrix" / "nuclei-templates"
        self._extra_template_dirs: List[Path] = []
        self._templates_verified = False

        # Auth credentials (set by kill chain via set_auth())
        self._auth_headers: List[str] = []  # ["-H", "Cookie: ...", "-H", "Auth: ..."]

        # Interactsh configuration
        self._interactsh_server: Optional[str] = None
        self._interactsh_token: Optional[str] = None

        # WAF/CDN bypass
        self._waf_detected: Optional[str] = None  # e.g. "Cloudflare", "Akamai"
        self._origin_ip: Optional[str] = None  # Direct IP to bypass CDN
        self._target_domain: Optional[str] = None  # Original domain for Host header

        # Realistic User-Agent (Chrome on Linux — matches session validator)
        self._user_agent = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )

        # Rate limiting — defaults adjusted if WAF detected
        self._rate_limit = self.config.get("nuclei_rate_limit", 10)

    def _find_nuclei(self) -> Optional[str]:
        """Find nuclei binary on PATH"""
        path = shutil.which("nuclei")
        if path:
            return path
        # Check common locations
        for candidate in ["/usr/bin/nuclei", "/usr/local/bin/nuclei",
                         str(Path.home() / "go/bin/nuclei"),
                         str(Path.home() / ".local/bin/nuclei")]:
            if Path(candidate).exists():
                return candidate
        return None

    @property
    def available(self) -> bool:
        return self.nuclei_path is not None

    @staticmethod
    def _dir_has_yaml(d: Path) -> bool:
        """Fast check: does directory contain at least one .yaml file?

        Uses next() with a generator instead of building a full list,
        so it short-circuits on the first match.
        """
        try:
            next(d.glob("**/*.yaml"))
            return True
        except StopIteration:
            return False

    async def _ensure_templates(self) -> bool:
        """Ensure all template sources are installed and fresh.

        Manages:
        1. Official nuclei-templates (auto-update > 7 days)
        2. External repos (fuzzing-templates, etc.)
        3. Custom user templates directory
        """
        if self._templates_verified:
            return True

        if not self.nuclei_path:
            return False

        # 1. Official templates
        await self._update_official_templates()

        # 2. External template repos
        await self._update_external_repos()

        # 3. Custom user templates
        self._setup_custom_templates()

        # Count available templates
        yaml_count = sum(1 for _ in self._template_dir.glob("**/*.yaml")) if self._template_dir.exists() else 0
        extra_count = sum(
            sum(1 for _ in d.glob("**/*.yaml"))
            for d in self._extra_template_dirs if d.exists()
        )
        custom_count = sum(1 for _ in self._custom_template_dir.glob("**/*.yaml")) if self._custom_template_dir.exists() else 0

        self.log(f"Templates: {yaml_count} official + {extra_count} external + {custom_count} custom")
        self._templates_verified = yaml_count > 0
        return self._templates_verified

    async def _update_official_templates(self) -> None:
        """Update official nuclei-templates if missing or stale (>7 days)."""
        template_marker = self._template_dir / ".checksum"
        needs_update = False

        if not self._template_dir.exists() or not self._dir_has_yaml(self._template_dir):
            self.log("Nuclei templates not found — downloading...")
            needs_update = True
        elif template_marker.exists():
            age_days = (time.time() - template_marker.stat().st_mtime) / 86400
            if age_days > 7:
                self.log(f"Nuclei templates are {age_days:.0f} days old — updating...")
                needs_update = True

        if needs_update:
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.nuclei_path, "-update-templates", "-silent",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=120)
                self.log("Nuclei templates updated")
            except (asyncio.TimeoutError, Exception) as e:
                self.log(f"Template update failed: {e} — proceeding with existing")

    async def _update_external_repos(self) -> None:
        """Clone/update external template repositories in parallel.

        Each repo is shallow-cloned on first run, then git-pulled if >7 days
        stale.  All clone/update operations run concurrently so first-run
        cost is ~2 min total instead of ~2 min × N repos.
        """
        base_dir = Path.home() / ".beatrix" / "external-templates"
        base_dir.mkdir(parents=True, exist_ok=True)

        async def _process_repo(repo: dict) -> Optional[Path]:
            """Clone or update a single repo. Returns repo_dir on success."""
            repo_dir = base_dir / repo["dir"]
            # Prevent git from prompting for credentials (blocks the scan)
            git_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
            try:
                if repo_dir.exists() and (repo_dir / ".git").exists():
                    # Update if > 7 days old
                    age_marker = repo_dir / ".last_update"
                    needs_update = True
                    if age_marker.exists():
                        age_days = (time.time() - age_marker.stat().st_mtime) / 86400
                        needs_update = age_days > 7

                    if needs_update:
                        proc = await asyncio.create_subprocess_exec(
                            "git", "-C", str(repo_dir), "pull", "--quiet",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            env=git_env,
                        )
                        ret = await asyncio.wait_for(proc.communicate(), timeout=60)
                        age_marker.touch()
                        self.log(f"Updated {repo['name']}")
                    # else: already fresh, no action needed
                else:
                    # Clone
                    self.log(f"Cloning {repo['name']}...")
                    proc = await asyncio.create_subprocess_exec(
                        "git", "clone", "--depth=1", repo["url"], str(repo_dir),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=git_env,
                    )
                    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
                    if proc.returncode != 0:
                        err_text = stderr.decode("utf-8", errors="replace").strip() if stderr else "unknown error"
                        self.log(f"Clone failed for {repo['name']}: {err_text}")
                        return repo_dir if repo_dir.exists() else None
                    (repo_dir / ".last_update").touch()
                    self.log(f"Cloned {repo['name']}")

                return repo_dir if repo_dir.exists() else None
            except asyncio.TimeoutError:
                self.log(f"Timeout cloning/updating {repo['name']} — skipping")
                return repo_dir if repo_dir.exists() else None
            except Exception as e:
                self.log(f"External repo {repo['name']}: {e}")
                return repo_dir if repo_dir.exists() else None

        # Run all repo operations in parallel
        results = await asyncio.gather(
            *[_process_repo(repo) for repo in self.TEMPLATE_REPOS],
            return_exceptions=True,
        )

        seen = set()
        for result in results:
            if isinstance(result, Exception):
                self.log(f"Repo task failed: {result}")
                continue
            if result and result.exists() and str(result) not in seen:
                if self._dir_has_yaml(result):
                    seen.add(str(result))
                    self._extra_template_dirs.append(result)
                else:
                    self.log(f"Skipping {result.name} — no .yaml templates found")

        if self._extra_template_dirs:
            self.log(f"External template sources: {len(self._extra_template_dirs)} repos loaded")

    def _setup_custom_templates(self) -> None:
        """Ensure custom templates directory exists for user extensions."""
        self._custom_template_dir.mkdir(parents=True, exist_ok=True)
        readme = self._custom_template_dir / "README.md"
        if not readme.exists():
            readme.write_text(
                "# Custom Nuclei Templates\n\n"
                "Place your custom nuclei YAML templates here.\n"
                "They will be automatically loaded during scans.\n\n"
                "Template syntax: https://docs.projectdiscovery.io/templates/introduction\n"
            )

    async def diagnostics(self) -> Dict:
        """Run nuclei diagnostics — verify binary, templates, version, and features."""
        result = {
            "binary": self.nuclei_path,
            "available": self.available,
            "version": None,
            "template_dir": str(self._template_dir),
            "custom_template_dir": str(self._custom_template_dir),
            "extra_template_dirs": [str(d) for d in self._extra_template_dirs],
            "template_count": 0,
            "custom_template_count": 0,
            "workflows_available": [],
            "detected_technologies": self._detected_technologies,
            "auth_configured": bool(self._auth_headers),
            "interactsh_configured": bool(self._interactsh_server),
        }

        if not self.nuclei_path:
            result["error"] = "nuclei binary not found"
            return result

        # Get version
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nuclei_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            version_text = (stdout or stderr).decode("utf-8", errors="replace").strip()
            result["version"] = version_text.split("\n")[0] if version_text else "unknown"
        except Exception as e:
            result["version"] = f"error: {e}"

        # Count templates
        if self._template_dir.exists():
            result["template_count"] = sum(1 for _ in self._template_dir.glob("**/*.yaml"))
        if self._custom_template_dir.exists():
            result["custom_template_count"] = sum(1 for _ in self._custom_template_dir.glob("**/*.yaml"))

        result["workflows_available"] = self._find_workflows()

        await self._ensure_templates()
        return result

    # =====================================================================
    # CONFIGURATION SETTERS (called by kill chain)
    # =====================================================================

    def add_urls(self, urls: List[str]) -> None:
        """Add URLs to scan — called by kill chain to feed discovered URLs."""
        self._urls_to_scan.update(urls)

    def add_network_targets(self, targets: List[str]) -> None:
        """Add network targets (host:port) for protocol scanning."""
        self._network_targets.extend(targets)

    def set_technologies(self, technologies) -> None:
        """Set detected technologies for dynamic template selection.

        Accepts dict (name -> version) or list.  Preserves version info
        so future template selection can match on specific versions.
        """
        if isinstance(technologies, dict):
            self._detected_technologies = {t.lower(): v for t, v in technologies.items()}
        else:
            self._detected_technologies = {t.lower(): "" for t in technologies}

    def set_auth(self, auth_headers: List[str]) -> None:
        """Set authentication headers for authenticated scanning.

        Args:
            auth_headers: List of ["-H", "Header: Value", ...] flags
        """
        self._auth_headers = auth_headers

    def set_interactsh(self, server: Optional[str] = None, token: Optional[str] = None) -> None:
        """Configure interactsh for OOB detection unification."""
        self._interactsh_server = server
        self._interactsh_token = token

    def set_waf(self, waf_name: Optional[str]) -> None:
        """Set detected WAF/CDN — adjusts rate limits to avoid blocks.

        When a WAF is detected, rate limits are dropped aggressively
        because WAFs fingerprint scanner behavior (User-Agent, rate,
        request patterns) and return blanket 403s.
        """
        self._waf_detected = waf_name
        if waf_name:
            # Reduce rates to stay under WAF bot-detection thresholds
            self._rate_limit = min(self._rate_limit, 5)
            self.log(f"WAF detected ({waf_name}) — rate limit reduced to {self._rate_limit} rps")

    def set_origin_ip(self, ip: str, domain: str) -> None:
        """Set origin IP for CDN bypass.

        When an origin IP is known, nuclei targets the IP directly with a
        Host header pointing to the real domain.  This bypasses Cloudflare/
        Akamai/etc. and lets templates actually reach the origin server.
        """
        self._origin_ip = ip
        self._target_domain = domain
        self.log(f"Origin IP bypass: {ip} (Host: {domain})")

    # =====================================================================
    # TAG & TEMPLATE INTELLIGENCE
    # =====================================================================

    def _build_recon_tags(self) -> str:
        """Build tags for Phase 1 recon pass — fast tech/panel/WAF detection.

        Covers: technology fingerprinting, exposed panels, misconfigs,
        leaked files/env, SSL/TLS issues, DNS issues, CORS, proxy.
        These are all low-risk checks that gather intel for Phase 4.
        """
        tags = {
            # Tech fingerprinting
            "tech", "detect", "panel", "waf", "fingerprint", "favicon",
            # Misconfigurations & exposure
            "misconfig", "exposure", "config", "disclosure",
            "default-login", "unauth",
            # Leaked files & secrets
            "git", "env", "backup", "debug", "log",
            # API surface
            "swagger", "openapi",
            # SSL/TLS & transport
            "ssl", "tls",
            # DNS
            "dns", "zone-transfer",
            # Proxy issues
            "proxy",
            # CORS (recon-safe: just checks headers)
            "cors",
            # Cache (detect cache-related headers/behavior)
            "cache",
        }
        for tech in self._detected_technologies:
            tech_lower = tech.lower().strip()
            for key, tech_tags in self.TECH_TAG_MAP.items():
                if key in tech_lower:
                    tags.update(tech_tags)
        return ",".join(sorted(tags))

    def _build_exploit_tags(self) -> str:
        """Build tags for Phase 4 exploit pass — CVEs and active exploitation.

        Every real vulnerability class that nuclei templates use as tags.
        This is the exhaustive list — if a vuln class tag exists in the
        nuclei-templates repo, it should be here.
        """
        tags = {
            # ── CVEs & known vulns ──
            "cve", "cnvd", "edb",
            # ── Injection classes ──
            "sqli", "xss", "ssti", "cmdi", "xxe", "ssrf", "lfi",
            "rce", "traversal", "injection",
            "crlf",             # CRLF injection (header injection)
            "host-header",      # Host header injection / poisoning
            # ── Access control ──
            "idor", "unauth", "default-login", "auth", "bruteforce",
            "misconfig", "exposure",
            # ── Redirect & routing ──
            "redirect", "open-redirect",
            # ── CORS & origin ──
            "cors",
            # ── Cache & web cache ──
            "cache", "web-cache",
            # ── Deserialization ──
            "deserialization",
            # ── Race conditions ──
            "race-condition",
            # ── Prototype pollution ──
            "prototype-pollution",
            # ── Secrets & tokens ──
            "token", "secret", "api", "apikey", "keys", "creds",
            # ── Takeover ──
            "takeover",
            # ── File & upload ──
            "fileupload", "file",
            # ── Cloud ──
            "cloud", "aws", "azure", "gcp",
            # ── OAST / OOB ──
            "oast",
            # ── SSL/TLS ──
            "ssl", "tls",
            # ── DNS ──
            "dns",
            # ── Proxy ──
            "proxy",
            # ── Generic catch-all (hundreds of templates use this) ──
            "generic",
            # ── Config & info (catch anything missed by recon) ──
            "config", "disclosure",
            # ── Network protocols ──
            "network",
        }

        # Add technology-specific tags
        for tech in self._detected_technologies:
            tech_lower = tech.lower().strip()
            for key, tech_tags in self.TECH_TAG_MAP.items():
                if key in tech_lower:
                    tags.update(tech_tags)

        return ",".join(sorted(tags))

    # Tags that should ALWAYS be excluded — never useful for bug bounty.
    ALWAYS_EXCLUDE_TAGS = {
        "dos",          # Denial of service — breaks targets, not a bounty finding
        "fuzz",         # Blind fuzzing — redundant with our SmartFuzzer
        "intrusive",    # Destructive operations (DELETE, DROP, etc.)
    }

    # Param names that carry high injection/redirect/IDOR risk.
    # URLs with these params are kept preferentially when deduplicating.
    _HIGH_RISK_PARAMS: Set[str] = {
        # Redirect / SSRF
        "url", "redirect_url", "redirect", "r", "next", "return", "return_url",
        "dest", "destination", "target", "goto", "callback", "continue",
        # File / path traversal
        "file", "path", "filepath", "dir", "folder", "page", "template", "include",
        # Command / eval
        "cmd", "exec", "command", "run", "eval",
        # IDOR
        "id", "user_id", "uid", "account_id", "order_id", "item_id", "pid",
        # Auth / token
        "token", "key", "api_key", "secret", "access_token", "auth",
        # Reference
        "src", "source", "ref", "referrer", "origin",
        # Search / query (SQLi surface)
        "q", "query", "search", "keyword", "term",
    }

    # Extensions that attract specific CVE/tech templates.
    _INTERESTING_EXTENSIONS: Set[str] = {
        ".php", ".aspx", ".asp", ".jsp", ".jspx", ".cfm", ".cgi", ".pl",
        ".do", ".action", ".axd", ".ashx", ".asmx", ".svc",
    }

    def _build_exclude_tags(self) -> str:
        """Build exclude tags: always-dangerous + technologies NOT detected.

        Two layers:
        1. Always exclude: dos, fuzz, intrusive (dangerous or redundant)
        2. CMS exclusion: if WordPress detected, skip Joomla/Drupal/etc.
        """
        exclude = set(self.ALWAYS_EXCLUDE_TAGS)

        if self._detected_technologies:
            detected_lower = {t.lower().strip() for t in self._detected_technologies}

            # CMS exclusion — only exclude if we've detected a DIFFERENT CMS
            cms_techs = {"wordpress", "joomla", "drupal", "magento", "shopify", "ghost", "hugo", "woocommerce"}
            detected_cms = cms_techs & detected_lower

            if detected_cms:
                for cms in cms_techs - detected_cms:
                    if cms in self.TECH_TAG_MAP:
                        exclude.update(self.TECH_TAG_MAP[cms])

            exclude.discard("php")  # Too common to exclude

        return ",".join(sorted(exclude))

    def _find_workflows(self) -> List[str]:
        """Find applicable workflow files based on detected technologies."""
        workflows = []
        workflow_dir = self._template_dir / "workflows"

        if not workflow_dir.exists():
            return workflows

        for tech in self._detected_technologies:
            tech_lower = tech.lower().strip()
            for key, workflow_file in self.WORKFLOW_TECH_MAP.items():
                if key in tech_lower:
                    wf_path = workflow_dir / workflow_file
                    if wf_path.exists():
                        workflows.append(str(wf_path))
                    else:
                        matches = list(workflow_dir.glob(f"**/{workflow_file}"))
                        if matches:
                            workflows.append(str(matches[0]))

        return list(set(workflows))

    def _sample_urls(self, urls: List[str], mode: str = "exploit") -> List[str]:
        """Deduplicate and prioritize URLs before handing them to nuclei.

        Three layers applied in order:

        1. Path-signature dedup — numeric IDs, UUIDs, and long hashes in path
           segments are normalized to placeholders, then only one representative
           URL is kept per (host, normalized-path) pair.  This collapses e.g.
           100 × /help/article/{id} URLs down to a single representative.

        2. Param-name dedup — query strings are reduced to the frozenset of
           their param *names*.  Multiple URLs that hit the same endpoint with
           the same parameter names but different values are collapsed to one.

        3. Priority scoring — within each group the highest-priority URL wins:
           high-risk param names (SSRF/redirect/IDOR surfaces), interesting
           file extensions (.php/.aspx/…), and API/admin path prefixes are
           all boosted.  The seed URL (context root) always scores highest.

        mode="recon"    — path-sig dedup only; param values don't matter for
                          panel/tech detection templates.
        mode="exploit"  — full three-layer dedup; keeps one URL per unique
                          (host, path-pattern, param-name-set).
        mode="headless" — most aggressive; path-sig only, browser rendering
                          cost makes per-value variation wasteful.
        """
        from urllib.parse import urlparse, parse_qs
        import re

        if not urls:
            return []

        def _path_sig(path: str) -> str:
            p = re.sub(
                r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                '/{uuid}', path, flags=re.IGNORECASE,
            )
            p = re.sub(r'/[0-9a-f]{32,}', '/{hash}', p, flags=re.IGNORECASE)
            p = re.sub(r'/\d+', '/{id}', p)
            # Collapse content slugs (blog posts, press releases, news articles).
            # Signal: 4+ hyphen-separated words in a single path segment.
            # This catches e.g. /airbnb-2026-summer-release/ but leaves
            # /become-a-host (3 parts) and /about-us (2 parts) alone.
            p = re.sub(r'/[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+){3,}', '/{slug}', p)
            return p

        def _param_sig(query: str) -> frozenset:
            if not query:
                return frozenset()
            # Normalize HTML-entity-encoded amp; prefixes that crawlers emit
            names = parse_qs(query.replace("amp;", ""), keep_blank_values=True).keys()
            return frozenset(names)

        def _score(url: str, parsed, param_names: frozenset) -> int:
            """Lower score = higher priority (kept over lower-priority peers)."""
            score = 0
            path = parsed.path

            # Shallow paths first (root and depth-1 get big boost)
            depth = path.rstrip("/").count("/")
            score += depth * 8

            # High-risk params are prime injection surfaces
            if param_names & self._HIGH_RISK_PARAMS:
                score -= 100

            # Tech-specific extensions attract CVE templates
            suffix = path.rsplit(".", 1)[-1].lower() if "." in path.split("/")[-1] else ""
            if f".{suffix}" in self._INTERESTING_EXTENSIONS:
                score -= 60

            # API / admin / panel paths
            path_lower = path.lower()
            if any(seg in path_lower for seg in (
                "/api/", "/admin", "/dashboard", "/panel",
                "/_/", "/graphql", "/v1/", "/v2/", "/v3/",
                "/swagger", "/actuator", "/debug",
            )):
                score -= 80

            return score

        # Parse all URLs, compute signatures and scores
        candidates = []
        for url in urls:
            try:
                parsed = urlparse(url)
                if not parsed.netloc:
                    continue
                psig = _path_sig(parsed.path)
                qsig = _param_sig(parsed.query) if parsed.query else frozenset()
                pnames = frozenset(
                    parse_qs(parsed.query.replace("amp;", ""), keep_blank_values=True).keys()
                ) if parsed.query else frozenset()
                score = _score(url, parsed, pnames)
                candidates.append((score, url, parsed.netloc, psig, qsig))
            except Exception:
                continue

        # Sort by score so the best representative wins each group
        candidates.sort(key=lambda x: x[0])

        seen: Set[tuple] = set()
        result: List[str] = []

        for score, url, netloc, psig, qsig in candidates:
            if mode in ("recon", "headless"):
                # Path-sig only — ignore param variation
                key = (netloc, psig)
            else:
                # Full dedup: path + param-name set
                key = (netloc, psig, qsig)

            if key not in seen:
                seen.add(key)
                result.append(url)

        orig = len(urls)
        sampled = len(result)
        if sampled < orig:
            self.log(
                f"[sample] {orig} → {sampled} URLs after dedup "
                f"(saved {orig - sampled} redundant targets, mode={mode})"
            )

        return result

    def _calculate_timeout(self, url_count: int, mode: str = "exploit") -> Optional[int]:
        """Calculate wall-clock timeout based on URL count and mode.

        Returns None when nuclei_timeout is not configured, meaning nuclei
        runs until completion with no wall-clock kill.  Set nuclei_timeout
        in config to impose a limit (e.g. nuclei_timeout: 7200 for 2h cap).
        """
        if self._base_timeout is None:
            return None  # unlimited — let nuclei finish naturally

        if mode == "recon":
            t = max(180, 120 + url_count * 3)
        elif mode == "network":
            t = max(180, 180 + len(self._network_targets) * 5)
        elif mode == "headless":
            t = max(300, 120 + url_count * 15)
        else:
            extra = max(0, url_count - 50) * 2
            t = max(int(self._base_timeout), int(self._base_timeout + extra))

        return t

    # =====================================================================
    # SCAN MODES
    # =====================================================================

    async def scan_recon(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Phase 1: Fast recon scan — tech detection, panels, WAF, misconfigs.

        Runs with info/low severity only, limited tags, short timeout.
        Output feeds technology detection for later phases.
        """
        if not self.nuclei_path or not await self._ensure_templates():
            return

        if context.extra and context.extra.get("technologies"):
            self.set_technologies(context.extra["technologies"])

        urls = set()
        urls.add(context.url)
        urls.update(self._urls_to_scan)
        sampled = self._sample_urls(list(urls), mode="recon")

        tags = self._build_recon_tags()
        exclude_tags = self._build_exclude_tags()
        self.timeout_seconds = self._calculate_timeout(len(sampled), mode="recon")
        limit_str = f"{self.timeout_seconds}s" if self.timeout_seconds is not None else "unlimited"
        self.log(f"[RECON] Scanning {len(sampled)} URLs (timeout {limit_str})")

        cmd_extra = ["-severity", "info,low"]
        if exclude_tags:
            cmd_extra.extend(["-exclude-tags", exclude_tags])

        async for finding in self._run_nuclei_parallel(sampled, tags, cmd_extra=cmd_extra):
            yield finding

    async def scan_exploit(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Phase 4: Full exploitation scan — CVEs, injections, auth bypass.

        Runs all discovered URLs with full severity, technology-aware tags,
        exclude-tags for irrelevant tech, authenticated if available.
        """
        if not self.nuclei_path or not await self._ensure_templates():
            return

        if context.extra and context.extra.get("technologies"):
            self.set_technologies(context.extra["technologies"])

        urls = set()
        urls.add(context.url)
        urls.update(self._urls_to_scan)
        sampled = self._sample_urls(list(urls), mode="exploit")

        tags = self._build_exploit_tags()
        exclude_tags = self._build_exclude_tags()

        self.timeout_seconds = self._calculate_timeout(len(sampled), mode="exploit")
        limit_str = f"{self.timeout_seconds}s" if self.timeout_seconds is not None else "unlimited"
        self.log(f"[EXPLOIT] Scanning {len(sampled)} URLs (timeout {limit_str})")

        cmd_extra = ["-severity", self._severity_filter]
        if exclude_tags:
            cmd_extra.extend(["-exclude-tags", exclude_tags])
            self.log(f"Excluding tags: {exclude_tags}")

        # Main tag-based scan
        async for finding in self._run_nuclei_parallel(sampled, tags, cmd_extra=cmd_extra):
            yield finding

        # Workflow scan — technology-specific multi-step attack chains
        workflows = self._find_workflows()
        if workflows:
            self.log(f"Running {len(workflows)} workflows: {', '.join(Path(w).stem for w in workflows)}")
            for wf in workflows:
                async for finding in self._run_nuclei_parallel(
                    sampled, tags="", cmd_extra=["-w", wf, "-severity", self._severity_filter]
                ):
                    yield finding

    async def scan_network(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Phase 1: Network protocol scanning on discovered non-HTTP ports.

        Feeds host:port targets to nuclei's network templates for
        Redis unauthenticated, MongoDB no-auth, Elasticsearch exposure, etc.
        """
        if not self.nuclei_path or not await self._ensure_templates():
            return

        if not self._network_targets:
            return

        self.timeout_seconds = self._calculate_timeout(0, mode="network")
        self.log(f"[NETWORK] Scanning {len(self._network_targets)} service targets")

        network_template_dir = self._template_dir / "network"
        if not network_template_dir.exists():
            self.log("No network templates found — skipping network scan")
            return

        cmd_extra = ["-t", str(network_template_dir), "-severity", self._severity_filter]

        async for finding in self._run_nuclei_parallel(
            self._network_targets, tags="", cmd_extra=cmd_extra
        ):
            yield finding

    async def scan_headless(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Phase 4: Headless browser scan for DOM-based vulnerabilities.

        Uses nuclei's headless mode with chromium for DOM XSS,
        prototype pollution, JS redirects, CSP bypass.
        """
        if not self.nuclei_path or not await self._ensure_templates():
            return

        raw_urls = list({context.url} | self._urls_to_scan)
        urls = self._sample_urls(raw_urls, mode="headless")

        self.timeout_seconds = self._calculate_timeout(len(urls), mode="headless")
        self.log(f"[HEADLESS] Scanning {len(urls)} URLs with browser mode")

        # Check all template directories for headless templates
        headless_templates = list(self._template_dir.glob("**/headless/**/*.yaml"))
        if self._custom_template_dir.exists():
            headless_templates.extend(self._custom_template_dir.glob("**/headless/**/*.yaml"))
        for extra_dir in self._extra_template_dirs:
            if extra_dir.exists():
                headless_templates.extend(extra_dir.glob("**/headless/**/*.yaml"))
        if not headless_templates:
            self.log("No headless templates found — skipping")
            return

        cmd_extra = ["-headless", "-tags", "headless", "-severity", self._severity_filter]

        async for finding in self._run_nuclei_parallel(list(set(urls)), tags="", cmd_extra=cmd_extra):
            yield finding

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Default scan entry point — runs exploit pass (backward compatible).

        The kill chain calls scan_recon() and scan_exploit() separately,
        but if nuclei is invoked standalone via 'beatrix strike -m nuclei',
        this runs the full exploit pass.
        """
        if not self.nuclei_path:
            self.log(
                "nuclei not found — install: "
                "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
            return

        if not await self._ensure_templates():
            self.log("No nuclei templates available — skipping")
            return

        if context.extra and context.extra.get("technologies"):
            self.set_technologies(context.extra["technologies"])

        # Set auth from context if available
        if context.extra and context.extra.get("auth"):
            auth = context.extra["auth"]
            if hasattr(auth, "nuclei_header_flags"):
                self.set_auth(auth.nuclei_header_flags())

        urls = set()
        urls.add(context.url)
        urls.update(self._urls_to_scan)

        tags = self._build_exploit_tags()
        exclude_tags = self._build_exclude_tags()

        self.timeout_seconds = self._calculate_timeout(len(urls))
        limit_str = f"{self.timeout_seconds}s" if self.timeout_seconds is not None else "unlimited"
        self.log(f"Running nuclei on {len(urls)} URLs (timeout {limit_str})")

        cmd_extra = ["-severity", self._severity_filter]
        if exclude_tags:
            cmd_extra.extend(["-exclude-tags", exclude_tags])

        async for finding in self._run_nuclei_parallel(list(urls), tags, cmd_extra=cmd_extra):
            yield finding

    # =====================================================================
    # CORE EXECUTION
    # =====================================================================

    @staticmethod
    def _host_of(target: str) -> str:
        """Best-effort host key for a target (URL, ``host:port``, or bare host)."""
        from urllib.parse import urlparse

        if "://" in target:
            host = urlparse(target).hostname
        else:
            # ``host:port`` network target or bare host — strip any path/port.
            host = target.split("/", 1)[0].rsplit(":", 1)[0]
        return (host or "").lower() or "_unknown"

    def _group_targets_by_host(self, targets: List[str]) -> Dict[str, List[str]]:
        """Partition targets by host, preserving order within each group."""
        groups: Dict[str, List[str]] = {}
        for t in targets:
            groups.setdefault(self._host_of(t), []).append(t)
        return groups

    def _resolve_parallelism(self, num_hosts: int) -> int:
        """How many single-host nuclei processes to run at once.

        Bounded by the number of hosts, the configured/derived ceiling, and
        available CPUs (each process is heavy). ``nuclei_max_parallel_hosts``
        overrides the derived default.
        """
        configured = self.config.get("nuclei_max_parallel_hosts")
        if configured:
            try:
                ceiling = max(1, int(configured))
            except (TypeError, ValueError):
                ceiling = _DEFAULT_MAX_PARALLEL_HOSTS
        else:
            cpu = os.cpu_count() or 4
            ceiling = max(2, min(cpu // 2 or 1, _DEFAULT_MAX_PARALLEL_HOSTS))
        return max(1, min(num_hosts, ceiling))

    async def _run_nuclei_parallel(
        self,
        targets: List[str],
        tags: str = "",
        cmd_extra: Optional[List[str]] = None,
    ) -> AsyncIterator[Finding]:
        """Scan ``targets`` grouped by host, several hosts concurrently.

        Each host runs as its own single-host ``_run_nuclei`` invocation so its
        rate limit and 429/resume handling apply to that host alone (no host
        absorbs another's share of a shared global rate). A semaphore caps how
        many run at once and their per-process concurrency is scaled down so the
        aggregate in-flight request count stays bounded — fast without a 429
        storm or pinning the box.

        Falls back to a single direct ``_run_nuclei`` when there's ≤1 host, so
        single-target scans behave exactly as before.
        """
        groups = self._group_targets_by_host(targets)
        if len(groups) <= 1:
            async for finding in self._run_nuclei(targets, tags, cmd_extra=cmd_extra):
                yield finding
            return

        parallel = self._resolve_parallelism(len(groups))
        per_host_concurrency = max(
            _MIN_HOST_CONCURRENCY, _PARALLEL_CONCURRENCY_BUDGET // parallel
        )
        self.log(
            f"[nuclei] Parallel scan across {len(groups)} hosts "
            f"({parallel} at a time, {per_host_concurrency} concurrency/host, "
            f"{self._rate_limit} rps/host)"
        )

        sem = asyncio.Semaphore(parallel)
        queue: asyncio.Queue = asyncio.Queue()
        _DONE = object()

        async def _worker(host: str, host_targets: List[str]) -> None:
            async with sem:
                try:
                    async for finding in self._run_nuclei(
                        host_targets, tags, cmd_extra=cmd_extra,
                        concurrency=per_host_concurrency,
                    ):
                        await queue.put(finding)
                except asyncio.CancelledError:
                    raise
                except Exception as e:  # noqa: BLE001 - one host must not sink the scan
                    self.log(f"[nuclei] host {host} scan failed: {type(e).__name__}: {e}")
                finally:
                    await queue.put(_DONE)

        tasks = [
            asyncio.create_task(_worker(host, host_targets))
            for host, host_targets in groups.items()
        ]

        finished = 0
        try:
            while finished < len(tasks):
                item = await queue.get()
                if item is _DONE:
                    finished += 1
                else:
                    yield item
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_nuclei(
        self,
        targets: List[str],
        tags: str = "",
        cmd_extra: Optional[List[str]] = None,
        *,
        concurrency: Optional[int] = None,
    ) -> AsyncIterator[Finding]:
        """Execute nuclei and stream findings.

        Core method called by all scan modes. Handles:
        - URL file management
        - Command construction (tags, auth, interactsh, rate limits)
        - Custom + external template directories
        - Process management and timeout
        - Streaming JSONL parsing
        """
        import tempfile

        if not targets:
            return

        # NOTE: Do NOT apply a fallback tag set when tags is empty.
        # Callers that pass tags="" explicitly want NO tag filtering —
        # they limit scope via cmd_extra instead (-t dir, -w workflow,
        # -headless).  Adding tags here would silently skip templates
        # that lack matching tags (e.g. network templates tagged only
        # as "redis-check" or "ftp-anon").

        # Origin IP bypass: add origin-targeted URLs as ADDITIONAL targets
        # alongside the normal CDN-routed URLs. This scans both paths:
        #   1. Through CDN (original URLs) — catches CDN-specific issues
        #   2. Direct to origin (rewritten URLs) — bypasses WAF/CDN protections
        # The Host header is ONLY added when origin targets are included,
        # ensuring nuclei sends it for origin-IP URLs.
        # NOTE: We only add a handful of origin URLs (the root domain matches)
        # to avoid doubling the entire scan.  Subdomains are NOT rewritten.
        effective_targets = list(targets)
        origin_targets_added = False
        if self._origin_ip and self._target_domain:
            from urllib.parse import urlparse, urlunparse
            for t in targets:
                parsed = urlparse(t) if "://" in t else None
                if parsed and parsed.hostname == self._target_domain:
                    origin_url = urlunparse(parsed._replace(netloc=
                        parsed.netloc.replace(self._target_domain, self._origin_ip, 1)
                    ))
                    effective_targets.append(origin_url)
                    origin_targets_added = True
            if origin_targets_added:
                self.log(
                    f"[nuclei] Added {len(effective_targets) - len(targets)} "
                    f"origin-bypass URLs targeting {self._origin_ip}"
                )

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for target in effective_targets:
                f.write(target + '\n')
            target_file = f.name

        try:
            # Resolve the target host once so we can consult/report the
            # shared cross-scanner rate ceiling (see base.py
            # _HostRateRegistry). nuclei has no live rate-adjustment API —
            # its -rate-limit is fixed at spawn — so reacting to a 429
            # flood means interrupting it (SIGINT triggers its own resume
            # checkpoint) and relaunching with a lower rate via -resume.
            watch_host: Optional[str] = None
            try:
                from urllib.parse import urlparse as _nuclei_urlparse
                watch_host = _nuclei_urlparse(effective_targets[0]).hostname
            except Exception:
                pass

            current_rate = self._rate_limit
            if watch_host:
                shared_rate = get_host_rate_ceiling(watch_host, self._rate_limit)
                if shared_rate < current_rate:
                    current_rate = max(1, int(shared_rate))
                    self.log(
                        f"[nuclei] Adopting shared host rate ceiling "
                        f"{current_rate} rps (below configured {self._rate_limit}) "
                        f"— another scanner already saw 429s on {watch_host}"
                    )

            resume_file = target_file + ".resume"
            max_attempts = 3
            rate_drop_restarts = 0

            findings_count = 0
            wall_start = time.monotonic()
            stderr_lines: List[str] = []  # merged across all attempts
            process = None

            for attempt in range(1, max_attempts + 1):
                cmd = [
                    self.nuclei_path,
                    "-l", target_file,
                    "-jsonl",
                    "-silent",
                    "-no-color",
                    "-timeout", "30",
                    "-retries", "2",
                    "-rate-limit", str(current_rate),
                    "-bulk-size", "50",
                    "-concurrency", str(concurrency or _DEFAULT_HOST_CONCURRENCY),
                    "-stats",
                    "-stats-interval", "15",
                    "-resume", resume_file,
                ]

                # Tags (skip if using -w workflow or -t specific dir)
                if tags:
                    cmd.extend(["-tags", tags])

                # Realistic User-Agent — prevents WAF fingerprinting nuclei's
                # default UA ("Nuclei - Open-source project (projectdiscovery.io)")
                cmd.extend(["-H", f"User-Agent: {self._user_agent}"])

                # Origin IP bypass — we've added origin-targeted URLs alongside
                # normal ones. We do NOT set a global Host header because that
                # would override the Host for CDN-routed URLs too.  Origin URLs
                # (http://<ip>/path) will send Host: <ip> — many origin servers
                # accept this for default-vhost routing.  For strict vhosts, a
                # separate origin-only scan with explicit Host would be needed.
                if origin_targets_added:
                    # TLS SNI helps the origin serve the right cert when accessed
                    # via HTTPS.  safe to set globally — CDN URLs already match.
                    cmd.extend(["-sni", self._target_domain])
                    # Don't skip the host after cert/connection errors — origin IPs
                    # may have transient issues but are still worth scanning
                    cmd.extend(["-no-mhe"])

                # Authentication headers
                if self._auth_headers:
                    cmd.extend(self._auth_headers)

                # Interactsh configuration
                if self._interactsh_server:
                    cmd.extend(["-iserver", self._interactsh_server])
                    if self._interactsh_token:
                        cmd.extend(["-itoken", self._interactsh_token])

                # Custom template directories
                if self._custom_template_dir.exists() and self._dir_has_yaml(self._custom_template_dir):
                    cmd.extend(["-t", str(self._custom_template_dir)])

                # External template directories (already verified during _ensure_templates)
                for ext_dir in self._extra_template_dirs:
                    cmd.extend(["-t", str(ext_dir)])

                # Extra flags (severity, exclude-tags, -w, -headless, etc.)
                if cmd_extra:
                    cmd.extend(cmd_extra)

                if attempt == 1:
                    self.log(f"Executing: {' '.join(cmd[:5])}...")
                else:
                    self.log(
                        f"[nuclei] Resuming interrupted scan at {current_rate} rps "
                        f"(attempt {attempt}/{max_attempts})"
                    )

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,   # Capture stderr for progress/errors
                    limit=1024 * 1024,  # 1MB line buffer (nuclei can output long lines)
                )

                # Shared activity tracker: both stdout and stderr reset this
                # timestamp.  The idle timeout checks this instead of relying
                # solely on stdout — nuclei writes template-compilation progress
                # to stderr before producing any stdout, and we must not kill the
                # process during that phase.
                last_activity = time.monotonic()
                readline_timeout = 120

                # Background task to drain stderr and log progress
                attempt_stderr_lines: List[str] = []

                async def _drain_stderr():
                    """Read stderr in background so the pipe doesn't block."""
                    nonlocal last_activity
                    try:
                        while True:
                            raw = await process.stderr.readline()
                            if not raw:
                                break
                            last_activity = time.monotonic()  # stderr counts as activity
                            text = raw.decode("utf-8", errors="replace").strip()
                            if text:
                                attempt_stderr_lines.append(text)
                                # Immediately log fatal/critical errors
                                text_lower = text.lower()
                                if any(kw in text_lower for kw in
                                       ("[ftl]", "[fat]", "fatal", "panic")):
                                    self.log(f"[nuclei] FATAL: {text}")
                                # Log stats/progress lines so the user sees activity
                                elif any(kw in text_lower for kw in
                                       ("templates", "hosts", "requests", "errors",
                                        "matched", "duration", "rps")):
                                    self.log(f"[nuclei] {text}")
                    except Exception:
                        pass

                # Background task to watch for a shared-host rate drop while
                # this attempt is running. A drop means another scanner (or
                # a previous nuclei attempt) hit a 429 burst on this exact
                # host — no point grinding the rest of this attempt out at
                # a rate we already know is too hot.
                rate_dropped = False

                async def _watch_host_rate():
                    nonlocal rate_dropped
                    if not watch_host:
                        return
                    try:
                        while True:
                            await asyncio.sleep(15)
                            shared = get_host_rate_ceiling(watch_host, current_rate)
                            if shared < current_rate * 0.9:
                                rate_dropped = True
                                return
                    except asyncio.CancelledError:
                        pass

                stderr_task = asyncio.create_task(_drain_stderr())
                watch_task = asyncio.create_task(_watch_host_rate()) if watch_host else None

                interrupted_for_restart = False

                # Stream stdout line by line (JSONL findings)
                try:
                    while True:
                        # Overall wall-clock timeout (skipped when timeout_seconds is None)
                        elapsed = time.monotonic() - wall_start
                        if self.timeout_seconds is not None and elapsed >= self.timeout_seconds:
                            self.log(f"Nuclei wall-clock timeout after {int(elapsed)}s")
                            process.kill()
                            break

                        if rate_dropped and attempt < max_attempts:
                            self.log(
                                f"[nuclei] Shared rate ceiling for {watch_host} dropped "
                                f"below {current_rate} rps mid-scan — interrupting to "
                                f"resume at a lower rate instead of continuing to eat 429s"
                            )
                            interrupted_for_restart = True
                            try:
                                process.send_signal(signal.SIGINT)
                            except ProcessLookupError:
                                pass
                            break

                        poll_interval = 5 if watch_host else 10  # tighter poll so a rate drop is noticed promptly
                        if self.timeout_seconds is not None:
                            remaining = self.timeout_seconds - elapsed
                            poll_interval = min(poll_interval, remaining)
                        poll_interval = max(0.1, poll_interval)

                        try:
                            line = await asyncio.wait_for(
                                process.stdout.readline(),
                                timeout=poll_interval
                            )
                        except asyncio.TimeoutError:
                            # No stdout line within poll_interval — check if there
                            # has been ANY activity (stdout or stderr) recently.
                            idle_seconds = time.monotonic() - last_activity
                            actual_elapsed = time.monotonic() - wall_start

                            if (self.timeout_seconds is not None
                                    and actual_elapsed >= self.timeout_seconds - 1):
                                self.log(
                                    f"Nuclei timed out after {int(actual_elapsed)}s "
                                    f"(wall-clock limit {self.timeout_seconds}s)"
                                )
                                process.kill()
                                break
                            elif idle_seconds >= readline_timeout:
                                # No stdout AND no stderr for readline_timeout seconds
                                self.log(
                                    f"Nuclei no output (stdout+stderr) for {readline_timeout}s — "
                                    f"assuming complete ({int(actual_elapsed)}s elapsed)"
                                )
                                process.kill()
                                break
                            else:
                                # stderr is still active (template compilation, stats, etc.) — keep waiting
                                continue

                        if not line:
                            # EOF — nuclei exited normally
                            break

                        last_activity = time.monotonic()  # stdout line received
                        decoded = line.decode('utf-8', errors='replace').strip()
                        if not decoded:
                            continue

                        # Parse JSONL finding
                        try:
                            data = json.loads(decoded)
                            finding = self._parse_nuclei_finding(data)
                            if finding:
                                findings_count += 1
                                yield finding
                        except json.JSONDecodeError:
                            # Non-JSON line (shouldn't happen with -jsonl -silent)
                            continue
                finally:
                    stderr_task.cancel()
                    try:
                        await stderr_task
                    except (asyncio.CancelledError, Exception):
                        pass
                    if watch_task:
                        watch_task.cancel()
                        try:
                            await watch_task
                        except (asyncio.CancelledError, Exception):
                            pass
                    if process.returncode is None:
                        if interrupted_for_restart:
                            # Give nuclei a moment to flush its resume
                            # checkpoint after SIGINT before forcing it down.
                            try:
                                await asyncio.wait_for(process.wait(), timeout=10)
                            except asyncio.TimeoutError:
                                process.kill()
                                await process.wait()
                        else:
                            process.kill()
                            await process.wait()
                    else:
                        await process.wait()

                stderr_lines.extend(attempt_stderr_lines)

                if not interrupted_for_restart:
                    break

                rate_drop_restarts += 1
                new_rate = get_host_rate_ceiling(watch_host, current_rate)
                new_rate = max(1, min(current_rate, int(new_rate)))
                if new_rate >= current_rate:
                    # Registry didn't actually give us a lower number
                    # (race between the drop and our read) — no point
                    # burning another attempt.
                    break
                current_rate = new_rate

            total_elapsed = int(time.monotonic() - wall_start)

            # Check for fatal errors in stderr
            fatal_errors = [s for s in stderr_lines if any(
                kw in s.lower() for kw in ("[ftl]", "[fat]", "fatal", "panic")
            )]

            # Check process exit code
            if process.returncode and process.returncode != 0:
                if fatal_errors:
                    self.log(f"Nuclei FAILED (exit {process.returncode}) after {total_elapsed}s: {fatal_errors[0]}")
                else:
                    self.log(f"Nuclei FAILED (exit {process.returncode}) after {total_elapsed}s — {findings_count} findings before failure")
            elif fatal_errors:
                self.log(f"Nuclei completed with ERRORS after {total_elapsed}s: {fatal_errors[0]}")
            else:
                self.log(f"Nuclei complete: {findings_count} findings in {total_elapsed}s")

            # Log the last few stderr lines (usually the scan summary)
            if stderr_lines:
                # If 0 findings, log all stderr for diagnostics
                lines_to_log = stderr_lines if findings_count == 0 else stderr_lines[-5:]
                for sline in lines_to_log:
                    self.log(f"[nuclei stderr] {sline}")

            # N-10: Parse scan stats from stderr
            templates_loaded = 0
            targets_loaded = 0
            total_requests = 0
            total_errors = 0
            for sline in stderr_lines:
                # "Templates loaded for current scan: 6543"
                m = re.search(r'[Tt]emplates\s+loaded[^:]*:\s*(\d+)', sline)
                if m:
                    templates_loaded = int(m.group(1))
                # "Targets loaded for current scan: 15"
                m = re.search(r'[Tt]argets\s+loaded[^:]*:\s*(\d+)', sline)
                if m:
                    targets_loaded = int(m.group(1))
                # Stats lines: "Requests: 45000/1234560" or "Requests: 45000"
                m = re.search(r'[Rr]equests:\s*(\d+)', sline)
                if m:
                    total_requests = int(m.group(1))
                # "Errors: 12" in stats lines
                m = re.search(r'[Ee]rrors:\s*(\d+)', sline)
                if m:
                    total_errors = int(m.group(1))

            self.log(
                f"[nuclei] Scan stats: templates={templates_loaded} "
                f"targets={targets_loaded} requests={total_requests} "
                f"errors={total_errors} findings={findings_count}"
            )

            # Warn on suspicious stats
            if templates_loaded == 0 and not fatal_errors:
                self.log("[nuclei] WARNING: 0 templates loaded — templates may not be installed")
            if targets_loaded == 0 and not fatal_errors:
                self.log("[nuclei] WARNING: 0 targets loaded — target list may be empty")
            # nuclei's own "errors" stat only counts connection-level
            # failures — HTTP 429 is a successful round-trip as far as
            # nuclei is concerned, so a WAF-throttled scan can report a
            # clean error rate while most requests were actually rejected.
            # rate_drop_restarts is the real signal for that case: it only
            # increments when the shared per-host rate ceiling (fed by
            # every scanner's 429 backoff, see base.py _HostRateRegistry)
            # dropped out from under this scan.
            if rate_drop_restarts:
                self.log(
                    f"[nuclei] WARNING: scan was interrupted and resumed "
                    f"{rate_drop_restarts} time(s) after other traffic to "
                    f"{watch_host} dropped the shared rate ceiling below "
                    f"{self._rate_limit} rps (final rate: {current_rate} rps) "
                    f"— target is likely rate-limiting/WAF-throttling; "
                    f"findings may be incomplete"
                )
            if total_requests > 0 and total_errors > 0:
                error_pct = (total_errors / total_requests) * 100
                if error_pct > 50:
                    self.log(
                        f"[nuclei] WARNING: {error_pct:.0f}% of requests errored "
                        f"({total_errors}/{total_requests}) — connectivity or target issues likely"
                    )

            # Sanity check: flag impossibly fast completions
            url_count = len(effective_targets)
            effective_rate = current_rate or self._rate_limit or 10
            # Minimum plausible time: at least 1 request per URL at the rate limit
            min_plausible_seconds = max(1, url_count // max(1, effective_rate))
            if (findings_count == 0 and total_elapsed < min_plausible_seconds
                    and url_count > 10 and not fatal_errors):
                self.log(
                    f"[nuclei] WARNING: {url_count} URLs scanned in {total_elapsed}s "
                    f"with 0 findings — expected at least {min_plausible_seconds}s at "
                    f"{effective_rate} rps. Nuclei may not have scanned effectively."
                )

        except Exception as e:
            self.log(f"Nuclei error: {e}")
        finally:
            try:
                Path(target_file).unlink()
            except Exception:
                pass
            try:
                Path(target_file + ".resume").unlink()
            except Exception:
                pass

    def _parse_nuclei_finding(self, data: Dict) -> Optional[Finding]:
        """Convert a nuclei JSON result to a Beatrix Finding"""
        try:
            info = data.get("info", {})
            template_id = data.get("template-id", data.get("templateID", "unknown"))
            matched_at = data.get("matched-at", data.get("matched", ""))

            # If we scanned via origin IP, map findings back to the real domain
            if self._origin_ip and self._target_domain and self._origin_ip in matched_at:
                matched_at = matched_at.replace(self._origin_ip, self._target_domain, 1)

            # Severity mapping
            sev_str = info.get("severity", "info").lower()
            severity = NUCLEI_SEVERITY_MAP.get(sev_str, Severity.INFO)

            # Build title
            name = info.get("name", template_id)
            title = f"[Nuclei] {name}"

            # Build description
            desc_parts = []
            if info.get("description"):
                desc_parts.append(info["description"])

            tags = info.get("tags", [])
            if tags:
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(",")]
                desc_parts.append(f"Tags: {', '.join(tags)}")

            if info.get("reference"):
                refs = info["reference"]
                if isinstance(refs, list):
                    desc_parts.append("References:\n" + "\n".join(f"- {r}" for r in refs))

            description = "\n\n".join(desc_parts) if desc_parts else f"Nuclei template {template_id} matched"

            # Build evidence
            evidence_parts = [f"Template: {template_id}"]

            matcher_name = data.get("matcher-name", data.get("matcher_name", ""))
            if matcher_name:
                evidence_parts.append(f"Matcher: {matcher_name}")

            extracted = data.get("extracted-results", data.get("extracted_results", []))
            if extracted:
                evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")

            curl_cmd = data.get("curl-command", data.get("curl_command", ""))
            if curl_cmd:
                evidence_parts.append(f"Reproduce: {curl_cmd}")

            # Include interaction data if OOB was triggered
            interaction = data.get("interaction", {})
            if interaction:
                evidence_parts.append(
                    f"OOB Interaction: {interaction.get('protocol', 'unknown')} "
                    f"from {interaction.get('remote-address', 'unknown')}"
                )

            evidence = "\n".join(evidence_parts)

            # Confidence scoring — uses template metadata, not just severity.
            # Start with a base, then adjust based on evidence quality.
            confidence = Confidence.FIRM

            # Strong positive signals
            has_extracted = bool(extracted)
            has_interaction = bool(interaction)
            has_curl = bool(curl_cmd)
            has_cvss = bool(info.get("classification", {}).get("cvss-score"))

            # OOB interaction is the strongest signal — server actually called back
            if has_interaction:
                confidence = Confidence.CERTAIN
            # Extracted results with high severity — template grabbed real data
            elif has_extracted and sev_str in ("critical", "high"):
                confidence = Confidence.CERTAIN
            # CVE/CVSS classified + high severity — well-researched template
            elif has_cvss and sev_str in ("critical", "high"):
                confidence = Confidence.CERTAIN
            # Medium severity with evidence
            elif sev_str == "medium" and (has_extracted or has_curl):
                confidence = Confidence.FIRM
            # Info-only templates are informational, not vulnerabilities
            elif sev_str == "info":
                confidence = Confidence.TENTATIVE

            # Negative signals: fuzzing/detect tags suggest best-effort matching
            if isinstance(tags, list):
                tag_set = {t.lower() for t in tags}
                if tag_set & {"fuzz", "fuzzing", "detect", "misc"}:
                    # Downgrade by one level
                    if confidence == Confidence.CERTAIN:
                        confidence = Confidence.FIRM
                    elif confidence == Confidence.FIRM:
                        confidence = Confidence.TENTATIVE

            # References
            refs = info.get("reference", [])
            if isinstance(refs, str):
                refs = [refs]

            return Finding(
                title=title,
                severity=severity,
                confidence=confidence,
                url=matched_at,
                description=description,
                evidence=evidence,
                remediation=info.get("remediation", ""),
                references=refs if isinstance(refs, list) else [],
                scanner_module="nuclei",
            )

        except Exception as e:
            self.log(f"Failed to parse nuclei finding: {e}")
            return None
