"""
BEATRIX Core Engine

Main orchestration engine that coordinates:
- Kill chain execution
- Module dispatch
- Finding aggregation
- AI integration

This is the heart of BEATRIX.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .kill_chain import KillChainExecutor, KillChainState
from .types import Confidence, Finding, ScanResult, Severity

# Ordinal ranking for severity comparison — Severity.value is a string,
# so alphabetical comparison would be wrong ("critical" < "high" etc.).
_SEV_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class EngineConfig:
    """Engine configuration"""
    # Scanning
    threads: int = 50
    rate_limit: int = 10  # requests per second
    timeout: int = 10

    # AI
    ai_enabled: bool = False
    ai_provider: str = "bedrock"
    ai_model: str = "us.anthropic.claude-3-5-haiku-20241022-v1:0"

    # Output
    output_dir: Path = Path("./results")
    verbose: bool = False

    # Tools
    nuclei_path: str = "nuclei"
    httpx_path: str = "httpx"
    ffuf_path: str = "ffuf"

    @classmethod
    def from_yaml(cls, path: Path) -> "EngineConfig":
        """Load config from YAML file"""
        if not path.exists():
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        return cls(
            threads=data.get("scanning", {}).get("threads", 50),
            rate_limit=data.get("scanning", {}).get("rate_limit", 10),
            timeout=data.get("scanning", {}).get("timeout", 10),
            ai_enabled=data.get("ai", {}).get("enabled", False),
            ai_provider=data.get("ai", {}).get("provider", "bedrock"),
            ai_model=data.get("ai", {}).get("model", "us.anthropic.claude-3-5-haiku-20241022-v1:0"),
            output_dir=Path(data.get("output", {}).get("dir", "./results")),
            verbose=data.get("output", {}).get("verbose", False),
        )


class BeatrixEngine:
    """
    The main BEATRIX engine.

    Coordinates all scanning operations, manages the kill chain,
    and aggregates findings.

    Usage:
        engine = BeatrixEngine()
        await engine.hunt("example.com", preset="full")
    """

    def __init__(self, config: Optional[EngineConfig] = None, on_event: Optional[Any] = None,
                 output_manager=None):
        self.config = config or EngineConfig()
        self.modules: Dict[str, Any] = {}
        self._on_event = on_event
        self.output_manager = output_manager
        self.kill_chain = KillChainExecutor(self, on_event=on_event,
                                            output_manager=output_manager)

        # Validators — lazy imported to avoid circular deps
        self._impact_validator = None
        self._readiness_gate = None
        self.target_context = None

        # State
        self.current_target: Optional[str] = None
        self.findings: List[Finding] = []
        self.running: bool = False

        # Load modules
        self._load_modules()

    def _load_modules(self) -> None:
        """Discover and load available scanner modules"""
        from beatrix.scanners import (
            AuthScanner,
            BACScanner,
            BackslashPoweredScanner,
            BusinessLogicScanner,
            CachePoisoningScanner,
            # === Core scanners (original 12) ===
            CORSScanner,
            DeserializationScanner,
            EndpointProber,
            ErrorDisclosureScanner,
            FileUploadScanner,
            GitHubRecon,
            GraphQLScanner,
            HeaderSecurityScanner,
            HTTPSmugglingScanner,
            IDORScanner,
            InjectionScanner,
            JSBundleAnalyzer,
            MassAssignmentScanner,
            NucleiScanner,
            OAuthRedirectScanner,
            OpenRedirectScanner,
            ParamMiner,
            PaymentScanner,
            PrototypePollutionScanner,
            ReDoSScanner,
            SequencerScanner,
            SSRFScanner,
            # === Expanded attack surface (15 new BaseScanner modules) ===
            SSTIScanner,
            SubdomainTakeoverScanner,
            TargetCrawler,
            WebSocketScanner,
            XXEScanner,
        )

        scanner_config = {
            "rate_limit": self.config.rate_limit,
            "nuclei_rate_limit": self.config.rate_limit,  # nuclei inherits global rate
            "timeout": self.config.timeout,
        }

        self.modules = {
            # ── Phase 1: Reconnaissance ───────────────────────────────────────
            "crawl": TargetCrawler(max_depth=3, max_pages=50, timeout=self.config.timeout),
            "endpoint_prober": EndpointProber(scanner_config),
            "js_analysis": JSBundleAnalyzer(scanner_config),
            "headers": HeaderSecurityScanner(scanner_config),
            "github_recon": GitHubRecon(scanner_config),
            "param_miner": ParamMiner(scanner_config),

            # ── Phase 2: Weaponization ────────────────────────────────────────
            "takeover": SubdomainTakeoverScanner(scanner_config),
            "error_disclosure": ErrorDisclosureScanner(scanner_config),
            "cache_poisoning": CachePoisoningScanner(scanner_config),
            "prototype_pollution": PrototypePollutionScanner(scanner_config),
            "sequencer": SequencerScanner(scanner_config),

            # ── Phase 3: Delivery ─────────────────────────────────────────────
            "cors": CORSScanner(scanner_config),
            "redirect": OpenRedirectScanner(scanner_config),
            "oauth_redirect": OAuthRedirectScanner(scanner_config),
            "http_smuggling": HTTPSmugglingScanner(scanner_config),
            "websocket": WebSocketScanner(scanner_config),

            # ── Phase 4: Exploitation ─────────────────────────────────────────
            "backslash": BackslashPoweredScanner(scanner_config),
            "injection": InjectionScanner(scanner_config),
            "ssrf": SSRFScanner(scanner_config),
            "idor": IDORScanner(config=scanner_config),
            "bac": BACScanner(config=scanner_config),
            "auth": AuthScanner(config=scanner_config),
            "ssti": SSTIScanner(scanner_config),
            "xxe": XXEScanner(scanner_config),
            "deserialization": DeserializationScanner(scanner_config),
            "graphql": GraphQLScanner(scanner_config),
            "mass_assignment": MassAssignmentScanner(scanner_config),
            "business_logic": BusinessLogicScanner(scanner_config),
            "redos": ReDoSScanner(scanner_config),
            "payment": PaymentScanner(),  # Uses its own CheckoutConfig, not scanner_config
            "nuclei": NucleiScanner(scanner_config),

            # ── Phase 5: Installation ─────────────────────────────────────────
            "file_upload": FileUploadScanner(scanner_config),
        }

        # Optional: DOM XSS scanner (requires playwright)
        try:
            from beatrix.scanners.dom_xss import DOMXSSScanner
            self.modules["dom_xss"] = DOMXSSScanner(scanner_config)
        except (ImportError, Exception):
            pass  # playwright not installed

    def register_module(self, name: str, module: Any) -> None:
        """Register a scanner module"""
        self.modules[name] = module

    # =========================================================================
    # PRESETS - One command, full power
    # =========================================================================

    PRESETS = {
        "quick": {
            "name": "Quick Scan",
            "description": "Fast surface-level scan (~5 min)",
            "phases": [1, 3],  # Recon + Delivery
            "modules": ["crawl", "endpoint_prober", "js_analysis", "headers",
                        "cors", "redirect"],
        },
        "standard": {
            "name": "Standard Hunt",
            "description": "Balanced recon + vuln scan (~15 min)",
            "phases": [1, 2, 3, 4],
            "modules": ["crawl", "endpoint_prober", "js_analysis", "headers",
                        "github_recon", "takeover", "error_disclosure",
                        "cors", "redirect", "oauth_redirect",
                        "http_smuggling", "websocket",
                        "injection", "ssti", "ssrf", "idor", "bac", "auth",
                        "graphql", "deserialization", "business_logic", "nuclei",
                        "dom_xss"],
        },
        "full": {
            "name": "Full Assault",
            "description": "Complete kill chain — all 29 modules (~30 min)",
            "phases": [1, 2, 3, 4, 5, 6, 7],
            "modules": [],  # Empty = run ALL loaded modules
        },
        "stealth": {
            "name": "Stealth Mode",
            "description": "Low-noise passive recon (~10 min)",
            "phases": [1],
            "modules": ["crawl", "endpoint_prober", "js_analysis", "headers",
                        "github_recon"],
        },
        "injection": {
            "name": "Injection Focus",
            "description": "All injection tests (~20 min)",
            "phases": [1, 3, 4],  # Phase 1 required for crawling
            "modules": ["crawl", "injection", "ssti", "xxe", "deserialization",
                        "ssrf", "http_smuggling", "mass_assignment",
                        "prototype_pollution", "redos", "graphql", "nuclei",
                        "dom_xss"],
        },
        "api": {
            "name": "API Security",
            "description": "API-focused testing (~15 min)",
            "phases": [1, 3, 4],
            "modules": ["crawl", "endpoint_prober", "cors", "idor", "bac",
                        "auth", "graphql", "mass_assignment",
                        "business_logic", "websocket",
                        "injection", "ssrf", "ssti", "xxe", "nuclei"],
        },
        "web": {
            "name": "Web Application",
            "description": "Comprehensive web vuln scan (~25 min)",
            "phases": [1, 2, 3, 4, 5],
            "modules": ["crawl", "endpoint_prober", "js_analysis", "headers",
                        "github_recon",
                        "takeover", "error_disclosure", "cache_poisoning",
                        "prototype_pollution",
                        "cors", "redirect", "oauth_redirect", "http_smuggling",
                        "websocket",
                        "injection", "ssti", "xxe", "ssrf", "idor", "bac",
                        "auth", "graphql", "mass_assignment", "deserialization",
                        "business_logic", "redos", "payment", "nuclei",
                        "file_upload", "dom_xss"],
        },
        "recon": {
            "name": "Recon Only",
            "description": "Deep reconnaissance + enumeration (~10 min)",
            "phases": [1, 2],
            "modules": ["crawl", "endpoint_prober", "js_analysis", "headers",
                        "github_recon", "error_disclosure", "takeover",
                        "cache_poisoning", "prototype_pollution"],
        },
    }

    # =========================================================================
    # MAIN ENTRY POINTS
    # =========================================================================

    async def hunt(
        self,
        target: str,
        preset: str = "standard",
        ai: bool = False,
        modules: Optional[List[str]] = None,
        auth: Optional[Any] = None,
        browser_auth: bool = False,
    ) -> KillChainState:
        """
        Execute a hunt against a target.

        Args:
            target: Target domain
            preset: Scan preset (quick, standard, full, etc.)
            ai: Enable AI analysis
            modules: Override modules to run
            auth: AuthCredentials object for authenticated scanning
            browser_auth: Force authenticated scan requests through a real
                browser network stack instead of httpx, bypassing
                SessionValidator's calibration heuristic. Use when you
                already know (e.g. from manual testing) that the target
                fingerprints scripted HTTP clients — calibration only
                samples a fixed list of common auth-check paths, so it can
                miss path-specific fingerprint blocking that a broader
                scan would still hit.

        Returns:
            KillChainState with all findings
        """
        self.running = True
        self.current_target = target
        self.findings = []

        # Get preset config
        preset_config = self.PRESETS.get(preset, self.PRESETS["standard"])
        phases = preset_config["phases"]

        if modules is None:
            modules = preset_config["modules"]

        # Enable AI if requested
        self.config.ai_enabled = ai

        # Build context with auth credentials
        context = {"modules": modules}
        if auth is not None:
            context["auth"] = auth
        if browser_auth:
            context["needs_browser_transport"] = True
            context["force_browser_transport"] = True  # skip calibration override

        # Execute kill chain
        state = await self.kill_chain.execute(
            target=target,
            phases=phases,
            context=context,
        )

        # Collect all findings and deduplicate
        raw_findings = state.all_findings
        self.findings = self._consolidate_findings(raw_findings)

        # Deterministic enrichment — fills poc_curl, impact, cwe_id, repro steps
        if self.findings:
            from beatrix.core.finding_enricher import FindingEnricher
            enricher = FindingEnricher()
            enricher.enrich_batch(self.findings)

        # AI enrichment — classify, add OWASP/CWE, remediation suggestions
        if self.config.ai_enabled and self.findings:
            await self._ai_enrich_findings()

        # Write findings and summary to output directory
        if self.output_manager:
            try:
                self.output_manager.write_findings(self.findings)
                duration = None
                if state.phase_results:
                    from datetime import datetime
                    started = min(
                        (r.started_at for r in state.phase_results.values() if r.started_at),
                        default=None,
                    )
                    completed = max(
                        (r.completed_at for r in state.phase_results.values() if r.completed_at),
                        default=None,
                    )
                    if started and completed:
                        duration = (completed - started).total_seconds()
                self.output_manager.write_findings_summary(self.findings, duration)
                self.output_manager.finalize()
            except Exception:
                pass  # Output saving is best-effort

        self.running = False
        return state

    def _consolidate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings using the IssueConsolidator."""
        from beatrix.core.issue_consolidator import IssueConsolidator

        consolidator = IssueConsolidator()
        for finding in findings:
            consolidator.add(finding)
        return consolidator.unique_findings()

    async def _ai_enrich_findings(self) -> None:
        """
        Enrich findings with AI-powered analysis.

        Three-phase AI enrichment:
        1. Classification — OWASP category, CWE ID, remediation
        2. False-positive filtering — flag likely false positives
        3. Severity re-assessment — adjust severity based on context

        Uses Claude Haiku for fast, cheap bulk analysis.
        Failures are silent — AI enrichment is best-effort.
        """
        import json as _json

        try:
            from beatrix.ai.assistant import AIConfig, AIProvider, HaikuGrunt
        except ImportError:
            return  # httpx not installed or AI module broken

        # Build AI config from engine config
        provider_map = {
            "bedrock": AIProvider.BEDROCK,
            "anthropic": AIProvider.ANTHROPIC,
            "openai": AIProvider.OPENAI,
        }
        provider = provider_map.get(self.config.ai_provider, AIProvider.BEDROCK)

        ai_config = AIConfig(
            provider=provider,
            model=self.config.ai_model if provider == AIProvider.BEDROCK else "claude-3-5-haiku-20241022",
        )

        try:
            grunt = HaikuGrunt(ai_config)
        except Exception:
            return

        if self._on_event:
            self._on_event("info", {"message": f"🧠 AI analyzing {len(self.findings)} findings..."})

        # ── Phase 1: Classification (OWASP/CWE/Remediation) ──────────────
        findings_summary = []
        for i, f in enumerate(self.findings):
            findings_summary.append({
                "idx": i,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "url": f.url,
                "module": f.scanner_module,
                "description": (f.description or "")[:300],
                "evidence": str(f.evidence or "")[:200],
            })

        classify_prompt = (
            "You are an expert bug bounty vulnerability analyst.\n"
            "For each finding below, return a JSON array where each element has:\n"
            '  {"idx": <int>, "owasp": "<OWASP Top 10 2025 category, e.g. A01:2025 - Broken Access Control>",\n'
            '   "cwe": <int CWE ID>, "remediation": "<one-sentence fix>",\n'
            '   "false_positive": <true if likely FP, false if likely real>,\n'
            '   "fp_reason": "<why you think it is/isn\'t a false positive>",\n'
            '   "severity_adj": "<critical|high|medium|low|info or null if no change>",\n'
            '   "impact": "<one-sentence real-world impact>"}\n\n'
            "IMPORTANT false-positive guidelines:\n"
            "- Missing security headers (CSP, HSTS, X-Frame-Options) on CDN/API domains are NOT false positives\n"
            "- CORS with specific origins (not *) is usually safe — mark as FP\n"
            "- Self-referencing open redirects (redirect to same domain) are FP\n"
            "- Info-severity tech disclosure (server version, framework) on public sites are real but low impact\n"
            "- Confirmed injection with evidence (error messages, time delays) are NOT FP\n"
            "- IDOR without proof of data leakage is tentative, not FP\n\n"
            "Skip purely informational findings (severity=info) — return them with null values.\n"
            "Return ONLY the JSON array, no explanation.\n\n"
            f"Findings:\n{_json.dumps(findings_summary, indent=2)}"
        )

        enriched_count = 0
        fp_count = 0

        try:
            result = await grunt.complete(classify_prompt)

            # Parse JSON from response
            json_start = result.find("[")
            json_end = result.rfind("]") + 1
            if json_start >= 0 and json_end > json_start:
                enrichments = _json.loads(result[json_start:json_end])

                for entry in enrichments:
                    idx = entry.get("idx")
                    if idx is not None and 0 <= idx < len(self.findings):
                        finding = self.findings[idx]
                        owasp = entry.get("owasp")
                        cwe = entry.get("cwe")
                        rem = entry.get("remediation")
                        impact = entry.get("impact")
                        is_fp = entry.get("false_positive", False)
                        fp_reason = entry.get("fp_reason", "")
                        sev_adj = entry.get("severity_adj")

                        if owasp and not finding.owasp_category:
                            finding.owasp_category = owasp
                        if cwe and not finding.cwe_id:
                            finding.cwe_id = cwe
                        if rem and not finding.remediation:
                            finding.remediation = rem
                        if impact and not finding.impact:
                            finding.impact = impact

                        # Mark likely false positives by downgrading confidence
                        if is_fp and finding.confidence != Confidence.CERTAIN:
                            finding.confidence = Confidence.WEAK
                            if fp_reason:
                                finding.description = (
                                    f"{finding.description}\n\n"
                                    f"⚠️ AI Assessment: Likely false positive — {fp_reason}"
                                )
                            fp_count += 1

                        # Adjust severity if AI disagrees (only downgrade, never upgrade)
                        if sev_adj and sev_adj != "null":
                            sev_map = {
                                "critical": Severity.CRITICAL,
                                "high": Severity.HIGH,
                                "medium": Severity.MEDIUM,
                                "low": Severity.LOW,
                                "info": Severity.INFO,
                            }
                            new_sev = sev_map.get(sev_adj.lower())
                            if new_sev and _SEV_RANK[new_sev] < _SEV_RANK[finding.severity]:
                                # AI says it's less severe — trust the downgrade
                                finding.severity = new_sev

                        enriched_count += 1

                if self._on_event:
                    msg = f"🧠 AI enriched {enriched_count}/{len(self.findings)} findings"
                    if fp_count:
                        msg += f" ({fp_count} flagged as likely FP)"
                    self._on_event("info", {"message": msg})

        except Exception:
            if self._on_event:
                self._on_event("info", {"message": "🧠 AI enrichment skipped (no credentials or API error)"})
            pass  # AI enrichment is best-effort; never break the hunt

    async def strike(
        self,
        target: str,
        module: str,
        **kwargs,
    ) -> ScanResult:
        """
        Execute a single module against a target.

        Args:
            target: Target URL/domain
            module: Module name to run
            **kwargs: Module-specific arguments

        Returns:
            ScanResult from the module
        """
        from beatrix.scanners import ScanContext

        result = ScanResult(
            target=target,
            module=module,
            started_at=datetime.now(),
        )

        scanner = self.modules.get(module)
        if not scanner:
            result.errors.append(f"Module '{module}' not found or not implemented")
            result.completed_at = datetime.now()
            return result

        try:
            # Create scan context
            context = ScanContext.from_url(target if "://" in target else f"https://{target}")

            # For nuclei: detect WAF and set realistic UA even in strike mode
            if module == "nuclei" and hasattr(scanner, 'set_waf'):
                try:
                    import httpx
                    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
                        resp = await client.head(context.url, headers={
                            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                        })
                        server = (resp.headers.get("server", "") + resp.headers.get("cf-ray", "")).lower()
                        if "cloudflare" in server or resp.headers.get("cf-ray"):
                            scanner.set_waf("Cloudflare")
                        elif "akamai" in server:
                            scanner.set_waf("Akamai")
                        elif "fastly" in server:
                            scanner.set_waf("Fastly")
                except Exception:
                    pass

            # Run the module with async context
            async with scanner:
                findings = []
                async for finding in scanner.scan(context):
                    findings.append(finding)
                    self.findings.append(finding)
                result.findings = findings
        except Exception as e:
            result.errors.append(str(e))
            import traceback
            traceback.print_exc()

        result.completed_at = datetime.now()
        return result

    async def probe(self, target: str) -> Dict[str, Any]:
        """
        Quick probe of a target to check if it's alive and gather basic info.

        This is the "wiggle your big toe" moment.

        Args:
            target: Target URL or domain

        Returns:
            Dict with probe results
        """
        import httpx

        results = {
            "target": target,
            "alive": False,
            "status_code": None,
            "title": None,
            "server": None,
            "technologies": [],
            "headers": {},
        }

        # Normalize target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                response = await client.get(target)

                results["alive"] = True
                results["status_code"] = response.status_code
                results["headers"] = dict(response.headers)
                results["server"] = response.headers.get("server", "")

                # Extract title
                if "text/html" in response.headers.get("content-type", ""):
                    import re
                    title_match = re.search(
                        r"<title[^>]*>([^<]+)</title>",
                        response.text,
                        re.IGNORECASE
                    )
                    if title_match:
                        results["title"] = title_match.group(1).strip()

                # Basic tech detection from headers
                techs = []
                if "x-powered-by" in response.headers:
                    techs.append(response.headers["x-powered-by"])
                if "x-aspnet-version" in response.headers:
                    techs.append("ASP.NET")
                if "server" in response.headers:
                    server = response.headers["server"].lower()
                    if "nginx" in server:
                        techs.append("nginx")
                    elif "apache" in server:
                        techs.append("Apache")
                    elif "cloudflare" in server:
                        techs.append("Cloudflare")

                results["technologies"] = techs

        except httpx.ConnectError:
            results["error"] = "Connection failed"
        except httpx.TimeoutException:
            results["error"] = "Timeout"
        except Exception as e:
            results["error"] = str(e)

        return results

    # =========================================================================
    # FINDING MANAGEMENT
    # =========================================================================

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results"""
        self.findings.append(finding)

    def validate_finding(self, finding: Finding) -> Dict[str, Any]:
        """
        Run a finding through impact validation + readiness gate.
        Returns dict with verdicts and whether it's submittable.
        """
        from beatrix.validators import ImpactValidator, ReportReadinessGate

        if not self._impact_validator:
            self._impact_validator = ImpactValidator()
        if not self._readiness_gate:
            self._readiness_gate = ReportReadinessGate()

        impact = self._impact_validator.validate(finding, self.target_context)
        readiness = self._readiness_gate.check(finding)

        return {
            "finding": finding,
            "impact_verdict": impact,
            "readiness_verdict": readiness,
            "submittable": impact.passed and readiness.ready,
            "summary": (
                f"Impact: {impact}\n"
                f"Readiness: {readiness.summary()}"
            ),
        }

    def validate_all(self) -> Dict[str, list]:
        """
        Validate all current findings. Returns grouped results.
        """
        results = {"submittable": [], "needs_work": [], "killed": []}

        for finding in self.findings:
            result = self.validate_finding(finding)
            if result["submittable"]:
                results["submittable"].append(result)
            elif result["impact_verdict"].kill_checks:
                results["killed"].append(result)
            else:
                results["needs_work"].append(result)

        return results

    def get_findings(
        self,
        severity: Optional[Severity] = None,
        validated: Optional[bool] = None,
    ) -> List[Finding]:
        """Get findings with optional filters"""
        results = self.findings

        if severity:
            results = [f for f in results if f.severity == severity]

        if validated is not None:
            results = [f for f in results if f.validated == validated]

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get scan statistics"""
        stats = {
            "total_findings": len(self.findings),
            "by_severity": {},
            "by_module": {},
            "validated": 0,
            "reported": 0,
        }

        for s in Severity:
            stats["by_severity"][s.value] = len(
                [f for f in self.findings if f.severity == s]
            )

        for f in self.findings:
            module = f.scanner_module or "unknown"
            stats["by_module"][module] = stats["by_module"].get(module, 0) + 1

            if f.validated:
                stats["validated"] += 1
            if f.reported:
                stats["reported"] += 1

        return stats
