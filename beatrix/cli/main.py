"""
BEATRIX CLI — The Black Mamba

Human-centric command-line interface for the Beatrix bug bounty hunting framework.
Built for operators who prefer a terminal over a GUI.

"Those of you lucky enough to have your lives, take them with you.
 However, leave the limbs you've lost. They belong to me now."

Usage:
    beatrix hunt example.com                    # Standard hunt
    beatrix hunt example.com --preset full      # Full kill chain
    beatrix strike api.example.com -m cors      # Single module strike
    beatrix probe example.com                   # Quick alive check
    beatrix recon example.com --deep            # Deep reconnaissance
    beatrix list --modules                      # Show available weapons
    beatrix help hunt                           # Detailed command help
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Suppress "Event loop is closed" RuntimeError from orphaned subprocess
# transports during KeyboardInterrupt shutdown.  These are cosmetic —
# the OS cleans up child processes when the parent exits.
_orig_unraisablehook = sys.unraisablehook


def _suppress_loop_closed(unraisable):
    if (isinstance(unraisable.exc_value, RuntimeError)
            and "Event loop is closed" in str(unraisable.exc_value)):
        return
    _orig_unraisablehook(unraisable)


sys.unraisablehook = _suppress_loop_closed

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from beatrix import __version__
from beatrix.core import BeatrixEngine, Confidence, Severity

console = Console()


def _fix_sudo_ownership(*paths: Path) -> None:
    """When running under sudo, chown output files/dirs back to the real user.

    sudo sets SUDO_UID and SUDO_GID to the invoking user's ids.  Without this,
    all output files end up owned by root and the user can't overwrite them on
    the next non-sudo run.
    """
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if not sudo_uid:
        return
    uid, gid = int(sudo_uid), int(sudo_gid or sudo_uid)
    for p in paths:
        try:
            p = Path(p)
            if p.is_dir():
                for child in p.rglob("*"):
                    os.chown(child, uid, gid)
            os.chown(p, uid, gid)
        except OSError:
            pass


# =============================================================================
# BANNER & THEME
# =============================================================================

BANNER = r"""
[bright_yellow]
    ____             __       _
   / __ )___  ____ _/ /______(_)  __
  / __  / _ \/ __ `/ __/ ___/ / |/_/
 / /_/ /  __/ /_/ / /_/ /  / />  <
/_____/\___/\__,_/\__/_/  /_/_/|_|
[/bright_yellow]
[dim]v{version} — "Revenge is a dish best served with a working PoC"[/dim]
[dim]The Black Mamba — Bug Bounty Hunting Framework[/dim]
"""

DEATH_LIST_HEADER = r"""[bright_yellow]
╔══════════════════════════════════════════╗
║          ☠  THE DEATH LIST  ☠           ║
╚══════════════════════════════════════════╝
[/bright_yellow]"""

KILL_BILL_QUOTES = [
    '"Wiggle your big toe."',
    '"You and I have unfinished business."',
    '"Revenge is a dish best served cold."',
    '"Those of you lucky enough to have your lives, take them with you."',
    '"It\'s mercy, compassion, and forgiveness I lack. Not rationality."',
    '"Silly rabbit, Trix are for kids."',
    '"When fortune smiles on something as violent as revenge, it seems proof like no other, that not only does God exist — you\'re doing his will."',
]


def print_banner():
    """Print the BEATRIX banner"""
    console.print(BANNER.format(version=__version__))


# =============================================================================
# HELP TEXT
# =============================================================================

COMMAND_HELP = {
    "hunt": """
[bright_yellow]⚔️  HUNT — Full Vulnerability Scan[/bright_yellow]

[bold]The Main Event.[/bold] Runs Beatrix against a target using the kill chain methodology.
Runs every scanner module in sequence against your target.

[bold cyan]USAGE:[/bold cyan]
  beatrix hunt TARGET [OPTIONS]
  beatrix hunt -f TARGETS_FILE [OPTIONS]

[bold cyan]ARGUMENTS:[/bold cyan]
  TARGET    Domain, URL, or IP to hunt. Examples:
              example.com
              https://api.example.com/v1
              192.168.1.1

[bold cyan]OPTIONS:[/bold cyan]
  -f, --file PATH    Text file with URLs/domains to hunt (one per line).
                       Lines starting with # are ignored.
  -p, --preset TEXT    Scan intensity preset:
                         [green]quick[/green]      — Surface scan, ~5 min (recon only)
                         [yellow]standard[/yellow]  — Balanced scan, ~15 min (DEFAULT)
                         [red]full[/red]       — Complete kill chain, ~30 min
                         [dim]stealth[/dim]    — Low-noise passive recon, ~10 min
                         [bright_red]injection[/bright_red] — Injection-focused, ~20 min
                         [cyan]api[/cyan]        — API security testing, ~15 min

  --ai                Enable AI-powered analysis (Claude Haiku via Bedrock)
  -m, --modules TEXT   Run specific modules only (can repeat)
  -o, --output PATH    Save results to directory

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Quick surface scan[/dim]
  beatrix hunt example.com --preset quick

  [dim]# Full assault with AI[/dim]
  beatrix hunt example.com --preset full --ai

  [dim]# Just CORS and IDOR modules[/dim]
  beatrix hunt api.example.com -m cors -m idor

  [dim]# Hunt all targets from a file[/dim]
  beatrix hunt -f targets.txt

  [dim]# Hunt targets from a file with full preset and reports[/dim]
  beatrix hunt -f targets.txt --preset full -o ./reports

  [dim]# Save results[/dim]
  beatrix hunt example.com -o ./results

[bold cyan]TARGETS FILE FORMAT:[/bold cyan]
  # My bug bounty targets
  https://api.example.com
  https://app.example.com
  example.com
  # Lines starting with # are comments

[bold cyan]KILL CHAIN PHASES:[/bold cyan]
  0. 🛡️  CDN Bypass      — Detects Cloudflare/Akamai/Fastly, discovers origin IPs
  1. 🔍 Reconnaissance  — Subdomain enum, port scan, service detection
  2. ⚔️  Weaponization   — Payload crafting, WAF fingerprinting
  3. 📦 Delivery        — Endpoint discovery, parameter fuzzing
  4. 💥 Exploitation    — Injection, auth bypass, IDOR, CORS, SSRF
  5. 🔧 Installation    — Persistence testing
  6. 📡 Command & Ctrl  — Data exfiltration, OOB channels
  7. 🎯 Objectives      — Impact assessment, PoC generation

[bold cyan]CDN BYPASS API KEYS (optional, via environment variables):[/bold cyan]
  SECURITYTRAILS_API_KEY     SecurityTrails DNS history
  CENSYS_API_ID              Censys certificate search
  CENSYS_API_SECRET          Censys API secret
  SHODAN_API_KEY             Shodan host search

  [dim]Without API keys, Beatrix uses free techniques: DNS history (ViewDNS,
  DNSDumpster), crt.sh SSL certificates, MX record analysis, subdomain
  correlation (40+ bypass subdomains), misconfiguration checks, and WHOIS.[/dim]
""",
    "strike": """
[bright_yellow]⚔️  STRIKE — Single Module Attack[/bright_yellow]

[bold]Surgical precision.[/bold] Execute one specific scanner against a target.
Like choosing your Hattori Hanzo sword for a specific fight.

[bold cyan]USAGE:[/bold cyan]
  beatrix strike TARGET -m MODULE

[bold cyan]ARGUMENTS:[/bold cyan]
  TARGET    URL to strike

[bold cyan]OPTIONS:[/bold cyan]
  -m, --module TEXT   [bold](required)[/bold] Scanner module to execute

[bold cyan]AVAILABLE MODULES:[/bold cyan]
  [green]cors[/green]             — CORS misconfiguration (origin reflection, null, wildcard)
  [green]injection[/green]        — SQL injection, XSS, command injection
  [green]headers[/green]          — Security header analysis (CSP, HSTS, X-Frame, etc.)
  [green]redirect[/green]         — Open redirect detection
  [green]ssrf[/green]             — Server-side request forgery (44 payloads, cloud metadata)
  [green]takeover[/green]         — Subdomain takeover (30+ services checked)
  [green]idor[/green]             — Insecure Direct Object Reference
  [green]bac[/green]              — Broken Access Control
  [green]auth[/green]             — Authentication bypass, JWT attacks
  [green]error_disclosure[/green] — Error message / stack trace leaks
  [green]js_analysis[/green]      — JavaScript bundle analysis (API routes, secrets)
  [green]endpoint_prober[/green]  — Endpoint discovery & probing

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Test for CORS issues[/dim]
  beatrix strike https://api.example.com -m cors

  [dim]# Check for injection vulns[/dim]
  beatrix strike https://example.com/login -m injection

  [dim]# Analyze JS bundles[/dim]
  beatrix strike https://app.example.com -m js_analysis

  [dim]# Look for SSRF[/dim]
  beatrix strike https://example.com/fetch?url=test -m ssrf
""",
    "probe": """
[bright_yellow]🔍 PROBE — Quick Target Check[/bright_yellow]

[bold]"Wiggle your big toe."[/bold]

The first step. Check if your target is alive, what server it runs,
and what technologies are in play. Fast and quiet.

[bold cyan]USAGE:[/bold cyan]
  beatrix probe TARGET

[bold cyan]WHAT IT CHECKS:[/bold cyan]
  • HTTP status code
  • Server header
  • Technology fingerprinting (X-Powered-By, etc.)
  • Page title
  • WAF detection

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix probe example.com
  beatrix probe https://api.example.com
  beatrix probe 192.168.1.1
""",
    "recon": """
[bright_yellow]🔍 RECON — Reconnaissance[/bright_yellow]

[bold]Know thy enemy.[/bold] Full reconnaissance on a target domain.
Subdomain enumeration, technology detection, JS analysis, endpoint discovery.

[bold cyan]USAGE:[/bold cyan]
  beatrix recon DOMAIN [OPTIONS]

[bold cyan]OPTIONS:[/bold cyan]
  -d, --deep         Deep scan (probe subdomain liveness)
  -j, --json-output  Output as JSON
  -o, --output PATH  Save results to file

[bold cyan]WHAT IT DISCOVERS:[/bold cyan]
  • Subdomains (via crt.sh, HackerTarget, DNS brute-force)
  • Live hosts (with --deep)
  • JavaScript files & inline scripts
  • API endpoints extracted from JS
  • URL parameters
  • Technology stack
  • Interesting patterns (debug endpoints, admin panels, etc.)

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Quick recon[/dim]
  beatrix recon example.com

  [dim]# Deep scan with JSON output[/dim]
  beatrix recon example.com --deep -j -o recon.json
""",
    "batch": """
[bright_yellow]📋 BATCH — Mass Scanning[/bright_yellow]

[bold]Unleash the Crazy 88.[/bold] Scan multiple targets from a file with one command.

[bold cyan]USAGE:[/bold cyan]
  beatrix batch TARGETS_FILE -m MODULE [OPTIONS]

[bold cyan]ARGUMENTS:[/bold cyan]
  TARGETS_FILE   Text file with one target per line (# for comments)

[bold cyan]OPTIONS:[/bold cyan]
  -m, --module TEXT     [bold](required)[/bold] Module to run against all targets
  -o, --output PATH    Output directory (default: ./reports)
  -t, --threads INT    Concurrent scans (default: 5)

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Scan all targets for CORS issues[/dim]
  beatrix batch targets.txt -m cors

  [dim]# Mass injection testing with reports[/dim]
  beatrix batch targets.txt -m injection -o ./reports

[bold cyan]TARGETS FILE FORMAT:[/bold cyan]
  # My targets
  https://api.example.com
  https://app.example.com
  https://dev.example.com
""",
    "ghost": """
[bright_yellow]👻 GHOST — Autonomous AI Pentester[/bright_yellow]

[bold]GHOST = Generative Heuristic Offensive Security Tester[/bold]

An AI-powered autonomous agent that thinks like a pentester. Give it a
target and an objective — it will investigate, test, and chain findings
on its own using 10 built-in tools.

[bold cyan]USAGE:[/bold cyan]
  beatrix ghost TARGET [OPTIONS]

[bold cyan]OPTIONS:[/bold cyan]
  -o, --objective TEXT    Investigation goal (default: "Find all security vulnerabilities")
  -X, --method TEXT       HTTP method for base request (default: GET)
  -H, --header TEXT       Add request header (repeatable)
  -d, --data TEXT         Request body
  -t, --max-turns INT     Max investigation iterations (default: 30)
  --model TEXT             Claude model (default: claude-sonnet-4-20250514)
  --api-key TEXT           Anthropic API key ($ANTHROPIC_API_KEY)
  --bedrock               Use AWS Bedrock instead of Anthropic API

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Basic investigation[/dim]
  beatrix ghost https://api.example.com/users?id=1

  [dim]# SQLi focused with POST data[/dim]
  beatrix ghost https://api.example.com -X POST -d '{{"user":"admin"}}' -o "Test for SQLi"

  [dim]# With auth header[/dim]
  beatrix ghost https://example.com -H "Authorization: Bearer token" --max-turns 50

[bold cyan]GHOST'S TOOLS:[/bold cyan]
  • HTTP requests (GET, POST, PUT, DELETE)
  • Payload fuzzing & injection testing
  • Response analysis & diff comparison
  • Authentication testing
  • Error-based probing
  • Attack chain reasoning
""",
    "rapid": """
[bright_yellow]⚡ RAPID — Multi-Target Quick Sweep[/bright_yellow]

[bold]Speed blitz.[/bold] Takeover checks, debug endpoint discovery, CORS scanning
across multiple targets simultaneously.

[bold cyan]USAGE:[/bold cyan]
  beatrix rapid [OPTIONS]

[bold cyan]OPTIONS:[/bold cyan]
  -t, --targets PATH    File with target domains (one per line)
  -d, --domain TEXT     Individual target domain (repeatable)
  -q, --quiet           Suppress verbose output
  -o, --output PATH     Save findings JSON to file

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix rapid -d target1.com -d target2.com
  beatrix rapid -t targets.txt -o findings.json
""",
    "haiku-hunt": """
[bright_yellow]🤖 HAIKU-HUNT — AI-Assisted Vulnerability Hunting[/bright_yellow]

[bold]Let Lil Bro do the grunt work.[/bold] Uses Claude Haiku via AWS Bedrock
for cheap (~$0.004/burst), fast AI-assisted vulnerability detection.

[bold cyan]USAGE:[/bold cyan]
  beatrix haiku-hunt TARGET [OPTIONS]

[bold cyan]OPTIONS:[/bold cyan]
  --no-ai              Disable AI analysis (scanners only)
  -d, --deep           Deep scan mode
  --region TEXT         AWS region for Bedrock (default: us-east-1)
  -o, --output PATH    Save findings JSON to file

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix haiku-hunt example.com
  beatrix haiku-hunt example.com --deep -o results.json
""",
    "github-recon": """
[bright_yellow]🔍 GITHUB-RECON — GitHub Secret Scanner[/bright_yellow]

[bold]Dig through the trash.[/bold] Scan a GitHub org/user for leaked secrets:
API keys, passwords, tokens, database credentials, private keys.

[bold cyan]USAGE:[/bold cyan]
  beatrix github-recon ORG [OPTIONS]

[bold cyan]OPTIONS:[/bold cyan]
  --repo TEXT           Specific repo (org/repo format)
  --token TEXT          GitHub personal access token
  --quick               Quick scan (skip git history)
  -o, --output PATH    Save report to file

[bold cyan]WHAT IT SCANS:[/bold cyan]
  • Hardcoded API keys, passwords, tokens
  • Database credentials in config files
  • Secrets committed then sanitized (git history)
  • Private keys, cloud credentials

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix github-recon acme-corp
  beatrix github-recon acme-corp --quick
  beatrix github-recon acme-corp --repo acme-corp/api-server -o report.md
""",
    "validate": """
[bright_yellow]✅ VALIDATE — Finding Validation[/bright_yellow]

[bold]The Readiness Gate.[/bold] Run ImpactValidator + ReadinessGate on previously
discovered findings. Prevents you from submitting theoretical garbage.

[bold cyan]USAGE:[/bold cyan]
  beatrix validate FINDINGS_FILE

[bold cyan]ARGUMENTS:[/bold cyan]
  FINDINGS_FILE    JSON report file with findings

[bold cyan]WHAT IT CHECKS:[/bold cyan]
  • Real exploitable impact (not theoretical)
  • Reproducible PoC
  • Proper evidence
  • Report completeness
  • Would it survive hostile triage?

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix validate beatrix_report_20260206.json
""",
    "config": """
[bright_yellow]⚙️  CONFIG — Configuration Management[/bright_yellow]

Settings are stored in [bold]~/.beatrix/config.yaml[/bold].

[bold cyan]USAGE:[/bold cyan]
  beatrix config --show                   Show current config
  beatrix config --set KEY VALUE          Set a config value

[bold cyan]CONFIG KEYS:[/bold cyan]
  scanning.threads      Number of concurrent threads (default: 50)
  scanning.rate_limit   Requests per second (default: 10)
  scanning.timeout      HTTP timeout in seconds (default: 10)
  ai.enabled            Enable AI features (true/false)
  ai.provider           AI provider: "bedrock" or "anthropic"
  ai.model              Model name
  output.dir            Default output directory
  output.verbose        Verbose logging (true/false)

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix config --show
  beatrix config --set scanning.rate_limit 50
  beatrix config --set ai.enabled true
  beatrix config --set output.dir ./my_results
""",
    "mobile": """
[bright_yellow]📱 MOBILE — Mobile App Traffic Interception[/bright_yellow]

[bold]Intercept and analyze mobile app traffic.[/bold]

[bold cyan]SUBCOMMANDS:[/bold cyan]
  beatrix mobile intercept    Launch emulator with proxy, capture traffic
  beatrix mobile analyze      Analyze previously captured traffic

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix mobile intercept --avd my_emulator -p com.example.app
  beatrix mobile analyze capture.json --secrets known_secrets.json
""",
    "arsenal": """
[bright_yellow]⚔️  ARSENAL — The Weapons Cache[/bright_yellow]

[bold]Full reference for every scanner module in Beatrix.[/bold]
Run [green]beatrix arsenal[/green] to see the full table with payload counts and OWASP mapping.

Each module can be used with:
  [green]beatrix strike TARGET -m MODULE[/green]
  [green]beatrix hunt TARGET -m MODULE -m MODULE[/green]
""",
    "list": """
[bright_yellow]📋 LIST — Available Modules & Presets[/bright_yellow]

Show what weapons and configurations are available.

[bold cyan]USAGE:[/bold cyan]
  beatrix list --modules     Show loaded scanner modules
  beatrix list --presets     Show scan presets
  beatrix list               Show both

[bold cyan]SEE ALSO:[/bold cyan]
  beatrix arsenal            Detailed module reference with payload counts
""",
}


# =============================================================================
# MODULE REFERENCE
# =============================================================================

MODULE_REFERENCE = {
    # ── Phase 0: CDN Bypass ───────────────────────────────────────────────────
    "origin_ip": {
        "name": "Origin IP Discovery",
        "category": "CDN Bypass",
        "description": "Discovers real origin IPs behind Cloudflare/Akamai/Fastly/CloudFront to bypass WAF protections",
        "payloads": "DNS history, crt.sh SSL certs, MX records, subdomain correlation, misconfig checks, WHOIS. Optional: SecurityTrails, Censys, Shodan APIs",
    },
    # ── Phase 1: Reconnaissance ───────────────────────────────────────────────
    "crawl": {
        "name": "Target Crawler",
        "category": "Reconnaissance",
        "description": "Builds attack surface — discovers URLs, parameters, forms, JS files, technologies",
        "payloads": "Link extraction, form parsing, JS URL discovery, tech fingerprinting",
    },
    "endpoint_prober": {
        "name": "Endpoint Prober",
        "category": "Reconnaissance",
        "description": "Discovers and probes API endpoints, admin panels, debug routes",
        "payloads": "Common path wordlist, status code analysis, response fingerprinting",
    },
    "js_analysis": {
        "name": "JS Bundle Analyzer",
        "category": "Reconnaissance",
        "description": "Extracts API routes, secrets, internal hostnames from JavaScript bundles",
        "payloads": "Regex pattern matching, entropy analysis for secrets",
    },
    "headers": {
        "name": "Header Security Scanner",
        "category": "A02: Cryptographic Failures",
        "description": "Analyzes security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.",
        "payloads": "Passive analysis, no active payloads",
    },
    "github_recon": {
        "name": "GitHub Recon Scanner",
        "category": "Reconnaissance",
        "description": "Searches GitHub repos for leaked API keys, DB creds, private keys",
        "payloads": "30+ secret patterns, git history analysis, org-wide scanning",
    },
    # ── Phase 2: Weaponization ────────────────────────────────────────────────
    "takeover": {
        "name": "Subdomain Takeover Scanner",
        "category": "Subdomain Takeover",
        "description": "Checks for dangling CNAME records pointing to claimable services",
        "payloads": "30+ service fingerprints (AWS S3, Heroku, Azure, GitHub Pages, Netlify, etc.)",
    },
    "error_disclosure": {
        "name": "Error Disclosure Scanner",
        "category": "A05: Security Misconfiguration",
        "description": "Triggers error responses to find stack traces, SQL errors, debug info",
        "payloads": "Malformed requests, invalid types, boundary values, special characters",
    },
    "cache_poisoning": {
        "name": "Cache Poisoning Scanner",
        "category": "A05: Security Misconfiguration",
        "description": "Web cache poisoning: CDN fingerprint, unkeyed headers, param cloaking",
        "payloads": "Fat GET, unkeyed header injection, cache deception, parameter cloaking",
    },
    "prototype_pollution": {
        "name": "Prototype Pollution Scanner",
        "category": "A08: Integrity Failures",
        "description": "Server-side __proto__ injection, Express QS pollution, client-side URL tests",
        "payloads": "JSON __proto__, constructor.prototype, Express query string variants",
    },
    # ── Phase 3: Delivery ─────────────────────────────────────────────────────
    "cors": {
        "name": "CORS Scanner",
        "category": "A02: Cryptographic Failures",
        "description": "Tests for CORS misconfigurations: origin reflection, null origin, wildcard, credential leaks",
        "payloads": "17+ test origins including subdomain tricks, null, protocol downgrade",
    },
    "redirect": {
        "name": "Open Redirect Scanner",
        "category": "Redirect Issues",
        "description": "Detects open redirects in URL parameters, valuable in OAuth chains",
        "payloads": "30+ redirect payloads including double-encoding, protocol-relative",
    },
    "oauth_redirect": {
        "name": "OAuth Redirect Scanner",
        "category": "A07: Authentication Failures",
        "description": "Tests OAuth redirect_uri manipulation for token theft",
        "payloads": "Path traversal, subdomain bypass, fragment tricks, open redirect chains",
    },
    "http_smuggling": {
        "name": "HTTP Smuggling Scanner",
        "category": "Transport Security",
        "description": "CL.TE/TE.CL timing, H2 desync, CRLF injection, 20+ TE obfuscation variants",
        "payloads": "CL.TE, TE.CL, CL.0, H2 smuggling, TE header obfuscation",
    },
    "websocket": {
        "name": "WebSocket Scanner",
        "category": "Transport Security",
        "description": "WebSocket upgrade checks, CSWSH origin validation, auth bypass, plaintext WS",
        "payloads": "Origin manipulation, cookie/token relay, protocol downgrade",
    },
    # ── Phase 4: Exploitation ─────────────────────────────────────────────────
    "injection": {
        "name": "Injection Scanner",
        "category": "A03: Injection",
        "description": "SQL injection, XSS, command injection with WAF bypass payloads",
        "payloads": "50+ SQLi, 30+ XSS, 20+ CMDi payloads with encoding variants",
    },
    "ssti": {
        "name": "SSTI Scanner",
        "category": "A03: Injection",
        "description": "Server-Side Template Injection for 16+ engines (Jinja2, Twig, FreeMarker, etc.)",
        "payloads": "Detection → ID → exploit chain for each template engine",
    },
    "xxe": {
        "name": "XXE Scanner",
        "category": "A03: Injection",
        "description": "XML External Entity: classic, OOB, error-based, XInclude, SSRF via cloud metadata",
        "payloads": "Classic XXE, OOB DNS/HTTP, parameter entities, encoding bypass",
    },
    "deserialization": {
        "name": "Deserialization Scanner",
        "category": "A08: Integrity Failures",
        "description": "Insecure deserialization: Java, PHP, Python pickle, .NET, Ruby, Node, YAML",
        "payloads": "Format detection + gadget chain signatures for 7 languages",
    },
    "ssrf": {
        "name": "SSRF Scanner",
        "category": "A10: SSRF",
        "description": "Server-Side Request Forgery with cloud metadata extraction",
        "payloads": "44 payloads: 16 localhost bypass, 16 cloud metadata (AWS/GCP/Azure), 4 internal, 8 protocol",
    },
    "idor": {
        "name": "IDOR Scanner",
        "category": "A01: Broken Access Control",
        "description": "Insecure Direct Object Reference testing with ID manipulation",
        "payloads": "Sequential, negative, zero, large value, UUID, and path traversal IDs",
    },
    "bac": {
        "name": "Broken Access Control Scanner",
        "category": "A01: Broken Access Control",
        "description": "Tests for broken access controls across endpoints",
        "payloads": "Method override, force browsing, privilege escalation patterns",
    },
    "auth": {
        "name": "Authentication Scanner",
        "category": "A07: Authentication Failures",
        "description": "JWT attacks, 2FA bypass, rate limiting, session management",
        "payloads": "Algorithm none, weak secrets, missing expiration, brute force checks",
    },
    "graphql": {
        "name": "GraphQL Scanner",
        "category": "A02: Cryptographic Failures",
        "description": "GraphQL endpoint discovery, introspection bypass, schema parsing, depth attack, batch",
        "payloads": "Introspection, field suggestion, alias overloading, batch query attacks",
    },
    "mass_assignment": {
        "name": "Mass Assignment Scanner",
        "category": "A01: Broken Access Control",
        "description": "Tests for mass assignment: privilege, financial, account takeover fields",
        "payloads": "30+ payload fields via JSON body + query param injection",
    },
    "business_logic": {
        "name": "Business Logic Scanner",
        "category": "A04: Insecure Design",
        "description": "Numeric boundaries, INT overflow, method confusion, race conditions",
        "payloads": "INT32/64 overflow, parameter pollution, HTTP method tampering",
    },
    "redos": {
        "name": "ReDoS Scanner",
        "category": "Denial of Service",
        "description": "Timing-based Regular Expression DoS with escalating payloads",
        "payloads": "Evil regex patterns for email, URL, numeric handlers",
    },
    "payment": {
        "name": "Payment Scanner",
        "category": "A04: Insecure Design",
        "description": "Checkout flow: price manipulation, coupon abuse, race conditions, IDOR, stage skip",
        "payloads": "Negative price, zero-cent, coupon replay, race condition, stage skipping",
    },
    "nuclei": {
        "name": "Nuclei Scanner",
        "category": "A06: Vulnerable Components",
        "description": "8000+ community templates: CVEs, misconfigs, default logins, exposed panels",
        "payloads": "Dynamic template selection based on target fingerprint",
    },
    # ── Phase 5: Installation ─────────────────────────────────────────────────
    "file_upload": {
        "name": "File Upload Scanner",
        "category": "A04: Insecure Design",
        "description": "Extension bypass (double, null byte), polyglots (GIF/PNG), SVG XSS, path traversal",
        "payloads": "Double extension, null byte, alt extensions, magic bytes, SVG XSS, zip traversal",
    },
}


# =============================================================================
# MAIN CLI GROUP
# =============================================================================

@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="beatrix")
@click.option("--quiet", "-q", is_flag=True, help="Suppress banner")
@click.pass_context
def cli(ctx, quiet):
    """
    \b
    ⚔️  BEATRIX — The Black Mamba
    Bug Bounty Hunting Framework

    \b
    QUICK START:
      beatrix hunt example.com              Scan a target
      beatrix strike example.com -m cors    Run one scanner
      beatrix probe example.com             Check if alive
      beatrix list --modules                See available weapons

    \b
    HELP:
      beatrix help <command>                Detailed command help
      beatrix manual                        Open the full HTML manual
      beatrix arsenal                       Full module reference
      beatrix setup                         Install all external tools
      beatrix --version                     Show version

    \b
    "Revenge is a dish best served with a working PoC."
    """
    ctx.ensure_object(dict)
    ctx.obj["quiet"] = quiet

    # Load GUI-saved AI keys from ~/.beatrix/.env (real env vars still win).
    try:
        from beatrix.cli.auth_gui import load_beatrix_env
        load_beatrix_env()
    except Exception:
        pass

    if not quiet and ctx.invoked_subcommand is None:
        print_banner()
        _show_quick_reference()
    elif not quiet and ctx.invoked_subcommand not in ("help", "arsenal"):
        print_banner()


def _show_quick_reference():
    """Show quick reference when beatrix is called with no command"""
    console.print()

    table = Table(
        title="[bright_yellow]The Death List — Command Reference[/bright_yellow]",
        show_header=True,
        header_style="bold cyan",
        border_style="bright_yellow",
        pad_edge=True,
    )
    table.add_column("Command", style="bold green", min_width=25)
    table.add_column("Description", style="white")
    table.add_column("Example", style="dim")

    table.add_row("hunt TARGET", "Full vulnerability scan", "beatrix hunt example.com")
    table.add_row("hunt -f FILE", "Hunt targets from file", "beatrix hunt -f targets.txt")
    table.add_row("strike TARGET -m MOD", "Single module attack", "beatrix strike api.com -m cors")
    table.add_row("probe TARGET", "Quick alive check", "beatrix probe example.com")
    table.add_row("recon DOMAIN", "Reconnaissance", "beatrix recon example.com --deep")
    table.add_row("batch FILE -m MOD", "Mass scanning", "beatrix batch targets.txt -m cors")
    table.add_row("rapid", "Multi-target quick sweep", "beatrix rapid -d target.com")
    table.add_row("haiku-hunt TARGET", "AI-assisted hunting", "beatrix haiku-hunt example.com")
    table.add_row("ghost TARGET", "AI autonomous pentester", "beatrix ghost https://api.com")
    table.add_row("github-recon ORG", "GitHub secret scanner", "beatrix github-recon acme-corp")
    table.add_row("validate FILE", "Validate findings", "beatrix validate report.json")
    table.add_row("mobile [sub]", "Mobile traffic intercept", "beatrix mobile intercept")
    table.add_row("config", "Configuration", "beatrix config --show")
    table.add_row("list", "List modules/presets", "beatrix list --modules")
    table.add_row("arsenal", "Full module reference", "beatrix arsenal")
    table.add_row("help CMD", "Detailed command help", "beatrix help hunt")
    table.add_row("manual", "Open HTML manual in browser", "beatrix manual")
    table.add_row("setup", "Install all external tools", "beatrix setup")

    console.print(table)
    console.print()
    console.print('[dim]Run [bold]beatrix help <command>[/bold] for detailed usage on any command.[/dim]')
    console.print()


# =============================================================================
# HELP COMMAND — Detailed per-command help
# =============================================================================

@cli.command("help")
@click.argument("command", required=False)
@click.pass_context
def help_cmd(ctx, command):
    """
    Show detailed help for a command.

    \b
    Examples:
        beatrix help hunt
        beatrix help strike
        beatrix help ghost
    """
    if command is None:
        # Show top-level help
        print_banner()
        _show_quick_reference()
        return

    command = command.lower().strip()

    if command in COMMAND_HELP:
        console.print(Panel(
            COMMAND_HELP[command],
            title=f"[bold bright_yellow]beatrix {command}[/bold bright_yellow]",
            border_style="bright_yellow",
            padding=(1, 2),
        ))
    else:
        console.print(f"[yellow]Unknown command: '{command}'[/yellow]")
        console.print(f"[dim]Available commands: {', '.join(sorted(COMMAND_HELP.keys()))}[/dim]")


# =============================================================================
# ARSENAL — Full module reference
# =============================================================================

@cli.command("arsenal")
@click.pass_context
def arsenal(ctx):
    """
    Display the full BEATRIX arsenal — all scanner modules with details.

    \b
    "Every weapon has a purpose."
    """
    console.print()
    console.print(Panel(
        "[bold bright_yellow]⚔️  THE ARSENAL — Available Weapons[/bold bright_yellow]\n\n"
        "[dim]Each module is a battle-tested scanner that can be used with:[/dim]\n"
        "  [green]beatrix strike TARGET -m MODULE[/green]\n"
        "  [green]beatrix hunt TARGET -m MODULE -m MODULE[/green]",
        border_style="bright_yellow",
    ))
    console.print()

    table = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="bright_yellow",
        pad_edge=True,
    )
    table.add_column("Module", style="bold green", min_width=18)
    table.add_column("OWASP Category", style="yellow", min_width=22)
    table.add_column("Description", style="white")
    table.add_column("Payloads", style="dim", min_width=20)

    for mod_name, mod_info in MODULE_REFERENCE.items():
        table.add_row(
            mod_name,
            mod_info["category"],
            mod_info["description"],
            mod_info["payloads"],
        )

    console.print(table)

    # Show external tool integrations
    console.print()
    console.print("[bold bright_yellow]🔧 External Tool Integrations[/bold bright_yellow]")
    ext_table = Table(show_header=True, header_style="bold cyan", border_style="dim", pad_edge=True)
    ext_table.add_column("Tool", style="bold green", min_width=15)
    ext_table.add_column("Status", style="white", min_width=12)
    ext_table.add_column("Purpose", style="dim")

    import shutil
    tools = [
        ("nuclei", "CVE scanning, misconfigs, default logins, 8000+ templates"),
        ("subfinder", "Passive subdomain enumeration from multiple sources"),
        ("httpx", "Rapid live-host probing and fingerprinting"),
        ("ffuf", "Directory fuzzing, parameter discovery, content brute-forcing"),
        ("katana", "Deep crawling and JavaScript analysis"),
        ("sqlmap", "Advanced database takeover and SQL injection exploitation"),
        ("nmap", "Port scanning, service detection, vulnerability scripts"),
        ("adb", "Android Debug Bridge for mobile app interception"),
        ("mitmproxy", "SSL/TLS traffic interception for mobile testing"),
        ("playwright", "Browser automation for DOM XSS and WAF evasion"),
        ("amass", "Advanced subdomain enumeration and attack surface mapping"),
        ("whatweb", "Technology fingerprinting and version detection"),
        ("webanalyze", "Technology fingerprinting and version detection (Wappalyzer engine)"),
        ("gospider", "Fast web spidering and URL discovery"),
        ("hakrawler", "Web crawler for discovering endpoints and assets"),
        ("gau", "Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl"),
        ("dirsearch", "Web path scanner and directory brute-forcing"),
        ("dalfox", "Parameter analysis and XSS scanning"),
        ("commix", "Automated command injection exploitation"),
        ("jwt_tool", "JSON Web Token manipulation and vulnerability testing"),
        ("msfconsole", "Metasploit Framework for advanced exploitation and post-exploitation"),
    ]
    venv_bin = Path(sys.executable).parent
    for tool_name, purpose in tools:
        found = shutil.which(tool_name) or (venv_bin / tool_name).is_file()
        status = "[green]✓ installed[/green]" if found else "[dim]○ not found[/dim]"
        ext_table.add_row(tool_name, status, purpose)

    console.print(ext_table)

    # Show standalone CLI-only modules
    console.print()
    console.print("[dim]Standalone modules (CLI-only, not in kill chain):[/dim]")
    standalone = [
        ("mobile_interceptor", "Android traffic capture via mitmproxy"),
        ("browser_scanner", "Playwright-based DOM XSS, clickjacking (needs playwright)"),
        ("credential_validator", "Validates leaked creds: AWS keys, GitHub tokens, Stripe, etc."),
        ("origin_ip_discovery", "WAF bypass via origin IP discovery"),
        ("power_injector", "Advanced SQLi/XSS/CMDi with 2000+ payloads"),
        ("polyglot_generator", "XSS polyglot & mXSS payload generator"),
    ]
    standalone_table = Table(show_header=False, border_style="dim", pad_edge=True)
    standalone_table.add_column("Module", style="dim green", min_width=22)
    standalone_table.add_column("Description", style="dim")
    for name, desc in standalone:
        standalone_table.add_row(name, desc)
    console.print(standalone_table)
    console.print()


# =============================================================================
# MANUAL — Open the comprehensive HTML manual in the user's browser
# =============================================================================

def _find_manual() -> Path | None:
    """Locate the manual HTML across all installation methods."""
    candidates = []

    # 1. Shipped inside the package wheel (pipx / pip install)
    pkg_dir = Path(__file__).resolve().parent.parent  # beatrix/
    candidates.append(pkg_dir / "_manual" / "index.html")

    # 2. Relative to source tree (editable / git clone)
    src_root = pkg_dir.parent  # repo root
    candidates.append(src_root / "docs" / "manual" / "index.html")

    # 3. Try git rev-parse if we're anywhere inside the repo
    try:
        import subprocess
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            repo = Path(result.stdout.strip())
            candidates.append(repo / "docs" / "manual" / "index.html")
    except Exception:
        pass

    for path in candidates:
        if path.exists():
            return path
    return None


@cli.command("manual")
@click.pass_context
def manual_cmd(ctx):
    """
    Open the BEATRIX manual in your default browser.

    \b
    Launches the comprehensive HTML reference manual covering
    all commands, modules, presets, and workflows.

    \b
    Examples:
        beatrix manual
    """
    import webbrowser

    manual_path = _find_manual()

    if manual_path is None:
        console.print("[red]✗ Manual not found.[/red]")
        console.print("[dim]Try reinstalling Beatrix: pipx install --force .[/dim]")
        raise SystemExit(1)

    url = manual_path.as_uri()
    console.print(f"[bright_yellow]📖 Opening manual in your browser...[/bright_yellow]")
    console.print(f"[dim]{url}[/dim]")
    webbrowser.open(url)


# =============================================================================
# SETUP — Install all external dependencies automatically
# =============================================================================

def _find_install_sh() -> Path | None:
    """Locate install.sh across all installation methods."""
    candidates = []

    pkg_dir = Path(__file__).resolve().parent.parent  # beatrix/
    src_root = pkg_dir.parent  # repo root

    # Editable / git clone
    candidates.append(src_root / "install.sh")

    # Try git rev-parse
    try:
        import subprocess
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            repo = Path(result.stdout.strip())
            candidates.append(repo / "install.sh")
    except Exception:
        pass

    for path in candidates:
        if path.exists():
            return path
    return None


@cli.command("setup")
@click.option("--check", is_flag=True, help="Only check tool status, don't install")
@click.pass_context
def setup_cmd(ctx, check):
    """
    Install all external security tools (the full arsenal).

    \b
    Automatically installs all 21 external dependencies:
    nuclei, httpx, subfinder, ffuf, katana, sqlmap, nmap,
    adb, mitmproxy, playwright, amass, whatweb, webanalyze,
    gospider, hakrawler, gau, dirsearch, dalfox, commix,
    jwt_tool, and metasploit.

    \b
    Uses the best method for each tool:
      • System packages (apt/dnf/pacman) for nmap, sqlmap, etc.
      • Go install for nuclei, subfinder, httpx, ffuf, etc.
      • pip for mitmproxy, playwright, dirsearch, commix
      • Go install for webanalyze
      • Official installer for metasploit

    \b
    Examples:
        beatrix setup           Install all missing tools
        beatrix setup --check   Just show what's installed
    """
    import shutil
    import subprocess

    tools = [
        "nuclei", "httpx", "subfinder", "ffuf", "katana", "sqlmap",
        "nmap", "adb", "mitmproxy", "playwright", "amass", "whatweb",
        "webanalyze", "gospider", "hakrawler", "gau", "dirsearch",
        "dalfox", "commix", "jwt_tool", "msfconsole",
    ]

    if check:
        # Check-only mode
        from rich.table import Table
        table = Table(title="External Tools Status", border_style="bright_yellow")
        table.add_column("Tool", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("Path", style="dim")

        found = 0
        for tool in tools:
            path = shutil.which(tool)
            if path:
                table.add_row(tool, "[green]✓ installed[/green]", path)
                found += 1
            else:
                table.add_row(tool, "[red]✗ missing[/red]", "")

        console.print(table)
        console.print(f"\n[bold]{found}/{len(tools)}[/bold] tools available.")
        if found < len(tools):
            console.print("[dim]Run [bold]beatrix setup[/bold] (without --check) to install missing tools.[/dim]")
        return

    # Install mode — delegate to install.sh
    install_sh = _find_install_sh()

    if install_sh is None:
        # Fallback: download install.sh from GitHub
        console.print("[bright_yellow]Downloading installer from GitHub...[/bright_yellow]")
        try:
            result = subprocess.run(
                ["curl", "-sSL", "https://raw.githubusercontent.com/SudoPacman-Syuu/Beatrix/main/install.sh"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and "install_external_tools" in result.stdout:
                import tempfile
                with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                    f.write(result.stdout)
                    install_sh = Path(f.name)
                install_sh.chmod(0o755)
            else:
                console.print("[red]✗ Could not download installer.[/red]")
                raise SystemExit(1)
        except Exception as e:
            console.print(f"[red]✗ Failed to fetch installer: {e}[/red]")
            raise SystemExit(1)

    console.print("[bright_yellow]⚔️  Arming the full arsenal...[/bright_yellow]")
    console.print(f"[dim]Using {install_sh}[/dim]\n")

    # Source install.sh and call install_external_tools directly
    bash_cmd = f'source "{install_sh}" && install_external_tools'
    try:
        proc = subprocess.run(
            ["bash", "-c", bash_cmd],
            env={**__import__("os").environ, "PYTHON": shutil.which("python3") or "python3"},
        )
        raise SystemExit(proc.returncode)
    except FileNotFoundError:
        console.print("[red]✗ bash not found.[/red]")
        raise SystemExit(1)


# =============================================================================
# HUNT — Main scanning command
# =============================================================================

def _run_ghost_hunt(target, *, cli_headers=(), cli_cookies=(), cli_token=None, verbose=False):
    """Run a single-target hunt through the GHOST v2 agent (`beatrix hunt --ghost`).

    Thin wrapper over ``beatrix.ai.ghost2.run_investigation`` that reuses the
    hunt command's auth options and prints a compact result.
    """
    try:
        from beatrix.ai.ghost2 import GhostV2Config, run_investigation
    except ImportError:
        console.print("[red]--ghost requires the 'agent' extra:[/red]")
        console.print("  [bold]pip install 'beatrix-cli[agent]'[/bold]")
        sys.exit(1)

    base_headers = {}
    for h in cli_headers:
        if ":" in h:
            name, value = h.split(":", 1)
            base_headers[name.strip()] = value.strip()
    if cli_token:
        base_headers.setdefault("Authorization", f"Bearer {cli_token}")
    base_cookies = {}
    for c in cli_cookies:
        if "=" in c:
            name, value = c.split("=", 1)
            base_cookies[name.strip()] = value.strip()

    cfg = GhostV2Config.load()
    key_hint = cfg.missing_key_message()
    if key_hint:
        console.print(f"[red]{key_hint}[/red]")
        sys.exit(1)

    console.print(Panel.fit(
        f"[bold]Target:[/bold] {target}\n[bold]Model:[/bold]  {cfg.model}\n"
        f"[bold]Mode:[/bold]   ghost-driven (GHOST v2)",
        title="[bold bright_red]👻 GHOST v2[/bold bright_red]", border_style="red",
    ))

    try:
        result = asyncio.run(run_investigation(
            target, cfg=cfg, base_headers=base_headers, base_cookies=base_cookies,
            console=console, verbose=verbose,
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Investigation interrupted.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    verdict_color = "red" if result["verdict"] == "VULNERABLE" else "green"
    console.print(f"\n[bold {verdict_color}]Verdict: {result['verdict']}[/bold {verdict_color}]")
    if result["findings"]:
        console.print(f"\n[bold]Findings ({result['num_findings']}):[/bold]")
        for finding in result["findings"]:
            console.print(f"  {finding.severity.icon} [{finding.severity.color}]{finding.title}[/{finding.severity.color}]")
    if result.get("hunt_id"):
        console.print(f"\n[dim]Saved to findings DB as hunt #{result['hunt_id']} (beatrix findings).[/dim]")
    if result.get("scan_dir"):
        console.print(f"[dim]Scan output: {result['scan_dir']}[/dim]")
    if result.get("final_output"):
        console.print(Panel(str(result["final_output"]), title="Summary", border_style="dim"))


@cli.command()
@click.argument("target", required=False, default=None)
@click.option(
    "--preset", "-p",
    type=click.Choice(["quick", "standard", "full", "stealth", "injection", "api", "web", "recon"]),
    default="standard",
    help="Scan preset (run 'beatrix help hunt' for details)"
)
@click.option("--ai", is_flag=True, help="Enable AI analysis (Claude Haiku)")
@click.option("--ghost", is_flag=True,
              help="Drive the hunt with the GHOST v2 autonomous agent instead of the "
                   "deterministic pipeline (requires the 'agent' extra). Single target only.")
@click.option("--modules", "-m", multiple=True, help="Specific modules to run (repeatable)")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--file", "-f", "targets_file", type=click.Path(exists=True),
              help="Text file with URLs/domains to hunt (one per line)")
# ── Authentication options ────────────────────────────────────────────────
@click.option("--auth-config", type=click.Path(exists=True),
              help="Path to auth YAML config file (default: ~/.beatrix/auth.yaml)")
@click.option("--cookie", "cli_cookies", multiple=True,
              help="Cookie to inject (repeatable, format: name=value)")
@click.option("--header", "cli_headers", multiple=True,
              help="Header to inject (repeatable, format: 'Name: Value')")
@click.option("--token", "cli_token", default=None,
              help="Bearer token for authenticated scanning")
@click.option("--auth-user", default=None, help="Username for basic auth")
@click.option("--auth-pass", default=None, help="Password for basic auth")
@click.option("--login-user", default=None, help="Username/email for auto-login (like Burp Suite)")
@click.option("--login-pass", default=None, help="Password for auto-login")
@click.option("--login-url", default=None, help="Login page URL (auto-detected if omitted)")
@click.option("--manual-login", is_flag=True, help="Open browser for manual login (handles OTP/captcha)")
@click.option("--fresh-login", is_flag=True, help="Ignore saved session, force re-authentication")
@click.option("--browser-auth", is_flag=True,
              help="Force authenticated requests through a real browser instead of httpx. "
                   "Use when you already know the target fingerprints scripted HTTP clients "
                   "(e.g. Akamai bot management) — SessionValidator's auto-detection only "
                   "samples a fixed list of common auth-check paths and can miss "
                   "path-specific blocking. Slower per-request; only affects authenticated "
                   "scanner requests, not bulk unauthenticated traffic.")
@click.option("--rate-limit", "rate_limit", type=int, default=None,
              help="Max requests per second across all scanners (default: 10). "
                   "Use lower values against WAF-protected targets.")
@click.option("--verbose", "-v", count=True,
              help="Verbosity: -v show all info, -vv show finding details, -vvv enable debug logging")
@click.pass_context
def hunt(ctx, target, preset, ai, ghost, modules, output, targets_file,
         auth_config, cli_cookies, cli_headers, cli_token, auth_user, auth_pass,
         login_user, login_pass, login_url, manual_login, fresh_login, browser_auth, rate_limit, verbose):
    """
    Hunt for vulnerabilities on TARGET or a file of targets.

    \b
    Examples:
        beatrix hunt example.com
        beatrix hunt example.com --preset full --ai
        beatrix hunt example.com --ghost          # autonomous GHOST v2 agent
        beatrix hunt api.example.com -m cors -m idor
        beatrix hunt -f targets.txt
        beatrix hunt -f targets.txt --preset full -o ./reports

    \b
    Run 'beatrix help hunt' for full documentation.
    """
    from datetime import datetime

    # ── Resolve target list ───────────────────────────────────────────────
    if targets_file:
        raw_lines = Path(targets_file).read_text().strip().splitlines()
        target_list = [
            line.strip() for line in raw_lines
            if line.strip() and not line.strip().startswith("#")
        ]
        if not target_list:
            console.print("[red]✗ No valid targets found in file.[/red]")
            sys.exit(1)
    elif target:
        target_list = [target]
    else:
        console.print("[red]✗ Provide a TARGET argument or --file/-f with a targets file.[/red]")
        console.print("[dim]  beatrix hunt example.com[/dim]")
        console.print("[dim]  beatrix hunt -f targets.txt[/dim]")
        sys.exit(1)

    # ── GHOST-driven mode ─────────────────────────────────────────────────
    # Hand the target to GHOST v2 instead of the deterministic pipeline. The
    # agent persists findings to the same FindingsDB / scan dir, so `beatrix
    # findings` and every reporter work identically.
    if ghost:
        if len(target_list) > 1:
            console.print("[red]✗ --ghost runs one target at a time; drop --file or pass a single target.[/red]")
            sys.exit(1)
        _run_ghost_hunt(
            target_list[0],
            cli_headers=cli_headers, cli_cookies=cli_cookies, cli_token=cli_token,
            verbose=bool(verbose),
        )
        return

    # ── Multi-target mode ─────────────────────────────────────────────────
    if len(target_list) > 1:
        console.print(f"\n[bright_yellow]📋 Batch hunt — {len(target_list)} targets from [bold]{targets_file}[/bold][/bright_yellow]")
        console.print(f"[dim]   Preset: {preset} | AI: {'enabled' if ai else 'disabled'}[/dim]")

        # Validate AI creds once before processing the whole batch
        if ai:
            _validate_ai_credentials()
        console.print()

        all_findings = []
        hunt_ids = []
        failed_targets = []

        for idx, t in enumerate(target_list, 1):
            console.print(Panel.fit(
                f"[bold]{t}[/bold]  ({idx}/{len(target_list)})",
                title=f"[bright_green]⚔️  Target {idx}[/bright_green]",
                border_style="green",
            ))
            try:
                h_id, h_findings = _hunt_single_target(
                    t, preset=preset, ai=ai,
                    modules=list(modules) if modules else None,
                    output=output,
                    auth_config=auth_config,
                    cli_cookies=cli_cookies,
                    cli_headers=cli_headers,
                    cli_token=cli_token,
                    auth_user=auth_user,
                    auth_pass=auth_pass,
                    login_user=login_user,
                    login_pass=login_pass,
                    login_url=login_url,
                    manual_login=manual_login,
                    fresh_login=fresh_login,
                    browser_auth=browser_auth,
                    verbose=verbose,
                )
                all_findings.extend(h_findings)
                if h_id:
                    hunt_ids.append((t, h_id))
            except KeyboardInterrupt:
                console.print("\n[yellow]Hunt interrupted. Showing partial results.[/yellow]")
                break
            except Exception as e:
                console.print(f"[red]  ✗ Failed: {e}[/red]")
                failed_targets.append((t, str(e)))

        # ── Aggregate summary ─────────────────────────────────────────────
        console.print()
        sev_counts = {}
        for f in all_findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        summary_lines = [
            f"[bold]Targets:[/bold]    {len(target_list)} ({len(target_list) - len(failed_targets)} succeeded, {len(failed_targets)} failed)",
            f"[bold]Findings:[/bold]   {len(all_findings)} total",
        ]
        for sev in Severity:
            cnt = sev_counts.get(sev.value, 0)
            if cnt:
                summary_lines.append(f"  {sev.icon} {sev.value.upper()}: {cnt}")
        if hunt_ids:
            summary_lines.append("")
            summary_lines.append("[bold]Hunt IDs:[/bold]")
            for t, hid in hunt_ids:
                summary_lines.append(f"  #{hid}  {t}")

        console.print(Panel(
            "\n".join(summary_lines),
            title="[bright_yellow]📋 Batch Hunt Complete[/bright_yellow]",
            border_style="yellow",
        ))

        # ── Save aggregate JSON if output specified ───────────────────────
        if output and all_findings:
            output_path = Path(output)
            if output_path.suffix == ".json" or str(output) == "-":
                _export_json(all_findings, output_path if str(output) != "-" else None, target=targets_file)
            else:
                output_path.mkdir(parents=True, exist_ok=True)
                from beatrix.reporters import ReportGenerator
                reporter = ReportGenerator(output_dir=output_path)
                batch_path = reporter.generate_batch_report(
                    all_findings, targets_file, program="Beatrix Batch Hunt"
                )
                console.print(f"\n[green]📄 Batch report saved: {batch_path}[/green]")
                json_path = output_path / "findings.json"
                reporter.export_json(all_findings, json_path, target=targets_file)
                console.print(f"[green]📦 JSON export saved: {json_path}[/green]")
                _fix_sudo_ownership(output_path)

        return

    # ── Single target mode (original behavior) ────────────────────────────
    target = target_list[0]

    console.print(f"\n[bright_green]⚔️  Initiating hunt on [bold]{target}[/bold][/bright_green]")
    _verbose_label = ["", " | -v", " | -vv", " | -vvv"][min(verbose, 3)] if verbose else ""
    console.print(f"[dim]   Preset: {preset} | AI: {'enabled' if ai else 'disabled'}{_verbose_label}[/dim]")
    if modules:
        console.print(f"[dim]   Modules: {', '.join(modules)}[/dim]")
    if verbose >= 3:
        import logging as _logging
        from rich.logging import RichHandler as _RichHandler
        _logging.basicConfig(
            level=_logging.DEBUG,
            format="%(name)s: %(message)s",
            datefmt="[%X]",
            handlers=[_RichHandler(console=console, rich_tracebacks=False, markup=False, show_path=False)],
            force=True,
        )
        console.print("[dim]  [cyan]⚙  -vvv: all internal scanner debug output enabled[/cyan][/dim]")
    elif verbose >= 2:
        import logging as _logging
        _logging.basicConfig(level=_logging.INFO, force=True)

    # Validate AI credentials early so the user isn't blindsided mid-scan
    if ai:
        _validate_ai_credentials()

    console.print()

    # ── Real-time progress state ──────────────────────────────────────────
    progress_state = {
        "phase": "",
        "phase_icon": "",
        "scanner": "",
        "status": "Initializing...",
        "findings_count": 0,
        "crawl_stats": None,
        "log": [],          # Last N events
        "start_time": datetime.now(),
    }

    def _on_event(event: str, data: dict) -> None:
        """Handle real-time progress events from the kill chain."""
        if event == "phase_start":
            progress_state["phase"] = data.get("phase", "")
            progress_state["phase_icon"] = data.get("icon", "")
            progress_state["status"] = f"Phase: {data.get('phase', '')}"
            progress_state["log"].append(
                f"{data.get('icon', '🔧')} [bold]{data.get('phase', '')}[/bold] — {data.get('description', '')}"
            )
        elif event == "phase_done":
            dur = data.get("duration", 0)
            n = data.get("findings", 0)
            progress_state["log"].append(
                f"  ✓ {data.get('phase', '')} complete — {n} finding{'s' if n != 1 else ''} ({dur:.1f}s)"
            )
        elif event == "crawl_start":
            progress_state["status"] = f"Crawling {data.get('target', '')}..."
            progress_state["log"].append("  🕷️  Crawling target...")
        elif event == "crawl_done":
            stats = {
                "pages": data.get("pages", 0),
                "urls": data.get("urls", 0),
                "params_urls": data.get("params_urls", 0),
                "js_files": data.get("js_files", 0),
                "forms": data.get("forms", 0),
                "technologies": data.get("technologies", []),
                "resolved_url": data.get("resolved_url", ""),
            }
            progress_state["crawl_stats"] = stats
            progress_state["log"].append(
                f"  🕷️  Crawl complete — {stats['pages']} pages, {stats['urls']} URLs, "
                f"{stats['params_urls']} with params, {stats['js_files']} JS files"
            )
            if stats["technologies"]:
                progress_state["log"].append(
                    f"  🔬 Technologies: {', '.join(stats['technologies'])}"
                )
        elif event == "crawl_error":
            progress_state["log"].append(f"  [red]✗ Crawl error: {data.get('error', '')}[/red]")
        elif event == "scanner_start":
            progress_state["scanner"] = data.get("scanner", "")
            progress_state["status"] = f"Running {data.get('scanner', '')} on {data.get('target', '')}"
            progress_state["log"].append(f"  ▸ {data.get('scanner', '')} → {data.get('target', '')}")
        elif event == "scanner_done":
            n = data.get("findings", 0)
            if n > 0:
                progress_state["log"].append(
                    f"  [yellow]  ⚡ {data.get('scanner', '')} found {n} issue{'s' if n != 1 else ''}[/yellow]"
                )
        elif event == "scanner_error":
            if verbose >= 2:
                progress_state["log"].append(
                    f"  [red]  ✗ {data.get('scanner', '')}: {data.get('error', '')}[/red]"
                )
            else:
                progress_state["log"].append(
                    f"  [dim]  ✗ {data.get('scanner', '')}: {data.get('error', '')}[/dim]"
                )
        elif event == "finding":
            progress_state["findings_count"] += 1
            f = data.get("finding")
            if f:
                sev = getattr(f, 'severity', None)
                icon = sev.icon if sev else "•"
                color = sev.color if sev else "white"
                progress_state["log"].append(
                    f"    {icon} [{color}]{getattr(f, 'title', 'Finding')}[/{color}]"
                )
                if verbose >= 2:
                    if getattr(f, 'url', None):
                        progress_state["log"].append(f"      [dim]URL:      {f.url}[/dim]")
                    if getattr(f, 'parameter', None):
                        progress_state["log"].append(f"      [dim]Param:    {f.parameter}[/dim]")
                    evidence = getattr(f, 'evidence', None)
                    if evidence:
                        ev_limit = 5000 if verbose >= 3 else 500
                        progress_state["log"].append(f"      [dim]Evidence: {str(evidence)[:ev_limit]}[/dim]")
        elif event == "info":
            progress_state["log"].append(f"  ℹ  {data.get('message', '')}")

        # Log buffer: unlimited at -vvv, 500 at -vv, 200 at -v, 50 default
        _log_cap = None if verbose >= 3 else (500 if verbose >= 2 else (200 if verbose >= 1 else 50))
        if _log_cap is not None and len(progress_state["log"]) > _log_cap:
            with _log_lock:
                excess = len(progress_state["log"]) - _log_cap
                del progress_state["log"][:excess]
                _printed_count[0] = max(_printed_count[0] - excess, 0)

    # Create scan output manager for organized output files
    output_mgr = None
    try:
        from beatrix.core.scan_output import ScanOutputManager
        output_mgr = ScanOutputManager(target)
        console.print(f"[dim]📁 Scan output → {output_mgr.scan_dir}[/dim]")
    except Exception as _som_err:
        console.print(f"[yellow]  ⚠  Scan output directory unavailable: {_som_err}[/yellow]")

    from beatrix.core.engine import EngineConfig
    _engine_config = EngineConfig()
    if rate_limit is not None:
        _engine_config.rate_limit = rate_limit
    engine = BeatrixEngine(config=_engine_config, on_event=_on_event, output_manager=output_mgr)

    # ── Load authentication credentials ───────────────────────────────────
    auth_creds = None
    try:
        from beatrix.core.auth_config import AuthConfigLoader
        auth_creds = AuthConfigLoader.load(
            target=target,
            config_path=auth_config,
            cli_cookies=list(cli_cookies) if cli_cookies else None,
            cli_headers=list(cli_headers) if cli_headers else None,
            cli_token=cli_token,
            cli_user=auth_user,
            cli_password=auth_pass,
            login_user=login_user,
            login_pass=login_pass,
            login_url=login_url,
        )

        # ── Manual browser login (for OTP/captcha sites) ──────────────────
        if manual_login:
            console.print(f"[cyan]🌐 Manual browser login for {target}...[/cyan]")
            try:
                from beatrix.core.auto_login import browser_interactive_login, save_session
                login_result = asyncio.run(browser_interactive_login(target))
                if login_result.success:
                    auth_creds.cookies.update(login_result.cookies)
                    auth_creds.headers.update(login_result.headers)
                    if login_result.token:
                        auth_creds.bearer_token = login_result.token
                    console.print(f"[green]🔐 {login_result.message}[/green]")
                else:
                    console.print(f"[red]🔐 Manual login failed: {login_result.message}[/red]")
                    console.print("[yellow]   Continuing scan without authenticated session[/yellow]")
            except Exception as e:
                console.print(f"[red]🔐 Manual login error: {e}[/red]")
                console.print("[yellow]   Continuing scan without authenticated session[/yellow]")

        # ── Check for saved session ────────────────────────────────────────
        elif not fresh_login and not auth_creds.has_auth:
            try:
                from beatrix.core.auto_login import load_session
                from urllib.parse import urlparse as _urlparse
                _domain = _urlparse(target if "://" in target else f"https://{target}").netloc
                saved = load_session(_domain)
                if saved and saved.success:
                    auth_creds.cookies.update(saved.cookies)
                    auth_creds.headers.update(saved.headers)
                    if saved.token:
                        auth_creds.bearer_token = saved.token
                    console.print(f"[green]🔐 {saved.message}[/green]")
            except Exception:
                pass

        # ── Auto-login if credentials provided ────────────────────────────
        if not manual_login and not auth_creds.has_auth and auth_creds.has_login_creds:
            console.print(f"[cyan]🔐 Auto-login: logging in as {auth_creds.login_username}...[/cyan]")
            try:
                from beatrix.core.auto_login import perform_auto_login, save_session
                login_result = asyncio.run(perform_auto_login(auth_creds, target=target))
                if login_result.success:
                    auth_creds.cookies.update(login_result.cookies)
                    auth_creds.headers.update(login_result.headers)
                    if login_result.token:
                        auth_creds.bearer_token = login_result.token
                    console.print(f"[green]🔐 {login_result.message}[/green]")
                    # Save session for reuse
                    from urllib.parse import urlparse as _urlparse
                    _domain = _urlparse(target if "://" in target else f"https://{target}").netloc
                    save_session(_domain, login_result)
                    console.print(f"[dim]   Session saved — will reuse on next scan (--fresh-login to re-auth)[/dim]")
                elif login_result.otp_required:
                    console.print(f"[yellow]🔐 {login_result.message}[/yellow]")
                    console.print("[yellow]   Tip: use --manual-login to complete OTP in browser[/yellow]")
                    console.print("[yellow]   Or:  beatrix auth browser " + target + "[/yellow]")
                    console.print("[yellow]   Continuing scan without authenticated session[/yellow]")
                else:
                    console.print(f"[red]🔐 Login failed: {login_result.message}[/red]")
                    console.print("[yellow]   Continuing scan without authenticated session[/yellow]")
            except Exception as e:
                console.print(f"[red]🔐 Auto-login error: {e}[/red]")
                console.print("[yellow]   Continuing scan without authenticated session[/yellow]")

        # ── Auto-login for IDOR users if they have login creds ──────────
        if auth_creds.has_idor_accounts:
            for label, idor_user in [("user1", auth_creds.idor_user1), ("user2", auth_creds.idor_user2)]:
                if idor_user and idor_user.has_login_creds and not idor_user.has_auth:
                    console.print(f"[cyan]🔐 IDOR {label}: logging in as {idor_user.login_username}...[/cyan]")
                    try:
                        from beatrix.core.auto_login import perform_auto_login
                        idor_login = asyncio.run(perform_auto_login(idor_user, target=target))
                        if idor_login.success:
                            idor_user.cookies.update(idor_login.cookies)
                            idor_user.headers.update(idor_login.headers)
                            if idor_login.token:
                                idor_user.bearer_token = idor_login.token
                            console.print(f"[green]🔐 IDOR {label}: {idor_login.message}[/green]")
                        else:
                            console.print(f"[red]🔐 IDOR {label} login failed: {idor_login.message}[/red]")
                    except Exception as e:
                        console.print(f"[red]🔐 IDOR {label} auto-login error: {e}[/red]")

        if auth_creds.has_auth:
            parts = []
            if auth_creds.cookies:
                parts.append(f"{len(auth_creds.cookies)} cookies")
            if auth_creds.merged_headers():
                parts.append(f"{len(auth_creds.merged_headers())} headers")
            if auth_creds.basic_auth:
                parts.append("basic auth")
            console.print(f"[green]🔐 Auth loaded: {', '.join(parts)}[/green]")
            if auth_creds.has_idor_accounts:
                console.print("[green]   ↳ IDOR: 2 user sessions configured[/green]")
    except Exception as e:
        console.print(f"[dim]  Auth config: {e}[/dim]")

    try:
        # Print events to console in real-time (non-blocking)
        import threading
        _printed_count = [0]
        _stop_printer = threading.Event()
        _log_lock = threading.Lock()

        def _printer():
            """Background thread that prints new log entries."""
            while not _stop_printer.is_set():
                with _log_lock:
                    while _printed_count[0] < len(progress_state["log"]):
                        line = progress_state["log"][_printed_count[0]]
                        console.print(line)
                        _printed_count[0] += 1
                _stop_printer.wait(0.1)
            # Flush remaining
            with _log_lock:
                while _printed_count[0] < len(progress_state["log"]):
                    line = progress_state["log"][_printed_count[0]]
                    console.print(line)
                    _printed_count[0] += 1

        printer_thread = threading.Thread(target=_printer, daemon=True)
        printer_thread.start()

        state = asyncio.run(engine.hunt(
            target=target,
            preset=preset,
            ai=ai,
            modules=list(modules) if modules else None,
            auth=auth_creds,
            browser_auth=browser_auth,
        ))

        _stop_printer.set()
        printer_thread.join(timeout=2)

        console.print()

        # Calculate duration and modules
        duration = (datetime.now() - state.started_at).total_seconds()
        modules_run = set()
        for pr in state.phase_results.values():
            modules_run.update(pr.modules_run)

        # Auto-save to findings database
        hunt_id = None
        try:
            from beatrix.core.findings_db import FindingsDB
            with FindingsDB() as db:
                hunt_id = db.save_hunt(
                    target=target,
                    preset=preset,
                    findings=engine.findings,
                    duration=duration,
                    modules_run=sorted(modules_run),
                    ai_enabled=ai,
                    started_at=state.started_at,
                )
        except Exception as e:
            console.print(f"[yellow]  ⚠  Failed to save hunt to database: {e}[/yellow]")

        _display_hunt_results(state, engine, hunt_id=hunt_id)

        if output_mgr:
            console.print(f"\n[green]📁 Full scan output saved to: {output_mgr.scan_dir}[/green]")

        # Handle output format
        if output:
            output_path = Path(output)
            if output_path.suffix == ".json" or str(output) == "-":
                # JSON output: to file or stdout
                _export_json(engine.findings, output_path if str(output) != "-" else None, target=target)
            else:
                # Directory output: full reports
                from beatrix.reporters import ReportGenerator
                reporter = ReportGenerator(output_dir=output_path)

                batch_path = reporter.generate_batch_report(
                    engine.findings, target, program="Beatrix Hunt"
                )
                console.print(f"\n[green]📄 Batch report saved: {batch_path}[/green]")

                for finding in engine.findings:
                    if finding.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                        report_path = reporter.generate_report(finding, program="Beatrix Hunt")
                        console.print(f"  [dim]→ {report_path.name}[/dim]")

                json_path = output_path / "findings.json"
                reporter.export_json(engine.findings, json_path, target=target)
                console.print(f"[green]📦 JSON export saved: {json_path}[/green]")
                _fix_sudo_ownership(output_path)
    except KeyboardInterrupt:
        _stop_printer.set()
        console.print("\n[yellow]Hunt interrupted. Saving partial results...[/yellow]")

        # Save whatever findings we have so far
        if output and engine.findings:
            try:
                output_path = Path(output)
                if output_path.suffix == ".json" or str(output) == "-":
                    _export_json(engine.findings, output_path if str(output) != "-" else None, target=target)
                else:
                    from beatrix.reporters import ReportGenerator
                    output_path.mkdir(parents=True, exist_ok=True)
                    reporter = ReportGenerator(output_dir=output_path)
                    batch_path = reporter.generate_batch_report(
                        engine.findings, target, program="Beatrix Hunt (partial)"
                    )
                    console.print(f"[yellow]📄 Partial report saved: {batch_path}[/yellow]")
                    json_path = output_path / "findings.json"
                    reporter.export_json(engine.findings, json_path, target=target)
                    console.print(f"[yellow]📦 Partial JSON saved: {json_path}[/yellow]")
                    _fix_sudo_ownership(output_path)
                _fix_sudo_ownership(Path(output))
                console.print(f"[yellow]  ↳ {len(engine.findings)} findings saved from interrupted scan[/yellow]")
            except Exception as save_err:
                console.print(f"[red]  ⚠  Failed to save partial results: {save_err}[/red]")
        elif output:
            console.print("[yellow]  No findings captured before interrupt.[/yellow]")

        sys.exit(1)
    except Exception as e:
        _stop_printer.set()
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def _hunt_single_target(target, preset="standard", ai=False, modules=None,
                        output=None, auth_config=None, cli_cookies=None,
                        cli_headers=None, cli_token=None, auth_user=None,
                        auth_pass=None, login_user=None, login_pass=None,
                        login_url=None, manual_login=False, fresh_login=False,
                        browser_auth=False, verbose=0):
    """
    Run a full hunt on a single target. Used by both single-target and
    multi-target (--file) modes.

    Returns:
        (hunt_id, findings) — hunt_id may be None if DB save fails.
    """
    import threading
    from datetime import datetime

    progress_state = {
        "phase": "", "phase_icon": "", "scanner": "",
        "status": "Initializing...", "findings_count": 0,
        "crawl_stats": None, "log": [], "start_time": datetime.now(),
    }
    _printed_count = [0]
    _stop_printer = threading.Event()

    def _on_event(event: str, data: dict) -> None:
        if event == "phase_start":
            progress_state["log"].append(
                f"{data.get('icon', '🔧')} [bold]{data.get('phase', '')}[/bold] — {data.get('description', '')}"
            )
        elif event == "phase_done":
            n = data.get("findings", 0)
            dur = data.get("duration", 0)
            progress_state["log"].append(
                f"  ✓ {data.get('phase', '')} complete — {n} finding{'s' if n != 1 else ''} ({dur:.1f}s)"
            )
        elif event == "crawl_done":
            stats = data
            progress_state["log"].append(
                f"  🕷️  Crawl complete — {stats.get('pages', 0)} pages, "
                f"{stats.get('urls', 0)} URLs, {stats.get('params_urls', 0)} with params"
            )
        elif event == "scanner_start":
            progress_state["log"].append(f"  ▸ {data.get('scanner', '')} → {data.get('target', '')}")
        elif event == "scanner_done":
            n = data.get("findings", 0)
            if n > 0:
                progress_state["log"].append(
                    f"  [yellow]  ⚡ {data.get('scanner', '')} found {n} issue{'s' if n != 1 else ''}[/yellow]"
                )
        elif event == "scanner_error":
            if verbose >= 2:
                progress_state["log"].append(
                    f"  [red]  ✗ {data.get('scanner', '')}: {data.get('error', '')}[/red]"
                )
            else:
                progress_state["log"].append(
                    f"  [dim]  ✗ {data.get('scanner', '')}: {data.get('error', '')}[/dim]"
                )
        elif event == "finding":
            progress_state["findings_count"] += 1
            f = data.get("finding")
            if f:
                sev = getattr(f, 'severity', None)
                icon = sev.icon if sev else "•"
                color = sev.color if sev else "white"
                progress_state["log"].append(
                    f"    {icon} [{color}]{getattr(f, 'title', 'Finding')}[/{color}]"
                )
                if verbose >= 2:
                    if getattr(f, 'url', None):
                        progress_state["log"].append(f"      [dim]URL:      {f.url}[/dim]")
                    if getattr(f, 'parameter', None):
                        progress_state["log"].append(f"      [dim]Param:    {f.parameter}[/dim]")
                    evidence = getattr(f, 'evidence', None)
                    if evidence:
                        ev_limit = 5000 if verbose >= 3 else 500
                        progress_state["log"].append(f"      [dim]Evidence: {str(evidence)[:ev_limit]}[/dim]")
        elif event == "info":
            progress_state["log"].append(f"  ℹ  {data.get('message', '')}")

        # Log buffer: unlimited at -vvv, 500 at -vv, 200 at -v, 50 default
        _log_cap = None if verbose >= 3 else (500 if verbose >= 2 else (200 if verbose >= 1 else 50))
        if _log_cap is not None and len(progress_state["log"]) > _log_cap:
            excess = len(progress_state["log"]) - _log_cap
            del progress_state["log"][:excess]
            _printed_count[0] = max(_printed_count[0] - excess, 0)

    # Create scan output manager for organized output files
    output_mgr = None
    try:
        from beatrix.core.scan_output import ScanOutputManager
        output_mgr = ScanOutputManager(target)
        console.print(f"[dim]📁 Scan output → {output_mgr.scan_dir}[/dim]")
    except Exception as _som_err:
        console.print(f"[yellow]  ⚠  Scan output directory unavailable: {_som_err}[/yellow]")

    engine = BeatrixEngine(on_event=_on_event, output_manager=output_mgr)

    # Load auth credentials for this target
    auth_creds = None
    try:
        from beatrix.core.auth_config import AuthConfigLoader
        auth_creds = AuthConfigLoader.load(
            target=target,
            config_path=auth_config,
            cli_cookies=list(cli_cookies) if cli_cookies else None,
            cli_headers=list(cli_headers) if cli_headers else None,
            cli_token=cli_token,
            cli_user=auth_user,
            cli_password=auth_pass,
            login_user=login_user,
            login_pass=login_pass,
            login_url=login_url,
        )

        # ── Manual browser login (for OTP/captcha sites) ──────────────
        if manual_login:
            console.print(f"[cyan]🌐 Manual browser login for {target}...[/cyan]")
            try:
                from beatrix.core.auto_login import browser_interactive_login, save_session
                login_result = asyncio.run(browser_interactive_login(target))
                if login_result.success:
                    auth_creds.cookies.update(login_result.cookies)
                    auth_creds.headers.update(login_result.headers)
                    if login_result.token:
                        auth_creds.bearer_token = login_result.token
                    console.print(f"[green]🔐 {login_result.message}[/green]")
                else:
                    console.print(f"[red]🔐 Manual login failed: {login_result.message}[/red]")
                    console.print("[yellow]   Continuing scan without authenticated session[/yellow]")
            except Exception as e:
                console.print(f"[red]🔐 Manual login error: {e}[/red]")
                console.print("[yellow]   Continuing scan without authenticated session[/yellow]")

        # Auto-login if credentials provided
        elif auth_creds.has_login_creds:
            # Check for saved session first (skip if --fresh-login)
            if not fresh_login:
                try:
                    from beatrix.core.auto_login import load_session
                    from urllib.parse import urlparse as _urlparse
                    _domain = _urlparse(target if "://" in target else f"https://{target}").netloc
                    saved = load_session(_domain)
                    if saved and saved.success:
                        auth_creds.cookies.update(saved.cookies)
                        auth_creds.headers.update(saved.headers)
                        if saved.token:
                            auth_creds.bearer_token = saved.token
                        console.print(f"[green]🔐 {saved.message}[/green]")
                except Exception:
                    pass

            if not auth_creds.has_auth:
                console.print(f"[cyan]🔐 Auto-login: logging in as {auth_creds.login_username}...[/cyan]")
                try:
                    from beatrix.core.auto_login import perform_auto_login, save_session
                    login_result = asyncio.run(perform_auto_login(auth_creds, target=target))
                    if login_result.success:
                        auth_creds.cookies.update(login_result.cookies)
                        auth_creds.headers.update(login_result.headers)
                        if login_result.token:
                            auth_creds.bearer_token = login_result.token
                        console.print(f"[green]🔐 {login_result.message}[/green]")
                        from urllib.parse import urlparse as _urlparse
                        _domain = _urlparse(target if "://" in target else f"https://{target}").netloc
                        save_session(_domain, login_result)
                    elif login_result.otp_required:
                        console.print(f"[yellow]🔐 {login_result.message}[/yellow]")
                        console.print(f"[yellow]   Tip: beatrix auth browser {target}[/yellow]")
                    else:
                        console.print(f"[red]🔐 Login failed: {login_result.message}[/red]")
                except Exception as e:
                    console.print(f"[red]🔐 Auto-login error: {e}[/red]")

        # ── Auto-login for IDOR users if they have login creds ──────────
        if auth_creds.has_idor_accounts:
            for label, idor_user in [("user1", auth_creds.idor_user1), ("user2", auth_creds.idor_user2)]:
                if idor_user and idor_user.has_login_creds and not idor_user.has_auth:
                    console.print(f"[cyan]🔐 IDOR {label}: logging in as {idor_user.login_username}...[/cyan]")
                    try:
                        from beatrix.core.auto_login import perform_auto_login
                        idor_login = asyncio.run(perform_auto_login(idor_user, target=target))
                        if idor_login.success:
                            idor_user.cookies.update(idor_login.cookies)
                            idor_user.headers.update(idor_login.headers)
                            if idor_login.token:
                                idor_user.bearer_token = idor_login.token
                            console.print(f"[green]🔐 IDOR {label}: {idor_login.message}[/green]")
                        else:
                            console.print(f"[red]🔐 IDOR {label} login failed: {idor_login.message}[/red]")
                    except Exception as e:
                        console.print(f"[red]🔐 IDOR {label} auto-login error: {e}[/red]")

        if auth_creds.has_auth:
            parts = []
            if auth_creds.cookies:
                parts.append(f"{len(auth_creds.cookies)} cookies")
            if auth_creds.merged_headers():
                parts.append(f"{len(auth_creds.merged_headers())} headers")
            if auth_creds.basic_auth:
                parts.append("basic auth")
            console.print(f"[green]🔐 Auth loaded: {', '.join(parts)}[/green]")
    except Exception:
        pass

    def _printer():
        while not _stop_printer.is_set():
            while _printed_count[0] < len(progress_state["log"]):
                console.print(progress_state["log"][_printed_count[0]])
                _printed_count[0] += 1
            _stop_printer.wait(0.1)
        while _printed_count[0] < len(progress_state["log"]):
            console.print(progress_state["log"][_printed_count[0]])
            _printed_count[0] += 1

    printer_thread = threading.Thread(target=_printer, daemon=True)
    printer_thread.start()

    try:
        state = asyncio.run(engine.hunt(
            target=target, preset=preset, ai=ai, modules=modules,
            auth=auth_creds,
        ))
    finally:
        _stop_printer.set()
        printer_thread.join(timeout=2)

    console.print()

    duration = (datetime.now() - state.started_at).total_seconds()
    modules_run = set()
    for pr in state.phase_results.values():
        modules_run.update(pr.modules_run)

    hunt_id = None
    try:
        from beatrix.core.findings_db import FindingsDB
        with FindingsDB() as db:
            hunt_id = db.save_hunt(
                target=target, preset=preset,
                findings=engine.findings, duration=duration,
                modules_run=sorted(modules_run), ai_enabled=ai,
                started_at=state.started_at,
            )
    except Exception:
        pass

    _display_hunt_results(state, engine, hunt_id=hunt_id)

    if output_mgr:
        console.print(f"\n[green]📁 Full scan output saved to: {output_mgr.scan_dir}[/green]")

    return hunt_id, list(engine.findings)


def _validate_ai_credentials(ai_config=None):
    """
    Validate AI credentials before running any AI-powered command.
    Prints a clear error and exits if credentials are broken.
    Returns True if valid.
    """
    from beatrix.ai.assistant import AIConfig, AIProvider, validate_credentials

    if ai_config is None:
        ai_config = AIConfig(provider=AIProvider.BEDROCK)

    console.print("[dim]  🔑 Validating AI credentials...[/dim]", end="")

    try:
        result = asyncio.run(validate_credentials(ai_config))
    except Exception as exc:
        console.print(f"  [red]✗[/red]")
        console.print(f"[red]✗ Credential validation failed: {exc}[/red]")
        console.print("[yellow]  Fix your credentials and try again.[/yellow]")
        sys.exit(1)

    if result["valid"]:
        auth_method = result["auth_method"]
        console.print(f"  [green]✓[/green]  [dim]({auth_method})[/dim]")
        return True
    else:
        console.print(f"  [red]✗[/red]")
        console.print(f"\n[red]✗ AI credentials are invalid![/red]")
        console.print(f"[red]  Error: {result['error']}[/red]")
        console.print(f"[dim]  Provider: {result['provider']} | Auth: {result['auth_method']}[/dim]")
        console.print("\n[yellow]  To fix:[/yellow]")
        if result["auth_method"] == "bedrock_api_key":
            console.print("[yellow]    • Check BEDROCK_API_KEY env var[/yellow]")
            console.print("[yellow]    • Verify the key hasn't been revoked in the AWS console[/yellow]")
        elif "iam" in result["auth_method"]:
            console.print("[yellow]    • Run: aws sts get-caller-identity[/yellow]")
            console.print("[yellow]    • Or set BEDROCK_API_KEY with a long-term API key[/yellow]")
        else:
            console.print("[yellow]    • Set ANTHROPIC_API_KEY or use --bedrock[/yellow]")
        sys.exit(1)


def _display_hunt_results(state, engine, hunt_id=None):
    """Display hunt results with full detail for each finding."""
    from datetime import datetime

    stats = engine.get_stats()
    duration = (datetime.now() - state.started_at).total_seconds()

    # Count modules actually run
    modules_run = set()
    for pr in state.phase_results.values():
        modules_run.update(pr.modules_run)

    # A-07: Collect scanner errors from the kill chain executor
    scanner_errors = getattr(engine.kill_chain, 'scanner_errors', []) if hasattr(engine, 'kill_chain') else []

    # ── Summary panel ─────────────────────────────────────────────────
    db_line = f"\n[bold]Hunt ID:[/bold]   #{hunt_id}  [dim](beatrix findings -h {hunt_id})[/dim]" if hunt_id else ""
    errors_line = f"\n[bold]Errors:[/bold]    [red]{len(scanner_errors)}[/red]" if scanner_errors else ""
    summary = f"""
[bold]Target:[/bold]     {state.target}
[bold]Duration:[/bold]   {duration:.1f}s
[bold]Scanners:[/bold]   {len(modules_run)} modules executed
[bold]Findings:[/bold]   {stats['total_findings']}
[bold]Validated:[/bold]  {stats['validated']}{errors_line}{db_line}
    """

    console.print(Panel(summary.strip(), title="[green]Hunt Complete[/green]", border_style="green"))

    if stats["total_findings"] == 0:
        console.print("[dim]No findings discovered. Target appears clean (or try --preset full).[/dim]")
        return

    # ── Severity breakdown table ──────────────────────────────────────
    table = Table(title="Findings by Severity")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    for sev in Severity:
        count = stats["by_severity"].get(sev.value, 0)
        if count > 0:
            table.add_row(
                f"{sev.icon} {sev.value.upper()}",
                str(count),
                style=sev.color
            )

    console.print(table)

    # ── Detailed findings ─────────────────────────────────────────────
    console.print()

    for i, finding in enumerate(engine.findings, 1):
        _render_finding_card(finding, index=i, total=len(engine.findings))

    # ── Module breakdown ──────────────────────────────────────────────
    if stats["by_module"]:
        console.print()
        mod_table = Table(title="Findings by Module", show_header=True)
        mod_table.add_column("Module", style="cyan")
        mod_table.add_column("Count", justify="right")
        for mod, count in sorted(stats["by_module"].items(), key=lambda x: -x[1]):
            mod_table.add_row(mod, str(count))
        console.print(mod_table)

    # ── A-07: Scanner error summary ───────────────────────────────────
    if scanner_errors:
        console.print()
        err_table = Table(title="Scanner Errors", show_header=True, border_style="red")
        err_table.add_column("Scanner", style="cyan")
        err_table.add_column("Error", style="red")
        for entry in scanner_errors:
            # Truncate long errors without losing the start
            err_text = entry["error"]
            if len(err_text) > 120:
                err_text = err_text[:117] + "..."
            err_table.add_row(entry["scanner"], err_text)
        console.print(err_table)

    # ── Footer hints ──────────────────────────────────────────────────
    console.print()
    hints = []
    if hunt_id:
        hints.append(f"[dim]  Query findings:  beatrix findings -h {hunt_id}[/dim]")
        hints.append("[dim]  Finding detail:  beatrix findings show <ID>[/dim]")
        hints.append(f"[dim]  Export JSON:     beatrix findings export -h {hunt_id}[/dim]")
    hints.append("[dim]  All hunts:       beatrix findings hunts[/dim]")
    console.print("\n".join(hints))


def _render_finding_card(finding, index=None, total=None, full=False):
    """
    Render a single finding as a rich panel with key details.

    Args:
        finding: Finding object or dict (from DB)
        index: Finding number in sequence
        total: Total findings count
        full: If True, show full evidence/request/response
    """
    # Handle both Finding objects and dicts from DB
    if isinstance(finding, dict):
        title = finding.get("title", "")
        severity_val = finding.get("severity", "info")
        confidence_val = finding.get("confidence", "tentative")
        url = finding.get("url", "")
        description = finding.get("description", "")
        evidence = finding.get("evidence", "")
        remediation = finding.get("remediation", "")
        scanner = finding.get("scanner_module", "")
        parameter = finding.get("parameter")
        payload = finding.get("payload")
        poc_curl = finding.get("poc_curl")
        request = finding.get("request")
        response = finding.get("response")
        refs = finding.get("refs", [])
        if isinstance(refs, str):
            try:
                refs = json.loads(refs)
            except (json.JSONDecodeError, TypeError):
                refs = []
        owasp = finding.get("owasp_category")
        cwe = finding.get("cwe_id")
        finding_id = finding.get("id")

        # Resolve severity/confidence to enums for display
        try:
            severity = Severity(severity_val)
        except (ValueError, KeyError):
            severity = Severity.INFO
        try:
            confidence = Confidence(confidence_val)
        except (ValueError, KeyError):
            confidence = Confidence.TENTATIVE
    else:
        title = finding.title
        severity = finding.severity
        confidence = finding.confidence
        url = finding.url
        description = finding.description
        evidence = finding.evidence
        remediation = finding.remediation
        scanner = finding.scanner_module
        parameter = finding.parameter
        payload = finding.payload
        poc_curl = finding.poc_curl
        request = finding.request
        response = finding.response
        refs = finding.references or []
        owasp = finding.owasp_category
        cwe = finding.cwe_id
        finding_id = getattr(finding, 'id', None)

    icon = severity.icon
    color = severity.color
    conf_icon = confidence.icon if hasattr(confidence, 'icon') else "?"

    # Build the card content
    lines = []

    # Header: severity + confidence + module
    meta_parts = [
        f"[{color}]{severity.value.upper()}[/{color}]",
        f"Confidence: {confidence.value} {conf_icon}",
    ]
    if scanner:
        meta_parts.append(f"Module: [cyan]{scanner}[/cyan]")
    if finding_id:
        meta_parts.append(f"ID: #{finding_id}")
    lines.append("  ".join(meta_parts))

    # URL
    lines.append(f"[dim]URL:[/dim] {url}")

    # Parameter + Payload (if applicable)
    if parameter:
        lines.append(f"[dim]Parameter:[/dim] {parameter}")
    if payload:
        lines.append(f"[dim]Payload:[/dim] {payload}")

    # Description (always show full)
    if description:
        lines.append("")
        # Wrap long descriptions but don't truncate
        desc_text = description.strip()
        if len(desc_text) > 500 and not full:
            desc_text = desc_text[:500] + "..."
        lines.append(desc_text)

    # Evidence (show key portion)
    if evidence:
        evidence_str = str(evidence)
        lines.append("")
        lines.append("[bold]Evidence:[/bold]")
        if len(evidence_str) > 300 and not full:
            lines.append(f"[dim]{evidence_str[:300]}...[/dim]")
        else:
            lines.append(f"[dim]{evidence_str}[/dim]")

    # Remediation
    if remediation:
        lines.append("")
        lines.append(f"[bold]Remediation:[/bold] {remediation}")

    # PoC curl command
    if poc_curl:
        lines.append("")
        lines.append("[bold]PoC:[/bold]")
        lines.append(f"[dim]  $ {poc_curl}[/dim]")

    # Request/Response (only in full mode)
    if full:
        if request:
            lines.append("")
            lines.append("[bold]Request:[/bold]")
            req_text = request[:2000] if len(request) > 2000 else request
            lines.append(f"[dim]{req_text}[/dim]")
        if response:
            lines.append("")
            lines.append("[bold]Response:[/bold]")
            resp_text = response[:2000] if len(response) > 2000 else response
            lines.append(f"[dim]{resp_text}[/dim]")

    # Classification footer
    class_parts = []
    if owasp:
        class_parts.append(f"OWASP: {owasp}")
    if cwe:
        class_parts.append(f"CWE: {cwe}")
    if refs:
        class_parts.append(f"Refs: {len(refs)}")
    if class_parts:
        lines.append("")
        lines.append(f"[dim]{' | '.join(class_parts)}[/dim]")

    # Build title
    panel_title = f"{icon} [{color}][bold]{title}[/bold][/{color}]"
    if index and total:
        panel_title += f" [{index}/{total}]"

    console.print(Panel(
        "\n".join(lines),
        title=panel_title,
        border_style=color,
        padding=(0, 1),
    ))


def _export_json(findings, filepath=None, target=None):
    """Export findings as JSON to file or stdout.

    Produces a standardised envelope::

        {"findings": [...], "metadata": {...}}

    so that ``beatrix validate <file>`` can consume it directly.
    """
    import json as _json
    from datetime import datetime

    finding_list = []
    for f in findings:
        d = {
            "title": f.title,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "url": f.url,
            "parameter": f.parameter,
            "payload": f.payload,
            "description": f.description,
            "evidence": f.evidence if isinstance(f.evidence, str) else str(f.evidence) if f.evidence else None,
            "request": f.request,
            "response": f.response,
            "impact": f.impact,
            "remediation": f.remediation,
            "poc_curl": f.poc_curl,
            "poc_python": f.poc_python,
            "reproduction_steps": f.reproduction_steps,
            "references": f.references,
            "owasp_category": f.owasp_category,
            "mitre_technique": f.mitre_technique,
            "cwe_id": str(f.cwe_id) if f.cwe_id else None,
            "scanner_module": f.scanner_module,
            "found_at": f.found_at.isoformat(),
            "validated": f.validated,
        }
        finding_list.append(d)

    report = {
        "findings": finding_list,
        "metadata": {
            "tool": "beatrix",
            "version": "1.0.0",
            "target": target,
            "total_findings": len(finding_list),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        },
    }

    json_str = _json.dumps(report, indent=2, default=str)

    if filepath:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text(json_str)
        _fix_sudo_ownership(Path(filepath))
        console.print(f"[green]📦 JSON saved: {filepath}[/green]")
    else:
        # stdout mode
        click.echo(json_str)


# =============================================================================
# FINDINGS — Query, inspect, compare, and export stored findings
# =============================================================================

@cli.group(invoke_without_command=True)
@click.option("--hunt", "-h", "hunt_id", type=int, help="Filter to specific hunt ID")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Filter by severity")
@click.option("--module", "-m", help="Filter by scanner module")
@click.option("--target", "-t", help="Filter by target (substring match)")
@click.option("--search", "-q", help="Search title/description/evidence")
@click.option("--limit", "-n", type=int, default=50, help="Max results (default: 50)")
@click.pass_context
def findings(ctx, hunt_id, severity, module, target, search, limit):
    """
    Query and inspect stored findings from past hunts.

    \b
    "The lioness has rejoined her cub, and all is right in the jungle."

    \b
    Every hunt is auto-saved. Use this command to query, drill into,
    compare, and export findings at any time.

    \b
    Examples:
        beatrix findings                          # Recent findings
        beatrix findings -h 3                     # All findings from hunt #3
        beatrix findings -s high                  # All HIGH severity findings
        beatrix findings -m cors                  # All CORS findings
        beatrix findings -t pinterest.com         # All findings for a target
        beatrix findings -q "unsafe-eval"         # Search across all fields
        beatrix findings show 42                  # Full detail for finding #42
        beatrix findings hunts                    # List all past hunts
        beatrix findings export -h 3              # Export hunt #3 as JSON
        beatrix findings diff 2 3                 # Compare two hunts
        beatrix findings delete 1                 # Delete hunt #1
    """
    if ctx.invoked_subcommand is not None:
        return  # Subcommand will handle it

    from beatrix.core.findings_db import FindingsDB

    try:
        db = FindingsDB()
    except Exception as e:
        console.print(f"[red]Database error: {e}[/red]")
        sys.exit(1)

    with db:
        results = db.get_findings(
            hunt_id=hunt_id,
            severity=severity,
            module=module,
            target=target,
            search=search,
            limit=limit,
        )

    if not results:
        console.print("[dim]No findings match your query.[/dim]")
        if not hunt_id:
            console.print("[dim]Run a hunt first: beatrix hunt example.com[/dim]")
        return

    # Group header
    filter_desc = []
    if hunt_id:
        filter_desc.append(f"hunt #{hunt_id}")
    if severity:
        filter_desc.append(f"severity={severity}")
    if module:
        filter_desc.append(f"module={module}")
    if target:
        filter_desc.append(f"target={target}")
    if search:
        filter_desc.append(f'search="{search}"')

    header = f"[bold]{len(results)} finding{'s' if len(results) != 1 else ''}[/bold]"
    if filter_desc:
        header += f" [dim]({', '.join(filter_desc)})[/dim]"
    console.print(f"\n{header}\n")

    # Render findings table
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("ID", style="dim", width=5, justify="right")
    table.add_column("Sev", width=3)
    table.add_column("Conf", width=4, style="dim")
    table.add_column("Title", min_width=30)
    table.add_column("Module", style="cyan", width=16)
    table.add_column("URL", style="dim", max_width=40)

    for f in results:
        try:
            sev = Severity(f["severity"])
        except (ValueError, KeyError):
            sev = Severity.INFO
        try:
            conf = Confidence(f["confidence"])
        except (ValueError, KeyError):
            conf = Confidence.TENTATIVE

        # Truncate URL for table display
        url = f.get("url", "")
        if len(url) > 40:
            url = url[:37] + "..."

        table.add_row(
            str(f["id"]),
            sev.icon,
            conf.icon,
            f"[{sev.color}]{f['title']}[/{sev.color}]",
            f.get("scanner_module", ""),
            url,
        )

    console.print(table)
    console.print("\n[dim]Tip: beatrix findings show <ID> for full detail[/dim]")


@findings.command("show")
@click.argument("finding_id", type=int)
def findings_show(finding_id):
    """
    Show full detail for a specific finding.

    \b
    Examples:
        beatrix findings show 42
        beatrix findings show 1
    """
    from beatrix.core.findings_db import FindingsDB

    with FindingsDB() as db:
        f = db.get_finding_detail(finding_id)

    if not f:
        console.print(f"[red]Finding #{finding_id} not found.[/red]")
        sys.exit(1)

    _render_finding_card(f, full=True)


@findings.command("hunts")
@click.option("--target", "-t", help="Filter by target")
@click.option("--limit", "-n", type=int, default=20, help="Max results")
def findings_hunts(target, limit):
    """
    List all past hunts.

    \b
    Examples:
        beatrix findings hunts
        beatrix findings hunts -t pinterest
    """
    from beatrix.core.findings_db import FindingsDB

    with FindingsDB() as db:
        hunts = db.list_hunts(target=target, limit=limit)

    if not hunts:
        console.print("[dim]No hunts recorded yet. Run: beatrix hunt example.com[/dim]")
        return

    table = Table(title="[bright_yellow]Hunt History[/bright_yellow]", show_header=True)
    table.add_column("ID", style="bold cyan", justify="right", width=5)
    table.add_column("Target", min_width=20)
    table.add_column("Preset", width=10)
    table.add_column("Findings", justify="right", width=9)
    table.add_column("Duration", justify="right", width=9)
    table.add_column("Date", style="dim", width=19)
    table.add_column("AI", width=3)

    for h in hunts:
        dur = h.get("duration_secs", 0)
        dur_str = f"{dur:.1f}s" if dur < 120 else f"{dur/60:.1f}m"
        date_str = h.get("started_at", "")[:19]
        ai_str = "✓" if h.get("ai_enabled") else ""

        table.add_row(
            str(h["id"]),
            h.get("target", ""),
            h.get("preset", ""),
            str(h.get("total_findings", 0)),
            dur_str,
            date_str,
            ai_str,
        )

    console.print(table)
    console.print("\n[dim]Tip: beatrix findings -h <ID> to see findings from a specific hunt[/dim]")


@findings.command("export")
@click.option("--hunt", "-h", "hunt_id", type=int, help="Export specific hunt")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--module", "-m", help="Filter by module")
@click.option("--target", "-t", help="Filter by target")
@click.option("--output", "-o", type=click.Path(), help="Output file (default: stdout)")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "jsonl", "csv"]),
              default="json", help="Export format")
def findings_export(hunt_id, severity, module, target, output, fmt):
    """
    Export findings as JSON, JSONL, or CSV.

    \b
    Examples:
        beatrix findings export -h 3                    # JSON to stdout
        beatrix findings export -h 3 -o results.json    # JSON to file
        beatrix findings export -s high -f csv -o h.csv # CSV of high findings
        beatrix findings export -f jsonl | jq .title    # Pipe JSONL to jq
    """
    from beatrix.core.findings_db import FindingsDB

    with FindingsDB() as db:
        results = db.get_findings(
            hunt_id=hunt_id,
            severity=severity,
            module=module,
            target=target,
            limit=10000,
        )

    if not results:
        console.print("[dim]No findings match your query.[/dim]", err=True)
        sys.exit(1)

    # Parse JSON fields
    for f in results:
        for key in ("refs", "reproduction_steps"):
            try:
                f[key] = json.loads(f.get(key, "[]") or "[]")
            except (json.JSONDecodeError, TypeError):
                f[key] = []

    if fmt == "json":
        from datetime import datetime
        report = {
            "findings": results,
            "metadata": {
                "tool": "beatrix",
                "version": "1.0.0",
                "target": target,
                "total_findings": len(results),
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "filters": {
                    "hunt_id": hunt_id,
                    "severity": severity,
                    "module": module,
                },
            },
        }
        output_str = json.dumps(report, indent=2, default=str)
    elif fmt == "jsonl":
        output_str = "\n".join(json.dumps(f, default=str) for f in results)
    elif fmt == "csv":
        import csv
        import io
        buf = io.StringIO()
        fields = ["id", "hunt_id", "severity", "confidence", "title", "url",
                   "scanner_module", "description", "evidence", "remediation"]
        writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
        output_str = buf.getvalue()

    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(output_str)
        console.print(f"[green]📦 Exported {len(results)} findings to {output}[/green]", err=True)
    else:
        click.echo(output_str)


@findings.command("diff")
@click.argument("hunt_a", type=int)
@click.argument("hunt_b", type=int)
def findings_diff(hunt_a, hunt_b):
    """
    Compare findings between two hunts.

    \b
    Shows what's new, fixed, and unchanged between two runs.

    \b
    Examples:
        beatrix findings diff 1 3
    """
    from beatrix.core.findings_db import FindingsDB

    with FindingsDB() as db:
        ha = db.get_hunt(hunt_a)
        hb = db.get_hunt(hunt_b)
        if not ha or not hb:
            missing = hunt_a if not ha else hunt_b
            console.print(f"[red]Hunt #{missing} not found.[/red]")
            sys.exit(1)

        fa = db.get_findings(hunt_id=hunt_a, limit=10000)
        fb = db.get_findings(hunt_id=hunt_b, limit=10000)

    # Fingerprint findings by title+url+module for comparison
    def fingerprint(f):
        return (f["title"], f["url"], f["scanner_module"])

    set_a = {fingerprint(f): f for f in fa}
    set_b = {fingerprint(f): f for f in fb}

    keys_a = set(set_a.keys())
    keys_b = set(set_b.keys())

    new_findings = keys_b - keys_a
    fixed_findings = keys_a - keys_b
    unchanged = keys_a & keys_b

    console.print(Panel(
        f"[bold]Hunt #{hunt_a}[/bold] ({ha['target']}, {ha.get('total_findings', 0)} findings)\n"
        f"  vs\n"
        f"[bold]Hunt #{hunt_b}[/bold] ({hb['target']}, {hb.get('total_findings', 0)} findings)",
        title="[bright_yellow]Hunt Diff[/bright_yellow]",
        border_style="yellow",
    ))

    if new_findings:
        console.print(f"\n[red]⊕ {len(new_findings)} NEW findings in hunt #{hunt_b}:[/red]")
        for key in sorted(new_findings):
            f = set_b[key]
            sev = Severity(f["severity"]) if f["severity"] in [s.value for s in Severity] else Severity.INFO
            console.print(f"  {sev.icon} [{sev.color}]{f['title']}[/{sev.color}]  [dim]{f['url']}[/dim]")

    if fixed_findings:
        console.print(f"\n[green]⊖ {len(fixed_findings)} FIXED (gone from hunt #{hunt_b}):[/green]")
        for key in sorted(fixed_findings):
            f = set_a[key]
            console.print(f"  [strikethrough dim]{f['title']}  {f['url']}[/strikethrough dim]")

    if unchanged:
        console.print(f"\n[dim]═ {len(unchanged)} unchanged[/dim]")

    console.print()


@findings.command("delete")
@click.argument("hunt_id", type=int)
@click.confirmation_option(prompt="Delete this hunt and all its findings?")
def findings_delete(hunt_id):
    """Delete a hunt and all its findings."""
    from beatrix.core.findings_db import FindingsDB

    with FindingsDB() as db:
        hunt = db.get_hunt(hunt_id)
        if not hunt:
            console.print(f"[red]Hunt #{hunt_id} not found.[/red]")
            sys.exit(1)

        db.delete_hunt(hunt_id)
    console.print(f"[green]Deleted hunt #{hunt_id} ({hunt['target']}, {hunt.get('total_findings', 0)} findings)[/green]")


@findings.command("summary")
@click.argument("hunt_id", type=int)
def findings_summary(hunt_id):
    """
    Show detailed summary for a specific hunt.

    \b
    Examples:
        beatrix findings summary 3
    """
    from beatrix.core.findings_db import FindingsDB

    with FindingsDB() as db:
        summary = db.get_hunt_summary(hunt_id)

    if not summary:
        console.print(f"[red]Hunt #{hunt_id} not found.[/red]")
        sys.exit(1)

    # Parse modules_run
    try:
        modules = json.loads(summary.get("modules_run", "[]"))
    except (json.JSONDecodeError, TypeError):
        modules = []

    dur = summary.get("duration_secs", 0)
    dur_str = f"{dur:.1f}s" if dur < 120 else f"{dur/60:.1f}m"

    info = f"""
[bold]Hunt #{hunt_id}[/bold]
[bold]Target:[/bold]     {summary.get('target', '')}
[bold]Preset:[/bold]     {summary.get('preset', '')}
[bold]Date:[/bold]       {summary.get('started_at', '')[:19]}
[bold]Duration:[/bold]   {dur_str}
[bold]AI:[/bold]         {'enabled' if summary.get('ai_enabled') else 'disabled'}
[bold]Modules:[/bold]    {', '.join(modules) if modules else 'unknown'}
[bold]Findings:[/bold]   {summary.get('total_findings', 0)}
    """
    console.print(Panel(info.strip(), border_style="cyan"))

    # Severity breakdown
    by_sev = summary.get("by_severity", {})
    if by_sev:
        table = Table(title="By Severity", show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev in Severity:
            count = by_sev.get(sev.value, 0)
            if count > 0:
                table.add_row(f"{sev.icon} {sev.value.upper()}", str(count), style=sev.color)
        console.print(table)

    # Module breakdown
    by_mod = summary.get("by_module", {})
    if by_mod:
        mod_table = Table(title="By Module", show_header=True)
        mod_table.add_column("Module", style="cyan")
        mod_table.add_column("Count", justify="right")
        for mod, count in sorted(by_mod.items(), key=lambda x: -x[1]):
            mod_table.add_row(mod, str(count))
        console.print(mod_table)

    console.print(f"\n[dim]See findings: beatrix findings -h {hunt_id}[/dim]")


# =============================================================================
# PROBE — Quick target check
# =============================================================================

@cli.command()
@click.argument("target")
@click.pass_context
def probe(ctx, target):
    """
    Quick probe to check if TARGET is alive.

    \b
    "Wiggle your big toe."

    Run 'beatrix help probe' for details.
    """
    console.print(f"\n[cyan]🔍 Probing {target}...[/cyan]\n")

    engine = BeatrixEngine()

    try:
        result = asyncio.run(engine.probe(target))

        if result["alive"]:
            console.print("[green]✓ Target is alive[/green]")
            console.print(f"  Status: {result['status_code']}")
            if result.get("title"):
                console.print(f"  Title:  {result['title']}")
            if result.get("server"):
                console.print(f"  Server: {result['server']}")
            if result.get("technologies"):
                console.print(f"  Tech:   {', '.join(result['technologies'])}")
        else:
            console.print("[red]✗ Target is not responding[/red]")
            if result.get("error"):
                console.print(f"  Error: {result['error']}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


# =============================================================================
# STRIKE — Single module execution
# =============================================================================

@cli.command()
@click.argument("target")
@click.option("--module", "-m", required=True,
              help="Module to execute (run 'beatrix arsenal' for list)")
@click.option("--verbose", "-v", count=True,
              help="Verbosity: -v, -vv, -vvv (enable debug logging)")
@click.pass_context
def strike(ctx, target, module, verbose):
    """
    Execute a single attack MODULE against TARGET.

    \b
    Examples:
        beatrix strike api.example.com -m cors
        beatrix strike example.com/login -m injection

    \b
    Run 'beatrix arsenal' to see all available modules.
    """
    console.print(f"\n[red]⚔️  Striking {target} with [bold]{module}[/bold][/red]\n")

    if verbose >= 3:
        import logging as _logging
        from rich.logging import RichHandler as _RichHandler
        _logging.basicConfig(
            level=_logging.DEBUG,
            format="%(name)s: %(message)s",
            datefmt="[%X]",
            handlers=[_RichHandler(console=console, rich_tracebacks=False, markup=False, show_path=False)],
            force=True,
        )
        console.print("[dim]  [cyan]⚙  -vvv: all internal scanner debug output enabled[/cyan][/dim]\n")

    engine = BeatrixEngine()

    try:
        result = asyncio.run(engine.strike(target, module))

        if result.errors:
            for error in result.errors:
                console.print(f"[red]Error: {error}[/red]")

        console.print("\n[bold]Results:[/bold]")
        console.print(f"  Findings: {len(result.findings)}")
        console.print(f"  Duration: {result.duration:.2f}s")

        for finding in result.findings:
            console.print(f"\n  {finding.severity.icon} [{finding.severity.color}]{finding.title}[/{finding.severity.color}]")
            if finding.url:
                console.print(f"      [dim]{finding.url}[/dim]")
            if finding.evidence:
                ev_limit = 5000 if verbose >= 3 else (2000 if verbose >= 2 else 200)
                evidence_str = str(finding.evidence)[:ev_limit]
                console.print(f"      [dim]Evidence: {evidence_str}[/dim]")
            if verbose >= 2:
                if getattr(finding, 'parameter', None):
                    console.print(f"      [dim]Parameter: {finding.parameter}[/dim]")
                if getattr(finding, 'request', None):
                    req_str = str(finding.request)[:2000]
                    console.print(f"      [dim cyan]Request:[/dim cyan]\n      [dim]{req_str}[/dim]")
                if getattr(finding, 'response', None):
                    res_str = str(finding.response)[:2000]
                    console.print(f"      [dim cyan]Response:[/dim cyan]\n      [dim]{res_str}[/dim]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


# =============================================================================
# LIST — Show available modules/presets
# =============================================================================

@cli.command("list")
@click.option("--modules", "-m", is_flag=True, help="List available modules")
@click.option("--presets", "-p", is_flag=True, help="List available presets")
@click.pass_context
def list_cmd(ctx, modules, presets):
    """
    List available modules or presets.

    \b
    Examples:
        beatrix list --presets
        beatrix list --modules
        beatrix list  (shows both)
    """
    engine = BeatrixEngine()

    if presets or (not modules and not presets):
        table = Table(title="[bright_yellow]Available Presets[/bright_yellow]")
        table.add_column("Preset", style="cyan bold")
        table.add_column("Description")
        table.add_column("Kill Chain Phases", justify="right")

        for name, cfg in engine.PRESETS.items():
            table.add_row(
                name,
                cfg["description"],
                str(cfg["phases"]),
            )

        console.print(table)
        console.print()

    if modules or (not modules and not presets):
        table = Table(title="[bright_yellow]Available Modules[/bright_yellow]")
        table.add_column("Module", style="cyan bold", min_width=18)
        table.add_column("Status")

        for name, mod in engine.modules.items():
            status = "[green]✓ loaded[/green]" if mod else "[dim]— not loaded[/dim]"
            table.add_row(name, status)

        console.print(table)
        console.print()
        console.print("[dim]Tip: Run 'beatrix arsenal' for detailed module documentation.[/dim]")


# =============================================================================
# CONFIG — Configuration management
# =============================================================================

@cli.command()
@click.option("--show", is_flag=True, help="Show current configuration")
@click.option("--set", "set_opt", nargs=2, multiple=True, help="Set config option (KEY VALUE)")
@click.pass_context
def config(ctx, show, set_opt):
    """
    Manage BEATRIX configuration.

    \b
    Configuration is stored in ~/.beatrix/config.yaml

    \b
    Examples:
        beatrix config --show
        beatrix config --set ai.enabled true
        beatrix config --set scanning.rate_limit 50  # or use --rate-limit on hunt

    \b
    Run 'beatrix help config' for all available keys.
    """
    config_path = Path.home() / ".beatrix" / "config.yaml"

    if show or (not show and not set_opt):
        if config_path.exists():
            console.print(f"[bold]Config file:[/bold] {config_path}")
            console.print()
            console.print(config_path.read_text())
        else:
            console.print(f"[bold]Config file:[/bold] {config_path} [dim](not created yet)[/dim]")
            console.print()
            console.print("[dim]Using defaults. Set a value to create the config file:[/dim]")
            console.print("[dim]  beatrix config --set scanning.rate_limit 50[/dim]")

    if set_opt:
        import yaml

        config_path.parent.mkdir(parents=True, exist_ok=True)

        if config_path.exists():
            data = yaml.safe_load(config_path.read_text()) or {}
        else:
            data = {}

        for key, value in set_opt:
            if value.lower() == "true":
                value = True
            elif value.lower() == "false":
                value = False
            elif value.lower() in ("null", "none"):
                value = None
            else:
                try:
                    value = int(value)
                except ValueError:
                    try:
                        value = float(value)
                    except ValueError:
                        pass

            parts = key.split(".")
            node = data
            for part in parts[:-1]:
                if part not in node or not isinstance(node[part], dict):
                    node[part] = {}
                node = node[part]
            node[parts[-1]] = value
            console.print(f"  [green]✓[/green] {key} = {value!r}")

        config_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
        console.print(f"\n[bold]Saved to[/bold] {config_path}")


# =============================================================================
# BATCH — Mass scanning
# =============================================================================

@cli.command()
@click.argument("targets_file", type=click.Path(exists=True))
@click.option("--module", "-m", required=True, help="Module to run")
@click.option("--output", "-o", type=click.Path(), default="./reports", help="Output directory")
@click.option("--threads", "-t", default=5, help="Concurrent scans")
@click.pass_context
def batch(ctx, targets_file, module, output, threads):
    """
    Batch scan multiple targets from a file.

    \b
    Examples:
        beatrix batch targets.txt -m cors -o ./reports
        beatrix batch domains.txt -m injection -t 3
    """
    from beatrix.reporters import ReportGenerator

    targets = Path(targets_file).read_text().strip().split("\n")
    targets = [t.strip() for t in targets if t.strip() and not t.startswith("#")]

    console.print(f"\n[bold cyan]📋 Batch scanning {len(targets)} targets with [bold]{module}[/bold][/bold cyan]\n")

    reporter = ReportGenerator(Path(output))
    all_findings = []

    async def _run_batch():
        engine = BeatrixEngine()
        for i, target in enumerate(targets, 1):
            console.print(f"[{i}/{len(targets)}] {target}...", end=" ")

            try:
                result = await engine.strike(target, module)

                if result.findings:
                    console.print(f"[red]🎯 {len(result.findings)} findings![/red]")
                    all_findings.extend(result.findings)

                    for finding in result.findings:
                        if finding.severity.value in ["critical", "high"]:
                            report_path = reporter.generate_report(finding)
                            console.print(f"    [dim]Report: {report_path}[/dim]")
                else:
                    console.print("[green]✓ clean[/green]")
            except Exception as e:
                console.print(f"[yellow]⚠ {e}[/yellow]")

    asyncio.run(_run_batch())

    console.print("\n[bold]Batch Complete:[/bold]")
    console.print(f"  Targets scanned: {len(targets)}")
    console.print(f"  Total findings:  {len(all_findings)}")

    if all_findings:
        batch_report = reporter.generate_batch_report(all_findings, targets_file)
        console.print(f"  Batch report:    {batch_report}")

        json_path = Path(output) / "findings.json"
        reporter.export_json(all_findings, json_path, target=targets_file)
        console.print(f"  JSON export:     {json_path}")
        _fix_sudo_ownership(Path(output))


# =============================================================================
# GITHUB RECON
# =============================================================================

@cli.command("github-recon")
@click.argument("org")
@click.option("--repo", help="Specific repo (org/repo format)")
@click.option("--token", help="GitHub personal access token")
@click.option("--quick", is_flag=True, help="Quick scan (skip git history)")
@click.option("--output", "-o", type=click.Path(), help="Output report file (markdown)")
@click.pass_context
def github_recon(ctx, org, repo, token, quick, output):
    """
    Scan a GitHub org/user for leaked secrets.

    \b
    Run 'beatrix help github-recon' for details.
    """
    from beatrix.scanners.github_recon import GitHubRecon

    console.print(f"\n[bright_green]🔍 GitHub Recon on [bold]{org}[/bold][/bright_green]")
    mode = "Quick (no git history)" if quick else "Full (includes git history)"
    console.print(f"[dim]   Mode: {mode}[/dim]\n")

    scanner = GitHubRecon(org_name=org, github_token=token)

    try:
        async def _run():
            async with scanner:
                if quick:
                    return await scanner.quick_scan(repo)
                else:
                    findings = []
                    async for finding in scanner.full_recon():
                        findings.append(finding)
                        console.print(
                            f"  {finding.severity.icon} [{finding.severity.color}]"
                            f"{finding.title}[/{finding.severity.color}]"
                        )
                    return findings

        findings = asyncio.run(_run())

        console.print(f"\n[bold]Results:[/bold] {len(findings)} secrets found")

        if quick:
            for sf in scanner.secret_findings:
                sev_color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue"}.get(
                    sf.severity.value, "white"
                )
                console.print(
                    f"  [{sev_color}][{sf.severity.value.upper()}][/{sev_color}] "
                    f"{sf.secret_type} in {sf.file_path}"
                )
                console.print(f"    [dim]→ {sf.evidence_url}[/dim]")

        if output:
            report = scanner.generate_report()
            Path(output).write_text(report)
            console.print(f"\n[green]Report saved to {output}[/green]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


# =============================================================================
# MOBILE INTERCEPT COMMANDS
# =============================================================================

@cli.group()
@click.pass_context
def mobile(ctx):
    """
    Mobile app traffic interception.

    \b
    Run 'beatrix help mobile' for details.
    """
    pass


@mobile.command("intercept")
@click.option("--avd", default="beatrix_hunter", help="AVD name")
@click.option("--apk", help="APK file to install")
@click.option("--package", "-p", default="com.example.app", help="Package to launch")
@click.option("--duration", "-d", type=int, default=300, help="Capture duration (seconds)")
@click.option("--port", type=int, default=8080, help="Proxy port")
@click.pass_context
def mobile_intercept(ctx, avd, apk, package, duration, port):
    """Launch emulator with proxy and capture traffic."""
    from beatrix.scanners.mobile_interceptor import MobileInterceptConfig, MobileInterceptor

    config_obj = MobileInterceptConfig(
        avd_name=avd, proxy_port=port, apk_path=apk, package_name=package,
    )

    interceptor = MobileInterceptor(config_obj)

    console.print(Panel.fit(
        f"[bold]AVD:[/bold]      {avd}\n"
        f"[bold]Proxy:[/bold]    127.0.0.1:{port}\n"
        f"[bold]Package:[/bold]  {package}\n"
        f"[bold]Duration:[/bold] {duration}s",
        title="[bold bright_yellow]📱 Mobile Intercept[/bold bright_yellow]",
    ))

    asyncio.run(interceptor.capture_session(duration=duration))

    analysis = interceptor.analyze_traffic()

    table = Table(title="Traffic Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Total Requests", str(analysis.total_requests))
    table.add_row("Unique Hosts", str(len(analysis.unique_hosts)))
    table.add_row("API Keys Found", str(len(analysis.api_keys_found)))
    table.add_row("JWT Tokens", str(len(analysis.jwt_tokens)))
    table.add_row("Credentials in Bodies", str(len(analysis.credentials_in_body)))
    console.print(table)


@mobile.command("analyze")
@click.argument("capture_file")
@click.option("--secrets", help="JSON file with known secrets to match")
@click.pass_context
def mobile_analyze(ctx, capture_file, secrets):
    """Analyze a previously captured traffic file."""
    import json as _json

    from beatrix.scanners.mobile_interceptor import MobileInterceptConfig, MobileInterceptor

    config_obj = MobileInterceptConfig(capture_file=capture_file)
    interceptor = MobileInterceptor(config_obj)
    interceptor._load_captures()

    known_secrets = None
    if secrets:
        with open(secrets) as f:
            known_secrets = _json.load(f)

    analysis = interceptor.analyze_traffic(known_secrets=known_secrets)
    report = interceptor.generate_report()
    console.print(report)

    if analysis.matched_leaked_keys:
        console.print("\n[bold red]⚠️  LEAKED KEYS CONFIRMED IN TRAFFIC[/bold red]")
        for m in analysis.matched_leaked_keys:
            console.print(f"  [red]✓[/red] {m['secret_name']} → {m['found_in']}")


# =============================================================================
# BROWSER SCANNER COMMANDS
# =============================================================================

@cli.group("browser")
@click.pass_context
def browser(ctx):
    """
    Playwright-based browser scanning (DOM XSS, clickjacking).

    \b
    Requires: pip install playwright && playwright install chromium
    Run 'beatrix help browser' for details.
    """
    pass


@browser.command("scan")
@click.argument("url")
@click.option("--login-url", help="Login page URL for authenticated scanning")
@click.option("--email", help="Login email/username")
@click.option("--password", help="Login password")
@click.option("--visible", is_flag=True, help="Show browser window (non-headless)")
@click.pass_context
def browser_scan(ctx, url, login_url, email, password, visible):
    """Run browser-based security scan against a URL."""
    from beatrix.scanners.browser_scanner import quick_browser_scan

    console.print(Panel.fit(
        f"[bold]Target:[/bold]  {url}\n"
        f"[bold]Auth:[/bold]    {'Yes' if email else 'No'}\n"
        f"[bold]Mode:[/bold]    {'Visible' if visible else 'Headless'}",
        title="[bold bright_cyan]🌐 Browser Scanner[/bold bright_cyan]",
        border_style="cyan",
    ))

    findings = asyncio.run(quick_browser_scan(
        url=url, email=email, password=password,
        login_url=login_url, headless=not visible,
    ))

    if findings:
        table = Table(title=f"Browser Findings ({len(findings)})")
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("URL", style="dim")
        for f_item in findings:
            sev_color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue"}.get(f_item.severity, "white")
            table.add_row(f"[{sev_color}]{f_item.severity.upper()}[/{sev_color}]", f_item.title, f_item.url)
        console.print(table)
    else:
        console.print("[green]No browser-based vulnerabilities found.[/green]")


# =============================================================================
# AUTH CONFIG COMMANDS
# =============================================================================

@cli.group("auth")
@click.pass_context
def auth_group(ctx):
    """
    Manage authentication configuration for scanning.

    Configure credentials that flow to all scanners — nuclei gets -H flags,
    IDOR gets user sessions, crawler gets cookies for authenticated crawling.

    Examples:
        beatrix auth              # Open the drag-and-drop auth GUI in your browser
        beatrix auth login        # Interactive credential setup wizard
        beatrix auth show         # Show current auth state
        beatrix auth init         # Generate sample auth config file
    """
    # Bare `beatrix auth` launches the browser GUI — no YAML editing required.
    if ctx.invoked_subcommand is None:
        ctx.invoke(auth_gui)


@auth_group.command("gui")
@click.option("--port", type=int, default=8765, help="Port to serve the GUI on (default: 8765)")
@click.option("--host", default="127.0.0.1", help="Interface to bind (default: 127.0.0.1)")
@click.option("--no-browser", is_flag=True, help="Don't try to open a browser automatically")
def auth_gui(port, host, no_browser):
    """Open a browser GUI to set up auth — drag-drop a HAR or paste cookies.

    \b
    Works in Codespaces / remote containers: starts a localhost web server that
    VS Code port-forwards to a browser tab. No YAML editing, no native window.
    Saves through the same path as `beatrix auth import`.
    """
    from beatrix.cli.auth_gui import serve_auth_gui
    try:
        serve_auth_gui(host=host, port=port, open_browser=not no_browser)
    except OSError as e:
        console.print(f"[red]Could not start GUI on {host}:{port} — {e}[/red]")
        console.print(f"[dim]Try a different port: beatrix auth gui --port 8899[/dim]")


@auth_group.command("init")
@click.option("--force", is_flag=True, help="Overwrite existing config")
def auth_init(force):
    """Generate a sample auth config file (~/.beatrix/auth.yaml)."""
    from pathlib import Path

    config_path = Path.home() / ".beatrix" / "auth.yaml"

    if config_path.exists() and not force:
        console.print(f"[yellow]Config already exists: {config_path}[/yellow]")
        console.print("[dim]Use --force to overwrite[/dim]")
        return

    try:
        from beatrix.core.auth_config import AuthConfigLoader
        config_path.parent.mkdir(parents=True, exist_ok=True)
        sample = AuthConfigLoader.generate_sample_config()
        config_path.write_text(sample)
        console.print(f"[green]✓ Sample auth config created: {config_path}[/green]")
        console.print()
        console.print("[bold]Next steps:[/bold]")
        console.print(f"  1. Edit [cyan]{config_path}[/cyan]")
        console.print("  2. Add your cookies, tokens, or login credentials")
        console.print("  3. Run [cyan]beatrix hunt target.com[/cyan] — auth is auto-loaded")
        console.print()
        console.print("[bold]Auto-login (like Burp Suite):[/bold]")
        console.print("  beatrix hunt target.com --login-user 'user@email.com' --login-pass 'password'")
        console.print("  beatrix hunt target.com --login-user 'admin' --login-pass 'pass' --login-url '/login'")
        console.print()
        console.print("[bold]Or use pre-authenticated tokens:[/bold]")
        console.print("  beatrix hunt target.com --token 'Bearer eyJ...'")
        console.print("  beatrix hunt target.com --cookie 'session=abc123'")
        console.print("  beatrix hunt target.com --header 'X-API-Key: key123'")
    except Exception as e:
        console.print(f"[red]Failed to create config: {e}[/red]")


@auth_group.command("config")
def auth_config_cmd():
    """Open the auth config file in your default editor."""
    import os
    import subprocess
    from pathlib import Path

    config_path = Path.home() / ".beatrix" / "auth.yaml"

    if not config_path.exists():
        console.print("[yellow]No config file found. Creating one first...[/yellow]")
        try:
            from beatrix.core.auth_config import AuthConfigLoader
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(AuthConfigLoader.generate_sample_config())
            console.print(f"[green]✓ Created {config_path}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to create config: {e}[/red]")
            return

    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL")
    if not editor:
        # Try common editors in order of preference
        for candidate in ["nano", "vim", "vi", "code"]:
            if subprocess.run(["which", candidate], capture_output=True).returncode == 0:
                editor = candidate
                break
        else:
            editor = "nano"

    console.print(f"[dim]Opening {config_path} with {editor}...[/dim]")
    os.execvp(editor, [editor, str(config_path)])


@auth_group.command("login")
@click.argument("target", required=False)
def auth_login_wizard(target):
    """Interactive credential setup — enter username & password for auto-login.

    \b
    Launches a guided wizard to configure login credentials.
    Beatrix will use these to auto-authenticate before scanning,
    just like setting up a login macro in Burp Suite.

    \b
    Examples:
        beatrix auth login              # General credentials
        beatrix auth login example.com   # Target-specific credentials
    """
    import getpass
    from pathlib import Path
    from rich.prompt import Prompt, Confirm

    console.print()
    console.print(Panel.fit(
        "[bold]Auto-Login Setup[/bold]\n"
        "[dim]Enter credentials and Beatrix will log in automatically,\n"
        "capture the session, and use it for authenticated scanning.[/dim]",
        title="[bold bright_cyan]🔐 Beatrix Auth[/bold bright_cyan]",
        border_style="cyan",
    ))
    console.print()

    # ── Step 1: Target ─────────────────────────────────────────────────
    if not target:
        target = Prompt.ask(
            "[bold]Target domain[/bold] [dim](e.g. example.com, blank for all)[/dim]",
            default="",
        ).strip()

    target_label = target or "all targets"
    console.print()

    # ── Step 2: Username / Email ───────────────────────────────────────
    username = Prompt.ask(
        "[bold]Username or email[/bold]",
    ).strip()
    if not username:
        console.print("[red]Username is required.[/red]")
        return
    console.print()

    # ── Step 3: Password (masked) ──────────────────────────────────────
    password = getpass.getpass("  Password: ")
    if not password:
        console.print("[red]Password is required.[/red]")
        return
    console.print()

    # ── Step 4: Login URL (optional) ───────────────────────────────────
    login_url = Prompt.ask(
        "[bold]Login URL[/bold] [dim](leave blank to auto-detect)[/dim]",
        default="",
    ).strip()
    console.print()

    # ── Step 5: Method ─────────────────────────────────────────────────
    method = Prompt.ask(
        "[bold]Login method[/bold]",
        choices=["auto", "form", "json"],
        default="auto",
    )
    console.print()

    # ── Step 6: Additional auth (optional) ─────────────────────────────
    add_token = ""
    add_cookies = {}
    if Confirm.ask("[bold]Add a bearer token or cookies too?[/bold]", default=False):
        token_str = Prompt.ask(
            "  [bold]Bearer token[/bold] [dim](blank to skip)[/dim]",
            default="",
        ).strip()
        if token_str:
            add_token = token_str

        cookie_str = Prompt.ask(
            "  [bold]Cookies[/bold] [dim](format: name=value; name2=value2, blank to skip)[/dim]",
            default="",
        ).strip()
        if cookie_str:
            for part in cookie_str.split(";"):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    add_cookies[k.strip()] = v.strip()
    console.print()

    # ── Save to config file ────────────────────────────────────────────
    config_path = Path.home() / ".beatrix" / "auth.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        import yaml
        has_yaml = True
    except ImportError:
        has_yaml = False

    if has_yaml:
        # Load existing config or start fresh
        existing = {}
        if config_path.exists():
            try:
                existing = yaml.safe_load(config_path.read_text()) or {}
            except Exception:
                existing = {}

        if target:
            # Per-target config
            targets_cfg = existing.get("targets") or {}
            existing["targets"] = targets_cfg
            target_cfg = targets_cfg.get(target) or {}
            targets_cfg[target] = target_cfg
            target_cfg["login"] = {
                "username": username,
                "password": password,
            }
            if login_url:
                target_cfg["login"]["url"] = login_url
            if method != "auto":
                target_cfg["login"]["method"] = method
            if add_token:
                hdrs = target_cfg.get("headers") or {}
                hdrs["Authorization"] = f"Bearer {add_token}"
                target_cfg["headers"] = hdrs
            if add_cookies:
                cks = target_cfg.get("cookies") or {}
                cks.update(add_cookies)
                target_cfg["cookies"] = cks
        else:
            # Global login config
            existing["login"] = {
                "username": username,
                "password": password,
            }
            if login_url:
                existing["login"]["url"] = login_url
            if method != "auto":
                existing["login"]["method"] = method
            if add_token:
                gcfg = existing.get("global") or {}
                hdrs = gcfg.get("headers") or {}
                hdrs["Authorization"] = f"Bearer {add_token}"
                gcfg["headers"] = hdrs
                existing["global"] = gcfg
            if add_cookies:
                gcfg = existing.get("global") or {}
                cks = gcfg.get("cookies") or {}
                cks.update(add_cookies)
                gcfg["cookies"] = cks
                existing["global"] = gcfg

        config_path.write_text(yaml.dump(existing, default_flow_style=False, sort_keys=False))
    else:
        # Fallback: write raw YAML manually
        lines = []
        if config_path.exists():
            lines = config_path.read_text().splitlines()
            lines.append("")

        if target:
            lines.append(f'targets:')
            lines.append(f'  "{target}":')
            lines.append(f'    login:')
        else:
            lines.append(f'login:')

        indent = "      " if target else "  "
        lines.append(f'{indent}username: "{username}"')
        lines.append(f'{indent}password: "{password}"')
        if login_url:
            lines.append(f'{indent}url: "{login_url}"')
        if method != "auto":
            lines.append(f'{indent}method: "{method}"')

        config_path.write_text("\n".join(lines) + "\n")

    # ── Summary ────────────────────────────────────────────────────────
    table = Table(title="Credentials Saved", border_style="green", show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Target", target_label)
    table.add_row("Username", username)
    table.add_row("Password", "•" * min(len(password), 12))
    if login_url:
        table.add_row("Login URL", login_url)
    table.add_row("Method", method)
    if add_token:
        table.add_row("Token", add_token[:20] + "...")
    if add_cookies:
        table.add_row("Cookies", ", ".join(add_cookies.keys()))
    table.add_row("Config", str(config_path))
    console.print(table)

    console.print()
    console.print("[green]✓ Ready! Beatrix will auto-login before scanning.[/green]")
    if target:
        console.print(f"[dim]  Run: beatrix hunt {target}[/dim]")
    else:
        console.print("[dim]  Run: beatrix hunt <target>[/dim]")
    console.print()


@auth_group.command("show")
@click.option("--target", "-t", help="Show auth for specific target")
def auth_show(target):
    """Show current authentication configuration."""
    from pathlib import Path

    config_path = Path.home() / ".beatrix" / "auth.yaml"

    if not config_path.exists():
        console.print("[dim]No auth config file found[/dim]")
        console.print(f"[dim]Run [cyan]beatrix auth init[/cyan] to create one at {config_path}[/dim]")
        return

    try:
        from beatrix.core.auth_config import AuthConfigLoader

        if target:
            creds = AuthConfigLoader.load(target=target, config_path=str(config_path))
            console.print(f"\n[bold]Auth for {target}:[/bold]")
            has_anything = creds.has_auth or creds.has_login_creds or creds.has_idor_accounts
            if has_anything:
                if creds.headers:
                    console.print(f"  Headers: {len(creds.headers)}")
                    for k in creds.headers:
                        console.print(f"    {k}: {'*' * 8}...")
                if creds.cookies:
                    console.print(f"  Cookies: {len(creds.cookies)}")
                    for k in creds.cookies:
                        console.print(f"    {k}: {'*' * 8}...")
                if creds.bearer_token:
                    console.print(f"  Bearer: {'*' * 8}...")
                if creds.basic_auth:
                    console.print(f"  Basic Auth: {creds.basic_auth[0]}")
                if creds.has_login_creds:
                    console.print(f"  Login: {creds.login_username} → {creds.login_url or 'auto-detect'}")
                if creds.has_idor_accounts:
                    console.print("  IDOR: 2 sessions configured")
            else:
                console.print("  [dim]No auth configured[/dim]")
        else:
            # Show config file contents summary
            console.print(f"\n[bold]Auth config:[/bold] {config_path}")
            try:
                text = config_path.read_text()
                # Count non-comment, non-empty lines
                lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
                console.print(f"  {len(lines)} config lines")
            except Exception:
                pass

            # Check env vars
            import os
            env_vars = ["BEATRIX_AUTH_TOKEN", "BEATRIX_AUTH_COOKIE", "BEATRIX_AUTH_HEADER",
                       "BEATRIX_AUTH_USER", "BEATRIX_AUTH_PASS",
                       "BEATRIX_LOGIN_USER", "BEATRIX_LOGIN_PASS", "BEATRIX_LOGIN_URL"]
            set_vars = [v for v in env_vars if os.environ.get(v)]
            if set_vars:
                console.print(f"  Environment: {', '.join(set_vars)}")
            else:
                console.print("  [dim]No env vars set[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@auth_group.command("browser")
@click.argument("target")
def auth_browser(target):
    """Manual browser login — handles OTP, captcha, anything.

    \b
    Opens a browser (or cookie-paste prompt in headless environments)
    for you to complete the login manually. Beatrix captures the session
    cookies and saves them for reuse in future scans.

    \b
    Use this when auto-login fails due to OTP, 2FA, captcha, or
    other interactive challenges.

    \b
    Examples:
        beatrix auth browser example.com
        beatrix auth browser https://app.example.com
    """
    from beatrix.core.auto_login import browser_interactive_login, save_session

    console.print(Panel.fit(
        f"[bold]Target:[/bold] {target}\n"
        "[dim]Complete the login in the browser (OTP, captcha, etc.).\n"
        "Beatrix will capture your session automatically.[/dim]",
        title="[bold bright_cyan]🌐 Manual Browser Login[/bold bright_cyan]",
        border_style="cyan",
    ))

    result = asyncio.run(browser_interactive_login(target))

    if result.success:
        console.print(f"\n[green]✓ {result.message}[/green]")

        from rich.table import Table as RichTable
        table = RichTable(title="Captured Session", border_style="green", show_header=False)
        table.add_column("Field", style="bold")
        table.add_column("Value")
        if result.cookies:
            table.add_row("Cookies", ", ".join(result.cookies.keys()))
        if result.token:
            table.add_row("Token", result.token[:30] + "...")
        table.add_row("Method", result.method_used)
        console.print(table)

        console.print(f"\n[green]Session saved! Run your scan:[/green]")
        console.print(f"[dim]  beatrix hunt {target}[/dim]")
    else:
        console.print(f"\n[red]✗ {result.message}[/red]")
        console.print("[dim]  You can also pass cookies directly:[/dim]")
        console.print(f'[dim]  beatrix hunt {target} --cookie "session=YOUR_SESSION_VALUE"[/dim]')


@auth_group.command("idor")
@click.argument("target", required=False)
def auth_idor_wizard(target):
    """Interactive wizard to set up dual credentials for IDOR scanning.

    \b
    IDOR testing needs TWO user accounts to compare access.
    This wizard runs the same login flow twice — once per account —
    and saves both to ~/.beatrix/auth.yaml automatically.

    \b
    Examples:
        beatrix auth idor              # Prompted for target
        beatrix auth idor example.com  # Target-specific IDOR setup
    """
    import getpass
    from pathlib import Path
    from rich.prompt import Prompt, Confirm

    console.print()
    console.print(Panel.fit(
        "[bold]IDOR Dual-Account Setup[/bold]\n"
        "[dim]Enter login credentials for two different user accounts.\n"
        "Beatrix will auto-login as both users, then use User 2's session\n"
        "to access User 1's resources to detect IDOR vulnerabilities.[/dim]",
        title="[bold bright_cyan]🔐 Beatrix IDOR Auth[/bold bright_cyan]",
        border_style="cyan",
    ))
    console.print()

    # ── Target ─────────────────────────────────────────────────────────
    if not target:
        target = Prompt.ask(
            "[bold]Target domain[/bold] [dim](e.g. example.com)[/dim]",
        ).strip()
        if not target:
            console.print("[red]Target domain is required for IDOR setup.[/red]")
            return

    console.print(f"  [dim]Target: {target}[/dim]\n")

    users = {}
    for user_num in [1, 2]:
        label = f"User {user_num}"
        console.print(f"[bold cyan]── {label} ──[/bold cyan]\n")

        # ── Username / Email ───────────────────────────────────────────
        username = Prompt.ask(
            f"  [bold]Username or email[/bold]",
        ).strip()
        if not username:
            console.print("[red]Username is required.[/red]")
            return
        console.print()

        # ── Password (masked) ─────────────────────────────────────────
        password = getpass.getpass("    Password: ")
        if not password:
            console.print("[red]Password is required.[/red]")
            return
        console.print()

        users[f"user{user_num}"] = {"username": username, "password": password}
        console.print(f"  [green]✓ {label} credentials captured[/green]\n")

    # ── Save to auth.yaml ──────────────────────────────────────────────
    config_path = Path.home() / ".beatrix" / "auth.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        import yaml
        has_yaml = True
    except ImportError:
        has_yaml = False

    if has_yaml:
        existing = {}
        if config_path.exists():
            try:
                existing = yaml.safe_load(config_path.read_text()) or {}
            except Exception:
                existing = {}

        # Save user1 as the primary per-target login (same as auth login)
        targets_cfg = existing.get("targets") or {}
        existing["targets"] = targets_cfg
        target_cfg = targets_cfg.get(target) or {}
        targets_cfg[target] = target_cfg
        target_cfg["login"] = {
            "username": users["user1"]["username"],
            "password": users["user1"]["password"],
        }

        # IDOR section with both users' login creds
        existing["idor"] = {
            "user1": {
                "login": {
                    "username": users["user1"]["username"],
                    "password": users["user1"]["password"],
                }
            },
            "user2": {
                "login": {
                    "username": users["user2"]["username"],
                    "password": users["user2"]["password"],
                }
            },
        }

        config_path.write_text(yaml.dump(existing, default_flow_style=False, sort_keys=False))
    else:
        # Fallback: append raw YAML
        lines = []
        if config_path.exists():
            in_idor = False
            for line in config_path.read_text().splitlines():
                if line.strip().startswith("idor:"):
                    in_idor = True
                    continue
                if in_idor and (line.startswith("  ") or line.strip() == ""):
                    continue
                in_idor = False
                lines.append(line)

        lines.append("")
        lines.append("idor:")
        for ukey in ["user1", "user2"]:
            lines.append(f"  {ukey}:")
            lines.append(f"    login:")
            lines.append(f'      username: "{users[ukey]["username"]}"')
            lines.append(f'      password: "{users[ukey]["password"]}"')

        config_path.write_text("\n".join(lines) + "\n")

    # ── Summary ────────────────────────────────────────────────────────
    table = Table(title="IDOR Dual Accounts Saved", border_style="green", show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Target", target)
    table.add_row("User 1", users["user1"]["username"])
    table.add_row("Password", "•" * min(len(users["user1"]["password"]), 12))
    table.add_row("User 2", users["user2"]["username"])
    table.add_row("Password", "•" * min(len(users["user2"]["password"]), 12))
    table.add_row("Config", str(config_path))
    console.print(table)

    console.print()
    console.print("[green]✓ Ready! Beatrix will auto-login both accounts before scanning.[/green]")
    console.print(f"[dim]  Run: beatrix hunt {target}[/dim]")
    console.print()


@auth_group.command("sessions")
@click.option("--clear", "-c", help="Clear saved session for a domain")
@click.option("--clear-all", is_flag=True, help="Clear all saved sessions")
def auth_sessions(clear, clear_all):
    """Manage saved login sessions.

    \b
    Sessions are saved after successful logins and reused automatically.
    They expire after 24 hours.

    \b
    Examples:
        beatrix auth sessions              # List all saved sessions
        beatrix auth sessions --clear example.com  # Clear one session
        beatrix auth sessions --clear-all  # Clear all sessions
    """
    from beatrix.core.auto_login import clear_session, list_sessions, SESSIONS_DIR

    if clear_all:
        if SESSIONS_DIR.exists():
            import shutil
            count = len(list(SESSIONS_DIR.glob("*.json")))
            shutil.rmtree(SESSIONS_DIR)
            console.print(f"[green]✓ Cleared {count} saved sessions[/green]")
        else:
            console.print("[dim]No saved sessions to clear[/dim]")
        return

    if clear:
        if clear_session(clear):
            console.print(f"[green]✓ Cleared session for {clear}[/green]")
        else:
            console.print(f"[dim]No saved session for {clear}[/dim]")
        return

    sessions = list_sessions()
    if not sessions:
        console.print("[dim]No saved sessions[/dim]")
        console.print("[dim]Run: beatrix auth browser <target>[/dim]")
        return

    from rich.table import Table as RichTable
    table = RichTable(title="Saved Sessions", border_style="cyan")
    table.add_column("Domain", style="bold")
    table.add_column("Age", style="dim")
    table.add_column("Cookies")
    table.add_column("Token")
    table.add_column("Method")
    table.add_column("Saved At", style="dim")

    for s in sessions:
        age_str = f"{s['age_hours']:.0f}h"
        expired = s['age_hours'] > 24
        age_color = "red" if expired else "green"
        table.add_row(
            s["domain"],
            f"[{age_color}]{age_str}{'  [expired]' if expired else ''}[/{age_color}]",
            str(s["cookies"]),
            "✓" if s["has_token"] else "—",
            s["method"],
            s["saved_at"],
        )
    console.print(table)


@auth_group.command("import")
@click.argument("target")
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["har", "cookies", "auto"]), default="auto",
              help="File format: har (HTTP Archive JSON), cookies (header string), auto (detect from extension/content)")
@click.option("--idor-slot", "idor_slot", type=click.Choice(["user1", "user2"]), default=None,
              help="Also write this session into idor.<slot> in ~/.beatrix/auth.yaml, for IDOR "
                   "dual-account testing. Run the command twice — once per HAR, once per slot — "
                   "to set up both accounts without touching credentials (works around 2FA, since "
                   "a HAR captures an already-authenticated session).")
def auth_import_cmd(target, file, fmt, idor_slot):
    """Import a session from a HAR archive or cookie string file.

    \b
    HAR files capture real browser traffic including all request headers,
    HttpOnly cookies, and auth tokens — the most complete import method.

    \b
    How to export a HAR from Chrome/Firefox/Edge:
      1. Open DevTools (F12) → Network tab
      2. Log in and complete any OTP/2FA
      3. Right-click any request → 'Save all as HAR with content'
      4. beatrix auth import example.com session.har

    \b
    Cookie string format (one line):
      name=value; name2=value2; session=abc123

    \b
    Examples:
        beatrix auth import example.com session.har
        beatrix auth import api.example.com traffic.har
        beatrix auth import example.com cookies.txt --format cookies

    \b
    IDOR dual-account setup from two HAR files (no credentials/2FA needed):
        beatrix auth import example.com account1.har --idor-slot user1
        beatrix auth import example.com account2.har --idor-slot user2
        beatrix hunt example.com
    """
    import json as _json
    from pathlib import Path as _Path
    from beatrix.core.auto_login import LoginResult, save_session

    file_path = _Path(file)

    # ── Detect format ─────────────────────────────────────────────────────────
    if fmt == "auto":
        suffix = file_path.suffix.lower()
        if suffix == ".har":
            fmt = "har"
        else:
            # Peek at content
            try:
                head = file_path.read_text(encoding="utf-8", errors="replace")[:200].strip()
                fmt = "har" if head.startswith("{") and '"log"' in head else "cookies"
            except Exception:
                fmt = "cookies"

    console.print()
    console.print(Panel.fit(
        f"[bold]Importing session for:[/bold] {target}\n"
        f"[dim]File: {file_path.name}  Format: {fmt}[/dim]",
        title="[bold bright_cyan]  Session Import[/bold bright_cyan]",
        border_style="cyan",
    ))
    console.print()

    if fmt == "har":
        result = _import_from_har(target, file_path)
    else:
        result = _import_from_cookie_string(target, file_path)

    if result is None:
        return

    # ── Resolve target domain for saving ──────────────────────────────────────
    from urllib.parse import urlparse as _urlparse
    _parsed = _urlparse(target if "://" in target else f"https://{target}")
    domain = _parsed.netloc or target

    save_session(domain, result)

    if idor_slot:
        _save_idor_slot(target, idor_slot, result)

    # ── Summary table ─────────────────────────────────────────────────────────
    table = Table(title="Imported Session", border_style="green", show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Domain", domain)
    table.add_row("Cookies", str(len(result.cookies)))
    if result.cookies:
        table.add_row("Cookie names", ", ".join(list(result.cookies.keys())[:8]))
    if result.headers:
        table.add_row("Auth headers", ", ".join(result.headers.keys()))
    if result.token:
        table.add_row("Bearer token", result.token[:40] + "...")
    table.add_row("Method", result.method_used)
    if idor_slot:
        table.add_row("IDOR slot", f"idor.{idor_slot} (~/.beatrix/auth.yaml)")
    console.print(table)
    console.print()
    if idor_slot:
        other = "user2" if idor_slot == "user1" else "user1"
        console.print(f"[green]Session saved to idor.{idor_slot}.[/green]")
        console.print(f"[dim]  Import the other account's HAR into idor.{other} the same way, then:[/dim]")
        console.print(f"[dim]  beatrix hunt {target}[/dim]")
    else:
        console.print("[green]Session saved. Run your scan:[/green]")
        console.print(f"[dim]  beatrix hunt {target}[/dim]")
    console.print()


def _save_idor_slot(target: str, slot: str, result: "Any") -> None:
    """Write an imported HAR/cookie session into idor.<slot> in ~/.beatrix/auth.yaml.

    Merges into the existing file rather than overwriting it — importing
    user2's HAR must not clobber user1's slot (or vice versa), since these
    are two separate `auth import` invocations.
    """
    import yaml
    from pathlib import Path

    config_path = Path.home() / ".beatrix" / "auth.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    existing = {}
    if config_path.exists():
        try:
            existing = yaml.safe_load(config_path.read_text()) or {}
        except Exception:
            existing = {}

    idor_cfg = existing.get("idor") or {}
    existing["idor"] = idor_cfg
    slot_cfg = idor_cfg.get(slot) or {}
    idor_cfg[slot] = slot_cfg

    if result.cookies:
        slot_cfg["cookies"] = dict(result.cookies)

    headers = dict(result.headers) if result.headers else {}
    if result.token and not any(h.lower() == "authorization" for h in headers):
        headers["Authorization"] = f"Bearer {result.token}"
    if headers:
        slot_cfg["headers"] = headers

    config_path.write_text(yaml.dump(existing, default_flow_style=False, sort_keys=False))


def _import_from_har(target: str, file_path) -> "Optional[Any]":
    """Parse a HAR file and extract the best authenticated session for target."""
    import json as _json
    from urllib.parse import urlparse as _urlparse

    try:
        har = _json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        console.print(f"[red]Could not parse HAR file: {e}[/red]")
        return None

    entries = []
    try:
        entries = har["log"]["entries"]
    except (KeyError, TypeError):
        console.print("[red]Invalid HAR format — expected log.entries array[/red]")
        return None

    # Extract target domain for filtering
    _parsed = _urlparse(target if "://" in target else f"https://{target}")
    target_host = _parsed.netloc or target
    # Strip port for matching
    target_domain = target_host.split(":")[0]

    # Session cookie names that strongly indicate an authenticated session
    SESSION_COOKIE_NAMES = {
        "session", "sessionid", "session_id", "sid", "ssid",
        "connect.sid", "phpsessid", "jsessionid", "laravel_session",
        "asp.net_sessionid", "_session_id", "rack.session",
        "auth", "token", "jwt", "access_token",
    }

    # Auth header names to capture
    AUTH_HEADER_NAMES = {
        "authorization", "x-api-key", "x-auth-token", "x-access-token",
        "x-session-token", "api-key", "x-token",
    }

    best_cookies: dict = {}
    best_headers: dict = {}
    best_token: str = ""
    best_score = -1

    for entry in entries:
        try:
            req = entry.get("request", {})
            req_url = req.get("url", "")
            req_host = _urlparse(req_url).netloc.split(":")[0]

            # Only consider requests to the target domain (or subdomains)
            if req_host != target_domain and not req_host.endswith("." + target_domain):
                continue

            raw_headers = req.get("headers", [])
            h_lower = {h["name"].lower(): h["value"] for h in raw_headers if "name" in h and "value" in h}

            # Extract Cookie header
            cookie_str = h_lower.get("cookie", "")
            entry_cookies: dict = {}
            if cookie_str:
                for part in cookie_str.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, _, v = part.partition("=")
                        entry_cookies[k.strip()] = v.strip()

            # Extract auth headers
            entry_headers: dict = {}
            entry_token = ""
            for hname, hval in h_lower.items():
                if hname in AUTH_HEADER_NAMES:
                    entry_headers[hname.title().replace("X-", "X-")] = hval
                    if hname == "authorization" and hval.lower().startswith("bearer "):
                        entry_token = hval[7:].strip()

            if not entry_cookies and not entry_headers:
                continue

            # Score: prefer entries with known session cookies
            score = len(entry_cookies) + len(entry_headers) * 2
            for cname in entry_cookies:
                if cname.lower() in SESSION_COOKIE_NAMES:
                    score += 5
            if entry_token:
                score += 10

            if score > best_score:
                best_score = score
                best_cookies = entry_cookies
                best_headers = entry_headers
                best_token = entry_token

        except Exception:
            continue

    if not best_cookies and not best_headers:
        console.print(f"[yellow]No authenticated requests found for {target_domain} in this HAR file.[/yellow]")
        console.print("[dim]  Make sure you exported the HAR after logging in, and that the")
        console.print(f"[dim]  domain matches. Entries in file: {len(entries)}[/dim]")
        return None

    console.print(f"[green]Found {len(best_cookies)} cookies and {len(best_headers)} auth headers[/green]")
    if best_token:
        console.print(f"[green]Bearer token: {best_token[:40]}...[/green]")

    from beatrix.core.auto_login import LoginResult
    return LoginResult(
        success=True,
        cookies=best_cookies,
        headers=best_headers,
        token=best_token or None,
        method_used="har_import",
        login_url=target,
        message=f"Imported from HAR: {len(best_cookies)} cookies, {len(best_headers)} headers",
    )


def _import_from_cookie_string(target: str, file_path) -> "Optional[Any]":
    """Parse a plain cookie string file and create a session."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace").strip()
    except Exception as e:
        console.print(f"[red]Could not read file: {e}[/red]")
        return None

    cookies: dict = {}
    headers: dict = {}
    token: str = ""

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Bearer token line
        if line.lower().startswith("authorization:") or line.lower().startswith("bearer "):
            val = line.split(":", 1)[-1].strip() if ":" in line else line
            if val.lower().startswith("bearer "):
                token = val[7:].strip()
            else:
                token = val
            headers["Authorization"] = f"Bearer {token}"
            continue
        # Cookie: header line
        if line.lower().startswith("cookie:"):
            line = line[7:].strip()
        # Parse as cookie string
        for part in line.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()

    if not cookies and not headers:
        console.print("[red]No cookies or auth headers found in file.[/red]")
        console.print("[dim]  Expected format: name=value; name2=value2[/dim]")
        console.print("[dim]  Or:              Cookie: name=value; name2=value2[/dim]")
        console.print("[dim]  Or:              Authorization: Bearer eyJ...[/dim]")
        return None

    console.print(f"[green]Parsed {len(cookies)} cookies" + (f" + bearer token" if token else "") + "[/green]")

    from beatrix.core.auto_login import LoginResult
    return LoginResult(
        success=True,
        cookies=cookies,
        headers=headers,
        token=token or None,
        method_used="cookie_import",
        login_url=target,
        message=f"Imported from file: {len(cookies)} cookies",
    )


# =============================================================================
# CREDENTIAL VALIDATOR COMMANDS
# =============================================================================

@cli.group("creds")
@click.pass_context
def creds(ctx):
    """
    Validate leaked credentials (AWS, GitHub, Stripe, JWT, etc.).

    \b
    Run 'beatrix help creds' for details.
    """
    pass


@creds.command("validate")
@click.argument("cred_type", type=click.Choice([
    "jwt_secret", "api_key", "aws_key", "github_token", "stripe_key",
    "sendgrid_key", "slack_webhook", "mongodb_uri", "redis_password", "generic",
], case_sensitive=False))
@click.argument("value")
@click.option("--host", help="Service host (for DB credentials)")
@click.option("--port", type=int, help="Service port (for DB credentials)")
@click.option("--username", "-u", help="Associated username")
@click.option("--service-url", help="API endpoint to test against")
@click.pass_context
def creds_validate(ctx, cred_type, value, host, port, username, service_url):
    """Validate a single credential against its target service."""
    from beatrix.scanners.credential_validator import CredentialTest, CredentialType, CredentialValidator

    type_map = {
        "jwt_secret": CredentialType.JWT_SECRET,
        "api_key": CredentialType.API_KEY,
        "aws_key": CredentialType.AWS_KEY,
        "github_token": CredentialType.GITHUB_TOKEN,
        "stripe_key": CredentialType.STRIPE_KEY,
        "sendgrid_key": CredentialType.SENDGRID_KEY,
        "slack_webhook": CredentialType.SLACK_WEBHOOK,
        "mongodb_uri": CredentialType.MONGODB_URI,
        "redis_password": CredentialType.REDIS_PASSWORD,
        "generic": CredentialType.GENERIC,
    }

    context = {}
    if host:
        context["host"] = host
    if port:
        context["port"] = port
    if username:
        context["username"] = username
    if service_url:
        context["service_url"] = service_url

    cred = CredentialTest(
        credential_type=type_map[cred_type.lower()],
        value=value,
        context=context,
    )

    console.print(Panel.fit(
        f"[bold]Type:[/bold]  {cred_type}\n"
        f"[bold]Value:[/bold] {value[:20]}{'...' if len(value) > 20 else ''}",
        title="[bold bright_yellow]🔑 Credential Validator[/bold bright_yellow]",
        border_style="yellow",
    ))

    validator = CredentialValidator()
    report = asyncio.run(validator.validate(cred))

    result_color = "green" if report.is_live else "red" if report.result.value == "invalid" else "yellow"
    console.print(f"\n  Result: [{result_color}]{report.result.value.upper()}[/{result_color}]")
    console.print(f"  Details: {report.details}")
    if report.access_level:
        console.print(f"  Access Level: [bold]{report.access_level}[/bold]")
    if report.service_info:
        console.print(f"  Service Info: {report.service_info}")
    console.print(f"  Risk: {report.risk_level.value}")


@creds.command("batch")
@click.argument("creds_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Save results to JSON file")
@click.pass_context
def creds_batch(ctx, creds_file, output):
    """Validate credentials from a JSON file.

    \b
    File format: [{"type": "github_token", "value": "ghp_...", "context": {...}}, ...]
    """
    import json as _json

    from beatrix.scanners.credential_validator import CredentialTest, CredentialType, CredentialValidator

    with open(creds_file) as f:
        cred_list = _json.load(f)

    console.print(f"\n[cyan]Validating {len(cred_list)} credentials from {creds_file}[/cyan]\n")

    type_map = {e.value: e for e in CredentialType}
    validator = CredentialValidator()

    async def _run():
        results = []
        for item in cred_list:
            ct = type_map.get(item.get("type", ""), CredentialType.GENERIC)
            cred = CredentialTest(
                credential_type=ct,
                value=item["value"],
                context=item.get("context", {}),
            )
            report = await validator.validate(cred)
            results.append(report)

            icon = "✅" if report.is_live else "❌"
            console.print(f"  {icon} [{ct.value}] {item['value'][:30]}... → {report.result.value}")
        return results

    results = asyncio.run(_run())

    live = sum(1 for r in results if r.is_live)
    console.print(f"\n[bold]Results: {live}/{len(results)} credentials confirmed live[/bold]")

    if output:
        data = [{"type": r.credential_type.value, "result": r.result.value,
                 "details": r.details, "risk": r.risk_level.value,
                 "access_level": r.access_level} for r in results]
        with open(output, "w") as fp:
            _json.dump(data, fp, indent=2)
        console.print(f"[green]Results saved to {output}[/green]")


# =============================================================================
# ORIGIN IP DISCOVERY COMMANDS
# =============================================================================

@cli.command("origin-ip")
@click.argument("domains", nargs=-1, required=True)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--output", "-o", type=click.Path(), help="Save results to JSON file")
@click.pass_context
def origin_ip(ctx, domains, verbose, output):
    """
    Discover real origin IPs behind CDN/WAF (Cloudflare, Akamai, etc.).

    \b
    Uses DNS history, SSL certs, subdomain correlation, mail servers, and more.

    Examples:
        beatrix origin-ip example.com
        beatrix origin-ip example.com target.com -v
    """
    from beatrix.scanners.origin_ip_discovery import run_origin_discovery

    console.print(Panel.fit(
        f"[bold]Domains:[/bold] {', '.join(domains)}\n"
        f"[bold]Verbose:[/bold] {verbose}",
        title="[bold bright_magenta]🎯 Origin IP Discovery[/bold bright_magenta]",
        border_style="magenta",
    ))

    results = asyncio.run(run_origin_discovery(
        domains=list(domains), verbose=verbose,
    ))

    for domain_result in results.get("domains", []):
        domain = domain_result.get("domain", "?")
        cdn = domain_result.get("cdn_detected", "Unknown")
        top_ips = domain_result.get("top_ips", [])

        console.print(f"\n[bold cyan]{domain}[/bold cyan] — CDN: {cdn}")

        if top_ips:
            table = Table(title=f"Origin IPs for {domain}")
            table.add_column("IP", style="bold")
            table.add_column("Confidence")
            table.add_column("Source", style="dim")
            table.add_column("Validated")
            for ip_info in top_ips:
                conf = ip_info.get("confidence", 0) * 100
                validated = "[green]✓[/green]" if ip_info.get("validated") else "[dim]?[/dim]"
                conf_color = "green" if conf >= 70 else "yellow" if conf >= 40 else "red"
                table.add_row(
                    ip_info.get("ip", "?"),
                    f"[{conf_color}]{conf:.0f}%[/{conf_color}]",
                    ip_info.get("source", "unknown"),
                    validated,
                )
            console.print(table)
        else:
            console.print("  [dim]No origin IPs discovered[/dim]")

    if output:
        import json as _json
        with open(output, "w") as fp:
            _json.dump(results, fp, indent=2)
        console.print(f"\n[green]Results saved to {output}[/green]")


# =============================================================================
# POWER INJECTOR COMMANDS
# =============================================================================

@cli.command("inject")
@click.argument("url")
@click.option("--deep", "-d", is_flag=True, help="Enable extended payload sets")
@click.option("--no-waf-bypass", is_flag=True, help="Skip WAF bypass payloads")
@click.option("--types", "-t", multiple=True,
              type=click.Choice(["sqli", "xss", "ssti", "cmdi", "ssrf", "lfi", "nosqli"], case_sensitive=False),
              help="Specific vulnerability types to test (default: all)")
@click.option("--timeout", type=int, default=15, help="Request timeout in seconds")
@click.option("--concurrency", "-c", type=int, default=10, help="Max concurrent requests")
@click.option("--ai", is_flag=True, help="Enable AI false-positive analysis")
@click.option("--output", "-o", type=click.Path(), help="Save findings to JSON file")
@click.pass_context
def inject(ctx, url, deep, no_waf_bypass, types, timeout, concurrency, ai, output):
    """
    Advanced injection scanner with 2000+ payloads (SQLi/XSS/CMDi/SSTI/SSRF/LFI).

    \b
    URL must include parameters, e.g.:
        beatrix inject "https://target.com/page?id=1&name=test"
        beatrix inject "https://target.com/api/search?q=test" --deep --types sqli xss
    """
    from beatrix.scanners.power_injector import PowerInjector, VulnType

    type_map = {
        "sqli": VulnType.SQLI, "xss": VulnType.XSS, "ssti": VulnType.SSTI,
        "cmdi": VulnType.CMDI, "ssrf": VulnType.SSRF, "lfi": VulnType.LFI,
        "nosqli": VulnType.NOSQLI,
    }

    vuln_types = [type_map[t.lower()] for t in types] if types else None

    console.print(Panel.fit(
        f"[bold]Target:[/bold]      {url}\n"
        f"[bold]Deep:[/bold]        {deep}\n"
        f"[bold]WAF Bypass:[/bold]  {not no_waf_bypass}\n"
        f"[bold]Types:[/bold]       {', '.join(types) if types else 'all'}\n"
        f"[bold]Concurrency:[/bold] {concurrency}\n"
        f"[bold]AI:[/bold]          {ai}",
        title="[bold bright_red]💉 PowerInjector[/bold bright_red]",
        border_style="red",
    ))

    injector = PowerInjector(timeout=timeout, max_concurrent=concurrency, use_ai=ai)
    findings = asyncio.run(injector.scan(
        url=url, vuln_types=vuln_types, deep=deep, waf_bypass=not no_waf_bypass,
    ))

    if findings:
        table = Table(title=f"Injection Findings ({len(findings)})")
        table.add_column("Severity", style="bold")
        table.add_column("Type")
        table.add_column("Parameter")
        table.add_column("Technique", style="dim")
        table.add_column("Evidence", max_width=40)
        for f_item in findings:
            sev_color = {"Critical": "red", "High": "bright_red", "Medium": "yellow", "Low": "blue"}.get(f_item.severity, "white")
            table.add_row(
                f"[{sev_color}]{f_item.severity}[/{sev_color}]",
                f_item.vuln_type.value,
                f_item.parameter,
                f_item.technique,
                f_item.evidence[:40],
            )
        console.print(table)
    else:
        console.print("[green]No injection vulnerabilities found.[/green]")

    if output:
        import json as _json
        data = [{"severity": f_item.severity, "type": f_item.vuln_type.value,
                 "url": f_item.url, "parameter": f_item.parameter,
                 "payload": f_item.payload, "evidence": f_item.evidence,
                 "technique": f_item.technique, "confidence": f_item.confidence}
                for f_item in findings]
        with open(output, "w") as fp:
            _json.dump(data, fp, indent=2)
        console.print(f"\n[green]Results saved to {output}[/green]")


# =============================================================================
# POLYGLOT GENERATOR COMMANDS
# =============================================================================

@cli.group("polyglot")
@click.pass_context
def polyglot(ctx):
    """
    Generate XSS polyglot, mXSS, and DOM clobbering payloads.

    \b
    Run 'beatrix help polyglot' for details.
    """
    pass


@polyglot.command("generate")
@click.option("--context", "-c", "xss_context",
              type=click.Choice([
                  "html_text", "html_attr_double", "html_attr_single", "html_attr_unquoted",
                  "script_string_double", "script_string_single", "script_template",
                  "script_block", "url_href", "url_src", "svg_context", "unknown",
              ], case_sensitive=False),
              default="html_text", help="Injection context")
@click.option("--waf", help="Target WAF for specific bypasses (e.g. cloudflare, akamai)")
@click.option("--no-bypass", is_flag=True, help="Exclude filter bypass payloads")
@click.option("--limit", "-n", type=int, help="Limit number of payloads")
@click.pass_context
def polyglot_generate(ctx, xss_context, waf, no_bypass, limit):
    """Generate context-aware XSS payloads."""
    from beatrix.scanners.polyglot_generator import XSSContext, get_xss_payloads

    context_map = {
        "html_text": XSSContext.HTML_TEXT,
        "html_attr_double": XSSContext.HTML_ATTR_DOUBLE,
        "html_attr_single": XSSContext.HTML_ATTR_SINGLE,
        "html_attr_unquoted": XSSContext.HTML_ATTR_UNQUOTED,
        "script_string_double": XSSContext.SCRIPT_STRING_DOUBLE,
        "script_string_single": XSSContext.SCRIPT_STRING_SINGLE,
        "script_template": XSSContext.SCRIPT_TEMPLATE,
        "script_block": XSSContext.SCRIPT_BLOCK,
        "url_href": XSSContext.URL_HREF,
        "url_src": XSSContext.URL_SRC,
        "svg_context": XSSContext.SVG_CONTEXT,
        "unknown": XSSContext.UNKNOWN,
    }

    context_enum = context_map[xss_context.lower()]
    payloads = get_xss_payloads(context=context_enum, include_bypass=not no_bypass, waf=waf)

    if limit:
        payloads = payloads[:limit]

    console.print(Panel.fit(
        f"[bold]Context:[/bold]    {xss_context}\n"
        f"[bold]WAF:[/bold]        {waf or 'generic'}\n"
        f"[bold]Payloads:[/bold]   {len(payloads)}",
        title="[bold bright_green]🧬 Polyglot Generator[/bold bright_green]",
        border_style="green",
    ))

    for i, payload in enumerate(payloads, 1):
        console.print(f"  [dim]{i:3d}.[/dim] {payload}")


@polyglot.command("mxss")
@click.option("--limit", "-n", type=int, help="Limit number of payloads")
@click.pass_context
def polyglot_mxss(ctx, limit):
    """Generate mutation XSS (mXSS) payloads."""
    from beatrix.scanners.polyglot_generator import get_mxss_payloads

    payloads = get_mxss_payloads()
    if limit:
        payloads = payloads[:limit]

    console.print(f"\n[bold]mXSS Payloads ({len(payloads)}):[/bold]\n")
    for i, payload in enumerate(payloads, 1):
        console.print(f"  [dim]{i:3d}.[/dim] {payload}")


@polyglot.command("clobber")
@click.option("--limit", "-n", type=int, help="Limit number of payloads")
@click.pass_context
def polyglot_clobber(ctx, limit):
    """Generate DOM clobbering payloads."""
    from beatrix.scanners.polyglot_generator import get_dom_clobbering_payloads

    payloads = get_dom_clobbering_payloads()
    if limit:
        payloads = payloads[:limit]

    console.print(f"\n[bold]DOM Clobbering Payloads ({len(payloads)}):[/bold]\n")
    for i, item in enumerate(payloads, 1):
        if isinstance(item, dict):
            console.print(f"  [dim]{i:3d}.[/dim] {item.get('payload', item)}")
            if item.get('description'):
                console.print(f"       [dim]{item['description']}[/dim]")
        else:
            console.print(f"  [dim]{i:3d}.[/dim] {item}")


# =============================================================================
# VALIDATE
# =============================================================================

@cli.command("validate")
@click.argument("findings_file", type=click.Path(exists=True))
@click.pass_context
def validate_findings(ctx, findings_file):
    """
    Validate findings from a JSON report file.

    \b
    Run 'beatrix help validate' for details.
    """
    import json as _json

    from beatrix.core.types import Finding, Severity
    from beatrix.validators import ImpactValidator, ReportReadinessGate

    with open(findings_file) as f:
        report = _json.load(f)

    # Support both formats: {"findings": [...]} or bare [...]
    if isinstance(report, list):
        raw_findings = report
    elif isinstance(report, dict):
        raw_findings = report.get("findings", report.get("results", []))
        # If dict has no findings/results key, treat all values that are lists of dicts
        if not raw_findings:
            for v in report.values():
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    raw_findings = v
                    break
    else:
        console.print(f"[red]Error: unexpected JSON format in {findings_file}[/red]")
        sys.exit(1)

    console.print(f"\n[cyan]Validating {len(raw_findings)} findings from {findings_file}[/cyan]\n")

    validator = ImpactValidator()
    gate = ReportReadinessGate()

    submittable = 0
    killed = 0
    needs_work = 0

    for rf in raw_findings:
        # Map confidence string to enum, default tentative
        _conf_str = rf.get("confidence", "tentative")
        try:
            from beatrix.core.types import Confidence as _Conf
            _confidence = _Conf(_conf_str)
        except (ValueError, KeyError):
            _confidence = _Conf.TENTATIVE

        finding = Finding(
            title=rf.get("title", ""),
            description=rf.get("description", ""),
            severity=Severity(rf.get("severity", "info")),
            confidence=_confidence,
            url=rf.get("url", ""),
            parameter=rf.get("parameter"),
            payload=rf.get("payload"),
            evidence=rf.get("evidence"),
            request=rf.get("request"),
            response=rf.get("response"),
            impact=rf.get("impact", ""),
            remediation=rf.get("remediation", ""),
            references=rf.get("references") or [],
            reproduction_steps=rf.get("reproduction_steps") or [],
            poc_curl=rf.get("poc_curl"),
            poc_python=rf.get("poc_python"),
            cwe_id=rf.get("cwe_id"),
            owasp_category=rf.get("owasp_category") or rf.get("owasp"),
            mitre_technique=rf.get("mitre_technique"),
            scanner_module=rf.get("scanner_module", ""),
            validated=rf.get("validated", False),
        )

        impact = validator.validate(finding, None)
        readiness = gate.check(finding)

        if impact.kill_checks:
            console.print(f"  [red]🗑️  KILLED[/red]  {finding.title} — {impact.reason}")
            killed += 1
        elif impact.passed and readiness.ready:
            console.print(f"  [green]✅ READY[/green]  {finding.title} (score: {readiness.score}/100)")
            submittable += 1
        else:
            console.print(f"  [yellow]⚠️  WORK[/yellow]  {finding.title}")
            if not impact.passed:
                console.print(f"           Impact: {impact.reason}")
            for c in readiness.failed_required:
                console.print(f"           ❌ {c.name}: {c.reason}")
            needs_work += 1

    console.print("\n[bold]Summary:[/bold]")
    console.print(f"  ✅ Submittable: {submittable}")
    console.print(f"  ⚠️  Needs work:  {needs_work}")
    console.print(f"  🗑️  Killed:      {killed}")


# =============================================================================
# GHOST — Autonomous AI pentester
# =============================================================================

@cli.command("ghost")
@click.argument("target")
@click.option("--objective", "-o", default="Find all security vulnerabilities",
              help="Investigation objective")
@click.option("--method", "-X", default="GET", help="HTTP method for base request")
@click.option("--header", "-H", multiple=True, help='Add header (format: "Name: Value")')
@click.option("--data", "-d", default="", help="Request body")
@click.option("--max-turns", "-t", type=int, default=30, help="Maximum investigation turns")
@click.option("--model", default="claude-sonnet-4-20250514", help="Claude model to use")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY", help="Anthropic API key")
@click.option("--bedrock/--no-bedrock", default=True, help="Use AWS Bedrock (default) or Anthropic API")
@click.pass_context
def ghost(ctx, target, objective, method, header, data, max_turns, model, api_key, bedrock):
    """
    Launch GHOST autonomous penetration testing agent (legacy).

    \b
    DEPRECATED: superseded by `beatrix ghost2` (or `beatrix hunt --ghost`),
    which runs on openai-agents + LiteLLM with native tool-calling, the full
    scanner arsenal, a Docker sandbox, subagents, and a grounding knowledge
    base. This command is kept for now and will be aliased to ghost2 later.

    \b
    Run 'beatrix help ghost' for details.
    """
    console.print(
        "[yellow]⚠ `beatrix ghost` is deprecated — use `beatrix ghost2` "
        "(or `beatrix hunt --ghost`) for the rebuilt agent.[/yellow]"
    )

    from beatrix.ai.assistant import AIConfig, AIProvider
    from beatrix.ai.ghost import GhostAgent, PrintCallback

    headers = {}
    for h in header:
        if ':' in h:
            name, value = h.split(':', 1)
            headers[name.strip()] = value.strip()

    if bedrock:
        ai_config = AIConfig(
            provider=AIProvider.BEDROCK, model=model,
            max_tokens=8192, temperature=0.3,
        )
    else:
        ai_config = AIConfig(
            provider=AIProvider.ANTHROPIC, api_key=api_key,
            model=model, max_tokens=8192, temperature=0.3,
        )

    console.print(Panel.fit(
        f"[bold]Target:[/bold]    {target}\n"
        f"[bold]Objective:[/bold] {objective}\n"
        f"[bold]Method:[/bold]    {method}\n"
        f"[bold]Max Turns:[/bold] {max_turns}\n"
        f"[bold]Model:[/bold]     {model}\n"
        f"[bold]Provider:[/bold]  {'Bedrock' if bedrock else 'Anthropic'}",
        title="[bold bright_red]👻 GHOST[/bold bright_red]",
        border_style="red",
    ))

    # Validate credentials before launching the agent
    _validate_ai_credentials(ai_config)

    agent = GhostAgent(config=ai_config, callback=PrintCallback(), max_iterations=max_turns)

    try:
        result = asyncio.run(agent.investigate(
            target_url=target, objective=objective,
            method=method, headers=headers, body=data,
        ))

        verdict_color = "red" if result["verdict"] == "VULNERABLE" else "green"
        console.print(f"\n[bold {verdict_color}]Verdict: {result['verdict']}[/bold {verdict_color}]")
        console.print(f"[dim]Iterations: {result['iterations']} | Responses: {result['responses_analyzed']}[/dim]")

        if result["findings"]:
            console.print(f"\n[bold]Findings ({len(result['findings'])}):[/bold]")
            for finding in result["findings"]:
                console.print(f"  {finding.severity.icon} [{finding.severity.color}]{finding.title}[/{finding.severity.color}]")

    except KeyboardInterrupt:
        agent.stop()
        console.print("\n[yellow]Investigation interrupted.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command("ghost2")
@click.argument("target")
@click.option("--objective", "-o", default="Find and validate security vulnerabilities.",
              help="Investigation objective")
@click.option("--header", "-H", multiple=True, help='Add base header (format: "Name: Value")')
@click.option("--model", default=None,
              help="LiteLLM model string (e.g. openai/gpt-4o, openrouter/anthropic/claude-3.7-sonnet). "
                   "Defaults to ai.model from config.yaml / BEATRIX_LLM.")
@click.option("--api-base", default=None, help="Provider API base URL (OpenRouter/Ollama/self-hosted)")
@click.option("--reasoning", type=click.Choice(["minimal", "low", "medium", "high"]), default=None,
              help="Reasoning effort (provider-dependent)")
@click.option("--sandbox", type=click.Choice(["docker", "host", "auto"]), default=None,
              help="Tool execution runtime: docker sandbox, host, or auto (Docker if available)")
@click.option("--allow-host-exec", is_flag=True, default=False,
              help="Permit shell/python_exec on the HOST runtime (unsafe; sandbox is preferred)")
@click.option("--max-turns", "-t", type=int, default=None,
              help="Max root-agent turns (default: unlimited — runs until finish_scan)")
@click.option("--no-persist", is_flag=True, help="Do not save findings to the findings database")
@click.option("--no-auth", is_flag=True, help="Do not auto-load saved auth (auth.yaml / sessions)")
@click.option("--no-web", is_flag=True, help="Disable the live browser dashboard (on by default)")
@click.option("--web-port", type=int, default=8799, help="Port for the live dashboard (default: 8799)")
@click.option("--verbose", "-v", is_flag=True, help="Show tool results and reasoning")
@click.pass_context
def ghost2(ctx, target, objective, header, model, api_base, reasoning, sandbox, allow_host_exec, max_turns, no_persist, no_auth, no_web, web_port, verbose):
    """
    Launch GHOST v2 — the Strix-style autonomous agent (openai-agents + LiteLLM).

    \b
    Works with any LLM provider via LiteLLM. Set the model with --model or
    ai.model in ~/.beatrix/config.yaml, and the key via LLM_API_KEY (or the
    provider-native env var, e.g. OPENAI_API_KEY / OPENROUTER_API_KEY).

    \b
    Examples:
        beatrix ghost2 http://testphp.vulnweb.com/
        beatrix ghost2 https://api.example.com --model openrouter/anthropic/claude-3.7-sonnet
    """
    try:
        from beatrix.ai.ghost2 import GhostV2Config, run_investigation
    except ImportError:
        console.print("[red]GHOST v2 requires the 'agent' extra:[/red]")
        console.print("  [bold]pip install 'beatrix-cli[agent]'[/bold]")
        sys.exit(1)

    base_headers = {}
    for h in header:
        if ':' in h:
            name, value = h.split(':', 1)
            base_headers[name.strip()] = value.strip()

    # ── Auto-load saved auth so the agent runs authenticated ──────────────
    # Only credentials that belong to THIS target's domain are attached — never
    # cross-domain (IDOR slots carry no domain and are deliberately NOT used as
    # base auth, so airbnb cookies can't leak to another host). Sources: the
    # per-target/global block of ~/.beatrix/auth.yaml plus a domain-matched
    # saved session (HAR/cookie import or the `beatrix auth` GUI). -H wins.
    base_cookies: dict = {}
    auth_status = "none"
    if not no_auth:
        try:
            from beatrix.core.auth_config import AuthConfigLoader
            from urllib.parse import urlparse as _up
            import json as _json
            from pathlib import Path as _P

            creds = AuthConfigLoader.load(target=target)
            if creds.cookies or creds.merged_headers():
                base_cookies.update(creds.cookies or {})
                for k, v in creds.merged_headers().items():
                    base_headers.setdefault(k, v)
                auth_status = "auth.yaml"

            # Domain-scoped saved session, matching apex/www variants only.
            host = (_up(target if "://" in target else f"https://{target}").netloc
                    or target).split(":")[0]
            variants = [host, host[4:] if host.startswith("www.") else "www." + host]
            sess_dir = _P.home() / ".beatrix" / "sessions"
            for cand in variants:
                sf = sess_dir / (cand.replace(":", "_").replace("/", "_") + ".json")
                if sf.exists():
                    data = _json.loads(sf.read_text())
                    base_cookies.update(data.get("cookies") or {})
                    for k, v in (data.get("headers") or {}).items():
                        base_headers.setdefault(k, v)
                    if data.get("token"):
                        base_headers.setdefault("Authorization", f"Bearer {data['token']}")
                    auth_status = f"session:{cand}"
                    break
        except Exception as e:  # noqa: BLE001 — auth is best-effort, never fatal
            console.print(f"[yellow]auth: could not load saved credentials ({e})[/yellow]")

    cfg = GhostV2Config.load(
        model=model, api_base=api_base, reasoning_effort=reasoning,
        sandbox=sandbox, allow_host_exec=(allow_host_exec or None), max_turns=max_turns,
    )

    console.print(Panel.fit(
        f"[bold]Target:[/bold]    {target}\n"
        f"[bold]Objective:[/bold] {objective}\n"
        f"[bold]Model:[/bold]     {cfg.model}\n"
        f"[bold]Reasoning:[/bold] {cfg.reasoning_effort or 'default'}\n"
        f"[bold]Sandbox:[/bold]   {cfg.sandbox}"
        + (" [dim](host exec enabled)[/dim]" if cfg.allow_host_exec else "") + "\n"
        f"[bold]Auth:[/bold]      "
        + (f"{auth_status} ({len(base_cookies)} cookies, {len(base_headers)} headers)"
           if auth_status != "none" else "none") + "\n"
        f"[bold]Max Turns:[/bold] {cfg.max_turns if cfg.max_turns else 'unlimited'}",
        title="[bold bright_red]👻 GHOST v2[/bold bright_red]",
        border_style="red",
    ))

    key_hint = cfg.missing_key_message()
    if key_hint:
        console.print(f"[red]{key_hint}[/red]")
        sys.exit(1)

    # ── Live web dashboard (on by default; --no-web to disable) ───────────
    web_server = None
    on_event = None
    if not no_web:
        try:
            from beatrix.cli.ghost_web import GhostWebServer
            web_server = GhostWebServer(
                meta={"target": target, "model": cfg.model,
                      "auth": auth_status, "objective": objective},
                port=web_port,
            )
            web_server.start(open_browser=True)
            on_event = web_server.emit
            console.print(f"[green]📺 Live dashboard:[/green] {web_server.url}")
            if web_server.public_url:
                console.print(f"[green]   Codespaces:[/green] {web_server.public_url}")
        except Exception as e:  # noqa: BLE001 — dashboard is optional, never fatal
            console.print(f"[yellow]Could not start --web dashboard: {e}[/yellow]")

    try:
        result = asyncio.run(run_investigation(
            target, cfg=cfg, objective=objective, base_headers=base_headers,
            base_cookies=base_cookies, console=console, verbose=verbose,
            persist=not no_persist, on_event=on_event,
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Investigation interrupted.[/yellow]")
        if web_server:
            web_server.stop()
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        if web_server:
            web_server.stop()
        sys.exit(1)

    if result.get("hit_turn_limit"):
        console.print(
            f"\n[yellow]Reached the {cfg.max_turns}-turn budget before the agent "
            "called finish_scan; results below are what it gathered. "
            "Raise --max-turns for a longer run.[/yellow]"
        )

    verdict_color = "red" if result["verdict"] == "VULNERABLE" else "green"
    console.print(f"\n[bold {verdict_color}]Verdict: {result['verdict']}[/bold {verdict_color}]")
    console.print(
        f"[dim]Turns budget: {cfg.max_turns if cfg.max_turns else 'unlimited'} | modules used: "
        f"{', '.join(result['modules_run']) or 'none'} | {result['duration_secs']}s[/dim]"
    )
    if result["findings"]:
        console.print(f"\n[bold]Findings ({result['num_findings']}):[/bold]")
        for finding in result["findings"]:
            console.print(f"  {finding.severity.icon} [{finding.severity.color}]{finding.title}[/{finding.severity.color}]")
    if result.get("hunt_id"):
        console.print(f"\n[dim]Saved to findings DB as hunt #{result['hunt_id']} (beatrix findings).[/dim]")
    if result.get("final_output"):
        console.print(Panel(str(result["final_output"]), title="Summary", border_style="dim"))

    # Keep the live dashboard up after the run so the user can scroll back — but
    # only when attached to a real terminal. If output is redirected or piped
    # (e.g. `ghost2 ... > out.txt`, CI), don't block: stop and let the command
    # return so scripts complete.
    if web_server:
        web_server.finish(result)
        interactive = sys.stdout.isatty() or sys.stderr.isatty()
        if interactive:
            console.print(
                f"\n[green]📺 Dashboard still live at {web_server.url}[/green] "
                "[dim](Ctrl-C to close)[/dim]"
            )
            web_server.wait()
        else:
            web_server.stop()


# =============================================================================
# RECON COMMAND
# =============================================================================

@cli.command()
@click.argument("domain")
@click.option("--deep", "-d", is_flag=True, help="Deep scan (check subdomain liveness)")
@click.option("--json-output", "-j", "json_out", is_flag=True, help="Output as JSON")
@click.option("--output", "-o", type=click.Path(), help="Save results to file")
def recon(domain, deep, json_out, output):
    """
    Reconnaissance: subdomain enum, tech detection, JS analysis, endpoint discovery.

    \b
    Run 'beatrix help recon' for details.
    """
    from beatrix.recon import ReconRunner

    console.print(Panel.fit(
        f"[bold]Domain:[/bold] {domain}\n"
        f"[bold]Deep:[/bold]   {deep}",
        title="[bold cyan]🔍 Reconnaissance[/bold cyan]",
        border_style="cyan",
    ))

    runner = ReconRunner(domain, verbose=True)
    result = asyncio.run(runner.run(deep=deep))

    table = Table(title="Recon Results")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="green")
    table.add_row("Subdomains", str(len(result.subdomains)))
    table.add_row("Endpoints", str(len(result.endpoints)))
    table.add_row("JS Files", str(len(result.js_files)))
    table.add_row("Parameters", str(len(result.parameters)))
    table.add_row("Technologies", str(len(result.technologies)))
    table.add_row("Interesting Findings", str(len(result.interesting_findings)))
    if deep:
        table.add_row("Alive Subdomains", str(len(result.alive_subdomains)))
    console.print(table)

    if result.technologies:
        tech_table = Table(title="Technologies Detected")
        tech_table.add_column("Tech", style="yellow")
        tech_table.add_column("Value", style="dim")
        for tech, val in result.technologies.items():
            tech_table.add_row(tech, val)
        console.print(tech_table)

    if result.interesting_findings:
        console.print("\n[bold]Interesting Findings:[/bold]")
        for note in result.interesting_findings:
            console.print(f"  • {note}")

    if json_out or output:
        import json as jsonlib
        data = result.to_dict()
        if output:
            with open(output, "w") as f:
                jsonlib.dump(data, f, indent=2)
            console.print(f"\n[green]Results saved to {output}[/green]")
        if json_out:
            console.print(jsonlib.dumps(data, indent=2))


# =============================================================================
# RAPID COMMAND
# =============================================================================

@cli.command()
@click.option("--targets", "-t", type=click.Path(exists=True), help="File with target domains")
@click.option("--domain", "-d", multiple=True, help="Individual target domain (repeatable)")
@click.option("--quiet", "-q", is_flag=True, help="Suppress verbose output")
@click.option("--output", "-o", type=click.Path(), help="Save findings JSON to file")
def rapid(targets, domain, quiet, output):
    """
    Rapid multi-target sweep: takeover, debug endpoints, CORS.

    \b
    Run 'beatrix help rapid' for details.
    """
    from beatrix.hunters.rapid import RapidHunter

    target_list = list(domain) if domain else None
    if targets:
        with open(targets) as f:
            target_list = [line.strip() for line in f if line.strip()]

    hunter = RapidHunter(targets=target_list, verbose=not quiet)
    findings = asyncio.run(hunter.run())

    console.print(f"\n[bold]Total findings: {len(findings)}[/bold]")
    if findings:
        for f_item in findings:
            sev = f_item.severity.value.upper()
            console.print(f"  [{sev}] {f_item.title}")
            console.print(f"    {f_item.url}")

    if output:
        import json as jsonlib
        data = [{"title": f_item.title, "severity": f_item.severity.value, "url": f_item.url,
                 "evidence": f_item.evidence, "description": f_item.description}
                for f_item in findings]
        with open(output, "w") as fp:
            jsonlib.dump(data, fp, indent=2)
        console.print(f"\n[green]Results saved to {output}[/green]")


# =============================================================================
# HAIKU-HUNT COMMAND
# =============================================================================

@cli.command("haiku-hunt")
@click.argument("target")
@click.option("--no-ai", is_flag=True, help="Disable AI analysis")
@click.option("--deep", "-d", is_flag=True, help="Deep scan")
@click.option("--region", default="us-east-1", help="AWS region for Bedrock")
@click.option("--output", "-o", type=click.Path(), help="Save findings JSON")
def haiku_hunt(target, no_ai, deep, region, output):
    """
    AI-assisted vulnerability hunting using Claude Haiku via Bedrock.

    \b
    Run 'beatrix help haiku-hunt' for details.
    """
    from beatrix.hunters.haiku import HaikuHunter

    console.print(Panel.fit(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]AI:[/bold]     {'Disabled' if no_ai else 'Enabled'}\n"
        f"[bold]Region:[/bold] {region}",
        title="[bold magenta]🤖 Haiku Hunt[/bold magenta]",
        border_style="magenta",
    ))

    # Validate credentials before launching AI-powered hunt
    if not no_ai:
        from beatrix.ai.assistant import AIConfig, AIProvider
        _validate_ai_credentials(AIConfig(provider=AIProvider.BEDROCK, aws_region=region))

    hunter = HaikuHunter(use_ai=not no_ai, region=region)
    findings = asyncio.run(hunter.hunt(target, deep=deep))

    console.print(f"\n[bold]Findings: {len(findings)}[/bold]")
    for f_item in findings:
        sev = f_item.severity.value.upper()
        conf = f_item.confidence.value if hasattr(f_item, 'confidence') else "?"
        console.print(f"  [{sev}|{conf}] {f_item.title}")

    if output:
        import json as jsonlib
        data = [{"title": f_item.title, "severity": f_item.severity.value, "url": f_item.url,
                 "evidence": f_item.evidence or ""}
                for f_item in findings]
        with open(output, "w") as fp:
            jsonlib.dump(data, fp, indent=2)
        console.print(f"\n[green]Results saved to {output}[/green]")


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    """Main entry point"""
    cli()


if __name__ == "__main__":
    main()
