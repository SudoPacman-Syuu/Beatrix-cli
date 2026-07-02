"""
BEATRIX External Tool Integrations

Subprocess wrappers for all external security tools in the arsenal.
Each wrapper follows the same pattern:
  - _find_binary() → locate on PATH or common locations
  - available property → bool
  - async method(s) → run the tool, parse output, return structured data

All wrappers gracefully return empty results if the tool is not installed.

Tools covered:
  Recon:        katana, amass, gospider, hakrawler, gau, whatweb, webanalyze, dirsearch
  Exploitation: sqlmap, dalfox, commix
  Auth:         jwt_tool
  Post-Exploit: msfconsole (resource file generation)
"""

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# =============================================================================
# BASE CLASS
# =============================================================================

class ExternalTool:
    """Base class for external tool wrappers."""

    BINARY_NAME: str = ""
    COMMON_PATHS: List[str] = []

    # Default kill chain phase for output organization (override in subclasses)
    DEFAULT_PHASE: int = 1

    def __init__(self, timeout: int = 120):
        self.path = self._find_binary()
        self.timeout = timeout
        self.output_manager = None  # Set by ExternalToolkit when available

    def _find_binary(self) -> Optional[str]:
        """Find the tool binary on PATH or common locations."""
        path = shutil.which(self.BINARY_NAME)
        if path:
            return path
        for candidate in self.COMMON_PATHS + [
            f"/usr/bin/{self.BINARY_NAME}",
            f"/usr/local/bin/{self.BINARY_NAME}",
            str(Path.home() / f"go/bin/{self.BINARY_NAME}"),
            str(Path.home() / f".local/bin/{self.BINARY_NAME}"),
        ]:
            if Path(candidate).exists():
                return candidate
        return None

    @property
    def available(self) -> bool:
        return self.path is not None

    @property
    def _verbose_mode(self) -> bool:
        """True when -vvv is active (Python logging at DEBUG level)."""
        return logging.getLogger(f"beatrix.tools.{self.BINARY_NAME}").isEnabledFor(logging.DEBUG)

    async def _run(self, cmd: List[str], stdin: Optional[str] = None,
                   output_manager=None, tool_name: str = "",
                   phase: int = 0) -> Optional[str]:
        """Run a command and return stdout, or None on failure/timeout.

        When the root logger is at DEBUG level (-vvv), streams each output line
        in real-time via the tool's own logger (beatrix.tools.<name>).
        Raw output is automatically saved when an output_manager is available.
        """
        if not self.available:
            return None
        _om = output_manager or self.output_manager
        _phase = phase if phase else self.DEFAULT_PHASE
        _log = logging.getLogger(f"beatrix.tools.{self.BINARY_NAME}")
        _streaming = _log.isEnabledFor(logging.DEBUG)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin else None,
            )

            if _streaming:
                _log.debug("▶ %s", " ".join(str(a) for a in cmd))
                stdout_lines: List[str] = []
                stderr_lines: List[str] = []

                async def _drain(stream, lines, tag):
                    async for raw in stream:
                        text = raw.decode("utf-8", errors="replace").rstrip()
                        if text:
                            _log.debug("[%s] %s", tag, text)
                            lines.append(text)

                try:
                    if stdin:
                        process.stdin.write(stdin.encode())
                        await process.stdin.drain()
                        process.stdin.close()
                    await asyncio.wait_for(
                        asyncio.gather(
                            _drain(process.stdout, stdout_lines, "out"),
                            _drain(process.stderr, stderr_lines, "err"),
                        ),
                        timeout=self.timeout,
                    )
                    await process.wait()
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    return None
                except asyncio.CancelledError:
                    process.kill()
                    await process.wait()
                    raise

                result = "\n".join(stdout_lines)
            else:
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(input=stdin.encode() if stdin else None),
                        timeout=self.timeout,
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    return None
                except asyncio.CancelledError:
                    process.kill()
                    await process.wait()
                    raise

                if process.returncode not in (0, None):
                    stderr_text = stderr.decode("utf-8", errors="replace").strip() if stderr else ""
                    if stderr_text:
                        logging.getLogger("beatrix.external_tools").debug(
                            "%s exited %s: %s", cmd[0], process.returncode, stderr_text[:500]
                        )

                result = stdout.decode("utf-8", errors="replace").strip()

            if _om and result:
                name = tool_name or self.BINARY_NAME
                try:
                    _om.write_tool_output(name, result, phase=_phase)
                except Exception:
                    pass

            return result
        except Exception:
            return None

    def _parse_lines(self, output: Optional[str]) -> List[str]:
        """Parse output into non-empty lines."""
        if not output:
            return []
        return [line.strip() for line in output.splitlines() if line.strip()]


# =============================================================================
# RECON TOOLS
# =============================================================================

class KatanaRunner(ExternalTool):
    """
    Katana — Deep crawling and JavaScript endpoint extraction.

    Crawls with headless browser support, extracts endpoints from JS,
    follows redirects, handles SPAs better than simple HTTP crawlers.

    Install: go install github.com/projectdiscovery/katana/cmd/katana@latest
    """

    BINARY_NAME = "katana"

    async def crawl(self, url: str, depth: int = 3, js_crawl: bool = True,
                   custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Crawl a target and return discovered URLs, JS endpoints, and forms.

        Args:
            custom_headers: Optional dict of HTTP headers to send on every
                request (e.g. {"Cookie": "session=abc"} for authenticated crawling).

        Returns:
            {urls: [...], js_urls: [...], form_urls: [...]}
        """
        cmd = [
            self.path,
            "-u", url,
            "-d", str(depth),
            "-timeout", "10",    # Per-request timeout
        ]
        if not self._verbose_mode:
            cmd.extend(["-silent", "-nc"])
        if js_crawl:
            cmd.extend(["-jc"])  # JavaScript crawling
        if custom_headers:
            for key, value in custom_headers.items():
                cmd.extend(["-H", f"{key}: {value}"])

        output = await self._run(cmd)
        lines = self._parse_lines(output)

        urls = set()
        js_urls = set()
        form_urls = set()

        for line in lines:
            line = line.strip()
            if not line or not line.startswith("http"):
                continue
            urls.add(line)
            if any(line.endswith(ext) for ext in (".js", ".mjs")) or ".js?" in line:
                js_urls.add(line)
            if any(kw in line.lower() for kw in ("login", "register", "submit", "form")):
                form_urls.add(line)

        return {
            "urls": sorted(urls),
            "js_urls": sorted(js_urls),
            "form_urls": sorted(form_urls),
        }


class AmassRunner(ExternalTool):
    """
    Amass — Advanced subdomain enumeration and attack surface mapping.

    Uses passive and active techniques across 50+ data sources.

    Install: go install github.com/owasp-amass/amass/v4/...@master
    """

    BINARY_NAME = "amass"

    def __init__(self, timeout: int = 180):
        super().__init__(timeout)

    async def enumerate(self, domain: str, passive: bool = True) -> List[str]:
        """
        Enumerate subdomains for a domain.

        Args:
            domain: Target domain (e.g., "example.com")
            passive: If True, only passive enumeration (faster, stealthier)

        Returns:
            List of discovered subdomains
        """
        if "://" in domain:
            domain = domain.split("://", 1)[1]
        domain = domain.split("/")[0].split(":")[0]

        cmd = [
            self.path,
            "enum",
            "-d", domain,
            "-timeout", "3",  # minutes
        ]
        if passive:
            cmd.append("-passive")
        if self._verbose_mode:
            cmd.append("-v")

        output = await self._run(cmd)
        subdomains = []
        for line in self._parse_lines(output):
            sub = line.strip().lower()
            if sub and sub.endswith(domain):
                subdomains.append(sub)

        return sorted(set(subdomains))


class GospiderRunner(ExternalTool):
    """
    Gospider — Fast web spidering and URL discovery.

    High-performance Go-based spider that discovers URLs, endpoints,
    subdomains, and interesting files.

    Install: go install github.com/jaeles-project/gospider@latest
    """

    BINARY_NAME = "gospider"

    async def spider(self, url: str, depth: int = 2,
                     custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Spider a target and return discovered assets.

        Args:
            custom_headers: Optional dict of HTTP headers to send on every
                request (e.g. {"Cookie": "session=abc"} for authenticated crawling).

        Returns:
            {urls: [...], subdomains: [...], js_files: [...], forms: [...]}
        """
        cmd = [
            self.path,
            "-s", url,
            "-d", str(depth),
            "--no-redirect",
            "-t", "5",       # Threads
            "--timeout", "10",
        ]
        if not self._verbose_mode:
            cmd.append("-q")
        if custom_headers:
            for key, value in custom_headers.items():
                cmd.extend(["-H", f"{key}: {value}"])

        output = await self._run(cmd)
        urls = set()
        subdomains = set()
        js_files = set()
        forms = set()

        base_domain = urlparse(url).netloc

        for line in self._parse_lines(output):
            # gospider output format: [type] - URL
            parts = line.split(" - ", 1)
            if len(parts) != 2:
                # Might just be a URL
                if line.startswith("http"):
                    urls.add(line)
                continue

            tag, value = parts[0].strip(), parts[1].strip()
            tag_lower = tag.lower()

            if value.startswith("http"):
                urls.add(value)
                parsed = urlparse(value)
                if parsed.netloc and parsed.netloc != base_domain:
                    subdomains.add(parsed.netloc)
                if value.endswith(".js") or ".js?" in value:
                    js_files.add(value)
                if "form" in tag_lower:
                    forms.add(value)

        return {
            "urls": sorted(urls),
            "subdomains": sorted(subdomains),
            "js_files": sorted(js_files),
            "forms": sorted(forms),
        }


class HakrawlerRunner(ExternalTool):
    """
    Hakrawler — Web crawler for discovering endpoints and assets.

    Simple, fast crawler that reads URLs from stdin and outputs
    discovered URLs including from JavaScript and forms.

    Install: go install github.com/hakluke/hakrawler@latest
    """

    BINARY_NAME = "hakrawler"

    async def crawl(self, url: str, depth: int = 2) -> List[str]:
        """
        Crawl a target URL and return discovered URLs.

        Returns:
            List of discovered URLs
        """
        cmd = [
            self.path,
            "-d", str(depth),
            "-t", "5",          # Threads
            "-timeout", "10",   # Request timeout
            "-subs",            # Include subdomains
        ]

        output = await self._run(cmd, stdin=url)
        urls = set()
        for line in self._parse_lines(output):
            if line.startswith("http"):
                urls.add(line)
        return sorted(urls)


class GauRunner(ExternalTool):
    """
    GAU — Fetch known URLs from AlienVault's OTX, Wayback Machine, and Common Crawl.

    Pulls historical URLs that may no longer be linked but are still live.
    Excellent for finding forgotten endpoints, old API versions, debug pages.

    Install: go install github.com/lc/gau/v2/cmd/gau@latest
    """

    BINARY_NAME = "gau"

    async def fetch_urls(self, domain: str, subs: bool = True) -> List[str]:
        """
        Fetch known URLs for a domain from passive sources.

        Args:
            domain: Target domain
            subs: Include subdomains

        Returns:
            List of historical URLs
        """
        if "://" in domain:
            domain = domain.split("://", 1)[1]
        domain = domain.split("/")[0].split(":")[0]

        cmd = [self.path]
        if subs:
            cmd.append("--subs")
        cmd.extend(["--threads", "3", "--timeout", "30"])

        output = await self._run(cmd, stdin=domain)

        urls = set()
        for line in self._parse_lines(output):
            if line.startswith("http"):
                # Filter out obvious junk
                if not any(ext in line.lower() for ext in [
                    ".png", ".jpg", ".gif", ".svg", ".ico", ".css",
                    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
                ]):
                    urls.add(line)

        return sorted(urls)


class WhatwebRunner(ExternalTool):
    """
    WhatWeb — Technology fingerprinting and version detection.

    Identifies web technologies, frameworks, CMS platforms, JS libraries,
    server software, and much more with 1800+ plugins.

    Install: install.sh clones from source to ~/.local/share/whatweb/
    """

    BINARY_NAME = "whatweb"

    def _find_binary(self) -> Optional[str]:
        """Prefer source-installed whatweb over the apt package.

        Apt-installed /usr/bin/whatweb breaks under RVM/rbenv because its
        $LOAD_PATH.unshift(__dir__) adds /usr/bin, but whatweb.rb lives in
        the system Ruby vendor path that RVM's Ruby doesn't load.  The source
        install keeps whatweb.rb alongside the binary so __dir__ resolves
        correctly regardless of which Ruby is active.
        """
        import subprocess as _sp
        preferred = [
            str(Path.home() / ".local/share/whatweb/whatweb"),
            str(Path.home() / ".local/bin/whatweb"),
        ]
        for p in preferred:
            if Path(p).exists():
                try:
                    if _sp.run([p, "--version"], capture_output=True, timeout=5).returncode == 0:
                        return p
                except Exception:
                    pass
        # Fall back to PATH, but verify the binary actually loads correctly.
        system = shutil.which(self.BINARY_NAME)
        if system:
            try:
                if _sp.run([system, "--version"], capture_output=True, timeout=5).returncode == 0:
                    return system
            except Exception:
                pass
        return None

    async def fingerprint(self, url: str) -> Dict[str, str]:
        """
        Fingerprint technologies on a URL.

        Returns:
            Dict of technology_name → version/detail
        """
        cmd = [
            self.path,
            "--log-json=-",     # JSON output to stdout
            "--max-redirects=3",
            "--open-timeout=10",
            "--read-timeout=15",
            url,
        ]
        if not self._verbose_mode:
            cmd.insert(1, "-q")

        output = await self._run(cmd)
        techs: Dict[str, str] = {}

        if not output:
            return techs

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                plugins = data.get("plugins", {})
                for name, info in plugins.items():
                    if name in ("IP", "Country", "HTTPServer"):
                        continue
                    version = ""
                    if isinstance(info, dict):
                        ver_list = info.get("version", [])
                        if ver_list:
                            version = ver_list[0] if isinstance(ver_list, list) else str(ver_list)
                        string_list = info.get("string", [])
                        if not version and string_list:
                            version = string_list[0] if isinstance(string_list, list) else str(string_list)
                    techs[name] = version
            except (json.JSONDecodeError, TypeError):
                continue

        return techs


class WebanalyzeRunner(ExternalTool):
    """
    Webanalyze — Wappalyzer-based technology fingerprinting (Go CLI).

    Uses the Wappalyzer fingerprint database to identify technologies.

    Install: go install github.com/rverton/webanalyze/cmd/webanalyze@latest
             install.sh also downloads technologies.json to ~/.local/share/webanalyze/
    """

    BINARY_NAME = "webanalyze"
    # technologies.json is downloaded here by install.sh; webanalyze fails without it.
    _APPS_PATH: Path = Path.home() / ".local/share/webanalyze/technologies.json"

    async def fingerprint(self, url: str) -> Dict[str, str]:
        """
        Fingerprint technologies on a URL.

        Returns:
            Dict of technology_name → version/category
        """
        if not self._APPS_PATH.exists():
            _log = logging.getLogger("beatrix.tools.webanalyze")
            _log.warning("technologies.json not found at %s — re-run install.sh to fix", self._APPS_PATH)
            return {}

        cmd = [
            self.path,
            "-host", url,
            "-crawl", "1",
            "-silent",
            "-apps", str(self._APPS_PATH),
        ]

        output = await self._run(cmd)
        techs: Dict[str, str] = {}

        if not output:
            return techs

        for line in self._parse_lines(output):
            # webanalyze output is typically: URL,tech_name,version,categories
            parts = line.split(",")
            if len(parts) >= 2:
                name = parts[1].strip()
                version = parts[2].strip() if len(parts) > 2 else ""
                if name:
                    techs[name] = version
            elif line and not line.startswith("http"):
                # Might just be tech name on its own line
                techs[line.strip()] = ""

        return techs


class DirsearchRunner(ExternalTool):
    """
    Dirsearch — Web path scanner and directory brute-forcing.

    Discovers hidden directories, files, and endpoints using wordlists.

    Install: pip install dirsearch
    """

    BINARY_NAME = "dirsearch"

    async def scan(self, url: str, extensions: str = "php,asp,aspx,jsp,html,js,json") -> Dict[str, Any]:
        """
        Run directory brute-force against a target.

        Returns:
            {found: [{path, status, size}, ...], total_found: int}
        """
        outfile = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        outfile.close()

        try:
            cmd = [
                self.path,
                "-u", url,
                "-e", extensions,
                "--format=json",
                "-o", outfile.name,
                "-t", "10",             # Threads
                "--timeout=10",
                "--retries=1",
                "--random-agent",
                "--exclude-status=404,403,500,502,503",
            ]
            if not self._verbose_mode:
                cmd.insert(3, "-q")

            await self._run(cmd)

            results = []
            try:
                with open(outfile.name, "r") as f:
                    data = json.load(f)

                # dirsearch JSON format varies by version:
                #   v0.4.x: {"results": {"https://target/": [entries...]}}
                #   v0.4.3+: {"results": [entries...]}
                #   Some versions: bare list [entries...]
                if isinstance(data, dict):
                    raw_results = data.get("results", [])
                    if isinstance(raw_results, dict):
                        # Keyed by target URL
                        for target_url, entries in raw_results.items():
                            if isinstance(entries, list):
                                for entry in entries:
                                    results.append({
                                        "path": entry.get("path", ""),
                                        "status": entry.get("status", 0),
                                        "size": entry.get("content-length", 0),
                                        "redirect": entry.get("redirect", ""),
                                    })
                    elif isinstance(raw_results, list):
                        # Flat list of entries
                        for entry in raw_results:
                            results.append({
                                "path": entry.get("path", entry.get("url", "")),
                                "status": entry.get("status", 0),
                                "size": entry.get("content-length", entry.get("size", 0)),
                                "redirect": entry.get("redirect", ""),
                            })
                elif isinstance(data, list):
                    for entry in data:
                        results.append({
                            "path": entry.get("path", entry.get("url", "")),
                            "status": entry.get("status", 0),
                            "size": entry.get("content-length", entry.get("size", 0)),
                        })
            except (json.JSONDecodeError, FileNotFoundError):
                pass

            return {"found": results, "total_found": len(results)}
        finally:
            try:
                os.unlink(outfile.name)
            except OSError:
                pass


# =============================================================================
# EXPLOITATION TOOLS
# =============================================================================

class SqlmapRunner(ExternalTool):
    """
    sqlmap — Automated SQL injection detection and exploitation.

    Takes confirmed or suspected SQLi insertion points from the injection
    scanner and performs deep exploitation: DB enumeration, data extraction,
    OS shell, file read/write.

    Install: sudo pacman -S sqlmap  (or apt/dnf equivalent)
    """

    BINARY_NAME = "sqlmap"
    DEFAULT_PHASE = 4

    async def exploit(
        self,
        url: str,
        param: Optional[str] = None,
        method: str = "GET",
        data: Optional[str] = None,
        level: int = 2,
        risk: int = 1,
        techniques: str = "BEUSTQ",
    ) -> Dict[str, Any]:
        """
        Run sqlmap exploitation against a confirmed SQLi point.

        Args:
            url: Vulnerable URL (with params for GET)
            param: Specific parameter to test (optional)
            method: HTTP method
            data: POST data string (for POST requests)
            level: sqlmap level (1-5)
            risk: sqlmap risk (1-3)
            techniques: BEUSTQ technique string

        Returns:
            {vulnerable: bool, dbms: str, databases: [...], tables: [...],
             injection_type: str, output: str}
        """
        outdir = tempfile.mkdtemp(prefix="beatrix_sqlmap_")

        try:
            cmd = [
                self.path,
                "-u", url,
                "--batch",              # Non-interactive
                "--level", str(level),
                "--risk", str(risk),
                "--technique", techniques,
                "--output-dir", outdir,
                "--threads=3",
                "--timeout=15",
                "--retries=1",
                "--smart",              # Only test params with heuristic indicators
                "--tamper=space2comment", # Basic WAF bypass
            ]

            if param:
                cmd.extend(["-p", param])
            if data:
                cmd.extend(["--data", data])
                cmd.extend(["--method", method])

            # Add enumeration flags
            cmd.extend([
                "--dbs",           # Enumerate databases
                "--current-db",    # Current database
                "--current-user",  # Current user
                "--is-dba",        # Check DBA privileges
            ])

            output = await self._run(cmd)

            result = {
                "vulnerable": False,
                "dbms": "",
                "databases": [],
                "current_db": "",
                "current_user": "",
                "is_dba": False,
                "injection_type": "",
                "output": output or "",
            }

            if not output:
                return result

            # Parse sqlmap output — check for genuine confirmation,
            # not negative messages like "do not appear to be injectable"
            out_lower = output.lower()
            has_positive = (
                "is vulnerable" in output
                or re.search(r"parameter ['\"]?[^'\"]+['\"]? is injectable", out_lower)
                or "injection point" in out_lower
                or "confirmed" in out_lower and "type:" in out_lower
            )
            has_negative = (
                "do not appear to be injectable" in out_lower
                or "might not be injectable" in out_lower
                or "not injectable" in out_lower
            )
            # Only mark vulnerable when sqlmap positively confirmed it
            # and didn't ultimately conclude non-injectable
            if has_positive and not has_negative:
                result["vulnerable"] = True

            # Extract DBMS
            dbms_match = re.search(r"back-end DBMS:\s*(.+?)(?:\n|$)", output)
            if dbms_match:
                result["dbms"] = dbms_match.group(1).strip()

            # Extract databases
            db_section = re.search(r"available databases.*?:\s*\n((?:\[\*\]\s+.+\n)+)", output)
            if db_section:
                for db_match in re.finditer(r"\[\*\]\s+(.+)", db_section.group(1)):
                    result["databases"].append(db_match.group(1).strip())

            # Extract current DB
            cdb_match = re.search(r"current database:\s*['\"]?(\w+)['\"]?", output)
            if cdb_match:
                result["current_db"] = cdb_match.group(1)

            # Extract current user
            cuser_match = re.search(r"current user:\s*['\"]?(.+?)['\"]?(?:\n|$)", output)
            if cuser_match:
                result["current_user"] = cuser_match.group(1).strip()

            # DBA check
            if "current user is DBA: True" in output:
                result["is_dba"] = True

            # Injection type
            inj_match = re.search(r"Type:\s*(.+?)(?:\n|$)", output)
            if inj_match:
                result["injection_type"] = inj_match.group(1).strip()

            return result

        finally:
            # Cleanup
            try:
                import shutil as _shutil
                _shutil.rmtree(outdir, ignore_errors=True)
            except Exception:
                pass


class DalfoxRunner(ExternalTool):
    """
    Dalfox — Parameter analysis and XSS scanning.

    Advanced XSS scanner with DOM analysis, WAF bypass, and
    blind XSS support. Validates XSS findings from the injection scanner.

    Install: go install github.com/hahwul/dalfox/v2@latest
    """

    BINARY_NAME = "dalfox"
    DEFAULT_PHASE = 4

    async def scan(self, url: str, param: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan a URL for XSS vulnerabilities.

        Args:
            url: Target URL with parameters
            param: Specific parameter to test (optional)

        Returns:
            List of {url, param, payload, type, severity} dicts
        """
        cmd = [
            self.path,
            "url", url,
            "--no-color",
            "--format", "json",
            "--timeout", "10",
            "--delay", "100",    # ms between requests
            "--waf-evasion",
        ]
        if not self._verbose_mode:
            cmd.insert(2, "--silence")

        if param:
            cmd.extend(["-p", param])

        output = await self._run(cmd)
        findings = []

        if not output:
            return findings

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, dict) and data.get("type"):
                    findings.append({
                        "url": data.get("data", url),
                        "param": data.get("param", param or ""),
                        "payload": data.get("payload", ""),
                        "type": data.get("type", ""),
                        "severity": data.get("severity", "medium"),
                        "evidence": data.get("evidence", ""),
                    })
            except json.JSONDecodeError:
                # Plain text format: [POC][G][VERIFY] URL
                if "[POC]" in line or "[VULN]" in line:
                    # Extract URL from the line
                    url_match = re.search(r"(https?://\S+)", line)
                    if url_match:
                        findings.append({
                            "url": url_match.group(1),
                            "param": param or "",
                            "payload": "",
                            "type": "reflected" if "Reflected" in line else "stored",
                            "severity": "high" if "[VULN]" in line else "medium",
                            "evidence": line,
                        })

        return findings


class CommixRunner(ExternalTool):
    """
    Commix — Automated command injection exploitation.

    Tests for OS command injection with multiple techniques:
    classic, eval-based, time-based, file-based.

    Install: pip install commix
    """

    BINARY_NAME = "commix"
    DEFAULT_PHASE = 4

    async def exploit(
        self,
        url: str,
        param: Optional[str] = None,
        data: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Test for command injection vulnerabilities.

        Returns:
            {vulnerable: bool, technique: str, os: str, output: str}
        """
        outdir = tempfile.mkdtemp(prefix="beatrix_commix_")

        try:
            cmd = [
                self.path,
                "--url", url,
                "--batch",
                "--output-dir", outdir,
                "--timeout=15",
                "--retries=1",
            ]

            if param:
                cmd.extend(["-p", param])
            if data:
                cmd.extend(["--data", data])

            output = await self._run(cmd)

            result = {
                "vulnerable": False,
                "technique": "",
                "os": "",
                "output": output or "",
            }

            if not output:
                return result

            if "is injectable" in output.lower() or "command injection" in output.lower():
                result["vulnerable"] = True

            tech_match = re.search(r"technique:\s*(.+?)(?:\n|$)", output, re.I)
            if tech_match:
                result["technique"] = tech_match.group(1).strip()

            os_match = re.search(r"operating system:\s*(.+?)(?:\n|$)", output, re.I)
            if os_match:
                result["os"] = os_match.group(1).strip()

            return result

        finally:
            try:
                import shutil as _shutil
                _shutil.rmtree(outdir, ignore_errors=True)
            except Exception:
                pass


# =============================================================================
# AUTH TOOLS
# =============================================================================

class JwtToolRunner(ExternalTool):
    """
    jwt_tool — JSON Web Token manipulation and vulnerability testing.

    Tests for: algorithm confusion, key brute force, claim tampering,
    blank password, CVE exploits, and more.

    Install: via install.sh or manually from https://github.com/ticarpi/jwt_tool
    """

    BINARY_NAME = "jwt_tool"
    DEFAULT_PHASE = 4
    COMMON_PATHS = [
        str(Path.home() / ".local/bin/jwt_tool"),
        str(Path.home() / ".local/share/jwt_tool/jwt_tool.py"),
    ]

    async def analyze(self, token: str) -> Dict[str, Any]:
        """
        Analyze a JWT token for vulnerabilities.

        Args:
            token: The JWT string (eyJ...)

        Returns:
            {vulnerabilities: [...], header: {}, payload: {}, output: str}
        """
        cmd = [
            self.path,
            token,
            "-M", "at",     # All tests mode
            "-np",           # No proxy
        ]

        output = await self._run(cmd)

        result = {
            "vulnerabilities": [],
            "header": {},
            "payload": {},
            "output": output or "",
        }

        if not output:
            return result

        # Parse vulnerabilities from jwt_tool output
        vuln_patterns = [
            (r"\[!\]\s*(.+?none.+?)(?:\n|$)", "Algorithm None Attack"),
            (r"\[!\]\s*(.+?blank password.+?)(?:\n|$)", "Blank Password"),
            (r"\[!\]\s*(.+?key confusion.+?)(?:\n|$)", "Key Confusion"),
            (r"\[\+\]\s*(.+?FOUND.+?)(?:\n|$)", "Weak Secret Found"),
            (r"\[!\]\s*(.+?CVE.+?)(?:\n|$)", "Known CVE"),
            (r"\[\+\]\s*(.+?crack.+?)(?:\n|$)", "Secret Cracked"),
        ]

        for pattern, vuln_type in vuln_patterns:
            for match in re.finditer(pattern, output, re.I):
                result["vulnerabilities"].append({
                    "type": vuln_type,
                    "detail": match.group(1).strip(),
                })

        return result

    async def tamper(self, token: str, claim: str, value: str) -> Optional[str]:
        """
        Tamper with a JWT claim (for PoC generation).

        Args:
            token: Original JWT
            claim: Claim to modify (e.g., "role")
            value: New value

        Returns:
            Tampered JWT string, or None on failure
        """
        cmd = [
            self.path,
            token,
            "-T",           # Tamper mode
            "-np",
            "-I",           # Inject claim
            "-pc", claim,
            "-pv", value,
        ]

        output = await self._run(cmd)
        if not output:
            return None

        # Extract tampered token from output
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("eyJ") and line.count(".") == 2:
                return line

        return None


# =============================================================================
# POST-EXPLOITATION
# =============================================================================

class MetasploitRunner(ExternalTool):
    """
    Metasploit Framework — PoC resource file generation.

    Rather than running msfconsole interactively (slow, requires DB),
    this generates .rc resource files that can be loaded with:
        msfconsole -r beatrix_exploit.rc

    For automated exploitation, it uses msfconsole's -x flag for
    single-shot commands when appropriate.

    Install: via install.sh or https://metasploit.com/
    """

    BINARY_NAME = "msfconsole"
    DEFAULT_PHASE = 5

    def generate_resource_file(
        self,
        exploit_module: str,
        target_host: str,
        target_port: int = 443,
        use_ssl: bool = True,
        payload: str = "",
        options: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Generate an .rc resource file for msfconsole.

        Args:
            exploit_module: Metasploit module path (e.g., "exploit/multi/http/apache_struts2_rest_xstream")
            target_host: Target IP/hostname
            target_port: Target port
            payload: Payload module (e.g., "cmd/unix/reverse_bash")
            options: Additional module options

        Returns:
            Resource file content as string
        """
        lines = [
            "# Beatrix Auto-Generated Metasploit Resource File",
            f"# Target: {target_host}:{target_port}",
            f"# Module: {exploit_module}",
            "#",
            "# Usage: msfconsole -r <this_file>.rc",
            "",
            f"use {exploit_module}",
            f"set RHOSTS {target_host}",
            f"set RPORT {target_port}",
        ]

        if payload:
            lines.append(f"set PAYLOAD {payload}")

        if options:
            for key, value in options.items():
                lines.append(f"set {key} {value}")

        if use_ssl:
            lines.append("set SSL true")

        lines.extend([
            "",
            "# Validate settings",
            "show options",
            "",
            "# Execute (check first, then exploit)",
            "check",
            "exploit -j",
            "",
        ])

        return "\n".join(lines)

    def generate_exploit_rc(self, finding_type: str, target: str, evidence: Dict) -> Optional[str]:
        """
        Generate a Metasploit RC file based on a vulnerability finding.

        Maps common vulnerability types to relevant Metasploit modules.

        Args:
            finding_type: Type of vulnerability (e.g., "sqli", "rce", "ssti")
            target: Target host
            evidence: Evidence dict from the finding

        Returns:
            Resource file content, or None if no applicable module
        """
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"

        module_map = {
            "sqli": [
                ("auxiliary/scanner/http/sql_injection", {}),
            ],
            "rce": [
                ("exploit/multi/http/apache_struts2_content_type_ognl", {}),
                ("exploit/multi/http/apache_struts2_rest_xstream", {}),
            ],
            "ssti": [
                ("exploit/multi/http/jinja2_template_injection", {}),
            ],
            "deserialization": [
                ("exploit/multi/misc/java_rmi_server", {}),
                ("exploit/multi/http/apache_commons_text4shell", {}),
            ],
            "xxe": [
                ("auxiliary/scanner/http/xxe_injection", {}),
            ],
            "file_upload": [
                ("exploit/multi/http/wp_file_manager_rce", {}),
            ],
        }

        modules = module_map.get(finding_type)
        if not modules:
            return None

        # Use first applicable module
        module_path, extra_opts = modules[0]
        return self.generate_resource_file(
            exploit_module=module_path,
            target_host=host,
            target_port=port,
            use_ssl=use_ssl,
            options=extra_opts,
        )

    async def search_modules(self, query: str) -> List[str]:
        """
        Search for Metasploit modules matching a query.

        Args:
            query: Search term (e.g., "struts", "wordpress", "sqli")

        Returns:
            List of matching module paths
        """
        cmd = [
            self.path,
            "-q",                    # Quiet
            "-x", f"search {query}; exit",
        ]

        output = await self._run(cmd)
        modules = []

        if not output:
            return modules

        for line in output.splitlines():
            line = line.strip()
            # Metasploit search output lines contain module paths
            for prefix in ("exploit/", "auxiliary/", "post/", "payload/"):
                if prefix in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith(prefix):
                            modules.append(part)
                            break

        return modules


# =============================================================================
# RECON TOOLS (continued)
# =============================================================================

class KiterRunnerRunner(ExternalTool):
    """
    Kiterunner — API endpoint discovery via route-aware bruteforcing.

    Uses real-world API route collections (assetnote wordlists) to discover
    REST and GraphQL endpoints that generic directory busters miss entirely.
    Understands API path patterns, versioning (/v1/, /v2/), and HTTP methods.

    Install: go install github.com/assetnote/kiterunner/cmd/kr@latest
    Wordlists: https://wordlists.assetnote.io/ (routes-small.kite, etc.)
    """

    BINARY_NAME = "kr"
    DEFAULT_PHASE = 1

    # Default wordlist locations that install.sh places kite files
    _WORDLIST_PATHS = [
        str(Path.home() / ".local/share/kiterunner/routes-small.kite"),
        str(Path.home() / ".local/share/kiterunner/routes-large.kite"),
        "/usr/share/kiterunner/routes-small.kite",
    ]

    def _find_wordlist(self) -> Optional[str]:
        for p in self._WORDLIST_PATHS:
            if Path(p).exists():
                return p
        return None

    async def scan(
        self,
        url: str,
        concurrency: int = 50,
        timeout: int = 3,
        fail_status_codes: str = "400,401,404,405,501,502,503",
    ) -> Dict[str, Any]:
        """
        Brute-force API routes against a target.

        Returns:
            {endpoints: [{url, method, status, length}, ...], total: int}
        """
        wordlist = self._find_wordlist()
        if not wordlist:
            logging.getLogger("beatrix.tools.kr").warning(
                "No kiterunner wordlist found — download from wordlists.assetnote.io "
                "and place at %s", self._WORDLIST_PATHS[0]
            )
            return {"endpoints": [], "total": 0}

        outfile = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        outfile.close()

        try:
            cmd = [
                self.path,
                "scan", url,
                "-w", wordlist,
                "-x", str(concurrency),
                "--timeout", str(timeout),
                "--fail-status-codes", fail_status_codes,
                "--output", "json",
                "--output-file", outfile.name,
                "--kitebuilder-full-scan",
            ]
            if not self._verbose_mode:
                cmd.append("--quiet")

            await self._run(cmd)

            endpoints = []
            try:
                with open(outfile.name) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            endpoints.append({
                                "url": entry.get("request", {}).get("URL",
                                        entry.get("URL", url)),
                                "method": entry.get("request", {}).get("Method",
                                           entry.get("Method", "GET")),
                                "status": entry.get("response", {}).get("StatusCode",
                                           entry.get("StatusCode", 0)),
                                "length": entry.get("response", {}).get("ContentLength",
                                           entry.get("ContentLength", 0)),
                            })
                        except json.JSONDecodeError:
                            # Plain-text line: "POST   200 [  1234, 12, 5] https://..."
                            m = re.match(
                                r'(\w+)\s+(\d+)\s+\[.*?\]\s+(https?://\S+)', line
                            )
                            if m:
                                endpoints.append({
                                    "url": m.group(3),
                                    "method": m.group(1),
                                    "status": int(m.group(2)),
                                    "length": 0,
                                })
            except FileNotFoundError:
                pass

            return {"endpoints": endpoints, "total": len(endpoints)}
        finally:
            try:
                os.unlink(outfile.name)
            except OSError:
                pass


class ArjunRunner(ExternalTool):
    """
    Arjun — Hidden HTTP parameter discovery.

    Discovers undocumented GET/POST/JSON parameters by observing response
    differences. Finds debug flags, hidden admin params, and undocumented
    API fields that crawlers and manual review miss.

    Install: pip install arjun  (or pipx install arjun)
    """

    BINARY_NAME = "arjun"
    DEFAULT_PHASE = 1

    async def discover(
        self,
        url: str,
        method: str = "GET",
        threads: int = 5,
        timeout: int = 15,
    ) -> Dict[str, Any]:
        """
        Discover hidden parameters on a URL.

        Returns:
            {params: ["param1", "param2", ...], url: str, method: str}
        """
        outfile = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        outfile.close()

        try:
            cmd = [
                self.path,
                "-u", url,
                "-m", method.upper(),
                "-t", str(threads),
                "--timeout", str(timeout),
                "-oJ", outfile.name,
            ]
            if not self._verbose_mode:
                cmd.append("-q")

            await self._run(cmd)

            params: List[str] = []
            try:
                with open(outfile.name) as f:
                    data = json.load(f)
                    # Arjun JSON: {"url": ..., "params": [...]} or list of such objects
                    if isinstance(data, list):
                        for entry in data:
                            params.extend(entry.get("params", []))
                    elif isinstance(data, dict):
                        params = data.get("params", [])
            except (json.JSONDecodeError, FileNotFoundError):
                pass

            return {"params": sorted(set(params)), "url": url, "method": method}
        finally:
            try:
                os.unlink(outfile.name)
            except OSError:
                pass


class ClairvoyanceRunner(ExternalTool):
    """
    Clairvoyance — GraphQL schema reconstruction despite disabled introspection.

    Recovers the full schema by fuzzing field names against error messages.
    Essential when the target disables introspection in production (common)
    but still leaks field names in validation error responses.

    Install: pip install clairvoyance
    """

    BINARY_NAME = "clairvoyance"
    DEFAULT_PHASE = 4

    async def reconstruct_schema(
        self,
        url: str,
        output_path: Optional[str] = None,
        timeout: int = 120,
    ) -> Dict[str, Any]:
        """
        Attempt to reconstruct the GraphQL schema.

        Returns:
            {schema: str, types: [...], queries: [...], mutations: [...],
             output_file: str, success: bool}
        """
        outfile = output_path or tempfile.mktemp(suffix=".json")
        _own_outfile = output_path is None

        try:
            cmd = [
                self.path,
                "-o", outfile,
                url,
            ]

            output = await self._run(cmd)

            result: Dict[str, Any] = {
                "schema": "",
                "types": [],
                "queries": [],
                "mutations": [],
                "output_file": outfile,
                "success": False,
                "raw_output": output or "",
            }

            try:
                if Path(outfile).exists():
                    with open(outfile) as f:
                        schema_data = json.load(f)
                    result["schema"] = json.dumps(schema_data, indent=2)
                    result["success"] = bool(schema_data)

                    # Extract type names from schema JSON
                    types = schema_data.get("data", {}).get("__schema", {}).get("types", [])
                    for t in types:
                        name = t.get("name", "")
                        if name and not name.startswith("__"):
                            result["types"].append(name)
                            fields = t.get("fields") or []
                            for field in fields:
                                fname = field.get("name", "")
                                if t.get("name") in ("Query", "query"):
                                    result["queries"].append(fname)
                                elif t.get("name") in ("Mutation", "mutation"):
                                    result["mutations"].append(fname)
            except (json.JSONDecodeError, FileNotFoundError):
                # clairvoyance may output SDL text instead of JSON
                if output and ("type " in output or "query {" in output):
                    result["schema"] = output
                    result["success"] = True

            return result
        finally:
            if _own_outfile:
                try:
                    Path(outfile).unlink(missing_ok=True)
                except Exception:
                    pass


class WaymoreRunner(ExternalTool):
    """
    Waymore — exhaustive historical URL discovery beyond what gau covers.

    Fetches URLs from Wayback Machine, AlienVault OTX, URLscan.io, Common
    Crawl, and VirusTotal simultaneously. Often surfaces forgotten /api/v1/
    endpoints, legacy admin panels, and old file-upload paths.

    Install: pip install waymore
    """

    BINARY_NAME = "waymore"
    DEFAULT_PHASE = 1

    async def fetch_urls(
        self,
        domain: str,
        mode: str = "U",   # U = URLs only (faster), R = also download responses
        timeout: int = 120,
    ) -> List[str]:
        """Return deduplicated list of historical URLs for *domain*."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                self.path,
                "-i", domain,
                "-mode", mode,
                "-oU", str(Path(tmpdir) / "urls.txt"),
                "--no-subs",   # avoid scope creep; gau already handles subs
            ]
            try:
                await self._run(cmd, timeout=timeout)
            except Exception:
                pass  # waymore exits non-zero even on partial success

            urls: List[str] = []
            url_file = Path(tmpdir) / "urls.txt"
            if url_file.exists():
                for line in url_file.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        urls.append(line)
            return urls


class Nomore403Runner(ExternalTool):
    """
    nomore403 — systematic 403 bypass via header manipulation and path tricks.

    Tests every protected URL with:
    - Header overrides (X-Forwarded-For, X-Original-URL, X-Rewrite-URL, etc.)
    - HTTP method override (X-HTTP-Method-Override: GET/POST)
    - Path normalization tricks (/admin/ → /%2fadmin/, /./admin/, //admin/)
    - Case variation, URL-encoding, double-encoding

    Install: go install github.com/devploit/nomore403@latest
    """

    BINARY_NAME = "nomore403"
    DEFAULT_PHASE = 4

    async def bypass(
        self,
        url: str,
        threads: int = 10,
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """
        Attempt to bypass a 403 on *url*.

        Returns:
            {bypassed: bool, bypass_url: str, technique: str, status: int,
             all_attempts: [{url, technique, status}]}
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tmpf:
            outfile = tmpf.name

        try:
            cmd = [
                self.path,
                "--url", url,
                "--threads", str(threads),
                "--output", outfile,
            ]
            output = await self._run(cmd, timeout=timeout) or ""

            result: Dict[str, Any] = {
                "bypassed": False,
                "bypass_url": "",
                "technique": "",
                "status": 403,
                "all_attempts": [],
            }

            # Parse stdout — nomore403 prints lines like:
            # [200] <url>  (<technique>)
            for line in output.splitlines():
                line = line.strip()
                parts = line.split()
                if not parts:
                    continue
                # Look for lines with a 2xx status that differs from 403
                try:
                    code_part = parts[0].strip("[]")
                    code = int(code_part)
                    if len(parts) >= 2:
                        attempt_url = parts[1]
                        technique = " ".join(parts[2:]).strip("()")
                        result["all_attempts"].append({
                            "url": attempt_url,
                            "technique": technique,
                            "status": code,
                        })
                        if 200 <= code < 300 and not result["bypassed"]:
                            result["bypassed"] = True
                            result["bypass_url"] = attempt_url
                            result["technique"] = technique
                            result["status"] = code
                except (ValueError, IndexError):
                    pass

            # Also check file output if available
            try:
                if Path(outfile).exists():
                    for line in Path(outfile).read_text(errors="replace").splitlines():
                        line = line.strip()
                        if not line or line in [a["url"] for a in result["all_attempts"]]:
                            continue
                        parts = line.split()
                        try:
                            code = int(parts[0].strip("[]"))
                            attempt_url = parts[1] if len(parts) > 1 else ""
                            technique = " ".join(parts[2:]).strip("()")
                            result["all_attempts"].append({
                                "url": attempt_url, "technique": technique, "status": code,
                            })
                            if 200 <= code < 300 and not result["bypassed"]:
                                result["bypassed"] = True
                                result["bypass_url"] = attempt_url
                                result["technique"] = technique
                                result["status"] = code
                        except (ValueError, IndexError):
                            pass
            except Exception:
                pass

            return result
        finally:
            try:
                Path(outfile).unlink(missing_ok=True)
            except Exception:
                pass


class CrlfuzzRunner(ExternalTool):
    """
    crlfuzz — dedicated CRLF injection / response splitting scanner.

    Beats nuclei's CRLF tag coverage by using a larger payload set and
    analysing response headers for injected \\r\\n sequences directly.
    Catches header injection, response splitting, and HTTP smuggling
    variants that signature-based templates miss.

    Install: go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
    """

    BINARY_NAME = "crlfuzz"
    DEFAULT_PHASE = 4

    async def scan(
        self,
        url: str,
        concurrency: int = 25,
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """
        Scan *url* for CRLF injection.

        Returns:
            {vulnerable: bool, findings: [{url, payload, evidence}]}
        """
        cmd = [
            self.path,
            "-u", url,
            "-c", str(concurrency),
            "-s",   # silent — only print vulnerable URLs
        ]
        output = await self._run(cmd, timeout=timeout) or ""

        findings = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("http") or "[vuln]" in line.lower():
                findings.append({
                    "url": line,
                    "payload": "",
                    "evidence": line,
                })

        return {
            "vulnerable": bool(findings),
            "findings": findings,
            "raw_output": output,
        }


class TlsxRunner(ExternalTool):
    """
    tlsx — fast TLS certificate inspection and cipher-suite enumeration.

    Extracts:
    - Subject / SAN hostnames (feeds into subdomain discovery)
    - Certificate chain and expiry
    - Weak cipher suites (RC4, 3DES, export ciphers)
    - TLS version support (SSLv3, TLSv1.0/1.1 — still live on many targets)
    - JARM fingerprint (C2 / WAF identification)

    Install: go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
    """

    BINARY_NAME = "tlsx"
    DEFAULT_PHASE = 1

    async def scan(
        self,
        host: str,
        port: int = 443,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """
        Run TLS scan against *host*:*port*.

        Returns:
            {host: str, port: int, san_domains: [...], tls_versions: [...],
             weak_ciphers: [...], expired: bool, expiry_date: str,
             jarm: str, raw: str}
        """
        cmd = [
            self.path,
            "-host", f"{host}:{port}",
            "-json",
            "-san",    # include Subject Alternative Names
            "-tls-version",
            "-cipher",
            "-jarm",
            "-expired",
            "-so",    # scan-output: stdout only
        ]
        output = await self._run(cmd, timeout=timeout) or ""

        result: Dict[str, Any] = {
            "host": host,
            "port": port,
            "san_domains": [],
            "tls_versions": [],
            "weak_ciphers": [],
            "expired": False,
            "expiry_date": "",
            "jarm": "",
            "raw": output,
        }

        _WEAK_CIPHERS = {
            "RC4", "3DES", "DES", "NULL", "EXPORT", "anon", "ADH", "AECDH",
        }

        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                result["tls_versions"] = obj.get("tls_version", []) or []
                if isinstance(result["tls_versions"], str):
                    result["tls_versions"] = [result["tls_versions"]]

                ciphers = obj.get("cipher", []) or []
                if isinstance(ciphers, str):
                    ciphers = [ciphers]
                result["weak_ciphers"] = [
                    c for c in ciphers
                    if any(w in c.upper() for w in _WEAK_CIPHERS)
                ]

                sans = obj.get("subject_an", []) or []
                result["san_domains"] = list(set(sans))

                result["expired"] = bool(obj.get("expired", False))
                result["expiry_date"] = obj.get("not_after", "") or ""
                result["jarm"] = obj.get("jarm", "") or ""
            except (json.JSONDecodeError, TypeError):
                pass

        return result


# =============================================================================
# CONVENIENCE: ALL TOOLS
# =============================================================================

class ExternalToolkit:
    """
    Convenience class that initializes all external tool wrappers.

    Usage:
        toolkit = ExternalToolkit()
        if toolkit.katana.available:
            result = await toolkit.katana.crawl(url)
    """

    def __init__(self):
        self.katana = KatanaRunner()
        self.amass = AmassRunner()
        self.gospider = GospiderRunner()
        self.hakrawler = HakrawlerRunner()
        self.gau = GauRunner()
        self.whatweb = WhatwebRunner()
        self.webanalyze = WebanalyzeRunner()
        self.dirsearch = DirsearchRunner()
        self.kiterunner = KiterRunnerRunner()
        self.arjun = ArjunRunner()
        self.clairvoyance = ClairvoyanceRunner()
        self.waymore = WaymoreRunner()
        self.nomore403 = Nomore403Runner()
        self.crlfuzz = CrlfuzzRunner()
        self.tlsx = TlsxRunner()
        self.sqlmap = SqlmapRunner(timeout=300)
        self.dalfox = DalfoxRunner()
        self.commix = CommixRunner()
        self.jwt_tool = JwtToolRunner()
        self.metasploit = MetasploitRunner()

    def status(self) -> Dict[str, bool]:
        """Return availability status of all tools."""
        return {
            "katana": self.katana.available,
            "amass": self.amass.available,
            "gospider": self.gospider.available,
            "hakrawler": self.hakrawler.available,
            "gau": self.gau.available,
            "whatweb": self.whatweb.available,
            "webanalyze": self.webanalyze.available,
            "dirsearch": self.dirsearch.available,
            "kiterunner": self.kiterunner.available,
            "arjun": self.arjun.available,
            "clairvoyance": self.clairvoyance.available,
            "waymore": self.waymore.available,
            "nomore403": self.nomore403.available,
            "crlfuzz": self.crlfuzz.available,
            "tlsx": self.tlsx.available,
            "sqlmap": self.sqlmap.available,
            "dalfox": self.dalfox.available,
            "commix": self.commix.available,
            "jwt_tool": self.jwt_tool.available,
            "msfconsole": self.metasploit.available,
        }

    def available_tools(self) -> List[str]:
        """Return names of available tools."""
        return [name for name, avail in self.status().items() if avail]

    def set_output_manager(self, output_manager) -> None:
        """Propagate a ScanOutputManager to all tool runners."""
        for attr in vars(self):
            tool = getattr(self, attr)
            if isinstance(tool, ExternalTool):
                tool.output_manager = output_manager
