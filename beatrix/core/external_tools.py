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
