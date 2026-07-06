"""
FFuf Engine - High-Performance Fuzzing via Go-based ffuf
=========================================================

Offloads exhaustive payload testing to ffuf for maximum performance.
Python handles orchestration, ffuf handles the heavy HTTP lifting.

Why ffuf?
- Written in Go: handles thousands of requests/second
- Battle-tested: used by professionals worldwide
- Flexible matching: regex, status codes, response size, word count
- JSON output: easy to parse back into Python

Architecture:
    ┌─────────────────────────────────────────────┐
    │  Python (This Module)                       │
    │  - Generate payload files from SecLists     │
    │  - Configure match conditions per vuln type │
    │  - Parse JSON results into findings         │
    └─────────────────┬───────────────────────────┘
                      │ subprocess
                      ▼
    ┌─────────────────────────────────────────────┐
    │  ffuf (Go Binary)                           │
    │  - Concurrent HTTP requests                 │
    │  - Response matching/filtering              │
    │  - Rate limiting                            │
    └─────────────────────────────────────────────┘

Usage:
    from core.ffuf_engine import FFufEngine

    engine = FFufEngine()
    findings = engine.fuzz_xss("https://target.com/search?q=FUZZ")
    findings = engine.fuzz_sqli("https://target.com/user?id=FUZZ")

    # Or run all injection tests on discovered endpoints
    all_findings = engine.exhaustive_injection_scan(endpoints)

Author: Beatrix Framework
Version: 1.0
"""

import json
import os
import random
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import SecLists manager
try:
    from .seclists_manager import SecListsManager, get_manager  # type: ignore
    HAS_SECLISTS = True
except ImportError:
    try:
        from seclists_manager import SecListsManager, get_manager  # noqa: F401 # type: ignore
        HAS_SECLISTS = True
    except ImportError:
        HAS_SECLISTS = False


# =============================================================================
# CONSTANTS
# =============================================================================

class VulnType(Enum):
    """Vulnerability types for fuzzing"""
    XSS = "xss"
    SQLI = "sqli"
    LFI = "lfi"
    RCE = "rce"
    SSTI = "ssti"
    SSRF = "ssrf"
    OPEN_REDIRECT = "redirect"


@dataclass
class FuzzTarget:
    """A target URL with fuzz point"""
    url: str
    method: str = "GET"
    parameter: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    data: str = ""  # POST data with FUZZ marker
    cookies: str = ""


@dataclass
class FuzzResult:
    """Result from ffuf fuzzing"""
    url: str
    payload: str
    status_code: int
    content_length: int
    words: int
    lines: int
    duration_ms: float
    content_type: str = ""
    redirect_location: str = ""
    matched_by: str = ""  # What matched (regex, status, etc.)
    resultfile: str = ""  # ffuf -od filename holding the raw response (if captured)


@dataclass
class Finding:
    """Vulnerability finding from fuzzing"""
    vuln_type: str
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: str
    confidence: str
    method: str = "GET"
    status_code: int = 0
    response_length: int = 0
    technique: str = ""
    cwe: str = ""


# =============================================================================
# MATCH CONFIGURATIONS PER VULNERABILITY TYPE
# =============================================================================

# These define what ffuf should look for to detect each vulnerability type
VULN_MATCHERS = {
    VulnType.XSS: {
        # XSS detection: payload reflected in response
        "match_regex": [
            r"<script.*?>",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"javascript:",
            r"<svg.*?onload",
            r"<img.*?onerror",
        ],
        "filter_status": "404,500,502,503",
        "severity": "high",
        "cwe": "CWE-79",
    },
    VulnType.SQLI: {
        # SQLi detection: error messages or behavior changes
        "match_regex": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"PostgreSQL.*ERROR",
            r"ORA-[0-9]+",
            r"Microsoft.*ODBC",
            r"SQLite.*error",
            r"Unclosed quotation",
            r"quoted string not properly terminated",
            r"SQLSTATE\[",
            r"pg_query\(\)",
            r"mysql_fetch",
            r"You have an error in your SQL syntax",
        ],
        "filter_status": "404,500,502,503",
        "severity": "critical",
        "cwe": "CWE-89",
    },
    VulnType.LFI: {
        # LFI detection: file contents in response
        "match_regex": [
            r"root:.*:0:0:",  # /etc/passwd
            r"\[boot loader\]",  # Windows boot.ini
            r"\[extensions\]",  # Windows php.ini
            r"<\?php",  # PHP source
            r"DB_PASSWORD",  # Config files
            r"mysql\.default_password",
        ],
        "filter_status": "404,400",
        "severity": "critical",
        "cwe": "CWE-98",
    },
    VulnType.RCE: {
        # RCE detection: command output
        "match_regex": [
            r"uid=\d+.*gid=\d+",  # id command
            r"Linux.*GNU",  # uname -a
            r"Windows.*NT",  # Windows systeminfo
            r"root:.*:0:0:",  # /etc/passwd via RCE
            r"total \d+",  # ls -la output
            r"Volume Serial Number",  # Windows dir
        ],
        "filter_status": "404,500,502,503",
        "severity": "critical",
        "cwe": "CWE-78",
    },
    VulnType.SSTI: {
        # SSTI detection: template evaluation
        "match_regex": [
            r"49",  # 7*7
            r"7777777",  # 7*'7'
            r"class.*subprocess",  # Python
            r"__class__",
            r"__mro__",
        ],
        "filter_status": "404,500,502,503",
        "severity": "critical",
        "cwe": "CWE-94",
    },
    VulnType.SSRF: {
        # SSRF detection: internal responses
        "match_regex": [
            r"ami-[a-f0-9]+",  # AWS metadata
            r"instance-id",
            r"local-hostname",
            r"169\.254\.169\.254",
            r"metadata\.google",
            r"127\.0\.0\.1",
            r"localhost",
        ],
        "filter_status": "404",
        "severity": "high",
        "cwe": "CWE-918",
    },
    VulnType.OPEN_REDIRECT: {
        # Open redirect: Location header check
        "match_status": "301,302,303,307,308",
        "severity": "medium",
        "cwe": "CWE-601",
    },
}


# ffuf's -od file interleaves the raw request and response, joined by a
# "---- Response ----"-style banner line (exact arrows vary by ffuf version).
_OD_RESPONSE_MARKER = re.compile(r"^-+.*Response.*-+\r?$", re.MULTILINE)
_HEADER_BODY_SEP = re.compile(r"\r?\n\r?\n")


def _extract_response_body(raw: str) -> str:
    """Pull just the response body out of one ffuf ``-od`` capture file.

    Falls back to returning the input unchanged if the expected markers
    aren't found, so a format quirk degrades to "no match" rather than
    raising.
    """
    marker = _OD_RESPONSE_MARKER.search(raw)
    section = raw[marker.end():].lstrip("\r\n") if marker else raw
    body_sep = _HEADER_BODY_SEP.search(section)
    return section[body_sep.end():] if body_sep else section


# =============================================================================
# FFUF ENGINE
# =============================================================================

class FFufEngine:
    """
    High-performance fuzzing engine using ffuf.

    Offloads exhaustive payload testing to Go-based ffuf while Python
    handles orchestration and result parsing.
    """

    def __init__(
        self,
        threads: int = 50,
        rate_limit: int = 0,  # 0 = unlimited
        timeout: int = 10,
        verbose: bool = True,
        follow_redirects: bool = False,
        waf_profile: Optional[str] = None,
    ):
        self.threads = threads
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.verbose = verbose
        self.follow_redirects = follow_redirects
        self._waf_profile = waf_profile

        # When WAF detected, apply safe defaults to avoid triggering blocks
        if waf_profile and rate_limit == 0:
            self.rate_limit = 30  # Cap at 30 rps when WAF detected
            self.threads = min(threads, 20)  # Reduce concurrency

        # Check if ffuf is available
        self.ffuf_path = self._find_ffuf()
        if not self.ffuf_path:
            raise RuntimeError(
                "ffuf not found. Install with: go install github.com/ffuf/ffuf/v2@latest\n"
                "Or: sudo apt install ffuf"
            )

        # SecLists manager for payloads
        self.seclists = get_manager() if HAS_SECLISTS else None
        if self.seclists:
            self.seclists.verbose = False

        # Temp directory for payload files
        self.temp_dir = Path(tempfile.mkdtemp(prefix="beatrix_ffuf_"))

        # Results storage
        self.findings: List[Finding] = []

    def _find_ffuf(self) -> Optional[str]:
        """Find ffuf binary"""
        # Check PATH
        ffuf = shutil.which("ffuf")
        if ffuf:
            return ffuf

        # Check common locations
        common_paths = [
            "/usr/bin/ffuf",
            "/usr/local/bin/ffuf",
            os.path.expanduser("~/go/bin/ffuf"),
            os.path.expanduser("~/.local/bin/ffuf"),
        ]

        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path

        return None

    def _write_payload_file(self, payloads: List[str], name: str) -> Path:
        """Write payloads to temporary file for ffuf"""
        payload_file = self.temp_dir / f"{name}.txt"
        with open(payload_file, 'w', encoding='utf-8') as f:
            for payload in payloads:
                if payload and payload.strip():
                    f.write(payload.strip() + '\n')
        return payload_file

    def _build_ffuf_command(
        self,
        url: str,
        wordlist: Path,
        output_file: Path,
        vuln_type: VulnType,
        method: str = "GET",
        headers: Dict[str, str] = None,
        data: str = None,
        cookies: str = None,
        od_dir: Optional[Path] = None,
    ) -> List[str]:
        """Build ffuf command with appropriate flags.

        ``od_dir``, when given, adds ``-od`` so ffuf writes each matched
        result's raw response to that directory — the response bodies
        ``_filter_results_by_regex`` needs to confirm a hit for pattern-based
        vuln types (XSS/SQLi/LFI/RCE/SSTI/SSRF).
        """

        cmd = [
            self.ffuf_path,
            "-u", url,
            "-w", str(wordlist),
            "-o", str(output_file),
            "-of", "json",  # JSON output format
            "-t", str(self.threads),
            "-timeout", str(self.timeout),
            "-ac",  # Auto-calibrate filtering
            "-se",  # Stop on spurious errors
        ]

        if od_dir is not None:
            cmd.extend(["-od", str(od_dir)])

        # Method
        if method.upper() != "GET":
            cmd.extend(["-X", method.upper()])

        # Rate limit
        if self.rate_limit > 0:
            cmd.extend(["-rate", str(self.rate_limit)])

        # Follow redirects
        if self.follow_redirects:
            cmd.append("-r")

        # Headers
        if headers:
            for name, value in headers.items():
                cmd.extend(["-H", f"{name}: {value}"])

        # Add common headers with a random realistic User-Agent
        _uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
        ]
        cmd.extend(["-H", f"User-Agent: {random.choice(_uas)}"])

        # Cookies
        if cookies:
            cmd.extend(["-b", cookies])

        # POST data
        if data:
            cmd.extend(["-d", data])

        # Matcher configuration based on vuln type
        matcher = VULN_MATCHERS.get(vuln_type, {})

        # Status code matching
        if "match_status" in matcher:
            cmd.extend(["-mc", matcher["match_status"]])
        else:
            cmd.extend(["-mc", "all"])  # Match all status codes

        # Filter out error status codes
        if "filter_status" in matcher:
            cmd.extend(["-fc", matcher["filter_status"]])

        # Regex matching (we'll do this in post-processing for more control)
        # ffuf's -mr is limited, so we match in Python after

        # Quiet mode (we parse JSON, don't need stdout)
        if not self.verbose:
            cmd.append("-s")

        return cmd

    def _run_ffuf(self, cmd: List[str]) -> Tuple[bool, str]:
        """Run ffuf and return success status and output file path"""
        try:
            if self.verbose:
                print(f"    [ffuf] Running with {self.threads} threads...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour max
            )

            # ffuf returns 0 on success
            return result.returncode == 0, result.stderr

        except subprocess.TimeoutExpired:
            if self.verbose:
                print("    [ffuf] Timeout after 1 hour")
            return False, "timeout"
        except Exception as e:
            return False, str(e)

    def _parse_ffuf_results(
        self,
        output_file: Path,
        vuln_type: VulnType,
        parameter: str = "",
    ) -> List[FuzzResult]:
        """Parse ffuf JSON output into FuzzResults"""
        results = []

        if not output_file.exists():
            return results

        try:
            with open(output_file) as f:
                data = json.load(f)

            for result in data.get("results", []):
                fuzz_result = FuzzResult(
                    url=result.get("url", ""),
                    payload=result.get("input", {}).get("FUZZ", ""),
                    status_code=result.get("status", 0),
                    content_length=result.get("length", 0),
                    words=result.get("words", 0),
                    lines=result.get("lines", 0),
                    duration_ms=result.get("duration", 0),
                    content_type=result.get("content-type", ""),
                    redirect_location=result.get("redirectlocation", ""),
                    resultfile=result.get("resultfile", ""),
                )
                results.append(fuzz_result)

            if self.verbose:
                print(f"    [ffuf] Found {len(results)} potential hits")

        except (json.JSONDecodeError, IOError) as e:
            if self.verbose:
                print(f"    [ffuf] Error parsing results: {e}")

        return results

    def _load_response_bodies(
        self,
        results: List[FuzzResult],
        od_dir: Path,
    ) -> Dict[str, str]:
        """Read the raw responses ffuf wrote via ``-od`` into a url->body map.

        Each result's ``resultfile`` names a file under ``od_dir`` containing
        the interleaved raw request and response ffuf sent/received for that
        hit; this pulls out just the response body for ``_filter_results_by_regex``.
        """
        responses: Dict[str, str] = {}
        for result in results:
            if not result.resultfile:
                continue
            try:
                raw = (od_dir / result.resultfile).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                continue
            responses[result.url] = _extract_response_body(raw)
        return responses

    def _filter_results_by_regex(
        self,
        results: List[FuzzResult],
        vuln_type: VulnType,
        responses: Dict[str, str],  # url -> response body
    ) -> List[FuzzResult]:
        """
        Filter results by checking if payload/patterns appear in response.

        This is more accurate than ffuf's built-in regex matching.
        """
        matcher = VULN_MATCHERS.get(vuln_type, {})
        patterns = matcher.get("match_regex", [])

        if not patterns:
            return results

        filtered = []
        compiled_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]

        for result in results:
            response_body = responses.get(result.url, "")

            # Check if any pattern matches
            for pattern in compiled_patterns:
                if pattern.search(response_body):
                    result.matched_by = pattern.pattern
                    filtered.append(result)
                    break

            # Also check if payload is reflected (for XSS)
            if vuln_type == VulnType.XSS and result not in filtered:
                # Check for payload reflection
                payload_decoded = urllib.parse.unquote(result.payload)
                if payload_decoded in response_body or result.payload in response_body:
                    result.matched_by = "payload_reflection"
                    filtered.append(result)

        return filtered

    def _results_to_findings(
        self,
        results: List[FuzzResult],
        vuln_type: VulnType,
        parameter: str,
        method: str = "GET",
    ) -> List[Finding]:
        """Convert FuzzResults to Findings"""
        findings = []
        matcher = VULN_MATCHERS.get(vuln_type, {})

        for result in results:
            # Determine confidence based on match type: a response actually
            # matching a vuln-specific pattern (SQL error text, /etc/passwd
            # contents, ...) is stronger evidence than a bare payload
            # reflection, which weaker signals (encoding, sanitization) can
            # still slip past.
            if result.matched_by == "payload_reflection":
                confidence = "medium"
            elif result.matched_by:
                confidence = "high"
            else:
                confidence = "low"

            finding = Finding(
                vuln_type=vuln_type.value.upper(),
                url=result.url.replace("FUZZ", result.payload),
                parameter=parameter,
                payload=result.payload,
                evidence=f"Matched: {result.matched_by}" if result.matched_by else f"Status: {result.status_code}",
                severity=matcher.get("severity", "medium"),
                confidence=confidence,
                method=method,
                status_code=result.status_code,
                response_length=result.content_length,
                technique="ffuf_exhaustive",
                cwe=matcher.get("cwe", ""),
            )
            findings.append(finding)

        return findings

    # =========================================================================
    # PUBLIC FUZZING METHODS
    # =========================================================================

    def fuzz_endpoint(
        self,
        url: str,
        payloads: List[str],
        vuln_type: VulnType,
        parameter: str = "",
        method: str = "GET",
        headers: Dict[str, str] = None,
        data: str = None,
        cookies: str = None,
        verify_reflection: bool = True,
    ) -> List[Finding]:
        """
        Fuzz a single endpoint with given payloads.

        Args:
            url: URL with FUZZ marker where payload goes
            payloads: List of payloads to test
            vuln_type: Type of vulnerability being tested
            parameter: Parameter name being fuzzed
            method: HTTP method
            headers: Additional headers
            data: POST data (use FUZZ marker for payload position)
            cookies: Cookies to send
            verify_reflection: Confirm each hit against the actual response
                body (vuln-specific regex patterns, plus raw payload
                reflection for XSS) instead of trusting ffuf's status/size
                filtering alone. Costs one extra response-body read per hit
                (via ffuf's -od); disable only if you want ffuf's raw,
                unfiltered hits.

        Returns:
            List of findings
        """
        if "FUZZ" not in url and (not data or "FUZZ" not in data):
            raise ValueError("URL or data must contain FUZZ marker")

        if self.verbose:
            print(f"\n[*] Fuzzing {vuln_type.value.upper()} on {url}")
            print(f"    Payloads: {len(payloads)}")

        # Write payloads to temp file
        payload_file = self._write_payload_file(
            payloads,
            f"{vuln_type.value}_{hash(url) % 10000}"
        )

        # Output file for results
        output_file = self.temp_dir / f"results_{vuln_type.value}_{hash(url) % 10000}.json"

        # Only ask ffuf to capture raw responses (-od) when there's a
        # matcher this filtering step can actually use — match_status-only
        # types (open redirect) are already fully filtered by ffuf's -mc/-fc.
        matcher = VULN_MATCHERS.get(vuln_type, {})
        needs_bodies = verify_reflection and bool(matcher.get("match_regex"))
        od_dir = (
            self.temp_dir / f"od_{vuln_type.value}_{hash(url) % 10000}"
            if needs_bodies else None
        )

        # Build and run ffuf command
        cmd = self._build_ffuf_command(
            url=url,
            wordlist=payload_file,
            output_file=output_file,
            vuln_type=vuln_type,
            method=method,
            headers=headers,
            data=data,
            cookies=cookies,
            od_dir=od_dir,
        )

        success, error = self._run_ffuf(cmd)

        if not success and self.verbose:
            print(f"    [ffuf] Warning: {error}")

        # Parse results
        results = self._parse_ffuf_results(output_file, vuln_type, parameter)

        # Confirm hits against the real response body instead of trusting
        # ffuf's status/size filtering alone (issue #3: this step existed
        # but was never wired in, so every ffuf hit became a finding).
        if needs_bodies and results:
            responses = self._load_response_bodies(results, od_dir)
            results = self._filter_results_by_regex(results, vuln_type, responses)
            if self.verbose:
                print(f"    [ffuf] {len(results)} confirmed by response-body match")

        if od_dir is not None:
            shutil.rmtree(od_dir, ignore_errors=True)

        # Convert to findings
        findings = self._results_to_findings(results, vuln_type, parameter, method)

        self.findings.extend(findings)
        return findings

    def fuzz_xss(
        self,
        url: str,
        parameter: str = "",
        method: str = "GET",
        headers: Dict[str, str] = None,
        cookies: str = None,
        exhaustive: bool = True,
    ) -> List[Finding]:
        """
        Fuzz for XSS vulnerabilities.

        Args:
            url: URL with FUZZ marker
            parameter: Parameter name
            method: HTTP method
            headers: Additional headers
            cookies: Cookies
            exhaustive: Use full SecLists XSS payloads
        """
        if exhaustive and self.seclists:
            payloads = self._get_exhaustive_xss_payloads()
        else:
            payloads = self._get_basic_xss_payloads()

        return self.fuzz_endpoint(
            url=url,
            payloads=payloads,
            vuln_type=VulnType.XSS,
            parameter=parameter,
            method=method,
            headers=headers,
            cookies=cookies,
        )

    def fuzz_sqli(
        self,
        url: str,
        parameter: str = "",
        method: str = "GET",
        headers: Dict[str, str] = None,
        cookies: str = None,
        exhaustive: bool = True,
    ) -> List[Finding]:
        """Fuzz for SQL Injection vulnerabilities."""
        if exhaustive and self.seclists:
            payloads = self._get_exhaustive_sqli_payloads()
        else:
            payloads = self._get_basic_sqli_payloads()

        return self.fuzz_endpoint(
            url=url,
            payloads=payloads,
            vuln_type=VulnType.SQLI,
            parameter=parameter,
            method=method,
            headers=headers,
            cookies=cookies,
        )

    def fuzz_lfi(
        self,
        url: str,
        parameter: str = "",
        method: str = "GET",
        headers: Dict[str, str] = None,
        cookies: str = None,
        exhaustive: bool = True,
    ) -> List[Finding]:
        """Fuzz for Local File Inclusion vulnerabilities."""
        if exhaustive and self.seclists:
            payloads = self._get_exhaustive_lfi_payloads()
        else:
            payloads = self._get_basic_lfi_payloads()

        return self.fuzz_endpoint(
            url=url,
            payloads=payloads,
            vuln_type=VulnType.LFI,
            parameter=parameter,
            method=method,
            headers=headers,
            cookies=cookies,
        )

    def fuzz_rce(
        self,
        url: str,
        parameter: str = "",
        method: str = "GET",
        headers: Dict[str, str] = None,
        cookies: str = None,
        exhaustive: bool = True,
    ) -> List[Finding]:
        """Fuzz for Remote Code Execution / Command Injection."""
        if exhaustive and self.seclists:
            payloads = self._get_exhaustive_rce_payloads()
        else:
            payloads = self._get_basic_rce_payloads()

        return self.fuzz_endpoint(
            url=url,
            payloads=payloads,
            vuln_type=VulnType.RCE,
            parameter=parameter,
            method=method,
            headers=headers,
            cookies=cookies,
        )

    def exhaustive_scan(
        self,
        targets: List[FuzzTarget],
        vuln_types: List[VulnType] = None,
    ) -> List[Finding]:
        """
        Run exhaustive injection scan on multiple targets.

        Args:
            targets: List of FuzzTarget objects
            vuln_types: Which vulnerability types to test (default: all)

        Returns:
            List of all findings
        """
        if vuln_types is None:
            vuln_types = [VulnType.XSS, VulnType.SQLI, VulnType.LFI, VulnType.RCE]

        all_findings = []

        for target in targets:
            if self.verbose:
                print(f"\n{'='*60}")
                print(f"Target: {target.url}")
                print(f"{'='*60}")

            for vuln_type in vuln_types:
                try:
                    if vuln_type == VulnType.XSS:
                        findings = self.fuzz_xss(
                            url=target.url,
                            parameter=target.parameter,
                            method=target.method,
                            headers=target.headers,
                            cookies=target.cookies,
                        )
                    elif vuln_type == VulnType.SQLI:
                        findings = self.fuzz_sqli(
                            url=target.url,
                            parameter=target.parameter,
                            method=target.method,
                            headers=target.headers,
                            cookies=target.cookies,
                        )
                    elif vuln_type == VulnType.LFI:
                        findings = self.fuzz_lfi(
                            url=target.url,
                            parameter=target.parameter,
                            method=target.method,
                            headers=target.headers,
                            cookies=target.cookies,
                        )
                    elif vuln_type == VulnType.RCE:
                        findings = self.fuzz_rce(
                            url=target.url,
                            parameter=target.parameter,
                            method=target.method,
                            headers=target.headers,
                            cookies=target.cookies,
                        )
                    else:
                        continue

                    all_findings.extend(findings)

                    if findings and self.verbose:
                        print(f"    ✓ Found {len(findings)} {vuln_type.value.upper()} issues")

                except Exception as e:
                    if self.verbose:
                        print(f"    ✗ {vuln_type.value.upper()} scan failed: {e}")

        return all_findings

    def parallel_endpoint_scan(
        self,
        urls: List[str],
        vuln_types: List[VulnType] = None,
        max_concurrent: int = 5,
    ) -> List[Finding]:
        """
        Scan multiple endpoints in parallel using connection pooling.

        This batches URLs and runs ffuf scans concurrently, sharing
        resources and reducing overall scan time.

        Args:
            urls: List of URLs (each should have FUZZ marker)
            vuln_types: Which vulnerability types to test
            max_concurrent: Maximum concurrent ffuf processes

        Returns:
            List of all findings across all URLs
        """
        import concurrent.futures
        import threading

        if vuln_types is None:
            vuln_types = [VulnType.XSS, VulnType.SQLI]

        all_findings = []
        findings_lock = threading.Lock()

        def scan_url(url: str) -> List[Finding]:
            """Scan a single URL with all vuln types"""
            url_findings = []

            for vuln_type in vuln_types:
                try:
                    if vuln_type == VulnType.XSS:
                        findings = self.fuzz_xss(url, exhaustive=False)
                    elif vuln_type == VulnType.SQLI:
                        findings = self.fuzz_sqli(url, exhaustive=False)
                    elif vuln_type == VulnType.LFI:
                        findings = self.fuzz_lfi(url)
                    elif vuln_type == VulnType.RCE:
                        findings = self.fuzz_rce(url)
                    else:
                        continue

                    url_findings.extend(findings)
                except Exception as e:
                    if self.verbose:
                        print(f"    [!] Error scanning {url}: {e}")

            return url_findings

        if self.verbose:
            print(f"\n[*] Parallel scanning {len(urls)} endpoints")
            print(f"    Concurrent processes: {max_concurrent}")
            print(f"    Vuln types: {[v.value for v in vuln_types]}")

        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # Submit all URLs
            future_to_url = {executor.submit(scan_url, url): url for url in urls}

            completed = 0
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    findings = future.result()
                    with findings_lock:
                        all_findings.extend(findings)
                    completed += 1

                    if self.verbose:
                        status = f"✓ {len(findings)} findings" if findings else "○ clean"
                        print(f"    [{completed}/{len(urls)}] {url[:50]}... {status}")

                except Exception as e:
                    completed += 1
                    if self.verbose:
                        print(f"    [{completed}/{len(urls)}] {url[:50]}... ✗ error: {e}")

        if self.verbose:
            print(f"\n[+] Parallel scan complete: {len(all_findings)} total findings")

        return all_findings

    def batch_fuzz_from_crawl(
        self,
        crawl_results: List[str],
        vuln_types: List[VulnType] = None,
        parameter_extraction: bool = True,
        max_urls: int = 100,
    ) -> List[Finding]:
        """
        Process URLs from a crawl, extract parameters, and fuzz them.

        Args:
            crawl_results: URLs discovered from crawling
            vuln_types: Which vulnerability types to test
            parameter_extraction: Auto-extract parameters from URLs
            max_urls: Maximum URLs to process

        Returns:
            List of findings
        """
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

        if vuln_types is None:
            vuln_types = [VulnType.XSS, VulnType.SQLI]

        # Extract URLs with parameters
        urls_with_params = []

        for url in crawl_results[:max_urls * 2]:  # Process more to find enough with params
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if params and parameter_extraction:
                # Create fuzzable URLs for each parameter
                for param_name in params.keys():
                    # Build URL with FUZZ marker
                    new_params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
                    new_params[param_name] = 'FUZZ'

                    fuzz_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urlencode(new_params),
                        ''
                    ))

                    urls_with_params.append({
                        'url': fuzz_url,
                        'parameter': param_name,
                        'original': url,
                    })

            if len(urls_with_params) >= max_urls:
                break

        if self.verbose:
            print(f"[*] Extracted {len(urls_with_params)} fuzzable URLs from {len(crawl_results)} crawled")

        if not urls_with_params:
            return []

        # Fuzz all extracted URLs
        fuzz_urls = [u['url'] for u in urls_with_params]
        return self.parallel_endpoint_scan(fuzz_urls, vuln_types)

    # =========================================================================
    # PAYLOAD LOADERS
    # =========================================================================

    def _get_exhaustive_xss_payloads(self) -> List[str]:
        """Load full XSS payload catalog from SecLists"""
        payloads = set()

        wordlists = [
            "Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt",
            "Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
            "Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt",
            "Fuzzing/XSS/human-friendly/XSS-RSNAKE.txt",
            "Fuzzing/XSS/Polyglots/XSS-Polyglots.txt",
            "Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt",
        ]

        for wl in wordlists:
            try:
                payloads.update(self.seclists.get_wordlist(wl))
            except Exception:
                pass

        if self.verbose:
            print(f"    Loaded {len(payloads)} XSS payloads from SecLists")

        return list(payloads)

    def _get_basic_xss_payloads(self) -> List[str]:
        """Basic XSS payloads for quick testing"""
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "{{7*7}}",
            "${7*7}",
        ]

    def _get_exhaustive_sqli_payloads(self) -> List[str]:
        """Load full SQLi payload catalog from SecLists"""
        payloads = set()

        wordlists = [
            "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
            "Fuzzing/Databases/SQLi/quick-SQLi.txt",
            "Fuzzing/Databases/SQLi/sqli.auth.bypass.txt",
            "Fuzzing/Databases/SQLi/SQLi-Polyglots.txt",
            "Fuzzing/Databases/SQLi/MySQL.fuzzdb.txt",
        ]

        for wl in wordlists:
            try:
                payloads.update(self.seclists.get_wordlist(wl))
            except Exception:
                pass

        if self.verbose:
            print(f"    Loaded {len(payloads)} SQLi payloads from SecLists")

        return list(payloads)

    def _get_basic_sqli_payloads(self) -> List[str]:
        """Basic SQLi payloads for quick testing"""
        return [
            "'",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "1' ORDER BY 1--",
            "1 UNION SELECT NULL--",
            "' AND SLEEP(5)--",
            "admin'--",
        ]

    def _get_exhaustive_lfi_payloads(self) -> List[str]:
        """Load full LFI payload catalog from SecLists"""
        payloads = set()

        wordlists = [
            "Fuzzing/LFI/LFI-Jhaddix.txt",
            "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
            "Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",
        ]

        for wl in wordlists:
            try:
                payloads.update(self.seclists.get_wordlist(wl))
            except Exception:
                pass

        if self.verbose:
            print(f"    Loaded {len(payloads)} LFI payloads from SecLists")

        return list(payloads)

    def _get_basic_lfi_payloads(self) -> List[str]:
        """Basic LFI payloads for quick testing"""
        return [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/proc/self/environ",
        ]

    def _get_exhaustive_rce_payloads(self) -> List[str]:
        """Load full RCE payload catalog from SecLists"""
        payloads = set()

        wordlists = [
            "Fuzzing/command-injection-commix.txt",
        ]

        for wl in wordlists:
            try:
                payloads.update(self.seclists.get_wordlist(wl))
            except Exception:
                pass

        if self.verbose:
            print(f"    Loaded {len(payloads)} RCE payloads from SecLists")

        return list(payloads)

    def _get_basic_rce_payloads(self) -> List[str]:
        """Basic RCE payloads for quick testing"""
        return [
            "; id",
            "| id",
            "|| id",
            "&& id",
            "`id`",
            "$(id)",
            "; sleep 5",
        ]

    # =========================================================================
    # CLEANUP
    # =========================================================================

    def cleanup(self):
        """Clean up temporary files"""
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass

    def __del__(self):
        self.cleanup()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def quick_xss_fuzz(url: str, exhaustive: bool = True) -> List[Finding]:
    """Quick XSS fuzzing on a URL with FUZZ marker"""
    engine = FFufEngine(verbose=True)
    try:
        return engine.fuzz_xss(url, exhaustive=exhaustive)
    finally:
        engine.cleanup()


def quick_sqli_fuzz(url: str, exhaustive: bool = True) -> List[Finding]:
    """Quick SQLi fuzzing on a URL with FUZZ marker"""
    engine = FFufEngine(verbose=True)
    try:
        return engine.fuzz_sqli(url, exhaustive=exhaustive)
    finally:
        engine.cleanup()


def parallel_fuzz(urls: List[str], vuln_types: List[VulnType] = None, max_concurrent: int = 5) -> List[Finding]:
    """
    Parallel fuzz multiple URLs for vulnerabilities.

    Args:
        urls: List of URLs (each should have FUZZ marker for parameter injection)
        vuln_types: Which vulnerability types to test (default: XSS, SQLI)
        max_concurrent: Maximum concurrent ffuf processes

    Returns:
        List of all findings across all URLs

    Example:
        urls = [
            "https://target.com/search?q=FUZZ",
            "https://target.com/user?id=FUZZ",
            "https://target.com/product?item=FUZZ",
        ]
        findings = parallel_fuzz(urls, max_concurrent=3)
    """
    engine = FFufEngine(verbose=True)
    try:
        return engine.parallel_endpoint_scan(urls, vuln_types, max_concurrent)
    finally:
        engine.cleanup()


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'FFufEngine',
    'VulnType',
    'FuzzTarget',
    'FuzzResult',
    'Finding',
    'quick_xss_fuzz',
    'quick_sqli_fuzz',
    'parallel_fuzz',
    'VULN_MATCHERS',
]
