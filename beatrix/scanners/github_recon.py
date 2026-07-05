#!/usr/bin/env python3
"""
BEATRIX GitHub Reconnaissance & Secret Scanner

Searches a target organization's public GitHub repositories for:
- Hardcoded secrets (API keys, passwords, tokens, private keys)
- Configuration files with credentials
- Git history leaks (secrets committed then "sanitized")
- Infrastructure disclosure (DB hosts, internal URLs, cloud configs)

Usage:
    scanner = GitHubRecon("target-org")
    async with scanner:
        findings = await scanner.full_recon()

Author: BEATRIX
"""

import asyncio
import math
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple

import httpx

from beatrix.core.types import Confidence, Finding, Severity
from beatrix.scanners.base import BaseScanner, ScanContext

# =============================================================================
# SECRET PATTERNS — regex patterns for detecting leaked credentials
# =============================================================================

SECRET_PATTERNS: List[Tuple[str, str, Severity]] = [
    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", Severity.CRITICAL),
    (r'(?i)aws[_\-\.]?secret[_\-\.]?access[_\-\.]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Access Key", Severity.CRITICAL),

    # Google
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", Severity.HIGH),
    (r'(?i)google[_\-\.]?api[_\-\.]?key\s*[=:]\s*["\']?([A-Za-z0-9\-_]{35,})', "Google API Key", Severity.HIGH),

    # Generic API keys and tokens
    (r'(?i)(?:api[_\-\.]?key|apikey|api_secret|api_token)\s*[=:]\s*["\']?([A-Za-z0-9\-_\.]{16,})["\']?', "API Key/Token", Severity.HIGH),
    (r'(?i)(?:access[_\-\.]?token|auth[_\-\.]?token|bearer)\s*[=:]\s*["\']?([A-Za-z0-9\-_\.]{16,})["\']?', "Access/Auth Token", Severity.HIGH),

    # JWT Secrets
    (r'(?i)(?:jwt[_\-\.]?secret|jwt[_\-\.]?key|token[_\-\.]?secret)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?', "JWT Secret", Severity.HIGH),

    # Database credentials
    (r'(?i)(?:db|database|mysql|postgres|pgsql|mongo|redis)[_\-\.]?(?:pass|password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{4,})["\']?', "Database Password", Severity.HIGH),
    (r'(?i)mongodb(?:\+srv)?://[^\s"\']+:[^\s"\']+@[^\s"\']+', "MongoDB Connection String", Severity.CRITICAL),
    (r'(?i)postgres(?:ql)?://[^\s"\']+:[^\s"\']+@[^\s"\']+', "PostgreSQL Connection String", Severity.CRITICAL),
    (r'(?i)mysql://[^\s"\']+:[^\s"\']+@[^\s"\']+', "MySQL Connection String", Severity.CRITICAL),
    (r'(?i)redis://[^\s"\']*:[^\s"\']+@[^\s"\']+', "Redis Connection String", Severity.HIGH),

    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key", Severity.CRITICAL),
    (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "PGP Private Key", Severity.CRITICAL),

    # Generic passwords in config
    (r'(?i)"password"\s*:\s*"([^"]{4,})"', "Password in JSON Config", Severity.HIGH),
    (r'(?i)"secret"\s*:\s*"([^"]{4,})"', "Secret in JSON Config", Severity.HIGH),

    # Encryption keys — require the value to look like an actual key (hex/base64), not code
    (r'(?i)(?:aes|encryption|cipher)[_\-\.]?(?:key|secret)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{16,})["\']', "Encryption Key", Severity.CRITICAL),

    # Slack/Discord webhooks
    (r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+', "Slack Webhook", Severity.MEDIUM),
    (r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+', "Discord Webhook", Severity.MEDIUM),

    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Secret Key (Live)", Severity.CRITICAL),
    (r'rk_live_[0-9a-zA-Z]{24,}', "Stripe Restricted Key (Live)", Severity.HIGH),

    # Twilio
    (r'SK[0-9a-fA-F]{32}', "Twilio API Key", Severity.HIGH),

    # SendGrid
    (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "SendGrid API Key", Severity.HIGH),

    # Heroku
    (r'(?i)heroku[_\-\.]?api[_\-\.]?key\s*[=:]\s*["\']?([0-9a-f\-]{36})["\']?', "Heroku API Key", Severity.HIGH),

    # GitHub tokens
    (r'gh[pousr]_[A-Za-z0-9_]{36,}', "GitHub Token", Severity.CRITICAL),

    # Generic high-entropy strings in key positions
    (r'(?i)(?:secret|token|key|password|passwd|pwd|apikey|api_key|auth)\s*[=:]\s*["\']([A-Za-z0-9@#$%^&*!]{12,})["\']', "Hardcoded Secret", Severity.MEDIUM),
]

# Patterns whose matched VALUE requires high entropy to be a real secret.
# Structural patterns (AWS key prefix, private key header, connection strings)
# are always valid regardless of entropy.
ENTROPY_REQUIRED_TYPES = {
    "API Key/Token", "Access/Auth Token", "JWT Secret",
    "Database Password", "Password in JSON Config", "Secret in JSON Config",
    "Hardcoded Secret", "Encryption Key", "Heroku API Key",
}

# Minimum Shannon entropy (bits/char) for generic secret values.
# Real secrets (hex, base64, random): 3.5-6.0
# English words: 2.0-3.2
# Repeated chars: <2.0
MIN_SECRET_ENTROPY = 3.2


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not s:
        return 0.0
    length = len(s)
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

# Files that commonly contain secrets
INTERESTING_FILES = [
    ".env", ".env.production", ".env.staging", ".env.local", ".env.development",
    "config/production.json", "config/staging.json", "config/default.json",
    "config/database.yml", "config/secrets.yml", "config/credentials.yml",
    "appsettings.json", "appsettings.Production.json",
    "application.properties", "application.yml", "application-prod.yml",
    "docker-compose.yml", "docker-compose.prod.yml",
    "Dockerfile", ".dockerenv",
    "wp-config.php", "settings.py", "local_settings.py",
    "firebase.json", ".firebaserc",
    "serverless.yml", "terraform.tfvars", "terraform.tfstate",
    ".npmrc", ".pypirc", ".gem/credentials",
    "id_rsa", "id_ecdsa", "id_ed25519",
    ".htpasswd", ".pgpass", ".my.cnf", ".netrc",
]

# Generic placeholder values to IGNORE (reduce false positives)
PLACEHOLDER_VALUES = {
    "supersecret", "supersecret!!!!!", "your-secret-here", "changeme",
    "password", "admin", "secret", "test", "example", "placeholder",
    "your-api-key", "your_api_key", "xxx", "TODO", "CHANGEME",
    "replace-me", "insert-here", "your-token", "put-your-key-here",
    "12345678", "abcdefgh", "qwerty", "password123",
    # Common dev/example passwords that pass entropy checks
    "passw0rd", "p@ssw0rd", "p@ssword", "p@ssword1", "password1",
    "devpasswd", "rootpassword", "mysecretpassword", "letmein",
    "some_random_secret_key", "some-random-secret-key",
    "my-secret-key", "my_secret_key", "secretkey", "secret_key",
    "testpassword", "development", "production",
}

# Common CI/test default credentials — always false positives
CI_TEST_CREDENTIALS = {
    "root", "root:root", "postgres", "postgres:postgres",
    "mysql", "mysql:mysql", "redis", "redis:redis",
    "testuser", "testpass", "testpassword", "test123",
    "sa", "localdb", "devpassword", "devuser",
    "db_password", "db_user", "database",
    "passw0rd", "p@ssw0rd", "password1", "admin123",
}

# Docker/container service hostnames — connection strings to these are local dev only
DOCKER_SERVICE_HOSTS = {
    "mysql", "postgres", "postgresql", "redis", "mongo", "mongodb",
    "elasticsearch", "rabbitmq", "memcached", "mariadb", "mssql",
    "db", "database", "cache", "queue", "broker",
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "host.docker.internal", "docker.internal",
}

# File paths that indicate example/demo/template context (always FP for secrets)
EXAMPLE_CONFIG_PATHS = {
    "example", "sample", "template", "demo", "quickstart",
    "bundled", "skeleton", "boilerplate", "starter",
    "getting-started", "getting_started", "tutorial",
    "containers/", "docker/", "docker-compose",
}

# File paths that indicate CI/test context (findings here are almost always FP)
CI_TEST_PATHS = {
    ".github/", "github/actions/", ".circleci/", ".travis.yml",
    "Jenkinsfile", ".gitlab-ci", "docker-compose.test",
    "docker-compose.ci", "test/", "tests/", "spec/",
    "fixtures/", "__tests__/", "e2e/",
}


@dataclass
class SecretFinding:
    """A discovered secret in a GitHub repository"""
    repo_name: str
    file_path: str
    secret_type: str
    matched_value: str
    severity: Severity
    line_number: Optional[int] = None
    commit_sha: Optional[str] = None
    commit_message: Optional[str] = None
    commit_date: Optional[str] = None
    in_history: bool = False  # True if found in git history (was sanitized)
    current_value: Optional[str] = None  # What it was changed TO (if sanitized)
    url: str = ""

    @property
    def was_sanitized(self) -> bool:
        """Check if this secret was found because it was removed/changed"""
        return self.in_history and self.current_value is not None

    @property
    def evidence_url(self) -> str:
        """URL to view the evidence"""
        if self.commit_sha:
            return f"https://github.com/{self.repo_name}/commit/{self.commit_sha}"
        return f"https://github.com/{self.repo_name}/blob/main/{self.file_path}"


class GitHubRecon(BaseScanner):
    """
    GitHub Reconnaissance & Secret Scanner

    Searches public repositories for leaked credentials,
    configuration files, and secrets in git history.

    This exact workflow has produced paid bounties for
    leaked AES encryption keys during real engagements.
    """

    name = "github_recon"
    description = "GitHub repository secret scanner & recon"
    version = "1.0.0"
    owasp_category = "A07:2021 – Identification and Authentication Failures"
    mitre_technique = "T1552.001"  # Unsecured Credentials: Credentials In Files

    checks = [
        "Hardcoded API keys",
        "Database credentials in config",
        "Private keys committed",
        "Secrets in git history",
        "JWT secrets exposed",
        "Encryption keys leaked",
        "Cloud provider credentials",
    ]

    GITHUB_API = "https://api.github.com"
    MAX_REPOS = 30          # Cap repos to scan for large orgs
    MAX_FILES_PER_REPO = 80 # Cap total file reads per repo
    SCANNER_TIMEOUT = 180   # 3-minute hard timeout for entire scan

    def __init__(
        self,
        org_name_or_config: Optional[Any] = None,
        github_token: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        # Handle being called as GitHubRecon(scanner_config) from engine
        # where scanner_config is a dict, not an org name
        if isinstance(org_name_or_config, dict) and config is None:
            config = org_name_or_config
            org_name = ""  # Will be set from target domain at scan time
        else:
            org_name = org_name_or_config or ""

        super().__init__(config)
        self.org_name = org_name
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN", "")
        self.secret_findings: List[SecretFinding] = []
        self._headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "BEATRIX-SecurityScanner/1.0",
        }
        if self.github_token:
            self._headers["Authorization"] = f"token {self.github_token}"

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            headers=self._headers,
        )
        return self

    # =========================================================================
    # MAIN ENTRY POINTS
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Main scan — run full GitHub recon on target org"""
        # If org_name wasn't set at construction (engine passes config dict),
        # derive it from the target domain (e.g., "pinterest.com" -> "pinterest")
        if not self.org_name and (context.url or context.base_url):
            from urllib.parse import urlparse
            from beatrix.utils.helpers import is_ip_address
            raw_target = context.url or context.base_url
            # Skip GitHub recon for IP targets — can't derive an org name from an IP
            if is_ip_address(raw_target):
                self.log("Target is an IP address — skipping GitHub recon")
                return
            parsed = urlparse(raw_target if '://' in raw_target else f'https://{raw_target}')
            domain = parsed.hostname or raw_target
            # Use the domain's second-level label as the org guess
            # e.g., "www.pinterest.com" -> "pinterest"
            parts = domain.replace('www.', '').split('.')
            self.org_name = parts[0] if parts else domain
            self.log(f"Derived GitHub org from target: {self.org_name}")

        if not self.org_name:
            self.log("No org_name set and no target to derive from — skipping GitHub recon")
            return

        # Use a deadline to enforce scanner timeout on async generator
        deadline = asyncio.get_running_loop().time() + self.SCANNER_TIMEOUT
        timed_out = False

        async for finding in self.full_recon():
            yield finding
            if asyncio.get_running_loop().time() >= deadline:
                self.log(f"GitHub recon timed out after {self.SCANNER_TIMEOUT}s — returning partial results")
                timed_out = True
                break

        if timed_out:
            self.log(f"Partial results: {len(self.secret_findings)} secrets found before timeout")

    async def full_recon(self) -> AsyncIterator[Finding]:
        """
        Complete GitHub reconnaissance:
        1. Enumerate org repos
        2. Scan interesting files for secrets
        3. Walk git history for sanitized secrets
        """
        self.log(f"Starting GitHub recon on organization: {self.org_name}")
        self._yielded_keys: Set[tuple] = set()  # Track already-yielded findings

        # Phase 1: Enumerate repos
        repos = await self.enumerate_repos()
        if not repos:
            self.log("No public repositories found")
            return

        # Cap repos for large orgs — prioritize recently updated
        if len(repos) > self.MAX_REPOS:
            self.log(f"Found {len(repos)} repos, capping to {self.MAX_REPOS} most recent")
            repos = repos[:self.MAX_REPOS]
        else:
            self.log(f"Found {len(repos)} public repositories")

        # Phase 2: Scan each repo — yield findings incrementally
        for repo in repos:
            repo_name = repo.get("full_name", "")
            default_branch = repo.get("default_branch", "main")

            self.log(f"Scanning {repo_name}...")
            files_read = 0

            # 2a: Get file tree
            tree = await self.get_repo_tree(repo_name, default_branch)

            # 2b: Scan interesting files for secrets
            interesting = self._filter_interesting_files(tree)
            for file_path in interesting:
                if files_read >= self.MAX_FILES_PER_REPO:
                    break
                content = await self.get_file_content(repo_name, file_path, default_branch)
                files_read += 1
                if content:
                    secrets = self._scan_content_for_secrets(content, repo_name, file_path)
                    self.secret_findings.extend(secrets)
                    # Yield new findings immediately
                    for sf in secrets:
                        key = (sf.repo_name, sf.matched_value, sf.secret_type)
                        if key not in self._yielded_keys:
                            self._yielded_keys.add(key)
                            yield self._secret_to_finding(sf)

            # 2c: Also scan config files
            config_files = [
                f for f in tree
                if any(f.endswith(ext) for ext in [
                    '.json', '.yml', '.yaml', '.env', '.cfg', '.ini',
                    '.conf', '.properties', '.toml', '.xml',
                ]) and f not in interesting
            ]
            for file_path in config_files[:30]:  # Tighter cap
                if files_read >= self.MAX_FILES_PER_REPO:
                    break
                content = await self.get_file_content(repo_name, file_path, default_branch)
                files_read += 1
                if content:
                    secrets = self._scan_content_for_secrets(content, repo_name, file_path)
                    self.secret_findings.extend(secrets)
                    for sf in secrets:
                        key = (sf.repo_name, sf.matched_value, sf.secret_type)
                        if key not in self._yielded_keys:
                            self._yielded_keys.add(key)
                            yield self._secret_to_finding(sf)

            # 2d: Scan source code files for hardcoded secrets
            source_files = [
                f for f in tree
                if any(f.endswith(ext) for ext in [
                    '.js', '.ts', '.py', '.rb', '.go', '.java', '.php',
                    '.cs', '.swift', '.kt',
                ]) and f not in interesting and f not in config_files
            ]
            for file_path in source_files[:50]:  # Tighter cap
                if files_read >= self.MAX_FILES_PER_REPO:
                    break
                content = await self.get_file_content(repo_name, file_path, default_branch)
                files_read += 1
                if content:
                    secrets = self._scan_content_for_secrets(content, repo_name, file_path)
                    self.secret_findings.extend(secrets)
                    for sf in secrets:
                        key = (sf.repo_name, sf.matched_value, sf.secret_type)
                        if key not in self._yielded_keys:
                            self._yielded_keys.add(key)
                            yield self._secret_to_finding(sf)

            # Phase 3: Check git history for sanitized secrets
            history_secrets = await self.scan_git_history(repo_name)
            self.secret_findings.extend(history_secrets)
            for sf in history_secrets:
                key = (sf.repo_name, sf.matched_value, sf.secret_type)
                if key not in self._yielded_keys:
                    self._yielded_keys.add(key)
                    yield self._secret_to_finding(sf)

            # Respect rate limits between repos
            await self._respect_rate_limit()

        self.log(f"GitHub recon complete. {len(self._yielded_keys)} unique secrets found.")

    # =========================================================================
    # GITHUB API METHODS
    # =========================================================================

    async def enumerate_repos(self) -> List[Dict]:
        """List all public repositories for the organization"""
        repos = []
        page = 1

        while True:
            try:
                # Try org endpoint first
                resp = await self.get(
                    f"{self.GITHUB_API}/orgs/{self.org_name}/repos",
                    params={"type": "public", "per_page": 100, "page": page},
                )

                if resp.status_code == 404:
                    # Might be a user, not an org
                    resp = await self.get(
                        f"{self.GITHUB_API}/users/{self.org_name}/repos",
                        params={"type": "public", "per_page": 100, "page": page},
                    )

                if resp.status_code != 200:
                    self.log(f"API error {resp.status_code}: {resp.text[:200]}")
                    break

                data = resp.json()
                if not data:
                    break

                repos.extend(data)

                if len(data) < 100:
                    break
                page += 1

            except Exception as e:
                self.log(f"Error enumerating repos: {e}")
                break

        # Sort by last updated (most recently active first)
        repos.sort(key=lambda r: r.get("updated_at", ""), reverse=True)
        return repos

    async def _respect_rate_limit(self, min_remaining: int = 10) -> None:
        """Check GitHub rate limit headers and back off if needed."""
        try:
            resp = await self.get(f"{self.GITHUB_API}/rate_limit")
            if resp.status_code == 200:
                data = resp.json()
                remaining = data.get("resources", {}).get("core", {}).get("remaining", 999)
                reset_ts = data.get("resources", {}).get("core", {}).get("reset", 0)
                if remaining < min_remaining:
                    wait = max(reset_ts - int(datetime.now().timestamp()), 1)
                    wait = min(wait, 60)  # Cap wait at 60s
                    self.log(f"Rate limit low ({remaining} remaining), sleeping {wait}s")
                    await asyncio.sleep(wait)
                else:
                    await asyncio.sleep(0.3)  # Brief courtesy delay
            else:
                await asyncio.sleep(0.5)
        except Exception:
            await asyncio.sleep(0.5)

    async def get_repo_tree(self, repo_name: str, branch: str = "main") -> List[str]:
        """Get full file tree of a repository"""
        try:
            resp = await self.get(
                f"{self.GITHUB_API}/repos/{repo_name}/git/trees/{branch}",
                params={"recursive": "1"},
            )

            if resp.status_code != 200:
                # Try 'master' if 'main' fails
                if branch == "main":
                    return await self.get_repo_tree(repo_name, "master")
                return []

            data = resp.json()
            return [item["path"] for item in data.get("tree", []) if item.get("type") == "blob"]

        except Exception as e:
            self.log(f"Error getting tree for {repo_name}: {e}")
            return []

    async def get_file_content(
        self, repo_name: str, file_path: str, branch: str = "main"
    ) -> Optional[str]:
        """Get raw file content from a repository"""
        try:
            resp = await self.get(
                f"https://raw.githubusercontent.com/{repo_name}/{branch}/{file_path}",
                headers={"Accept": "text/plain"},
            )

            if resp.status_code == 200:
                # Skip binary files
                try:
                    return resp.text
                except UnicodeDecodeError:
                    return None
            return None

        except Exception as e:
            self.log(f"Error reading {file_path}: {e}")
            return None

    async def get_commits(
        self, repo_name: str, path: Optional[str] = None, max_commits: int = 50
    ) -> List[Dict]:
        """Get commit history, optionally filtered by path"""
        try:
            params = {"per_page": min(max_commits, 100)}
            if path:
                params["path"] = path

            resp = await self.get(
                f"{self.GITHUB_API}/repos/{repo_name}/commits",
                params=params,
            )

            if resp.status_code != 200:
                return []

            return resp.json()

        except Exception as e:
            self.log(f"Error getting commits: {e}")
            return []

    async def get_commit_diff(self, repo_name: str, commit_sha: str) -> Optional[str]:
        """Get the diff for a specific commit"""
        try:
            resp = await self.get(
                f"https://github.com/{repo_name}/commit/{commit_sha}.diff",
                headers={"Accept": "text/plain", "User-Agent": "BEATRIX/1.0"},
            )

            if resp.status_code == 200:
                return resp.text
            return None

        except Exception as e:
            self.log(f"Error getting diff for {commit_sha}: {e}")
            return None

    # =========================================================================
    # SECRET SCANNING
    # =========================================================================

    def _scan_content_for_secrets(
        self,
        content: str,
        repo_name: str,
        file_path: str,
    ) -> List[SecretFinding]:
        """Scan file content against all secret patterns"""
        findings = []
        lines = content.split('\n')

        for pattern, secret_type, severity in SECRET_PATTERNS:
            for i, line in enumerate(lines, 1):
                matches = re.finditer(pattern, line)
                for match in matches:
                    value = match.group(1) if match.lastindex else match.group(0)

                    # Skip placeholder values
                    if self._is_placeholder(value):
                        continue

                    # Skip very short matches (likely false positives)
                    if len(value) < 4:
                        continue

                    # Skip values that look like code (function calls, method chains)
                    if self._is_code_pattern(value):
                        continue

                    # Skip low-entropy matches for generic patterns (English words)
                    if secret_type in ENTROPY_REQUIRED_TYPES:
                        entropy = _shannon_entropy(value)
                        if entropy < MIN_SECRET_ENTROPY:
                            continue

                    # Commented-out lines are usually documentation/example
                    # snippets, not live secrets — "mysql://username:password
                    # @hostname/database" in a doc comment is a syntax example,
                    # not a leak. Only keep it if the value still looks like a
                    # genuine secret (high entropy) rather than dictionary
                    # placeholder words used as connection-string components.
                    stripped = line.strip()
                    if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
                        looks_like_docs = (
                            any(p in value.lower() for p in
                                ['example', 'test', 'sample', 'todo',
                                 'username', 'password', 'hostname', 'changeme'])
                            or _shannon_entropy(value) < MIN_SECRET_ENTROPY
                        )
                        if looks_like_docs:
                            continue

                    # Skip CI/test credentials (almost always FP)
                    if self._is_ci_test_credential(value, file_path):
                        continue

                    # Skip Docker/container dev secrets (local-only, not exploitable)
                    if self._is_docker_dev_secret(value, file_path):
                        continue

                    findings.append(SecretFinding(
                        repo_name=repo_name,
                        file_path=file_path,
                        secret_type=secret_type,
                        matched_value=value,
                        severity=severity,
                        line_number=i,
                        url=f"https://github.com/{repo_name}/blob/main/{file_path}#L{i}",
                    ))

        return findings

    def _is_code_pattern(self, value: str) -> bool:
        """Check if a matched value looks like code rather than an actual secret."""
        v = value.strip().strip('"\'')

        # Function calls: Fernet.generate_key(), encrypt(password), etc.
        if '(' in v and ')' in v:
            return True

        # Method chains: key.decode('utf-8'), obj.method()
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\.', v):
            return True

        # Variable references: ${VAR}, $VAR, os.environ.get(...)
        if v.startswith('$') or v.startswith('os.environ') or v.startswith('process.env'):
            return True

        # Common code patterns: None, True, False, null, undefined
        if v.lower() in ('none', 'true', 'false', 'null', 'undefined', 'nil'):
            return True

        # Template literals: {{ }}, {% %}
        if '{{' in v or '{%' in v:
            return True

        # Objective-C/Swift k-prefix constants: kPlainErrorKey, kSecAttrAccount, etc.
        if re.match(r'^k[A-Z][a-zA-Z]{4,}', v):
            return True

        # ALL_CAPS_CONSTANT references (not values): ERROR_KEY, SECRET_NAME, etc.
        if re.match(r'^[A-Z][A-Z0-9_]{3,}$', v) and '_' in v:
            return True

        # Variable/identifier names: env_access_token, my_api_key, authToken, etc.
        # Real secrets don't contain underscores separating English words
        if re.match(r'^[a-z][a-z0-9]*(?:_[a-z][a-z0-9]*){2,}$', v):
            return True

        # camelCase identifiers: accessToken, translatedCount, processorExceptions
        if re.match(r'^[a-z]+(?:[A-Z][a-z0-9]+)+$', v):
            return True

        # PascalCase identifiers: AccessTokenCommon, DataInputStream, etc.
        if re.match(r'^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+$', v):
            return True

        # English words joined by underscores/hyphens — not secrets
        # e.g., "transaction_count", "manually_redirected", "internal_failure"
        words = re.split(r'[_\-]', v.lower())
        if len(words) >= 2 and all(w.isalpha() and len(w) >= 3 for w in words):
            return True

        # Test fixture tokens: test-access-token-1, mock-bearer-token, etc.
        if re.match(r'^(?:test|mock|fake|stub|dummy)[_\-]', v, re.I):
            return True

        return False

    def _is_ci_test_credential(self, value: str, file_path: str = "") -> bool:
        """Check if this is a common CI/test default credential (false positive)."""
        v = value.lower().strip().strip('"\'')

        # Check value against known CI/test defaults
        if v in CI_TEST_CREDENTIALS:
            return True

        # Check if the file is in a CI/test path
        fp = file_path.lower()
        if any(ci_path in fp for ci_path in CI_TEST_PATHS):
            return True

        return False

    def _is_docker_dev_secret(self, value: str, file_path: str = "") -> bool:
        """Check if a connection string or secret points to a Docker/local dev environment."""
        v = value.lower().strip().strip('"\'')
        fp = file_path.lower()

        # Connection string analysis: extract hostname from URI patterns
        # mysql+pymysql://user:pass@hostname:port/db, redis://x:pass@hostname, etc.
        conn_match = re.match(
            r'(?:mysql|postgres|postgresql|redis|mongo|mongodb|amqp|mssql)'
            r'(?:\+[a-z]+)?://[^@]*@([^:/\s]+)',
            v,
        )
        if conn_match:
            host = conn_match.group(1)
            if host in DOCKER_SERVICE_HOSTS:
                return True

        # File path indicates container/docker example context
        if any(ctx in fp for ctx in EXAMPLE_CONFIG_PATHS):
            # For connection strings in example configs, always FP
            if any(proto in v for proto in ('://', 'conn', 'connection')):
                return True
            # For other secrets in example configs with dev-looking values
            if any(dev_val in v for dev_val in (
                'passw0rd', 'password', 'secret', 'test', 'changeme',
                'some_random', 'some-random', 'my_secret', 'my-secret',
            )):
                return True

        # FLASK_SECRET_KEY, DJANGO_SECRET_KEY with obviously fake values
        if any(kw in v for kw in ('some_random_secret', 'change_me', 'replace_this')):
            return True

        return False

    def _is_placeholder(self, value: str) -> bool:
        """Check if a matched value is just a placeholder"""
        v = value.lower().strip().strip('"\'')

        # Exact match against known placeholders
        if v in PLACEHOLDER_VALUES:
            return True

        # Patterns that indicate placeholder
        placeholder_patterns = [
            r'^your[_\-]',
            r'^<.*>$',
            r'^\$\{',
            r'^%\(',
            r'x{4,}',
            r'^todo',
            r'^change',
            r'^replace',
            r'^insert',
            r'^put[_\-]',
            r'^enter[_\-]',
            r'^fake',
            r'^dummy',
            r'^sample',
            r'^example',
            r'^test[_\-]?(?:key|token|secret|pass)',
        ]

        for p in placeholder_patterns:
            if re.match(p, v, re.IGNORECASE):
                return True

        return False

    def _filter_interesting_files(self, tree: List[str]) -> List[str]:
        """Filter the file tree to find interesting config files"""
        interesting = []

        for file_path in tree:
            basename = os.path.basename(file_path)

            # Exact match against known interesting files
            if basename in INTERESTING_FILES or file_path in INTERESTING_FILES:
                interesting.append(file_path)
                continue

            # Patterns that match interesting files
            if any([
                basename.startswith('.env'),
                'config' in file_path.lower() and any(
                    file_path.endswith(ext) for ext in ['.json', '.yml', '.yaml', '.xml', '.properties']
                ),
                basename in ['secrets.json', 'credentials.json', 'auth.json'],
                'production' in basename.lower() and any(
                    file_path.endswith(ext) for ext in ['.json', '.yml', '.yaml', '.xml']
                ),
                basename == '.npmrc' or basename == '.pypirc',
            ]):
                interesting.append(file_path)

        return interesting

    # =========================================================================
    # GIT HISTORY ANALYSIS
    # =========================================================================

    async def scan_git_history(
        self,
        repo_name: str,
        max_commits: int = 30,
    ) -> List[SecretFinding]:
        """
        Walk git history looking for secrets that were committed then removed.

        This technique catches secrets committed then removed — e.g., a developer
        commits production keys, then later replaces them with "supersecret!!!!!".
        The git diff permanently preserves the original values.
        """
        findings = []

        # Get commits that modified config/env files

        commits = await self.get_commits(repo_name, max_commits=max_commits)

        for commit in commits:
            sha = commit.get("sha", "")
            message = commit.get("commit", {}).get("message", "")
            date = commit.get("commit", {}).get("committer", {}).get("date", "")

            # Prioritize commits with suspicious messages
            msg_lower = message.lower()
            is_suspicious = any(kw in msg_lower for kw in [
                'remove', 'delete', 'clean', 'sanitize', 'redact', 'hide',
                'update', 'fix', 'change', 'rotate', 'mask', 'obfuscate',
                'security', 'secret', 'credential', 'password', 'key', 'token',
                'config', 'env', 'production', '.env',
            ])

            if not is_suspicious:
                continue

            # Get the diff
            diff = await self.get_commit_diff(repo_name, sha)
            if not diff:
                continue

            # Parse diff for removed lines containing secrets
            diff_findings = self._parse_diff_for_secrets(diff, repo_name, sha, message, date)
            findings.extend(diff_findings)

            # Rate limiting
            await asyncio.sleep(0.3)

        return findings

    def _parse_diff_for_secrets(
        self,
        diff: str,
        repo_name: str,
        commit_sha: str,
        commit_message: str,
        commit_date: str,
    ) -> List[SecretFinding]:
        """Parse a git diff to find secrets in removed lines"""
        findings = []
        current_file = None

        for line in diff.split('\n'):
            # Track which file we're in
            if line.startswith('--- a/') or line.startswith('+++ b/'):
                file_path = line[6:] if line.startswith('+++ b/') else line[6:]
                if line.startswith('+++ b/'):
                    current_file = file_path
                continue

            # Look at REMOVED lines (lines starting with -)
            # These are the lines that CONTAINED secrets before sanitization
            if line.startswith('-') and not line.startswith('---'):
                removed_content = line[1:]  # Strip the leading -

                for pattern, secret_type, severity in SECRET_PATTERNS:
                    matches = re.finditer(pattern, removed_content)
                    for match in matches:
                        value = match.group(1) if match.lastindex else match.group(0)

                        if self._is_placeholder(value):
                            continue

                        if len(value) < 4:
                            continue

                        # Check if the ADDED line has a different (sanitized) value
                        # This is the key insight: if the same key was changed from
                        # a real value to a placeholder, it WAS a real secret
                        # Skip Docker/container dev secrets in history too
                        if self._is_docker_dev_secret(value, current_file or ""):
                            continue

                        # Skip code patterns in diffs (variable names, UI tokens)
                        if self._is_code_pattern(value):
                            continue

                        # Entropy filter for generic patterns in diffs
                        if secret_type in ENTROPY_REQUIRED_TYPES:
                            entropy = _shannon_entropy(value)
                            if entropy < MIN_SECRET_ENTROPY:
                                continue

                        finding = SecretFinding(
                            repo_name=repo_name,
                            file_path=current_file or "unknown",
                            secret_type=f"{secret_type} (in git history)",
                            matched_value=value,
                            severity=severity,
                            commit_sha=commit_sha,
                            commit_message=commit_message,
                            commit_date=commit_date,
                            in_history=True,
                            url=f"https://github.com/{repo_name}/commit/{commit_sha}",
                        )
                        findings.append(finding)

        return findings

    # =========================================================================
    # DEDUPLICATION & REPORTING
    # =========================================================================

    def _deduplicate_findings(self) -> List[SecretFinding]:
        """Remove duplicate secret findings"""
        seen = set()
        deduped = []

        for sf in self.secret_findings:
            # Key is the actual secret value + repo
            key = (sf.repo_name, sf.matched_value, sf.secret_type)
            if key not in seen:
                seen.add(key)
                deduped.append(sf)

        # Sort by severity (critical first), then by whether it's a history find
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        deduped.sort(key=lambda x: (severity_order.get(x.severity, 5), not x.in_history))

        return deduped

    def _secret_to_finding(self, sf: SecretFinding) -> Finding:
        """Convert a SecretFinding to a BEATRIX Finding"""
        if sf.in_history:
            description = (
                f"**{sf.secret_type}** found in git commit history of `{sf.repo_name}`.\n\n"
                f"The secret was committed and later sanitized, but remains permanently "
                f"recoverable from the git diff.\n\n"
                f"**Commit:** `{sf.commit_sha[:12]}`\n"
                f"**Message:** {sf.commit_message}\n"
                f"**Date:** {sf.commit_date}\n\n"
                f"**Evidence URL:** {sf.url}\n\n"
                f"**Reproduce:**\n```\n"
                f"curl -s {sf.url}.diff\n"
                f"```"
            )
        else:
            description = (
                f"**{sf.secret_type}** found in `{sf.file_path}` "
                f"of public repo `{sf.repo_name}`.\n\n"
                f"**Line:** {sf.line_number}\n"
                f"**Evidence URL:** {sf.url}\n\n"
                f"**Reproduce:**\n```\n"
                f"curl -s https://raw.githubusercontent.com/{sf.repo_name}/main/{sf.file_path}\n"
                f"```"
            )

        # Mask the actual secret value in the finding (show first/last 4 chars)
        if len(sf.matched_value) > 12:
            masked = sf.matched_value[:4] + "..." + sf.matched_value[-4:]
        else:
            masked = sf.matched_value[:2] + "..." + sf.matched_value[-2:]

        return self.create_finding(
            title=f"{sf.secret_type} in {sf.repo_name}",
            severity=sf.severity,
            confidence=Confidence.CERTAIN if sf.in_history else Confidence.FIRM,
            url=sf.url,
            description=description,
            evidence=f"Matched value: {masked} (full value available for verification)",
            remediation=(
                "1. Rotate the exposed credential immediately\n"
                "2. Audit usage of the credential for unauthorized access\n"
                "3. Use BFG Repo-Cleaner or git filter-branch to purge from history\n"
                "4. Move secrets to a secrets manager (Vault, AWS Secrets Manager)\n"
                "5. Add secret scanning to CI/CD pipeline (e.g., gitleaks, truffleHog)"
            ),
            references=[
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                sf.url,
            ],
        )

    # =========================================================================
    # CONVENIENCE METHODS
    # =========================================================================

    async def quick_scan(self, repo_name: Optional[str] = None) -> List[SecretFinding]:
        """
        Quick scan — just check interesting files, no history walk.
        Use for fast initial assessment.
        """
        if repo_name:
            repos = [{"full_name": repo_name, "default_branch": "main"}]
        else:
            repos = await self.enumerate_repos()

        for repo in repos:
            name = repo.get("full_name", "")
            branch = repo.get("default_branch", "main")

            tree = await self.get_repo_tree(name, branch)
            interesting = self._filter_interesting_files(tree)

            for file_path in interesting:
                content = await self.get_file_content(name, file_path, branch)
                if content:
                    secrets = self._scan_content_for_secrets(content, name, file_path)
                    self.secret_findings.extend(secrets)

        return self._deduplicate_findings()

    def generate_report(self) -> str:
        """Generate a markdown report of all findings"""
        deduped = self._deduplicate_findings()

        if not deduped:
            return f"# GitHub Recon Report: {self.org_name}\n\nNo secrets found."

        lines = [
            f"# GitHub Recon Report: {self.org_name}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Total Findings:** {len(deduped)}",
            "",
            "## Summary",
            "",
            "| # | Severity | Type | Repository | File | In History? |",
            "|---|----------|------|------------|------|-------------|",
        ]

        for i, sf in enumerate(deduped, 1):
            history_marker = "YES (sanitized)" if sf.in_history else "No"
            lines.append(
                f"| {i} | {sf.severity.value.upper()} | {sf.secret_type} | "
                f"`{sf.repo_name}` | `{sf.file_path}` | {history_marker} |"
            )

        lines.extend(["", "## Detailed Findings", ""])

        for i, sf in enumerate(deduped, 1):
            lines.extend([
                f"### Finding {i}: {sf.secret_type}",
                f"- **Severity:** {sf.severity.value.upper()}",
                f"- **Repository:** `{sf.repo_name}`",
                f"- **File:** `{sf.file_path}`",
                f"- **Evidence:** [{sf.evidence_url}]({sf.evidence_url})",
            ])

            if sf.in_history:
                lines.extend([
                    f"- **Commit:** `{sf.commit_sha[:12]}`",
                    f"- **Commit Message:** {sf.commit_message}",
                    f"- **Commit Date:** {sf.commit_date}",
                    "- **Note:** This secret was sanitized but remains in git history",
                ])

            lines.append("")

        return "\n".join(lines)


# =============================================================================
# CLI INTERFACE
# =============================================================================

async def main():
    """CLI entry point for GitHub recon"""
    import argparse

    parser = argparse.ArgumentParser(description="BEATRIX GitHub Secret Scanner")
    parser.add_argument("org", help="GitHub organization or user to scan")
    parser.add_argument("--repo", help="Specific repo to scan (org/repo format)")
    parser.add_argument("--token", help="GitHub personal access token")
    parser.add_argument("--quick", action="store_true", help="Quick scan (no history)")
    parser.add_argument("--output", help="Output file for report (markdown)")

    args = parser.parse_args()

    scanner = GitHubRecon(
        org_name=args.org,
        github_token=args.token,
    )

    async with scanner:
        if args.quick:
            findings = await scanner.quick_scan(args.repo)
            print(f"\n[+] Found {len(findings)} secrets")
            for sf in findings:
                print(f"  [{sf.severity.value.upper()}] {sf.secret_type} in {sf.file_path}")
                print(f"    → {sf.evidence_url}")
        else:
            findings = []
            async for finding in scanner.full_recon():
                findings.append(finding)
                print(f"  [{finding.severity.value.upper()}] {finding.title}")

        if args.output:
            report = scanner.generate_report()
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
