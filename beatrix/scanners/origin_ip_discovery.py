"""
Origin IP Discovery Module

Discovers real origin IPs behind CDN/WAF services like Cloudflare.
Uses multiple techniques: DNS history, SSL certificates, subdomains, etc.

Techniques implemented:
1. DNS History (via SecurityTrails, ViewDNS, DNSDumpster)
2. SSL Certificate Search (via Censys, crt.sh)
3. Subdomain IP Correlation
4. Common Misconfiguration Checks
5. Mail Server Analysis (MX records often reveal origin)
6. Direct IP Scanning (via Shodan, Censys)
"""

import asyncio
import json
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import aiohttp

# CDN/WAF IP ranges (partial - for detection)
CLOUDFLARE_IP_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Cloudflare DNS / WARP — NOT origin IPs
    "1.0.0.0/24", "1.1.1.0/24",
]

AKAMAI_IP_RANGES = [
    "23.0.0.0/12", "23.192.0.0/11", "23.32.0.0/11", "23.64.0.0/14",
    "104.64.0.0/10"
]

FASTLY_IP_RANGES = [
    "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
    "103.245.224.0/24", "104.156.80.0/20", "151.101.0.0/16", "157.52.64.0/18",
    "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
    "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16"
]

# Known hosting/SaaS provider IP ranges — these are NEVER the target's
# origin IP, they're shared infrastructure serving many tenants.
HOSTING_PROVIDER_RANGES = [
    # Shopify
    "23.227.32.0/20",       # 23.227.32.0 – 23.227.47.255
    # Heroku
    "3.0.0.0/15", "52.0.0.0/11",   # subset of AWS used by Heroku
    # GitHub Pages
    "185.199.108.0/22",
    # Netlify
    "75.2.60.0/24", "99.83.231.0/24",
    # Vercel
    "76.76.21.0/24",
    # Squarespace
    "198.185.159.0/24", "198.49.23.0/24",
    # Wix
    "185.230.63.0/24", "185.230.60.0/22",
    # WordPress.com (Automattic)
    "192.0.64.0/18",
    # Webflow (ASN 209242 — shared hosting for Webflow sites)
    "198.202.208.0/20",     # 198.202.208.0 – 198.202.223.255
    # Ghost(Pro)
    "178.128.0.0/15",       # subset of DigitalOcean used by Ghost(Pro)
    # Fly.io (commonly used by SaaS/hosting)
    "66.241.124.0/24", "137.66.0.0/16",
]

# Subdomains that typically point to third-party SaaS, not the origin.
# IPs from these should be heavily penalized or excluded.
THIRD_PARTY_SUBDOMAIN_PREFIXES = [
    "shop", "store", "blog", "mail", "email", "smtp", "imap", "pop",
    "support", "help", "helpdesk", "desk", "status", "docs", "wiki",
    "calendar", "meet", "chat", "slack", "jira", "confluence",
    "sentry", "cdn", "static", "assets", "media", "img", "images",
    "staging", "dev", "test", "sandbox", "demo", "preview",
    "autodiscover", "lyncdiscover", "sip", "selector1", "selector2",
    "em", "click", "track", "link", "go", "redirect",
]


@dataclass
class OriginIPResult:
    """Result from origin IP discovery"""
    domain: str
    discovered_ips: List[Dict[str, Any]] = field(default_factory=list)
    cdn_detected: Optional[str] = None
    cdn_ips: List[str] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class OriginIPDiscovery:
    """
    Multi-technique origin IP discovery for CDN bypass
    """

    def __init__(self, config: Optional[Dict] = None):
        import os

        self.config = config or {}
        self.timeout = aiohttp.ClientTimeout(total=30)
        self.results: List[OriginIPResult] = []

        # API keys — config dict wins, then environment variables, then None
        self.securitytrails_key = (
            self.config.get('securitytrails_api_key')
            or os.environ.get('SECURITYTRAILS_API_KEY')
        )
        self.censys_id = (
            self.config.get('censys_api_id')
            or os.environ.get('CENSYS_API_ID')
        )
        self.censys_secret = (
            self.config.get('censys_api_secret')
            or os.environ.get('CENSYS_API_SECRET')
        )
        self.shodan_key = (
            self.config.get('shodan_api_key')
            or os.environ.get('SHODAN_API_KEY')
        )

        # User agent rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]

    async def run(self, target: str, shared_data: dict = None) -> dict:
        """
        Beatrix module interface - wraps discover() method

        Args:
            target: Target URL or domain
            shared_data: Shared data from other modules (unused)

        Returns:
            Module results in Beatrix format
        """
        # Extract domain from URL if needed
        if '://' in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            domain = parsed.netloc
        else:
            domain = target.split('/')[0]

        print(f"[*] Running Origin IP Discovery on {domain}")

        try:
            result = await self.discover(domain)

            # Convert to Beatrix findings format
            findings = []
            for ip_info in result.discovered_ips:
                findings.append({
                    'type': 'origin_ip',
                    'severity': 'info' if ip_info.get('confidence', 0) < 0.7 else 'medium',
                    'domain': domain,
                    'ip': ip_info.get('ip'),
                    'confidence': ip_info.get('confidence', 0),
                    'source': ip_info.get('source', 'unknown'),
                    'validated': ip_info.get('validated', False),
                    'cdn_detected': result.cdn_detected,
                    'description': f"Potential origin IP: {ip_info.get('ip')} (confidence: {ip_info.get('confidence', 0)*100:.0f}%)",
                    'recommendation': f"Test {ip_info.get('ip')} with Host header set to {domain}"
                })

            return {
                'module': 'origin',
                'domain': domain,
                'cdn_detected': result.cdn_detected,
                'cdn_ips': result.cdn_ips,
                'findings': findings,
                'techniques_used': result.techniques_used,
                'total_ips_discovered': len(result.discovered_ips),
                'high_confidence': len([ip for ip in result.discovered_ips if ip.get('confidence', 0) >= 0.7])
            }

        except Exception as e:
            print(f"[!] Origin IP discovery error: {e}")
            return {
                'module': 'origin',
                'domain': domain,
                'error': str(e),
                'findings': [],
                'total_ips_discovered': 0,
                'high_confidence': 0
            }

    async def discover(self, domain: str) -> OriginIPResult:
        """
        Run all origin IP discovery techniques against a domain
        """
        result = OriginIPResult(domain=domain)

        # First, detect CDN
        result.cdn_detected, result.cdn_ips = await self.detect_cdn(domain)

        # Run discovery techniques in parallel
        techniques = [
            self._dns_history_lookup(domain),
            self._ssl_certificate_search(domain),
            self._mx_record_analysis(domain),
            self._subdomain_correlation(domain),
            self._common_misconfigs(domain),
            self._historical_whois(domain),
        ]

        # Add API-based techniques if keys available
        if self.securitytrails_key:
            techniques.append(self._securitytrails_history(domain))
        if self.censys_id and self.censys_secret:
            techniques.append(self._censys_certificate_search(domain))
        if self.shodan_key:
            techniques.append(self._shodan_search(domain))

        # Execute all techniques
        technique_results = await asyncio.gather(*techniques, return_exceptions=True)

        # Aggregate results
        seen_ips: Set[str] = set()
        for tech_result in technique_results:
            if isinstance(tech_result, Exception):
                continue
            if isinstance(tech_result, dict) and tech_result.get('ips'):
                result.techniques_used.append(tech_result.get('technique', 'unknown'))
                for ip_info in tech_result['ips']:
                    ip = ip_info.get('ip')
                    if ip and ip not in seen_ips and not self._is_cdn_ip(ip):
                        seen_ips.add(ip)
                        result.discovered_ips.append(ip_info)
                        result.confidence_scores[ip] = ip_info.get('confidence', 0.5)

        # Validate discovered IPs
        validated = await self._validate_origin_ips(domain, result.discovered_ips)
        result.discovered_ips = validated

        self.results.append(result)
        return result

    async def detect_cdn(self, domain: str) -> tuple:
        """Detect if domain is behind a CDN/WAF"""
        cdn_detected = None
        cdn_ips = []

        try:
            # Resolve domain
            ips = socket.gethostbyname_ex(domain)[2]
            cdn_ips = ips

            # Check against known CDN ranges
            for ip in ips:
                if self._ip_in_ranges(ip, CLOUDFLARE_IP_RANGES):
                    cdn_detected = "Cloudflare"
                    break
                elif self._ip_in_ranges(ip, AKAMAI_IP_RANGES):
                    cdn_detected = "Akamai"
                    break
                elif self._ip_in_ranges(ip, FASTLY_IP_RANGES):
                    cdn_detected = "Fastly"
                    break

            # Check HTTP headers for CDN signatures
            if not cdn_detected:
                cdn_detected = await self._detect_cdn_headers(domain)

        except Exception:
            pass

        return cdn_detected, cdn_ips

    async def _detect_cdn_headers(self, domain: str) -> Optional[str]:
        """Detect CDN from HTTP response headers"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    f"https://{domain}",
                    allow_redirects=True,
                    ssl=False
                ) as resp:
                    headers = resp.headers

                    # Cloudflare
                    if 'cf-ray' in headers or 'cf-cache-status' in headers:
                        return "Cloudflare"

                    # Akamai — header *names* commonly carry the signal
                    # (Akamai-Request-BC, X-Akamai-Transformed, ...) without
                    # a consistent prefix, and the Server header is usually
                    # just the origin's own value (e.g. "nginx") since Akamai
                    # passes it through. Search the full header blob, not
                    # just Server, and don't require an "x-" prefix.
                    if 'akamai' in str(headers).lower():
                        return "Akamai"

                    # Fastly
                    if 'x-fastly' in headers or 'fastly' in headers.get('via', '').lower():
                        return "Fastly"

                    # AWS CloudFront
                    if 'x-amz-cf-id' in headers or 'cloudfront' in headers.get('via', '').lower():
                        return "CloudFront"

                    # Sucuri
                    if 'x-sucuri' in headers or 'sucuri' in headers.get('server', '').lower():
                        return "Sucuri"

                    # Incapsula
                    if 'x-cdn' in headers and 'incapsula' in headers.get('x-cdn', '').lower():
                        return "Incapsula"

        except Exception:
            pass

        return None

    async def _dns_history_lookup(self, domain: str) -> Dict:
        """Look up historical DNS records via free sources"""
        result = {'technique': 'DNS History', 'ips': []}

        # Try ViewDNS.info (free, no API key needed)
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"https://viewdns.info/iphistory/?domain={domain}"
                async with session.get(url, headers={'User-Agent': self.user_agents[0]}) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        # Parse IP addresses from the response
                        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                        ips = re.findall(ip_pattern, html)
                        for ip in set(ips):
                            if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                                result['ips'].append({
                                    'ip': ip,
                                    'source': 'ViewDNS History',
                                    'confidence': 0.6
                                })
        except Exception:
            pass

        # Try DNSDumpster
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # Get CSRF token first
                async with session.get('https://dnsdumpster.com/') as resp:
                    html = await resp.text()
                    csrf_match = re.search(r'csrfmiddlewaretoken.*?value=["\']([^"\']+)', html)
                    if csrf_match:
                        csrf_token = csrf_match.group(1)

                        # Submit domain lookup
                        data = {
                            'csrfmiddlewaretoken': csrf_token,
                            'targetip': domain,
                            'user': 'free'
                        }
                        headers = {
                            'Referer': 'https://dnsdumpster.com/',
                            'User-Agent': self.user_agents[1]
                        }
                        async with session.post(
                            'https://dnsdumpster.com/',
                            data=data,
                            headers=headers
                        ) as post_resp:
                            if post_resp.status == 200:
                                result_html = await post_resp.text()
                                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', result_html)
                                for ip in set(ips):
                                    if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                                        if not any(r['ip'] == ip for r in result['ips']):
                                            result['ips'].append({
                                                'ip': ip,
                                                'source': 'DNSDumpster',
                                                'confidence': 0.5
                                            })
        except Exception:
            pass

        return result

    async def _ssl_certificate_search(self, domain: str) -> Dict:
        """Search for SSL certificates via crt.sh to find origin IPs"""
        result = {'technique': 'SSL Certificate Search', 'ips': []}

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        try:
                            certs = await resp.json()
                            # Extract unique names from certificates
                            names = set()
                            for cert in certs[:50]:  # Limit to prevent overwhelming
                                name = cert.get('name_value', '')
                                for n in name.split('\n'):
                                    n = n.strip().lower()
                                    if n and '*' not in n and domain in n:
                                        names.add(n)

                            # Resolve each subdomain
                            for name in list(names)[:20]:
                                try:
                                    # Skip subdomains that obviously point to SaaS
                                    is_third_party = self._is_third_party_subdomain(name, domain)

                                    ips = socket.gethostbyname_ex(name)[2]
                                    for ip in ips:
                                        if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                                            if not any(r['ip'] == ip for r in result['ips']):
                                                # Third-party subdomains (shop.*, blog.*, etc.)
                                                # get heavily penalized — their IPs are almost
                                                # never the real origin.
                                                conf = 0.2 if is_third_party else 0.7
                                                result['ips'].append({
                                                    'ip': ip,
                                                    'source': f'SSL Cert ({name})',
                                                    'confidence': conf,
                                                })
                                except Exception:
                                    pass
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass

        return result

    async def _mx_record_analysis(self, domain: str) -> Dict:
        """Analyze MX records - mail servers often reveal origin"""
        result = {'technique': 'MX Record Analysis', 'ips': []}

        try:

            # Get MX records
            proc = await asyncio.create_subprocess_exec(
                'dig', '+short', 'MX', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            mx_records = stdout.decode().strip().split('\n')
            for mx in mx_records:
                if mx:
                    parts = mx.split()
                    if len(parts) >= 2:
                        mx_host = parts[1].rstrip('.')
                        # Skip external mail services
                        external_mail = ['google', 'outlook', 'protonmail', 'zoho', 'mailgun', 'sendgrid']
                        if not any(ext in mx_host.lower() for ext in external_mail):
                            try:
                                ips = socket.gethostbyname_ex(mx_host)[2]
                                for ip in ips:
                                    if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                                        result['ips'].append({
                                            'ip': ip,
                                            'source': f'MX Record ({mx_host})',
                                            'confidence': 0.8  # High confidence - mail often on origin
                                        })
                            except Exception:
                                pass
        except Exception:
            pass

        return result

    async def _subdomain_correlation(self, domain: str) -> Dict:
        """Check common subdomains that might point to origin"""
        result = {'technique': 'Subdomain Correlation', 'ips': []}

        # Subdomains that often bypass CDN — split by likelihood.
        # "direct", "origin", "backend" are strong signals.
        # "mail", "ftp", "cpanel" are moderate — may or may not be on origin.
        HIGH_SIGNAL = {
            'direct', 'direct-connect', 'origin', 'origin-www', 'real',
            'backend', 'server', 'old', 'legacy', 'www2', 'web', 'web1',
            'web2', 'secure', 'portal', 'api', 'api1', 'api2', 'internal',
            'intranet', 'private', 'vpn', 'remote', 'gateway',
        }
        bypass_subdomains = list(HIGH_SIGNAL) + [
            'mail', 'webmail', 'smtp', 'pop', 'imap', 'mx', 'mx1', 'mx2',
            'ftp', 'sftp', 'ssh', 'admin', 'panel', 'cpanel', 'whm',
            'ns1', 'ns2', 'dns', 'dns1', 'dev', 'staging', 'test',
        ]

        async def resolve_subdomain(subdomain: str):
            fqdn = f"{subdomain}.{domain}"
            try:
                ips = socket.gethostbyname_ex(fqdn)[2]
                for ip in ips:
                    if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                        # High-signal subdomains get more confidence
                        conf = 0.75 if subdomain in HIGH_SIGNAL else 0.55
                        # Third-party subdomains get penalized
                        if self._is_third_party_subdomain(fqdn, domain):
                            conf = 0.2
                        return {
                            'ip': ip,
                            'source': f'Subdomain ({fqdn})',
                            'confidence': conf,
                        }
            except Exception:
                pass
            return None

        # Resolve in parallel
        tasks = [resolve_subdomain(sub) for sub in bypass_subdomains]
        results = await asyncio.gather(*tasks)

        seen = set()
        for r in results:
            if r and r['ip'] not in seen:
                seen.add(r['ip'])
                result['ips'].append(r)

        return result

    async def _common_misconfigs(self, domain: str) -> Dict:
        """Check common misconfigurations that expose origin"""
        result = {'technique': 'Misconfiguration Check', 'ips': []}

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            # Check various headers and paths
            checks = [
                # Check if origin leaks in headers when accessed by IP
                ('x-forwarded-for', f'https://{domain}'),
                # Check direct IP access
                ('origin-ip', f'https://{domain}'),
            ]

            for check_type, url in checks:
                try:
                    headers = {
                        'User-Agent': self.user_agents[0],
                        'X-Forwarded-For': '127.0.0.1',
                        'X-Real-IP': '127.0.0.1',
                        'X-Originating-IP': '127.0.0.1',
                        'Host': domain
                    }
                    async with session.get(url, headers=headers, ssl=False) as resp:
                        # Check response headers for IP leaks.
                        # Only headers that plausibly expose origin IPs — NOT
                        # Set-Cookie, Content-Type, or other unrelated headers.
                        ORIGIN_LEAK_HEADERS = {
                            'x-real-ip', 'x-origin-ip', 'x-forwarded-for',
                            'x-backend-server', 'x-served-by', 'x-host',
                            'x-backend', 'x-upstream', 'via', 'server',
                            'x-varnish', 'x-cache-backend',
                        }
                        for header, value in resp.headers.items():
                            if header.lower() not in ORIGIN_LEAK_HEADERS:
                                continue
                            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(value))
                            if ip_match:
                                ip = ip_match.group()
                                if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                                    result['ips'].append({
                                        'ip': ip,
                                        'source': f'Header Leak ({header})',
                                        'confidence': 0.85
                                    })
                except Exception:
                    pass

            # Check /server-status, /nginx_status if exposed
            status_paths = ['/server-status', '/nginx_status', '/status', '/.well-known/']
            for path in status_paths:
                try:
                    async with session.get(f"https://{domain}{path}", ssl=False) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
                            for ip in set(ips):
                                if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                                    if not any(r['ip'] == ip for r in result['ips']):
                                        result['ips'].append({
                                            'ip': ip,
                                            'source': f'Status Page ({path})',
                                            'confidence': 0.85
                                        })
                except Exception:
                    pass

        return result

    async def _historical_whois(self, domain: str) -> Dict:
        """Check historical WHOIS for IP references"""
        result = {'technique': 'Historical WHOIS', 'ips': []}

        try:
            proc = await asyncio.create_subprocess_exec(
                'whois', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            whois_data = stdout.decode()
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', whois_data)
            for ip in set(ips):
                if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                    result['ips'].append({
                        'ip': ip,
                        'source': 'WHOIS Record',
                        'confidence': 0.4  # Lower confidence - might be registrar IP
                    })
        except Exception:
            pass

        return result

    async def _securitytrails_history(self, domain: str) -> Dict:
        """Use SecurityTrails API for DNS history (requires API key)"""
        result = {'technique': 'SecurityTrails DNS History', 'ips': []}

        if not self.securitytrails_key:
            return result

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
                headers = {'APIKEY': self.securitytrails_key}
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        records = data.get('records', [])
                        for record in records:
                            for value in record.get('values', []):
                                ip = value.get('ip')
                                if ip and self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                                    result['ips'].append({
                                        'ip': ip,
                                        'source': 'SecurityTrails History',
                                        'first_seen': record.get('first_seen'),
                                        'last_seen': record.get('last_seen'),
                                        'confidence': 0.85
                                    })
        except Exception:
            pass

        return result

    async def _censys_certificate_search(self, domain: str) -> Dict:
        """Use Censys API for certificate search (requires API key)"""
        result = {'technique': 'Censys Certificate Search', 'ips': []}

        if not self.censys_id or not self.censys_secret:
            return result

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                auth = aiohttp.BasicAuth(self.censys_id, self.censys_secret)
                url = "https://search.censys.io/api/v2/certificates/search"
                query = {"q": f"names: {domain}", "per_page": 25}
                async with session.post(url, json=query, auth=auth) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        hits = data.get('result', {}).get('hits', [])
                        for hit in hits:
                            ip = hit.get('ip')
                            if ip and self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                                result['ips'].append({
                                    'ip': ip,
                                    'source': 'Censys Certificate',
                                    'confidence': 0.8
                                })
        except Exception:
            pass

        return result

    async def _shodan_search(self, domain: str) -> Dict:
        """Use Shodan API to find hosts (requires API key)"""
        result = {'technique': 'Shodan Search', 'ips': []}

        if not self.shodan_key:
            return result

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # Search for SSL certs with the domain
                url = "https://api.shodan.io/shodan/host/search"
                params = {
                    'key': self.shodan_key,
                    'query': f'ssl:"{domain}"'
                }
                async with session.get(url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        matches = data.get('matches', [])
                        for match in matches:
                            ip = match.get('ip_str')
                            if ip and self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                                result['ips'].append({
                                    'ip': ip,
                                    'source': 'Shodan SSL Search',
                                    'port': match.get('port'),
                                    'confidence': 0.75
                                })
        except Exception:
            pass

        return result

    async def _validate_origin_ips(
        self,
        domain: str,
        candidates: List[Dict]
    ) -> List[Dict]:
        """Validate discovered IPs by checking if they actually serve the domain.

        A real origin IP should:
        1. Respond to HTTP requests with Host: <domain>
        2. Return content that references the domain (not a generic hosting page)
        3. NOT return a Shopify/Heroku/etc. branded error page
        """
        validated = []

        # Known hosting provider signatures in response bodies/headers
        HOSTING_SIGNATURES = [
            "shopify", "squarespace", "wix.com", "herokuapp.com",
            "wordpress.com", "ghost.io", "webflow.com", "netlify",
            "vercel", "github.io", "pages.dev", "only a shopify store",
        ]

        # ASN names that indicate shared hosting / CDN / SaaS infrastructure.
        # An origin IP should NOT belong to these — they're multi-tenant.
        HOSTING_ASN_KEYWORDS = [
            "cloudflare", "akamai", "fastly", "amazon", "aws", "google cloud",
            "microsoft", "azure", "digitalocean", "linode", "vultr", "ovh",
            "hetzner", "shopify", "squarespace", "wix", "webflow", "netlify",
            "vercel", "heroku", "github", "automattic", "wordpress",
            "godaddy", "bluehost", "hostgator", "namecheap", "dreamhost",
            "incapsula", "imperva", "sucuri", "stackpath", "limelight",
        ]

        async def _lookup_asn(ip: str) -> Optional[str]:
            """DNS-based ASN lookup via Team Cymru (no extra deps needed)."""
            try:
                import dns.resolver
                # Reverse the IP octets and query .origin.asn.cymru.com
                octets = ip.split(".")
                if len(octets) != 4:
                    return None
                query = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.origin.asn.cymru.com"
                answers = dns.resolver.resolve(query, "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    # Format: "ASN | prefix | CC | registry | date"
                    parts = [p.strip() for p in txt.split("|")]
                    if len(parts) >= 1:
                        asn_number = parts[0]
                        # Now look up the ASN name
                        try:
                            name_answers = dns.resolver.resolve(
                                f"AS{asn_number}.asn.cymru.com", "TXT"
                            )
                            for nr in name_answers:
                                return str(nr).strip('"')
                        except Exception:
                            return txt
                return None
            except Exception:
                return None

        async def check_ip(ip_info: Dict) -> Optional[Dict]:
            ip = ip_info['ip']

            # N-02: ASN infrastructure check — reject IPs from known hosting ASNs
            asn_info = await _lookup_asn(ip)
            if asn_info:
                ip_info['asn_info'] = asn_info
                asn_lower = asn_info.lower()
                if any(kw in asn_lower for kw in HOSTING_ASN_KEYWORDS):
                    ip_info['validated'] = False
                    ip_info['hosting_provider_detected'] = True
                    ip_info['rejection_reason'] = f"ASN belongs to hosting/CDN provider: {asn_info}"
                    ip_info['confidence'] = min(
                        ip_info.get('confidence', 0.5) * 0.2, 0.1
                    )
                    return ip_info

            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    for scheme in ("https", "http"):
                        try:
                            ssl_arg = False if scheme == "https" else None
                            async with session.get(
                                f"{scheme}://{ip}/",
                                headers={'Host': domain},
                                ssl=ssl_arg,
                                allow_redirects=False,
                            ) as resp:
                                if resp.status >= 500:
                                    continue

                                # Check response body for hosting provider signatures
                                try:
                                    body = (await resp.text())[:4000].lower()
                                except Exception:
                                    body = ""

                                # If the response body OR headers contain hosting
                                # provider branding, this IP belongs to that
                                # provider, not our target.
                                # Check body
                                is_hosting = any(sig in body for sig in HOSTING_SIGNATURES)

                                # N-04: Also check response headers (server,
                                # x-served-by, x-powered-by, via) — hosting
                                # providers often identify themselves there even
                                # when the body renders the customer's content.
                                if not is_hosting:
                                    hosting_headers = " ".join(
                                        str(resp.headers.get(h, ""))
                                        for h in ("server", "x-served-by",
                                                   "x-powered-by", "via",
                                                   "x-hosted-by")
                                    ).lower()
                                    is_hosting = any(
                                        sig in hosting_headers
                                        for sig in HOSTING_SIGNATURES
                                    )

                                if is_hosting:
                                    ip_info['validated'] = False
                                    ip_info['hosting_provider_detected'] = True
                                    # Slash confidence — this isn't the origin
                                    ip_info['confidence'] = min(
                                        ip_info.get('confidence', 0.5) * 0.3, 0.15
                                    )
                                    return ip_info

                                # Real validation: the response should reference the
                                # target domain or return meaningful content.
                                domain_in_response = (
                                    domain in body
                                    or domain in str(resp.headers).lower()
                                    or resp.status in (200, 301, 302, 403)
                                )
                                if domain_in_response:
                                    ip_info['validated'] = True
                                    ip_info[f'{scheme}_status'] = resp.status
                                    boost = 0.2 if domain in body else 0.05
                                    ip_info['confidence'] = min(
                                        ip_info.get('confidence', 0.5) + boost, 1.0
                                    )
                                    return ip_info
                        except Exception:
                            pass

            except Exception:
                pass

            # No response or no match — unvalidated
            ip_info['validated'] = False
            return ip_info

        # Validate in parallel
        tasks = [check_ip(ip_info) for ip_info in candidates]
        results = await asyncio.gather(*tasks)

        for r in results:
            if r:
                validated.append(r)

        # Sort by confidence
        validated.sort(key=lambda x: x.get('confidence', 0), reverse=True)

        return validated

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid public IP"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False

            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False

            # Filter private IPs
            first = int(parts[0])
            second = int(parts[1])

            if first == 10:  # 10.0.0.0/8
                return False
            if first == 172 and 16 <= second <= 31:  # 172.16.0.0/12
                return False
            if first == 192 and second == 168:  # 192.168.0.0/16
                return False
            if first == 127:  # Loopback
                return False
            if first == 0 or first >= 224:  # Reserved/multicast
                return False

            return True
        except Exception:
            return False

    def _is_cdn_ip(self, ip: str) -> bool:
        """Check if IP belongs to known CDN or hosting provider ranges.

        Hosting provider IPs (Shopify, Heroku, GitHub Pages, etc.) are shared
        infrastructure — they're never the target's true origin.
        """
        all_excluded = (
            CLOUDFLARE_IP_RANGES + AKAMAI_IP_RANGES + FASTLY_IP_RANGES
            + HOSTING_PROVIDER_RANGES
        )
        return self._ip_in_ranges(ip, all_excluded)

    def _is_third_party_subdomain(self, subdomain: str, base_domain: str) -> bool:
        """Check if a subdomain likely points to third-party SaaS, not origin.

        e.g. shop.example.com → Shopify, mail.example.com → Google/O365
        """
        # Strip the base domain to get the prefix
        sub = subdomain.lower().replace(f".{base_domain}", "").strip(".")
        # Get just the leftmost label
        prefix = sub.split(".")[0] if sub else ""
        return prefix in THIRD_PARTY_SUBDOMAIN_PREFIXES

    def _ip_in_ranges(self, ip: str, ranges: List[str]) -> bool:
        """Check if IP falls within any of the given CIDR ranges"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            for cidr in ranges:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
        except Exception:
            pass
        return False

    def get_results_summary(self) -> Dict:
        """Get summary of all discovery results"""
        summary = {
            'total_domains': len(self.results),
            'total_ips_discovered': 0,
            'cdn_bypassed': 0,
            'high_confidence_ips': [],
            'domains': []
        }

        for result in self.results:
            domain_summary = {
                'domain': result.domain,
                'cdn_detected': result.cdn_detected,
                'ips_found': len(result.discovered_ips),
                'techniques_used': result.techniques_used,
                'top_ips': []
            }

            for ip_info in result.discovered_ips[:5]:  # Top 5
                domain_summary['top_ips'].append({
                    'ip': ip_info['ip'],
                    'confidence': ip_info.get('confidence', 0),
                    'source': ip_info.get('source', 'unknown'),
                    'validated': ip_info.get('validated', False)
                })

                if ip_info.get('confidence', 0) >= 0.8:
                    summary['high_confidence_ips'].append({
                        'domain': result.domain,
                        'ip': ip_info['ip'],
                        'confidence': ip_info['confidence']
                    })

            summary['total_ips_discovered'] += len(result.discovered_ips)
            if result.cdn_detected and result.discovered_ips:
                summary['cdn_bypassed'] += 1

            summary['domains'].append(domain_summary)

        return summary


async def run_origin_discovery(
    domains: List[str],
    config: Optional[Dict] = None,
    verbose: bool = False
) -> Dict:
    """
    Main entry point for origin IP discovery

    Args:
        domains: List of domains to discover origin IPs for
        config: Optional configuration with API keys
        verbose: Print progress

    Returns:
        Discovery results summary
    """
    discovery = OriginIPDiscovery(config)

    for domain in domains:
        if verbose:
            print(f"[*] Discovering origin IP for: {domain}")

        result = await discovery.discover(domain)

        if verbose:
            if result.cdn_detected:
                print(f"    CDN Detected: {result.cdn_detected}")
            print(f"    IPs Found: {len(result.discovered_ips)}")
            for ip_info in result.discovered_ips[:3]:
                conf = ip_info.get('confidence', 0) * 100
                validated = "✓" if ip_info.get('validated') else "?"
                print(f"      {validated} {ip_info['ip']} ({conf:.0f}% confidence) - {ip_info.get('source', 'unknown')}")

    return discovery.get_results_summary()


# Module interface for Beatrix integration
async def discover_origin_ips(
    targets: List[str],
    config: Optional[Dict] = None
) -> Dict:
    """
    Beatrix module interface for origin IP discovery

    Args:
        targets: List of target domains
        config: Module configuration

    Returns:
        Module results in Beatrix format
    """
    config = config or {}
    verbose = config.get('verbose', False)

    # Extract just domain names if URLs provided
    domains = []
    for target in targets:
        if '://' in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            domains.append(parsed.netloc)
        else:
            domains.append(target.split('/')[0])

    results = await run_origin_discovery(
        domains=list(set(domains)),
        config=config,
        verbose=verbose
    )

    # Convert to Beatrix findings format
    findings = []
    for domain_result in results.get('domains', []):
        for ip_info in domain_result.get('top_ips', []):
            findings.append({
                'type': 'origin_ip',
                'severity': 'info' if ip_info['confidence'] < 0.7 else 'medium',
                'domain': domain_result['domain'],
                'ip': ip_info['ip'],
                'confidence': ip_info['confidence'],
                'source': ip_info['source'],
                'validated': ip_info.get('validated', False),
                'cdn_detected': domain_result.get('cdn_detected'),
                'description': f"Potential origin IP discovered for {domain_result['domain']}: {ip_info['ip']} (confidence: {ip_info['confidence']*100:.0f}%)",
                'recommendation': f"Consider testing {ip_info['ip']} directly with Host header set to {domain_result['domain']} to bypass WAF"
            })

    return {
        'module': 'origin_ip_discovery',
        'summary': results,
        'findings': findings,
        'stats': {
            'domains_scanned': results.get('total_domains', 0),
            'ips_discovered': results.get('total_ips_discovered', 0),
            'cdn_bypassed': results.get('cdn_bypassed', 0),
            'high_confidence': len(results.get('high_confidence_ips', []))
        }
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python origin_ip_discovery.py <domain> [domain2] ...")
        print("\nEnvironment variables for enhanced discovery:")
        print("  SECURITYTRAILS_API_KEY - SecurityTrails API key")
        print("  CENSYS_API_ID / CENSYS_API_SECRET - Censys API credentials")
        print("  SHODAN_API_KEY - Shodan API key")
        sys.exit(1)

    import os
    config = {
        'securitytrails_api_key': os.environ.get('SECURITYTRAILS_API_KEY'),
        'censys_api_id': os.environ.get('CENSYS_API_ID'),
        'censys_api_secret': os.environ.get('CENSYS_API_SECRET'),
        'shodan_api_key': os.environ.get('SHODAN_API_KEY')
    }

    domains = sys.argv[1:]
    results = asyncio.run(run_origin_discovery(domains, config, verbose=True))

    print("\n" + "="*60)
    print("DISCOVERY SUMMARY")
    print("="*60)
    print(f"Domains Scanned: {results['total_domains']}")
    print(f"Total IPs Found: {results['total_ips_discovered']}")
    print(f"CDN Bypasses: {results['cdn_bypassed']}")

    if results['high_confidence_ips']:
        print("\nHigh Confidence Origin IPs:")
        for item in results['high_confidence_ips']:
            print(f"  {item['domain']}: {item['ip']} ({item['confidence']*100:.0f}%)")
