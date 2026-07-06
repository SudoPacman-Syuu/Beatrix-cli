"""
BEATRIX Authentication & Session Scanner (A07:2025)

Hunts for authentication and session management flaws.
These often lead to account takeover - HIGH BOUNTY targets.

TARGETS:
- Password reset token predictability
- Session fixation
- JWT weaknesses (none alg, weak secret, no expiry)
- 2FA/MFA bypass
- Rate limiting failures (brute force)
- Username enumeration
"""

import asyncio
import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import AsyncIterator, Dict, List, Optional
from urllib.parse import urlparse

import httpx
import jwt

from beatrix.core.types import Confidence, Finding, Severity
from beatrix.scanners.base import BaseScanner, ScanContext


@dataclass
class AuthEndpoint:
    """Authentication-related endpoint"""
    url: str
    endpoint_type: str  # login, register, reset, verify, 2fa, logout
    method: str
    params: Dict[str, str]


class AuthScanner(BaseScanner):
    """
    Authentication & Session Management Scanner

    OWASP A07:2025 - Authentication Failures

    Checks for:
    - Weak JWT implementations
    - Password reset vulnerabilities
    - Session management issues
    - 2FA/MFA bypass opportunities
    - Rate limiting bypass
    - Username enumeration
    """

    name = "auth"
    description = "Authentication & Session Scanner"
    author = "BEATRIX"
    version = "1.0.0"

    checks = [
        "jwt_none_algorithm",
        "jwt_weak_secret",
        "jwt_no_expiry",
        "password_reset_token_leak",
        "session_fixation",
        "2fa_bypass",
        "rate_limit_bypass",
        "username_enumeration",
    ]

    owasp_category = "A07:2025 - Authentication Failures"

    # Common weak JWT secrets
    WEAK_SECRETS = [
        "secret",
        "password",
        "123456",
        "key",
        "private",
        "jwt_secret",
        "your-256-bit-secret",
        "your-secret-key",
        "supersecret",
        "changeme",
        "changeit",
        "test",
        "development",
        "dev",
        "auth",
        "token",
        "",
    ]

    # Auth-related endpoints
    AUTH_ENDPOINTS = {
        'login': ['/login', '/signin', '/auth/login', '/api/auth/login', '/api/login', '/api/v1/login', '/session', '/api/session'],
        'register': ['/register', '/signup', '/auth/register', '/api/auth/register', '/api/register', '/api/v1/register'],
        'reset': ['/reset-password', '/forgot-password', '/password/reset', '/api/password/reset', '/api/auth/reset'],
        'verify': ['/verify', '/confirm', '/activate', '/api/verify', '/api/confirm'],
        '2fa': ['/2fa', '/mfa', '/otp', '/api/2fa', '/api/mfa', '/verify-otp', '/totp'],
        'logout': ['/logout', '/signout', '/api/logout', '/api/auth/logout'],
    }

    def __init__(self, config=None, timeout: float = 10.0):
        # Support being called with a dict (from engine) or timeout float
        if isinstance(config, (int, float)):
            timeout = float(config)
            config = None
        elif isinstance(config, dict):
            timeout = config.get("timeout", timeout)

        super().__init__(config)
        self.timeout = timeout

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=False,
        )
        return self

    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()

    # =========== JWT ANALYSIS ===========

    def decode_jwt_unsafe(self, token: str) -> Optional[Dict]:
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode header
            header = parts[0]
            header += '=' * (4 - len(header) % 4)
            header_data = json.loads(base64.urlsafe_b64decode(header))

            # Decode payload
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)
            payload_data = json.loads(base64.urlsafe_b64decode(payload))

            return {
                'header': header_data,
                'payload': payload_data,
                'signature': parts[2],
            }
        except Exception:
            return None

    def analyze_jwt(self, token: str) -> List[Finding]:
        """Analyze JWT for security issues"""
        findings = []
        decoded = self.decode_jwt_unsafe(token)

        if not decoded:
            return findings

        header = decoded['header']
        payload = decoded['payload']

        # Check 1: Algorithm "none"
        alg = header.get('alg', '').lower()
        if alg == 'none':
            findings.append(Finding(
                title="JWT Algorithm 'none' Accepted",
                description=f"""
**Critical JWT Vulnerability - Algorithm None**

The JWT uses algorithm "none", which means NO signature verification.
An attacker can forge any JWT payload.

**Token Header:** {json.dumps(header)}

**Exploitation:**
1. Decode the JWT payload
2. Modify claims (user ID, role, etc.)
3. Create new JWT with alg=none and no signature
4. Use forged token for account takeover

**PoC:**
```python
import base64
import json

# Forge admin token
header = {{"alg": "none", "typ": "JWT"}}
payload = {{"user_id": 1, "role": "admin"}}
forged = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode() + '.'
forged += base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode() + '.'
print(forged)
```
""".strip(),
                severity=Severity.CRITICAL,
                confidence=Confidence.CERTAIN,
                evidence={'token': token[:50] + '...', 'header': header, 'algorithm': alg},
                cwe_id=345,
                owasp_category=self.owasp_category,
            ))

        # Check 2: Weak algorithm
        if alg in ['hs256', 'hs384', 'hs512']:
            # Try common weak secrets
            for secret in self.WEAK_SECRETS:
                try:
                    jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                    findings.append(Finding(
                        title=f"JWT Signed with Weak Secret: '{secret}'",
                        description=f"""
**JWT Weak Secret Vulnerability**

The JWT is signed with a weak/guessable secret: `{secret}`

**Impact:** An attacker can forge valid JWTs with any claims.

**Decoded Token:**
- Header: {json.dumps(header)}
- Payload: {json.dumps(payload)}

**Exploitation:**
```python
import jwt
token = jwt.encode({{"user_id": 1, "admin": True}}, "{secret}", algorithm="HS256")
```
""".strip(),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CERTAIN,
                        evidence={'weak_secret': secret, 'header': header, 'payload': payload},
                        cwe_id=798,
                        owasp_category=self.owasp_category,
                    ))
                    break
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue

        # Check 3: No expiration
        if 'exp' not in payload:
            findings.append(Finding(
                title="JWT Missing Expiration Claim",
                description=f"""
**JWT Never Expires**

The JWT has no `exp` (expiration) claim. Tokens never expire,
meaning stolen tokens remain valid indefinitely.

**Payload:** {json.dumps(payload)}

**Impact:**
- Stolen tokens can be used forever
- No session timeout
- Compromised accounts harder to secure
""".strip(),
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                evidence={'payload': payload, 'missing': 'exp'},
                cwe_id=613,
                owasp_category=self.owasp_category,
            ))
        else:
            # Check if expiration is very long
            exp = payload.get('exp', 0)
            if exp > 0:
                exp_dt = datetime.fromtimestamp(exp)
                now = datetime.now()
                days_until_exp = (exp_dt - now).days

                if days_until_exp > 30:
                    findings.append(Finding(
                        title=f"JWT Has Excessive Lifetime: {days_until_exp} days",
                        description=f"""
**JWT Expiration Too Long**

The JWT expires in {days_until_exp} days, which is excessively long.
Best practice is < 24 hours for most tokens.

**Expiration:** {exp_dt.isoformat()}
""".strip(),
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        evidence={'exp': exp, 'exp_datetime': exp_dt.isoformat(), 'days': days_until_exp},
                        cwe_id=613,
                        owasp_category=self.owasp_category,
                    ))

        # Check 4: Sensitive data in payload
        sensitive_keys = ['password', 'secret', 'private_key', 'credit_card', 'ssn', 'api_key']
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                findings.append(Finding(
                    title=f"JWT Contains Sensitive Data: {key}",
                    description=f"""
**Sensitive Data in JWT Payload**

The JWT payload contains potentially sensitive data in the `{key}` field.
JWTs are only base64-encoded, not encrypted - anyone can read the payload.

**Field:** {key}
**Value:** (redacted)

**Impact:** Information disclosure
""".strip(),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    evidence={'sensitive_field': key},
                    cwe_id=200,
                    owasp_category=self.owasp_category,
                ))

        return findings

    async def test_username_enumeration(self, login_url: str) -> List[Finding]:
        """Test for username enumeration via error messages or timing"""
        findings = []

        if not self.client:
            return findings

        # Use multiple real-looking usernames to increase detection accuracy
        likely_real_usernames = ["admin", "test", "user", "info"]
        fake_usernames = [
            "beatrix_definitely_not_real_xk7q2",
            "beatrix_fake_user_m9p3z",
            "beatrix_nonexistent_w4r8j",
        ]

        real_responses = []
        fake_responses = []

        for username in likely_real_usernames[:2]:
            try:
                start = asyncio.get_running_loop().time()
                response = await self.post(
                    login_url,
                    data={"username": username, "password": "wrongpassword123"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                elapsed = asyncio.get_running_loop().time() - start
                real_responses.append({
                    'username': username, 'status': response.status_code,
                    'body': response.text[:500], 'time': elapsed,
                })
            except Exception:
                continue
            await asyncio.sleep(0.5)

        for username in fake_usernames:
            try:
                start = asyncio.get_running_loop().time()
                response = await self.post(
                    login_url,
                    data={"username": username, "password": "wrongpassword123"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                elapsed = asyncio.get_running_loop().time() - start
                fake_responses.append({
                    'username': username, 'status': response.status_code,
                    'body': response.text[:500], 'time': elapsed,
                })
            except Exception:
                continue
            await asyncio.sleep(0.5)

        if real_responses and fake_responses:
            # Check for different error messages (comparing all real vs all fake)
            real_bodies = set(r['body'] for r in real_responses)
            fake_bodies = set(r['body'] for r in fake_responses)

            if real_bodies != fake_bodies and len(real_bodies) == 1 and len(fake_bodies) == 1:
                findings.append(Finding(
                    title="Username Enumeration via Different Error Messages",
                    description=f"""
**Username Enumeration Vulnerability**

The login endpoint returns different error messages for valid vs invalid usernames.

**Likely-valid username response ({real_responses[0]['username']}):**
```
{real_responses[0]['body'][:200]}
```

**Invalid username response ({fake_responses[0]['username']}):**
```
{fake_responses[0]['body'][:200]}
```

**Impact:**
- Attacker can discover valid usernames
- Enables targeted password attacks
- Information disclosure about user accounts

**Remediation:**
Use generic error messages like "Invalid username or password"
""".strip(),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=login_url,
                    evidence={'real_responses': real_responses, 'fake_responses': fake_responses},
                    cwe_id=204,
                    owasp_category=self.owasp_category,
                ))

            # Check for timing difference — use statistical comparison
            # Average timing for real vs fake usernames, require > 300ms diff
            # across multiple samples to avoid network jitter false positives
            avg_real_time = sum(r['time'] for r in real_responses) / len(real_responses)
            avg_fake_time = sum(r['time'] for r in fake_responses) / len(fake_responses)
            timing_diff = abs(avg_real_time - avg_fake_time)

            if timing_diff > 0.3:  # 300ms threshold with averaged samples
                findings.append(Finding(
                    title="Username Enumeration via Response Timing",
                    description=f"""
**Timing-Based Username Enumeration**

The login endpoint has significantly different average response times for
valid vs invalid usernames.

**Avg time for likely-valid usernames:** {avg_real_time:.3f}s
**Avg time for invalid usernames:** {avg_fake_time:.3f}s
**Difference:** {timing_diff:.3f}s (across {len(real_responses)+len(fake_responses)} samples)

This suggests different code paths are executed based on username validity.
""".strip(),
                    severity=Severity.LOW,
                    confidence=Confidence.TENTATIVE,
                    url=login_url,
                    evidence={
                        'avg_real_time': avg_real_time,
                        'avg_fake_time': avg_fake_time,
                        'difference': timing_diff,
                        'samples': len(real_responses) + len(fake_responses),
                    },
                    cwe_id=208,
                    owasp_category=self.owasp_category,
                ))

        return findings

    # =========== EMAIL ENUMERATION VIA REGISTRATION / GUEST CHECKOUT ===========

    async def test_email_enumeration(self, base_url: str) -> List[Finding]:
        """
        Test for email/account enumeration via registration and guest checkout endpoints.

        Lesson from a real-world engagement: The guest checkout endpoint returned:
        - 200 with customerId + customerType='GC' for new emails (guest created)
        - 200 with customerId=null + CHECKOUT_PREVIEW_CUSTOMER_EXISTING_EMAIL for registered emails
        Same HTTP status, but different JSON body = enumeration via response content.

        Also checks:
        - Registration endpoints (different status codes: 200 vs 409)
        - Password reset endpoints (different messages for valid/invalid emails)
        - Guest checkout endpoints (differential JSON responses)
        - Newsletter subscription endpoints
        """
        findings = []

        if not self.client:
            return findings

        # Test email: use a definitely-not-registered email vs a likely-registered one
        test_email = f"beatrix_enum_test_{int(asyncio.get_running_loop().time())}@nonexistent-domain-test.com"
        likely_emails = ["admin@test.com", "test@test.com", "info@test.com"]

        # ---- Guest checkout enumeration (e-commerce pattern) ----
        guest_checkout_paths = [
            # Common e-commerce path
            '/semiprotected/api/checkout/state-api/v2/customer/basic-guest-customer',
            # Common variations
            '/api/checkout/guest',
            '/api/guest/customer',
            '/api/v1/guest-checkout',
            '/api/v2/guest-checkout',
            '/api/checkout/guest-customer',
            '/checkout/api/guest',
        ]

        for path in guest_checkout_paths:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                # Test with a random new email
                new_resp = await self.post(
                    url,
                    json={"email": test_email, "firstName": "Test", "lastName": "User"},
                    headers={"Content-Type": "application/json"}
                )

                if new_resp.status_code not in [200, 201]:
                    continue  # Endpoint doesn't exist or different format

                # This endpoint exists — now test with likely-registered emails
                for likely_email in likely_emails:
                    existing_resp = await self.post(
                        url,
                        json={"email": likely_email, "firstName": "Test", "lastName": "User"},
                        headers={"Content-Type": "application/json"}
                    )

                    # E-commerce pattern: same 200 status, but different JSON content
                    if existing_resp.status_code == new_resp.status_code:
                        try:
                            new_json = new_resp.json() if new_resp.text.strip().startswith('{') else {}
                            existing_json = existing_resp.json() if existing_resp.text.strip().startswith('{') else {}
                        except Exception:
                            new_json = {}
                            existing_json = {}

                        # Deep check for differential indicators
                        new_text = json.dumps(new_json).lower() if new_json else new_resp.text.lower()
                        existing_text = json.dumps(existing_json).lower() if existing_json else existing_resp.text.lower()

                        enum_indicators = [
                            'existing_email', 'email_taken', 'already_registered',
                            'customer_existing', 'account_exists', 'duplicate_email',
                            'email_in_use', 'existing_customer', 'registered',
                            # E-commerce-specific
                            'checkout_preview_customer_existing_email',
                        ]

                        # Check if either response has enumeration indicator that the other doesn't
                        new_has_indicator = any(ind in new_text for ind in enum_indicators)
                        existing_has_indicator = any(ind in existing_text for ind in enum_indicators)

                        if existing_has_indicator and not new_has_indicator:
                            findings.append(Finding(
                                title=f"Email Enumeration via Guest Checkout ({path})",
                                description=f"""
**Email Enumeration via Differential Guest Checkout Response**

The guest checkout endpoint returns different JSON responses for
registered vs unregistered email addresses, allowing account enumeration.

**NO AUTHENTICATION REQUIRED.**

**Pattern (common e-commerce finding):**

**Unregistered email:** {test_email}
Response: customerId assigned, guest account created
```json
{new_resp.text[:400]}
```

**Registered email:** {likely_email}
Response: contains enumeration indicator keyword
```json
{existing_resp.text[:400]}
```

**Impact:**
- Enumerate registered users at scale (no auth, no CAPTCHA)
- GDPR violation: reveals account existence for EU company
- Build target list for credential stuffing / phishing
- Mass guest account creation (DB pollution, sequential CIDs)

**Remediation:**
1. Return identical responses for registered and unregistered emails
2. Add CAPTCHA before processing guest checkout
3. Rate limit per IP on this endpoint
4. Deduplicate guest customer entries by email
""".strip(),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.CERTAIN,
                                url=url,
                                evidence={
                                    'new_email': test_email,
                                    'likely_email': likely_email,
                                    'new_status': new_resp.status_code,
                                    'existing_status': existing_resp.status_code,
                                    'new_body': new_resp.text[:500],
                                    'existing_body': existing_resp.text[:500],
                                },
                                cwe_id=204,
                                owasp_category=self.owasp_category,
                            ))
                            break

                        # Also check for mass account creation (customerId assigned)
                        if new_json and new_json.get('customer', {}).get('customerId'):
                            cid = new_json['customer']['customerId']
                            findings.append(Finding(
                                title=f"Mass Guest Account Creation Without Auth ({path})",
                                description=f"""
**Unauthenticated Mass Guest Account Creation**

The guest checkout endpoint creates real customer accounts
without any authentication, CAPTCHA, or rate limiting.

**Created customer ID:** {cid}
**Customer type:** {new_json.get('customer', {}).get('customerType', 'Unknown')}

**Impact:**
- Database pollution with unlimited guest accounts
- Sequential customer IDs enable enumeration
- Resource exhaustion
- No deduplication (same email → new CID each time)
""".strip(),
                                severity=Severity.LOW,
                                confidence=Confidence.CERTAIN,
                                url=url,
                                evidence={'customerId': cid, 'response': new_resp.text[:500]},
                                cwe_id=799,
                                owasp_category=self.owasp_category,
                            ))

                    # Different status codes = classic enumeration
                    elif new_resp.status_code != existing_resp.status_code:
                        findings.append(Finding(
                            title=f"Email Enumeration via Guest Checkout Status Code ({path})",
                            description=f"""
**Email Enumeration via HTTP Status Code Difference**

**New email:** {test_email} → {new_resp.status_code}
**Existing email:** {likely_email} → {existing_resp.status_code}
""".strip(),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.FIRM,
                            url=url,
                            evidence={
                                'new_status': new_resp.status_code,
                                'existing_status': existing_resp.status_code,
                            },
                            cwe_id=204,
                            owasp_category=self.owasp_category,
                        ))
                        break

            except Exception:
                continue

        # ---- Registration endpoint enumeration ----
        registration_paths = [
            '/register', '/signup', '/sign-up', '/api/register', '/api/signup',
            '/api/auth/register', '/api/v1/register', '/api/v2/register',
            '/account/create', '/api/account/create', '/api/accounts',
            '/api/customer/register', '/api/customers/register',
            '/customer-data/api/v2/customers',  # e-commerce pattern
            '/api/users', '/users/register',
        ]

        for path in registration_paths:
            url = f"{base_url.rstrip('/')}{path}"

            try:
                # Test with new email
                new_resp = await self.post(
                    url,
                    json={"email": test_email, "password": "TestPass123!@#"},
                    headers={"Content-Type": "application/json"}
                )

                # Test with likely-existing email
                for likely_email in likely_emails:
                    existing_resp = await self.post(
                        url,
                        json={"email": likely_email, "password": "TestPass123!@#"},
                        headers={"Content-Type": "application/json"}
                    )

                    # Check for differential response (e-commerce pattern: 200 vs 409)
                    if new_resp.status_code != existing_resp.status_code:
                        findings.append(Finding(
                            title=f"Email Enumeration via Registration ({path})",
                            description=f"""
**Email Enumeration via Differential Response on Registration**

The registration endpoint returns different HTTP status codes for
new vs existing email addresses, allowing account enumeration.

**New email:** {test_email}
**Response:** {new_resp.status_code}

**Existing email:** {likely_email}
**Response:** {existing_resp.status_code}

**Pattern (e-commerce style):**
- New email → {new_resp.status_code} (account creation attempted)
- Existing email → {existing_resp.status_code} (conflict/error)

**Impact:**
- Enumerate registered users' email addresses
- Build target list for credential stuffing
- Privacy violation (reveal who has an account)

**Remediation:**
Return the same status code and response regardless of whether
the email exists. Use generic messages like "If this email is
registered, you will receive a confirmation."
""".strip(),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.FIRM,
                            url=url,
                            evidence={
                                'new_email_status': new_resp.status_code,
                                'existing_email_status': existing_resp.status_code,
                                'new_body': new_resp.text[:300],
                                'existing_body': existing_resp.text[:300],
                            },
                            cwe_id=204,
                            owasp_category=self.owasp_category,
                        ))
                        break  # Found enumeration on this endpoint, no need to test more emails

                    # Also check body differences (same status but different message)
                    elif new_resp.text != existing_resp.text and len(new_resp.text) > 10:
                        # Check for enumeration-indicating keywords
                        existing_lower = existing_resp.text.lower()
                        enum_keywords = ['already exists', 'already registered', 'email taken',
                                        'account exists', 'duplicate', 'conflict', 'in use',
                                        'already in use', 'username taken']
                        if any(kw in existing_lower for kw in enum_keywords):
                            findings.append(Finding(
                                title=f"Email Enumeration via Response Body ({path})",
                                description=f"""
**Email Enumeration via Different Error Messages on Registration**

The registration endpoint returns different response bodies for
new vs existing emails, revealing whether an account exists.

**Endpoint:** {url}
**Both returned:** {new_resp.status_code}

**New email response:** {new_resp.text[:200]}
**Existing email response:** {existing_resp.text[:200]}
""".strip(),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.FIRM,
                                url=url,
                                evidence={
                                    'new_body': new_resp.text[:300],
                                    'existing_body': existing_resp.text[:300],
                                },
                                cwe_id=204,
                                owasp_category=self.owasp_category,
                            ))
                            break

            except Exception:
                continue

        # ---- Password reset enumeration ----
        reset_paths = [
            '/reset-password', '/forgot-password', '/password/reset',
            '/api/password/reset', '/api/auth/reset', '/api/auth/forgot-password',
            '/api/v1/auth/forgot-password', '/api/v2/auth/forgot-password',
        ]

        for path in reset_paths:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                valid_resp = await self.post(
                    url,
                    json={"email": "admin@test.com"},
                    headers={"Content-Type": "application/json"}
                )
                invalid_resp = await self.post(
                    url,
                    json={"email": test_email},
                    headers={"Content-Type": "application/json"}
                )

                if valid_resp.status_code != invalid_resp.status_code:
                    findings.append(Finding(
                        title=f"Email Enumeration via Password Reset ({path})",
                        description=f"""
**Email Enumeration via Password Reset Endpoint**

Different status codes for valid ({valid_resp.status_code}) vs
invalid ({invalid_resp.status_code}) email addresses.

**Remediation:** Always return 200 with "If this email exists,
a reset link has been sent."
""".strip(),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        url=url,
                        evidence={
                            'valid_status': valid_resp.status_code,
                            'invalid_status': invalid_resp.status_code,
                        },
                        cwe_id=204,
                        owasp_category=self.owasp_category,
                    ))

            except Exception:
                continue

        return findings

    # =========== OAUTH / KEYCLOAK PROBING ===========

    async def test_oauth_misconfig(self, base_url: str) -> List[Finding]:
        """
        Test for OAuth/OpenID Connect misconfigurations.

        Lessons from a real-world engagement:
        - Keycloak well-known endpoint exposed realm configuration
        - redirect_uri validated with wildcard path matching (any path on *.example.*)
        - PKCE not enforced on public client (frontend-authorizer)
        - Public client = no client_secret required for code exchange
        - Auth codes stolen via arbitrary redirect_uri path → exchanged for PII tokens
        - Multiple Keycloak clients with different configs (public vs confidential)

        Attack chain that worked:
        1. Discover OIDC config → find auth/token endpoints
        2. Extract client_id from frontend JS/HTML
        3. Test redirect_uri with arbitrary path on target domain (NOT evil.com)
        4. Confirm no PKCE enforcement (no code_challenge required)
        5. Public client = code exchangeable without client_secret
        6. Full account takeover: steal code → exchange → get PII tokens
        """
        findings = []

        if not self.client:
            return findings

        # ---- Step 1: Discover well-known endpoints ----
        wellknown_paths = [
            '/.well-known/openid-configuration',
            '/auth/realms/master/.well-known/openid-configuration',
            '/auth/realms/app/.well-known/openid-configuration',
            '/realms/master/.well-known/openid-configuration',
            '/oauth/.well-known/openid-configuration',
            '/.well-known/oauth-authorization-server',
        ]

        # Also try to derive realm name from the target domain
        parsed_base = urlparse(base_url)
        domain_parts = parsed_base.netloc.replace('www.', '').split('.')
        if len(domain_parts) >= 2:
            brand = domain_parts[0]  # e.g., 'example' from www.example.com
            wellknown_paths.extend([
                f'/auth/realms/{brand}/.well-known/openid-configuration',
                f'/realms/{brand}/.well-known/openid-configuration',
            ])

        oidc_config = None

        for path in wellknown_paths:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = await self.get(url)
                if resp.status_code == 200:
                    try:
                        config = resp.json()
                        if 'authorization_endpoint' in config:
                            oidc_config = config

                            findings.append(Finding(
                                title=f"OpenID Connect Configuration Exposed ({path})",
                                description=f"""
**OpenID Connect Configuration Discovery**

The OpenID Connect configuration is publicly accessible.
While this is by design, it reveals important attack surface.

**Authorization Endpoint:** {config.get('authorization_endpoint', 'N/A')}
**Token Endpoint:** {config.get('token_endpoint', 'N/A')}
**Issuer:** {config.get('issuer', 'N/A')}
**Grant Types:** {config.get('grant_types_supported', [])}
**Response Types:** {config.get('response_types_supported', [])}
**PKCE Support:** {'S256' in config.get('code_challenge_methods_supported', [])}

This information aids in testing OAuth flows for vulnerabilities.
""".strip(),
                                severity=Severity.INFO,
                                confidence=Confidence.CERTAIN,
                                url=url,
                                evidence=config,
                                cwe_id=200,
                                owasp_category=self.owasp_category,
                            ))
                            break
                    except Exception:
                        pass
            except Exception:
                continue

        # ---- Step 2: Extract client IDs from frontend ----
        discovered_client_ids = await self._discover_oauth_client_ids(base_url)

        if not oidc_config:
            # Even without OIDC config, we can check if login.{domain} has Keycloak
            login_hosts = [
                f"https://login.{parsed_base.netloc.replace('www.', '')}",
                f"https://auth.{parsed_base.netloc.replace('www.', '')}",
                f"https://sso.{parsed_base.netloc.replace('www.', '')}",
                f"https://id.{parsed_base.netloc.replace('www.', '')}",
                f"https://accounts.{parsed_base.netloc.replace('www.', '')}",
            ]
            for login_host in login_hosts:
                for realm in ['master', brand if len(domain_parts) >= 2 else 'app']:
                    url = f"{login_host}/auth/realms/{realm}/.well-known/openid-configuration"
                    try:
                        resp = await self.get(url, timeout=5)
                        if resp.status_code == 200:
                            config = resp.json()
                            if 'authorization_endpoint' in config:
                                oidc_config = config
                                findings.append(Finding(
                                    title=f"Keycloak Instance Discovered at {login_host}",
                                    description=f"""
**Keycloak OIDC Endpoint Found on Separate Host**

Found OpenID Connect configuration at {url}

**Issuer:** {config.get('issuer', 'N/A')}
**Authorization:** {config.get('authorization_endpoint', 'N/A')}
**Token:** {config.get('token_endpoint', 'N/A')}
""".strip(),
                                    severity=Severity.INFO,
                                    confidence=Confidence.CERTAIN,
                                    url=url,
                                    evidence={'issuer': config.get('issuer')},
                                    cwe_id=200,
                                    owasp_category=self.owasp_category,
                                ))
                                break
                    except Exception:
                        continue
                if oidc_config:
                    break

        if not oidc_config:
            return findings

        auth_endpoint = oidc_config.get('authorization_endpoint', '')
        token_endpoint = oidc_config.get('token_endpoint', '')
        pkce_methods = oidc_config.get('code_challenge_methods_supported', [])

        # If no client IDs discovered from frontend, use generic test IDs
        if not discovered_client_ids:
            discovered_client_ids = ['test']

        # ---- Step 3: Test each discovered client ID ----
        for client_id in discovered_client_ids:
            await asyncio.sleep(1)  # Rate limiting between client tests

            # 3a: Test if redirect_uri uses wildcard path matching
            # KEY LESSON: Test with the TARGET APP domain, not evil.com
            # Target accepted https://www.example.com/ANY-PATH-HERE
            target_domain = parsed_base.netloc  # e.g., www.example.com

            redirect_tests = [
                # Path-based wildcard on TARGET domain (highest value — this is what works in practice)
                (f"https://{target_domain}/beatrix-oauth-test-{int(asyncio.get_running_loop().time())}",
                 "path_wildcard_target", Severity.HIGH),
                # Completely different path on target
                (f"https://{target_domain}/some/fake/path/that/does/not/exist",
                 "deep_path_wildcard", Severity.HIGH),
                # External domain (should always be rejected)
                ("https://evil.com/callback", "external_domain", Severity.CRITICAL),
                # Subdomain of target
                (f"https://evil.{target_domain}", "subdomain_injection", Severity.HIGH),
                # Suffix attack (target.com.evil.com)
                (f"https://{target_domain}.evil.com", "domain_suffix", Severity.CRITICAL),
                # Protocol downgrade
                (f"http://{target_domain}/callback", "protocol_downgrade", Severity.MEDIUM),
                # Port bypass
                (f"https://{target_domain}:8443/callback", "port_bypass", Severity.MEDIUM),
                # Path traversal
                (f"https://{target_domain}/callback/../../../evil", "path_traversal", Severity.HIGH),
            ]

            accepted_redirects = []
            rejected_redirects = []

            for redirect_uri, bypass_name, sev in redirect_tests:
                try:
                    test_url = (
                        f"{auth_endpoint}?response_type=code&client_id={client_id}"
                        f"&redirect_uri={redirect_uri}&scope=openid"
                        f"&state=beatrix_test&nonce=beatrix_nonce"
                    )
                    resp = await self.get(test_url, follow_redirects=False)

                    # Determine if accepted or rejected
                    is_accepted = False
                    if resp.status_code in [200, 302]:
                        body_lower = resp.text[:5000].lower() if resp.status_code == 200 else ""
                        location = resp.headers.get('location', '').lower()

                        # Rejection indicators
                        reject_indicators = [
                            'invalid_redirect_uri', 'redirect_uri_mismatch',
                            'invalid redirect', 'not allowed', 'unauthorized_redirect',
                            'invalid_request', 'invalid parameter', 'something went wrong',
                        ]

                        # If we got a login page or redirect with code, it's accepted
                        if resp.status_code == 302 and 'code=' in location:
                            is_accepted = True  # SSO auto-login gave us a code!
                        elif resp.status_code == 200 and not any(ind in body_lower for ind in reject_indicators):
                            # Got login page = redirect_uri was accepted
                            accept_indicators = ['login', 'sign in', 'password', 'authenticate',
                                                'username', 'email']
                            if any(ind in body_lower for ind in accept_indicators):
                                is_accepted = True
                        elif resp.status_code == 302:
                            # Redirect but not to error page
                            if not any(ind in location for ind in reject_indicators):
                                # Check if redirecting to the target URI (means code was issued!)
                                if target_domain in location and 'code=' in location:
                                    is_accepted = True

                    if is_accepted:
                        accepted_redirects.append((redirect_uri, bypass_name, sev, resp))
                    elif resp.status_code == 400:
                        rejected_redirects.append((redirect_uri, bypass_name))

                except Exception:
                    continue

                await asyncio.sleep(0.5)

            # Analyze results: if arbitrary paths accepted but evil.com rejected = wildcard path
            external_rejected = any(name == "external_domain" for _, name in rejected_redirects)
            path_accepted = any(name in ("path_wildcard_target", "deep_path_wildcard")
                               for _, name, _, _ in accepted_redirects)

            if path_accepted and external_rejected:
                # Classic e-commerce pattern: domain validated, path wildcarded
                findings.append(Finding(
                    title=f"OAuth redirect_uri Wildcard Path Matching (client: {client_id})",
                    description=f"""
**OAuth redirect_uri Accepts Arbitrary Paths on Target Domain**

The authorization endpoint accepts ANY path under the target domain
as a valid redirect_uri, but correctly rejects external domains.

**Client ID:** {client_id}
**Pattern:** Domain validated ✓, Path wildcarded ✗

**Accepted redirect_uris:**
{chr(10).join(f'  - {uri} ({name})' for uri, name, _, _ in accepted_redirects)}

**Rejected redirect_uris:**
{chr(10).join(f'  - {uri} ({name})' for uri, name in rejected_redirects)}

**Impact (HIGH — Common e-commerce pattern):**
Any XSS, open redirect, or user-controlled content on {target_domain}
can be chained to steal OAuth authorization codes. The code leaks via:
1. Referer header to third-party resources loaded on the redirect page
2. JavaScript reading window.location on a page the attacker controls
3. Browser history / shared device access

If this client is a PUBLIC client (no client_secret required), the
stolen code can be exchanged for access tokens directly.

**RFC Violations:**
- RFC 6749 §3.1.2.2: redirect_uri MUST use exact matching
- RFC 9700 §4.2.4: MUST NOT use wildcard redirect URIs
""".strip(),
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    url=auth_endpoint,
                    evidence={
                        'client_id': client_id,
                        'accepted': [(u, n) for u, n, _, _ in accepted_redirects],
                        'rejected': rejected_redirects,
                    },
                    cwe_id=601,
                    owasp_category=self.owasp_category,
                ))

            for redirect_uri, bypass_name, sev, resp in accepted_redirects:
                if bypass_name in ("external_domain", "domain_suffix"):
                    findings.append(Finding(
                        title=f"OAuth redirect_uri External Domain Accepted (client: {client_id})",
                        description=f"""
**CRITICAL: OAuth Authorization Code Theft via External Domain**

The authorization endpoint accepted an attacker-controlled external domain
as redirect_uri. This enables direct authorization code theft.

**Client ID:** {client_id}
**Accepted redirect_uri:** {redirect_uri}
**Bypass type:** {bypass_name}

**No chaining required — direct account takeover.**
""".strip(),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CERTAIN,
                        url=auth_endpoint,
                        evidence={
                            'client_id': client_id,
                            'redirect_uri': redirect_uri,
                            'bypass_type': bypass_name,
                        },
                        cwe_id=601,
                        owasp_category=self.owasp_category,
                    ))

            # 3b: Test PKCE enforcement
            if pkce_methods and 'S256' in pkce_methods:
                # Already tested above — if any redirect was accepted without code_challenge,
                # PKCE is not enforced for this client
                if accepted_redirects:
                    findings.append(Finding(
                        title=f"PKCE Not Enforced (client: {client_id})",
                        description=f"""
**OAuth PKCE Not Required**

The authorization endpoint accepted a request for client '{client_id}'
WITHOUT a code_challenge parameter, even though the server supports PKCE.

**PKCE Methods Supported:** {pkce_methods}
**Enforcement:** Optional (not required)

**Impact:** Authorization code interception attacks are possible.
Combined with redirect_uri wildcard, an attacker can:
1. Steal authorization code via manipulated redirect_uri
2. Exchange the code for tokens WITHOUT a code_verifier
3. Obtain access_token, refresh_token, and id_token

This was the exact attack chain found in a real-world engagement.
""".strip(),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        url=auth_endpoint,
                        evidence={'client_id': client_id, 'pkce_methods': pkce_methods},
                        cwe_id=287,
                        owasp_category=self.owasp_category,
                    ))

            # 3c: Test if client is public (no client_secret needed for token exchange)
            if token_endpoint and accepted_redirects:
                try:
                    # Try to exchange a dummy code without client_secret
                    token_resp = await self.post(
                        token_endpoint,
                        data={
                            'grant_type': 'authorization_code',
                            'client_id': client_id,
                            'code': 'dummy_code_for_detection',
                            'redirect_uri': accepted_redirects[0][0],
                        },
                        headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    )

                    # If we get "invalid_grant" (not "invalid_client" or "unauthorized_client"),
                    # the client accepts requests without client_secret = PUBLIC CLIENT
                    if token_resp.status_code == 400:
                        try:
                            error_data = token_resp.json()
                            error_code = error_data.get('error', '')

                            if error_code == 'invalid_grant':
                                # Public client! The code was wrong, but client auth passed
                                findings.append(Finding(
                                    title=f"Public OAuth Client Without PKCE (client: {client_id})",
                                    description=f"""
**CRITICAL: Public OAuth Client Allows Token Exchange Without Secrets**

The client '{client_id}' is configured as a PUBLIC client:
- No client_secret required for token exchange
- Combined with redirect_uri wildcard = FULL ACCOUNT TAKEOVER

**Token endpoint response to dummy code:** {error_code}
(error='invalid_grant' means the client authenticated successfully
but the authorization code was invalid — proving no secret is needed)

**Complete Attack Chain:**
1. Craft OAuth URL with redirect_uri=https://{target_domain}/attacker-page
2. Victim clicks link → SSO auto-login → code sent to attacker path
3. Attacker intercepts code (Referer leak, XSS, open redirect)
4. POST code to {token_endpoint} with just client_id (no secret!)
5. Receive: access_token (PII), refresh_token (persistent), id_token

**This is the exact vulnerability found in a real-world engagement.**
""".strip(),
                                    severity=Severity.HIGH,
                                    confidence=Confidence.CERTAIN,
                                    url=token_endpoint,
                                    evidence={
                                        'client_id': client_id,
                                        'error_response': error_code,
                                        'is_public_client': True,
                                    },
                                    cwe_id=287,
                                    owasp_category=self.owasp_category,
                                ))
                            elif error_code in ('invalid_client', 'unauthorized_client'):
                                # Confidential client — needs client_secret
                                pass  # Not exploitable without secret
                        except Exception:
                            pass
                except Exception:
                    pass

            # 3d: Test implicit flow (should be disabled per best practice)
            try:
                implicit_url = (
                    f"{auth_endpoint}?response_type=token&client_id={client_id}"
                    f"&redirect_uri=https://{target_domain}/callback&scope=openid"
                )
                resp = await self.get(implicit_url, follow_redirects=False)

                if resp.status_code in [200, 302]:
                    body_lower = resp.text[:3000].lower() if resp.status_code == 200 else ""
                    location = resp.headers.get('location', '')

                    # If we see a login page (not error), implicit is enabled
                    reject_indicators = ['unauthorized_client', 'implicit flow is disabled',
                                        'client not allowed', 'unsupported_response_type']
                    if not any(ind in body_lower + location.lower() for ind in reject_indicators):
                        if any(ind in body_lower for ind in ['login', 'sign in', 'password']):
                            findings.append(Finding(
                                title=f"OAuth Implicit Flow Enabled (client: {client_id})",
                                description=f"""
**Implicit Flow Enabled — Token Exposure Risk**

The implicit grant type (response_type=token) is enabled for client '{client_id}'.
This returns tokens directly in the URL fragment, making them vulnerable to:
- Browser history leakage
- Referer header leakage
- XSS token theft

**Best practice:** Disable implicit flow, use authorization code with PKCE.
""".strip(),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.FIRM,
                                url=implicit_url,
                                evidence={'client_id': client_id},
                                cwe_id=522,
                                owasp_category=self.owasp_category,
                            ))
            except Exception:
                pass

            # 3e: Test password grant (should be disabled for frontend clients)
            try:
                password_resp = await self.post(
                    token_endpoint,
                    data={
                        'grant_type': 'password',
                        'client_id': client_id,
                        'username': 'test@test.com',
                        'password': 'test',
                    },
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                )

                if password_resp.status_code == 200:
                    findings.append(Finding(
                        title=f"Password Grant Enabled on Client (client: {client_id})",
                        description=f"""
**OAuth Resource Owner Password Grant Enabled**

The client '{client_id}' accepts direct password authentication.
This enables credential stuffing and brute-force attacks directly
against the token endpoint.

**This should NEVER be enabled for frontend/public clients.**
""".strip(),
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=token_endpoint,
                        evidence={'client_id': client_id},
                        cwe_id=287,
                        owasp_category=self.owasp_category,
                    ))
                elif password_resp.status_code == 400:
                    try:
                        err = password_resp.json()
                        # "unauthorized_client" or "Client not allowed for direct access grants" = properly disabled
                        if err.get('error') not in ('unauthorized_client',):
                            # Other errors might indicate enabled but wrong credentials
                            if err.get('error') == 'invalid_grant':
                                findings.append(Finding(
                                    title=f"Password Grant Accepted (client: {client_id})",
                                    description=f"""
**Password Grant Enabled — Credentials Were Wrong But Grant Type Accepted**

The client '{client_id}' processed a password grant request
(returned invalid_grant, not unauthorized_client).

**This enables direct credential brute-forcing.**
""".strip(),
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.FIRM,
                                    url=token_endpoint,
                                    evidence={'client_id': client_id, 'error': err},
                                    cwe_id=307,
                                    owasp_category=self.owasp_category,
                                ))
                    except Exception:
                        pass
            except Exception:
                pass

        return findings

    async def _discover_oauth_client_ids(self, base_url: str) -> List[str]:
        """
        Discover OAuth client IDs from the frontend application.

        Client IDs are often in:
        - HTML page source (config objects, meta tags)
        - JavaScript bundles (SPA config)
        - Login page hidden fields
        - Redirect URLs in the page

        Lesson from a real-world engagement: Found 'frontend-authorizer' in
        checkout login page's frontendAuthorizerConfig JSON object.
        """
        client_ids = set()

        if not self.client:
            return list(client_ids)

        # Pages likely to contain OAuth config
        pages_to_check = [
            base_url,
            f"{base_url.rstrip('/')}/login",
            f"{base_url.rstrip('/')}/signin",
            f"{base_url.rstrip('/')}/auth",
            f"{base_url.rstrip('/')}/checkout/login",
            f"{base_url.rstrip('/')}/account",
        ]

        client_id_patterns = [
            # JSON config patterns
            re.compile(r'["\']?client[_-]?[Ii]d["\']?\s*[:=]\s*["\']([a-zA-Z0-9._-]{5,60})["\']'),
            # OAuth redirect URLs containing client_id
            re.compile(r'client_id=([a-zA-Z0-9._-]{5,60})'),
            # Keycloak-style config
            re.compile(r'clientId["\']?\s*[:=]\s*["\']([a-zA-Z0-9._-]{5,60})["\']'),
            # OIDC config in JS
            re.compile(r'oidc[_-]?client[_-]?id["\']?\s*[:=]\s*["\']([a-zA-Z0-9._-]{5,60})["\']'),
        ]

        for page_url in pages_to_check:
            try:
                resp = await self.get(page_url)
                if resp.status_code == 200:
                    body = resp.text[:100000]  # First 100KB
                    for pattern in client_id_patterns:
                        for match in pattern.finditer(body):
                            cid = match.group(1)
                            # Filter out common false positives
                            if cid.lower() not in ('test', 'example', 'your-client-id', 'client-id',
                                                   'your_client_id', 'changeme', 'undefined', 'null'):
                                client_ids.add(cid)
            except Exception:
                continue

        return list(client_ids)

    # =========== RATE LIMITING ===========

    # Status codes that mean the request never reached working auth logic, so
    # they can neither be a "successful" attempt nor evidence of missing rate
    # limiting: the handler didn't run. 404 not found, 405 wrong method, 415
    # unsupported media, 501 not implemented.
    _NON_AUTH_STATUS = frozenset({404, 405, 415, 501})

    async def test_rate_limiting(self, url: str, method: str = "POST", data: Optional[Dict] = None) -> List[Finding]:
        """Test if rate limiting is properly implemented"""
        findings = []

        if not self.client:
            return findings

        # Send multiple rapid requests
        num_requests = 20
        success_count = 0
        responses = []

        data = data or {"username": "test", "password": "test"}

        for i in range(num_requests):
            try:
                if method == "POST":
                    response = await self.post(url, data=data)
                else:
                    response = await self.get(url)

                responses.append(response.status_code)
                is_redirect = 300 <= response.status_code < 400
                # A "success" here means a real auth attempt got processed and
                # was NOT throttled. Throttling (429/403), redirects, and codes
                # that mean the handler never ran (404/405/415/501) don't count.
                if (response.status_code not in (429, 403)
                        and not is_redirect
                        and response.status_code not in self._NON_AUTH_STATUS):
                    success_count += 1

            except Exception:
                continue

        # If most requests succeeded, no rate limiting
        if success_count >= num_requests - 2:
            # Skip if no request ever reached working auth logic — every
            # response was a redirect or a "handler didn't run" code (404 not
            # found, 405 method not allowed on a GET-only/other endpoint, ...).
            # The test proves nothing about whether real auth rate-limits.
            # (This also subsumes the all-404 and all-redirect cases.)
            if responses and all(
                (300 <= code < 400) or code in self._NON_AUTH_STATUS
                for code in responses
            ):
                return findings

            findings.append(Finding(
                title="Missing Rate Limiting on Authentication Endpoint",
                description=f"""
**No Rate Limiting Detected**

The endpoint processed {success_count}/{num_requests} requests without rate limiting.

**Endpoint:** {url}
**Method:** {method}

**Impact:**
- Enables brute force attacks on passwords
- Account lockout bypass
- Credential stuffing attacks

**Recommendations:**
1. Implement rate limiting (e.g., 5 attempts per minute)
2. Use progressive delays / exponential backoff
3. Implement CAPTCHA after failed attempts
4. Consider account lockout policies
""".strip(),
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=url,
                evidence={
                    'requests_sent': num_requests,
                    'requests_succeeded': success_count,
                    'response_codes': responses,
                },
                cwe_id=307,
                owasp_category=self.owasp_category,
            ))

        return findings

    # =========== 2FA BYPASS TESTS ===========

    async def test_2fa_bypass(self, base_url: str, auth_headers: Optional[Dict] = None) -> List[Finding]:
        """Test for common 2FA bypass vulnerabilities"""
        findings = []
        auth_headers = auth_headers or {}

        if not self.client:
            return findings

        # Common 2FA bypass patterns
        bypass_tests = [
            # Empty/null OTP
            {"otp": "", "code": "", "totp": ""},
            {"otp": "000000", "code": "000000"},
            {"otp": "123456"},
            # Skip 2FA by directly accessing authenticated endpoint
            # (Would need to know a post-auth endpoint)
        ]

        for endpoint_type, endpoints in [('2fa', self.AUTH_ENDPOINTS.get('2fa', []))]:
            for endpoint in endpoints:
                url = f"{base_url.rstrip('/')}{endpoint}"

                for bypass_data in bypass_tests:
                    try:
                        response = await self.post(
                            url,
                            data=bypass_data,
                            headers=auth_headers
                        )

                        # If we get 200 or redirect to dashboard, potential bypass
                        if response.status_code in [200, 302, 303]:
                            location = response.headers.get('location', '')
                            # Check if it redirected to something that looks like success
                            if 'dashboard' in location.lower() or 'home' in location.lower():
                                findings.append(Finding(
                                    title="Potential 2FA Bypass",
                                    description=f"""
**2FA/MFA Bypass Vulnerability**

The 2FA verification may be bypassable using: {bypass_data}

**Endpoint:** {url}
**Response:** {response.status_code}
**Location:** {location}

**Manual verification required!**
""".strip(),
                                    severity=Severity.HIGH,
                                    confidence=Confidence.TENTATIVE,
                                    url=url,
                                    evidence={'bypass_data': bypass_data, 'status': response.status_code},
                                    cwe_id=287,
                                    owasp_category=self.owasp_category,
                                ))

                    except Exception:
                        continue

        return findings

    # =========== MAIN SCAN ===========

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        """
        Main scanning entry point.

        Enhanced with:
        - Email enumeration via registration/password reset (e-commerce lesson)
        - OAuth/Keycloak misconfiguration testing
        - PKCE enforcement checking
        - redirect_uri wildcard detection
        """
        # Ensure client is initialized (engine manages context, so check first)
        if not self.client:
            await self.__aenter__()

        # Check for JWTs in response
        if ctx.response:
            # Look for JWTs in Set-Cookie, Authorization responses, body
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

            # Check headers
            for header_name, header_value in ctx.response.headers.items():
                for match in re.finditer(jwt_pattern, header_value):
                    for finding in self.analyze_jwt(match.group()):
                        finding.url = ctx.url
                        yield finding

            # Check body
            if ctx.response.body:
                body_text = ctx.response.body.decode('utf-8', errors='ignore') if isinstance(ctx.response.body, bytes) else str(ctx.response.body)
                for match in re.finditer(jwt_pattern, body_text):
                    for finding in self.analyze_jwt(match.group()):
                        finding.url = ctx.url
                        yield finding

        # ── jwt_tool deep analysis — external tool (optional) ─────────────
        # Extract all JWT tokens found so far and run jwt_tool for deeper analysis
        try:
            from beatrix.core.external_tools import JwtToolRunner
            jwt_tool = JwtToolRunner()
            if jwt_tool.available and ctx.response:
                jwt_pattern_deep = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
                tokens_checked = set()
                # Collect tokens from all response locations
                all_text = ""
                for _, hv in ctx.response.headers.items():
                    all_text += hv + "\n"
                if ctx.response.body:
                    all_text += ctx.response.body.decode('utf-8', errors='ignore') if isinstance(ctx.response.body, bytes) else str(ctx.response.body)

                for match in re.finditer(jwt_pattern_deep, all_text):
                    token = match.group()
                    if token in tokens_checked:
                        continue
                    tokens_checked.add(token)
                    try:
                        jwt_result = await jwt_tool.analyze(token)
                        if jwt_result and jwt_result.get("vulnerabilities"):
                            # Enrich evidence with decoded header/payload
                            base_evidence = {
                                "token_prefix": token[:50],
                                "header": jwt_result.get("header", {}),
                                "payload": jwt_result.get("payload", {}),
                            }

                            for vuln in jwt_result["vulnerabilities"]:
                                vuln_evidence = {**base_evidence, "jwt_tool_result": vuln}
                                desc_parts = [f"jwt_tool deep analysis found: {vuln.get('detail', 'Unknown vulnerability')}"]

                                # Attempt role-escalation tamper PoC for exploitable vulns
                                vtype = vuln.get("type", "").lower()
                                if any(k in vtype for k in ("none", "confusion", "blank", "crack")):
                                    try:
                                        tampered = await jwt_tool.tamper(token, "role", "admin")
                                        if tampered:
                                            vuln_evidence["tampered_token"] = tampered
                                            vuln_evidence["tamper_claim"] = "role → admin"
                                            desc_parts.append(f"\nRole-escalation PoC: tampered 'role' claim to 'admin'")
                                            desc_parts.append(f"Tampered token: {tampered[:80]}...")
                                    except Exception:
                                        pass

                                if jwt_result.get("header"):
                                    desc_parts.append(f"\nJWT Header: {jwt_result['header']}")
                                if jwt_result.get("payload"):
                                    desc_parts.append(f"JWT Payload claims: {list(jwt_result['payload'].keys()) if isinstance(jwt_result['payload'], dict) else jwt_result['payload']}")

                                yield Finding(
                                    title=f"jwt_tool: {vuln.get('type', 'JWT Vulnerability')}",
                                    description="\n".join(desc_parts),
                                    severity=Severity.HIGH,
                                    confidence=Confidence.FIRM,
                                    url=ctx.url,
                                    evidence=vuln_evidence,
                                    cwe_id=345,
                                    owasp_category=self.owasp_category,
                                    scanner_module="jwt_tool",
                                )
                    except Exception:
                        pass  # jwt_tool failed on this token — internal checks still ran
        except ImportError:
            pass  # external_tools not available

        # Test auth endpoints
        for findings in [
            await self.test_username_enumeration(ctx.base_url + "/login"),
            await self.test_rate_limiting(ctx.base_url + "/login"),
        ]:
            for finding in findings:
                yield finding

        # Email enumeration via registration/guest checkout
        for finding in await self.test_email_enumeration(ctx.base_url):
            yield finding

        # OAuth/Keycloak misconfig testing
        for finding in await self.test_oauth_misconfig(ctx.base_url):
            yield finding

    async def analyze_token(self, token: str) -> List[Finding]:
        """Analyze a JWT token directly"""
        return self.analyze_jwt(token)


# Quick CLI
if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python auth.py <jwt_token|url>")
            return

        scanner = AuthScanner()
        target = sys.argv[1]

        if target.startswith('eyJ'):
            # It's a JWT
            print("[*] Analyzing JWT token...")
            findings = await scanner.analyze_token(target)
        else:
            # It's a URL
            print(f"[*] Scanning auth endpoints on: {target}")
            ctx = ScanContext.from_url(target)
            findings = []
            async for f in scanner.scan(ctx):
                findings.append(f)

        if findings:
            print(f"\n[!] Found {len(findings)} issues:\n")
            for f in findings:
                print(f"  [{f.severity.value.upper()}] {f.title}")
                print(f"    {f.description[:150]}...")
                print()
        else:
            print("\n[✓] No authentication issues detected")

    asyncio.run(main())
