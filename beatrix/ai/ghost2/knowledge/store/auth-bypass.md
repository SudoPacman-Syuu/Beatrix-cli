# Authentication Bypass & Session Flaws

Weaknesses that let an attacker authenticate as another user, forge sessions,
or skip authentication — including JWT flaws and OAuth misconfigurations.

## Detect
- `run_scanner auth` and `run_scanner oauth_redirect`.
- JWT: decode the token. Check for `alg: none`, weak HMAC secrets (brute
  common keys), `alg` confusion (RS256→HS256 using the public key as the HMAC
  secret), missing `exp`, unverified `kid`/`jku` header injection.
- Session: fixation (session id unchanged across login), predictable/short
  tokens, missing invalidation on logout, cookies without `HttpOnly`/`Secure`.
- OAuth: open `redirect_uri`, leaked `code`/token via redirect, `state` missing
  (CSRF), implicit-flow token leakage.

## Confirm real impact
- Forge or tamper a token/session and show it grants access as **another
  identity** — retrieve that user's data or perform an authenticated action.
- For `alg:none` / key confusion, present the forged token and show it's
  accepted (a protected endpoint returns 200 with the impersonated user's
  context).
- For OAuth redirect leakage, show the `code`/token actually delivered to an
  attacker-controlled URL and that it's usable.

## False positives to reject
- Decoding a JWT and *noticing* a weak-looking claim — you must show the server
  **accepts** a forged variant. An unmodified token is not a finding.
- Missing `HttpOnly`/`Secure` flags reported as high severity in isolation —
  these are hardening issues (Low/Info) absent a concrete exploitation path.
- `redirect_uri` values that are validated against an allowlist.
- Short token lifetime treated as a bug; it's usually a control.

## Severity
Critical for full authentication bypass / account takeover; cookie-flag and
hardening gaps are Low/Info on their own.
