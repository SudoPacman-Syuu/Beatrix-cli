# CORS Misconfiguration

The server's Cross-Origin Resource Sharing policy is permissive enough to let a
malicious origin read authenticated responses.

## Detect
- `run_scanner cors`.
- Send requests with varied `Origin` headers and inspect the reflected
  `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials`
  (ACAC) response headers.

## Confirm real impact — the dangerous combination
- The exploitable case is **ACAO reflects an arbitrary/attacker origin AND
  ACAC: true**, on an endpoint that returns sensitive, credentialed data. That
  combination lets attacker-origin JS read the victim's data.
- Also exploitable: ACAO trusts `null`, or a weak regex (e.g. suffix match so
  `evil-example.com` or `example.com.evil.com` is accepted) — show the bad
  origin is reflected.
- Prove it: with a spoofed `Origin`, the response reflects it in ACAO with
  credentials allowed on a data endpoint.

## False positives to reject
- `ACAO: *` **without** `ACAC: true` — the wildcard cannot be used with
  credentials, so no cross-origin reading of authenticated data. Low/Info at
  most, and only if the data is sensitive-but-public.
- ACAO reflecting the origin but the endpoint returns only public, unauthenticated
  content.
- Preflight allowing methods/headers without a permissive ACAO+credentials pair.
- A trusted, legitimately-allowlisted origin being reflected.

## Severity
High when reflected arbitrary origin + credentials exposes user data; otherwise
Low/Info.
