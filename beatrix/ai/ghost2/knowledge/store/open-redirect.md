# Open Redirect

A parameter controls a redirect destination without validation, sending users
to an attacker-chosen site. Impact is usually Low on its own but can chain
(OAuth token theft, SSRF, phishing, filter bypass).

## Detect
- `run_scanner redirect` and `run_scanner oauth_redirect`.
- Params like `redirect`, `return`, `next`, `url`, `dest`, `continue`,
  `returnTo`. Set them to an external host and follow the response.

## Confirm real impact
- The server must issue a redirect (3xx `Location:`, or a meta/JS redirect) to
  your **external, attacker-controlled** host. Show the `Location` header
  pointing off-site.
- Test bypasses of weak validation: `//evil.com`, `https:evil.com`,
  `/\evil.com`, `https://trusted@evil.com`, whitelisted-prefix tricks
  (`trusted.com.evil.com`).
- Raise severity by chaining: redirect that leaks an OAuth `code`/token, or
  feeds an SSRF sink.

## False positives to reject
- Redirects only to **same-origin / relative** paths — not open.
- Validation that rejects external hosts (you land back on an error/login).
- The parameter reflected but no actual redirect occurs.
- A redirect the browser performs to a host on the site's own allowlist.

## Severity
Low/Info alone; Medium/High when chained into token theft or SSRF.
