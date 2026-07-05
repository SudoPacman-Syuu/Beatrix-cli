# SQL Injection

User input reaches a SQL query without safe parameterization, letting an
attacker alter the query's structure.

## Detect
- `run_scanner injection` covers error-based, boolean-blind, time-blind and
  UNION vectors with WAF-aware payloads. Start there.
- Manually: send a single quote `'`, then the balanced pair `''`. A 500 on `'`
  that clears on `''` is a classic tell. Try boolean pairs like `' AND '1'='1`
  vs `' AND '1'='2` and compare responses (`compare_responses`).
- For blind, use time payloads (`'||pg_sleep(5)--`, `' OR SLEEP(5)--`) and
  confirm the delay tracks the requested seconds across at least two values.

## Confirm real impact
- **Boolean**: the true/false payloads must produce a *stable, reproducible*
  content difference tied to the injected logic — not random length jitter.
- **Time-based**: response time must scale with the sleep argument (e.g. 3s vs
  6s) across repeats; a single slow response is not proof.
- **Error/UNION**: extract a concrete value that could only come from the DB
  (version string, a table/column name, a row you then re-read).
- Best proof: pull a value via UNION or blind extraction and show it matches
  data you can independently verify.

## False positives to reject
- A 500 on `'` alone with no differential behavior — many apps just log and
  error on odd input.
- Time deltas that don't scale with the payload, or that also occur on benign
  requests (slow endpoint, network jitter). Repeat before believing.
- WAF block pages (403/406) — that's the WAF reacting, not the DB.
- Reflected payload in an error message without query-structure control.
- **Behavioral/fingerprint divergence on a WAF or bot-protection endpoint**
  (captcha, challenge, PerimeterX, DataDome, Cloudflare `/cdn-cgi/`,
  Turnstile). These systems are *designed* to respond differently to
  malicious-looking input — a fingerprint difference there is the WAF doing
  its job, not the database reacting. Only error-based or data-extraction
  proof counts on these endpoints.

*Enforced by code:* `record_finding` runs this through `ImpactValidator`'s
`behavioral_sqli_waf` check (auto-kills behavioral-only findings on known
WAF/challenge paths) and `error_only` (kills a bare DB error with no
actionable leaked data).

## Severity
Critical when it yields data extraction or auth bypass; High for confirmed
blind injection without demonstrated extraction.
