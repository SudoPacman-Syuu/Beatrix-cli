# Content & parameter discovery (fuzzing)

Fuzzing widens the attack surface recon found: hidden endpoints, backup files,
and — often more valuable — undocumented *parameters* on endpoints you already
know. Tools: ffuf/feroxbuster for paths, arjun for parameters, gau/katana for
historical URLs.

## Path/content discovery
- Fuzz for routes and files: admin panels, `/.git/`, `/backup`, `.env`,
  swagger/openapi docs, `/actuator`, old API versions.
- **Calibrate against the app's own 404 first.** Many sites return 200 with a
  soft "not found" page, so a 200 is not "found." Record the baseline 404 body
  size/shape and filter it (`-fs`, `-fw`, `-mc`), or you drown in false hits.
- Rank hits by what they unlock: an exposed `/.git/` or `/api/v1/internal` beats
  another marketing page.

## Parameter discovery
- Undocumented params are where IDOR, SSRF, open-redirect, and mass-assignment
  hide. arjun (or a param wordlist) finds inputs the UI never exposes.
- For each discovered param, note the endpoint + method and hand it to the right
  test: a `url=`/`next=`/`redirect=` param → SSRF/open-redirect; an `id`/`uuid`
  → IDOR; unexpected writable fields on a JSON body → mass assignment.

## Confirmation bar / false positives
- A discovered path is only a finding if it exposes something (source, secrets,
  unprotected admin function) — existence alone is recon, not a vulnerability.
- Filter the soft-404 baseline before trusting any status/length signal.
- Rate-limited or WAF-throttled responses can look like a wall of identical
  hits; confirm a handful manually before acting on the wordlist run.
