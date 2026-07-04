# Server-Side Request Forgery (SSRF)

The server can be induced to make HTTP (or other-protocol) requests to an
attacker-chosen destination — internal services, cloud metadata, or an
external collaborator.

## Detect
- `run_scanner ssrf` probes URL/host parameters, redirect chains, and
  metadata targets.
- Look for parameters that take a URL, hostname, file path, or that fetch
  remote content: `url=`, `image=`, `callback=`, `webhook=`, `dest=`, XML/PDF
  renderers, link-preview/import features.

## Confirm real impact — OOB is the ground truth
- `oob_register` to get a unique collaborator URL, plant it in the candidate
  parameter, then `oob_poll`. A DNS *or* HTTP callback from the target's
  infrastructure is proof the server made the request.
- Escalate to demonstrate *reach*: fetch `http://169.254.169.254/latest/meta-data/`
  (AWS), `http://metadata.google.internal/` (GCP), or an internal-only host,
  and return the response body. Reading cloud credentials is Critical.
- Note whether it's full-response (you see the body) or blind (only the
  callback fires) — impact differs.

## False positives to reject
- The payload host resolving/loading in *your* browser or the scanner host —
  the request must originate from the **target server** (that's what the OOB
  callback proves).
- A parameter reflected in a response but never fetched server-side.
- Client-side redirects (the browser follows them), which are open-redirect,
  not SSRF.
- Callbacks to a shared CDN/analytics domain that the app legitimately calls.

## Severity
Critical when it reaches cloud metadata / internal services / credentials;
High for confirmed blind SSRF via OOB with limited demonstrated reach.
