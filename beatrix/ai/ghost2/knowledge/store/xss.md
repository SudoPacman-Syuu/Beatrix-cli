# Cross-Site Scripting (XSS)

Attacker-controlled input is rendered into a page such that it executes as
script in a victim's browser (reflected, stored, or DOM-based).

## Detect
- `run_scanner injection` tests reflected/DOM contexts with context-aware
  payloads; `run_scanner js_analysis` surfaces DOM sinks.
- Manually: inject a unique marker and find where it lands. The *context*
  decides exploitability — HTML body, attribute, JS string, URL, or CSS.
- DOM XSS: trace `location`/`document.referrer`/`postMessage` into sinks like
  `innerHTML`, `eval`, `document.write`, `setTimeout`.

## Confirm real impact
- Reflection must break out of its context into script execution. Show a
  payload that would actually run: e.g. closing the attribute/tag and injecting
  an event handler or `<script>`, appropriate to the context.
- Verify the payload is **not neutralized**: no HTML-encoding of `<`, `>`, `"`
  in the reflected output; CSP does not block the vector.
- Strongest proof: an executing PoC (alert/DOM change) or an OOB callback fired
  from injected JS (`oob_register`, then exfiltrate to the callback URL).

## False positives to reject
- Reflection that is HTML-encoded (`&lt;script&gt;`) — not exploitable.
- Markers reflected only inside a value that is properly attribute-encoded or
  JSON-encoded with no breakout.
- A strict CSP (`script-src 'self'` with no unsafe-inline/JSONP) that blocks
  inline execution — downgrade unless you find a CSP bypass.
- Self-XSS requiring the victim to paste a payload into their own console.

## Severity
High for stored/reflected XSS with a working execution PoC; Medium for
DOM XSS needing unusual preconditions; downgrade CSP-blocked reflections.
