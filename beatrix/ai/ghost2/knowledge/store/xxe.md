# XML External Entity (XXE) Injection

An XML parser processes attacker-defined external entities, enabling local
file disclosure, SSRF, or (rarely) RCE.

## Detect
- `run_scanner xxe` probes XML-accepting endpoints.
- Any endpoint consuming XML: SOAP, SAML, `Content-Type: application/xml` or
  `text/xml`, XML file uploads (DOCX/SVG/XLSX are ZIP+XML), RSS/SVG parsers.
- Classic in-band probe defines an entity pointing at a local file and
  references it in an element that gets echoed back.

## Confirm real impact
- **In-band**: response contains the contents of a file you referenced
  (`/etc/passwd`, `/etc/hostname`, `C:\Windows\win.ini`) — direct proof.
- **Blind (OOB)**: define an external entity pointing at `oob_register`'s URL;
  a callback confirms the parser fetched it. Escalate to out-of-band file
  exfiltration via a parameter entity + external DTD.
- SSRF-via-XXE: point the entity at an internal host / metadata endpoint and
  confirm via callback or reflected response.

## False positives to reject
- The XML echoed back with the entity **unexpanded** (`&xxe;` literal) — the
  parser has external entities disabled.
- A parse error alone; errors mean the input was rejected, not that entities
  resolved.
- Callbacks that come from your own tooling rather than the target parser.

*Enforced by code:* `record_finding` runs this through `ImpactValidator`'s
`error_only` and `evidence_exists`/`reproducible` checks — a parse error with
no leaked file content or OOB callback will be flagged.

## Severity
High to Critical: local file read of sensitive files, or SSRF to internal
services / cloud metadata.
