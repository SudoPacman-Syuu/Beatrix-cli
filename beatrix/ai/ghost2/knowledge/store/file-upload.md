# Unrestricted File Upload

An upload feature fails to constrain file type, content, or storage location,
letting an attacker place executable or malicious content.

## Detect
- `run_scanner file_upload`.
- Any upload: avatars, documents, imports, attachments. Test the validation:
  extension (`.php`, `.phtml`, `.jsp`, `.aspx`, `.svg`, `.html`), MIME type,
  magic bytes, double extensions (`shell.php.jpg`), null bytes, case tricks,
  content-type mismatch.

## Confirm real impact
- The strong case is **execution**: upload a server-side script, locate its
  stored URL, request it, and show it executed (an OOB callback or reflected
  command output). That's RCE.
- Lesser but real: stored XSS via uploaded HTML/SVG served inline
  (see [[xss]]); path traversal in the filename writing outside the upload dir
  (see [[path-traversal]]); XXE via DOCX/SVG (see [[xxe]]).
- Show the uploaded file is **retrievable and interpreted**, not just accepted.

## False positives to reject
- Upload accepted but stored where it can't execute (rewritten name, random
  path, served with `Content-Disposition: attachment` / a non-executing
  content-type, or off a CDN as static bytes).
- Validation that rejects your payload extension/type.
- An uploaded file you can't locate or retrieve — no demonstrated impact.

*Enforced by code:* `record_finding` runs this through `ImpactValidator`'s
`evidence_exists`/`reproducible` checks — an accepted upload with no
demonstrated execution/retrieval will be flagged.

## Severity
Critical for code execution; High/Medium for stored XSS or traversal via
upload, scoped to the demonstrated effect.
