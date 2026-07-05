# Insecure Deserialization

The app deserializes attacker-controlled data with an unsafe deserializer,
enabling object injection and often RCE.

## Detect
- `run_scanner deserialization`.
- Spot serialized blobs: Java (`rO0` base64 / `application/x-java-serialized-object`),
  PHP (`O:8:"..."`), Python pickle, .NET (`ViewState`, `__VIEWSTATE`), Ruby
  Marshal, Node `node-serialize`. Look in cookies, hidden fields, headers, APIs.

## Confirm real impact
- Blind RCE is typical. Craft a gadget-chain payload (ysoserial for Java/.NET,
  PHP POP chains) whose side effect is an OOB callback: `oob_register`, embed a
  DNS/HTTP callout, submit, then `oob_poll`. A callback = confirmed execution.
- If a gadget triggers a distinguishable error vs. benign input, that supports
  the finding but isn't proof on its own.

## False positives to reject
- Recognizing a serialized format is **not** a vulnerability — many apps
  deserialize signed/HMAC'd or trusted-only data safely.
- `__VIEWSTATE` present without confirming MAC is disabled/known-key.
- A parse error from a corrupted blob (rejection), with no callback.
- Base64 that merely *looks* serialized but is plain JSON/text.

*Enforced by code:* `record_finding` runs this through `ImpactValidator`'s
`evidence_exists`/`reproducible` checks — recognizing a serialized format
without an OOB callback or execution proof will be flagged.

## Severity
Critical on confirmed code execution; do not report as high without an OOB
callback or equivalent execution proof.
