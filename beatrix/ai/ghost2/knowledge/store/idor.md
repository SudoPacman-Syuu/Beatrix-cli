# IDOR / Broken Object-Level Authorization (BOLA)

A request references an object by identifier (numeric id, UUID, filename,
account number) and the server returns or mutates it **without checking the
caller is authorized** for that object.

## Detect
- `run_scanner idor` fuzzes object references and compares authorized vs.
  cross-account access.
- Find endpoints that take an id: `/api/users/1234`, `?invoice=5001`,
  `/documents/<uuid>`. Enumerate or swap the id.

## Confirm real impact — you need two identities
- The gold standard is a **cross-account differential**: as user A, request
  user B's object. If you receive B's private data (or successfully mutate it),
  that's a confirmed IDOR. Use two auth contexts and `compare_responses`.
- The returned data must be **B's and sensitive** — PII, another tenant's
  records, private documents. Show a value that is clearly not A's own.
- For write/mutation IDOR, prove the state change persisted (re-read as B).

## False positives to reject
- Enumerable ids that return **your own** data or 403/404 for others — access
  control is working.
- Public objects that are *meant* to be readable by id (a public blog post,
  a shared/published link with an unguessable token acting as the capability).
- A 200 with an empty/placeholder body for another id — no sensitive data
  disclosed.
- Guessable ids alone. Predictability is not a vuln without missing authZ.
- Non-guessable identifiers (a booking reference, an opaque per-object token)
  swapped only because you already had both values. If the target requires an
  auth token/id an attacker can't reasonably obtain, you must show how they'd
  get it (enumeration, prediction, leak elsewhere) — not just that swapping it
  works once you already have both.

*Enforced by code:* `record_finding` runs this through `ImpactValidator` —
`evidence_exists`, `reproducible`, and `auth_required` will flag or reject a
claim that doesn't clear this bar.

## Severity
High to Critical depending on data sensitivity and whether it's read-only or
allows modification/deletion across accounts.
