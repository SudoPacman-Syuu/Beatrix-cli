# Mass Assignment / Autobinding

An endpoint binds request parameters directly onto a model, letting an attacker
set fields they shouldn't control (`role`, `is_admin`, `balance`, `verified`,
`user_id`).

## Detect
- `run_scanner mass_assignment`.
- On create/update endpoints (registration, profile edit, settings), add extra
  JSON/form fields beyond what the UI sends. Infer field names from GET
  responses, GraphQL schema, or JS.

## Confirm real impact
- Submit the extra field and then **re-read the object** to prove it was
  persisted with your attacker-chosen value — e.g. set `"role":"admin"` and
  confirm the account now has admin rights (a privileged action succeeds), or
  `"balance":99999` reflected back and usable.
- The changed field must be **security-relevant**; showing the effect (elevated
  access, altered price) is what makes it a finding.

## False positives to reject
- Extra fields accepted in the request but **ignored** — re-read shows no
  change. Silent acceptance is not assignment.
- Server echoing your input back in the immediate response without persisting
  it (reflect ≠ store — re-read on a fresh request).
- Setting a non-sensitive field (display name, timezone).

*Enforced by code:* `record_finding` runs this through `ImpactValidator`'s
`evidence_exists`/`reproducible` checks — an accepted field with no re-read
proof of persistence will be flagged.

## Severity
High to Critical when it grants privilege escalation or financial impact;
otherwise scoped to the affected field's sensitivity.
