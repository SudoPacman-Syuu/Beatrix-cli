# Race Conditions (TOCTOU)

Concurrent requests interleave between a check and a use, letting an attacker
exceed a limit that should hold once — double-spend, coupon reuse, limit
bypass, duplicate account actions.

## Detect
- `run_scanner sequencer` helps with token analysis; race testing itself is
  manual/scripted.
- Target single-use or limited operations: redeem code/coupon, withdraw/transfer,
  "claim once", vote, apply-discount, MFA/OTP attempts.

## Confirm real impact
- Fire N parallel requests at the same operation (single-packet / last-byte-sync
  where possible) using `python_exec` in the sandbox, and show the guarded
  action succeeded **more times than allowed** — e.g. a $10 coupon applied
  twice, two withdrawals from a balance that covers one.
- Demonstrate the resulting **state**: final balance, duplicate records,
  multiple accepted redemptions — reproducibly, not a one-off.

## False positives to reject
- Parallel requests where only one succeeds and the rest 409/return "already
  used" — the guard holds.
- Apparent duplicates that reconcile later (idempotency keys, eventual
  dedup) — verify the final persisted state.
- Timing variance mistaken for a race without a demonstrated limit breach.

*Enforced by code:* `record_finding` runs this through `ImpactValidator`'s
`evidence_exists`/`reproducible` checks — a claimed race without a shown,
reproduced final-state breach will be flagged.

## Severity
High to Critical for financial / integrity impact (double-spend, limit bypass);
requires a clear, reproduced breach of a per-operation limit.
