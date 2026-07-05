# Business Logic Flaws

The application behaves exactly as coded, but the workflow itself can be abused —
negative quantities, skipped steps, price/parameter tampering, replay, or
unintended state transitions. No signature; requires understanding intent.

## Detect
- `run_scanner business_logic` and `run_scanner payment` for commerce flows.
- Map multi-step workflows (checkout, transfer, signup, approval). Ask at each
  step: what invariant is assumed, and can I violate it out of order or with a
  hostile value?

## Confirm real impact
- Show a concrete, adverse outcome: negative/oversized quantity yielding a
  refund or free goods; price/currency parameter tampering that the server
  honors at settlement; skipping payment/verification and still reaching the
  granted state; replaying a one-time action.
- Prove the **final state** reflects the abuse (order placed at wrong price,
  balance credited, entitlement granted) — reproducibly.

## False positives to reject
- Client-side price/qty edits that the server **recomputes/rejects** server-side.
- A step that appears skippable but the backend still enforces the invariant
  (you end blocked or corrected).
- "Weird but harmless" behavior with no security or financial consequence.

*Enforced by code:* `record_finding` runs this through `ImpactValidator`'s
`evidence_exists`/`reproducible` and `not_info_noise` checks — a described
abuse without a shown, reproduced final-state outcome will be flagged.

## Severity
Case-by-case, driven by the demonstrated impact (financial loss, entitlement
bypass, integrity violation). Always anchor to a shown outcome.
