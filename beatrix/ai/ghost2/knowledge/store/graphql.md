# GraphQL Vulnerabilities

GraphQL endpoints expose a flexible query surface that concentrates several
bug classes: introspection leakage, authorization gaps, injection, and
denial-of-service via nested queries.

## Detect
- `run_scanner graphql`.
- Find the endpoint (`/graphql`, `/api/graphql`, `/v1/graphql`). Try an
  introspection query; check if it's enabled in production.
- Enumerate mutations/queries and test each for missing authorization.

## Confirm real impact
- **AuthZ / IDOR-in-GraphQL**: call a query/mutation for another user's object
  or a privileged operation as a low-priv user and receive their data / a
  successful state change (see [[idor]], [[access-control]]).
- **Injection**: argument values flowing into SQL/NoSQL — confirm as per
  [[sqli]] (differential or extracted value).
- **Batching/nesting DoS**: show a deeply nested or aliased/batched query
  causing disproportionate, repeatable resource use — but only report DoS with
  clear authorization and measured impact.

## False positives to reject
- Introspection enabled, alone: information exposure (Low/Info) unless it
  reveals something otherwise-protected. It is *not* an auth bypass.
- Field suggestions / verbose errors as high severity by themselves.
- A query erroring for another user's object — authorization is working.

## Severity
Follows the underlying class: Critical/High for authZ bypass or injection;
Low/Info for introspection or verbose errors alone.
