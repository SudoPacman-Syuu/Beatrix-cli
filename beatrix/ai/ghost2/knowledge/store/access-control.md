# Broken Access Control (Function-Level / Vertical)

The app fails to enforce *what actions* a user may perform — a low-privilege
user reaches admin functionality, or an endpoint trusts a client-supplied role.
(Object-level access control is IDOR — see [[idor]].)

## Detect
- `run_scanner bac`.
- Enumerate admin/privileged routes (`/admin`, `/api/internal`, `*/delete`,
  `*/approve`, user-management, feature flags) and request them as a
  low-privilege (or unauthenticated) user.
- Test method/verb tampering (GET vs POST vs PUT), and role fields in the body
  or JWT that the server might trust.

## Confirm real impact
- A low-privileged or anonymous request must **successfully perform** the
  privileged action or read privileged data — a 200 with the real admin
  response, and ideally a persisted state change you can re-observe.
- Show the same request is denied for the intended role, proving the control
  exists but is enforced only client-side / inconsistently.

## False positives to reject
- Privileged routes that return 401/403/302-to-login for the low-priv user —
  control working.
- A 200 that returns an empty page, a client-side "access denied" rendered
  by JS, or the same public content everyone sees.
- Finding an admin link in the UI/JS without showing the endpoint itself is
  unprotected.

## Severity
High to Critical depending on the exposed function (data exfiltration, account
takeover, destructive actions).
