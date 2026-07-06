# Driving sqlmap on a confirmed lead

sqlmap is an escalation tool, not a discovery scanner. Point it at a *specific*
injectable input you already have a signal for (an error, a boolean/time
difference), let it confirm the DBMS and technique, then extract only the
minimum needed to prove impact.

## When to reach for it
- A parameter shows a SQL-ish signal: DB error strings, a boolean difference
  between `id=1` and `id=1 AND 1=2`, or a reliable time delay on `SLEEP()`.
- You need to move from "looks injectable" to "confirmed, with the DBMS and a
  concrete technique" and a safe demonstration of data access.

## Running it focused
- Give it the exact request. Capture the real authenticated request (headers,
  cookies, body) to a file and use `-r request.txt`; specify the parameter with
  `-p`. This avoids sqlmap re-crawling and keeps it on the input you vetted.
- Start low and slow: `--level`/`--risk` only as high as needed; a low level
  that confirms is better than a high level that hammers the target.
- Prove impact minimally: `--banner`, `--current-user`, `--current-db`, or a
  single `--dump` of one non-sensitive table is enough to demonstrate the bug.
  Do not exfiltrate real user data on a live target — that is impact you can
  describe, not data you need to take.

## Confirmation bar
A finding is real when sqlmap confirms an injection technique against a specific
parameter and you can reproduce a data-bearing response (banner, version, a
controlled row). A single anomaly sqlmap could not turn into a confirmed
technique stays a lead, not a finding.

## Common false positives
- Time-based "hits" on an endpoint whose latency is just noisy — require a
  consistent, payload-correlated delay across repeats.
- WAF/proxy error pages mistaken for DB errors.
- A reflected input echoed in an error template with no actual query impact.
