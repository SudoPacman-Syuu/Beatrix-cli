# Path Traversal / Local File Inclusion

A file path derived from user input isn't confined to the intended directory,
letting an attacker read (or include) files outside it.

## Detect
- Params that name a file/template/path: `file=`, `path=`, `template=`,
  `download=`, `lang=`, `page=`, `include=`.
- Probe with `../` sequences and encodings: `../../etc/passwd`,
  `..%2f..%2fetc%2fpasswd`, `....//`, absolute paths, null-byte / extension
  tricks on legacy stacks.

## Confirm real impact
- Retrieve the **contents of a file outside the web root** that you couldn't
  otherwise access: `/etc/passwd` (root:x:0:0 lines), app source/config with
  secrets, `/proc/self/environ`. Return the distinctive content as evidence.
- LFI escalation: include a log/session/wrapper you can poison for code
  execution — confirm with an OOB callback or executed marker.

## False positives to reject
- Payload reflected in an error but no file content returned.
- Traversal that stays within an allowed directory or is normalized/blocked
  (you get a 400/404 or the sanitized filename).
- Reading a file you were already authorized to read (no boundary crossed).
- A generic "file not found" for `../` input — filtering is working.

## Severity
High to Critical: source/secret disclosure or a path to code execution;
scoped by what you can actually read.
