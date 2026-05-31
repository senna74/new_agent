---
name: script-generator
description: "Use this skill when the executor needs a custom one-off script (Python/Bash/Go) for a specific recon or exploit task and no prebuilt tool fits. Triggers: \"write me a script to do X\", missing tool in the recon pipeline, novel parsing requirement. Generates optimized, syntax-validated scripts on demand. Never executes — only generates, optimizes, validates. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

# Script Generator

Generates optimized, syntax-validated scripts on demand. **Never executes scripts.**

## When to Use

- Scripts exceed ~30 lines
- Parallel operations on multiple targets
- Multi-library patterns (impacket + ldap3, pypsrp + concurrent.futures)
- Repeated auth handshakes or connection setup

## Request Format

```
LANGUAGE: python3 | powershell | bash
TASK: What the script should accomplish
TARGETS: IPs, hostnames, URLs
CREDENTIALS: user, pass, hash, domain, certs
AVAILABLE_LIBRARIES: What's installed
OUTPUT_FORMAT: stdout format, file writes
CONSTRAINTS: timeout, no destructive ops, output directory
CONTEXT: (optional) Prior output, errors, what failed
```

## Optimization

- Multiple targets → `concurrent.futures.ThreadPoolExecutor`
- >3 HTTP requests to same host → `requests.Session`
- Repeated auth → single auth, reuse session/token
- Prefer high-level libraries (impacket, ldap3, requests)

## Output

Write to `OUTPUT_DIR/artifacts/<task_name>.<ext>`. Return:

```
SCRIPT_PATH: OUTPUT_DIR/artifacts/task_name.py
LANGUAGE: python3
VALIDATION: PASSED
EXECUTION: python3 OUTPUT_DIR/artifacts/task_name.py
DEPENDENCIES: impacket, concurrent.futures (stdlib)
```

## Rules

- Never execute scripts — only generate, optimize, validate
- Per-operation error handling — no bare `except:`
- Timeout enforcement on all I/O
- Validate syntax before returning
- No secrets hardcoded — credentials as variables at top

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle
