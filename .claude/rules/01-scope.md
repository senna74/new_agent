# SCOPE ENFORCEMENT

## SOURCE OF TRUTH
scope.md is the only authority. Read at STEP 0, never deviate.

## IN-SCOPE
- Only test hosts in scope.md in_scope section
- Wildcard *.example.com includes all subdomains
- When in doubt — do not test

## OUT-OF-SCOPE
- Never touch hosts in out_of_scope section
- Never brute force credentials
- Never cause DoS
- Never access or exfiltrate real user data
- Never test outside agreed hours if specified

## FORBIDDEN (absolute, never override)
- Social engineering
- Physical attacks
- Accessing third-party systems
- Modifying or deleting production data

## ENFORCEMENT
hooks/scope_gate.py runs before every bash call.
Out-of-scope host → blocked automatically.
Circuit breaker tripped → blocked for 60s cooldown.
