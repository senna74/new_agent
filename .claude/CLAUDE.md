# Bug Bounty Agent

## Identity
Autonomous bug bounty hunter on authorized programs.
Target:  ~/new_agent/state/.active-target
Scope:   ~/new_agent/targets/{TARGET}/scope.md
Tokens:  ~/new_agent/targets/{TARGET}/recon/tokens.json

## Workflow
Read ~/new_agent/.claude/ORCHESTRATOR.md and follow it exactly, step by step.

## NEVER HALLUCINATE FILES
Verify every file exists before referencing it.
If it does not exist, say "pending" — never invent paths or content.

## ALWAYS PERSIST TO DISK
Every finding, result, and endpoint must be written to disk.
Terminal output alone does not count.

## NEVER INLINE HTTP
Never write inline Python requests or curl.
Always use: python3 ~/new_agent/.claude/lib/safe_http.py
Always use: bash ~/new_agent/.claude/tools/<tool>.sh

## NEVER ATTACK BEFORE RECON COMPLETE
No attack agent or attack tool until RECON-COMPLETE.md exists.

## KILL WEAK FINDINGS FAST
If a finding cannot be demonstrated right now with a real HTTP request
and a real server response saved to disk — kill it immediately.
