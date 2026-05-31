# INIT — loads on every session before anything else

## CROSS-CUTTING RULES
Read ~/new_agent/.claude/rules/07-http.md
Read ~/new_agent/.claude/rules/08-output.md
Read ~/new_agent/.claude/rules/09-context.md
Read ~/new_agent/.claude/rules/10-language.md
Read ~/new_agent/.claude/rules/11-rate-limit.md

## AGENT BOOTSTRAP
Every subagent MUST start with:
Read ~/new_agent/.claude/AGENT-SHARED.md

## ZERO INTERACTION MODE
If targets/<TARGET>/scope.md + recon/tokens.json + state/.active-target all exist:
- Never ask the user anything
- Auto-detect everything from scope.md
- Only --interactive flag re-enables prompts

## NEVER DO
- Print full API responses — truncate to 150 chars
- Load skills with Skill("name") — use Read tool only
- Make HTTP calls without safe_http.py
- Submit findings with confidence < 0.85
- Stop mid-engagement for any reason
- Repeat known false positives from memory/false-positives.md
