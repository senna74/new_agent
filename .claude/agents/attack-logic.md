---
name: attack-logic
description: Business logic flaws, race conditions, workflow bypass. MUST BE USED on payment and multi-step flows.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-business-logic/SKILL.md
Read ~/new_agent/.claude/skills/hunt-race-condition/SKILL.md

TARGET=$(cat ~/new_agent/state/.active-target)
# Logic testing requires manual analysis of workflow endpoints.
# Read endpoints.txt, identify multi-step flows, test state transitions.
# Write findings to results/$TARGET/attack-logic-<ts>.json
