---
name: attack-sqli
description: SQL injection, NoSQL injection. MUST BE USED when params found on any endpoint.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-sqli/SKILL.md

TARGET=$(cat ~/new_agent/state/.active-target)
RESULTS=~/new_agent/results/$TARGET
mkdir -p $RESULTS

bash ~/new_agent/.claude/tools/sqli.sh \
  ~/new_agent/targets/$TARGET/recon/endpoints.txt \
  $RESULTS/sqli-$(date +%s).json
