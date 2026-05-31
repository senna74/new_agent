---
name: attack-xss
description: XSS stored, reflected, DOM. MUST BE USED when reflection found in responses.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-xss/SKILL.md

TARGET=$(cat ~/new_agent/state/.active-target)
RESULTS=~/new_agent/results/$TARGET
mkdir -p $RESULTS

bash ~/new_agent/.claude/tools/dalfox.sh \
  ~/new_agent/targets/$TARGET/recon/endpoints.txt \
  $RESULTS/xss-$(date +%s).json
