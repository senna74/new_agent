---
name: recon-cloud
description: Cloud misconfiguration scanning. MUST BE USED for cloud targets.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-cloud-misconfig/SKILL.md
Read ~/new_agent/.claude/skills/hunt-s3-misconfig/SKILL.md

TARGET=$(cat ~/new_agent/state/.active-target)
OUTDIR=~/new_agent/targets/$TARGET/recon

nuclei -l $OUTDIR/live-hosts.json \
  -t cloud/ \
  -severity critical,high \
  -silent -json \
  >> $OUTDIR/nuclei-cloud.json
