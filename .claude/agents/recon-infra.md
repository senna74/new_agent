---
name: recon-infra
description: Port scanning and infrastructure nuclei scan. MUST BE USED for infra discovery.
---
Read ~/new_agent/.claude/AGENT-SHARED.md

TARGET=$(cat ~/new_agent/state/.active-target)
OUTDIR=~/new_agent/targets/$TARGET/recon

bash ~/new_agent/.claude/tools/portscan.sh $OUTDIR/subdomains.txt $OUTDIR/ports/

nuclei -l $OUTDIR/live-hosts.json \
  -t exposures/ -t misconfigurations/ \
  -severity critical,high,medium \
  -silent -json \
  >> $OUTDIR/nuclei-expose.json
