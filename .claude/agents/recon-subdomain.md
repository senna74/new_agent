---
name: recon-subdomain
description: Subdomain enumeration and HTTP probing. MUST BE USED for subdomain discovery.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-subdomain/SKILL.md

TARGET=$(cat ~/new_agent/state/.active-target)
OUTDIR=~/new_agent/targets/$TARGET/recon
mkdir -p $OUTDIR

# Enumerate subdomains
bash ~/new_agent/.claude/tools/subdomain.sh $TARGET $OUTDIR/subdomains.txt

# Probe live hosts
bash ~/new_agent/.claude/tools/httpx.sh $OUTDIR/subdomains.txt $OUTDIR/live-hosts.json

# Emit events for every live host
python3 << 'PYEOF'
import json, sys
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
TARGET = open('/home/hunter/new_agent/state/.active-target').read().strip()
with open(f'/home/hunter/new_agent/targets/{TARGET}/recon/live-hosts.json') as f:
    for line in f:
        try:
            h = json.loads(line)
            entry = {"event":"live_host_found","url":h.get("url",""),"status":h.get("status_code",0)}
            with open('/home/hunter/new_agent/state/queue.jsonl','a') as q:
                q.write(json.dumps(entry)+'\n')
        except: pass
PYEOF
