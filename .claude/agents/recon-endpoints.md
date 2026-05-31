---
name: recon-endpoints
description: Endpoint crawling, parameter discovery, directory fuzzing. MUST BE USED for endpoint discovery.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-recon/SKILL.md

TARGET=$(cat ~/new_agent/state/.active-target)
OUTDIR=~/new_agent/targets/$TARGET/recon

# Read live hosts and crawl each
python3 << 'PYEOF'
import json, subprocess, os
TARGET = open('/home/hunter/new_agent/state/.active-target').read().strip()
OUTDIR = f'/home/hunter/new_agent/targets/{TARGET}/recon'
QUEUE  = '/home/hunter/new_agent/state/queue.jsonl'

with open(f'{OUTDIR}/live-hosts.json') as f:
    for line in f:
        try:
            h = json.loads(line)
            url = h.get('url', '')
            if not url: continue

            # Katana crawl
            subprocess.run(['bash', '/home/hunter/new_agent/.claude/tools/katana.sh',
                          url, f'{OUTDIR}/endpoints.txt'])

            # Params discovery
            subprocess.run(['bash', '/home/hunter/new_agent/.claude/tools/params.sh',
                          url, f'{OUTDIR}/params.txt'])

            # Fuzz dirs
            subprocess.run(['bash', '/home/hunter/new_agent/.claude/tools/fuzz.sh',
                          url, f'{OUTDIR}/fuzz-dirs.txt'])

            # Emit events
            with open(QUEUE, 'a') as q:
                q.write(json.dumps({"event":"endpoint_found","url":url})+'\n')
        except: pass
PYEOF
