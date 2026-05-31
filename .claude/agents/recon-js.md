---
name: recon-js
description: Authenticated JS extraction and endpoint mining. Uses real tools only.
---
Read ~/new_agent/.claude/AGENT-SHARED.md

TARGET=$(cat ~/new_agent/state/.active-target)
OUTDIR=~/new_agent/targets/$TARGET/recon
TOKENS=~/new_agent/targets/$TARGET/recon/tokens.json

COOKIES=$(python3 -c "import json; t=json.load(open('$TOKENS')); print(t['ADMIN']['full_cookies'])")

# Step 1: JS extraction
bash ~/new_agent/.claude/tools/js-extract.sh "$TARGET" "$COOKIES" "$OUTDIR"

# Step 2: Browser recon on authenticated SPA
PROJECT_URL=$(python3 -c "
import json, os
f='$OUTDIR/identity/SUMMARY.json'
if os.path.exists(f):
    d=json.load(open(f))
    pids=d.get('ADMIN',{}).get('projects',[])
    if pids: print(f'https://mixpanel.com/project/{pids[0]}/app/boards')
" 2>/dev/null)

[ -n "$PROJECT_URL" ] && bash ~/new_agent/.claude/tools/browser-recon.sh "$COOKIES" "$PROJECT_URL" "$OUTDIR"

# Step 3: Emit endpoint events
python3 << 'PYEOF'
import json, time, os
TARGET = open('/home/hunter/new_agent/state/.active-target').read().strip()
OUTDIR = f'/home/hunter/new_agent/targets/{TARGET}/recon'
QUEUE  = '/home/hunter/new_agent/state/queue.jsonl'
all_paths = set()
for f in [f'{OUTDIR}/endpoints/all-paths.txt', f'{OUTDIR}/endpoints/browser-api-calls.txt']:
    if os.path.exists(f):
        for line in open(f):
            line = line.strip()
            if line.startswith('/'):
                all_paths.add(line)
with open(QUEUE, 'a') as q:
    for p in sorted(all_paths):
        q.write(json.dumps({"event":"endpoint_found","url":f"https://{TARGET}{p}","source":"js_mining","ts":time.strftime("%Y-%m-%dT%H:%M:%SZ")})+'\n')
print(f"Emitted {len(all_paths)} endpoint events")
PYEOF
