---
name: attack-idor
description: IDOR, BAC, horizontal and vertical privilege escalation. MUST BE USED when numeric/UUID IDs found or multi-tenant target.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-bac-privesc/SKILL.md
Read ~/new_agent/.claude/skills/hunt-idor/SKILL.md

TARGET=$(cat ~/new_agent/state/.active-target)

# Test every endpoint with all roles
python3 << 'PYEOF'
import sys, json, sqlite3, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp
sh = SafeHttp(allow_raw_for_waf=True)

TARGET = open('/home/hunter/new_agent/state/.active-target').read().strip()
tokens = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/recon/tokens.json'))
QUEUE  = '/home/hunter/new_agent/state/queue.jsonl'
RESULTS = f'/home/hunter/new_agent/results/{TARGET}'

import os; os.makedirs(RESULTS, exist_ok=True)

roles = {
    'ADMIN':  tokens.get('ADMIN',  {}).get('jwt', ''),
    'MEMBER': tokens.get('MEMBER', tokens.get('LOW', {})).get('jwt', ''),
    'IDOR':   tokens.get('IDOR',   {}).get('jwt', ''),
}

# Read endpoints from queue
with open(f'/home/hunter/new_agent/targets/{TARGET}/recon/endpoints.txt') as f:
    endpoints = [l.strip() for l in f if l.strip()]

for url in endpoints:
    responses = {}
    for role, jwt in roles.items():
        if not jwt: continue
        try:
            r = sh.request("GET", url, headers={"Authorization": f"Bearer {jwt}"})
            responses[role] = {"status": r.status_code, "len": len(r.text), "body": r.text[:150]}
        except: pass

    # Compare responses — different data = IDOR candidate
    statuses = [v['status'] for v in responses.values()]
    lengths  = [v['len']    for v in responses.values()]

    if len(set(lengths)) > 1 or (200 in statuses and 403 in statuses):
        finding = {
            "event": "finding_found",
            "type":  "idor_candidate",
            "url":   url,
            "roles": responses,
            "ts":    time.strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        with open(f'{RESULTS}/attack-idor-{int(time.time())}.json', 'w') as out:
            json.dump(finding, out, indent=2)
        with open(QUEUE, 'a') as q:
            q.write(json.dumps({"event":"finding_found","type":"idor","url":url})+'\n')
PYEOF
