---
name: attack-graphql
description: GraphQL IDOR, introspection abuse, batching attacks. MUST BE USED when GraphQL endpoint found.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-graphql/SKILL.md

TARGET=$(cat ~/new_agent/state/.active-target)

python3 << 'PYEOF'
import sys, json, time, os
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp
sh = SafeHttp(allow_raw_for_waf=True)

TARGET  = open('/home/hunter/new_agent/state/.active-target').read().strip()
tokens  = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/recon/tokens.json'))
QUEUE   = '/home/hunter/new_agent/state/queue.jsonl'
RESULTS = f'/home/hunter/new_agent/results/{TARGET}'
os.makedirs(RESULTS, exist_ok=True)

scope   = open(f'/home/hunter/new_agent/targets/{TARGET}/scope.md').read()
jwt     = tokens.get('ADMIN', {}).get('jwt', '')
headers = {"Authorization": f"Bearer {jwt}", "Content-Type": "application/json"}

INTROSPECTION = {"query":"{__schema{types{name fields{name}}}}"}

with open(f'/home/hunter/new_agent/targets/{TARGET}/recon/endpoints.txt') as f:
    for url in f:
        url = url.strip()
        if 'graphql' not in url.lower(): continue
        try:
            r = sh.request("POST", url, json_body=INTROSPECTION, headers=headers)
            if '__schema' in r.text or 'types' in r.text:
                finding = {"event":"finding_found","type":"graphql_introspection",
                          "url":url,"response":r.text[:150]}
                with open(f'{RESULTS}/attack-graphql-{int(time.time())}.json','w') as out:
                    json.dump(finding, out, indent=2)
                with open(QUEUE,'a') as q:
                    q.write(json.dumps({"event":"finding_found","type":"graphql_introspection","url":url})+'\n')
        except: pass
PYEOF
