---
name: attack-privesc
description: Privilege escalation, role confusion, mass assignment. MUST BE USED when admin endpoints or role params found.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-bac-privesc/SKILL.md
Read ~/new_agent/.claude/skills/hunt-ato/SKILL.md

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

admin_jwt  = tokens.get('ADMIN',  {}).get('jwt', '')
member_jwt = tokens.get('MEMBER', tokens.get('LOW', {})).get('jwt', '')

ADMIN_PATTERNS = ['/admin','/manage','/internal','/superuser','/staff','/system','/config']

with open(f'/home/hunter/new_agent/targets/{TARGET}/recon/endpoints.txt') as f:
    for url in f:
        url = url.strip()
        if not any(p in url.lower() for p in ADMIN_PATTERNS): continue
        try:
            r_member = sh.request("GET", url, headers={"Authorization": f"Bearer {member_jwt}"})
            r_admin  = sh.request("GET", url, headers={"Authorization": f"Bearer {admin_jwt}"})
            if r_member.status_code == 200 and r_admin.status_code == 200:
                if abs(len(r_member.text) - len(r_admin.text)) < 100:
                    finding = {"event":"finding_found","type":"privesc",
                              "url":url,"member_status":r_member.status_code,
                              "admin_status":r_admin.status_code}
                    with open(f'{RESULTS}/attack-privesc-{int(time.time())}.json','w') as out:
                        json.dump(finding, out, indent=2)
                    with open(QUEUE,'a') as q:
                        q.write(json.dumps({"event":"finding_found","type":"privesc","url":url})+'\n')
        except: pass
PYEOF
