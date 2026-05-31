---
name: attack-auth
description: JWT attacks, OAuth flaws, MFA bypass, SAML, session fixation. MUST BE USED when JWT/OAuth/SAML found.
---
Read ~/new_agent/.claude/AGENT-SHARED.md
Read ~/new_agent/.claude/skills/hunt-jwt/SKILL.md
Read ~/new_agent/.claude/skills/hunt-oauth/SKILL.md

TARGET=$(cat ~/new_agent/state/.active-target)

# JWT analysis on all tokens
python3 << 'PYEOF'
import sys, json, subprocess, time, os
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')

TARGET  = open('/home/hunter/new_agent/state/.active-target').read().strip()
tokens  = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/recon/tokens.json'))
QUEUE   = '/home/hunter/new_agent/state/queue.jsonl'
RESULTS = f'/home/hunter/new_agent/results/{TARGET}'
os.makedirs(RESULTS, exist_ok=True)

for role, data in tokens.items():
    jwt = data.get('jwt', '')
    if not jwt: continue
    target_url = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/scope.md'.replace('scope.md','scope.md')))
    result = subprocess.run(
        ['bash', '/home/hunter/new_agent/.claude/tools/jwt.sh', jwt, TARGET],
        capture_output=True, text=True
    )
    if result.stdout:
        out_file = f'{RESULTS}/attack-auth-jwt-{role}-{int(time.time())}.json'
        with open(out_file, 'w') as f:
            f.write(result.stdout)
        with open(QUEUE, 'a') as q:
            q.write(json.dumps({"event":"finding_found","type":"jwt_analysis","role":role})+'\n')
PYEOF
