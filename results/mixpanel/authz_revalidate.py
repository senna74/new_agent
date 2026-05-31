#!/usr/bin/env python3
"""Re-validate: find the actual org-management paths, and confirm 4025923 access is granted membership."""
import sys, json, time, re
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)
tokens = json.load(open('/home/hunter/new_agent/targets/mixpanel/recon/tokens.json'))
ADMIN = tokens['ADMIN']; MEMBER = tokens['MEMBER']

def hh(role):
    h = dict(role['api_request_headers'])
    h['Accept'] = 'application/json'
    return h

def g(role, path, extra=None):
    h = hh(role)
    if extra: h.update(extra)
    try:
        r = sh.request("GET", "https://mixpanel.com" + path, headers=h, timeout=20, allow_redirects=False)
    except Exception as e:
        return ('ERR', str(e)[:80], '', '')
    return (r.status_code, r.headers.get('content-type','')[:30], (r.text or '')[:160].replace('\n',' '), r.headers.get('location',''))

# Check MEMBER's actual project list and project_membership for 4025923
print("=== /api/app/projects (MEMBER) ===")
print(g(MEMBER, "/api/app/projects"))
print()
print("=== /api/app/projects (ADMIN) ===")
print(g(ADMIN, "/api/app/projects"))
print()
# Try alternate org paths
for p in [
    "/api/app/organizations",
    "/api/app/organizations/3100781/projects",
    "/api/app/organizations/3100781/settings",
    "/api/app/organizations/3100781/users",
    "/api/app/organizations/3100781/invites",
    "/api/2.0/organizations/3100781",
    "/api/2.0/organizations/3100781/members",
    "/api/app/orgs/3100781",
    "/api/app/orgs/3100781/members",
    "/api/app/organization/3100781",
    "/api/app/organization",
]:
    a = g(ADMIN, p)
    m = g(MEMBER, p)
    print(f"{p}\n  ADMIN  {a}\n  MEMBER {m}")

# Re-test 4025923/cohorts three times to confirm stability
print("\n=== Stability of 4025923 reads (MEMBER, 3x) ===")
for path in ["/api/app/projects/4025923/cohorts", "/api/app/projects/4025923/bookmarks", "/api/app/projects/4025923/webhooks"]:
    for i in range(3):
        r = g(MEMBER, path)
        print(f"  [{i}] {path} → {r[0]} {r[1]}")
        time.sleep(0.4)

# Probe /api/app/me to see project_id permissions for MEMBER
print("\n=== MEMBER /api/app/me — extract project memberships ===")
h = hh(MEMBER)
r = sh.request("GET", "https://mixpanel.com/api/app/me", headers=h, timeout=20, allow_redirects=False)
data = r.json()
me = data.get('results', {})
print("orgs:", list(me.get('organizations', {}).keys()))
for oid, org in me.get('organizations', {}).items():
    print(f"  org {oid}: role={org.get('role')} permissions={len(org.get('permissions', []))}")
print("projects field keys:", [k for k in me.keys() if 'project' in k.lower()])
projects = me.get('projects', {})
if isinstance(projects, dict):
    for pid, proj in projects.items():
        print(f"  proj {pid}: role={proj.get('role')} permissions={proj.get('permissions',[])[:5]}")
elif isinstance(projects, list):
    print(f"  {len(projects)} projects listed")
    for proj in projects[:5]:
        print(f"   - {proj.get('id')} role={proj.get('role')}")
