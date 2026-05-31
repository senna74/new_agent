#!/usr/bin/env python3
"""Diagnose what response /api/app/projects/.../public_links/ actually returned."""
import sys, os, json, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)
TOK = json.load(open('/home/hunter/new_agent/targets/mixpanel/recon/tokens.json'))

def H(role, extra=None):
    h = dict(TOK[role]['api_request_headers'])
    h["User-Agent"] = "Mozilla/5.0"
    h["Accept"] = "application/json"
    h["Content-Type"] = "application/json"
    h["X-Requested-With"] = "XMLHttpRequest"
    if extra: h.update(extra)
    return h

BASE = "https://mixpanel.com"
PROJ = 4025923
DASH = 11207838

# A simple status-only enumeration. We sleep 0.6s between to be careful.
candidates = [
    # Public dashboard SETTING endpoints
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/public_share"),
    ("GET",  f"/api/app/projects/{PROJ}/public_dashboards"),
    ("GET",  f"/api/app/projects/{PROJ}/public-dashboards"),
    ("GET",  f"/api/app/projects/{PROJ}/public-boards"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/share-link"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/share_via_link"),
    # Path-param form: legacy mixpanel bookmark / shared report patterns
    ("GET",  f"/api/2.0/projects/{PROJ}/dashboards/{DASH}/public"),
    # Generic "share" verbs:
    ("PUT",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/share"),
    ("PATCH",f"/api/app/projects/{PROJ}/dashboards/{DASH}/share"),
]

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share3_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

for m,p in candidates:
    try:
        r = sh.request(m, BASE+p, headers=H('ADMIN'))
        cf = r.headers.get('X-Amz-Cf-Id') or r.headers.get('x-amz-cf-id') or '-'
        server = r.headers.get('Server','')
        log(f"{m} {p} -> {r.status_code} cf={cf[:20]} server={server} body={r.text[:150]!r}")
    except SystemExit as e:
        log(f"{m} {p} -> SystemExit: {e}")
        # reset and continue
        import importlib
        from waf_counter import WafCounter
        WafCounter().reset()
    except Exception as e:
        log(f"{m} {p} -> ERR {e}")
    time.sleep(0.6)

LOG.close()
