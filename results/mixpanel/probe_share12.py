#!/usr/bin/env python3
"""Enable public boards on the project, then create a public link."""
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

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share12_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

# Project-settings endpoint that toggles public-boards. Guess paths:
candidates = [
    ("PATCH", f"{BASE}/api/app/projects/{PROJ}/public-dashboard-settings", json.dumps({"has_public_dashboards_enabled": True})),
    ("POST",  f"{BASE}/api/app/projects/{PROJ}/public-dashboard-settings", json.dumps({"has_public_dashboards_enabled": True})),
    ("PUT",   f"{BASE}/api/app/projects/{PROJ}/public-dashboard-settings", json.dumps({"has_public_dashboards_enabled": True})),
    ("GET",   f"{BASE}/api/app/projects/{PROJ}/public-dashboard-settings", None),
    ("GET",   f"{BASE}/api/app/projects/{PROJ}/public_dashboard_settings", None),
    ("PATCH", f"{BASE}/api/app/projects/{PROJ}/public_dashboard_settings", json.dumps({"has_public_dashboards_enabled": True})),
    ("GET",   f"{BASE}/api/app/projects/{PROJ}/public-board-settings", None),
    ("GET",   f"{BASE}/api/app/projects/{PROJ}/public-dashboards/settings", None),
    ("PATCH", f"{BASE}/api/app/projects/{PROJ}/public-dashboards", json.dumps({"has_public_dashboards_enabled": True})),
    # Org-level
    ("GET",   f"{BASE}/api/app/organizations/3100781/public-dashboards", None),
    ("PATCH", f"{BASE}/api/app/organizations/3100781/public-dashboards", json.dumps({"enabled":True})),
]
for m, url, body in candidates:
    try:
        kw = {}
        if body is not None: kw['data'] = body
        r = sh.request(m, url, headers=H('ADMIN'), **kw)
        log(f"{m} {url} body={body} -> {r.status_code} body={r.text[:250]!r}")
    except Exception as e:
        log(f"{m} {url} -> ERR {e}")
    time.sleep(0.6)

LOG.close()
