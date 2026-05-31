#!/usr/bin/env python3
"""Check has_public_dashboards_enabled on project + grep share-create route in main bundle."""
import sys, os, json, time, re
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

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share9_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

BASE = "https://mixpanel.com"
PROJ = 4025923
DASH = 11207838

# 1. Get full project settings to see has_public_dashboards_enabled
for p in [
    f"/api/app/projects/{PROJ}",
    f"/api/app/projects/{PROJ}/",
    f"/api/app/projects/{PROJ}/settings",
    f"/api/app/projects/{PROJ}/settings/",
    f"/api/app/projects/{PROJ}/info",
    f"/api/app/me",
    f"/api/app/projects/{PROJ}/public-dashboards-settings",
]:
    try:
        r = sh.request("GET", BASE+p, headers=H('ADMIN'))
        body = r.text
        if 'public' in body.lower() or 'share' in body.lower():
            idx = body.lower().find('public_dashboard')
            log(f"GET {p} -> {r.status_code} len={len(body)} public_dashboard@={idx} snippet={body[max(0,idx-50):idx+200]!r}")
        else:
            log(f"GET {p} -> {r.status_code} len={len(body)} (no 'public/share')")
    except Exception as e:
        log(f"GET {p} -> ERR {e}")
    time.sleep(0.5)

# 2. Try to enable the feature via PATCH to project settings, or via the org settings
for body in [json.dumps({"has_public_dashboards_enabled": True})]:
    for url in [
        f"{BASE}/api/app/projects/{PROJ}",
        f"{BASE}/api/app/projects/{PROJ}/settings",
        f"{BASE}/api/app/organizations/3100781/settings",
    ]:
        for m in ("PATCH","PUT","POST"):
            try:
                r = sh.request(m, url, headers=H('ADMIN'), data=body)
                log(f"{m} {url} body={body} -> {r.status_code} body={r.text[:200]!r}")
            except Exception as e:
                log(f"{m} {url} -> ERR {e}")
            time.sleep(0.5)

LOG.close()
