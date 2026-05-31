#!/usr/bin/env python3
"""Find the correct method and body shape via OPTIONS + a few variants."""
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
    h["Referer"] = f"https://mixpanel.com/project/4025923/app/boards#4525935/board/11207838"
    if extra: h.update(extra)
    return h

BASE = "https://mixpanel.com"
PROJ = 4025923
DASH = 11207838

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share5_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

# 1. OPTIONS on the collection — see allowed methods
for url in [
    f"{BASE}/api/app/projects/{PROJ}/public-dashboards",
    f"{BASE}/api/app/projects/{PROJ}/public-dashboards/{DASH}",
]:
    try:
        r = sh.request("OPTIONS", url, headers=H('ADMIN'))
        log(f"OPTIONS {url} -> {r.status_code} allow={r.headers.get('Allow')} access-ctrl-allow-methods={r.headers.get('Access-Control-Allow-Methods')} body={r.text[:150]!r}")
    except Exception as e:
        log(f"OPTIONS {url} -> ERR {e}")
    time.sleep(0.5)

# 2. Try PUT on collection without trailing slash
for m, url, body in [
    ("PUT", f"{BASE}/api/app/projects/{PROJ}/public-dashboards", json.dumps({"dashboard_id": DASH})),
    ("PUT", f"{BASE}/api/app/projects/{PROJ}/public-dashboards/", json.dumps({"dashboard_id": DASH})),
    # form-encoded body instead of json
]:
    try:
        r = sh.request(m, url, headers=H('ADMIN'), data=body)
        log(f"{m} {url} body={body} -> {r.status_code} allow={r.headers.get('Allow','-')} body={r.text[:200]!r}")
    except Exception as e:
        log(f"{m} {url} -> ERR {e}")
    time.sleep(0.5)

# 3. form-encoded POST
for url in [
    f"{BASE}/api/app/projects/{PROJ}/public-dashboards",
    f"{BASE}/api/app/projects/{PROJ}/public-dashboards/",
    f"{BASE}/api/app/projects/{PROJ}/public-dashboards/{DASH}",
]:
    headers = H('ADMIN', {"Content-Type":"application/x-www-form-urlencoded"})
    try:
        r = sh.request("POST", url, headers=headers, data=f"dashboard_id={DASH}")
        log(f"POST(form) {url} -> {r.status_code} allow={r.headers.get('Allow','-')} body={r.text[:200]!r}")
    except Exception as e:
        log(f"POST(form) {url} -> ERR {e}")
    time.sleep(0.5)

LOG.close()
