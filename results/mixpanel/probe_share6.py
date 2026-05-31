#!/usr/bin/env python3
"""Test more body shapes + GET existing /p/<token> endpoints."""
import sys, os, json, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)
TOK = json.load(open('/home/hunter/new_agent/targets/mixpanel/recon/tokens.json'))

def H(role, extra=None):
    h = dict(TOK[role]['api_request_headers'])
    h["User-Agent"] = "Mozilla/5.0"
    h["Accept"] = "application/json"
    h["X-Requested-With"] = "XMLHttpRequest"
    h["Origin"] = "https://mixpanel.com"
    h["Referer"] = f"https://mixpanel.com/project/4025923/app/boards#board/11207838"
    if extra: h.update(extra)
    return h

BASE = "https://mixpanel.com"
PROJ = 4025923
DASH = 11207838

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share6_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

# 1. POST to /public-dashboards/{DASH} with different body shapes
url = f"{BASE}/api/app/projects/{PROJ}/public-dashboards/{DASH}"

bodies = [
    (None, None),
    ('application/json', "{}"),
    ('application/json', json.dumps({"project_id": PROJ})),
    ('application/json', json.dumps({"project_id": PROJ, "dashboard_id": DASH})),
    ('application/x-www-form-urlencoded', f"project_id={PROJ}"),
    ('application/x-www-form-urlencoded', f"project_id={PROJ}&dashboard_id={DASH}"),
    ('application/x-www-form-urlencoded', f"project_id={PROJ}&board_id={DASH}"),
    ('application/x-www-form-urlencoded', f"dashboard_id={DASH}"),
]
for ct, body in bodies:
    h = H('ADMIN')
    if ct: h["Content-Type"] = ct
    try:
        r = sh.request("POST", url, headers=h, data=body)
        log(f"POST CT={ct} body={body!r} -> {r.status_code} body={r.text[:300]!r}")
        if r.status_code in (200, 201):
            with open('/home/hunter/new_agent/results/mixpanel/public_link_created.json','w') as f:
                f.write(r.text)
            log(">>> CREATED, saved.")
    except Exception as e:
        log(f"POST -> ERR {e}")
    time.sleep(0.6)

# 2. GET the existing recon /p/<token> short-links (these may be a different feature)
short_tokens = [
    "2cv24kB3k5n9reXr9bSJKU",
    "5dbqyToAtFMaDJVJNzUeuG",
    "BkaDwovdEpEcMJp33R6sah",
    "CEngFwLvPa5zvTSLvFTHNH",
    "MKDgQSoYBZciN4AGgY7Mgh",
    "QLBHa24vdYuK2MJLiNUA1S",
]
for t in short_tokens[:3]:
    try:
        r = sh.request("GET", f"{BASE}/p/{t}", headers={"User-Agent":"Mozilla/5.0"})
        log(f"GET /p/{t} (no auth) -> {r.status_code} loc={r.headers.get('Location','-')[:200]} body_first={r.text[:200]!r}")
    except Exception as e:
        log(f"GET /p/{t} -> ERR {e}")
    time.sleep(0.6)

LOG.close()
