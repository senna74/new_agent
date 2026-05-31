#!/usr/bin/env python3
"""Probe share/public board endpoints on Mixpanel."""
import sys, os, json, time, base64, binascii
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)
TOK = json.load(open('/home/hunter/new_agent/targets/mixpanel/recon/tokens.json'))
ADMIN_H = dict(TOK['ADMIN']['api_request_headers'])
ADMIN_H["User-Agent"] = "Mozilla/5.0"
ADMIN_H["Accept"] = "application/json"

# Add CSRF header redundancy and project select header that mixpanel often expects
def H(role, extra=None):
    h = dict(TOK[role]['api_request_headers'])
    h["User-Agent"] = "Mozilla/5.0"
    h["Accept"] = "application/json"
    h["Content-Type"] = "application/json"
    h["X-Requested-With"] = "XMLHttpRequest"
    if extra: h.update(extra)
    return h

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

BASE = "https://mixpanel.com"

# 1. List existing boards/dashboards in project 4025923
PROJ = 4025923

paths = [
    f"/api/app/projects/{PROJ}/dashboards/",
    f"/api/app/projects/{PROJ}/boards/",
    f"/api/app/projects/{PROJ}/dashboards",
    f"/api/app/projects/{PROJ}/boards",
]

for p in paths:
    try:
        r = sh.request("GET", BASE+p, headers=H('ADMIN'))
        log(f"GET {p} -> {r.status_code} len={len(r.text)} ct={r.headers.get('Content-Type','')[:30]} body_first={r.text[:200]!r}")
        if r.status_code == 200 and 'json' in r.headers.get('Content-Type', '').lower():
            with open(f'/home/hunter/new_agent/results/mixpanel/list_{p.replace("/","_")}.json','w') as f:
                f.write(r.text)
    except Exception as e:
        log(f"GET {p} -> ERR {e}")

# Also probe known existing 11207838 board (per task) to see fields
for p in [
    f"/api/app/projects/{PROJ}/dashboards/11207838",
    f"/api/app/projects/{PROJ}/dashboards/11207838/",
    f"/api/app/projects/{PROJ}/boards/11207838",
    f"/api/app/projects/{PROJ}/boards/11207838/",
]:
    try:
        r = sh.request("GET", BASE+p, headers=H('ADMIN'))
        log(f"GET {p} -> {r.status_code} len={len(r.text)} body_first={r.text[:300]!r}")
        if r.status_code == 200:
            with open(f'/home/hunter/new_agent/results/mixpanel/board_{p.replace("/","_")}.json','w') as f:
                f.write(r.text)
    except Exception as e:
        log(f"GET {p} -> ERR {e}")

LOG.close()
