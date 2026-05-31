#!/usr/bin/env python3
"""Fetch authenticated SPA app shell and find share-create endpoint."""
import sys, os, json, time, re
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)
TOK = json.load(open('/home/hunter/new_agent/targets/mixpanel/recon/tokens.json'))

def H(role, extra=None):
    h = dict(TOK[role]['api_request_headers'])
    h["User-Agent"] = "Mozilla/5.0"
    if extra: h.update(extra)
    return h

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share11_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

BASE = "https://mixpanel.com"
# Get the actual dashboards page in the SPA (authenticated)
for url in [
    f"{BASE}/project/4025923/app/boards",
    f"{BASE}/project/4025923/app/boards#board/11207838",
    f"{BASE}/report/4025923/dashboards",
]:
    try:
        r = sh.request("GET", url, headers=H('ADMIN'))
        log(f"GET {url} -> {r.status_code} ct={r.headers.get('Content-Type','')[:30]} len={len(r.text)} body_first={r.text[:200]!r}")
        # Extract bundle URLs
        bundles = sorted(set(re.findall(r'(?:src|href)="(/?(?:static|assets)/[^"]+\.js)"', r.text)))
        log(f"  bundles_found_local: {bundles[:10]}")
        cdn_bundles = sorted(set(re.findall(r'(?:src|href)="((?:https?:)?//[^"]*\.js)"', r.text)))
        log(f"  bundles_cdn[{len(cdn_bundles)}]: {cdn_bundles[:10]}")
        # Save full HTML
        fname = re.sub(r'[^a-z0-9]','_', url.lower().replace("https://mixpanel.com",""))[:80] + '.html'
        with open(f'/home/hunter/new_agent/results/mixpanel/spa_{fname}','w') as f:
            f.write(r.text)
    except Exception as e:
        log(f"GET {url} -> ERR {e}")
    time.sleep(0.6)

LOG.close()
