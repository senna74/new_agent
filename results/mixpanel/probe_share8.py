#!/usr/bin/env python3
"""Fetch project-details bundle + find public-board API endpoints inside."""
import sys, os, json, time, re
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share8_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

bundles = [
    "//cdn.mxpnl.com/static/asset-cache/assets/index-DINw891O.js",
    "//cdn.mxpnl.com/static/asset-cache/assets/project-details-CaKYOg-Z.js",
]
combined = ""
for b in bundles:
    url = "https:" + b if b.startswith("//") else b
    try:
        r = sh.request("GET", url, headers={"User-Agent":"Mozilla/5.0"})
        log(f"GET {url} -> {r.status_code} len={len(r.text)}")
        combined += "\n" + r.text
    except Exception as e:
        log(f"GET {url} -> ERR {e}")
    time.sleep(0.5)

# find any /api or /p/ or /public/ routes mentioned in bundles
routes = sorted(set(re.findall(r'["`/]/?(?:api|public|p)/[a-zA-Z0-9/_\-\.\:]{3,90}["`)]', combined)))
log(f"=== Routes found ({len(routes)}) ===")
for r in routes[:80]:
    log(f"  {r}")

# Also find any reference to 'public', 'share' near function-call sites
log("=== 'public_dashboard' / 'public-dashboard' string sightings ===")
for m in re.finditer(r'(public[-_]dashboard|public_link|share_link|share_token|public_board|public-board)', combined):
    idx = m.start()
    log(f"  @{idx}: ...{combined[max(0,idx-80):idx+120]!r}...")
    if len(re.findall(r'public[-_]dashboard', combined)) > 30:
        break

LOG.close()
