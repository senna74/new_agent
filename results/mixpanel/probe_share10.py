#!/usr/bin/env python3
"""Probe /public/dashboard/* and /public/* with the recon-collected short tokens."""
import sys, os, json, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)
TOK = json.load(open('/home/hunter/new_agent/targets/mixpanel/recon/tokens.json'))

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share10_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

BASE = "https://mixpanel.com"

short_tokens = [
    "2cv24kB3k5n9reXr9bSJKU",
    "5dbqyToAtFMaDJVJNzUeuG",
    "BkaDwovdEpEcMJp33R6sah",
    "CEngFwLvPa5zvTSLvFTHNH",
    "MKDgQSoYBZciN4AGgY7Mgh",
    "QLBHa24vdYuK2MJLiNUA1S",
]

# 1. test /public/dashboard/<token> with various permutations
for t in short_tokens[:2]:
    for p in [
        f"/public/dashboard/{t}",
        f"/public/dashboard/{t}/",
        f"/public/{t}",
        f"/public/{t}/",
        f"/p/{t}",
        f"/p/{t}/",
        f"/public/dashboard/{t}.json",
        # API endpoints that the page itself probably calls
        f"/api/public/dashboards/{t}",
        f"/api/public/dashboard/{t}",
        f"/api/app/public-dashboards/{t}",
        f"/api/app/public/{t}",
    ]:
        try:
            r = sh.request("GET", BASE+p, headers={"User-Agent":"Mozilla/5.0"})
            log(f"GET {p} -> {r.status_code} ct={r.headers.get('Content-Type','')[:30]} body={r.text[:120]!r}")
        except Exception as e:
            log(f"GET {p} -> ERR {e}")
        time.sleep(0.4)

# 2. From a working /p/<token> page, see what API XHR it makes — look in the response
# Already have it cached. Re-fetch one fresh and grep for fetch/api hints
import re
with open('/home/hunter/new_agent/results/mixpanel/p_2cv24kB3k5n9reXr9bSJKU.html') as f:
    h = f.read()
# look for inline data
log("=== inline data hints in p_<token>.html ===")
for pat in [r'window\.[A-Z_]+\s*=\s*[^;]{0,500}', r'data-[a-z\-]+="[^"]{1,200}"', r'fetch\(`[^`]{0,200}`\)', r'fetch\("[^"]{0,200}"\)']:
    for m in re.finditer(pat, h)[:5] if hasattr(re.finditer(pat, h), '__getitem__') else list(re.finditer(pat, h))[:5]:
        log(f"  {m.group()[:200]!r}")

LOG.close()
