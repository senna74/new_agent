#!/usr/bin/env python3
"""oEmbed endpoint check + final cross-tenant safety check."""
import sys, json, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)
TOK = json.load(open('/home/hunter/new_agent/targets/mixpanel/recon/tokens.json'))

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share15_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

BASE = "https://mixpanel.com"
t = "2cv24kB3k5n9reXr9bSJKU"
# Try oEmbed endpoints
from urllib.parse import quote
for u in [f"https://mixpanel.com/p/{t}", f"https://mixpanel.com/public/{t}"]:
    for path in ["/oembed", "/api/oembed", "/api/app/oembed", "/api/app/embeds", "/oembed.json"]:
        url = f"{BASE}{path}?url={quote(u)}&format=json"
        try:
            r = sh.request("GET", url, headers={"User-Agent":"Mozilla/5.0", "Accept":"application/json"})
            log(f"GET {url} -> {r.status_code} ct={r.headers.get('Content-Type','')[:30]} body={r.text[:200]!r}")
        except Exception as e:
            log(f"GET {url} -> ERR {e}")
        time.sleep(0.5)

# Header-fetch: iframely / meta tags
import re
with open('/home/hunter/new_agent/results/mixpanel/p_2cv24kB3k5n9reXr9bSJKU.html') as f:
    h = f.read()
meta = re.findall(r'<meta\s+[^>]+>', h)
for m in meta:
    log(f"META: {m}")

LOG.close()
