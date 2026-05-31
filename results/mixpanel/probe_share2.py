#!/usr/bin/env python3
"""Find share-public-link endpoint."""
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
    if extra: h.update(extra)
    return h

LOG = open('/home/hunter/new_agent/results/mixpanel/probe_share2_log.txt', 'w')
def log(msg):
    print(msg); LOG.write(msg+"\n"); LOG.flush()

BASE = "https://mixpanel.com"
PROJ = 4025923
DASH = 11207838

# Candidate share endpoints (varied phrasing)
candidates = [
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/share"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/share/"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/public_links"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/public_links/"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/public_link"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/share_public"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/links"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/share_settings"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/permissions"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/embed"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/embeds"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/shared_link"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/share_token"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/share_link"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/public"),
    ("GET",  f"/api/app/projects/{PROJ}/public_links"),
    ("GET",  f"/api/app/projects/{PROJ}/public_links/"),
    ("GET",  f"/api/app/projects/{PROJ}/public_boards"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/public_dashboards"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/public_share"),
    ("GET",  f"/api/app/projects/{PROJ}/dashboards/{DASH}/oembed"),
]
for m, p in candidates:
    try:
        r = sh.request(m, BASE+p, headers=H('ADMIN'))
        log(f"{m} {p} -> {r.status_code} len={len(r.text)} body={r.text[:200]!r}")
    except Exception as e:
        log(f"{m} {p} -> ERR {e}")

LOG.close()
