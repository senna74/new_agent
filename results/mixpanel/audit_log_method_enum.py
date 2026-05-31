#!/usr/bin/env python3
"""Method enumeration on 3 405-returning endpoints + cross-role/cross-tenant probes."""
import sys, os, json, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)

TARGET = 'mixpanel'
tokens = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/recon/tokens.json'))
ADMIN  = tokens['ADMIN']
MEMBER = tokens['MEMBER']
IDOR   = tokens['IDOR']

LOG_PATH = f'/home/hunter/new_agent/targets/{TARGET}/notes/session-log.md'
def log(msg):
    with open(LOG_PATH, 'a') as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] AUDIT-LOG: {msg}\n")

def headers_for(role):
    return {
        "Cookie": role['full_cookies'],
        "X-CSRFToken": role['csrf'],
        "Authorization": "Session",
        "Referer": "https://mixpanel.com/",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Content-Type": "application/json",
    }

BASE = "https://mixpanel.com"
ENDPOINTS = [
    "/api/app/organizations/3100781/audit-logs",
    "/api/app/projects/4025923/audit-logs",
    "/api/app/projects/4025923/integrations",
]

results = []

def record(label, method, path, role, status, ctype, allow, body_first, req_body=None):
    snippet = body_first[:200] if body_first else ""
    rec = {
        "label": label,
        "method": method,
        "path": path,
        "role": role,
        "status": status,
        "content_type": ctype,
        "allow_header": allow,
        "body_first_200": snippet,
        "req_body": req_body,
    }
    results.append(rec)
    log(f"{label} | {method} {path} as {role} -> {status} | Allow={allow} | CT={ctype} | body={snippet[:120]}")

ROLE_MAP = {"ADMIN": ADMIN, "MEMBER": MEMBER, "IDOR": IDOR}

def call(method, path, role, body=None, extra_headers=None, label="enum"):
    role_dict = ROLE_MAP[role] if isinstance(role, str) else role
    h = headers_for(role_dict)
    if extra_headers:
        h.update(extra_headers)
    url = BASE + path
    try:
        if body is not None:
            resp = sh.request(method, url, headers=h, json_body=body, timeout=20)
        else:
            resp = sh.request(method, url, headers=h, timeout=20)
        status = resp.status_code
        ctype = resp.headers.get("Content-Type", "")
        allow = resp.headers.get("Allow", resp.headers.get("allow", ""))
        text = resp.text or ""
        record(label, method, path, role, status, ctype, allow, text, req_body=body)
        return status, allow, text
    except Exception as e:
        record(label, method, path, role, -1, "", "", f"ERR:{e}", req_body=body)
        return -1, "", str(e)

# === A. Method enumeration with ADMIN ===
log("=== PHASE A: Method enumeration as ADMIN ===")
for P in ENDPOINTS:
    call("HEAD",    P, "ADMIN", label="A-HEAD")
    call("OPTIONS", P, "ADMIN", label="A-OPTIONS")
    call("POST",    P, "ADMIN", body={}, label="A-POST-empty")
    call("POST",    P, "ADMIN", body={"start_date":"2026-05-01","end_date":"2026-05-30","limit":10}, label="A-POST-range")
    call("PUT",     P, "ADMIN", body={"start_date":"2026-05-01","end_date":"2026-05-30","limit":10}, label="A-PUT")
    call("PATCH",   P, "ADMIN", body={"start_date":"2026-05-01","end_date":"2026-05-30","limit":10}, label="A-PATCH")
    call("GET",     P + "?start_date=2026-05-01&end_date=2026-05-30&limit=10&page=1", "ADMIN", label="A-GET-qs")

# Save intermediate before later phases
ts = int(time.time())
out_a = f"/home/hunter/new_agent/results/mixpanel/audit-log-phaseA-{ts}.json"
with open(out_a, 'w') as f:
    json.dump(results, f, indent=2)
log(f"Phase A saved -> {out_a} ({len(results)} records)")
print(f"PHASE_A_SAVED {out_a} records={len(results)}")
