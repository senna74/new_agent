# ORCHESTRATOR.md
# Single source of truth for all hunt operations.
# All variables are derived at runtime from disk — nothing hardcoded.
# Enforcement is in hooks. This file is instructions only.

---

## RUNTIME VARIABLES
# Derive these at the start of every session before any step.

TARGET  = $(cat ~/new_agent/state/.active-target)
SCOPE   = ~/new_agent/targets/$TARGET/scope.md
TOKENS  = ~/new_agent/targets/$TARGET/recon/tokens.json
OUTDIR  = ~/new_agent/targets/$TARGET/recon
RESULTS = ~/new_agent/results/$TARGET
LEADS   = ~/new_agent/targets/$TARGET/leads
FINDS   = ~/new_agent/targets/$TARGET/findings
REPORTS = ~/new_agent/targets/$TARGET/reports
NOTES   = ~/new_agent/targets/$TARGET/notes
QUEUE   = ~/new_agent/state/queue.jsonl
MEMORY  = ~/new_agent/memory

# Auth headers — load dynamically from tokens.json:
ADMIN_H  = tokens[$TARGET]["ADMIN"]["api_request_headers"]
MEMBER_H = tokens[$TARGET]["MEMBER"]["api_request_headers"]
IDOR_H   = tokens[$TARGET]["IDOR"]["api_request_headers"]

# Base URL — load from scope.md urls.dashboard:
BASE_URL = scope.md → urls.dashboard

# Project IDs and Org IDs — discovered in STEP 3, used in all later steps.
# Do not hardcode. Read from $OUTDIR/identity/SUMMARY.json after STEP 3.

---

## STEP 0 — BOOT

Run:
  test -f ~/new_agent/state/.active-target      || { echo "ERROR: no active target"; exit 1; }
  test -f $SCOPE                                 || { echo "ERROR: scope.md missing"; exit 1; }
  test -f $TOKENS                                || { echo "ERROR: tokens.json missing"; exit 1; }

Create directories:
  mkdir -p $OUTDIR/{identity,endpoints,js,secrets}
  mkdir -p $RESULTS $LEADS $FINDS $REPORTS $NOTES $MEMORY

Print: BOOT target=$TARGET

---

## STEP 1 — TOKEN HEALTH CHECK

Load auth headers from $TOKENS:
  Read $TOKENS
  For each role (ADMIN, MEMBER, IDOR):
    headers = tokens[role]["api_request_headers"]
    base    = scope.md → urls.dashboard

  Test each role:
    python3 ~/new_agent/.claude/lib/safe_http.py GET $BASE_URL/api/app/me \
      --headers "$headers"

  IF status != 200:
    python3 ~/new_agent/.claude/lib/oidc-login.py {ROLE}
    Reload $TOKENS
    Retry once

Output file: $OUTDIR/identity/token-health.json
  { "ADMIN": "ok|fail", "MEMBER": "ok|fail", "IDOR": "ok|fail" }

Print: TOKENS ADMIN={status} MEMBER={status} IDOR={status}

---

## STEP 2 — READ DOCS

Read $SCOPE → docs.links section.
For each URL in docs.links:
  Fetch the URL
  Extract: API endpoints, roles, permissions, features, auth methods
  Append extracted intel to $OUTDIR/docs-summary.md

Output file: $OUTDIR/docs-summary.md

Print: DOCS read={N} urls

---

## STEP 3 — IDENTITY MAP

For each role (ADMIN, MEMBER, IDOR):
  python3 ~/new_agent/.claude/lib/safe_http.py GET $BASE_URL/api/app/me \
    --headers "$headers"

  From response extract:
    - org IDs and roles
    - project IDs
    - full permissions list (every single permission string)

Output file: $OUTDIR/identity/SUMMARY.json
  {
    "ADMIN":  { "org_ids": [...], "project_ids": [...], "permissions": [...] },
    "MEMBER": { "org_ids": [...], "project_ids": [...], "permissions": [...] },
    "IDOR":   { "org_ids": [...], "project_ids": [...], "permissions": [...] }
  }

Print: IDENTITY mapped roles=3

---

## STEP 4 — PERMISSION TO ENDPOINT MAP

Read $OUTDIR/identity/SUMMARY.json.
Read $OUTDIR/docs-summary.md.

For each permission in each role's permissions list:
  Map to endpoint family using the docs and this reference table:

  write_project_webhooks    → {BASE_URL}/api/app/projects/{pid}/webhooks
  view_audit_logs           → {BASE_URL}/api/app/organizations/{oid}/audit-logs
  manage_service_accounts   → {BASE_URL}/api/app/organizations/{oid}/service-accounts
  view_billing              → {BASE_URL}/api/app/billing_v2/get_invoices/account/{oid}
  view_billing              → {BASE_URL}/api/app/billing_v2/get_payments/account/{oid}
  view_billing              → {BASE_URL}/api/app/billing_v2/account/{oid}/card_info
  edit_userroles            → {BASE_URL}/api/app/organizations/{oid}/members
  request_gdpr_data         → {BASE_URL}/api/app/organizations/{oid}/gdpr
  reset_api_key             → {BASE_URL}/api/app/projects/{pid}/reset-api-key
  view_project_secret       → {BASE_URL}/api/app/projects/{pid}/secret
  write_lookup_tables       → {BASE_URL}/api/app/projects/{pid}/lookup-tables
  write_warehouse_sources   → {BASE_URL}/api/app/projects/{pid}/warehouse-sources
  transfer_project          → {BASE_URL}/api/app/projects/{pid}/transfer
  delete_project            → {BASE_URL}/api/app/projects/{pid}
  update_org                → {BASE_URL}/api/app/organizations/{oid}
  delete_org                → {BASE_URL}/api/app/organizations/{oid}
  update_user               → {BASE_URL}/api/app/me
  write_scim                → {BASE_URL}/api/app/scim/v2/Users
  write_scim                → {BASE_URL}/api/app/scim/v2/Groups
  manage_sso                → {BASE_URL}/api/app/organizations/{oid}/sso
  import_events             → {BASE_URL}/api/app/projects/{pid}/users/import
  write_dashboards          → {BASE_URL}/api/app/projects/{pid}/dashboards
  write_cohorts             → {BASE_URL}/api/app/projects/{pid}/cohorts
  write_bookmarks           → {BASE_URL}/api/app/projects/{pid}/bookmarks
  write_custom_properties   → {BASE_URL}/api/app/projects/{pid}/custom_properties
  write_themes              → {BASE_URL}/api/app/projects/{pid}/themes
  write_feature_flags       → {BASE_URL}/api/app/projects/{pid}/feature-flags
  write_experiments         → {BASE_URL}/api/app/projects/{pid}/experiments
  write_annotations         → {BASE_URL}/api/app/projects/{pid}/annotations
  write_metrics             → {BASE_URL}/api/app/projects/{pid}/metrics
  write_behaviors           → {BASE_URL}/api/app/projects/{pid}/behaviors

  For any permission NOT in this table:
    Use docs-summary.md to derive the endpoint.
    If docs don't mention it, fuzz it in STEP 8.

  Fill {pid} with every project_id from SUMMARY.json.
  Fill {oid} with every org_id from SUMMARY.json.

Output file: $OUTDIR/permission-map.json
  {
    "ADMIN":  { "{full_url}": "{permission_name}", ... },
    "MEMBER": { ... },
    "IDOR":   { ... }
  }

Print: PERM-MAP endpoints={N}

---

## STEP 5 — JS MINING

Load cookies:
  COOKIES = tokens["ADMIN"]["full_cookies"]

Run:
  bash ~/new_agent/.claude/tools/js-extract.sh $TARGET "$COOKIES" $OUTDIR

Wait for completion.

Output files:
  $OUTDIR/js/js-urls.txt
  $OUTDIR/js/*.js
  $OUTDIR/endpoints/all-paths.txt

Print: JS-MINING js-files={N} paths={M}

---

## STEP 6 — BROWSER RECON

Read $OUTDIR/identity/SUMMARY.json.
Get first project_id from ADMIN.project_ids.

PROJECT_URL = $BASE_URL/project/{first_pid}/app/boards

Run:
  bash ~/new_agent/.claude/tools/browser-recon.sh "$COOKIES" "$PROJECT_URL" $OUTDIR

Wait for completion.

Merge results:
  cat $OUTDIR/endpoints/browser-api-calls.txt >> $OUTDIR/endpoints/all-paths.txt
  sort -u $OUTDIR/endpoints/all-paths.txt -o $OUTDIR/endpoints/all-paths.txt

Download any new JS URLs from $OUTDIR/js/browser-js-urls.txt with auth cookies.
Run jsluice on new JS files. Append new paths to all-paths.txt.

Print: BROWSER-RECON new-paths={N}

---

## STEP 7 — BUILD WORDLIST

Extract from all sources:
  1. $OUTDIR/endpoints/all-paths.txt  — last path segment of every line
  2. $OUTDIR/permission-map.json      — endpoint name segments
  3. $OUTDIR/docs-summary.md          — any word resembling an endpoint name

Always include these entries:
  service-accounts service_accounts
  billing_v2 get_invoices get_payments card_info
  audit-logs audit_logs
  members invitations roles permissions
  sso scim webhooks connectors integrations
  export import gdpr delete reset transfer
  secret tokens api-keys api_keys
  settings usage plan subscription
  version health status me profile
  account org organization project workspace team
  user users invite accept reject approve revoke
  rotate regenerate verify validate
  lookup-tables lookup_tables warehouse-sources warehouse_sources
  custom-properties custom_properties feature-flags feature_flags
  experiments annotations behaviors metrics
  playlists themes boards dashboards bookmarks cohorts
  funnels retention flows insights reports

Output file: ~/new_agent/.claude/lib/api-wordlist.txt

Print: WORDLIST size={N}

---

## STEP 8 — FUZZING

Read $OUTDIR/identity/SUMMARY.json for all pids and oids.
Read $SCOPE for BASE_URL.

Run fuzz.sh on every base path:
  For each pid in ADMIN.project_ids + MEMBER.project_ids + IDOR.project_ids:
    bash ~/new_agent/.claude/tools/fuzz.sh \
      $BASE_URL/api/app/projects/$pid \
      ~/new_agent/.claude/lib/api-wordlist.txt

  For each oid in all org_ids:
    bash ~/new_agent/.claude/tools/fuzz.sh \
      $BASE_URL/api/app/organizations/$oid \
      ~/new_agent/.claude/lib/api-wordlist.txt

  Also fuzz:
    bash ~/new_agent/.claude/tools/fuzz.sh $BASE_URL/api/app ~/new_agent/.claude/lib/api-wordlist.txt
    bash ~/new_agent/.claude/tools/fuzz.sh $BASE_URL/api/2.0 ~/new_agent/.claude/lib/api-wordlist.txt

  If scope.md mentions additional API versions or paths, fuzz those too.

Wait for all fuzzing to finish.
Append fuzz hits to $OUTDIR/endpoints/all-paths.txt.

Print: FUZZ done hits={N}

---

## STEP 9 — PROBE ALL ENDPOINTS

Merge all sources into final list:
  cat $OUTDIR/endpoints/all-paths.txt          >> $OUTDIR/endpoints-complete.txt
  cat $OUTDIR/endpoints/browser-api-calls.txt  >> $OUTDIR/endpoints-complete.txt
  Extract all keys from $OUTDIR/permission-map.json >> $OUTDIR/endpoints-complete.txt
  sort -u $OUTDIR/endpoints-complete.txt -o $OUTDIR/endpoints-complete.txt

For every endpoint in $OUTDIR/endpoints-complete.txt:
  Test with ADMIN_H, MEMBER_H, IDOR_H, and no headers.
  Use python3 ~/new_agent/.claude/lib/safe_http.py for every request.
  Record: status code + body[:150] + content-type for each role.

Output file: $OUTDIR/endpoint-probe-results.json
  {
    "{endpoint}": {
      "ADMIN":  { "status": N, "len": N, "body": "...", "ctype": "..." },
      "MEMBER": { "status": N, "len": N, "body": "...", "ctype": "..." },
      "IDOR":   { "status": N, "len": N, "body": "...", "ctype": "..." },
      "NOAUTH": { "status": N, "len": N, "body": "...", "ctype": "..." }
    }
  }

Print: PROBE endpoints={N} done

---

## STEP 10 — RECON COMPLETE

Write output file: $OUTDIR/RECON-COMPLETE.md
  # Recon Complete
  target: $TARGET
  timestamp: {ISO}
  endpoints_total: {N}
  js_files: {N}
  permissions_mapped: {N}
  docs_read: {N}

Append to $QUEUE:
  {"event":"recon_complete","target":"$TARGET","endpoints":{N},"ts":"{ISO}"}

Print: RECON-COMPLETE endpoints={N}

---
## ATTACK PHASE — hooks enforce no attack before RECON-COMPLETE.md exists
---

## STEP 11 — TRIAGE

Read $OUTDIR/endpoint-probe-results.json
Read $OUTDIR/permission-map.json

For every endpoint:
  expected = permission-map.json (which roles should access)
  actual   = endpoint-probe-results.json (which roles actually access)

  Flag as CANDIDATE if any condition is true:
    MEMBER accesses endpoint not in MEMBER permission-map
    IDOR accesses endpoint belonging to a different org
    NOAUTH accesses any protected endpoint
    MEMBER and ADMIN get identical response on admin-only endpoint
    Any role gets 200 where permission-map says they should get 403

Output file: $LEADS/triage-candidates.json

Print: TRIAGE candidates={N}

---

## STEP 12 — ATTACK AGENTS

Spawn one agent at a time. Wait for each to finish before spawning next.
Each agent reads from $LEADS/triage-candidates.json and $OUTDIR/endpoints-complete.txt.
Each agent writes output to $RESULTS/.

  12a. Use agent: attack-idor
       Input:  BAC and cross-tenant candidates
       Output: $RESULTS/attack-idor-{ts}.json

  12b. Use agent: attack-privesc
       Input:  privesc candidates
       Output: $RESULTS/attack-privesc-{ts}.json

  12c. Use agent: attack-ssrf
       Input:  endpoints containing webhook, connector, import, export
       Output: $RESULTS/attack-ssrf-{ts}.json

  12d. Use agent: attack-auth
       Input:  endpoints containing scim, sso, oauth, token
       Output: $RESULTS/attack-auth-{ts}.json

  12e. Use agent: attack-xss
       Input:  endpoints with reflection in response body
       Output: $RESULTS/attack-xss-{ts}.json

  12f. Use agent: attack-sqli
       Input:  endpoints with query parameters
       Output: $RESULTS/attack-sqli-{ts}.json

  If scope.md features contains additional surfaces (graphql, llm, rce, etc.):
    Spawn relevant agents from ~/new_agent/.claude/agents/ for those surfaces.

Print: ATTACK done

---

## STEP 13 — FINDINGS TRIAGE

Read ~/new_agent/.claude/rules/04-triage.md
For every result file in $RESULTS/:
  Apply 7-question gate from 04-triage.md
  confidence >= 0.85  → write to $FINDS/
  confidence 0.40-0.84 → write to $LEADS/
  confidence < 0.40   → append pattern to $MEMORY/false-positives.md

Print: FINDINGS confirmed={N} leads={N} skipped={N}

---

## STEP 14 — REPORT

Read ~/new_agent/.claude/rules/05-reporting.md
For every finding in $FINDS/:
  Write report to $REPORTS/
  Update $FINDS/MASTER-SUMMARY.md

Print: DONE findings={N} leads={N} reports={N}
