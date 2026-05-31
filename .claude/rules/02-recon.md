# RECON METHODOLOGY — SEQUENTIAL, NO ATTACK UNTIL COMPLETE

## ABSOLUTE RULE
Attack agents NEVER start until recon/RECON-COMPLETE.md exists.

## PHASE 1 — Read Docs
Read every URL in scope.md docs.links.
Save: targets/<TARGET>/recon/docs-summary.md

## PHASE 2 — Permission → Endpoint Map
GET /api/app/me with ALL roles.
Map every permission to endpoint family:
  write_project_webhooks    → /api/app/projects/{pid}/webhooks
  view_audit_logs           → /api/app/organizations/{oid}/audit-logs
  manage_service_accounts   → /api/app/organizations/{oid}/service-accounts
  view_billing              → /api/app/billing_v2/*
  edit_userroles            → /api/app/organizations/{oid}/members
  request_gdpr_data         → /api/app/organizations/{oid}/gdpr
  reset_api_key             → /api/app/projects/{pid}/reset-api-key
  view_project_secret       → /api/app/projects/{pid}/secret
  write_lookup_tables       → /api/app/projects/{pid}/lookup-tables
  write_warehouse_sources   → /api/app/projects/{pid}/warehouse-sources
  transfer_project          → /api/app/projects/{pid}/transfer
  update_org                → /api/app/organizations/{oid}
  edit_userroles            → /api/app/organizations/{oid}/members
  write_scim                → /api/app/scim/v2/*
  manage_sso                → /api/app/organizations/{oid}/sso
Save: targets/<TARGET>/recon/permission-map.json

## PHASE 3 — JS Mining
bash tools/js-extract.sh <domain> <cookies> <outdir>
bash tools/browser-recon.sh <cookies> <project_url> <outdir>
Output: recon/endpoints/all-paths.txt

## PHASE 4 — Fuzzing
bash tools/fuzz.sh <base_url> recon/fuzz-dirs.txt
bash tools/httpx.sh recon/candidates.txt recon/live-endpoints.json

## PHASE 5 — Probe All Endpoints (all roles)
For every path in endpoints-complete.txt:
  Test with ADMIN, MEMBER, IDOR, no-auth via safe_http.py
  Save: recon/endpoint-probe-results.json

## PHASE 6 — Signal Complete
Merge all → recon/endpoints-complete.txt
Write recon/RECON-COMPLETE.md
Emit {"event":"recon_complete"} to queue.jsonl
