# LEAD: Audit-Log API Method/Schema Discovery + Authz Confirmation

**Date:** 2026-05-30
**Status:** Method enumeration complete; no privesc found; full authz boundary intact
**Confidence:** 0.40 (intel only, not a finding)

## Endpoints tested

| Path | Method (correct) | ADMIN | MEMBER (0 perms in org 3100781) |
|------|-----------------|-------|-----|
| `/api/app/organizations/3100781/audit-logs` | **POST** with `{}` body | 200 (data) | 403 `User does not have permission` |
| `/api/app/projects/4025923/audit-logs`     | **POST** with `{}` body | 200 (data) | 403 `... permission "view_audit_logs" in project 4025923` |
| `/api/app/projects/4025923/integrations`   | NOT IMPLEMENTED (404 on POST even as ADMIN; 405 only fires on GET/PUT/PATCH from generic catch-all) | 404 | 403 |

## Method enumeration table (ADMIN, org audit-log)

| Method | Status | Notes |
|--------|--------|-------|
| HEAD    | 405 | `Allow: POST` |
| OPTIONS | 405 | `Allow: POST` |
| GET     | 405 | `Allow: POST` |
| POST {} | 200 | Returns first page of audit records |
| POST {start_date,end_date,limit} | 400 | `Additional properties are not allowed` — strict schema |
| PUT     | 405 | text/html generic |
| PATCH   | 405 | text/html generic |

POST is the canonical method. The schema is strict JSON Schema (visible in 400 response, lists `Action` enum with ~50 audit actions). Pagination is via the schema's accepted fields (not `start_date/end_date/limit`).

## Record shape (sample, organization audit-log)

```json
{"project_id":"4025923","organization_id":"3100781","created":"2026-05-30T16:54:47Z",
 "id":"cfc4b300-…","service":"webapp","event_category":"data_mutate",
 "organization_name":"org name 1","client_ip":"173.212.245.147","http_method":"DELETE",
 "http_request_headers":{"User-Agent":"…","X-Forwarded-For":"…"}}
```

Sensitive fields exposed (to authorized callers only): `client_ip`, full request headers including `X-Forwarded-For`, `User-Agent`, `Referer`.

## Authorization enforcement matrix — VERIFIED CORRECT

| Caller | Path | Expected | Actual |
|--------|------|----------|--------|
| ADMIN  | /org/3100781/audit-logs | 200 | 200 ✓ |
| ADMIN  | /org/3100795/audit-logs (IDOR's org) | 403 | 403 `User does not have permission` ✓ |
| MEMBER | /org/3100781/audit-logs (no perm) | 403 | 403 ✓ |
| MEMBER | /project/4025923/audit-logs (no perm) | 403 | 403 with explicit `view_audit_logs` reference ✓ |
| MEMBER | /project/4025923/integrations (no perm) | 403 | 403 with explicit `edit_integrations` ✓ |
| MEMBER | /org/3100810/audit-logs (own org admin) | 200 | 200 ✓ (legitimate baseline) |
| MEMBER | /org/3100795/audit-logs (IDOR's org) | 403 | 403 ✓ |

## Header smuggling tests — NONE BYPASS

| Test | Result |
|------|--------|
| ADMIN cookie + `X-Original-URL: /org/3100795/audit-logs` | 200 with **3100781** data (header ignored — actual path wins). No cross-tenant. |
| ADMIN cookie + `X-Rewrite-URL: /org/3100795/audit-logs`  | Same — header ignored. |
| MEMBER + `X-Original-URL: /org/3100781/audit-logs` on own org path | 200 with **own** org data. Header ignored. |
| MEMBER + `X-Original-URL` on a forbidden project path | 403 — path authz still applies. |
| MEMBER POST `/api/app/organizations/3100810/../3100781/audit-logs` | 403 (path normalized to 3100781 → MEMBER denied correctly). |
| MEMBER POST with `;a=b` semicolon trick | 404 (router does not normalize) |
| MEMBER POST with `//organizations` double-slash | 404 |

## Conclusion

The 405 on GET for the two `/audit-logs` endpoints is a **correct method-routing response** (`Allow: POST`). The `integrations` endpoint is simply not implemented at that project path (404 on POST as ADMIN; 405 for non-POST is a generic catch-all). Authorization is enforced consistently on both organization- and project-scoped audit-log endpoints, across vertical (MEMBER → ADMIN org) and horizontal (ADMIN → IDOR org) directions, and is not bypassable via `X-Original-URL`, `X-Rewrite-URL`, `..` traversal, semicolon, or double-slash tricks.

**No submittable finding.** Filing as a lead so future chain attempts know POST is the canonical method, the request schema is leaked on 400, and the audit-log response contains `client_ip` + full request headers (potentially useful for OSINT chaining if a separate ID-confusion bug is ever found).

## Evidence files
- `/home/hunter/new_agent/results/mixpanel/audit-log-phaseA-1780160045.json`
- `/home/hunter/new_agent/results/mixpanel/audit-log-phasesABDE-1780160117.json`
- `/home/hunter/new_agent/results/mixpanel/audit-log-phaseF-1780160182.json`
