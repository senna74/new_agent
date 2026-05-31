# Mixpanel REST Endpoint Surface — Recon Summary
_Generated 2026-05-30 18:50:36 UTC by recon-endpoints agent_

## Probe Overview
- Total candidates probed: **314**
- Confirmed live (2xx): **18**
- Auth-required (401/403): **4**
- Method exists but wrong verb (405): **3**
- Server errors (5xx): **0**
- Redirects (3xx): **1**
- 404 (not present): **257**

## Source of Truth
- Marketing-site JS bundles: only 4 `/api/app/*` paths surfaced (billing/forms only)
- SPA bundles at `/project/<pid>/app/*` are gated behind `/request_access` redirect (HTML shell unreachable even with admin cookies — likely IP/CSRF/Referer policy on HTML render)
- Master endpoint surface was built by combining: existing agent probes (lookup_tables, cohorts, dashboards, etc.), the 113-permission list from `ADMIN-me.json`, and Mixpanel public-docs REST conventions

## Pattern Confirmed: Project-scoped REST
`/api/app/projects/{pid}/{resource}` is the dominant pattern. Org-scoped is `/api/app/organizations/{oid}/{resource}`. 
GraphQL: `/api/app/graphql` returns JSON 404 (path-pattern enabled but endpoint not registered). No `/graphql`, `/api/graphql`, `/api/2.0/graphql` etc.

## High-Value Live Endpoints (status 200)

- `GET /api/app/me` — `{"status": "ok", "results": {"date_joined_iso": "2026-05-19T13:06:10", "is_staff`
- `GET /api/app/projects` — `{"status": "ok", "results": [{"id": 4025923, "name": "project 1 name"}, {"id": 4`
- `GET /api/app/projects/4025923/annotations` — `{"status": "ok", "results": []}`
- `GET /api/app/projects/4025923/behaviors` — `{"status": "ok", "results": {}}`
- `GET /api/app/projects/4025923/boards` — `{"status": "ok", "results": [{"id": 11207838, "title": "\ud83c\udf31 Starter Boa`
- `GET /api/app/projects/4025923/bookmarks` — `{"status": "ok", "results": [{"id": 90220699, "project_id": 4025923, "dashboard_`
- `GET /api/app/projects/4025923/cohorts` — `{"status": "ok", "results": []}`
- `GET /api/app/projects/4025923/custom_properties` — `{"status": "ok", "results": [{"customPropertyId": 5867414, "project": 4025923, "`
- `GET /api/app/projects/4025923/dashboards` — `{"status": "ok", "results": [{"id": 11207838, "title": "\ud83c\udf31 Starter Boa`
- `GET /api/app/projects/4025923/experiments` — `{"status": "ok", "results": []}`
- `GET /api/app/projects/4025923/feature-flags` — `{"status": "ok", "results": []}`
- `GET /api/app/projects/4025923/metrics` — `{"status": "ok", "results": {}}`
- `GET /api/app/projects/4025923/playlists` — `{"status": "ok", "results": []}`
- `GET /api/app/projects/4025923/users/import` — `{"status": "ok", "results": {"active": false, "role": null, "teams": [], "recent`
- `GET /api/app/projects/4025923/webhooks` — `{"status": "ok", "results": [{"id": "3b82f560-d587-4b8f-9c71-f35ae4d092c8", "nam`
- `GET /api/app/scim/v2/ServiceProviderConfig` — `{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"], "do`
- `GET /api/app/version` — `79e74a6c6a00750d70ca63fa3f4fb9ff4bd33eec`
- `GET /public/dashboard/` — `<!DOCTYPE html> <html lang="en">   <head>     <meta name="iframely" content="all`

## Auth-Gated Endpoints (401/403) — confirm via cross-role
These endpoints exist but rejected ADMIN — likely require different role/permission/auth scheme.
- `403 GET /api/app/projects/4025923/themes` — `{"status": "error", "error": "Cannot use custom themes with your current plan"}`
- `403 GET /api/app/projects/4025923/workspaces` — `{"error": "Your plan does not support DataViews", "status": "error"}`
- `401 GET /api/app/scim/v2/Groups` — `{"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": "Only \"B`
- `401 GET /api/app/scim/v2/Users` — `{"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": "Only \"B`

## Wrong-Method (405) — endpoint exists, try POST/PUT/PATCH/DELETE
- `405 GET /api/app/organizations/3100781/audit-logs`
- `405 GET /api/app/projects/4025923/audit-logs`
- `405 GET /api/app/projects/4025923/integrations`

## Attack-Surface Categories
### Admin/Security (1)
- `GET /api/app/scim/v2/ServiceProviderConfig`

### Data/IDOR Candidates (6)
- `GET /api/app/projects/4025923/boards`
- `GET /api/app/projects/4025923/cohorts`
- `GET /api/app/projects/4025923/dashboards`
- `GET /api/app/projects/4025923/users/import`
- `GET /api/app/projects/4025923/webhooks`
- `GET /public/dashboard/`

### GDPR/Destructive (0)

### Billing (0)

### Public/Embed/Share (1)
- `GET /public/dashboard/`

### GraphQL (0)

## Secrets in JS / HTML
- **optimizely** in `app_shell_boards.html` — `optimizely.com/js/5838709522694144.js`
- **qualified_token** in `app_shell_boards.html` — `gSDtTCjJ2BozXgw6`
- **sentry_dsn** in `https___mixpanel_com_home_.html` — `https://d73fef86381aca393554093c8e57ce75@o81318.ingest.us.sentry.io/4509680689938432`
- **sentry_dsn2** in `https___mixpanel_com_home_.html` — `https://d73fef86381aca393554093c8e57ce75@o81318.ingest.us.sentry.io/4509680689938432`
- **sentry_dsn** in `_app-30065074a8f69b05.js` — `https://17401c3faae61f8b0bf1e9796db774d5@o81318.ingest.us.sentry.io/4509680692428805`
- **sentry_dsn2** in `_app-30065074a8f69b05.js` — `https://17401c3faae61f8b0bf1e9796db774d5@o81318.ingest.us.sentry.io/4509680692428805`

_Note: Sentry DSNs are public client-side IDs (NOT exfil tokens) — informational only._

## Files
- `recon/endpoints-from-js.txt` — paths extracted via regex from JS
- `recon/endpoints-confirmed.txt` — paths returning 200/401/403/405/500
- `recon/endpoint-probe-results.json` — full probe results with status+snippet
- `recon/endpoints-graphql.txt`, `endpoints-embed.txt`, `endpoints-generic.txt`
- `recon/secrets/secrets-deep.json` — secret-pattern scan results
- `recon/js/*.js` — 18 downloaded JS bundles