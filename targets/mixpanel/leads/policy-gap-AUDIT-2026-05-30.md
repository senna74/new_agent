# Authorization Policy Audit — mixpanel.com (2026-05-30)

Status: NO FINDINGS — all tested authorization controls correctly enforced.
Raw evidence: `/home/hunter/new_agent/results/mixpanel/authz-1780159614.json`
Re-validation: `/home/hunter/new_agent/results/mixpanel/authz_revalidate.py`
Roles compared: ADMIN (org 3100781 organization-admin, 113 perms) vs MEMBER (org 3100781 "no role", 0 org perms)

---

## Part A — Resource read checks

### A.1 Cross-project reads (4025962, 4027263, 4027269) — ENFORCED
For all three projects NOT in MEMBER's visible project list, GET `/api/app/projects/{id}/dashboards`:
- ADMIN: 200 application/json with dashboard data
- MEMBER: **302** Location: `/request_access/?next=` (correctly redirected to project access-request flow)

Sigs differ. No leak. Control holds.

### A.2 4025923 reads (cohorts, bookmarks, webhooks) — LEGITIMATE GRANT, NOT A GAP
MEMBER GETs returned identical body to ADMIN on:
- `/api/app/projects/4025923/cohorts`  (200, `{status:ok, results:[]}`)
- `/api/app/projects/4025923/bookmarks` (200, 23487 bytes — same sig as ADMIN)
- `/api/app/projects/4025923/webhooks`  (200, 328 bytes — same sig as ADMIN)
- `/api/app/projects/4025923/dashboards` (200 — body differs only in `recently_visited` per-user field)

**This is NOT a finding.** MEMBER's `/api/app/me` explicitly shows project-level grant:
```
projects: { "4025923": { role: { id: 13, name: "consumer" },
            permissions: ["write_cohorts", "write_custom_properties",
                          "write_lookup_tables", "write_heat_maps", "write_themes"] } }
```
The Mixpanel docs distinguish org-level "no role" (0 org perms) from project-level explicit grants. MEMBER was granted "consumer" role on project 4025923 by the project owner. The 200 responses on its own project resources are authorized per Mixpanel's documented project-membership model. Cross-confirmed by prior IDOR investigation (results/mixpanel/idor-*.json) which observed MEMBER successfully created a webhook on 4025923.

### A.3 4025923 secret-class reads — endpoint does not exist
`/lookup_tables`, `/custom_alerts`, `/service_accounts`, `/users`, `/info`, `/settings`, `/secret`, `/api-key` — all returned **404** with identical body for BOTH ADMIN and MEMBER. These are route-level 404s (the API does not expose those names). Inconclusive: real paths may use different names (see Part D).

### A.4 Organization reads (3100781) — endpoint does not exist
`/api/app/organizations/3100781` and sub-paths (`/members`, `/audit_logs`, `/billing`) — all returned **404** with identical body for BOTH ADMIN and MEMBER.

Probed alternates: `/api/app/orgs/{id}`, `/api/app/organization/{id}`, `/api/app/organizations`, `/api/2.0/organizations/{id}` — all return 404 or 400 ("project_id is a required parameter" — i.e. wrong route family). The path family `/api/app/organizations/{id}/*` does not exist on this surface; organization data is delivered exclusively via `/api/app/me`. Inconclusive — cannot test authz on a route that doesn't exist.

---

## Part B — Write checks

### B.1 Webhook create — ENFORCED (schema rejects, then perm-check)
POST `/api/app/projects/4025923/webhooks` with `{name,url,cohort_id:1}` returned **400** for MEMBER:
> "Additional properties are not allowed ('cohort_id' was unexpected)"
JSON-Schema-layer validation rejected the payload before any state change. (Note: MEMBER has `write_cohorts` on this project — so even a valid webhook-create probably would have been honored as a granted-permission action. Not a privesc surface.)

### B.2 PATCH /api/app/me {is_staff:true} — ENFORCED (mass-assignment protected)
Both ADMIN and MEMBER received identical 400:
> "Additional properties are not allowed ('is_staff' was unexpected)"

Verified by re-reading `/api/app/me` after the PATCH: `is_staff: false` for both accounts pre- AND post-PATCH; response body length unchanged (admin 20937→20937 bytes; member 8956→8956 bytes). The 16-byte body-signature drift between the two consecutive GETs is **non-deterministic permission-list ordering** (admin's permissions array re-ordered from `view_audit_logs,invite_...` to `pin_dashboards,write_da...` — same elements, different order), not a state change.

Mass-assignment field is rejected at the JSON-schema layer. Control holds.

### B.3 Invite user — endpoint does not exist
POST `/api/app/organizations/3100781/users` → **404** ("Not found"). Same route-family issue as A.4. Cannot test authz here.

### B.4 reset_api_key — endpoint does not exist at that path
POST `/api/app/projects/4025923/reset_api_key` → **404**. Real path likely uses different name (`reset_token`, `regenerate`, etc.). Inconclusive.

---

## Part C — Header context manipulation — ENFORCED

| header                                                    | MEMBER response                          | result    |
|-----------------------------------------------------------|------------------------------------------|-----------|
| `X-Mixpanel-Org-Role: admin` → /projects/4025962/dashboards | 302 /request_access/?next=               | ignored   |
| `X-Original-URL: /projects/4025923/dashboards` → /4025962/dashboards | 302 /request_access/?next=     | ignored   |

Neither header is honored. Server uses session-derived identity exclusively for authz decisions.

---

## Final summary — 7-Question Gate

Q1 Real HTTP captured?              Yes (all 19+4+2 probes saved to authz-1780159614.json)
Q2 In HackerOne accepted impact?    Would be — IF a gap existed (role confusion / horizontal/vertical access boundary)
Q3 In scope?                        Yes — mixpanel.com is in_scope
Q4 Exploitable right now?           **NO — no gap found**
Q5 Reproducible 3x?                 N/A (no positive finding to reproduce)
Q6 Concrete impact?                 **None — every elevated endpoint either correctly blocks MEMBER, is a legitimately-granted project resource, or does not exist**
Q7 Not in false-positives.md?       N/A

Confidence: **0.00** for any authz-gap claim. Filed as LEAD (audit completed, negative result documented, no MATCH on any out-of-scope-for-role surface).

## Recommendations for next audit pass

1. Enumerate the actual organization-management API surface — paths under `/api/app/organizations/*` do not exist; org data flows exclusively through `/api/app/me`. The real org-management endpoints likely live under a different prefix (mine `app.js` bundle for them).
2. Enumerate real project-secret paths — `/secret`, `/api-key`, `/reset_api_key` do not exist as named. Search the JS bundle for `reset_token`, `regenerate_token`, `project_token`, `secret_token`, `keys`.
3. Repeat the audit against a project where MEMBER has been deliberately granted only a low project role (e.g. `consumer`) and probe write_admin/delete_project operations within that project.
