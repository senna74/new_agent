
## Mixpanel — 2026-05-30 (attack-idor)

- `/api/app/projects/{pid}/{ep}` — request_access HTML page is served with HTTP 200
  after a 302 redirect to `/request_access/?next=/`. Body length 31086.
  Filtering only on status==200 + len>50 will produce false positives. ALWAYS
  inspect Content-Type and snippet — the request_access page begins with
  `<!DOCTYPE html>` and contains `<title>Request Access - Mixpanel</title>`.
- `/api/app/projects/{pid}/{ep}/` (trailing slash) and `/dashboards/.` (dot-slash):
  same 302 → request_access. NOT bypasses.
- Project 4025923 is owned by ADMIN but contains a "Starter Board" (id 11207838)
  with creator=Mixpanel / eng-accounts@mixpanel.com. This is a per-project
  onboarding board, not a shared demo. Each ADMIN project gets its own distinct one.
- MEMBER account (user_id 6492622) is a legitimate member of both ADMIN's project
  4025923 AND its own project 4025974. Cross-project access by MEMBER to 4025923
  is by design (multi-org membership), not an IDOR.
- /api/2.0/* endpoints enforce project ownership via query-param project_id; 403
  for foreign projects — properly gated.
- /graphql, /api/graphql, /internal/graphql — not exposed on mixpanel.com.
