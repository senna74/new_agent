# BAC / IDOR / Privilege Escalation — Research Findings 2025-2026

Generated 2026-05-27. Compiled from 50+ web searches, academic papers, conference talks, disclosed bug bounty reports, CVE databases, and practitioner blogs. Source links retained at the bottom.

---

## EXECUTIVE SUMMARY

1. **Broken Access Control remained #1 in OWASP Top 10 2025** (final released January 2026). It now absorbs **SSRF (CWE-918)**, expands from 34 to 40 CWEs, and shows **100% of tested apps have some form of BAC**. (owasp.org/Top10/2025/A01)
2. **Bugcrowd 2025 CISO Report**: Critical BAC vulnerabilities rose **36%** in 2025. (bugcrowd.com 2025)
3. **HackerOne 2025 HPSR**: Valid IDOR reports jumped **29% since 2024**; authorization flaws rising while XSS/SQLi declining.
4. **Inspectiv 2025**: BAC = **38%** of all submissions across their platform — single largest category.
5. **OWASP API Security Top 10 (2023 edition)** still authoritative in 2026 (no 2025 update issued). **BOLA, BFLA, BOPLA account for 58%** of all API security incidents. (42Crunch / OWASP)
6. New high-impact CVE classes in 2025: **Next.js middleware bypass (CVE-2025-29927, CVSS 9.1)**, **Entra ID Actor tokens (CVE-2025-55241, CVSS 10.0)**, **Grafana SCIM externalId mapping (CVE-2025-41115, CVSS 10.0)**, **Apache Tomcat semicolon path equivalence (CVE-2025-24813)**, **Spring Security method-annotation bypass (CVE-2025-41232/41248/41249)**, **Keycloak UMA Protection API (CVE-2025-14778)**, **ServiceNow BodySnatcher (CVE-2025-12420, CVSS 9.3)**.

---

## TOP-VALUE BUG BOUNTY CASE STUDIES (2024-2026)

### Top 20 Highest-Paid Authorization/BAC Reports (HackerOne, all-time, focused on disclosed)

| Bounty | Target | Title | Class |
|--------|--------|-------|-------|
| $18,000 | LocalTapiola | Oracle WebCenter `/cs/Satellite` admin from internet | Forced-browsing + path |
| $15,250 | Shopify | Email Confirmation Bypass → Partner invite → any shop owner | SSO bridging |
| $15,000 | TikTok | Authorization flaw on intelbot internal service | Internal exposure |
| $12,500 | HackerOne | Delete certifications via GraphQL mutation | GraphQL BFLA |
| $10,500 | Superhuman | Disable any organization's SSO → ATO opportunity | Org-level BAC |
| $10,500 | PayPal | Add secondary user to any business account | Cross-tenant |
| $10,000 | GitHub | Arbitrary read of another user's private repo | Object-level authz |
| $5,000 | Kubernetes | CVE-2023-5528 Windows node privilege escalation | Privesc primitive |
| $4,500 | Uber | Unauthorized access to tax-docs portal via exposed subdomain | Forced browse |
| $4,000 | Mapbox | OAuth bypass enabling admin panel access | OAuth scope |
| $3,900 | Shipt | Add product to other users' orders | Order-level BAC |
| $3,500 | Shopify | Partners invitation → privesc without email verification | Email-confirm bypass |
| $3,000 | GitLab | Email-verification bypass for OAuth → 3rd-party ATO | Email-confirm bypass |
| $3,000 | HackerOne | Jira integration JWT leak | JWT mishandling |
| $2,940 | X/Twitter | OAuth permission screen lets DM access without consent | OAuth scope confusion |
| $2,500 | HackerOne | Cross-team access to report_sources via Team GraphQL | GraphQL BOLA |
| $2,500 | TikTok | IDOR on support ticket viewing | Object-level BOLA |
| $2,500 | Kubernetes | Privesc in kOps via GCE/GCP provider | Privesc primitive |
| $2,000 | LocalTapiola | User access to company details w/o permission | Object-level |
| $1,750 | Shopify | Staff member privesc via partner email-confirm bypass | Bridging |

### Massive 2025 Incidents (post-disclosure / breach-level)

- **McHire / McDonald's (June 2025)** — **64 million job applications leaked.** Two bugs: (1) admin login accepted "123456:123456", (2) `/api/lead/cem-xhr` with `lead_id` parameter incrementally enumerable. Discovered by sample/Sam Curry. PoC: change one integer. (ian.sh/mcdonalds)
- **CVE-2025-55241 — Microsoft Entra ID Actor Token (CVSS 10.0)** — Discovered by Dirk-jan Mollema while prepping Black Hat USA 2025. "Actor tokens" requested in attacker's tenant + Azure AD Graph API failing to validate tenant claim = silent **Global Admin in ANY tenant**, bypassing MFA, Conditional Access, AND logging. Microsoft confirmed no exploitation observed pre-fix.
- **CVE-2025-41115 — Grafana Enterprise SCIM (CVSS 10.0)** — `externalId` field in SCIM provisioning request mapped to internal `user.uid`. Set `externalId: "1"` → become admin of grafana instance.
- **CVE-2025-29927 — Next.js Middleware Auth Bypass (CVSS 9.1)** — Send `x-middleware-subrequest` header → middleware skipped entirely. Affects all self-hosted Next.js apps using `output: standalone`.
- **CVE-2025-12420 — ServiceNow BodySnatcher (CVSS 9.3)** — Hardcoded universal client secret + email-based account linking. Email-only impersonation of any user incl. admins, bypassing MFA/SSO. Patched October 30, 2025.

---

## NEW / UPDATED 2025-2026 TAXONOMY

### A01 Broken Access Control (OWASP Top 10:2025) — Now includes:
- CWE-200, CWE-201, CWE-918 (SSRF — newly absorbed), CWE-352 (CSRF)
- Eight named common weaknesses: violation of least privilege, URL/parameter tampering, IDOR, missing API method controls, privilege escalation, JWT/metadata tampering, CORS misconfig, **forced browsing**.

### OWASP API Top 10 (2023, still current 2026)
- **API1: BOLA** — object-level (covered in `hunt-idor`)
- **API3: BOPLA** — Object Property Level Auth = Mass Assignment + Excessive Data Exposure merged
- **API5: BFLA** — Function-level (admin/route access)

### Newly Emergent BAC Classes in 2025-2026

1. **Agentic AI / LLM Scope Violation** — AI agents with tool-use access data with their auth but output to shared contexts. CFO's agent in shared Slack channel exposes exec comp to junior analyst. (Okta, OpenID 2025)
2. **Cross-tenant via SCIM externalId confusion** — CVE-2025-41115 pattern; SCIM tokens & provisioning APIs trust user-supplied identifiers.
3. **OAuth Token Exchange (RFC 8693) abuse** — Scope upgrade by trading low-priv tokens for high-priv tokens. Spec permits unauthenticated exchanges; RFC 9700 (Jan 2025) is BCP update warning against this.
4. **Spring Method Security annotation bypass on parameterized generics** (CVE-2025-41248/41249) — `@PreAuthorize` ignored on methods in generic type hierarchies.
5. **Apollo Federation interface-directive bypass** — `@authenticated`, `@requiresScopes`, `@policy` on GraphQL interfaces NOT propagated to implementing types; inline fragments bypass. (Late 2025 CVEs vs Apollo Federation < 2.9.5/2.10.4/2.11.5/2.12.1)
6. **WebSocket subprotocol / shared-token authz hijack** — OpenClaw (GHSA-rqpp-rjj8-7wv8), LXD GHSA-3g72-chj4-2228, Fortinet FG-IR-25-006, Spring CSRF bypass CVE-2025-41254.

---

## COMPLETE ATTACK TECHNIQUE INVENTORY (2025-2026)

### 1. Vertical Privilege Escalation
- Direct admin endpoint hit with low-priv token
- Role-update via self-API (`PATCH /api/users/me` body `{role:"admin"}`)
- Team-invite hijack (Shopify $15,250)
- Impersonation token replay (GitLab #493324)
- SCIM provisioning abuse (CVE-2025-41115)
- JWT role-claim forge

### 2. Horizontal Access Control
- Sequential ID enumeration (McHire 64M)
- UUID v1 timestamp prediction
- UUID v4 leak via emails, logs, sourcemaps
- Method tampering (GET→POST→PUT→DELETE)
- Object reference in nested objects
- Format/extension trick (`/bugs/12345` 403 vs `/bugs/12345.json` 200)

### 3. Cross-Tenant / Multi-Tenant Breach
- `tenant_id` injection into filter
- SCIM cross-tenant (Grafana)
- GraphQL Relay node-interface bypass
- Org-swap mid-flow (header switch)
- Actor token replay (Entra ID)
- Webhook cross-tenant (Azure Event Grid CVE-2025-59273)

### 4. Mass Assignment / BOPLA
- Top-level field injection: role, is_admin, isAdmin, IsAdmin
- Nested object injection: `{user:{role:"admin"}}`
- Prototype pollution: `{"__proto__":{"is_admin":true}}`
- Array injection: `{"role":["user","admin"]}`
- Type confusion: `{"is_admin":1}` `{"is_admin":"true"}`
- Case bypass: `IsAdmin`, `ROLE`, `IS_ADMIN`, `is-admin`
- KYC/email_verified bypass

### 5. JWT Privilege Escalation
- `alg: none` (still works on ~10% of targets per researcher data 2026)
- RS256 → HS256 confusion
- `kid` path traversal: `../../../dev/null`
- `kid` SQLi: `' UNION SELECT 'secret' --`
- `jku`/`x5u` injection (attacker-controlled JWKS URL)
- Embedded `jwk` in header
- Empty signature on HMAC
- CVE-2022-21449 family ES256 r=s=0
- Refresh token rotation reuse
- CVE-2025-14559 Keycloak token exchange for disabled user

### 6. 403/401 Bypass Tree
- Case manipulation (`/Admin`, `/ADMIN`)
- Double slash, dot-slash, trailing slash, semicolon
- Extension trick (`.json`, `.xml`, `.css`, `.html`)
- Encoded slash/dot (`%2f`, `%2e`)
- Tomcat `;` semicolon (CVE-2025-24813)
- `..;/` path traversal
- API version drift (`/api/v0/`, `/api/_legacy/`)
- Header injection: X-Original-URL, X-Rewrite-URL, X-Forwarded-For: 127.0.0.1, Referer
- Method tampering (GET→OPTIONS reveals via Allow)
- HTTP Method Override (`X-HTTP-Method-Override`, `_method`)

### 7. Email-Confirm / SSO Bridging
- Skip verify step (POST directly to next)
- Replay OLD confirm token
- Modify confirmed-email field
- Domain-based auto-binding to SSO mapping
- Shopify $15,250 pattern → mass shop ATO

### 8. OAuth / OIDC Scope Upgrade
- Token-exchange RFC 8693 with higher scope
- Old refresh token still valid post-rotation
- New RT issued at higher scope than original
- Multi-scope tokens
- `redirect_uri` to attacker Collaborator → JWT leak (2025 case)
- Scope `email_verified` mutable claim trust

### 9. GraphQL BAC
- Introspect → find admin mutations (`createAdminUser`, `deleteUser`, `banUser`)
- Mutation-level RBAC missing (only type-level enforced)
- Field-level authz missing on nested objects
- Aliasing & batching to bypass rate limits + brute force
- Apollo Federation interface-directive bypass
- Relay `node{id}` query returning any entity
- WebSocket GraphQL → SQLi PII leak chain (2026 case)

### 10. Force-Browse / Hidden Endpoints
- robots.txt, sitemap.xml, security.txt
- .well-known directories
- swagger.json, openapi.json, /docs, /redoc, /rapidoc
- JS source map mining (.map files)
- React `lazy()` admin imports
- Wayback Machine + Common Crawl
- katana, hakrawler, gospider with 3-5 depth
- ffuf with SecLists, kiterunner with smart fuzzing
- Mobile app APK/IPA endpoint extraction

### 11. Method Tampering & Verb Tunneling
- GET 403 → POST 200
- `X-HTTP-Method-Override: DELETE`
- `_method=PUT` query param
- HEAD, OPTIONS, TRACE, PROPFIND
- DEBUG (ASP.NET)

### 12. HTTP Parameter Pollution
- Stack-specific: PHP=last, Java=first, ASP.NET=joined, Express=array, Flask=list, Ruby=last
- Duplicate key in JSON: `{"id":"mine","id":"victim"}`
- Array variant: `{"id":["mine","victim"]}`
- Nested mix: `{"user":{"id":"mine"},"user_id":"victim"}`

### 13. Race Condition / TOCTOU (Authz)
- Multi-request burst exploiting check-vs-use gap
- Login flood during high latency (2025 case)
- Invitation accept race
- Plan/tier upgrade race

### 14. Customer-Success / Staff Tool Abuse
- `/staff/lookup?email=X` endpoint in support-page JS bundle
- Test with low-priv → PII dump

### 15. Impersonation / "View-As" Token Retention
- Admin "view as user" issues token; replay after impersonation ends
- Common in support / helpdesk tools

### 16. Feature-Flag / Subscription Manipulation
- `PATCH /api/featureflags {"enable_admin":true}`
- Tier upgrade via client-controlled field

### 17. Second-Order BAC
- Input stored, used later in privileged context
- Scheduled jobs that read user-input IDs without re-auth
- Webhook callback re-using stored secret

### 18. Format/Route Variant Bypass
- `/bugs/12345` 403 vs `/bugs/12345.json` 200 (HackerOne #2487889)
- Rails HTML vs JSON content-type authz mismatch

### 19. WebSocket Authorization Bypass
- WebSocket connection accepts cookie/token but doesn't validate per-message authorization
- Shared-token role declaration
- Cross-user emit (wrong room)
- Pre-init message authz missing (CVE-2025-41254)

### 20. Microservices / Service-Mesh BAC
- Istio/Linkerd authz policies missing on internal services
- mTLS without authz = network identity, not user identity
- Direct service-to-service call bypassing edge auth

### 21. Agentic AI / LLM Authorization (NEW 2025-2026)
- Agent retrieves with its auth, outputs to shared context
- System prompt confusion → IDOR via natural language
- Tool-use with attacker-controlled URL → cross-user data theft
- ServiceNow BodySnatcher: hardcoded secret + email auto-link

---

## CRITICAL CVE INVENTORY (2025-2026)

| CVE | CVSS | Target | Class |
|-----|------|--------|-------|
| CVE-2025-29927 | 9.1 | Next.js middleware | Header-trust auth bypass |
| CVE-2025-55241 | 10.0 | Microsoft Entra ID | Cross-tenant actor token |
| CVE-2025-41115 | 10.0 | Grafana Enterprise SCIM | externalId privesc to admin |
| CVE-2025-12420 | 9.3 | ServiceNow AI Platform | BodySnatcher (email→ATO) |
| CVE-2025-3089 | High | ServiceNow AI | Broken Access Control |
| CVE-2025-3648 | High | ServiceNow | Misconfigured ACLs data exposure |
| CVE-2025-24813 | 9.8 | Apache Tomcat | Path equivalence semicolon RCE |
| CVE-2025-55752 | High | Apache Tomcat | Relative path traversal via RewriteValve |
| CVE-2025-2825 | 9.8 | CrushFTP | X-Forwarded-For=127.0.0.1 auth bypass |
| CVE-2025-41232 | Medium | Spring Security | Method-security annotation on private methods |
| CVE-2025-41248 | Medium | Spring Security | Annotation on parameterized types |
| CVE-2025-41249 | Medium | Spring Framework | Annotation detection in generic hierarchies |
| CVE-2025-41253 | Medium | Spring Cloud Gateway | Actuator SpEL info disclosure |
| CVE-2025-41254 | Medium | Spring WebSocket | STOMP CSRF / pre-init bypass |
| CVE-2025-14778 | High | Keycloak | UMA Protection API horizontal privesc |
| CVE-2025-13881 | High | Keycloak | Admin API unmanagedAttributes bypass |
| CVE-2025-14083 | High | Keycloak | Admin REST schema exposure |
| CVE-2025-14559 | High | Keycloak | Token exchange for disabled user |
| CVE-2025-13526 | 7.5 | OneClick Chat to Order (WP) | Unauth IDOR mass enum |
| CVE-2025-13932 | 8.3 | SolisCloud | Authenticated IDOR plant data |
| CVE-2025-3013 | High | NightWolf Pentest Portal | IDOR access control |
| CVE-2025-14777 | High | Keycloak Admin API | IDOR cross-client resource |
| CVE-2025-59273 | High | Azure Event Grid | Webhook cross-tenant |
| CVE-2025-55205 | 9.1 | Capsule Kubernetes | Namespace label injection cross-tenant |
| CVE-2025-30066 | Critical | tj-actions/changed-files | Compromised action → privesc |

---

## ACADEMIC RESEARCH (2025)

### BACFuzz (arxiv 2507.15984, 2025)
- Grey-box fuzzing + LLM for BAC discovery in web apps
- Disclosed CVE-2024-7437 (WordPress), CVE-2025-8290, multiple PrestaShop
- Tested PHP/SQL stacks, OWASP-aligned

### ACBreaker (Sensors / PMC12074161, 2025)
- LLM-Powered Protected Interface Evasion for IoT BAC
- Analyzed 1,274,646 lines of code across 11 IoT devices
- Discovered 39 previously unknown vulnerabilities

---

## TOOLS & METHODOLOGY (CONFIRMED CURRENT)

### Best Tools 2025-2026
- **Autorize** (Burp BApp Store) — automatic enforcement detector
- **Auth Analyzer** — multi-session simultaneous testing
- **PwnFox** (Firefox) — Firefox Multi-Account Containers (1-8 colors), tabbed Burp coloring
- **nomore403** (github.com/devploit/nomore403)
- **gobypass403** (github.com/slicingmelon/gobypass403) — Go, WAF-parser preserving
- **Burp Bypass-403 extension**
- **Param Miner** — hidden header/param discovery
- **Arjun, ParamSpider, x8, ffuf** — parameter brute
- **kiterunner** — API endpoint smart-fuzzing
- **katana, hakrawler, gospider** — deep crawl
- **LinkFinder, JS Miner** — JS extraction
- **Clairvoyance** — GraphQL when introspection disabled

### Wordlists
- SecLists `Discovery/Web-Content/api/objects.txt`
- SecLists `Discovery/Web-Content/api/api-endpoints.txt`
- SecLists `Discovery/Web-Content/raft-large-words.txt`
- SecLists `Discovery/Web-Content/AdminPanels.txt`
- SecLists `Discovery/Web-Content/Common-PHP-Filenames.txt`

### Jason Haddix Methodology (still updated, 2025)
- Recon Methodology highly recommended for larger scopes
- The Bug Hunter's Methodology Live Course (since 2023)
- Active recon → endpoint mapping → JS analysis → roles/perms mapping → auth-state testing

### Intigriti BugQuest 2026 31-Day BAC Campaign Curriculum
Phase 1 Foundation (Days 1-7): RBAC/ABAC/DAC/MAC models; vertical vs horizontal vs function-level
Phase 2 Discovery (Days 8-15): robots.txt → sitemap → security.txt → .well-known → JS/sourcemap → swagger → mobile APK/IPA → GraphQL introspection
Phase 3 Testing (Days 16-22): method tampering, parameter pollution, keyword swap, JWT confusion, multi-step logic gaps, second-order, path traversal in middleware
Phase 4 Scenarios (Days 23-29): IDOR, keyword/UUID resolution bypass, method-specific protection, GraphQL resolvers, JWT alg confusion, middleware path-traversal, Rails HTML-vs-JSON format authz
Phase 5 Tools (Days 30-31): Firefox Multi-Account Containers + Burp Autorize

---

## KEY DATA POINTS

- **OWASP Top 10:2025**: Total BAC occurrences = 1,839,701; Total CVEs = 32,654; Max incidence 20.15%; Avg exploit 7.04; Avg impact 3.84
- **Bugcrowd 2025**: Critical BAC up 36%; Hardware vulns up 88%; Network vulns 2x
- **HackerOne 2025**: $81M total payouts; 580K+ valid vulnerabilities; AI vuln reports up 210%; prompt injection up 540%; IDOR up 29%
- **Inspectiv 2025**: BAC = 38% of all reports
- **API breach context**: 41% of orgs faced API incident; 63% of those led to data breach; 90% had auth but weak authz

---

## NEW PATTERNS WORTH CALLING OUT

1. **Header trust class** — Next.js's `x-middleware-subrequest` and similar internal-routing headers are the new attack class. Headers that are "internal" but accepted from public traffic.
2. **SCIM provisioning as a backdoor** — SCIM tokens leak from CI/CD, JS bundles, partner integrations. SCIM endpoint trust is universally weaker than user-facing auth.
3. **AI agent shared-context authz** — entirely new attack surface. Agent operates with one set of perms but its output reaches users with different perms. Okta, OpenID Foundation, ServiceNow research 2025.
4. **Method-security annotation parsing in generic types** — JVM ecosystem-wide pattern, applied to Spring 5.x and 6.x.
5. **Apollo Federation interface-directive non-propagation** — first-time-documented schema-design class.
6. **Webhook cross-tenant** — Azure Event Grid CVE-2025-59273 shows webhook configuration leakage class.

---

## SOURCES (selected)

- OWASP Top 10:2025 A01: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
- OWASP API Security: https://owasp.org/API-Security/
- HackerOne disclosed reports authorization tops: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPAUTHORIZATION.md
- McHire IDOR (ian.sh / Sam Curry): https://ian.sh/mcdonalds
- CVE-2025-29927 Next.js: https://nvd.nist.gov/vuln/detail/CVE-2025-29927
- CVE-2025-55241 Entra ID writeup by Mollema: https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/
- CVE-2025-41115 Grafana SCIM: https://grafana.com/blog/grafana-enterprise-security-update-critical-severity-security-fix-for-cve-2025-41115/
- CVE-2025-12420 ServiceNow BodySnatcher: https://appomni.com/ao-labs/bodysnatcher-agentic-ai-security-vulnerability-in-servicenow/
- CVE-2025-24813 Tomcat: https://github.com/threadpoolx/CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat
- CVE-2025-41248 Spring: https://spring.io/security/cve-2025-41248/
- CVE-2025-14778 Keycloak: https://www.sentinelone.com/vulnerability-database/cve-2025-14778/
- Intigriti BugQuest 2026 31 Days of BAC: https://www.intigriti.com/researchers/blog/hacking-tools/bugquest-2026-31-days-of-broken-access-control
- BACFuzz academic paper: https://arxiv.org/pdf/2507.15984
- Inspectiv BAC data: https://www.inspectiv.com/articles/broken-access-control-why-it-tops-both-owasp-and-inspectivs-bug-bounty-reports
- HackerOne Hacker-Powered Security 9th Edition: https://www.hackerone.com/report/hacker-powered-security
- Apollo Federation directive bypass (Feb 2026): https://medium.com/@instatunnel/federated-sub-graph-injection-the-blind-graphql-data-leak-e34b7e88ea48
- Doyensec OAuth common vulns (2025): https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html
