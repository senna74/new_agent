# IDOR Research Findings (2025-2026)

Comprehensive research synthesis from 50+ web sources, used to rewrite SKILL.md.

## Executive Summary

- **OWASP Top 10 #1** (web) and **OWASP API Security #1** (BOLA) — unchanged 2019→2026.
- **HackerOne 2025 HPSR**: access-control / IDOR variations rose 18–29% YoY.
- **$81M paid by HackerOne** in past 12 months (13% YoY growth).
- IDOR is the #1 reported class in: government (18%), medical (36%), professional services (31%), retail/ecommerce (15%).
- Average bounty: $1.5k–$5k; chains to ATO/cross-tenant → $10k–$50k.

## Mega-Scale 2025 Incidents

### McHire (McDonald's) — 64M records, June 30, 2025
- Researchers: Ian Carroll + Sam Curry.
- Entry: default creds `123456:123456` at `mchire.com/signin` (Paradox team-member login).
- **Exact vulnerable endpoint**: `PUT /api/lead/cem-xhr`
- **Vulnerable parameter**: `lead_id` (highest observed ~64,185,742)
- Decrement → full PII (name, email, phone, address) + chat transcripts + auth tokens → consumer-UI impersonation.
- Disclosure → fix in 38 minutes (creds disabled); full fix < 24 hours.
- Lesson: default creds + sequential int + admin proxy endpoint = catastrophic IDOR.

### CVE-2025-13526 — OneClick Chat to Order WordPress plugin
- Affected: ≤ v1.0.8 (~thousands of WP stores).
- Function: `wa_order_thank_you_override` trusts `order_id` URL param without auth check.
- **Pre-auth** mass enumeration → names, emails, phones, billing/shipping addresses, order items, payment-method metadata.
- CVSS 7.5 (High). Fixed in 1.0.9.

### CVE-2025-65017 — Decidim private exports
- Versions ≥ 0.30.0 and < 0.30.4.
- UUID collision (ActiveStorage record_id stored as bigint → conversion loss).
- ~2.3% theoretical collision rate; private exports become cross-readable.

### CVE-2025-31481 — API Platform GraphQL Relay node bypass
- API Platform Core < 4.0.22 (also < 3.4.17).
- `node(id: "/books/1")` bypasses security checks that `book(id: "/books/1")` enforced.
- Root cause: `ResolverFactory.resolve` creates a new Query operation without re-running security.
- CVSS 7.5.

### CVE-2024-46528 — KubeSphere
- Versions 3.0.0–3.4.1 and 4.x < 4.1.3.
- Excessive `authenticated` GlobalRole → low-priv read of cluster monitoring + user lists.
- Reporter: Okan Kurtuluş.

### CVE-2025-12030 — ACF to REST API WordPress
- Authenticated contributor-level → modify ACF fields on any object (not just own).
- Mass-assignment class IDOR.

### CVE-2025-3013 — NightWolf Penetration Testing Customer Portal < 2.1.4
- IDOR in access control via parameter/object-reference manipulation.

### CVE-2025-13808 — Orionsec Orion-ops
- User Profile Handler auth bypass, network-exploitable, no auth required.

### CVE-2025-52389 — Envasadora H2O Soda Cristal v40.20.4
- Unauthenticated IDOR → sensitive other-user data via crafted HTTP request.

### CVE-2025-51533 — Sage DPW ≤ v2024_12_004
- Unauthorized access to internal forms via crafted GET.

### CVE-2025-65672 — ClassroomIO v0.1.13
- Student (non-priv) → restricted Course Settings via missing auth checks.

### CVE-2026-41277 — Flowise DocumentStore mass-assignment + IDOR
- Affects flowise ≤ 3.0.13 and 3.1.0.
- `POST /api/v1/document-store` with `id` from Workspace A → implicit UPSERT migrates store to attacker's workspace.

### Chamilo LMS — March 2026 — Learning Path progress IDOR (CVSS 7.1).

## CORRECTION FROM PREVIOUS SKILL
- **Pandora/Viper car alarms IDOR was 2019, NOT 2025.** Original skill claimed 2025. Verified: TechCrunch / SecurityWeek dated March 2019. Still a good "physical safety class" example but date corrected.
- McHire endpoint was `PUT /api/lead/cem-xhr` (not `/api/leads/{id}`). Corrected.

## Top HackerOne Disclosed IDOR Reports (top 251 mined)

### Tier S — $10k+ bounty
- **#415081 PayPal** — Add secondary users to any business account — **$10,500** (781 upvotes)
- **#2122671 HackerOne** — GraphQL `CreateOrUpdateHackerCertification` delete-by-id — **$12,500** (381 upvotes)

### Tier A — $5k+ bounty
- **#1066203 Stripe** — GraphQL cross-tenant on `UpdateAtlasApplicationPerson` (24 upvotes, undisclosed amount but listed as $0 in dataset — confirmed paid in disclosure narrative)
- **#2207248 Shopify** — GraphQL `billingDocumentDownload(id: ...)` IDOR — **$5,000** (176 upvotes)
- **#1658418 Reddit** — Mod logs for any subreddit via `subreddit=` param — **$5,000** (153 upvotes)

### Tier B — $1k+
- **#380410 Pornhub** — Delete photos/albums — **$1,500** (266)
- **#681473 Pornhub** — Edit anyone's videos — **$1,500** (248)
- **#186279 Pornhub** — Private video disclosure — **$1,500** (32)
- **#1966006 Unikrn** — Cashier `/cashier/info?user_id=N` PII enum — **$3,000** (226)
- **#723461 Mail.ru** — Order delivery address — **$3,000** (125)
- **#349291 New Relic** — `internal_api/users` enumeration — **$1,500** (77)
- **#459443 New Relic** — Insights dashboard filter — **$2,500** (28)
- **#419875 New Relic** — Alerts/synthetics user-name leak — **$1,500** (14)
- **#476958 New Relic** — Full-name disclosure via sharing — **$750** (6)
- **#2528293 GitLab** — ML models cross-project — **$1,160** (106)
- **#2218334 HackerOne** — Unreleased Copilot GraphQL `DestroyLlmConversation` — **$2,500** (CVSS 7.0)
- **#1392630 TikTok** — Seller platform support ticket access — **$2,500** (73)
- **#1410498 Judge.me** — Buyer info + comments — **$1,250** (44)
- **#484339 Mail.ru** — Change user address — **$1,000** (33)
- **#56511 Shopify** — Expire other-user sessions — **$1,000** (29)
- **#243943 Shopify** — Partners shop info / staff leak — **$500** (32)
- **#853130 Shopify** — Stocky settings — **$750** (12)
- **#1372216 GitLab** — External status check API data — **$610** (33)
- **#46397 HackerOne** — General — **$500** (8)

### Tier C — $500
- **#1559739 TikTok** — Ads report download — **$500** (23)
- **#2848610 TikTok** — Unauthorized product addition — **$500** (127)
- **#2381816 Tools for Humanity** — `FetchMemberships` team-data — **$500** (85)
- **#1213765 Reddit** — Coin purchase manipulation — **$500** (41)
- **#754044 Razer** — Razer Pay `queryDrawRedLog` — **$500** (12)
- **#790829 Razer** — `eform.molpay.com` IDOR — **$500** (21)
- **#1626508 DoD** — Document download soldier PII — **$500** (73)
- **#1323406 Affirm** — View other-user orders — **$500** (83)
- **#404797 Eternal/Zomato** — Delete store images — **$600** (66)
- **#194790 Open-Xchange** — Attachment downloads — **$888** (26)
- **#204984 Open-Xchange** — File saveAs — **$888** (20)
- **#285432 Open-Xchange** — `setAttribute` API — **$400** (13)
- **#199321 Open-Xchange** — Signature deletion — **$300** (20)

### Tier D — Notable disclosed (varied amounts)
- **#3219944 SingleStore** — `GetNotebookScheduledPaginatedJobs?projectID=VICTIM` — second-order IDOR (75 upvotes)
- **#3560256 GitHub** — Cross-repository: modify `secret_scanning push_protection_delegated_bypass_reviewers` of other repo via `owner_id` body param (50 upvotes)
- **#3401612 Revive Adserver** — Banner-deletion IDOR; any Manager deletes any other Manager's banners (47 upvotes)
- **#3154983 Mozilla** — Account deletion via session-misbinding (232 upvotes)
- **#3085742 Bykea** — Hardcoded zombie endpoint in mobile app (125 upvotes)
- **#2968039 Autodesk** — GraphQL `deleteProfileImages(id:...)` mutation (75)
- **#2965357 Autodesk** — Profile info exposure (70)
- **#2944357 Yelp** — Reservation cancellation (74)
- **#2487889 HackerOne** — `/bugs.json` private-report disclosure (252 upvotes — "route variant trick")
- **#2633771 HackerOne** — `AddTagToAssets` (167)
- **#915114 Automattic** — CrowdSignal IDOR → ATO via email edit (200)
- **#950881 Automattic** — Email-editing → ATO (48)
- **#1695454 Automattic** — API tokens + ATO (54)
- **#2132183 Mars** — `member_id` ATO (40)
- **#876300 Starbucks** — Singapore ATO via PHPSESSID cross-site cookie copy (257)
- **#1063022 Uber** — Cross-tenant business privesc (29)
- **#984965 TikTok** — `AddRulesToPixelEvents` cross-tenant pixel rules (83)
- **#1475520 TikTok** — Delete tickets on `ads.tiktok.com` (214)
- **#1733627 TikTok** — Memory privacy settings via `aweme_id` (119)
- **#1559739 TikTok** — Reports download (23)
- **#1527906 TikTok** — Ads endpoint (108)
- **#1509057 TikTok** — Seller platform (30)
- **#1586950 TikTok** — Family pairing API (41)
- **#391092 Yelp** — Link victim's credit card to attacker's order — composite IDOR (212)
- **#358143 Yelp** — Link other user's credit card (86)
- **#361984 Yelp** — Edit credit card info (31)
- **#2381816 Tools for Humanity (Worldcoin/World)** — `FetchMemberships` team leak (85)
- **#544329 X/xAI** — Order + statistics leak (140)
- **#1096560 X/xAI** — Add images to issues (64)
- **#1969141 HackerOne** — Delete campaigns (344 upvotes)
- **#262661 HackerOne** — Feedback review (77)
- **#291721 HackerOne** — Program visibility (32)
- **#510759 HackerOne** — Report CSV export (66)
- **#663431 HackerOne** — Bugs overview (32)
- **#2456603 IBM** — HTTP method-bypass IDOR (53)
- **#1085782 DoD** — PHI/PII exposure (29)
- **#2967032 DoD** — Tens of thousands PII (15)
- **#1687415 DoD** — Email-edit mass ATO (17)
- **#685338 DoD** — Unauthenticated IDOR mass ATO (17)
- **#969223 DoD** — Account takeover (26)
- **#847876 Mail.ru** — Driver logs city-mobil — **$150** (20)
- **#923851 Mail.ru** — Dictor.mail.ru contracts — **$150** (16)
- **#312555 Mail.ru** — mcs.mail.ru — **$150** (14)
- **#328337 Mail.ru** — widget.support.my.com (22)
- **#850637 Mail.ru** — Chat messages — **$150** (6)

## Modern Bypass / Discovery Techniques (2025-2026)

### Parameter Pollution (HPP) for IDOR Bypass
- Some frameworks: first value wins; others: last value wins; others: array.
- `?user_id=mine&user_id=victim` → server-side WAF/auth checks first value, backend uses last.
- JSON body equivalent: `{"user_id":"mine","user_id":"victim"}` — many JSON parsers keep last.

### JSON Glob / Type-Confusion (Intigriti)
- Array: `{"id":[1234]}`, `{"id":[1234,1235]}`
- Object wrap: `{"id":{"value":1235}}`
- Boolean: `{"id":true}`
- Wildcards: `{"id":"*"}` / `{"id":"%"}` / `{"id":null}` / `{"id":""}`
- Leading zeros: `{"id":"00001235"}`
- Negative: `{"id":-1}` (sometimes admin)
- Decimal: `{"id":1235.0}` (parses different than 1235)
- Delimited: `{"id":"1234,1235"}`

### Content-Type Manipulation
- Same endpoint with `Content-Type: application/xml` vs `application/json` vs `application/x-www-form-urlencoded` → different parser path → different auth middleware.

### "current" / "me" / "self" → numeric substitution
- Endpoints accepting `/api/users/me` often also accept `/api/users/{n}` if the placeholder is server-side resolved late.
- Try `current`, `me`, `self`, `mine`, `_me`, `default`, `0`, `1`, `-1`.

### X-Original-URL / X-Rewrite-URL header injection
- IIS / reverse proxy honors these.
- `GET /api/v5/admin/99` with `X-Original-URL: /api/v5/admin/100` → backend serves 100, edge auth keyed on 99.
- Variants: `X-Forwarded-Path`, `X-Override-URL`, `X-HTTP-Path-Override`.

### Path normalization / dual-decode tricks
- `/api/v5/user/22652/../1` — different normalization layers
- URL-encoded `%2e%2e` and double-encoded `%252e%252e`
- `/api/user/22652%2F../../1`
- Null byte: `/api/user/22652%00.json`

### Route variants (the .json/.xml/.csv trick — H1 #2487889)
- `/reports/{id}` → 403
- `/reports/{id}.json` → 200 (privacy check only on HTML controller)
- Also: `.xml`, `.csv`, `.pdf`, `/raw`, `/preview`, `/export`, `/download`, `/print`
- Version drift: `/api/v1/reports/{id}` 403 vs `/api/v2/reports/{id}` 200 (or vice versa)
- Prefix swaps: `/api/internal/reports`, `/api/_legacy/reports`, `/api/mobile/reports`, `/api/private/reports`

### Method tampering
- GET 403 → POST/PUT/PATCH/DELETE/HEAD/OPTIONS 200
- Override headers: `X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`, body `_method=DELETE`
- IBM #2456603 pattern.

### URL Shortener bypass (Detectify research)
- Submit attacker-controlled shortener → resolved server-side → SSRF + IDOR composite.

### Session Poisoning IDOR (Intigriti)
- One feature overwrites session vars, another feature reads them without re-auth → second-order IDOR via session reuse.

## Hidden ID Locations (Expanded for 2026)

### HTTP Headers
```
X-User-ID, X-Account-ID, X-Org-ID, X-Tenant-ID, X-Workspace-ID,
X-Customer-ID, X-Impersonate, X-On-Behalf-Of, X-Subject-Token,
X-Selected-Tenant, X-Actor-Id, X-Switch-User, X-Sudo-User,
X-Original-URL, X-Rewrite-URL, X-Forwarded-Path, X-Forwarded-User
Authorization: Bearer (decode JWT, look at `sub` / `acct` claims)
```

### JSON body keys (extensive)
```
user_id, owner_id, created_by, target_user_id, recipient_id,
on_behalf_of, acting_as, actor.id, audience[], scope.org_id,
delegate_id, principal_id, subject_id, assigned_to,
proxy_id, impersonate, masquerade, sudo_user, switch_user,
member_id, customer.id, account.id, business.id, tenant.id,
workspace.id, project.id, team.id, group.id, channel.id,
space.id, organization.id, division.id, branch.id
```

### Cookies
- Direct ID: `user_id=12345`, `account=67890`
- Serialized state: `prefs={"selected_org":"ORG_A"}`
- Session cookie value swap (Starbucks H1 #876300 pattern — cross-site cookie copy)

### GraphQL (expanded 2026)
```graphql
# Variables
{"variables":{"userId":"X","input":{"ownerId":"X"}}}

# Inline
{ user(id:"X"){...} }
{ orders(filter:{userId:"X"}){...} }

# Relay node interface
{ node(id:"T3JkZXI6MTIzNDU="){...on Order{customer{email}}} }
{ nodes(ids:["a","b","c"]){...} }

# Alias batching (rate-limit bypass — Turbo Intruder pattern)
{ a1:user(id:"1"){email} ... a10000:user(id:"10000"){email} }

# WebSocket subscriptions (under-tested)
{"type":"start","payload":{"query":"subscription{ msg(threadId:\"VICTIM\"){ content sender }}"}}

# Mutation IDOR (2024-2026 top class)
mutation { deleteCampaign(id:"VICTIM"){ok} }
mutation { destroyLlmConversation(id:"VICTIM"){ok} }  # H1 #2218334 pattern
mutation { deleteProfileImages(id:"VICTIM"){ok} }    # H1 #2968039 pattern
mutation { addTagToAssets(assetId:"VICTIM"){...} }   # H1 #2633771 pattern
```

### WebSocket frames
```
{"type":"subscribe","channel":"user:VICTIM"}
{"type":"join","room":"org-VICTIM"}
{"action":"watch","resource":"invoice:VICTIM"}
```

### Multipart / form-data
```
Content-Disposition: form-data; name="user_id"\r\n\r\n12345
Content-Disposition: form-data; name="ownerId"\r\n\r\n12345
Content-Disposition: form-data; name="actId"\r\n\r\nVICTIM
```
- A $5k bug bounty was found in multipart `actId`/`njfbRefNo` parameters (referenced in writeups).

### URL path segments (mobile/legacy zombie)
- `/uploads/user_12345/file.pdf` — IDOR via path swap
- `/storage/{tenant}/{user}/doc`
- `/static/avatars/{user_id}.jpg` — public but pivots to private

### Indirect / second-order
- Return IDs from list endpoint → reuse in detail endpoint as different user
- Webhook callbacks contain object IDs → register attacker URL → harvest
- Async export → ticket-ID → poll as different user
- Scheduled jobs store user_id at create-time → run later without re-auth (SingleStore template)
- Email notification HTML body contains UUIDs → harvest

## UUIDv1 Sandwich Attack (deeper detail)

The "sandwich" pattern from Realize Security / AppSec Labs / NullSecurityX / landh.tech:

1. Attacker triggers reset on **own account** at T1 → captures UUID-A (top "bread").
2. Attacker triggers reset on **victim** at T1+Δ → victim's UUID (the "filling") generated.
3. Attacker triggers reset on **own account** at T1+2Δ → captures UUID-B (bottom "bread").
4. UUIDs are time-monotonic per node; victim's UUID lies between UUID-A and UUID-B.
5. Decompose UUID = 60-bit timestamp + 14-bit clock_seq + 48-bit MAC.
   - MAC = constant per-server → known from UUID-A.
   - clock_seq → bounded by A and B.
   - timestamp → bounded by A.timestamp ≤ victim.timestamp ≤ B.timestamp.
6. Brute-force the bounded interval (typically 50ms–5s → 100k–500k candidates) against `/password/reset?token=`.
7. Tool: **uuidv1_exploit** (github.com/ilanr/uuidv1_exploit) + **UUIDv1 Sandwicher** (referenced by NullSecurityX).

Real cases: landh.tech "0 Click ATO with the Sandwich Attack" 2023; AppSec Labs walkthroughs 2024-2025.

### UUIDv1 mitigation insight (Mohamed AboElKheir)
- Switch to UUIDv4 (122 random bits).
- For DB performance, use UUIDv7 as PK but UUIDv4 as external/exposed ID.
- UUIDv47 (SipHash UUIDv7 → UUIDv4-shape) is a 2025 academic proposal.

## Snowflake ID Predictability

- Twitter/X Snowflake = 41-bit timestamp + 10-bit machine + 12-bit sequence.
- Future IDs predictable from time and machine fingerprint.
- Discord, Twitter tweets, DMs, lists, all object types — all snowflakes.
- If an app uses Snowflake for share-link tokens / reset tokens / private invite IDs without secondary auth → enumerate by guessing timestamp + sequence.

## GraphQL Alias-Batching Mass Enumeration

- PentesterLab + Checkmarx + Escape research show:
- Send 10,000 aliases in a single HTTP request → bypass rate-limit-per-HTTP-request defenses.
- Turbo Intruder reduces a 1B-request attack to 100k via batching (Checkmarx case study).
- CrackQL (github.com/nicholasaleks/CrackQL) — purpose-built GraphQL brute-force tool.
- Defense (rarely deployed): limit array-batching to 5–10, alias-count to 20, body-size cap.

## API Gateway IDOR Pattern

- Gateway enforces auth on **path** + **token presence**, not **(token, object) tuple**.
- Backend microservice trusts upstream call → object look-up succeeds.
- Test: hit gateway with B's token + A's object → service-to-service call leaks.
- Bypass: find direct origin (often via JS bundle leak) → call service directly, no gateway involvement.

## LLM/AI Era IDOR (2026 trends)

### IDOR-via-AI patterns
- Chatbot reads other-user data because system prompt confused with user prompt.
- Agentic copilot has tool that queries by ID → user prompt injects victim's ID → leak.
- RAG retrieves cross-user docs because vector store partition missing tenant filter.
- AI feature with conversation_id IDOR — H1 #2218334 (HackerOne's own Copilot mutation).
- McHire (2025) — biggest precedent: AI chatbot session API → 64M leak.

### BOLABuster (Unit 42 / Palo Alto Networks)
Five-stage LLM-driven BOLA detection:
1. Identify endpoints accepting ID parameters returning sensitive data.
2. Map producer→consumer dependency graph from OpenAPI spec.
3. Generate execution paths (multi-call sequences).
4. Convert to bash test scripts using ≥2 authenticated user contexts.
5. Run + flag 200-with-other-user-data; human triage.

Discovered: CVE-2024-1313 (Grafana cross-org dashboard delete), CVE-2024-22278 (Harbor maintainer→admin), 15 Easy!Appointments BOLAs.

### Semgrep AI-Powered Detection (Nov 2025)
- 1.9× recall vs Claude Code alone.
- Claude Code standalone: 22% TP rate (13/59 findings).
- OpenAI models: 0–4.5%.
- LLMs strong at: absent-authz, single-file logic.
- LLMs weak at: cross-file RBAC, framework-implicit auth, decorator-based controls.
- **For human hunters**: LLM AI tools will flood with FPs; the un-checked, single-function-scope IDORs LLMs find easily → assume devs may auto-fix soon → hunt cross-file and framework-implicit gaps for premium bounties.

## Best Tooling (Updated 2026)

| Tool | Use |
|------|-----|
| Autorize (Burp BApp) | Auto-replay every request with B's cookie while browsing as A |
| AuthMatrix (Burp) | Matrix table of users × requests; click-to-run permutations |
| PwnFox (Firefox + Burp) | Per-tab containerized identities; color-coded in Burp |
| Auth Analyzer (Burp) | Newer alternative to Autorize, finer-grained rules |
| jwt_tool | JWT alg=none, kid traversal, claim tampering |
| uuidv1_exploit / UUIDv1 Sandwicher | UUIDv1 prediction |
| CrackQL | GraphQL alias-batch brute force |
| Turbo Intruder | High-throughput Burp brute force with alias batching |
| jadx-gui / apktool | Android APK decompilation |
| Frida | Runtime mobile API instrumentation (encrypted bodies) |
| MobSF | Mobile static analysis |
| BOLABuster (research) | OpenAPI → LLM-driven BOLA finder |
| Hadrian / APIsec / Salt | Commercial automated BOLA scanners |
| Escape Agentic DAST | AI-driven business-logic finder |

## Killer Chains (2026 update)

### McHire-class chain (mass PII)
1. Find admin-portal default creds (`/_admin`, `/_internal`, `/staff/login`, `/dashboard/login`).
2. From any authenticated context, look for `lead_id`, `applicant_id`, `customer_id`, `member_id` accepting numeric param.
3. Decrement to 1 — enumerate full range — extract PII per HIT.
4. Critical-tier on first 100 hits; submit.

### Cross-tenant org-OWNERSHIP-takeover chain
1. Sign up Org B.
2. Find org-A's tenant_id via leaked email/webhook/SAML metadata.
3. `POST /api/orgs/ORG_A/members` body `{"role":"OWNER","email":"attacker"}` from Org B session.
4. Attacker becomes Org A owner — full takeover (Shopify Partners pattern, ~$15k tier).

### Mass-assignment + IDOR composite (Flowise / Shopify pattern)
1. POST a "create" endpoint with a primary-key field (`id`, `uuid`, `slug`) supplied by attacker.
2. Backend treats as UPSERT → existing object's ownership moved to attacker (Flowise DocumentStore — CVE-2026-41277).
3. Send PATCH on victim's object now in attacker's workspace → state change.

### IDOR → ATO via 2FA disable
1. `POST /api/users/VICTIM/disable-2fa` from attacker session (blind IDOR — no response data).
2. Trigger password reset for victim (their email).
3. Reset succeeds (2FA disabled).
4. Caveat: only works if 2FA-disable doesn't require current password + cur 2FA — often the case in mobile/admin UIs.

### IDOR → SSRF chain
1. Attacker triggers webhook/preview/import with arbitrary URL.
2. Bound to ID stored at request time.
3. Worker fetches URL using saved context → leaks `http://169.254.169.254/...` → IMDS → cloud creds.
4. Worker-side second-order SSRF often bypasses initial URL allowlist that runs on creator's side only.

### .json route variant chain (H1 #2487889)
1. `GET /bugs/{N}` → 403.
2. `GET /bugs/{N}.json` → 200 with full report body.
3. Loop → mass private-report disclosure.

### GitHub cross-repo IDOR (#3560256)
1. Attacker admin in Repo A.
2. `PATCH /repos/A/secret-scanning/push-protection/delegated-bypass-reviewers` with `{"owner_id": "REPO_B_OWNER"}`.
3. Server applies change to Repo B — attacker is now reviewer there.

### Reservation-IDOR composite (Yelp #391092)
1. IDOR-1: Attacker creates order with victim's `payment_method_id`.
2. IDOR-2: Confirmation skips re-validating PM ownership.
3. → Free meal on victim's CC.

### SingleStore second-order (#3219944)
1. `GET /api/v1/notebook/scheduled-jobs?projectID=VICTIM_PROJECT`.
2. Returns job config including stored DB creds / API tokens.
3. Use creds to access victim's internal services laterally.

## Validation Gate Refinements (2026)

### What still gets rejected
- 200 with empty array
- 200 with redacted fields ("***")
- 200 returning attacker's own data regardless of supplied ID
- Public-by-design resources (blog posts, public profiles)
- 404 on guessed UUIDv4 with no enum path
- Single self-only access
- "Could be exploited at scale" without dump
- "Behind admin login" without valid low-priv account

### Triage-fast wins (modern bar)
- Concrete victim PII (name + email + phone OR full address OR SSN)
- ≥10k enumerable hits (or arithmetic proof)
- State-change you can re-verify as victim
- Cross-tenant proof: org-A's data fetched from org-B session, both newly created during PoC
- ATO chain: end-to-end victim login from attacker-only initial state

## Anti-Patterns Specific to LLM-Triaged Programs (2026)
- Don't write "could potentially allow" — LLM triagers downgrade these aggressively.
- Show the verbatim curl + response and the differential in three lines.
- Avoid generic "could be chained" — show the actual chained PoC.
- "Bypassing rate-limit via GraphQL aliasing" without target PII = often closed as info.

## Confidence-Scoring Heuristic (for self-triage)

Score each finding 0.0-1.0; only submit if ≥ 0.85:

| Criterion | Weight |
|-----------|--------|
| Other-user data visible in response | 0.25 |
| Enumeration scale > 100 | 0.10 |
| Two independent accounts in PoC | 0.10 |
| Reproduces in < 10 min from zero | 0.10 |
| PII or financial impact | 0.20 |
| State-change verified as victim | 0.10 |
| ATO chain demonstrated | 0.15 |

(Sum = 1.0; require 0.85)

## OWASP Top 10 / API Top 10 Alignment (2026)

- **OWASP Top 10 #1**: Broken Access Control (A01:2025) — includes IDOR.
- **OWASP API Security Top 10**: BOLA (API1:2023) — IDOR's API-specific framing.
- **CWE-639**: Authorization Bypass Through User-Controlled Key — KubeSphere CVE-2024-46528.
- **CWE-862**: Missing Authorization.
- **CWE-863**: Incorrect Authorization.
- **CWE-913**: Improper Control of Dynamically-Managed Code Resources (mass-assignment).

## Cross-References Updated

- `hunt-bac-privesc` — BAC parent skill
- `hunt-graphql` — Relay node, alias batching, mutations
- `hunt-ato` — IDOR → email-change → reset → ATO chain
- `hunt-mass-assignment` (if exists) — mass-assignment + IDOR composite
- `hunt-jwt` — JWT sub-claim tampering
- `hunt-second-order` — Scheduled jobs, webhooks, async
- `hunt-business-logic` — Composite chains (Yelp CC + reservation)
- `hunt-api-misconfig` — Zombie endpoints, hidden params
- `hunt-websocket` — WS-frame IDOR
- `hunt-metadata-ssrf` — IDOR → SSRF cloud creds chain
