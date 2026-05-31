---
name: hunt-http-smuggling
description: "Hunt HTTP request smuggling (CL.TE, TE.CL, H2.CL, H2.TE). Cause: front-end proxy and back-end server disagree on where one request ends and the next begins (Content-Length vs Transfer-Encoding header parsing inconsistency). CL.TE: front-end uses CL, back uses TE → smuggle by sending TE: chunked but with body that fits CL count. TE.CL: opposite. H2.CL: HTTP/2 downgrade, smuggle CL into HTTP/1.1 back-end. Detection tools: Burp HTTP Request Smuggler extension, smuggler.py, h2csmuggler. Confirm: time-delay technique (smuggled GET with 30s timeout) — if front-end returns slow on next victim request, smuggling works. Validate: cache poisoning chain (smuggle request that gets cached for victim), credential theft (smuggle X-Forwarded-For override that captures next user's cookies), bypass auth (smuggled internal-path request). Real paid examples from major CDN deployments. Use when hunting H1 paid programs running CDN+origin stacks, when targeting load balancer / WAF bypass. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

## 17. HTTP REQUEST SMUGGLING
> Lowest dup rate. $5K–$30K. PortSwigger research by James Kettle.

### CL.TE (Content-Length front, Transfer-Encoding back)
```http
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### Detection
```
1. Burp extension: HTTP Request Smuggler
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Manual timing: CL.TE probe + ~10s delay = backend waiting for rest of body
```

### Impact Chain
```
Poison next request → access admin as victim
Steal credentials → capture victim's session
Cache poisoning → stored XSS at scale
```

---

## Target-Suitability Matrix (2026 reality check)

The classic CL.TE / TE.CL payloads are NOT universally exploitable in 2026. Modern proxies are RFC 9112 strict by default. Fingerprint the front-end BEFORE investing time.

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
|---|---|---|---|---|---|
| **Nginx ≥ 1.21** | NO | NO | partial (H2 ingress) | partial | RFC-strict; rejects CL+TE with HTTP 400. Verified locally on Nginx 1.27 — all 9 documented variants killed by front-end ([docs/verification/phase2h-smuggling-cachepoison.md](../../docs/verification/phase2h-smuggling-cachepoison.md)). |
| **Caddy 2.x** | NO | NO | — | — | Hardened by default |
| **Envoy ≥ 1.20** | NO | NO | partial | partial | Hardened in most paths |
| **HAProxy ≤ 2.4** | ✓ | ✓ | — | — | **Vulnerable**, see CVE-2021-40346 |
| **AWS ALB + specific upstream** | partial | partial | ✓ | ✓ | Several disclosed-paid reports 2022-2024 |
| **Cloudflare → S3 / Lambda chains** | — | — | ✓ | ✓ | H2-downgrade attacks remain viable |
| **Older F5 BIG-IP (TMM < 16)** | ✓ | — | — | — | Vendor advisories |
| **Citrix ADC / NetScaler (older firmware)** | ✓ | ✓ | — | — | Disclosed in 2020-2022 |
| **Squid 3.x** | ✓ | — | — | — | Older deployments |
| **Apache Traffic Server (older)** | ✓ | ✓ | ✓ | ✓ | PortSwigger research |
| **Custom Python / Go proxies** | ✓ | ✓ | — | — | Frequently miss RFC enforcement |

### Operator fingerprint quick-check

```bash
curl -sI https://target/ | grep -i "Server:"
```

- `nginx/1.21+`, `Caddy`, `envoy` → CL/TE classic is dead — pivot to H2.CL/H2.TE if the front-end speaks HTTP/2, or look for legacy proxies upstream
- `HAProxy`, header points to AWS/CDN → run the full payload matrix
- No Server header → assume hardened, but run a single quick `space-before-colon` probe; if it doesn't 400, dig deeper

### H2.CL / H2.TE (the modern dominant vector)

H2-downgrade smuggling attacks rely on the front-end speaking HTTP/2 to the client and HTTP/1.1 to origin. The downgrade introduces CL/TE confusion because HTTP/2's frame-length headers don't survive the conversion cleanly. Most CDN+origin chains in 2024-2026 use this exact topology.

Tools that send HTTP/2 raw frames (Burp Pro's HTTP Request Smuggler extension, `h2csmuggler`, `smuggler.py`) are the right starting point against CDN-fronted targets. Avoid HTTP/1.1-only test clients (curl, raw sockets) against H2-front-ended targets — you'll send the wrong protocol entirely.

---

## Related Skills & Chains

- **`hunt-cache-poison`** — Smuggling + cache is the canonical critical chain; one smuggled request becomes the cached response for every subsequent victim. Chain primitive: CL.TE smuggle a request whose response body contains attacker HTML/JS → front-end cache stores it under a popular URL (`/`, `/login`) → de-sync poisoning where the smuggled request becomes the cached response for the next N victims, persisting for the cache TTL.
- **`hunt-auth-bypass`** — Smuggling reaches internal-only routes that the front-end WAF/auth-proxy filters out. Chain primitive: smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*` → backend processes the smuggled request as if from a trusted internal source → bypass front-end auth by smuggling internal-routed request → admin data in the response queue.
- **`hunt-idor`** — Smuggling attaches the NEXT user's session cookies to an attacker-controlled request path. Chain primitive: smuggle `GET /api/me HTTP/1.1` with no cookies → backend pairs it with the next legitimate user's incoming connection cookies → victim's session cookie attached to attacker's smuggled request → attacker reads the response containing victim's PII/tokens.
- **`hunt-xss`** — Smuggling injects XSS payloads into the response stream of the next victim without ever appearing in a URL parameter. Chain primitive: smuggled request body contains reflected payload that the backend renders into the next response in the queue → next visitor to `/` receives attacker HTML inline → reflected XSS at every visitor without any URL parameter visible to them or to logs.
- **`security-arsenal`** — Reach for the smuggling payload bank (CL.TE / TE.CL / TE.TE obfuscations, H2.CL downgrade probes, h2csmuggler one-liners, Burp HTTP Request Smuggler extension config) and the time-delay confirmation template before manual hex-editing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the smuggled-request effect MUST land on a request issued by a different client/session, not your own follow-up. A timing delta in your own browser alone is parser disagreement, not exploitable smuggling.



## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle

## Real-World HackerOne Disclosed Reports

Top techniques observed in disclosed HackerOne reports for this vuln class:

| # | Technique | Target | Bounty | Source |
|---|-----------|--------|--------|--------|
| 1 | Bypass for #488147 enables stored XSS on paypal.com/signin (smuggling chain) | PayPal | $20,000 | H1 #510152 |
| 2 | Stored XSS on paypal.com/signin via cache poisoning + smuggling | PayPal | $18,900 | H1 #488147 |
| 3 | HTTP Request Smuggling via HTTP/2 (H2.CL downgrade) on Basecamp | Basecamp | $7,500 | H1 #1211724 |
| 4 | HTTP Request Smuggling in Cloudflare Transform Rules via hex escapes in concat() | Cloudflare | $6,000 | H1 #1478633 |
| 5 | HTTP request smuggling on canpol.deti.mail.ru | Mail.ru | $5,000 | H1 #957881 |
| 6 | Apache Tomcat HTTP Request Smuggling - Client-Side Desync (CVE-2024-21733) | IBB / Tomcat | $4,660 | H1 #2327341 |
| 7 | Pause-based desync in Apache HTTPD | IBB / Apache | $4,000 | H1 #1667974 |
| 8 | HTTP request smuggling via newlines in Cloudflare Origin Rules host_header param | Cloudflare | $3,100 | H1 #1575912 |
| 9 | Password theft on login.newrelic.com via Request Smuggling (CL.TE) | New Relic | $3,000 | H1 #498052 |
| 10 | Apache mod_proxy_ajp request smuggling | IBB / Apache | $2,400 | H1 #1594627 |

**High-confidence patterns (3+ reports):**
- **CL.TE / TE.CL parser disagreement** — classic primitive in PayPal $20k/$18.9k, New Relic $3k (password theft), Slack mass ATO, Zomato X-Access-Token bulk theft, LINE admin ATO. Front-end uses `Content-Length`, back-end uses `Transfer-Encoding` (or vice-versa). Smuggle prefix `GET /victim HTTP/1.1\r\nCookie:` so the next user's request body becomes the smuggled URL/cookie.
- **HTTP/2 downgrade (H2.CL / H2.TE)** — Basecamp $7.5k, multiple Cloudflare. Front-end speaks H2 to client and HTTP/1.1 to backend. Send H2 frames with conflicting `content-length` pseudo-header vs body length -> backend desync. Use `h2csmuggler` / Burp's HTTP/2 probe.
- **Transfer-Encoding obfuscation (TE.TE)** — Node.js x6, Ruby webrick, Apache Tomcat. Send two `Transfer-Encoding` headers or whitespace/case-mutated variants (`Transfer-Encoding: chunked`, `Transfer-encoding : chunked`, `Transfer-Encoding:[tab]chunked`). One proxy honors it, the other doesn't.
- **Pause-based / client-side desync** — Apache HTTPD $4k, Tomcat $4.66k, Cloudflare $6k. The browser itself becomes the desync vector by sending a partial request that the front-end queues until a follow-up arrives. Triggers victim-browser-driven exploitation without needing a shared connection pool.
- **Smuggling -> cache poisoning chain (highest payouts)** — PayPal $20k + $18.9k both chained smuggling -> cached stored XSS on /signin. Always test if the smuggled response gets cached; that single chain step turns $500 smuggling into a five-figure stored-XSS bounty.
- **Smuggling -> credential / session theft** — Slack (864 upvotes, mass ATO), Zomato X-Access-Token bulk, LINE admin ATO, New Relic password theft $3k. Smuggle a request whose response steals the NEXT user's auth header attached by the backend.

