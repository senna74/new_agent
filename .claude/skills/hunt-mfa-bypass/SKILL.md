---
name: hunt-mfa-bypass
description: "Modern MFA/2FA bypass hunting (2025-2026). Use when target has TOTP/SMS/Email/Push/WebAuthn 2FA. Covers response manipulation (success:false→true), status code tampering (403→200), brute-force on weak rate-limits, backup-code reuse, OTP code reuse, race conditions on OTP validation, MFA-step skip via direct nav, recovery-code dump via /api/me, factor downgrade (TOTP→SMS), session-not-invalidated bug, password-change-without-MFA chain. PoC: attacker session reaches post-MFA state without performing MFA. Skip if MFA is fully enforced with WebAuthn-only and rate-limited."
---

# MFA / 2FA Bypass Hunt — 2025-2026 Powerful Edition

MFA bypass on a payments / SaaS app pays $1k–$15k. Chain with leaked credentials (breach corpus, password spray) = full ATO without device. Most MFA implementations have at least one of the 12 holes below.

> **PoC bar:** Attacker session post-login skips MFA challenge AND reaches authenticated state. Demonstrate by reaching `/dashboard` without entering OTP.

---

## 0. 60-Second Recon

```bash
# Map MFA flow
# 1. Try to log in with test account that has MFA enabled
# 2. Capture every request/response in the flow:
#    POST /login → 200 {"mfa_required":true, "mfa_token":"X"}
#    POST /mfa/verify → with OTP code
#    POST /mfa/verify → returns session cookie / JWT
# 3. Note all state transitions
```

**Fingerprint:**
- Factor types: TOTP (Google Authenticator), SMS, Email OTP, Push (Duo/Auth0 Guardian), WebAuthn, Backup codes, Recovery codes
- Code length: 4 (weak), 6 (standard), 8 (better)
- Lifetime: 30s (TOTP), 5 min (SMS), 1 hour (email/backup)
- Rate limit: per-IP? Per-account? Per-session?
- Stateful: server tracks attempts? Or stateless cookie-based?

---

## 1. The Attack Matrix

| # | Technique | Detection | Bounty |
|---|-----------|-----------|--------|
| 1 | Response manipulation `success:false→true` | OTP check returns JSON | $1k–$5k |
| 2 | Status code manipulation `403→200` | OTP check returns status | $500–$3k |
| 3 | No rate limit (brute-force 6-digit OTP) | 1000+ attempts accepted | $1k–$10k |
| 4 | Race condition on OTP validation | Burp parallel | $2k–$10k |
| 5 | OTP code reuse | same code accepted twice | $500–$5k |
| 6 | MFA step skip via direct nav | go to /dashboard skipping /mfa | $1k–$8k |
| 7 | Backup code reuse | same backup code accepted again | $500–$3k |
| 8 | Recovery code dump via API | /api/me leaks backup codes | $1k–$5k |
| 9 | Factor downgrade (TOTP→SMS no rate limit) | swap factor in flow | $1k–$5k |
| 10 | MFA not enforced on sensitive endpoints | password change without MFA | $1k–$10k |
| 11 | Session not invalidated on MFA enable | pre-MFA session still works | $500–$3k |
| 12 | MFA token reuse | same mfa_token used twice/across users | $1k–$5k |
| 13 | OAuth/SSO bypasses MFA | login via SSO skips MFA | $1k–$8k |
| 14 | Cookie persistence across logout | pre-logout cookie still authed | $500–$3k |
| 15 | Email MFA token in URL/Referer | leak via 3rd-party | $1k–$5k |

---

## 2. Response / Status Manipulation (highest-frequency bug)

### 2.1 Response body manipulation
Intercept the `/mfa/verify` response:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"success":false,"message":"Invalid code"}
```
Modify to:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"success":true,"redirect":"/dashboard","token":"X"}
```
If client honors `success:true` and proceeds → bypass.

### 2.2 Status code manipulation
Server returns `401 Unauthorized` or `403 Forbidden`. Modify to `200 OK`. If client just checks status:
```http
HTTP/1.1 401 Unauthorized
→ change to:
HTTP/1.1 200 OK
```

### 2.3 Test in Burp
Match-and-replace rule: response status 401 → 200, body `false` → `true`. Run flow. Watch for auth state.

### 2.4 Real reports
- Common $1k–$5k finding on smaller fintech / SaaS targets.

---

## 3. No Rate Limit on OTP Validation

### 3.1 Detection
Submit OTP `000000`, `000001`, `000002`... 50 in a row. Server still accepts attempts after 10? 100? 1000?

### 3.2 Brute force
```python
# 6-digit OTP = 10^6 = 1M attempts
# At 100 req/s = 10,000s = ~2.7 hours to fully brute force
# Most TOTP windows are 30s but lookback is ±1 step (90s window)
# 90s × 100 req/s = 9000 attempts per window = good chance of hit
```

### 3.3 Burp Intruder
- Type: Sniper
- Payload: numeric range 000000-999999
- Filter: response length differs / redirect / "success"

### 3.4 Modern variations
- 4-digit codes = 10,000 (trivial)
- 8-digit codes = 10^8 (impractical unless years of TOTP window)
- SMS codes often have very weak rate limit (a few attempts per code, but unlimited new codes)

---

## 4. Race Condition

### 4.1 Burp Turbo Intruder — submit same OTP 50× in parallel
Some impls increment counter after validation but read-before-write:
```python
def queueRequests(target):
  engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=50)
  for _ in range(50):
    engine.queue(template, attack='000000')

def handleResponse(req, interesting):
  if 'success' in req.response:
    table.add(req)
```

### 4.2 Race the counter
Use a leaked TOTP value (e.g., from screenshot in social engineering scenario). Submit in parallel windows.

---

## 5. OTP Code Reuse

### 5.1 Detection
1. Login with MFA. Use OTP `123456`. Reach dashboard.
2. Logout.
3. Login again. Use same `123456`. Accepted?

Within TOTP 30s window, this might be a feature. After expiry → reuse = bug.

### 5.2 Cross-session reuse
1. Session A uses OTP `123456`.
2. Session B (different browser) uses same OTP `123456`.

If both succeed → no per-OTP tracking.

---

## 6. MFA Step Skip via Direct Navigation

### 6.1 The flaw
After `POST /login`, server sets `mfa_required` session flag and returns `redirect: /mfa/verify`. But it also creates the authed session cookie!

Test:
1. POST /login → 200 with `mfa_required:true`, but cookies include `session_id=X`
2. Don't go to /mfa/verify. Directly navigate to /dashboard.
3. If accepted → MFA gate is client-side only.

### 6.2 Cookie inspection
```bash
curl -v -X POST https://target.com/login -d 'email=x&pass=Y' 2>&1 | grep -i Set-Cookie
# Are 2 cookies set? One auth-only, one MFA-pending?
# Or one cookie that's already auth and just needs MFA?
```

### 6.3 API direct call
SPA shows MFA prompt UI, but the underlying `/api/*` endpoints don't enforce MFA flag. Direct curl with session cookie reaches all endpoints.

---

## 7. Backup Code Vulnerabilities

### 7.1 Backup code reuse
1. Use a backup code. Pass MFA.
2. Use same code again. Accepted?

Many implementations forget to mark used.

### 7.2 Backup code brute force
- Often 8-digit numeric or 10-char alphanumeric.
- Same code per user; if rate-limit absent, brute.

### 7.3 Backup codes never expire
- Old backup code leaked via email forwarded years ago → still valid.

### 7.4 Backup-code disable MFA
- "Use backup code to disable MFA" feature → enter backup code → MFA off → no more challenge.
- Backup code itself a weak factor.

---

## 8. Recovery Code Dump via API

### 8.1 Look for these endpoints
```
GET /api/me                       — does it include backup_codes field?
GET /api/users/me                 — same
GET /api/account                   — same
GET /api/mfa/backup-codes          — public? Should require step-up MFA
GET /api/security/recovery-codes   — same
```

### 8.2 Test
Login as your account (no MFA challenge if you skipped or aren't required). Hit `/api/me`. See if response body includes `backup_codes`, `recovery_codes`, `mfa_secret`, `totp_secret`.

If yes → attacker with even temporary session access can pull all backup codes.

---

## 9. Factor Downgrade

### 9.1 TOTP → SMS swap
1. User has TOTP enabled. Login flow shows TOTP prompt.
2. Tamper request: change `factor=totp` to `factor=sms`.
3. SMS sent (no rate limit) — attacker phishes the SMS or intercepts.

Or change to a less-rate-limited factor.

### 9.2 New factor enrollment without MFA
- Add attacker's phone as a recovery number without confirming current MFA.
- Then use new phone to receive OTP.

---

## 10. MFA Not Enforced on Sensitive Endpoints

The big one. Even when MFA is required to log in:
- `/api/change-password` doesn't require step-up MFA → attacker with session cookie changes password
- `/api/change-email` → email victim's account away from them
- `/api/withdraw` → drain funds
- `/api/api-keys` → generate API key, use it forever

### 10.1 Step-up check
Each high-value action should re-prompt MFA. Check:
- Settings page → MFA prompt before changes
- Money transfer → MFA prompt
- API key generation → MFA prompt
- Email/password change → MFA prompt

Find one that doesn't → critical chain with cookie theft (XSS) or session reuse.

---

## 11. Session Not Invalidated on MFA Enable

1. User has session (no MFA configured).
2. User enables MFA.
3. Old session cookie should be invalidated.
4. If not → attacker who stole pre-MFA cookie retains access.

### 11.1 Test
Login. Note cookies. Enable MFA. Old browser still works?

---

## 12. MFA Token Reuse / Cross-Account

After `POST /login`, the server issues a temporary `mfa_token` to track which user is mid-flow. Test:
- Use `mfa_token` from session A in session B → mid-flow takeover
- Reuse `mfa_token` for the same user in second flow → second factor never validated
- `mfa_token` is base64 of `user_id`? Then forge for victim user.

---

## 13. SSO / OAuth Bypasses MFA

Many apps require MFA on email/password login but skip MFA on "Login with Google/SSO" flow. Once OAuth code → token → session, no MFA prompt.

### 13.1 Test
- Enable MFA on victim account.
- Use OAuth login. Did MFA prompt appear?
- If no → SSO is an MFA bypass path → chain with hunt-oauth `redirect_uri` bypass = full ATO without MFA.

---

## 14. Email OTP Token in URL / Referer

Email-based MFA sometimes uses magic links: `?mfa_token=ABCDEF`. Click in email → page loads. If page contains 3rd-party scripts/links, Referer leaks token.

Same Referer-leak pattern as password reset (see hunt-ato §1.3).

---

## 15. Cookie Persistence Across Logout

1. Login. Note session cookie.
2. Logout. Server returns `Set-Cookie: session=; expires=past`.
3. Reuse the OLD cookie value in a different browser.
4. If accepted → logout didn't invalidate server-side → stolen-cookie attacks work after the user logs out.

---

## 16. Chain Templates

```
Breach corpus password + MFA bypass = ATO (no device needed)
Cookie theft (XSS) + no MFA on sensitive endpoint = ATO (defeats HttpOnly + MFA)
IDOR on /api/me + MFA secrets leak = bypass + cross-user
Race condition on OTP + valid password = brute MFA in one window
SSO bypass + OAuth redirect_uri = ATO without MFA challenge
SMS factor downgrade + SIM-swap (out of scope but documented chain)
Email MFA + Referer leak via reset-page link = ATO
```

---

## 17. Validation Gate

Before reporting:
1. **Demonstrated attacker reaches authed state without performing MFA** on victim's account
2. **Test account confirms** — your test victim has MFA enabled, attacker bypasses it
3. **Not "MFA is not the only auth"** — that's not a bypass, that's not having MFA enforced (Medium)
4. **Reproducible** — single-curl PoC where possible
5. **Not session-fixation false positive** — your test browser doesn't share cookies

---

## 18. Tools

```bash
# Burp Intruder: brute OTP
# Burp Turbo Intruder: race on OTP
# Match-and-replace rule for response manipulation
# Custom mitmproxy script to swap mfa_token across users

# Authy/Google Authenticator clones for testing
oathtool --totp -b "TOTPSECRET"           # generate valid TOTP

# Burp ext: Authmatrix (visualizes per-user/per-endpoint MFA)
```

---

## 19. Disclosed Reports

| Target | Bounty | Technique |
|--------|--------|-----------|
| Multiple H1 | $1k–$10k | Response body manipulation `false→true` |
| Various | $2k–$8k | No rate limit, brute 6-digit OTP |
| Various | $1k–$5k | Backup code reuse |
| HackerOne (self) | varies | 2FA can be bypassed via X path (disclosed) |
| Multiple SaaS | $2k–$15k | Password change without step-up MFA chain |

---

## 20. Mantras

- Try response manipulation FIRST. It's a 5-minute test that pays.
- Rate limit on OTP is often per-OTP-code, not per-account. Try 6 codes per minute on 6 different test attempts.
- MFA "enabled" doesn't mean "enforced on every endpoint." Test ALL sensitive endpoints for step-up.
- OAuth/SSO often skips MFA. That's an MFA bypass.
- Backup codes are usually the weakest factor. Test reuse + brute.
- "MFA token" issued mid-flow is just another session cookie. Treat it like one.
