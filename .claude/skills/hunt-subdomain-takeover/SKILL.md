---
name: hunt-subdomain-takeover
description: "Hunt subdomain takeover and dangling DNS — detect dangling CNAMEs/A records pointing at decommissioned PaaS (GitHub Pages, Heroku, S3, Azure, Netlify, Vercel, Fastly, AWS CloudFront, Shopify, Tumblr, Zendesk, Helpscout, Statuspage, Read the Docs, ~30 more), monitor Certificate Transparency logs continuously for new subdomain registration, validate fingerprints and claim PoCs without destructive write, and chain takeover into cookie scoping bypass (parent-domain cookies), SSO callback abuse, and CORS allowlist exploitation. Use when a target has many subdomains, when shadow IT and abandoned PaaS apps are likely, or when you find a CNAME pointing at a third-party service the org no longer controls. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

## Crown Jewel Targets

Subdomain takeover is a textbook bug-bounty payout: low effort to find (DNS-based, no live target needed), high impact (cookie theft, SSO bypass, phishing on trusted domain). 2026 reality: takeover findings continue to pay $500–$5k for direct, $5k–$25k+ for chained-into-ATO.

Highest-impact subdomains to take over:
- **Anything in the org's primary domain with cookie scope = `.target.com`** — read all victim cookies
- **OAuth/SAML callback hosts** — `auth.target.com`, `sso.target.com`
- **API CORS allowlist entries** — if `*.target.com` is allowed and `forgotten.target.com` is takeoverable
- **Marketing subdomains** linked from the main app — `blog.target.com`, `docs.target.com`, `careers.target.com`
- **Status pages** — `status.target.com` — high-trust phishing surface
- **Help / support subdomains** — `help.target.com`, `support.target.com`
- **Mobile API hosts** — `m.target.com`, `mobile.target.com`

---

## Attack Surface Signals

### What makes a subdomain takeoverable
Two conditions together:
1. **The DNS record exists.** A CNAME (most common) or A record on a subdomain you don't control, pointing at a third-party service.
2. **The third-party resource is unclaimed.** The org provisioned an app/site/bucket there once, decommissioned it, but never deleted the DNS entry. You can register the resource with the same name and serve content.

### High-yield third-party services (with claim difficulty in 2026)

| Service              | CNAME pattern                            | Claim difficulty | Fingerprint                                        |
|----------------------|------------------------------------------|------------------|----------------------------------------------------|
| GitHub Pages         | `*.github.io`                            | Easy (free)      | "There isn't a GitHub Pages site here."            |
| Heroku               | `*.herokuapp.com`, `*.herokussl.com`     | Easy (free tier was deprecated, paid only now — but easier on EU/legacy regions) | "No such app" |
| AWS S3               | `*.s3.amazonaws.com`, `*.s3-website-*`   | Easy             | "NoSuchBucket" + bucket name shown                |
| AWS CloudFront       | `*.cloudfront.net`                       | Hard (paid)      | "Bad request" / "ERROR The request could not be satisfied" |
| Azure (multiple)     | `*.azurewebsites.net`, `*.cloudapp.net`, `*.trafficmanager.net`, `*.azureedge.net`, `*.blob.core.windows.net` | Medium | "404 Web Site not found" or similar |
| Netlify              | `*.netlify.app`, `*.netlify.com`         | Easy (free)      | "Not Found - Request ID:"                         |
| Vercel               | `*.vercel.app`                           | Easy (free)      | "DEPLOYMENT_NOT_FOUND"                            |
| Fastly               | `*.fastly.net`                           | Hard (paid)      | "Fastly error: unknown domain"                    |
| Shopify              | `*.myshopify.com`                        | Hard (paid)      | "Sorry, this shop is currently unavailable"      |
| Tumblr               | `*.tumblr.com`                           | Easy (free)      | "There's nothing here."                           |
| Zendesk              | `*.zendesk.com`                          | Hard (paid trial)| "Help Center Closed"                              |
| Helpscout            | `*.helpscoutdocs.com`                    | Hard (paid)      | "No settings were found"                          |
| Statuspage           | `*.statuspage.io`                        | Hard (paid)      | "You are being redirected"                        |
| Read the Docs        | `*.readthedocs.io`                       | Easy (free)      | "Unknown to Read the Docs"                        |
| Pantheon             | `*.pantheonsite.io`                      | Easy             | "The gods are wise"                               |
| WPEngine             | `*.wpengine.com`                         | Hard             | varies                                            |
| Squarespace          | `*.squarespace.com`                      | Hard             | varies                                            |
| Bigcartel            | `*.bigcartel.com`                        | Easy             | "Oops! We couldn't find that page"                |
| Cargo Collective     | `*.cargocollective.com`                  | Easy             | "404 Not Found"                                   |
| Surge.sh             | `*.surge.sh`                             | Easy             | "project not found"                               |
| Webflow              | `*.webflow.io`                           | Easy (trial)     | "The page you are looking for doesn't exist..."   |
| Tilda                | `*.tilda.ws`                             | Easy             | "Please renew your subscription"                  |
| Ghost.io             | `*.ghost.io`                             | Easy (trial)     | "Domain error"                                    |
| Strikingly           | `*.s.strikinglydns.com`                  | Easy             | "404 Not Found"                                   |
| Smartling            | `*.smartling.com`                        | Medium           | "Domain is not configured"                        |
| Worksites.net        | `*.worksites.net`                        | Medium           | "Hello! Sorry, but this website..."               |
| Uberflip             | `*.uberflip.com`                         | Medium           | "The URL you've requested..."                     |
| Help Juice           | `*.helpjuice.com`                        | Medium           | "We could not find what you're looking for"       |
| Tave                 | `*.tave.com`                             | Medium           | "<no_pun_intended>"                               |
| LaunchRock           | `*.launchrock.com`                       | Easy             | "It looks like you may have taken a wrong turn"   |
| Pingdom              | `*.pingdom.com`                          | Hard             | "public report not activated"                     |
| Brightcove           | `*.brightcove.net`                       | Medium           | "<error>Unknown account</error>"                  |
| Campaign Monitor     | `createsend.com`                         | Hard             | "Double check the URL or"                          |
| Acquia               | `*.acquia-sites.com`                     | Hard             | "If you are the site owner..."                    |
| Anima                | `*.animaapp.io`                          | Easy             | "If this is your website..."                      |
| Aha                  | `*.aha.io`                               | Medium           | "There is no portal here..."                      |

NOTE: Easy = free service tier or no payment required. Hard = paid claim. Easy ones are the bulk of real takeovers.

### Other dangling patterns

- **Dangling NS records** (you control the nameserver) — can take over the entire zone. Rare but devastating.
- **Dangling MX records** — receive the org's email. Phishing gold.
- **Dangling A records** to a cloud IP that's been released back to the provider's pool — claim the IP via AWS/Azure cycling (lottery-style; possible at scale).
- **Internal-DNS dangling** — internal AD names pointing to decommissioned machines (less of a BB issue, more of a red-team primitive).

---

## Step-by-Step Methodology

### 1. Subdomain enumeration (broad)

Use the multi-source approach (see `web2-recon` / `recon` skills). Output: a list of every subdomain the org has ever had.

```bash
TARGET=target.com
mkdir -p recon/$TARGET
subfinder -d $TARGET -all -recursive -silent | tee recon/$TARGET/subs-subfinder.txt
amass enum -passive -d $TARGET -o recon/$TARGET/subs-amass.txt
assetfinder --subs-only $TARGET | tee recon/$TARGET/subs-assetfinder.txt
findomain -t $TARGET --quiet | tee recon/$TARGET/subs-findomain.txt
curl -s "https://crt.sh/?q=%.$TARGET&output=json" | jq -r '.[].name_value' | tr ',' '\n' | tee recon/$TARGET/subs-crt.txt
curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | tee recon/$TARGET/subs-certspotter.txt
cat recon/$TARGET/subs-*.txt | sort -u > recon/$TARGET/subs-all.txt
```

### 2. Resolve and classify CNAMEs

```bash
# dnsx with CNAME mode — fast
dnsx -l recon/$TARGET/subs-all.txt -cname -resp -silent > recon/$TARGET/cnames.txt

# Or massdns + grep
cat recon/$TARGET/subs-all.txt | massdns -r resolvers.txt -t CNAME -o S -w recon/$TARGET/massdns.txt

# Identify CNAMEs pointing at third-party services (the takeover candidates)
grep -E '\.(github\.io|herokuapp\.com|s3\.amazonaws\.com|cloudfront\.net|azurewebsites\.net|trafficmanager\.net|azureedge\.net|netlify\.app|vercel\.app|fastly\.net|myshopify\.com|tumblr\.com|zendesk\.com|statuspage\.io|readthedocs\.io|pantheonsite\.io|wpengine\.com|webflow\.io|surge\.sh|ghost\.io|launchrock\.com|brightcove\.net|acquia-sites\.com)$' recon/$TARGET/cnames.txt > recon/$TARGET/takeover-candidates.txt
```

### 3. Fingerprint each candidate

Two automated tools cover most known fingerprints:

```bash
# subjack — battle-tested
subjack -w recon/$TARGET/subs-all.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -o recon/$TARGET/subjack.txt

# subzy — newer, more up-to-date fingerprints
subzy run --targets recon/$TARGET/subs-all.txt --concurrency 100 --hide_fails | tee recon/$TARGET/subzy.txt

# nuclei — has takeover templates
nuclei -l recon/$TARGET/subs-all.txt -t http/takeovers/ -silent -o recon/$TARGET/nuclei-takeover.txt
```

False-positive guard: tools sometimes flag based on generic 404 pages. Always manually verify.

### 4. Manual verification

For each candidate the tools flag:

```bash
SUB="dead.target.com"
dig +short CNAME $SUB                          # confirm CNAME target
curl -sI https://$SUB                          # response code + Server header
curl -s  https://$SUB | head -c 500            # body — match against known fingerprint
```

Compare body to the fingerprint table above. If exact match → takeoverable. If different/redirect → may be claimed, may be different service.

### 5. PoC (read-only "I could claim this")

The bug-bounty standard for safe PoC:

**Option A — text on the rogue page (preferred):**
1. Register the resource on the third-party (create GitHub Pages site at `target-org/target-org.github.io`).
2. Serve a single HTML page identifying you as the researcher, with a unique token in the body.
3. Capture screenshot of `curl https://dead.target.com` returning your token.
4. **Do not** serve content that could be confused with the target. No login forms, no scripts, no cookies.

**Option B — DNS-only proof (when the claim is hard/paid):**
1. Show the dangling CNAME via `dig`.
2. Cite the unclaimed-state of the third-party endpoint.
3. Provide the fingerprint match.
4. Reference public docs explaining the takeover path.

Always remove the claimed resource immediately after report acceptance.

### 6. Map to impact (this is the report differentiator)

| Asset                                   | Direct impact | Possible chain                                                      |
|-----------------------------------------|--------------|---------------------------------------------------------------------|
| `blog.target.com` (marketing)           | Phishing on trusted domain | XSS → cookie steal if cookies scoped `.target.com`           |
| `auth.target.com` callback              | OAuth code interception | Full ATO                                                        |
| `*.target.com` CORS allowlist match     | Credentialed cross-origin reads | Full API read of victim                                       |
| `static.target.com` (script source)     | Stored XSS on main app | Full ATO via every page that loads scripts                       |
| `cookie-scoped subdomain`               | Read `Domain=.target.com` cookies | Full session theft if cookies aren't `Secure; SameSite=Strict` |
| `status.target.com`                     | Phishing — high trust          | Social engineering attacks                                       |
| `email-link.target.com` (click-tracker)| Phishing via legitimate emails  | Smear domain reputation                                          |

---

## Certificate Transparency Monitoring (Continuous)

CT logs are how attackers find new takeover candidates *before* the security team notices:

```bash
# certstream — real-time stream of every TLS cert issued globally
# pipe through grep for your target
certstream | grep -E '\.target\.com'

# crt.sh — periodic poll
while true; do
    curl -s "https://crt.sh/?q=%.target.com&output=json" \
      | jq -r '.[] | "\(.entry_timestamp)\t\(.name_value)"' \
      | sort -u > /tmp/crt-now.txt
    diff /tmp/crt-prev.txt /tmp/crt-now.txt | grep '^>' >> /tmp/crt-new-subs.log
    mv /tmp/crt-now.txt /tmp/crt-prev.txt
    sleep 3600
done

# Aggregator: SecurityTrails, Censys, Shodan all support saved searches with email alerts
```

When a new cert is issued for `unknown.target.com`, immediately:
1. Resolve its CNAME.
2. Check if the CNAME target is unclaimed (running fingerprint checks).
3. If yes — file the report before someone else does.

---

## Tooling Quick Reference

```bash
# Subdomain enum
subfinder, amass, assetfinder, findomain, github-subdomains, dnsgen, alterx

# Takeover-specific scanners
subjack, subzy, nuclei (takeovers template dir), takeover.sh (manual fingerprints), can-i-take-over-xyz

# Validation
dig, dnsx, massdns, curl

# CT monitoring
certstream-py, crt.sh, censys, securitytrails, axiom subdomain monitor
```

---

## Bypass / False-Positive Patterns

**False positive 1: Generic 404 from CDN**
Some CDNs (CloudFront, Fastly) return a generic error when a distribution doesn't match. That's NOT always takeover — claiming a CloudFront distribution requires AWS account, paid plan, and provisioning a distribution with the *exact ID*, which is randomly assigned by AWS at provisioning. So `*.cloudfront.net` generic 404 is rarely takeoverable.

**False positive 2: Apex/owner-claimed but content removed**
The third-party might still own the CNAME slot (e.g., GitHub repo exists but Pages is disabled). You can't take it over. Fingerprint must indicate *unclaimed*, not just *empty*.

**False positive 3: Reserved names**
Some services reserve common names (`admin`, `api`, `www`). You can't register `admin.github.io` even if the CNAME pointed there.

**Edge case: dynamic CNAME (CDN traffic management)**
Some orgs use Akamai/Cloudflare which dynamically rewrite CNAMEs. These look dangling to dnsx but aren't actually takeover-able. Check the actual third-party config, not just the DNS state.

**Edge case: GitHub Pages org-scoped**
`org.github.io/page` requires you to register a repo *inside the target org*, which usually requires being invited. Different from `username.github.io/page` which is per-user.

---

## Gate 0 Validation

1. **Fingerprint matches a known-takeoverable state.** Don't report based on "404" — match against the specific service's unclaimed-fingerprint string.

2. **You demonstrate (or could demonstrate, safely) actual claim.** Show your registered resource serving content, OR show the third-party admin panel confirming "this name is available," OR cite the platform's documented claim process.

3. **You map to impact** — what does owning this subdomain let you do *against the program's users or assets*? "Subdomain takeoverable" alone is informational; "subdomain takeoverable + parent-domain cookies + this is an OAuth callback" is critical.

---

## Real Impact Examples

### Scenario 1: Blog Subdomain Takeover → Session Cookie Theft → ATO
`blog.target.com` had a CNAME at `target.github.io` — but the GitHub Pages repo was deleted years ago when the team moved to Ghost. Claimed `target.github.io`, served a page that read `document.cookie` and exfiltrated it. Because the main app set its session cookie with `Domain=.target.com`, that cookie was sent on requests to `blog.target.com`. Single victim visit → full session theft → ATO. Critical.

### Scenario 2: OAuth Callback Subdomain
`auth-test.target.com` was an old Heroku app, dangling CNAME at `target-auth-test.herokuapp.com`. The main OAuth flow's `redirect_uri` allowlist accepted `*.target.com`. Claimed the Heroku app, registered an OAuth flow that returned the auth code to `auth-test.target.com/callback`, attacker collected codes and exchanged for tokens. Critical, $25k+.

### Scenario 3: CORS Allowlist Match
Main API had `Access-Control-Allow-Origin` set to any `*.target.com` with credentials. `helpdesk.target.com` was a dangling Zendesk subdomain. Trial-claimed Zendesk, set up a page that fetched the credentialed API from the takeoverable origin — full API read on behalf of victim. Critical.

### Scenario 4: Statuspage Phishing
`status.target.com` was dangling at `target.statuspage.io`. Claimed it (trial), posted a "scheduled maintenance — please re-authenticate at https://login-target.com" notice. Trusted-domain phishing chain; chained with email infrastructure recon for additional impact.

---

## Related Skills & Chains

- **`hunt-subdomain`** — Broader subdomain enumeration. Feeds the list this skill consumes.
- **`web2-recon`** — Multi-source subdomain enum pipeline.
- **`hunt-github-recon`** — Pair with this skill: GitHub recon finds the *real* services in use, helps you spot which CNAME targets the org *should* have, vs the dangling ones.
- **`hunt-xss`** — Takeover + parent-domain cookie scope = sets up XSS for cookie theft.
- **`hunt-oauth`** — Takeover of OAuth callback hosts is the canonical high-impact chain.
- **`hunt-cloud-misconfig`** — AWS S3 bucket takeovers are a special case (CNAME pointing at NoSuchBucket).
- **`hunt-second-order`** — Once you own a script-source subdomain, every page loading from it is a delayed-execution XSS sink.
- **`triage-validation`** — Apply the Impact-Mapping gate: a takeover finding *must* explain what owning the subdomain enables. "I could put a page on it" is informational; "I could read all session cookies" is critical.

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle

## Real-World Reports (from Community Writeups)

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| **Subdomain Takeover to Authentication bypass** | Roblox | $0 | H1 #335330 |
| Subdomain takeover of datacafe-cert.starbucks.com | Starbucks | $0 | H1 #665398 |
| **Auth bypass on auth.uber.com via takeover of saostatic.uber.com** | Uber | $0 | H1 #219205 |
| Subdomain takeover of storybook.lystit.com | Lyst | $1,000 | H1 #779442 |
| Hacker.One Subdomain Takeover | HackerOne | $0 | H1 #159156 |
| Subdomain Takeover via Insecure CloudFront cdn.grab.com | Grab | $1,000 | H1 #352869 |
| Subdomain takeover at info.hacker.one | HackerOne | $0 | H1 #202767 |
| Multiple Subdomain Takeovers fly.staging.shipt.com | Shipt | $0 | H1 #576857 |
| Subdomain takeover of mydailydev.starbucks.com | Starbucks | $0 | H1 #570651 |
| Subdomain takeover of productioncontroller.starbucks.com | Starbucks | $0 | H1 #661751 |
| Subdomain takeover on fastly.sc-cdn.net | Snapchat | $3,000 | H1 #154425 |
| Subdomain takeover on svcgatewayus.starbucks.com | Starbucks | $0 | H1 #325336 |
| Subdomain takeover on happymondays.starbucks.com (S3) | Starbucks | $0 | H1 #186766 |
| Subdomain takeover on usclsapipma.cv.ford.com | Ford | $0 | H1 #484420 |
| Subdomain takeover of resources.hackerone.com | HackerOne | $500 | H1 #863551 |
| Subdomain Takeover at creatorforum.roblox.com | Roblox | $0 | H1 #264494 |
| Subdomain takeover in GitLab pages | GitLab | $0 | H1 #2523654 |
| Subdomain takeover of v.zego.com | Zego | $0 | H1 #1180697 |

**PROVEN patterns** (3+ reports): dangling CNAME at S3/CloudFront (Starbucks x4, Grab, Snapchat), GitLab Pages / GitHub Pages CNAME without claim, Heroku/Fastly dangling, takeover → auth bypass via parent-domain cookie scope (Roblox, Uber).

## High-Value Chains (from Reports)

1. **CNAME takeover → parent-domain cookie scope → full ATO**
   - Roblox (H1 #335330) — claimed dangling subdomain, served JS that read `*.roblox.com` cookies, hijacked auth.
2. **CDN takeover → host malicious JS on trusted origin → bypass CSP/SOP**
   - Snapchat fastly.sc-cdn.net (H1 #154425, $3k) — served arbitrary JS under trusted CDN, executed in app context.
3. **Static CDN takeover → OAuth redirect_uri allowlist abuse → code theft**
   - Uber saostatic.uber.com (H1 #219205) — took over static host, used as OAuth allowlisted redirect, stole authorization codes.
4. **S3 bucket-name takeover → serve attacker content → phishing under brand**
   - Starbucks (H1 #186766, #325336, #570651, #661751, #665398) — five separate dangling S3 references all claimable.
5. **Resources/blog subdomain takeover → CSRF token + cookie theft via XSS**
   - HackerOne resources.hackerone.com (H1 #863551, $500) — abandoned marketing platform claimed, JS injection on trusted subdomain.
