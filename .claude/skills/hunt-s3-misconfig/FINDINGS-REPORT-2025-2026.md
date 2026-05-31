# Cloud Storage Misconfiguration Research Report (2024-2026)

**Compiled:** 2026-05-27
**Scope:** AWS S3, Google Cloud Storage, Azure Blob, Firebase, Cloudflare R2, Backblaze B2, DigitalOcean Spaces
**Purpose:** Synthesis of every novel attack technique, real-world incident, conference talk, tool, and bug bounty payout related to cloud-object-storage misconfiguration disclosed between Jan 2024 and May 2026.

---

## 1. HEADLINE INCIDENTS (2024-2026)

### 1.1 watchTowr Labs — 150 Abandoned S3 Buckets (Feb 2025)
- **Researchers:** Benjamin Harris et al., watchTowr Labs.
- **Investigation:** Oct 2024 → Jan 2025.
- **Method:** Identified 150 deleted S3 buckets still actively referenced by deployment code, software updaters, OS update channels, CloudFormation templates, SSL VPN configs, and JS bundles.
- **Cost:** $420.85 to re-register all 150 buckets in AWS.
- **Result:** 8,000,000+ HTTP requests received over 2 months.
- **Requesters:** NASA, US/UK/Australia government agencies, Fortune 100, a major payment card network, banks, infosec firms, casinos, OSS projects.
- **Files requested:** Software updates, unsigned Windows/Linux/macOS binaries, VM images, JS files, CloudFormation templates, Terraform state, SSL VPN configs.
- **Quote:** "SolarWinds adventures would look amateurish and insignificant" had they been weaponised.
- **Outcome:** AWS sinkholed all 150 buckets after disclosure.
- **Source:** https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/

### 1.2 Codefinger Ransomware (Jan 2025)
- **Disclosure:** Halcyon Jan 13 2025.
- **Mechanism:** Threat actor uses compromised AWS keys to call `PutObject` with `x-amz-server-side-encryption-customer-algorithm: AES256` and `x-amz-server-side-encryption-customer-key: <attacker AES-256 key>`. AWS encrypts in place; only the attacker's key can decrypt.
- **Recoverability:** Zero — AWS only logs an HMAC of the customer key in CloudTrail, not the key itself.
- **Pressure:** 7-day deletion lifecycle policy ratchets victim urgency.
- **Defence:** IAM `Deny` on `s3:x-amz-server-side-encryption-customer-algorithm = AES256`; enforce SSE-KMS only; turn on Object Lock in Compliance mode.
- **Source:** https://arcticwolf.com/resources/blog/ransomware-campaign-encrypting-amazon-s3-buckets-using-sse-c/

### 1.3 Tea App Firebase Breach (Jul 2025)
- **Trigger:** Anonymous 4chan post Jul 25 2025.
- **Bucket:** Firebase Storage — no authentication, directory listing enabled.
- **First leak:** 72k images (13k selfies + IDs, 59k post/message attachments).
- **Second leak (404 Media, Jul 28):** 1.1 million private chat messages from Feb 2023 – Jul 2025.
- **Root cause:** Legacy migration left old Firebase bucket unsecured and discoverable; client URL still referenced it.
- **Source:** https://medium.com/@tahirbalarabe2/tea-app-security-fail-firebase-leak-reveals-drivers-licenses-selfies-fb8f98d7be13

### 1.4 Sysdig 8-Minute AWS Takeover (Nov 2025)
- **Date:** 28 Nov 2025.
- **Chain:** S3 public bucket → leaked AWS access key → `GetCallerIdentity` validation → Lambda code injection → 19 lateral principals → Bedrock LLMjacking + GPU instance abuse for model training.
- **Speed:** 8 minutes credential → admin.
- **Signal of LLM use:** Verbose comments, comprehensive exception handling, real-time syntactically correct Boto3 — all hallmarks of LLM-generated code.
- **Source:** https://www.sysdig.com/blog/ai-assisted-cloud-intrusion-achieves-admin-access-in-8-minutes

### 1.5 Indian Financial Bucket (Aug-Sep 2025)
- **Scope:** Open S3 bucket containing hundreds of thousands of PDFs (bank-transfer mandates, recurring debit authorisations) with names, addresses, phones, emails of Indian banking customers.

### 1.6 Aqua Security "Bucket Monopoly" (Black Hat USA 2024)
- **Researchers:** Yakir Kadkoda, Michael Katchinskiy, Ofek Itach (Aqua Nautilus).
- **Affected services:** CloudFormation, Glue, EMR, SageMaker, ServiceCatalog, CodeStar.
- **Mechanism:** Predictable bucket-naming pattern (`cf-templates-<hash>-<region>`, `aws-glue-assets-<acct>-<region>`, etc.). Attacker pre-registers buckets in regions the victim hasn't yet expanded into; when the victim enables the service in that region, AWS *trusts* and writes data to the attacker-owned bucket.
- **Impact:** RCE (Glue jobs), XSS (EMR Jupyter notebooks), data poisoning (SageMaker training data), full account takeover via CloudFormation template injection.
- **Disclosed:** Feb 16 2024 → Fixed by AWS by Jun 26 2024.
- **Source:** https://www.aquasec.com/blog/bucket-monopoly-breaching-aws-accounts-through-shadow-resources/

### 1.7 AWS CDK Bootstrap Bucket TakeOver (Oct 2024)
- **Researchers:** Aqua Security.
- **Bug:** `cdk-hnb659fds-assets-<account_id>-<region>` predictable name. Attacker creates the bucket in a region the victim never bootstrapped. When the victim runs `cdk bootstrap` later, the FilePublishingRole writes CFN templates into the attacker's bucket. Attacker injects an admin-trust-policy role into the template → admin in victim account.
- **Fix:** CDK v2.149.0+ — bootstrap role now scoped to buckets owned by the bootstrapping account.

### 1.8 Trusted Advisor Detection Evasion (May 2025)
- **Researchers:** Fog Security ("Mistrusted Advisor").
- **Technique:** Add bucket-policy `Deny` for `s3:GetBucketAcl`, `s3:GetBucketPolicyStatus`, `s3:GetPublicAccessBlock` to the Trusted Advisor service principal. Bucket can then be public via ACL or Policy, but Trusted Advisor reports it as green.
- **Variant 2:** Use `s3:x-amz-server-side-encryption-aws-kms-key-id` condition with non-existent key — IAM does not validate existence; bucket evaluates as "not public" while still allowing any principal to put objects with that key.
- **Fixed:** AWS deployed a partial fix May 30 2025; ACL evaluation still wrong on retest Jun 13 2025; final fix shipped late Jun 2025. Trusted Advisor now `Warn`-statuses any bucket that blocks its query path.
- **Source:** https://www.fogsecurity.io/blog/mistrusted-advisor-public-s3-buckets

### 1.9 Microsoft Azure Blob Storage Wave (Oct 2025)
- **Microsoft Security Blog 2025-10-20:** Industrial spike in adversary activity targeting Azure Blob via leaked SAS tokens, key extraction, Cloud Shell persistence abuse, and overly permissive container ACLs (`Container` public-access level).
- **Pattern:** Reconnaissance for `*.blob.core.windows.net`, key extraction from public repos / mobile apps, lateral movement via SAS replay (developers commonly issue tokens with `expiry = now+10yrs`).

### 1.10 GCP Dangling Bucket Takeover Advisory (Aug 2025)
- **Google Cloud Blog:** Confirms "silent" GCS bucket takeover is in scope — GCS buckets are globally namespaced; deleting a bucket frees the name for any GCP customer to reclaim.
- **Defence (now official Google guidance):** Create a placeholder bucket with the same name immediately on deletion; apply `iam.deny` on `allUsers`/`allAuthenticatedUsers`; enable `Public Access Prevention` org-policy.

### 1.11 OpenStack Keystone CVE-2025-65073
- **High severity authorisation bypass:** Anyone with a valid S3 presigned URL can replay the signature to the Keystone EC2/S3 token endpoint to receive a fully-scoped project token. Affects private/hybrid clouds running Keystone with EC2 compat enabled.

---

## 2. NOVEL ATTACK PRIMITIVES

### 2.1 Account-ID Enumeration via `s3:ResourceAccount` (Cloudar / Tracebit)
- AWS account IDs are 12-digit identifiers. Brute force naïvely = 10^12 attempts. With wildcard match on `s3:ResourceAccount` you walk one digit at a time = max 120 attempts.
- **Setup:** Need your own AWS account + a role with `s3:GetObject` or `s3:ListBucket` on the target bucket (anonymous works if bucket is public-read).
- **Policy template:**
  ```json
  { "Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::TARGET/*",
    "Condition":{"StringLike":{"s3:ResourceAccount":"1*"}} }
  ```
- Increment first digit 0-9 until access succeeds; lock that digit; repeat.
- **Tracebit variant:** Use a VPC endpoint with the same condition + CloudTrail differential logging — works on *private* buckets you have any access to.
- **Tools:** `s3-account-search` (WeAreCloudar), `find-s3-account` (Tracebit).
- **Stealth:** STS actions stay in *your* account; bucket-owner CloudTrail sees nothing because S3 data events aren't logged by default.

### 2.2 SSE-C Ransomware Without Exploits
- Requires only `s3:PutObject` (no bucket-admin needed).
- AWS performs the encryption with the attacker's supplied key; victim cannot decrypt without it.
- Combined with a 7-day deletion lifecycle, this is the most operationally viable cloud-native ransomware in the wild.
- Defence: bucket policy `Deny` for any request that includes `x-amz-server-side-encryption-customer-algorithm` headers; require SSE-KMS exclusively.

### 2.3 Shadow-Resource / Bucket Monopoly Pattern
- Look for AWS services whose generated bucket names contain *only* the account ID and region (not random suffixes).
- Pre-claim the bucket in every region the victim has not yet expanded into.
- When the victim eventually enables that service in that region, AWS uses *your* bucket.
- Affected (now-fixed) services: CloudFormation (`cf-templates-<hash>-<region>`), CDK bootstrap (`cdk-hnb659fds-assets-<acct>-<region>`), Glue, EMR, SageMaker, ServiceCatalog, CodeStar, Code* (other services may still be vulnerable — test fresh ones).

### 2.4 KMS-Condition Block Public Access Bypass
- `s3:x-amz-server-side-encryption-aws-kms-key-id` condition is *not* validated for existence by IAM.
- Bucket policy with this condition allows `Principal:*` but evaluates as *non-public* by AWS's own "public" classifier.
- Letssquidget any actor to upload as long as they include the matching (or any) KMS-key header.

### 2.5 R2.DEV Subdomain Public Exposure (Cloudflare)
- Cloudflare R2 buckets get a `pub-<hash>.r2.dev` subdomain when "public" is enabled. Intended for *testing only*.
- Many developers leave it on in production.
- Reconnaissance: TLS SNI sweep for `r2.dev` and Suricata alerts in production traffic confirm exposure.
- R2 lacks bucket policies and ACLs — only token-scoped access, so misconfigured CORS or left-on dev URL is the only knob.

### 2.6 GCS `endpoints.googleusercontent.com` Bucket Disclosure
- Authenticated browser downloads from private GCS buckets redirect to `https://<rand>-apidata.googleusercontent.com/download/storage/v1/b/<BUCKET>/o/<OBJECT>`.
- Anywhere this URL is logged (proxy logs, browser history, referers, error pages) the bucket+object name leaks → next stage tries direct anonymous access.

### 2.7 Presigned URL "filePath=/" → Full Bucket Listing
- $20,000 H1 finding pattern: server endpoint generates a presigned URL using a user-supplied path parameter.
- Submitting `filePath=/` results in a presigned URL for the *bucket root* → ListBucket → attacker reads all objects.
- Variant: `filePath=../other-user/` — presigned URL escapes the per-user prefix.

### 2.8 SVG Stored XSS Through Image Bucket
- Image-only buckets that accept SVG → SVG embeds `<script>` → served from a sibling of the main app domain (e.g. `cdn.target.com`) → cookies scoped to `.target.com` exfiltrated.
- Bypasses: `payload.svg.png`, dual extensions, content-type override on upload, path traversal in object key (`../../`), CRLF in PUT to set `Content-Type: image/svg+xml`.

### 2.9 Bucket-Hosted Static Site Cookie Tossing
- S3-website endpoint + dangling subdomain takeover → set cookies for `.parent.com` → bypass CSRF or fix-victim session.
- Mitigation requires `__Host-` cookie prefix; few apps use it.

### 2.10 IPv4 Address-As-Bucket-Region Disclosure
- `HeadBucket` to *any* region returns `x-amz-bucket-region` regardless of permission — reveals where the bucket lives even when 403.

---

## 3. CONFERENCE COVERAGE 2024-2025

### Black Hat USA 2024
- **"Bucket Monopoly: Breaching AWS Accounts Through Shadow Resources"** — Aqua Security.
- 6 AWS services affected; one path to AWS account takeover.

### DEF CON 32 (2024) Cloud Village
- GCP Cloud Functions default-service-account privesc → Storage admin.
- AWS shadow-resource talks.
- Azure Policy bypass — list storage with public access without log evidence.

### DEF CON 33 (Aug 2025) Cloud Village
- NetSPI: Anonymous ownership disclosure on cloud resources.
- AmberWolf: Zero Trust Network Access bypasses (Zscaler, Netskope, Check Point Perimeter 81) — relevant because many of these proxy traffic to cloud-storage admin consoles.
- Azure Guest User can create+own subscriptions in joined tenants.

### Black Hat USA 2025
- watchTowr's abandoned-S3 work covered in mainline keynotes; ECS undocumented internal protocol exposed.

### Black Hat Europe 2025 (London, Dec 2025)
- Wiz launched $5M cloud-and-AI hacking competition.
- Agneyastra (Firebase misconfig tool) presented at Arsenal.

---

## 4. TOOLING UPDATES (2024-2026)

| Tool | Update | Notes |
|---|---|---|
| **TruffleHog** | 800+ secret detectors, native S3/GCS sources, IAM role-assume for cross-account S3 scans | CVE-2025-41390 hardened temp-dir handling |
| **Gitleaks** | Pre-commit-hook canonical | Fast regex first pass; pair with TruffleHog in CI |
| **cloud_enum** | Maintained; AWS+GCP+Azure unified `-k` flag | OSINT keyword-mutation engine |
| **S3Scanner** (sa7mon) | Active; multi-region, no-sign-request | Best fast permission tester |
| **s3enum** (koenrh) | DNS-based, no HTTP — *no* CloudTrail logs on the bucket owner | Stealth recon |
| **s3-account-search** (WeAreCloudar) | Recovers AWS account ID from any public bucket | One-digit-at-a-time wildcard |
| **find-s3-account** (Tracebit) | VPC endpoint variant; works on *private* buckets you can access | Stealth: STS calls stay in attacker account |
| **goblob** (Macmod) | Azure Blob enumeration; goroutine concurrency | Faster than MicroBurst |
| **MicroBurst** (NetSPI) | `Invoke-EnumerateAzureBlobs.ps1` — DNS lookups + Bing | Standard Azure recon |
| **basicblobfinder** (joswr1ght) | Naïve wordlist-based Azure blob hunting | Slow, single-threaded; teaching aid |
| **Agneyastra** (RedHunt Labs) | Firebase auth+storage+RTDB+Firestore+Remote Config misconfig kit; Black Hat EU 2025 Arsenal | Inputs an API key, autoextracts project, runs unauth → anon-auth → email-signup test ladder |
| **GrayHatWarfare** | Premium tier: full-path search, regex, +sorting, +20 exclude slots; Early Access 2-week beta channel | Goldmine for `.env`, `id_rsa`, `terraform.tfstate` |
| **Nuclei** | `cloud/aws/s3/` templates expanded; `http/takeovers/` for fingerprint-based subdomain takeover | Routine sweep |

---

## 5. BUG BOUNTY ECONOMICS (selected disclosed cases)

| Target | Bug | Payout |
|---|---|---|
| Private program | Presigned URL `filePath=/` → entire bucket | $20,000 |
| Private program | S3 signed URL flaw → all docs leak | $25,000 |
| Reddit | S3 bucket takeover (presentation subdomain) | Disclosed, undisclosed amount |
| Brave Software | S3 takeover | Disclosed |
| US DoD | Misconfigured S3 (PII) | Disclosed (gov bounty) |
| Greenhouse | Open S3 accessible to any AWS user | Disclosed |
| Courier | Open S3 — all uploads readable | Disclosed |
| GoCD | S3 open to any AWS user | Disclosed |
| Ruby | S3 writeable to any AWS user | Disclosed |
| Backblaze | Hardcoded B2 API key in Android APK → bucket takeover | Resolved (internal-test scope reduced impact) |
| DigitalOcean Spaces | Console hides API-set public ACL | Disclosed |

---

## 6. NEW DETECTION/SOC POSTURE — WHAT BLUE TEAMS ARE WATCHING

| Signal | Source |
|---|---|
| `403 AccessDenied` × ≥30 / second per source IP per bucket | Elastic prebuilt rule, GuardDuty |
| `r2.dev` in TLS SNI | Suricata signature in Cloudflare-aware nets |
| `PutObject` with `x-amz-server-side-encryption-customer-algorithm` header | Codefinger ransomware indicator |
| Lifecycle policies adding `Expiration < 8 days` | Codefinger pressure tactic |
| `PutBucketAcl` with `acl=public-read-write` from non-bucket-owner | High-confidence misconfig in progress |
| Bucket policy mutations adding `Principal:*` | Critical alert |

Implication for hunters: stay below per-second thresholds. `aws s3 ls --no-sign-request` is fine; recursive sync may trip alerts.

---

## 7. RESPONSE-CODE REFERENCE (Updated 2026)

| Code/Body | Meaning | Action |
|---|---|---|
| `200 OK` | Bucket exists, list permitted | Enumerate objects |
| `403 Forbidden + x-amz-bucket-region` | Bucket exists, no list, region disclosed | Try direct object guess, try `ResourceAccount` enum |
| `404 NotFound + NoSuchBucket` | Bucket deleted → **TAKEOVER candidate** | Verify CNAME still points here, register same name same region |
| `404 NotFound` (no NoSuchBucket body) | Post-2023 AWS hardening — bucket name suppressed | Need to enumerate bucket name through alt channel before takeover |
| `301 Moved` + `x-amz-bucket-region` | Wrong region — follow redirect | Continue testing |
| `AllAccessDisabled` | Account-level Block Public Access on | Move to next bucket |
| `AccessDenied` | Bucket policy explicit deny | Try cross-account creds, presigned URLs |
| `NoSuchKey` | Bucket exists, object doesn't | Bucket is enumerable; try directory listing |
| `MethodNotAllowed` | Object-level vs bucket-level confusion | Re-check virtual-hosted vs path style |

---

## 8. CHAIN MATRIX — STORAGE → CRITICAL

| From | Through | To | Severity |
|---|---|---|---|
| Public S3 ListBucket | `.env`/`.tfstate`/`credentials` file | AWS root keys → full account takeover | CRITICAL |
| Public S3 PutObject on JS-serving bucket | Replace `main.js` | Stored XSS on all visitors → mass ATO | CRITICAL |
| Dangling CNAME → S3 takeover | Cookie scoping `.target.com` | CSRF bypass, session fixation, phishing | HIGH→CRITICAL |
| GCS `allUsers` write on `firebasestorage` | Replace ID-photo or post-image | Tampering with KYC pipeline | HIGH |
| Firebase Storage public + insecure rules | Read `users/*/private/*` | Mass PII leak (Tea-app pattern) | CRITICAL |
| Azure SAS token expiring in 2099 | Replay token | Persistent data exfil | HIGH |
| Bucket Monopoly pre-registration | Victim enables service in new region | RCE / template-driven AWS account takeover | CRITICAL |
| SSE-C PutObject loop | 7-day deletion lifecycle | Cloud-native ransomware | CRITICAL |
| Presigned URL `filePath=../../` | Bypass user-prefix scope | Cross-tenant file read | HIGH |
| `s3:ResourceAccount` wildcard | Walk account ID one digit at a time | Identify victim AWS account → next-stage AWS phishing or social-engineering | MEDIUM (info-disclosure pivot) |
| Public EBS snapshot search using stolen account ID | snapshot mount | Credential extraction from disk | HIGH |
| Abandoned bucket re-registration | Serve malicious update | Supply-chain RCE on every requester | CRITICAL |

---

## 9. GAPS AND OPEN QUESTIONS

1. **Cloudflare R2** — no bucket policies / ACLs; only API-token scope. Mostly bug-bounty-relevant via CORS or `r2.dev` exposure. Few public disclosures; under-hunted territory.
2. **DigitalOcean Spaces** — console-vs-API divergence still possible; needs more research.
3. **Backblaze B2** — global bucket namespace; takeover requires valid creds. Hunt for hardcoded keys in mobile/desktop binaries.
4. **AI-driven attacks** — Sysdig's 8-minute case is the first publicly-confirmed end-to-end LLM-piloted breach; expect more.
5. **MCP servers exposed (Trend Micro Jul 2025 → 1,467 exposed)** — many proxy to S3/Bedrock/Azure; cross-cuts with cloud-storage attack surface.

---

## 10. KEY URL REFERENCE LIST

- watchTowr 8M requests: https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/
- Aqua Bucket Monopoly: https://www.aquasec.com/blog/bucket-monopoly-breaching-aws-accounts-through-shadow-resources/
- Aqua CDK takeover: https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/
- Fog Mistrusted Advisor: https://www.fogsecurity.io/blog/mistrusted-advisor-public-s3-buckets
- Fog BPA bypass: https://www.fogsecurity.io/blog/s3-block-public-access-bypass
- Sysdig 8-min: https://www.sysdig.com/blog/ai-assisted-cloud-intrusion-achieves-admin-access-in-8-minutes
- Halcyon Codefinger: https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c
- Arctic Wolf Codefinger: https://arcticwolf.com/resources/blog/ransomware-campaign-encrypting-amazon-s3-buckets-using-sse-c/
- Tracebit account ID: https://tracebit.com/blog/how-to-find-the-aws-account-id-of-any-s3-bucket
- Cloudar account ID: https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/
- Hacking The Cloud (S3): https://hackingthe.cloud/aws/exploitation/orphaned_cloudfront_or_dns_takeover_via_s3/
- Detectify signed URL bypass: https://labs.detectify.com/writeups/bypassing-and-exploiting-bucket-upload-policies-and-signed-urls/
- ivision presigned URL: https://research.ivision.com/signed-sealed-delivered-secure.html
- Bug Bounty Reports Explained $20k: https://www.bugbountyexplained.com/my-20000-s3-bug-that-leaked-everyones-attachments-s3-bucket-misconfig-of-pre-signed-urls/
- m1tz Firebase: https://blog.m1tz.com/posts/2025/07/hacking-firebase-projects-enumeration-and-common-misconfigurations/
- RedHunt Agneyastra: https://redhuntlabs.com/blog/agneyastra-to-the-rescue-protecting-your-firebase-projects-before-the-tea-spills-out/
- Intigriti Cloudflare R2: https://www.intigriti.com/researchers/blog/hacking-tools/hacking-misconfigured-cloudflare-r2-buckets-a-complete-guide
- Microsoft Azure Blob warning: https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/
- NetSPI Azure file enumeration: https://www.netspi.com/blog/technical-blog/cloud-pentesting/anonymously-enumerating-azure-file-resources/
- Google Cloud dangling bucket guidance: https://cloud.google.com/blog/products/identity-security/best-practices-to-prevent-dangling-bucket-takeovers
- ogwilliam GCP takeover: https://blog.ogwilliam.com/post/gcp-storage-security-preventing-takeovers
- Comparitech 6% GCS public: https://www.comparitech.com/blog/information-security/google-cloud-buckets-unauthorized-access-report/
