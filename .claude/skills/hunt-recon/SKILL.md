---
name: hunt-recon
description: Production-grade reconnaissance pipeline covering horizontal recon, subdomain enumeration, live host probing, URL mining, JS analysis, directory fuzzing, parameter discovery, API discovery, cloud recon, GitHub secrets, takeover detection, DNS deep recon, endpoint scoring, and nuclei automation. 15 phases. Run before any /hunt wave. Produces recon/recon-summary.md + recon/endpoint-scores.json + recon/top-endpoints.txt. Skip a phase only if its tools are missing — never abort. Use when /hunt requires PHASE 0 recon gate, when an agent needs an endpoint scoring map, or when the operator runs /recon directly.
---

# hunt-recon

Production reconnaissance pipeline. Runs in 15 ordered phases. Reads target config from `~/.claude/orchestration/target.json`. Writes everything to `{HUNT_DIR}/recon/`. Final output is `recon/recon-summary.md`, `recon/endpoint-scores.json`, `recon/top-endpoints.txt`.

## Hard rules

- Never abort. If a tool is missing, skip its phase and continue.
- Never stop on rate-limit. Back off 2s, retry once, log, continue.
- Never block on permission errors. Log to `notes/recon-errors.log`, continue.
- Always produce `recon-summary.md` even if partial.
- Touch `recon/.recon-done` at the very end to signal completion.
- Phases run sequentially; sub-tasks inside a phase run in parallel (`&` + `wait`).
- Mask any token printed to console (first 10 + last 4 chars).

## Variables (set at start)

```bash
TARGET_NAME=$(python3 -c "import json;print(json.load(open('/home/hunter/.claude/orchestration/target.json'))['meta']['target_name'])")
DASHBOARD_URL=$(python3 -c "import json;print(json.load(open('/home/hunter/.claude/orchestration/target.json'))['urls']['dashboard'])")
HUNT_DIR=$(python3 -c "import json;print(json.load(open('/home/hunter/.claude/orchestration/target.json'))['meta']['hunt_dir'])")
DOMAIN=$(echo "$DASHBOARD_URL" | sed 's|https\?://||' | cut -d/ -f1)
OUT="$HUNT_DIR/recon"
mkdir -p "$OUT" "$OUT/screenshots" "$OUT/js_analysis" "$OUT/gospider"
mkdir -p "$HUNT_DIR/notes"
touch "$HUNT_DIR/notes/recon-errors.log"
echo "[RECON] target=$TARGET_NAME domain=$DOMAIN out=$OUT"
```

---

## PHASE 0 — Tool check + install missing

```bash
echo "[RECON] Phase 0: Tool check"

need_go() {
    command -v "$1" >/dev/null 2>&1 && return 0
    echo "[RECON] Installing $1..."
    go install "$2" 2>>"$HUNT_DIR/notes/recon-errors.log" || echo "[RECON] FAILED to install $1"
}

# Ensure GOPATH/bin in PATH
export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin:$HOME/go/bin"

need_go subfinder    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
need_go dnsx         github.com/projectdiscovery/dnsx/cmd/dnsx@latest
need_go httpx        github.com/projectdiscovery/httpx/cmd/httpx@latest
need_go naabu        github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
need_go katana       github.com/projectdiscovery/katana/cmd/katana@latest
need_go nuclei       github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
need_go uncover      github.com/projectdiscovery/uncover/cmd/uncover@latest
need_go puredns      github.com/d3mondev/puredns/v2@latest
need_go gotator      github.com/Josue87/gotator@latest
need_go alterx       github.com/projectdiscovery/alterx/cmd/alterx@latest
need_go ffuf         github.com/ffuf/ffuf/v2@latest
need_go feroxbuster  github.com/epi052/feroxbuster@latest
need_go gau          github.com/tomnomnom/gau/v2/cmd/gau@latest
need_go waybackurls  github.com/tomnomnom/waybackurls@latest
need_go gospider     github.com/jaeles-project/gospider@latest
need_go hakrawler    github.com/hakluke/hakrawler@latest
need_go gobuster     github.com/OJ/gobuster/v3@latest
need_go tlsx         github.com/projectdiscovery/tlsx/cmd/tlsx@latest
need_go gowitness    github.com/sensepost/gowitness@latest
need_go dalfox       github.com/hahwul/dalfox/v2@latest
need_go trufflehog   github.com/trufflesecurity/trufflehog/v3@latest
need_go uro          github.com/s0md3v/uro@latest

command -v arjun >/dev/null   || pip3 install arjun --break-system-packages 2>>"$HUNT_DIR/notes/recon-errors.log"
command -v waymore >/dev/null || pip3 install waymore --break-system-packages 2>>"$HUNT_DIR/notes/recon-errors.log"
command -v s3scanner >/dev/null || pip3 install git+https://github.com/sa7mon/S3Scanner --break-system-packages 2>>"$HUNT_DIR/notes/recon-errors.log"
command -v wafw00f >/dev/null || pip3 install wafw00f --break-system-packages 2>>"$HUNT_DIR/notes/recon-errors.log"

mkdir -p ~/wordlists
[ ! -f ~/wordlists/subdomains.txt ]   && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -o ~/wordlists/subdomains.txt
[ ! -f ~/wordlists/raft-large.txt ]   && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words-lowercase.txt -o ~/wordlists/raft-large.txt
[ ! -f ~/wordlists/permutations.txt ] && curl -sL https://raw.githubusercontent.com/six2dez/gotator/main/permutations.txt -o ~/wordlists/permutations.txt
[ ! -f ~/wordlists/resolvers.txt ]    && curl -sL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o ~/wordlists/resolvers.txt
[ ! -f ~/wordlists/backup-files.txt ] && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CommonBackupExtensions.fuzz.txt -o ~/wordlists/backup-files.txt

[ ! -d ~/nuclei-templates ] && nuclei -update-templates 2>/dev/null
```

---

## PHASE 1 — Horizontal recon (org → root domains)

```bash
echo "[RECON] Phase 1: Horizontal recon"

> "$OUT/asn_roots.txt"

command -v amass >/dev/null && amass intel -org "$TARGET_NAME" -active -o "$OUT/asn_intel.txt" 2>/dev/null
[ -f "$OUT/asn_intel.txt" ] && cat "$OUT/asn_intel.txt" >> "$OUT/asn_roots.txt"

ASN=$(dig +short "$DOMAIN" 2>/dev/null | head -1 | xargs -I{} whois {} 2>/dev/null | grep -iE "^(origin|originas)" | head -1 | awk '{print $2}')
if [ -n "$ASN" ]; then
    whois -h whois.radb.net -- "-i origin $ASN" 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+" >> "$OUT/asn_cidrs.txt"
fi

curl -s "https://crt.sh/?q=$TARGET_NAME&output=json" 2>/dev/null | \
    python3 -c "import json,sys; data=json.load(sys.stdin); [print(d.get('name_value','')) for d in data]" 2>/dev/null | \
    grep -oE "[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}" | awk -F. '{print $(NF-1)"."$NF}' | sort -u >> "$OUT/asn_roots.txt"

echo "$DOMAIN" >> "$OUT/asn_roots.txt"
sort -u "$OUT/asn_roots.txt" | grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" > "$OUT/roots.txt"
echo "[RECON] Root domains: $(wc -l < $OUT/roots.txt)"
```

---

## PHASE 2 — Subdomain enumeration

```bash
echo "[RECON] Phase 2: Subdomain enumeration"

# Passive — parallel
( command -v subfinder >/dev/null && subfinder -d "$DOMAIN" -all -recursive -silent -o "$OUT/subfinder.txt" 2>/dev/null ) &
( curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    python3 -c "import json,sys; [print(d['name_value']) for d in json.load(sys.stdin)]" 2>/dev/null | \
    sed 's/\*\.//g' | tr -d '"' | sort -u > "$OUT/crtsh.txt" ) &
( curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" 2>/dev/null | \
    python3 -c "import json,sys; [print(r['hostname']) for r in json.load(sys.stdin).get('passive_dns',[])]" 2>/dev/null > "$OUT/otx.txt" ) &
( curl -s "https://urlscan.io/api/v1/search/?q=domain:$DOMAIN&size=10000" 2>/dev/null | \
    python3 -c "import json,sys; [print(r['page']['domain']) for r in json.load(sys.stdin).get('results',[])]" 2>/dev/null > "$OUT/urlscan.txt" ) &
( command -v tlsx >/dev/null && echo "$DOMAIN" | tlsx -san -cn -silent -resp-only > "$OUT/tls_subs.txt" 2>/dev/null ) &
wait

cat "$OUT/subfinder.txt" "$OUT/crtsh.txt" "$OUT/otx.txt" "$OUT/urlscan.txt" "$OUT/tls_subs.txt" 2>/dev/null | \
    grep -iE "\.$DOMAIN$" | tr '[:upper:]' '[:lower:]' | sort -u > "$OUT/passive_subs.txt"
echo "[RECON] Passive subs: $(wc -l < $OUT/passive_subs.txt)"

# Active bruteforce
if command -v puredns >/dev/null; then
    puredns bruteforce ~/wordlists/subdomains.txt "$DOMAIN" \
        -r ~/wordlists/resolvers.txt --wildcard-tests 30 \
        --write "$OUT/puredns_brute.txt" 2>/dev/null
fi

# Permutations
if command -v gotator >/dev/null && command -v puredns >/dev/null; then
    gotator -sub "$OUT/passive_subs.txt" -perm ~/wordlists/permutations.txt \
        -depth 1 -numbers 3 -mindup -adv -md 2>/dev/null | \
        puredns resolve -r ~/wordlists/resolvers.txt \
        --write "$OUT/permutations_resolved.txt" 2>/dev/null
fi

if command -v alterx >/dev/null && command -v dnsx >/dev/null; then
    alterx -l "$OUT/passive_subs.txt" -enrich 2>/dev/null | \
        dnsx -silent -r ~/wordlists/resolvers.txt > "$OUT/alterx_resolved.txt" 2>/dev/null
fi

# Zone transfers
> "$OUT/zonetransfer.txt"
for ns in $(dig ns "$DOMAIN" +short 2>/dev/null); do
    dig +multi axfr @"$ns" "$DOMAIN" 2>/dev/null | \
        grep -oE "[a-zA-Z0-9._-]+\.$DOMAIN" >> "$OUT/zonetransfer.txt"
done

cat "$OUT/passive_subs.txt" "$OUT/puredns_brute.txt" "$OUT/permutations_resolved.txt" \
    "$OUT/alterx_resolved.txt" "$OUT/zonetransfer.txt" 2>/dev/null | sort -u > "$OUT/all_subs_raw.txt"

if command -v dnsx >/dev/null; then
    dnsx -l "$OUT/all_subs_raw.txt" -a -resp-only -silent \
        -r ~/wordlists/resolvers.txt -o "$OUT/resolved_subs.txt" 2>/dev/null
else
    cp "$OUT/all_subs_raw.txt" "$OUT/resolved_subs.txt"
fi
echo "[RECON] Total resolved: $(wc -l < $OUT/resolved_subs.txt)"
```

---

## PHASE 2.5 — Sensitive data sweep (run BEFORE deep fuzzing)

```bash
echo "[RECON] Phase 2.5: Sensitive data sweep"

# HIGH VALUE FILES — probe these first before anything else
cat > /tmp/high_value_paths.txt << 'PATHS'
.git/config
.git/HEAD
.git/logs/HEAD
.env
.env.production
.env.local
.env.prod
.env.bak
wp-config.php.bak
config.php.bak
database.yml
web.config.bak
composer.lock
package-lock.json
.htpasswd
backup.zip
db.sql
dump.sql
users.csv
swagger.json
openapi.json
api-docs
v2/api-docs
graphql
graphiql
console
actuator
actuator/env
actuator/heapdump
server-status
phpinfo.php
info.php
test.php
_profiler
debug/pprof
rails/info/routes
rails/info/properties
PATHS

mkdir -p "$OUT/evidence"
> "$OUT/high_value_found.txt"
> "$OUT/secrets_in_files.txt"

# Probe all live hosts for high-value files
cat "$OUT/live.txt" 2>/dev/null | while read url; do
  while read path; do
    code=$(curl -sk -o /tmp/hv_check -w "%{http_code}" "$url/$path" --max-time 5)
    if [ "$code" = "200" ]; then
      size=$(wc -c < /tmp/hv_check)
      # Check for real content not just redirect/error page
      if [ $size -gt 50 ]; then
        content=$(head -c 200 /tmp/hv_check)
        echo "[$code] ${size}b $url/$path" >> "$OUT/high_value_found.txt"
        # Check for actual secrets in content
        if echo "$content" | grep -qiE "password|secret|api_key|aws_|private_key|token|DB_PASS"; then
          echo "SECRETS: $url/$path" >> "$OUT/secrets_in_files.txt"
          cp /tmp/hv_check "$OUT/evidence/hv_$(echo $url$path | md5sum | cut -c1-8).txt"
        fi
      fi
    fi
  done < /tmp/high_value_paths.txt
done

echo "[RECON] High value files: $(wc -l < $OUT/high_value_found.txt 2>/dev/null)"
```

---

## PHASE 2.6 — Git reconstruction

```bash
echo "[RECON] Phase 2.6: Git reconstruction"

# For every exposed .git found
grep "\.git/config" "$OUT/high_value_found.txt" 2>/dev/null | while read line; do
  url=$(echo $line | awk '{print $3}' | sed 's|/.git/config||')
  echo "[RECON] Reconstructing git from: $url"
  dump_id=$(echo $url | md5sum | cut -c1-8)
  mkdir -p "$OUT/git_dumps/$dump_id"
  cd "$OUT/git_dumps/$dump_id"

  # GitTools dump
  if command -v gitdumper.sh &>/dev/null; then
    gitdumper.sh "$url/.git/" ./dump/ 2>/dev/null
    cd dump && git checkout -- . 2>/dev/null
    # Search for secrets in history
    git log -p --all 2>/dev/null | grep -iE "password|secret|api_key|aws_access|stripe|token" > ../secrets.txt
    command -v trufflehog >/dev/null && trufflehog filesystem . --only-verified 2>/dev/null >> ../trufflehog.txt
  else
    # Manual download of key files
    for f in HEAD config description COMMIT_EDITMSG index; do
      curl -sk "$url/.git/$f" -o "$f" 2>/dev/null
    done
  fi
  cd "$OUT"
done
```

---

## PHASE 2.7 — JS secrets deep scan

```bash
echo "[RECON] Phase 2.7: JS secrets deep scan"

# Secret patterns to hunt
SECRET_PATTERNS='AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|AIza[0-9A-Za-z_\-]{35}|xox[baprs]-[0-9a-zA-Z\-]{10,72}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}|-----BEGIN.*PRIVATE KEY-----|DB_PASSWORD=|aws_secret_access_key|STRIPE_SECRET|SENDGRID_API|TWILIO_AUTH'

# Scan all downloaded JS files
if [ -d "$OUT/js_analysis" ]; then
  grep -rhoE "$SECRET_PATTERNS" "$OUT/js_analysis/" 2>/dev/null | sort -u > "$OUT/js_secrets_verified.txt"
  echo "[RECON] JS secrets found: $(wc -l < $OUT/js_secrets_verified.txt)"
fi

# Source map recovery
> "$OUT/sourcemap_secrets.txt"
cat "$OUT/all_urls.txt" 2>/dev/null | grep '\.js\.map$' | while read mapurl; do
  curl -sk "$mapurl" -o /tmp/sourcemap.json 2>/dev/null
  python3 -c "
import json, sys
try:
  d = json.load(open('/tmp/sourcemap.json'))
  sources = d.get('sources', [])
  content = d.get('sourcesContent', [])
  for i, src in enumerate(sources):
    if i < len(content) and content[i]:
      with open('/dev/stdout', 'a') as f:
        f.write(f'// SOURCE: {src}\n{content[i]}\n\n')
except: pass
" 2>/dev/null | grep -iE "$SECRET_PATTERNS" >> "$OUT/sourcemap_secrets.txt"
done

echo "[RECON] Sourcemap secrets: $(wc -l < $OUT/sourcemap_secrets.txt 2>/dev/null)"
```

---

## PHASE 2.8 — Cloud bucket sweep

```bash
echo "[RECON] Phase 2.8: Cloud bucket sweep"

TARGET_CLEAN=$(echo $TARGET_NAME | tr '[:upper:]' '[:lower:]' | tr -d '.-')

# Generate comprehensive bucket name permutations
python3 << PYEOF > /tmp/bucket_names.txt
import itertools
bases = ['$TARGET_NAME', '$TARGET_CLEAN', '${TARGET_NAME//./-}']
envs = ['', 'prod', 'production', 'dev', 'development', 'staging', 'stage', 'test', 'qa', 'uat']
types = ['', 'assets', 'static', 'media', 'uploads', 'files', 'backup', 'backups', 'data', 'logs', 'images', 'cdn', 'api']
names = set()
for b in bases:
  for e in envs:
    for t in types:
      parts = [x for x in [b, e, t] if x]
      names.add('-'.join(parts))
      names.add('.'.join(parts))
      names.add('_'.join(parts))
print('\n'.join(names))
PYEOF

> "$OUT/cloud_findings.txt"
> "$OUT/cloud_exists.txt"

# S3 check
while read name; do
  code=$(curl -sk -o /tmp/s3_check -w "%{http_code}" "https://$name.s3.amazonaws.com/" --max-time 3)
  if [ "$code" = "200" ]; then
    echo "S3 PUBLIC READ: $name" >> "$OUT/cloud_findings.txt"
    head -c 500 /tmp/s3_check >> "$OUT/cloud_findings.txt"
  elif [ "$code" = "403" ]; then
    echo "S3 EXISTS (403): $name" >> "$OUT/cloud_exists.txt"
  fi
done < /tmp/bucket_names.txt &

# GCS check
while read name; do
  code=$(curl -sk -o /tmp/gcs_check -w "%{http_code}" "https://storage.googleapis.com/storage/v1/b/$name/o" --max-time 3)
  [ "$code" = "200" ] && echo "GCS PUBLIC: $name" >> "$OUT/cloud_findings.txt"
done < /tmp/bucket_names.txt &

# Firebase check
for name in $TARGET_CLEAN ${TARGET_CLEAN}app ${TARGET_CLEAN}-app; do
  code=$(curl -sk -o /tmp/fb_check -w "%{http_code}" "https://$name.firebaseio.com/.json" --max-time 5)
  if [ "$code" = "200" ]; then
    size=$(wc -c < /tmp/fb_check)
    echo "FIREBASE OPEN: https://$name.firebaseio.com/.json ($size bytes)" >> "$OUT/cloud_findings.txt"
  fi
done &
wait

echo "[RECON] Cloud findings: $(wc -l < $OUT/cloud_findings.txt 2>/dev/null)"
```

---

## PHASE 3 — Live host probing + tech + screenshots

```bash
echo "[RECON] Phase 3: Live host probing"

if command -v httpx >/dev/null; then
    httpx -l "$OUT/resolved_subs.txt" \
        -ports 80,443,8080,8443,8000,8888,3000,5000,7000,9000,9090,4000,4443,6443 \
        -threads 200 -silent \
        -status-code -title -tech-detect -web-server \
        -follow-redirects -ip -cdn \
        -json -o "$OUT/live_hosts.json" 2>/dev/null

    python3 -c "
import json
with open('$OUT/live_hosts.json') as f:
    for line in f:
        try:
            d = json.loads(line)
            print(d.get('url',''))
        except: pass
" | grep -v '^$' > "$OUT/live.txt"
fi
echo "[RECON] Live hosts: $(wc -l < $OUT/live.txt 2>/dev/null)"

if command -v naabu >/dev/null && [ -f "$OUT/live_hosts.json" ]; then
    python3 -c "
import json
seen=set()
with open('$OUT/live_hosts.json') as f:
    for line in f:
        try:
            d = json.loads(line)
            h = d.get('host','')
            if h and h not in seen:
                seen.add(h); print(h)
        except: pass
" > "$OUT/live_ips.txt"
    naabu -l "$OUT/live_ips.txt" -top-ports 1000 -ec -c 50 -silent -o "$OUT/ports.txt" 2>/dev/null
fi

command -v gowitness >/dev/null && [ -s "$OUT/live.txt" ] && \
    gowitness file -f "$OUT/live.txt" -P "$OUT/screenshots/" --no-http 2>/dev/null

command -v wafw00f >/dev/null && [ -s "$OUT/live.txt" ] && \
    wafw00f -i "$OUT/live.txt" -o "$OUT/waf.txt" 2>/dev/null

if command -v nuclei >/dev/null && [ -s "$OUT/live.txt" ] && [ -d ~/nuclei-templates/http/technologies ]; then
    nuclei -l "$OUT/live.txt" -t ~/nuclei-templates/http/technologies/ \
        -silent -o "$OUT/tech_nuclei.txt" 2>/dev/null
fi
```

---

## PHASE 4 — URL mining + historical data

```bash
echo "[RECON] Phase 4: URL mining"

( command -v gau >/dev/null && echo "$DOMAIN" | gau --subs > "$OUT/gau.txt" 2>/dev/null ) &
( command -v waybackurls >/dev/null && [ -s "$OUT/live.txt" ] && cat "$OUT/live.txt" | waybackurls > "$OUT/wayback.txt" 2>/dev/null ) &
( command -v waymore >/dev/null && waymore -i "$DOMAIN" -mode U -oU "$OUT/waymore.txt" 2>/dev/null ) &
wait

if command -v katana >/dev/null && [ -s "$OUT/live.txt" ]; then
    katana -list "$OUT/live.txt" -d 5 -jc -ct 30m -aff -fx -silent -o "$OUT/katana.txt" 2>/dev/null
fi

if command -v gospider >/dev/null && [ -s "$OUT/live.txt" ]; then
    gospider -S "$OUT/live.txt" -d 3 -c 10 -t 20 --sitemap -q -o "$OUT/gospider/" 2>/dev/null
fi

if command -v hakrawler >/dev/null && [ -s "$OUT/live.txt" ]; then
    cat "$OUT/live.txt" | hakrawler -d 3 > "$OUT/hakrawler.txt" 2>/dev/null
fi

cat "$OUT/gau.txt" "$OUT/wayback.txt" "$OUT/waymore.txt" "$OUT/katana.txt" "$OUT/hakrawler.txt" 2>/dev/null > "$OUT/_urls_raw.txt"
[ -d "$OUT/gospider" ] && find "$OUT/gospider" -type f -exec cat {} \; 2>/dev/null | grep -oE "https?://[^ ]+" >> "$OUT/_urls_raw.txt"

if command -v uro >/dev/null; then
    cat "$OUT/_urls_raw.txt" | uro | sort -u > "$OUT/all_urls.txt"
else
    sort -u "$OUT/_urls_raw.txt" > "$OUT/all_urls.txt"
fi
rm -f "$OUT/_urls_raw.txt"

grep -E "\.js(\?|$)" "$OUT/all_urls.txt" | sort -u > "$OUT/js_files.txt"
grep -E "\.(json|yaml|yml|xml|env|config|bak|old|sql|backup|zip|tar)(\?|$)" "$OUT/all_urls.txt" | sort -u > "$OUT/interesting_files.txt"
grep -iE "admin|dashboard|api|internal|debug|swagger|graphql|manage" "$OUT/all_urls.txt" | sort -u > "$OUT/interesting_urls.txt"

echo "[RECON] URLs: $(wc -l < $OUT/all_urls.txt) | JS: $(wc -l < $OUT/js_files.txt) | Interesting: $(wc -l < $OUT/interesting_urls.txt)"
```

---

## PHASE 5 — JavaScript analysis

```bash
echo "[RECON] Phase 5: JS analysis"

> "$OUT/js_urls_downloaded.txt"
while IFS= read -r url; do
    [ -z "$url" ] && continue
    fname=$(echo -n "$url" | md5sum | cut -d' ' -f1).js
    curl -sk --max-time 15 "$url" -o "$OUT/js_analysis/$fname" 2>/dev/null && \
        echo "$fname $url" >> "$OUT/js_urls_downloaded.txt"
done < <(head -300 "$OUT/js_files.txt")

if [ -f ~/LinkFinder/linkfinder.py ]; then
    python3 ~/LinkFinder/linkfinder.py -i "$OUT/js_analysis/" -d -o cli > "$OUT/js_endpoints.txt" 2>/dev/null
else
    grep -hroE '["'"'"'`](/(?:api|v[0-9]|admin|internal)[^"'"'"'`\s]{0,150})["'"'"'`]' "$OUT/js_analysis/" 2>/dev/null | \
        tr -d '"`'"'" | sort -u > "$OUT/js_endpoints.txt"
fi

grep -hroE \
    "(api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|password|passwd|credentials|aws[_-]?access|private[_-]?key|client[_-]?secret|AKIA[A-Z0-9]{16}|sk_live_[A-Za-z0-9]+|eyJ[A-Za-z0-9_-]{20,})" \
    "$OUT/js_analysis/" 2>/dev/null | sort -u > "$OUT/js_secrets.txt"

grep -hroE '["'"'"'`](/api/v[0-9][^"'"'"'`\s]{0,100})["'"'"'`]' "$OUT/js_analysis/" 2>/dev/null | \
    tr -d '"`'"'" | sort -u > "$OUT/js_api_paths.txt"

# Source maps
> "$OUT/sourcemap_files.txt"
grep -E '\.map$' "$OUT/all_urls.txt" | while read -r url; do
    curl -sk --max-time 10 "$url" -o /tmp/sourcemap.json 2>/dev/null
    python3 -c "
import json
try:
    d = json.load(open('/tmp/sourcemap.json'))
    for s in d.get('sources',[]): print(s)
except: pass
" 2>/dev/null >> "$OUT/sourcemap_files.txt"
done

command -v trufflehog >/dev/null && \
    trufflehog filesystem "$OUT/js_analysis/" --only-verified --no-update 2>/dev/null > "$OUT/trufflehog_js.txt"

echo "[RECON] JS endpoints: $(wc -l < $OUT/js_endpoints.txt 2>/dev/null) | Secrets: $(wc -l < $OUT/js_secrets.txt 2>/dev/null)"
```

---

## PHASE 6 — Directory + path fuzzing

```bash
echo "[RECON] Phase 6: Directory fuzzing"

> "$OUT/backup_files.txt"
> "$OUT/api_versions.txt"

if command -v ffuf >/dev/null && [ -s "$OUT/live.txt" ]; then
    head -10 "$OUT/live.txt" | while read -r url; do
        echo "[RECON] ffuf: $url"
        host_id=$(echo -n "$url" | md5sum | cut -d' ' -f1)
        ffuf -u "$url/FUZZ" -w ~/wordlists/raft-large.txt \
            -mc 200,201,301,302,401,403 -ac -s -t 50 \
            -o "$OUT/ffuf_${host_id}.json" -of json 2>/dev/null &
        ffuf -u "$url/FUZZ" -w ~/wordlists/backup-files.txt \
            -e .bak,.old,.swp,.zip,.sql,.tar.gz,.env,.config,.json,.yaml \
            -mc 200,301 -ac -s -t 30 2>/dev/null >> "$OUT/backup_files.txt" &
        wait
    done
fi

# API version sweep across all live hosts
if [ -s "$OUT/live.txt" ]; then
    while read -r url; do
        for path in api/v0 api/v1 api/v2 api/v3 api/v4 api/beta api/internal api/admin v1 v2 v3 _api api-internal private swagger swagger-ui openapi.json api-docs graphql graphiql health metrics debug actuator; do
            code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "$url/$path" 2>/dev/null)
            [ -n "$code" ] && [ "$code" != "404" ] && [ "$code" != "000" ] && \
                echo "$code $url/$path" >> "$OUT/api_versions.txt"
        done
    done < "$OUT/live.txt"
fi

# Feroxbuster on important subdomains
if command -v feroxbuster >/dev/null; then
    for sub in api dev admin staging test beta internal portal; do
        target=$(grep -E "^https?://${sub}\." "$OUT/live.txt" 2>/dev/null | head -1)
        [ -n "$target" ] && feroxbuster -u "$target" -w ~/wordlists/raft-large.txt \
            -t 50 -r --silent -x bak,old,zip,sql,env,json,config,yaml \
            -o "$OUT/ferox_$sub.txt" 2>/dev/null &
    done
    wait
fi
```

---

## PHASE 7 — Parameter discovery

```bash
echo "[RECON] Phase 7: Parameter discovery"

grep -E "\?" "$OUT/all_urls.txt" 2>/dev/null | \
    grep -vE "\.(css|js|png|jpg|jpeg|gif|woff|woff2|ico|svg)(\?|$)" | \
    sort -u | head -100 > "$OUT/param_targets.txt"

if command -v arjun >/dev/null && [ -s "$OUT/param_targets.txt" ]; then
    arjun -i "$OUT/param_targets.txt" -m GET,POST --stable --passive -t 10 \
        -oT "$OUT/arjun_params.txt" 2>/dev/null
fi

if [ -f ~/paramspider/paramspider.py ]; then
    python3 ~/paramspider/paramspider.py --domain "$DOMAIN" \
        --exclude woff,css,js,png,jpg,gif -q \
        --output "$OUT/paramspider.txt" 2>/dev/null
elif command -v paramspider >/dev/null; then
    paramspider -d "$DOMAIN" -o "$OUT/paramspider.txt" 2>/dev/null
fi

echo "[RECON] Params: $(wc -l < $OUT/arjun_params.txt 2>/dev/null)"
```

---

## PHASE 8 — API discovery

```bash
echo "[RECON] Phase 8: API discovery"

> "$OUT/swagger_found.txt"
> "$OUT/graphql_found.txt"

if [ -s "$OUT/live.txt" ]; then
    while read -r url; do
        for path in swagger.json openapi.json api-docs/swagger.json swagger/v1/swagger.json swagger-ui.html swagger-ui/index.html api/swagger.json v1/swagger.json v2/swagger.json v3/swagger.json redoc docs; do
            code=$(curl -sk -o /tmp/swagger_check -w "%{http_code}" --max-time 8 "$url/$path" 2>/dev/null)
            if [ "$code" = "200" ]; then
                size=$(wc -c < /tmp/swagger_check 2>/dev/null)
                [ "$size" -gt 100 ] && echo "$url/$path (${size}b)" >> "$OUT/swagger_found.txt"
            fi
        done
        for gql in graphql graphiql api/graphql query api/query v1/graphql; do
            code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 \
                -X POST -H "Content-Type: application/json" \
                -d '{"query":"{__schema{types{name}}}"}' "$url/$gql" 2>/dev/null)
            [ "$code" = "200" ] && echo "$url/$gql" >> "$OUT/graphql_found.txt"
        done
    done < "$OUT/live.txt"
fi

if command -v kr >/dev/null && [ -f ~/kiterunner/routes-large.kite ]; then
    kr scan "$DOMAIN" -w ~/kiterunner/routes-large.kite \
        -x 5 -j 100 --fail-status-codes 404,429,500 \
        -o "$OUT/kiterunner.txt" 2>/dev/null
fi

curl -s "https://www.postman.com/_api/ws/proxy" \
    -H "Content-Type: application/json" \
    -d "{\"service\":\"search\",\"method\":\"POST\",\"path\":\"/search-all\",\"body\":{\"queryIndices\":[\"collaboration.workspace\"],\"queryText\":\"$DOMAIN\"}}" \
    2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    for r in d.get('data',{}).get('collaboration.workspace',{}).get('hits',{}).get('hits',[]):
        print(r.get('_source',{}).get('slug',''))
except: pass
" > "$OUT/postman_workspaces.txt" 2>/dev/null

echo "[RECON] Swagger: $(wc -l < $OUT/swagger_found.txt) | GraphQL: $(wc -l < $OUT/graphql_found.txt)"
```

---

## PHASE 9 — Cloud recon

```bash
echo "[RECON] Phase 9: Cloud recon"

python3 -c "
target='$TARGET_NAME'
base = list(set([target, target.replace('-',''), target.replace('.','-'), target.lower(), target.lower().replace('-','')]))
suffixes = ['','prod','dev','staging','test','backup','data','assets','static','cdn','api','uploads','files','media','images','logs','archive']
prefixes = ['','prod-','dev-','staging-','backup-','old-']
names=set()
for b in base:
    for pre in prefixes:
        for suf in suffixes:
            names.add(f'{pre}{b}{suf}')
            if suf: names.add(f'{pre}{b}-{suf}')
print('\n'.join(sorted(names)))
" > /tmp/cloud_names.txt

command -v s3scanner >/dev/null && \
    s3scanner -bucket-file /tmp/cloud_names.txt -out-format tsv 2>/dev/null > "$OUT/s3_results.txt"
[ -f "$OUT/s3_results.txt" ] && grep -viE "NoSuchBucket|AccessDenied|^bucket" "$OUT/s3_results.txt" > "$OUT/s3_interesting.txt"

command -v cloud_enum >/dev/null && \
    cloud_enum -kf /tmp/cloud_names.txt -l "$OUT/cloud_enum.txt" 2>/dev/null

> "$OUT/gcs_results.txt"
while read -r name; do
    [ -z "$name" ] && continue
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        "https://storage.googleapis.com/storage/v1/b/$name/o" 2>/dev/null)
    [ -n "$code" ] && [ "$code" != "404" ] && [ "$code" != "000" ] && \
        echo "$code gs://$name" >> "$OUT/gcs_results.txt"
done < /tmp/cloud_names.txt &

> "$OUT/firebase_results.txt"
firebase_base="${DOMAIN%%.*}"
for fb in "$firebase_base" "${firebase_base//-/}" "${firebase_base//./-}" "${TARGET_NAME}" "${TARGET_NAME//-/}"; do
    [ -z "$fb" ] && continue
    code=$(curl -sk -o /tmp/firebase_check -w "%{http_code}" --max-time 5 \
        "https://${fb}.firebaseio.com/.json" 2>/dev/null)
    if [ "$code" = "200" ]; then
        size=$(wc -c < /tmp/firebase_check)
        echo "OPEN https://${fb}.firebaseio.com/.json (${size}b)" >> "$OUT/firebase_results.txt"
    fi
done &
wait

echo "[RECON] Cloud scan done"
```

---

## PHASE 10 — GitHub & code recon

```bash
echo "[RECON] Phase 10: GitHub recon"

ORG=$(echo "$DOMAIN" | cut -d. -f1)

if command -v trufflehog >/dev/null && [ -n "$GITHUB_TOKEN" ]; then
    trufflehog github --org "$ORG" --token "$GITHUB_TOKEN" \
        --results=verified --include-wikis --no-update 2>/dev/null > "$OUT/trufflehog_github.txt"
elif command -v trufflehog >/dev/null; then
    trufflehog github --org "$ORG" --results=verified --no-update 2>/dev/null > "$OUT/trufflehog_github.txt"
fi

if command -v gh >/dev/null && command -v gitleaks >/dev/null; then
    gh repo list "$ORG" --limit 200 --json url 2>/dev/null | \
        python3 -c "import json,sys; [print(r['url']) for r in json.load(sys.stdin)]" 2>/dev/null | \
        while read -r repo; do
            tmp=$(mktemp -d)
            git clone --depth 1 "$repo" "$tmp" 2>/dev/null
            gitleaks detect --source "$tmp" --report-format json \
                --report-path "$OUT/gitleaks_$(basename $repo).json" 2>/dev/null
            rm -rf "$tmp"
        done
fi

cat > "$OUT/google_dorks.txt" <<DORKS
site:$DOMAIN ext:env
site:$DOMAIN ext:sql
site:$DOMAIN ext:bak
site:$DOMAIN inurl:admin
site:$DOMAIN inurl:swagger
site:$DOMAIN "stack trace"
site:github.com "$DOMAIN" "api_key"
site:github.com "$DOMAIN" "password"
site:github.com "$DOMAIN" "secret"
site:pastebin.com "$DOMAIN"
site:trello.com "$DOMAIN"
DORKS

echo "[RECON] GitHub scan complete"
```

---

## PHASE 11 — Subdomain takeover

```bash
echo "[RECON] Phase 11: Takeover checks"

if command -v nuclei >/dev/null && [ -d ~/nuclei-templates/http/takeovers ] && [ -s "$OUT/resolved_subs.txt" ]; then
    nuclei -l "$OUT/resolved_subs.txt" -t ~/nuclei-templates/http/takeovers/ \
        -silent -o "$OUT/takeovers.txt" 2>/dev/null
fi

> "$OUT/takeover_candidates.txt"
while read -r sub; do
    cname=$(dig CNAME "$sub" +short 2>/dev/null | head -1)
    [ -z "$cname" ] && continue
    body=$(curl -sk --max-time 5 "https://$sub" 2>/dev/null)
    if echo "$body" | grep -qiE "NoSuchBucket|There is no app|Repository not found|The specified bucket|Page Not Found|404 Not Found|Heroku.*not found|GitHub.*not found|herokucdn|domain not found"; then
        echo "POTENTIAL: $sub -> $cname" >> "$OUT/takeover_candidates.txt"
    fi
done < "$OUT/resolved_subs.txt"

echo "[RECON] Takeover candidates: $(wc -l < $OUT/takeover_candidates.txt)"
```

---

## PHASE 12 — DNS deep recon

```bash
echo "[RECON] Phase 12: DNS recon"

if command -v dnsx >/dev/null && [ -s "$OUT/resolved_subs.txt" ]; then
    dnsx -l "$OUT/resolved_subs.txt" \
        -a -aaaa -cname -mx -ns -txt -soa -ptr \
        -resp -silent -o "$OUT/dns_records.txt" 2>/dev/null
fi

dig txt "_dmarc.$DOMAIN" +short > "$OUT/dmarc.txt" 2>/dev/null
dig txt "$DOMAIN" +short 2>/dev/null | grep "v=spf1" > "$OUT/spf.txt"
dig txt "default._domainkey.$DOMAIN" +short > "$OUT/dkim.txt" 2>/dev/null

> "$OUT/dns_findings.txt"
grep -q "p=none" "$OUT/dmarc.txt" 2>/dev/null && \
    echo "DMARC p=none — email spoofing possible" >> "$OUT/dns_findings.txt"
[ ! -s "$OUT/spf.txt" ] && \
    echo "No SPF record — email spoofing possible" >> "$OUT/dns_findings.txt"
[ ! -s "$OUT/dmarc.txt" ] && \
    echo "No DMARC record — email spoofing possible" >> "$OUT/dns_findings.txt"
```

---

## PHASE 13 — Endpoint scoring

```python
import json
from pathlib import Path
from urllib.parse import urlparse
import os

HUNT_DIR = Path(os.environ.get("HUNT_DIR", "."))
OUT = HUNT_DIR / "recon"

scores = {}

def score_url(url):
    score = 0
    try: p = urlparse(url)
    except: return 0
    path = (p.path or "").lower()
    params = (p.query or "")
    if any(x in path for x in ['/api/','/v1/','/v2/','/v3/','/graphql','/admin','/internal','/debug','/swagger','/upload','/import','/export','/webhook','/callback']): score += 15
    if any(x in path for x in ['/user','/account','/profile','/auth','/login','/token','/session','/password']): score += 10
    if any(x in path for x in ['/payment','/billing','/subscription','/invoice','/checkout']): score += 15
    if any(x in path for x in ['/file','/download','/attachment','/media','/image','/document']): score += 10
    if params: score += 10
    if params.count('=') > 2: score += 5
    if any(x in params for x in ['url=','redirect=','next=','return=','path=','file=','id=','user=','email=','token=']): score += 15
    sub = (p.netloc or "").split('.')[0].lower()
    if any(x in sub for x in ['api','admin','dev','staging','test','beta','internal','portal','dashboard']): score += 20
    return min(score, 100)

all_urls = set()
for fname in ['all_urls.txt','js_endpoints.txt','api_versions.txt','interesting_urls.txt']:
    f = OUT / fname
    if f.exists():
        for line in f.read_text(errors='ignore').splitlines():
            url = line.strip().split()[-1] if line.strip() else ''
            if url.startswith('http'):
                all_urls.add(url)

for url in all_urls:
    scores[url] = score_url(url)

sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
(OUT/'endpoint-scores.json').write_text(json.dumps(dict(sorted_scores), indent=2))

top50 = [url for url, s in sorted_scores[:50] if s >= 30]
(OUT/'top-endpoints.txt').write_text('\n'.join(top50))

high_count = sum(1 for s in scores.values() if s >= 50)
print(f"[RECON] Scored {len(scores)} endpoints, high-value (>=50): {high_count}")
```

Run with: `HUNT_DIR=$HUNT_DIR python3 /tmp/score_endpoints.py` (write the python block to a temp file first).

---

## PHASE 14 — Nuclei prioritized scanning

```bash
echo "[RECON] Phase 14: Nuclei - prioritized scanning"

# PRIORITY 1: Exposures (sensitive files, tokens, secrets)
nuclei -l "$OUT/live.txt" \
  -tags exposure,config,backup,token \
  -severity medium,high,critical \
  -silent -rate-limit 30 \
  -o "$OUT/nuclei_exposures.txt" 2>/dev/null &

# PRIORITY 2: Exposed admin panels (Jenkins, GitLab, Confluence, etc)
nuclei -l "$OUT/live.txt" \
  -tags panel,login \
  -silent -rate-limit 30 \
  -o "$OUT/nuclei_panels.txt" 2>/dev/null &

# PRIORITY 3: KEV/vKEV (CISA known exploited vulnerabilities - highest RCE probability)
nuclei -l "$OUT/live.txt" \
  -tags kev,vkev \
  -severity critical,high \
  -silent -rate-limit 20 \
  -o "$OUT/nuclei_kev.txt" 2>/dev/null &
wait

# PRIORITY 4: 2025 CVEs (after panels are identified)
nuclei -l "$OUT/live.txt" \
  -t ~/nuclei-templates/http/cves/2025/ \
  -severity critical,high \
  -silent -rate-limit 20 \
  -o "$OUT/nuclei_cves2025.txt" 2>/dev/null

# PRIORITY 5: Misconfiguration
nuclei -l "$OUT/live.txt" \
  -t ~/nuclei-templates/http/misconfiguration/ \
  -severity medium,high,critical \
  -silent -rate-limit 30 \
  -o "$OUT/nuclei_misconfig.txt" 2>/dev/null

echo "[RECON] Nuclei results:"
echo "  Exposures: $(wc -l < $OUT/nuclei_exposures.txt 2>/dev/null)"
echo "  Panels: $(wc -l < $OUT/nuclei_panels.txt 2>/dev/null)"
echo "  KEV/Critical CVEs: $(wc -l < $OUT/nuclei_kev.txt 2>/dev/null)"
echo "  2025 CVEs: $(wc -l < $OUT/nuclei_cves2025.txt 2>/dev/null)"
```

---

## PHASE 14.5 — Admin panel RCE testing

```bash
echo "[RECON] Phase 14.5: Admin panel RCE testing"

> "$OUT/rce_candidates.txt"
> "$OUT/heapdump_secrets.txt"

# Jenkins
grep -i jenkins "$OUT/nuclei_panels.txt" 2>/dev/null | awk '{print $NF}' | while read url; do
  # Try unauthenticated script console
  code=$(curl -sk -o /tmp/jenkins_test -w "%{http_code}" "$url/script" --max-time 5)
  if [ "$code" = "200" ]; then
    echo "JENKINS CONSOLE OPEN: $url/script" >> "$OUT/rce_candidates.txt"
  fi
  # Try anonymous API
  code=$(curl -sk -o /tmp/jenkins_api -w "%{http_code}" "$url/api/json" --max-time 5)
  [ "$code" = "200" ] && echo "JENKINS API OPEN: $url/api/json" >> "$OUT/rce_candidates.txt"
done

# Flask/Werkzeug debug console
grep -i werkzeug "$OUT/nuclei_panels.txt" 2>/dev/null | awk '{print $NF}' | while read url; do
  code=$(curl -sk -o /tmp/flask_test -w "%{http_code}" "$url/console" --max-time 5)
  if [ "$code" = "200" ] && grep -q "interactive" /tmp/flask_test 2>/dev/null; then
    echo "FLASK DEBUG CONSOLE: $url/console" >> "$OUT/rce_candidates.txt"
  fi
done

# Spring Boot Actuator heapdump
grep -i actuator "$OUT/nuclei_exposures.txt" 2>/dev/null | while read line; do
  url=$(echo $line | awk '{print $NF}')
  base=$(echo $url | sed 's|/actuator.*||')
  code=$(curl -sk -o "/tmp/heapdump.hprof" -w "%{http_code}" "$base/actuator/heapdump" --max-time 15)
  if [ "$code" = "200" ]; then
    size=$(wc -c < /tmp/heapdump.hprof)
    echo "HEAPDUMP: $base/actuator/heapdump ($size bytes)" >> "$OUT/rce_candidates.txt"
    # Extract credentials from heap
    strings /tmp/heapdump.hprof | grep -iE "password|secret|api_key|token" | head -20 >> "$OUT/heapdump_secrets.txt"
  fi
done

echo "[RECON] RCE candidates: $(wc -l < $OUT/rce_candidates.txt 2>/dev/null)"
```

---

## PHASE 15 — Recon summary generation

Write summary via python (no heredoc to avoid quoting hell):

```python
import json
from pathlib import Path
from datetime import datetime
import os

HUNT_DIR = Path(os.environ.get("HUNT_DIR","."))
OUT = HUNT_DIR / "recon"

def count_lines(p):
    try: return len(Path(p).read_text(errors='ignore').strip().splitlines())
    except: return 0

stats = [
    ("Root domains",          OUT/'roots.txt'),
    ("Subdomains (passive)",  OUT/'passive_subs.txt'),
    ("Subdomains (total)",    OUT/'all_subs_raw.txt'),
    ("Live hosts",            OUT/'live.txt'),
    ("Total URLs",            OUT/'all_urls.txt'),
    ("JS files",              OUT/'js_files.txt'),
    ("JS endpoints",          OUT/'js_endpoints.txt'),
    ("JS secrets",            OUT/'js_secrets.txt'),
    ("JS secrets (verified)", OUT/'js_secrets_verified.txt'),
    ("Sourcemap secrets",     OUT/'sourcemap_secrets.txt'),
    ("API paths (JS)",        OUT/'js_api_paths.txt'),
    ("Swagger/OpenAPI",       OUT/'swagger_found.txt'),
    ("GraphQL endpoints",     OUT/'graphql_found.txt'),
    ("High value files",      OUT/'high_value_found.txt'),
    ("Secrets in files",      OUT/'secrets_in_files.txt'),
    ("Cloud findings",        OUT/'cloud_findings.txt'),
    ("RCE candidates",        OUT/'rce_candidates.txt'),
    ("Takeover candidates",   OUT/'takeover_candidates.txt'),
    ("S3 interesting",        OUT/'s3_interesting.txt'),
    ("GitHub secrets",        OUT/'trufflehog_github.txt'),
    ("Nuclei exposures",      OUT/'nuclei_exposures.txt'),
    ("Nuclei panels",         OUT/'nuclei_panels.txt'),
    ("Nuclei KEV",            OUT/'nuclei_kev.txt'),
    ("Nuclei 2025 CVEs",      OUT/'nuclei_cves2025.txt'),
]

lines = [f"# Recon Summary: {HUNT_DIR.name}", f"Generated: {datetime.now().isoformat()}", "", "## Stats", "| Category | Count |", "|---|---|"]
for label, path in stats:
    lines.append(f"| {label} | {count_lines(path)} |")

scores_file = OUT/'endpoint-scores.json'
hv = 0
if scores_file.exists():
    try:
        scores = json.loads(scores_file.read_text())
        hv = sum(1 for s in scores.values() if s >= 50)
    except: pass
lines.append(f"| High-value endpoints (>=50) | {hv} |")
lines.append("")
lines.append("## Immediate Actions Required")

priority = [
    (OUT/'rce_candidates.txt',      'RCE CANDIDATES'),
    (OUT/'high_value_found.txt',    'HIGH VALUE FILES'),
    (OUT/'secrets_in_files.txt',    'SECRETS IN EXPOSED FILES'),
    (OUT/'js_secrets_verified.txt', 'JS SECRETS (VERIFIED)'),
    (OUT/'sourcemap_secrets.txt',   'SOURCEMAP SECRETS'),
    (OUT/'cloud_findings.txt',      'CLOUD FINDINGS'),
    (OUT/'takeover_candidates.txt', 'TAKEOVER CANDIDATES'),
    (OUT/'js_secrets.txt',          'SECRETS IN JS'),
    (OUT/'trufflehog_github.txt',   'GITHUB SECRETS'),
    (OUT/'firebase_results.txt',    'OPEN FIREBASE'),
    (OUT/'s3_interesting.txt',      'INTERESTING S3'),
    (OUT/'graphql_found.txt',       'GRAPHQL ENDPOINTS'),
    (OUT/'swagger_found.txt',       'SWAGGER/OPENAPI'),
    (OUT/'nuclei_panels.txt',       'EXPOSED PANELS'),
    (OUT/'nuclei_kev.txt',          'NUCLEI KEV (CISA EXPLOITED)'),
    (OUT/'nuclei_cves2025.txt',     'NUCLEI 2025 CVES'),
    (OUT/'dns_findings.txt',        'DNS ISSUES'),
]
for f, label in priority:
    if f.exists() and f.stat().st_size > 0:
        lines.append("")
        lines.append(f"### {label}")
        for ln in f.read_text(errors='ignore').strip().splitlines()[:10]:
            lines.append(f"- {ln}")

(OUT/'recon-summary.md').write_text('\n'.join(lines))
(OUT/'.recon-done').touch()
print('\n'.join(lines))
print(f"[RECON] Complete — recon-summary.md written")
```

---

## Output guarantees

After full run these files MUST exist (empty is allowed; missing is not):

- `recon/recon-summary.md`
- `recon/endpoint-scores.json`
- `recon/top-endpoints.txt`
- `recon/live.txt`
- `recon/resolved_subs.txt`
- `recon/all_urls.txt`
- `recon/.recon-done` (signal file for orchestrator)

## Fallback chain

1. Tool missing → skip the sub-step, log to `notes/recon-errors.log`, continue.
2. Domain doesn't resolve → mark `notes/dns-failed.log`, still probe via `live.txt` if any.
3. Rate-limited (429) → sleep 2s, retry once, then skip endpoint.
4. Permission denied (filesystem) → log + continue.
5. Network timeout → skip target, continue.
6. Always write `recon-summary.md` and touch `.recon-done` even on partial runs.

## How wave agents consume recon output

- BAC / IDOR → `recon/top-endpoints.txt` first, then `recon/api_versions.txt`
- SSRF → `recon/interesting_urls.txt` + `recon/js_endpoints.txt` (URL params)
- Auth → `recon/swagger_found.txt` + `recon/graphql_found.txt` + `recon/js_api_paths.txt`
- Infra → `recon/takeover_candidates.txt` + `recon/s3_interesting.txt` + `recon/firebase_results.txt`
- Injection → `recon/arjun_params.txt` + `recon/param_targets.txt`
- XSS → `recon/all_urls.txt` filtered by `?` params, `recon/arjun_params.txt`
- Mobile/AI → `recon/js_secrets.txt` + `recon/sourcemap_files.txt`

Every wave agent MUST read `recon/endpoint-scores.json` and test highest-scored endpoints first.

---

## POST-RECON DECISION RULES

After recon completes, agent reads findings and prioritizes:

STOP RECON AND ESCALATE IMMEDIATELY if:
- `rce_candidates.txt` has any entries → test RCE immediately, skip all other recon
- `cloud_findings.txt` has PUBLIC entries → test data access, document, submit
- `secrets_in_files.txt` has entries → validate secrets, assess blast radius, submit
- `js_secrets_verified.txt` has verified live keys → submit immediately

FEED THESE TO ATTACK AGENTS:
- `nuclei_panels.txt` → Agent CRITICAL-RCE (test each panel)
- `high_value_found.txt` → Agent HIGH-INJECTION (look for SQL in exposed configs)
- `swagger_found.txt` → Agent HIGH-PRIVESC (enumerate all API endpoints)
- `js_endpoints.txt` + `js_api_paths.txt` → All agents (test discovered endpoints)
- `top-endpoints.txt` → All agents (highest scored attack surface)
- `rce_candidates.txt` → Agent CRITICAL-RCE (immediate priority)
