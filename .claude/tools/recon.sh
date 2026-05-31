#!/bin/bash
# recon.sh — discovery pipeline: subfinder + dnsx + httpx + katana
# Usage: recon.sh <target-domain>
# Stdout: JSON summary { live_count, urls_count, subs_count, output_dir }
# Files:  ~/Targets/<target>/tool-output/recon/

set +e
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

TARGET="${1:?target domain required}"
HUNT_DIR="${HOME}/Targets/${TARGET}"
OUT_DIR="${HUNT_DIR}/tool-output/recon"
mkdir -p "$OUT_DIR"

SUBS="${OUT_DIR}/subdomains.txt"
RESOLVED="${OUT_DIR}/resolved.txt"
LIVE="${OUT_DIR}/live.txt"
LIVE_JSON="${OUT_DIR}/live.json"
URLS="${OUT_DIR}/urls.txt"

# Subdomain discovery (60s cap)
timeout 60 subfinder -d "$TARGET" -all -silent 2>/dev/null > "$SUBS"
echo "$TARGET" >> "$SUBS"
sort -u -o "$SUBS" "$SUBS"

# DNS resolution (60s cap)
timeout 60 dnsx -l "$SUBS" -silent -a -resp 2>/dev/null \
  | awk '{print $1}' | sort -u > "$RESOLVED"

# Live host probe (90s cap)
timeout 90 httpx -l "$RESOLVED" -silent -status-code -title -tech-detect -json 2>/dev/null > "$LIVE_JSON"
awk -F'"url":"' '/url/ {split($2,a,"\""); print a[1]}' "$LIVE_JSON" | sort -u > "$LIVE"

# URL crawl (120s cap)
timeout 120 katana -list "$LIVE" -silent -d 2 -jc 2>/dev/null > "$URLS"
timeout 60 waybackurls < "$LIVE" 2>/dev/null | anew "$URLS" >/dev/null

# Output summary as JSON
SUBS_N=$(wc -l < "$SUBS" 2>/dev/null || echo 0)
LIVE_N=$(wc -l < "$LIVE" 2>/dev/null || echo 0)
URLS_N=$(wc -l < "$URLS" 2>/dev/null || echo 0)

cat <<EOF
{"tool":"recon","target":"${TARGET}","output_dir":"${OUT_DIR}","subs_count":${SUBS_N},"live_count":${LIVE_N},"urls_count":${URLS_N},"files":{"subdomains":"${SUBS}","live":"${LIVE}","urls":"${URLS}","live_json":"${LIVE_JSON}"}}
EOF
