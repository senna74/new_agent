#!/bin/bash
# fuzz.sh — directory/parameter fuzzing via ffuf
# Usage: fuzz.sh <target-url> [wordlist]
# Stdout: JSON summary { hits_count, output_file }
# Files:  ~/Targets/<host>/tool-output/fuzz/

set +e
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

URL="${1:?target URL required (e.g. https://example.com)}"
WORDLIST="${2:-/usr/share/wordlists/dirb/common.txt}"

if [ ! -f "$WORDLIST" ]; then
  WORDLIST="${HOME}/wordlists/common.txt"
  if [ ! -f "$WORDLIST" ]; then
    mkdir -p "${HOME}/wordlists"
    cat > "$WORDLIST" <<'WL'
admin
api
backup
config
console
debug
dev
graphql
internal
login
manager
swagger
test
.env
.git/HEAD
.well-known/security.txt
robots.txt
sitemap.xml
WL
  fi
fi

HOST=$(echo "$URL" | awk -F'/' '{print $3}')
HUNT_DIR="${HOME}/Targets/${HOST}"
OUT_DIR="${HUNT_DIR}/tool-output/fuzz"
mkdir -p "$OUT_DIR"

OUT="${OUT_DIR}/ffuf.json"

# 4 min cap, status filter excludes 404/403 noise unless interesting
timeout 240 ffuf -x socks5h://127.0.0.1:9050 -u "${URL}/FUZZ" -w "$WORDLIST" -mc 200,204,301,302,307,401,500 \
  -fs 0 -t 30 -p 0.1 -of json -o "$OUT" -s 2>/dev/null

HITS=$(grep -c '"status"' "$OUT" 2>/dev/null || echo 0)

cat <<EOF
{"tool":"fuzz","url":"${URL}","wordlist":"${WORDLIST}","output_file":"${OUT}","hits_count":${HITS}}
EOF
