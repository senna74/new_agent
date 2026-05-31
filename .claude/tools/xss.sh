#!/bin/bash
# xss.sh — dalfox XSS analyzer against URLs with parameters
# Usage: xss.sh <target-domain>
# Stdout: JSON summary { confirmed_count, output_file }
# Files:  ~/Targets/<target>/tool-output/xss/

set +e
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

TARGET="${1:?target domain required}"
HUNT_DIR="${HOME}/Targets/${TARGET}"
OUT_DIR="${HUNT_DIR}/tool-output/xss"
mkdir -p "$OUT_DIR"

URLS="${HUNT_DIR}/tool-output/recon/urls.txt"
PARAM_URLS="${OUT_DIR}/param-urls.txt"
OUT="${OUT_DIR}/dalfox.jsonl"

# Filter URLs that contain a query parameter
[ -s "$URLS" ] && grep '?' "$URLS" | grep '=' | sort -u > "$PARAM_URLS"

if [ ! -s "$PARAM_URLS" ]; then
  echo '{"tool":"xss","target":"'"$TARGET"'","confirmed_count":0,"reason":"no parameterized URLs in recon output"}'
  exit 0
fi

# Cap to top 200 URLs for speed
head -200 "$PARAM_URLS" > "${PARAM_URLS}.top"

# 5 min cap
timeout 300 dalfox file "${PARAM_URLS}.top" --silence --format json --output "$OUT" \
  --worker 50 --skip-bav --skip-mining-dom 2>/dev/null

COUNT=$(grep -c '"type":"V"' "$OUT" 2>/dev/null || echo 0)

cat <<EOF
{"tool":"xss","target":"${TARGET}","output_file":"${OUT}","confirmed_count":${COUNT},"urls_tested":$(wc -l < "${PARAM_URLS}.top" 2>/dev/null || echo 0)}
EOF
