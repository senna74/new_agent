#!/bin/bash
# scan.sh — nuclei scan against discovered assets
# Usage: scan.sh <target-domain> [severity]
# Stdout: JSON summary { findings_count, output_file }
# Files:  ~/Targets/<target>/tool-output/scan/

set +e
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

TARGET="${1:?target domain required}"
SEVERITY="${2:-medium,high,critical}"
HUNT_DIR="${HOME}/Targets/${TARGET}"
OUT_DIR="${HUNT_DIR}/tool-output/scan"
mkdir -p "$OUT_DIR"

LIVE="${HUNT_DIR}/tool-output/recon/live.txt"
FINDINGS="${OUT_DIR}/nuclei-findings.jsonl"
LOG="${OUT_DIR}/nuclei.log"

# Fallback: scan target itself if no live.txt yet
if [ ! -s "$LIVE" ]; then
  LIVE="${OUT_DIR}/single-target.txt"
  echo "https://${TARGET}" > "$LIVE"
fi

# Ensure templates are up to date (silent, max 30s)
timeout 30 nuclei -ut -silent 2>/dev/null

# Run scan (max 5 min)
timeout 300 nuclei -l "$LIVE" -severity "$SEVERITY" -silent -jsonl -o "$FINDINGS" \
  -rate-limit 50 -concurrency 25 -timeout 10 2>"$LOG"

COUNT=$(wc -l < "$FINDINGS" 2>/dev/null || echo 0)

cat <<EOF
{"tool":"scan","target":"${TARGET}","output_file":"${FINDINGS}","findings_count":${COUNT},"severity":"${SEVERITY}"}
EOF
