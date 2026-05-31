#!/bin/bash
# dalfox.sh — XSS scanning (replaces xss.sh for automation)
# Usage: dalfox.sh <urls_file> <output_file>
URLS=$1
OUTPUT=${2:-dalfox-out.txt}

dalfox file "$URLS" \
  --skip-bav \
  --silence \
  --output "$OUTPUT" \
  --format json \
  --timeout 10 \
  --delay 100 2>/dev/null

echo "[dalfox] done → $OUTPUT"
