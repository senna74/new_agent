#!/bin/bash
# httpx.sh — HTTP probing
# Usage: httpx.sh <domains_file> <output_file>
DOMAINS=${1:-/dev/stdin}
OUTPUT=${2:-httpx-out.json}
httpx -l "$DOMAINS" \
  -silent \
  -status-code \
  -title \
  -tech-detect \
  -follow-redirects \
  -threads 50 \
  -rate-limit 50 \
  -json \
  -o "$OUTPUT"
