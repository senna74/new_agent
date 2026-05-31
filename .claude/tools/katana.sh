#!/bin/bash
# katana.sh — crawling + endpoint discovery
# Usage: katana.sh <url> <output_file>
URL=$1
OUTPUT=${2:-katana-out.txt}
katana -u "$URL" \
  -depth 3 \
  -jc \
  -jsl \
  -kf all \
  -aff \
  -silent \
  -rate-limit 50 \
  -o "$OUTPUT"
