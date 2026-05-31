#!/bin/bash
# params.sh — parameter discovery
# Usage: params.sh <url> <output_file>
URL=$1
OUTPUT=${2:-params-out.txt}

# Arjun — parameter discovery
arjun -u "$URL" -oT "$OUTPUT" -q 2>/dev/null

# x8 — hidden parameter discovery
x8 -u "$URL" -o "${OUTPUT%.txt}-x8.txt" -q 2>/dev/null

echo "[params] done → $OUTPUT"
