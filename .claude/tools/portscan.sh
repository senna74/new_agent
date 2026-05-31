#!/bin/bash
# portscan.sh — port scanning
# Usage: portscan.sh <hosts_file> <output_dir>
HOSTS=$1
OUTDIR=${2:-portscan-out}
mkdir -p "$OUTDIR"

# naabu fast scan
naabu -list "$HOSTS" \
  -top-ports 1000 \
  -silent \
  -rate 1000 \
  -o "$OUTDIR/open-ports.txt" 2>/dev/null

# httpx on discovered ports
httpx -l "$OUTDIR/open-ports.txt" \
  -silent \
  -status-code \
  -title \
  -json \
  -o "$OUTDIR/http-services.json" 2>/dev/null

echo "[portscan] done → $OUTDIR"
