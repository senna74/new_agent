#!/bin/bash
# subdomain.sh — subdomain enumeration
# Usage: subdomain.sh <domain> <output_file>
DOMAIN=$1
OUTPUT=${2:-subdomains.txt}
TMP=$(mktemp -d)

subfinder -d "$DOMAIN" -silent -all > "$TMP/subfinder.txt" 2>/dev/null
assetfinder --subs-only "$DOMAIN" > "$TMP/assetfinder.txt" 2>/dev/null
amass enum -passive -d "$DOMAIN" -silent > "$TMP/amass.txt" 2>/dev/null
waybackurls "$DOMAIN" 2>/dev/null | grep -oP '[a-zA-Z0-9._-]+\.'$DOMAIN > "$TMP/wayback.txt" 2>/dev/null

cat "$TMP"/*.txt | sort -u | \
  dnsx -silent -resp-only > "$OUTPUT"

rm -rf "$TMP"
echo "[subdomain] found $(wc -l < "$OUTPUT") subdomains → $OUTPUT"
