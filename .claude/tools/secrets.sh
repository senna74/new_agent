#!/bin/bash
# secrets.sh — JS secret scanning
# Usage: secrets.sh <urls_file> <output_dir>
URLS=$1
OUTDIR=${2:-secrets-out}
mkdir -p "$OUTDIR"

# Extract JS files
grep -iE "\.js(\?|$)" "$URLS" | sort -u > "$OUTDIR/js-files.txt"

# jsluice — secrets + endpoints
cat "$OUTDIR/js-files.txt" | while read url; do
  curl -sk "$url" | jsluice secrets >> "$OUTDIR/jsluice-secrets.txt" 2>/dev/null
  curl -sk "$url" | jsluice urls -R "$(echo $url | grep -oP 'https?://[^/]+')" >> "$OUTDIR/jsluice-urls.txt" 2>/dev/null
done

# trufflehog on JS content
trufflehog filesystem "$OUTDIR" --json > "$OUTDIR/trufflehog.json" 2>/dev/null

echo "[secrets] done → $OUTDIR"
