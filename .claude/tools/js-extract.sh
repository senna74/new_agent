#!/bin/bash
# js-extract.sh — Extract ALL endpoints from JS using real tools
# Usage: js-extract.sh <target_domain> <cookies> <output_dir>

DOMAIN=$1
COOKIES=$2
OUTDIR=$3

mkdir -p "$OUTDIR/js" "$OUTDIR/endpoints"

echo "[js-extract] Starting on $DOMAIN"

# Step 1: gau + waybackurls — historical JS URLs
echo "[js-extract] Step 1: historical JS URLs"
{
  gau --subs "$DOMAIN" 2>/dev/null
  waybackurls "$DOMAIN" 2>/dev/null
} | grep -iE "\.js(\?|$)" \
  | grep -v "google\|facebook\|twitter\|optimizely\|trustarc\|analytics" \
  | sort -u > "$OUTDIR/js/js-urls.txt"

echo "[js-extract] Found $(wc -l < $OUTDIR/js/js-urls.txt) JS URLs"

# Step 2: katana — crawl with auth cookies
echo "[js-extract] Step 2: katana crawl"
katana -u "https://$DOMAIN" \
  -depth 4 \
  -jc \
  -jsl \
  -kf all \
  -aff \
  -silent \
  -H "Cookie: $COOKIES" \
  -rate-limit 10 \
  2>/dev/null >> "$OUTDIR/js/js-urls.txt"

sort -u "$OUTDIR/js/js-urls.txt" -o "$OUTDIR/js/js-urls.txt"
echo "[js-extract] Total JS URLs: $(wc -l < $OUTDIR/js/js-urls.txt)"

# Step 3: Download ALL JS files with auth
echo "[js-extract] Step 3: downloading JS files"
while IFS= read -r url; do
  [ -z "$url" ] && continue
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -sk \
    -H "Cookie: $COOKIES" \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    -H "Referer: https://$DOMAIN/" \
    --max-time 10 \
    "$url" -o "$OUTDIR/js/$filename"
  [ -s "$OUTDIR/js/$filename" ] || rm -f "$OUTDIR/js/$filename"
done < "$OUTDIR/js/js-urls.txt"

JS_COUNT=$(ls "$OUTDIR/js/"*.js 2>/dev/null | wc -l)
echo "[js-extract] Downloaded $JS_COUNT JS files"

# Step 4: jsluice — understands JS AST, extracts all URL patterns
echo "[js-extract] Step 4: jsluice full extraction"
for jsfile in "$OUTDIR/js/"*.js; do
  [ -f "$jsfile" ] || continue
  jsluice urls -R "https://$DOMAIN" < "$jsfile" 2>/dev/null \
    >> "$OUTDIR/endpoints/jsluice-urls.json"
  jsluice secrets < "$jsfile" 2>/dev/null \
    >> "$OUTDIR/endpoints/jsluice-secrets.json"
done

# Step 5: extract all paths from jsluice output
echo "[js-extract] Step 5: extract paths"
jq -r '.url // empty' "$OUTDIR/endpoints/jsluice-urls.json" 2>/dev/null \
  | grep -oP '(?<=https?://[^/]{3,100})/[^\s"'"'"'`>]+' \
  | sort -u > "$OUTDIR/endpoints/jsluice-paths.txt"

# Step 6: trufflehog
echo "[js-extract] Step 6: trufflehog"
trufflehog filesystem "$OUTDIR/js/" \
  --json --no-update 2>/dev/null \
  > "$OUTDIR/endpoints/trufflehog.json"

# Step 7: merge all paths — NO filter on /api/ only
echo "[js-extract] Step 7: merge all paths"
{
  cat "$OUTDIR/endpoints/jsluice-paths.txt" 2>/dev/null

  jq -r '.url // empty' "$OUTDIR/endpoints/jsluice-urls.json" 2>/dev/null

  grep -roh '"\/[a-zA-Z0-9_/.-][a-zA-Z0-9_/.-]*"' \
    "$OUTDIR/js/"*.js 2>/dev/null | tr -d '"'

  grep -roh "'\/[a-zA-Z0-9_/.-][a-zA-Z0-9_/.-]*'" \
    "$OUTDIR/js/"*.js 2>/dev/null | tr -d "'"

  grep -roh '`\/[a-zA-Z0-9_/${}.-][a-zA-Z0-9_/${}.-]*`' \
    "$OUTDIR/js/"*.js 2>/dev/null | tr -d '`'

  grep -rohP '(?:fetch|axios|get|post|put|patch|delete|request)\s*\(\s*[`'"'"'"][^`'"'"'"]+[`'"'"'"]' \
    "$OUTDIR/js/"*.js 2>/dev/null \
    | grep -oP '(?<=[`'"'"'"])/[^`'"'"'"]+(?=[`'"'"'"])'

} | grep -E '^/' \
  | grep -v '^//' \
  | sort -u > "$OUTDIR/endpoints/all-paths.txt"

echo "[js-extract] DONE"
echo "[js-extract] Total paths: $(wc -l < $OUTDIR/endpoints/all-paths.txt)"
echo "[js-extract] jsluice secrets: $(wc -l < $OUTDIR/endpoints/jsluice-secrets.json 2>/dev/null || echo 0)"
echo "[js-extract] trufflehog hits: $(grep -c 'SourceMetadata' $OUTDIR/endpoints/trufflehog.json 2>/dev/null || echo 0)"
