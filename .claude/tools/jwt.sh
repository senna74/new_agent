#!/bin/bash
# jwt.sh — jwt_tool analyzer against a JWT token
# Usage: jwt.sh <jwt-token> [target-domain]
# Stdout: JSON summary { issues_count, output_file }

set +e

TOKEN="${1:?JWT token required}"
TARGET="${2:-jwt-analysis}"
HUNT_DIR="${HOME}/Targets/${TARGET}"
OUT_DIR="${HUNT_DIR}/tool-output/jwt"
mkdir -p "$OUT_DIR"

JWT_TOOL_DIR="${HOME}/tools/jwt_tool"
OUT="${OUT_DIR}/jwt-analysis.txt"

if [ ! -d "$JWT_TOOL_DIR" ]; then
  echo '{"tool":"jwt","error":"jwt_tool not installed at ~/tools/jwt_tool"}'
  exit 1
fi

# Mode -M pb = playbook (all checks). 2 min cap.
timeout 120 python3 "${JWT_TOOL_DIR}/jwt_tool.py" "$TOKEN" -M at 2>/dev/null > "$OUT"

ISSUES=$(grep -cE "Vulnerable|WEAK|CRITICAL" "$OUT" 2>/dev/null || echo 0)
ALG=$(grep -oE '"alg": *"[^"]+"' "$OUT" | head -1 | sed 's/.*"alg": *"//;s/"//' || echo "unknown")

cat <<EOF
{"tool":"jwt","target":"${TARGET}","output_file":"${OUT}","issues_count":${ISSUES},"alg":"${ALG}"}
EOF
