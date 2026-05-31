#!/bin/bash
# nuclei.sh — vulnerability scanning
# Usage: nuclei.sh <targets_file> <output_file> [severity]
TARGETS=$1
OUTPUT=${2:-nuclei-out.json}
SEVERITY=${3:-critical,high,medium}
nuclei -l "$TARGETS" \
  -severity "$SEVERITY" \
  -silent \
  -json-export "$OUTPUT" \
  -rate-limit 50 \
  -bulk-size 25 \
  -concurrency 10 \
  -retries 2 \
  -timeout 10
