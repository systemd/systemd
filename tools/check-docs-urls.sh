#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -euo pipefail

# check-docs-urls.sh
# Extract external URLs from docs/ using git grep, clean them, de-duplicate,
# and check HTTP status codes with curl. Writes results to a status file.

OUT_LIST=${1:-/tmp/docs-urls.txt}
OUT_STATUS=${2:-/tmp/docs-url-status.txt}

usage() {
    cat <<EOF
Usage: $0 [URL_LIST_OUT] [STATUS_OUT]

Extract external URLs from docs/, dedupe and clean them, then check each URL
with curl. Defaults:
  URL_LIST_OUT = /tmp/docs-urls.txt
  STATUS_OUT   = /tmp/docs-url-status.txt

Examples:
  $0
  $0 /tmp/my-urls.txt /tmp/my-status.txt
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

command -v curl >/dev/null 2>&1 || { echo "ERROR: curl not found in PATH" >&2; exit 2; }

# Extract likely URLs. Pattern stops at whitespace, angle bracket or quote/paren to avoid trailing HTML tags.
# Then strip trailing punctuation like ,.;:)\"' and any accidental trailing angle brackets.
git grep 'https*://' docs \
    | sed -e 's|^.*http|http|; s/["`'"'"')< ].*$//' \
    | sort -u > "$OUT_LIST"

echo "Found $(wc -l < "$OUT_LIST") unique urls (written to $OUT_LIST)"

# Check each URL with curl (follows redirects). Output: HTTP_CODE URL
: > "$OUT_STATUS"
while read -r url; do
    [[ -z "$url" ]] && continue
    # Use a reasonable timeout and follow redirects
    code=$(curl -sS -L -o /dev/null -w "%{http_code}" --max-time 3 "$url" || echo "000")
    printf "%s %s\n" "$code" "$url" >> "$OUT_STATUS"
done < "$OUT_LIST"

echo "Wrote status results to $OUT_STATUS"

# Show non-2xx/3xx entries
echo "Non-OK results (not 2xx/3xx):"
grep -E "^[^23]" "$OUT_STATUS" || true

exit 0
