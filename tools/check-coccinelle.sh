#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

SRC_DIR="${1:?}"
COCCI_DIR="${2:?}"

FOUND=0

for cocci in "$COCCI_DIR"/check-*.cocci; do
    [[ -f "$cocci" ]] || continue
    output=$(spatch --very-quiet --sp-file "$cocci" --dir "$SRC_DIR" 2>&1)
    if [[ -n "$output" ]]; then
        echo "FAIL: $(basename "$cocci") found issues in $SRC_DIR:"
        echo "$output"
        FOUND=1
    fi
done

if [[ "$FOUND" -ne 0 ]]; then
    echo ""
    echo "Coccinelle check(s) failed. For each flagged dereference, either:"
    echo "  - Add assert(param)/ASSERT_PTR(param) at the top of the function (if the parameter must not be NULL)"
    echo "  - Add an if (param) guard before the dereference (if NULL is valid)"
    echo "  - Add POINTER_MAY_BE_NULL(param) if NULL is okay for param"
    exit 1
fi
