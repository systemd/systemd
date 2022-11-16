#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e
set -o pipefail

bootctl="${1:?}"

command -v jq >/dev/null || {
    echo "jq is not available, skipping tests" 1>&2
    exit 77
}

"$bootctl" --no-pager list >/dev/null || {
    echo "$bootctl list failed, skipping tests" 1>&2
    exit 77
}

set -x
"$bootctl" list --json=pretty | jq . >/dev/null
"$bootctl" list --json=short | jq . >/dev/null
