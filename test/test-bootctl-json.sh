#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e
set -o pipefail

bootctl="${1:?}"

"$bootctl" --no-pager list >/dev/null || {
    echo "$bootctl list failed, skipping tests" 1>&2
    exit 77
}

set -x

"$bootctl" list --json=pretty | python3 -m json.tool >/dev/null
"$bootctl" list --json=short | python3 -m json.tool >/dev/null

command -v jq >/dev/null || {
    echo "jq is not available, skipping jq tests" 1>&2
    exit 0
}

"$bootctl" list --json=pretty | jq . >/dev/null
"$bootctl" list --json=short | jq . >/dev/null
