#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e
set -o pipefail

userdbctl="${1:?}"
nobody="${2:?}"
nogroup="${3:?}"

command -v jq >/dev/null || {
    echo "jq is not available, skipping tests" 1>&2
    exit 77
}

"$userdbctl" --no-pager user root >/dev/null || {
    echo "$userdbctl user root failed, skipping tests" 1>&2
    exit 77
}

set -x

for format in --json=pretty --json=short -j; do
    "$userdbctl" $format user root                      | jq . >/dev/null
    "$userdbctl" $format user root "$nobody"            | jq . >/dev/null
    "$userdbctl" $format user                           | jq . >/dev/null

    "$userdbctl" $format group root                     | jq . >/dev/null
    "$userdbctl" $format group root "$nogroup"          | jq . >/dev/null
    "$userdbctl" $format group                          | jq . >/dev/null

    "$userdbctl" $format users-in-group root            | jq . >/dev/null
    "$userdbctl" $format users-in-group root "$nogroup" | jq . >/dev/null
    "$userdbctl" $format users-in-group                 | jq . >/dev/null

    "$userdbctl" $format groups-of-user root            | jq . >/dev/null
    "$userdbctl" $format groups-of-user root "$nobody"  | jq . >/dev/null
    "$userdbctl" $format groups-of-user                 | jq . >/dev/null

    "$userdbctl" $format services                       | jq . >/dev/null

    "$userdbctl" $format ssh-authorized-keys root       | jq . >/dev/null
    "$userdbctl" $format ssh-authorized-keys "$nobody"  | jq . >/dev/null
done
