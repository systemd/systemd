#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e
set -o pipefail

userdbctl="${1:?}"
nobody="${2:?}"
nogroup="${3:?}"

"$userdbctl" --no-pager user root >/dev/null || {
    echo "$userdbctl user root failed, skipping tests" 1>&2
    exit 77
}

set -x

for format in --json=pretty --json=short -j; do
    "$userdbctl" $format user root                      | python3 -m json.tool >/dev/null
    "$userdbctl" $format user root "$nobody"            | python3 -m json.tool >/dev/null
    "$userdbctl" $format user                           | python3 -m json.tool >/dev/null

    "$userdbctl" $format group root                     | python3 -m json.tool >/dev/null
    "$userdbctl" $format group root "$nogroup"          | python3 -m json.tool >/dev/null
    "$userdbctl" $format group                          | python3 -m json.tool >/dev/null

    "$userdbctl" $format users-in-group root            | python3 -m json.tool >/dev/null
    "$userdbctl" $format users-in-group root "$nogroup" | python3 -m json.tool >/dev/null
    "$userdbctl" $format users-in-group                 | python3 -m json.tool >/dev/null

    "$userdbctl" $format groups-of-user root            | python3 -m json.tool >/dev/null
    "$userdbctl" $format groups-of-user root "$nobody"  | python3 -m json.tool >/dev/null
    "$userdbctl" $format groups-of-user                 | python3 -m json.tool >/dev/null

    "$userdbctl" $format services                       | python3 -m json.tool >/dev/null
done
