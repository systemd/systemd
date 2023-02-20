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

# bootctl --print-root-device should either succeed or fail with exit status 80
# (because not backed by a single block device), but not fail otherwise.
"$bootctl" -R || test "$?" -eq 80
"$bootctl" -RR || test "$?" -eq 80

if "$bootctl" -R > /dev/null ; then
    P=$("$bootctl" -R)
    PP=$("$bootctl" -RR)

    echo "$P vs $PP"
    test -b "$P"
    test -b "$PP"

    # $P must be a prefix of $PP
    [[ $P = $PP* ]]
fi
