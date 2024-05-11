#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

assert_eq "$LISTEN_FDS" "$1"
assert_eq "$LISTEN_FDNAMES" "$2"

for ((i = 3; i < 3 + LISTEN_FDS; i++)); do
    read -r -u "$i" text
    assert_eq "$text" "${!i}" # Dereference $i to get i'th arg
done
