#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Check that create operations do not follow symlinks in parent directories.
set -eux
set -o pipefail

ROOT=/tmp/tmpfiles-no-follow-create

test_no_follow_parent() {
    local argument="${3:-}"
    local name="node-${1:?}-${2:?}"
    local type="${1:?}"

    if [[ -n "$argument" ]]; then
        (! systemd-tmpfiles --create - <<EOF
$type     $ROOT/link/$name    - - - - $argument
EOF
        )
    else
        (! systemd-tmpfiles --create - <<EOF
$type     $ROOT/link/$name    - - - -
EOF
        )
    fi

    test ! -e "$ROOT/target/$name"
    test -L "$ROOT/link"
}

rm -rf "$ROOT"
mkdir -p "$ROOT/target"
ln -s target "$ROOT/link"

for type in d D v q Q p; do
    test_no_follow_parent "$type" "parent"
done

if mknod "$ROOT/probe-char" c 1 3 2>/dev/null; then
    rm -f "$ROOT/probe-char"
    test_no_follow_parent c "parent" "1:3"
fi

if mknod "$ROOT/probe-block" b 7 0 2>/dev/null; then
    rm -f "$ROOT/probe-block"
    test_no_follow_parent b "parent" "7:0"
fi

rm -rf "$ROOT"
