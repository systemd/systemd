#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Check that create operations do not follow symlinks in parent directories.
set -eux
set -o pipefail

ROOT=/tmp/tmpfiles-no-follow-create

setup_symlink_parent() {
    rm -rf "$ROOT"
    mkdir -p "$ROOT/target"
    ln -s target "$ROOT/link"
}

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

test_replace_symlink_parent() {
    local name="node-d-replace"

    setup_symlink_parent

    systemd-tmpfiles --root="$ROOT" --dry-run --create - <<EOF
d=     /link/$name    - - - -
EOF

    test -L "$ROOT/link"
    test ! -e "$ROOT/target/$name"

    systemd-tmpfiles --root="$ROOT" --create - <<EOF
d=     /link/$name    - - - -
EOF

    test -d "$ROOT/link"
    test ! -L "$ROOT/link"
    test -d "$ROOT/link/$name"
    test ! -e "$ROOT/target/$name"
}

test_no_follow_parent_with_root() {
    local chroot="$ROOT/chroot"
    local name="node-d-root"

    rm -rf "$ROOT"
    mkdir -p "$chroot/target"
    ln -s target "$chroot/link"

    (! systemd-tmpfiles --root="$chroot" --create - <<EOF
d      /link/$name    - - - -
EOF
    )

    test ! -e "$chroot/target/$name"
    test -L "$chroot/link"
}

test_follow_parent_for_excluded_types() {
    setup_symlink_parent
    mkdir -p "$ROOT/source"
    echo copy >"$ROOT/source/file"
    touch "$ROOT/target/write"

    systemd-tmpfiles --root="$ROOT" --create - <<EOF
f      /link/f-file       - - - - -
F      /link/F-file       - - - - -
C      /link/C-dir        - - - - /source
w      /link/write        - - - - written
L      /link/L-link       - - - - /source/file
EOF

    test -L "$ROOT/link"
    test -f "$ROOT/target/f-file"
    test -f "$ROOT/target/F-file"
    test -f "$ROOT/target/C-dir/file"
    test "$(cat "$ROOT/target/write")" = written
    test "$(readlink "$ROOT/target/L-link")" = /source/file
}

setup_symlink_parent

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

test_replace_symlink_parent
test_no_follow_parent_with_root
test_follow_parent_for_excluded_types

rm -rf "$ROOT"
