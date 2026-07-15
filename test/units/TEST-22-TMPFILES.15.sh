#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Check specifier expansion in L lines.
#
set -eux

rm -fr /tmp/L
mkdir  /tmp/L

# Check that %h expands to $home.
home='/somewhere'
dst='/tmp/L/1'
src="$home"
HOME="$home" \
systemd-tmpfiles --dry-run --create - <<EOF
L     $dst    - - - - %h
EOF
test ! -h "$dst"

HOME="$home" \
systemd-tmpfiles --create - <<EOF
L     $dst    - - - - %h
EOF
test "$(readlink "$dst")" = "$src"

# Check that %h in the path is expanded, but
# the result of this expansion is not expanded once again.
root='/tmp/L/2'
home='/%U'
src="/usr/share/factory$home"
mkdir -p "$root$src"
dst="$root$home"
HOME="$home" \
systemd-tmpfiles --create --dry-run --root="$root" - <<EOF
L     %h    - - - -
EOF
test ! -h "$dst"

HOME="$home" \
systemd-tmpfiles --create --root="$root" - <<EOF
L     %h    - - - -
EOF
test "$(readlink "$dst")" = "$src"

# Check that directory specifiers are not prefixed with --root twice.
root='/tmp/L/3'
rm -rf "$root"
mkdir -p "$root"

output="$(systemd-tmpfiles --create --dry-run --root="$root" - <<EOF
d     %t/test    - - - -
EOF
)"
[[ "$output" == *"Would create directory $root/run/test"* ]]
[[ "$output" != *"$root$root"* ]]

# Check that L? resolves relative targets from the symlink's parent directory.
root='/tmp/L/4'
rm -rf "$root"
mkdir -p "$root"
touch "$root/target"

systemd-tmpfiles --create - <<EOF
L?    $root/link    - - - - target
EOF
test "$(readlink "$root/link")" = "target"

rm -f "$root/link" "$root/target"
systemd-tmpfiles --create - <<EOF
L?    $root/link    - - - - target
EOF
test ! -e "$root/link"

# Conflicting symlink targets for the same path should not be ignored.
root='/tmp/L/5'
rm -rf "$root"
mkdir -p "$root"

(! systemd-tmpfiles --create - <<EOF
L     $root/link    - - - - /one
L     $root/link    - - - - /two
EOF
)
test ! -e "$root/link"
